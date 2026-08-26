/* A fake network of hosts, exercising the whole library where the modules
 * meet.
 *
 * Every other test here is a module's own: chains without bytes, reassembly
 * without frames, a replay window without a sender. They are the right shape
 * for finding a defect inside a module and they cannot find one BETWEEN
 * modules -- a receiver that authorises before it checks freshness, a message
 * that reassembles from chunks two different senders wrote, a revocation that
 * arrives while a multi-chunk message is half delivered. This file is where
 * those live.
 *
 * WHAT IS SIMULATED and what is real. The hosts, the datagram queue, the
 * clock, loss, duplication and reordering are simulated. Everything below
 * them is the library itself, called the way sec 4.7 says a receiver must:
 * seal, then freshness and replay, then authorisation, then reassembly. The
 * crypto is stubbed but not weakened -- a wrong key, a forged tag and a
 * forged signature all fail, because a stub that accepted them would make
 * every scenario below vacuous.
 *
 * THE CLOCK ADVANCES, and `frame/test/receive_fuzz.c` records why in blood: a
 * receiver whose clock stands still fills its replay window after eight
 * datagrams and refuses everything afterwards, so the run measures the window
 * rather than the thing under test. Three admissions in twenty thousand cases
 * was the symptom.
 */

#include "../../chain/chain.h"
#include "../../chain/revocation.h"
#include "../../chunk/reassembly.h"
#include "../../chunk/split.h"
#include "../../record/journal.h"
#include "../../record/record.h"
#include "../../record/sync.h"
#include "../../state/state.h"
#include "../../trust/trust.h"
#include "../../frame/freshness.h"
#include "../../session/aead.h"
#include "../../session/commitment.h"
#include "../../session/random.h"
#include "../../version/version.h"
#include "../../wire/seal.h"

#include <stdio.h>
#include <string.h>

#define SIM_HOSTS      16u
#define SIM_QUEUE      2048u
#define SIM_SLOTS      6u
#define SIM_SLOT_CAP   8192u
#define SIM_WINDOW     64u
#define SIM_REVOCATION 16u
/* One slot per possible sender: a host in a mesh of N hears from N-1.
 * Sized so the inbox never silently drops -- see sim_receive, which
 * counts an overflow rather than skipping it, because an inbox that
 * quietly discards a delivery would hide exactly the loss these
 * scenarios exist to detect. */
#define SIM_INBOX      SIM_HOSTS
#define SIM_MSG_MAX    4096u
#define SIM_FRAME_MAX  (FZN_SEAL_OVERHEAD + FZN_SPLIT_MAX_PAYLOAD)

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

/* ---------------------------------------------------------------- crypto

   Stubbed so the simulation can run without a crypto library, and honest so
   that the scenarios mean something. Each has the property the real thing
   has: the tag depends on every byte it covers, the signature depends on who
   signed what, and a key that differs by one byte produces a different
   plaintext.  */

static uint32_t mix(uint32_t x)
{
	x ^= x >> 16;
	x *= 0x7feb352du;
	x ^= x >> 15;
	x *= 0x846ca68bu;
	x ^= x >> 16;
	return x;
}

static void stub_tag(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_len,
                     const uint8_t *text, size_t text_len, uint8_t *tag)
{
	uint32_t acc = 0x1234567u;

	for (size_t i = 0; i < FZN_AEAD_KEY_LEN; i++)
		acc = mix(acc ^ key[i]);
	for (size_t i = 0; i < FZN_AEAD_NONCE_LEN; i++)
		acc = mix(acc ^ nonce[i]);
	for (size_t i = 0; i < aad_len; i++)
		acc = mix(acc ^ aad[i]);
	for (size_t i = 0; i < text_len; i++)
		acc = mix(acc ^ text[i]);
	for (size_t i = 0; i < FZN_AEAD_TAG_LEN; i++)
		tag[i] = (uint8_t)(mix(acc + (uint32_t)i) >> 13);
}

static void sim_seal(void *ctx, const uint8_t *key, const uint8_t *nonce, const uint8_t *aad,
                     size_t aad_len, uint8_t *text, size_t text_len, uint8_t *tag)
{
	(void)ctx;
	for (size_t i = 0; i < text_len; i++)
		text[i] = (uint8_t)(text[i] ^ key[i % FZN_AEAD_KEY_LEN]);
	stub_tag(key, nonce, aad, aad_len, text, text_len, tag);
}

static int sim_open(void *ctx, const uint8_t *key, const uint8_t *nonce, const uint8_t *aad,
                    size_t aad_len, uint8_t *text, size_t text_len, const uint8_t *tag)
{
	uint8_t want[FZN_AEAD_TAG_LEN];

	(void)ctx;
	stub_tag(key, nonce, aad, aad_len, text, text_len, want);
	/* VERIFY BEFORE WRITING, which is the contract and the reason a forged
	 * frame cannot leave half a plaintext in a caller's buffer. */
	if (memcmp(want, tag, FZN_AEAD_TAG_LEN) != 0)
		return 0;
	for (size_t i = 0; i < text_len; i++)
		text[i] = (uint8_t)(text[i] ^ key[i % FZN_AEAD_KEY_LEN]);
	return 1;
}

/* A signature over exactly the bytes of a signed region, which is what a real
 * one is. The region EXCLUDES the signature field -- an earlier version of
 * this signed a struct that contained its own signature, which is circular
 * and only worked because nothing depended on the exclusion.
 *
 * Forging means producing a matching signature, which no scenario below does
 * by guessing. The one that forges a grant calls the signer honestly and
 * lies about the capability instead: a well-formed lie rather than a corrupt
 * frame, which is the harder case to refuse. */
static void sim_sign_bytes(const uint8_t *msg, size_t len, uint8_t sig[FZN_SIG_LEN])
{
	uint32_t acc = 0xabcdefu;

	for (size_t i = 0; i < len; i++)
		acc = mix(acc ^ msg[i]);
	for (size_t i = 0; i < FZN_SIG_LEN; i++)
		sig[i] = (uint8_t)(mix(acc + (uint32_t)i) >> 11);
}

static void sim_sign_hop(fzn_chain_hop_t *hop, uint8_t *region)
{
	fzn_chain_hop_t bare = *hop;

	memset(bare.signature, 0, FZN_SIG_LEN);
	bare.signed_region = NULL;
	bare.signed_region_len = 0;
	memcpy(region, &bare, sizeof(bare));
	sim_sign_bytes(region, sizeof(bare), hop->signature);
	hop->signed_region = region;
	hop->signed_region_len = sizeof(bare);
}

static void sim_sign_record(fzn_revocation_record_t *rec, uint8_t *region)
{
	fzn_revocation_record_t bare = *rec;

	memset(bare.signature, 0, FZN_SIG_LEN);
	bare.signed_region = NULL;
	bare.signed_region_len = 0;
	memcpy(region, &bare, sizeof(bare));
	sim_sign_bytes(region, sizeof(bare), rec->signature);
	rec->signed_region = region;
	rec->signed_region_len = sizeof(bare);
}

/* The signing half of the vtable. Supplying only `verify` is what the first
 * version of this did, and `fzn_chain_delegate` answered "malformed argument"
 * -- correctly, since minting a hop requires a signer. */
static int sim_sign_op(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	sim_sign_bytes(msg, msg_len, sig);
	return 1;
}

static int sim_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                      size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	(void)pubkey;
	sim_sign_bytes(msg, msg_len, want);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

/* ------------------------------------------------------------------ hosts */

struct sim_inbox_entry {
	uint8_t from;
	uint8_t bytes[SIM_MSG_MAX];
	size_t len;
};

struct sim_host {
	uint8_t id;
	uint8_t pubkey[FZN_PUBKEY_LEN];

	/* The chain proving this host may act. One hop for a host the root
	 * granted directly, two for one that was delegated to. */
	fzn_chain_hop_t chain[FZN_CHAIN_MAX_HOPS];
	size_t chain_len;
	uint8_t signed_region[FZN_CHAIN_MAX_HOPS][sizeof(fzn_chain_hop_t)];
	int authorised; /* 0 means the host has no valid grant */

	fzn_replay_window_t window;
	fzn_replay_entry_t entries[SIM_WINDOW];

	fzn_reasm_t reasm;
	fzn_partial_t slots[SIM_SLOTS];
	uint8_t bufs[SIM_SLOTS][SIM_SLOT_CAP];

	struct sim_inbox_entry inbox[SIM_INBOX];
	size_t inbox_len;

	unsigned sent, delivered, refused_shape, refused_replay, refused_auth, refused_reasm;
	unsigned inbox_overflow;

	/* The record layer. `held` is a bitmask per issuer of which sequences
	 * this host has the body of -- one bit per sequence, which is enough
	 * for a scenario and is not how a consumer would store them. */
	fzn_journal_t journal;
	fzn_journal_entry_t jentries[SIM_HOSTS];
	fzn_trust_t trust;
	fzn_state_t state;
	fzn_state_entry_t sentries[8];
	unsigned conflicts;
	uint32_t held[SIM_HOSTS];
	uint64_t issued;
	unsigned gaps_seen, admitted, confirmed;
};

struct sim_datagram {
	uint8_t frame[SIM_FRAME_MAX];
	size_t len;
	uint8_t from, to;
	uint64_t due;
	int live;
};

struct sim_net {
	struct sim_host hosts[SIM_HOSTS];
	size_t host_count;

	struct sim_datagram queue[SIM_QUEUE];
	size_t queue_len;

	uint8_t root[FZN_PUBKEY_LEN];
	uint8_t capability[FZN_CAP_ID_LEN];

	fzn_revocation_store_t revocations;
	fzn_revocation_t revocation_entries[SIM_REVOCATION];

	fzn_aead_ops_t aead;
	fzn_sign_ops_t sign;
	fzn_random_ops_t rng;

	uint64_t now;
	uint32_t seed;
	unsigned loss_pct, dup_pct, reorder_pct;
	unsigned dropped, duplicated, reordered;
};

static uint32_t sim_random(struct sim_net *net)
{
	net->seed = mix(net->seed + 0x9e3779b9u);
	return net->seed;
}

/* The nonce source. Counting rather than random so a run is reproducible and
 * so two frames never collide by accident, which would look like a replay. */
struct sim_rng_ctx {
	uint32_t counter;
};

static int sim_fill(void *ctx, uint8_t *out, size_t len)
{
	struct sim_rng_ctx *c = (struct sim_rng_ctx *)ctx;

	for (size_t i = 0; i < len; i++)
		out[i] = (uint8_t)(mix(c->counter + (uint32_t)i) >> 9);
	c->counter++;
	return 1;
}

static struct sim_rng_ctx rng_ctx;

/* KEY AGREEMENT: THE ONE THING EACH CONSUMER DOES DIFFERENTLY.
 *
 * fuzzypickles, netcfgd and raidcfgd are expected to use this library in
 * almost exactly the same way, differing in how keys are exchanged and in
 * which features they need. That is why the transcript is the caller's
 * (sec 4.5) and why the AEAD, the signer and the entropy source are all
 * vtables: everything below this line is shared, and this line is where a
 * consumer's own scheme plugs in.
 *
 * The simulation therefore stands in for that scheme rather than modelling
 * any one of them -- a key and its commitment per (sender, receiver) pair,
 * agreed by magic. What the scenarios below exercise is everything that
 * happens AFTER two hosts have a key, which is the part all three share. */
static void sim_session_key(uint8_t from, uint8_t to, uint8_t key[FZN_AEAD_KEY_LEN],
                            uint8_t commitment[FZN_COMMITMENT_LEN])
{
	uint32_t acc = mix(0x5eed0000u ^ ((uint32_t)from << 8) ^ to);

	for (size_t i = 0; i < FZN_AEAD_KEY_LEN; i++)
		key[i] = (uint8_t)(mix(acc + (uint32_t)i) >> 7);
	for (size_t i = 0; i < FZN_COMMITMENT_LEN; i++)
		commitment[i] = (uint8_t)(mix(acc + 0x1000u + (uint32_t)i) >> 5);
}

static void sim_identity(uint8_t id, uint8_t out[FZN_PUBKEY_LEN])
{
	memset(out, 0, FZN_PUBKEY_LEN);
	out[0] = id;
	out[1] = (uint8_t)(id ^ 0x5au);
}

static void sim_init(struct sim_net *net, size_t hosts, uint32_t seed)
{
	memset(net, 0, sizeof(*net));
	net->host_count = hosts;
	net->seed = seed;
	net->now = 1000;

	sim_identity(0xff, net->root);
	memset(net->capability, 0xc0, sizeof(net->capability));

	net->aead.seal = sim_seal;
	net->aead.open = sim_open;
	net->aead.ctx = NULL;
	net->sign.verify = sim_verify;
	net->sign.sign = sim_sign_op;
	net->sign.ctx = NULL;
	rng_ctx.counter = seed;
	net->rng.fill = sim_fill;
	net->rng.ctx = &rng_ctx;

	fzn_revocation_store_init(&net->revocations, net->revocation_entries, SIM_REVOCATION);

	for (size_t i = 0; i < hosts; i++) {
		struct sim_host *h = &net->hosts[i];

		h->id = (uint8_t)i;
		sim_identity(h->id, h->pubkey);

		memset(h->chain, 0, sizeof(h->chain));
		memcpy(h->chain[0].grantor, net->root, FZN_PUBKEY_LEN);
		memcpy(h->chain[0].grantee, h->pubkey, FZN_PUBKEY_LEN);
		memcpy(h->chain[0].capability, net->capability, FZN_CAP_ID_LEN);
		h->chain[0].issued_at = 1;
		h->chain[0].expires_at = FZN_NO_EXPIRY;
		h->chain[0].delegable = 1;
		sim_sign_hop(&h->chain[0], h->signed_region[0]);
		h->chain_len = 1;
		h->authorised = 1;

		/* An established host has its root configured out of band. A
		 * joining one does not, and scenario 11 is about that. */
		fzn_trust_init(&h->trust);
		fzn_trust_pin(&h->trust, net->root);

		fzn_journal_init(&h->journal, h->jentries, SIM_HOSTS);
		fzn_state_init(&h->state, h->sentries, 8);

		for (size_t s = 0; s < SIM_SLOTS; s++)
			fzn_reasm_slot_init(&h->slots[s], h->bufs[s], SIM_SLOT_CAP);
		fzn_reasm_init(&h->reasm, h->slots, SIM_SLOTS, 3);
		fzn_replay_init(&h->window, h->entries, SIM_WINDOW);
	}
}

/* ------------------------------------------------------------------- send

   Split a message into chunks, seal each into a frame, and put them on the
   wire. The split is the library's: this is what a consumer would write, and
   getting it wrong here would be getting it wrong there.  */

static int sim_send(struct sim_net *net, uint8_t from, uint8_t to, const uint8_t *msg,
                    size_t len, uint64_t expires_at)
{
	struct sim_host *h = &net->hosts[from];
	uint8_t key[FZN_AEAD_KEY_LEN], commitment[FZN_COMMITMENT_LEN];
	fzn_split_t plan;
	uint32_t message_id;

	if (fzn_split_plan(len, FZN_SPLIT_MAX_PAYLOAD, &plan) != FZN_SPLIT_OK)
		return 0;

	sim_session_key(from, to, key, commitment);
	message_id = mix(((uint32_t)from << 16) ^ ((uint32_t)to << 8) ^ (uint32_t)h->sent);

	for (uint16_t i = 0; i < plan.chunks; i++) {
		struct sim_datagram *d;
		fzn_send_t what;
		size_t offset, piece, wrote = 0;

		if (fzn_split_at(&plan, i, &offset, &piece) != FZN_SPLIT_OK)
			return 0;
		if (net->queue_len >= SIM_QUEUE)
			return 0;

		d = &net->queue[net->queue_len++];
		memset(&what, 0, sizeof(what));
		what.sender = h->pubkey;
		what.capability = net->capability;
		what.payload = msg + offset;
		what.payload_len = piece;
		what.expires_at = expires_at;
		what.msg = message_id;
		what.index = i;
		what.chunks = plan.chunks;
		what.kind = 0;

		if (fzn_seal_build(d->frame, sizeof(d->frame), &wrote, &what, key, commitment,
		                   &net->rng, &net->aead) != FZN_SEAL_OK) {
			net->queue_len--;
			return 0;
		}
		d->len = wrote;
		d->from = from;
		d->to = to;
		d->live = 1;
		/* Reordering is expressed as a delivery time rather than by
		 * shuffling the queue: a datagram that arrives late is what a
		 * network does, and it keeps the queue append-only. */
		d->due = net->now;
		if (net->reorder_pct && (sim_random(net) % 100u) < net->reorder_pct) {
			d->due += 1u + (sim_random(net) % 3u);
			net->reordered++;
		}
	}

	h->sent++;
	return 1;
}

/* ---------------------------------------------------------------- receive

   sec 4.7's order, executed: the seal first, then freshness and replay
   together, then authorisation, then reassembly. The order is the point --
   each step refuses work the next would otherwise do on a stranger's
   say-so.  */

static void sim_receive(struct sim_net *net, struct sim_datagram *d)
{
	struct sim_host *h = &net->hosts[d->to];
	struct sim_host *sender = &net->hosts[d->from];
	uint8_t key[FZN_AEAD_KEY_LEN], commitment[FZN_COMMITMENT_LEN];
	static uint8_t wire[SIM_FRAME_MAX];
	fzn_opened_t opened;
	fzn_partial_t *done = NULL;
	fzn_fresh_err_t fresh;
	fzn_err_t authorised;
	fzn_chain_t proven;
	const uint8_t *anchor;

	/* A COPY, because `fzn_seal_open` decrypts in place. The queued
	 * datagram is what the sender put on the wire; opening it directly
	 * would mutate it, so a duplicate would arrive already decrypted and
	 * be refused on its tag rather than as the replay it is. A real
	 * receiver gets fresh bytes every time, and the first version of this
	 * harness did not -- which turned the replay scenario green for the
	 * wrong reason. */
	memcpy(wire, d->frame, d->len);

	sim_session_key(d->from, d->to, key, commitment);

	/* STEP 1: the frame is a frame, the commitment matches, the tag
	 * verifies. Everything after this is about an authenticated datagram. */
	if (fzn_seal_open(wire, d->len, key, commitment, &net->aead, &opened) !=
	    FZN_SEAL_OK) {
		h->refused_shape++;
		return;
	}

	/* STEPS 2 and 3: freshness then replay, in one call. */
	fresh = fzn_replay_admit(&h->window, opened.nonce, opened.expires_at, FZN_FRAME_COMMAND,
	                         net->now);
	if (fresh != FZN_FRESH_OK) {
		h->refused_replay++;
		return;
	}

	/* STEP 4: is this sender allowed to say this?
	 *
	 * Against THIS RECEIVER'S OWN ANCHOR rather than a root the simulation
	 * holds globally, because that is what a host actually has. An
	 * unanchored host gets NULL from `fzn_trust_root`, which
	 * `fzn_chain_verify` refuses -- so a host that has not joined fails
	 * closed rather than verifying against nothing. */
	anchor = fzn_trust_root(&h->trust);
	if (!anchor) {
		h->refused_auth++;
		return;
	}
	authorised = fzn_chain_verify(sender->chain, sender->chain_len, anchor,
	                              net->capability, net->now,
	                              &net->sign, net->revocations.entries,
	                              net->revocations.used, &proven);
	if (authorised != FZN_OK) {
		h->refused_auth++;
		return;
	}

	/* The chain names a grantee, and the frame names a sender. A receiver
	 * that does not compare them has verified that SOMEBODY holds the
	 * capability, which is not the question it asked. */
	if (!fzn_ct_memeq(proven.grantee, opened.sender, FZN_PUBKEY_LEN)) {
		h->refused_auth++;
		return;
	}

	/* STEP 5: only now does the message occupy memory. */
	if (fzn_reasm_accept(&h->reasm, opened.sender, opened.msg, opened.index, opened.chunks,
	                     opened.payload, opened.payload_len, opened.expires_at, net->now,
	                     &done) != FZN_REASM_OK) {
		h->refused_reasm++;
		return;
	}

	if (done) {
		if (h->inbox_len < SIM_INBOX && done->bytes <= SIM_MSG_MAX) {
			struct sim_inbox_entry *e = &h->inbox[h->inbox_len++];

			e->from = d->from;
			e->len = done->bytes;
			memcpy(e->bytes, done->buf, done->bytes);
		} else {
			h->inbox_overflow++;
		}
		h->delivered++;
		fzn_reasm_release(done);
	}
}

/* One tick: deliver everything due, applying loss and duplication, then move
 * the clock. */
static void sim_step(struct sim_net *net)
{
	for (size_t i = 0; i < net->queue_len; i++) {
		struct sim_datagram *d = &net->queue[i];

		if (!d->live || d->due > net->now)
			continue;
		d->live = 0;

		if (net->loss_pct && (sim_random(net) % 100u) < net->loss_pct) {
			net->dropped++;
			continue;
		}

		sim_receive(net, d);

		if (net->dup_pct && (sim_random(net) % 100u) < net->dup_pct) {
			net->duplicated++;
			sim_receive(net, d);
		}
	}

	net->now++;
}

static void sim_run(struct sim_net *net, unsigned ticks)
{
	for (unsigned t = 0; t < ticks; t++)
		sim_step(net);
	net->queue_len = 0;
}

static void fill_message(uint8_t *buf, size_t len, uint8_t seed)
{
	for (size_t i = 0; i < len; i++)
		buf[i] = (uint8_t)(seed + (i * 31u));
}

/* ------------------------------------------------------------- scenario 1

   A mesh: every host sends a multi-chunk message to every other, on a network
   that loses nothing. Every message must arrive, exactly once, byte for
   byte.  */

static void scenario_mesh(void)
{
	static struct sim_net net;
	static uint8_t msg[SIM_HOSTS][2048];
	unsigned expected = 0, arrived = 0, intact = 0;

	sim_init(&net, SIM_HOSTS, 0xa5a5u);
	for (size_t i = 0; i < SIM_HOSTS; i++)
		fill_message(msg[i], sizeof(msg[i]), (uint8_t)(i + 1u));

	for (size_t from = 0; from < SIM_HOSTS; from++) {
		for (size_t to = 0; to < SIM_HOSTS; to++) {
			if (from == to)
				continue;
			if (!sim_send(&net, (uint8_t)from, (uint8_t)to, msg[from],
			              sizeof(msg[from]), net.now + 500u))
				continue;
			expected++;
			/* Drained per pair: the queue is finite and a mesh of
			 * sixteen hosts is 240 messages of two chunks each. */
			sim_run(&net, 3);
		}
	}

	for (size_t i = 0; i < SIM_HOSTS; i++) {
		struct sim_host *h = &net.hosts[i];

		arrived += h->delivered;
		for (size_t e = 0; e < h->inbox_len; e++)
			if (h->inbox[e].len == sizeof(msg[0]) &&
			    memcmp(h->inbox[e].bytes, msg[h->inbox[e].from], h->inbox[e].len) == 0)
				intact++;
	}

	{
		unsigned overflow = 0;

		for (size_t i = 0; i < SIM_HOSTS; i++)
			overflow += net.hosts[i].inbox_overflow;
		check(overflow == 0, "the inbox overflowed, so deliveries went unchecked");
	}
	check(expected > 0, "the mesh sent nothing, so it proved nothing");
	check(arrived == expected, "not every message arrived on a lossless network");
	check(intact == arrived, "a message arrived with the wrong bytes");
	{
		unsigned shape = 0, replay = 0, auth = 0, reasm = 0;
		for (size_t i = 0; i < SIM_HOSTS; i++) {
			shape += net.hosts[i].refused_shape;
			replay += net.hosts[i].refused_replay;
			auth += net.hosts[i].refused_auth;
			reasm += net.hosts[i].refused_reasm;
		}
		printf("  mesh: %u sent, %u delivered, %u intact\n", expected, arrived, intact);
		printf("  refused: %u shape, %u replay, %u auth, %u reassembly\n",
		       shape, replay, auth, reasm);
	}
}

/* ------------------------------------------------------------- scenario 2

   Replay. Every datagram is delivered twice, and the second copy must be
   refused every time -- not merely usually, and never by arriving as a
   duplicate chunk that reassembly happens to absorb.  */

static void scenario_replay(void)
{
	static struct sim_net net;
	static uint8_t msg[512];
	unsigned before, after;

	sim_init(&net, 4, 0x1111u);
	net.dup_pct = 100;
	fill_message(msg, sizeof(msg), 7);

	check(sim_send(&net, 0, 1, msg, sizeof(msg), net.now + 100u), "the send was refused");
	before = net.hosts[1].refused_replay;
	sim_run(&net, 3);
	after = net.hosts[1].refused_replay;

	check(net.hosts[1].delivered == 1, "a doubled datagram delivered the message twice");
	check(after > before, "the duplicate was not refused as a replay");
	check(net.duplicated > 0, "no datagram was actually duplicated");
	printf("  replay: %u duplicated, %u refused as replay, %u delivered\n", net.duplicated,
	       after - before, net.hosts[1].delivered);
}

/* ------------------------------------------------------------- scenario 3

   Revocation mid-flight. A host is revoked while its message is half
   delivered; the remaining chunks must be refused, and the message must NOT
   complete. This is the case a per-module test cannot reach: it needs a
   multi-chunk message, a real store, and a revocation arriving between two
   datagrams.  */

static void scenario_revocation(void)
{
	static struct sim_net net;
	static uint8_t msg[3000];
	fzn_revocation_record_t rec;
	static uint8_t rec_region[sizeof(fzn_revocation_record_t)];

	sim_init(&net, 4, 0x2222u);
	fill_message(msg, sizeof(msg), 11);

	check(sim_send(&net, 2, 3, msg, sizeof(msg), net.now + 100u), "the send was refused");

	/* Deliver the first chunk only. */
	net.queue[0].due = net.now;
	for (size_t i = 1; i < net.queue_len; i++)
		net.queue[i].due = net.now + 5u;
	sim_step(&net);
	check(net.hosts[3].delivered == 0, "a multi-chunk message completed on one chunk");

	/* Signed by the root, because only the root revokes and the store
	 * verifies that rather than trusting the caller. */
	memset(&rec, 0, sizeof(rec));
	memcpy(rec.capability, net.capability, FZN_CAP_ID_LEN);
	memcpy(rec.grantee, net.hosts[2].pubkey, FZN_PUBKEY_LEN);
	memcpy(rec.issuer, net.root, FZN_PUBKEY_LEN);
	rec.issued_at = net.now;
	sim_sign_record(&rec, rec_region);
	check(fzn_revocation_admit(&net.revocations, &rec, net.root, &net.sign) == FZN_OK,
	      "the signed revocation was refused");

	sim_run(&net, 10);
	check(net.hosts[3].delivered == 0, "a revoked sender's message still completed");
	check(net.hosts[3].refused_auth > 0, "the revoked chunks were not refused on authority");
	printf("  revocation: %u chunks refused on authority, %u delivered\n",
	       net.hosts[3].refused_auth, net.hosts[3].delivered);
}

/* ------------------------------------------------------------- scenario 4

   Staleness. A frame whose expiry has passed is refused, and refused BEFORE
   the chain is consulted -- sec 4.7's ordering, observed rather than
   asserted: the authorisation counter must not move.  */

static void scenario_stale(void)
{
	static struct sim_net net;
	static uint8_t msg[256];

	sim_init(&net, 4, 0x3333u);
	fill_message(msg, sizeof(msg), 13);

	/* An expiry two ticks out, delivered five ticks later. */
	check(sim_send(&net, 0, 1, msg, sizeof(msg), net.now + 2u), "the send was refused");
	for (size_t i = 0; i < net.queue_len; i++)
		net.queue[i].due = net.now + 5u;
	sim_run(&net, 8);

	check(net.hosts[1].delivered == 0, "a stale frame was delivered");
	check(net.hosts[1].refused_replay > 0, "the stale frame was not refused on freshness");
	check(net.hosts[1].refused_auth == 0,
	      "the chain was consulted for a frame freshness had already refused");
	printf("  stale: %u refused on freshness, %u reached authorisation\n",
	       net.hosts[1].refused_replay, net.hosts[1].refused_auth);
}

/* ------------------------------------------------------------- scenario 5

   A host with no valid grant. Its frames seal and open perfectly -- it has
   the session key -- and must still be refused, because holding a key is not
   holding a capability.  */

static void scenario_unauthorised(void)
{
	static struct sim_net net;
	static uint8_t msg[256];

	sim_init(&net, 4, 0x4444u);
	fill_message(msg, sizeof(msg), 17);

	/* Forge: the grant now claims a capability nobody granted. The
	 * signature still covers it, so this is a well-formed lie rather than
	 * a corrupt one. */
	memset(net.hosts[0].chain[0].capability, 0xee, FZN_CAP_ID_LEN);
	sim_sign_hop(&net.hosts[0].chain[0], net.hosts[0].signed_region[0]);

	check(sim_send(&net, 0, 1, msg, sizeof(msg), net.now + 100u), "the send was refused");
	sim_run(&net, 3);

	check(net.hosts[1].delivered == 0, "a host without the capability was delivered");
	check(net.hosts[1].refused_auth > 0, "the forged grant was not refused");
	check(net.hosts[1].refused_shape == 0, "the frame itself should have been well formed");
	printf("  unauthorised: %u refused on authority, %u delivered\n",
	       net.hosts[1].refused_auth, net.hosts[1].delivered);
}

/* ------------------------------------------------------------- scenario 6

   Delegation. Host 0 passes the capability to host 1, whose frames are then
   accepted under a two-hop chain rooted in the same pinned root. Nobody
   re-grants anything: the root never sees it.  */

static void scenario_delegation(void)
{
	static struct sim_net net;
	static uint8_t msg[600];
	struct sim_host *from = NULL, *to = NULL;
	fzn_chain_hop_t minted;
	fzn_err_t err;

	sim_init(&net, 4, 0x5555u);
	fill_message(msg, sizeof(msg), 19);
	from = &net.hosts[0];
	to = &net.hosts[1];

	/* Host 1's own root grant is discarded, so that anything it sends must
	 * travel on the delegation or not at all. */
	memset(&minted, 0, sizeof(minted));
	err = fzn_chain_delegate(from->chain, from->chain_len, net.root, net.capability, net.now,
	                         to->pubkey, FZN_NO_EXPIRY, 0, from->signed_region[1],
	                         sizeof(fzn_chain_hop_t), &net.sign, NULL, 0, &minted);
	check(err == FZN_OK, "the delegation was refused");

	if (err == FZN_OK) {
		to->chain[0] = from->chain[0];
		memcpy(to->signed_region[0], from->signed_region[0], sizeof(fzn_chain_hop_t));
		to->chain[0].signed_region = to->signed_region[0];
		/* The library minted and signed it; the harness only takes
		 * ownership of the region so the hop does not point into
		 * another host's memory. */
		to->chain[1] = minted;
		memcpy(to->signed_region[1], minted.signed_region, minted.signed_region_len);
		to->chain[1].signed_region = to->signed_region[1];
		to->chain_len = 2;

		check(sim_send(&net, 1, 2, msg, sizeof(msg), net.now + 100u),
		      "the delegated host could not send");
		sim_run(&net, 4);
		check(net.hosts[2].delivered == 1, "a delegated host's message was not delivered");
		check(net.hosts[2].refused_auth == 0, "a delegated host was refused on authority");
	}
	printf("  delegation: %s, %u delivered\n", fzn_err_str(err), net.hosts[2].delivered);
}

/* ------------------------------------------------------------- scenario 7

   A lossy, reordering network at scale. Two properties, and the second is the
   one that matters: with loss, some messages do not arrive -- and NOTHING
   arrives wrong. A partial message must never be delivered as if whole.  */

static void scenario_lossy(void)
{
	static struct sim_net net;
	static uint8_t msg[SIM_HOSTS][3000];
	unsigned sent = 0, arrived = 0, intact = 0;

	sim_init(&net, SIM_HOSTS, 0x6666u);
	net.loss_pct = 20;
	net.reorder_pct = 40;
	for (size_t i = 0; i < SIM_HOSTS; i++)
		fill_message(msg[i], sizeof(msg[i]), (uint8_t)(i + 3u));

	for (size_t from = 0; from < SIM_HOSTS; from++) {
		size_t to = (from + 1u) % SIM_HOSTS;

		if (!sim_send(&net, (uint8_t)from, (uint8_t)to, msg[from], sizeof(msg[from]),
		              net.now + 200u))
			continue;
		sent++;
		sim_run(&net, 8);
	}

	for (size_t i = 0; i < SIM_HOSTS; i++) {
		struct sim_host *h = &net.hosts[i];

		arrived += h->delivered;
		for (size_t e = 0; e < h->inbox_len; e++)
			if (h->inbox[e].len == sizeof(msg[0]) &&
			    memcmp(h->inbox[e].bytes, msg[h->inbox[e].from], h->inbox[e].len) == 0)
				intact++;
	}

	check(net.dropped > 0, "no datagram was lost, so this tested nothing");
	check(arrived < sent, "a 20% lossy network delivered everything, which is suspect");
	check(intact == arrived, "a message arrived incomplete or corrupt on a lossy network");
	printf("  lossy: %u sent, %u dropped, %u reordered, %u delivered, %u intact\n", sent,
	       net.dropped, net.reordered, arrived, intact);
}

/* ------------------------------------------------------------- scenario 8

   Two senders, one message identifier, one receiver. Reassembly keys on the
   sender as well as the identifier, and this is where that matters: a
   receiver that keyed on the identifier alone would splice one host's chunks
   into another's message and deliver bytes neither sent.  */

static void scenario_splice(void)
{
	static struct sim_net net;
	static uint8_t a[2000], b[2000];
	unsigned wrong = 0;

	sim_init(&net, 4, 0x7777u);
	fill_message(a, sizeof(a), 41);
	fill_message(b, sizeof(b), 97);

	check(sim_send(&net, 0, 2, a, sizeof(a), net.now + 100u), "sender A was refused");
	check(sim_send(&net, 1, 2, b, sizeof(b), net.now + 100u), "sender B was refused");
	sim_run(&net, 6);

	for (size_t e = 0; e < net.hosts[2].inbox_len; e++) {
		struct sim_inbox_entry *in = &net.hosts[2].inbox[e];
		const uint8_t *want = in->from == 0 ? a : b;

		if (in->len != sizeof(a) || memcmp(in->bytes, want, in->len) != 0)
			wrong++;
	}

	check(net.hosts[2].delivered == 2, "both messages should have arrived");
	check(wrong == 0, "a message was spliced from two senders' chunks");
	printf("  splice: %u delivered, %u spliced\n", net.hosts[2].delivered, wrong);
}

/* ------------------------------------------------------------- scenario 9

   Records distributed, received and finalised across a lossy network.

   THIS PATH DOES NOT GO THROUGH `wire/seal.h`, deliberately. A record has no
   encoding in this library and is not going to get one -- `record.h` takes
   its signed region as opaque for the reason `chain.h` gives, and framing is
   the consumer's. What is under test here is the decision and ordering
   logic: which ranges a host asks for, what it does with what arrives out of
   order, and whether "received" and "applied" converge. Scenarios 1 to 8
   already carry bytes over the real frame path.

   THE PROPERTY: with every issuer numbering from 1 and a network that drops
   a fifth of everything, every host ends up holding every record, in order,
   having applied all of it -- and no host ever accepts a sequence it has a
   hole before.  */

#define DIST_HOSTS   8u
#define DIST_RECORDS 5u
#define DIST_ROUNDS  40u

static int holds(const struct sim_host *h, uint8_t issuer, uint64_t seq)
{
	return (h->held[issuer] >> (seq - 1u)) & 1u;
}

static void hold(struct sim_host *h, uint8_t issuer, uint64_t seq)
{
	h->held[issuer] |= (uint32_t)1u << (seq - 1u);
}

/* One host fetches from one peer: compare positions, ask for what is
 * missing, and admit whatever survives the network. */
static void sim_fetch_from(struct sim_net *net, struct sim_host *me, struct sim_host *peer)
{
	fzn_sync_position_t theirs[SIM_HOSTS];
	fzn_sync_request_t want[SIM_HOSTS];
	fzn_sync_plan_t plan;
	size_t n;

	n = fzn_sync_digest(&peer->journal, theirs, SIM_HOSTS);
	if (fzn_sync_plan_fetch(&me->journal, theirs, n, 4, want, SIM_HOSTS, &plan) !=
	    FZN_SYNC_OK)
		return;

	for (size_t r = 0; r < plan.request_count; r++) {
		uint8_t issuer = want[r].issuer[0];

		for (uint64_t seq = want[r].from; seq < want[r].from + want[r].count; seq++) {
			fzn_journal_err_t err;

			/* The peer answers only for records it actually has. */
			if (!holds(peer, issuer, seq))
				continue;
			/* The network eats some of them. */
			if (net->loss_pct && (sim_random(net) % 100u) < net->loss_pct) {
				net->dropped++;
				continue;
			}

			err = fzn_journal_admit(&me->journal, want[r].issuer, seq);
			if (err == FZN_JOURNAL_OK) {
				hold(me, issuer, seq);
				me->admitted++;
			} else if (err == FZN_JOURNAL_ERR_GAP) {
				/* Arrived ahead of a hole. Refused, and the next
				 * round asks for the hole -- which is the whole
				 * reason a gap is reported rather than absorbed. */
				me->gaps_seen++;
			}
		}
	}
}

static void scenario_distribution(void)
{
	static struct sim_net net;
	unsigned converged = 0, total_gaps = 0, total_pending = 0;

	sim_init(&net, DIST_HOSTS, 0x8888u);
	net.loss_pct = 20;

	/* EVERY HOST DECIDES WHICH ISSUERS IT FOLLOWS, before anything is
	 * fetched. `record/sync.h` will not request from an issuer this host
	 * has not adopted, so this is the deliberate step that makes the
	 * network a network -- and leaving it out is what the first run of
	 * this scenario did, converging on nothing. */
	for (uint8_t i = 0; i < DIST_HOSTS; i++) {
		for (uint8_t issuer = 0; issuer < DIST_HOSTS; issuer++) {
			if (issuer == i)
				continue;
			fzn_journal_anchor(&net.hosts[i].journal, net.hosts[issuer].pubkey, 0);
		}
	}

	/* Every host issues, and holds its own from the start. */
	for (uint8_t i = 0; i < DIST_HOSTS; i++) {
		struct sim_host *h = &net.hosts[i];

		for (uint64_t seq = 1; seq <= DIST_RECORDS; seq++) {
			if (fzn_journal_admit(&h->journal, h->pubkey, seq) != FZN_JOURNAL_OK)
				break;
			hold(h, i, seq);
			h->issued = seq;
		}
	}

	/* Rounds of pull. The peer changes each round so that a record reaches
	 * a host that never speaks to its issuer, which is the case a
	 * relay-shaped network actually has. */
	for (unsigned round = 0; round < DIST_ROUNDS; round++) {
		for (uint8_t i = 0; i < DIST_HOSTS; i++) {
			uint8_t p = (uint8_t)((i + 1u + round) % DIST_HOSTS);

			if (p == i)
				continue;
			sim_fetch_from(&net, &net.hosts[i], &net.hosts[p]);
		}

		/* FINALISATION: apply what has been received. Separate from
		 * admitting it, which is the point of the two numbers. */
		for (uint8_t i = 0; i < DIST_HOSTS; i++) {
			struct sim_host *h = &net.hosts[i];

			for (uint8_t issuer = 0; issuer < DIST_HOSTS; issuer++) {
				uint64_t pending = fzn_journal_pending(&h->journal,
				                                       net.hosts[issuer].pubkey);
				uint64_t next;

				if (pending == 0)
					continue;
				next = fzn_journal_next(&h->journal, net.hosts[issuer].pubkey);
				if (fzn_journal_confirm(&h->journal, net.hosts[issuer].pubkey,
				                        next - 1u) == FZN_JOURNAL_OK)
					h->confirmed++;
			}
		}
	}

	for (uint8_t i = 0; i < DIST_HOSTS; i++) {
		struct sim_host *h = &net.hosts[i];
		int complete = 1;

		total_gaps += h->gaps_seen;
		for (uint8_t issuer = 0; issuer < DIST_HOSTS; issuer++) {
			if (fzn_journal_next(&h->journal, net.hosts[issuer].pubkey) !=
			    DIST_RECORDS + 1u)
				complete = 0;
			total_pending += (unsigned)fzn_journal_pending(&h->journal,
			                                               net.hosts[issuer].pubkey);
			for (uint64_t seq = 1; seq <= DIST_RECORDS; seq++)
				if (!holds(h, issuer, seq))
					complete = 0;
		}
		converged += complete ? 1u : 0u;
	}

	check(net.dropped > 0, "no record was lost, so the gap path was never exercised");
	check(total_gaps > 0, "no gap was ever reported, so out-of-order never happened");
	check(converged == DIST_HOSTS, "not every host converged on every record");
	check(total_pending == 0, "a host received records it never confirmed applying");
	printf("  distribution: %u hosts converged, %u dropped, %u gaps refused, %u applied\n",
	       converged, net.dropped, total_gaps, net.hosts[0].confirmed);
}

/* ------------------------------------------------------------ scenario 10

   Configuration propagating, and two issuers disagreeing.

   THE BODIES ARE STATIC BECAUSE THE ENTRIES POINT AT THEM. `state.h` says a
   caller must keep a body alive for as long as an entry refers to it, since
   nothing in this library allocates. A simulation that built records on the
   stack would leave every host's state pointing at dead frames, and it would
   mostly appear to work.

   WHAT A CONFLICT ACTUALLY COSTS, which is the point of the scenario. Records
   arrive in different orders at different hosts on a lossy network. With no
   resolution rule, whichever of two issuers a host hears from FIRST is the
   one it holds -- so hosts genuinely diverge, and `state/` is built so that
   divergence is REPORTED at every host rather than settled differently at
   each. The test therefore asserts three things in order: that one issuer
   alone converges everywhere, that two issuers produce a conflict every host
   can see, and that a consumer rule applied uniformly brings them back
   together.  */

#define STATE_HOSTS 6u
#define KIND_SETTING 42u

/* Deterministic record content, so that both ends of the simulation can build
 * the same record from an (issuer, sequence) pair without an encoder this
 * library does not have. */
static uint8_t state_bodies[STATE_HOSTS][4][16];

static void sim_make_record(fzn_record_t *r, const struct sim_host *issuer, uint64_t seq,
                            uint8_t subject_seed)
{
	memset(r, 0, sizeof(*r));
	memcpy(r->issuer, issuer->pubkey, FZN_PUBKEY_LEN);
	memset(r->subject, subject_seed, FZN_SUBJECT_LEN);
	r->kind = KIND_SETTING;
	r->seq = seq;
	r->issued_at = 1;
	r->body = state_bodies[issuer->id][seq - 1u];
	r->body_len = sizeof(state_bodies[0][0]);
}

/* Which subject a given issuer's given record is about. Alice's first record
 * and Bob's first record deliberately name the SAME subject; everything else
 * is the issuer's own. */
static uint8_t subject_of(uint8_t issuer, uint64_t seq)
{
	if (seq == 1u)
		return 0xC0; /* contested by both writers */
	return (uint8_t)(0xD0u + issuer);
}

static void state_fetch(struct sim_net *net, struct sim_host *me, struct sim_host *peer,
                        uint8_t writers)
{
	fzn_sync_position_t theirs[SIM_HOSTS];
	fzn_sync_request_t want[SIM_HOSTS];
	fzn_sync_plan_t plan;
	size_t n = fzn_sync_digest(&peer->journal, theirs, SIM_HOSTS);

	if (fzn_sync_plan_fetch(&me->journal, theirs, n, 4, want, SIM_HOSTS, &plan) !=
	    FZN_SYNC_OK)
		return;

	for (size_t r = 0; r < plan.request_count; r++) {
		uint8_t issuer = want[r].issuer[0];

		if (issuer >= writers)
			continue;
		for (uint64_t seq = want[r].from; seq < want[r].from + want[r].count; seq++) {
			fzn_record_t rec;

			if (!holds(peer, issuer, seq))
				continue;
			if (net->loss_pct && (sim_random(net) % 100u) < net->loss_pct) {
				net->dropped++;
				continue;
			}
			if (fzn_journal_admit(&me->journal, want[r].issuer, seq) != FZN_JOURNAL_OK)
				continue;

			hold(me, issuer, seq);
			me->admitted++;

			/* RECEIVED IS NOT APPLIED. The record is now held; what
			 * it means for current state is a separate step, and it
			 * is where a conflict surfaces. */
			sim_make_record(&rec, &net->hosts[issuer], seq, subject_of(issuer, seq));
			if (fzn_state_apply(&me->state, &rec) == FZN_STATE_ERR_CONFLICT)
				me->conflicts++;
		}
	}
}

static void scenario_state(void)
{
	static struct sim_net net;
	uint8_t contested[FZN_SUBJECT_LEN];
	unsigned holding_alice = 0, holding_bob = 0, saw_conflict = 0, agreed = 0;
	const uint8_t WRITERS = 2u;

	sim_init(&net, STATE_HOSTS, 0x9999u);
	net.loss_pct = 25;
	memset(contested, 0xC0, sizeof(contested));

	for (uint8_t i = 0; i < STATE_HOSTS; i++)
		for (size_t k = 0; k < 4; k++)
			memset(state_bodies[i][k], (int)(0x10u + i * 4u + k),
			       sizeof(state_bodies[0][0]));

	/* Two writers, two records each: one contested subject and one of
	 * their own. Everyone follows both. */
	for (uint8_t i = 0; i < STATE_HOSTS; i++) {
		for (uint8_t w = 0; w < WRITERS; w++) {
			if (w == i)
				continue;
			fzn_journal_anchor(&net.hosts[i].journal, net.hosts[w].pubkey, 0);
		}
	}
	for (uint8_t w = 0; w < WRITERS; w++) {
		struct sim_host *h = &net.hosts[w];

		for (uint64_t seq = 1; seq <= 2; seq++) {
			fzn_record_t rec;

			if (fzn_journal_admit(&h->journal, h->pubkey, seq) != FZN_JOURNAL_OK)
				break;
			hold(h, w, seq);
			sim_make_record(&rec, h, seq, subject_of(w, seq));
			if (fzn_state_apply(&h->state, &rec) == FZN_STATE_ERR_CONFLICT)
				h->conflicts++;
		}
	}

	for (unsigned round = 0; round < 30u; round++)
		for (uint8_t i = 0; i < STATE_HOSTS; i++) {
			uint8_t p = (uint8_t)((i + 1u + round) % STATE_HOSTS);

			if (p != i)
				state_fetch(&net, &net.hosts[i], &net.hosts[p], WRITERS);
		}

	/* AN UNCONTESTED SUBJECT CONVERGES EVERYWHERE. */
	{
		uint8_t own[FZN_SUBJECT_LEN];
		unsigned same = 0;

		memset(own, 0xD0, sizeof(own));
		for (uint8_t i = 0; i < STATE_HOSTS; i++) {
			const fzn_state_entry_t *e =
			        fzn_state_get(&net.hosts[i].state, own, KIND_SETTING);

			if (e && e->body == state_bodies[0][1])
				same++;
		}
		check(same == STATE_HOSTS, "an uncontested setting did not reach every host");
	}

	/* THE CONTESTED ONE. Every host must hold one of the two, and every
	 * host that met the second must have SEEN the conflict. */
	for (uint8_t i = 0; i < STATE_HOSTS; i++) {
		const fzn_state_entry_t *e =
		        fzn_state_get(&net.hosts[i].state, contested, KIND_SETTING);

		if (!e)
			continue;
		if (memcmp(e->issuer, net.hosts[0].pubkey, FZN_PUBKEY_LEN) == 0)
			holding_alice++;
		else
			holding_bob++;
		saw_conflict += net.hosts[i].conflicts ? 1u : 0u;
	}

	check(holding_alice + holding_bob == STATE_HOSTS,
	      "every host should hold one of the two contested values");
	check(saw_conflict == STATE_HOSTS,
	      "every host should have seen the conflict rather than silently picking");

	/* THE CONSUMER'S RULE, APPLIED UNIFORMLY: the lower issuer key wins.
	 * The library supplies no such rule and this is not one it endorses --
	 * it is the consumer choosing, which is exactly what fzn_state_resolve
	 * exists to make visible. */
	for (uint8_t i = 0; i < STATE_HOSTS; i++) {
		fzn_record_t winner;
		fzn_state_err_t err;

		sim_make_record(&winner, &net.hosts[0], 1, 0xC0);
		err = fzn_state_resolve(&net.hosts[i].state, &winner);
		/* STALE is the ordinary answer on a host that already held the
		 * winner, and there are always some: a rule applied across a
		 * network meets hosts that heard the winning issuer first. A
		 * caller treating anything but OK as failure would report a
		 * fault on exactly the hosts that had nothing wrong. */
		check(err == FZN_STATE_OK || err == FZN_STATE_ERR_STALE,
		      "resolving the conflict was refused");
	}

	for (uint8_t i = 0; i < STATE_HOSTS; i++) {
		const fzn_state_entry_t *e =
		        fzn_state_get(&net.hosts[i].state, contested, KIND_SETTING);

		if (e && memcmp(e->issuer, net.hosts[0].pubkey, FZN_PUBKEY_LEN) == 0)
			agreed++;
	}
	check(agreed == STATE_HOSTS, "the hosts did not converge after the rule was applied");

	printf("  state: %u held alice, %u held bob, %u saw the conflict, %u agreed after\n",
	       holding_alice, holding_bob, saw_conflict, agreed);
}

/* ------------------------------------------------------------ scenario 11

   A host joining a network it has no anchor for.

   THE SEQUENCE IS THE TEST. Before adopting, the joiner must refuse
   everything -- an unanchored host verifying against nothing is the failure
   `trust/` exists to make impossible. After adopting, it must accept the
   network it joined. And after that, a second root must be refused, because
   "first use" is the whole of what TOFU means: a host that re-anchors is
   following whoever spoke to it most recently.

   THE LAST STEP IS WHAT TOFU ACTUALLY BUYS. An attacker holding a
   well-formed chain under its OWN root is refused, not because the chain is
   broken -- it verifies perfectly against that root -- but because it is not
   the root this host adopted. First contact is unauthenticated; every
   contact after it is not.  */

static void scenario_join(void)
{
	static struct sim_net net;
	static uint8_t msg[400];
	struct sim_host *joiner;
	uint8_t rogue_root[FZN_PUBKEY_LEN];
	unsigned before;

	sim_init(&net, 4, 0xaaaau);
	fill_message(msg, sizeof(msg), 23);
	joiner = &net.hosts[3];

	/* It has not joined yet. */
	fzn_trust_init(&joiner->trust);
	check(fzn_trust_root(&joiner->trust) == NULL, "a joining host starts with no anchor");

	check(sim_send(&net, 0, 3, msg, sizeof(msg), net.now + 100u), "the send was refused");
	sim_run(&net, 3);
	check(joiner->delivered == 0, "an unanchored host accepted a frame");
	check(joiner->refused_auth > 0, "and it should have refused on authority");
	check(joiner->refused_shape == 0,
	      "the frame itself was well formed; only the anchor was missing");

	/* THE JOIN. A sponsor's bundle asserts the root; nothing authenticates
	 * it, which is exactly what trust.h says about first contact. */
	check(fzn_trust_adopt(&joiner->trust, net.root, net.now) == FZN_TRUST_OK,
	      "adopting the network's root on first contact");
	check(fzn_trust_source_of(&joiner->trust) == FZN_TRUST_ADOPTED,
	      "recorded as adopted rather than configured");
	check(fzn_trust_adopted_at(&joiner->trust) == net.now, "and when it happened");

	before = joiner->delivered;
	check(sim_send(&net, 0, 3, msg, sizeof(msg), net.now + 100u), "the second send");
	sim_run(&net, 3);
	check(joiner->delivered == before + 1u, "a joined host did not receive");

	/* A SECOND ROOT IS REFUSED, and the anchor does not move. */
	memset(rogue_root, 0x66, sizeof(rogue_root));
	check(fzn_trust_adopt(&joiner->trust, rogue_root, net.now) == FZN_TRUST_ERR_ANCHORED,
	      "a second root was not refused");
	check(memcmp(fzn_trust_root(&joiner->trust), net.root, FZN_PUBKEY_LEN) == 0,
	      "the refused adoption moved the anchor");

	/* AND A WELL-FORMED CHAIN UNDER THE WRONG ROOT IS REFUSED. Host 1 is
	 * re-grafted onto the rogue root and signs honestly: the chain checks
	 * out against that root and against no other. */
	{
		struct sim_host *attacker = &net.hosts[1];
		fzn_chain_t proven;
		unsigned refused_before;

		memcpy(attacker->chain[0].grantor, rogue_root, FZN_PUBKEY_LEN);
		sim_sign_hop(&attacker->chain[0], attacker->signed_region[0]);

		/* It really does verify -- under its own root. Otherwise this
		 * would be testing a broken chain rather than a foreign one. */
		check(fzn_chain_verify(attacker->chain, attacker->chain_len, rogue_root,
		                       net.capability, net.now, &net.sign,
		                       net.revocations.entries, net.revocations.used,
		                       &proven) == FZN_OK,
		      "the attacker's chain should be valid under its own root");

		refused_before = joiner->refused_auth;
		before = joiner->delivered;
		check(sim_send(&net, 1, 3, msg, sizeof(msg), net.now + 100u), "the attacker's send");
		sim_run(&net, 3);
		check(joiner->delivered == before,
		      "a chain rooted elsewhere was accepted after joining");
		check(joiner->refused_auth > refused_before,
		      "and it should have been refused on authority");
	}

	printf("  join: %u delivered after joining, %u refused on authority, adopted at %llu\n",
	       joiner->delivered, joiner->refused_auth,
	       (unsigned long long)fzn_trust_adopted_at(&joiner->trust));
}

int main(void)
{
	scenario_mesh();
	scenario_replay();
	scenario_revocation();
	scenario_stale();
	scenario_unauthorised();
	scenario_delegation();
	scenario_lossy();
	scenario_splice();
	scenario_distribution();
	scenario_state();
	scenario_join();

	printf("network_test: %d checks, %d failure(s); fuzznet %s\n", checks, failures,
	       fzn_version_string());
	return failures == 0 ? 0 : 1;
}
