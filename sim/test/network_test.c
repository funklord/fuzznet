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

	/* STEP 4: is this sender allowed to say this? */
	authorised = fzn_chain_verify(sender->chain, sender->chain_len, net->root,
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

	printf("network_test: %d checks, %d failure(s); fuzznet %s\n", checks, failures,
	       fzn_version_string());
	return failures == 0 ? 0 : 1;
}
