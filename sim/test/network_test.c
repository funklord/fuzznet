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
#include "../../tree/tree.h"
#include "../../record/record.h"
#include "../../record/sync.h"
#include "../../state/state.h"
#include "../../trust/trust.h"
#include "../../frame/freshness.h"
#include "../../session/aead.h"
#include "../../session/commitment.h"
#include "../../session/agree.h"
#include "../../session/session.h"
#include "../../prekey/prekey.h"
#include "../../persist/persist.h"
#include "../../ratchet/ratchet.h"
#include "../../chain/authz.h"
#include "../../session/random.h"
#include "../../version/version.h"
#include "../../wire/seal.h"

#include <stdio.h>
#include <string.h>

/* How long a half-finished message may hold a slot. Generous, because what
 * these cases test is the bound EXISTING -- a zero expiry no longer means
 * for ever -- rather than any particular value of it. */
#define REASM_MAX_HOLD 1000000u

#define SIM_HOSTS      16u
#define SIM_QUEUE      2048u
#define SIM_SLOTS      6u
#define SIM_SLOT_CAP   8192u
#define SIM_WINDOW     64u
/* The replay horizon each simulated host is sized for. The widest expiry any
 * scenario below states is `now + 500`, so 1000 leaves every one of them
 * exactly where it was -- nothing here is refused FZN_FRESH_ERR_HORIZON, and
 * the horizon's own rules are `frame/test/freshness_test.c`'s subject. */
#define SIM_MAX_AHEAD  1000u
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
		fprintf(stderr, "  FAIL: %s\n", what);
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

/* A signature over exactly the bytes of a signed region, BY A NAMED
 * IDENTITY, which is what a real one is. The region EXCLUDES the signature
 * field -- an earlier version of this signed a struct that contained its own
 * signature, which is circular and only worked because nothing depended on
 * the exclusion.
 *
 * `signer` is folded in first and in full, so a signature is a function of
 * who made it as well as of what it covers, and two identities agreeing on
 * every byte but the last produce different signatures over the same
 * message. That is what gives a key comparison anywhere below it a length
 * that can be wrong.
 *
 * Forging means producing a matching signature, which no scenario below does
 * by guessing. The one that forges a grant calls the signer honestly and
 * lies about the capability instead: a well-formed lie rather than a corrupt
 * frame, which is the harder case to refuse. */
static void sim_sign_bytes(const uint8_t signer[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                           uint8_t sig[FZN_SIG_LEN])
{
	uint32_t acc = 0xabcdefu;

	for (size_t i = 0; i < FZN_PUBKEY_LEN; i++)
		acc = mix(acc ^ signer[i]);
	for (size_t i = 0; i < len; i++)
		acc = mix(acc ^ msg[i]);
	for (size_t i = 0; i < FZN_SIG_LEN; i++)
		sig[i] = (uint8_t)(mix(acc + (uint32_t)i) >> 11);
}

/* THE TWO SIGNERS THIS FILE USED TO CARRY ARE GONE, and what they were is
 * worth recording because it is the defect in miniature.
 *
 * `sim_sign_hop` did `memcpy(region, &bare, sizeof(bare))` -- it signed the
 * STRUCT, padding included. That binds within one process and one ABI and
 * cannot cross a host boundary, and it was the only thing in the tree
 * producing any agreement at all between a hop's fields and its signed bytes.
 * It existed because the library had no encoder; there is one now, so the
 * simulation mints through `fzn_chain_mint` and `fzn_revocation_issue` like
 * any consumer, and the bytes it signs are the bytes the wire carries. */

/* The signing half of the vtable. Supplying only `verify` is what the first
 * version of this did, and `fzn_chain_delegate` answered "malformed argument"
 * -- correctly, since minting a hop requires a signer.
 *
 * `ctx` IS THE SIGNING IDENTITY, and it is the only way it could be. The
 * vtable's sign op takes no key by design -- "Nothing here takes a secret
 * key", `chain.h` -- so a stub that binds a signature to an identity has to
 * be told who is holding the pen some other way. `sim_signer` below fills it.
 *
 * REFUSING WHEN NOBODY IS NAMED is the half that keeps the binding honest.
 * `net->sign` carries a NULL `ctx` and is what verify-only callers pass; a
 * signing site that reaches for it has forgotten to say who signs, and
 * signing as the all-zero identity would produce a hop that verifies under
 * nobody while looking exactly like a minting failure nobody checked. It
 * fails loudly instead: every caller here tests the result. */
static int sim_sign_op(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	const uint8_t *signer = (const uint8_t *)ctx;

	if (!signer)
		return 0;
	sim_sign_bytes(signer, msg, msg_len, sig);
	return 1;
}

/* A KEY-BOUND VERIFIER: the answer is a function of `pubkey` as well as of
 * the message, so a signature made by one identity verifies under that
 * identity and under no other. It agrees with `sim_sign_op` above exactly
 * when the key that signed is the key being verified against.
 *
 * IT USED TO DISCARD `pubkey`, and what that cost was measured rather than
 * argued. With the answer a function of the MESSAGE ALONE, every key
 * "signed" identically and every key verified everything. Changing
 * `chain/chain.c` so that every hop's signature is checked against
 * `fzn_hop_grantor(hops[0])` -- the root -- instead of against its own
 * grantor is textbook key confusion, and it gave:
 *
 *     chain_test    271 checks, 39 failure(s)
 *     network_test  186 checks,  0 failure(s)
 *
 * `chain/test/chain_test.c`'s stub records which keys it was handed, which is
 * why it noticed; this one could notice nothing about keys at all. So no
 * scenario in this file could catch verification against the wrong key, and
 * where a scenario appeared to establish that a host cannot act on another's
 * grant -- `scenario_substitution`, `scenario_delegation`, `scenario_join` --
 * the refusal came from STRUCTURAL linkage (a grantee field compared against
 * a sender field, a grantor field compared against a pinned root) and not
 * from a signature. Every cryptographic claim the harness made was really a
 * structural one, including the one at the top of this file saying the
 * signature depends on who signed what.
 *
 * THE MEASUREMENT IS KEPT BECAUSE IT IS THE REASON. A fix whose motivation
 * has been deleted gets reverted by somebody who cannot see why it exists,
 * and the shape of this one invites that: folding a key into a digest looks
 * like decoration until the second number is beside the first.
 *
 * WHAT IT TOOK, since the asymmetry is the interesting part. Verification
 * needed no plumbing -- `verify` is handed the very key it must check
 * against. Only SIGNING needed a context, because the sign op takes no key,
 * so each signing site names its signer through `sim_signer`.
 *
 * The mutation above now fails `scenario_delegation` by name, at 195 checks
 * and 3 failures -- the assertion that says a hop's signature is checked
 * against that hop's grantor, plus the two delivery counts downstream of it.
 * The structural
 * comparisons are still worth what they were and the near-miss legs below
 * still matter: nothing here replaces them, and what changed is that they
 * are no longer carrying the whole weight of the harness's crypto. */
static int sim_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                      size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	sim_sign_bytes(pubkey, msg, msg_len, want);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

/* A per-signer copy of a signing vtable, naming the identity that signs.
 *
 * The base vtable is copied rather than rebuilt, so a signing op added to
 * `fzn_sign_ops_t` reaches every signer here without a second edit; only
 * `ctx` differs, and it points at this signer's own copy of the key so that
 * the caller's key may be a const array or a temporary.
 *
 * A CALLER'S `struct sim_signer` MUST OUTLIVE THE CALL IT IS PASSED TO.
 * Every use below is a local in the block that makes the call, which is the
 * shape that cannot get this wrong. */
struct sim_signer {
	uint8_t key[FZN_PUBKEY_LEN];
	fzn_sign_ops_t ops;
};

static const fzn_sign_ops_t *sim_signer(struct sim_signer *who, const fzn_sign_ops_t *base,
                                        const uint8_t key[FZN_PUBKEY_LEN])
{
	memcpy(who->key, key, FZN_PUBKEY_LEN);
	who->ops = *base;
	who->ops.ctx = who->key;
	return &who->ops;
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
	/* The encoded hops, and views onto them. A hop is a view now, so the
	 * bytes must outlive it -- which is the property bought: a field
	 * cannot disagree with the signature because there is one of them. */
	uint8_t hop_bytes[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	fzn_chain_hop_t chain[FZN_CHAIN_MAX_HOPS];
	size_t chain_len;
	int authorised; /* 0 means the host has no valid grant */

	/* WHAT THIS HOST KNOWS HAS BEEN REVOKED, and it is per host for the
	 * same reason the anchor is: a revocation is something a host either
	 * has been told or has not, and no host holds the network's view of
	 * them.
	 *
	 * It used to live on `struct sim_net`, one store shared by every
	 * simulated host, and that made a whole class of case unreachable.
	 * With one store there is no such thing as two hosts disagreeing
	 * about what is revoked, so `scenario_revocation` proved the cascade
	 * and could say nothing about propagation -- while sec 14 names the
	 * propagation half as the serious open gap. A harness that cannot
	 * exhibit a defect the project knows it has is a check that cannot
	 * fail. `scenario_revocation_split` is the case this field exists to
	 * make expressible. */
	fzn_revocation_store_t revocations;
	fzn_revocation_t revocation_entries[SIM_REVOCATION];

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

	/* RECORDS THIS HOST REFUSED BECAUSE THE ISSUER DID NOT SIGN THEM.
	 *
	 * Same shape as `refused_auth` and `refused_shape` above, and for the
	 * same reason: every scenario here that moves records runs on a lossy
	 * network, so a record that is merely not admitted is indistinguishable
	 * from one the network ate. The count is what tells the two apart.
	 * Incremented in `sim_receive_record` and asserted once per scenario --
	 * never inside a fetch loop, per `total_digest_dropped`. */
	unsigned refused_record;
	uint32_t held[SIM_HOSTS][2];
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
	fzn_cap_id_t capability;

	fzn_aead_ops_t aead;
	fzn_hash_ops_t hash;
	fzn_sign_ops_t sign;
	fzn_random_ops_t rng;

	uint64_t now;
	uint32_t seed;
	unsigned loss_pct, dup_pct, reorder_pct;
	unsigned dropped, duplicated, reordered;

	/* Forces every send to use this message identifier instead of deriving
	 * one. Zero means derive, which is every scenario but the splice.
	 *
	 * It exists because the derivation folds the SENDER in -- see
	 * `sim_send` -- so two hosts cannot collide by accident, and scenario 8
	 * is about what happens when they do collide. Without a way to force
	 * it, that scenario sent two messages whose identifiers differed by
	 * construction and proved nothing. */
	uint32_t forced_msg_id;
};

/* Digest positions that did not fit a harness buffer, summed over the whole
 * run and asserted ONCE, in main. File scope because each scenario owns its
 * own `sim_net`.
 *
 * It was a `check()` at each of the three fetch helpers, which sounds
 * harmless and was not: those helpers run in loops, so one assertion became
 * 630 of them and this file's headline count went from 86 to 716. Nearly
 * nine tenths of the number being quoted as coverage was one line about the
 * HARNESS's own buffers, saying nothing about the library at all. A check
 * count that grows with the number of rounds is not a measure of what is
 * checked, and it was mine -- added earlier today. */
static unsigned total_digest_dropped;

/* Grants the harness could not mint or open while setting a scenario up,
 * summed over the whole run and asserted once. Same reason as the counter
 * above: a per-host `check()` inflates the count without measuring more.
 *
 * `sim_make_record` FEEDS THIS TOO, since 2026-08-27. It carried two
 * `check()` calls and runs thirty times a run, so SIXTY of this file's
 * checks were the harness asserting it could sign and open its own
 * records -- more than a quarter of the total, measuring nothing about
 * the library. That is the third time this pattern has been undone here
 * and the first two are the counters above; a helper that checks is a
 * helper whose call count becomes a test count. */
static unsigned setup_faults;

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
/* WHAT A PAIR SHARES IS A KEY AND A COMMITMENT KEY, not a commitment.
 *
 * This used to hand back a finished commitment, and that was the design being
 * modelled: `f(transcript)` is a constant per pair, so the same 16 bytes rode
 * in the clear on every datagram beside `sender[32]` and any observer read the
 * two together to get the endpoints of a conversation.
 *
 * The commitment is now derived per frame from the nonce, inside
 * `fzn_seal_build` and `fzn_seal_open`, so the harness cannot precompute one
 * -- which is the point. Until this changed, the tree's only end-to-end
 * witness of the receive order was modelling the design the library had
 * removed. */
static void sim_session_key(uint8_t from, uint8_t to, uint8_t key[FZN_AEAD_KEY_LEN],
                            uint8_t commitment_key[FZN_COMMITMENT_KEY_LEN])
{
	uint32_t acc = mix(0x5eed0000u ^ ((uint32_t)from << 8) ^ to);

	for (size_t i = 0; i < FZN_AEAD_KEY_LEN; i++)
		key[i] = (uint8_t)(mix(acc + (uint32_t)i) >> 7);
	for (size_t i = 0; i < FZN_COMMITMENT_KEY_LEN; i++)
		commitment_key[i] = (uint8_t)(mix(acc + 0x1000u + (uint32_t)i) >> 5);
}

/* The hash seam, as a stub. Real BLAKE2b is `session/hash_monocypher.c` and is
 * exercised there; what the simulation needs is a function of its whole input,
 * so that a commitment derived from one nonce differs from one derived from
 * another. A constant here would make every frame's commitment equal and hide
 * exactly the property the split exists for. */
static int sim_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint32_t acc = 0x9e3779b9u;
	size_t i;

	(void)ctx;
	if (!out || out_len == 0 || !in)
		return 0;
	for (i = 0; i < in_len; i++)
		acc = mix(acc ^ in[i]);
	for (i = 0; i < out_len; i++)
		out[i] = (uint8_t)(mix(acc + (uint32_t)i) >> 9);
	return 1;
}

/* The key-agreement seam, as a stub, and COMMUTATIVE -- which is the only
 * property `scenario_session` asks of it. Real X25519 is
 * `session/agree_monocypher.c` and is exercised there against the published
 * low-order points; what the simulation needs is that two hosts reach the
 * same secret from opposite halves, so that a disagreement below is the
 * session layer's and not the arithmetic's. */
static int sim_agree_public(void *ctx, uint8_t out[FZN_AGREE_PUBLIC_LEN],
                            const uint8_t secret[FZN_AGREE_SECRET_LEN])
{
	size_t i;

	(void)ctx;
	for (i = 0; i < FZN_AGREE_PUBLIC_LEN; i++)
		out[i] = (uint8_t)(secret[i] ^ 0x3cu);
	return 1;
}

static int sim_agree_shared(void *ctx, uint8_t out[FZN_AGREE_SHARED_LEN],
                            const uint8_t secret[FZN_AGREE_SECRET_LEN],
                            const uint8_t peer[FZN_AGREE_PUBLIC_LEN])
{
	size_t i;

	(void)ctx;
	for (i = 0; i < FZN_AGREE_SHARED_LEN; i++)
		out[i] = (uint8_t)(secret[i] ^ (peer[i] ^ 0x3cu));
	return 1;
}

/* An identity, spread across the WHOLE key.
 *
 * It used to be `out[0] = id; out[1] = id ^ 0x5a;` with the other thirty
 * bytes left zero, so any two identities in the simulation differed at byte 0
 * and a comparison of ONE byte separated them exactly as well as a comparison
 * of thirty-two. That made every key comparison this harness reaches
 * unfalsifiable from here. Measured, before this was changed: truncating
 * `chunk/reassembly.c`'s `memcmp(slot->sender, sender, FZN_SENDER_LEN)` to
 * `1u` left this file at 172 checks and 0 failures, with `scenario_splice`
 * still printing `2 delivered, 0 spliced`, while
 * `chunk/test/reassembly_test` failed three times. Truncating
 * `chain/chain.c`'s root pin the same way was the same story against
 * `chain/test/chain_test`. The gap was specifically at the integration
 * level: the modules' own suites caught both.
 *
 * WHY THAT IS NOT TIDINESS. Real public keys are effectively random, so two
 * senders share a first byte one time in 256 -- a truncated sender
 * comparison would splice in deployment, and sec 5a cites `scenario_splice`
 * as what establishes "two senders, one message id; no cross-sender splice".
 * The harness making the claim could not see the defect the claim is about.
 *
 * Spreading the bytes is necessary and not sufficient: two ids still differ
 * at byte 0. What decides a LENGTH is a near miss, which is
 * `sim_near_identity` below.
 *
 * Byte 0 stays the id. Nothing in this file reads it -- hosts are addressed
 * by `struct sim_host::id` and datagrams by index, never by a key byte --
 * but it costs nothing and a key that names its host is easier to read in a
 * dump. */
static void sim_identity(uint8_t id, uint8_t out[FZN_PUBKEY_LEN])
{
	out[0] = id;
	for (size_t i = 1; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(id ^ i);
}

/* A SECOND IDENTITY AGREEING WITH `base` ON EVERY BYTE BUT THE LAST.
 *
 * This is the pair that gives a key comparison a length to get wrong: only a
 * full-length comparison separates the two, so a scenario built on one fails
 * when the comparison is truncated and passes when it is not. Same shape as
 * `twin_senders` in `chunk/test/reassembly_test.c` and the twin cases in
 * `log/test/log_test.c` and `state/test/state_test.c`; this is that shape
 * brought to the integration harness, where the comparisons run against a
 * whole receive path rather than against one function.
 *
 * A case using it asserts the property of the pair FIRST -- that they agree
 * on the first thirty-one bytes and differ somewhere -- so that a fixture
 * which quietly stopped producing a near miss fails by name instead of
 * turning the case green for the wrong reason. */
static void sim_near_identity(const uint8_t base[FZN_PUBKEY_LEN], uint8_t out[FZN_PUBKEY_LEN])
{
	memcpy(out, base, FZN_PUBKEY_LEN);
	out[FZN_PUBKEY_LEN - 1u] ^= 0x01u;
}

/* Re-mint a host's grant, for a scenario that has changed the host's key or
 * the root it answers to.
 *
 * A chain names its grantee, and `sim_receive` compares that grantee against
 * the sender the frame carries -- so a scenario that rewrites `h->pubkey`
 * without re-minting is not testing a near miss, it is testing the
 * substitution check, which `scenario_substitution` already owns. This is
 * `sim_init`'s minting, lifted out so both callers do it the same way, and
 * it accumulates into `setup_faults` for the same reason `sim_init` does. */
static void sim_regrant(struct sim_net *net, struct sim_host *h,
                        const uint8_t root[FZN_PUBKEY_LEN])
{
	struct sim_signer signer;

	/* SIGNED BY THE ROOT THIS GRANT NAMES, which is the whole of what
	 * `sim_signer` buys: a caller re-grafting a host onto a near-miss root
	 * gets a hop signed by that root, so the grant checks out under it and
	 * under nothing else. Passing `&net->sign` here would refuse to sign. */
	if (fzn_chain_mint(root, h->pubkey, &net->capability, 1, FZN_NO_EXPIRY, 1,
	                   sim_signer(&signer, &net->sign, root),
	                   h->hop_bytes[0]) != FZN_CHAIN_OK)
		setup_faults++;
	if (fzn_hop_open(h->hop_bytes[0], FZN_HOP_LEN, &h->chain[0]) != FZN_CHAIN_OK)
		setup_faults++;
	h->chain_len = 1;
}

static void sim_init(struct sim_net *net, size_t hosts, uint32_t seed)
{
	memset(net, 0, sizeof(*net));
	net->host_count = hosts;
	net->seed = seed;
	net->now = 1000;

	sim_identity(0xff, net->root);
	memset(net->capability.b, 0xc0, sizeof(net->capability));

	net->aead.seal = sim_seal;
	net->aead.open = sim_open;
	net->aead.ctx = NULL;
	net->hash.hash = sim_hash;
	net->hash.ctx = NULL;
	net->sign.verify = sim_verify;
	net->sign.sign = sim_sign_op;
	net->sign.ctx = NULL;
	rng_ctx.counter = seed;
	net->rng.fill = sim_fill;
	net->rng.ctx = &rng_ctx;

	for (size_t i = 0; i < hosts; i++) {
		struct sim_host *h = &net->hosts[i];

		h->id = (uint8_t)i;
		sim_identity(h->id, h->pubkey);

		memset(h->chain, 0, sizeof(h->chain));
		/* ACCUMULATED, NOT CHECKED HERE. `sim_init` runs once per
		 * scenario and mints for every host, so a `check()` in this
		 * loop is a few hundred of them -- and a check count that grows
		 * with the number of hosts measures the harness rather than the
		 * library. Asserted once, in main. */
		sim_regrant(net, h, net->root);
		h->authorised = 1;

		/* An established host has its root configured out of band. A
		 * joining one does not, and scenario 11 is about that. */
		fzn_trust_init(&h->trust);
		fzn_trust_pin(&h->trust, net->root);

		/* AND ITS OWN REVOCATION STORE, empty. Nothing is revoked
		 * until a scenario says so, and it says so at a named host or
		 * at every one of them -- see `sim_revoke_all`. */
		fzn_revocation_store_init(&h->revocations, h->revocation_entries,
		                          SIM_REVOCATION);

		fzn_journal_init(&h->journal, h->jentries, SIM_HOSTS);
		fzn_state_init(&h->state, h->sentries, 8);

		for (size_t s = 0; s < SIM_SLOTS; s++)
			fzn_reasm_slot_init(&h->slots[s], h->bufs[s], SIM_SLOT_CAP);
		fzn_reasm_init(&h->reasm, h->slots, SIM_SLOTS, 3, REASM_MAX_HOLD);
		fzn_replay_init(&h->window, h->entries, SIM_WINDOW, SIM_MAX_AHEAD);
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
	uint8_t key[FZN_AEAD_KEY_LEN], commitment_key[FZN_COMMITMENT_KEY_LEN];
	fzn_split_t plan;
	uint32_t message_id;

	if (fzn_split_plan(len, FZN_SPLIT_MAX_PAYLOAD, &plan) != FZN_SPLIT_OK)
		return 0;

	sim_session_key(from, to, key, commitment_key);
	message_id = net->forced_msg_id
	                     ? net->forced_msg_id
	                     : mix(((uint32_t)from << 16) ^ ((uint32_t)to << 8) ^
	                           (uint32_t)h->sent);

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
		what.capability = net->capability.b;
		what.payload = msg + offset;
		what.payload_len = piece;
		what.expires_at = expires_at;
		what.msg = message_id;
		what.index = i;
		what.chunks = plan.chunks;
		what.kind = 0;

		if (fzn_seal_build(d->frame, sizeof(d->frame), &wrote, &what, key,
		                   commitment_key, &net->hash, &net->rng,
		                   &net->aead) != FZN_SEAL_OK) {
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
   say-so.

   THIS FILE WAS RIGHT AND THE DOCUMENT WAS WRONG, which is worth recording
   because the citation above used to be false. sec 4.7 put freshness at step
   2 and replay at step 3, both BEFORE the tag at step 5, so a stranger who
   could send datagrams wrote into the replay window -- and with no bound on
   `expires_at` that is a permanent denial of service for `capacity`
   datagrams, off-path, with no key.

   This harness opened the seal first anyway, and scenario 8c derives the
   reason in the right words. It cited sec 4.7 for an order sec 4.7 did not
   state, and nobody noticed in either direction: the document was not
   checked against the harness, and the harness's comment was not checked
   against the document.

   sec 4.7 has since been rewritten to what this file does, so the citation
   is now true. What changed is the document.  */

static void sim_receive(struct sim_net *net, struct sim_datagram *d)
{
	struct sim_host *h = &net->hosts[d->to];
	struct sim_host *sender = &net->hosts[d->from];
	uint8_t key[FZN_AEAD_KEY_LEN], commitment_key[FZN_COMMITMENT_KEY_LEN];
	static uint8_t wire[SIM_FRAME_MAX];
	fzn_opened_t opened;
	fzn_partial_t *done = NULL;
	fzn_fresh_err_t fresh;
	fzn_chain_err_t authorised;
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

	sim_session_key(d->from, d->to, key, commitment_key);

	/* STEP 1: the frame is a frame, the commitment matches, the tag
	 * verifies. Everything after this is about an authenticated datagram. */
	if (fzn_seal_open(wire, d->len, key, commitment_key, &net->hash, &net->aead,
	                  &opened) != FZN_SEAL_OK) {
		h->refused_shape++;
		return;
	}

	/* STEPS 2 and 3: freshness then replay, in one call. */
	fresh = fzn_replay_admit(&h->window, opened.nonce, opened.expires_at, FZN_EXPIRY_REQUIRED,
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
	 * closed rather than verifying against nothing.
	 *
	 * AND AGAINST THIS RECEIVER'S OWN REVOCATIONS, for exactly the same
	 * reason, which is a reason this line did not use to carry: it passed
	 * a store the simulation held globally, so every host on the network
	 * revoked in the same instant and no scenario could describe one that
	 * had not heard yet. See `struct sim_host`. */
	anchor = fzn_trust_root(&h->trust);
	if (!anchor) {
		h->refused_auth++;
		return;
	}
	authorised = fzn_chain_verify(sender->chain, sender->chain_len, anchor,
	                              &net->capability, net->now,
	                              &net->sign, &h->revocations, &proven);

	/* AND THE DECISION LAYER MUST AGREE WITH THE VERIFIER, on every frame
	 * this network delivers, which is what puts `chain/authz.c` in a seam
	 * rather than only in its own suite.
	 *
	 * `fzn_authz_decide` is what a real receiver calls: it takes the
	 * policy for the kind, refuses to let a missing chain read as a kind
	 * that needs none, and collapses every refusal to one verdict. Here
	 * the policy is spelled -- this network guards everything with one
	 * capability -- so the decision must be GRANTED exactly when the
	 * verifier says OK, and DENIED otherwise. A disagreement is the
	 * decision layer having drifted from the thing it decides about.
	 *
	 * The zeroed policy beside it is the case no consumer writes on
	 * purpose and every consumer can produce by forgetting. It is checked
	 * on live traffic rather than in a unit test because that is where
	 * somebody would actually leave one. */
	{
		fzn_authz_verdict_t verdict =
		        fzn_authz_decide(fzn_authz_requires(&net->capability, FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, sender->chain,
		                         sender->chain_len, anchor, net->now, &net->sign,
		                         &h->revocations);
		fzn_authz_policy_t forgotten;

		check((authorised == FZN_CHAIN_OK)
		              == (verdict == FZN_AUTHZ_GRANTED_BY_CHAIN),
		      "the authorisation decision disagrees with the verifier it wraps");

		memset(&forgotten, 0, sizeof(forgotten));
		check(fzn_authz_decide(forgotten, FZN_ORIGIN_REMOTE, sender->chain, sender->chain_len, anchor,
		                       net->now, &net->sign, &h->revocations)
		              == FZN_AUTHZ_DENIED,
		      "a policy nobody spelled granted on live traffic, so absence reads "
		      "as not-required where it would actually happen");
	}

	if (authorised != FZN_CHAIN_OK) {
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

/* Tell EVERY host about a revocation, and report how many refused it.
 *
 * The store is per host, so a scenario that wants the whole network to agree
 * has to say so -- which is the honest shape, because agreeing is a state a
 * network reaches rather than one it starts in. This is what the old
 * net-wide store did implicitly, and it is used exactly where that store was
 * being filled.
 *
 * A COUNT RATHER THAN A `check()` PER HOST. Admission runs once per host, so
 * asserting inside the loop would make one property into `host_count` of
 * them and grow this file's headline count with the size of a mesh -- the
 * mistake `total_digest_dropped` and `setup_faults` above were both written
 * to undo. The caller asserts the count, once. */
/* Admit to every host, and REFUSE TO ADMIT UNDER A ROOT THE HOST HAS NOT
 * ANCHORED.
 *
 * The simulation holds one root and pins it into every host, so `net->root`
 * and `fzn_trust_root(&h->trust)` are the same key -- which is why this
 * helper could pass the simulation's copy and be right. It is right by
 * coincidence. `sim_receive` verifies against the host's OWN anchor,
 * deliberately, because that is what a host actually has; admitting against
 * a key the simulation happens to hold is the same shortcut this harness
 * already had to remove once, when the revocation store was global while the
 * anchor was per host.
 *
 * Now that a store entry keeps its issuer, the two coinciding is load-
 * bearing rather than cosmetic: a host whose anchor differed from the key
 * its revocations were admitted under would silently stop honouring them,
 * and every scenario here would still pass. So the helper asserts the
 * identity rather than assuming it, and admits under the host's own anchor.
 */
static unsigned sim_revoke_all(struct sim_net *net, fzn_revocation_record_t rec)
{
	unsigned refused = 0, unanchored = 0, mismatched = 0;

	for (size_t i = 0; i < net->host_count; i++) {
		const uint8_t *anchor = fzn_trust_root(&net->hosts[i].trust);

		if (!anchor) {
			unanchored++;
			continue;
		}
		if (memcmp(anchor, net->root, FZN_PUBKEY_LEN) != 0)
			mismatched++;
		if (fzn_revocation_admit(&net->hosts[i].revocations, fzn_revocation_offer_root(rec), anchor,
		                         &net->sign, &net->hash, NULL) != FZN_CHAIN_OK)
			refused++;
	}

	check(unanchored == 0, "a host had no anchor to admit a revocation under");
	check(mismatched == 0,
	      "a host's anchor differs from the simulation's root, so admitting under "
	      "the simulation's copy would have recorded an issuer the host cannot match");
	return refused;
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
	struct sim_signer root_signer;
	static uint8_t rec_region[FZN_REVOCATION_LEN];

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
	 * verifies that rather than trusting the caller -- and now signed WITH
	 * the root's key rather than merely naming it as issuer, so
	 * `fzn_revocation_admit` is checking a signature and not a field. */
	check(fzn_revocation_issue(net.root, &net.capability, net.hosts[2].pubkey, net.now,
	                           sim_signer(&root_signer, &net.sign, net.root),
	                           rec_region) == FZN_CHAIN_OK,
	      "the simulation could not issue a revocation");
	check(fzn_revocation_open(rec_region, FZN_REVOCATION_LEN, &rec) == FZN_CHAIN_OK,
	      "the simulation could not open the revocation it issued");
	check(sim_revoke_all(&net, rec) == 0, "the signed revocation was refused");

	sim_run(&net, 10);
	check(net.hosts[3].delivered == 0, "a revoked sender's message still completed");
	check(net.hosts[3].refused_auth > 0, "the revoked chunks were not refused on authority");

	/* THE POSITIVE CONTROL. Everything above asserts a refusal, and a
	 * refusal proves nothing on its own: a receiver that refused EVERY
	 * frame would satisfy all of it. Measured -- mutating the simulation's
	 * `fzn_chain_verify` result to refuse unconditionally left this
	 * scenario green.
	 *
	 * So run the identical send on an identical network with no revocation
	 * admitted, and require that it arrives. The two legs differ in exactly
	 * one thing, which is what makes the refusal above attributable to it.
	 *
	 * A separate net rather than a reset, so that neither leg can leave
	 * state the other reads. */
	{
		static struct sim_net control;
		static uint8_t control_msg[3000];

		sim_init(&control, 4, 0x2222u);
		fill_message(control_msg, sizeof(control_msg), 11);
		check(sim_send(&control, 2, 3, control_msg, sizeof(control_msg),
		               control.now + 100u),
		      "the control send was refused");
		sim_run(&control, 10);
		check(control.hosts[3].delivered > 0,
		      "the same message did not arrive without the revocation, so the "
		      "refusal above is not evidence that revocation caused it");
	}
	printf("  revocation: %u chunks refused on authority, %u delivered\n",
	       net.hosts[3].refused_auth, net.hosts[3].delivered);
}

/* ------------------------------------------------------------ scenario 3b

   ONE REVOCATION, KNOWN AT ONE HOST AND NOT THE OTHER.

   Two receivers, anchored to the same root, verifying the same sender's
   chain, sent the same message at the same moment. One of them has been told
   that the sender is revoked; the other has not. The first refuses. The
   second delivers.

   THE SECOND DELIVERING IS THE OPEN GAP NAMED IN project.md sec 14, NOT A
   FAULT IN THIS SCENARIO. That section states it in as many words: a
   revocation stops a chain only at a host that HAS it, and a host cannot
   tell "nothing was revoked" from "I am missing the revocations". A
   revocation is a standalone signed object riding no stream and carrying no
   sequence, so absence and up to date are the same observation -- and a host
   that joined this morning, has been offline, or is partitioned by an
   attacker goes on verifying a chain the rest of the network withdrew last
   week. Being a relay on the path is enough to hold it there.

   WHEN PROPAGATION IS BUILT, THE ASSERTION ABOUT THE UNTOLD HOST IS THE ONE
   THAT MUST CHANGE. It records the gap rather than endorsing it: a network
   that carries revocations on contact makes that host refuse too, and this
   scenario must then demand the refusal instead. It is written as an
   assertion and not as a comment precisely so that closing the gap breaks
   the suite -- a note in a comment is a note nobody is made to read.

   THIS COULD NOT BE WRITTEN UNTIL THE STORE WENT PER HOST. With one store
   shared by the whole simulation, two hosts disagreeing about what is
   revoked was not a state the harness had, so `scenario_revocation` above
   proved the cascade and was quoted for revocation entire. A check that
   cannot fail is worse than no check, because it is cited afterwards as
   though it had discriminated.

   THE TWO LEGS ARE EACH OTHER'S CONTROL, which is why this scenario needs
   no second net the way scenarios 3 to 5 do: same sender, same chain, same
   root, same bytes, same clock, one revocation. The only thing that differs
   between them is which receiver was told about it.  */

static void scenario_revocation_split(void)
{
	static struct sim_net net;
	static uint8_t msg[256];
	static uint8_t rec_region[FZN_REVOCATION_LEN];
	fzn_revocation_record_t rec;
	struct sim_host *sender, *told, *untold;
	struct sim_signer root_signer;

	sim_init(&net, 4, 0x2323u);
	fill_message(msg, sizeof(msg), 31);
	sender = &net.hosts[2];
	told = &net.hosts[0];
	untold = &net.hosts[1];

	/* THE SAME ROOT AT BOTH RECEIVERS, asserted rather than assumed. If
	 * the two anchors differed, the refusal below would be the anchor's
	 * doing and this would be scenario 11 wearing a revocation's name. */
	check(fzn_trust_root(&told->trust) && fzn_trust_root(&untold->trust) &&
	              memcmp(fzn_trust_root(&told->trust), fzn_trust_root(&untold->trust),
	                     FZN_PUBKEY_LEN) == 0,
	      "the two receivers should be anchored to the same root");
	/* AND THE SAME CHAIN, which needs no copying: `sim_receive` reads the
	 * chain out of the SENDING host, so both receivers are handed the one
	 * chain that exists. */
	check(sender->chain_len == 1, "the sender should hold a one-hop root grant");

	/* Signed by the root, as scenario 3's is and for the same reason. */
	check(fzn_revocation_issue(net.root, &net.capability, sender->pubkey, net.now,
	                           sim_signer(&root_signer, &net.sign, net.root),
	                           rec_region) == FZN_CHAIN_OK,
	      "the simulation could not issue a revocation");
	check(fzn_revocation_open(rec_region, FZN_REVOCATION_LEN, &rec) == FZN_CHAIN_OK,
	      "the simulation could not open the revocation it issued");

	/* ONE HOST HEARS IT. The other is the host that joined this morning,
	 * or was offline, or sits behind somebody who declines to relay. */
	check(fzn_revocation_admit(&told->revocations, fzn_revocation_offer_root(rec), net.root, &net.sign,
	                           &net.hash, NULL) == FZN_CHAIN_OK,
	      "the signed revocation was refused by the host that was told");
	check(untold->revocations.used == 0, "the host that was not told holds a revocation");

	check(sim_send(&net, sender->id, told->id, msg, sizeof(msg), net.now + 100u),
	      "the send to the host that was told was refused");
	check(sim_send(&net, sender->id, untold->id, msg, sizeof(msg), net.now + 100u),
	      "the send to the host that was not told was refused");
	sim_run(&net, 4);

	/* THE HALF THAT WORKS: a host holding the revocation refuses. */
	check(told->delivered == 0, "a revoked sender was delivered at a host that had been told");
	check(told->refused_auth > 0, "and it should have been refused on authority");

	/* THE HALF THAT DOES NOT, AND IS WHY THIS SCENARIO EXISTS. Both lines
	 * assert the gap. Read the header before changing either. */
	check(untold->delivered == 1,
	      "a host that was never told refused a revoked chain, so either sec 14's "
	      "gap has closed and this scenario must now demand that refusal, or the "
	      "message failed to arrive for some reason unrelated to revocation");
	check(untold->refused_auth == 0,
	      "the untold host refused on authority for some other reason, so its "
	      "delivery is not evidence about revocation propagation");
	check(untold->refused_shape == 0,
	      "the frames themselves were well formed; only the revocation differs");

	printf("  revocation split: told refused %u on authority and took %u, "
	       "untold took %u with %zu revocations\n",
	       told->refused_auth, told->delivered, untold->delivered,
	       untold->revocations.used);
}

/* ------------------------------------------------------------ scenario 3c

   A WITHDRAWAL, AND THE HALF OF IT THAT REACHES NOBODY.

   Two receivers, anchored to the same root, holding the same revocation of
   the same sender. One of them is then handed the withdrawal that undoes it;
   the other is not. The first delivers again. The second still refuses.

   THE SECOND STILL REFUSING IS THE OPEN GAP NAMED IN project.md sec 56 AND
   IN chain/revocation.h, NOT A FAULT HERE. A withdrawal has no distribution
   path in this library. `fzn_manifest_issue` omits withdrawn pairs --
   correctly, since a manifest states what IS revoked and publishing a
   restored pair would tell every receiver to revoke it again under the
   withdrawing issuer's own signature -- and the deficit machinery is the
   wrong shape rather than missing a case: it computes what THIS host lacks
   from a peer's manifest, and a withdrawal is something this host HAS that
   the peer lacks.

   SO A HOST THAT WITHDRAWS CONVERGES NOBODY. The record is well formed and
   admission is idempotent, so a consumer can carry it by whatever path it
   already uses for records; what the library gives no host is any way to
   LEARN that it should ask.

   WHEN PROPAGATION IS BUILT, THE ASSERTION ABOUT THE UNTOLD HOST IS THE ONE
   THAT MUST CHANGE, exactly as in scenario 3b. It is written as an assertion
   rather than a comment so that closing the gap breaks this suite: a note in
   a comment is a note nobody is made to read.

   THE THIRD LEG IS WHAT SEPARATES A MISSING MECHANISM FROM A BROKEN ONE.
   After the untold host is handed the same record directly, it delivers too.
   Without that leg, "the untold host refuses" would be satisfied by a
   withdrawal that did not work at all, and the scenario would be evidence
   for the wrong thing.  */
static void scenario_withdrawal(void)
{
	static struct sim_net net;
	static uint8_t msg[256];
	static uint8_t rec_region[FZN_REVOCATION_LEN];
	static uint8_t wd_region[FZN_REVOCATION_LEN];
	uint8_t id[FZN_REVOCATION_ID_LEN];
	fzn_revocation_record_t rec, wd;
	struct sim_host *sender, *told, *untold;
	struct sim_signer root_signer;

	sim_init(&net, 4, 0x2424u);
	fill_message(msg, sizeof(msg), 37);
	sender = &net.hosts[2];
	told = &net.hosts[0];
	untold = &net.hosts[1];

	check(fzn_trust_root(&told->trust) && fzn_trust_root(&untold->trust) &&
	              memcmp(fzn_trust_root(&told->trust), fzn_trust_root(&untold->trust),
	                     FZN_PUBKEY_LEN) == 0,
	      "the two receivers should be anchored to the same root");

	/* The root revokes the sender, and BOTH receivers hear it. That is the
	 * difference from scenario 3b: there the split is in the revocation,
	 * here it is in the withdrawal. */
	check(fzn_revocation_issue(net.root, &net.capability, sender->pubkey, net.now,
	                           sim_signer(&root_signer, &net.sign, net.root),
	                           rec_region) == FZN_CHAIN_OK,
	      "the simulation could not issue a revocation");
	check(fzn_revocation_open(rec_region, FZN_REVOCATION_LEN, &rec) == FZN_CHAIN_OK,
	      "the simulation could not open the revocation it issued");
	check(sim_revoke_all(&net, rec) == 0, "the signed revocation was refused");
	check(fzn_revocation_covers(&told->revocations, net.root, &net.capability,
	                            sender->pubkey) == 1 &&
	              fzn_revocation_covers(&untold->revocations, net.root, &net.capability,
	                                    sender->pubkey) == 1,
	      "both receivers should hold the sender revoked before the withdrawal");

	/* The root changes its mind. The withdrawal names the revocation by
	 * hash -- over the whole record, which is what travelled. */
	check(sim_hash(NULL, id, sizeof(id), rec_region, FZN_REVOCATION_LEN),
	      "the simulation could not hash the revocation");
	check(fzn_revocation_issue_withdrawal(net.root, &net.capability, sender->pubkey,
	                                      net.now + 1u, id,
	                                      sim_signer(&root_signer, &net.sign, net.root),
	                                      wd_region) == FZN_CHAIN_OK,
	      "the simulation could not issue a withdrawal");
	check(fzn_revocation_open(wd_region, FZN_REVOCATION_LEN, &wd) == FZN_CHAIN_OK,
	      "the simulation could not open the withdrawal it issued");
	check(fzn_revocation_is_withdrawal(wd), "it is not a withdrawal");

	/* ONE HOST IS HANDED IT. Nothing in the library would have carried it
	 * there; a consumer did. */
	check(fzn_revocation_admit(&told->revocations, fzn_revocation_offer_root(wd),
	                           net.root, &net.sign, &net.hash, NULL) == FZN_CHAIN_OK,
	      "the withdrawal was refused by the host that was told");
	check(told->revocations.used == 1,
	      "the withdrawal appended rather than replacing, so the entry that "
	      "recognises a stale copy is not the one being read");

	check(sim_send(&net, sender->id, told->id, msg, sizeof(msg), net.now + 100u),
	      "the send to the host that was told was refused");
	check(sim_send(&net, sender->id, untold->id, msg, sizeof(msg), net.now + 100u),
	      "the send to the host that was not told was refused");
	sim_run(&net, 4);

	/* THE HALF THAT WORKS: the host holding the withdrawal delivers again,
	 * which is the outage ending. */
	check(told->delivered == 1,
	      "a host holding the withdrawal still refused the restored sender, so a "
	      "withdrawn capability does not come back");
	check(told->refused_auth == 0,
	      "and it refused something on authority, so the delivery above is not "
	      "evidence that the withdrawal took effect");

	/* THE HALF THAT DOES NOT. Read sec 56 before changing either line. */
	check(untold->delivered == 0,
	      "a host that was never handed the withdrawal delivered anyway, so either "
	      "propagation has been built and this scenario must now demand that "
	      "delivery, or its store stopped honouring a revocation it holds");
	check(untold->refused_auth > 0,
	      "the untold host refused for some reason other than authority, so its "
	      "refusal is not evidence about withdrawal propagation");

	/* THE THIRD LEG. The same record, handed over directly, converges it --
	 * so what is missing is discovery and not the mechanism. */
	check(fzn_revocation_admit(&untold->revocations, fzn_revocation_offer_root(wd),
	                           net.root, &net.sign, &net.hash, NULL) == FZN_CHAIN_OK,
	      "the same withdrawal was refused by the second host");
	check(fzn_revocation_covers(&untold->revocations, net.root, &net.capability,
	                            sender->pubkey) == 0,
	      "the second host still holds the sender revoked after admitting the "
	      "withdrawal, so the record does not work rather than merely not "
	      "travelling");

	check(sim_send(&net, sender->id, untold->id, msg, sizeof(msg), net.now + 100u),
	      "the second send to the untold host was refused");
	sim_run(&net, 4);
	check(untold->delivered == 1,
	      "the second host did not deliver after being handed the withdrawal, so "
	      "the gap is in the mechanism and not only in its distribution");

	printf("  withdrawal: told took %u and refused %u; untold refused %u until "
	       "handed the record, then took %u\n",
	       told->delivered, told->refused_auth, untold->refused_auth,
	       untold->delivered);
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

	/* THE POSITIVE CONTROL, for the reason given in scenario 3: the three
	 * checks above are all satisfied by a receiver that refuses
	 * everything, and `refused_auth == 0` is satisfied MOST easily by a
	 * frame that never got that far for some quite different reason.
	 *
	 * The control differs in one thing -- an expiry beyond the delivery
	 * time rather than before it. */
	{
		static struct sim_net control;
		static uint8_t control_msg[256];

		sim_init(&control, 4, 0x3333u);
		fill_message(control_msg, sizeof(control_msg), 13);
		check(sim_send(&control, 0, 1, control_msg, sizeof(control_msg),
		               control.now + 100u),
		      "the control send was refused");
		for (size_t i = 0; i < control.queue_len; i++)
			control.queue[i].due = control.now + 5u;
		sim_run(&control, 8);
		check(control.hosts[1].delivered > 0,
		      "an unexpired frame did not arrive either, so staleness is not "
		      "what the refusal above measured");
	}
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
	{
		fzn_cap_id_t forged_cap;
		struct sim_signer root_signer;

		memset(forged_cap.b, 0xee, sizeof(forged_cap));
		check(fzn_chain_mint(net.root, net.hosts[0].pubkey, &forged_cap, 1, FZN_NO_EXPIRY,
		                     1, sim_signer(&root_signer, &net.sign, net.root),
		                     net.hosts[0].hop_bytes[0]) == FZN_CHAIN_OK,
		      "the forged grant could not be minted");
		check(fzn_hop_open(net.hosts[0].hop_bytes[0], FZN_HOP_LEN,
		                   &net.hosts[0].chain[0]) == FZN_CHAIN_OK,
		      "the forged grant could not be opened");
	}

	check(sim_send(&net, 0, 1, msg, sizeof(msg), net.now + 100u), "the send was refused");
	sim_run(&net, 3);

	check(net.hosts[1].delivered == 0, "a host without the capability was delivered");
	check(net.hosts[1].refused_auth > 0, "the forged grant was not refused");
	check(net.hosts[1].refused_shape == 0, "the frame itself should have been well formed");

	/* THE POSITIVE CONTROL, and this scenario needs it most: it asserts
	 * only refusals, so a receiver that refused every frame for any reason
	 * at all would pass it completely. The control forges nothing. */
	{
		static struct sim_net control;
		static uint8_t control_msg[256];

		sim_init(&control, 4, 0x4444u);
		fill_message(control_msg, sizeof(control_msg), 17);
		check(sim_send(&control, 0, 1, control_msg, sizeof(control_msg),
		               control.now + 100u),
		      "the control send was refused");
		sim_run(&control, 3);
		check(control.hosts[1].delivered > 0,
		      "an unforged grant was not delivered either, so the forgery is not "
		      "what the refusal above measured");
		check(control.hosts[1].refused_auth == 0,
		      "an unforged grant was refused on authority");
	}
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
	struct sim_signer from_signer;
	fzn_chain_err_t err;

	sim_init(&net, 4, 0x5555u);
	fill_message(msg, sizeof(msg), 19);
	from = &net.hosts[0];
	to = &net.hosts[1];

	/* Host 1's own root grant is discarded, so that anything it sends must
	 * travel on the delegation or not at all. */
	/* The delegated hop is written straight into the recipient's own
	 * storage. A hop is a view now, so "take ownership of the region" is
	 * no longer a step a harness has to remember -- the bytes ARE the hop,
	 * and minting into `to->hop_bytes[1]` is the whole of it.
	 *
	 * SIGNED BY THE DELEGATING HOST, which is who the new hop names as its
	 * grantor -- `fzn_chain_delegate` passes `existing.grantee` to its
	 * signer. The same vtable re-verifies the chain being delegated from,
	 * which needs no signer at all: `verify` reads the key it is handed. */
	err = fzn_chain_delegate(from->chain, from->chain_len, net.root, &net.capability, net.now,
	                         to->pubkey, FZN_NO_EXPIRY, 0,
	                         sim_signer(&from_signer, &net.sign, from->pubkey), NULL,
	                         to->hop_bytes[1]);
	check(err == FZN_CHAIN_OK, "the delegation was refused");

	if (err == FZN_CHAIN_OK) {
		memcpy(to->hop_bytes[0], from->hop_bytes[0], FZN_HOP_LEN);
		check(fzn_hop_open(to->hop_bytes[0], FZN_HOP_LEN, &to->chain[0]) == FZN_CHAIN_OK,
		      "the copied root grant would not open");
		check(fzn_hop_open(to->hop_bytes[1], FZN_HOP_LEN, &to->chain[1]) == FZN_CHAIN_OK,
		      "the delegated hop would not open");
		to->chain_len = 2;

		check(sim_send(&net, 1, 2, msg, sizeof(msg), net.now + 100u),
		      "the delegated host could not send");
		sim_run(&net, 4);
		check(net.hosts[2].delivered == 1, "a delegated host's message was not delivered");
		check(net.hosts[2].refused_auth == 0, "a delegated host was refused on authority");
	}

	/* WHICH KEY EACH HOP IS CHECKED AGAINST, asked directly rather than
	 * through a delivery count.
	 *
	 * This is the leg the harness could not carry until `sim_verify` bound
	 * the key. With a verifier that ignored `pubkey`, `chain/chain.c` could
	 * be changed to check every hop against the ROOT and this whole file
	 * stayed green -- chain_test 271 checks and 39 failures on that mutation,
	 * this file 186 checks and none -- while the two refusals below could not
	 * be written at all, since a key-blind verifier accepts a hop signed by
	 * anybody. A two-hop chain is where the question first exists at all,
	 * because hop 1's grantor is the delegating host and hop 0's is the
	 * root, so the two keys are only the same key in a one-hop chain --
	 * which is every other scenario in this file.
	 *
	 * The two directions are separate properties and neither implies the
	 * other. The first fails for a verifier that checks the right signature
	 * against the wrong key; the second for one that does not check the key
	 * at all, and it is the one the old stub made unaskable. */
	if (err == FZN_CHAIN_OK && to->chain_len == 2) {
		struct sim_signer impostor;
		fzn_chain_hop_t hops[2];
		fzn_chain_t proven;
		uint8_t forged[FZN_HOP_LEN];
		uint8_t near_grantor[FZN_PUBKEY_LEN];

		check(fzn_chain_verify(to->chain, to->chain_len, net.root, &net.capability,
		                       net.now, &net.sign, NULL, &proven) == FZN_CHAIN_OK,
		      "a delegated hop signed by its own grantor was refused -- each hop's "
		      "signature must be checked against THAT hop's grantor, not against the "
		      "root");

		/* The same shape of hop, structurally perfect: its grantor is the
		 * delegating host, so the linkage check that ties hop 1 to hop 0's
		 * grantee passes and the capability and dates are the chain's own.
		 * The only thing wrong with it is who held the pen. */
		check(fzn_chain_mint(from->pubkey, to->pubkey, &net.capability, net.now,
		                     FZN_NO_EXPIRY, 0,
		                     sim_signer(&impostor, &net.sign, net.hosts[2].pubkey),
		                     forged) == FZN_CHAIN_OK,
		      "the impostor's hop could not be minted");
		hops[0] = to->chain[0];
		check(fzn_hop_open(forged, FZN_HOP_LEN, &hops[1]) == FZN_CHAIN_OK,
		      "the impostor's hop would not open");
		check(fzn_chain_verify(hops, 2, net.root, &net.capability, net.now, &net.sign,
		                       NULL, &proven) == FZN_CHAIN_ERR_CHAIN_INVALID,
		      "a hop whose grantor names one host and whose signature was made by "
		      "another was accepted -- the signature is not being checked against a "
		      "key at all");

		/* AND ONCE MORE WITH A SIGNER THE GRANTOR ONLY ALMOST IS, for the
		 * reason the near-miss legs elsewhere exist: a key comparison has a
		 * LENGTH, and a stub folding part of a key would pass the case
		 * above and fail here. The fixture is asserted before anything
		 * rests on it. */
		sim_near_identity(from->pubkey, near_grantor);
		check(memcmp(near_grantor, from->pubkey, FZN_PUBKEY_LEN - 1u) == 0,
		      "the near-miss signer must agree with the grantor on every byte but "
		      "the last, or this case is not testing what it says");
		check(memcmp(near_grantor, from->pubkey, FZN_PUBKEY_LEN) != 0,
		      "the near-miss signer must differ somewhere, or nothing here can fail");
		check(fzn_chain_mint(from->pubkey, to->pubkey, &net.capability, net.now,
		                     FZN_NO_EXPIRY, 0,
		                     sim_signer(&impostor, &net.sign, near_grantor),
		                     forged) == FZN_CHAIN_OK,
		      "the near-miss signer's hop could not be minted");
		check(fzn_hop_open(forged, FZN_HOP_LEN, &hops[1]) == FZN_CHAIN_OK,
		      "the near-miss signer's hop would not open");
		check(fzn_chain_verify(hops, 2, net.root, &net.capability, net.now, &net.sign,
		                       NULL, &proven) == FZN_CHAIN_ERR_CHAIN_INVALID,
		      "a hop signed by a key matching its grantor in all but its last byte "
		      "was accepted -- the signature check is not reading the whole key");
	}
	printf("  delegation: %s, %u delivered\n", fzn_chain_err_str(err), net.hosts[2].delivered);
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
	/* THE FLOOR, and it is the check this scenario was missing. `arrived <
	 * sent` is satisfied by zero, and `intact == arrived` is 0 == 0 -- so
	 * the whole scenario passed in a world where nothing was ever
	 * delivered, which is what a mutation refusing every chain proved. A
	 * 20% lossy network that delivers nothing is a broken receiver, not a
	 * lossy network. */
	check(arrived > 0, "a 20% lossy network delivered nothing at all");
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
	unsigned wrong = 0, near_wrong = 0;

	sim_init(&net, 4, 0x7777u);
	fill_message(a, sizeof(a), 41);
	fill_message(b, sizeof(b), 97);

	/* THE COLLISION HAS TO BE BUILT, and this scenario used not to build
	 * it. `sim_send` derives the identifier from `from << 16`, so two
	 * senders NEVER collide by accident -- the two messages below carried
	 * different identifiers, and a receiver keyed on the identifier alone
	 * would have filed them in separate slots and passed this scenario
	 * exactly as it stands. It asserted the property while arranging for
	 * the property to be untestable.
	 *
	 * Forcing one identifier for both senders is the whole point: now the
	 * only thing keeping the two messages apart is that reassembly keys on
	 * the sender too. Verified by mutation -- removing the sender from the
	 * reassembly key fails this scenario and did not before. */
	net.forced_msg_id = 0xabcd1234u;

	check(sim_send(&net, 0, 2, a, sizeof(a), net.now + 100u), "sender A was refused");
	check(sim_send(&net, 1, 2, b, sizeof(b), net.now + 100u), "sender B was refused");

	/* AND THE CHUNKS HAVE TO INTERLEAVE. A shared identifier is still not
	 * enough on its own: the queue holds A's chunks then B's, so A's
	 * message completes and frees its slot before B's first chunk is ever
	 * looked up, and the two never contend for one slot at all. Measured --
	 * with the identifier forced but the order left alone, removing the
	 * sender from the reassembly key STILL passed this scenario.
	 *
	 * Interleaving them is what puts two senders in the table at once,
	 * which is the state the sender-keying exists for. Both messages are
	 * 2000 bytes, so the queue is A0 A1 B0 B1 and one swap gives
	 * A0 B0 A1 B1. */
	check(net.queue_len == 4, "the splice scenario expects two chunks from each sender");
	{
		struct sim_datagram swap = net.queue[1];

		net.queue[1] = net.queue[2];
		net.queue[2] = swap;
	}

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

	/* AND AGAIN WITH A PAIR ONLY A FULL COMPARISON SEPARATES.
	 *
	 * Everything above survives a sender comparison truncated to one byte,
	 * because hosts 0 and 1 differ at byte 0. Measured: `chunk/reassembly.c`'s
	 * `memcmp(slot->sender, sender, FZN_SENDER_LEN)` cut to `1u` left this
	 * file at 172 checks and 0 failures and this scenario still printing
	 * `2 delivered, 0 spliced`, while `chunk/test/reassembly_test` failed
	 * three times. The property sec 5a cites this scenario for was being
	 * asserted by a fixture that could not express its violation.
	 *
	 * So run the same collision between two senders whose keys agree on
	 * every byte but the last. Now the only thing holding the two messages
	 * apart is a comparison of the WHOLE sender, and a short one folds a
	 * stranger's chunk into a victim's half-built message -- which on a real
	 * network needs no near miss to arrange, only the one first byte in 256
	 * that two random keys share. */
	sim_init(&net, 4, 0x7778u);
	sim_near_identity(net.hosts[0].pubkey, net.hosts[1].pubkey);
	sim_regrant(&net, &net.hosts[1], net.root);

	/* THE FIXTURE, ASSERTED BEFORE ANYTHING RESTS ON IT. A pair that
	 * quietly stopped being a near miss would turn every check below green
	 * for the wrong reason, which is the failure this whole leg exists to
	 * remove rather than to reproduce one level up. */
	check(memcmp(net.hosts[0].pubkey, net.hosts[1].pubkey, FZN_PUBKEY_LEN - 1u) == 0,
	      "the twin senders must agree on every byte but the last, or this leg is "
	      "not testing what it says");
	check(memcmp(net.hosts[0].pubkey, net.hosts[1].pubkey, FZN_PUBKEY_LEN) != 0,
	      "the twin senders must differ somewhere, or nothing here can fail");

	net.forced_msg_id = 0xabcd1234u;
	check(sim_send(&net, 0, 2, a, sizeof(a), net.now + 100u),
	      "the first twin sender was refused");
	check(sim_send(&net, 1, 2, b, sizeof(b), net.now + 100u),
	      "the second twin sender was refused");
	check(net.queue_len == 4, "the near-miss leg expects two chunks from each sender");
	{
		struct sim_datagram swap = net.queue[1];

		net.queue[1] = net.queue[2];
		net.queue[2] = swap;
	}

	sim_run(&net, 6);

	for (size_t e = 0; e < net.hosts[2].inbox_len; e++) {
		struct sim_inbox_entry *in = &net.hosts[2].inbox[e];
		const uint8_t *want = in->from == 0 ? a : b;

		if (in->len != sizeof(a) || memcmp(in->bytes, want, in->len) != 0)
			near_wrong++;
	}

	/* Three ways the same defect surfaces, and it is worth naming all
	 * three: the intruding chunk is refused as a duplicate index, so the
	 * victim's message completes without it and the stranger's never
	 * completes at all. A count of refusals is the one that fingers
	 * reassembly rather than the network. */
	check(net.hosts[2].refused_reasm == 0,
	      "a chunk from a sender differing only in its last key byte was refused -- "
	      "it was looked up in the other sender's slot, so reassembly is not reading "
	      "the whole sender");
	check(net.hosts[2].delivered == 2,
	      "both near-miss senders' messages should have arrived");
	check(near_wrong == 0,
	      "a message was spliced from two senders whose keys differ only in their "
	      "last byte");
	printf("  splice near miss: %u delivered, %u spliced, %u refused by reassembly\n",
	       net.hosts[2].delivered, near_wrong, net.hosts[2].refused_reasm);
}

/* ------------------------------------------------------------ scenario 8b

   Substitution. A host presents somebody else's grant as its own. Nothing is
   forged: the chain is genuine, correctly signed, names the right capability
   and verifies against the pinned root. It simply names a different grantee
   than the host that is sending.

   This is the cheapest attack on the whole design, because a chain is not a
   secret -- it travels in the clear and any host that has ever received one
   holds a copy. What stops it is the receiver comparing the grantee the
   chain proves against the sender the frame names, and until now nothing
   exercised that comparison: every scenario sent under its own grant, so the
   two were equal in every frame the suite had ever produced.  */

static void scenario_substitution(void)
{
	static struct sim_net net;
	static uint8_t msg[256];

	sim_init(&net, 4, 0x8888u);
	fill_message(msg, sizeof(msg), 23);

	/* Host 2 takes host 0's chain wholesale -- the BYTES, which is all a
	 * chain is. Copying them is exactly what an attacker does, since a
	 * chain travels in the clear and anyone who has been talked to holds a
	 * copy. The re-pointing this used to need is gone: a hop is a view, so
	 * opening host 2's own copy is the whole of taking ownership. */
	memcpy(net.hosts[2].hop_bytes, net.hosts[0].hop_bytes, sizeof(net.hosts[0].hop_bytes));
	for (size_t i = 0; i < net.hosts[0].chain_len; i++)
		check(fzn_hop_open(net.hosts[2].hop_bytes[i], FZN_HOP_LEN,
		                   &net.hosts[2].chain[i]) == FZN_CHAIN_OK,
		      "the stolen chain would not open");
	net.hosts[2].chain_len = net.hosts[0].chain_len;

	check(sim_send(&net, 2, 1, msg, sizeof(msg), net.now + 100u), "the send was refused");
	sim_run(&net, 3);

	check(net.hosts[1].delivered == 0,
	      "a host was accepted while acting on somebody else's grant");
	check(net.hosts[1].refused_auth > 0, "the substituted grant was not refused");
	/* The frame itself is impeccable -- correct key, correct commitment,
	 * valid tag. Asserting this separates "refused because the binding
	 * failed" from "refused because something was malformed". */
	check(net.hosts[1].refused_shape == 0, "the frame itself should have been well formed");

	/* The control, for the reason the other refusal scenarios carry one:
	 * host 0 sending under the very same chain must be delivered. */
	{
		static struct sim_net control;
		static uint8_t control_msg[256];

		sim_init(&control, 4, 0x8888u);
		fill_message(control_msg, sizeof(control_msg), 23);
		check(sim_send(&control, 0, 1, control_msg, sizeof(control_msg),
		               control.now + 100u),
		      "the control send was refused");
		sim_run(&control, 3);
		check(control.hosts[1].delivered > 0,
		      "the same chain did not work for its own grantee either, so the "
		      "refusal above is not evidence the binding caused it");
	}

	printf("  substitution: %u refused on authority, %u delivered\n",
	       net.hosts[1].refused_auth, net.hosts[1].delivered);
}

/* ------------------------------------------------------------ scenario 8c

   A tampered frame must not spend the nonce it claims.

   The order in sec 4.7 puts the seal first, and this is the reason that
   ordering is load-bearing rather than tidy. The replay window records a
   nonce so that a second frame carrying it is refused -- but if a frame that
   FAILED its tag were recorded too, anybody who can put bytes on the wire
   could burn a victim's nonces without holding any key at all. Garbage
   addressed to a host, carrying nonces it has not used yet, would make that
   host refuse its own legitimate traffic when it arrived.

   That is a denial of service available to an attacker with no key, no
   capability and no chain, and it is invisible: the victim's frames are
   refused as replays, which is exactly what a working replay defence looks
   like from the outside.  */

static void scenario_tamper(void)
{
	static struct sim_net net;
	static uint8_t msg[256];

	sim_init(&net, 4, 0x9999u);
	fill_message(msg, sizeof(msg), 29);

	check(sim_send(&net, 0, 1, msg, sizeof(msg), net.now + 100u), "the send was refused");
	check(net.queue_len == 1, "this scenario expects a single-chunk message");

	/* Two copies of one frame: the second is the original, the first is
	 * the original with a byte of its sealed region flipped. Both claim
	 * the same nonce, because they ARE the same frame. */
	net.queue[1] = net.queue[0];
	net.queue_len = 2;
	net.queue[0].frame[net.queue[0].len - 1u] ^= 0x40u;
	net.queue[0].due = net.now;
	net.queue[1].due = net.now;

	sim_run(&net, 4);

	check(net.hosts[1].refused_shape == 1, "the tampered frame was not refused on its tag");
	/* THE POINT. The intact frame carries the same nonce as the tampered
	 * one. If the tampered frame had been admitted to the replay window
	 * before its tag was checked, this would be refused as a replay -- and
	 * an attacker who cannot seal anything could silence this host. */
	check(net.hosts[1].refused_replay == 0,
	      "a frame that failed its tag spent its nonce, so an attacker with no "
	      "key can burn a victim's replay window");
	check(net.hosts[1].delivered == 1,
	      "the intact frame did not arrive after a tampered copy of it");

	printf("  tamper: %u refused on shape, %u refused as replay, %u delivered\n",
	       net.hosts[1].refused_shape, net.hosts[1].refused_replay,
	       net.hosts[1].delivered);
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
	return (h->held[issuer][0] >> (seq - 1u)) & 1u;
}

static void hold(struct sim_host *h, uint8_t issuer, uint64_t seq)
{
	h->held[issuer][0] |= (uint32_t)1u << (seq - 1u);
}

/* One host fetches from one peer: compare positions, ask for what is
 * missing, and admit whatever survives the network. */
/* THE COUNT THIS HARNESS ITERATES IS THE LIBRARY'S, AND IT IS BOUNDED.
 *
 * sync.h promises `request_count <= out_cap`, and `add_range` keeps that by
 * counting a range it cannot fit rather than writing past the array. Three
 * scenarios below then walk `plan.request_count`, which is exactly what a
 * real consumer does.
 *
 * WHY IT IS CHECKED RATHER THAN TRUSTED, and it is not about defending the
 * library. A `fzn_sync_plan_t` that reaches a caller uncleared carries the
 * caller's previous bytes AS A LENGTH -- record/test/sync_test.c measures
 * one at 3689348814741910323 from a plan pre-filled with 0x33, and refuses
 * it there by name. Walking that is an unbounded loop over memory nothing
 * wrote.
 *
 * Measured with `make sabotage`: removing `clear_plan`'s zeroing in
 * record/sync.c took this binary past any bound, and because it runs BEFORE
 * the unit tests of the modules it composes, the twenty-two binaries after
 * it never ran -- including sync_test, which catches that same defect in
 * under a second and says which line. So the cost of trusting the number
 * was not this scenario; it was every diagnostic behind it.
 *
 * One comparison converts that into a named failure. running-code.md is the
 * general form: the bound that matters lives inside the program, because a
 * wrapper only guards the way somebody did not run it.
 */
static size_t plan_requests(const fzn_sync_plan_t *plan, size_t cap)
{
	if (plan->request_count > cap) {
		check(0, "the plan's request_count is past the array it was given");
		return 0;
	}
	return plan->request_count;
}

static void sim_fetch_from(struct sim_net *net, struct sim_host *me, struct sim_host *peer)
{
	fzn_sync_position_t theirs[SIM_HOSTS];
	fzn_sync_request_t want[SIM_HOSTS];
	fzn_sync_plan_t plan;
	size_t dropped = 0;
	size_t n;

	n = fzn_sync_digest(&peer->journal, theirs, SIM_HOSTS, &dropped);
	/* The simulation sizes every digest buffer at SIM_HOSTS, so a drop here
	 * means the harness has outgrown its own buffers -- which would make
	 * every sync scenario below quietly partial. */
	total_digest_dropped += (unsigned)dropped;
	if (fzn_sync_plan_fetch(&me->journal, theirs, n, 4, want, SIM_HOSTS, &plan) !=
	    FZN_SYNC_OK)
		return;

	for (size_t r = 0, nreq = plan_requests(&plan, SIM_HOSTS); r < nreq; r++) {
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

			err = fzn_journal_admit(&me->journal, want[r].issuer, 0, seq);
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
	/* INCLUDING ITS OWN, which used to be skipped. `fzn_journal_admit` once
	 * created an entry for any unseen issuer arriving at sequence 1, so a
	 * host's own records opened their stream on the way past. Admitting no
	 * longer adopts -- following a stream is a decision, and a host follows
	 * its own like any other. */
	for (uint8_t i = 0; i < DIST_HOSTS; i++) {
		for (uint8_t issuer = 0; issuer < DIST_HOSTS; issuer++)
			fzn_journal_anchor(&net.hosts[i].journal, net.hosts[issuer].pubkey, 0, 0);
	}

	/* Every host issues, and holds its own from the start. */
	for (uint8_t i = 0; i < DIST_HOSTS; i++) {
		struct sim_host *h = &net.hosts[i];

		for (uint64_t seq = 1; seq <= DIST_RECORDS; seq++) {
			if (fzn_journal_admit(&h->journal, h->pubkey, 0, seq) != FZN_JOURNAL_OK)
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
				                                       net.hosts[issuer].pubkey, 0);
				uint64_t next;

				if (pending == 0)
					continue;
				next = fzn_journal_next(&h->journal, net.hosts[issuer].pubkey, 0);
				if (fzn_journal_confirm(&h->journal, net.hosts[issuer].pubkey, 0,
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
			if (fzn_journal_next(&h->journal, net.hosts[issuer].pubkey, 0) !=
			    DIST_RECORDS + 1u)
				complete = 0;
			total_pending += (unsigned)fzn_journal_pending(&h->journal,
			                                               net.hosts[issuer].pubkey, 0);
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

/* Storage for the encoded records this scenario builds. A record is a VIEW
 * over bytes now, so the bytes have to live somewhere the view outlasts --
 * which is the whole point: there is one representation and the fields are
 * read from the same bytes the signature covers. */
static uint8_t state_wire[STATE_HOSTS][4][FZN_RECORD_MAX_LEN];

/* The stream this scenario's records ride on. Named rather than 0 because
 * `state/` now takes the writer to be (issuer, stream), so the number is part
 * of the identity rather than a placeholder. */
#define STREAM_STATE 3u

/* Build a real, signed, canonical record and open a view onto it.
 *
 * This used to fill an `fzn_record_t`'s fields directly and leave
 * `signed_region` NULL, which was the only thing it could do: there was no
 * encoder. That is exactly the defect the binding closed -- the decoded
 * fields and the signed bytes had no relationship, so a signature proved
 * nothing about any field. The harness could not have demonstrated otherwise
 * because the library gave it nothing to demonstrate with. */
static void sim_make_record(struct sim_net *net, fzn_record_t *r, const struct sim_host *issuer,
                            uint64_t seq, uint8_t subject_seed)
{
	uint8_t subject[FZN_SUBJECT_LEN];
	uint8_t *wire = state_wire[issuer->id][seq - 1u];
	struct sim_signer signer;
	size_t wrote = 0;

	memset(subject, subject_seed, sizeof(subject));
	/* ZEROED FIRST, so a failure leaves the caller a view that refuses
	 * rather than one holding whatever was on its stack. Callers do not
	 * test this helper's outcome -- it cannot fail on genuine input --
	 * and before this they would have carried an uninitialised
	 * `fzn_record_t` into the library. Found by sabotaging the signing
	 * call to prove the fault counter below fires: it segfaulted instead
	 * of counting, which is the wrong way to learn a helper has no
	 * failure path. */
	memset(r, 0, sizeof(*r));
	/* THE ISSUER SIGNS, and `fzn_record_verify` checks against
	 * `fzn_record_issuer` -- so the two agree only for a record whose issuer
	 * really made it. `sim_receive_record` below is where that check now
	 * happens, and `scenario_forgery` is what proves it discriminates. */
	if (fzn_record_sign(issuer->pubkey, subject, STREAM_STATE, KIND_SETTING, seq, 1,
	                    state_bodies[issuer->id][seq - 1u], sizeof(state_bodies[0][0]),
	                    sim_signer(&signer, &net->sign, issuer->pubkey),
	                    wire, FZN_RECORD_MAX_LEN, &wrote) != FZN_RECORD_OK)
		setup_faults++;
	else if (fzn_record_open(wire, wrote, r) != FZN_RECORD_OK)
		setup_faults++;
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

/* ONE RECORD ARRIVING AT ONE HOST, in the order a consumer has to use.
 *
 * THE SIGNATURE FIRST, AND BEFORE THE JOURNAL MOVES. `record/journal.h` says
 * it in as many words -- "the record itself is not stored and not verified
 * here; a caller that admits an unverified record has skipped a step this
 * module cannot see" -- and the cost of skipping it is not just that a
 * forgery lands. `fzn_journal_admit` ADVANCES the stream's position, so a
 * forged record admitted at sequence n has spent n, and the genuine record
 * carrying n is refused as a duplicate for ever afterwards. Refusing before
 * admitting is what keeps a stranger from wedging a stream it cannot write.
 *
 * AGAINST THE RECORD'S OWN COORDINATES. The issuer, stream and sequence are
 * read out of the record rather than taken from the caller, because that is
 * what the binding bought: they live inside the range the signature covers,
 * so a verified record cannot be admitted under a name or at a position its
 * signer did not write. A caller passing its own copy of them would be back
 * to two representations that can disagree.
 *
 * REFUSED AND COUNTED, never dropped. See `struct sim_host::refused_record`.
 *
 * Returns 1 when the record was admitted, 0 when it was refused. */
static int sim_receive_record(struct sim_net *net, struct sim_host *me, fzn_record_t rec)
{
	if (fzn_record_verify(rec, &net->sign) != FZN_RECORD_OK) {
		me->refused_record++;
		return 0;
	}

	if (fzn_journal_admit(&me->journal, fzn_record_issuer(rec), fzn_record_stream(rec),
	                      fzn_record_seq(rec)) != FZN_JOURNAL_OK)
		return 0;
	me->admitted++;

	/* RECEIVED IS NOT APPLIED. The record is now held; what it means for
	 * current state is a separate step, and it is where a conflict
	 * surfaces. */
	if (fzn_state_apply(&me->state, &rec) == FZN_STATE_ERR_CONFLICT)
		me->conflicts++;
	return 1;
}

static void state_fetch(struct sim_net *net, struct sim_host *me, struct sim_host *peer,
                        uint8_t writers)
{
	fzn_sync_position_t theirs[SIM_HOSTS];
	fzn_sync_request_t want[SIM_HOSTS];
	fzn_sync_plan_t plan;
	size_t dropped = 0;
	size_t n = fzn_sync_digest(&peer->journal, theirs, SIM_HOSTS, &dropped);

	total_digest_dropped += (unsigned)dropped;

	if (fzn_sync_plan_fetch(&me->journal, theirs, n, 4, want, SIM_HOSTS, &plan) !=
	    FZN_SYNC_OK)
		return;

	for (size_t r = 0, nreq = plan_requests(&plan, SIM_HOSTS); r < nreq; r++) {
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
			/* THE RECORD THE PEER ANSWERS WITH, built here because
			 * this library has no transport: what a real peer would
			 * put on the wire is exactly these bytes. It is checked
			 * before it is worth anything to the receiver, which is
			 * what `sim_receive_record` is for -- and it is built
			 * BEFORE the journal is asked, because verifying after
			 * admitting is the ordering that check exists to refuse.
			 *
			 * Measured on both sides of the move, because a
			 * reordering that changed how often the builder ran
			 * would move this file's check count without moving
			 * anything real: `fzn_journal_admit` never once refuses
			 * in this loop, 0 refusals against 20 admissions, so
			 * building the record earlier costs nothing. */
			sim_make_record(net, &rec, &net->hosts[issuer], seq,
			                subject_of(issuer, seq));
			if (!sim_receive_record(net, me, rec))
				continue;

			hold(me, issuer, seq);
		}
	}
}

static void scenario_state(void)
{
	static struct sim_net net;
	uint8_t contested[FZN_SUBJECT_LEN];
	unsigned holding_alice = 0, holding_bob = 0, saw_conflict = 0, agreed = 0;
	unsigned refused_records = 0;
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
		for (uint8_t w = 0; w < WRITERS; w++)
			fzn_journal_anchor(&net.hosts[i].journal, net.hosts[w].pubkey,
			                   STREAM_STATE, 0);
	}
	for (uint8_t w = 0; w < WRITERS; w++) {
		struct sim_host *h = &net.hosts[w];

		for (uint64_t seq = 1; seq <= 2; seq++) {
			fzn_record_t rec;

			if (fzn_journal_admit(&h->journal, h->pubkey, STREAM_STATE, seq) != FZN_JOURNAL_OK)
				break;
			hold(h, w, seq);
			sim_make_record(&net, &rec, h, seq, subject_of(w, seq));
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

	/* EVERY RECORD HERE IS GENUINE, so none of them may be refused. Summed
	 * and asserted once rather than checked per fetch, and it is the half
	 * that stops the convergence checks below from being satisfied by a
	 * verifier that says no to everything: such a host would converge on
	 * nothing, and this says so by name instead of leaving it to be
	 * inferred from an empty state. */
	for (uint8_t i = 0; i < STATE_HOSTS; i++)
		refused_records += net.hosts[i].refused_record;
	check(refused_records == 0, "a genuine record was refused for its signature");

	/* AN UNCONTESTED SUBJECT CONVERGES EVERYWHERE. */
	{
		uint8_t own[FZN_SUBJECT_LEN];
		unsigned same = 0;

		memset(own, 0xD0, sizeof(own));
		for (uint8_t i = 0; i < STATE_HOSTS; i++) {
			const fzn_state_entry_t *e =
			        fzn_state_get(&net.hosts[i].state, own, KIND_SETTING);

			/* CONTENT, NOT THE POINTER. This compared `e->body`
			 * against the fixture's own buffer, which only worked
			 * because a record used to carry the caller's pointer
			 * straight through. A record is a view over its encoded
			 * bytes now, so the entry points into those -- and
			 * comparing what the hosts AGREE ON is what this check
			 * meant all along. */
			if (e && e->body_len == sizeof(state_bodies[0][0]) &&
			    memcmp(e->body, state_bodies[0][1], e->body_len) == 0)
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

		sim_make_record(&net, &winner, &net.hosts[0], 1, 0xC0);
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

	printf("  state: %u held alice, %u held bob, %u saw the conflict, %u agreed after,"
	       " %u refused unsigned\n",
	       holding_alice, holding_bob, saw_conflict, agreed, refused_records);
}

/* ----------------------------------------------------------- scenario 10b

   A record whose CONTENT is beyond reproach and whose SIGNATURE is somebody
   else's.

   WHY THIS IS WORTH WRITING NOW AND WAS NOT BEFORE. Until `sim_verify` began
   folding the key it is handed, every identity in this harness verified
   everything, so a record check here would have been a check that could not
   fail and this scenario would have been decoration. The verifier is
   key-bound now -- see the measurement above it -- which is what gives the
   refusals below something to be about.

   The forgery names the right issuer, rides the right stream, carries the
   right sequence and the same body, and agrees with the genuine record on
   every byte the signature covers. Only the pen differs. So the case asserts
   that agreement BEFORE it asserts any outcome, and then presents the same
   content correctly signed and requires it to be ACCEPTED: a leg that only
   shows a refusal cannot tell a working signature check from a receiver that
   refuses everything, or from a record malformed for some other reason.

   THE ORDER OF THE TWO PRESENTATIONS IS LOAD-BEARING. The forgery goes first,
   at the sequence the genuine record will claim. Presented second it would be
   refused by `fzn_journal_admit` as a duplicate whatever its signature said,
   and the leg would pass without the signature being consulted at all.

   AND A NEAR MISS, following `scenario_splice` and `scenario_join`: a signer
   agreeing with the issuer on every byte but the last. Hosts 0 and 1 differ
   at byte 0, so the first leg survives a key comparison truncated to one
   byte; only the near miss gives that comparison a LENGTH it can get wrong.  */

#define FORGE_HOSTS 3u
#define FORGE_BODY  16u

/* Build a record NAMING one identity and SIGNED BY another.
 *
 * The two keys are the same for a genuine record and different for a forged
 * one, and nothing else varies -- which is what lets this scenario say a
 * refusal was about the signature. `fzn_record_sign` writes `issuer` into the
 * buffer and asks the vtable for a signature over it, and the vtable's `ctx`
 * is who holds the pen; the two are independent here exactly as they are for
 * an attacker holding its own key and somebody else's name.
 *
 * Returns the encoded length, or 0 if signing was refused. */
static size_t sim_sign_record_as(const struct sim_net *net,
                                 const uint8_t issuer[FZN_PUBKEY_LEN],
                                 const uint8_t signer[FZN_PUBKEY_LEN], uint64_t seq,
                                 uint8_t subject_seed, uint8_t *out)
{
	uint8_t subject[FZN_SUBJECT_LEN];
	uint8_t body[FORGE_BODY];
	struct sim_signer who;
	size_t wrote = 0;

	memset(subject, subject_seed, sizeof(subject));
	memset(body, subject_seed, sizeof(body));
	if (fzn_record_sign(issuer, subject, STREAM_STATE, KIND_SETTING, seq, 1, body,
	                    sizeof(body), sim_signer(&who, &net->sign, signer), out,
	                    FZN_RECORD_MAX_LEN, &wrote) != FZN_RECORD_OK)
		return 0;
	return wrote;
}

static void scenario_forgery(void)
{
	static struct sim_net net;
	/* THE BYTES A RECORD IS A VIEW OF must outlive the view and everything
	 * the view was stored into -- `record.h` says so and `state/` stores
	 * one, so a stack array here would be dead under the entry that
	 * `fzn_state_get` hands back. Same reason `state_wire` above is static. */
	static uint8_t wire[4][FZN_RECORD_MAX_LEN];
	struct sim_host *issuer, *impostor, *receiver;
	uint8_t near_key[FZN_PUBKEY_LEN];
	uint8_t first[FZN_SUBJECT_LEN], second[FZN_SUBJECT_LEN];
	fzn_record_t genuine, forged, near, genuine_two;
	size_t wrote[4];
	const uint8_t *at_a, *at_b;
	size_t len_a, len_b;
	unsigned refused;

	sim_init(&net, FORGE_HOSTS, 0xccccu);
	issuer = &net.hosts[0];
	impostor = &net.hosts[1];
	receiver = &net.hosts[2];
	memset(first, 0xC0, sizeof(first));
	memset(second, 0xC1, sizeof(second));

	/* The receiver follows the issuer's stream. Without this nothing is
	 * admissible at all, and every refusal below would be the journal
	 * declining an issuer nobody adopted rather than a signature failing. */
	check(fzn_journal_anchor(&receiver->journal, issuer->pubkey, STREAM_STATE, 0) ==
	      FZN_JOURNAL_OK, "the receiver could not follow the issuer's stream");

	wrote[0] = sim_sign_record_as(&net, issuer->pubkey, issuer->pubkey, 1u, 0xC0u, wire[0]);
	wrote[1] = sim_sign_record_as(&net, issuer->pubkey, impostor->pubkey, 1u, 0xC0u,
	                              wire[1]);
	check(wrote[0] != 0 && wrote[1] != 0, "the scenario could not sign its records");
	check(fzn_record_open(wire[0], wrote[0], &genuine) == FZN_RECORD_OK,
	      "the genuine record is not shaped like a record");
	check(fzn_record_open(wire[1], wrote[1], &forged) == FZN_RECORD_OK,
	      "the forged record must be well formed, or it would be refused for its "
	      "shape rather than for its signature");

	/* THE FIXTURE, ASSERTED BEFORE ANYTHING RESTS ON IT. */
	check(memcmp(issuer->pubkey, impostor->pubkey, FZN_PUBKEY_LEN) != 0,
	      "the impostor must be a different identity from the issuer");
	check(memcmp(fzn_record_issuer(forged), issuer->pubkey, FZN_PUBKEY_LEN) == 0,
	      "the forged record must name the real issuer, or it is somebody else's "
	      "record rather than a forgery");
	fzn_record_signed_bytes(genuine, &at_a, &len_a);
	fzn_record_signed_bytes(forged, &at_b, &len_b);
	check(len_a == len_b && memcmp(at_a, at_b, len_a) == 0,
	      "the two records must agree on every signed byte, or a refusal below "
	      "could be about their content rather than about who signed");
	check(memcmp(fzn_record_signature(genuine), fzn_record_signature(forged),
	             FZN_SIG_LEN) != 0,
	      "the two signatures must differ, or nothing here can fail");

	/* THE FORGERY IS REFUSED, and the refusal is visible. */
	refused = receiver->refused_record;
	check(fzn_record_verify(forged, &net.sign) == FZN_RECORD_ERR_UNSIGNED,
	      "the forged record should be refused as unsigned rather than as malformed");
	check(sim_receive_record(&net, receiver, forged) == 0,
	      "a record signed by a host that is not its issuer was accepted");
	check(receiver->refused_record == refused + 1u,
	      "the refusal was not counted, so a forged record is indistinguishable "
	      "from one the network ate");
	check(fzn_journal_next(&receiver->journal, issuer->pubkey, STREAM_STATE) == 1u,
	      "the forged record moved the journal position, so the sequence it claimed "
	      "is spent and the genuine record carrying it can never land");
	check(fzn_state_get(&receiver->state, first, KIND_SETTING) == NULL,
	      "the forged record reached the receiver's state");

	/* AND THE SAME CONTENT, CORRECTLY SIGNED, IS ACCEPTED. Without this the
	 * leg above passes just as loudly against a receiver that refuses every
	 * record it is offered. */
	check(sim_receive_record(&net, receiver, genuine) == 1,
	      "the genuine record was refused");
	check(receiver->refused_record == refused + 1u,
	      "the genuine record was counted as a refusal");
	check(fzn_journal_next(&receiver->journal, issuer->pubkey, STREAM_STATE) == 2u,
	      "the genuine record did not move the journal position");
	{
		const fzn_state_entry_t *e = fzn_state_get(&receiver->state, first,
		                                           KIND_SETTING);

		check(e != NULL && memcmp(e->issuer, issuer->pubkey, FZN_PUBKEY_LEN) == 0,
		      "the genuine record did not reach the receiver's state");
	}

	/* AND AGAIN WITH A SIGNER ONLY A FULL COMPARISON SEPARATES FROM THE
	 * ISSUER. Everything above survives a key folded one byte at a time and
	 * stopped after the first, because hosts 0 and 1 differ at byte 0 --
	 * the same hole `sim_near_identity` was written for and the same one
	 * `scenario_splice` and `scenario_join` close one layer down. A
	 * signature is checked against a key an attacker chooses, so the LENGTH
	 * of that key is the property, and only a near miss asks about it.
	 *
	 * SEQUENCE 2, not 1. At 1 the journal would refuse the near miss as a
	 * duplicate and the leg would be green with the signature never
	 * consulted -- which is the same trap the ordering note above names. */
	sim_near_identity(issuer->pubkey, near_key);
	check(memcmp(near_key, issuer->pubkey, FZN_PUBKEY_LEN - 1u) == 0,
	      "the near signer must agree with the issuer on every byte but the last, "
	      "or this leg is not testing what it says");
	check(memcmp(near_key, issuer->pubkey, FZN_PUBKEY_LEN) != 0,
	      "the near signer must differ somewhere, or nothing here can fail");

	wrote[2] = sim_sign_record_as(&net, issuer->pubkey, near_key, 2u, 0xC1u, wire[2]);
	wrote[3] = sim_sign_record_as(&net, issuer->pubkey, issuer->pubkey, 2u, 0xC1u,
	                              wire[3]);
	check(wrote[2] != 0 && wrote[3] != 0,
	      "the scenario could not sign its near-miss records");
	check(fzn_record_open(wire[2], wrote[2], &near) == FZN_RECORD_OK,
	      "the near-miss record is not shaped like a record");
	check(fzn_record_open(wire[3], wrote[3], &genuine_two) == FZN_RECORD_OK,
	      "the near-miss pair's genuine half is not shaped like a record");
	fzn_record_signed_bytes(near, &at_a, &len_a);
	fzn_record_signed_bytes(genuine_two, &at_b, &len_b);
	check(len_a == len_b && memcmp(at_a, at_b, len_a) == 0,
	      "the near-miss pair must agree on every signed byte, or its refusal "
	      "could be about content rather than about the key's last byte");

	refused = receiver->refused_record;
	check(sim_receive_record(&net, receiver, near) == 0,
	      "a record signed by a key differing from the issuer's only in its last "
	      "byte was accepted -- the signature is not checked against the whole key");
	check(receiver->refused_record == refused + 1u,
	      "the near-miss refusal was not counted");
	check(fzn_journal_next(&receiver->journal, issuer->pubkey, STREAM_STATE) == 2u,
	      "the near-miss record moved the journal position");
	check(fzn_state_get(&receiver->state, second, KIND_SETTING) == NULL,
	      "the near-miss record reached the receiver's state");

	check(sim_receive_record(&net, receiver, genuine_two) == 1,
	      "the near-miss pair's genuine half was refused");
	check(fzn_journal_next(&receiver->journal, issuer->pubkey, STREAM_STATE) == 3u,
	      "the near-miss pair's genuine half did not move the journal position");
	check(fzn_state_get(&receiver->state, second, KIND_SETTING) != NULL,
	      "the near-miss pair's genuine half did not reach the receiver's state");

	printf("  forgery: %u refused unsigned, %u admitted, journal at %llu\n",
	       receiver->refused_record, receiver->admitted,
	       (unsigned long long)fzn_journal_next(&receiver->journal, issuer->pubkey,
	                                            STREAM_STATE));
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
	check(fzn_trust_root(&joiner->trust)
	              && memcmp(fzn_trust_root(&joiner->trust), net.root, FZN_PUBKEY_LEN) == 0,
	      "the refused adoption moved the anchor");

	/* AND A WELL-FORMED CHAIN UNDER THE WRONG ROOT IS REFUSED. Host 1 is
	 * re-grafted onto the rogue root and signs honestly: the chain checks
	 * out against that root and against no other. */
	{
		struct sim_host *attacker = &net.hosts[1];
		struct sim_signer rogue_signer;
		fzn_chain_t proven;
		unsigned refused_before;

		check(fzn_chain_mint(rogue_root, attacker->pubkey, &net.capability, 1,
		                     FZN_NO_EXPIRY, 1,
		                     sim_signer(&rogue_signer, &net.sign, rogue_root),
		                     attacker->hop_bytes[0]) == FZN_CHAIN_OK,
		      "the rogue grant could not be minted");
		check(fzn_hop_open(attacker->hop_bytes[0], FZN_HOP_LEN,
		                   &attacker->chain[0]) == FZN_CHAIN_OK,
		      "the rogue grant could not be opened");

		/* It really does verify -- under its own root. Otherwise this
		 * would be testing a broken chain rather than a foreign one. */
		check(fzn_chain_verify(attacker->chain, attacker->chain_len, rogue_root,
		                       &net.capability, net.now, &net.sign,
		                       &joiner->revocations, &proven) == FZN_CHAIN_OK,
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

	/* AND A ROOT THAT MISSES THE PIN BY ONE BYTE.
	 *
	 * The rogue root above is `memset(0x66)` against a pinned root whose
	 * first byte is 0xff, so the refusal it proves survives
	 * `chain/chain.c`'s pin truncated to a single byte -- measured, along
	 * with the whole of this file: 172 checks, 0 failures, while
	 * `chain/test/chain_test` failed on exactly that mutation. A pin is a
	 * comparison against an attacker-chosen key, so its LENGTH is the
	 * property, and a near miss is the only fixture that asks about it.
	 *
	 * Host 2 is re-grafted onto a root agreeing with the pin on every byte
	 * but the last, and signs honestly. A short pin admits it, and the
	 * joiner ends up acting on a grant issued by somebody it never
	 * anchored. */
	{
		struct sim_host *attacker = &net.hosts[2];
		uint8_t near_root[FZN_PUBKEY_LEN];
		fzn_chain_t proven;
		unsigned refused_before;

		sim_near_identity(net.root, near_root);
		check(memcmp(near_root, net.root, FZN_PUBKEY_LEN - 1u) == 0,
		      "the near root must agree with the pin on every byte but the last, "
		      "or this case is not testing what it says");
		check(memcmp(near_root, net.root, FZN_PUBKEY_LEN) != 0,
		      "the near root must differ somewhere, or nothing here can fail");

		sim_regrant(&net, attacker, near_root);

		/* It really does verify -- under its own root. Otherwise this
		 * would be testing a broken chain rather than a near-miss one. */
		check(fzn_chain_verify(attacker->chain, attacker->chain_len, near_root,
		                       &net.capability, net.now, &net.sign,
		                       &joiner->revocations, &proven) == FZN_CHAIN_OK,
		      "the near-miss chain should be valid under its own root");

		refused_before = joiner->refused_auth;
		before = joiner->delivered;
		check(sim_send(&net, 2, 3, msg, sizeof(msg), net.now + 100u),
		      "the near-miss attacker's send");
		sim_run(&net, 3);
		check(joiner->delivered == before,
		      "a chain rooted at a key matching the pin only in its first byte was "
		      "accepted -- the root pin is not reading the whole key");
		check(joiner->refused_auth > refused_before,
		      "and it should have been refused on authority");
	}

	printf("  join: %u delivered after joining, %u refused on authority, adopted at %llu\n",
	       joiner->delivered, joiner->refused_auth,
	       (unsigned long long)fzn_trust_adopted_at(&joiner->trust));
}

/* ------------------------------------------------------------ scenario 12

   Two fidelities of the same thing, and two kinds of recipient.

   THE CASE THAT WAS IMPOSSIBLE BEFORE `stream`. An issuer publishes a precise
   track and a coarse one. Some hosts are entitled to both; some only to the
   coarse. With one sequence per issuer, the coarse-only hosts could never
   hold a contiguous position -- every precise record they were not allowed to
   see was a hole they could not fill, and `fzn_journal_admit` refuses a gap.
   They would have asked for ever for records nobody would send them.

   The property now: **every host converges on exactly what it is entitled
   to**, contiguously, on a network dropping a fifth of everything -- and the
   coarse-only hosts hold nothing at all from the precise stream, which is the
   other half and the one a privacy claim rests on.  */

#define FID_HOSTS    6u
#define FID_RECORDS  5u
#define STREAM_FINE  1u
#define STREAM_COARSE 2u

/* Which hosts may see the precise stream. Host 0 is the issuer; 1 and 2 are
 * trusted with the fine track; 3, 4 and 5 get the coarse one only. */
static int entitled_to_fine(uint8_t host)
{
	return host <= 2u;
}

static void fidelity_fetch(struct sim_net *net, struct sim_host *me, struct sim_host *peer,
                           uint8_t issuer_id)
{
	fzn_sync_position_t theirs[SIM_HOSTS * 2u];
	fzn_sync_request_t want[SIM_HOSTS * 2u];
	fzn_sync_plan_t plan;
	size_t dropped = 0;
	size_t n = fzn_sync_digest(&peer->journal, theirs, SIM_HOSTS * 2u, &dropped);

	total_digest_dropped += (unsigned)dropped;

	if (fzn_sync_plan_fetch(&me->journal, theirs, n, 4, want, SIM_HOSTS * 2u, &plan) !=
	    FZN_SYNC_OK)
		return;

	for (size_t r = 0, nreq = plan_requests(&plan, SIM_HOSTS * 2u); r < nreq; r++) {
		uint32_t stream = want[r].stream;

		for (uint64_t seq = want[r].from; seq < want[r].from + want[r].count; seq++) {
			if (!(peer->held[issuer_id][stream == STREAM_FINE ? 0u : 1u] >>
			      (seq - 1u) & 1u))
				continue;
			if (net->loss_pct && (sim_random(net) % 100u) < net->loss_pct) {
				net->dropped++;
				continue;
			}
			if (fzn_journal_admit(&me->journal, want[r].issuer, stream, seq) !=
			    FZN_JOURNAL_OK)
				continue;
			me->held[issuer_id][stream == STREAM_FINE ? 0u : 1u] |=
			        (uint32_t)1u << (seq - 1u);
			me->admitted++;
		}
	}
}

static void scenario_fidelity(void)
{
	static struct sim_net net;
	unsigned fine_complete = 0, coarse_complete = 0, leaked = 0;

	sim_init(&net, FID_HOSTS, 0xbbbbu);
	net.loss_pct = 20;

	/* The issuer follows both of its own streams before it publishes on
	 * them. Admitting no longer adopts, so a stream must be followed before
	 * anything can be admitted to it -- including by the host that issues
	 * it. */
	fzn_journal_anchor(&net.hosts[0].journal, net.hosts[0].pubkey, STREAM_COARSE, 0);
	fzn_journal_anchor(&net.hosts[0].journal, net.hosts[0].pubkey, STREAM_FINE, 0);

	/* The issuer publishes both, each numbered from one. */
	for (uint64_t seq = 1; seq <= FID_RECORDS; seq++) {
		fzn_journal_admit(&net.hosts[0].journal, net.hosts[0].pubkey, STREAM_FINE, seq);
		fzn_journal_admit(&net.hosts[0].journal, net.hosts[0].pubkey, STREAM_COARSE, seq);
		net.hosts[0].held[0][0] |= (uint32_t)1u << (seq - 1u);
		net.hosts[0].held[0][1] |= (uint32_t)1u << (seq - 1u);
	}

	/* EACH HOST FOLLOWS WHAT IT MAY. Entitlement is expressed by which
	 * streams a host anchors -- and in a real consumer that decision is a
	 * capability check, which `chain/` already answers. */
	for (uint8_t i = 1; i < FID_HOSTS; i++) {
		fzn_journal_anchor(&net.hosts[i].journal, net.hosts[0].pubkey, STREAM_COARSE, 0);
		if (entitled_to_fine(i))
			fzn_journal_anchor(&net.hosts[i].journal, net.hosts[0].pubkey,
			                   STREAM_FINE, 0);
	}

	for (unsigned round = 0; round < 40u; round++)
		for (uint8_t i = 1; i < FID_HOSTS; i++)
			fidelity_fetch(&net, &net.hosts[i], &net.hosts[0], 0);

	for (uint8_t i = 1; i < FID_HOSTS; i++) {
		struct sim_host *h = &net.hosts[i];
		uint64_t fine = fzn_journal_next(&h->journal, net.hosts[0].pubkey, STREAM_FINE);
		uint64_t coarse = fzn_journal_next(&h->journal, net.hosts[0].pubkey, STREAM_COARSE);

		/* THE COARSE STREAM MUST BE COMPLETE FOR EVERYONE. This is the
		 * case that could not have worked before: a coarse-only host
		 * reaching the end without ever being able to fill a hole it
		 * was not entitled to. */
		if (coarse == FID_RECORDS + 1u)
			coarse_complete++;

		if (entitled_to_fine(i)) {
			if (fine == FID_RECORDS + 1u)
				fine_complete++;
		} else {
			/* AND NOTHING OF THE FINE STREAM LEAKED. A privacy
			 * claim rests on this half, not on the other. */
			if (fine != 1u || h->held[0][0] != 0u)
				leaked++;
		}
	}

	check(coarse_complete == FID_HOSTS - 1u,
	      "every host should hold the whole coarse stream, whatever else it may see");
	check(fine_complete == 2u, "both entitled hosts should hold the whole fine stream");
	check(leaked == 0, "a host not entitled to the fine stream holds part of it");
	check(net.dropped > 0, "no record was lost, so this proved less than it looks");
	printf("  fidelity: %u of %u complete on coarse, %u on fine, %u leaked, %u dropped\n",
	       coarse_complete, FID_HOSTS - 1u, fine_complete, leaked, net.dropped);
}

/* ------------------------------------------------------------------------
 * A SESSION, END TO END, BETWEEN TWO SIMULATED HOSTS.
 *
 * WHY THIS SCENARIO EXISTS AND WHY IT IS LAST. This file's own opening says
 * module tests "cannot find a defect BETWEEN modules". Six modules were added
 * in one day -- prekey, agree, session, ratchet, authz, blob -- and this file
 * reached NONE of them, which was measured rather than noticed: a grep for
 * each module's prefix returned zero.
 *
 * That is exactly the gap the day's sharpest defect lived in. `ratchet/` was
 * written correct, tested, fuzzed, and had NO CALLERS AT ALL until
 * `fzn_session_chains` was written hours later -- a correct function that was
 * not a working feature, and no module test could have said so.
 *
 * So this walks the whole path with nothing stubbed above the vtables: each
 * host mints a prekey, publishes a signed record, the other pins it on first
 * use, both derive the same session root from opposite points of view, both
 * derive directed chain seeds, both ratchet, and the message keys must match.
 * Then a rotation, and the root must move.
 */
static void scenario_session(void)
{
	struct sim_net net;
	fzn_agree_ops_t agree_ops = { sim_agree_public, sim_agree_shared, NULL };
	fzn_hash_ops_t hash_ops = { sim_hash, NULL };
	fzn_agree_secret_t sk[2];
	fzn_prekey_peer_t pinned[2];
	uint8_t secret[2][FZN_AGREE_SECRET_LEN];
	uint8_t record_bytes[2][FZN_PREKEY_LEN_TOTAL];
	fzn_prekey_record_t record[2];
	uint8_t key[2][FZN_AEAD_KEY_LEN], ckey[2][FZN_COMMITMENT_KEY_LEN];
	uint8_t send_chain[2][FZN_CHAIN_KEY_LEN], recv_chain[2][FZN_CHAIN_KEY_LEN];
	fzn_ratchet_chain_t chain_a, chain_b, moved;
	uint8_t mk_a[FZN_MESSAGE_KEY_LEN], mk_b[FZN_MESSAGE_KEY_LEN];
	unsigned h;
	int ok = 1;

	sim_init(&net, 2, 0x5e5510au);

	/* Each host mints a prekey and publishes a record signed under its
	 * own identity. The record is real bytes, signed and reopened, not a
	 * struct filled in -- the property this file already holds for hops. */
	for (h = 0; h < 2u; h++) {
		unsigned i;

		memset(&sk[h], 0, sizeof(sk[h]));
		fzn_prekey_peer_init(&pinned[h]);
		for (i = 0; i < FZN_AGREE_SECRET_LEN; i++)
			secret[h][i] = (uint8_t)((h * 61u) + (i * 7u) + 3u);
		if (fzn_agree_secret_install(&sk[h], &agree_ops, secret[h]) != FZN_AGREE_OK)
			ok = 0;
		if (!fzn_agree_secret_public(&sk[h]))
			ok = 0;
	}
	check(ok, "a simulated host could not mint a prekey");
	if (!ok)
		return;

	for (h = 0; h < 2u; h++) {
		struct sim_signer who;
		const fzn_sign_ops_t *signer =
		        sim_signer(&who, &net.sign, net.hosts[h].pubkey);

		if (fzn_prekey_issue(net.hosts[h].pubkey, fzn_agree_secret_public(&sk[h]),
		                     500u + h, signer, record_bytes[h]) != FZN_PREKEY_OK)
			ok = 0;
		if (fzn_prekey_open(record_bytes[h], FZN_PREKEY_LEN_TOTAL, &record[h])
		    != FZN_PREKEY_OK)
			ok = 0;
	}
	check(ok, "a simulated host could not publish a prekey record");
	if (!ok)
		return;

	/* FIRST USE, EACH PINNING THE OTHER. Adopted rather than confirmed,
	 * because a simulated network has no out-of-band channel -- which is
	 * exactly the provenance `trust/` exists to keep visible. */
	check(fzn_prekey_pin(&pinned[0], record[1], &net.sign, FZN_TRUST_ADOPTED, net.now)
	              == FZN_PREKEY_OK, "host 0 could not pin host 1's prekey");
	check(fzn_prekey_pin(&pinned[1], record[0], &net.sign, FZN_TRUST_ADOPTED, net.now)
	              == FZN_PREKEY_OK, "host 1 could not pin host 0's prekey");
	check(fzn_trust_source_of(&pinned[0].trust) == FZN_TRUST_ADOPTED,
	      "a pin over the network reported itself as out-of-band confirmed");

	/* THE SESSION, FROM OPPOSITE POINTS OF VIEW AND WITH NO ROLE AGREED.
	 * This is the assertion the whole scenario is for: two hosts that
	 * never negotiated who started must land on the same root. */
	check(fzn_session_establish(&sk[0], &agree_ops, &hash_ops, net.hosts[0].pubkey,
	                           net.hosts[1].pubkey, pinned[0].prekey, key[0], ckey[0])
	              == FZN_SESSION_OK, "host 0 could not establish");
	check(fzn_session_establish(&sk[1], &agree_ops, &hash_ops, net.hosts[1].pubkey,
	                           net.hosts[0].pubkey, pinned[1].prekey, key[1], ckey[1])
	              == FZN_SESSION_OK, "host 1 could not establish");
	check(memcmp(key[0], key[1], FZN_AEAD_KEY_LEN) == 0,
	      "two hosts derived different session roots, so they cannot talk");
	check(memcmp(ckey[0], ckey[1], FZN_COMMITMENT_KEY_LEN) == 0,
	      "two hosts derived different commitment keys");

	/* THE DIRECTED SEEDS, AND THE RATCHET THEY DRIVE. A message goes one
	 * way: host 0's send chain must be host 1's receive chain, and the
	 * first message key on each side must match. This is the composition
	 * that did not exist at all until hours after the ratchet was
	 * written. */
	check(fzn_session_chains(&hash_ops, key[0], net.hosts[0].pubkey, net.hosts[1].pubkey,
	                        send_chain[0], recv_chain[0]) == FZN_SESSION_OK,
	      "host 0 could not derive its chain seeds");
	check(fzn_session_chains(&hash_ops, key[1], net.hosts[1].pubkey, net.hosts[0].pubkey,
	                        send_chain[1], recv_chain[1]) == FZN_SESSION_OK,
	      "host 1 could not derive its chain seeds");
	check(memcmp(send_chain[0], recv_chain[1], FZN_CHAIN_KEY_LEN) == 0,
	      "host 0's send chain is not host 1's receive chain");
	check(memcmp(send_chain[0], recv_chain[0], FZN_CHAIN_KEY_LEN) != 0,
	      "the two directions share a chain, so a message replayed at its sender "
	      "decrypts under the key it is waiting to receive under");

	fzn_ratchet_init(&chain_a, send_chain[0], 0);
	fzn_ratchet_init(&chain_b, recv_chain[1], 0);
	check(fzn_ratchet_advance(&hash_ops, &chain_a, 0, mk_a, &moved, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_OK, "the sender could not advance");
	check(fzn_ratchet_advance(&hash_ops, &chain_b, 0, mk_b, &moved, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_OK, "the receiver could not advance");
	check(memcmp(mk_a, mk_b, FZN_MESSAGE_KEY_LEN) == 0,
	      "the two hosts derived different message keys for the first message, so "
	      "the session and the ratchet do not compose");

	/* AND A ROTATION MOVES THE ROOT, which is where the forward secrecy
	 * comes from and is worthless if a rotated prekey derives the same
	 * session. */
	{
		uint8_t rotated[FZN_AGREE_SECRET_LEN];
		uint8_t after[FZN_AEAD_KEY_LEN], after_ck[FZN_COMMITMENT_KEY_LEN];
		unsigned i;

		for (i = 0; i < FZN_AGREE_SECRET_LEN; i++)
			rotated[i] = (uint8_t)((i * 13u) + 41u);
		check(fzn_agree_secret_install(&sk[1], &agree_ops, rotated) == FZN_AGREE_OK,
		      "host 1 could not rotate its prekey");
		{
			struct sim_signer who;
			const fzn_sign_ops_t *signer =
			        sim_signer(&who, &net.sign, net.hosts[1].pubkey);

			check(fzn_prekey_issue(net.hosts[1].pubkey,
			                       fzn_agree_secret_public(&sk[1]), 900u, signer,
			                       record_bytes[1]) == FZN_PREKEY_OK,
			      "host 1 could not publish its rotated prekey");
		}
		check(fzn_prekey_open(record_bytes[1], FZN_PREKEY_LEN_TOTAL, &record[1])
		              == FZN_PREKEY_OK, "the rotated record does not open");
		check(fzn_prekey_pin(&pinned[0], record[1], &net.sign, FZN_TRUST_ADOPTED,
		                     net.now) == FZN_PREKEY_OK,
		      "host 0 refused a legitimate rotation");
		check(fzn_session_establish(&sk[0], &agree_ops, &hash_ops, net.hosts[0].pubkey,
		                            net.hosts[1].pubkey, pinned[0].prekey, after,
		                            after_ck) == FZN_SESSION_OK,
		      "host 0 could not re-establish after the rotation");
		check(memcmp(key[0], after, FZN_AEAD_KEY_LEN) != 0,
		      "a rotated prekey derived the same session root, so rotation buys "
		      "no forward secrecy");

		/* AND THE ROLLBACK: host 1's OLD record, replayed by anybody
		 * who saw it, must not take. */
		{
			struct sim_signer who;
			const fzn_sign_ops_t *signer =
			        sim_signer(&who, &net.sign, net.hosts[1].pubkey);

			check(fzn_prekey_issue(net.hosts[1].pubkey,
			                       fzn_agree_secret_public(&sk[0]), 500u, signer,
			                       record_bytes[1]) == FZN_PREKEY_OK,
			      "could not build the replayed record");
		}
		check(fzn_prekey_open(record_bytes[1], FZN_PREKEY_LEN_TOTAL, &record[1])
		              == FZN_PREKEY_OK, "the replayed record does not open");
		check(fzn_prekey_pin(&pinned[0], record[1], &net.sign, FZN_TRUST_ADOPTED,
		                     net.now) == FZN_PREKEY_ERR_ROLLBACK,
		      "an older, genuine, correctly signed prekey was accepted over a newer");
	}

	for (h = 0; h < 2u; h++)
		fzn_agree_secret_wipe(&sk[h]);
}

/*
 * A HOST THAT LOSES ITS MEMORY AND COMES BACK, which nothing in this file
 * could express before it.
 *
 * `persist/` exists for exactly one reason -- four kinds of state must
 * survive a restart -- and every scenario here keeps its hosts alive from
 * the first line to the last, so the one question the module answers was the
 * one question the simulation could not ask. `persist_test.c` round-trips
 * each blob and checks its fields, which proves the PACKERS; it cannot prove
 * the SET is sufficient, because sufficiency is a property of a host trying
 * to carry on afterwards. That is `evidence.md`'s correct-function-versus-
 * working-feature split, and this is the missing half.
 *
 * THE SCRUB IS CHECKED BEFORE IT IS RELIED ON. Between destroying host 1's
 * state and restoring it, the scenario asserts that host 1 CANNOT follow the
 * conversation. Without that, a scrub that quietly failed to land -- a
 * memset over the wrong struct, a copy left in a local -- would leave the
 * restore looking like it worked when nothing had been lost in the first
 * place. A sabotage that did not apply and a check that cannot fail are
 * indistinguishable from the output.
 */
/*
 * A HOST THAT WAS AWAY FOR A LONG TIME, AND THE NETWORK MOVED ON.
 *
 * `scenario_restart` covers a host that loses its memory and comes back; this
 * is the other absence, and they are not the same shape. There the host is
 * gone for no TIME -- the conversation waits for it -- and the question is
 * whether `persist/` carried enough. Here the host keeps everything it had
 * and the question is whether it can catch up on what happened without it.
 *
 * WHY IT NEEDED WRITING. project.md sec 46 answers the holder's shattered-
 * estate requirement partly by claiming that healing is already built: sync
 * is pull-shaped, so "a host that missed eighteen months asks for eighteen
 * months". That claim was made from reading `record/sync.h` and nothing
 * exercised it. `scenario_distribution` converges eight hosts under loss, but
 * every one of them starts empty at the same moment and follows the same five
 * records -- nobody is ever far behind anybody.
 *
 * THE PART THAT COULD PLAUSIBLY FAIL IS THE BOUND. `fzn_sync_plan_fetch`
 * takes `max_per_request`, and this harness passes 4, so a host twenty-four
 * records behind cannot be answered in one exchange -- it must ask, apply,
 * and ask again from its new position, six times at least. A plan that
 * computed the gap from the peer's numbers rather than from this host's own
 * would stall or re-ask forever, and neither shows up when the gap is smaller
 * than the bound. So the assertion is not merely that it converges: it is
 * that convergence took MORE THAN ONE ROUND, which is what says the bound was
 * actually exercised rather than stepped over.
 *
 * THE ABSENCE IS CHECKED BEFORE THE RECOVERY IS, for `scenario_restart`'s
 * reason: a returning host that had quietly never fallen behind would satisfy
 * every check below while proving nothing, and an absence that did not happen
 * looks exactly like a recovery that worked.
 */

#define ABS_HOSTS    3u
#define ABS_RECORDS  24u
#define ABS_ROUNDS   40u

/*
 * TWO MEMBERS UNDER ONE ROOT, AND ONLY ONE OF THEM RETIRED.
 *
 * project.md sec 46 answers the holder's question about a fourth consumer by
 * recommending that each application be a MEMBER under the estate root rather
 * than a co-holder of the root key -- and the argument that decides it is
 * revocation granularity: a revocation names `(capability, grantee, issuer)`,
 * so retiring one application without touching another is already sayable,
 * whereas a shared identity cannot express it at all.
 *
 * THAT WAS AN ARGUMENT FROM READING `chain/revocation.h`, and nothing ran it.
 * `scenario_revocation` revokes a sender and proves the refusal is caused by
 * the revocation, with a positive control on a second network. What it does
 * not ask is whether the revocation is CONFINED -- every host in that
 * scenario is either the revoked one or a receiver.
 *
 * THE TWO SENDS DIFFER IN EXACTLY ONE THING. Same root, same capability, same
 * receiver, same network, same moment; one grantee is revoked and the other
 * is not. That is what makes this a statement about the grantee field rather
 * than about revocation working at all, and it is why both legs run on ONE
 * network instead of the two `scenario_revocation` needs -- there the
 * comparison is between worlds, here it is within one.
 *
 * THE SURVIVING MEMBER IS CHECKED AFTER THE REVOCATION IS IN FORCE, not
 * before. A send that arrived before anything was revoked would prove only
 * that the network works, which is the failure mode the positive control in
 * `scenario_revocation` exists to catch, one step along.
 */

#define EST_ROUNDS 10u

static void scenario_estate(void)
{
	static struct sim_net net;
	static uint8_t msg[200];
	static uint8_t rec_region[FZN_REVOCATION_LEN];
	fzn_revocation_record_t rec;
	struct sim_signer root_signer;
	unsigned delivered_before, refused_before;

	sim_init(&net, 4, 0x6363u);
	fill_message(msg, sizeof(msg), 23);

	/* Both members work to begin with. Without this the refusal below could
	 * be a member that never had a usable grant. */
	check(sim_send(&net, 1, 3, msg, sizeof(msg), net.now + 100u),
	      "the first member's send was refused");
	sim_run(&net, EST_ROUNDS);
	check(net.hosts[3].delivered > 0, "the first member could not reach the receiver");

	check(sim_send(&net, 2, 3, msg, sizeof(msg), net.now + 100u),
	      "the second member's send was refused");
	sim_run(&net, EST_ROUNDS);
	check(net.hosts[3].delivered > 1, "the second member could not reach the receiver");
	check(net.hosts[3].refused_auth == 0,
	      "something was refused on authority before anything was revoked");

	/* Retire the SECOND member only. */
	check(fzn_revocation_issue(net.root, &net.capability, net.hosts[2].pubkey, net.now,
	                           sim_signer(&root_signer, &net.sign, net.root),
	                           rec_region) == FZN_CHAIN_OK,
	      "the simulation could not issue the revocation");
	check(fzn_revocation_open(rec_region, FZN_REVOCATION_LEN, &rec) == FZN_CHAIN_OK,
	      "the simulation could not open the revocation it issued");
	check(sim_revoke_all(&net, rec) == 0, "the signed revocation was refused");

	/* The retired member is refused. */
	delivered_before = net.hosts[3].delivered;
	refused_before = net.hosts[3].refused_auth;
	check(sim_send(&net, 2, 3, msg, sizeof(msg), net.now + 100u),
	      "the retired member's send was refused before it left");
	sim_run(&net, EST_ROUNDS);
	check(net.hosts[3].delivered == delivered_before,
	      "the retired member still reached the receiver");
	check(net.hosts[3].refused_auth > refused_before,
	      "the retired member's frames were not refused on authority");

	/* AND THE SIBLING IS UNTOUCHED, which is the whole scenario. Same root,
	 * same capability, same receiver, with the revocation in force. */
	delivered_before = net.hosts[3].delivered;
	refused_before = net.hosts[3].refused_auth;
	check(sim_send(&net, 1, 3, msg, sizeof(msg), net.now + 100u),
	      "the surviving member's send was refused before it left");
	sim_run(&net, EST_ROUNDS);
	check(net.hosts[3].delivered > delivered_before,
	      "revoking one member stopped another member under the same root");
	check(net.hosts[3].refused_auth == refused_before,
	      "the surviving member's frames were refused on authority");

	printf("  estate: %u delivered, %u refused on authority, one member retired\n",
	       net.hosts[3].delivered, net.hosts[3].refused_auth);
}

static void scenario_absence(void)
{
	static struct sim_net net;
	struct sim_host *issuer, *present, *away;
	unsigned round, returned_at = 0, converged_at = 0;
	uint64_t seq;

	sim_init(&net, ABS_HOSTS, 0x5151u);

	issuer = &net.hosts[0];
	present = &net.hosts[1];
	away = &net.hosts[2];

	for (uint8_t i = 0; i < ABS_HOSTS; i++)
		fzn_journal_anchor(&net.hosts[i].journal, issuer->pubkey, 0, 0);

	for (seq = 1; seq <= ABS_RECORDS; seq++) {
		if (fzn_journal_admit(&issuer->journal, issuer->pubkey, 0, seq)
		    != FZN_JOURNAL_OK)
			break;
		hold(issuer, 0, seq);
		issuer->issued = seq;
	}
	check(issuer->issued == ABS_RECORDS, "the issuer published its whole run");

	/* The absence. `away` simply does not fetch, which is what being off
	 * the network is -- no refusal, no error, nothing to observe locally. */
	for (round = 0; round < 12u; round++) {
		sim_fetch_from(&net, present, issuer);
		{
			uint64_t next = fzn_journal_next(&present->journal, issuer->pubkey, 0);

			if (next > 1u)
				fzn_journal_confirm(&present->journal, issuer->pubkey, 0,
				                    next - 1u);
		}
	}

	/* THE ABSENCE, CHECKED. Without this the rest is satisfied by a host
	 * that was never behind. */
	check(fzn_journal_next(&present->journal, issuer->pubkey, 0) == ABS_RECORDS + 1u,
	      "the present host kept up while the other was away");
	check(fzn_journal_next(&away->journal, issuer->pubkey, 0) == 1u,
	      "the absent host holds nothing, so it really was away");

	/* It comes back and asks. Nothing tells it how far behind it is: it
	 * compares positions and asks for what is missing, which is the whole
	 * of the healing story sec 46 relies on. */
	returned_at = round;
	for (; round < ABS_ROUNDS; round++) {
		uint64_t next;

		sim_fetch_from(&net, away, issuer);
		next = fzn_journal_next(&away->journal, issuer->pubkey, 0);
		if (next > 1u)
			fzn_journal_confirm(&away->journal, issuer->pubkey, 0, next - 1u);
		if (fzn_journal_next(&away->journal, issuer->pubkey, 0) == ABS_RECORDS + 1u) {
			converged_at = round + 1u;
			break;
		}
	}

	check(converged_at != 0, "the returning host caught up at all");
	check(fzn_journal_next(&away->journal, issuer->pubkey, 0) == ABS_RECORDS + 1u,
	      "the returning host reached the position the network was at");

	/* THE BOUND WAS EXERCISED, which is the assertion that distinguishes
	 * this from a gap small enough to be answered in one exchange. */
	check(converged_at - returned_at > 1u,
	      "catching up took more than one exchange, so max_per_request was "
	      "actually iterated rather than stepped over");

	/* And it holds every record, not merely a position that claims so. A
	 * journal position is a number; the bitmap is what was received. */
	{
		unsigned missing = 0;

		for (seq = 1; seq <= ABS_RECORDS; seq++)
			if (!holds(away, 0, seq))
				missing++;
		check(missing == 0, "the returning host holds every record it missed");
	}

	printf("  absence: away %u rounds, caught up in %u exchanges, %llu records\n",
	       returned_at, converged_at - returned_at,
	       (unsigned long long)ABS_RECORDS);
}

/* ================================ tree ================================
 *
 * WHAT THIS SCENARIO IS FOR, AND WHAT IT DELIBERATELY IS NOT.
 *
 * `tree/` makes one claim that unit tests over hand-built arrays cannot
 * reach: **the structure a host computes is a function of the SET of node
 * records it holds, never of the order they arrived in.** sec 50 refuses to
 * resolve concurrent reparents for that reason, so what replaces resolution
 * is this property, and until now it was held by fixtures I wrote myself.
 *
 * HOW THE SET IS BUILT HERE IS NOT `record/sync`'s JOB TWICE. Distribution
 * over the journal, gaps, digests and fetch plans are `scenario_distribution`
 * and are tested there. What this needs is hosts arriving at DIFFERENT
 * SUBSETS in DIFFERENT ORDERS, which a lossy gossip over the same signed
 * records produces directly. Reusing the fetch path would test the fetch
 * path a second time and the tree claim no harder.
 *
 * THREE PROPERTIES, and the second is the one worth the scenario:
 *
 *   1. CONVERGENCE. Two hosts holding the same records compute the same
 *      reachable set. This is the claim.
 *
 *   2. MONOTONICITY. If one host's set is a SUBSET of another's, its
 *      reachable set is a subset too. Records only ever add parent claims,
 *      and a path to the root that existed cannot stop existing -- so
 *      learning more can reveal a node and can never hide one. That is the
 *      CRDT-shaped half of sec 50 and nothing else here tests it.
 *
 *   3. SIBLING ORDER AGREES. Restricted to nodes two hosts both hold, the
 *      children of the root come back in the same order on both -- because
 *      the order is `(order, id)` and both hosts have both fields.
 *
 * THE GRAPH IS BUILT TO BE AWKWARD ON PURPOSE: a rooted chain, a two-node
 * cycle, an orphan whose parent is never issued by anybody, and one node id
 * claimed by two different issuers naming two different parents. Without the
 * cycle and the orphan, "reachable" is "everything" and the checks below
 * pass against a function that returns all ones.
 */

#define TREE_HOSTS 5u
#define TREE_NODES 8u
#define KIND_NODE 77u
#define STREAM_TREE 5u

static uint8_t tree_wire[TREE_NODES][FZN_RECORD_MAX_LEN];
static size_t tree_wire_len[TREE_NODES];

/* Which issuer signs each node, and what it says. `parent` 0 means the root;
 * 9 is an id nobody ever issues, so node 6 is a permanent orphan. Nodes 3 and
 * 4 name each other, which is the cycle. Node 7 re-uses node 2's id under a
 * different issuer and a different parent: two parent claims, unresolved. */
static const struct {
	uint8_t issuer, id, parent, order;
} tree_plan[TREE_NODES] = {
	{ 0u, 1u, 0u, 10u },  /* under the root */
	{ 0u, 2u, 1u, 20u },  /* under 1 */
	{ 1u, 5u, 2u, 30u },  /* under 2, so depth three */
	{ 1u, 3u, 4u, 40u },  /* cycle with 4 */
	{ 2u, 4u, 3u, 50u },  /* cycle with 3 */
	{ 2u, 6u, 9u, 60u },  /* orphan: parent 9 is never issued */
	{ 3u, 8u, 0u, 10u },  /* ties with node 1 on order, so id decides */
	{ 4u, 2u, 8u, 20u },  /* SECOND claim on id 2, parent 8 */
};

static void tree_id(uint8_t out[FZN_TREE_ID_LEN], uint8_t n)
{
	memset(out, n, FZN_TREE_ID_LEN);
}

/* Sign one node record. The body is `fzn_tree_body`'s, so the sim is the
 * consumer here in the way a consumer actually is: it chooses `kind`, and
 * the library reads the body. */
static void tree_make(struct sim_net *net, size_t n)
{
	uint8_t id[FZN_TREE_ID_LEN], parent[FZN_TREE_ID_LEN];
	uint8_t body[FZN_RECORD_BODY_MAX];
	uint8_t content[4] = { 0xC0, 0x0D, 0xE0, 0x00 };
	struct sim_host *h = &net->hosts[tree_plan[n].issuer];
	struct sim_signer signer;
	size_t body_len = 0u;

	tree_id(id, tree_plan[n].id);
	if (tree_plan[n].parent == 0u)
		memset(parent, 0, sizeof(parent));
	else
		tree_id(parent, tree_plan[n].parent);

	content[3] = (uint8_t)n;
	if (fzn_tree_body(parent, tree_plan[n].order, 1u, content, sizeof(content),
	                  body, sizeof(body), &body_len) != FZN_TREE_OK) {
		setup_faults++;
		return;
	}
	if (fzn_record_sign(h->pubkey, id, STREAM_TREE, KIND_NODE, (uint64_t)n + 1u, 1,
	                    body, body_len,
	                    sim_signer(&signer, &net->sign, h->pubkey),
	                    tree_wire[n], FZN_RECORD_MAX_LEN, &tree_wire_len[n])
	    != FZN_RECORD_OK)
		setup_faults++;
}

/* The nodes one host holds, opened from the wire it holds them on. A record
 * that will not open or will not verify is not counted -- which is what makes
 * the refusal counter below meaningful rather than decorative. */
/* `step` is what makes two hosts see the same SET in a different ORDER, and
 * it is not decoration. Walking the plan in index order puts every parent
 * ahead of its children in every host's array, so a reachability pass that
 * only ever propagated one level would answer correctly here and the
 * order-independence claim would be tested by nothing. Measured: with the
 * walk fixed at index order, removing the fixed point from
 * `fzn_tree_reachable` left this scenario green. A stride coprime with
 * TREE_NODES visits every index exactly once and hands each host a
 * different order. */
static size_t tree_nodes_of(struct sim_net *net, uint32_t holds, size_t step,
                            fzn_tree_node_t *out, fzn_record_t *recs,
                            size_t *plan_index)
{
	size_t count = 0u, k;

	for (k = 0; k < TREE_NODES; k++) {
		size_t n = (k * step + step) % TREE_NODES;

		if (!((holds >> n) & 1u))
			continue;
		if (fzn_record_open(tree_wire[n], tree_wire_len[n], &recs[count])
		    != FZN_RECORD_OK)
			continue;
		if (fzn_record_verify(recs[count], &net->sign) != FZN_RECORD_OK)
			continue;
		if (fzn_tree_open(recs[count], &out[count]) != FZN_TREE_OK)
			continue;
		if (plan_index != NULL)
			plan_index[count] = n;
		count++;
	}
	return count;
}

/* The reachable set as a bitmask over PLAN INDICES rather than over array
 * positions, so two hosts holding different subsets can be compared at all.
 * Comparing positions would compare two different things and agree by
 * accident on the empty case. */
static uint32_t tree_reach_mask(struct sim_net *net, uint32_t holds, size_t step)
{
	fzn_tree_node_t nodes[TREE_NODES];
	fzn_record_t recs[TREE_NODES];
	size_t plan_index[TREE_NODES];
	uint8_t mark[TREE_NODES];
	fzn_tree_walk_t walk;
	uint32_t mask = 0u;
	size_t count, k;

	count = tree_nodes_of(net, holds, step, nodes, recs, plan_index);
	if (count == 0u)
		return 0u;
	if (fzn_tree_reachable(nodes, count, mark, sizeof(mark), &walk) != FZN_TREE_OK)
		return 0u;

	/* The mask is over PLAN indices, so two hosts that walked the same set
	 * in different orders produce comparable answers. Deriving it from the
	 * walk position instead would compare two different things. */
	for (k = 0; k < count; k++)
		if (mark[k])
			mask |= (uint32_t)1u << plan_index[k];
	return mask;
}

static void scenario_tree(void)
{
	static struct sim_net net;
	uint32_t holds[TREE_HOSTS];
	uint32_t reach[TREE_HOSTS];
	unsigned round, pairs_same = 0, pairs_subset = 0, refused = 0;
	unsigned ordered_pairs = 0;
	size_t n, i, j;

	sim_init(&net, TREE_HOSTS, 0x7373u);
	net.loss_pct = 30;

	for (n = 0; n < TREE_NODES; n++)
		tree_make(&net, n);

	/* Each issuer starts holding its own. */
	for (i = 0; i < TREE_HOSTS; i++)
		holds[i] = 0u;
	for (n = 0; n < TREE_NODES; n++)
		holds[tree_plan[n].issuer] |= (uint32_t)1u << n;

	/* Lossy gossip. Deliberately stopped while hosts still disagree: a run
	 * long enough for everyone to hold everything would make the subset
	 * check vacuous, and the subset check is the one that tests
	 * monotonicity. */
	for (round = 0; round < 6u; round++) {
		for (i = 0; i < TREE_HOSTS; i++) {
			size_t p = (i + 1u + round) % TREE_HOSTS;

			if (p == i)
				continue;
			for (n = 0; n < TREE_NODES; n++) {
				if (!((holds[p] >> n) & 1u))
					continue;
				if ((sim_random(&net) % 100u) < net.loss_pct)
					continue;
				holds[i] |= (uint32_t)1u << n;
			}
		}
	}

	/* Strides 1, 3, 5, 7, 9 -- each coprime with TREE_NODES (8), so each
	 * host visits every held node exactly once in a different order. */
	for (i = 0; i < TREE_HOSTS; i++)
		reach[i] = tree_reach_mask(&net, holds[i], 2u * i + 1u);

	/* A host that holds everything is the reference: the cycle pair and the
	 * orphan must be unreachable, and the rooted chain reachable. Without
	 * this the two relational checks below are satisfied by a function that
	 * marks nothing. */
	{
		uint32_t all = ((uint32_t)1u << TREE_NODES) - 1u;
		uint32_t full = tree_reach_mask(&net, all, 3u);

		check((full & (1u << 0)) != 0u, "the node under the root was not reachable");
		check((full & (1u << 1)) != 0u, "the node one level down was not reachable");
		check((full & (1u << 2)) != 0u, "the node three deep was not reachable");
		check((full & (1u << 3)) == 0u, "a node in a cycle was reported reachable");
		check((full & (1u << 4)) == 0u, "the other node in the cycle was reachable");
		check((full & (1u << 5)) == 0u, "an orphan was reported reachable");
		check((full & (1u << 6)) != 0u, "the second root child was not reachable");
		check((full & (1u << 7)) != 0u,
		      "the contested id was not reachable by its second claim");
	}

	for (i = 0; i < TREE_HOSTS; i++) {
		for (j = i + 1u; j < TREE_HOSTS; j++) {
			if (holds[i] == holds[j]) {
				pairs_same++;
				check(reach[i] == reach[j],
				      "two hosts with the same records disagreed about the tree");
			}
			if ((holds[i] & ~holds[j]) == 0u && holds[i] != holds[j]) {
				pairs_subset++;
				check((reach[i] & ~reach[j]) == 0u,
				      "a host learned a record and lost a reachable node");
			}
			if ((holds[j] & ~holds[i]) == 0u && holds[i] != holds[j]) {
				pairs_subset++;
				check((reach[j] & ~reach[i]) == 0u,
				      "a host learned a record and lost a reachable node");
			}
		}
	}

	/* Sibling order, restricted to what two hosts both hold. */
	for (i = 0; i + 1u < TREE_HOSTS; i++) {
		fzn_tree_node_t na[TREE_NODES], nb[TREE_NODES];
		fzn_record_t ra[TREE_NODES], rb[TREE_NODES];
		const fzn_tree_node_t *ca[TREE_NODES], *cb[TREE_NODES];
		fzn_tree_walk_t wa, wb;
		uint32_t both = holds[i] & holds[i + 1u];
		uint8_t root[FZN_TREE_ID_LEN];
		size_t cnt_a, cnt_b, k;

		memset(root, 0, sizeof(root));
		/* DIFFERENT STRIDES ON PURPOSE. Handing both hosts the same walk
		 * order makes the comparison below agree whenever the two are
		 * wrong in the same way -- measured: with both at index order,
		 * dropping the insertion sort from `fzn_tree_children` left this
		 * scenario green, because unsorted output is identical on two
		 * hosts that built their arrays identically. */
		cnt_a = tree_nodes_of(&net, both, 1u, na, ra, NULL);
		cnt_b = tree_nodes_of(&net, both, 3u, nb, rb, NULL);
		check(cnt_a == cnt_b, "the same held set opened to two different counts");
		if (fzn_tree_children(na, cnt_a, root, ca, TREE_NODES, &wa) != FZN_TREE_OK ||
		    fzn_tree_children(nb, cnt_b, root, cb, TREE_NODES, &wb) != FZN_TREE_OK) {
			check(0, "children refused a valid call in the simulation");
			continue;
		}
		check(wa.emitted == wb.emitted, "two hosts saw different numbers of root children");
		for (k = 0; k < wa.emitted && k < wb.emitted; k++)
			check(memcmp(ca[k]->id, cb[k]->id, FZN_TREE_ID_LEN) == 0,
			      "two hosts ordered the root's children differently");

		/* AND AGAINST THE ORDER THE PLAN DICTATES, not only against each
		 * other. Nodes 1 and 8 are both children of the root at order 10,
		 * so the tie breaks on id and 1 must come first. Two hosts
		 * agreeing is satisfied by two hosts being wrong together; this
		 * is what says which answer is right. */
		if (wa.emitted == 2u) {
			check(ca[0]->id[0] == 1u,
			      "the lower id did not come first at an equal order");
			check(ca[1]->id[0] == 8u,
			      "the higher id did not come second at an equal order");
			ordered_pairs++;
		}
	}

	for (n = 0; n < TREE_NODES; n++)
		if (tree_wire_len[n] == 0u)
			refused++;
	check(refused == 0u, "a node record was never signed");

	/* COVERAGE FLOORS, because both relational checks above are satisfied
	 * by having no pairs to check. If the gossip ever converges fully every
	 * pair is identical and the subset check tests nothing; if it converges
	 * not at all there are no identical pairs and convergence tests
	 * nothing. Neither would fail, and neither would be reported -- which
	 * is the vacuous pass this file exists to refuse elsewhere. */
	check(pairs_same > 0u,
	      "no two hosts ended with the same records, so convergence was not tested");
	check(pairs_subset > 0u,
	      "no host's records were a subset of another's, so monotonicity was not tested");
	check(ordered_pairs > 0u,
	      "no pair held both root children, so sibling order was never checked");

	printf("  tree: %u nodes, %u hosts, %u identical pairs, %u subset pairs, "
	       "%u of %u reachable at full knowledge\n",
	       (unsigned)TREE_NODES, (unsigned)TREE_HOSTS, pairs_same, pairs_subset,
	       (unsigned)__builtin_popcount(tree_reach_mask(&net,
	                       ((uint32_t)1u << TREE_NODES) - 1u, 3u)),
	       (unsigned)TREE_NODES);
}

static void scenario_restart(void)
{
	struct sim_net net;
	fzn_agree_ops_t agree_ops = { sim_agree_public, sim_agree_shared, NULL };
	fzn_hash_ops_t hash_ops = { sim_hash, NULL };
	fzn_agree_secret_t sk[2];
	fzn_prekey_peer_t pinned[2];
	uint8_t secret[2][FZN_AGREE_SECRET_LEN];
	uint8_t record_bytes[2][FZN_PREKEY_LEN_TOTAL];
	fzn_prekey_record_t record[2];
	uint8_t key[2][FZN_AEAD_KEY_LEN], ckey[2][FZN_COMMITMENT_KEY_LEN];
	uint8_t send_chain[2][FZN_CHAIN_KEY_LEN], recv_chain[2][FZN_CHAIN_KEY_LEN];
	fzn_ratchet_chain_t sender, receiver, moved;
	uint8_t mk_send[FZN_MESSAGE_KEY_LEN], mk_recv[FZN_MESSAGE_KEY_LEN];
	uint8_t blob_secret[FZN_PERSIST_MAX], blob_peer[FZN_PERSIST_MAX];
	uint8_t blob_chain[FZN_PERSIST_MAX];
	size_t len_secret = 0, len_peer = 0, len_chain = 0;
	unsigned h, n;
	int ok = 1;

	sim_init(&net, 2, 0x7e51a27u);

	for (h = 0; h < 2u; h++) {
		unsigned i;

		memset(&sk[h], 0, sizeof(sk[h]));
		fzn_prekey_peer_init(&pinned[h]);
		for (i = 0; i < FZN_AGREE_SECRET_LEN; i++)
			secret[h][i] = (uint8_t)((h * 47u) + (i * 11u) + 5u);
		if (fzn_agree_secret_install(&sk[h], &agree_ops, secret[h]) != FZN_AGREE_OK)
			ok = 0;
	}
	for (h = 0; h < 2u; h++) {
		struct sim_signer who;
		const fzn_sign_ops_t *signer = sim_signer(&who, &net.sign, net.hosts[h].pubkey);

		if (fzn_prekey_issue(net.hosts[h].pubkey, fzn_agree_secret_public(&sk[h]),
		                     700u + h, signer, record_bytes[h]) != FZN_PREKEY_OK)
			ok = 0;
		if (fzn_prekey_open(record_bytes[h], FZN_PREKEY_LEN_TOTAL, &record[h])
		    != FZN_PREKEY_OK)
			ok = 0;
	}
	check(ok, "the restart scenario could not set its hosts up");
	if (!ok)
		return;

	check(fzn_prekey_pin(&pinned[0], record[1], &net.sign, FZN_TRUST_ADOPTED, net.now)
	              == FZN_PREKEY_OK, "host 0 could not pin host 1");
	check(fzn_prekey_pin(&pinned[1], record[0], &net.sign, FZN_TRUST_ADOPTED, net.now)
	              == FZN_PREKEY_OK, "host 1 could not pin host 0");
	check(fzn_session_establish(&sk[0], &agree_ops, &hash_ops, net.hosts[0].pubkey,
	                            net.hosts[1].pubkey, pinned[0].prekey, key[0], ckey[0])
	              == FZN_SESSION_OK, "host 0 could not establish");
	check(fzn_session_establish(&sk[1], &agree_ops, &hash_ops, net.hosts[1].pubkey,
	                            net.hosts[0].pubkey, pinned[1].prekey, key[1], ckey[1])
	              == FZN_SESSION_OK, "host 1 could not establish");
	check(fzn_session_chains(&hash_ops, key[0], net.hosts[0].pubkey, net.hosts[1].pubkey,
	                         send_chain[0], recv_chain[0]) == FZN_SESSION_OK,
	      "host 0 could not derive chains");
	check(fzn_session_chains(&hash_ops, key[1], net.hosts[1].pubkey, net.hosts[0].pubkey,
	                         send_chain[1], recv_chain[1]) == FZN_SESSION_OK,
	      "host 1 could not derive chains");

	/* THREE MESSAGES BEFORE THE RESTART, so the chain is somewhere other
	 * than its seed. A restart tested at sequence zero would pass against
	 * a chain blob that stored the seed and forgot the counter, which is
	 * the field a restart is most likely to lose. */
	fzn_ratchet_init(&sender, send_chain[0], 0);
	fzn_ratchet_init(&receiver, recv_chain[1], 0);
	for (n = 0; n < 3u; n++) {
		check(fzn_ratchet_advance(&hash_ops, &sender, n, mk_send, &moved, NULL, 0, NULL,
		                          NULL) == FZN_RATCHET_OK, "the sender could not advance");
		sender = moved;
		check(fzn_ratchet_advance(&hash_ops, &receiver, n, mk_recv, &moved, NULL, 0, NULL,
		                          NULL) == FZN_RATCHET_OK,
		      "the receiver could not advance");
		receiver = moved;
		check(memcmp(mk_send, mk_recv, FZN_MESSAGE_KEY_LEN) == 0,
		      "a message did not agree before the restart");
	}

	/* WHAT HOST 1 WRITES DOWN. Three of the four kinds: its own agreement
	 * secret, the peer it pinned, and the receive chain it is following.
	 * The trust anchor rides inside the peer blob, and its provenance is
	 * asserted below rather than assumed. */
	check(fzn_persist_secret_pack(&sk[1], blob_secret, sizeof(blob_secret), &len_secret)
	              == FZN_PERSIST_OK, "host 1 could not persist its agreement secret");
	check(fzn_persist_peer_pack(&pinned[1], blob_peer, sizeof(blob_peer), &len_peer)
	              == FZN_PERSIST_OK, "host 1 could not persist the peer it pinned");
	check(fzn_persist_chain_pack(&receiver, blob_chain, sizeof(blob_chain), &len_chain)
	              == FZN_PERSIST_OK, "host 1 could not persist its receive chain");

	/*
	 * AND THE OPENERS WRITE EVERY BYTE THEY CLAIM, which is what makes the
	 * scrubs below honest for the peer and the chain.
	 *
	 * Removing either of those two scrubs changes no result -- measured --
	 * because their restore overwrites the same storage, so there is no
	 * leftover for a later assertion to pass on. That is only true while
	 * the restore is TOTAL, and nothing said it was. A field an opener
	 * forgot would keep whatever the struct held, which on a real host is
	 * the previous run's value or uninitialised stack, and a scenario like
	 * this one would never see it.
	 *
	 * So it is asserted as a relationship rather than a value: open the
	 * same blob into two buffers poisoned differently, and the results
	 * must be identical. A byte the opener LEAKS from the caller's buffer
	 * differs, and neither buffer had to be right for the difference to
	 * show.
	 *
	 * WHAT IT DOES AND DOES NOT COVER, measured rather than claimed. The
	 * openers call `fzn_prekey_peer_init` and `fzn_ratchet_init` first, so
	 * a field one of them forgot comes back as init's value from BOTH
	 * poisons -- identical, and this check stays green. That is correct
	 * and not a hole: with the init in place a forgotten field is a wrong
	 * VALUE, which is `persist_test.c`'s business, rather than a leak of
	 * whatever the caller had. Dropping the init alone also stays green,
	 * because the openers do write every field. Dropping the init AND
	 * forgetting a field is caught, which is the pair that constitutes the
	 * leak. Stated because the first draft of this comment claimed the
	 * check caught a forgotten field outright, and it does not.
	 */
	{
		fzn_prekey_peer_t peer_a, peer_b;
		fzn_ratchet_chain_t chain_a, chain_b;

		memset(&peer_a, 0x00, sizeof(peer_a));
		memset(&peer_b, 0xa5, sizeof(peer_b));
		check(fzn_persist_peer_open(blob_peer, len_peer, &peer_a) == FZN_PERSIST_OK
		              && fzn_persist_peer_open(blob_peer, len_peer, &peer_b)
		                 == FZN_PERSIST_OK,
		      "the peer blob did not open twice");
		check(memcmp(&peer_a, &peer_b, sizeof(peer_a)) == 0,
		      "opening one peer blob into two differently-poisoned buffers gave two "
		      "different peers, so the opener leaves a field holding whatever was "
		      "there before");

		memset(&chain_a, 0x00, sizeof(chain_a));
		memset(&chain_b, 0xa5, sizeof(chain_b));
		check(fzn_persist_chain_open(blob_chain, len_chain, &chain_a) == FZN_PERSIST_OK
		              && fzn_persist_chain_open(blob_chain, len_chain, &chain_b)
		                 == FZN_PERSIST_OK,
		      "the chain blob did not open twice");
		check(memcmp(&chain_a, &chain_b, sizeof(chain_a)) == 0,
		      "opening one chain blob into two differently-poisoned buffers gave two "
		      "different chains");
	}

	/* THE RESTART. Everything host 1 held in memory is destroyed -- not
	 * zeroed, which a struct might read as a valid empty, but filled with
	 * a byte that is wrong in every field. */
	memset(&sk[1], 0xdd, sizeof(sk[1]));
	memset(&pinned[1], 0xdd, sizeof(pinned[1]));
	memset(&receiver, 0xdd, sizeof(receiver));
	memset(key[1], 0xdd, sizeof(key[1]));
	memset(ckey[1], 0xdd, sizeof(ckey[1]));
	memset(recv_chain[1], 0xdd, sizeof(recv_chain[1]));
	memset(secret[1], 0xdd, sizeof(secret[1]));

	/* THE CONTROL, and the scenario is worth nothing without it. Host 0
	 * sends message 3; a host whose state really is gone must not be able
	 * to follow it. */
	check(fzn_ratchet_advance(&hash_ops, &sender, 3u, mk_send, &moved, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_OK, "the sender could not advance past the restart");
	sender = moved;
	{
		uint8_t lost[FZN_MESSAGE_KEY_LEN];
		fzn_ratchet_chain_t scratch = receiver, went;
		int followed = fzn_ratchet_advance(&hash_ops, &scratch, 3u, lost, &went, NULL, 0,
		                                   NULL, NULL) == FZN_RATCHET_OK
		               && memcmp(lost, mk_send, FZN_MESSAGE_KEY_LEN) == 0;

		check(!followed, "a host whose memory was scrubbed still followed the "
		                 "conversation, so the scrub did not land and everything "
		                 "below proves nothing");
	}

	/* AND A SECOND CONTROL, FOR THE OTHER HALF. The one above proves the
	 * CHAIN is gone and says nothing about the secret -- so with the
	 * secret left in memory, the re-establish below would pass on what
	 * survived rather than on what was written down, and the two look
	 * identical from the output. Found by removing the secret's scrub and
	 * watching the scenario stay green: one control does not cover two
	 * claims. */
	{
		uint8_t stale[FZN_AEAD_KEY_LEN], stale_ck[FZN_COMMITMENT_KEY_LEN];
		/* THE PEER'S REAL PREKEY, not the scrubbed `pinned[1]`. With
		 * the scrubbed one this control cannot fire at all: the
		 * establish fails on the garbage prekey whether or not the
		 * secret survived, so it would be testing the conjunction of
		 * the two scrubs and reporting it as either. Measured -- with
		 * the secret's scrub removed it stayed green until this line
		 * used host 0's live public key. */
		int derived = fzn_session_establish(&sk[1], &agree_ops, &hash_ops,
		                                    net.hosts[1].pubkey, net.hosts[0].pubkey,
		                                    fzn_agree_secret_public(&sk[0]), stale,
		                                    stale_ck) == FZN_SESSION_OK
		              && memcmp(stale, key[0], FZN_AEAD_KEY_LEN) == 0;

		check(!derived, "a host whose secret was scrubbed still derived the session "
		                "root, so the re-establish below proves nothing");
	}

	/* AND BACK. Only the blobs are read; nothing else survived. */
	check(fzn_persist_secret_open(blob_secret, len_secret, &agree_ops, &sk[1])
	              == FZN_PERSIST_OK, "the agreement secret did not come back");
	check(fzn_persist_peer_open(blob_peer, len_peer, &pinned[1]) == FZN_PERSIST_OK,
	      "the pinned peer did not come back");
	check(fzn_persist_chain_open(blob_chain, len_chain, &receiver) == FZN_PERSIST_OK,
	      "the receive chain did not come back");

	/* PROVENANCE SURVIVES, which is the field a restart is most likely to
	 * launder: a peer taken on faith must not come back claiming it was
	 * confirmed out of band. */
	check(fzn_trust_source_of(&pinned[1].trust) == FZN_TRUST_ADOPTED,
	      "a peer adopted on faith came back reporting out-of-band confirmation");

	/* THE SUFFICIENCY CLAIM, HALF ONE: the restored secret and peer are
	 * enough to derive the same session root again. */
	check(fzn_session_establish(&sk[1], &agree_ops, &hash_ops, net.hosts[1].pubkey,
	                            net.hosts[0].pubkey, pinned[1].prekey, key[1], ckey[1])
	              == FZN_SESSION_OK, "the restarted host could not re-establish");
	check(memcmp(key[0], key[1], FZN_AEAD_KEY_LEN) == 0,
	      "the restarted host derived a different session root, so what it wrote "
	      "down was not enough to come back");
	check(memcmp(ckey[0], ckey[1], FZN_COMMITMENT_KEY_LEN) == 0,
	      "the restarted host derived a different commitment key");

	/* HALF TWO: the restored chain is where the conversation is, not back
	 * at its seed. This is the half re-deriving cannot supply. */
	check(fzn_ratchet_advance(&hash_ops, &receiver, 3u, mk_recv, &moved, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_OK, "the restarted host could not advance its chain");
	receiver = moved;
	check(memcmp(mk_send, mk_recv, FZN_MESSAGE_KEY_LEN) == 0,
	      "the restarted host derived a different key for the first message after "
	      "the restart, so the conversation is over");

	/* AND IT KEEPS GOING. One message could agree by luck of a chain that
	 * happened to land right; four more cannot. */
	for (n = 4u; n < 8u; n++) {
		check(fzn_ratchet_advance(&hash_ops, &sender, n, mk_send, &moved, NULL, 0, NULL,
		                          NULL) == FZN_RATCHET_OK, "the sender stalled");
		sender = moved;
		check(fzn_ratchet_advance(&hash_ops, &receiver, n, mk_recv, &moved, NULL, 0, NULL,
		                          NULL) == FZN_RATCHET_OK, "the restarted host stalled");
		receiver = moved;
		check(memcmp(mk_send, mk_recv, FZN_MESSAGE_KEY_LEN) == 0,
		      "a later message after the restart did not agree, so the restored "
		      "chain landed right once by luck rather than being the chain");
	}

	for (h = 0; h < 2u; h++)
		fzn_agree_secret_wipe(&sk[h]);
}

int main(void)
{
	scenario_mesh();
	scenario_replay();
	scenario_revocation();
	scenario_revocation_split();
	scenario_withdrawal();
	scenario_stale();
	scenario_unauthorised();
	scenario_delegation();
	scenario_lossy();
	scenario_splice();
	scenario_substitution();
	scenario_tamper();
	scenario_distribution();
	scenario_state();
	scenario_forgery();
	scenario_join();
	scenario_fidelity();
	scenario_session();
	scenario_restart();
	scenario_absence();
	scenario_estate();
	scenario_tree();

	/* Asserted ONCE, not once per fetch. See `digest_dropped`. */
	check(total_digest_dropped == 0, "a simulation digest buffer was too small");
	check(setup_faults == 0,
	      "the simulation could not mint, open or sign something it set up");

	printf("network_test: %d checks, %d failure(s); fuzznet %s\n", checks, failures,
	       fzn_version_string());
	return failures == 0 ? 0 : 1;
}
