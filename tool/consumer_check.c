/* What a consumer does, compiled two ways, so that neither quietly breaks.
 *
 * project.md sec 10 step 5 makes netcfgd's agent the first real consumer,
 * and sec 7 says how it will take this library: a git submodule, built from
 * source, with these sources compiled into that project's own objects and
 * no shipped archive. Nothing tested that. The suites all build from inside
 * the tree, which is the one arrangement a consumer never has.
 *
 * Two failures it is here to catch, and both are silent:
 *
 *   - a header added to a module and not to the Makefile's HDRS, so
 *     `make install` ships an incomplete set and a consumer's include
 *     fails on a machine that is not this one. HDRS is hand-maintained and
 *     nothing else reads it back.
 *   - a relative include between modules that resolves inside the tree and
 *     not once installed -- chain.h reaches constant_time.h that way, and
 *     the two layouts are not the same shape.
 *
 * It is deliberately dull. It calls one function from each module and
 * checks the answers it can check, because its job is to prove the headers
 * and sources go together, not to test behaviour the suites already cover.
 *
 * A FAILURE PRINTS ITSELF. See `FAIL` below: each check keeps its own small
 * code, and the code and line are written to stderr rather than encoded in
 * the exit status, which is 1 for every failure.
 *
 * WHAT THIS REPLACED, because the reasoning is worth keeping and one half of
 * it was wrong. The codes used to BE the report, so reading a failure meant
 * finding the number in this file. A comment here also claimed the scheme
 * was nearly exhausted -- "213 distinct codes, seven remain" -- and both
 * figures were wrong: 213 counted every `return <literal>` line including
 * the vtable callbacks above, whose `return 1;` is the seam's success
 * convention, and "seven" was 255 minus 248, **a ceiling minus a maximum
 * presented as remaining capacity**. Measured, there were 204 sites, 174
 * distinct codes, and 81 free values.
 *
 * So the change was made for the OUTPUT and not for the exhaustion. It does
 * retire a real edge as a side effect -- a 256th code would have exited 0
 * and reported a pass -- but that edge was 81 codes away and was not the
 * reason. project.md sec 49 carries the wrong arithmetic as its own instance
 * of a class this tree signalled to the workspace the same day.
 *
 * Compiled twice by `make installcheck`: once against an installed tree
 * with angle-bracket includes, once against the source tree with module
 * paths, which are the two arrangements a consumer can be in.
 */

#ifdef FZN_CONSUMER_INSTALLED
#include <fuzznet/chain/chain.h>
#include <fuzznet/chain/manifest.h>
#include <fuzznet/chain/authz.h>
#include <fuzznet/blob/blob.h>
#include <fuzznet/ratchet/ratchet.h>
#include <fuzznet/prekey/prekey.h>
#include <fuzznet/session/agree.h>
#include <fuzznet/session/session.h>
#include <fuzznet/persist/persist.h>
#include <fuzznet/spool/spool.h>
#include <fuzznet/spool/plan.h>
/* The default backend's header ships whenever the subsystem is built, so the
 * installcheck gate requires this file to include it -- a header named in
 * HDRS and included by nothing passes that gate as loudly as one a consumer
 * exercises. It declares a type and one function over `persist.h`'s own
 * types and pulls in no POSIX of its own, so including it costs a consumer
 * that never calls it exactly nothing. */
#ifdef FZN_PERSIST_FILE_ON
#include <fuzznet/persist/persist_file.h>
#endif
#ifdef FZN_SPOOL_FILE_ON
#include <fuzznet/spool/spool_file.h>
#endif
#include <fuzznet/chain/revocation.h>
#include <fuzznet/chunk/reassembly.h>
#include <fuzznet/chunk/split.h>
#include <fuzznet/constant_time/constant_time.h>
#include <fuzznet/frame/freshness.h>
#include <fuzznet/local/peer.h>
#include <fuzznet/local/vocabulary.h>
#include <fuzznet/session/aead.h>
#include <fuzznet/session/commitment.h>
#include <fuzznet/session/random.h>
#include <fuzznet/record/journal.h>
#include <fuzznet/log/log.h>
#include <fuzznet/record/record.h>
#include <fuzznet/tree/tree.h>
#include <fuzznet/link/link.h>
#include <fuzznet/sched/sched.h>
#include <fuzznet/record/sync.h>
#include <fuzznet/state/state.h>
#include <fuzznet/trust/trust.h>
#include <fuzznet/session/random_system.h>
#include <fuzznet/version/version.h>
#include <fuzznet/wire/relay.h>
#include <fuzznet/wire/seal.h>
#else
#include "chain/chain.h"
#include "chain/manifest.h"
#include "chain/authz.h"
#include "blob/blob.h"
#include "ratchet/ratchet.h"
#include "prekey/prekey.h"
#include "session/agree.h"
#include "session/session.h"
#include "persist/persist.h"
#include "spool/spool.h"
#include "spool/plan.h"
#ifdef FZN_PERSIST_FILE_ON
#include "persist/persist_file.h"
#endif
#ifdef FZN_SPOOL_FILE_ON
#include "spool/spool_file.h"
#endif
#include "chain/revocation.h"
#include "chunk/reassembly.h"
#include "chunk/split.h"
#include "constant_time/constant_time.h"
#include "frame/freshness.h"
#include "local/peer.h"
#include "local/vocabulary.h"
#include "session/aead.h"
#include "session/commitment.h"
#include "session/random.h"
#include "record/journal.h"
#include "log/log.h"
#include "record/record.h"
#include "tree/tree.h"
#include "link/link.h"
#include "sched/sched.h"
#include "record/sync.h"
#include "state/state.h"
#include "trust/trust.h"
#include "session/random_system.h"
#include "version/version.h"
#include "wire/bytes.h"
#include "wire/relay.h"
#include "wire/seal.h"
#endif

/* The optional Monocypher bindings, which `install` puts in the tree
 * alongside the rest.
 *
 * They are here because the HDRS check above them found them missing: with
 * the bindings built, `make installcheck` refused, saying it would "pass
 * whatever those headers did". It was right. Two headers were installable and
 * unverifiable, in the configuration that is hardest to notice because the
 * default build never produces it.
 *
 * THE INCLUDES ARE UNCONDITIONAL AND THE USE BELOW IS NOT, which is the
 * point rather than an inconsistency. None of these three headers includes
 * <monocypher.h> -- they declare vtables over this library's own types --
 * so they compile in the arrangement that has no Monocypher at all, and
 * that is the arrangement in which they most need checking: they ship
 * whether or not the consumer has the primitive, and a header nobody can
 * compile without a dependency it does not name is the fault this whole
 * target exists to find. Guarding the includes as well as the use put them
 * back out of reach of the only arm that could have caught it -- the HDRS
 * check greps this file for a NAME, so a mention inside a dead #ifdef
 * satisfied it and proved nothing.
 *
 * What still needs the define is the reference to the vtable OBJECTS, which
 * needs them linked. */
#ifdef FZN_CONSUMER_INSTALLED
#include <fuzznet/chain/sign_monocypher.h>
#include <fuzznet/session/hash_monocypher.h>
#include <fuzznet/session/aead_monocypher.h>
#include <fuzznet/session/agree_monocypher.h>
#else
#include "chain/sign_monocypher.h"
#include "session/hash_monocypher.h"
#include "session/aead_monocypher.h"
#include "session/agree_monocypher.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int always_good(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	(void)ctx;
	(void)pubkey;
	(void)msg;
	(void)msg_len;
	(void)sig;
	return 1;
}

/* A mixing function and a toy AEAD, so the blob path below can be exercised
 * rather than merely compiled. Neither is cryptography and neither pretends
 * to be -- blob/test/blob_test.c is where the properties are checked. What
 * this file asks is narrower and is the thing an installed header can get
 * wrong: that the declarations, the constants and the sources agree, and
 * that a consumer holding only the installed prefix can call them. */
static int consumer_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in,
                         size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	h ^= (uint64_t)out_len;
	h *= 0x100000001b3ull;
	for (i = 0; i < in_len; i++) {
		h ^= in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
	return 1;
}

/* Record identity for `fzn_revocation_admit`, over the same seam every other
 * hash in this consumer uses. */
static const fzn_hash_ops_t CONSUMER_HASH = { consumer_hash, NULL };

static void consumer_seal(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
                          const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad,
                          size_t aad_len, uint8_t *text, size_t text_len,
                          uint8_t tag[FZN_AEAD_TAG_LEN])
{
	size_t i;

	(void)ctx;
	(void)aad;
	(void)aad_len;
	for (i = 0; i < text_len; i++)
		text[i] = (uint8_t)(text[i] ^ key[i % FZN_AEAD_KEY_LEN] ^ nonce[i % FZN_AEAD_NONCE_LEN]);
	for (i = 0; i < FZN_AEAD_TAG_LEN; i++)
		tag[i] = (uint8_t)(key[i] ^ nonce[i] ^ (uint8_t)text_len);
}

static int consumer_open(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
                         const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad,
                         size_t aad_len, uint8_t *text, size_t text_len,
                         const uint8_t tag[FZN_AEAD_TAG_LEN])
{
	uint8_t want[FZN_AEAD_TAG_LEN];
	size_t i;

	(void)ctx;
	(void)aad;
	(void)aad_len;
	for (i = 0; i < FZN_AEAD_TAG_LEN; i++)
		want[i] = (uint8_t)(key[i] ^ nonce[i] ^ (uint8_t)text_len);
	if (memcmp(want, tag, FZN_AEAD_TAG_LEN) != 0)
		return 0;
	for (i = 0; i < text_len; i++)
		text[i] = (uint8_t)(text[i] ^ key[i % FZN_AEAD_KEY_LEN] ^ nonce[i % FZN_AEAD_NONCE_LEN]);
	return 1;
}

/* A toy key agreement: commutative, which is the one property the block below
 * asserts. Not Diffie-Hellman -- a consumer supplies the real thing, and
 * session/test/agree_monocypher_test.c exercises X25519 behind this seam. */
static int consumer_public_of(void *ctx, uint8_t out[FZN_AGREE_PUBLIC_LEN],
                              const uint8_t secret[FZN_AGREE_SECRET_LEN])
{
	unsigned i;

	(void)ctx;
	for (i = 0; i < FZN_AGREE_PUBLIC_LEN; i++)
		out[i] = (uint8_t)(secret[i] ^ 0x3cu);
	return 1;
}

static int consumer_agree(void *ctx, uint8_t out[FZN_AGREE_SHARED_LEN],
                          const uint8_t secret[FZN_AGREE_SECRET_LEN],
                          const uint8_t peer[FZN_AGREE_PUBLIC_LEN])
{
	unsigned i;

	(void)ctx;
	/* Commutative because `peer` is the other side's secret xored with a
	 * constant, so undoing it before combining gives both sides the same
	 * answer. */
	for (i = 0; i < FZN_AGREE_SHARED_LEN; i++)
		out[i] = (uint8_t)(secret[i] ^ (peer[i] ^ 0x3cu));
	return 1;
}

/* The signing half. A consumer that builds a record or mints a hop needs one,
 * and the installed headers are what this file exercises. */
static int always_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	uint32_t acc = 0x9e3779b9u;
	size_t i;

	(void)ctx;
	for (i = 0; i < msg_len; i++)
		acc = (acc * 31u) + msg[i];
	for (i = 0; i < FZN_SIG_LEN; i++)
		sig[i] = (uint8_t)(acc >> ((i % 4u) * 8u));
	return 1;
}

/* WHERE A FAILURE SAYS WHAT IT WAS.
 *
 * Each check used to `return` its own small integer and the exit status was
 * the whole report, so reading a failure meant finding that number in this
 * file. The number is better on stderr: it costs nothing, it can carry the
 * LINE as well, and the arrangement that failed is already printed by the
 * Makefile above it.
 *
 * The codes are unchanged and still identify a check -- 174 of them, reused
 * where sites belong to one check. What changed is that they are printed
 * rather than encoded in eight bits of exit status, which also retires the
 * edge the previous comment here was about: a 256th code would have exited
 * 0 and reported a pass. That is now impossible rather than distant, and it
 * is a side effect of the change and not its reason.
 *
 * Returns 1 for every failure, because `make` asks only whether this
 * process failed and the detail it used to encode is now in the output. */
#define FAIL(code)                                                             \
	do {                                                                   \
		fprintf(stderr, "consumer_check: failed check %d, line %d\n",  \
		        (code), __LINE__);                                     \
		return 1;                                                      \
	} while (0)

int main(void)
{
	uint8_t hop_bytes[FZN_HOP_LEN];
	fzn_sign_ops_t sign = { always_good, always_sign, NULL };
	fzn_replay_entry_t window_storage[4];
	fzn_replay_window_t window;
	fzn_revocation_store_t store;
	fzn_revocation_t store_storage[4];
	fzn_chain_hop_t hop;
	fzn_chain_t chain;
	fzn_split_t plan;
	uint8_t root[FZN_PUBKEY_LEN], nonce[FZN_NONCE_LEN];
	fzn_cap_id_t cap;
	uint8_t equal_a[4] = { 0 }, equal_b[4] = { 0 };

	memset(root, 0x01, sizeof(root));
	memset(cap.b, 0x02, sizeof(cap.b));
	memset(nonce, 0x03, sizeof(nonce));

	if (!fzn_ct_memeq(equal_a, equal_b, sizeof(equal_a)))
		FAIL(1);

	/* The version a consumer compiled against must be the one it linked.
	 * This is the comparison version.h asks every consumer to make at
	 * startup, made here so that the installed arrangement proves the
	 * function is reachable and answers -- an installed header declaring a
	 * function nothing calls would link fine and mean nothing. */
	/* The journal, reached through installed headers: a record's position
	 * is admitted, and admitting it twice is refused. An installed header
	 * declaring functions nothing calls would link and mean nothing. */
	{
		fzn_journal_t journal;
		fzn_journal_entry_t slots[2];
		uint8_t issuer[FZN_PUBKEY_LEN];

		memset(issuer, 0x77, sizeof(issuer));
		if (fzn_journal_init(&journal, slots, 2) != FZN_JOURNAL_OK)
			FAIL(30);
		/* FOLLOWING AN ISSUER IS A DECISION. Admitting no longer adopts
		 * one, so a consumer anchors first -- which is the step this
		 * file exists to show. */
		if (fzn_journal_anchor(&journal, issuer, 0, 0) != FZN_JOURNAL_OK)
			FAIL(30);
		if (fzn_journal_admit(&journal, issuer, 0, 1) != FZN_JOURNAL_OK)
			FAIL(31);
		if (fzn_journal_admit(&journal, issuer, 0, 1) != FZN_JOURNAL_ERR_DUPLICATE)
			FAIL(32);
		if (fzn_journal_next(&journal, issuer, 0) != 2)
			FAIL(33);
		{
			fzn_sync_position_t theirs;
			fzn_sync_request_t want;
			fzn_sync_plan_t sync_plan;

			memcpy(theirs.issuer, issuer, FZN_PUBKEY_LEN);
			theirs.stream = 0;
			theirs.received = 4;
			if (fzn_sync_plan_fetch(&journal, &theirs, 1, 8, &want, 1, &sync_plan) !=
			    FZN_SYNC_OK)
				FAIL(34);
			if (sync_plan.request_count != 1 || want.from != 2 || want.count != 3)
				FAIL(35);
		}
	}

	/* And the state layer: a value set, superseded by its own issuer, and
	 * refused to another's. Reached through installed headers. */
	{
		fzn_state_t st;
		fzn_state_entry_t slots[2];
		fzn_record_t r;
		fzn_sign_ops_t ops;
		uint8_t alice[FZN_PUBKEY_LEN], mallory[FZN_PUBKEY_LEN];
		uint8_t subject[FZN_SUBJECT_LEN];
		static uint8_t wire[FZN_RECORD_MAX_LEN];
		static const uint8_t body[] = "v";
		size_t wrote = 0;

		if (fzn_state_init(&st, slots, 2) != FZN_STATE_OK)
			FAIL(40);
		memset(&ops, 0, sizeof(ops));
		ops.sign = always_sign;
		memset(alice, 0x01, sizeof(alice));
		memset(mallory, 0x09, sizeof(mallory));
		memset(subject, 0x02, sizeof(subject));

		/* A RECORD IS BUILT, NOT FILLED IN. This block used to memset a
		 * struct and set its fields; a record is a view over the bytes
		 * its signature covers now, so a consumer signs one and opens
		 * it -- which is what this file exists to demonstrate. */
		if (fzn_record_sign(alice, subject, 0, 1, 1, 1, body, sizeof(body), &ops, wire,
		                    sizeof(wire), &wrote) != FZN_RECORD_OK)
			FAIL(41);
		if (fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
			FAIL(41);
		if (fzn_state_apply(&st, &r) != FZN_STATE_OK)
			FAIL(41);

		if (fzn_record_sign(alice, subject, 0, 1, 2, 1, body, sizeof(body), &ops, wire,
		                    sizeof(wire), &wrote) != FZN_RECORD_OK ||
		    fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
			FAIL(42);
		if (fzn_state_apply(&st, &r) != FZN_STATE_OK)
			FAIL(42);

		if (fzn_record_sign(alice, subject, 0, 1, 1, 1, body, sizeof(body), &ops, wire,
		                    sizeof(wire), &wrote) != FZN_RECORD_OK ||
		    fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
			FAIL(43);
		if (fzn_state_apply(&st, &r) != FZN_STATE_ERR_STALE)
			FAIL(43);

		if (fzn_record_sign(mallory, subject, 0, 1, 99, 1, body, sizeof(body), &ops, wire,
		                    sizeof(wire), &wrote) != FZN_RECORD_OK ||
		    fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
			FAIL(44);
		if (fzn_state_apply(&st, &r) != FZN_STATE_ERR_CONFLICT)
			FAIL(44);
		if (fzn_state_count(&st) != 1)
			FAIL(45);
	}

	/* Trust on first use, through installed headers: adopted once, and a
	 * second different root refused. */
	{
		fzn_trust_t anchor;
		uint8_t k1[FZN_PUBKEY_LEN], k2[FZN_PUBKEY_LEN];

		memset(k1, 0x31, sizeof(k1));
		memset(k2, 0x32, sizeof(k2));
		fzn_trust_init(&anchor);
		if (fzn_trust_root(&anchor) != NULL)
			FAIL(50);
		if (fzn_trust_adopt(&anchor, k1, 7) != FZN_TRUST_OK)
			FAIL(51);
		if (fzn_trust_adopt(&anchor, k2, 8) != FZN_TRUST_ERR_ANCHORED)
			FAIL(52);
		if (memcmp(fzn_trust_root(&anchor), k1, FZN_PUBKEY_LEN) != 0)
			FAIL(53);
	}

	/* The log, through installed headers: append past capacity, and the
	 * evicted sequence must answer GONE rather than merely absent. */
	{
		fzn_log_t lg;
		fzn_log_entry_t slots[2];
		fzn_record_t r;
		fzn_journal_t jr;
		fzn_journal_entry_t jslots[2];
		fzn_sign_ops_t ops;
		const fzn_log_entry_t *e;
		uint8_t who[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN];
		static uint8_t wire[FZN_RECORD_MAX_LEN];
		static const uint8_t b[] = "x";
		size_t wrote = 0;

		if (fzn_log_init(&lg, slots, 2) != FZN_LOG_OK)
			FAIL(60);
		if (fzn_journal_init(&jr, jslots, 2) != FZN_JOURNAL_OK)
			FAIL(60);
		memset(&ops, 0, sizeof(ops));
		ops.sign = always_sign;
		memset(who, 0x41, sizeof(who));
		memset(subject, 0, sizeof(subject));
		if (fzn_journal_anchor(&jr, who, 0, 0) != FZN_JOURNAL_OK)
			FAIL(60);

		for (uint64_t q = 1; q <= 3; q++) {
			if (fzn_record_sign(who, subject, 0, 1, q, 1, b, sizeof(b), &ops, wire,
			                    sizeof(wire), &wrote) != FZN_RECORD_OK ||
			    fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
				FAIL(61);
			if (fzn_log_append(&lg, &r) != FZN_LOG_OK)
				FAIL(61);
			if (fzn_journal_admit(&jr, who, 0, q) != FZN_JOURNAL_OK)
				FAIL(61);
		}
		/* GONE COMES FROM THE POSITION, so the journal is a parameter --
		 * a log alone cannot tell what retention removed from what never
		 * arrived. */
		if (fzn_log_get(&lg, &jr, who, 0, 1, &e) != FZN_LOG_ERR_GONE)
			FAIL(62);
		if (fzn_log_get(&lg, &jr, who, 0, 9, &e) != FZN_LOG_ERR_ABSENT)
			FAIL(63);
		if (fzn_log_dropped(&lg) != 1)
			FAIL(64);
	}

	/* The hop budget, through installed headers: an inflated claim must be
	 * clamped rather than believed. */
	{
		uint8_t hop_frame[64];
		uint8_t budget = 0;

		memset(hop_frame, 0, sizeof(hop_frame));
		hop_frame[0] = 1;
		hop_frame[1] = 255;
		if (fzn_relay_budget(hop_frame, sizeof(hop_frame), FZN_RELAY_MAX_HOPS,
		                     &budget) != FZN_RELAY_OK)
			FAIL(70);
		if (budget != FZN_RELAY_MAX_HOPS)
			FAIL(71);
		if (fzn_relay_spend(hop_frame, sizeof(hop_frame), FZN_RELAY_MAX_HOPS) !=
		    FZN_RELAY_OK)
			FAIL(72);
		if (hop_frame[1] != FZN_RELAY_MAX_HOPS - 1u)
			FAIL(73);
	}

	/* Link selection, through installed headers: two classes over the same
	 * two links must disagree, which is the property the module exists for. */
	{
		fzn_sched_candidate_t pair[2] = {
			{ 1, 10, 20, 150, 1500, 1 },
			{ 2, 10, 4000, 1, 1500, 1 },
		};
		fzn_class_t voice = { 200, 0, 0, 0, 10, 0 };
		fzn_class_t important = { 0, 50, 0, 0, 0, 100 };
		size_t pick = 99;

		if (fzn_sched_select(pair, 2, &voice, &pick) != FZN_SCHED_OK || pick != 0)
			FAIL(80);
		if (fzn_sched_select(pair, 2, &important, &pick) != FZN_SCHED_OK || pick != 1)
			FAIL(81);
	}

	/* Link tracking feeding link selection, through installed headers: a
	 * link that declared itself quick and measures slow must lose. */
	{
		fzn_link_table_t lt;
		fzn_link_entry_t rows[2];
		fzn_sched_candidate_t snap[2];
		fzn_class_t any = { 0, 0, 0, 0, 1, 0 };
		size_t pick = 99, n;

		if (fzn_link_table_init(&lt, rows, 2) != FZN_LINK_OK)
			FAIL(90);
		if (fzn_link_register(&lt, 1, 0, 10, 0, 1500) != FZN_LINK_OK)
			FAIL(91);
		if (fzn_link_register(&lt, 2, 0, 60, 0, 1500) != FZN_LINK_OK)
			FAIL(92);
		for (int k = 0; k < 40; k++) {
			if (fzn_link_observe_ack(&lt, 1, 5000, (uint64_t)k) != FZN_LINK_OK)
				FAIL(93);
		}
		{
			size_t dropped = 1;

			n = fzn_link_snapshot(&lt, snap, 2, &dropped);
			if (n != 2 || dropped != 0)
				FAIL(94);
		}
		if (fzn_sched_select(snap, n, &any, &pick) != FZN_SCHED_OK || pick != 1)
			FAIL(95);
	}

	if (fzn_version_number() != (unsigned long)FZN_VERSION_NUMBER)
		FAIL(20);
	if (strcmp(fzn_version_string(), FZN_VERSION_STRING) != 0)
		FAIL(21);

	if (fzn_split_plan(100, 8, &plan) != FZN_SPLIT_OK || plan.chunks != 13)
		FAIL(2);

	/*
	 * REASSEMBLY, WHICH THIS FILE HAS NEVER TOUCHED despite being one of
	 * the two halves a consumer takes from `chunk/`. The property walked
	 * is the one a consumer reaches by FORGETTING -- ignoring the return
	 * code and reading the range count as the answer.
	 *
	 * A plan for a message the table does not hold must be ABSENT and not
	 * OK-with-nothing, because OK with zero ranges reads as "I have every
	 * chunk". That is the fail-open direction, and a zeroed sender with id
	 * zero is the exact query that reaches a free slot -- release and
	 * expire both zero a slot, so no other query can.
	 */
	{
		fzn_reasm_t table;
		fzn_partial_t slot;
		uint8_t slot_bytes[64];
		uint8_t nobody[FZN_SENDER_LEN];
		fzn_reasm_range_t ranges[4];
		size_t range_count = 99u;

		memset(&slot, 0, sizeof(slot));
		memset(nobody, 0, sizeof(nobody));
		if (fzn_reasm_slot_init(&slot, slot_bytes, sizeof(slot_bytes)) != FZN_REASM_OK)
			FAIL(96);
		if (fzn_reasm_init(&table, &slot, 1u, 1u, 1000u) != FZN_REASM_OK)
			FAIL(97);
		if (fzn_reasm_plan_want(&table, nobody, 0u, 8u, ranges, 4u, &range_count)
		    != FZN_REASM_ERR_ABSENT)
			FAIL(98);
		/* And a bound a caller forgot is refused rather than read as no
		 * bound, which is `record/sync.h`'s rule that every planner in
		 * this library inherits. */
		if (fzn_reasm_plan_want(&table, nobody, 0u, 0u, ranges, 4u, &range_count)
		    != FZN_REASM_ERR_MALFORMED)
			FAIL(99);
	}

	/* The horizon is set beside the capacity, because they are two halves
	 * of one sizing decision: the window must hold what can arrive within
	 * the longest expiry it will accept. */
	if (fzn_replay_init(&window, window_storage, 4, 4000) != FZN_FRESH_OK)
		FAIL(3);
	if (fzn_replay_admit(&window, nonce, 2000, FZN_EXPIRY_REQUIRED, 1000) != FZN_FRESH_OK)
		FAIL(4);
	if (fzn_replay_admit(&window, nonce, 2000, FZN_EXPIRY_REQUIRED, 1000) !=
	    FZN_FRESH_ERR_REPLAY)
		FAIL(5);

	if (fzn_revocation_store_init(&store, store_storage, 4) != FZN_CHAIN_OK)
		FAIL(6);

	/* A REAL HOP, MINTED AND OPENED. This used to point `signed_region` at
	 * the literal "a signed region" while filling the fields separately --
	 * which demonstrated to every consumer reading this file exactly the
	 * shape that made a captured signature reusable with rewritten fields.
	 * A hop is a view over the bytes its signature covers now, so there is
	 * no separate set of fields to disagree. */
	{
		uint8_t grantee[FZN_PUBKEY_LEN];

		memset(grantee, 0x09, sizeof(grantee));
		if (fzn_chain_mint(root, grantee, &cap, 100, FZN_NO_EXPIRY, 0, &sign,
		                   hop_bytes) != FZN_CHAIN_OK)
			FAIL(7);
		if (fzn_hop_open(hop_bytes, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK)
			FAIL(7);
	}

	if (fzn_chain_verify(&hop, 1, root, &cap, 2000, &sign, &store, &chain) != FZN_CHAIN_OK)
		FAIL(7);
	if (chain.hop_count != 1)
		FAIL(8);

	/* REVOCATION, END TO END, AND THIS FILE COULD NOT SEE IT BEFORE.
	 *
	 * `installcheck` guarantees coverage at HEADER granularity: it refuses
	 * when an installed header is not named here, and a header that IS
	 * named passes as loudly whether the functions it declares are called
	 * or not. `chain/revocation.h` was included and nothing in it was
	 * called except `fzn_revocation_store_init`, so the consumer-facing
	 * gate could not see a change to the revocation API at all. Measured:
	 * giving `fzn_revocation_covers` a bogus extra parameter left
	 * `make installcheck` at exit 0 while `make test` failed with 15
	 * errors -- the gate whose whole job is to catch a break a consumer
	 * would hit was the one that missed it.
	 *
	 * So the sequence a consumer actually performs is performed: issue a
	 * record, open it, ask before, admit, ask after, and hand the store to
	 * the verifier. Each step's arity and types are now the consumer's
	 * problem, which is the only way this gate can have an opinion. */
	{
		uint8_t rev_bytes[FZN_REVOCATION_LEN];
		uint8_t grantee[FZN_PUBKEY_LEN];
		fzn_revocation_record_t rec;

		memset(grantee, 0x09, sizeof(grantee));
		if (fzn_revocation_issue(root, &cap, grantee, 1500, &sign, rev_bytes) !=
		    FZN_CHAIN_OK)
			FAIL(100);
		if (fzn_revocation_open(rev_bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
			FAIL(101);
		if (fzn_revocation_covers(&store, fzn_revocation_issuer(rec),
		                          fzn_revocation_capability(rec),
		                          fzn_revocation_grantee(rec)) != 0)
			FAIL(102);
		if (fzn_revocation_admit(&store, fzn_revocation_offer_root(rec), root, &sign, &CONSUMER_HASH,
		                         NULL) != FZN_CHAIN_OK)
			FAIL(103);
		if (store.used != 1)
			FAIL(104);
		if (fzn_revocation_covers(&store, fzn_revocation_issuer(rec),
		                          fzn_revocation_capability(rec),
		                          fzn_revocation_grantee(rec)) != 1)
			FAIL(105);

		/* The store reaches the verifier, which is the property the
		 * signature change of 2026-08-27 exists for: the same hop that
		 * verified above must now be refused. */
		if (fzn_chain_verify(&hop, 1, root, &cap, 2000, &sign, &store, &chain) !=
		    FZN_CHAIN_ERR_REVOKED)
			FAIL(106);

		/* And NULL still means "no revocations known", which is what
		 * the old `NULL, 0` said and what a consumer holding no store
		 * relies on. */
		if (fzn_chain_verify(&hop, 1, root, &cap, 2000, &sign, NULL, &chain) !=
		    FZN_CHAIN_OK)
			FAIL(107);
	}

	/* GRANTOR-REVOKES-DESCENDANT, END TO END, for the reason the block
	 * above states about header granularity. `fzn_revocation_admit` and
	 * `fzn_revocation_merge` changed shape on 2026-08-28 -- both take an
	 * `fzn_revocation_offer_t` now, because a batch whose members are
	 * issued by different keys cannot be an array of records with one
	 * chain beside it -- and a consumer that only ever built root offers
	 * would compile against the new header and exercise none of it.
	 *
	 * So the sequence a consumer performs is performed: mint a delegable
	 * grant, delegate it onward, have the MIDDLE key withdraw the
	 * capability from the leaf, admit that with the chain that entitles
	 * it, and watch the two-hop chain be refused. */
	{
		uint8_t mid_bytes[FZN_HOP_LEN], leaf_bytes[FZN_HOP_LEN];
		uint8_t rev_bytes[FZN_REVOCATION_LEN];
		uint8_t mid[FZN_PUBKEY_LEN], leaf[FZN_PUBKEY_LEN];
		fzn_chain_hop_t pair[2];
		fzn_revocation_record_t rec;
		fzn_revocation_store_t estate;
		fzn_revocation_t estate_storage[4];
		fzn_chain_err_t merged = FZN_CHAIN_OK;
		fzn_revocation_offer_t offer;

		memset(mid, 0x21, sizeof(mid));
		memset(leaf, 0x22, sizeof(leaf));

		if (fzn_revocation_store_init(&estate, estate_storage, 4) != FZN_CHAIN_OK)
			FAIL(130);
		if (fzn_chain_mint(root, mid, &cap, 100, FZN_NO_EXPIRY, 1, &sign, mid_bytes) !=
		    FZN_CHAIN_OK)
			FAIL(131);
		if (fzn_hop_open(mid_bytes, FZN_HOP_LEN, &pair[0]) != FZN_CHAIN_OK)
			FAIL(132);
		if (fzn_chain_delegate(pair, 1, root, &cap, 2000, leaf, FZN_NO_EXPIRY, 0, &sign,
		                       NULL, leaf_bytes) != FZN_CHAIN_OK)
			FAIL(133);
		if (fzn_hop_open(leaf_bytes, FZN_HOP_LEN, &pair[1]) != FZN_CHAIN_OK)
			FAIL(134);
		if (fzn_chain_verify(pair, 2, root, &cap, 2000, &sign, &estate, &chain) !=
		    FZN_CHAIN_OK)
			FAIL(135);

		/* The middle key withdraws the capability from the leaf. */
		if (fzn_revocation_issue(mid, &cap, leaf, 1500, &sign, rev_bytes) !=
		    FZN_CHAIN_OK)
			FAIL(136);
		if (fzn_revocation_open(rev_bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
			FAIL(137);

		/* With no chain it is a stranger's record, refused exactly as
		 * it always was -- which is what makes the offer below the
		 * thing that changed. */
		if (fzn_revocation_admit(&estate, fzn_revocation_offer_root(rec), root, &sign, &CONSUMER_HASH,
		                         NULL) != FZN_CHAIN_ERR_WRONG_ROOT)
			FAIL(138);

		offer = fzn_revocation_offer_chain(rec, pair, 1);
		if (fzn_revocation_merge(&estate, &offer, 1, root, &sign, &CONSUMER_HASH, &merged, NULL) != 1 ||
		    merged != FZN_CHAIN_OK)
			FAIL(139);
		if (estate.used != 1)
			FAIL(140);
		if (fzn_chain_verify(pair, 2, root, &cap, 2000, &sign, &estate, &chain) !=
		    FZN_CHAIN_ERR_REVOKED)
			FAIL(141);

		/* And the entitled set is derived from the chain rather than
		 * supplied: the same store says nothing about the middle key's
		 * own one-hop chain, which the middle key is not an ancestor
		 * of. */
		if (fzn_chain_verify(pair, 1, root, &cap, 2000, &sign, &estate, &chain) !=
		    FZN_CHAIN_OK)
			FAIL(142);

		/* The verify-side predicate directly, so a change to its arity
		 * or its types is the consumer's problem too. */
		{
			uint8_t revoked[FZN_CHAIN_MAX_HOPS];

			fzn_revocation_covers_chain(&estate, pair, 2, &cap, revoked);
			if (revoked[0] != 0 || revoked[1] != 1)
				FAIL(143);
		}
	}


	/* WITHDRAWAL, END TO END, for the reason the two blocks around it
	 * state: a header named in HDRS and called by nothing passes this gate
	 * as loudly as one a consumer really exercises. `fzn_revocation_admit`
	 * and `fzn_revocation_merge` grew a hash seam on 2026-09-03 and the
	 * record grew a `supersedes` field, so a consumer that only ever
	 * revoked would compile against the new header and exercise none of
	 * it.
	 *
	 * THE SEQUENCE IS THE ONE A CONSUMER PERFORMS, in the order it
	 * performs it: revoke, discover the pair is revoked, withdraw, watch
	 * it come back, then try to revoke again -- which is where a consumer
	 * meets the chaining rule as a REFUSAL rather than as a paragraph, and
	 * is the step most likely to be got wrong. The last leg is the
	 * withdrawal arriving before the revocation it undoes, which on a mesh
	 * is ordinary rather than exceptional. */
	{
		uint8_t rev_bytes[FZN_REVOCATION_LEN];
		uint8_t wd_bytes[FZN_REVOCATION_LEN];
		uint8_t again_bytes[FZN_REVOCATION_LEN];
		uint8_t id[FZN_REVOCATION_ID_LEN];
		uint8_t grantee[FZN_PUBKEY_LEN];
		fzn_revocation_record_t rec;
		fzn_revocation_store_t store;
		fzn_revocation_t storage[4];

		memset(grantee, 0x31, sizeof(grantee));
		if (fzn_revocation_store_init(&store, storage, 4) != FZN_CHAIN_OK)
			FAIL(260);

		/* Revoke, and read the pair back as revoked. */
		if (fzn_revocation_issue(root, &cap, grantee, 1000, &sign, rev_bytes) !=
		    FZN_CHAIN_OK)
			FAIL(261);
		if (fzn_revocation_open(rev_bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
			FAIL(262);
		if (fzn_revocation_is_withdrawal(rec))
			FAIL(263);
		if (fzn_revocation_admit(&store, fzn_revocation_offer_root(rec), root, &sign,
		                         &CONSUMER_HASH, NULL) != FZN_CHAIN_OK)
			FAIL(264);
		if (fzn_revocation_covers(&store, root, &cap, grantee) != 1)
			FAIL(265);

		/* THE RECORD'S IDENTITY IS THE CONSUMER'S TO COMPUTE, over the
		 * whole record and with the same seam it hands to `admit`. A
		 * consumer that hashed the signed range instead would build a
		 * withdrawal naming nothing this store holds. */
		if (!consumer_hash(NULL, id, sizeof(id), rev_bytes, FZN_REVOCATION_LEN))
			FAIL(266);

		if (fzn_revocation_issue_withdrawal(root, &cap, grantee, 2000, id, &sign,
		                                    wd_bytes) != FZN_CHAIN_OK)
			FAIL(267);
		if (fzn_revocation_open(wd_bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
			FAIL(268);
		if (!fzn_revocation_is_withdrawal(rec))
			FAIL(269);
		if (memcmp(fzn_revocation_supersedes(rec), id, sizeof(id)) != 0)
			FAIL(270);
		if (fzn_revocation_admit(&store, fzn_revocation_offer_root(rec), root, &sign,
		                         &CONSUMER_HASH, NULL) != FZN_CHAIN_OK)
			FAIL(271);

		/* THE TWO PREDICATES ANSWER DIFFERENTLY NOW, and a consumer
		 * that reads the wrong one loops. `covers` is the
		 * authorization question and says no; `known` is the
		 * replication question -- do I still need to fetch this -- and
		 * says yes, because the entry is still here. */
		if (fzn_revocation_covers(&store, root, &cap, grantee) != 0)
			FAIL(272);
		if (fzn_revocation_known(&store, root, &cap, grantee) != 1)
			FAIL(273);
		if (store.used != 1)
			FAIL(274);

		/* RE-REVOKING WITH `issue` IS REFUSED, and this is the step a
		 * consumer gets wrong. The record it mints names nothing, and
		 * against a store holding a withdrawal for this triple that is
		 * exactly the un-chained re-revocation the design forbids. The
		 * error is its own so the consumer can tell it from a forgery.
		 *
		 * A LATER `issued_at` IS WHAT REACHES THE RULE. At the
		 * original instant the record is byte-identical to the first
		 * and is refused one line earlier, as the stale copy it cannot
		 * be told apart from. */
		if (fzn_revocation_issue(root, &cap, grantee, 4000, &sign, again_bytes) !=
		    FZN_CHAIN_OK)
			FAIL(275);
		if (fzn_revocation_open(again_bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
			FAIL(276);
		if (fzn_revocation_admit(&store, fzn_revocation_offer_root(rec), root, &sign,
		                         &CONSUMER_HASH, NULL) != FZN_CHAIN_ERR_UNKNOWN_TARGET)
			FAIL(277);
		if (fzn_revocation_covers(&store, root, &cap, grantee) != 0)
			FAIL(278);

		/* And the call that is correct for this case. */
		if (fzn_revocation_reissue(root, &cap, grantee, 5000, id, &sign,
		                           again_bytes) != FZN_CHAIN_OK)
			FAIL(279);
		if (fzn_revocation_open(again_bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
			FAIL(280);
		if (fzn_revocation_admit(&store, fzn_revocation_offer_root(rec), root, &sign,
		                         &CONSUMER_HASH, NULL) != FZN_CHAIN_OK)
			FAIL(281);
		if (fzn_revocation_covers(&store, root, &cap, grantee) != 1)
			FAIL(282);
		if (store.used != 1)
			FAIL(283);
	}

	/* THE WITHDRAWAL THAT ARRIVES FIRST, which is a separate store because
	 * the point is a host that has never held the revocation. On a mesh
	 * this is what happens whenever the withdrawing host has a shorter
	 * path to a peer than the revoking host did. */
	{
		uint8_t rev_bytes[FZN_REVOCATION_LEN];
		uint8_t wd_bytes[FZN_REVOCATION_LEN];
		uint8_t id[FZN_REVOCATION_ID_LEN];
		uint8_t grantee[FZN_PUBKEY_LEN];
		fzn_revocation_record_t rec;
		fzn_revocation_store_t store;
		fzn_revocation_t storage[4];

		memset(grantee, 0x32, sizeof(grantee));
		if (fzn_revocation_store_init(&store, storage, 4) != FZN_CHAIN_OK)
			FAIL(284);

		/* Minted in order, delivered in the other. */
		if (fzn_revocation_issue(root, &cap, grantee, 1000, &sign, rev_bytes) !=
		    FZN_CHAIN_OK)
			FAIL(285);
		if (!consumer_hash(NULL, id, sizeof(id), rev_bytes, FZN_REVOCATION_LEN))
			FAIL(286);
		if (fzn_revocation_issue_withdrawal(root, &cap, grantee, 2000, id, &sign,
		                                    wd_bytes) != FZN_CHAIN_OK)
			FAIL(287);

		if (fzn_revocation_open(wd_bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
			FAIL(288);
		if (fzn_revocation_admit(&store, fzn_revocation_offer_root(rec), root, &sign,
		                         &CONSUMER_HASH, NULL) != FZN_CHAIN_OK)
			FAIL(289);

		/* The revocation it undoes, arriving late. It must not take
		 * effect -- not "take effect and then be undone", which would
		 * leave a window in which the host was revoked. */
		if (fzn_revocation_open(rev_bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
			FAIL(290);
		if (fzn_revocation_admit(&store, fzn_revocation_offer_root(rec), root, &sign,
		                         &CONSUMER_HASH, NULL) != FZN_CHAIN_OK)
			FAIL(291);
		if (fzn_revocation_covers(&store, root, &cap, grantee) != 0)
			FAIL(292);
		if (store.used != 1)
			FAIL(293);
	}

	/* THE MANIFEST, END TO END, for the reason the block above states: a
	 * header named in HDRS and called by nothing passes this gate as
	 * loudly as one a consumer really exercises. So the whole sequence
	 * runs -- follow, issue from the issuer's own store, open, admit
	 * against a host that holds nothing, read the deficit back, then admit
	 * the revocation and watch the deficit drain. */
	{
		static uint8_t man_bytes[FZN_MANIFEST_LEN(4)];
		fzn_manifest_state_t manifest;
		fzn_manifest_issuer_t followed[2];
		fzn_manifest_deficit_t missing[4];
		fzn_manifest_pair_t want[4];
		fzn_manifest_record_t man;
		fzn_revocation_store_t fresh;
		fzn_revocation_t fresh_storage[4];
		fzn_revocation_record_t rec;
		uint8_t rev_bytes[FZN_REVOCATION_LEN];
		uint8_t grantee[FZN_PUBKEY_LEN];
		size_t man_len = 0, dropped = 1;

		memset(grantee, 0x09, sizeof(grantee));
		if (fzn_manifest_init(&manifest, followed, 2, missing, 4) != FZN_MANIFEST_OK)
			FAIL(110);
		if (fzn_manifest_follow(&manifest, root) != FZN_MANIFEST_OK)
			FAIL(111);

		/* `store` holds the one revocation the block above admitted,
		 * so the manifest derived from it names exactly that pair. */
		if (fzn_manifest_issue(root, &store, &sign, man_bytes, sizeof(man_bytes),
		                       &man_len) != FZN_MANIFEST_OK)
			FAIL(112);
		if (man_len != FZN_MANIFEST_LEN(1))
			FAIL(113);
		if (fzn_manifest_open(man_bytes, man_len, &man) != FZN_MANIFEST_OK)
			FAIL(114);
		if (fzn_manifest_count(man) != 1)
			FAIL(115);

		/* Admitted by a host that knows of no revocations, which is
		 * the fresh joiner: the pair it names is a deficit. */
		if (fzn_manifest_admit(&manifest, NULL, man, &sign) != FZN_MANIFEST_OK)
			FAIL(116);
		if (fzn_manifest_pending(&manifest, root) != 1)
			FAIL(117);
		if (fzn_manifest_overflowed(&manifest, root) != 0)
			FAIL(118);
		if (fzn_manifest_deficit(&manifest, root, want, 4, &dropped) != 1 || dropped != 0)
			FAIL(119);
		if (!fzn_ct_memeq(want[0].grantee, grantee, FZN_PUBKEY_LEN))
			FAIL(120);

		/* THE RESUMABLE FORM, AND `from = 0` MUST BE THE PLAIN ONE.
		 * `fzn_manifest_deficit` is defined as this call's zero case, so
		 * a consumer that has adopted the cursor and one that has not
		 * must get the same answer for the same table. Checked against
		 * the result above rather than restated, so the two cannot drift
		 * apart without this failing. */
		{
			fzn_manifest_pair_t resumed[4];
			size_t from_dropped = 1, next = 1;

			memset(resumed, 0, sizeof(resumed));
			if (fzn_manifest_deficit_from(&manifest, root, 0, resumed, 4,
			                              &from_dropped, &next) != 1)
				FAIL(36);
			if (from_dropped != 0)
				FAIL(37);
			/* A table that fits leaves nothing for a next request,
			 * and `next` says so rather than pointing past the end. */
			if (next != 0)
				FAIL(38);
			if (!fzn_ct_memeq(resumed[0].grantee, want[0].grantee,
			                  FZN_PUBKEY_LEN))
				FAIL(39);
		}

		/* And the revocation arriving settles it, which is the whole
		 * of the parameter `fzn_revocation_admit` gained. */
		if (fzn_revocation_store_init(&fresh, fresh_storage, 4) != FZN_CHAIN_OK)
			FAIL(121);
		if (fzn_revocation_issue(root, &cap, grantee, 1500, &sign, rev_bytes) !=
		    FZN_CHAIN_OK)
			FAIL(122);
		if (fzn_revocation_open(rev_bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
			FAIL(123);
		if (fzn_revocation_admit(&fresh, fzn_revocation_offer_root(rec), root, &sign, &CONSUMER_HASH,
		                         &manifest) != FZN_CHAIN_OK)
			FAIL(124);
		if (fzn_manifest_pending(&manifest, root) != 0)
			FAIL(125);

		/* THE SERVE SIDE, and it must come after the admit above:
		 * `fresh` is the store that now holds the one revocation, so a
		 * peer naming that triple is answered "held" and a peer naming a
		 * grantee nobody revoked is answered "not held" rather than
		 * being left out -- the per-item verdict the header argues for.
		 * Placed before the admit in the first draft, where it failed
		 * against an empty store, which is the check working. */
		{
			fzn_manifest_deficit_t asked[2];
			uint8_t holds[2] = { 9u, 9u };
			fzn_manifest_offer_t offer;

			memset(asked, 0, sizeof(asked));
			memcpy(asked[0].issuer, root, FZN_PUBKEY_LEN);
			asked[0].capability = want[0].capability;
			memcpy(asked[0].grantee, want[0].grantee, FZN_PUBKEY_LEN);
			asked[1] = asked[0];
			memset(asked[1].grantee, 0xEE, FZN_PUBKEY_LEN);

			memset(&offer, 0, sizeof(offer));
			if (fzn_manifest_plan_offer(&fresh, asked, 2, holds, 2,
			                            &offer) != FZN_MANIFEST_OK)
				FAIL(46);
			if (offer.examined != 2 || offer.truncated != 0)
				FAIL(47);
			if (holds[0] != 1u || holds[1] != 0u)
				FAIL(48);
			if (offer.held != 1)
				FAIL(49);

			/* A ceiling of zero is refused rather than read as
			 * unlimited, which is the rule a serve path needs
			 * because the peer chooses the count. */
			if (fzn_manifest_plan_offer(&fresh, asked, 2, holds, 0,
			                            &offer) != FZN_MANIFEST_ERR_MALFORMED)
				FAIL(54);
		}
		if (fzn_manifest_err_str(FZN_MANIFEST_ERR_UNKNOWN_ISSUER) == NULL)
			FAIL(126);
	}

	/* The two modules added after this file was written, and the reason
	 * `installcheck` now checks its own coverage: both were installed and
	 * neither was included here, so a break in either would have passed. */
	{
		fzn_peer_t peer;

		memset(&peer, 0, sizeof(peer));
		if (fzn_peer_groups_parse("Groups:\t20 24\n", 14, &peer) != 1)
			FAIL(9);
		if (peer.group_count != 2 || !peer.groups_known)
			FAIL(10);
		if (fzn_peer_is_member(&peer, 24) != 1)
			FAIL(11);
		if (fzn_peer_group_verdict(&peer, 999) != FZN_PEER_NOT_MEMBER)
			FAIL(12);

		/* The vocabulary bound over the same peer: a table that
		 * names the verb for a group it holds admits it, and an
		 * empty table denies. */
		{
			static const uint8_t verb[] = "status";
			const fzn_verb_rule_t rules[] = {
				{ 24, verb, sizeof(verb) - 1u }
			};

			if (fzn_vocabulary_admit(&peer, verb, sizeof(verb) - 1u,
			                         rules, 1) != FZN_PEER_MEMBER)
				FAIL(22);
			if (fzn_vocabulary_admit(&peer, verb, sizeof(verb) - 1u,
			                         rules, 0) != FZN_PEER_NOT_MEMBER)
				FAIL(23);
		}

		/* THE ASSERTION THAT WAS HERE COULD NOT FAIL, and then it could
		 * fail for the wrong reason. It read
		 *
		 *     FZN_DERIVED_LEN != FZN_AEAD_KEY_LEN + FZN_COMMITMENT_LEN
		 *
		 * which was the same expression twice while `FZN_DERIVED_LEN`
		 * was defined as that sum -- `wire/test/constants_test.c`
		 * deleted its identical copy for exactly that reason. When the
		 * commitment split into a root derivation and a per-frame one,
		 * the derived block became key plus COMMITMENT KEY, and the
		 * tautology started failing while nothing was wrong.
		 *
		 * A check that cannot fail, and then fails spuriously the first
		 * time the code around it moves, is worse than no check. What
		 * this file exists to prove is that the installed headers build
		 * and link, which the calls above do. */
	}

	/* THESE TWO BLOCKS WERE INSIDE `#ifdef FZN_CONSUMER_MONOCYPHER`, and
	 * neither needs it: one opens a frame with a NULL AEAD to reach the
	 * argument guard, the other drives the nonce source. So in a default
	 * `make installcheck` -- the arrangement almost everyone runs --
	 * neither was COMPILED, and this file reported that headers and sources
	 * agree without having asked them about the frame path at all.
	 *
	 * Found when `fzn_seal_open` grew two parameters and every other caller
	 * in the tree failed to build while this one did not. A check that
	 * cannot fail is a shape this project keeps finding; a check that is
	 * not compiled is the same shape with the compiler's help removed. */
	/* The blob path, walked end to end rather than compiled: seal two
	 * leaves, hash them, build the tree, take the root, and verify an
	 * inclusion proof against it. A header named in HDRS and called by
	 * nothing passes this gate as loudly as one a consumer exercises,
	 * which is the same argument the manifest block above makes. */
	{
		fzn_hash_ops_t bhash = { consumer_hash, NULL };
		fzn_aead_ops_t baead = { consumer_seal, consumer_open, NULL };
		fzn_blob_tree_t tree;
		uint8_t ckey[FZN_BLOB_KEY_LEN];
		uint8_t plain[64];
		uint8_t sealed[FZN_BLOB_SEALED_MAX];
		uint8_t leaf[2][FZN_BLOB_HASH_LEN];
		uint8_t blob_root[FZN_BLOB_HASH_LEN];
		uint8_t siblings[FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
		uint8_t back[64];
		size_t sealed_len = 0, back_len = 0;
		unsigned sibling_count = 0;
		unsigned i;

		memset(ckey, 0x3c, sizeof(ckey));
		memset(plain, 0x5e, sizeof(plain));

		fzn_blob_tree_init(&tree);
		for (i = 0; i < 2u; i++) {
			plain[0] = (uint8_t)i;
			if (fzn_blob_leaf_seal(&bhash, &baead, ckey, i, plain, sizeof(plain),
			                       sealed, sizeof(sealed), &sealed_len)
			    != FZN_BLOB_OK)
				FAIL(130);
			if (sealed_len != sizeof(plain) + FZN_BLOB_LEAF_OVERHEAD)
				FAIL(131);
			if (fzn_blob_leaf_hash(&bhash, sealed, sealed_len, leaf[i]) != FZN_BLOB_OK)
				FAIL(132);
			if (fzn_blob_tree_push(&bhash, &tree, leaf[i]) != FZN_BLOB_OK)
				FAIL(133);
		}
		if (fzn_blob_leaf_open(&bhash, &baead, ckey, 1u, sealed, sealed_len, back,
		                       sizeof(back), &back_len) != FZN_BLOB_OK)
			FAIL(134);
		if (back_len != sizeof(plain) || back[0] != 1u)
			FAIL(135);
		if (fzn_blob_tree_root(&bhash, &tree, blob_root) != FZN_BLOB_OK)
			FAIL(136);
		if (fzn_blob_proof_build(&bhash, leaf[0], 2u, 1u, siblings, sizeof(siblings),
		                         &sibling_count) != FZN_BLOB_OK)
			FAIL(137);
		if (fzn_blob_proof_verify(&bhash, leaf[1], 1u, 2u, siblings, sibling_count,
		                          blob_root) != FZN_BLOB_OK)
			FAIL(138);
		/* And a refusal, so the acceptance above is not the only
		 * outcome this consumer can observe. */
		if (fzn_blob_proof_verify(&bhash, leaf[0], 1u, 2u, siblings, sibling_count,
		                          blob_root) != FZN_BLOB_ERR_PROOF)
			FAIL(139);
	}

	/* PER-PEER-PER-CAPABILITY OPT-IN, WHICH THIS TREE ALREADY HAS UNDER
	 * ANOTHER NAME, and this block is here to prove that rather than let
	 * project.md assert it.
	 *
	 * fuzzypickles carries `share_location` as a named boolean on their
	 * peer record with `fzp_peer_may_share_location` as its gate. A
	 * library serving three consumers cannot have a field per subsystem,
	 * so the generic form is forced -- and `state/` already is it: a cell
	 * keyed on a 32-byte SUBJECT and a u32 KIND. Put the peer's key in
	 * the subject and the capability in the kind and the map exists.
	 *
	 * Granted, read back as permitted, withdrawn by its own issuer, read
	 * back as absent. The withdrawal is the half a boolean gets right by
	 * accident and a map has to be shown doing.
	 */
	{
		fzn_state_t opt;
		fzn_state_entry_t opt_slots[2];
		fzn_record_t r;
		fzn_sign_ops_t ops;
		const fzn_state_entry_t *cell;
		uint8_t owner[FZN_PUBKEY_LEN];
		uint8_t peer_key[FZN_SUBJECT_LEN];
		static uint8_t wire[FZN_RECORD_MAX_LEN];
		static const uint8_t yes[] = "1";
		/* A capability the consumer names; this library never reads it. */
		const uint32_t KIND_SHARE_LOCATION = 0x10cu;
		size_t wrote = 0;

		memset(&ops, 0, sizeof(ops));
		ops.sign = always_sign;
		memset(owner, 0x51, sizeof(owner));
		memset(peer_key, 0x52, sizeof(peer_key));

		if (fzn_state_init(&opt, opt_slots, 2) != FZN_STATE_OK)
			FAIL(170);
		if (fzn_record_sign(owner, peer_key, 0, KIND_SHARE_LOCATION, 1, 1, yes,
		                    sizeof(yes), &ops, wire, sizeof(wire), &wrote)
		    != FZN_RECORD_OK)
			FAIL(171);
		if (fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
			FAIL(172);
		if (fzn_state_apply(&opt, &r) != FZN_STATE_OK)
			FAIL(173);

		cell = fzn_state_get(&opt, peer_key, KIND_SHARE_LOCATION);
		if (!cell || !cell->live)
			FAIL(174);
		/* And a DIFFERENT capability for the same peer is a different
		 * cell, which is the whole of "per capability". */
		if (fzn_state_get(&opt, peer_key, KIND_SHARE_LOCATION + 1u) != NULL)
			FAIL(175);

		if (fzn_record_sign(owner, peer_key, 0, KIND_SHARE_LOCATION, 2, 1, yes,
		                    sizeof(yes), &ops, wire, sizeof(wire), &wrote)
		    != FZN_RECORD_OK)
			FAIL(176);
		if (fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
			FAIL(177);
		if (fzn_state_clear(&opt, &r) != FZN_STATE_OK)
			FAIL(178);
		if (fzn_state_get(&opt, peer_key, KIND_SHARE_LOCATION) != NULL)
			FAIL(179);
	}

	/* The piece store, which is what a consumer assembling a blob out of
	 * order needs and should not have to write. The property walked here
	 * is the one that makes it safe to point at a stranger: an unverified
	 * leaf never reaches the backend. */
	{
		fzn_spool_t sp;
		uint8_t map[FZN_SPOOL_BITMAP_LEN(2)];
		uint8_t fake_root[FZN_BLOB_HASH_LEN];
		fzn_spool_ops_t nops;

		memset(&nops, 0, sizeof(nops));
		memset(fake_root, 0x77, sizeof(fake_root));
		/* A backend with no write is refused at open rather than at the
		 * first placement. */
		if (fzn_spool_open(&sp, fake_root, 2u, map, sizeof(map), &nops)
		    != FZN_SPOOL_ERR_MALFORMED)
			FAIL(240);
		/* And a blob past the ceiling costs a comparison, not a bitmap. */
		if (fzn_spool_open(&sp, fake_root, (uint64_t)FZN_SPOOL_MAX_LEAVES + 1u, map,
		                   sizeof(map), &nops) != FZN_SPOOL_ERR_MALFORMED
		    && fzn_spool_open(&sp, fake_root, (uint64_t)FZN_SPOOL_MAX_LEAVES + 1u, map,
		                      sizeof(map), &nops) != FZN_SPOOL_ERR_TOO_LARGE)
			FAIL(241);

		/* The transfer planners, which is what a consumer needs to
		 * ask a peer for what it lacks. The property walked is the
		 * one a consumer would get wrong: a request naming nothing
		 * must buy nothing, which is the defect `record/sync` shipped
		 * once and this library must not ship twice. */
		{
			fzn_spool_range_t ranges[2];
			size_t plan_n = 99u;

			if (fzn_spool_open(&sp, fake_root, 2u, map, sizeof(map), &nops)
			    != FZN_SPOOL_ERR_MALFORMED)
				FAIL(245);
			memset(&sp, 0, sizeof(sp));
			sp.present = map;
			sp.leaves = 2u;
			sp.present_len = sizeof(map);
			map[0] = 0x03u;
			if (fzn_spool_plan_offer(&sp, NULL, 0u, 100u, ranges, 2u, &plan_n)
			    != FZN_SPOOL_OK)
				FAIL(246);
			if (plan_n != 0u)
				FAIL(247);
			/* And a bound a caller forgot is refused rather than
			 * read as no bound. */
			if (fzn_spool_plan_want(&sp, 0u, 0u, ranges, 2u, &plan_n)
			    != FZN_SPOOL_ERR_MALFORMED)
				FAIL(248);
		}

#ifdef FZN_SPOOL_FILE_ON
		/* And the default backend refuses a path it cannot open rather
		 * than handing back ops that fail later. A consumer checking
		 * NULL here is checking the whole of it. */
		{
			fzn_spool_file_t backend;

			if (fzn_spool_file_open(&backend, NULL) != NULL)
				FAIL(242);
			/* Safe on a struct that never opened -- which is the
			 * shape of every cleanup path a caller writes after
			 * the line above returns NULL. */
			backend.fd = -1;
			fzn_spool_file_close(&backend);
			/* And the resume half, which is what a consumer
			 * needs before its first restart mid-transfer: a
			 * checkpoint through a backend that is not open
			 * must refuse rather than write a bitmap for data
			 * it cannot sync. */
			if (fzn_spool_file_checkpoint(&backend, &sp) != FZN_SPOOL_ERR_MALFORMED)
				FAIL(243);
			if (fzn_spool_file_resume(&backend, fake_root, 2u, map, sizeof(map))
			    != FZN_SPOOL_ERR_MALFORMED
			    && fzn_spool_file_resume(&backend, fake_root, 2u, map, sizeof(map))
			       != FZN_SPOOL_ERR_ABSENT)
				FAIL(244);
		}
#endif
	}

	/* Persistence: the contract a consumer needs before its first restart.
	 * Walked rather than compiled, because the property that matters is
	 * the one a naive round trip would lose -- an adopted anchor coming
	 * back adopted rather than claiming it was confirmed. */
	{
		fzn_trust_t anchor_in, anchor_back;
		uint8_t blob[FZN_PERSIST_MAX];
		uint8_t k[FZN_PUBKEY_LEN];
		size_t blob_len = 0;

		memset(k, 0x64, sizeof(k));
		fzn_trust_init(&anchor_in);
		if (fzn_trust_adopt(&anchor_in, k, 99u) != FZN_TRUST_OK)
			FAIL(230);
		if (fzn_persist_trust_pack(&anchor_in, blob, sizeof(blob), &blob_len)
		    != FZN_PERSIST_OK)
			FAIL(231);
		if (fzn_persist_trust_open(blob, blob_len, &anchor_back) != FZN_PERSIST_OK)
			FAIL(232);
		if (!fzn_trust_root(&anchor_back))
			FAIL(233);
		if (memcmp(fzn_trust_root(&anchor_back), k, FZN_PUBKEY_LEN) != 0)
			FAIL(234);
		if (fzn_trust_source_of(&anchor_back) != FZN_TRUST_ADOPTED)
			FAIL(235);
		/* An unanchored trust must not pack: saving one over a real
		 * anchor would succeed and erase it. */
		fzn_trust_init(&anchor_in);
		if (fzn_persist_trust_pack(&anchor_in, blob, sizeof(blob), &blob_len)
		    != FZN_PERSIST_ERR_MALFORMED)
			FAIL(236);

#ifdef FZN_PERSIST_FILE_ON
		/* And the default backend installs, which is the whole point of
		 * shipping one: a consumer should not have to write it. */
		{
			fzn_persist_file_t backend;

			if (fzn_persist_file_init(&backend, NULL) != NULL)
				FAIL(237);
		}
#endif
	}

	/* The authorisation decision, which is the question a consumer asks
	 * before it trusts a record's issuer. Walked rather than compiled,
	 * because the case that matters is the one a consumer produces by
	 * FORGETTING: a zeroed policy must deny. */
	{
		fzn_authz_policy_t zeroed;
		fzn_revocation_store_t empty;
		fzn_revocation_t empty_slots[1];
		fzn_cap_id_t any_cap;

		memset(&zeroed, 0, sizeof(zeroed));
		memset(any_cap.b, 0x5b, sizeof(any_cap.b));
		if (fzn_revocation_store_init(&empty, empty_slots, 1) != FZN_CHAIN_OK)
			FAIL(220);

		/* A memset policy is not "unguarded". */
		if (fzn_authz_decide(zeroed, FZN_ORIGIN_REMOTE, NULL, 0, root, 1000, &sign, &empty)
		    != FZN_AUTHZ_DENIED)
			FAIL(221);
		/* Nor is a required capability with no chain held. */
		if (fzn_authz_decide(fzn_authz_requires(&any_cap, FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, NULL, 0, root, 1000, &sign,
		                     &empty) != FZN_AUTHZ_DENIED)
			FAIL(222);
		/* Only saying so out loud grants, and it says which grant it is. */
		if (fzn_authz_decide(fzn_authz_unguarded(FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, NULL, 0, root, 1000, &sign, &empty)
		    != FZN_AUTHZ_GRANTED_UNGUARDED)
			FAIL(223);
		if ((int)FZN_AUTHZ_DENIED != 0)
			FAIL(224);
	}

	/* Key agreement: the seam a consumer fills to get deletable material
	 * into a session transcript. Walked rather than compiled -- install,
	 * agree both ways, rotate, and confirm the rotation destroyed what it
	 * replaced, which is the property forward secrecy rests on. */
	{
		fzn_agree_ops_t aops = { consumer_public_of, consumer_agree, NULL };
		fzn_agree_secret_t a, b;
		uint8_t a_sec[FZN_AGREE_SECRET_LEN], b_sec[FZN_AGREE_SECRET_LEN];
		uint8_t rotated[FZN_AGREE_SECRET_LEN];
		uint8_t sa[FZN_AGREE_SHARED_LEN], sb[FZN_AGREE_SHARED_LEN];
		uint8_t after[FZN_AGREE_SHARED_LEN];
		unsigned i;

		memset(&a, 0, sizeof(a));
		memset(&b, 0, sizeof(b));
		for (i = 0; i < FZN_AGREE_SECRET_LEN; i++) {
			a_sec[i] = (uint8_t)(i + 2u);
			b_sec[i] = (uint8_t)((i * 3u) + 5u);
			rotated[i] = (uint8_t)((i * 7u) + 13u);
		}
		if (fzn_agree_secret_install(&a, &aops, a_sec) != FZN_AGREE_OK)
			FAIL(180);
		if (fzn_agree_secret_install(&b, &aops, b_sec) != FZN_AGREE_OK)
			FAIL(181);
		if (!fzn_agree_secret_public(&a) || !fzn_agree_secret_public(&b))
			FAIL(182);
		if (fzn_agree_shared(&a, &aops, fzn_agree_secret_public(&b), sa) != FZN_AGREE_OK)
			FAIL(183);
		if (fzn_agree_shared(&b, &aops, fzn_agree_secret_public(&a), sb) != FZN_AGREE_OK)
			FAIL(184);
		if (memcmp(sa, sb, FZN_AGREE_SHARED_LEN) != 0)
			FAIL(185);

		/* Rotate, and the old secret must be gone. */
		if (fzn_agree_secret_install(&a, &aops, rotated) != FZN_AGREE_OK)
			FAIL(186);
		if (fzn_agree_secret_generation(&a) != 1u)
			FAIL(187);
		if (fzn_agree_shared(&a, &aops, fzn_agree_secret_public(&b), after) != FZN_AGREE_OK)
			FAIL(188);
		if (memcmp(sa, after, FZN_AGREE_SHARED_LEN) == 0)
			FAIL(189);
		fzn_agree_secret_wipe(&a);
		if (fzn_agree_secret_public(&a) != NULL)
			FAIL(190);
		if (fzn_agree_shared(&a, &aops, fzn_agree_secret_public(&b), after)
		    != FZN_AGREE_ERR_ABSENT)
			FAIL(191);
	}

	/* A session, established from both sides. The property a consumer
	 * depends on is that two hosts reach the same root without agreeing
	 * who started it, so this checks exactly that through the installed
	 * headers -- and then that rotating a prekey moves the root, which is
	 * where the forward secrecy comes from. */
	{
		fzn_agree_ops_t aops = { consumer_public_of, consumer_agree, NULL };
		fzn_hash_ops_t shash = { consumer_hash, NULL };
		fzn_agree_secret_t pa, pb;
		uint8_t sa[FZN_AGREE_SECRET_LEN], sb[FZN_AGREE_SECRET_LEN];
		uint8_t rot[FZN_AGREE_SECRET_LEN];
		uint8_t ida[FZN_SESSION_IDENTITY_LEN], idb[FZN_SESSION_IDENTITY_LEN];
		uint8_t ka[FZN_AEAD_KEY_LEN], kb[FZN_AEAD_KEY_LEN], kc[FZN_AEAD_KEY_LEN];
		uint8_t ca[FZN_COMMITMENT_KEY_LEN], cb[FZN_COMMITMENT_KEY_LEN];
		unsigned i;

		memset(&pa, 0, sizeof(pa));
		memset(&pb, 0, sizeof(pb));
		for (i = 0; i < FZN_AGREE_SECRET_LEN; i++) {
			sa[i] = (uint8_t)(i + 17u);
			sb[i] = (uint8_t)((i * 5u) + 23u);
			rot[i] = (uint8_t)((i * 11u) + 41u);
		}
		memset(ida, 0x1a, sizeof(ida));
		memset(idb, 0xb2, sizeof(idb));

		if (fzn_agree_secret_install(&pa, &aops, sa) != FZN_AGREE_OK)
			FAIL(200);
		if (fzn_agree_secret_install(&pb, &aops, sb) != FZN_AGREE_OK)
			FAIL(201);
		if (!fzn_agree_secret_public(&pa) || !fzn_agree_secret_public(&pb))
			FAIL(202);
		if (fzn_session_establish(&pa, &aops, &shash, ida, idb,
		                          fzn_agree_secret_public(&pb), ka, ca) != FZN_SESSION_OK)
			FAIL(203);
		if (fzn_session_establish(&pb, &aops, &shash, idb, ida,
		                          fzn_agree_secret_public(&pa), kb, cb) != FZN_SESSION_OK)
			FAIL(204);
		/* No role was negotiated and both sides must still agree. */
		if (memcmp(ka, kb, FZN_AEAD_KEY_LEN) != 0)
			FAIL(205);
		if (memcmp(ca, cb, FZN_COMMITMENT_KEY_LEN) != 0)
			FAIL(206);

		/* And a rotation must move the root, or rotation buys nothing. */
		if (fzn_agree_secret_install(&pb, &aops, rot) != FZN_AGREE_OK)
			FAIL(207);
		if (fzn_session_establish(&pa, &aops, &shash, ida, idb,
		                          fzn_agree_secret_public(&pb), kc, ca) != FZN_SESSION_OK)
			FAIL(208);
		if (memcmp(ka, kc, FZN_AEAD_KEY_LEN) == 0)
			FAIL(209);
		/* A session with yourself has no canonical order and is refused. */
		if (fzn_session_establish(&pa, &aops, &shash, ida, ida,
		                          fzn_agree_secret_public(&pb), kc, ca)
		    != FZN_SESSION_ERR_SELF)
			FAIL(210);

		/* And the ephemeral exchange, both halves, since a consumer
		 * that wants sender-side forward secrecy drives exactly this
		 * pair and needs them to agree. */
		{
			fzn_agree_secret_t eph;
			uint8_t es[FZN_AGREE_SECRET_LEN];
			uint8_t ki[FZN_AEAD_KEY_LEN], kr[FZN_AEAD_KEY_LEN];
			uint8_t cki[FZN_COMMITMENT_KEY_LEN], ckr[FZN_COMMITMENT_KEY_LEN];

			memset(&eph, 0, sizeof(eph));
			for (i = 0; i < FZN_AGREE_SECRET_LEN; i++)
				es[i] = (uint8_t)((i * 13u) + 7u);
			if (fzn_agree_secret_install(&eph, &aops, es) != FZN_AGREE_OK)
				FAIL(211);
			if (fzn_session_establish_initiator(&pa, &eph, &aops, &shash, ida, idb,
			                                    fzn_agree_secret_public(&pb), ki,
			                                    cki) != FZN_SESSION_OK)
				FAIL(212);
			if (fzn_session_establish_responder(&pb, &aops, &shash, idb, ida,
			                                    fzn_agree_secret_public(&pa),
			                                    fzn_agree_secret_public(&eph), kr,
			                                    ckr) != FZN_SESSION_OK)
				FAIL(213);
			if (memcmp(ki, kr, FZN_AEAD_KEY_LEN) != 0)
				FAIL(214);
			/* And it is a different session from the base one. */
			if (memcmp(ki, kc, FZN_AEAD_KEY_LEN) == 0)
				FAIL(215);
			/* The ephemeral is destroyed by the caller, which is
			 * the property; this is where a consumer does it. */
			fzn_agree_secret_wipe(&eph);
		}
		fzn_agree_secret_wipe(&pa);
		fzn_agree_secret_wipe(&pb);
	}

	/* The prekey record and the act of pinning it, which are one feature
	 * and are exercised as one: issue, open, verify, pin, then the three
	 * refusals a consumer has to be able to tell apart. */
	{
		uint8_t host[FZN_PUBKEY_LEN], pk1[FZN_PREKEY_LEN], pk2[FZN_PREKEY_LEN];
		uint8_t other[FZN_PUBKEY_LEN];
		uint8_t rec1[FZN_PREKEY_LEN_TOTAL], rec2[FZN_PREKEY_LEN_TOTAL];
		uint8_t rec3[FZN_PREKEY_LEN_TOTAL];
		fzn_prekey_record_t r1, r2, r3;
		fzn_prekey_peer_t peer;

		memset(host, 0x2a, sizeof(host));
		memset(other, 0x2b, sizeof(other));
		memset(pk1, 0x3a, sizeof(pk1));
		memset(pk2, 0x3b, sizeof(pk2));

		if (fzn_prekey_issue(host, pk1, 100u, &sign, rec1) != FZN_PREKEY_OK)
			FAIL(150);
		if (fzn_prekey_issue(host, pk2, 200u, &sign, rec2) != FZN_PREKEY_OK)
			FAIL(151);
		if (fzn_prekey_issue(other, pk1, 300u, &sign, rec3) != FZN_PREKEY_OK)
			FAIL(152);
		if (fzn_prekey_open(rec1, sizeof(rec1), &r1) != FZN_PREKEY_OK)
			FAIL(153);
		if (fzn_prekey_open(rec2, sizeof(rec2), &r2) != FZN_PREKEY_OK)
			FAIL(154);
		if (fzn_prekey_open(rec3, sizeof(rec3), &r3) != FZN_PREKEY_OK)
			FAIL(155);
		if (fzn_prekey_verify(r1, &sign) != FZN_PREKEY_OK)
			FAIL(156);

		fzn_prekey_peer_init(&peer);
		if (fzn_prekey_pin(&peer, r1, &sign, FZN_TRUST_ADOPTED, 1u) != FZN_PREKEY_OK)
			FAIL(157);
		if (fzn_trust_source_of(&peer.trust) != FZN_TRUST_ADOPTED)
			FAIL(158);
		/* A rotation forward, then the same record back again, then a
		 * different host: three outcomes, three codes. */
		if (fzn_prekey_pin(&peer, r2, &sign, FZN_TRUST_ADOPTED, 2u) != FZN_PREKEY_OK)
			FAIL(159);
		if (fzn_prekey_pin(&peer, r1, &sign, FZN_TRUST_ADOPTED, 3u)
		    != FZN_PREKEY_ERR_ROLLBACK)
			FAIL(160);
		if (fzn_prekey_pin(&peer, r3, &sign, FZN_TRUST_ADOPTED, 4u)
		    != FZN_PREKEY_ERR_WRONG_HOST)
			FAIL(161);
		/* And a rotation must not raise an adopted anchor to a
		 * confirmed one, which is the provenance a consumer shows its
		 * user. */
		if (fzn_trust_source_of(&peer.trust) != FZN_TRUST_ADOPTED)
			FAIL(162);
	}

	/* The ratchet, walked rather than compiled: one step, a fast-forward
	 * that must agree with stepping, and the two refusals a consumer has
	 * to be able to tell apart. */
	{
		fzn_hash_ops_t rhash = { consumer_hash, NULL };
		fzn_ratchet_chain_t ratchet;
		fzn_ratchet_chain_t next_ratchet;
		uint8_t ck[FZN_CHAIN_KEY_LEN];
		uint8_t stepped[FZN_CHAIN_KEY_LEN];
		uint8_t mk[FZN_MESSAGE_KEY_LEN];
		uint8_t jumped[FZN_MESSAGE_KEY_LEN];
		unsigned i;

		memset(ck, 0x71, sizeof(ck));
		memcpy(stepped, ck, sizeof(stepped));
		for (i = 0; i <= 3u; i++)
			if (fzn_ratchet_derive(&rhash, stepped, mk, stepped) != FZN_RATCHET_OK)
				FAIL(140);

		fzn_ratchet_init(&ratchet, ck, 0);
		/* THE WHOLE RECIPE, since it is the thing a consumer has to get
		 * right: derive into a SEPARATE chain, verify, then commit. The
		 * in-place form is refused, so there is no other way to spell
		 * it. */
		if (fzn_ratchet_advance(&rhash, &ratchet, 3u, jumped, &next_ratchet, NULL, 0,
		                        NULL, NULL) != FZN_RATCHET_OK)
			FAIL(141);
		if (memcmp(jumped, mk, FZN_MESSAGE_KEY_LEN) != 0)
			FAIL(142);
		if (ratchet.seq != 0u || next_ratchet.seq != 4u)
			FAIL(143);
		ratchet = next_ratchet; /* committed, as a real caller would after opening */
		if (fzn_ratchet_advance(&rhash, &ratchet, 3u, jumped, &ratchet, NULL, 0, NULL,
		                        NULL) != FZN_RATCHET_ERR_IN_PLACE)
			FAIL(144);
		/* A duplicate and a caller bug must not share a code, which is
		 * the distinction a consumer's logging depends on. */
		if (fzn_ratchet_advance(&rhash, &ratchet, 0, jumped, &next_ratchet, NULL, 0,
		                        NULL, NULL) != FZN_RATCHET_ERR_BEHIND)
			FAIL(145);
		if (fzn_ratchet_advance(&rhash, &ratchet,
		                        ratchet.seq + (uint64_t)FZN_RATCHET_MAX_ADVANCE + 1u,
		                        jumped, &next_ratchet, NULL, 0, NULL, NULL)
		    != FZN_RATCHET_ERR_TOO_FAR)
			FAIL(146);
		fzn_ratchet_wipe(&ratchet);
		fzn_ratchet_wipe(&next_ratchet);
	}

	/* The frame path. A consumer takes this to open a datagram, so the
	 * check is that the header and the source go together and that a
	 * refused open is refused -- not that the cryptography works, which
	 * wire/test/seal_test.c covers. A null AEAD is the cheapest refusal
	 * that reaches the argument guard. */
	{
		fzn_opened_t opened;
		uint8_t frame[144];
		uint8_t key[FZN_AEAD_KEY_LEN], ckey[FZN_COMMITMENT_KEY_LEN];
		fzn_hash_ops_t hash;

		memset(frame, 0, sizeof(frame));
		memset(key, 0x11, sizeof(key));
		memset(ckey, 0x22, sizeof(ckey));
		memset(&hash, 0, sizeof(hash));
		/* The commitment is derived per frame from the nonce now, so a
		 * consumer hands over the commitment KEY and a hash seam rather
		 * than a finished commitment it could not have computed. */
		if (fzn_seal_open(frame, sizeof(frame), key, ckey, &hash, NULL, &opened) !=
		    FZN_SEAL_ERR_MALFORMED)
			FAIL(18);
		if (FZN_AEAD_NONCE_LEN != FZN_NONCE_LEN)
			FAIL(19);

		/* PEEKING REFUSES WHAT OPENING REFUSES, which is the property a
		 * consumer selecting a key depends on: `fzn_seal_peek_sender`
		 * runs before any key is chosen, so if it accepted frames
		 * `fzn_seal_open` will not, a receiver would select on a pointer
		 * into something that is not a frame. Asked of the same buffer
		 * the line above just had refused, so the two answers are about
		 * one input rather than two. */
		{
			fzn_peek_t peek, zeroed;
			const uint8_t *claimed = (const uint8_t *)&peek;

			memset(&peek, 0xA5, sizeof(peek));
			memset(&zeroed, 0, sizeof(zeroed));
			/* SHAPE, NOT MALFORMED, AND THE DIFFERENCE IS THE
			 * POINT. `fzn_seal_open` above answers MALFORMED for
			 * this buffer because it was handed a null AEAD --
			 * a caller's bug. Peek takes no ops at all, so the only
			 * thing it can object to is the bytes, and it says so
			 * with its own code: an all-zero frame is not the shape
			 * the schema describes. A consumer that folded the two
			 * together would report its own mistakes as a peer's
			 * bad datagrams. */
			if (fzn_seal_peek(frame, sizeof(frame), &peek) !=
			    FZN_SEAL_ERR_SHAPE)
				FAIL(25);
			/* A REFUSAL LEAVES THE STRUCT ZEROED, which is better
			 * than leaving it alone and is what a consumer can
			 * rely on: both peek calls clear their output BEFORE
			 * validating, so a caller that ignores the return code
			 * reads zeroes rather than whatever was on its stack.
			 * Compared whole rather than field by field, because a
			 * check naming two fields passes a refusal that wrote
			 * a third. */
			if (memcmp(&peek, &zeroed, sizeof(peek)) != 0)
				FAIL(26);
			if (fzn_seal_peek_sender(frame, sizeof(frame), &claimed) !=
			    FZN_SEAL_ERR_SHAPE)
				FAIL(27);
			/* And the narrow call nulls its pointer for the same
			 * reason, rather than leaving the caller's sentinel. */
			if (claimed != NULL)
				FAIL(28);
		}

		/* THE COMMAND VOCABULARY, AS LITERALS. `fzn_kind` is a closed
		 * four-value set with a consumer's own commands in the sealed
		 * payload beneath it, so these numbers are part of what two
		 * implementations must agree on. Written out rather than
		 * compared against each other: a check that says only that they
		 * differ is satisfied by any four values. */
		if (FZN_KIND_NOP != 0u || FZN_KIND_UNIT != 1u ||
		    FZN_KIND_CHUNK != 2u || FZN_KIND_ACK != 3u)
			FAIL(29);
	}

	/* The nonce source. A consumer needs one before it can seal anything,
	 * and the property worth a line here is the refusal: an ops with no
	 * fill must not produce a nonce, which is what a platform without a
	 * source leaves behind. */
	{
		fzn_random_ops_t rng = { NULL, NULL };
		/* `aead_nonce` rather than `nonce`, which is taken by the
		 * outer FZN_NONCE_LEN buffer. The two constants are equal
		 * and wire/seal.c now asserts they stay so, but a consumer
		 * building with -Wshadow should not have to establish that
		 * from a warning our own conformance check emitted. */
		uint8_t aead_nonce[FZN_AEAD_NONCE_LEN];

		memset(aead_nonce, 0x5a, sizeof(aead_nonce));
		if (fzn_nonce_next(&rng, aead_nonce) != 0)
			FAIL(20);
		fzn_random_system_init(&rng);
#if defined(__linux__)
		if (!rng.fill || fzn_nonce_next(&rng, aead_nonce) != 1)
			FAIL(21);
#endif
	}

	/* THE TREE, EXERCISED RATHER THAN MERELY INCLUDED. `installcheck`
	 * requires every installed header to be included here, and an include
	 * alone proves only that the header parses. These calls are the ones a
	 * consumer building a nesting structure actually makes, and the two
	 * that matter are the ones with no single right answer to guess:
	 * running out of order keys, and a set the root cannot fully reach. */
	{
		uint8_t parent[FZN_TREE_ID_LEN];
		uint8_t ids[2][FZN_TREE_ID_LEN];
		uint8_t body[FZN_RECORD_BODY_MAX];
		fzn_tree_node_t nodes[2];
		const fzn_tree_node_t *kids[2];
		fzn_tree_walk_t walk;
		uint8_t mark[2];
		uint64_t order = 0u;
		size_t body_len = 0u;

		memset(parent, 0, sizeof parent);
		if (!fzn_tree_is_root(parent))
			FAIL(249);

		if (fzn_tree_body(parent, 100u, 1u, NULL, 0u,
		                  body, sizeof body, &body_len) != FZN_TREE_OK)
			FAIL(250);
		if (body_len != (size_t)FZN_TREE_BODY_HEADER_LEN)
			FAIL(251);

		/* Adjacent neighbours have no midpoint, and the library says so
		 * without refusing to answer -- a consumer inserting between two
		 * notes needs the key back either way. */
		if (fzn_tree_order_between(4u, 5u, &order) != FZN_TREE_ORDER_EXHAUSTED)
			FAIL(252);
		if (order != 4u)
			FAIL(253);

		memset(ids[0], 1, sizeof ids[0]);
		memset(ids[1], 2, sizeof ids[1]);
		nodes[0].id = ids[0];
		nodes[0].parent = parent;
		nodes[0].content = NULL;
		nodes[0].content_len = 0u;
		nodes[0].order = 10u;
		nodes[0].content_type = 0u;
		/* Node 2 names node 2 as its own parent: a one-node cycle, which
		 * is the shape a walk without a mark array never returns from. */
		nodes[1] = nodes[0];
		nodes[1].id = ids[1];
		nodes[1].parent = ids[1];

		if (fzn_tree_children(nodes, 2u, parent, kids, 2u, &walk) != FZN_TREE_OK)
			FAIL(254);
		if (walk.emitted != 1u || walk.truncated != 0)
			FAIL(255);

		if (fzn_tree_reachable(nodes, 2u, mark, sizeof mark, &walk) != FZN_TREE_OK)
			FAIL(13);
		if (mark[0] == 0u || mark[1] != 0u)
			FAIL(24);
	}

#ifdef FZN_CONSUMER_MONOCYPHER
	/* One call through each binding, which is this file's standard: enough
	 * to prove the header and the source go together, not a test of the
	 * cryptography -- chain/test/sign_monocypher_test.c does that. */
	{
		fzn_sign_monocypher_t signer;
		fzn_sign_ops_t real_sign;
		fzn_hash_ops_t real_hash;
		/* THE THIRD BINDING, and it was the one left out. The comment
		 * above says two headers were installable and unverifiable; the
		 * fix that followed it covered two of the three and missed
		 * `aead_monocypher.h`, so `make installcheck MONOCYPHER_DIR=...`
		 * failed on exactly the header nobody had included -- in the
		 * configuration the default build never produces, which is why
		 * it went unnoticed. Counting the headers a fix covers against
		 * the headers that exist is the check that was missing. */
		fzn_aead_ops_t real_aead;
		uint8_t derived[FZN_DERIVED_LEN];
		/* SOMETHING TO HASH, AND IT WAS MISSING ENTIRELY. The call below
		 * has always named `region`, which is declared nowhere in this
		 * file -- so this whole block has NEVER COMPILED. It could not
		 * be noticed, because it builds only under
		 * FZN_CONSUMER_MONOCYPHER and that arrangement failed the
		 * header-coverage check first, before the compiler ever reached
		 * this line. A gate that refuses early hides whatever is behind
		 * it. */
		static const uint8_t region[] = "a region to hash";

		memset(&signer, 0, sizeof(signer));
		fzn_sign_monocypher_init(&real_sign, &signer);
		if (!real_sign.verify || real_sign.ctx != &signer)
			FAIL(14);

		/* A verify-only signer holds no key and must not claim to sign. */
		if (signer.can_sign)
			FAIL(15);

		/* PEEK AGAINST A FRAME THAT REALLY IS ONE. The block in the
		 * common path proves peek refuses what open refuses; it cannot
		 * prove peek reads the right fields, because a frame peek would
		 * accept needs the crypto to build. So the positive half lives
		 * here, and it is the half a receiver depends on: `sender` is
		 * what sec 4.7 step 2 selects a key on, and it must be the
		 * sender that was put in rather than some other 32 bytes of a
		 * plaintext head. */
		{
			fzn_send_t what;
			fzn_peek_t peek;
			const uint8_t *claimed = NULL;
			fzn_random_ops_t sys_rng;
			fzn_hash_ops_t peek_hash;
			fzn_aead_ops_t peek_aead;
			uint8_t built[FZN_SEAL_OVERHEAD + 8];
			uint8_t sender_id[FZN_PUBKEY_LEN];
			uint8_t cap_id[FZN_CAP_ID_LEN];
			uint8_t seal_key[FZN_AEAD_KEY_LEN];
			uint8_t seal_ckey[FZN_COMMITMENT_KEY_LEN];
			static const uint8_t payload[8] = "peekable";
			size_t built_len = 0;

			memset(sender_id, 0x7E, sizeof(sender_id));
			memset(cap_id, 0x3C, sizeof(cap_id));
			memset(seal_key, 0x41, sizeof(seal_key));
			memset(seal_ckey, 0x42, sizeof(seal_ckey));
			fzn_hash_monocypher_init(&peek_hash);
			fzn_aead_monocypher_init(&peek_aead);
			fzn_random_system_init(&sys_rng);

			memset(&what, 0, sizeof(what));
			what.sender = sender_id;
			what.capability = cap_id;
			what.payload = payload;
			what.payload_len = sizeof(payload);
			what.expires_at = 0x0102030405060708ull;
			what.msg = 0xCAFEBABEu;
			what.index = 2u;
			what.chunks = 5u;
			what.kind = FZN_KIND_CHUNK;

			if (fzn_seal_build(built, sizeof(built), &built_len, &what,
			                   seal_key, seal_ckey, &peek_hash, &sys_rng,
			                   &peek_aead) != FZN_SEAL_OK)
				FAIL(55);
			if (built_len != sizeof(built))
				FAIL(56);

			/* Every field the head carries, against what went in,
			 * one at a time so a failure names which field moved
			 * rather than only that the head disagrees. */
			if (fzn_seal_peek(built, built_len, &peek) != FZN_SEAL_OK)
				FAIL(57);
			if (memcmp(peek.sender, sender_id, FZN_PUBKEY_LEN) != 0)
				FAIL(58);
			if (peek.expires_at != what.expires_at)
				FAIL(59);
			if (peek.msg != what.msg)
				FAIL(62);
			if (peek.index != what.index)
				FAIL(63);
			if (peek.chunks != what.chunks)
				FAIL(64);
			if (peek.kind != FZN_KIND_CHUNK)
				FAIL(65);
			/* The two pointers are into the frame, so they must land
			 * inside it rather than merely be non-null. */
			if (peek.nonce < built || peek.nonce >= built + built_len)
				FAIL(66);
			if (peek.commitment < built ||
			    peek.commitment >= built + built_len)
				FAIL(67);

			/* AND THE CHEAP ACCESSOR AGREES WITH THE WHOLE HEAD.
			 * Two functions reading one field is exactly where a
			 * layout change breaks one and not the other. */
			if (fzn_seal_peek_sender(built, built_len, &claimed) !=
			    FZN_SEAL_OK)
				FAIL(68);
			if (claimed != peek.sender)
				FAIL(69);

			/* A CLAIM, NOT A FACT, MADE CHECKABLE. The head is
			 * plaintext, so anyone can write any sender into a
			 * frame: rewriting it must still peek, and must report
			 * the NEW bytes. A consumer reading this should see
			 * that peek is for choosing a key, not for deciding who
			 * sent something. The byte is reached through the
			 * pointer peek returned rather than through an offset,
			 * which needs no layout knowledge -- the same thing
			 * peek exists to spare a consumer. */
			{
				uint8_t *in_head = (uint8_t *)(uintptr_t)peek.sender;

				in_head[0] ^= 0xFFu;
				if (fzn_seal_peek_sender(built, built_len,
				                         &claimed) != FZN_SEAL_OK)
					FAIL(70);
				if (memcmp(claimed, sender_id,
				           FZN_PUBKEY_LEN) == 0)
					FAIL(71);
				in_head[0] ^= 0xFFu;
				if (memcmp(claimed, sender_id,
				           FZN_PUBKEY_LEN) != 0)
					FAIL(72);
			}
		}
		fzn_sign_monocypher_wipe(&signer);

		fzn_hash_monocypher_init(&real_hash);
		if (!real_hash.hash)
			FAIL(16);
		if (!real_hash.hash(real_hash.ctx, derived, sizeof(derived), region,
		                    sizeof(region) - 1))
			FAIL(17);

		/* One call through the AEAD binding, to the same standard as the
		 * two above: enough to prove the header and the source go
		 * together. A null op here is the whole failure this is watching
		 * for -- a binding that installs and does not link. */
		fzn_aead_monocypher_init(&real_aead);
		if (!real_aead.seal || !real_aead.open)
			FAIL(18);

		/* And the agreement binding, to the same standard: a binding
		 * that installs and does not link is the failure this watches
		 * for. */
		{
			fzn_agree_ops_t real_agree;

			fzn_agree_monocypher_init(&real_agree);
			if (!real_agree.public_of || !real_agree.agree)
				FAIL(19);
		}
	}

	printf("consumer_check: headers and sources agree, Monocypher bindings included\n");
	return 0;
#else
	printf("consumer_check: headers and sources agree\n");
	return 0;
#endif
}
