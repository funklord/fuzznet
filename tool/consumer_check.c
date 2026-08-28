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
 * Compiled twice by `make installcheck`: once against an installed tree
 * with angle-bracket includes, once against the source tree with module
 * paths, which are the two arrangements a consumer can be in.
 */

#ifdef FZN_CONSUMER_INSTALLED
#include <fuzznet/chain/chain.h>
#include <fuzznet/chain/manifest.h>
#include <fuzznet/blob/blob.h>
#include <fuzznet/ratchet/ratchet.h>
#include <fuzznet/prekey/prekey.h>
#include <fuzznet/session/agree.h>
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
#include "blob/blob.h"
#include "ratchet/ratchet.h"
#include "prekey/prekey.h"
#include "session/agree.h"
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
	uint8_t root[FZN_PUBKEY_LEN], cap[FZN_CAP_ID_LEN], nonce[FZN_NONCE_LEN];
	uint8_t equal_a[4] = { 0 }, equal_b[4] = { 0 };

	memset(root, 0x01, sizeof(root));
	memset(cap, 0x02, sizeof(cap));
	memset(nonce, 0x03, sizeof(nonce));

	if (!fzn_ct_memeq(equal_a, equal_b, sizeof(equal_a)))
		return 1;

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
			return 30;
		/* FOLLOWING AN ISSUER IS A DECISION. Admitting no longer adopts
		 * one, so a consumer anchors first -- which is the step this
		 * file exists to show. */
		if (fzn_journal_anchor(&journal, issuer, 0, 0) != FZN_JOURNAL_OK)
			return 30;
		if (fzn_journal_admit(&journal, issuer, 0, 1) != FZN_JOURNAL_OK)
			return 31;
		if (fzn_journal_admit(&journal, issuer, 0, 1) != FZN_JOURNAL_ERR_DUPLICATE)
			return 32;
		if (fzn_journal_next(&journal, issuer, 0) != 2)
			return 33;
		{
			fzn_sync_position_t theirs;
			fzn_sync_request_t want;
			fzn_sync_plan_t sync_plan;

			memcpy(theirs.issuer, issuer, FZN_PUBKEY_LEN);
			theirs.stream = 0;
			theirs.received = 4;
			if (fzn_sync_plan_fetch(&journal, &theirs, 1, 8, &want, 1, &sync_plan) !=
			    FZN_SYNC_OK)
				return 34;
			if (sync_plan.request_count != 1 || want.from != 2 || want.count != 3)
				return 35;
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
			return 40;
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
			return 41;
		if (fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
			return 41;
		if (fzn_state_apply(&st, &r) != FZN_STATE_OK)
			return 41;

		if (fzn_record_sign(alice, subject, 0, 1, 2, 1, body, sizeof(body), &ops, wire,
		                    sizeof(wire), &wrote) != FZN_RECORD_OK ||
		    fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
			return 42;
		if (fzn_state_apply(&st, &r) != FZN_STATE_OK)
			return 42;

		if (fzn_record_sign(alice, subject, 0, 1, 1, 1, body, sizeof(body), &ops, wire,
		                    sizeof(wire), &wrote) != FZN_RECORD_OK ||
		    fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
			return 43;
		if (fzn_state_apply(&st, &r) != FZN_STATE_ERR_STALE)
			return 43;

		if (fzn_record_sign(mallory, subject, 0, 1, 99, 1, body, sizeof(body), &ops, wire,
		                    sizeof(wire), &wrote) != FZN_RECORD_OK ||
		    fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
			return 44;
		if (fzn_state_apply(&st, &r) != FZN_STATE_ERR_CONFLICT)
			return 44;
		if (fzn_state_count(&st) != 1)
			return 45;
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
			return 50;
		if (fzn_trust_adopt(&anchor, k1, 7) != FZN_TRUST_OK)
			return 51;
		if (fzn_trust_adopt(&anchor, k2, 8) != FZN_TRUST_ERR_ANCHORED)
			return 52;
		if (memcmp(fzn_trust_root(&anchor), k1, FZN_PUBKEY_LEN) != 0)
			return 53;
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
			return 60;
		if (fzn_journal_init(&jr, jslots, 2) != FZN_JOURNAL_OK)
			return 60;
		memset(&ops, 0, sizeof(ops));
		ops.sign = always_sign;
		memset(who, 0x41, sizeof(who));
		memset(subject, 0, sizeof(subject));
		if (fzn_journal_anchor(&jr, who, 0, 0) != FZN_JOURNAL_OK)
			return 60;

		for (uint64_t q = 1; q <= 3; q++) {
			if (fzn_record_sign(who, subject, 0, 1, q, 1, b, sizeof(b), &ops, wire,
			                    sizeof(wire), &wrote) != FZN_RECORD_OK ||
			    fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
				return 61;
			if (fzn_log_append(&lg, &r) != FZN_LOG_OK)
				return 61;
			if (fzn_journal_admit(&jr, who, 0, q) != FZN_JOURNAL_OK)
				return 61;
		}
		/* GONE COMES FROM THE POSITION, so the journal is a parameter --
		 * a log alone cannot tell what retention removed from what never
		 * arrived. */
		if (fzn_log_get(&lg, &jr, who, 0, 1, &e) != FZN_LOG_ERR_GONE)
			return 62;
		if (fzn_log_get(&lg, &jr, who, 0, 9, &e) != FZN_LOG_ERR_ABSENT)
			return 63;
		if (fzn_log_dropped(&lg) != 1)
			return 64;
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
			return 70;
		if (budget != FZN_RELAY_MAX_HOPS)
			return 71;
		if (fzn_relay_spend(hop_frame, sizeof(hop_frame), FZN_RELAY_MAX_HOPS) !=
		    FZN_RELAY_OK)
			return 72;
		if (hop_frame[1] != FZN_RELAY_MAX_HOPS - 1u)
			return 73;
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
			return 80;
		if (fzn_sched_select(pair, 2, &important, &pick) != FZN_SCHED_OK || pick != 1)
			return 81;
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
			return 90;
		if (fzn_link_register(&lt, 1, 0, 10, 0, 1500) != FZN_LINK_OK)
			return 91;
		if (fzn_link_register(&lt, 2, 0, 60, 0, 1500) != FZN_LINK_OK)
			return 92;
		for (int k = 0; k < 40; k++) {
			if (fzn_link_observe_ack(&lt, 1, 5000, (uint64_t)k) != FZN_LINK_OK)
				return 93;
		}
		{
			size_t dropped = 1;

			n = fzn_link_snapshot(&lt, snap, 2, &dropped);
			if (n != 2 || dropped != 0)
				return 94;
		}
		if (fzn_sched_select(snap, n, &any, &pick) != FZN_SCHED_OK || pick != 1)
			return 95;
	}

	if (fzn_version_number() != (unsigned long)FZN_VERSION_NUMBER)
		return 20;
	if (strcmp(fzn_version_string(), FZN_VERSION_STRING) != 0)
		return 21;

	if (fzn_split_plan(100, 8, &plan) != FZN_SPLIT_OK || plan.chunks != 13)
		return 2;

	/* The horizon is set beside the capacity, because they are two halves
	 * of one sizing decision: the window must hold what can arrive within
	 * the longest expiry it will accept. */
	if (fzn_replay_init(&window, window_storage, 4, 4000) != FZN_FRESH_OK)
		return 3;
	if (fzn_replay_admit(&window, nonce, 2000, FZN_EXPIRY_REQUIRED, 1000) != FZN_FRESH_OK)
		return 4;
	if (fzn_replay_admit(&window, nonce, 2000, FZN_EXPIRY_REQUIRED, 1000) !=
	    FZN_FRESH_ERR_REPLAY)
		return 5;

	if (fzn_revocation_store_init(&store, store_storage, 4) != FZN_CHAIN_OK)
		return 6;

	/* A REAL HOP, MINTED AND OPENED. This used to point `signed_region` at
	 * the literal "a signed region" while filling the fields separately --
	 * which demonstrated to every consumer reading this file exactly the
	 * shape that made a captured signature reusable with rewritten fields.
	 * A hop is a view over the bytes its signature covers now, so there is
	 * no separate set of fields to disagree. */
	{
		uint8_t grantee[FZN_PUBKEY_LEN];

		memset(grantee, 0x09, sizeof(grantee));
		if (fzn_chain_mint(root, grantee, cap, 100, FZN_NO_EXPIRY, 0, &sign,
		                   hop_bytes) != FZN_CHAIN_OK)
			return 7;
		if (fzn_hop_open(hop_bytes, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK)
			return 7;
	}

	if (fzn_chain_verify(&hop, 1, root, cap, 2000, &sign, &store, &chain) != FZN_CHAIN_OK)
		return 7;
	if (chain.hop_count != 1)
		return 8;

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
		if (fzn_revocation_issue(root, cap, grantee, 1500, &sign, rev_bytes) !=
		    FZN_CHAIN_OK)
			return 100;
		if (fzn_revocation_open(rev_bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
			return 101;
		if (fzn_revocation_covers(&store, fzn_revocation_issuer(rec),
		                          fzn_revocation_capability(rec),
		                          fzn_revocation_grantee(rec)) != 0)
			return 102;
		if (fzn_revocation_admit(&store, fzn_revocation_offer_root(rec), root, &sign,
		                         NULL) != FZN_CHAIN_OK)
			return 103;
		if (store.used != 1)
			return 104;
		if (fzn_revocation_covers(&store, fzn_revocation_issuer(rec),
		                          fzn_revocation_capability(rec),
		                          fzn_revocation_grantee(rec)) != 1)
			return 105;

		/* The store reaches the verifier, which is the property the
		 * signature change of 2026-08-27 exists for: the same hop that
		 * verified above must now be refused. */
		if (fzn_chain_verify(&hop, 1, root, cap, 2000, &sign, &store, &chain) !=
		    FZN_CHAIN_ERR_REVOKED)
			return 106;

		/* And NULL still means "no revocations known", which is what
		 * the old `NULL, 0` said and what a consumer holding no store
		 * relies on. */
		if (fzn_chain_verify(&hop, 1, root, cap, 2000, &sign, NULL, &chain) !=
		    FZN_CHAIN_OK)
			return 107;
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
			return 130;
		if (fzn_chain_mint(root, mid, cap, 100, FZN_NO_EXPIRY, 1, &sign, mid_bytes) !=
		    FZN_CHAIN_OK)
			return 131;
		if (fzn_hop_open(mid_bytes, FZN_HOP_LEN, &pair[0]) != FZN_CHAIN_OK)
			return 132;
		if (fzn_chain_delegate(pair, 1, root, cap, 2000, leaf, FZN_NO_EXPIRY, 0, &sign,
		                       NULL, leaf_bytes) != FZN_CHAIN_OK)
			return 133;
		if (fzn_hop_open(leaf_bytes, FZN_HOP_LEN, &pair[1]) != FZN_CHAIN_OK)
			return 134;
		if (fzn_chain_verify(pair, 2, root, cap, 2000, &sign, &estate, &chain) !=
		    FZN_CHAIN_OK)
			return 135;

		/* The middle key withdraws the capability from the leaf. */
		if (fzn_revocation_issue(mid, cap, leaf, 1500, &sign, rev_bytes) !=
		    FZN_CHAIN_OK)
			return 136;
		if (fzn_revocation_open(rev_bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
			return 137;

		/* With no chain it is a stranger's record, refused exactly as
		 * it always was -- which is what makes the offer below the
		 * thing that changed. */
		if (fzn_revocation_admit(&estate, fzn_revocation_offer_root(rec), root, &sign,
		                         NULL) != FZN_CHAIN_ERR_WRONG_ROOT)
			return 138;

		offer = fzn_revocation_offer_chain(rec, pair, 1);
		if (fzn_revocation_merge(&estate, &offer, 1, root, &sign, &merged, NULL) != 1 ||
		    merged != FZN_CHAIN_OK)
			return 139;
		if (estate.used != 1)
			return 140;
		if (fzn_chain_verify(pair, 2, root, cap, 2000, &sign, &estate, &chain) !=
		    FZN_CHAIN_ERR_REVOKED)
			return 141;

		/* And the entitled set is derived from the chain rather than
		 * supplied: the same store says nothing about the middle key's
		 * own one-hop chain, which the middle key is not an ancestor
		 * of. */
		if (fzn_chain_verify(pair, 1, root, cap, 2000, &sign, &estate, &chain) !=
		    FZN_CHAIN_OK)
			return 142;

		/* The verify-side predicate directly, so a change to its arity
		 * or its types is the consumer's problem too. */
		{
			uint8_t revoked[FZN_CHAIN_MAX_HOPS];

			fzn_revocation_covers_chain(&estate, pair, 2, cap, revoked);
			if (revoked[0] != 0 || revoked[1] != 1)
				return 143;
		}
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
			return 110;
		if (fzn_manifest_follow(&manifest, root) != FZN_MANIFEST_OK)
			return 111;

		/* `store` holds the one revocation the block above admitted,
		 * so the manifest derived from it names exactly that pair. */
		if (fzn_manifest_issue(root, &store, &sign, man_bytes, sizeof(man_bytes),
		                       &man_len) != FZN_MANIFEST_OK)
			return 112;
		if (man_len != FZN_MANIFEST_LEN(1))
			return 113;
		if (fzn_manifest_open(man_bytes, man_len, &man) != FZN_MANIFEST_OK)
			return 114;
		if (fzn_manifest_count(man) != 1)
			return 115;

		/* Admitted by a host that knows of no revocations, which is
		 * the fresh joiner: the pair it names is a deficit. */
		if (fzn_manifest_admit(&manifest, NULL, man, &sign) != FZN_MANIFEST_OK)
			return 116;
		if (fzn_manifest_pending(&manifest, root) != 1)
			return 117;
		if (fzn_manifest_overflowed(&manifest, root) != 0)
			return 118;
		if (fzn_manifest_deficit(&manifest, root, want, 4, &dropped) != 1 || dropped != 0)
			return 119;
		if (!fzn_ct_memeq(want[0].grantee, grantee, FZN_PUBKEY_LEN))
			return 120;

		/* And the revocation arriving settles it, which is the whole
		 * of the parameter `fzn_revocation_admit` gained. */
		if (fzn_revocation_store_init(&fresh, fresh_storage, 4) != FZN_CHAIN_OK)
			return 121;
		if (fzn_revocation_issue(root, cap, grantee, 1500, &sign, rev_bytes) !=
		    FZN_CHAIN_OK)
			return 122;
		if (fzn_revocation_open(rev_bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
			return 123;
		if (fzn_revocation_admit(&fresh, fzn_revocation_offer_root(rec), root, &sign,
		                         &manifest) != FZN_CHAIN_OK)
			return 124;
		if (fzn_manifest_pending(&manifest, root) != 0)
			return 125;
		if (fzn_manifest_err_str(FZN_MANIFEST_ERR_UNKNOWN_ISSUER) == NULL)
			return 126;
	}

	/* The two modules added after this file was written, and the reason
	 * `installcheck` now checks its own coverage: both were installed and
	 * neither was included here, so a break in either would have passed. */
	{
		fzn_peer_t peer;

		memset(&peer, 0, sizeof(peer));
		if (fzn_peer_groups_parse("Groups:\t20 24\n", 14, &peer) != 1)
			return 9;
		if (peer.group_count != 2 || !peer.groups_known)
			return 10;
		if (fzn_peer_is_member(&peer, 24) != 1)
			return 11;
		if (fzn_peer_group_verdict(&peer, 999) != FZN_PEER_NOT_MEMBER)
			return 12;

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
				return 22;
			if (fzn_vocabulary_admit(&peer, verb, sizeof(verb) - 1u,
			                         rules, 0) != FZN_PEER_NOT_MEMBER)
				return 23;
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
				return 130;
			if (sealed_len != sizeof(plain) + FZN_BLOB_LEAF_OVERHEAD)
				return 131;
			if (fzn_blob_leaf_hash(&bhash, sealed, sealed_len, leaf[i]) != FZN_BLOB_OK)
				return 132;
			if (fzn_blob_tree_push(&bhash, &tree, leaf[i]) != FZN_BLOB_OK)
				return 133;
		}
		if (fzn_blob_leaf_open(&bhash, &baead, ckey, 1u, sealed, sealed_len, back,
		                       sizeof(back), &back_len) != FZN_BLOB_OK)
			return 134;
		if (back_len != sizeof(plain) || back[0] != 1u)
			return 135;
		if (fzn_blob_tree_root(&bhash, &tree, blob_root) != FZN_BLOB_OK)
			return 136;
		if (fzn_blob_proof_build(&bhash, leaf[0], 2u, 1u, siblings, sizeof(siblings),
		                         &sibling_count) != FZN_BLOB_OK)
			return 137;
		if (fzn_blob_proof_verify(&bhash, leaf[1], 1u, 2u, siblings, sibling_count,
		                          blob_root) != FZN_BLOB_OK)
			return 138;
		/* And a refusal, so the acceptance above is not the only
		 * outcome this consumer can observe. */
		if (fzn_blob_proof_verify(&bhash, leaf[0], 1u, 2u, siblings, sibling_count,
		                          blob_root) != FZN_BLOB_ERR_PROOF)
			return 139;
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
			return 170;
		if (fzn_record_sign(owner, peer_key, 0, KIND_SHARE_LOCATION, 1, 1, yes,
		                    sizeof(yes), &ops, wire, sizeof(wire), &wrote)
		    != FZN_RECORD_OK)
			return 171;
		if (fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
			return 172;
		if (fzn_state_apply(&opt, &r) != FZN_STATE_OK)
			return 173;

		cell = fzn_state_get(&opt, peer_key, KIND_SHARE_LOCATION);
		if (!cell || !cell->live)
			return 174;
		/* And a DIFFERENT capability for the same peer is a different
		 * cell, which is the whole of "per capability". */
		if (fzn_state_get(&opt, peer_key, KIND_SHARE_LOCATION + 1u) != NULL)
			return 175;

		if (fzn_record_sign(owner, peer_key, 0, KIND_SHARE_LOCATION, 2, 1, yes,
		                    sizeof(yes), &ops, wire, sizeof(wire), &wrote)
		    != FZN_RECORD_OK)
			return 176;
		if (fzn_record_open(wire, wrote, &r) != FZN_RECORD_OK)
			return 177;
		if (fzn_state_clear(&opt, &r) != FZN_STATE_OK)
			return 178;
		if (fzn_state_get(&opt, peer_key, KIND_SHARE_LOCATION) != NULL)
			return 179;
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
			return 180;
		if (fzn_agree_secret_install(&b, &aops, b_sec) != FZN_AGREE_OK)
			return 181;
		if (!fzn_agree_secret_public(&a) || !fzn_agree_secret_public(&b))
			return 182;
		if (fzn_agree_shared(&a, &aops, fzn_agree_secret_public(&b), sa) != FZN_AGREE_OK)
			return 183;
		if (fzn_agree_shared(&b, &aops, fzn_agree_secret_public(&a), sb) != FZN_AGREE_OK)
			return 184;
		if (memcmp(sa, sb, FZN_AGREE_SHARED_LEN) != 0)
			return 185;

		/* Rotate, and the old secret must be gone. */
		if (fzn_agree_secret_install(&a, &aops, rotated) != FZN_AGREE_OK)
			return 186;
		if (fzn_agree_secret_generation(&a) != 1u)
			return 187;
		if (fzn_agree_shared(&a, &aops, fzn_agree_secret_public(&b), after) != FZN_AGREE_OK)
			return 188;
		if (memcmp(sa, after, FZN_AGREE_SHARED_LEN) == 0)
			return 189;
		fzn_agree_secret_wipe(&a);
		if (fzn_agree_secret_public(&a) != NULL)
			return 190;
		if (fzn_agree_shared(&a, &aops, fzn_agree_secret_public(&b), after)
		    != FZN_AGREE_ERR_ABSENT)
			return 191;
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
			return 150;
		if (fzn_prekey_issue(host, pk2, 200u, &sign, rec2) != FZN_PREKEY_OK)
			return 151;
		if (fzn_prekey_issue(other, pk1, 300u, &sign, rec3) != FZN_PREKEY_OK)
			return 152;
		if (fzn_prekey_open(rec1, sizeof(rec1), &r1) != FZN_PREKEY_OK)
			return 153;
		if (fzn_prekey_open(rec2, sizeof(rec2), &r2) != FZN_PREKEY_OK)
			return 154;
		if (fzn_prekey_open(rec3, sizeof(rec3), &r3) != FZN_PREKEY_OK)
			return 155;
		if (fzn_prekey_verify(r1, &sign) != FZN_PREKEY_OK)
			return 156;

		fzn_prekey_peer_init(&peer);
		if (fzn_prekey_pin(&peer, r1, &sign, FZN_TRUST_ADOPTED, 1u) != FZN_PREKEY_OK)
			return 157;
		if (fzn_trust_source_of(&peer.trust) != FZN_TRUST_ADOPTED)
			return 158;
		/* A rotation forward, then the same record back again, then a
		 * different host: three outcomes, three codes. */
		if (fzn_prekey_pin(&peer, r2, &sign, FZN_TRUST_ADOPTED, 2u) != FZN_PREKEY_OK)
			return 159;
		if (fzn_prekey_pin(&peer, r1, &sign, FZN_TRUST_ADOPTED, 3u)
		    != FZN_PREKEY_ERR_ROLLBACK)
			return 160;
		if (fzn_prekey_pin(&peer, r3, &sign, FZN_TRUST_ADOPTED, 4u)
		    != FZN_PREKEY_ERR_WRONG_HOST)
			return 161;
		/* And a rotation must not raise an adopted anchor to a
		 * confirmed one, which is the provenance a consumer shows its
		 * user. */
		if (fzn_trust_source_of(&peer.trust) != FZN_TRUST_ADOPTED)
			return 162;
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
				return 140;

		fzn_ratchet_init(&ratchet, ck, 0);
		/* THE WHOLE RECIPE, since it is the thing a consumer has to get
		 * right: derive into a SEPARATE chain, verify, then commit. The
		 * in-place form is refused, so there is no other way to spell
		 * it. */
		if (fzn_ratchet_advance(&rhash, &ratchet, 3u, jumped, &next_ratchet, NULL, 0,
		                        NULL, NULL) != FZN_RATCHET_OK)
			return 141;
		if (memcmp(jumped, mk, FZN_MESSAGE_KEY_LEN) != 0)
			return 142;
		if (ratchet.seq != 0u || next_ratchet.seq != 4u)
			return 143;
		ratchet = next_ratchet; /* committed, as a real caller would after opening */
		if (fzn_ratchet_advance(&rhash, &ratchet, 3u, jumped, &ratchet, NULL, 0, NULL,
		                        NULL) != FZN_RATCHET_ERR_IN_PLACE)
			return 144;
		/* A duplicate and a caller bug must not share a code, which is
		 * the distinction a consumer's logging depends on. */
		if (fzn_ratchet_advance(&rhash, &ratchet, 0, jumped, &next_ratchet, NULL, 0,
		                        NULL, NULL) != FZN_RATCHET_ERR_BEHIND)
			return 145;
		if (fzn_ratchet_advance(&rhash, &ratchet,
		                        ratchet.seq + (uint64_t)FZN_RATCHET_MAX_ADVANCE + 1u,
		                        jumped, &next_ratchet, NULL, 0, NULL, NULL)
		    != FZN_RATCHET_ERR_TOO_FAR)
			return 146;
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
			return 18;
		if (FZN_AEAD_NONCE_LEN != FZN_NONCE_LEN)
			return 19;
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
			return 20;
		fzn_random_system_init(&rng);
#if defined(__linux__)
		if (!rng.fill || fzn_nonce_next(&rng, aead_nonce) != 1)
			return 21;
#endif
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
			return 14;

		/* A verify-only signer holds no key and must not claim to sign. */
		if (signer.can_sign)
			return 15;
		fzn_sign_monocypher_wipe(&signer);

		fzn_hash_monocypher_init(&real_hash);
		if (!real_hash.hash)
			return 16;
		if (!real_hash.hash(real_hash.ctx, derived, sizeof(derived), region,
		                    sizeof(region) - 1))
			return 17;

		/* One call through the AEAD binding, to the same standard as the
		 * two above: enough to prove the header and the source go
		 * together. A null op here is the whole failure this is watching
		 * for -- a binding that installs and does not link. */
		fzn_aead_monocypher_init(&real_aead);
		if (!real_aead.seal || !real_aead.open)
			return 18;

		/* And the agreement binding, to the same standard: a binding
		 * that installs and does not link is the failure this watches
		 * for. */
		{
			fzn_agree_ops_t real_agree;

			fzn_agree_monocypher_init(&real_agree);
			if (!real_agree.public_of || !real_agree.agree)
				return 19;
		}
	}

	printf("consumer_check: headers and sources agree, Monocypher bindings included\n");
	return 0;
#else
	printf("consumer_check: headers and sources agree\n");
	return 0;
#endif
}
