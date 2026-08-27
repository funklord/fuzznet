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

/* The optional Monocypher bindings, which ship only when MONOCYPHER_DIR names
 * a checkout -- and which `install` then puts in the tree alongside the rest.
 *
 * They are here because the HDRS check above them found them missing: with
 * the bindings built, `make installcheck` refused, saying it would "pass
 * whatever those headers did". It was right. Two headers were installable and
 * unverifiable, in the configuration that is hardest to notice because the
 * default build never produces it. */
#ifdef FZN_CONSUMER_MONOCYPHER
#ifdef FZN_CONSUMER_INSTALLED
#include <fuzznet/chain/sign_monocypher.h>
#include <fuzznet/session/hash_monocypher.h>
#include <fuzznet/session/aead_monocypher.h>
#else
#include "chain/sign_monocypher.h"
#include "session/hash_monocypher.h"
#include "session/aead_monocypher.h"
#endif
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
		if (fzn_revocation_admit(&store, rec, root, &sign) != FZN_CHAIN_OK)
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
	}

	printf("consumer_check: headers and sources agree, Monocypher bindings included\n");
	return 0;
#else
	printf("consumer_check: headers and sources agree\n");
	return 0;
#endif
}
