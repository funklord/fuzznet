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
#include <fuzznet/record/record.h>
#include <fuzznet/record/sync.h>
#include <fuzznet/state/state.h>
#include <fuzznet/trust/trust.h>
#include <fuzznet/session/random_system.h>
#include <fuzznet/version/version.h>
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
#include "record/record.h"
#include "record/sync.h"
#include "state/state.h"
#include "trust/trust.h"
#include "session/random_system.h"
#include "version/version.h"
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
#else
#include "chain/sign_monocypher.h"
#include "session/hash_monocypher.h"
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

int main(void)
{
	static const uint8_t region[] = "a signed region";
	fzn_sign_ops_t sign = { always_good, NULL, NULL };
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
		if (fzn_journal_admit(&journal, issuer, 1) != FZN_JOURNAL_OK)
			return 31;
		if (fzn_journal_admit(&journal, issuer, 1) != FZN_JOURNAL_ERR_DUPLICATE)
			return 32;
		if (fzn_journal_next(&journal, issuer) != 2)
			return 33;
		{
			fzn_sync_position_t theirs;
			fzn_sync_request_t want;
			fzn_sync_plan_t plan;

			memcpy(theirs.issuer, issuer, FZN_PUBKEY_LEN);
			theirs.received = 4;
			if (fzn_sync_plan_fetch(&journal, &theirs, 1, 8, &want, 1, &plan) !=
			    FZN_SYNC_OK)
				return 34;
			if (plan.request_count != 1 || want.from != 2 || want.count != 3)
				return 35;
		}
	}

	/* And the state layer: a value set, superseded by its own issuer, and
	 * refused to another's. Reached through installed headers. */
	{
		fzn_state_t st;
		fzn_state_entry_t slots[2];
		fzn_record_t r;
		static const uint8_t body[] = "v";

		if (fzn_state_init(&st, slots, 2) != FZN_STATE_OK)
			return 40;
		memset(&r, 0, sizeof(r));
		memset(r.issuer, 0x01, sizeof(r.issuer));
		memset(r.subject, 0x02, sizeof(r.subject));
		r.kind = 1;
		r.seq = 1;
		r.body = body;
		r.body_len = sizeof(body);
		if (fzn_state_apply(&st, &r) != FZN_STATE_OK)
			return 41;
		r.seq = 2;
		if (fzn_state_apply(&st, &r) != FZN_STATE_OK)
			return 42;
		r.seq = 1;
		if (fzn_state_apply(&st, &r) != FZN_STATE_ERR_STALE)
			return 43;
		memset(r.issuer, 0x09, sizeof(r.issuer));
		r.seq = 99;
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

	if (fzn_version_number() != (unsigned long)FZN_VERSION_NUMBER)
		return 20;
	if (strcmp(fzn_version_string(), FZN_VERSION_STRING) != 0)
		return 21;

	if (fzn_split_plan(100, 8, &plan) != FZN_SPLIT_OK || plan.chunks != 13)
		return 2;

	if (fzn_replay_init(&window, window_storage, 4) != FZN_FRESH_OK)
		return 3;
	if (fzn_replay_admit(&window, nonce, 2000, FZN_FRAME_COMMAND, 1000) != FZN_FRESH_OK)
		return 4;
	if (fzn_replay_admit(&window, nonce, 2000, FZN_FRAME_COMMAND, 1000) !=
	    FZN_FRESH_ERR_REPLAY)
		return 5;

	if (fzn_revocation_store_init(&store, store_storage, 4) != FZN_OK)
		return 6;

	memset(&hop, 0, sizeof(hop));
	memcpy(hop.grantor, root, sizeof(root));
	memcpy(hop.capability, cap, sizeof(cap));
	memset(hop.grantee, 0x09, sizeof(hop.grantee));
	hop.issued_at = 100;
	hop.signed_region = region;
	hop.signed_region_len = sizeof(region) - 1;

	if (fzn_chain_verify(&hop, 1, root, cap, 2000, &sign, store.entries, store.used,
	                     &chain) != FZN_OK)
		return 7;
	if (chain.hop_count != 1)
		return 8;

	/* The two modules added after this file was written, and the reason
	 * `installcheck` now checks its own coverage: both were installed and
	 * neither was included here, so a break in either would have passed. */
	{
		fzn_peer_t peer;
		fzn_revocation_store_t unused_store;

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

		(void)unused_store;
		if (FZN_DERIVED_LEN != FZN_AEAD_KEY_LEN + FZN_COMMITMENT_LEN)
			return 13;
	}

#ifdef FZN_CONSUMER_MONOCYPHER
	/* One call through each binding, which is this file's standard: enough
	 * to prove the header and the source go together, not a test of the
	 * cryptography -- chain/test/sign_monocypher_test.c does that. */
	{
		fzn_sign_monocypher_t signer;
		fzn_sign_ops_t real_sign;
		fzn_hash_ops_t real_hash;
		uint8_t derived[FZN_DERIVED_LEN];

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
	}
	/* The frame path. A consumer takes this to open a datagram, so the
	 * check is that the header and the source go together and that a
	 * refused open is refused -- not that the cryptography works, which
	 * wire/test/seal_test.c covers. A null AEAD is the cheapest refusal
	 * that reaches the argument guard. */
	{
		fzn_opened_t opened;
		uint8_t frame[144];
		uint8_t key[FZN_AEAD_KEY_LEN], commit[FZN_COMMITMENT_LEN];

		memset(frame, 0, sizeof(frame));
		memset(key, 0x11, sizeof(key));
		memset(commit, 0x22, sizeof(commit));
		if (fzn_seal_open(frame, sizeof(frame), key, commit, NULL, &opened) !=
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
		uint8_t nonce[FZN_AEAD_NONCE_LEN];

		memset(nonce, 0x5a, sizeof(nonce));
		if (fzn_nonce_next(&rng, nonce) != 0)
			return 20;
		fzn_random_system_init(&rng);
#if defined(__linux__)
		if (!rng.fill || fzn_nonce_next(&rng, nonce) != 1)
			return 21;
#endif
	}

	printf("consumer_check: headers and sources agree, Monocypher bindings included\n");
	return 0;
#else
	printf("consumer_check: headers and sources agree\n");
	return 0;
#endif
}
