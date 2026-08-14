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
#include <fuzznet/session/commitment.h>
#else
#include "chain/chain.h"
#include "chain/revocation.h"
#include "chunk/reassembly.h"
#include "chunk/split.h"
#include "constant_time/constant_time.h"
#include "frame/freshness.h"
#include "local/peer.h"
#include "session/commitment.h"
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

		(void)unused_store;
		if (FZN_DERIVED_LEN != FZN_AEAD_KEY_LEN + FZN_COMMITMENT_LEN)
			return 13;
	}

	printf("consumer_check: headers and sources agree\n");
	return 0;
}
