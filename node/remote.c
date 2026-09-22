/* See remote.h. */

#include "remote.h"

#include <string.h>

#include "../frame/freshness.h"

fzn_node_remote_result_t fzn_node_serve_datagram(const fzn_node_config_t *config,
                                                 const fzn_node_peer_t *peer,
                                                 const fzn_hash_ops_t *hash,
                                                 const fzn_aead_ops_t *aead,
                                                 const fzn_sign_ops_t *sign,
                                                 fzn_replay_window_t *replay,
                                                 uint64_t now, uint8_t *frame,
                                                 size_t frame_len,
                                                 fzn_opened_t *opened)
{
	const uint8_t *sender;
	fzn_opened_t scratch;
	fzn_authz_verdict_t verdict;
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	size_t i;

	if (!config || !peer || !hash || !aead || !frame || !replay)
		return FZN_NODE_REMOTE_DROPPED;
	if (!opened)
		opened = &scratch;

	/* Which session key to try is named by the sender in the clear. */
	if (fzn_seal_peek_sender(frame, frame_len, &sender) != FZN_SEAL_OK)
		return FZN_NODE_REMOTE_DROPPED;
	/* The daemon routed this peer by that sender; a frame whose sender
	 * does not match the session it arrived on is not this peer's. */
	if (memcmp(sender, peer->sender, FZN_PUBKEY_LEN) != 0)
		return FZN_NODE_REMOTE_DROPPED;

	/* Authenticate: the seal opens only under the session key the two
	 * agreed, so a frame that opens is one this peer sealed. */
	if (fzn_seal_open(frame, frame_len, peer->recv_key, peer->recv_ckey,
	                  hash, aead, opened) != FZN_SEAL_OK)
		return FZN_NODE_REMOTE_DROPPED;

	/* Freshness and replay in one call on the authenticated frame (sec 4.7
	 * steps 5-6): a command must carry an expiry neither passed nor beyond
	 * the window's horizon, and a nonce already seen is refused. The admit
	 * records the nonce only if it passes, so a forgery -- which never
	 * opened the seal above -- spends no slot. */
	if (fzn_replay_admit(replay, opened->nonce, opened->expires_at,
	                     FZN_EXPIRY_REQUIRED, now) != FZN_FRESH_OK)
		return FZN_NODE_REMOTE_DROPPED;

	/* Open the peer's owned hop bytes into views the decision reads. The
	 * views point into peer->hop_bytes, which outlives this call. */
	for (i = 0; i < peer->hop_count && i < FZN_CHAIN_MAX_HOPS; i++)
		if (fzn_hop_open(peer->hop_bytes[i], FZN_HOP_LEN, &hops[i]) !=
		    FZN_CHAIN_OK)
			return FZN_NODE_REMOTE_DENIED;

	/* Authorise: the capability chain this peer holds must grant what the
	 * node requires, from the REMOTE origin. */
	verdict = fzn_node_decide(config, FZN_ORIGIN_REMOTE, hops,
	                          peer->hop_count, now, sign, NULL, NULL);
	return (verdict == FZN_AUTHZ_DENIED) ? FZN_NODE_REMOTE_DENIED
	                                     : FZN_NODE_REMOTE_GRANTED;
}

int fzn_node_seal_reply_chunk(const fzn_node_peer_t *peer,
                              const uint8_t node_pubkey[FZN_PUBKEY_LEN],
                              const uint8_t *payload, size_t payload_len,
                              uint32_t msg, uint16_t index, uint16_t chunks,
                              uint64_t expires_at,
                              const fzn_hash_ops_t *hash,
                              const fzn_random_ops_t *rng,
                              const fzn_aead_ops_t *aead, uint8_t *out,
                              size_t out_cap, size_t *out_len)
{
	fzn_send_t what;
	static const uint8_t no_cap[FZN_CAP_ID_LEN] = { 0 };

	if (!peer || !node_pubkey || (!payload && payload_len) || !hash || !rng ||
	    !aead || !out || !out_len)
		return -1;
	/* NO INDEX/CHUNKS GUARD HERE, and there was one until the sabotage run
	 * showed nothing could see it. `fzn_seal_build` already refuses
	 * `index > chunks - 1`, widened to int64_t so a `chunks` of zero gives
	 * -1 and refuses every index -- its comment records that widening as
	 * load-bearing. A copy here was a second statement of one rule, which
	 * is the thing this tree keeps paying for, and it could not be shown
	 * to fail because the real check intercepted every case. The tests
	 * below still drive both refusals; they simply prove seal.c's rule. */

	memset(&what, 0, sizeof(what));
	/* The reply is from the node, and carries no capability: the caller
	 * does not authorise the node. */
	what.sender = node_pubkey;
	what.capability = no_cap;
	what.payload = payload;
	what.payload_len = payload_len;
	what.expires_at = expires_at;
	what.msg = msg;
	what.index = index;
	what.chunks = chunks;
	/* DERIVED, NEVER PASSED. A CHUNK frame claiming to be the only piece,
	 * or a UNIT frame that is one of several, are states a receiver would
	 * have to reconcile and a caller has no reason to be able to build. */
	what.kind = (chunks == 1u) ? FZN_KIND_UNIT : FZN_KIND_CHUNK;
	/* Sealed under the peer session key, which is symmetric, so the caller
	 * opens it with the key it seals its own requests with. */
	if (fzn_seal_build(out, out_cap, out_len, &what, peer->recv_key,
	                   peer->recv_ckey, hash, rng, aead) != FZN_SEAL_OK)
		return -1;
	return 0;
}

int fzn_node_seal_reply(const fzn_node_peer_t *peer,
                        const uint8_t node_pubkey[FZN_PUBKEY_LEN],
                        const uint8_t *payload, size_t payload_len,
                        uint32_t msg, uint64_t expires_at,
                        const fzn_hash_ops_t *hash, const fzn_random_ops_t *rng,
                        const fzn_aead_ops_t *aead, uint8_t *out, size_t out_cap,
                        size_t *out_len)
{
	/* The one-piece case, and it is a call rather than a copy so the two
	 * cannot come to disagree about what a reply head carries. */
	return fzn_node_seal_reply_chunk(peer, node_pubkey, payload, payload_len,
	                                 msg, 0u, 1u, expires_at, hash, rng, aead,
	                                 out, out_cap, out_len);
}
