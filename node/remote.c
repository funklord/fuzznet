/* See remote.h. */

#include "remote.h"

#include <string.h>

fzn_node_remote_result_t fzn_node_serve_datagram(const fzn_node_config_t *config,
                                                 const fzn_node_peer_t *peer,
                                                 const fzn_hash_ops_t *hash,
                                                 const fzn_aead_ops_t *aead,
                                                 const fzn_sign_ops_t *sign,
                                                 uint64_t now, uint8_t *frame,
                                                 size_t frame_len,
                                                 fzn_opened_t *opened)
{
	const uint8_t *sender;
	fzn_opened_t scratch;
	fzn_authz_verdict_t verdict;

	if (!config || !peer || !hash || !aead || !frame)
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

	/* A command carries an expiry and a stale one is not served: grants
	 * do not expire, commands do (sec 4.3). Zero is no expiry. */
	if (opened->expires_at != 0 && opened->expires_at <= now)
		return FZN_NODE_REMOTE_DROPPED;

	/* Authorise: the capability chain this peer holds must grant what the
	 * node requires, from the REMOTE origin. */
	verdict = fzn_node_decide(config, FZN_ORIGIN_REMOTE, peer->hops,
	                          peer->hop_count, now, sign, NULL, NULL);
	return (verdict == FZN_AUTHZ_DENIED) ? FZN_NODE_REMOTE_DENIED
	                                     : FZN_NODE_REMOTE_GRANTED;
}
