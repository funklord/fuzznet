/* See peer_persist.h. */

#include "peer_persist.h"

#include <string.h>

/* Offsets within the body, named once so pack and open cannot disagree about
 * where a field is -- which is the failure a second set of literals makes
 * silent, because both halves compile. */
#define OFF_SENDER 0u
#define OFF_RECV_KEY (OFF_SENDER + (size_t)FZN_PUBKEY_LEN)
#define OFF_RECV_CKEY (OFF_RECV_KEY + (size_t)FZN_AEAD_KEY_LEN)
#define OFF_HOP_COUNT (OFF_RECV_CKEY + (size_t)FZN_COMMITMENT_KEY_LEN)
#define OFF_HOPS (OFF_HOP_COUNT + 1u)

_Static_assert(OFF_HOPS == FZN_NODE_PEER_BODY_FIXED,
               "the fixed body and the offsets disagree");

static size_t body_for(size_t hop_count)
{
	return FZN_NODE_PEER_BODY_FIXED + hop_count * (size_t)FZN_HOP_LEN;
}

fzn_persist_err_t fzn_node_peer_pack(const fzn_node_peer_t *peer, uint8_t *out,
                                     size_t cap, size_t *len)
{
	size_t body;
	size_t i;
	fzn_persist_err_t err;

	if (!peer || !out || !len)
		return FZN_PERSIST_ERR_MALFORMED;
	/* A PEER THIS LIBRARY WOULD REFUSE TO VERIFY IS NOT ONE IT WRITES
	 * DOWN. `fzn_chain_verify` refuses a hop count past the maximum, so a
	 * blob carrying one would restore a peer that can never authorise --
	 * present in the file, listed by the node, and silently useless. */
	if (peer->hop_count > (size_t)FZN_CHAIN_MAX_HOPS)
		return FZN_PERSIST_ERR_MALFORMED;

	body = body_for(peer->hop_count);
	err = fzn_persist_head_write(out, cap, body, FZN_PERSIST_BLOB_NODE_PEER);
	if (err != FZN_PERSIST_OK)
		return err;

	memcpy(out + FZN_PERSIST_HEAD_LEN + OFF_SENDER, peer->sender,
	       FZN_PUBKEY_LEN);
	memcpy(out + FZN_PERSIST_HEAD_LEN + OFF_RECV_KEY, peer->recv_key,
	       FZN_AEAD_KEY_LEN);
	memcpy(out + FZN_PERSIST_HEAD_LEN + OFF_RECV_CKEY, peer->recv_ckey,
	       FZN_COMMITMENT_KEY_LEN);
	out[FZN_PERSIST_HEAD_LEN + OFF_HOP_COUNT] = (uint8_t)peer->hop_count;
	for (i = 0; i < peer->hop_count; i++)
		memcpy(out + FZN_PERSIST_HEAD_LEN + OFF_HOPS +
		           (i * (size_t)FZN_HOP_LEN),
		       peer->hop_bytes[i], FZN_HOP_LEN);
	*len = FZN_PERSIST_HEAD_LEN + body;
	return FZN_PERSIST_OK;
}

fzn_persist_err_t fzn_node_peer_open(const uint8_t *bytes, size_t len,
                                     fzn_node_peer_t *out)
{
	size_t hop_count;
	size_t i;
	fzn_persist_err_t err;

	if (!bytes || !out)
		return FZN_PERSIST_ERR_MALFORMED;
	/* THE COUNT IS INSIDE THE BODY, so it is read before the length can be
	 * checked against it -- and reading it needs its own bound first, or
	 * the read is past the end of a short blob. The order is: enough bytes
	 * to hold the count, then the count, then the exact length. */
	if (len < FZN_PERSIST_HEAD_LEN + FZN_NODE_PEER_BODY_FIXED)
		return FZN_PERSIST_ERR_SHAPE;
	hop_count = bytes[FZN_PERSIST_HEAD_LEN + OFF_HOP_COUNT];
	if (hop_count > (size_t)FZN_CHAIN_MAX_HOPS)
		return FZN_PERSIST_ERR_SHAPE;
	/* Exact, version and tag, all from the shared head check -- so a blob
	 * claiming eight hops and carrying two is refused here rather than
	 * opened with six hops of whatever followed it in the file. */
	err = fzn_persist_head_check(bytes, len, body_for(hop_count),
	                             FZN_PERSIST_BLOB_NODE_PEER);
	if (err != FZN_PERSIST_OK)
		return err;

	memset(out, 0, sizeof(*out));
	memcpy(out->sender, bytes + FZN_PERSIST_HEAD_LEN + OFF_SENDER,
	       FZN_PUBKEY_LEN);
	memcpy(out->recv_key, bytes + FZN_PERSIST_HEAD_LEN + OFF_RECV_KEY,
	       FZN_AEAD_KEY_LEN);
	memcpy(out->recv_ckey, bytes + FZN_PERSIST_HEAD_LEN + OFF_RECV_CKEY,
	       FZN_COMMITMENT_KEY_LEN);
	out->hop_count = hop_count;
	for (i = 0; i < hop_count; i++)
		memcpy(out->hop_bytes[i],
		       bytes + FZN_PERSIST_HEAD_LEN + OFF_HOPS +
		           (i * (size_t)FZN_HOP_LEN),
		       FZN_HOP_LEN);
	return FZN_PERSIST_OK;
}
