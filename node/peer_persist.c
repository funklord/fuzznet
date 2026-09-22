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

fzn_persist_err_t fzn_node_peer_save(const fzn_persist_ops_t *ops,
                                     const fzn_node_peer_t *peer)
{
	uint8_t blob[FZN_NODE_PEER_BLOB_MAX];
	size_t len = 0;
	fzn_persist_err_t err;

	if (!ops || !ops->save || !peer)
		return FZN_PERSIST_ERR_MALFORMED;
	err = fzn_node_peer_pack(peer, blob, sizeof(blob), &len);
	if (err != FZN_PERSIST_OK)
		return err;
	/* Keyed by the peer's own identity, which is what `list` hands back and
	 * what `load` then asks for -- so the three agree by construction
	 * rather than by a caller remembering the convention. */
	if (!ops->save(ops->ctx, FZN_PERSIST_NODE_PEER, peer->sender, blob, len))
		return FZN_PERSIST_ERR_BACKEND;
	return FZN_PERSIST_OK;
}

fzn_persist_err_t fzn_node_peers_load(const fzn_persist_ops_t *ops,
                                      fzn_node_peer_t *out, size_t cap,
                                      size_t *count)
{
	uint8_t subjects[FZN_NODE_PEERS_MAX * FZN_PUBKEY_LEN];
	uint8_t blob[FZN_NODE_PEER_BLOB_MAX];
	size_t found = 0;
	size_t i;

	if (!ops || !ops->load || !out || !count)
		return FZN_PERSIST_ERR_MALFORMED;
	*count = 0;
	/* REPORTED, NOT TURNED INTO AN EMPTY SET. peer_persist.h says why: an
	 * empty set and "I cannot tell you" look identical to a caller and
	 * mean opposite things. */
	if (!ops->list)
		return FZN_PERSIST_ERR_BACKEND;
	if (cap > FZN_NODE_PEERS_MAX)
		cap = FZN_NODE_PEERS_MAX;
	if (!ops->list(ops->ctx, FZN_PERSIST_NODE_PEER, subjects, cap, &found))
		return FZN_PERSIST_ERR_BACKEND;

	for (i = 0; i < found; i++) {
		size_t len = 0;
		fzn_persist_err_t err;

		if (!ops->load(ops->ctx, FZN_PERSIST_NODE_PEER,
		               subjects + (i * (size_t)FZN_PUBKEY_LEN), blob,
		               sizeof(blob), &len))
			return FZN_PERSIST_ERR_BACKEND;
		err = fzn_node_peer_open(blob, len, &out[i]);
		if (err != FZN_PERSIST_OK)
			return err;
		/* THE FILE'S NAME AND THE BLOB'S CONTENTS MUST AGREE. A record
		 * stored under one identity and carrying another is either a
		 * corrupted store or a file somebody placed, and serving it would
		 * mean the node answers to a key the store does not index --
		 * findable by nothing, removable by nothing. */
		if (memcmp(out[i].sender, subjects + (i * (size_t)FZN_PUBKEY_LEN),
		           FZN_PUBKEY_LEN) != 0)
			return FZN_PERSIST_ERR_SHAPE;
	}
	*count = found;
	return FZN_PERSIST_OK;
}
