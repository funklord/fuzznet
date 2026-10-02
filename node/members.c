/* See members.h. */

#include "members.h"

#include "../wire/bytes.h"

#include <string.h>

/* The largest page a puller takes whole: a few members at their longest. */
#define PULL_REPLY_MAX 16384u
/* Pages a pull asks for at most: far past what FZN_NODE_PEERS_MAX needs. */
#define PULL_PAGES_MAX 256u
#define NOTES_SYNC_VERSION 2u

const char *fzn_node_members_err_str(fzn_node_members_err_t err)
{
	switch (err) {
	case FZN_NODE_MEMBERS_OK:
		return "ok";
	case FZN_NODE_MEMBERS_ERR_MALFORMED:
		return "malformed";
	case FZN_NODE_MEMBERS_ERR_NO_ANSWER:
		return "the peer did not answer";
	case FZN_NODE_MEMBERS_ERR_SHAPE:
		return "the peer answered with something else";
	}
	return "unknown";
}

size_t fzn_node_members_answer(const fzn_node_config_t *config, const fzn_node_peer_t *peers,
                               size_t peer_count, const uint8_t *request, size_t request_len,
                               uint8_t *reply, size_t reply_cap)
{
	size_t total = 0, from, i, seen = 0, n = 0, used = FZN_NODE_MEMBERS_HEAD_LEN;

	if (!config || (!peers && peer_count) || !request || !reply
	    || request_len != FZN_NODE_MEMBERS_QUERY_LEN || request[0] != NOTES_SYNC_VERSION
	    || request[1] != FZN_NODE_MEMBERS_QUERY || reply_cap < FZN_NODE_MEMBERS_HEAD_LEN)
		return 0;
	from = fzn_get_be16(request + 2);
	/* A CONTACT IS NO MEMBER: a share's chain is not membership. */
	for (i = 0; i < peer_count; i++)
		if (!fzn_node_peer_contact(config, &peers[i]))
			total++;
	for (i = 0; i < peer_count; i++) {
		const fzn_node_peer_t *p = &peers[i];
		size_t need = FZN_PUBKEY_LEN + 1u + (p->hop_count * FZN_HOP_LEN), h;

		if (fzn_node_peer_contact(config, p))
			continue;
		if (seen++ < from)
			continue;
		if (p->hop_count == 0u || p->hop_count > FZN_CHAIN_MAX_HOPS || n >= 255u
		    || reply_cap - used < need)
			break;
		memcpy(reply + used, p->sender, FZN_PUBKEY_LEN);
		reply[used + FZN_PUBKEY_LEN] = (uint8_t)p->hop_count;
		for (h = 0; h < p->hop_count; h++)
			memcpy(reply + used + FZN_PUBKEY_LEN + 1u + (h * FZN_HOP_LEN), p->hop_bytes[h],
			       FZN_HOP_LEN);
		used += need;
		n++;
	}
	reply[0] = NOTES_SYNC_VERSION;
	reply[1] = FZN_NODE_MEMBERS_REPLY;
	fzn_put_be16(reply + 2, (uint16_t)total);
	fzn_put_be16(reply + 4, (uint16_t)(from > total ? total : from));
	reply[6] = (uint8_t)n;
	return used;
}

/* One entry's chain, proved: it verifies against `root` for `capability` and
 * authorises the key it is listed under. */
static int proves(const uint8_t *key, const uint8_t *hops, size_t hop_count,
                  const uint8_t root[FZN_PUBKEY_LEN], const fzn_cap_id_t *capability,
                  uint64_t now, const fzn_sign_ops_t *sign,
                  const fzn_revocation_store_t *revocations)
{
	fzn_chain_hop_t views[FZN_CHAIN_MAX_HOPS];
	fzn_chain_t verdict;
	size_t h;

	for (h = 0; h < hop_count; h++)
		if (fzn_hop_open(hops + (h * FZN_HOP_LEN), FZN_HOP_LEN, &views[h]) != FZN_CHAIN_OK)
			return 0;
	return fzn_chain_verify(views, hop_count, root, capability, now, sign, revocations, NULL,
	                        &verdict)
	               == FZN_CHAIN_OK
	       && memcmp(verdict.grantee, key, FZN_PUBKEY_LEN) == 0;
}

fzn_node_members_err_t fzn_node_members_pull(fzn_node_members_ask_t ask, void *ask_ctx,
                                             const uint8_t root[FZN_PUBKEY_LEN],
                                             const fzn_cap_id_t *capability, uint64_t now,
                                             const fzn_sign_ops_t *sign,
                                             const fzn_revocation_store_t *revocations,
                                             uint8_t (*out)[FZN_PUBKEY_LEN], size_t cap,
                                             size_t *count, size_t *refused)
{
	static uint8_t reply[PULL_REPLY_MAX];
	uint8_t request[FZN_NODE_MEMBERS_QUERY_LEN];
	size_t from = 0, total = 0, pages;

	if (!ask || !root || !capability || !sign || !out || !count || !refused)
		return FZN_NODE_MEMBERS_ERR_MALFORMED;
	*count = 0;
	*refused = 0;
	for (pages = 0; pages < PULL_PAGES_MAX; pages++) {
		size_t reply_len = 0, n, i, at = FZN_NODE_MEMBERS_HEAD_LEN;

		request[0] = NOTES_SYNC_VERSION;
		request[1] = FZN_NODE_MEMBERS_QUERY;
		fzn_put_be16(request + 2, (uint16_t)from);
		if (!ask(ask_ctx, request, sizeof(request), reply, sizeof(reply), &reply_len))
			return FZN_NODE_MEMBERS_ERR_NO_ANSWER;
		if (reply_len < FZN_NODE_MEMBERS_HEAD_LEN || reply[0] != NOTES_SYNC_VERSION
		    || reply[1] != FZN_NODE_MEMBERS_REPLY || fzn_get_be16(reply + 4) != from)
			return FZN_NODE_MEMBERS_ERR_SHAPE;
		total = fzn_get_be16(reply + 2);
		n = reply[6];
		for (i = 0; i < n; i++) {
			const uint8_t *key = reply + at;
			size_t hop_count, k;
			int have = 0;

			if (reply_len - at < FZN_PUBKEY_LEN + 1u)
				return FZN_NODE_MEMBERS_ERR_SHAPE;
			hop_count = reply[at + FZN_PUBKEY_LEN];
			if (hop_count == 0u || hop_count > FZN_CHAIN_MAX_HOPS
			    || reply_len - at - FZN_PUBKEY_LEN - 1u < hop_count * FZN_HOP_LEN)
				return FZN_NODE_MEMBERS_ERR_SHAPE;
			/* ADMITTED ONLY ON PROOF, and once. */
			for (k = 0; k < *count && !have; k++)
				have = memcmp(out[k], key, FZN_PUBKEY_LEN) == 0;
			if (!have) {
				if (!proves(key, reply + at + FZN_PUBKEY_LEN + 1u, hop_count, root,
				            capability, now, sign, revocations)
				    || *count >= cap)
					(*refused)++;
				else
					memcpy(out[(*count)++], key, FZN_PUBKEY_LEN);
			}
			at += FZN_PUBKEY_LEN + 1u + (hop_count * FZN_HOP_LEN);
		}
		if (at != reply_len)
			return FZN_NODE_MEMBERS_ERR_SHAPE;
		from += n;
		/* A PAGE THAT BRINGS NOTHING ends it, or a short server would be
		 * asked the same page for ever. */
		if (from >= total || n == 0u)
			break;
	}
	return FZN_NODE_MEMBERS_OK;
}
