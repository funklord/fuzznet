/* See members.h. */

#include "members.h"
#include "../wire/generated/members_wire.h"
#include "../wire/generated/members_wire_build.h"

#include "../wire/bytes.h"

#include <string.h>

/* The largest page a puller takes whole: a few members at their longest. */
#define PULL_REPLY_MAX 16384u
/* Pages a pull asks for at most: far past what FZN_NODE_PEERS_MAX needs. */
#define PULL_PAGES_MAX 256u
#include "../wire/cmd.h"

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
	situ_msg_t m, out;
	situ_view_t q, v;

	/* THE QUERY READ AS THE SCHEMA SAYS, sec 1394. */
	if (!config || (!peers && peer_count) || !request || !reply
	    || request_len != FZN_NODE_MEMBERS_QUERY_LEN || reply_cap < FZN_NODE_MEMBERS_HEAD_LEN
	    || reply_cap > UINT32_MAX)
		return 0;
	situ_msg_init(&m, (uint8_t *)(uintptr_t)request, (uint32_t)request_len);
	if (fzn_members_wire_fzn_members_query_view(&m, 0u, &q) != SITU_OK
	    || fzn_members_wire_fzn_members_query_validate(q) != SITU_OK)
		return 0;
	from = fzn_members_wire_fzn_members_query_from_get(q);
	/* A CONTACT IS NO MEMBER: a share's chain is not membership. */
	for (i = 0; i < peer_count; i++)
		if (!fzn_node_peer_contact(config, &peers[i]))
			total++;
	for (i = 0; i < peer_count; i++) {
		const fzn_node_peer_t *p = &peers[i];
		size_t need = FZN_PUBKEY_LEN + 1u + (p->hop_count * FZN_HOP_LEN);
		uint32_t wrote = 0;

		if (fzn_node_peer_contact(config, p))
			continue;
		if (seen++ < from)
			continue;
		if (p->hop_count == 0u || p->hop_count > FZN_CHAIN_MAX_HOPS || n >= 255u
		    || reply_cap - used < need)
			break;
		/* EACH MEMBER BUILT BY THE GENERATED BUILDER, sec 1394. */
		if (fzn_members_wire_fzn_members_member_build(reply + used, (uint32_t)(reply_cap - used), p->sender,
		                                              &p->hop_bytes[0][0],
		                                              (uint32_t)(p->hop_count * FZN_HOP_LEN), &wrote)
		            != SITU_OK
		    || wrote != need)
			return 0;
		used += need;
		n++;
	}
	/* THE HEAD WRITTEN THROUGH ITS VIEW, the members already in place. */
	situ_msg_init(&out, reply, (uint32_t)used);
	if (fzn_members_wire_fzn_members_page_view(&out, 0u, (uint32_t)used, &v) != SITU_OK)
		return 0;
	fzn_members_wire_fzn_members_page_version_set(v, FZN_CMD_MEMBERS);
	fzn_members_wire_fzn_members_page_type_set(v, FZN_MEMBERS_WIRE_FZN_MEMBERS_TYPE_MEMBERS);
	fzn_members_wire_fzn_members_page_total_set(v, (uint16_t)total);
	fzn_members_wire_fzn_members_page_from_set(v, (uint16_t)(from > total ? total : from));
	fzn_members_wire_fzn_members_page_count_set(&out, v, (uint8_t)n);
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

/* ---- the pull as steps, sec 636 ------------------------------------------ */

enum { MEMBERS_PAGING = 1, MEMBERS_DONE = 2 };

static void members_query(const fzn_node_members_pulling_t *p, uint8_t *request,
                          size_t *request_len)
{
	uint32_t wrote = 0;

	(void)fzn_members_wire_fzn_members_query_build(request, FZN_NODE_MEMBERS_QUERY_LEN, FZN_CMD_MEMBERS,
	                                               FZN_MEMBERS_WIRE_FZN_MEMBERS_TYPE_MEMBERS_QUERY, (uint16_t)p->from,
	                                               &wrote);
	*request_len = FZN_NODE_MEMBERS_QUERY_LEN;
}

fzn_node_members_err_t fzn_node_members_pull_begin(
        fzn_node_members_pulling_t *p, const uint8_t root[FZN_PUBKEY_LEN],
        const fzn_cap_id_t *capability, uint64_t now, const fzn_sign_ops_t *sign,
        const fzn_revocation_store_t *revocations, uint8_t (*out)[FZN_PUBKEY_LEN], size_t cap,
        uint8_t *request, size_t request_cap, size_t *request_len)
{
	if (!p || !root || !capability || !sign || !out || !request
	    || request_cap < FZN_NODE_MEMBERS_QUERY_LEN || !request_len)
		return FZN_NODE_MEMBERS_ERR_MALFORMED;
	memset(p, 0, sizeof(*p));
	p->root = root;
	p->capability = capability;
	p->now = now;
	p->sign = sign;
	p->revocations = revocations;
	p->out = out;
	p->cap = cap;
	p->phase = MEMBERS_PAGING;
	members_query(p, request, request_len);
	return FZN_NODE_MEMBERS_OK;
}

/* THE PULL OVER, with `err`. */
static fzn_node_members_err_t members_end(fzn_node_members_pulling_t *p, int *done,
                                          fzn_node_members_err_t err)
{
	p->phase = MEMBERS_DONE;
	*done = 1;
	return err;
}

fzn_node_members_err_t fzn_node_members_pull_step(fzn_node_members_pulling_t *p,
                                                  const uint8_t *reply, size_t reply_len,
                                                  uint8_t *request, size_t request_cap,
                                                  size_t *request_len, int *done)
{
	size_t n, i, at = FZN_NODE_MEMBERS_HEAD_LEN;
	situ_msg_t m;
	situ_view_t v, e, h;
	uint32_t need = 0;

	if (!p || p->phase != MEMBERS_PAGING || !request
	    || request_cap < FZN_NODE_MEMBERS_QUERY_LEN || !request_len || !done)
		return FZN_NODE_MEMBERS_ERR_MALFORMED;
	*done = 0;
	if (!reply)
		return members_end(p, done, FZN_NODE_MEMBERS_ERR_NO_ANSWER);
	/* THE PAGE'S HEAD READ AS THE SCHEMA SAYS, sec 1394; each member read
	 * and proved as it comes, as before, through a cursor held here (the
	 * generated `_at` is O(index) for a run of variable records), and
	 * EXACTLY ITS MEMBERS checked by `required` once all are. */
	if (reply_len < FZN_NODE_MEMBERS_HEAD_LEN || reply_len > UINT32_MAX)
		return members_end(p, done, FZN_NODE_MEMBERS_ERR_SHAPE);
	situ_msg_init(&m, (uint8_t *)(uintptr_t)reply, (uint32_t)reply_len);
	if (fzn_members_wire_fzn_members_page_view(&m, 0u, (uint32_t)reply_len, &v) != SITU_OK
	    || fzn_members_wire_fzn_members_page_version_get(v) != FZN_CMD_MEMBERS
	    || fzn_members_wire_fzn_members_page_type_get(v) != FZN_MEMBERS_WIRE_FZN_MEMBERS_TYPE_MEMBERS
	    || fzn_members_wire_fzn_members_page_from_get(v) != p->from)
		return members_end(p, done, FZN_NODE_MEMBERS_ERR_SHAPE);
	p->total = fzn_members_wire_fzn_members_page_total_get(v);
	n = fzn_members_wire_fzn_members_page_count_get(v);
	for (i = 0; i < n; i++) {
		const uint8_t *key;
		size_t hop_count, k;
		int have = 0;

		if (fzn_members_wire_fzn_members_member_required(reply + at, (uint32_t)(reply_len - at), &need)
		            != SITU_OK
		    || fzn_members_wire_fzn_members_member_view(&m, (uint32_t)at, need, &e) != SITU_OK
		    || fzn_members_wire_fzn_members_member_validate(e) != SITU_OK
		    || fzn_members_wire_fzn_members_member_hops_at(e, 0u, &h) != SITU_OK)
			return members_end(p, done, FZN_NODE_MEMBERS_ERR_SHAPE);
		key = fzn_members_wire_fzn_members_member_key_ptr(e);
		hop_count = fzn_members_wire_fzn_members_member_hop_count_get(e);
		/* ADMITTED ONLY ON PROOF, and once. */
		for (k = 0; k < p->count && !have; k++)
			have = memcmp(p->out[k], key, FZN_PUBKEY_LEN) == 0;
		if (!have) {
			if (!proves(key, situ_base(h), hop_count, p->root,
			            p->capability, p->now, p->sign, p->revocations)
			    || p->count >= p->cap)
				p->refused++;
			else
				memcpy(p->out[p->count++], key, FZN_PUBKEY_LEN);
		}
		at += need;
	}
	if (fzn_members_wire_fzn_members_page_required(reply, (uint32_t)reply_len, &need) != SITU_OK
	    || need != reply_len)
		return members_end(p, done, FZN_NODE_MEMBERS_ERR_SHAPE);
	p->from += n;
	/* A PAGE THAT BRINGS NOTHING ends it, or a short server would be asked
	 * the same page for ever. */
	if (p->from >= p->total || n == 0u || ++p->pages >= PULL_PAGES_MAX)
		return members_end(p, done, FZN_NODE_MEMBERS_OK);
	members_query(p, request, request_len);
	return FZN_NODE_MEMBERS_OK;
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
	fzn_node_members_pulling_t p;
	uint8_t request[FZN_NODE_MEMBERS_QUERY_LEN];
	size_t request_len = 0, reply_len;
	fzn_node_members_err_t err;
	int done = 0, answered;

	if (!ask || !count || !refused)
		return FZN_NODE_MEMBERS_ERR_MALFORMED;
	*count = 0;
	*refused = 0;
	err = fzn_node_members_pull_begin(&p, root, capability, now, sign, revocations, out, cap,
	                                  request, sizeof(request), &request_len);
	while (err == FZN_NODE_MEMBERS_OK && !done) {
		/* Asked first, apart from the step: see `record/exchange.c`. */
		reply_len = 0;
		answered = ask(ask_ctx, request, request_len, reply, sizeof(reply), &reply_len);
		err = fzn_node_members_pull_step(&p, answered ? reply : NULL, reply_len, request,
		                                 sizeof(request), &request_len, &done);
	}
	*count = p.count;
	*refused = p.refused;
	return err;
}
