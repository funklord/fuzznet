/* This user's groups in binary: groups_binary.h, sec 1170. */
#include "groups_binary.h"

#include <stdint.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/groups_local.h"
#include "../wire/generated/groups_local_build.h"
#include "../wire/status.h"

static int status(fzn_node_groups_put_t put, void *ctx, fzn_status_t code, const char *why)
{
	uint8_t out[FZN_STATUS_LEN_MAX];
	size_t n = fzn_status_write(out, sizeof(out), code, why);

	return n && put(ctx, out, n);
}

struct rows {
	fzn_node_groups_put_t put;
	void *ctx;
	int ok;
};

static void row_one(void *ctx, const fzn_node_group_row_t *r)
{
	struct rows *w = ctx;
	uint8_t row[FZN_NODE_GROUPS_BINARY_MAX], out[FZN_NODE_GROUPS_BINARY_MAX + 8u];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = r->name_len <= 32u
	        && fzn_groups_local_row_build(row, sizeof(row), r->id,
	                                      (uint32_t)(r->members > UINT32_MAX ? UINT32_MAX : r->members),
	                                      (uint8_t)(r->admin ? 1 : 0), r->lines, (const uint8_t *)r->name,
	                                      (uint32_t)r->name_len, &row_len)
	                   == SITU_OK
	        && fzn_groups_local_message_build_row(out, sizeof(out), (uint8_t)FZN_CMD_GROUPS, row, row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

static void member_one(void *ctx, const fzn_node_group_member_t *mb)
{
	struct rows *w = ctx;
	uint8_t row[FZN_NODE_GROUPS_BINARY_MAX], out[FZN_NODE_GROUPS_BINARY_MAX + 8u];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = mb->name_len <= 32u
	        && fzn_groups_local_member_row_build(row, sizeof(row), mb->key, (uint8_t)(mb->admin ? 1 : 0),
	                                             (const uint8_t *)mb->name, (uint32_t)mb->name_len, &row_len)
	                   == SITU_OK
	        && fzn_groups_local_message_build_member_row(out, sizeof(out), (uint8_t)FZN_CMD_GROUPS, row, row_len,
	                                                     &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

int fzn_node_groups_binary(const fzn_node_groups_t *g, const uint8_t *msg, size_t len,
                           fzn_node_groups_put_t put, void *put_ctx)
{
	situ_msg_t m;
	situ_view_t v;
	struct rows w = { put, put_ctx, 1 };

	if (!put)
		return 0;
	if (!g || !msg || len > UINT32_MAX)
		return status(put, put_ctx, FZN_STATUS_ERROR, "no groups here");
	situ_msg_init(&m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (fzn_groups_local_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_groups_local_message_validate(v) != SITU_OK)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a groups request");
	/* ONE GROUP'S ROSTER, sec 1179: a row a member, then a STATUS ok; a
	 * group this user is not in, refused as the text verb refuses it. */
	if (fzn_groups_local_message_op_get(v) == FZN_GROUPS_LOCAL_OP_MEMBERS) {
		situ_view_t b;

		if (fzn_groups_local_message_body_members_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a groups request");
		if (!fzn_node_groups_members_each(g, fzn_groups_local_members_ask_id_ptr(b), member_one, &w))
			return w.ok && status(put, put_ctx, FZN_STATUS_ERROR, "no group by that id");
		return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
	}
	if (fzn_groups_local_message_op_get(v) != FZN_GROUPS_LOCAL_OP_LIST)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a groups request");
	/* A ROW EACH, then a STATUS ok: an ended list told from a cut one. */
	if (!fzn_node_groups_each(g, row_one, &w))
		return w.ok && status(put, put_ctx, FZN_STATUS_ERROR, "the groups did not read");
	return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
}
