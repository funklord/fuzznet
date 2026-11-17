/* This user's groups in binary: groups_binary.h, sec 1170. */
#include "groups_binary.h"

#include <stdint.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/groups_local.h"
#include "../wire/generated/groups_local_build.h"
#include "../wire/status.h"
#include "../local/vocabulary.h"

#include <stdio.h>

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

/* A VERB'S ANSWER AS A STATUS, sec 1222, as the notebook's are (sec
 * 1218): ok, denied, or an error in the verb's words -- never malformed,
 * which a client takes for a node reading no binary. */
static int verb_status(fzn_node_groups_put_t put, void *ctx, const char *reply, size_t len)
{
	char why[FZN_STATUS_WHY_MAX + 1u];
	const char *sp;
	size_t n;

	while (len && (reply[len - 1u] == '\n' || reply[len - 1u] == '\r'))
		len--;
	if (len >= 2u && memcmp(reply, "ok", 2u) == 0 && (len == 2u || reply[2] == ' '))
		return status(put, ctx, FZN_STATUS_OK, NULL);
	sp = memchr(reply, ' ', len);
	n = sp ? len - (size_t)(sp + 1 - reply) : 0u;
	if (n > FZN_STATUS_WHY_MAX)
		n = FZN_STATUS_WHY_MAX;
	memcpy(why, sp ? sp + 1 : "", n);
	why[n] = '\0';
	return status(put, ctx, len >= 6u && memcmp(reply, "denied", 6u) == 0 ? FZN_STATUS_DENIED : FZN_STATUS_ERROR,
	              n ? why : "the group would not change");
}

/* THE GROUP WRITES, sec 1222: each as its verb, through the verbs' own
 * handler, the request built as a line would give it -- so every check is
 * the verb's -- and its answer said as rows and a STATUS. */
static int group_write(const fzn_node_groups_t *g, situ_view_t v, fzn_node_groups_put_t put, void *put_ctx)
{
	static const char *const SUBJECT[] = { "", "group", "group", "member", "member", "admin", "admin",
		                               "group", "group" };
	static char reply[FZN_REPLY_MAX];
	uint8_t arg[16 + 64 + 1 + 64 + 16], row[64], out[72];
	fzn_request_t req;
	situ_view_t b;
	size_t used, r;
	uint32_t row_len = 0, out_len = 0;
	unsigned what;

	memset(&req, 0, sizeof(req));
	if (fzn_groups_local_message_op_get(v) == FZN_GROUPS_LOCAL_OP_BACKFILL) {
		if (fzn_groups_local_message_body_backfill_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a groups request");
		used = (size_t)snprintf((char *)arg, sizeof(arg), "group %.*s backfill",
		                        (int)fzn_groups_local_backfill_ask_group_len(b),
		                        (const char *)fzn_groups_local_backfill_ask_group_ptr(b));
		req.parsed = FZN_VERB_GET;
		req.arg = arg;
		req.arg_len = used;
		r = fzn_node_groups_local(g, &req, reply, sizeof(reply));
		if (r < 4u || memcmp(reply, "ok ", 3u) != 0 || (reply[3] != '0' && reply[3] != '1'))
			return verb_status(put, put_ctx, reply, r);
		if (fzn_groups_local_backfill_row_build(row, sizeof(row), (uint8_t)(reply[3] - '0'), &row_len) != SITU_OK
		    || fzn_groups_local_message_build_backfill_row(out, sizeof(out), (uint8_t)FZN_CMD_GROUPS, row,
		                                                   row_len, &out_len)
		               != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_ERROR, "the answer would not write");
		return put(put_ctx, out, out_len) && status(put, put_ctx, FZN_STATUS_OK, NULL);
	}
	if (fzn_groups_local_message_body_change_view(v, &b) != SITU_OK)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a groups request");
	what = (unsigned)fzn_groups_local_change_what_get(b);
	if (what < 1u || what > 8u || ((what >= 3u && what <= 6u) != (fzn_groups_local_change_who_len(b) > 0u)))
		return status(put, put_ctx, FZN_STATUS_ERROR, "a member or an admin names a contact, nothing else");
	used = (size_t)snprintf((char *)arg, sizeof(arg), "%s %.*s", SUBJECT[what],
	                        (int)fzn_groups_local_change_group_len(b),
	                        (const char *)fzn_groups_local_change_group_ptr(b));
	if (what >= 3u && what <= 6u)
		used += (size_t)snprintf((char *)arg + used, sizeof(arg) - used, " %.*s",
		                         (int)fzn_groups_local_change_who_len(b),
		                         (const char *)fzn_groups_local_change_who_ptr(b));
	if (what >= 7u)
		used += (size_t)snprintf((char *)arg + used, sizeof(arg) - used, " backfill %c", what == 7u ? '1' : '0');
	req.parsed = what == 1u || what == 3u || what == 5u ? FZN_VERB_ADD
	             : what >= 7u                            ? FZN_VERB_SET
	                                                     : FZN_VERB_REMOVE;
	req.arg = arg;
	req.arg_len = used;
	r = fzn_node_groups_local(g, &req, reply, sizeof(reply));
	/* MADE: `ok ID`, its id as a row. */
	if (what == 1u && r >= 3u + 64u && memcmp(reply, "ok ", 3u) == 0) {
		uint8_t id[32];
		size_t i;

		for (i = 0; i < 32u; i++) {
			unsigned x = 0;

			if (sscanf(reply + 3u + 2u * i, "%2x", &x) != 1)
				return status(put, put_ctx, FZN_STATUS_ERROR, "the group's id did not read");
			id[i] = (uint8_t)x;
		}
		if (fzn_groups_local_created_build(row, sizeof(row), id, &row_len) != SITU_OK
		    || fzn_groups_local_message_build_created(out, sizeof(out), (uint8_t)FZN_CMD_GROUPS, row, row_len,
		                                              &out_len)
		               != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_ERROR, "the answer would not write");
		return put(put_ctx, out, out_len) && status(put, put_ctx, FZN_STATUS_OK, NULL);
	}
	/* WAITING ON OTHER ADMINS: `ok proposed APPROVALS NEEDED`, as a row. */
	if ((what == 5u || what == 6u) && r > 12u && memcmp(reply, "ok proposed ", 12u) == 0) {
		unsigned approvals = 0, needed = 0;

		if (sscanf(reply + 12, "%u %u", &approvals, &needed) != 2
		    || fzn_groups_local_proposed_build(row, sizeof(row), (uint16_t)approvals, (uint16_t)needed, &row_len)
		               != SITU_OK
		    || fzn_groups_local_message_build_proposed(out, sizeof(out), (uint8_t)FZN_CMD_GROUPS, row, row_len,
		                                               &out_len)
		               != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_ERROR, "the answer would not write");
		return put(put_ctx, out, out_len) && status(put, put_ctx, FZN_STATUS_OK, NULL);
	}
	return verb_status(put, put_ctx, reply, r);
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
	if (fzn_groups_local_message_op_get(v) == FZN_GROUPS_LOCAL_OP_CHANGE
	    || fzn_groups_local_message_op_get(v) == FZN_GROUPS_LOCAL_OP_BACKFILL)
		return group_write(g, v, put, put_ctx);
	if (fzn_groups_local_message_op_get(v) != FZN_GROUPS_LOCAL_OP_LIST)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a groups request");
	/* A ROW EACH, then a STATUS ok: an ended list told from a cut one. */
	if (!fzn_node_groups_each(g, row_one, &w))
		return w.ok && status(put, put_ctx, FZN_STATUS_ERROR, "the groups did not read");
	return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
}
