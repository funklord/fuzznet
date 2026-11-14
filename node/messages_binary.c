/* Every conversation's newest line and count in binary: messages_binary.h, sec 1155. */
#include "messages_binary.h"

#include <stdint.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/messages_local.h"
#include "../wire/generated/messages_local_build.h"
#include "../wire/status.h"

static int status(fzn_node_messages_put_t put, void *ctx, fzn_status_t code, const char *why)
{
	uint8_t out[FZN_STATUS_LEN_MAX];
	size_t n = fzn_status_write(out, sizeof(out), code, why);

	return n && put(ctx, out, n);
}

struct rows {
	fzn_node_messages_put_t put;
	void *ctx;
	int ok;
};

static void newest_one(void *ctx, const fzn_node_newest_t *l)
{
	struct rows *w = ctx;
	uint8_t row[FZN_NODE_MESSAGES_BINARY_MAX], out[FZN_NODE_MESSAGES_BINARY_MAX + 8u];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = l->sender_len <= 64u && l->text_len <= 1024u
	        && fzn_messages_local_newest_row_build(row, sizeof(row), l->key, l->stime_ms,
	                                               (uint8_t)(l->outgoing ? 1 : 0),
	                                               (fzn_messages_local_kind_t)l->kind,
	                                               (const uint8_t *)l->sender, (uint32_t)l->sender_len,
	                                               (const uint8_t *)l->text, (uint32_t)l->text_len,
	                                               &row_len)
	                   == SITU_OK
	        && fzn_messages_local_message_build_newest_row(out, sizeof(out), (uint8_t)FZN_CMD_MESSAGES, row,
	                                                       row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

static void unread_one(void *ctx, const uint8_t key[FZN_PUBKEY_LEN], size_t count, int more)
{
	struct rows *w = ctx;
	uint8_t row[64], out[80];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = fzn_messages_local_unread_row_build(row, sizeof(row), key,
	                                            (uint32_t)(count > UINT32_MAX ? UINT32_MAX : count),
	                                            (uint8_t)(more ? 1 : 0), &row_len)
	                == SITU_OK
	        && fzn_messages_local_message_build_unread_row(out, sizeof(out), (uint8_t)FZN_CMD_MESSAGES, row,
	                                                       row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

static void line_one(void *ctx, const fzn_node_line_t *l)
{
	struct rows *w = ctx;
	uint8_t row[FZN_NODE_MESSAGES_BINARY_MAX], out[FZN_NODE_MESSAGES_BINARY_MAX + 8u];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = l->name_len <= 64u && l->sender_len <= 64u && l->text_len <= 512u
	        && fzn_messages_local_line_row_build(row, sizeof(row), l->key, l->id, (uint8_t)(l->group ? 1 : 0),
	                                             (uint8_t)(l->outgoing ? 1 : 0), (uint8_t)l->state,
	                                             (uint8_t)(l->readable ? 1 : 0), l->stime_ms, l->written_ms,
	                                             (const uint8_t *)l->name, (uint32_t)l->name_len,
	                                             (const uint8_t *)l->sender, (uint32_t)l->sender_len,
	                                             (const uint8_t *)l->text, (uint32_t)l->text_len, &row_len)
	                   == SITU_OK
	        && fzn_messages_local_message_build_line_row(out, sizeof(out), (uint8_t)FZN_CMD_MESSAGES, row,
	                                                     row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

int fzn_node_messages_binary(fzn_node_messages_t *nm, const uint8_t *msg, size_t len,
                             fzn_node_messages_put_t put, void *put_ctx)
{
	situ_msg_t m;
	situ_view_t v;
	struct rows w = { put, put_ctx, 1 };
	int listed;

	if (!put)
		return 0;
	if (!nm || !msg || len > UINT32_MAX)
		return status(put, put_ctx, FZN_STATUS_ERROR, "no messages here");
	situ_msg_init(&m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (fzn_messages_local_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_messages_local_message_validate(v) != SITU_OK)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a messages request");
	switch (fzn_messages_local_message_op_get(v)) {
	case FZN_MESSAGES_LOCAL_OP_NEWEST:
		listed = fzn_node_messages_newest_each(nm, newest_one, &w);
		break;
	case FZN_MESSAGES_LOCAL_OP_UNREAD:
		listed = fzn_node_messages_unread_each(nm, unread_one, &w);
		break;
	case FZN_MESSAGES_LOCAL_OP_LINES: {
		situ_view_t b;

		if (fzn_messages_local_message_body_lines_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a messages request");
		listed = fzn_node_messages_lines_each(nm,
		                                      fzn_messages_local_lines_ask_one_get(b)
		                                              ? fzn_messages_local_lines_ask_key_ptr(b)
		                                              : NULL,
		                                      fzn_messages_local_lines_ask_from_get(b),
		                                      fzn_messages_local_lines_ask_max_get(b), line_one, &w);
		/* NO SUCH CONVERSATION, said as the text verb says a WHO it cannot
		 * name. */
		if (listed < 0)
			return status(put, put_ctx, FZN_STATUS_ERROR, "no contact or group by that key");
		break;
	}
	default:
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "no such messages request");
	}
	/* A ROW EACH, then a STATUS ok: an ended list told from a cut one. */
	if (!listed)
		return w.ok && status(put, put_ctx, FZN_STATUS_ERROR, "the conversations did not list");
	return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
}
