/* The sticker packs in binary: stickers_binary.h, sec 1172. */
#include "stickers_binary.h"

#include <stdint.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/stickers_local.h"
#include "../wire/generated/stickers_local_build.h"
#include "../wire/status.h"
#include "../local/vocabulary.h"
#include "../sticker/pack.h"

#include <stdio.h>

static int status(fzn_node_stickers_put_t put, void *ctx, fzn_status_t code, const char *why)
{
	uint8_t out[FZN_STATUS_LEN_MAX];
	size_t n = fzn_status_write(out, sizeof(out), code, why);

	return n && put(ctx, out, n);
}

struct rows {
	fzn_node_stickers_put_t put;
	void *ctx;
	int ok;
};

static void row_one(void *ctx, const fzn_node_sticker_pack_t *p)
{
	struct rows *w = ctx;
	uint8_t row[FZN_NODE_STICKERS_BINARY_MAX], out[FZN_NODE_STICKERS_BINARY_MAX + 8u];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = p->name_len <= FZN_STICKER_NAME_MAX
	        && fzn_stickers_local_pack_row_build(row, sizeof(row), p->root, p->length, (uint8_t)(p->held ? 1 : 0),
	                                             (uint8_t)(p->estate ? 1 : 0), (const uint8_t *)p->name,
	                                             (uint32_t)p->name_len, &row_len)
	                   == SITU_OK
	        && fzn_stickers_local_message_build_pack_row(out, sizeof(out), (uint8_t)FZN_CMD_STICKERS, row, row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

/* ONE STICKER AS A ROW, sec 1248. */
static void item_one(void *ctx, const struct fzn_sticker_entry *e, unsigned main_w, unsigned main_h)
{
	struct rows *w = ctx;
	uint8_t row[FZN_NODE_STICKERS_BINARY_MAX], out[FZN_NODE_STICKERS_BINARY_MAX + 8u];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = e->description_len <= FZN_STICKER_DESC_MAX
	        && fzn_stickers_local_item_row_build(row, sizeof(row), e->id, e->type, e->flags, e->text_limit, e->text_x,
	                                             e->text_y, e->text_w, e->text_h, e->text_fill, e->text_ink,
	                                             e->text_turn, (uint16_t)main_w, (uint16_t)main_h,
	                                             (const uint8_t *)e->description, (uint32_t)e->description_len,
	                                             &row_len)
	                   == SITU_OK
	        && fzn_stickers_local_message_build_item_row(out, sizeof(out), (uint8_t)FZN_CMD_STICKERS, row, row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

/* A PACK KEPT OR LET GO, sec 1248: through the verbs' own handler, as
 * `add sticker REF` and `remove sticker ROOT`, so every check is theirs;
 * kept, its root said as a row. Never malformed for a refusal. */
static int pack_write(const fzn_node_stickers_t *st, situ_view_t v, fzn_node_stickers_put_t put, void *put_ctx)
{
	static char reply[512];
	char arg[16 + 2u * 72u + 1u];
	fzn_request_t req;
	situ_view_t b;
	const uint8_t *bytes;
	size_t i, r, n = 0, want;
	const int keep = fzn_stickers_local_message_op_get(v) == FZN_STICKERS_LOCAL_OP_KEEP;

	memset(&req, 0, sizeof(req));
	if (keep) {
		uint8_t raw[72];

		if (fzn_stickers_local_message_body_keep_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a stickers request");
		memcpy(raw, fzn_stickers_local_keep_ask_root_ptr(b), 32);
		memcpy(raw + 32, fzn_stickers_local_keep_ask_key_ptr(b), 32);
		for (i = 0; i < 8u; i++)
			raw[64 + i] = (uint8_t)(fzn_stickers_local_keep_ask_length_get(b) >> (56u - 8u * i));
		bytes = raw;
		want = 72u;
		n = (size_t)snprintf(arg, sizeof(arg), "sticker ");
		for (i = 0; i < want; i++)
			n += (size_t)snprintf(arg + n, sizeof(arg) - n, "%02x", bytes[i]);
		req.parsed = FZN_VERB_ADD;
	} else {
		if (fzn_stickers_local_message_body_forget_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a stickers request");
		bytes = fzn_stickers_local_pack_ask_root_ptr(b);
		n = (size_t)snprintf(arg, sizeof(arg), "sticker ");
		for (i = 0; i < 32u; i++)
			n += (size_t)snprintf(arg + n, sizeof(arg) - n, "%02x", bytes[i]);
		req.parsed = FZN_VERB_REMOVE;
	}
	req.arg = (const uint8_t *)arg;
	req.arg_len = n;
	r = fzn_node_stickers_local((void *)(uintptr_t)st, FZN_ORIGIN_SAME_USER, &req, reply, sizeof(reply));
	while (r && (reply[r - 1u] == '\n' || reply[r - 1u] == '\r'))
		reply[--r] = '\0';
	if (r < 2u || memcmp(reply, "ok", 2u) != 0 || (r > 2u && reply[2] != ' '))
		return status(put, put_ctx,
		              r > 7u && memcmp(reply, "denied ", 7u) == 0 ? FZN_STATUS_DENIED : FZN_STATUS_ERROR,
		              memchr(reply, ' ', r) ? (const char *)memchr(reply, ' ', r) + 1 : "the pack would not change");
	/* KEPT: `ok ROOT` for the estate, `ok ROOT host` for this host alone. */
	if (keep) {
		uint8_t row[40], out[56];
		uint32_t row_len = 0, m = 0;

		if (fzn_stickers_local_kept_row_build(row, sizeof(row), bytes, (uint8_t)(strstr(reply, " host") ? 0 : 1),
		                                      &row_len)
		            != SITU_OK
		    || fzn_stickers_local_message_build_kept(out, sizeof(out), (uint8_t)FZN_CMD_STICKERS, row, row_len, &m)
		               != SITU_OK
		    || !put(put_ctx, out, m))
			return 0;
	}
	return status(put, put_ctx, FZN_STATUS_OK, NULL);
}

int fzn_node_stickers_binary(const fzn_node_stickers_t *st, const uint8_t *msg, size_t len,
                             fzn_node_stickers_put_t put, void *put_ctx)
{
	situ_msg_t m;
	situ_view_t v;
	struct rows w = { put, put_ctx, 1 };

	if (!put)
		return 0;
	if (!st || !msg || len > UINT32_MAX)
		return status(put, put_ctx, FZN_STATUS_ERROR, "no stickers here");
	situ_msg_init(&m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (fzn_stickers_local_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_stickers_local_message_validate(v) != SITU_OK)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a stickers request");
	if (fzn_stickers_local_message_op_get(v) == FZN_STICKERS_LOCAL_OP_KEEP
	    || fzn_stickers_local_message_op_get(v) == FZN_STICKERS_LOCAL_OP_FORGET)
		return pack_write(st, v, put, put_ctx);
	/* ONE PACK'S STICKERS, sec 1248: a row each, then ok; no such pack, or
	 * one not here whole, refused in words. */
	if (fzn_stickers_local_message_op_get(v) == FZN_STICKERS_LOCAL_OP_ITEMS) {
		situ_view_t b;
		int r;

		if (fzn_stickers_local_message_body_items_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a stickers request");
		r = fzn_node_stickers_items(st, fzn_stickers_local_pack_ask_root_ptr(b), item_one, &w);
		if (r <= 0)
			return status(put, put_ctx, FZN_STATUS_ERROR,
			              r < 0 ? "that pack is not here whole, or is no pack" : "no such pack is saved");
		return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
	}
	if (fzn_stickers_local_message_op_get(v) != FZN_STICKERS_LOCAL_OP_PACKS)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a stickers request");
	/* A ROW EACH, then a STATUS ok: an ended list told from a cut one. */
	if (!fzn_node_stickers_each(st, row_one, &w))
		return w.ok && status(put, put_ctx, FZN_STATUS_ERROR, "the packs did not list");
	return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
}
