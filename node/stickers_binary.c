/* The sticker packs in binary: stickers_binary.h, sec 1172. */
#include "stickers_binary.h"

#include <stdint.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/stickers_local.h"
#include "../wire/generated/stickers_local_build.h"
#include "../wire/status.h"

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
	w->ok = p->name_len <= 48u
	        && fzn_stickers_local_pack_row_build(row, sizeof(row), p->root, p->length, (uint8_t)(p->held ? 1 : 0),
	                                             (uint8_t)(p->estate ? 1 : 0), (const uint8_t *)p->name,
	                                             (uint32_t)p->name_len, &row_len)
	                   == SITU_OK
	        && fzn_stickers_local_message_build_pack_row(out, sizeof(out), (uint8_t)FZN_CMD_STICKERS, row, row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
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
	    || fzn_stickers_local_message_validate(v) != SITU_OK
	    || fzn_stickers_local_message_op_get(v) != FZN_STICKERS_LOCAL_OP_PACKS)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a stickers request");
	/* A ROW EACH, then a STATUS ok: an ended list told from a cut one. */
	if (!fzn_node_stickers_each(st, row_one, &w))
		return w.ok && status(put, put_ctx, FZN_STATUS_ERROR, "the packs did not list");
	return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
}
