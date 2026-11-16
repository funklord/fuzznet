/* What this node has moved, in binary: meter_binary.h, sec 1177. */
#include "meter_binary.h"

#include <stdint.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/meter_local.h"
#include "../wire/generated/meter_local_build.h"
#include "../wire/status.h"

static int status(fzn_node_meter_put_t put, void *ctx, fzn_status_t code, const char *why)
{
	uint8_t out[FZN_STATUS_LEN_MAX];
	size_t n = fzn_status_write(out, sizeof(out), code, why);

	return n && put(ctx, out, n);
}

struct rows {
	fzn_node_meter_put_t put;
	void *ctx;
	int ok;
};

static void row_one(void *ctx, const fzn_meter_row_t *r)
{
	struct rows *w = ctx;
	const char *family = fzn_meter_family_name(r->family);
	uint8_t row[FZN_NODE_METER_BINARY_MAX], out[FZN_NODE_METER_BINARY_MAX + 8u];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = fzn_meter_local_transfer_row_build(row, sizeof(row), (const uint8_t *)family,
	                                           (uint32_t)strlen(family), (const uint8_t *)r->peer,
	                                           (uint32_t)r->peer_len, (uint8_t)(r->has_key ? 1 : 0),
	                                           r->key, r->up, r->down, r->rate_up, r->rate_down,
	                                           r->first_s, r->last_s, &row_len)
	                == SITU_OK
	        && fzn_meter_local_message_build_transfer_row(out, sizeof(out), (uint8_t)FZN_CMD_TRANSFER,
	                                                      row, row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

int fzn_node_meter_binary(const fzn_meter_t *m, const uint8_t *msg, size_t len,
                          fzn_node_meter_put_t put, void *put_ctx)
{
	situ_msg_t sm;
	situ_view_t v;
	struct rows w = { put, put_ctx, 1 };
	size_t f;

	if (!put)
		return 0;
	if (!m || !msg || len > UINT32_MAX)
		return status(put, put_ctx, FZN_STATUS_ERROR, "this node meters nothing");
	situ_msg_init(&sm, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (fzn_meter_local_message_view(&sm, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_meter_local_message_validate(v) != SITU_OK
	    || fzn_meter_local_message_op_get(v) != FZN_METER_LOCAL_OP_TRANSFERS)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a transfers request");
	/* EACH FAMILY THAT HAS MOVED ANYTHING, as `get transfer` says them. */
	for (f = 0; f < FZN_METER_FAMILIES && w.ok; f++) {
		const char *family = fzn_meter_family_name((fzn_meter_family_t)f);
		uint64_t up, down, rate_up, rate_down;
		uint8_t row[FZN_NODE_METER_BINARY_MAX], out[FZN_NODE_METER_BINARY_MAX + 8u];
		uint32_t row_len = 0, n = 0;
		size_t rows;

		fzn_meter_family_totals(m, (fzn_meter_family_t)f, &up, &down, &rate_up, &rate_down, &rows);
		if (!up && !down)
			continue;
		w.ok = fzn_meter_local_family_row_build(row, sizeof(row), (const uint8_t *)family,
		                                        (uint32_t)strlen(family), up, down, &row_len)
		               == SITU_OK
		       && fzn_meter_local_message_build_family_row(out, sizeof(out), (uint8_t)FZN_CMD_TRANSFER,
		                                                   row, row_len, &n)
		                  == SITU_OK
		       && put(put_ctx, out, n);
	}
	/* THEN EVERY ROW, and a STATUS ok: an ended list told from a cut one. */
	if (w.ok)
		(void)fzn_meter_rows(m, row_one, &w);
	return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
}
