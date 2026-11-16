/* The forks in binary: decisions_binary.h, sec 1187. */
#include "decisions_binary.h"

#include <stdint.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/settings_local.h"
#include "../wire/generated/settings_local_build.h"
#include "../wire/status.h"

static int status(fzn_node_decisions_put_t put, void *ctx, fzn_status_t code, const char *why)
{
	uint8_t out[FZN_STATUS_LEN_MAX];
	size_t n = fzn_status_write(out, sizeof(out), code, why);

	return n && put(ctx, out, n);
}

struct rows {
	fzn_node_decisions_put_t put;
	void *ctx;
	int ok;
};

static void row_one(void *ctx, const fzn_node_decision_t *d)
{
	struct rows *w = ctx;
	uint8_t row[FZN_NODE_DECISIONS_BINARY_MAX], out[FZN_NODE_DECISIONS_BINARY_MAX + 8u];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = fzn_settings_local_fork_row_build(row, sizeof(row), d->subject, (uint32_t)d->subject_len, d->host,
	                                          d->at, d->grounds, (uint32_t)d->grounds_len, d->value,
	                                          (uint32_t)d->value_len, &row_len)
	                == SITU_OK
	        && fzn_settings_local_message_build_fork_row(out, sizeof(out), (uint8_t)FZN_CMD_SETTINGS, row,
	                                                     row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

int fzn_node_decisions_binary(const fzn_node_records_t *nr, const uint8_t *msg, size_t len,
                              fzn_node_decisions_put_t put, void *put_ctx)
{
	situ_msg_t m;
	situ_view_t v;
	struct rows w = { put, put_ctx, 1 };

	if (!put)
		return 0;
	if (!nr || !msg || len > UINT32_MAX)
		return status(put, put_ctx, FZN_STATUS_ERROR, "this node keeps no decisions");
	situ_msg_init(&m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (fzn_settings_local_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_settings_local_message_validate(v) != SITU_OK
	    || fzn_settings_local_message_op_get(v) != FZN_SETTINGS_LOCAL_OP_FORKS)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a settings request");
	/* A ROW A HEAD, then a STATUS ok: an ended list told from a cut one. */
	if (fzn_node_decisions_forks(nr, row_one, &w) < 0)
		return w.ok && status(put, put_ctx, FZN_STATUS_ERROR, "the decisions could not be read");
	return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
}
