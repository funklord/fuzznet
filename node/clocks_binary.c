/* The clocks in binary: clocks_binary.h, sec 1184. */
#include "clocks_binary.h"

#include <stdint.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/time_local.h"
#include "../wire/generated/time_local_build.h"
#include "../wire/status.h"

static int status(fzn_node_clocks_put_t put, void *ctx, fzn_status_t code, const char *why)
{
	uint8_t out[FZN_STATUS_LEN_MAX];
	size_t n = fzn_status_write(out, sizeof(out), code, why);

	return n && put(ctx, out, n);
}

int fzn_node_clocks_binary(fzn_node_clocks_t *c, uint64_t now, const uint8_t *msg, size_t len,
                           fzn_node_clocks_put_t put, void *put_ctx)
{
	situ_msg_t m;
	situ_view_t v;
	size_t i, n;

	if (!put)
		return 0;
	if (!c || !msg || len > UINT32_MAX)
		return status(put, put_ctx, FZN_STATUS_ERROR, "this node keeps no clocks");
	situ_msg_init(&m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (fzn_time_local_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_time_local_message_validate(v) != SITU_OK
	    || fzn_time_local_message_op_get(v) != FZN_TIME_LOCAL_OP_CLOCKS)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a clocks request");
	/* A ROW EACH, the stale forgotten first, then a STATUS ok. */
	n = fzn_node_clocks_current(c, now);
	for (i = 0; i < n; i++) {
		uint8_t row[FZN_NODE_CLOCKS_BINARY_MAX], out[FZN_NODE_CLOCKS_BINARY_MAX + 8u];
		uint32_t row_len = 0, out_len = 0;

		if (fzn_time_local_clock_row_build(row, sizeof(row), c->rows[i].peer, (uint8_t)(c->rows[i].ahead ? 1 : 0),
		                                   c->rows[i].seconds, c->rows[i].at, &row_len) != SITU_OK
		    || fzn_time_local_message_build_clock_row(out, sizeof(out), (uint8_t)FZN_CMD_TIME, row, row_len,
		                                               &out_len) != SITU_OK
		    || !put(put_ctx, out, out_len))
			return 0;
	}
	return status(put, put_ctx, FZN_STATUS_OK, NULL);
}
