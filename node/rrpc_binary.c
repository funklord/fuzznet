/* A procedure called in binary on the local leg: rrpc_binary.h, sec 1411. */
#include "rrpc_binary.h"

#include "types.h"
#include "../wire/cmd.h"
#include "../wire/generated/rrpc_local.h"
#include "../wire/generated/rrpc_local_build.h"

#include <string.h>

static int status(fzn_node_rrpc_put_t put, void *ctx, fzn_status_t code, const char *why)
{
	uint8_t msg[FZN_STATUS_LEN_MAX];
	const size_t n = fzn_status_write(msg, sizeof(msg), code, why);

	return n && put(ctx, msg, n);
}

/* A NAME AS `call NAME` TAKES IT: a-z and 0-9. The length is the schema's. */
static int name_ok(const uint8_t *name, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (!((name[i] >= 'a' && name[i] <= 'z') || (name[i] >= '0' && name[i] <= '9')))
			return 0;
	return len != 0u;
}

/* THE CALL'S VIEW, when MSG is a call with a name as `call` takes it. */
static int call_view(const uint8_t *msg, size_t len, situ_msg_t *m, situ_view_t *b)
{
	situ_view_t v;

	if (!msg || len > UINT32_MAX)
		return 0;
	situ_msg_init(m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	return fzn_rrpc_local_message_view(m, 0u, (uint32_t)len, &v) == SITU_OK
	       && fzn_rrpc_local_message_validate(v) == SITU_OK
	       && fzn_rrpc_local_message_op_get(v) == FZN_RRPC_LOCAL_OP_CALL
	       && fzn_rrpc_local_message_body_call_view(v, b) == SITU_OK
	       && name_ok(fzn_rrpc_local_call_name_ptr(*b), fzn_rrpc_local_call_name_len(*b));
}

int fzn_node_rrpc_binary_name(const uint8_t *msg, size_t len, const uint8_t **name, size_t *name_len)
{
	situ_msg_t m;
	situ_view_t b;

	if (!name || !name_len || !call_view(msg, len, &m, &b))
		return 0;
	*name = fzn_rrpc_local_call_name_ptr(b);
	*name_len = fzn_rrpc_local_call_name_len(b);
	return 1;
}

int fzn_node_rrpc_binary(const uint8_t *msg, size_t len, fzn_node_rrpc_run_t run, void *run_ctx, uint8_t *answer,
                         size_t room, fzn_node_rrpc_put_t put, void *put_ctx)
{
	uint8_t part[2u + FZN_NODE_RRPC_PART_MAX];
	situ_msg_t m;
	situ_view_t b;
	fzn_status_t code = FZN_STATUS_ERROR;
	const char *why = NULL;
	size_t n, at;

	if (!put)
		return 0;
	if (!run || !answer || !msg || len > UINT32_MAX)
		return status(put, put_ctx, FZN_STATUS_UNSUPPORTED, "no procedures here");
	if (!call_view(msg, len, &m, &b))
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a call: a name of a-z and 0-9, then its arguments");
	n = run(run_ctx, fzn_rrpc_local_call_name_ptr(b), fzn_rrpc_local_call_name_len(b),
	        fzn_rrpc_local_call_args_ptr(b), fzn_rrpc_local_call_args_len(b), answer, room, &code, &why);
	if (code != FZN_STATUS_OK)
		return status(put, put_ctx, code, why);
	if (n > room)
		return status(put, put_ctx, FZN_STATUS_ERROR, "the procedure said more than it had room for");
	/* THE ANSWER IN PARTS, in order, then ok: an answer cut short ends
	 * without the ok, which a reader tells from a whole one. */
	for (at = 0; at < n;) {
		const size_t one = n - at < FZN_NODE_RRPC_PART_MAX ? n - at : FZN_NODE_RRPC_PART_MAX;
		uint32_t wrote = 0;

		if (fzn_rrpc_local_message_build_part(part, sizeof(part), FZN_CMD_RRPC, answer + at, (uint32_t)one, &wrote)
		            != SITU_OK
		    || !put(put_ctx, part, wrote))
			return 0;
		at += one;
	}
	return status(put, put_ctx, FZN_STATUS_OK, NULL);
}
