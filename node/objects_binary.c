/* Named objects asked in binary on the local leg: objects_binary.h, sec 1152. */
#include "objects_binary.h"

#include <stdint.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/objects.h"
#include "../wire/generated/objects_build.h"
#include "../wire/status.h"

/* A STATUS, as between hosts: ok, or why not in words. */
static int status(fzn_node_objects_put_t put, void *ctx, fzn_status_t code, const char *why)
{
	uint8_t out[FZN_STATUS_LEN_MAX];
	size_t n = fzn_status_write(out, sizeof(out), code, why);

	return n && put(ctx, out, n);
}

/* THE NODE'S WORDS FOR WHAT IT REFUSED, the text path's (objects.c `refused`). */
static int refused(fzn_node_objects_put_t put, void *ctx, fzn_node_object_err_t err)
{
	switch (err) {
	case FZN_NODE_OBJECT_MALFORMED:
		return status(put, ctx, FZN_STATUS_MALFORMED,
		              "a name is a-z 0-9 _ to 32 bytes, a value one word to 64");
	case FZN_NODE_OBJECT_ABSENT:
		return status(put, ctx, FZN_STATUS_ERROR, "no such object");
	case FZN_NODE_OBJECT_REFUSED:
		return status(put, ctx, FZN_STATUS_DENIED, "a value that object may not have");
	case FZN_NODE_OBJECT_EXISTS:
		return status(put, ctx, FZN_STATUS_ERROR, "that object exists, with other values");
	default:
		return status(put, ctx, FZN_STATUS_ERROR, "the object was not kept");
	}
}

/* ONE OBJECT AS A ROW MESSAGE: its length, or 0 when it did not build. */
static size_t row_of(const fzn_node_object_t *x, uint8_t *out, size_t cap)
{
	uint8_t row[FZN_NODE_OBJECTS_BINARY_MAX];
	uint32_t row_len = 0, n = 0;

	if (x->allowed_len > 255u
	    || fzn_objects_row_build(row, sizeof(row), (const uint8_t *)x->name, (uint32_t)x->name_len,
	                             (const uint8_t *)x->value, (uint32_t)x->value_len, x->at, x->by,
	                             x->allowed, (uint32_t)x->allowed_len, &row_len)
	               != SITU_OK
	    || fzn_objects_message_build_row(out, (uint32_t)cap, (uint8_t)FZN_CMD_OBJECTS, row, row_len, &n)
	               != SITU_OK)
		return 0;
	return n;
}

struct listing {
	fzn_node_objects_put_t put;
	void *ctx;
	int ok;
};

static void list_one(void *ctx, const fzn_node_object_t *x)
{
	struct listing *l = ctx;
	uint8_t out[FZN_NODE_OBJECTS_BINARY_MAX];
	size_t n;

	if (!l->ok)
		return;
	n = row_of(x, out, sizeof(out));
	l->ok = n && l->put(l->ctx, out, n);
}

int fzn_node_objects_binary_changes(const uint8_t *msg, size_t len)
{
	return msg && len >= 2u && msg[0] == FZN_CMD_OBJECTS
	       && (msg[1] == FZN_OBJECTS_OP_ADD || msg[1] == FZN_OBJECTS_OP_SET
	           || msg[1] == FZN_OBJECTS_OP_REMOVE);
}

int fzn_node_objects_binary(const fzn_node_objects_t *o, const uint8_t *msg, size_t len,
                            int may_change, fzn_node_objects_put_t put, void *put_ctx)
{
	static fzn_node_object_t x;
	situ_msg_t m;
	situ_view_t v, b;
	fzn_node_object_err_t err;

	if (!put)
		return 0;
	if (!o || !msg || len > UINT32_MAX)
		return status(put, put_ctx, FZN_STATUS_ERROR, "no objects here");
	situ_msg_init(&m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (fzn_objects_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_objects_message_validate(v) != SITU_OK)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not an objects request");
	if (!may_change && fzn_node_objects_binary_changes(msg, len))
		return status(put, put_ctx, FZN_STATUS_DENIED, "only read is granted on objects");
	if (!o->records || !o->records->b || !o->records->verify)
		return status(put, put_ctx, FZN_STATUS_UNSUPPORTED, "no store for records");
	switch (fzn_objects_message_op_get(v)) {
	case FZN_OBJECTS_OP_ADD:
		if (fzn_objects_message_body_add_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not an objects request");
		err = fzn_node_object_add(o, fzn_objects_add_name_ptr(b), fzn_objects_add_name_len(b),
		                          fzn_objects_add_allowed_ptr(b), fzn_objects_add_allowed_len(b));
		break;
	case FZN_OBJECTS_OP_SET:
		if (fzn_objects_message_body_set_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not an objects request");
		err = fzn_node_object_set(o, fzn_objects_set_name_ptr(b), fzn_objects_set_name_len(b),
		                          fzn_objects_set_value_ptr(b), fzn_objects_set_value_len(b), NULL);
		/* TAKEN, AND HELD TO ITS WINDOW, sec 1034, as the text path says it. */
		if (err == FZN_NODE_OBJECT_HELD)
			return status(put, put_ctx, FZN_STATUS_OK, "held");
		break;
	case FZN_OBJECTS_OP_REMOVE:
		if (fzn_objects_message_body_remove_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not an objects request");
		err = fzn_node_object_remove(o, fzn_objects_named_name_ptr(b), fzn_objects_named_name_len(b));
		break;
	case FZN_OBJECTS_OP_GET: {
		uint8_t out[FZN_NODE_OBJECTS_BINARY_MAX];
		size_t n;

		if (fzn_objects_message_body_get_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not an objects request");
		err = fzn_node_object_get(o, fzn_objects_named_name_ptr(b), fzn_objects_named_name_len(b), &x);
		/* NO SUCH OBJECT IS NO ROW and ok, as the text verb answers `absent`. */
		if (err == FZN_NODE_OBJECT_ABSENT)
			return status(put, put_ctx, FZN_STATUS_OK, NULL);
		if (err != FZN_NODE_OBJECT_OK)
			return refused(put, put_ctx, err);
		n = row_of(&x, out, sizeof(out));
		return n ? put(put_ctx, out, n) : status(put, put_ctx, FZN_STATUS_ERROR, "the row did not build");
	}
	case FZN_OBJECTS_OP_LIST: {
		struct listing l = { put, put_ctx, 1 };

		/* A ROW EACH, then a STATUS ok to say the list is whole: a reader can
		 * tell an ended list from a cut connection. */
		if (!fzn_node_objects_each(o, list_one, &l))
			return status(put, put_ctx, FZN_STATUS_ERROR, "the objects could not be listed");
		return l.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
	}
	default:
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "no such objects request");
	}
	if (err != FZN_NODE_OBJECT_OK)
		return refused(put, put_ctx, err);
	return status(put, put_ctx, FZN_STATUS_OK, NULL);
}
