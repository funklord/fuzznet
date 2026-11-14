/* This user's contacts in binary: contacts_binary.h, sec 1162. */
#include "contacts_binary.h"

#include <stdint.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/contacts_local.h"
#include "../wire/generated/contacts_local_build.h"
#include "../wire/status.h"

static int status(fzn_node_contacts_put_t put, void *ctx, fzn_status_t code, const char *why)
{
	uint8_t out[FZN_STATUS_LEN_MAX];
	size_t n = fzn_status_write(out, sizeof(out), code, why);

	return n && put(ctx, out, n);
}

struct rows {
	fzn_node_contacts_put_t put;
	void *ctx;
	int ok;
};

static void row_one(void *ctx, const uint8_t key[FZN_PUBKEY_LEN], const char *name, size_t name_len,
                    unsigned standing)
{
	struct rows *w = ctx;
	uint8_t row[FZN_NODE_CONTACTS_BINARY_MAX], out[FZN_NODE_CONTACTS_BINARY_MAX + 8u];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = name_len <= 32u && standing <= 3u
	        && fzn_contacts_local_row_build(row, sizeof(row), key, (fzn_contacts_local_standing_t)standing,
	                                        (const uint8_t *)name, (uint32_t)name_len, &row_len)
	                   == SITU_OK
	        && fzn_contacts_local_message_build_row(out, sizeof(out), (uint8_t)FZN_CMD_CONTACTS, row, row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

int fzn_node_contacts_binary(fzn_node_admin_t *admin, const uint8_t *msg, size_t len,
                             fzn_node_contacts_put_t put, void *put_ctx)
{
	situ_msg_t m;
	situ_view_t v;
	struct rows w = { put, put_ctx, 1 };

	if (!put)
		return 0;
	if (!admin || !msg || len > UINT32_MAX)
		return status(put, put_ctx, FZN_STATUS_ERROR, "no contacts here");
	situ_msg_init(&m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (fzn_contacts_local_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_contacts_local_message_validate(v) != SITU_OK
	    || fzn_contacts_local_message_op_get(v) != FZN_CONTACTS_LOCAL_OP_LIST)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a contacts request");
	/* A ROW EACH, then a STATUS ok: an ended list told from a cut one. */
	if (!fzn_node_admin_contacts_each(admin, row_one, &w))
		return w.ok && status(put, put_ctx, FZN_STATUS_ERROR, "the contacts did not read");
	return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
}
