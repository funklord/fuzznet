/* This user's contacts in binary: contacts_binary.h, sec 1162. */
#include "contacts_binary.h"

#include <stdint.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/contacts_local.h"
#include "../wire/generated/contacts_local_build.h"
#include "../wire/status.h"
#include "../contact/contact.h"

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

/* ADDED OR RENAMED, sec 1167, as `add contact NAME KEY` does: a `clash`
 * for each other contact of the same name, then a STATUS. */
static int add_one(fzn_node_admin_t *admin, situ_view_t v, fzn_node_contacts_put_t put, void *put_ctx)
{
	uint8_t others[4][FZN_PUBKEY_LEN];
	situ_view_t b;
	const uint8_t *key;
	const char *name, *why = NULL;
	size_t name_len, n = 0, i;
	int r;

	if (fzn_contacts_local_message_body_add_view(v, &b) != SITU_OK)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a contacts request");
	key = fzn_contacts_local_add_key_ptr(b);
	name = (const char *)fzn_contacts_local_add_name_ptr(b);
	name_len = fzn_contacts_local_add_name_len(b);
	r = fzn_node_admin_contact_add(admin, key, name, name_len, &why);
	if (r != 0)
		return status(put, put_ctx,
		              r == -2 ? FZN_STATUS_MALFORMED : r == -3 ? FZN_STATUS_DENIED : FZN_STATUS_ERROR,
		              why ? why : "the contact was not added");
	if (fzn_contact_named(admin->store, name, name_len, key, others, 4u, &n) != FZN_CONTACT_OK)
		n = 0;
	for (i = 0; i < n && i < 4u; i++) {
		uint8_t out[48];
		uint32_t k = 0;
		uint8_t inner[40];
		uint32_t inner_len = 0;

		if (fzn_contacts_local_keyed_build(inner, sizeof(inner), others[i], &inner_len) != SITU_OK
		    || fzn_contacts_local_message_build_clash(out, sizeof(out), (uint8_t)FZN_CMD_CONTACTS, inner,
		                                              inner_len, &k)
		               != SITU_OK
		    || !put(put_ctx, out, k))
			return 0;
	}
	return status(put, put_ctx, FZN_STATUS_OK, NULL);
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
	    || fzn_contacts_local_message_validate(v) != SITU_OK)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a contacts request");
	switch (fzn_contacts_local_message_op_get(v)) {
	case FZN_CONTACTS_LOCAL_OP_LIST:
		break;
	case FZN_CONTACTS_LOCAL_OP_ADD:
		return add_one(admin, v, put, put_ctx);
	case FZN_CONTACTS_LOCAL_OP_REMOVE: {
		situ_view_t b;
		const char *why = NULL;
		int r;

		if (fzn_contacts_local_message_body_remove_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a contacts request");
		r = fzn_node_admin_contact_remove(admin, fzn_contacts_local_keyed_key_ptr(b), &why);
		return status(put, put_ctx, r == 0 ? FZN_STATUS_OK : r == -3 ? FZN_STATUS_DENIED : FZN_STATUS_ERROR,
		              r == 0 ? NULL : why ? why : "the contact was not removed");
	}
	default:
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "no such contacts request");
	}
	/* A ROW EACH, then a STATUS ok: an ended list told from a cut one. */
	if (!fzn_node_admin_contacts_each(admin, row_one, &w))
		return w.ok && status(put, put_ctx, FZN_STATUS_ERROR, "the contacts did not read");
	return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
}
