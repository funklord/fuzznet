/* See contact.h. */

#include "contact.h"

#include "../wire/bytes.h"

#include <stdlib.h>
#include <string.h>

#define BODY_LEN(n) (1u + (size_t)(n) + 8u)
#define BLOB_MAX ((size_t)FZN_PERSIST_HEAD_LEN + BODY_LEN(FZN_CONTACT_NAME_MAX))

const char *fzn_contact_err_str(fzn_contact_err_t err)
{
	switch (err) {
	case FZN_CONTACT_OK:
		return "ok";
	case FZN_CONTACT_ERR_MALFORMED:
		return "malformed";
	case FZN_CONTACT_ERR_NAME:
		return "not a contact name: 1 to 32 of A-Z, a-z, 0-9 and _";
	case FZN_CONTACT_ERR_TAKEN:
		return "another contact has that name";
	case FZN_CONTACT_ERR_ABSENT:
		return "no such contact";
	case FZN_CONTACT_ERR_FULL:
		return "no room for another contact";
	case FZN_CONTACT_ERR_BACKEND:
		return "the store refused";
	case FZN_CONTACT_ERR_SHAPE:
		return "a contact entry will not read";
	}
	return "unknown";
}

int fzn_contact_name_ok(const char *name, size_t len)
{
	size_t i;

	if (!name || len == 0u || len > FZN_CONTACT_NAME_MAX)
		return 0;
	for (i = 0; i < len; i++) {
		char c = name[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		      || c == '_'))
			return 0;
	}
	return 1;
}

fzn_contact_err_t fzn_contact_get(const fzn_persist_ops_t *store,
                                  const uint8_t key[FZN_PUBKEY_LEN], fzn_contact_t *out)
{
	uint8_t blob[BLOB_MAX];
	const uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	size_t len = 0, n;

	if (!store || !store->load || !key || !out)
		return FZN_CONTACT_ERR_MALFORMED;
	if (!store->load(store->ctx, FZN_PERSIST_CONTACT, key, blob, sizeof(blob), &len))
		return FZN_CONTACT_ERR_ABSENT;
	if (len < FZN_PERSIST_HEAD_LEN + 1u)
		return FZN_CONTACT_ERR_SHAPE;
	n = body[0];
	if (fzn_persist_head_check(blob, len, BODY_LEN(n), FZN_PERSIST_BLOB_CONTACT)
	            != FZN_PERSIST_OK
	    || !fzn_contact_name_ok((const char *)body + 1, n))
		return FZN_CONTACT_ERR_SHAPE;
	memset(out, 0, sizeof(*out));
	memcpy(out->key, key, FZN_PUBKEY_LEN);
	memcpy(out->name, body + 1, n);
	out->name_len = n;
	out->added_at_ms = fzn_get_be64(body + 1 + n);
	return FZN_CONTACT_OK;
}

static int name_order(const void *a, const void *b)
{
	const fzn_contact_t *x = (const fzn_contact_t *)a, *y = (const fzn_contact_t *)b;

	return strcmp(x->name, y->name);
}

fzn_contact_err_t fzn_contact_list(const fzn_persist_ops_t *store, fzn_contact_t *out,
                                   size_t cap, size_t *count)
{
	static uint8_t keys[FZN_CONTACTS_MAX][FZN_PUBKEY_LEN];
	size_t held = 0, i, n = 0;

	if (!store || !store->list || !out || !count)
		return FZN_CONTACT_ERR_MALFORMED;
	*count = 0;
	if (!store->list(store->ctx, FZN_PERSIST_CONTACT, (uint8_t *)keys, FZN_CONTACTS_MAX, &held))
		return FZN_CONTACT_ERR_BACKEND;
	for (i = 0; i < held && n < cap; i++)
		if (fzn_contact_get(store, keys[i], &out[n]) == FZN_CONTACT_OK)
			n++;
	qsort(out, n, sizeof(out[0]), name_order);
	*count = n;
	return FZN_CONTACT_OK;
}

fzn_contact_err_t fzn_contact_find(const fzn_persist_ops_t *store, const char *name,
                                   size_t name_len, fzn_contact_t *out)
{
	static fzn_contact_t all[FZN_CONTACTS_MAX];
	size_t count = 0, i;
	fzn_contact_err_t err;

	if (!store || !name || !out)
		return FZN_CONTACT_ERR_MALFORMED;
	if (!fzn_contact_name_ok(name, name_len))
		return FZN_CONTACT_ERR_NAME;
	err = fzn_contact_list(store, all, FZN_CONTACTS_MAX, &count);
	if (err != FZN_CONTACT_OK)
		return err;
	for (i = 0; i < count; i++)
		if (all[i].name_len == name_len && memcmp(all[i].name, name, name_len) == 0) {
			*out = all[i];
			return FZN_CONTACT_OK;
		}
	return FZN_CONTACT_ERR_ABSENT;
}

fzn_contact_err_t fzn_contact_add(const fzn_persist_ops_t *store,
                                  const uint8_t key[FZN_PUBKEY_LEN], const char *name,
                                  size_t name_len, uint64_t now_ms)
{
	static fzn_contact_t all[FZN_CONTACTS_MAX];
	uint8_t blob[BLOB_MAX];
	uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	uint64_t added = now_ms;
	size_t count = 0, i;
	int held = 0;
	fzn_contact_err_t err;

	if (!store || !store->save || !key || !name)
		return FZN_CONTACT_ERR_MALFORMED;
	if (!fzn_contact_name_ok(name, name_len))
		return FZN_CONTACT_ERR_NAME;
	err = fzn_contact_list(store, all, FZN_CONTACTS_MAX, &count);
	if (err != FZN_CONTACT_OK)
		return err;
	for (i = 0; i < count; i++) {
		if (memcmp(all[i].key, key, FZN_PUBKEY_LEN) == 0) {
			held = 1;
			added = all[i].added_at_ms;
			continue;
		}
		/* ONE NAME, ONE KEY: a name is how a person picks a contact, and
		 * two keys under one name is a choice made for them. */
		if (all[i].name_len == name_len && memcmp(all[i].name, name, name_len) == 0)
			return FZN_CONTACT_ERR_TAKEN;
	}
	if (!held && count >= FZN_CONTACTS_MAX)
		return FZN_CONTACT_ERR_FULL;
	if (fzn_persist_head_write(blob, sizeof(blob), BODY_LEN(name_len), FZN_PERSIST_BLOB_CONTACT)
	    != FZN_PERSIST_OK)
		return FZN_CONTACT_ERR_MALFORMED;
	body[0] = (uint8_t)name_len;
	memcpy(body + 1, name, name_len);
	fzn_put_be64(body + 1 + name_len, added);
	if (!store->save(store->ctx, FZN_PERSIST_CONTACT, key, blob,
	                 FZN_PERSIST_HEAD_LEN + BODY_LEN(name_len)))
		return FZN_CONTACT_ERR_BACKEND;
	return FZN_CONTACT_OK;
}

fzn_contact_err_t fzn_contact_remove(const fzn_persist_ops_t *store,
                                     const uint8_t key[FZN_PUBKEY_LEN])
{
	fzn_contact_t c;
	fzn_contact_err_t err;

	if (!store || !key)
		return FZN_CONTACT_ERR_MALFORMED;
	if (!store->remove)
		return FZN_CONTACT_ERR_BACKEND;
	err = fzn_contact_get(store, key, &c);
	if (err == FZN_CONTACT_ERR_ABSENT)
		return err;
	if (!store->remove(store->ctx, FZN_PERSIST_CONTACT, key))
		return FZN_CONTACT_ERR_BACKEND;
	return FZN_CONTACT_OK;
}
