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
	case FZN_CONTACT_ERR_ROOM:
		return "more contacts held than the caller had room for";
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

/* ONE ROW, walked into a contact for `fn`: a row that will not read is
 * passed over, as the list always passed it over. */
struct contacts_walk {
	const fzn_persist_ops_t *store;
	int (*fn)(void *ctx, const fzn_contact_t *c);
	void *ctx;
};

static int contact_walked(void *arg, const uint8_t key[FZN_PUBKEY_LEN])
{
	struct contacts_walk *w = arg;
	fzn_contact_t c;

	if (fzn_contact_get(w->store, key, &c) != FZN_CONTACT_OK)
		return 1;
	return w->fn(w->ctx, &c);
}

fzn_contact_err_t fzn_contact_each(const fzn_persist_ops_t *store,
                                   int (*fn)(void *ctx, const fzn_contact_t *c), void *ctx)
{
	struct contacts_walk w;

	if (!store || !fn)
		return FZN_CONTACT_ERR_MALFORMED;
	w.store = store;
	w.fn = fn;
	w.ctx = ctx;
	return fzn_persist_each(store, FZN_PERSIST_CONTACT, contact_walked, &w)
	       ? FZN_CONTACT_OK
	       : FZN_CONTACT_ERR_BACKEND;
}

/* INTO THE CALLER'S ROOM while there is any, and counted past it. */
struct contacts_into {
	fzn_contact_t *out;
	size_t cap, n;
};

static int contact_into(void *ctx, const fzn_contact_t *c)
{
	struct contacts_into *in = ctx;

	if (in->n < in->cap)
		in->out[in->n] = *c;
	in->n++;
	return 1;
}

fzn_contact_err_t fzn_contact_list(const fzn_persist_ops_t *store, fzn_contact_t *out,
                                   size_t cap, size_t *count)
{
	struct contacts_into in;
	fzn_contact_err_t err;

	if (!store || (!out && cap) || !count)
		return FZN_CONTACT_ERR_MALFORMED;
	*count = 0;
	in.out = out;
	in.cap = cap;
	in.n = 0;
	err = fzn_contact_each(store, contact_into, &in);
	if (err != FZN_CONTACT_OK)
		return err;
	*count = in.n;
	if (in.n > cap)
		return FZN_CONTACT_ERR_ROOM;
	qsort(out, in.n, sizeof(out[0]), name_order);
	return FZN_CONTACT_OK;
}

/* THE ONE NAMED, found as the walk passes it. */
struct contacts_named {
	const char *name;
	size_t len;
	fzn_contact_t *out;
	int found;
};

static int contact_named(void *ctx, const fzn_contact_t *c)
{
	struct contacts_named *f = ctx;

	if (c->name_len == f->len && memcmp(c->name, f->name, f->len) == 0) {
		*f->out = *c;
		f->found = 1;
		return 0;
	}
	return 1;
}

fzn_contact_err_t fzn_contact_find(const fzn_persist_ops_t *store, const char *name,
                                   size_t name_len, fzn_contact_t *out)
{
	struct contacts_named f;
	fzn_contact_err_t err;

	if (!store || !name || !out)
		return FZN_CONTACT_ERR_MALFORMED;
	if (!fzn_contact_name_ok(name, name_len))
		return FZN_CONTACT_ERR_NAME;
	f.name = name;
	f.len = name_len;
	f.out = out;
	f.found = 0;
	err = fzn_contact_each(store, contact_named, &f);
	if (err != FZN_CONTACT_OK)
		return err;
	return f.found ? FZN_CONTACT_OK : FZN_CONTACT_ERR_ABSENT;
}

/* WHAT AN ADD MUST KNOW of the contacts held: whether this key is one, and
 * when it was added; whether another key has the name. */
struct contacts_adding {
	const uint8_t *key;
	const char *name;
	size_t len;
	int held, taken;
	uint64_t added;
};

static int contact_adding(void *ctx, const fzn_contact_t *c)
{
	struct contacts_adding *a = ctx;

	if (memcmp(c->key, a->key, FZN_PUBKEY_LEN) == 0) {
		a->held = 1;
		a->added = c->added_at_ms;
		return 1;
	}
	/* ONE NAME, ONE KEY: a name is how a person picks a contact, and two
	 * keys under one name is a choice made for them. */
	if (c->name_len == a->len && memcmp(c->name, a->name, a->len) == 0) {
		a->taken = 1;
		return 0;
	}
	return 1;
}

fzn_contact_err_t fzn_contact_add(const fzn_persist_ops_t *store,
                                  const uint8_t key[FZN_PUBKEY_LEN], const char *name,
                                  size_t name_len, uint64_t now_ms)
{
	struct contacts_adding a;
	uint8_t blob[BLOB_MAX];
	uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	fzn_contact_err_t err;

	if (!store || !store->save || !key || !name)
		return FZN_CONTACT_ERR_MALFORMED;
	if (!fzn_contact_name_ok(name, name_len))
		return FZN_CONTACT_ERR_NAME;
	a.key = key;
	a.name = name;
	a.len = name_len;
	a.held = a.taken = 0;
	a.added = now_ms;
	err = fzn_contact_each(store, contact_adding, &a);
	if (err != FZN_CONTACT_OK)
		return err;
	if (a.taken)
		return FZN_CONTACT_ERR_TAKEN;
	if (fzn_persist_head_write(blob, sizeof(blob), BODY_LEN(name_len), FZN_PERSIST_BLOB_CONTACT)
	    != FZN_PERSIST_OK)
		return FZN_CONTACT_ERR_MALFORMED;
	body[0] = (uint8_t)name_len;
	memcpy(body + 1, name, name_len);
	fzn_put_be64(body + 1 + name_len, a.added);
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
