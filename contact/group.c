/* See group.h. */

#include "group.h"

#include "../wire/bytes.h"

#include <stdlib.h>
#include <string.h>

#define LABEL "fuzznet.contact.group"
#define BODY_LEN(n, c) (1u + (size_t)(n) + 1u + ((size_t)(c) * FZN_PUBKEY_LEN) + 8u)
#define BLOB_MAX \
	((size_t)FZN_PERSIST_HEAD_LEN + BODY_LEN(FZN_CONTACT_NAME_MAX, FZN_GROUP_MEMBERS_MAX))

fzn_contact_err_t fzn_group_id(const fzn_hash_ops_t *hash, const char *name, size_t len,
                               uint8_t out[FZN_PUBKEY_LEN])
{
	uint8_t in[sizeof(LABEL) + FZN_CONTACT_NAME_MAX];

	if (!hash || !hash->hash || !name || !out)
		return FZN_CONTACT_ERR_MALFORMED;
	if (!fzn_contact_name_ok(name, len))
		return FZN_CONTACT_ERR_NAME;
	/* THE LABEL AND ITS NUL, then the name: a group's id is no contact's
	 * key and no other hash this tree takes of a name. */
	memcpy(in, LABEL, sizeof(LABEL));
	memcpy(in + sizeof(LABEL), name, len);
	/* NONZERO IS SUCCESS on this seam, as `session/commitment.h` says. */
	if (!hash->hash(hash->ctx, out, FZN_PUBKEY_LEN, in, sizeof(LABEL) + len))
		return FZN_CONTACT_ERR_MALFORMED;
	return FZN_CONTACT_OK;
}

fzn_contact_err_t fzn_group_get(const fzn_persist_ops_t *store,
                                const uint8_t id[FZN_PUBKEY_LEN], fzn_group_t *out)
{
	static uint8_t blob[BLOB_MAX];
	const uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	size_t len = 0, n, c, i;

	if (!store || !store->load || !id || !out)
		return FZN_CONTACT_ERR_MALFORMED;
	if (!store->load(store->ctx, FZN_PERSIST_CONTACT_GROUP, id, blob, sizeof(blob), &len))
		return FZN_CONTACT_ERR_ABSENT;
	if (len < FZN_PERSIST_HEAD_LEN + 2u)
		return FZN_CONTACT_ERR_SHAPE;
	n = body[0];
	if (n == 0u || n > FZN_CONTACT_NAME_MAX || len < FZN_PERSIST_HEAD_LEN + 2u + n)
		return FZN_CONTACT_ERR_SHAPE;
	c = body[1 + n];
	if (c > FZN_GROUP_MEMBERS_MAX
	    || fzn_persist_head_check(blob, len, BODY_LEN(n, c), FZN_PERSIST_BLOB_CONTACT_GROUP)
	               != FZN_PERSIST_OK
	    || !fzn_contact_name_ok((const char *)body + 1, n))
		return FZN_CONTACT_ERR_SHAPE;
	memset(out, 0, sizeof(*out));
	memcpy(out->id, id, FZN_PUBKEY_LEN);
	memcpy(out->name, body + 1, n);
	out->name_len = n;
	out->count = c;
	for (i = 0; i < c; i++)
		memcpy(out->members[i], body + 2 + n + (i * FZN_PUBKEY_LEN), FZN_PUBKEY_LEN);
	out->made_at_ms = fzn_get_be64(body + 2 + n + (c * FZN_PUBKEY_LEN));
	return FZN_CONTACT_OK;
}

static fzn_contact_err_t put(const fzn_persist_ops_t *store, const fzn_group_t *g)
{
	static uint8_t blob[BLOB_MAX];
	uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	size_t i, body_len = BODY_LEN(g->name_len, g->count);

	if (!store->save
	    || fzn_persist_head_write(blob, sizeof(blob), body_len, FZN_PERSIST_BLOB_CONTACT_GROUP)
	               != FZN_PERSIST_OK)
		return FZN_CONTACT_ERR_MALFORMED;
	body[0] = (uint8_t)g->name_len;
	memcpy(body + 1, g->name, g->name_len);
	body[1 + g->name_len] = (uint8_t)g->count;
	for (i = 0; i < g->count; i++)
		memcpy(body + 2 + g->name_len + (i * FZN_PUBKEY_LEN), g->members[i], FZN_PUBKEY_LEN);
	fzn_put_be64(body + 2 + g->name_len + (g->count * FZN_PUBKEY_LEN), g->made_at_ms);
	if (!store->save(store->ctx, FZN_PERSIST_CONTACT_GROUP, g->id, blob,
	                 FZN_PERSIST_HEAD_LEN + body_len))
		return FZN_CONTACT_ERR_BACKEND;
	return FZN_CONTACT_OK;
}

static int name_order(const void *a, const void *b)
{
	return strcmp(((const fzn_group_t *)a)->name, ((const fzn_group_t *)b)->name);
}

fzn_contact_err_t fzn_group_list(const fzn_persist_ops_t *store, fzn_group_t *out, size_t cap,
                                 size_t *count)
{
	static uint8_t ids[FZN_GROUPS_MAX][FZN_PUBKEY_LEN];
	size_t held = 0, i, n = 0;

	if (!store || !store->list || !out || !count)
		return FZN_CONTACT_ERR_MALFORMED;
	*count = 0;
	if (!store->list(store->ctx, FZN_PERSIST_CONTACT_GROUP, (uint8_t *)ids, FZN_GROUPS_MAX,
	                 &held))
		return FZN_CONTACT_ERR_BACKEND;
	for (i = 0; i < held && n < cap; i++)
		if (fzn_group_get(store, ids[i], &out[n]) == FZN_CONTACT_OK)
			n++;
	qsort(out, n, sizeof(out[0]), name_order);
	*count = n;
	return FZN_CONTACT_OK;
}

fzn_contact_err_t fzn_group_find(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                 const char *name, size_t len, fzn_group_t *out)
{
	uint8_t id[FZN_PUBKEY_LEN];
	fzn_contact_err_t err;

	if (!store || !out)
		return FZN_CONTACT_ERR_MALFORMED;
	err = fzn_group_id(hash, name, len, id);
	if (err != FZN_CONTACT_OK)
		return err;
	return fzn_group_get(store, id, out);
}

fzn_contact_err_t fzn_group_add(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                const char *name, size_t len, uint64_t now_ms)
{
	static fzn_group_t g;
	static uint8_t ids[FZN_GROUPS_MAX][FZN_PUBKEY_LEN];
	size_t held = 0;
	fzn_contact_err_t err;

	if (!store || !store->list)
		return FZN_CONTACT_ERR_MALFORMED;
	err = fzn_group_find(store, hash, name, len, &g);
	if (err == FZN_CONTACT_OK)
		return FZN_CONTACT_ERR_TAKEN;
	if (err != FZN_CONTACT_ERR_ABSENT)
		return err;
	if (!store->list(store->ctx, FZN_PERSIST_CONTACT_GROUP, (uint8_t *)ids, FZN_GROUPS_MAX,
	                 &held))
		return FZN_CONTACT_ERR_BACKEND;
	if (held >= FZN_GROUPS_MAX)
		return FZN_CONTACT_ERR_FULL;
	memset(&g, 0, sizeof(g));
	(void)fzn_group_id(hash, name, len, g.id);
	memcpy(g.name, name, len);
	g.name_len = len;
	g.made_at_ms = now_ms;
	return put(store, &g);
}

fzn_contact_err_t fzn_group_remove(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                   const char *name, size_t len)
{
	static fzn_group_t g;
	fzn_contact_err_t err;

	if (!store)
		return FZN_CONTACT_ERR_MALFORMED;
	err = fzn_group_find(store, hash, name, len, &g);
	if (err != FZN_CONTACT_OK)
		return err;
	if (!store->remove || !store->remove(store->ctx, FZN_PERSIST_CONTACT_GROUP, g.id))
		return FZN_CONTACT_ERR_BACKEND;
	return FZN_CONTACT_OK;
}

fzn_contact_err_t fzn_group_join(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                 const char *name, size_t len,
                                 const uint8_t key[FZN_PUBKEY_LEN])
{
	static fzn_group_t g;
	size_t i;
	fzn_contact_err_t err;

	if (!store || !key)
		return FZN_CONTACT_ERR_MALFORMED;
	err = fzn_group_find(store, hash, name, len, &g);
	if (err != FZN_CONTACT_OK)
		return err;
	for (i = 0; i < g.count; i++)
		if (memcmp(g.members[i], key, FZN_PUBKEY_LEN) == 0)
			return FZN_CONTACT_OK;
	if (g.count >= FZN_GROUP_MEMBERS_MAX)
		return FZN_CONTACT_ERR_FULL;
	memcpy(g.members[g.count++], key, FZN_PUBKEY_LEN);
	return put(store, &g);
}

fzn_contact_err_t fzn_group_leave(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                  const char *name, size_t len,
                                  const uint8_t key[FZN_PUBKEY_LEN])
{
	static fzn_group_t g;
	size_t i;
	fzn_contact_err_t err;

	if (!store || !key)
		return FZN_CONTACT_ERR_MALFORMED;
	err = fzn_group_find(store, hash, name, len, &g);
	if (err != FZN_CONTACT_OK)
		return err;
	for (i = 0; i < g.count; i++)
		if (memcmp(g.members[i], key, FZN_PUBKEY_LEN) == 0) {
			memmove(g.members[i], g.members[i + 1u],
			        (g.count - i - 1u) * FZN_PUBKEY_LEN);
			g.count--;
			return put(store, &g);
		}
	return FZN_CONTACT_ERR_ABSENT;
}

fzn_contact_err_t fzn_group_ids_of(const fzn_persist_ops_t *store,
                                   const uint8_t key[FZN_PUBKEY_LEN],
                                   uint8_t (*out)[FZN_PUBKEY_LEN], size_t cap, size_t *count)
{
	static fzn_group_t all[FZN_GROUPS_MAX];
	size_t held = 0, i, j, n = 0;
	fzn_contact_err_t err;

	if (!store || !key || !out || !count)
		return FZN_CONTACT_ERR_MALFORMED;
	*count = 0;
	err = fzn_group_list(store, all, FZN_GROUPS_MAX, &held);
	if (err != FZN_CONTACT_OK)
		return err;
	for (i = 0; i < held && n < cap; i++)
		for (j = 0; j < all[i].count; j++)
			if (memcmp(all[i].members[j], key, FZN_PUBKEY_LEN) == 0) {
				memcpy(out[n++], all[i].id, FZN_PUBKEY_LEN);
				break;
			}
	*count = n;
	return FZN_CONTACT_OK;
}
