/* See holdings.h. */

#include "holdings.h"

#include "settings.h"
#include "../chain/chain.h"
#include "../chain/revocation.h"
#include "../chain/root_log.h"
#include "../chain/succession.h"
#include "../roster/roster.h"
#include "../wire/bytes.h"

#include <stdlib.h>
#include <string.h>

const char *fzn_holdings_err_str(fzn_holdings_err_t err)
{
	switch (err) {
	case FZN_HOLDINGS_OK:
		return "ok";
	case FZN_HOLDINGS_MALFORMED:
		return "malformed";
	case FZN_HOLDINGS_BACKEND:
		return "the store could not list or load";
	case FZN_HOLDINGS_FULL:
		return "more objects of the class than are listed";
	}
	return "unknown";
}

/* WHERE A CLASS'S OBJECT SITS IN ITS ROW: after a persist head, after a
 * setting row's own head, or the whole row; at a fixed length or to the
 * row's end; under one of up to four tags. */
enum head { HEAD_NONE, HEAD_PERSIST, HEAD_SETTING };

static const struct class_shape {
	fzn_persist_slot_t slot;
	enum head head;
	size_t len; /* 0: to the row's end */
	uint8_t tags[4];
} SHAPES[FZN_HOLDINGS_CLASSES] = {
	[FZN_HOLDINGS_GRANTS] = { FZN_PERSIST_GRANT, HEAD_NONE, FZN_HOP_LEN, { FZN_OBJECT_HOP } },
	[FZN_HOLDINGS_ROOTS] = {
		FZN_PERSIST_ROOT_CHANGE, HEAD_PERSIST, 0u,
		{
			FZN_OBJECT_ROOT_ADD, FZN_OBJECT_ROOT_REMOVE,
			FZN_OBJECT_QUORUM_SET, FZN_OBJECT_RETENTION_SET,
		},
	},
	[FZN_HOLDINGS_VOTES] = { FZN_PERSIST_VOTE, HEAD_PERSIST, FZN_REVOCATION_LEN,
	                         { FZN_OBJECT_REVOCATION, FZN_OBJECT_WITHDRAWAL } },
	[FZN_HOLDINGS_CONFIRMS] = { FZN_PERSIST_ADMIN_CONFIRM, HEAD_PERSIST, FZN_ADMIN_CONFIRM_LEN,
	                            { FZN_OBJECT_ADMIN_CONFIRM } },
	[FZN_HOLDINGS_RETENTION] = { FZN_PERSIST_ADMIN_RETENTION, HEAD_PERSIST,
	                             FZN_RETENTION_SET_LEN, { FZN_OBJECT_RETENTION_SET } },
	[FZN_HOLDINGS_ROSTER] = {
		FZN_PERSIST_ROSTER, HEAD_PERSIST, FZN_ROSTER_MIN_LEN,
		{ FZN_OBJECT_ROSTER_ADD, FZN_OBJECT_ROSTER_REMOVE, FZN_OBJECT_ROSTER_SET },
	},
	[FZN_HOLDINGS_SUCCESSIONS] = { FZN_PERSIST_SUCCESSION, HEAD_PERSIST, FZN_SUCCESSION_LEN,
	                               { FZN_OBJECT_SUCCESSION } },
	[FZN_HOLDINGS_SETTINGS] = { FZN_PERSIST_SETTING, HEAD_SETTING, 0u, { FZN_OBJECT_SETTING } },
};

/* The class's object in `row`: its offset and length, or 0. */
static int object_in(const struct class_shape *shape, const uint8_t *row, size_t len, size_t *at,
                     size_t *object_len)
{
	size_t start = 0, n, i;

	if (shape->head == HEAD_PERSIST)
		start = FZN_PERSIST_HEAD_LEN;
	else if (shape->head == HEAD_SETTING && !(start = fzn_node_settings_row_setting(row, len)))
		return 0;
	if (len <= start + 2u)
		return 0;
	n = shape->len ? shape->len : len - start;
	if (len - start < n || row[start] != (uint8_t)FZN_SIGNED_VERSION)
		return 0;
	for (i = 0; i < sizeof(shape->tags) && shape->tags[i]; i++)
		if (row[start + 1u] == shape->tags[i]) {
			*at = start;
			*object_len = n;
			return 1;
		}
	return 0;
}

fzn_holdings_err_t fzn_holdings_each(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                     fzn_holdings_class_t cls, fzn_holdings_fn each, void *ctx,
                                     size_t *count)
{
	static uint8_t rows[FZN_HOLDINGS_MAX * FZN_PUBKEY_LEN];
	static uint8_t row[4096];
	const struct class_shape *shape;
	size_t n = 0, i, handed = 0;

	if (count)
		*count = 0;
	if (!store || !store->list || !store->load || !hash || !hash->hash || !each
	    || (unsigned)cls >= FZN_HOLDINGS_CLASSES)
		return FZN_HOLDINGS_MALFORMED;
	shape = &SHAPES[cls];
	/* A LIST THAT DOES NOT FIT FAILS, by the persist ops' own rule, and a
	 * class listed in part is not a class digested. */
	if (!store->list(store->ctx, shape->slot, rows, FZN_HOLDINGS_MAX, &n))
		return FZN_HOLDINGS_FULL;
	for (i = 0; i < n; i++) {
		uint8_t id[FZN_HOLDINGS_ID_LEN];
		size_t len = 0, at = 0, object_len = 0;

		if (!store->load(store->ctx, shape->slot, rows + (i * FZN_PUBKEY_LEN), row, sizeof(row),
		                 &len))
			return FZN_HOLDINGS_BACKEND;
		if (!object_in(shape, row, len, &at, &object_len))
			continue;
		if (!hash->hash(hash->ctx, id, sizeof(id), row + at, object_len))
			return FZN_HOLDINGS_BACKEND;
		handed++;
		if (!each(ctx, id, row + at, object_len))
			break;
	}
	if (count)
		*count = handed;
	return FZN_HOLDINGS_OK;
}

struct collecting {
	uint8_t (*ids)[FZN_HOLDINGS_ID_LEN];
	size_t max, n;
	int full;
};

static int collect(void *ctx, const uint8_t id[FZN_HOLDINGS_ID_LEN], const uint8_t *object,
                   size_t len)
{
	struct collecting *c = (struct collecting *)ctx;

	(void)object;
	(void)len;
	if (c->n >= c->max) {
		c->full = 1;
		return 0;
	}
	memcpy(c->ids[c->n++], id, FZN_HOLDINGS_ID_LEN);
	return 1;
}

static int by_id(const void *a, const void *b)
{
	return memcmp(a, b, FZN_HOLDINGS_ID_LEN);
}

fzn_holdings_err_t fzn_holdings_ids(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                    fzn_holdings_class_t cls,
                                    uint8_t (*ids)[FZN_HOLDINGS_ID_LEN], size_t max,
                                    size_t *count)
{
	struct collecting c;
	fzn_holdings_err_t err;

	if (!ids || !count)
		return FZN_HOLDINGS_MALFORMED;
	*count = 0;
	c.ids = ids;
	c.max = max;
	c.n = 0;
	c.full = 0;
	err = fzn_holdings_each(store, hash, cls, collect, &c, NULL);
	if (err != FZN_HOLDINGS_OK)
		return err;
	if (c.full)
		return FZN_HOLDINGS_FULL;
	qsort(ids, c.n, FZN_HOLDINGS_ID_LEN, by_id);
	*count = c.n;
	return FZN_HOLDINGS_OK;
}

int fzn_holdings_among(const uint8_t (*ids)[FZN_HOLDINGS_ID_LEN], size_t count,
                       const uint8_t id[FZN_HOLDINGS_ID_LEN])
{
	return ids && id && count && bsearch(id, ids, count, FZN_HOLDINGS_ID_LEN, by_id) != NULL;
}

fzn_holdings_err_t fzn_holdings_digest(const fzn_persist_ops_t *store,
                                       const fzn_hash_ops_t *hash, fzn_holdings_class_t cls,
                                       uint8_t digest[FZN_HOLDINGS_ID_LEN], size_t *count)
{
	static const char DOMAIN[] = "fuzznet.holdings";
	static uint8_t in[sizeof(DOMAIN) - 1u + 1u + 8u
	                  + (size_t)FZN_HOLDINGS_MAX * FZN_HOLDINGS_ID_LEN];
	size_t n = 0, at = sizeof(DOMAIN) - 1u;
	fzn_holdings_err_t err;

	if (count)
		*count = 0;
	if (!digest)
		return FZN_HOLDINGS_MALFORMED;
	err = fzn_holdings_ids(store, hash, cls,
	                       (uint8_t (*)[FZN_HOLDINGS_ID_LEN])(in + at + 1u + 8u),
	                       FZN_HOLDINGS_MAX, &n);
	if (err != FZN_HOLDINGS_OK)
		return err;
	memcpy(in, DOMAIN, at);
	in[at] = (uint8_t)cls;
	fzn_put_be64(in + at + 1u, (uint64_t)n);
	if (!hash->hash(hash->ctx, digest, FZN_HOLDINGS_ID_LEN, in,
	                at + 1u + 8u + (n * FZN_HOLDINGS_ID_LEN)))
		return FZN_HOLDINGS_BACKEND;
	if (count)
		*count = n;
	return FZN_HOLDINGS_OK;
}
