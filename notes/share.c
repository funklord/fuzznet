/* See share.h. */

#include "share.h"

#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#include <stdlib.h>
#include <string.h>

/* Sixteen bytes, as this tree's other derivation labels are. */
static const char SHARE_LABEL[16] = "fuzznet-share-v1";

#define BODY_LEN (FZN_TREE_ID_LEN + FZN_PUBKEY_LEN + 8u + 1u)
/* A ROW WRITTEN BEFORE sec 655, with no catch-up byte: read as the group's. */
#define BODY_LEN_V0 (FZN_TREE_ID_LEN + FZN_PUBKEY_LEN + 8u)
#define BLOB_LEN ((size_t)FZN_PERSIST_HEAD_LEN + BODY_LEN)

fzn_notes_err_t fzn_notes_share_capability(uint32_t service, uint32_t product,
                                           const fzn_hash_ops_t *hash, fzn_cap_id_t *out)
{
	if (!hash || !out)
		return FZN_NOTES_ERR_MALFORMED;
	if (fzn_service_capability(service, product, (const uint8_t *)FZN_NOTES_SHARE_NAME,
	                           sizeof(FZN_NOTES_SHARE_NAME) - 1u, hash, out)
	    != FZN_CHAIN_OK)
		return FZN_NOTES_ERR_MALFORMED;
	return FZN_NOTES_OK;
}

/* The persist subject a share is filed under: the pair, hashed. */
static fzn_notes_err_t share_key(const fzn_notes_store_t *store,
                                 const uint8_t subtree[FZN_TREE_ID_LEN],
                                 const uint8_t contact[FZN_PUBKEY_LEN],
                                 uint8_t out[FZN_PUBKEY_LEN])
{
	uint8_t input[sizeof(SHARE_LABEL) + FZN_TREE_ID_LEN + FZN_PUBKEY_LEN];

	memcpy(input, SHARE_LABEL, sizeof(SHARE_LABEL));
	memcpy(input + sizeof(SHARE_LABEL), subtree, FZN_TREE_ID_LEN);
	memcpy(input + sizeof(SHARE_LABEL) + FZN_TREE_ID_LEN, contact, FZN_PUBKEY_LEN);
	if (!store->hash->hash(store->hash->ctx, out, FZN_PUBKEY_LEN, input, sizeof(input)))
		return FZN_NOTES_ERR_BACKEND;
	return FZN_NOTES_OK;
}

static fzn_notes_err_t share_get(const fzn_notes_store_t *store,
                                 const uint8_t key[FZN_PUBKEY_LEN], fzn_notes_share_t *out)
{
	uint8_t blob[BLOB_LEN];
	const uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	uint8_t check[FZN_PUBKEY_LEN];
	size_t len = 0;

	if (!store->ops->load(store->ops->ctx, FZN_PERSIST_NOTE_SHARE, key, blob, sizeof(blob),
	                      &len))
		return FZN_NOTES_ERR_ABSENT;
	if (fzn_persist_head_check(blob, len, BODY_LEN, FZN_PERSIST_BLOB_NOTE_SHARE)
	            != FZN_PERSIST_OK
	    && fzn_persist_head_check(blob, len, BODY_LEN_V0, FZN_PERSIST_BLOB_NOTE_SHARE)
	               != FZN_PERSIST_OK)
		return FZN_NOTES_ERR_SHAPE;
	memcpy(out->subtree, body, FZN_TREE_ID_LEN);
	memcpy(out->contact, body + FZN_TREE_ID_LEN, FZN_PUBKEY_LEN);
	out->shared_at_ms = fzn_get_be64(body + FZN_TREE_ID_LEN + FZN_PUBKEY_LEN);
	out->catch_up = len == FZN_PERSIST_HEAD_LEN + BODY_LEN ? body[BODY_LEN_V0]
	                                                       : FZN_NOTES_SHARE_CATCH_UP_GROUP;
	if (out->catch_up > FZN_NOTES_SHARE_CATCH_UP_NO)
		return FZN_NOTES_ERR_SHAPE;
	/* FILED WHERE IT SAYS: a row under another pair's key is a share
	 * nobody made. */
	if (share_key(store, out->subtree, out->contact, check) != FZN_NOTES_OK
	    || !fzn_ct_memeq(check, key, FZN_PUBKEY_LEN))
		return FZN_NOTES_ERR_SHAPE;
	return FZN_NOTES_OK;
}

/* EVERY ROW'S KEY, into `*keys` grown as needed: a list holding more than
 * it was asked for fails, so the room doubles until it holds them. */
static fzn_notes_err_t share_keys(const fzn_notes_store_t *store, uint8_t **keys, size_t *room,
                                  size_t *held)
{
	size_t max = *room ? *room : 64u;

	*held = 0;
	if (!store->ops->list)
		return FZN_NOTES_ERR_BACKEND;
	for (;;) {
		if (max > *room) {
			uint8_t *more = realloc(*keys, max * FZN_PUBKEY_LEN);

			if (!more)
				return FZN_NOTES_ERR_BACKEND;
			*keys = more;
			*room = max;
		}
		if (store->ops->list(store->ops->ctx, FZN_PERSIST_NOTE_SHARE, *keys, max, held))
			return FZN_NOTES_OK;
		if (max > ((size_t)1 << 24))
			return FZN_NOTES_ERR_BACKEND;
		max *= 2u;
	}
}

static uint8_t *listed_keys;
static size_t listed_room;

fzn_notes_err_t fzn_notes_share_list(const fzn_notes_store_t *store, fzn_notes_share_t *out,
                                     size_t cap, size_t *count)
{
	size_t held = 0, i, n = 0;
	fzn_notes_err_t err;

	if (!store || !store->ops || !out || !count)
		return FZN_NOTES_ERR_MALFORMED;
	*count = 0;
	err = share_keys(store, &listed_keys, &listed_room, &held);
	if (err != FZN_NOTES_OK)
		return err;
	for (i = 0; i < held && n < cap; i++)
		if (share_get(store, listed_keys + i * FZN_PUBKEY_LEN, &out[n]) == FZN_NOTES_OK)
			n++;
	*count = n;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_share_all(const fzn_notes_store_t *store, fzn_notes_share_t **out,
                                    size_t *room, size_t *count)
{
	size_t held = 0, i, n = 0;
	fzn_notes_err_t err;

	if (!store || !store->ops || !out || !room || !count)
		return FZN_NOTES_ERR_MALFORMED;
	*count = 0;
	err = share_keys(store, &listed_keys, &listed_room, &held);
	if (err != FZN_NOTES_OK)
		return err;
	if (held > *room) {
		fzn_notes_share_t *more = realloc(*out, held * sizeof(**out));

		if (!more)
			return FZN_NOTES_ERR_BACKEND;
		*out = more;
		*room = held;
	}
	for (i = 0; i < held; i++)
		if (share_get(store, listed_keys + i * FZN_PUBKEY_LEN, &(*out)[n]) == FZN_NOTES_OK)
			n++;
	*count = n;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_share_add(const fzn_notes_store_t *store,
                                    const uint8_t subtree[FZN_TREE_ID_LEN],
                                    const uint8_t contact[FZN_PUBKEY_LEN], uint64_t now_ms)
{
	uint8_t key[FZN_PUBKEY_LEN], blob[BLOB_LEN];
	uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	fzn_notes_share_t held;
	fzn_notes_err_t err;

	if (!store || !store->ops || !subtree || !contact)
		return FZN_NOTES_ERR_MALFORMED;
	err = share_key(store, subtree, contact, key);
	if (err != FZN_NOTES_OK)
		return err;
	if (share_get(store, key, &held) == FZN_NOTES_OK)
		return FZN_NOTES_OK;
#ifdef FZN_NOTES_SHARES_MAX
	/* A `small` BUILD'S BOUND, sec 922: its rows counted, few as they are. */
	{
		size_t count = 0;

		err = share_keys(store, &listed_keys, &listed_room, &count);
		if (err != FZN_NOTES_OK)
			return err;
		if (count >= FZN_NOTES_SHARES_MAX)
			return FZN_NOTES_ERR_FULL;
	}
#endif
	if (fzn_persist_head_write(blob, sizeof(blob), BODY_LEN, FZN_PERSIST_BLOB_NOTE_SHARE)
	    != FZN_PERSIST_OK)
		return FZN_NOTES_ERR_MALFORMED;
	memcpy(body, subtree, FZN_TREE_ID_LEN);
	memcpy(body + FZN_TREE_ID_LEN, contact, FZN_PUBKEY_LEN);
	fzn_put_be64(body + FZN_TREE_ID_LEN + FZN_PUBKEY_LEN, now_ms);
	body[BODY_LEN_V0] = FZN_NOTES_SHARE_CATCH_UP_GROUP;
	if (!store->ops->save(store->ops->ctx, FZN_PERSIST_NOTE_SHARE, key, blob, sizeof(blob)))
		return FZN_NOTES_ERR_BACKEND;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_share_set_catch_up(const fzn_notes_store_t *store,
                                             const uint8_t subtree[FZN_TREE_ID_LEN],
                                             const uint8_t contact[FZN_PUBKEY_LEN],
                                             uint8_t catch_up)
{
	uint8_t key[FZN_PUBKEY_LEN], blob[BLOB_LEN];
	uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	fzn_notes_share_t held;
	fzn_notes_err_t err;

	if (!store || !store->ops || !subtree || !contact
	    || catch_up > FZN_NOTES_SHARE_CATCH_UP_NO)
		return FZN_NOTES_ERR_MALFORMED;
	err = share_key(store, subtree, contact, key);
	if (err != FZN_NOTES_OK)
		return err;
	err = share_get(store, key, &held);
	if (err != FZN_NOTES_OK)
		return err;
	/* REWRITTEN WHOLE, its time kept: a row of the old length gains the
	 * byte. */
	if (fzn_persist_head_write(blob, sizeof(blob), BODY_LEN, FZN_PERSIST_BLOB_NOTE_SHARE)
	    != FZN_PERSIST_OK)
		return FZN_NOTES_ERR_MALFORMED;
	memcpy(body, held.subtree, FZN_TREE_ID_LEN);
	memcpy(body + FZN_TREE_ID_LEN, held.contact, FZN_PUBKEY_LEN);
	fzn_put_be64(body + FZN_TREE_ID_LEN + FZN_PUBKEY_LEN, held.shared_at_ms);
	body[BODY_LEN_V0] = catch_up;
	if (!store->ops->save(store->ops->ctx, FZN_PERSIST_NOTE_SHARE, key, blob, sizeof(blob)))
		return FZN_NOTES_ERR_BACKEND;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_share_remove(const fzn_notes_store_t *store,
                                       const uint8_t subtree[FZN_TREE_ID_LEN],
                                       const uint8_t contact[FZN_PUBKEY_LEN])
{
	uint8_t key[FZN_PUBKEY_LEN];
	fzn_notes_share_t held;
	fzn_notes_err_t err;

	if (!store || !store->ops || !subtree || !contact)
		return FZN_NOTES_ERR_MALFORMED;
	if (!store->ops->remove)
		return FZN_NOTES_ERR_UNSUPPORTED;
	err = share_key(store, subtree, contact, key);
	if (err != FZN_NOTES_OK)
		return err;
	if (share_get(store, key, &held) == FZN_NOTES_ERR_ABSENT)
		return FZN_NOTES_ERR_ABSENT;
	if (!store->ops->remove(store->ops->ctx, FZN_PERSIST_NOTE_SHARE, key))
		return FZN_NOTES_ERR_BACKEND;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_share_forget(const fzn_notes_store_t *store,
                                       const uint8_t contact[FZN_PUBKEY_LEN], size_t *removed)
{
	static fzn_notes_share_t *all;
	static size_t room;
	size_t count = 0, i;
	fzn_notes_err_t err;

	if (!store || !store->ops || !contact || !removed)
		return FZN_NOTES_ERR_MALFORMED;
	*removed = 0;
	if (!store->ops->remove)
		return FZN_NOTES_ERR_UNSUPPORTED;
	err = fzn_notes_share_all(store, &all, &room, &count);
	if (err != FZN_NOTES_OK)
		return err;
	for (i = 0; i < count; i++) {
		if (!fzn_ct_memeq(all[i].contact, contact, FZN_PUBKEY_LEN))
			continue;
		err = fzn_notes_share_remove(store, all[i].subtree, contact);
		if (err != FZN_NOTES_OK && err != FZN_NOTES_ERR_ABSENT)
			return err;
		(*removed)++;
	}
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_share_with(const fzn_notes_store_t *store,
                                     const uint8_t contact[FZN_PUBKEY_LEN],
                                     uint8_t (*out)[FZN_TREE_ID_LEN], size_t cap, size_t *count)
{
	static fzn_notes_share_t *all;
	static size_t room;
	size_t held = 0, i, n = 0;
	fzn_notes_err_t err;

	if (!store || !contact || !out || !count)
		return FZN_NOTES_ERR_MALFORMED;
	*count = 0;
	err = fzn_notes_share_all(store, &all, &room, &held);
	if (err != FZN_NOTES_OK)
		return err;
	for (i = 0; i < held && n < cap; i++)
		if (memcmp(all[i].contact, contact, FZN_PUBKEY_LEN) == 0)
			memcpy(out[n++], all[i].subtree, FZN_TREE_ID_LEN);
	*count = n;
	return FZN_NOTES_OK;
}

static int claim_by_id(const void *a, const void *b)
{
	return memcmp((*(const fzn_tree_node_t *const *)a)->id,
	              (*(const fzn_tree_node_t *const *)b)->id, FZN_TREE_ID_LEN);
}

static int claim_by_parent(const void *a, const void *b)
{
	return memcmp((*(const fzn_tree_node_t *const *)a)->parent,
	              (*(const fzn_tree_node_t *const *)b)->parent, FZN_TREE_ID_LEN);
}

/* THE FIRST OF `rows` AT OR PAST `id`, by each row's id or its parent. */
static size_t first_at(const fzn_tree_node_t *const *rows, size_t count, const uint8_t *id,
                       int by_parent)
{
	size_t low = 0, high = count;

	while (low < high) {
		size_t mid = low + (high - low) / 2u;
		const uint8_t *at = by_parent ? rows[mid]->parent : rows[mid]->id;

		if (memcmp(at, id, FZN_TREE_ID_LEN) < 0)
			low = mid + 1u;
		else
			high = mid;
	}
	return low;
}

size_t fzn_notes_share_reach(const fzn_notes_view_t *view,
                             const uint8_t (*seeds)[FZN_TREE_ID_LEN], size_t seed_count,
                             uint8_t (*out)[FZN_TREE_ID_LEN], size_t cap)
{
	static const fzn_tree_node_t *under[FZN_NOTES_MAX], *named[FZN_NOTES_MAX];
	static uint8_t seen[FZN_NOTES_MAX];
	size_t n = 0, i, j, k, at, held;

	if (!view || !seeds || !out)
		return 0;
	held = view->count;
	for (i = 0; i < seed_count && n < cap; i++) {
		int have = 0;

		for (j = 0; j < n && !have; j++)
			have = memcmp(out[j], seeds[i], FZN_TREE_ID_LEN) == 0;
		if (!have)
			memcpy(out[n++], seeds[i], FZN_TREE_ID_LEN);
	}
	for (i = 0; i < held; i++)
		under[i] = named[i] = &view->nodes[i];
	if (held > 1u) {
		qsort(under, held, sizeof(under[0]), claim_by_parent);
		qsort(named, held, sizeof(named[0]), claim_by_id);
	}
	memset(seen, 0, held);
	for (i = 0; i < n; i++) {
		at = first_at(named, held, out[i], 0);
		if (at < held && memcmp(named[at]->id, out[i], FZN_TREE_ID_LEN) == 0)
			seen[at] = 1u;
	}
	/* A WALK OUT FROM WHAT IS REACHED: a node joins when any claim on it names a
	 * parent already reached, and each joins once, so a cycle ends. Every node
	 * tried against everything reached was the square of a shared folder, and past
	 * about 1500 notes a share's first question went unanswered, sec 942. */
	for (i = 0; i < n; i++)
		for (k = first_at(under, held, out[i], 1);
		     k < held && memcmp(under[k]->parent, out[i], FZN_TREE_ID_LEN) == 0 && n < cap; k++) {
			at = first_at(named, held, under[k]->id, 0);
			if (seen[at])
				continue;
			seen[at] = 1u;
			memcpy(out[n++], under[k]->id, FZN_TREE_ID_LEN);
		}
	return n;
}
