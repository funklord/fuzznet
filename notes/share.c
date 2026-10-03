/* See share.h. */

#include "share.h"

#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#include <string.h>

/* Sixteen bytes, as this tree's other derivation labels are. */
static const char SHARE_LABEL[16] = "fuzznet-share-v1";

#define BODY_LEN (FZN_TREE_ID_LEN + FZN_PUBKEY_LEN + 8u)
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
	    != FZN_PERSIST_OK)
		return FZN_NOTES_ERR_SHAPE;
	memcpy(out->subtree, body, FZN_TREE_ID_LEN);
	memcpy(out->contact, body + FZN_TREE_ID_LEN, FZN_PUBKEY_LEN);
	out->shared_at_ms = fzn_get_be64(body + FZN_TREE_ID_LEN + FZN_PUBKEY_LEN);
	/* FILED WHERE IT SAYS: a row under another pair's key is a share
	 * nobody made. */
	if (share_key(store, out->subtree, out->contact, check) != FZN_NOTES_OK
	    || !fzn_ct_memeq(check, key, FZN_PUBKEY_LEN))
		return FZN_NOTES_ERR_SHAPE;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_share_list(const fzn_notes_store_t *store, fzn_notes_share_t *out,
                                     size_t cap, size_t *count)
{
	static uint8_t keys[FZN_NOTES_SHARES_MAX][FZN_PUBKEY_LEN];
	size_t held = 0, i, n = 0;

	if (!store || !store->ops || !out || !count)
		return FZN_NOTES_ERR_MALFORMED;
	*count = 0;
	if (!store->ops->list
	    || !store->ops->list(store->ops->ctx, FZN_PERSIST_NOTE_SHARE, (uint8_t *)keys,
	                         FZN_NOTES_SHARES_MAX, &held))
		return FZN_NOTES_ERR_BACKEND;
	for (i = 0; i < held && n < cap; i++)
		if (share_get(store, keys[i], &out[n]) == FZN_NOTES_OK)
			n++;
	*count = n;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_share_add(const fzn_notes_store_t *store,
                                    const uint8_t subtree[FZN_TREE_ID_LEN],
                                    const uint8_t contact[FZN_PUBKEY_LEN], uint64_t now_ms)
{
	static fzn_notes_share_t all[FZN_NOTES_SHARES_MAX];
	uint8_t key[FZN_PUBKEY_LEN], blob[BLOB_LEN];
	uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	fzn_notes_share_t held;
	size_t count = 0;
	fzn_notes_err_t err;

	if (!store || !store->ops || !subtree || !contact)
		return FZN_NOTES_ERR_MALFORMED;
	err = share_key(store, subtree, contact, key);
	if (err != FZN_NOTES_OK)
		return err;
	if (share_get(store, key, &held) == FZN_NOTES_OK)
		return FZN_NOTES_OK;
	err = fzn_notes_share_list(store, all, FZN_NOTES_SHARES_MAX, &count);
	if (err != FZN_NOTES_OK)
		return err;
	if (count >= FZN_NOTES_SHARES_MAX)
		return FZN_NOTES_ERR_FULL;
	if (fzn_persist_head_write(blob, sizeof(blob), BODY_LEN, FZN_PERSIST_BLOB_NOTE_SHARE)
	    != FZN_PERSIST_OK)
		return FZN_NOTES_ERR_MALFORMED;
	memcpy(body, subtree, FZN_TREE_ID_LEN);
	memcpy(body + FZN_TREE_ID_LEN, contact, FZN_PUBKEY_LEN);
	fzn_put_be64(body + FZN_TREE_ID_LEN + FZN_PUBKEY_LEN, now_ms);
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
	static fzn_notes_share_t all[FZN_NOTES_SHARES_MAX];
	size_t count = 0, i;
	fzn_notes_err_t err;

	if (!store || !store->ops || !contact || !removed)
		return FZN_NOTES_ERR_MALFORMED;
	*removed = 0;
	if (!store->ops->remove)
		return FZN_NOTES_ERR_UNSUPPORTED;
	err = fzn_notes_share_list(store, all, FZN_NOTES_SHARES_MAX, &count);
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
	static fzn_notes_share_t all[FZN_NOTES_SHARES_MAX];
	size_t held = 0, i, n = 0;
	fzn_notes_err_t err;

	if (!store || !contact || !out || !count)
		return FZN_NOTES_ERR_MALFORMED;
	*count = 0;
	err = fzn_notes_share_list(store, all, FZN_NOTES_SHARES_MAX, &held);
	if (err != FZN_NOTES_OK)
		return err;
	for (i = 0; i < held && n < cap; i++)
		if (memcmp(all[i].contact, contact, FZN_PUBKEY_LEN) == 0)
			memcpy(out[n++], all[i].subtree, FZN_TREE_ID_LEN);
	*count = n;
	return FZN_NOTES_OK;
}

size_t fzn_notes_share_reach(const fzn_notes_view_t *view,
                             const uint8_t (*seeds)[FZN_TREE_ID_LEN], size_t seed_count,
                             uint8_t (*out)[FZN_TREE_ID_LEN], size_t cap)
{
	size_t n = 0, i, j;
	int grew = 1;

	if (!view || !seeds || !out)
		return 0;
	for (i = 0; i < seed_count && n < cap; i++) {
		int have = 0;

		for (j = 0; j < n && !have; j++)
			have = memcmp(out[j], seeds[i], FZN_TREE_ID_LEN) == 0;
		if (!have)
			memcpy(out[n++], seeds[i], FZN_TREE_ID_LEN);
	}
	/* A FIXED POINT, not a walk: a node joins when any claim on it names a
	 * parent already reached. Passes are bounded by the view's size, so a
	 * cycle cannot keep it going. */
	while (grew && n < cap) {
		grew = 0;
		for (i = 0; i < view->count && n < cap; i++) {
			int have = 0, under = 0;

			for (j = 0; j < n && !have; j++)
				have = memcmp(out[j], view->nodes[i].id, FZN_TREE_ID_LEN) == 0;
			if (have)
				continue;
			for (j = 0; j < n && !under; j++)
				under = memcmp(out[j], view->nodes[i].parent, FZN_TREE_ID_LEN) == 0;
			if (!under)
				continue;
			memcpy(out[n++], view->nodes[i].id, FZN_TREE_ID_LEN);
			grew = 1;
		}
	}
	return n;
}
