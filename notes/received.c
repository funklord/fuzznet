/* See received.h. */

#include "received.h"

#include <string.h>

/* Sixteen bytes, as this tree's other derivation labels are. */
static const char ROW_LABEL[16] = "fuzznet-recvd-v1";

#define PREFIX_LEN (2u * FZN_PUBKEY_LEN) /* sharer | claim key */
#define ROW_MAX ((size_t)FZN_PERSIST_HEAD_LEN + PREFIX_LEN + FZN_RECORD_MAX_LEN)

static int row_key(const fzn_notes_received_t *seam, const uint8_t claim[FZN_PUBKEY_LEN],
                   uint8_t out[FZN_PUBKEY_LEN])
{
	uint8_t input[sizeof(ROW_LABEL) + PREFIX_LEN];

	memcpy(input, ROW_LABEL, sizeof(ROW_LABEL));
	memcpy(input + sizeof(ROW_LABEL), seam->sharer, FZN_PUBKEY_LEN);
	memcpy(input + sizeof(ROW_LABEL) + FZN_PUBKEY_LEN, claim, FZN_PUBKEY_LEN);
	return seam->hash->hash(seam->hash->ctx, out, FZN_PUBKEY_LEN, input, sizeof(input));
}

/* A row as it is stored, checked to be a SHARED_NOTE blob; its record is
 * the bytes past the prefix. */
static int row_read(const fzn_persist_ops_t *base, const uint8_t key[FZN_PUBKEY_LEN],
                    uint8_t *row, size_t *len)
{
	*len = 0;
	if (!base->load(base->ctx, FZN_PERSIST_SHARED_NOTE, key, row, ROW_MAX, len)
	    || *len <= FZN_PERSIST_HEAD_LEN + PREFIX_LEN
	    || fzn_persist_head_check(row, *len, *len - FZN_PERSIST_HEAD_LEN,
	                              FZN_PERSIST_BLOB_SHARED_NOTE)
	               != FZN_PERSIST_OK)
		return 0;
	return 1;
}

static int seam_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                     size_t cap, size_t *len)
{
	const fzn_notes_received_t *seam = (const fzn_notes_received_t *)ctx;
	static uint8_t row[ROW_MAX];
	const uint8_t *prefix = row + FZN_PERSIST_HEAD_LEN;
	uint8_t key[FZN_PUBKEY_LEN];
	size_t n = 0, record_len;

	/* NOTHING BUT NOTES: no sequence, no purge, no partner is held in a
	 * sharer's tree, so each reads absent. */
	if (slot != FZN_PERSIST_NOTE || !subject || !row_key(seam, subject, key)
	    || !row_read(seam->base, key, row, &n))
		return 0;
	/* THE ROW IT SAYS IT IS: this sharer's, this claim's. */
	if (memcmp(prefix, seam->sharer, FZN_PUBKEY_LEN) != 0
	    || memcmp(prefix + FZN_PUBKEY_LEN, subject, FZN_PUBKEY_LEN) != 0)
		return 0;
	record_len = n - FZN_PERSIST_HEAD_LEN - PREFIX_LEN;
	if (fzn_persist_head_write(out, cap, record_len, FZN_PERSIST_BLOB_NOTE) != FZN_PERSIST_OK)
		return 0;
	memcpy(out + FZN_PERSIST_HEAD_LEN, prefix + PREFIX_LEN, record_len);
	*len = FZN_PERSIST_HEAD_LEN + record_len;
	return 1;
}

static int seam_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                     const uint8_t *bytes, size_t len)
{
	const fzn_notes_received_t *seam = (const fzn_notes_received_t *)ctx;
	static uint8_t row[ROW_MAX];
	uint8_t key[FZN_PUBKEY_LEN];
	size_t record_len;

	/* A SHARER'S TREE IS WRITTEN ONLY BY PULLING: a counter, a purge or a
	 * partner saved here would be this node acting in a tree it does not
	 * own. */
	if (slot != FZN_PERSIST_NOTE || !subject || !bytes || len <= FZN_PERSIST_HEAD_LEN
	    || fzn_persist_head_check(bytes, len, len - FZN_PERSIST_HEAD_LEN, FZN_PERSIST_BLOB_NOTE)
	               != FZN_PERSIST_OK)
		return 0;
	record_len = len - FZN_PERSIST_HEAD_LEN;
	if (fzn_persist_head_write(row, sizeof(row), PREFIX_LEN + record_len,
	                           FZN_PERSIST_BLOB_SHARED_NOTE)
	            != FZN_PERSIST_OK
	    || !row_key(seam, subject, key))
		return 0;
	memcpy(row + FZN_PERSIST_HEAD_LEN, seam->sharer, FZN_PUBKEY_LEN);
	memcpy(row + FZN_PERSIST_HEAD_LEN + FZN_PUBKEY_LEN, subject, FZN_PUBKEY_LEN);
	memcpy(row + FZN_PERSIST_HEAD_LEN + PREFIX_LEN, bytes + FZN_PERSIST_HEAD_LEN, record_len);
	return seam->base->save(seam->base->ctx, FZN_PERSIST_SHARED_NOTE, key, row,
	                        FZN_PERSIST_HEAD_LEN + PREFIX_LEN + record_len);
}

static int seam_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max,
                     size_t *count)
{
	const fzn_notes_received_t *seam = (const fzn_notes_received_t *)ctx;
	static uint8_t keys[FZN_NOTES_RECEIVED_ROWS][FZN_PUBKEY_LEN];
	static uint8_t row[ROW_MAX];
	uint8_t check[FZN_PUBKEY_LEN];
	size_t held = 0, i, n = 0, len;

	if (!out || !count)
		return 0;
	*count = 0;
	if (slot != FZN_PERSIST_NOTE)
		return 1;
	if (!seam->base->list(seam->base->ctx, FZN_PERSIST_SHARED_NOTE, (uint8_t *)keys,
	                      FZN_NOTES_RECEIVED_ROWS, &held))
		return 0;
	for (i = 0; i < held; i++) {
		const uint8_t *prefix = row + FZN_PERSIST_HEAD_LEN;

		if (!row_read(seam->base, keys[i], row, &len)
		    || memcmp(prefix, seam->sharer, FZN_PUBKEY_LEN) != 0)
			continue;
		/* FILED WHERE IT SAYS, or it is not listed: a row copied under
		 * another key would otherwise name a claim twice. */
		if (!row_key(seam, prefix + FZN_PUBKEY_LEN, check)
		    || memcmp(check, keys[i], FZN_PUBKEY_LEN) != 0)
			continue;
		/* TRUNCATION IS A FAILURE, as `persist.h` asks of every list. */
		if (n >= max)
			return 0;
		memcpy(out + (n * FZN_PUBKEY_LEN), prefix + FZN_PUBKEY_LEN, FZN_PUBKEY_LEN);
		n++;
	}
	*count = n;
	return 1;
}

static int seam_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	const fzn_notes_received_t *seam = (const fzn_notes_received_t *)ctx;
	uint8_t key[FZN_PUBKEY_LEN];

	if (slot != FZN_PERSIST_NOTE)
		return 1; /* nothing else is held, so it is gone */
	if (!subject || !seam->base->remove || !row_key(seam, subject, key))
		return 0;
	return seam->base->remove(seam->base->ctx, FZN_PERSIST_SHARED_NOTE, key);
}

fzn_notes_err_t fzn_notes_received_ops(fzn_notes_received_t *seam, const fzn_persist_ops_t *base,
                                       const fzn_hash_ops_t *hash,
                                       const uint8_t sharer[FZN_PUBKEY_LEN],
                                       fzn_persist_ops_t *ops)
{
	if (!seam || !base || !base->load || !base->save || !base->list || !hash || !hash->hash
	    || !sharer || !ops)
		return FZN_NOTES_ERR_MALFORMED;
	seam->base = base;
	seam->hash = hash;
	memcpy(seam->sharer, sharer, FZN_PUBKEY_LEN);
	ops->load = seam_load;
	ops->save = seam_save;
	ops->list = seam_list;
	ops->remove = seam_remove;
	ops->ctx = seam;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_received_forget(const fzn_persist_ops_t *base,
                                          const uint8_t sharer[FZN_PUBKEY_LEN], size_t *removed)
{
	static uint8_t keys[FZN_NOTES_RECEIVED_ROWS][FZN_PUBKEY_LEN];
	static uint8_t row[ROW_MAX];
	size_t held = 0, i, n = 0, len;

	if (removed)
		*removed = 0;
	if (!base || !base->list || !base->load || !sharer)
		return FZN_NOTES_ERR_MALFORMED;
	if (!base->remove)
		return FZN_NOTES_ERR_UNSUPPORTED;
	if (!base->list(base->ctx, FZN_PERSIST_SHARED_NOTE, (uint8_t *)keys, FZN_NOTES_RECEIVED_ROWS,
	                &held))
		return FZN_NOTES_ERR_BACKEND;
	for (i = 0; i < held; i++) {
		if (!row_read(base, keys[i], row, &len)
		    || memcmp(row + FZN_PERSIST_HEAD_LEN, sharer, FZN_PUBKEY_LEN) != 0)
			continue;
		if (!base->remove(base->ctx, FZN_PERSIST_SHARED_NOTE, keys[i]))
			return FZN_NOTES_ERR_BACKEND;
		n++;
	}
	if (removed)
		*removed = n;
	return FZN_NOTES_OK;
}

size_t fzn_notes_received_roots(const fzn_notes_view_t *view, const fzn_tree_node_t **out,
                                size_t cap)
{
	size_t n = 0, i, j, k;

	if (!view || !out)
		return 0;
	for (i = 0; i < view->count && n < cap; i++) {
		int parent_held = 0, listed = 0;

		/* ANY CLAIM ON THIS NOTE naming a held parent places it. */
		for (k = 0; k < view->count && !parent_held; k++) {
			if (memcmp(view->nodes[k].id, view->nodes[i].id, FZN_TREE_ID_LEN) != 0)
				continue;
			for (j = 0; j < view->count && !parent_held; j++)
				parent_held = memcmp(view->nodes[j].id, view->nodes[k].parent,
				                     FZN_TREE_ID_LEN)
				              == 0;
		}
		if (parent_held)
			continue;
		/* ONCE, however many writers claim it. */
		for (j = 0; j < n && !listed; j++)
			listed = memcmp(out[j]->id, view->nodes[i].id, FZN_TREE_ID_LEN) == 0;
		if (!listed)
			out[n++] = &view->nodes[i];
	}
	return n;
}
