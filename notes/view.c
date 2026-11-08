/* See view.h. */

#include "view.h"

#include <stdlib.h>
#include <string.h>

fzn_notes_err_t fzn_notes_view_load(const fzn_notes_store_t *store, fzn_notes_view_t *view)
{
	static uint8_t keys[FZN_NOTES_MAX][FZN_PUBKEY_LEN];
	fzn_tree_walk_t walk;
	size_t count = 0, i;
	fzn_notes_err_t err;
	uint64_t stamp;

	if (!store || !view)
		return FZN_NOTES_ERR_MALFORMED;
	/* NOTHING WRITTEN SINCE, sec 928: as loaded. */
	stamp = store->stamp ? store->stamp(store->stamp_ctx) : 0u;
	if (store->stamp && view->loaded_from == store->ops && view->loaded_at == stamp)
		return FZN_NOTES_OK;
	view->loaded_from = NULL;
	view->generation++;
	view->arena_used = 0;
	view->count = 0;
	view->unreadable = 0;
	memset(view->mark, 0, sizeof(view->mark));
	err = fzn_notes_claims(store, keys, FZN_NOTES_MAX, &count);
	if (err != FZN_NOTES_OK)
		return err;

	for (i = 0; i < count; i++) {
		uint8_t *slot = view->arena + view->arena_used;
		size_t got = 0;
		fzn_record_t rec;
		fzn_tree_node_t node;

		/* THE ARENA HOLDS EVERY CLAIM AT FULL SIZE, so this cannot run
		 * out for a store within its bound; checked anyway, since a
		 * truncated traversal would fall on the user with most notes. */
		if (sizeof(view->arena) - view->arena_used < (size_t)FZN_RECORD_MAX_LEN)
			return FZN_NOTES_ERR_FULL;
		if (fzn_notes_get_key(store, keys[i], slot, FZN_RECORD_MAX_LEN, &got) != FZN_NOTES_OK
		    || fzn_record_open(slot, got, &rec) != FZN_RECORD_OK
		    || fzn_record_kind(rec) != FZN_NOTE_KIND
		    || fzn_tree_open(rec, &node) != FZN_TREE_OK) {
			view->unreadable++;
			continue;
		}
		view->arena_used += got;
		view->nodes[view->count] = node;
		view->writers[view->count] = fzn_record_issuer(rec);
		view->count++;
	}
	if (view->count > 0u
	    && fzn_tree_reachable(view->nodes, view->count, view->mark, sizeof(view->mark), &walk)
	               != FZN_TREE_OK)
		return FZN_NOTES_ERR_MALFORMED;
	if (store->stamp) {
		view->loaded_from = store->ops;
		view->loaded_at = stamp;
	}
	return FZN_NOTES_OK;
}

int fzn_notes_view_took(const fzn_notes_store_t *store, fzn_notes_view_t *view, uint64_t stamp,
                        const uint8_t *record, size_t len)
{
	uint8_t *slot;
	fzn_record_t rec;
	fzn_tree_node_t node;
	size_t i;

	if (!store || !view || !record || !store->stamp || view->loaded_from != store->ops
	    || view->loaded_at != stamp || view->count >= FZN_NOTES_MAX
	    || sizeof(view->arena) - view->arena_used < len)
		return 0;
	slot = view->arena + view->arena_used;
	memcpy(slot, record, len);
	if (fzn_record_open(slot, len, &rec) != FZN_RECORD_OK
	    || fzn_record_kind(rec) != FZN_NOTE_KIND || fzn_tree_open(rec, &node) != FZN_TREE_OK)
		return 0;
	/* A NODE HELD UNDER ITS ID already is not a new note: read afresh. */
	for (i = 0; i < view->count; i++)
		if (memcmp(view->nodes[i].id, node.id, FZN_TREE_ID_LEN) == 0) {
			view->loaded_from = NULL;
			return 0;
		}
	view->mark[view->count] = fzn_tree_is_root(node.parent) ? 1u : 0u;
	for (i = 0; i < view->count && !view->mark[view->count]; i++)
		if (view->mark[i] && memcmp(view->nodes[i].id, node.parent, FZN_TREE_ID_LEN) == 0)
			view->mark[view->count] = 1u;
	view->arena_used += len;
	view->nodes[view->count] = node;
	view->writers[view->count] = fzn_record_issuer(rec);
	view->count++;
	view->generation++;
	view->loaded_at = store->stamp(store->stamp_ctx);
	return 1;
}

fzn_notes_err_t fzn_notes_children(const fzn_notes_view_t *view,
                                   const uint8_t parent[FZN_TREE_ID_LEN],
                                   const fzn_tree_node_t **out, size_t cap, size_t *count,
                                   int *truncated)
{
	fzn_tree_walk_t walk;

	if (!view || !parent || !out || !count)
		return FZN_NOTES_ERR_MALFORMED;
	*count = 0;
	if (truncated)
		*truncated = 0;
	if (view->count == 0u)
		return FZN_NOTES_OK;
	if (fzn_tree_children(view->nodes, view->count, parent, out, cap, &walk) != FZN_TREE_OK)
		return FZN_NOTES_ERR_MALFORMED;
	*count = walk.emitted;
	if (truncated)
		*truncated = walk.truncated;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_top_level(const fzn_notes_view_t *view, const fzn_tree_node_t **out,
                                    size_t cap, size_t *count, int *truncated)
{
	static const uint8_t root[FZN_TREE_ID_LEN];
	size_t n = 0, i;
	int cut = 0;
	fzn_notes_err_t err;

	if (!view || !out || !count)
		return FZN_NOTES_ERR_MALFORMED;
	err = fzn_notes_children(view, root, out, cap, &n, &cut);
	if (err != FZN_NOTES_OK)
		return err;
	/* WHAT THE ROOT CANNOT REACH, after its children: a node in a cycle
	 * or waiting for its parent is shown here rather than nowhere. */
	for (i = 0; i < view->count && !cut; i++) {
		if (view->mark[i])
			continue;
		if (n >= cap) {
			cut = 1;
			break;
		}
		out[n++] = &view->nodes[i];
	}
	*count = n;
	if (truncated)
		*truncated = cut;
	return FZN_NOTES_OK;
}

int fzn_notes_reachable(const fzn_notes_view_t *view, size_t i)
{
	return view && i < view->count && view->mark[i] != 0u;
}

static int claim_cmp(const void *a, const void *b)
{
	const fzn_tree_node_t *x = *(const fzn_tree_node_t *const *)a;
	const fzn_tree_node_t *y = *(const fzn_tree_node_t *const *)b;
	int cmp = memcmp(x->id, y->id, FZN_TREE_ID_LEN);

	return cmp ? cmp : memcmp(x->parent, y->parent, FZN_TREE_ID_LEN);
}

/* THE CLAIMS SORTED, so one note's stand together, its parents in order: every pair
 * compared cost two thirds of a page at 3000 notes, sec 940. */
size_t fzn_notes_contested(const fzn_notes_view_t *view, uint8_t (*out)[FZN_TREE_ID_LEN],
                           size_t cap)
{
	static const fzn_tree_node_t *claims[FZN_NOTES_MAX];
	size_t found = 0, i, end;

	if (!view)
		return 0;
	for (i = 0; i < view->count; i++)
		claims[i] = &view->nodes[i];
	if (view->count > 1u)
		qsort(claims, view->count, sizeof(claims[0]), claim_cmp);
	for (i = 0; i < view->count; i = end) {
		const uint8_t *id = claims[i]->id;

		for (end = i + 1u;
		     end < view->count && memcmp(claims[end]->id, id, FZN_TREE_ID_LEN) == 0; end++)
			;
		/* Two claims under ONE parent are two writers agreeing on where
		 * a note is, which is not a contest. */
		if (memcmp(claims[i]->parent, claims[end - 1u]->parent, FZN_TREE_ID_LEN) == 0)
			continue;
		if (out && found < cap)
			memcpy(out[found], id, FZN_TREE_ID_LEN);
		found++;
	}
	return found;
}
