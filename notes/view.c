/* See view.h. */

#include "view.h"

#include <string.h>

fzn_notes_err_t fzn_notes_view_load(const fzn_notes_store_t *store, fzn_notes_view_t *view)
{
	static uint8_t keys[FZN_NOTES_MAX][FZN_PUBKEY_LEN];
	fzn_tree_walk_t walk;
	size_t count = 0, i;
	fzn_notes_err_t err;

	if (!store || !view)
		return FZN_NOTES_ERR_MALFORMED;
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
	return FZN_NOTES_OK;
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

size_t fzn_notes_contested(const fzn_notes_view_t *view, uint8_t (*out)[FZN_TREE_ID_LEN],
                           size_t cap)
{
	size_t found = 0, i, j;

	if (!view)
		return 0;
	for (i = 0; i < view->count; i++) {
		const uint8_t *id = view->nodes[i].id;
		int earlier = 0, contested = 0;

		/* EACH ID ONCE: counted at its first claim only. */
		for (j = 0; j < i && !earlier; j++)
			earlier = memcmp(view->nodes[j].id, id, FZN_TREE_ID_LEN) == 0;
		if (earlier)
			continue;
		/* Two claims under ONE parent are two writers agreeing on where
		 * a note is, which is not a contest. */
		for (j = i + 1u; j < view->count; j++)
			if (memcmp(view->nodes[j].id, id, FZN_TREE_ID_LEN) == 0
			    && memcmp(view->nodes[j].parent, view->nodes[i].parent, FZN_TREE_ID_LEN)
			               != 0)
				contested = 1;
		if (!contested)
			continue;
		if (out && found < cap)
			memcpy(out[found], id, FZN_TREE_ID_LEN);
		found++;
	}
	return found;
}
