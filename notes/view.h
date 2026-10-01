/* A host's notes as a tree, read out of `notes/store.h`. sec 425.
 *
 * Ported from fuzzypickles' `notes_view` at b419405. Everything here is
 * `tree/tree.h` applied to what the store holds: a view loads every claim,
 * opens each as a node, marks what the root can reach, and answers children
 * and top level from that. It writes nothing, so two hosts holding the same
 * records compute the same view, and a repair cannot replicate or race.
 *
 * EVERY CLAIM IS A NODE IN THE VIEW, so a note two writers hold appears
 * twice -- under two parents when they disagree, which `fzn_notes_contested`
 * names, and under one parent twice when they agree on where it is. That is
 * `tree/`'s refusal to pick a winner carried through, and it is fuzzypickles'
 * behaviour unchanged.
 *
 * WHAT THE ROOT CANNOT REACH IS SHOWN AT TOP LEVEL, whether it sits in a
 * cycle or waits for a parent that has not arrived: a user who caused a cycle
 * sees their notes in the wrong place rather than not at all.
 *
 * A CLAIM THAT WILL NOT READ IS COUNTED, NOT DROPPED. Storage damage and a
 * version this build does not know are both things a user should be told, and
 * a loader that skipped them would make a damaged store look like a smaller
 * one. The view is large -- every claim at full record size -- and is the
 * caller's, as everything in this library is.
 */

#ifndef FZN_NOTES_VIEW_H
#define FZN_NOTES_VIEW_H

#include <stddef.h>
#include <stdint.h>

#include "store.h"
#include "../tree/tree.h"

typedef struct fzn_notes_view {
	/* The record bytes, packed. Nodes point in here, so it lives in the
	 * same object and must outlive them. */
	uint8_t arena[FZN_NOTES_MAX * (size_t)FZN_RECORD_MAX_LEN];
	size_t arena_used;
	fzn_tree_node_t nodes[FZN_NOTES_MAX];
	/* Who wrote nodes[i]: a view of the record's own issuer field. */
	const uint8_t *writers[FZN_NOTES_MAX];
	/* Non-zero once the root can reach nodes[i]. */
	uint8_t mark[FZN_NOTES_MAX];
	size_t count;
	/* Claims held that did not read as a note node. */
	size_t unreadable;
} fzn_notes_view_t;

/* Load every claim the store holds. The store's own put admitted each one;
 * a record this build cannot open as a node is counted in `unreadable`. */
fzn_notes_err_t fzn_notes_view_load(const fzn_notes_store_t *store, fzn_notes_view_t *view);

/* The claims under `parent`, in sibling order, into a caller-owned array.
 * `*truncated` (may be NULL) is set when `out` ran out: then the array is NOT
 * the first `cap` children, since a later node may sort before one written. */
fzn_notes_err_t fzn_notes_children(const fzn_notes_view_t *view,
                                   const uint8_t parent[FZN_TREE_ID_LEN],
                                   const fzn_tree_node_t **out, size_t cap, size_t *count,
                                   int *truncated);

/* The root's children, then every claim the root cannot reach. */
fzn_notes_err_t fzn_notes_top_level(const fzn_notes_view_t *view, const fzn_tree_node_t **out,
                                    size_t cap, size_t *count, int *truncated);

/* Whether the root can reach nodes[i]. Out of range is 0. */
int fzn_notes_reachable(const fzn_notes_view_t *view, size_t i);

/* The note ids claimed under more than one parent, each once, `cap` of them
 * written; returns how many there are. */
size_t fzn_notes_contested(const fzn_notes_view_t *view, uint8_t (*out)[FZN_TREE_ID_LEN],
                           size_t cap);

#endif /* FZN_NOTES_VIEW_H */
