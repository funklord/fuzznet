/* Notes a contact shared with this node: one tree per sharer. sec 437,
 * phase 4 of the notes move.
 *
 * A SEPARATE TREE PER SHARER, fuzzypickles' sec 22 decision, and forced by
 * the mechanism rather than chosen: `notes/view.h`'s top level is the root's
 * children FOLLOWED BY every note the root cannot reach, and a shared
 * subtree's top note names a parent the recipient does not hold. In one store
 * every note anybody shared would surface in the recipient's own top level,
 * mixed with theirs.
 *
 * SO THIS IS A `persist/` SEAM, NOT A SECOND STORE. `fzn_notes_received_ops`
 * hands back a `fzn_persist_ops_t` that files the NOTE slot's rows in slot
 * SHARED_NOTE under the sharer's key, and `notes/store.h`, `notes/view.h` and
 * `notes/sync.h` run over it unchanged. Two sharers' trees cannot collide and
 * neither can be walked into from the other, or from the user's own notes,
 * without any check somebody has to remember: the namespace is the address.
 *
 * READ-ONLY BY CONSTRUCTION, as far as the seam can make it. The recipient
 * never authors in a sharer's tree, so the other notes slots -- a sequence,
 * purges, partners -- are absent here and refuse a write: a store over this
 * seam asked to sign a note finds no counter it may save.
 *
 * A ROW IS FILED UNDER hash(label | sharer | claim key) and carries both, and
 * a row whose sharer or claim is not the one asked for is refused: a hash is
 * a promise about inputs, not about a backend (`notes/store.h`'s rule).
 */

#ifndef FZN_NOTES_RECEIVED_H
#define FZN_NOTES_RECEIVED_H

#include <stddef.h>
#include <stdint.h>

#include "store.h"
#include "view.h"

/* Rows in slot SHARED_NOTE across every sharer: FZN_NOTES_MAX per sharer
 * for eight sharers. A bound, and the failure past it is a refused save or
 * a list that fails, never a short one. */
#define FZN_NOTES_RECEIVED_ROWS (8u * FZN_NOTES_MAX)

/* The seam for one sharer's tree. Owned by the caller and outliving the ops
 * built over it. */
typedef struct fzn_notes_received {
	const fzn_persist_ops_t *base;
	const fzn_hash_ops_t *hash;
	uint8_t sharer[FZN_PUBKEY_LEN];
} fzn_notes_received_t;

/* Fill `seam` and `ops` so a store over `ops` holds `sharer`'s tree in
 * `base`. MALFORMED for a null, or a base that cannot load, save and list. */
fzn_notes_err_t fzn_notes_received_ops(fzn_notes_received_t *seam, const fzn_persist_ops_t *base,
                                       const fzn_hash_ops_t *hash,
                                       const uint8_t sharer[FZN_PUBKEY_LEN],
                                       fzn_persist_ops_t *ops);

/* Forget every note `sharer` shared with this node. `*removed` (may be NULL)
 * counts the rows. UNSUPPORTED when the base cannot remove. */
fzn_notes_err_t fzn_notes_received_forget(const fzn_persist_ops_t *base,
                                          const uint8_t sharer[FZN_PUBKEY_LEN], size_t *removed);

/* THE ROOTS OF A SHARER'S TREE as this node holds it: the notes whose parent
 * it does not hold, `cap` of them, in the view's order. `notes/view.h`'s top
 * level is the wrong question here -- every note of a shared subtree is
 * unreachable from a root nobody shared, so it would list them all, flat --
 * and the shared subtrees' own roots are what a person browses from. A note
 * claimed under two parents is a root only when neither is held. */
size_t fzn_notes_received_roots(const fzn_notes_view_t *view, const fzn_tree_node_t **out,
                                size_t cap);

#endif /* FZN_NOTES_RECEIVED_H */
