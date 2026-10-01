/* Notes shared with contacts: which subtree, with whom, and the capability a
 * contact holds to fetch them. sec 436, phase 4 of the notes move.
 *
 * THE HOLDER'S SHAPE (sec 435): a share is a capability granted to a
 * contact's node key, and the contact's node pulls the subtree through the
 * remote hop by `notes/sync.h`. Revoking the grant, or removing the share
 * here, is unsharing.
 *
 * ONE CAPABILITY FOR EVERY SHARE, a service capability named
 * "fuzznet.notes.share", granted by this node's own key -- a share is this
 * node's grant of its own notes, not the estate's. What a request reaches is
 * decided here, by the table: the subtrees shared with the key asking.
 *
 * NOT ONE PER SUBTREE, which was the first design and is refused by the
 * transport: a node holds ONE chain per peer (`node/remote.h`), so a second
 * subtree shared with the same contact would have replaced the first one's
 * grant, and the contact would have lost the first share without anybody
 * unsharing it. With one capability the chain says "may fetch shared notes"
 * and the table says which; unsharing one subtree is removing its row.
 *
 * THE TABLE IS WHAT A REQUEST IS CHECKED AGAINST, so it is core
 * (`persist/persist.h`): a share rolled back would be a contact reading a
 * subtree after it was unshared.
 *
 * WHAT A SHARE REACHES is the subtree's root note and everything the root
 * of that subtree reaches below it in this node's view, whoever wrote it.
 * fuzzypickles' rule that containment is not a security boundary on the
 * RECEIVING side (their notes_share_internal.h) is about admitting records;
 * on the serving side a share is exactly the subtree, since serving outside
 * it would hand out notes nobody shared.
 */

#ifndef FZN_NOTES_SHARE_H
#define FZN_NOTES_SHARE_H

#include <stddef.h>
#include <stdint.h>

#include "view.h"
#include "../chain/chain.h"
#include "../chain/service.h"

#define FZN_NOTES_SHARE_NAME "fuzznet.notes.share"
#define FZN_NOTES_SHARES_MAX 64u

typedef struct fzn_notes_share {
	uint8_t subtree[FZN_TREE_ID_LEN];
	uint8_t contact[FZN_PUBKEY_LEN];
	uint64_t shared_at_ms;
} fzn_notes_share_t;

/* The capability a contact holds to fetch what is shared with it, for a
 * node of `service` and `product`. */
fzn_notes_err_t fzn_notes_share_capability(uint32_t service, uint32_t product,
                                           const fzn_hash_ops_t *hash, fzn_cap_id_t *out);

/* Record that `subtree` is shared with `contact`; a share already held is
 * kept, with its time. FULL past FZN_NOTES_SHARES_MAX. */
fzn_notes_err_t fzn_notes_share_add(const fzn_notes_store_t *store,
                                    const uint8_t subtree[FZN_TREE_ID_LEN],
                                    const uint8_t contact[FZN_PUBKEY_LEN], uint64_t now_ms);

/* Unshare. ABSENT when it was not shared. What the contact already fetched
 * stays with it. */
fzn_notes_err_t fzn_notes_share_remove(const fzn_notes_store_t *store,
                                       const uint8_t subtree[FZN_TREE_ID_LEN],
                                       const uint8_t contact[FZN_PUBKEY_LEN]);

/* Every share, `cap` of them. */
fzn_notes_err_t fzn_notes_share_list(const fzn_notes_store_t *store, fzn_notes_share_t *out,
                                     size_t cap, size_t *count);

/* The subtrees shared with `contact`, `cap` of them, into `out`. A count of
 * 0 is a contact this node shares nothing with, whose requests reach
 * nothing. */
fzn_notes_err_t fzn_notes_share_with(const fzn_notes_store_t *store,
                                     const uint8_t contact[FZN_PUBKEY_LEN],
                                     uint8_t (*out)[FZN_TREE_ID_LEN], size_t cap, size_t *count);

/* The ids shares of the `seed_count` subtrees in `seeds` reach in `view`:
 * each subtree's root and everything reachable from one by parent claims,
 * into `out`, `cap` of them. A node claimed under two parents is reached if
 * either is. */
size_t fzn_notes_share_reach(const fzn_notes_view_t *view,
                             const uint8_t (*seeds)[FZN_TREE_ID_LEN], size_t seed_count,
                             uint8_t (*out)[FZN_TREE_ID_LEN], size_t cap);

#endif /* FZN_NOTES_SHARE_H */
