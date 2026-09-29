/* A node's view of its estate's roots: the root log and the root set it
 * holds, persisted, and attached to its revocation store. project.md sec 407.
 *
 * sec 403 gave an estate several roots, each acting alone and each
 * removable; secs 404 to 406 built the log, the set and verification against
 * them in `chain/`. This is where a node keeps them. Every root log entry and
 * every root-add or root-remove it learns is saved in the core directory --
 * losing one would let a removed root count again, or leave a removal's cut
 * impossible to follow -- and admitted again at start, before any revocation,
 * so that a revocation by a member root re-admits.
 *
 * ATTACHED, the node's revocation store and every `fzn_chain_verify` over it
 * read the set: a chain may start at any root it names, and a removed root's
 * acts after its cut stop counting. With only the genesis root in the set --
 * the estate's pinned root, which is every node before sec 407 -- the answers
 * are the single-root answers exactly.
 *
 * WHAT IT DOES NOT DO YET: sign as a root, log this node's own root acts, or
 * carry the log and the set between nodes. Those come next (sec 407).
 */

#ifndef FZN_NODE_ROOTS_H
#define FZN_NODE_ROOTS_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/revocation.h"
#include "../chain/root_log.h"
#include "../persist/persist.h"

/* The most log entries a node keeps. A log never evicts, and an estate's
 * roots act rarely: a pairing, a revocation, a change to the set. */
#define FZN_NODE_ROOT_LOG_MAX 256u

typedef enum fzn_node_roots_err {
	FZN_NODE_ROOTS_OK = 0,
	FZN_NODE_ROOTS_MALFORMED = -1,
	/* The record would not admit: its shape, its signature, or a full log
	 * or set. */
	FZN_NODE_ROOTS_REFUSED = -2,
	/* Admitted and not saved: known until a restart, and forgotten by one. */
	FZN_NODE_ROOTS_NOT_SAVED = -3,
	/* A stored record would not read or admit again: the store changed
	 * underneath this node. */
	FZN_NODE_ROOTS_STORE = -4
} fzn_node_roots_err_t;

const char *fzn_node_roots_err_str(fzn_node_roots_err_t err);

typedef struct fzn_node_roots {
	fzn_root_log_t log;
	fzn_root_log_entry_t entries[FZN_NODE_ROOT_LOG_MAX];
	fzn_root_set_t set;
	fzn_root_change_t changes[FZN_ROOT_SET_MAX];
	fzn_root_view_t view;
	fzn_root_ops_t ops;
	const fzn_sign_ops_t *sign;
	const fzn_hash_ops_t *hash;
} fzn_node_roots_t;

/* An estate grown from `genesis`, holding nothing yet. `sign` and `hash`
 * verify and name what it learns, and must outlive it. */
fzn_node_roots_err_t fzn_node_roots_init(fzn_node_roots_t *roots,
                                         const uint8_t genesis[FZN_PUBKEY_LEN],
                                         const fzn_sign_ops_t *sign,
                                         const fzn_hash_ops_t *hash);

/* At start: admit every root log entry (slot 12) and root change (slot 13)
 * in `store`. A record that will not read or admit FAILS the load, as a
 * revocation does (sec 380). `count` is how many were admitted. */
fzn_node_roots_err_t fzn_node_roots_load(fzn_node_roots_t *roots,
                                         const fzn_persist_ops_t *store, size_t *count);

/* Learn one record -- a root log entry, a root-add or a root-remove, told
 * apart by its object byte -- admit it, and save it. The view is settled
 * again, so an attached store answers under it at once. */
fzn_node_roots_err_t fzn_node_roots_learn(fzn_node_roots_t *roots,
                                          const fzn_persist_ops_t *store,
                                          const uint8_t *bytes, size_t len);

/* Point `revocations`, and every chain verified over it, at this set. The
 * roots must outlive the store's use of them. */
fzn_node_roots_err_t fzn_node_roots_attach(fzn_node_roots_t *roots,
                                           fzn_revocation_store_t *revocations);

#endif /* FZN_NODE_ROOTS_H */
