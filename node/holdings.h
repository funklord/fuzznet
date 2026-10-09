/*
 * WHAT A NODE HOLDS OF THE ESTATE'S STATE, by class, as signed objects: the
 * half of reconciliation (project.md sec 550) that reads a store.
 *
 * The journal is a window (secs 544-549). A node away longer than it, or a
 * node that missed a record a peer has since cut, cannot replay its way to
 * the estate's state; it reconciles instead, every round and with every
 * peer, comparing what each holds and fetching what it lacks. That is the
 * holder's "never merely a one-shot process" of 2026-10-09: an object one
 * peer leaves out is filled by any other that has it, so omission is
 * repaired rather than ruled out before finishing.
 *
 * A CLASS is the rows of one persist slot that hold one family of signed
 * objects, each verifiable alone and applied, wherever it comes from, by
 * `fzn_node_apply_object` -- the same judgment a journal record gets. An
 * object's ID is the hash of its signed bytes, and the DIGEST of a class is
 * the hash of its count and its ids in order, so two nodes holding the same
 * set agree on it whatever order they learned it in.
 *
 * Per node and secret slots are not classes, nor are conversations: lines
 * carry no signatures and their transfer was deferred by the holder. Note
 * claims are a class whose objects are whole stream-0 records, filed by the
 * notes store's own path rather than `fzn_node_apply_object` (sec 555).
 */
#ifndef FZN_NODE_HOLDINGS_H
#define FZN_NODE_HOLDINGS_H

#include <stddef.h>
#include <stdint.h>

#include "../persist/persist.h"
#include "../session/commitment.h"

#define FZN_HOLDINGS_ID_LEN 32u

/* The most objects of one class a node lists or digests: past it the class
 * is FULL rather than silently a subset. */
#define FZN_HOLDINGS_MAX 4096u

typedef enum fzn_holdings_class {
	FZN_HOLDINGS_GRANTS = 0,      /* slot 39, grant hops */
	FZN_HOLDINGS_ROOTS = 1,       /* slot 13, root adds, removes, k and root retention */
	FZN_HOLDINGS_VOTES = 2,       /* slot 11, revocations and withdrawals */
	FZN_HOLDINGS_CONFIRMS = 3,    /* slot 15, admin confirmations */
	FZN_HOLDINGS_RETENTION = 4,   /* slot 27, admins' retention */
	FZN_HOLDINGS_ROSTER = 5,      /* slot 28, roster records */
	FZN_HOLDINGS_SUCCESSIONS = 6, /* slot 30, successions */
	FZN_HOLDINGS_SETTINGS = 7,    /* slot 38, settings standing */
	/* slot 17, the newest note record of each (note, writer): last, since
	 * a writer is admitted by the estate state before it. sec 555. */
	FZN_HOLDINGS_NOTES = 8,
	FZN_HOLDINGS_CLASSES = 9
} fzn_holdings_class_t;

typedef enum fzn_holdings_err {
	FZN_HOLDINGS_OK = 0,
	FZN_HOLDINGS_MALFORMED = -1,
	/* The store could not list or load. */
	FZN_HOLDINGS_BACKEND = -2,
	/* More than FZN_HOLDINGS_MAX of the class. */
	FZN_HOLDINGS_FULL = -3
} fzn_holdings_err_t;

const char *fzn_holdings_err_str(fzn_holdings_err_t err);

/* One held object: its id, and its signed bytes, valid for the call. Nonzero
 * to go on. */
typedef int (*fzn_holdings_fn)(void *ctx, const uint8_t id[FZN_HOLDINGS_ID_LEN],
                               const uint8_t *object, size_t len);

/* EVERY OBJECT OF `class` the store holds, to `each`, in the store's order.
 * A row of the class that does not hold an object of it -- the wrong tag,
 * the wrong length -- is passed over, as a row its own module would not
 * read. `*count` (may be NULL) is how many were handed. */
fzn_holdings_err_t fzn_holdings_each(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                     fzn_holdings_class_t cls, fzn_holdings_fn each, void *ctx,
                                     size_t *count);

/* THE CLASS'S DIGEST: the hash of a domain, the class, the count and the
 * ids in ascending order -- equal on two nodes exactly when they hold the
 * same objects. `*count` (may be NULL) is how many. */
fzn_holdings_err_t fzn_holdings_digest(const fzn_persist_ops_t *store,
                                       const fzn_hash_ops_t *hash, fzn_holdings_class_t cls,
                                       uint8_t digest[FZN_HOLDINGS_ID_LEN], size_t *count);

/* THE CLASS'S IDS, ascending, into `ids` (room for `max`): what a
 * reconciler searches to know what it lacks. FULL past `max`. */
fzn_holdings_err_t fzn_holdings_ids(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                    fzn_holdings_class_t cls,
                                    uint8_t (*ids)[FZN_HOLDINGS_ID_LEN], size_t max,
                                    size_t *count);

/* Whether `id` is among `count` ascending `ids`. */
int fzn_holdings_among(const uint8_t (*ids)[FZN_HOLDINGS_ID_LEN], size_t count,
                       const uint8_t id[FZN_HOLDINGS_ID_LEN]);

#endif /* FZN_NODE_HOLDINGS_H */
