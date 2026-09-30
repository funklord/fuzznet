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
 * CARRIED AS VOTES ARE (sec 408): `get root [FROM]` pages every root record a
 * node holds, `e` and a log entry, `a` and a root-add, `x` and a root-remove,
 * `q` and a setting of k (sec 418),
 * each whole, and a puller learns each. Every item stands alone, so no state
 * crosses a page. A record that will not admit is counted and skipped, for the
 * reason a vote is: a peer may hold what this node never will.
 *
 * A NODE'S OWN ROOT KEY (sec 409), separate from its identity as sec 403
 * decided: at most one, its seed in the core slot 14, seated as the identity's
 * is. The node ACTS as a root with that key while the set says it stands, and
 * otherwise with its identity key while THAT stands -- which is how a node
 * that is its estate's genesis root, every root node before sec 409, goes on
 * working unchanged. Every act signed as a root is appended to the root's log
 * at the next seq after its head, and a root whose log has forked -- a key
 * used in two places -- is refused rather than extended.
 *
 * A PAIRING CARD'S PROOF (sec 410): a card whose chain starts at a root
 * other than the genesis carries the root-adds that made it one, and the
 * device saves them with `fzn_node_roots_save`, so a node joining that way
 * knows the root its chain starts at when it next loads.
 *
 * PAIRING THROUGH THE ROOT KEY (sec 411): `fzn_node_roots_self_grant`
 * mints the key's grant to the node's identity and the proof that the key is
 * a root, as an authority `fzn_node_pair` extends. The card it makes is too
 * long for one reply line, so it is `fuzznetd --pair` that uses it.
 */

#ifndef FZN_NODE_ROOTS_H
#define FZN_NODE_ROOTS_H

#include <stddef.h>
#include <stdint.h>

#include "caller.h"
#include "pair.h"
#include "revoke.h"
#include "../chain/revocation.h"
#include "../chain/root_log.h"
#include "../persist/persist.h"
#include "../session/random.h"

/* The most log entries a node keeps. A log never evicts, and an estate's
 * roots act rarely: a pairing, a revocation, a change to the set. */
#define FZN_NODE_ROOT_LOG_MAX 256u

/* The most settings of k a node keeps: each is a root's deliberate act. */
#define FZN_NODE_ROOT_SETTINGS_MAX 64u

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
	FZN_NODE_ROOTS_STORE = -4,
	/* This node holds no key that stands as a root. */
	FZN_NODE_ROOTS_NOT_ROOT = -5,
	/* The acting root's log has two entries at one seq: its key is in use
	 * somewhere else, and extending either branch would be choosing one. */
	FZN_NODE_ROOTS_FORKED = -6,
	/* A root key is already held; a second would be a second authority on
	 * one host. */
	FZN_NODE_ROOTS_HELD = -7,
	/* No chain of at most FZN_PROVISION_PROOF_MAX root-adds this node holds
	 * reaches from the estate's root to its root key. */
	FZN_NODE_ROOTS_NO_PROOF = -8
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
	/* The roots' settings of the estate's k, sec 418, each checked. */
	uint8_t settings[FZN_NODE_ROOT_SETTINGS_MAX][FZN_QUORUM_SET_LEN];
	size_t settings_used;
	/* The root key this node holds, if any: `sign` is the signer a seat
	 * armed with its seed. */
	int key_held;
	uint8_t key[FZN_PUBKEY_LEN];
	const fzn_sign_ops_t *key_sign;
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

/* Save one root record as `fzn_node_roots_learn` would, without admitting
 * it here: for a caller that has verified it some other way -- the proof on a
 * pairing card, sec 410 -- and holds no set to admit it to. The next load
 * admits it, and fails if it will not. */
fzn_node_roots_err_t fzn_node_roots_save(const fzn_persist_ops_t *store,
                                         const fzn_hash_ops_t *hash, const uint8_t *bytes,
                                         size_t len);

/* Point `revocations`, and every chain verified over it, at this set. The
 * roots must outlive the store's use of them. */
fzn_node_roots_err_t fzn_node_roots_attach(fzn_node_roots_t *roots,
                                           fzn_revocation_store_t *revocations);

/* This node's root key from slot 14, seated into `seat`, whose signer is
 * `sign`. OK with none stored, `key_held` then 0. */
fzn_node_roots_err_t fzn_node_roots_key_load(fzn_node_roots_t *roots,
                                             const fzn_persist_ops_t *store,
                                             const fzn_sign_seat_t *seat,
                                             const fzn_sign_ops_t *sign);

/* Generate a root key, save it, and seat it. HELD when one is stored
 * already. Its public key is `roots->key`; it becomes a root only when a
 * standing root adds it. */
fzn_node_roots_err_t fzn_node_roots_key_create(fzn_node_roots_t *roots,
                                               const fzn_persist_ops_t *store,
                                               const fzn_random_ops_t *rng,
                                               const fzn_sign_seat_t *seat,
                                               const fzn_sign_ops_t *sign);

/* The key this node acts as a root with, and its signer: its own root key if
 * it stands, else `identity` if that stands. 1 when there is one. */
int fzn_node_roots_acting(const fzn_node_roots_t *roots, const uint8_t identity[FZN_PUBKEY_LEN],
                          const fzn_sign_ops_t *identity_sign, const uint8_t **pubkey,
                          const fzn_sign_ops_t **sign);

/* Log `record` as an act of root `pubkey`, signed by `sign`, at the next seq
 * after the root's head in this log, and learn the entry. FORKED when the
 * root's log has forked. */
fzn_node_roots_err_t fzn_node_roots_log_act(fzn_node_roots_t *roots,
                                            const fzn_persist_ops_t *store,
                                            const uint8_t pubkey[FZN_PUBKEY_LEN],
                                            const fzn_sign_ops_t *sign, uint8_t kind,
                                            const uint8_t *record, size_t len);

/* Add `subject` as a root, or with `remove` remove it at `cut` (NULL for
 * none of its acts standing), as this node's acting root: mint the change,
 * learn it, and log it. NOT_ROOT when this node stands as no root. */
fzn_node_roots_err_t fzn_node_roots_change(fzn_node_roots_t *roots,
                                           const fzn_persist_ops_t *store,
                                           const uint8_t identity[FZN_PUBKEY_LEN],
                                           const fzn_sign_ops_t *identity_sign, int remove,
                                           const uint8_t subject[FZN_PUBKEY_LEN],
                                           const uint8_t cut[FZN_ROOT_ACT_ID_LEN]);

/* PAIRING THROUGH THIS NODE'S ROOT KEY, sec 411. `hop` receives the root
 * key's grant of `cap` to `identity`, delegable and never expiring, and
 * `authority` is filled to pair with it: the hop, and the root-adds from the
 * estate's root to the key, read from `store`, into `proof`. NOT_ROOT when
 * the key is not held or does not stand, NO_PROOF when no path of adds this
 * node holds reaches it.
 *
 * THE SAME HOP EVERY TIME. It is minted at issued_at 0, and Ed25519 is
 * deterministic, so one capability is one act and is logged once, however
 * many devices are paired under it -- the log never evicts. A revocation of
 * the identity under the key covers it for good, which is what revoking a
 * node's own identity means; a withdrawal restores it. */
fzn_node_roots_err_t fzn_node_roots_self_grant(fzn_node_roots_t *roots,
                                               const fzn_persist_ops_t *store,
                                               const uint8_t identity[FZN_PUBKEY_LEN],
                                               const fzn_cap_id_t *cap,
                                               uint8_t hop[FZN_HOP_LEN],
                                               uint8_t proof[FZN_PROVISION_PROOF_MAX]
                                                           [FZN_PROVISION_PROOF_ITEM_LEN],
                                               fzn_node_authority_t *authority);

/* THE ESTATE'S k, sec 418: resolved from the settings held under the set, or
 * `fallback` when none counts. */
uint8_t fzn_node_roots_quorum(const fzn_node_roots_t *roots, uint8_t fallback);

/* Set the estate's k as this node's acting root, replacing the setting that
 * is current now: minted, logged as a setting, learned and saved. NOT_ROOT
 * when this node stands as no root. */
fzn_node_roots_err_t fzn_node_roots_set_quorum(fzn_node_roots_t *roots,
                                               const fzn_persist_ops_t *store,
                                               const uint8_t identity[FZN_PUBKEY_LEN],
                                               const fzn_sign_ops_t *identity_sign, uint8_t k);

/* Every root record the store holds, as items from `from`, written as
 * ` ITEM` into `out` while they fit in `cap`; `*len` written, `*total` items.
 * 0 when the store cannot list or a stored record will not read. */
int fzn_node_roots_page(const fzn_persist_ops_t *store, size_t from, char *out, size_t cap,
                        size_t *len, size_t *total);

/* One page, `reply` answering `get root FROM`: learn every item, and set
 * `*next` and `*total`. `*learned` and `*refused` count on. */
fzn_node_pull_err_t fzn_node_roots_absorb(fzn_node_roots_t *roots,
                                          const fzn_persist_ops_t *store,
                                          const uint8_t *reply, size_t reply_len, size_t from,
                                          size_t *next, size_t *total, size_t *learned,
                                          size_t *refused);

/* The whole stream from the peer `caller` reaches. */
fzn_node_pull_err_t fzn_node_roots_pull(fzn_node_roots_t *roots, const fzn_persist_ops_t *store,
                                        fzn_caller_t *caller, uint64_t now, size_t *learned,
                                        size_t *refused);

#endif /* FZN_NODE_ROOTS_H */
