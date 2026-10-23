/* A node's view of its estate's roots: the root set it holds, persisted, and
 * attached to its revocation store. project.md sec 407.
 *
 * sec 403 gave an estate several roots, each acting alone and each
 * removable; secs 404 to 406 built the set and verification against it in
 * `chain/`. This is where a node keeps it. Every root-add, root-remove and
 * root setting it learns is saved in the core directory -- losing one would
 * let a removed root count again -- and admitted again at start, before any
 * revocation, so that a revocation by a member root re-admits.
 *
 * THE ACT LOG IS THE JOURNAL, sec 508. Every act this node signs is logged
 * into its journal (`logged`), and a removal's or a vote's cut is a record
 * id in the signer's stream, judged by the journal the roots are given with
 * `fzn_node_roots_set_journal`. Roots with no journal log nothing and judge
 * no cut: nothing a removed root or a revoked key did can be shown to stand,
 * which errs toward removal. The root-log entries of secs 404 to 497 are
 * gone.
 *
 * ATTACHED, the node's revocation store and every `fzn_chain_verify` over it
 * read the set: a chain may start at any root it names, and a removed root's
 * acts after its cut stop counting. With only the genesis root in the set --
 * the estate's pinned root, which is every node before sec 407 -- the answers
 * are the single-root answers exactly.
 *
 * CARRIED IN THE JOURNAL (sec 505): a root change, a setting of k and a
 * root's retention setting are each their signer's act, logged and so in its
 * journal (`node/journal.h`), and a reader applies each through
 * `fzn_node_roots_learn` (`node/apply.h`). The `get root` stream that carried
 * them from sec 408 is gone.
 *
 * A NODE'S OWN ROOT KEY (sec 409), separate from its identity as sec 403
 * decided: at most one, its seed in the core slot 14, seated as the identity's
 * is. The node ACTS as a root with that key while the set says it stands, and
 * otherwise with its identity key while THAT stands -- which is how a node
 * that is its estate's genesis root, every root node before sec 409, goes on
 * working unchanged. Every act signed as a root is appended to its key's
 * stream, and a key whose stream has forked -- a key used in two places -- is
 * refused rather than extended.
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
#include "../log/retain.h"
#include "../persist/persist.h"
#include "../session/random.h"

/* THE SETTINGS OF k A NODE KEEPS IN ITS OWN TABLE, and the retention
 * records (sec 476: adds, changes and removals together). Not limits on an
 * estate, sec 703: none of these is ever let go, so 64 was once every
 * change an estate could make in its life. A node needing more is given
 * tables of the caller's (`fzn_node_roots_use`), and told it needs them by
 * FZN_NODE_ROOTS_FULL. */
#define FZN_NODE_ROOT_SETTINGS_MAX 64u
#define FZN_NODE_ROOT_RETENTION_MAX 64u

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
	FZN_NODE_ROOTS_NO_PROOF = -8,
	/* A table is full and the record was not taken: `fzn_node_roots_wants`
	 * says which and how large it must be. sec 703. */
	FZN_NODE_ROOTS_FULL = -9
} fzn_node_roots_err_t;

const char *fzn_node_roots_err_str(fzn_node_roots_err_t err);

typedef struct fzn_node_roots {
	fzn_root_set_t set;
	/* THE SET'S CHANGES ON THE NODE'S OWN TABLE until it is given one
	 * (`fzn_node_roots_use`), and the view's flags beside them. */
	fzn_root_change_t changes[FZN_ROOT_SET_MAX];
	uint8_t *view_flags;
	size_t view_capacity;
	fzn_root_view_t view;
	fzn_root_ops_t ops;
	/* The log asked about any key's acts, sec 497 -- the journal's since
	 * sec 508, and unset without one: what a cut is judged against, set on
	 * every store this is attached to. */
	fzn_act_log_ops_t acts;
	const fzn_sign_ops_t *sign;
	const fzn_hash_ops_t *hash;
	/* The roots' settings of the estate's k, sec 418, each checked: in
	 * `settings_own` or the caller's table. */
	uint8_t (*settings)[FZN_QUORUM_SET_LEN];
	size_t settings_used, settings_capacity;
	uint8_t settings_own[FZN_NODE_ROOT_SETTINGS_MAX][FZN_QUORUM_SET_LEN];
	/* The retention records, sec 476 -- roots' and, since sec 479, admins'
	 * -- each checked, the same way. */
	uint8_t (*retention)[FZN_RETENTION_SET_LEN];
	size_t retention_used, retention_capacity;
	uint8_t retention_own[FZN_NODE_ROOT_RETENTION_MAX][FZN_RETENTION_SET_LEN];
	/* WHAT A RESOLUTION WORKS IN, as large as the larger of the two tables
	 * above, and where a load lists the store's rows. */
	fzn_root_scratch_t scratch;
	uint8_t scratch_ids[FZN_NODE_ROOT_RETENTION_MAX][FZN_ROOT_ACT_ID_LEN];
	uint8_t scratch_flags[2][FZN_NODE_ROOT_RETENTION_MAX];
	uint8_t *subjects;
	size_t subjects_capacity;
	/* A TABLE FOUND FULL, sec 703: how large each must be to take what was
	 * refused. 0 where none was. */
	size_t changes_wanted, settings_wanted, retention_wanted;
	/* THE REVOCATIONS ATTACHED (`fzn_node_roots_attach`), which say which
	 * admins stand, and the ops that judge a retention record by either:
	 * its setter's act under the set, or its setter standing as an admin.
	 * sec 479. */
	fzn_revocation_store_t *revocations;
	fzn_root_ops_t judge;
	/* The root key this node holds, if any: `sign` is the signer a seat
	 * armed with its seed. */
	int key_held;
	uint8_t key[FZN_PUBKEY_LEN];
	const fzn_sign_ops_t *key_sign;
	/* CALLED FOR EVERY ACT LOGGED, sec 501: `pubkey` signed the act whose
	 * hash is `act`, of the act log's `kind`, with `sign`; `record` is the
	 * act's own signed bytes, `len` of them, since sec 502 -- what the
	 * daemon carries in the journal (`node/journal.h`). 0 fails the
	 * logging, as an act unrecorded must not pass for one recorded. NULL
	 * for none. */
	int (*logged)(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const fzn_sign_ops_t *sign,
	              uint8_t kind, const uint8_t act[FZN_ROOT_ACT_ID_LEN], const uint8_t *record,
	              size_t len);
	void *logged_ctx;
	/* THE JOURNAL THAT JUDGES, sec 506, or NULL for none:
	 * `fzn_node_roots_set_journal`. */
	struct fzn_node_journal *journal;
} fzn_node_roots_t;

/* JUDGE BY `journal` from here on, sec 506: every cut -- a vote's, a
 * removal's -- is asked of the journal's streams, here and in the store
 * attached, and `fzn_node_roots_head` answers with the journal's head. The
 * journal is the per-key act log, chained by `prev` and carried to every
 * follower, so a cut is a record id. `journal` must outlive `roots`.
 * MALFORMED for a NULL. */
struct fzn_node_journal;
fzn_node_roots_err_t fzn_node_roots_set_journal(fzn_node_roots_t *roots,
                                                struct fzn_node_journal *journal);

/* An estate grown from `genesis`, holding nothing yet. `sign` and `hash`
 * verify and name what it learns, and must outlive it. */
fzn_node_roots_err_t fzn_node_roots_init(fzn_node_roots_t *roots,
                                         const uint8_t genesis[FZN_PUBKEY_LEN],
                                         const fzn_sign_ops_t *sign,
                                         const fzn_hash_ops_t *hash);

/* TABLES OF THE CALLER'S, sec 703, the holder's of 2026-10-23: no change an
 * estate makes is ever let go, so a node that keeps them all is given room
 * for them rather than refusing the next one for good. Each array of
 * `capacity` entries; `view_flags` FZN_ROOT_VIEW_FLAGS(`changes_capacity`)
 * bytes; `scratch` at least as large as the larger of `settings_capacity`
 * and `retention_capacity`; `subjects` room for `subjects_capacity` keys of
 * FZN_PUBKEY_LEN, every row a load lists. All must outlive `roots`. */
typedef struct fzn_node_roots_tables {
	fzn_root_change_t *changes;
	uint8_t *view_flags;
	size_t changes_capacity;
	uint8_t (*settings)[FZN_QUORUM_SET_LEN];
	size_t settings_capacity;
	uint8_t (*retention)[FZN_RETENTION_SET_LEN];
	size_t retention_capacity;
	fzn_root_scratch_t scratch;
	uint8_t *subjects;
	size_t subjects_capacity;
} fzn_node_roots_tables_t;

/* `roots` moved onto `tables`, what it holds copied over and the view
 * settled again: MALFORMED for a table smaller than what is held, or a
 * scratch smaller than either table. What the caller held before is no
 * longer read, and may be let go. */
fzn_node_roots_err_t fzn_node_roots_use(fzn_node_roots_t *roots,
                                        const fzn_node_roots_tables_t *tables);

/* WHETHER A TABLE WAS FOUND FULL since `roots` was last given tables, and
 * the size each must be: 1 with the three in `*changes`, `*settings` and
 * `*retention` -- each the larger of its table's present size and what the
 * refused record needed. 0 when none was. */
int fzn_node_roots_wants(const fzn_node_roots_t *roots, size_t *changes, size_t *settings,
                         size_t *retention);

/* At start: admit every root record (slot 13) in `store`. A record that will
 * not read or admit FAILS the load, as a revocation does (sec 380). `count`
 * is how many were admitted. */
fzn_node_roots_err_t fzn_node_roots_load(fzn_node_roots_t *roots,
                                         const fzn_persist_ops_t *store, size_t *count);

/* Learn one record -- a root-add, a root-remove, a setting of k or a root's
 * retention setting, told apart by its object byte -- admit it, and save it.
 * The view is settled again, so an attached store answers under it at
 * once. */
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

/* WHETHER `key` WAS EVER A ROOT HERE: the genesis, or the subject of a
 * root-add this node holds, whether that add still counts or not. What a
 * root record's signer must be when it arrives, sec 700: standing judged on
 * arrival, a cut still judged when read, so a removed root's acts from
 * before its cut are admitted however late they come. */
int fzn_node_roots_known(const fzn_node_roots_t *roots, const uint8_t key[FZN_PUBKEY_LEN]);

/* The key this node acts as a root with, and its signer: its own root key if
 * it stands, else `identity` if that stands. 1 when there is one. */
int fzn_node_roots_acting(const fzn_node_roots_t *roots, const uint8_t identity[FZN_PUBKEY_LEN],
                          const fzn_sign_ops_t *identity_sign, const uint8_t **pubkey,
                          const fzn_sign_ops_t **sign);

/* LOG AN ACT THIS NODE SIGNED, by whichever of its keys `signer` is: its
 * identity (signed by `identity_sign`) or the root key it holds. Every act,
 * as a root or not, sec 497: a revocation's cut is drawn in the signer's own
 * stream, so an act never logged falls at the signer's revocation whatever
 * the line. Logging is `logged`, the journal's append, since sec 508. OK,
 * logging nothing, when `signer` is neither of this node's keys -- a record
 * relayed rather than signed here. FORKED when the signer's stream has. */
fzn_node_roots_err_t fzn_node_roots_log_signed(fzn_node_roots_t *roots,
                                               const fzn_persist_ops_t *store,
                                               const uint8_t identity[FZN_PUBKEY_LEN],
                                               const fzn_sign_ops_t *identity_sign,
                                               const uint8_t signer[FZN_PUBKEY_LEN],
                                               uint8_t kind, const uint8_t *record,
                                               size_t len);

/* THE HEAD OF `key`'s STREAM in the journal, the id of its last record: what
 * a vote against `key` trusts by default -- everything this node had seen it
 * do. 0, writing nothing, with no journal, or when it holds nothing of
 * `key`'s or the stream has forked, since a fork's head is the thief's
 * choice as readily as the owner's. secs 497 and 506. */
int fzn_node_roots_head(const fzn_node_roots_t *roots, const uint8_t key[FZN_PUBKEY_LEN],
                        uint8_t id[FZN_ROOT_ACT_ID_LEN]);

/* Every root of the estate that stands -- the genesis and each one added,
 * less those removed -- into `out`, at most `cap`. The count. A root
 * removed and added again is named once per add; a caller wanting a set
 * takes each once, as `fzn_node_notes_admit_members` does. sec 450. */
size_t fzn_node_roots_standing(const fzn_node_roots_t *roots, uint8_t (*out)[FZN_PUBKEY_LEN],
                               size_t cap);

/* Log `record` as an act of `pubkey`, signed by `sign`: `logged` is told,
 * which appends it to the key's stream. FORKED when the key's stream has
 * forked. Any key, not only a root's, since sec 497. `store` is unused since
 * sec 508, which retired the root log's own entries. */
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

/* THE ESTATE'S RETENTION RULES, sec 476: the current records' rules,
 * resolved under the set, into `out`, `cap` of them. A record whose text is
 * no rule -- a newer syntax, say -- and a rule past `cap` are passed over
 * and counted in `*unread`, so a caller can say so rather than drop them
 * unseen. */
fzn_node_roots_err_t fzn_node_roots_retention(const fzn_node_roots_t *roots,
                                              fzn_retain_rule_t *out, size_t cap, size_t *count,
                                              size_t *unread);

/* Add one estate rule, or remove one, as this node's acting root: minted in
 * the rule's canonical text, logged as a setting, learned and saved. HELD
 * when the rule to add is current already; REFUSED when the rule to remove
 * is not current, or the records are full. NOT_ROOT when this node stands
 * as no root. */
fzn_node_roots_err_t fzn_node_roots_set_retention(fzn_node_roots_t *roots,
                                                  const fzn_persist_ops_t *store,
                                                  const uint8_t identity[FZN_PUBKEY_LEN],
                                                  const fzn_sign_ops_t *identity_sign,
                                                  const fzn_retain_rule_t *rule, int add);

/* AN ADMIN'S RETENTION RECORDS, sec 479: the holder's "an estate wide admin
 * (and root) capability". An admin's record carries its admin chain, which
 * a node admits into its revocations (`fzn_revocation_admin_admit`) so the
 * record counts while the admin stands -- confirmed, rooted, unrevoked --
 * and stops when it does not. They are kept in slot 27 with the chain, and
 * since sec 505 one is logged as its setter's act and travels in the
 * setter's journal; a reader rebuilds the chain from the grants it holds.
 * All of these need the revocations attached.
 *
 * Learn one, checked: its shape and signature, its chain granting the admin
 * capability to its setter from `root` or a member root. Saved, then
 * counted. REFUSED for any failing check. */
fzn_node_roots_err_t fzn_node_roots_learn_admin_retention(
        fzn_node_roots_t *roots, const fzn_persist_ops_t *store, const uint8_t *record,
        size_t len, const uint8_t (*hops)[FZN_HOP_LEN], size_t hop_count,
        const uint8_t root[FZN_PUBKEY_LEN]);

/* At start, after the revocations are loaded and attached: every one held.
 * A record that will not read or admit FAILS the load, as a root record's
 * does. */
fzn_node_roots_err_t fzn_node_roots_load_admin_retention(fzn_node_roots_t *roots,
                                                         const fzn_persist_ops_t *store,
                                                         const uint8_t root[FZN_PUBKEY_LEN],
                                                         size_t *count);

/* One held, by its subject, for a stream: the record and its chain. */
int fzn_node_roots_admin_retention_get(const fzn_persist_ops_t *store,
                                       const uint8_t subject[FZN_PUBKEY_LEN],
                                       uint8_t record[FZN_RETENTION_SET_LEN],
                                       uint8_t (*hops)[FZN_HOP_LEN], size_t *hop_count);

/* Add or remove one estate rule as an admin, on `hops`, the admin chain to
 * `identity` this node holds: as `fzn_node_roots_set_retention` does for a
 * root. NOT_ROOT when `identity` does not stand as an admin. */
fzn_node_roots_err_t fzn_node_roots_set_retention_as_admin(
        fzn_node_roots_t *roots, const fzn_persist_ops_t *store,
        const uint8_t identity[FZN_PUBKEY_LEN], const fzn_sign_ops_t *identity_sign,
        const uint8_t (*hops)[FZN_HOP_LEN], size_t hop_count, const uint8_t root[FZN_PUBKEY_LEN],
        const fzn_retain_rule_t *rule, int add);

/* PAIRING AS A ROOT BY IDENTITY, sec 419: when this node's identity stands as
 * a root other than the genesis, fill `authority` with no hops and the adds
 * from the genesis to the identity, read from `store` into `proof`, so
 * `fzn_node_pair` mints the device's hop as the chain's first and the card
 * carries the proof. NOT_ROOT when the identity is the genesis or does not
 * stand; NO_PROOF when no path of adds reaches it. */
fzn_node_roots_err_t fzn_node_roots_identity_root(fzn_node_roots_t *roots,
                                                  const fzn_persist_ops_t *store,
                                                  const uint8_t identity[FZN_PUBKEY_LEN],
                                                  uint8_t proof[FZN_PROVISION_PROOF_MAX]
                                                              [FZN_PROVISION_PROOF_ITEM_LEN],
                                                  fzn_node_authority_t *authority);

#endif /* FZN_NODE_ROOTS_H */
