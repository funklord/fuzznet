/* An estate's roots: the root set, its changes and their cuts, the estate's
 * k, its retention rules, and the kinds of act a key logs. project.md secs
 * 404 to 418.
 *
 * WHY CUTS. sec 403 gives a root the whole estate's authority and lets any
 * root remove another. The holder asked that a removal undo only what the
 * removed root did SINCE IT WAS STOLEN. A thief holding the key can sign any
 * `issued_at` it likes, so time cannot say that. Ancestry can: every act a
 * key signs is logged, each naming the one before it by hash, and a removal
 * names a CUT -- the last act the remover trusts -- so an act stands exactly
 * when it lies on the chain that ends at the cut. Acts after the cut fall,
 * and so do acts on a fork.
 *
 * THE LOG IS ASKED, NOT KEPT, HERE. Since sec 509 a key's acts are the
 * records of its estate stream in the node's journal (`node/journal.h`),
 * and the root set asks them through `fzn_act_log_ops_t`
 * (`chain/revocation.h`). The 171-byte root-log entry of secs 404 to 497 and
 * the log that kept it are gone; the cut is a record id.
 */

#ifndef FZN_ROOT_LOG_H
#define FZN_ROOT_LOG_H

#include <stddef.h>
#include <stdint.h>

#include "chain.h"
#include "../session/commitment.h"

/* An act's id, and a cut: the hash of a record. */
#define FZN_ROOT_ACT_ID_LEN 32u

/* What kind of act a key logs, told to the roots' `logged` hook
 * (`node/roots.h`); the journal records the act under its object's tag. */
typedef enum fzn_root_act_kind {
	FZN_ROOT_ACT_GRANT = 1u,
	FZN_ROOT_ACT_REVOCATION = 2u,
	FZN_ROOT_ACT_ROSTER = 3u,
	FZN_ROOT_ACT_ROOT_ADD = 4u,
	FZN_ROOT_ACT_ROOT_REMOVE = 5u,
	/* A setting of the estate's, sec 418: its k. */
	FZN_ROOT_ACT_SETTING = 6u
} fzn_root_act_kind_t;

typedef enum fzn_root_log_err {
	FZN_ROOT_LOG_OK = 0,
	/* A null argument, or a store that is not sound: the caller's bug. */
	FZN_ROOT_LOG_ERR_MALFORMED = -1,
	/* The bytes are not the record they claim to be: length, version or
	 * object. */
	FZN_ROOT_LOG_ERR_SHAPE = -2,
	/* The signature is not the named root's. */
	FZN_ROOT_LOG_ERR_SIGNATURE = -3,
	/* No room for another record. Nothing evicts: a record dropped is a
	 * change, setting or rule that stops counting. */
	FZN_ROOT_LOG_ERR_FULL = -4,
	/* The signer or the hash would not run. */
	FZN_ROOT_LOG_ERR_CRYPTO = -5
} fzn_root_log_err_t;

const char *fzn_root_log_err_str(fzn_root_log_err_t err);

/*
 * THE ROOT SET. project.md sec 405.
 *
 * An estate starts from one GENESIS root and changes its set of roots by two
 * records, each signed by a root and logged by it as an act:
 *
 *     root-add     version | object | adder[32] | added[32] | signature
 *     root-remove  version | object | remover[32] | removed[32] | cut[32]
 *                  | signature
 *
 * A removal's CUT is the id of the removed root's last act the remover
 * trusts -- a record in its stream, since sec 509; all-zero means none of
 * its acts stands.
 *
 * THE RULE, judged from the records held and the log, never from arrival
 * order:
 *
 *   - A key is a MEMBER when it is the genesis root, or the subject of an add
 *     whose act counts.
 *   - A removal COUNTS when its remover is a member -- even one removed
 *     itself: removals win, so two roots removing each other both fall.
 *   - An act by a root COUNTS when the root is a member and is not removed,
 *     or when the act stands, in the log, under the cut of every counting
 *     removal of it.
 *
 * Membership and removal refer to each other, so they are settled in rounds:
 * with the removals fixed, membership is the least fixed point from the
 * genesis root; the removals are then recomputed from it; until they stop
 * changing. A set of records that never settles -- only a contrived cycle of
 * roots removing the roots that added them does that -- takes every removal
 * any round saw, which errs toward removal.
 */
#define FZN_ROOT_ADD_BODY_LEN 66u
#define FZN_ROOT_ADD_LEN (FZN_ROOT_ADD_BODY_LEN + (size_t)FZN_SIG_LEN)
#define FZN_ROOT_REMOVE_BODY_LEN 98u
#define FZN_ROOT_REMOVE_LEN (FZN_ROOT_REMOVE_BODY_LEN + (size_t)FZN_SIG_LEN)

#define FZN_ROOT_SET_OFF_SIGNER 2u
#define FZN_ROOT_SET_OFF_SUBJECT 34u
#define FZN_ROOT_SET_OFF_CUT 66u

/* Sign a root-add: `adder` adds `added`. `out` receives FZN_ROOT_ADD_LEN. */
fzn_root_log_err_t fzn_root_add_issue(const uint8_t adder[FZN_PUBKEY_LEN],
                                      const uint8_t added[FZN_PUBKEY_LEN],
                                      const fzn_sign_ops_t *sign, uint8_t *out);

/* Sign a root-remove: `remover` removes `removed` at `cut`, or NULL for no
 * act of it standing. `out` receives FZN_ROOT_REMOVE_LEN. */
fzn_root_log_err_t fzn_root_remove_issue(const uint8_t remover[FZN_PUBKEY_LEN],
                                         const uint8_t removed[FZN_PUBKEY_LEN],
                                         const uint8_t cut[FZN_ROOT_ACT_ID_LEN],
                                         const fzn_sign_ops_t *sign, uint8_t *out);

/* A root-set record as a set keeps it. `id` is the hash of its whole bytes,
 * which is the subject of its signer's record in the journal. */
typedef struct fzn_root_change {
	uint8_t object;
	uint8_t signer[FZN_PUBKEY_LEN];
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t cut[FZN_ROOT_ACT_ID_LEN];
	uint8_t id[FZN_ROOT_ACT_ID_LEN];
} fzn_root_change_t;

/* The most changes a set judges: its flags live on the stack, since this
 * library allocates nothing, and an estate changes its roots rarely. */
#define FZN_ROOT_SET_MAX 64u

typedef struct fzn_root_set {
	uint8_t genesis[FZN_PUBKEY_LEN];
	fzn_root_change_t *changes;
	size_t capacity;
	size_t used;
} fzn_root_set_t;

/* MALFORMED for a capacity of 0 or past FZN_ROOT_SET_MAX. */
fzn_root_log_err_t fzn_root_set_init(fzn_root_set_t *set, const uint8_t genesis[FZN_PUBKEY_LEN],
                                     fzn_root_change_t *changes, size_t capacity);

/* Verify a root-add or root-remove, by its object byte, and keep it.
 * Idempotent. Nothing is judged here: whether its signer may make it is
 * asked when the set is read. */
fzn_root_log_err_t fzn_root_set_admit(fzn_root_set_t *set, const uint8_t *bytes, size_t len,
                                      const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash);

struct fzn_act_log_ops;

/* A READING OF THE SET, settled once and asked many times: what a revocation
 * store judging a chain asks per entry, where settling per question would
 * repeat the rounds for every one. Take a new view when the set or the log
 * changes. */
typedef struct fzn_root_view {
	const fzn_root_set_t *set;
	const struct fzn_act_log_ops *acts;
	uint8_t add_ok[FZN_ROOT_SET_MAX];
	uint8_t rem_ok[FZN_ROOT_SET_MAX];
} fzn_root_view_t;

/* Settle `set` against `acts`, the log of every key's acts (NULL for none),
 * into `view`, which borrows both. A removal's cut is asked of `acts` --
 * a root log's (`fzn_root_log_acts`) or, since sec 506, a node's journal's.
 * MALFORMED for an unsound set. */
fzn_root_log_err_t fzn_root_view_init(fzn_root_view_t *view, const fzn_root_set_t *set,
                                      const struct fzn_act_log_ops *acts);

int fzn_root_view_counts(const fzn_root_view_t *view, const uint8_t root[FZN_PUBKEY_LEN],
                         const uint8_t act[FZN_ROOT_ACT_ID_LEN]);
int fzn_root_view_stands(const fzn_root_view_t *view, const uint8_t key[FZN_PUBKEY_LEN]);
int fzn_root_view_member(const fzn_root_view_t *view, const uint8_t key[FZN_PUBKEY_LEN]);

/* Fill `ops` so that a revocation store asks `view`, which must outlive
 * them. See `fzn_revocation_store_set_roots`. */
struct fzn_root_ops;
void fzn_root_view_ops(const fzn_root_view_t *view, struct fzn_root_ops *ops);

/* Whether `act` (the hash of a record) by `root` counts, under the rule
 * above, with `acts` the log this host holds (NULL for none, in which case
 * nothing a removed root did stands). */
int fzn_root_set_counts(const fzn_root_set_t *set, const struct fzn_act_log_ops *acts,
                        const uint8_t root[FZN_PUBKEY_LEN],
                        const uint8_t act[FZN_ROOT_ACT_ID_LEN]);

/* Whether `key` is a root that stands: a member not removed. */
int fzn_root_set_stands(const fzn_root_set_t *set, const struct fzn_act_log_ops *acts,
                        const uint8_t key[FZN_PUBKEY_LEN]);

/* Whether `key` is a member at all, removed or not: a root whose acts
 * before its cut may still count. */
int fzn_root_set_member(const fzn_root_set_t *set, const struct fzn_act_log_ops *acts,
                        const uint8_t key[FZN_PUBKEY_LEN]);

/*
 * THE ESTATE'S k, SET BY A ROOT. sec 418, the holder's decisions of
 * 2026-09-30: any root sets it alone, and between concurrent settings the
 * higher k wins.
 *
 *     quorum-set  version | object | setter[32] | replaces[32] | k | signature
 *
 * `replaces` is the hash of the setting this one follows, all-zero for none,
 * so a deliberate change -- lowering included -- supersedes what it saw. A
 * setting COUNTS when its setter's act does under the root set: always while
 * the root stands, and after its removal only when its log shows the setting
 * before the cut. The CURRENT settings are the counting ones no counting
 * setting replaces; with two, set without seeing each other, the higher k
 * wins. A root logs each setting as an act of kind FZN_ROOT_ACT_SETTING.
 *
 * k is 1 to 255: a setting of 0 is refused, as `fzn_revocation_store_set_quorum`
 * refuses a quorum of 0.
 */
#define FZN_QUORUM_SET_OFF_SETTER 2u
#define FZN_QUORUM_SET_OFF_REPLACES 34u
#define FZN_QUORUM_SET_OFF_K 66u
#define FZN_QUORUM_SET_BODY_LEN 67u
#define FZN_QUORUM_SET_LEN (FZN_QUORUM_SET_BODY_LEN + (size_t)FZN_SIG_LEN)

/* Sign a setting: `setter` sets k, after the setting whose hash is
 * `replaces` (NULL for none). `out` receives FZN_QUORUM_SET_LEN bytes. */
fzn_root_log_err_t fzn_quorum_set_issue(const uint8_t setter[FZN_PUBKEY_LEN], uint8_t k,
                                        const uint8_t replaces[FZN_ROOT_ACT_ID_LEN],
                                        const fzn_sign_ops_t *sign, uint8_t *out);

/* Its shape and its setter's signature. OK, SHAPE or SIGNATURE. */
fzn_root_log_err_t fzn_quorum_set_check(const uint8_t *bytes, size_t len,
                                        const fzn_sign_ops_t *sign);

/* THE ESTATE'S k from `count` settings laid end to end in `records`, each
 * already checked, judged by `roots` (NULL: every setting counts, the single
 * pinned root's case) and named by `hash`. `fallback` when none counts. */
uint8_t fzn_quorum_resolve(const uint8_t *records, size_t count,
                           const struct fzn_root_ops *roots, const fzn_hash_ops_t *hash,
                           uint8_t fallback);

/* The same, and the hash of the winning setting into `winner` -- what a new
 * setting names as the one it replaces. 1 when a setting won, 0 when
 * `fallback` was answered and `winner` is untouched. */
int fzn_quorum_winner(const uint8_t *records, size_t count, const struct fzn_root_ops *roots,
                      const fzn_hash_ops_t *hash, uint8_t *k,
                      uint8_t winner[FZN_ROOT_ACT_ID_LEN]);

/*
 * THE ESTATE'S RETENTION RULES, SET BY A ROOT. sec 476, the holder's word of
 * 2026-10-03: setting retention is an estate-wide admin and root capability,
 * scopable, started simple -- roots first, estate-wide.
 *
 *     retention-set  version | object | setter[32] | replaces[32] | text[128] | signature
 *
 * ONE RULE A RECORD. `text` is the rule's line (`log/retain.h`), in its
 * canonical spelling by convention, NUL-padded; this layer checks only that
 * it is printable, since the chain does not read log rules. A record with
 * no text REMOVES the rule it replaces, and must replace one. A record
 * that replaces another with text CHANGES it.
 *
 * WHICH RULES APPLY: a record counts as a quorum setting does -- its
 * setter's act under the root set -- and the CURRENT records are the
 * counting ones no counting record replaces. Every current record with
 * text is a rule of the estate. Two roots adding rules without seeing each
 * other leaves both, which is the holder's "combine as one rule set".
 * Logged as an act of kind FZN_ROOT_ACT_SETTING, as a setting of k is.
 */
#define FZN_RETENTION_SET_OFF_SETTER 2u
#define FZN_RETENTION_SET_OFF_REPLACES 34u
#define FZN_RETENTION_SET_OFF_TEXT 66u
#define FZN_RETENTION_SET_TEXT_MAX 128u
#define FZN_RETENTION_SET_BODY_LEN (FZN_RETENTION_SET_OFF_TEXT + FZN_RETENTION_SET_TEXT_MAX)
#define FZN_RETENTION_SET_LEN (FZN_RETENTION_SET_BODY_LEN + (size_t)FZN_SIG_LEN)

/* Sign a retention record: `text`, `len` bytes of 0x20 to 0x7e and at most
 * FZN_RETENTION_SET_TEXT_MAX - 1, after the record whose hash is `replaces`
 * (NULL for none). `len` 0 removes `replaces`, which must then be given.
 * `out` receives FZN_RETENTION_SET_LEN bytes. */
fzn_root_log_err_t fzn_retention_set_issue(const uint8_t setter[FZN_PUBKEY_LEN],
                                           const char *text, size_t len,
                                           const uint8_t replaces[FZN_ROOT_ACT_ID_LEN],
                                           const fzn_sign_ops_t *sign, uint8_t *out);

/* Its shape and its setter's signature. OK, SHAPE or SIGNATURE. */
fzn_root_log_err_t fzn_retention_set_check(const uint8_t *bytes, size_t len,
                                           const fzn_sign_ops_t *sign);

/* Each current rule's text, NUL-terminated, and its record's hash. */
typedef void (*fzn_retention_each_fn)(void *ctx, const char *text, size_t len,
                                      const uint8_t id[FZN_ROOT_ACT_ID_LEN]);

/* THE ESTATE'S RULES from `count` records laid end to end in `records`, each
 * already checked, judged by `roots` (NULL: every record counts) and named by
 * `hash`: each current one with text handed to `each`, in the order of their
 * hashes so the answer does not depend on the order held. The number handed,
 * or -1 when `count` is past what one resolution judges. */
int fzn_retention_current(const uint8_t *records, size_t count, const struct fzn_root_ops *roots,
                          const fzn_hash_ops_t *hash, fzn_retention_each_fn each, void *ctx);

#endif /* FZN_ROOT_LOG_H */
