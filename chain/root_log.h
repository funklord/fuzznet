/* A root's log: every act a root signs, chained. project.md sec 404.
 *
 * WHY. sec 403 gives a root the whole estate's authority and lets any root
 * remove another. The holder asked that a removal undo only what the removed
 * root did SINCE IT WAS STOLEN. A thief holding the key can sign any
 * `issued_at` it likes, so time cannot say that. Ancestry can: if every act a
 * root signs is logged, each entry naming the root's previous entry by hash,
 * then a removal names a CUT -- the last entry the remover trusts -- and an
 * act stands exactly when its entry lies on the chain that ends at the cut.
 * Acts after the cut fall, and so do acts on a fork: a thief replaying from
 * an earlier point makes two entries with one predecessor, which is also how
 * the fork is seen.
 *
 * WHAT IS LOGGED. An entry names an act by the hash of the act's whole signed
 * record -- a hop, a revocation, a roster record, a change to the root set --
 * and says which kind it is. The acts themselves are unchanged: nothing about
 * a hop or a revocation says it was logged, and a root that stands needs no
 * log to be believed. The log is asked only about a REMOVED root.
 *
 * WHAT FALLS BESIDES. An act whose entry this host never received cannot be
 * shown to lie before the cut, so it falls too. The cut is the remover's
 * statement of what it trusts, and a host can only stand behind what it
 * holds.
 *
 * THE LAYOUT. Big-endian, fixed width, as every signed object here.
 *
 *     offset  size  field
 *          0     1  version    (= FZN_SIGNED_VERSION)
 *          1     1  object     (= FZN_OBJECT_ROOT_ACT)
 *          2    32  root       (the root key that signed it)
 *         34     8  seq        (0 for the root's first act)
 *         42    32  prev       (the previous entry's id; zero at seq 0)
 *         74     1  kind       (FZN_ROOT_ACT_*)
 *         75    32  act        (the hash of the act's whole record)
 *        107    64  signature
 *
 * An entry's ID is the hash of its whole 171 bytes, as a revocation's is.
 */

#ifndef FZN_ROOT_LOG_H
#define FZN_ROOT_LOG_H

#include <stddef.h>
#include <stdint.h>

#include "chain.h"
#include "../session/commitment.h"

#define FZN_ROOT_ACT_BODY_LEN 107u
#define FZN_ROOT_ACT_LEN (FZN_ROOT_ACT_BODY_LEN + (size_t)FZN_SIG_LEN)
#define FZN_ROOT_ACT_ID_LEN 32u

#define FZN_ROOT_ACT_OFF_VERSION 0u
#define FZN_ROOT_ACT_OFF_OBJECT 1u
#define FZN_ROOT_ACT_OFF_ROOT 2u
#define FZN_ROOT_ACT_OFF_SEQ 34u
#define FZN_ROOT_ACT_OFF_PREV 42u
#define FZN_ROOT_ACT_OFF_KIND 74u
#define FZN_ROOT_ACT_OFF_ACT 75u
#define FZN_ROOT_ACT_OFF_SIGNATURE FZN_ROOT_ACT_BODY_LEN

/* What kind of act an entry logs. Zero is refused, so a zeroed record names
 * no act. */
typedef enum fzn_root_act_kind {
	FZN_ROOT_ACT_GRANT = 1u,
	FZN_ROOT_ACT_REVOCATION = 2u,
	FZN_ROOT_ACT_ROSTER = 3u,
	FZN_ROOT_ACT_ROOT_ADD = 4u,
	FZN_ROOT_ACT_ROOT_REMOVE = 5u
} fzn_root_act_kind_t;

typedef enum fzn_root_log_err {
	FZN_ROOT_LOG_OK = 0,
	/* A null argument, or a store that is not sound: the caller's bug. */
	FZN_ROOT_LOG_ERR_MALFORMED = -1,
	/* The bytes are not an entry: length, version, object, kind, or a seq
	 * and prev that disagree (seq 0 names no predecessor; every later one
	 * must). */
	FZN_ROOT_LOG_ERR_SHAPE = -2,
	/* The signature is not the named root's. */
	FZN_ROOT_LOG_ERR_SIGNATURE = -3,
	/* No room for a new entry. A log never evicts: an entry dropped is an
	 * act that can no longer be shown to stand. */
	FZN_ROOT_LOG_ERR_FULL = -4,
	/* The signer or the hash would not run. */
	FZN_ROOT_LOG_ERR_CRYPTO = -5
} fzn_root_log_err_t;

const char *fzn_root_log_err_str(fzn_root_log_err_t err);

/* A view over an opened entry, as every signed object here is viewed. */
typedef struct fzn_root_act {
	const uint8_t *base;
} fzn_root_act_t;

fzn_root_log_err_t fzn_root_act_open(const uint8_t *bytes, size_t len, fzn_root_act_t *out);

static inline const uint8_t *fzn_root_act_root(fzn_root_act_t a)
{
	return a.base + FZN_ROOT_ACT_OFF_ROOT;
}

static inline uint64_t fzn_root_act_seq(fzn_root_act_t a)
{
	return fzn_get_be64(a.base + FZN_ROOT_ACT_OFF_SEQ);
}

static inline const uint8_t *fzn_root_act_prev(fzn_root_act_t a)
{
	return a.base + FZN_ROOT_ACT_OFF_PREV;
}

static inline uint8_t fzn_root_act_kind(fzn_root_act_t a)
{
	return a.base[FZN_ROOT_ACT_OFF_KIND];
}

static inline const uint8_t *fzn_root_act_act(fzn_root_act_t a)
{
	return a.base + FZN_ROOT_ACT_OFF_ACT;
}

/* Sign an entry: `root` logs act `act` (the hash of its record) of `kind` at
 * `seq`, after `prev` (NULL, or ignored, at seq 0). `out` receives
 * FZN_ROOT_ACT_LEN bytes. As `fzn_revocation_issue`, `root` is a public key
 * and whether the signer holds its secret is not asked. */
fzn_root_log_err_t fzn_root_act_issue(const uint8_t root[FZN_PUBKEY_LEN], uint64_t seq,
                                      const uint8_t prev[FZN_ROOT_ACT_ID_LEN], uint8_t kind,
                                      const uint8_t act[FZN_ROOT_ACT_ID_LEN],
                                      const fzn_sign_ops_t *sign, uint8_t *out);

/* An entry as a log keeps it: the fields the questions below read, and its
 * id. Verified once, on admission. */
typedef struct fzn_root_log_entry {
	uint8_t root[FZN_PUBKEY_LEN];
	uint64_t seq;
	uint8_t id[FZN_ROOT_ACT_ID_LEN];
	uint8_t prev[FZN_ROOT_ACT_ID_LEN];
	uint8_t act[FZN_ROOT_ACT_ID_LEN];
	uint8_t kind;
} fzn_root_log_entry_t;

/* The entries a host holds, for every root. Caller-owned storage. */
typedef struct fzn_root_log {
	fzn_root_log_entry_t *entries;
	size_t capacity;
	size_t used;
} fzn_root_log_t;

fzn_root_log_err_t fzn_root_log_init(fzn_root_log_t *log, fzn_root_log_entry_t *entries,
                                     size_t capacity);

/* Verify an entry and keep it. Idempotent: an entry already held is OK and
 * not stored twice. A second entry at a seq the root has already used is
 * KEPT, not refused -- it is the evidence of a fork, and refusing it would
 * make what a host sees depend on which of the two arrived first. */
fzn_root_log_err_t fzn_root_log_admit(fzn_root_log_t *log, const uint8_t *bytes, size_t len,
                                      const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash);

/* DOES THIS ACT STAND UNDER THIS CUT? 1 when `root` logged `act` on the chain
 * that ends at the entry whose id is `cut`: the cut itself, or an entry
 * reached from it by following `prev`, each step one seq lower and signed by
 * the same root, down to seq 0. 0 otherwise -- after the cut, on a fork, or
 * behind a link this log does not hold. */
int fzn_root_log_stands(const fzn_root_log_t *log, const uint8_t root[FZN_PUBKEY_LEN],
                        const uint8_t cut[FZN_ROOT_ACT_ID_LEN],
                        const uint8_t act[FZN_ROOT_ACT_ID_LEN]);

/* Whether `root` has signed two different entries at one seq: the mark of a
 * key used in two places, which is what a stolen root looks like. */
int fzn_root_log_forked(const fzn_root_log_t *log, const uint8_t root[FZN_PUBKEY_LEN]);

#endif /* FZN_ROOT_LOG_H */
