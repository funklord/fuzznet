/*
 * A STAGED CHANGE, sec 873: a setting made with a window in which it must
 * be confirmed, or every host reverts it. netcfgd's commit-confirm made
 * the estate's: a change that cuts its operator off from the hosts it
 * changed is undone by those hosts, which is the case confirm exists for
 * -- so the revert cannot be the operator's to send.
 *
 * THE REVERT IS SIGNED AT STAGING. The setter signs the new value at
 * version V and, beside it, a revert -- the cell's value before, or a
 * clear -- at V + 1, newer than the change. A STAGE object carries the
 * revert, a token and a deadline in estate time (ms), through the
 * setter's estate stream; every host holds it. Unconfirmed at the
 * deadline, a host applies the revert itself: a setting its setter
 * signed, so applying it is the setter's word and every host reverts to
 * the same bytes. A CONFIRM object, the same tag, names the token, and a
 * host holding it lets the revert go unapplied.
 *
 * A NEWER WRITE SUPERSEDES THE STAGE. At the deadline the revert is taken
 * only while the cell still stands at the staged version by the staged
 * setter; a change made since is the operator's later word, and the held
 * revert is dropped rather than undoing it.
 *
 *     0     1  FZN_SIGNED_VERSION
 *     1     1  FZN_OBJECT_STAGE
 *     2    32  setter
 *    34     1  act: 1 stage, 2 confirm
 *    35    16  token
 *    51     8  deadline, estate ms (0 in a confirm)
 *    59     2  revert_len (0 in a confirm)
 *    61     n  the revert, a setting the setter signed
 *  61+n    64  signature by the setter over everything before it
 *
 * HELD in FZN_PERSIST_STAGE, keyed by the token and the setter's first
 * sixteen bytes, the stage object as it came.
 */
#ifndef FZN_NODE_STAGE_H
#define FZN_NODE_STAGE_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"
#include "../persist/persist.h"

#define FZN_STAGE_TOKEN_LEN 16u
#define FZN_STAGE_ACT_STAGE 1u
#define FZN_STAGE_ACT_CONFIRM 2u
#define FZN_STAGE_OFF_SETTER 2u
#define FZN_STAGE_HEAD (2u + FZN_PUBKEY_LEN + 1u + FZN_STAGE_TOKEN_LEN + 8u + 2u)
/* A revert is a setting, at most FZN_SETTING_MAX. */
#define FZN_STAGE_REVERT_MAX 512u
#define FZN_STAGE_MAX (FZN_STAGE_HEAD + FZN_STAGE_REVERT_MAX + FZN_SIG_LEN)
/* The longest window a stage may ask: a day. */
#define FZN_STAGE_WINDOW_MAX_MS (86400u * 1000u)

typedef struct fzn_stage {
	uint8_t act;
	const uint8_t *setter;
	const uint8_t *token;
	uint64_t deadline_ms;
	const uint8_t *revert;
	size_t revert_len;
} fzn_stage_t;

/* SIGN a stage or a confirm into `out` (FZN_STAGE_MAX bytes). 1 with
 * `*len`, or 0 for a revert out of bound or a signer refusing. */
int fzn_stage_issue(const uint8_t setter[FZN_PUBKEY_LEN], const fzn_sign_ops_t *sign, uint8_t act,
                    const uint8_t token[FZN_STAGE_TOKEN_LEN], uint64_t deadline_ms,
                    const uint8_t *revert, size_t revert_len, uint8_t *out, size_t *len);

/* OPEN `len` bytes: 1 with `out`'s views into them when they are one
 * stage or confirm of the shape above, signed by its setter, or 0. A
 * confirm carries no revert and no deadline. */
int fzn_stage_open(const uint8_t *bytes, size_t len, const fzn_sign_ops_t *verify,
                   fzn_stage_t *out);

/* HELD, sec 873: a stage object kept, dropped, or each walked. */
int fzn_stage_hold(const fzn_persist_ops_t *store, const uint8_t *bytes, size_t len,
                   const fzn_stage_t *s);
int fzn_stage_drop(const fzn_persist_ops_t *store, const uint8_t setter[FZN_PUBKEY_LEN],
                   const uint8_t token[FZN_STAGE_TOKEN_LEN]);
/* Each held stage's bytes to `each`, which may drop it. How many, or -1. */
long fzn_stage_each(const fzn_persist_ops_t *store, const fzn_sign_ops_t *verify,
                    void (*each)(void *ctx, const uint8_t *bytes, size_t len,
                                 const fzn_stage_t *s),
                    void *ctx);

#endif /* FZN_NODE_STAGE_H */
