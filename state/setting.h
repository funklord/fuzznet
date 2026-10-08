/* One cell of the estate's configuration, as a signed object. project.md
 * sec 540, stage 2 of sec 535.
 *
 * A SETTING names a scope (`state/scope.h`), what it is about -- a host's
 * key for a host scope, the estate's root for the estate -- a key, and
 * either a value or a clear, at a version, signed by its setter:
 *
 *     setting  version | object | setter[32] | scope | about[32] |
 *              version_no[8] | key_len | key | op | value_len[2] | value |
 *              signature
 *
 * The CELL is (scope, the scoped subject of `about`, key). Every admin node is
 * a source for every cell, and every node that follows the estate holds every
 * cell: the holder's distributed configuration, each node a backup of the
 * others' (sec 535).
 *
 * WHICH SETTING STANDS IS DECIDED IN TWO STEPS, the holder's of 2026-10-08:
 * RANK FIRST -- a root over an admin over the host itself -- then, within a
 * rank, the higher version, a tie going to the greater setter key. A rank is
 * not in the object: it is what the setter's standing is judged to be where
 * the object is applied (`node/settings.h`), so no setter can claim one.
 *
 * ONE LAYER PER RANK, so a clear withdraws its own rank's value and no more:
 * an admin clearing a host's cell leaves the host's own value in force again,
 * rather than a tombstone that outranks the host for ever. Within a rank a
 * clear is a tombstone, as `state/state.h`'s is: a clear at version 7 refuses
 * a set at version 6 afterwards, so a replay cannot bring a value back.
 *
 * KEYS are 1 to FZN_SETTING_KEY_MAX bytes of a-z, 0-9 and `._/-`, so a key is
 * one word on the admin grammar and in any listing. VALUES are printable ASCII
 * (0x20 to 0x7e), at most FZN_SETTING_VALUE_MAX bytes: what is configured here
 * is text a person reads and writes, a retention rule's line among them.
 */

#ifndef FZN_STATE_SETTING_H
#define FZN_STATE_SETTING_H

#include <stddef.h>
#include <stdint.h>

#include "scope.h"
#include "../chain/chain.h"

#define FZN_SETTING_KEY_MAX 64u
#define FZN_SETTING_VALUE_MAX 256u

#define FZN_SETTING_OFF_SETTER 2u
#define FZN_SETTING_OFF_SCOPE (FZN_SETTING_OFF_SETTER + FZN_PUBKEY_LEN)
#define FZN_SETTING_OFF_ABOUT (FZN_SETTING_OFF_SCOPE + 1u)
#define FZN_SETTING_OFF_VERSION (FZN_SETTING_OFF_ABOUT + FZN_SUBJECT_LEN)
#define FZN_SETTING_OFF_KEY_LEN (FZN_SETTING_OFF_VERSION + 8u)
#define FZN_SETTING_OFF_KEY (FZN_SETTING_OFF_KEY_LEN + 1u)
/* The shortest object, a clear of a one-byte key, and the longest. */
#define FZN_SETTING_MIN (FZN_SETTING_OFF_KEY + 1u + 1u + 2u + (size_t)FZN_SIG_LEN)
#define FZN_SETTING_MAX (FZN_SETTING_OFF_KEY + FZN_SETTING_KEY_MAX + 1u + 2u \
                         + FZN_SETTING_VALUE_MAX + (size_t)FZN_SIG_LEN)

/* A setter's standing, judged where a setting is applied. Higher wins. */
typedef enum fzn_setting_rank {
	FZN_SETTING_RANK_HOST = 0,
	FZN_SETTING_RANK_ADMIN = 1,
	FZN_SETTING_RANK_ROOT = 2
} fzn_setting_rank_t;

#define FZN_SETTING_RANKS 3u

typedef enum fzn_setting_err {
	FZN_SETTING_OK = 0,
	FZN_SETTING_ERR_MALFORMED = -1,  /* a null, or a key or value out of shape */
	FZN_SETTING_ERR_SHAPE = -2,      /* bytes that are not a setting */
	FZN_SETTING_ERR_SIGNATURE = -3,  /* its setter did not sign it */
	FZN_SETTING_ERR_SCOPE = -4       /* a scope with no cell, or one not yet served */
} fzn_setting_err_t;

const char *fzn_setting_err_str(fzn_setting_err_t err);

/* A setting opened: views into the bytes it was opened from. */
typedef struct fzn_setting {
	const uint8_t *setter;
	fzn_scope_t scope;
	const uint8_t *about;
	uint64_t version;
	const uint8_t *key;
	size_t key_len;
	int set;          /* 1: `value` is the cell's; 0: a clear */
	const uint8_t *value;
	size_t value_len;
} fzn_setting_t;

/* Whether `key`, `len` bytes, is a key: 1 to FZN_SETTING_KEY_MAX of a-z, 0-9
 * and `._/-`. */
int fzn_setting_key_ok(const uint8_t *key, size_t len);

/*
 * SIGN A SETTING into `out` (FZN_SETTING_MAX bytes), `*out_len` of them:
 * `set` 1 with `value` (`value_len` printable bytes), or 0 for a clear with
 * no value. The scopes served are FZN_SCOPE_HOST and FZN_SCOPE_ESTATE;
 * another is SCOPE.
 */
fzn_setting_err_t fzn_setting_issue(const uint8_t setter[FZN_PUBKEY_LEN],
                                    const fzn_sign_ops_t *sign, fzn_scope_t scope,
                                    const uint8_t about[FZN_SUBJECT_LEN], uint64_t version,
                                    const uint8_t *key, size_t key_len, int set,
                                    const uint8_t *value, size_t value_len, uint8_t *out,
                                    size_t *out_len);

/* OPEN `bytes`: its shape and its setter's signature, into `out`. */
fzn_setting_err_t fzn_setting_open(const uint8_t *bytes, size_t len, const fzn_sign_ops_t *sign,
                                   fzn_setting_t *out);

/* The cell `s` is a setting of, named under `hash`, into `cell`. */
int fzn_setting_cell(const fzn_setting_t *s, const fzn_hash_ops_t *hash,
                     uint8_t cell[FZN_SUBJECT_LEN]);

/* The same, from its parts. */
int fzn_setting_cell_of(fzn_scope_t scope, const uint8_t about[FZN_SUBJECT_LEN],
                        const uint8_t *key, size_t key_len, const fzn_hash_ops_t *hash,
                        uint8_t cell[FZN_SUBJECT_LEN]);

/* WHETHER `a` STANDS OVER `b` WITHIN ONE RANK: the higher version, or at one
 * version the greater setter key. 0 for the same setting. */
int fzn_setting_supersedes(const fzn_setting_t *a, const fzn_setting_t *b);

#endif /* FZN_STATE_SETTING_H */
