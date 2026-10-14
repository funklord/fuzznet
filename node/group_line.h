/*
 * A GROUP LINE IN TRANSIT, project.md sec 628: step 5b's second part on
 * sec 627's epochs, laid out as `node/group_line.situ`.
 *
 * WHAT IT SAYS, in the clear: the group, the group epoch it is sealed in,
 * the member who wrote it (a user's root), the host that sealed it, the
 * line's id and when it was written. Sealed: the text.
 *
 * THE KEY is the hash of a label, the epoch's secret and the sealing host:
 * one key per host per epoch, so two hosts of one user -- one sender --
 * never share a key, and a random 24-byte nonce per line keeps a key from
 * repeating one. Every member's host holds the epoch's secret, so every
 * member reads every line of an epoch it was given, and none of an epoch
 * after it left.
 *
 * NOT SIGNED, fuzzypickles' deniability decision for group lines (sec
 * 625): whoever holds the secret could seal a line naming any member. What
 * a receiver checks is that the line opens under the epoch's secret, and
 * for the current epoch that its host is a host the log lists for the
 * member it names (`fzn_group_line_admit`). An older epoch's host may have
 * left the log since, so there the line's opening is the whole check.
 *
 * The group epoch is a count of membership changes (`node/group_log.h`),
 * not the month `messages/` calls an epoch.
 */
#ifndef FZN_NODE_GROUP_LINE_H
#define FZN_NODE_GROUP_LINE_H

#include <stddef.h>
#include <stdint.h>

#include "group_log.h"
#include "../session/aead.h"
#include "../session/random.h"

#define FZN_GROUP_LINE_VERSION 1u
#define FZN_GROUP_LINE_ID_LEN 16u
/* The most text a line carries: two of `messages/`'s parts. */
#define FZN_GROUP_LINE_TEXT_MAX 880u
#define FZN_GROUP_LINE_HEAD_LEN                                                             \
	(1u + FZN_GROUP_ID_LEN + 4u + FZN_PUBKEY_LEN + FZN_PUBKEY_LEN + FZN_GROUP_LINE_ID_LEN + 8u)
#define FZN_GROUP_LINE_MAX                                                                  \
	(FZN_GROUP_LINE_HEAD_LEN + FZN_AEAD_NONCE_LEN + 2u + FZN_GROUP_LINE_TEXT_MAX         \
	 + FZN_AEAD_TAG_LEN)

typedef enum fzn_group_line_err {
	FZN_GROUP_LINE_OK = 0,
	FZN_GROUP_LINE_ERR_MALFORMED = -1, /* a null, a field out of range, no room */
	FZN_GROUP_LINE_ERR_SHAPE = -2,     /* bytes that are not a group line */
	FZN_GROUP_LINE_ERR_OPEN = -3,      /* not sealed under this secret, or altered */
	FZN_GROUP_LINE_ERR_STRANGER = -4,  /* its sender or host is not the group's */
	FZN_GROUP_LINE_ERR_OPS = -5        /* the hash, the AEAD or the randomness refused */
} fzn_group_line_err_t;

const char *fzn_group_line_err_str(fzn_group_line_err_t err);

typedef struct fzn_group_line {
	uint8_t group[FZN_GROUP_ID_LEN];
	uint32_t epoch;
	uint8_t sender[FZN_PUBKEY_LEN]; /* the member who wrote it */
	uint8_t host[FZN_PUBKEY_LEN];   /* the host that sealed it */
	uint8_t id[FZN_GROUP_LINE_ID_LEN];
	uint64_t stime;
	uint8_t text[FZN_GROUP_LINE_TEXT_MAX];
	size_t text_len;
} fzn_group_line_t;

/* SEAL `line`'s text under epoch `line->epoch`'s `secret`, a nonce drawn
 * from `rng`, into `out`. */
fzn_group_line_err_t fzn_group_line_seal(const fzn_group_line_t *line,
                                         const uint8_t secret[FZN_GROUP_SECRET_LEN],
                                         const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                         const fzn_random_ops_t *rng, uint8_t *out, size_t cap,
                                         size_t *len);

/* THE CLEAR HEAD of a line's bytes -- group, epoch, sender, host, id,
 * stime -- into `out`, its text empty: what a receiver needs to find the
 * secret it opens under. */
fzn_group_line_err_t fzn_group_line_peek(const uint8_t *bytes, size_t len,
                                         fzn_group_line_t *out);

/* OPEN a line's bytes under `secret` into `out`, head and text. */
fzn_group_line_err_t fzn_group_line_open(const uint8_t *bytes, size_t len,
                                         const uint8_t secret[FZN_GROUP_SECRET_LEN],
                                         const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                         fzn_group_line_t *out);

/* WHETHER GROUP `g` TAKES `line` as its sender's: the group's, sent in an
 * epoch the group has reached, and in the current epoch its sender a
 * member and its host one the log lists for that member. A line of an
 * older epoch is history: its sender may have left since. STRANGER
 * otherwise. */
fzn_group_line_err_t fzn_group_line_admit(const fzn_group_t *g, const fzn_group_line_t *line);

#endif /* FZN_NODE_GROUP_LINE_H */
