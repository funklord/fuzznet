/*
 * A GROUP'S LINES AS A HOST HOLDS THEM, project.md sec 629: step 5c on sec
 * 628's sealed lines.
 *
 * EACH SEALING HOST'S LINES IN A GROUP ARE A LOG of their own, numbered
 * from 1 in the order it sealed them. Every member's host keeps every
 * line it is given, sealed as it travelled, so it can pass them on: a
 * line reaches a member's host through any host that shares the group
 * with both, as the group's acts do (sec 626), and no two members need to
 * be each other's contacts.
 *
 * HELD CONTIGUOUSLY: a host's line `n` is taken only after `n - 1`, so
 * what a host holds of another's is one number, its HEAD, and a sync asks
 * for what lies past each head. A head also says how far the lines held
 * have been FILED into `messages/` here -- opened under their epoch's
 * secret, admitted and written -- since a line may arrive before the
 * secret it was sealed under.
 *
 * FILED UNDER AN ID OF ITS OWN: the hash of the sealing host and the
 * line's id, so two members choosing one id never collide in the group's
 * conversation; and that id's SENDER kept beside it, the member's root,
 * which `messages/` has no field for.
 *
 * Kept in FZN_PERSIST_GROUP_LINE (a line), FZN_PERSIST_GROUP_LINE_HEAD (a
 * head) and FZN_PERSIST_GROUP_LINE_SENDER (a filed id's sender), none of
 * them core: a line lost is fetched again from any member's host.
 */
#ifndef FZN_NODE_GROUP_LINES_H
#define FZN_NODE_GROUP_LINES_H

#include <stddef.h>
#include <stdint.h>

#include "group_line.h"

/* Heads one host holds across every group. */
#define FZN_GROUP_LINE_HEADS_MAX 1024u

typedef enum fzn_group_lines_err {
	FZN_GROUP_LINES_OK = 0,
	FZN_GROUP_LINES_ERR_MALFORMED = -1, /* a null, or a field out of range */
	FZN_GROUP_LINES_ERR_HELD = -2,      /* that line is already held */
	FZN_GROUP_LINES_ERR_GAP = -3,       /* the line before it is not held yet */
	FZN_GROUP_LINES_ERR_ABSENT = -4,    /* no such line or head */
	FZN_GROUP_LINES_ERR_BACKEND = -5    /* the store refused, or cannot list */
} fzn_group_lines_err_t;

const char *fzn_group_lines_err_str(fzn_group_lines_err_t err);

typedef struct fzn_group_lines {
	const fzn_persist_ops_t *store;
	const fzn_hash_ops_t *hash;
} fzn_group_lines_t;

/* WHAT IS HELD of `host`'s lines in `group`: the last line `have`, and the
 * last filed here `filed`. */
typedef struct fzn_group_line_head {
	uint8_t group[FZN_GROUP_ID_LEN];
	uint8_t host[FZN_PUBKEY_LEN];
	uint32_t have;
	uint32_t filed;
	/* THE LAST LINE TRIMMED, sec 664: lines 1 to `base` are gone here, and
	 * a line is served and filed from `base` + 1. 0 for none. */
	uint32_t base;
} fzn_group_line_head_t;

/* `host`'s head in `group`; one of nothing held when there is none. */
fzn_group_lines_err_t fzn_group_lines_head(const fzn_group_lines_t *l,
                                           const uint8_t group[FZN_GROUP_ID_LEN],
                                           const uint8_t host[FZN_PUBKEY_LEN],
                                           fzn_group_line_head_t *out);

/* Every head held for `group`, `cap` of them. */
fzn_group_lines_err_t fzn_group_lines_heads(const fzn_group_lines_t *l,
                                            const uint8_t group[FZN_GROUP_ID_LEN],
                                            fzn_group_line_head_t *out, size_t cap,
                                            size_t *count);

/* TAKE line `n` of its sealing host's, in `bytes` (a sealed line, whose
 * head names the group and the host): HELD when it is, GAP when line
 * `n - 1` is not. Nothing is opened. */
fzn_group_lines_err_t fzn_group_lines_put(const fzn_group_lines_t *l, uint32_t n,
                                          const uint8_t *bytes, size_t len);

/* Line `n` of `host`'s in `group`, sealed, into `out`. */
fzn_group_lines_err_t fzn_group_lines_get(const fzn_group_lines_t *l,
                                          const uint8_t group[FZN_GROUP_ID_LEN],
                                          const uint8_t host[FZN_PUBKEY_LEN], uint32_t n,
                                          uint8_t *out, size_t cap, size_t *len);

/* TRIM `host`'s lines in `group` up to `upto`, sec 664: each removed, and
 * the head's base, have and filed moved past them -- what a retention rule
 * that trimmed their month here asks, or what a sender's own trim means
 * for its lines here. `*removed` (may be NULL) counts lines removed. */
fzn_group_lines_err_t fzn_group_lines_trim(const fzn_group_lines_t *l,
                                           const uint8_t group[FZN_GROUP_ID_LEN],
                                           const uint8_t host[FZN_PUBKEY_LEN], uint32_t upto,
                                           size_t *removed);

/* PUT the line at `n`, taking the lines before it as trimmed at their
 * sender when it starts past this head -- for the first line of a host an
 * answer gives, which starts past what was asked only when the sender
 * trimmed (sec 664). HELD as `fzn_group_lines_put`. */
fzn_group_lines_err_t fzn_group_lines_put_from(const fzn_group_lines_t *l, uint32_t n,
                                               const uint8_t *bytes, size_t len);

/* `host`'s lines in `group` filed here up to `filed`. */
fzn_group_lines_err_t fzn_group_lines_filed(const fzn_group_lines_t *l,
                                            const uint8_t group[FZN_GROUP_ID_LEN],
                                            const uint8_t host[FZN_PUBKEY_LEN], uint32_t filed);

/* THE ID a line is filed under in the group's conversation. */
int fzn_group_lines_filed_id(const fzn_hash_ops_t *hash, const uint8_t host[FZN_PUBKEY_LEN],
                             const uint8_t id[FZN_GROUP_LINE_ID_LEN],
                             uint8_t out[FZN_GROUP_LINE_ID_LEN]);

/* THE SENDER of the line filed under `filed_id` in `group`: kept with
 * `fzn_group_lines_sender_keep`, read with `fzn_group_lines_sender`. */
fzn_group_lines_err_t fzn_group_lines_sender_keep(const fzn_group_lines_t *l,
                                                  const uint8_t group[FZN_GROUP_ID_LEN],
                                                  const uint8_t filed_id[FZN_GROUP_LINE_ID_LEN],
                                                  const uint8_t sender[FZN_PUBKEY_LEN]);
fzn_group_lines_err_t fzn_group_lines_sender(const fzn_group_lines_t *l,
                                             const uint8_t group[FZN_GROUP_ID_LEN],
                                             const uint8_t filed_id[FZN_GROUP_LINE_ID_LEN],
                                             uint8_t sender[FZN_PUBKEY_LEN]);

#endif /* FZN_NODE_GROUP_LINES_H */
