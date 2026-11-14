/*
 * This user's groups asked in binary on the local leg: fuzznet sec 1170,
 * its messages node/groups_local.situ's -- what a conversation list asks on
 * every refresh, beside every conversation's newest line and count (sec
 * 1155).
 *
 * A request is FZN_CMD_GROUPS (13) with `list`; the answer is a row per
 * group this user is in -- id, members, admin, lines held, name -- and then
 * a STATUS ok, or a STATUS refusing it. The text verb (`list group`) stays
 * beside it. Who may ask is the caller's to judge: this node's own user,
 * as the text verb allows.
 */
#ifndef FZN_NODE_GROUPS_BINARY_H
#define FZN_NODE_GROUPS_BINARY_H

#include <stddef.h>
#include <stdint.h>

#include "groups.h"

/* The most bytes one answer message takes: a row at its widest. */
#define FZN_NODE_GROUPS_BINARY_MAX 96u

/* Each answer message, whole, for the caller to frame and write; nonzero
 * when it was written. */
typedef int (*fzn_node_groups_put_t)(void *ctx, const uint8_t *msg, size_t len);

/* Answers MSG, a FZN_CMD_GROUPS request, through `put`: 1 once answered,
 * every refusal included, and 0 when an answer could not be written. */
int fzn_node_groups_binary(const fzn_node_groups_t *g, const uint8_t *msg, size_t len,
                           fzn_node_groups_put_t put, void *put_ctx);

#endif /* FZN_NODE_GROUPS_BINARY_H */
