/*
 * Peers whose clocks disagree with this node's, asked in binary on the
 * local leg: fuzznet sec 1184, its messages node/time_local.situ's -- what
 * a clock notice lists, `list clock` in one answer.
 *
 * A request is FZN_CMD_TIME (15) with `clocks`; the answer is a row per
 * peer -- key, ahead, seconds, when -- and then a STATUS ok, or a STATUS
 * refusing it. Rows past their keeping are forgotten first, as the text
 * verb forgets them. Who may ask is the caller's to judge: this node's own
 * user, as the verb allows.
 */
#ifndef FZN_NODE_CLOCKS_BINARY_H
#define FZN_NODE_CLOCKS_BINARY_H

#include <stddef.h>
#include <stdint.h>

#include "clocks.h"

/* The most bytes one answer message takes: a row. */
#define FZN_NODE_CLOCKS_BINARY_MAX 56u

/* Each answer message, whole, for the caller to frame and write; nonzero
 * when it was written. */
typedef int (*fzn_node_clocks_put_t)(void *ctx, const uint8_t *msg, size_t len);

/* Answers MSG, a FZN_CMD_TIME request, at `now`, through `put`: 1 once
 * answered, every refusal included, and 0 when an answer could not be
 * written. */
int fzn_node_clocks_binary(fzn_node_clocks_t *c, uint64_t now, const uint8_t *msg, size_t len,
                           fzn_node_clocks_put_t put, void *put_ctx);

#endif /* FZN_NODE_CLOCKS_BINARY_H */
