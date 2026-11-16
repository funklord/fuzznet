/*
 * The forks asked in binary on the local leg: fuzznet sec 1187, its
 * messages node/settings_local.situ's -- what a forks view lists, `list
 * fork` in one answer.
 *
 * A request is FZN_CMD_SETTINGS (24) with `forks`; the answer is a row per
 * head of each fork -- subject, host, when, grounds, value, the last two
 * raw -- and then a STATUS ok, or a STATUS refusing it. Who may ask is the
 * caller's to judge: this node's own user, as the verb allows.
 */
#ifndef FZN_NODE_DECISIONS_BINARY_H
#define FZN_NODE_DECISIONS_BINARY_H

#include <stddef.h>
#include <stdint.h>

#include "decisions.h"

/* The most bytes one answer message takes: a row at its widest. */
#define FZN_NODE_DECISIONS_BINARY_MAX 432u

/* Each answer message, whole, for the caller to frame and write; nonzero
 * when it was written. */
typedef int (*fzn_node_decisions_put_t)(void *ctx, const uint8_t *msg, size_t len);

/* Answers MSG, a FZN_CMD_SETTINGS request, through `put`: 1 once answered,
 * every refusal included, and 0 when an answer could not be written. */
int fzn_node_decisions_binary(const fzn_node_records_t *nr, const uint8_t *msg, size_t len,
                              fzn_node_decisions_put_t put, void *put_ctx);

#endif /* FZN_NODE_DECISIONS_BINARY_H */
