/*
 * What this node has sent and received, asked in binary on the local leg:
 * fuzznet sec 1177, its messages node/meter_local.situ's -- what the
 * transfers view refreshes, `get transfer` and every page of `list
 * transfer` as one answer.
 *
 * A request is FZN_CMD_TRANSFER (23) with `transfers`; the answer is a
 * family_row per family that has moved anything, as `get transfer` lists
 * them, a transfer_row per row the meter holds, in `list transfer`'s order,
 * and then a STATUS ok -- or a STATUS refusing it. The verbs stay beside it.
 * Who may ask is the caller's to judge: this node's own user, as the verbs
 * allow.
 */
#ifndef FZN_NODE_METER_BINARY_H
#define FZN_NODE_METER_BINARY_H

#include <stddef.h>
#include <stdint.h>

#include "meter.h"

/* The most bytes one answer message takes: a row at its widest. */
#define FZN_NODE_METER_BINARY_MAX 192u

/* Each answer message, whole, for the caller to frame and write; nonzero
 * when it was written. */
typedef int (*fzn_node_meter_put_t)(void *ctx, const uint8_t *msg, size_t len);

/* Answers MSG, a FZN_CMD_TRANSFER request, through `put`: 1 once answered,
 * every refusal included, and 0 when an answer could not be written. */
int fzn_node_meter_binary(const fzn_meter_t *m, const uint8_t *msg, size_t len,
                          fzn_node_meter_put_t put, void *put_ctx);

#endif /* FZN_NODE_METER_BINARY_H */
