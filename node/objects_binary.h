/*
 * Named objects asked in binary on the local leg: fuzznet sec 1152, the
 * pilot of sec 1101's staging, its messages node/objects.situ's.
 *
 * The holder left sec 1101's choice between A and B to this tree
 * (2026-11-14), and it is A: each local operation a SUBCMD under its
 * subject's CMD, in the range kept for the local socket. So a request is
 * FZN_CMD_OBJECTS (21) with its operation -- add, set, get, list, remove --
 * and the answer is a STATUS, or for `get` one `row`, for `list` a `row` per
 * object. The text verbs (`fzn_node_objects_local`) stay, beside it, as the
 * CLI's and for clients not yet moved.
 *
 * WHO MAY ASK IS THE CALLER'S TO JUDGE, as on the text path: the node's own
 * user, or a caller `local/permit/object` lets read (`may_change` 0) or
 * change (1). This file answers what it is asked.
 */
#ifndef FZN_NODE_OBJECTS_BINARY_H
#define FZN_NODE_OBJECTS_BINARY_H

#include <stddef.h>
#include <stdint.h>

#include "objects.h"

/* The most bytes one answer message takes: a row at its widest. */
#define FZN_NODE_OBJECTS_BINARY_MAX 512u

/* Each answer message, whole, for the caller to frame and write; nonzero
 * when it was written. */
typedef int (*fzn_node_objects_put_t)(void *ctx, const uint8_t *msg, size_t len);

/* Whether MSG asks a change, as a permit judges it: add, set and remove. 0
 * for get, list, and anything that is no objects request. */
int fzn_node_objects_binary_changes(const uint8_t *msg, size_t len);

/* Answers MSG, a FZN_CMD_OBJECTS request, through `put`: 1 once answered,
 * every refusal included, and 0 when an answer could not be written.
 * `may_change` 0 refuses add, set and remove as denied. */
int fzn_node_objects_binary(const fzn_node_objects_t *o, const uint8_t *msg, size_t len,
                            int may_change, fzn_node_objects_put_t put, void *put_ctx);

#endif /* FZN_NODE_OBJECTS_BINARY_H */
