/*
 * Every conversation's newest line and unread count asked in binary on the
 * local leg: fuzznet sec 1155, the second category in the holder's A (sec
 * 1152), its messages node/messages_local.situ's -- what a conversation list
 * asks on every refresh (fuzzypickles' inbox 20261114T1030Z).
 *
 * A request is FZN_CMD_MESSAGES (10) with its operation, `newest` or
 * `unread`; the answer is a row per conversation and then a STATUS ok, or a
 * STATUS refusing it. The text verbs (`list message newest|unread`) stay
 * beside it. Who may ask is the caller's to judge: this node's own user, as
 * the text verbs allow.
 */
#ifndef FZN_NODE_MESSAGES_BINARY_H
#define FZN_NODE_MESSAGES_BINARY_H

#include <stddef.h>
#include <stdint.h>

#include "messages.h"

/* The most bytes one answer message takes: a newest row at its widest. */
#define FZN_NODE_MESSAGES_BINARY_MAX 1200u

/* Each answer message, whole, for the caller to frame and write; nonzero
 * when it was written. */
typedef int (*fzn_node_messages_put_t)(void *ctx, const uint8_t *msg, size_t len);

/* Answers MSG, a FZN_CMD_MESSAGES request, through `put`: 1 once answered,
 * every refusal included, and 0 when an answer could not be written. */
int fzn_node_messages_binary(fzn_node_messages_t *nm, const uint8_t *msg, size_t len,
                             fzn_node_messages_put_t put, void *put_ctx);

#endif /* FZN_NODE_MESSAGES_BINARY_H */
