/*
 * One request in binary on the local leg, the typed client's half of fuzznet
 * sec 1152 (the holder's sec 1101 A, its pilot named objects): a message as
 * between hosts, framed by two bytes of length (sec 1113), sent on its own
 * connection; each answer message handed on as it comes, until the node
 * closes. The calls that speak it fall back to the text verbs where the node
 * cannot: one from before the category answers any binary request but a
 * media channel's with a STATUS malformed, and a client whose `answer` hook
 * speaks text alone (a test's scripted node) has no binary path at all.
 */
#ifndef FZN_LOCAL_RPC_BINARY_H
#define FZN_LOCAL_RPC_BINARY_H

#include <stddef.h>
#include <stdint.h>

#include "rpc.h"

/* Each answer message, whole, in the order the node wrote them. */
typedef void (*fzn_rpc_binary_each_t)(void *ctx, const uint8_t *msg, size_t len);

/* FZN_RPC_OK once the node answered and closed, each message handed to
 * `each`; *text 1 instead when this node or this client speaks text alone
 * for it, the call to be made by its verb. Otherwise the failure, said in
 * c->error. */
int fzn_rpc_binary(fzn_rpc_t *c, const uint8_t *msg, size_t len, fzn_rpc_binary_each_t each,
                   void *ctx, int *text);

#endif /* FZN_LOCAL_RPC_BINARY_H */
