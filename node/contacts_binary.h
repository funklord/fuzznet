/*
 * This user's contacts asked in binary on the local leg: fuzznet sec 1162,
 * the category fuzzypickles named after messages, its messages
 * node/contacts_local.situ's.
 *
 * A request is FZN_CMD_CONTACTS (11) with `list`; the answer is a row per
 * contact -- key, standing and name -- and then a STATUS ok, or a STATUS
 * refusing it. The text verb (`list contact`) stays beside it. Who may ask
 * is the caller's to judge: this node's own user, as the text verb allows.
 */
#ifndef FZN_NODE_CONTACTS_BINARY_H
#define FZN_NODE_CONTACTS_BINARY_H

#include <stddef.h>
#include <stdint.h>

#include "admin.h"

/* The most bytes one answer message takes: a row at its widest. */
#define FZN_NODE_CONTACTS_BINARY_MAX 80u

/* Each answer message, whole, for the caller to frame and write; nonzero
 * when it was written. */
typedef int (*fzn_node_contacts_put_t)(void *ctx, const uint8_t *msg, size_t len);

/* Answers MSG, a FZN_CMD_CONTACTS request, through `put`: 1 once answered,
 * every refusal included, and 0 when an answer could not be written. */
int fzn_node_contacts_binary(fzn_node_admin_t *admin, const uint8_t *msg, size_t len,
                             fzn_node_contacts_put_t put, void *put_ctx);

#endif /* FZN_NODE_CONTACTS_BINARY_H */
