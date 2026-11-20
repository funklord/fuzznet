/*
 * The one search in binary on the local leg: fuzznet sec 1293, its
 * messages node/search_local.situ's -- what a client's search box asks.
 *
 * FZN_CMD_SEARCH (26) with `list`, `fetch` or `get`, as `list search`,
 * `fetch search` and `get search` (`node/search.h`). LIST and GET are
 * answered with a PAGE -- how many hits, whether more follow, the hosts
 * asked, answered and late -- a HIT each, and a STATUS ok; FETCH with
 * FETCHED, the hosts asked, and a STATUS ok. A refusal is a STATUS. Who
 * may ask is the caller's to judge: this node's own user, as the verbs
 * allow.
 */
#ifndef FZN_NODE_SEARCH_BINARY_H
#define FZN_NODE_SEARCH_BINARY_H

#include <stddef.h>
#include <stdint.h>

#include "search.h"

/* The most bytes one answer message takes: a hit at its widest, 201. */
#define FZN_NODE_SEARCH_BINARY_MAX 256u

/* Each answer message, whole, for the caller to frame and write; nonzero
 * when it was written. */
typedef int (*fzn_node_search_put_t)(void *ctx, const uint8_t *msg, size_t len);

/* Answers MSG, a FZN_CMD_SEARCH request of the local leg, through `put`:
 * 1 once answered, every refusal included, and 0 when an answer could
 * not be written. */
int fzn_node_search_binary(fzn_node_search_t *s, const uint8_t *msg, size_t len, fzn_node_search_put_t put,
                           void *put_ctx);

#endif /* FZN_NODE_SEARCH_BINARY_H */
