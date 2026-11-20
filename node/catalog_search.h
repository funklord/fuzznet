/*
 * THE LIBRARY'S FILES AS A STORE OF THE ONE SEARCH, sec 1299: the
 * catalogue (`node/catalog.h`) searched by each file's name and kind, as
 * the library view shows them. A file is keyed by its root, which every
 * host names it by, so the user's hosts' answers merge into one hit; its
 * snippet is its name. No time: when a host learnt a file differs host by
 * host (sec 1287's rule, the contacts store's reason).
 *
 * A USER'S LIBRARY IS ITS OWN DEVICES' (sec 633): a contact asking is
 * answered nothing here.
 */
#ifndef FZN_NODE_CATALOG_SEARCH_H
#define FZN_NODE_CATALOG_SEARCH_H

#include <stdint.h>

#include "catalog.h"
#include "../search/search.h"

/* A `search/search.h` store's run, `ctx` the node's catalogue. */
int fzn_node_catalog_search(void *ctx, const fzn_search_query_t *q, const uint8_t *asker, fzn_search_emit_t emit,
                            void *emit_ctx);

#endif /* FZN_NODE_CATALOG_SEARCH_H */
