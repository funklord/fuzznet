/*
 * THIS NODE'S STORES FOR THE ONE SEARCH, sec 1287 step 1: a conversation's
 * lines, the kept stickers and the contacts, each a `search/search.h` store,
 * and `list search` over them -- this host's own, for its own user. Asking
 * another host, and merging, are the next steps; a store here already
 * scores an item from the item and the query alone, and keys it by the id
 * every host knows it by, so its answers merge.
 *
 *     list search [in STORE] [after CURSOR] WORDS
 *
 * WORDS the rest of the line, as `list sticker match` takes them. STORE
 * `lines`, `stickers` or `contacts`, repeatable; none asks all. CURSOR the
 * last row of the page before, as `STORE,KEY,SCORE,TIME`. Answered
 *
 *     ok COUNT MORE STORE,KEY,SCORE,TIME,SNIPPET ...
 *
 * KEY in hex, SNIPPET escaped; as many rows as a reply holds, MORE 1 when
 * there are more past them, which the last row's cursor asks for.
 *
 * KEYS: a line, its conversation's key and the id it is known by on every
 * host (`fzn_node_messages_shared_id`); a sticker, its pack's root and its
 * id, big endian; a contact, its root key.
 */
#ifndef FZN_NODE_SEARCH_H
#define FZN_NODE_SEARCH_H

#include <stddef.h>
#include <stdint.h>

#include "../search/search.h"
#include "../local/vocabulary.h"
#include "../chain/authz.h"
#include "../persist/persist.h"

struct fzn_node_messages;

typedef struct fzn_node_search {
	struct fzn_node_messages *messages; /* NULL: no lines store */
	const fzn_persist_ops_t *contacts;  /* NULL: no contacts store */
	/* ONE MORE STORE, a subsystem's own -- the kept stickers', from
	 * `fzn_node_stickers_search` -- so this module links none of them. */
	fzn_search_store_t extra;
} fzn_node_search_t;

#define FZN_NODE_SEARCH_STORES 3u

/* THIS NODE'S STORES, those it has, into `out`: how many. */
size_t fzn_node_search_stores(fzn_node_search_t *s, fzn_search_store_t out[FZN_NODE_SEARCH_STORES]);

/* `list search ...`, this node's own user's alone. 0 for a request not
 * this verb's. */
size_t fzn_node_search_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request, char *reply,
                             size_t cap);

#endif /* FZN_NODE_SEARCH_H */
