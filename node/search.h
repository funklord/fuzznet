/*
 * THIS NODE'S STORES FOR THE ONE SEARCH, sec 1287: a conversation's lines,
 * the kept stickers and the contacts, each a `search/search.h` store; `list
 * search` over them, this host's own; and the search of every host of this
 * user (steps 2 and 3) -- a store here scores an item from the item and the
 * query alone, and keys it by the id every host knows it by, so the hosts'
 * answers merge.
 *
 *     list search [with CONTACT] [in STORE] [after CURSOR] WORDS
 *     fetch search [with CONTACT] [in STORE] [after CURSOR] WORDS
 *                                                      ok ASKED
 *     get search                                       ok COUNT MORE ASKED ANSWERED LATE ROWS
 *
 * WORDS the rest of the line, as `list sticker match` takes them. STORE
 * `lines`, `stickers`, `notes`, `files` or `contacts`, repeatable; none asks all. CURSOR the
 * last row of the page before, as `STORE,KEY,SCORE,TIME`. Answered
 *
 *     ok COUNT MORE STORE,KEY,SCORE,TIME,SNIPPET ...
 *
 * KEY in hex, SNIPPET escaped; as many rows as a reply holds, MORE 1 when
 * there are more past them, which the last row's cursor asks for.
 *
 * `fetch search` searches this host's stores at once and asks each other
 * host of this user that a round reaches, at most FZN_NODE_SEARCH_HOSTS_MAX,
 * ASKED how many; `get search` says the page merged from this host's hits
 * and every answer come, with ASKED, ANSWERED and LATE (no answer by the
 * deadline): the page is everything only once ANSWERED is ASKED. One search
 * is held at a time; the next page is `fetch search after CURSOR` again.
 *
 * `with CONTACT`, by its name here (sec 1292), searches what this user and
 * that contact share: this host's stores run as the contact -- their
 * conversation, the groups both are in, the notes shared with it -- and
 * the contact's hosts are asked in place of this user's own, each running
 * its stores as this user. The words go to that contact and nobody else.
 *
 * KEYS: a line, its conversation's key and the id it is known by on every
 * host (`fzn_node_messages_shared_id`) -- a group's id, or for a contact's
 * conversation this user's root XOR the contact's, the same on both
 * users' hosts (sec 1294), whose XOR with this user's root is the contact;
 * a sticker, its pack's root and its id, big endian; a note, its id; a
 * library file, its root; a contact, its root key.
 */
#ifndef FZN_NODE_SEARCH_H
#define FZN_NODE_SEARCH_H

#include <stddef.h>
#include <stdint.h>

#include "../search/search.h"
#include "../search/remote.h"
#include "../local/vocabulary.h"
#include "../chain/authz.h"
#include "../persist/persist.h"

struct fzn_node_messages;

/* How many subsystems' stores a node's search holds besides its own. */
#define FZN_NODE_SEARCH_EXTRA 4u

typedef struct fzn_node_search {
	struct fzn_node_messages *messages; /* NULL: no lines store */
	/* THIS USER'S ROOT KEY, through the pointer that holds it (fuzznetd's
	 * pinned root, which a cut-over re-points): what keys a conversation
	 * with a contact alike on both users' hosts (sec 1294). NULL, or
	 * pointing at NULL, keys it by the contact as before. */
	const uint8_t *const *user;
	const fzn_persist_ops_t *contacts;  /* NULL: no contacts store */
	/* SUBSYSTEMS' OWN STORES -- the kept stickers', from
	 * `fzn_node_stickers_search`; the notes', from `fzn_node_notes_search`
	 * -- so this module links none of them. An empty slot's `run` is NULL. */
	fzn_search_store_t extra[FZN_NODE_SEARCH_EXTRA];
	/* THIS USER'S OTHER HOSTS ASKED `ask`, the daemon's -- or, `with` a
	 * contact's root key, that contact's hosts alone (sec 1292), or a
	 * shared group's member's, the hosts the group lists (sec 1406): how many
	 * it sent to, each answer handed to `fzn_node_search_answered` with
	 * `generation`, or NULL by the deadline. NULL asks nobody. */
	size_t (*ask_hosts)(void *ctx, const uint8_t *ask, size_t len, const uint8_t *with, unsigned generation);
	void *ask_hosts_ctx;
} fzn_node_search_t;

/* The most other hosts one search asks. */
#define FZN_NODE_SEARCH_HOSTS_MAX 8u

/* AN ANSWER TO THE SEARCH OF `generation`, or NULL for one that did not
 * come: taken into the search held, or let go when a later one replaced
 * it. */
void fzn_node_search_answered(fzn_node_search_t *s, unsigned generation, const uint8_t *answer, size_t len);

/* ANOTHER HOST'S ASK answered from this node's stores, run for `asker`:
 * NULL for this user's own (another host of the estate), else a
 * contact's root key, each store then answering only what that contact
 * reads here (sec 1291). The answer's length in `reply`, or 0. Who may
 * ask is the caller's (`fzn_node_relay_refuse_search`). */
size_t fzn_node_search_remote(fzn_node_search_t *s, const uint8_t *asker, const uint8_t *request, size_t len,
                              uint8_t *reply, size_t cap);

#define FZN_NODE_SEARCH_STORES (2u + FZN_NODE_SEARCH_EXTRA)

/* THIS NODE'S STORES, those it has, into `out`: how many. */
size_t fzn_node_search_stores(fzn_node_search_t *s, fzn_search_store_t out[FZN_NODE_SEARCH_STORES]);

/* THE SEARCHES, by an ask's bytes as one host sends another (`search/
 * remote.h`), for the verbs and the binary leg alike, `with` a contact's
 * root key or NULL (sec 1292). LIST: this host's stores alone, into
 * `hits`, `*count` and `*more`; 1, or 0 for an ask that will not read.
 * FETCH: the search held from now on, this host's hits and the hosts
 * asked, `*asked` how many; 1, or 0. HELD: the search held, merged as far
 * as answered, with the hosts asked, answered and late; 0 for none. */
int fzn_node_search_list(fzn_node_search_t *s, const uint8_t *ask, size_t len, const uint8_t *with,
                         fzn_search_hit_t *hits, size_t *count, int *more);
int fzn_node_search_fetch(fzn_node_search_t *s, const uint8_t *ask, size_t len, const uint8_t *with,
                          size_t *asked);
int fzn_node_search_held(fzn_node_search_t *s, fzn_search_hit_t *hits, size_t *count, int *more, size_t *asked,
                         size_t *answered, size_t *late);

/* Whether `key` is a contact's root key here. */
int fzn_node_search_is_contact(const fzn_node_search_t *s, const uint8_t key[FZN_PUBKEY_LEN]);

/* `list search ...`, this node's own user's alone. 0 for a request not
 * this verb's. */
size_t fzn_node_search_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request, char *reply,
                             size_t cap);

#endif /* FZN_NODE_SEARCH_H */
