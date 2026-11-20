/*
 * ONE SEARCH ASKED OF ANOTHER HOST, and its answer, sec 1287 step 2: the
 * query and the hits as `search/search_wire.situ` lays them out
 * (FZN_CMD_SEARCH, 26), and the host's whole part -- an ask read, its own
 * stores run, its best K after the cursor written back -- in one call, so
 * a test holds it without a daemon.
 *
 * WHO MAY ASK is the caller's to decide before it calls: step 2 answers
 * another host of this host's own user, whose stores are all that user's.
 * A store that holds anybody else's (a group's, a contact's, step 4) reads
 * `asker` and emits only what that user may read here.
 */
#ifndef FZN_SEARCH_REMOTE_H
#define FZN_SEARCH_REMOTE_H

#include <stddef.h>
#include <stdint.h>

#include "search.h"
#include "../facet/facet.h"
#include "filter.h"

/* The most words an ask carries, as typed, and the most stores it names. */
#define FZN_SEARCH_TEXT_MAX 255u
#define FZN_SEARCH_ASK_STORES_MAX 8u
/* THE LONGEST ANSWER: K_MAX hits at their longest, and its head. */
#define FZN_SEARCH_ANSWER_MAX                                                                          \
	(4u + FZN_SEARCH_K_MAX * (1u + FZN_SEARCH_STORE_NAME_MAX + 1u + FZN_SEARCH_KEY_MAX + 4u + 8u + 1u \
	                          + FZN_SEARCH_SNIPPET_MAX))


/* AN ASK READ: its query, with the room what the query points at lives in
 * -- the filter's bytes and the expression decoded from them included, so
 * it is not to be copied once a filter is set: the query points into it. */
typedef struct fzn_search_ask {
	fzn_search_query_t query;
	char words[FZN_SEARCH_TEXT_MAX + 1u];
	size_t words_len;
	char names[FZN_SEARCH_ASK_STORES_MAX][FZN_SEARCH_STORE_NAME_MAX + 1u];
	const char *stores[FZN_SEARCH_ASK_STORES_MAX];
	fzn_search_hit_t after;
	uint8_t filter[FZN_SEARCH_FILTER_MAX];
	size_t filter_len;
	fzn_facet_term_t pos[FZN_SEARCH_FILTER_TERMS], neg[FZN_SEARCH_FILTER_TERMS];
	fzn_facet_node_t members[FZN_SEARCH_FILTER_MEMBERS];
	fzn_facet_expr_t expr;
} fzn_search_ask_t;

/* THE FILTER `filter` SET ON `a`, sec 1319: its bytes kept, decoded, and
 * `a->query.keep` installed to hold each hit's facets to it
 * (`fzn_facet_entity_matches`). 1; 0 for bytes that are no expression, more
 * terms or members than room, or a RANGE, which one hit cannot answer.
 * None (`len` 0) clears it. */
int fzn_search_ask_filter(fzn_search_ask_t *a, const uint8_t *filter, size_t len);

/* AN ASK for `q`, whose words were `words` as typed, into `out`: its
 * length, or 0 for words past FZN_SEARCH_TEXT_MAX or none, more than
 * FZN_SEARCH_ASK_STORES_MAX stores, or a name past its bound. */
size_t fzn_search_ask_write(const char *words, size_t words_len, const fzn_search_query_t *q, uint8_t *out,
                            size_t cap);

/* `len` bytes READ AS AN ASK into `out`, `out->query` ready to run: 1, or
 * 0 for anything else, a store name with a byte below a space, or a
 * cursor half there. */
int fzn_search_ask_read(const uint8_t *in, size_t len, fzn_search_ask_t *out);

/* AN ANSWER of `n` hits, at most FZN_SEARCH_K_MAX, and whether there are
 * MORE, into `out`: its length, or 0 where it does not fit. */
size_t fzn_search_answer_write(const fzn_search_hit_t *hits, size_t n, int more, uint8_t *out, size_t cap);

/* `len` bytes READ AS AN ANSWER: its hits into `hits`, at most `cap`, with
 * `*n` and `*more`: 1, or 0 for anything else, or more hits than `cap`. */
int fzn_search_answer_read(const uint8_t *in, size_t len, fzn_search_hit_t *hits, size_t cap, size_t *n,
                           int *more);

/* THE HOST'S PART: `ask` read, `stores` run for `asker`, the answer
 * written into `out`. Its length, or 0 for an ask that does not read or a
 * store that would not. */
size_t fzn_search_answer_ask(const fzn_search_store_t *stores, size_t n_stores, const uint8_t *ask,
                             size_t ask_len, const uint8_t *asker, uint8_t *out, size_t cap);

#endif /* FZN_SEARCH_REMOTE_H */
