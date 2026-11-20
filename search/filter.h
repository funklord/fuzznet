/*
 * A SEARCH FILTER AS A PERSON TYPES IT, sec 1319 and 1324: the words of
 * `where DIM=VALUE` and `not DIM=VALUE` turned into the facet expression a
 * query carries (`search/search.h`'s FILTER). Apart from `search/remote.h`
 * so a client links it with `facet` alone, not the engine.
 */
#ifndef FZN_SEARCH_FILTER_H
#define FZN_SEARCH_FILTER_H

#include <stddef.h>
#include <stdint.h>

#include "../facet/facet.h"

/* A FILTER'S MOST TERMS on each side, and alternation members in all. */
#define FZN_SEARCH_FILTER_TERMS 8u
#define FZN_SEARCH_FILTER_MEMBERS 16u

/* A FILTER AS TYPED, sec 1319 and 1324: each word `DIM=VALUE` -- a term a
 * hit must be at, or with NEGATED one it must not -- `DIM=A|B` for any of
 * several; `fzn_search_filter_word` adds one, 1 or 0 for a word that is
 * none or past the room; `fzn_search_filter_encode` writes them as
 * `facet/codec.h`'s canonical encoding (F16-F19), its length, or 0 -- for
 * no term a hit must be at among them (F14) included. The words are
 * borrowed: they must outlive the encode. Shared by fuzznetd's verb and the
 * client, so a filter is typed one way. */
typedef struct fzn_search_filter_words {
	fzn_facet_term_t pos[FZN_SEARCH_FILTER_TERMS], neg[FZN_SEARCH_FILTER_TERMS];
	fzn_facet_node_t members[FZN_SEARCH_FILTER_MEMBERS];
	size_t n_pos, n_neg, n_members;
} fzn_search_filter_words_t;
int fzn_search_filter_word(fzn_search_filter_words_t *f, int negated, const char *w, size_t n);
size_t fzn_search_filter_encode(fzn_search_filter_words_t *f, uint8_t *out, size_t cap);

/* A FILTER FROM A LINE OF WORDS, as the verb and the client take it:
 * `where DIM=VALUE`, `not DIM=VALUE`, in any order, as `out`'s encoding --
 * its length; 0 for any other word, a `where` or `not` with nothing after,
 * or no `where` at all. `line` is borrowed until the call returns. */
size_t fzn_search_filter_line(const char *line, size_t len, uint8_t *out, size_t cap);

#endif /* FZN_SEARCH_FILTER_H */
