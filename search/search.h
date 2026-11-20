/*
 * ONE SEARCH OVER EVERY STORE, sec 1287: the query, the hit, the store each
 * subsystem registers, and the engine that merges what they find.
 *
 * A STORE is a provider: a name and one call that, given the query and who
 * asks, emits its hits. The engine knows no store. A search on this host is
 * the distributed one with one host answering, so there is one merge, one
 * order and one cursor for both: every host answers "your best K after this
 * point", and the merge of those answers is the next page.
 *
 * ONE TOTAL ORDER: score descending, then time descending, then the store's
 * name, then the key -- bytewise. A CURSOR is the last hit of a page; the
 * next page is the best K strictly after it. An offset would mean nothing
 * across hosts that hold different things.
 *
 * ONE HIT PER ITEM: a KEY is the id an item has on every host that holds it
 * (a group line's shared id, sec 1285; a pack's root and a sticker's id), so
 * the same item emitted twice -- by two stores' passes or two hosts -- is
 * one hit, its best score kept.
 *
 * A FILTER SELECTS BY WHAT A STORE TAGS A HIT WITH (sec 1319): each hit
 * carries its FACETS, dimension and value as the store chooses them (a
 * conversation, a direction, a pack), and a query may carry a FILTER, a
 * `facet` expression over them -- facet being the one filter language,
 * opaque about what it classifies, so no second one is written. The engine
 * knows no facet: it asks the query's KEEP of each hit, which whoever reads
 * the filter installs (`search/remote.h`). A filter runs where the data is;
 * hits merged from other hosts carry no facets and were filtered there.
 *
 * A STORE SCORES AN ITEM FROM THE ITEM AND THE QUERY ALONE -- never from
 * what else a host holds -- so every host that holds it gives it one score
 * and one time, and a copy can never stand after the cursor its twin was
 * already shown before. A score that varied by host would repeat items
 * across pages.
 */
#ifndef FZN_SEARCH_H
#define FZN_SEARCH_H

#include <stddef.h>
#include <stdint.h>

#include "words.h"

#define FZN_SEARCH_STORE_NAME_MAX 16u
#define FZN_SEARCH_KEY_MAX 48u
#define FZN_SEARCH_SNIPPET_MAX 120u
/* A HIT'S FACETS: at most four, a dimension's name and a value of at most
 * 64 bytes, each a node `facet` selects by -- closed upward by the store
 * where its dimension is a tree (`fzn_facet_entity_matches`). */
#define FZN_SEARCH_FACETS_MAX 4u
#define FZN_SEARCH_FACET_DIM_MAX 16u
#define FZN_SEARCH_FACET_VALUE_MAX 64u
/* A FILTER'S MOST BYTES, as `facet/codec.h` encodes an expression. */
#define FZN_SEARCH_FILTER_MAX 512u
/* THE MOST HITS A QUERY ASKS ONE HOST FOR, and so the most one page holds. */
#define FZN_SEARCH_K_MAX 50u

typedef struct fzn_search_facet {
	char dim[FZN_SEARCH_FACET_DIM_MAX + 1u];
	size_t dim_len;
	char value[FZN_SEARCH_FACET_VALUE_MAX + 1u];
	size_t value_len;
} fzn_search_facet_t;

typedef struct fzn_search_hit {
	char store[FZN_SEARCH_STORE_NAME_MAX + 1u];
	uint8_t key[FZN_SEARCH_KEY_MAX];
	size_t key_len;
	unsigned score;
	uint64_t time_ms;
	/* WHAT THE STORE SHOWS OF IT, its own words, at most 120 bytes. */
	char snippet[FZN_SEARCH_SNIPPET_MAX + 1u];
	size_t snippet_len;
	/* WHAT A FILTER CAN SELECT IT BY, here only: never carried to another
	 * host, which filters its own. */
	fzn_search_facet_t facets[FZN_SEARCH_FACETS_MAX];
	size_t n_facets;
} fzn_search_hit_t;

typedef struct fzn_search_query {
	/* THE WORDS ASKED, read once into `words` by `fzn_search_query_init`. */
	fzn_search_words_t words;
	/* A WINDOW in ms by the item's time; 0 leaves that end open. */
	uint64_t from_ms, to_ms;
	/* THE STORES ASKED, by name; none asks every store. */
	const char *const *stores;
	size_t n_stores;
	/* THE MOST HITS WANTED, 1 to FZN_SEARCH_K_MAX. */
	size_t k;
	/* THE LAST HIT OF THE PAGE BEFORE, or NULL for the first page. */
	const fzn_search_hit_t *after;
	/* THE FILTER, `facet/codec.h`'s encoding of an expression over the
	 * hits' facets, carried as it is to every host asked; none when 0. */
	const uint8_t *filter;
	size_t filter_len;
	/* WHETHER A HIT IS KEPT, from the filter: installed by whoever read it
	 * (`fzn_search_ask_filter`), NULL keeping every hit. */
	int (*keep)(void *ctx, const fzn_search_hit_t *hit);
	void *keep_ctx;
} fzn_search_query_t;

/* A STORE'S HIT, handed to the engine: 1 to go on, 0 when the engine wants
 * no more (it never does before the store is done; a store may stop early on
 * its own budget). */
typedef int (*fzn_search_emit_t)(void *ctx, const fzn_search_hit_t *hit);

typedef struct fzn_search_store {
	const char *name;
	/* EVERY HIT THIS STORE HOLDS FOR `q`, that `asker` may read, emitted in
	 * any order: the engine orders, windows and pages them. `asker` is the
	 * user who asks -- NULL for this host's own, whose every store is; else
	 * another user's root key -- and a store emits nothing that user may
	 * not read here. 1 once done, 0 when the store would not read, and 2
	 * when it stopped short on its own budget with items it never looked at
	 * (sec 1328) -- which no next page reaches, so the answer is PARTIAL,
	 * not merely MORE. */
	int (*run)(void *ctx, const fzn_search_query_t *q, const uint8_t *asker, fzn_search_emit_t emit,
	           void *emit_ctx);
	void *ctx;
} fzn_search_store_t;

/* THE QUERY FOR `words`, `len` bytes, everything else open: `k` hits. 1, or
 * 0 for no word to search by or a `k` out of range. */
int fzn_search_query_init(fzn_search_query_t *q, const char *words, size_t len, size_t k);

/* A FACET ON `hit`, as a store tags it: 1, or 0 where it already holds
 * FZN_SEARCH_FACETS_MAX or a part is past its bound. */
int fzn_search_facet_add(fzn_search_hit_t *hit, const char *dim, const char *value, size_t value_len);

/* Whether hit `a` comes before hit `b` in the one order. */
int fzn_search_before(const fzn_search_hit_t *a, const fzn_search_hit_t *b);

/* SEARCH `stores`, as `asker`: the best `q->k` hits after `q->after`, in the
 * one order, each item once, into `out` (room for `q->k`). `*count` how many;
 * `*more` 1 when there are hits past them. 1, or 0 for a store that would not
 * read -- the hits of the others still given. */
int fzn_search_run(const fzn_search_store_t *stores, size_t n_stores, const fzn_search_query_t *q,
                   const uint8_t *asker, fzn_search_hit_t *out, size_t *count, int *more);
/* THE SAME, saying whether a store stopped short (sec 1328): `*partial` 1
 * when one did, so the page is not everything this host holds -- however
 * it is paged. */
int fzn_search_run_partial(const fzn_search_store_t *stores, size_t n_stores, const fzn_search_query_t *q,
                           const uint8_t *asker, fzn_search_hit_t *out, size_t *count, int *more,
                           int *partial);

/* HITS GATHERED ELSEWHERE, merged as `fzn_search_run` merges its stores'
 * -- the stores asked, the window, the cursor, one hit per item, the one
 * order, K; not the filter, which each host ran on its own -- into `out`:
 * the page several hosts' answers make. MORE_HELD
 * where any of them said it holds more past what it sent, which a merge of
 * what was sent cannot see. 1, or 0 for a query that cannot run. */
int fzn_search_merge(const fzn_search_query_t *q, const fzn_search_hit_t *hits, size_t n, int more_held,
                     fzn_search_hit_t *out, size_t *count, int *more);

/* A SNIPPET OF `text`: the window of at most FZN_SEARCH_SNIPPET_MAX bytes
 * around the first word of `q` it holds, cut at a character's start at each
 * end; the whole text where it fits. Into `hit`. */
void fzn_search_snippet(const fzn_search_query_t *q, const char *text, size_t len, fzn_search_hit_t *hit);

#endif /* FZN_SEARCH_H */
