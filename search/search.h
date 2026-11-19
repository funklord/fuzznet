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
/* THE MOST HITS A QUERY ASKS ONE HOST FOR, and so the most one page holds. */
#define FZN_SEARCH_K_MAX 50u

typedef struct fzn_search_hit {
	char store[FZN_SEARCH_STORE_NAME_MAX + 1u];
	uint8_t key[FZN_SEARCH_KEY_MAX];
	size_t key_len;
	unsigned score;
	uint64_t time_ms;
	/* WHAT THE STORE SHOWS OF IT, its own words, at most 120 bytes. */
	char snippet[FZN_SEARCH_SNIPPET_MAX + 1u];
	size_t snippet_len;
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
} fzn_search_query_t;

/* A STORE'S HIT, handed to the engine: 1 to go on, 0 when the engine wants
 * no more (it never does before the store is done; a store may stop early on
 * its own budget). */
typedef int (*fzn_search_emit_t)(void *ctx, const fzn_search_hit_t *hit);

typedef struct fzn_search_store {
	const char *name;
	/* EVERY HIT THIS STORE HOLDS FOR `q`, that `asker` may read, emitted in
	 * any order: the engine orders, windows and pages them. `asker` is the
	 * user who asks -- this host's own, or a peer's root when another host
	 * asks -- and a store emits nothing that user may not read here. 1 once
	 * done, 0 when the store would not read. */
	int (*run)(void *ctx, const fzn_search_query_t *q, const uint8_t *asker, fzn_search_emit_t emit,
	           void *emit_ctx);
	void *ctx;
} fzn_search_store_t;

/* THE QUERY FOR `words`, `len` bytes, everything else open: `k` hits. 1, or
 * 0 for no word to search by or a `k` out of range. */
int fzn_search_query_init(fzn_search_query_t *q, const char *words, size_t len, size_t k);

/* Whether hit `a` comes before hit `b` in the one order. */
int fzn_search_before(const fzn_search_hit_t *a, const fzn_search_hit_t *b);

/* SEARCH `stores`, as `asker`: the best `q->k` hits after `q->after`, in the
 * one order, each item once, into `out` (room for `q->k`). `*count` how many;
 * `*more` 1 when there are hits past them. 1, or 0 for a store that would not
 * read -- the hits of the others still given. */
int fzn_search_run(const fzn_search_store_t *stores, size_t n_stores, const fzn_search_query_t *q,
                   const uint8_t *asker, fzn_search_hit_t *out, size_t *count, int *more);

/* HITS GATHERED ELSEWHERE, merged as `fzn_search_run` merges its stores'
 * -- the stores asked, the window, the cursor, one hit per item, the one
 * order, K -- into `out`: the page several hosts' answers make. MORE_HELD
 * where any of them said it holds more past what it sent, which a merge of
 * what was sent cannot see. 1, or 0 for a query that cannot run. */
int fzn_search_merge(const fzn_search_query_t *q, const fzn_search_hit_t *hits, size_t n, int more_held,
                     fzn_search_hit_t *out, size_t *count, int *more);

/* A SNIPPET OF `text`: the window of at most FZN_SEARCH_SNIPPET_MAX bytes
 * around the first word of `q` it holds, cut at a character's start at each
 * end; the whole text where it fits. Into `hit`. */
void fzn_search_snippet(const fzn_search_query_t *q, const char *text, size_t len, fzn_search_hit_t *hit);

#endif /* FZN_SEARCH_H */
