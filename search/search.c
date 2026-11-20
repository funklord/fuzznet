/* One search over every store, sec 1287: the engine. */
#include "search.h"

#include <string.h>

int fzn_search_query_init(fzn_search_query_t *q, const char *words, size_t len, size_t k)
{
	if (!q || !words || k == 0u || k > FZN_SEARCH_K_MAX)
		return 0;
	memset(q, 0, sizeof(*q));
	fzn_search_words_of(words, len, &q->words);
	q->k = k;
	return q->words.n != 0u;
}

int fzn_search_before(const fzn_search_hit_t *a, const fzn_search_hit_t *b)
{
	int c;
	size_t n;

	if (a->score != b->score)
		return a->score > b->score;
	if (a->time_ms != b->time_ms)
		return a->time_ms > b->time_ms;
	if ((c = strcmp(a->store, b->store)) != 0)
		return c < 0;
	n = a->key_len < b->key_len ? a->key_len : b->key_len;
	if ((c = memcmp(a->key, b->key, n)) != 0)
		return c < 0;
	return a->key_len < b->key_len;
}

static int same_item(const fzn_search_hit_t *a, const fzn_search_hit_t *b)
{
	return a->key_len == b->key_len && !strcmp(a->store, b->store) && !memcmp(a->key, b->key, a->key_len);
}

/* THE PAGE BEING GATHERED: at most k + 1 hits kept in the one order, the
 * last only to say there is more. */
struct gather {
	const fzn_search_query_t *q;
	fzn_search_hit_t keep[FZN_SEARCH_K_MAX + 1u];
	size_t n;
	int more;
};

static int asked(const fzn_search_query_t *q, const char *store)
{
	size_t i;

	if (!q->n_stores)
		return 1;
	for (i = 0; i < q->n_stores; i++)
		if (q->stores[i] && !strcmp(q->stores[i], store))
			return 1;
	return 0;
}

static int take(void *ctx, const fzn_search_hit_t *h)
{
	struct gather *g = ctx;
	const fzn_search_query_t *q = g->q;
	const size_t cap = q->k + 1u;
	size_t i, at;

	if (!h || !h->score || h->key_len > FZN_SEARCH_KEY_MAX || (q->from_ms && h->time_ms < q->from_ms)
	    || (q->to_ms && h->time_ms > q->to_ms) || (q->after && !fzn_search_before(q->after, h))
	    || (q->keep && !q->keep(q->keep_ctx, h)))
		return 1;
	/* ONE HIT PER ITEM, its best kept: a worse copy is let go, a better one
	 * takes the place of the one held. */
	for (i = 0; i < g->n; i++) {
		if (!same_item(&g->keep[i], h))
			continue;
		if (!fzn_search_before(h, &g->keep[i]))
			return 1;
		memmove(&g->keep[i], &g->keep[i + 1u], (g->n - i - 1u) * sizeof(g->keep[0]));
		g->n--;
		break;
	}
	/* ITS PLACE IN THE ONE ORDER; past the k + 1 kept, there is more. */
	for (at = g->n; at > 0u && fzn_search_before(h, &g->keep[at - 1u]); at--)
		;
	if (at >= cap) {
		g->more = 1;
		return 1;
	}
	if (g->n == cap)
		g->more = 1;
	else
		g->n++;
	memmove(&g->keep[at + 1u], &g->keep[at], (g->n - 1u - at) * sizeof(g->keep[0]));
	g->keep[at] = *h;
	return 1;
}

int fzn_search_run(const fzn_search_store_t *stores, size_t n_stores, const fzn_search_query_t *q,
                   const uint8_t *asker, fzn_search_hit_t *out, size_t *count, int *more)
{
	static struct gather g;
	size_t i;
	int ok = 1;

	if (!q || !out || !count || !more || q->k == 0u || q->k > FZN_SEARCH_K_MAX || (n_stores && !stores))
		return 0;
	memset(&g, 0, sizeof(g));
	g.q = q;
	for (i = 0; i < n_stores; i++)
		if (stores[i].name && stores[i].run && asked(q, stores[i].name)
		    && !stores[i].run(stores[i].ctx, q, asker, take, &g))
			ok = 0;
	*count = g.n > q->k ? q->k : g.n;
	*more = g.more || g.n > q->k;
	memcpy(out, g.keep, *count * sizeof(out[0]));
	return ok;
}

int fzn_search_merge(const fzn_search_query_t *q, const fzn_search_hit_t *hits, size_t n, int more_held,
                     fzn_search_hit_t *out, size_t *count, int *more)
{
	static struct gather g;
	fzn_search_query_t unfiltered;
	size_t i;

	if (!q || !out || !count || !more || q->k == 0u || q->k > FZN_SEARCH_K_MAX || (n && !hits))
		return 0;
	/* EACH HOST FILTERED ITS OWN: what it sent carries no facets. */
	unfiltered = *q;
	unfiltered.keep = NULL;
	memset(&g, 0, sizeof(g));
	g.q = &unfiltered;
	for (i = 0; i < n; i++)
		if (asked(q, hits[i].store))
			(void)take(&g, &hits[i]);
	*count = g.n > q->k ? q->k : g.n;
	*more = more_held || g.more || g.n > q->k;
	memcpy(out, g.keep, *count * sizeof(out[0]));
	return 1;
}

int fzn_search_facet_add(fzn_search_hit_t *hit, const char *dim, const char *value, size_t value_len)
{
	fzn_search_facet_t *f;
	size_t dim_len = dim ? strlen(dim) : 0u;

	if (!hit || !dim_len || dim_len > FZN_SEARCH_FACET_DIM_MAX || (value_len && !value)
	    || value_len > FZN_SEARCH_FACET_VALUE_MAX || hit->n_facets >= FZN_SEARCH_FACETS_MAX)
		return 0;
	f = &hit->facets[hit->n_facets++];
	memcpy(f->dim, dim, dim_len);
	f->dim[dim_len] = '\0';
	f->dim_len = dim_len;
	if (value_len)
		memcpy(f->value, value, value_len);
	f->value[value_len] = '\0';
	f->value_len = value_len;
	return 1;
}

/* A CHARACTER'S START: no UTF-8 continuation byte. */
static int starts(const char *s, size_t i)
{
	return ((unsigned char)s[i] & 0xC0u) != 0x80u;
}

void fzn_search_snippet(const fzn_search_query_t *q, const char *text, size_t len, fzn_search_hit_t *hit)
{
	size_t from = 0, to, i, j, word_at = 0;
	int found = 0;

	if (!hit)
		return;
	hit->snippet_len = 0;
	hit->snippet[0] = '\0';
	if (!text || !len)
		return;
	if (len > FZN_SEARCH_SNIPPET_MAX && q && q->words.n) {
		/* THE FIRST QUERY WORD THE TEXT HOLDS, found by byte as it reads. */
		for (j = 0; j < q->words.n && !found; j++)
			for (i = 0; i + q->words.len[j] <= len && !found; i++) {
				size_t k;

				for (k = 0; k < q->words.len[j]; k++) {
					char c = text[i + k];

					if (c >= 'A' && c <= 'Z')
						c = (char)(c - 'A' + 'a');
					if (c != q->words.buf[q->words.at[j] + k])
						break;
				}
				if (k == q->words.len[j])
					found = 1, word_at = i;
			}
		if (found && word_at > FZN_SEARCH_SNIPPET_MAX / 3u)
			from = word_at - FZN_SEARCH_SNIPPET_MAX / 3u;
	}
	if (len - from > FZN_SEARCH_SNIPPET_MAX && from + FZN_SEARCH_SNIPPET_MAX > len)
		from = len - FZN_SEARCH_SNIPPET_MAX;
	while (from < len && !starts(text, from))
		from++;
	to = len - from > FZN_SEARCH_SNIPPET_MAX ? from + FZN_SEARCH_SNIPPET_MAX : len;
	while (to > from && to < len && !starts(text, to))
		to--;
	memcpy(hit->snippet, text + from, to - from);
	hit->snippet_len = to - from;
	hit->snippet[hit->snippet_len] = '\0';
}
