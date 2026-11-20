/* A search filter as typed: search/filter.h, sec 1324. */
#include "filter.h"

#include <string.h>

#include "../facet/codec.h"

int fzn_search_filter_word(fzn_search_filter_words_t *f, int negated, const char *word, size_t n)
{
	fzn_facet_term_t *t;
	const uint8_t *w = (const uint8_t *)word;
	const uint8_t *eq = w ? memchr(w, '=', n) : NULL, *v, *end = w + n;
	size_t dim_len, first = f->n_members;

	if (!f || !eq || eq == w || eq + 1 == end || (negated ? f->n_neg : f->n_pos) == FZN_SEARCH_FILTER_TERMS)
		return 0;
	dim_len = (size_t)(eq - w);
	t = negated ? &f->neg[f->n_neg++] : &f->pos[f->n_pos++];
	memset(t, 0, sizeof(*t));
	for (v = eq + 1; v < end;) {
		const uint8_t *bar = memchr(v, '|', (size_t)(end - v)), *stop = bar ? bar : end;

		if (stop == v || f->n_members == FZN_SEARCH_FILTER_MEMBERS)
			return 0;
		f->members[f->n_members++] = (fzn_facet_node_t){ w, dim_len, v, (size_t)(stop - v) };
		v = bar ? bar + 1 : end;
	}
	if (f->n_members - first == 1u) {
		t->kind = FZN_FACET_PREFIX;
		t->node = f->members[--f->n_members];
	} else {
		t->kind = FZN_FACET_ALT;
		t->node.dim = w; /* F8: an alternation's dimension, its members' */
		t->node.dim_len = dim_len;
		t->members = &f->members[first];
		t->member_count = f->n_members - first;
	}
	return 1;
}

size_t fzn_search_filter_encode(fzn_search_filter_words_t *f, uint8_t *out, size_t cap)
{
	uint8_t scratch[2u * 600u];
	fzn_facet_expr_t e;
	size_t len = 0;

	if (!f || !out || !f->n_pos)
		return 0;
	if (fzn_facet_normalize(f->pos, &f->n_pos, f->neg, &f->n_neg) != FZN_FACET_OK
	    || fzn_facet_expr_sort(f->pos, &f->n_pos, f->neg, &f->n_neg, scratch, sizeof(scratch)) != FZN_FACET_OK)
		return 0;
	e = (fzn_facet_expr_t){ f->pos, f->n_pos, f->neg, f->n_neg };
	return fzn_facet_expr_encode(&e, out, cap, &len) == FZN_FACET_OK ? len : 0u;
}

size_t fzn_search_filter_line(const char *line, size_t len, uint8_t *out, size_t cap)
{
	static fzn_search_filter_words_t f;
	size_t at = 0;

	if (!line || !out)
		return 0;
	memset(&f, 0, sizeof(f));
	for (;;) {
		size_t w, n, v;
		int negated;

		while (at < len && line[at] == ' ')
			at++;
		if (at == len)
			break;
		for (w = at; at < len && line[at] != ' '; at++)
			;
		n = at - w;
		if (!((n == 5u && !memcmp(line + w, "where", 5u)) || (n == 3u && !memcmp(line + w, "not", 3u))))
			return 0;
		negated = n == 3u;
		while (at < len && line[at] == ' ')
			at++;
		for (v = at; at < len && line[at] != ' '; at++)
			;
		if (at == v || !fzn_search_filter_word(&f, negated, line + v, at - v))
			return 0;
	}
	return fzn_search_filter_encode(&f, out, cap);
}
