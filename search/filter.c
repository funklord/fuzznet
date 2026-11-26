/* A search filter as typed: search/filter.h, sec 1324. */
#include "filter.h"

#include <string.h>

#include "../facet/codec.h"

int fzn_search_filter_word(fzn_search_filter_words_t *f, int negated, const char *word, size_t n)
{
	fzn_facet_term_t *t;
	const uint8_t *w = (const uint8_t *)word;
	const uint8_t *eq = w ? memchr(w, '=', n) : NULL, *v, *end = w + n;
	size_t dim_len, first;

	if (!f || !eq || eq == w || eq + 1 == end || (negated ? f->n_neg : f->n_pos) == FZN_SEARCH_FILTER_TERMS)
		return 0;
	/* READ AFTER THE CHECK, not in the declaration above it: there a null
	 * `f` was dereferenced before it was refused (gcc -fanalyzer). */
	first = f->n_members;
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

void fzn_search_filter_named_read(fzn_search_filter_named_t *f, const uint8_t *filter, size_t len)
{
	if (!f)
		return;
	f->any = filter && len
	         && fzn_facet_expr_decode(filter, len, f->pos, FZN_SEARCH_FILTER_TERMS, f->neg, FZN_SEARCH_FILTER_TERMS,
	                                  f->members, FZN_SEARCH_FILTER_MEMBERS, &f->expr, NULL)
	                    == FZN_FACET_OK;
}

static int node_names(const fzn_facet_node_t *n, const char *dim, size_t dim_len, const char *value, size_t value_len,
                      int any_value)
{
	return n->dim_len == dim_len && !memcmp(n->dim, dim, dim_len)
	       && (any_value || !value || (n->id_len == value_len && !memcmp(n->id, value, value_len)));
}

static int term_names(const fzn_facet_term_t *t, const char *dim, size_t dim_len, const char *value, size_t value_len)
{
	size_t m;

	if (t->kind != FZN_FACET_ALT)
		return node_names(&t->node, dim, dim_len, value, value_len, t->kind == FZN_FACET_RANGE);
	for (m = 0; m < t->member_count; m++)
		if (node_names(&t->members[m], dim, dim_len, value, value_len, 0))
			return 1;
	return 0;
}

int fzn_search_filter_names(const fzn_search_filter_named_t *f, const char *dim, size_t dim_len, const char *value,
                            size_t value_len)
{
	size_t i;

	if (!f || !f->any || !dim)
		return 0;
	for (i = 0; i < f->expr.pos_count; i++)
		if (term_names(&f->expr.pos[i], dim, dim_len, value, value_len))
			return 1;
	for (i = 0; i < f->expr.neg_count; i++)
		if (term_names(&f->expr.neg[i], dim, dim_len, value, value_len))
			return 1;
	return 0;
}
