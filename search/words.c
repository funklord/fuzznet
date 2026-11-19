/* Words as every search reads them, sec 1287: lifted from the sticker
 * matcher, sec 1272. */
#include "words.h"

#include <string.h>

void fzn_search_words_of(const char *s, size_t n, fzn_search_words_t *w)
{
	size_t i, used = 0, start = 0;
	int in = 0;

	w->n = 0;
	w->open_end = 0;
	if (n > FZN_SEARCH_WORDS_BYTES)
		s += n - FZN_SEARCH_WORDS_BYTES, n = FZN_SEARCH_WORDS_BYTES;
	for (i = 0; i <= n; i++) {
		const unsigned char c = i < n ? (unsigned char)s[i] : ' ';

		if (c == '\'') {
			continue;
		}
		if (c == 0xe2u && i + 2u < n && (unsigned char)s[i + 1u] == 0x80u && (unsigned char)s[i + 2u] == 0x99u) {
			i += 2u;
			continue;
		}
		if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || c >= 0x80u) {
			if (!in) {
				in = 1;
				start = used;
			}
			if (used < FZN_SEARCH_WORDS_BYTES)
				w->buf[used++] = (char)((c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c);
			if (i + 1u == n)
				w->open_end = 1;
			continue;
		}
		if (in) {
			in = 0;
			if (w->n == FZN_SEARCH_WORDS_MAX) {
				memmove(w->at, w->at + 1, (FZN_SEARCH_WORDS_MAX - 1u) * sizeof(w->at[0]));
				memmove(w->len, w->len + 1, (FZN_SEARCH_WORDS_MAX - 1u) * sizeof(w->len[0]));
				w->n--;
			}
			w->at[w->n] = start;
			w->len[w->n++] = used - start;
		}
	}
}

/* A WORD'S PLAIN FORM's length: a closing -ing, -ed, -es or -s let go
 * where enough of the word is left to still be one. */
static size_t stem_len(const char *w, size_t n)
{
	if (n > 5u && !memcmp(w + n - 3u, "ing", 3u))
		return n - 3u;
	if (n > 4u && !memcmp(w + n - 2u, "ed", 2u))
		return n - 2u;
	if (n > 4u && !memcmp(w + n - 2u, "es", 2u))
		return n - 2u;
	if (n > 3u && w[n - 1u] == 's' && w[n - 2u] != 's')
		return n - 1u;
	return n;
}

int fzn_search_same_word(const char *a, size_t an, const char *b, size_t bn)
{
	size_t as, bs;

	if (an == bn && !memcmp(a, b, an))
		return 1;
	as = stem_len(a, an);
	bs = stem_len(b, bn);
	return as == bs && !memcmp(a, b, as);
}

/* WORDS TOO COMMON TO SAY WHAT A TEXT IS about. */
int fzn_search_common_word(const char *w, size_t n)
{
	static const char *const COMMON[] = { "a",  "an", "the", "and", "or", "of", "to", "in",
		                              "on", "at", "is", "it",  "its", "with", "for", "very" };
	size_t i;

	for (i = 0; i < sizeof(COMMON) / sizeof(COMMON[0]); i++)
		if (strlen(COMMON[i]) == n && !memcmp(COMMON[i], w, n))
			return 1;
	return 0;
}

unsigned fzn_search_score(const fzn_search_words_t *q, const char *text, size_t text_len)
{
	static fzn_search_words_t t;
	size_t i, j, telling = 0, found = 0, run = 0, best_run = 0, prev = 0;
	unsigned score = 0;
	int all_common = 1;

	if (!q || !q->n || !text)
		return 0;
	fzn_search_words_of(text, text_len, &t);
	t.open_end = 0;
	for (i = 0; i < q->n; i++)
		if (!fzn_search_common_word(q->buf + q->at[i], q->len[i]))
			all_common = 0;
	for (i = 0; i < q->n; i++) {
		const char *w = q->buf + q->at[i];
		const size_t wl = q->len[i];
		const int last_open = i + 1u == q->n && q->open_end;
		const int counts = all_common || !fzn_search_common_word(w, wl);
		unsigned got = 0;
		size_t where = 0;

		for (j = 0; j < t.n && !got; j++) {
			if (fzn_search_same_word(w, wl, t.buf + t.at[j], t.len[j]))
				got = 100u, where = j;
			else if (last_open && (wl >= 2u || q->n >= 2u) && wl < t.len[j] && !memcmp(w, t.buf + t.at[j], wl))
				got = 60u, where = j;
		}
		if (counts) {
			telling++;
			if (!got)
				return 0;
			found++;
		}
		score += got;
		/* IN ORDER, SIDE BY SIDE: the query's words standing together. */
		run = got && i && where == prev + 1u ? run + 1u : got ? 1u : 0u;
		if (run > best_run)
			best_run = run;
		if (got)
			prev = where;
	}
	if (!telling || found < telling)
		return 0;
	return score + (q->n > 1u && best_run == q->n ? 50u : 0u);
}
