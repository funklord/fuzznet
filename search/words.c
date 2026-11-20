/* Words as every search reads them, sec 1287: lifted from the sticker
 * matcher, sec 1272. */
#include "words.h"

#include <string.h>

/* ONE CHARACTER past ASCII at `s`, `n` bytes left: its code point and its
 * length, or a length of 1 and code point 0 for a byte that starts none. */
static unsigned decode(const unsigned char *s, size_t n, size_t *len)
{
	unsigned cp;
	size_t k, want;

	*len = 1u;
	if (s[0] >= 0xc2u && s[0] <= 0xdfu)
		want = 2u, cp = s[0] & 0x1fu;
	else if (s[0] >= 0xe0u && s[0] <= 0xefu)
		want = 3u, cp = s[0] & 0x0fu;
	else if (s[0] >= 0xf0u && s[0] <= 0xf4u)
		want = 4u, cp = s[0] & 0x07u;
	else
		return 0;
	if (n < want)
		return 0;
	for (k = 1; k < want; k++) {
		if ((s[k] & 0xc0u) != 0x80u)
			return 0;
		cp = cp << 6 | (s[k] & 0x3fu);
	}
	*len = want;
	return cp;
}

/* PUNCTUATION AND SPACES PAST ASCII, sec 1297: a gap between words, as an
 * ASCII mark is -- a typographic quote, a dash or a no-break space was a
 * letter, so "quoted" in curly quotes was never found by `quoted`. The
 * Latin-1 marks (not the ordinal letters or the micro sign), the general
 * punctuation block and the CJK one. */
static int is_gap(unsigned cp)
{
	return (cp >= 0xa0u && cp <= 0xbfu && cp != 0xaau && cp != 0xb5u && cp != 0xbau) || cp == 0xd7u
	       || cp == 0xf7u || (cp >= 0x2000u && cp <= 0x206fu) || (cp >= 0x3000u && cp <= 0x303fu)
	       || cp == 0xfeffu;
}

/* A CAPITAL'S SMALL LETTER, sec 1297: Unicode's simple case folding where
 * it keeps a character's length -- Latin-1, Latin Extended-A, Greek and
 * Cyrillic -- so a Swedish name in capitals finds it written small, as
 * "ASA" finds "asa". A fold is the Unicode Character Database's, not a
 * guess at a script's rules; the dotted capital I, which folds to two
 * characters, is left as it is. */
static unsigned fold(unsigned cp)
{
	if (cp >= 0xc0u && cp <= 0xdeu && cp != 0xd7u)
		return cp + 0x20u;
	if ((cp >= 0x100u && cp <= 0x12fu) || (cp >= 0x132u && cp <= 0x137u) || (cp >= 0x14au && cp <= 0x177u))
		return cp | 1u;
	if ((cp >= 0x139u && cp <= 0x148u) || (cp >= 0x179u && cp <= 0x17eu))
		return cp & 1u ? cp + 1u : cp;
	if (cp == 0x178u)
		return 0xffu;
	if ((cp >= 0x391u && cp <= 0x3a1u) || (cp >= 0x3a3u && cp <= 0x3abu))
		return cp + 0x20u;
	if (cp == 0x3c2u) /* final sigma, which Unicode folds to sigma */
		return 0x3c3u;
	if (cp == 0x386u)
		return 0x3acu;
	if (cp >= 0x388u && cp <= 0x38au)
		return cp + 0x25u;
	if (cp == 0x38cu)
		return 0x3ccu;
	if (cp == 0x38eu || cp == 0x38fu)
		return cp + 0x3fu;
	if (cp >= 0x410u && cp <= 0x42fu)
		return cp + 0x20u;
	if (cp >= 0x400u && cp <= 0x40fu)
		return cp + 0x50u;
	return cp;
}

/* `cp` written as UTF-8 at `out`, its length -- 2 or 3 bytes, all a fold
 * above makes. */
static size_t encode(unsigned cp, char *out)
{
	if (cp < 0x800u) {
		out[0] = (char)(0xc0u | cp >> 6);
		out[1] = (char)(0x80u | (cp & 0x3fu));
		return 2u;
	}
	out[0] = (char)(0xe0u | cp >> 12);
	out[1] = (char)(0x80u | (cp >> 6 & 0x3fu));
	out[2] = (char)(0x80u | (cp & 0x3fu));
	return 3u;
}

void fzn_search_words_of(const char *s, size_t n, fzn_search_words_t *w)
{
	size_t i, used = 0, start = 0;
	int in = 0;

	w->n = 0;
	w->open_end = 0;
	if (n > FZN_SEARCH_WORDS_BYTES)
		s += n - FZN_SEARCH_WORDS_BYTES, n = FZN_SEARCH_WORDS_BYTES;
	for (i = 0; i <= n; i++) {
		unsigned char c = i < n ? (unsigned char)s[i] : ' ';

		if (c == '\'') {
			continue;
		}
		if (c == 0xe2u && i + 2u < n && (unsigned char)s[i + 1u] == 0x80u && (unsigned char)s[i + 2u] == 0x99u) {
			i += 2u;
			continue;
		}
		/* PAST ASCII, a character at a time: a gap where it is a mark,
		 * folded where it is a capital, and as it is otherwise -- a byte
		 * starting no character included, as before. */
		if (c >= 0x80u) {
			size_t len = 1u;
			const unsigned cp = decode((const unsigned char *)s + i, n - i, &len);

			if (cp && is_gap(cp)) {
				i += len - 1u;
				c = ' ';
			} else {
				char folded[4];
				const unsigned to = cp ? fold(cp) : 0u;
				const size_t out = to != cp && to ? encode(to, folded) : len;

				if (!in) {
					in = 1;
					start = used;
				}
				if (used + out <= FZN_SEARCH_WORDS_BYTES) {
					memcpy(w->buf + used, to != cp && to ? folded : s + i, out);
					used += out;
				}
				i += len - 1u;
				if (i + 1u == n)
					w->open_end = 1;
				continue;
			}
		}
		if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')) {
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
