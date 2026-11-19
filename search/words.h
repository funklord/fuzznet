/*
 * WORDS AS EVERY SEARCH READS THEM, sec 1287: one normalisation for every
 * store, so "Thanks" finds "thank" in messages, stickers and names alike.
 * Lifted from the sticker matcher (sec 1272), which reads them here now.
 *
 * A WORD is a run of ASCII letters and digits, folded to lower case, and of
 * any byte of a character past ASCII; an apostrophe (' or U+2019) is
 * dropped from inside it; anything else is a gap. Two words are the SAME
 * where they are equal, or where their plain forms are -- a closing -ing,
 * -ed, -es or -s let go where enough of the word is left to still be one.
 * Past ASCII nothing is folded or stemmed: a script's own rules are not
 * guessed at.
 */
#ifndef FZN_SEARCH_WORDS_H
#define FZN_SEARCH_WORDS_H

#include <stddef.h>

#define FZN_SEARCH_WORDS_MAX 64u
#define FZN_SEARCH_WORDS_BYTES 1024u

typedef struct fzn_search_words {
	char buf[FZN_SEARCH_WORDS_BYTES];
	size_t at[FZN_SEARCH_WORDS_MAX], len[FZN_SEARCH_WORDS_MAX], n;
	/* THE TEXT ENDS INSIDE A WORD, so its last may be half typed. */
	int open_end;
} fzn_search_words_t;

/* THE WORDS OF `s`, as many as fit, FROM THE END: what was typed last is
 * what a search while typing answers. */
void fzn_search_words_of(const char *s, size_t n, fzn_search_words_t *w);

/* Whether two words are one, as above. */
int fzn_search_same_word(const char *a, size_t an, const char *b, size_t bn);

/* A word too common to say what a text is about: "the", "and", "of" ... */
int fzn_search_common_word(const char *w, size_t n);

/* HOW WELL `text` ANSWERS THE WORDS `q`, on the one scale every store
 * scores by: 0 when a telling word of the query is absent, else 100 a word
 * found, the query's last perhaps only begun where `q->open_end` (60) --
 * two letters of it, or one after other words, as the sticker matcher --
 * 50 more where the query's words stand together in the text in order. A
 * query of common words alone needs them all. */
unsigned fzn_search_score(const fzn_search_words_t *q, const char *text, size_t text_len);

#endif /* FZN_SEARCH_WORDS_H */
