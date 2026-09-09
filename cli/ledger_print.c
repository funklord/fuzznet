/* See ledger_print.h. */

#include "ledger_print.h"

#include <string.h>

#define DIGITS_MAX 21u

struct sink {
	char *out;
	size_t used;
};

static void put(struct sink *s, const char *bytes, size_t len)
{
	if (s->out)
		memcpy(s->out + s->used, bytes, len);
	s->used += len;
}

static void put_str(struct sink *s, const char *text)
{
	put(s, text, strlen(text));
}

static void put_u64(struct sink *s, uint64_t value)
{
	char digits[DIGITS_MAX];
	size_t at = sizeof(digits);

	do {
		digits[--at] = (char)('0' + (value % 10u));
		value /= 10u;
	} while (value);

	put(s, digits + at, sizeof(digits) - at);
}

static void render(struct sink *s, fzn_ledger_line_t state, uint64_t confirmed,
                   uint64_t current)
{
	/*
	 * THE VERDICT LEADS, on sec 207's rule, and here the evidence is two
	 * version numbers rather than a key -- but the ordering argument is the
	 * same: a terminal clips from the right and the word that must survive
	 * is the one saying whether anything on the line is evidence at all.
	 *
	 * ALL FIVE NAMED, NO `default:`.
	 */
	switch (state) {
	case FZN_LEDGER_LINE_NONE:
		put_str(s, "cannot say -- there is no ledger to read\n");
		return;
	case FZN_LEDGER_LINE_UNREADABLE:
		/* NOT "NOTHING CONFIRMED". The two shared a zero until
		 * `fzn_ledger_sound` existed, and they are opposite: one peer
		 * has not acknowledged, or EVERY peer reads that way and none
		 * of it is evidence. */
		put_str(s, "cannot say -- this ledger cannot be scanned, so every peer reads "
		           "as behind\n");
		return;
	case FZN_LEDGER_LINE_UNKNOWN:
		/* The ledger's own words for its zero: the absence of a
		 * question rather than an answer of none. */
		put_str(s, "nothing confirmed -- this peer has never acknowledged this "
		           "subject\n");
		return;
	case FZN_LEDGER_LINE_BEHIND:
		put_str(s, "behind: confirmed ");
		put_u64(s, confirmed);
		put_str(s, ", this host holds ");
		put_u64(s, current);
		put_str(s, "\n");
		return;
	case FZN_LEDGER_LINE_CURRENT:
		put_str(s, "up to date at ");
		put_u64(s, confirmed);
		put_str(s, "\n");
		return;
	}
}

fzn_ledger_err_t fzn_ledger_print(const fzn_ledger_t *ledger,
                                  const uint8_t peer[FZN_PUBKEY_LEN],
                                  const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind,
                                  uint64_t current, char *out, size_t cap, size_t *len_out,
                                  fzn_ledger_line_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_ledger_line_t said = FZN_LEDGER_LINE_NONE;
	uint64_t confirmed = 0u;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_LEDGER_LINE_NONE;

	if (!out || !len_out || !state_out)
		return FZN_LEDGER_ERR_MALFORMED;

	if (ledger && peer && subject) {
		/* SOUNDNESS IS ASKED FIRST, because every other accessor
		 * answers an unreadable ledger in the voice of a readable one:
		 * `confirmed` returns 0, which reads as "never acknowledged",
		 * and `behind` returns non-zero, which reads as a measured
		 * comparison. The header has the pair. */
		if (!fzn_ledger_sound(ledger)) {
			said = FZN_LEDGER_LINE_UNREADABLE;
		} else {
			confirmed = fzn_ledger_confirmed(ledger, peer, subject, kind);
			if (confirmed == 0u)
				said = FZN_LEDGER_LINE_UNKNOWN;
			else if (confirmed < current)
				said = FZN_LEDGER_LINE_BEHIND;
			else
				said = FZN_LEDGER_LINE_CURRENT;
		}
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said, confirmed, current);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_LEDGER_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said, confirmed, current);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_LEDGER_OK;
}
