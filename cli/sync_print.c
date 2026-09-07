#include "sync_print.h"

#include <string.h>

/* A screenful of pairs, as `gui/sync_view` takes. This reads rather than
 * fetches, so the `from = 0` form is the right one -- manifest.h says it is
 * "right for a report a human reads". */
#define PAIRS 32u

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

/* The line, written twice: once to measure and once to place. Same bargain as
 * `cli/log_print` -- it is what buys "nothing is written unless the whole
 * thing fits", and a status line cut in half is worse than none. */
static void render(struct sink *s, fzn_sync_state_t state, size_t missing, size_t dropped)
{
	switch (state) {
	case FZN_SYNC_UNMEASURED:
		/* NOT A ZERO. The deficit is unmeasured, and the words say so
		 * rather than reporting a number that would read as healthy. */
		put_str(s, "cannot say -- not followed, absent, or a report was dropped");
		break;
	case FZN_SYNC_UP_TO_DATE:
		put_str(s, "up to date");
		break;
	default:
		put_u64(s, (uint64_t)missing);
		put_str(s, " outstanding");
		if (dropped > 0u) {
			put_str(s, "; ");
			put_u64(s, (uint64_t)dropped);
			put_str(s, " more did not fit, so this count is short");
		}
		break;
	}
	put_str(s, "\n");
}

fzn_manifest_err_t fzn_sync_print(const fzn_manifest_state_t *state,
                                  const uint8_t issuer[FZN_PUBKEY_LEN], char *out,
                                  size_t cap, size_t *len_out, fzn_sync_state_t *state_out)
{
	fzn_manifest_pair_t pairs[PAIRS];
	struct sink measure;
	struct sink write;
	fzn_sync_state_t said = FZN_SYNC_UNMEASURED;
	size_t missing = 0;
	size_t dropped = 0;

	if (len_out)
		*len_out = 0;
	/* CONSERVATIVE BEFORE ANY REFUSAL, so a caller that ignores the return
	 * value still reads "cannot say" rather than whatever its stack held.
	 * The same reasoning `fzn_chain_store_lookup` gives for clearing its
	 * out-parameters first. */
	if (state_out)
		*state_out = FZN_SYNC_UNMEASURED;

	if (!issuer || !out || !len_out || !state_out)
		return FZN_MANIFEST_ERR_MALFORMED;

	/* THE LIBRARY'S ANSWER, ASKED FIRST AND NOT SHORT-CIRCUITED. A NULL
	 * state, disagreeing fields and an unfollowed issuer are one fact to
	 * `fzn_manifest_overflowed`, and deciding any of them here would be
	 * this file re-deciding what manifest.c has decided. */
	if (!fzn_manifest_overflowed(state, issuer)) {
		missing = fzn_manifest_deficit(state, issuer, pairs, PAIRS, &dropped);
		said = (missing == 0u && dropped == 0u) ? FZN_SYNC_UP_TO_DATE
		                                        : FZN_SYNC_BEHIND;
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said, missing, dropped);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_MANIFEST_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said, missing, dropped);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_MANIFEST_OK;
}
