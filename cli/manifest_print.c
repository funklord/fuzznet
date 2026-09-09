/* See manifest_print.h. */

#include "manifest_print.h"

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

static void put_size(struct sink *s, size_t value)
{
	char digits[DIGITS_MAX];
	size_t at = sizeof(digits);

	do {
		digits[--at] = (char)('0' + (value % 10u));
		value /= 10u;
	} while (value);

	put(s, digits + at, sizeof(digits) - at);
}

static void render(struct sink *s, fzn_manifest_line_t state, size_t pending)
{
	/*
	 * THE VERDICT LEADS, on sec 207's rule. There is no long identifier on
	 * this line, but the reason holds anyway: a terminal clips from the
	 * right, and the word that must survive is the one saying whether the
	 * number can be believed.
	 *
	 * ALL FIVE NAMED, NO `default:`, so a sixth state added later is a
	 * compiler warning rather than a line that silently reads as one of
	 * these.
	 */
	switch (state) {
	case FZN_MANIFEST_LINE_NONE:
		/* NOT "0 OUTSTANDING". A zero here would read as a measurement
		 * of a real thing, which is exactly the fail-open this file
		 * exists to make visible. */
		put_str(s, "cannot say -- there is no manifest state to read\n");
		return;
	case FZN_MANIFEST_LINE_UNFOLLOWED:
		/* `fzn_manifest_pending` calls its zero here "the absence of a
		 * question", and a person shown "0 outstanding" would read an
		 * answer. */
		put_str(s, "not followed -- nothing this issuer revokes is tracked\n");
		return;
	case FZN_MANIFEST_LINE_COMPLETE:
		put_str(s, "up to date -- no revocation from this issuer is outstanding\n");
		return;
	case FZN_MANIFEST_LINE_PENDING:
		put_size(s, pending);
		put_str(s, pending == 1u ? " revocation outstanding\n"
		                         : " revocations outstanding\n");
		return;
	case FZN_MANIFEST_LINE_UNDERSTATED:
		/* THE ONE LINE THIS FILE IS FOR. A floor of zero is not "up to
		 * date" and must not be able to read as it, which is why the
		 * zero case is worded rather than falling into the counted
		 * one. */
		if (pending == 0u) {
			put_str(s, "AT LEAST ONE MISSING -- none this host can name is "
			           "outstanding, and it knows there are more it cannot\n");
			return;
		}
		put_str(s, "AT LEAST ");
		put_size(s, pending);
		put_str(s, pending == 1u ? " revocation outstanding" : " revocations outstanding");
		put_str(s, " -- and more this host cannot name\n");
		return;
	}
}

fzn_manifest_err_t fzn_manifest_print(const fzn_manifest_state_t *state,
                                      const uint8_t issuer[FZN_PUBKEY_LEN], char *out,
                                      size_t cap, size_t *len_out,
                                      fzn_manifest_line_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_manifest_line_t said = FZN_MANIFEST_LINE_NONE;
	size_t pending = 0;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_MANIFEST_LINE_NONE;

	if (!out || !len_out || !state_out)
		return FZN_MANIFEST_ERR_MALFORMED;

	if (state && issuer) {
		/* FOLLOWS IS ASKED FIRST, because the other two accessors both
		 * answer the unfollowed case in the voice of something else:
		 * `pending` returns 0, which reads as complete, and
		 * `overflowed` returns 1, which reads as a dropped pair. The
		 * header has the measurement. */
		if (!fzn_manifest_follows(state, issuer)) {
			said = FZN_MANIFEST_LINE_UNFOLLOWED;
		} else {
			pending = fzn_manifest_pending(state, issuer);
			if (fzn_manifest_overflowed(state, issuer))
				said = FZN_MANIFEST_LINE_UNDERSTATED;
			else if (pending == 0u)
				said = FZN_MANIFEST_LINE_COMPLETE;
			else
				said = FZN_MANIFEST_LINE_PENDING;
		}
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said, pending);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_MANIFEST_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said, pending);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_MANIFEST_OK;
}
