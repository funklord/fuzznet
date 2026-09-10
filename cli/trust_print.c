#include "trust_print.h"

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

static void render(struct sink *s, const fzn_trust_t *trust, fzn_trust_line_t state)
{
	char print[FZN_TRUST_FINGERPRINT_LEN];

	if (state == FZN_TRUST_LINE_NONE) {
		/* NOT AN EMPTY FINGERPRINT. A blank where one belongs reads as
		 * a fingerprint of something, and somebody comparing would
		 * conclude the peer is wrong rather than that this host has no
		 * anchor. */
		put_str(s, "no anchor -- this host trusts nothing yet\n");
		return;
	}

	/*
	 * HOW IT WAS TRUSTED COMES FIRST, and the fingerprint follows. The
	 * order was the other way round until 2026-09-08. sec 207.
	 *
	 * trust.h calls an adopted anchor "authenticated by nothing", and a
	 * fingerprint printed without that invites comparing it as though
	 * somebody had vouched -- so the two have to be on one line. Which
	 * comes first is decided by the terminal: a fingerprint spells to 79
	 * characters, a terminal clips from the RIGHT, and with the
	 * fingerprint first the source began at column 82. On a standard
	 * terminal an operator saw the key and never learned whether it was
	 * pinned, adopted or this node's own -- which is exactly the
	 * distinction between a root somebody checked and one taken from
	 * whoever answered first.
	 *
	 * The words are `fzn_trust_source_str`'s, so a terminal and a dialog
	 * say the same thing.
	 */
	put_str(s, fzn_trust_source_str(trust->source));

	if (state == FZN_TRUST_LINE_ADOPTED)
		put_str(s, ", authenticated by nothing");
	else if (state == FZN_TRUST_LINE_SELF)
		/* A WORKING STATE, said so plainly, because an operator told
		 * their host has no anchor will go and fix it -- and an
		 * unanchored node adopts whoever reaches it first. */
		put_str(s, ", a complete estate of one");

	if (trust->adopted_at != 0u) {
		put_str(s, ", at ");
		put_u64(s, trust->adopted_at);
	}

	put_str(s, " -- ");

	/* THE ELSE CANNOT ARRIVE, and it stays. `fzn_trust_fingerprint`
		 * fails on a null key, a null destination or a capacity below
		 * FZN_TRUST_FINGERPRINT_LEN; the destination is a local array
		 * and the capacity its own sizeof, and the key is an array
		 * member of a struct already refused when null. Checking the
		 * status is what status_gate.py requires, and a check must
		 * have an else -- so this is said rather than removed, and
		 * said so nobody reads the sentence as a path anything runs.
		 * sec 266. */
	if (fzn_trust_fingerprint(trust->root, print, sizeof(print)) == FZN_TRUST_OK)
		put_str(s, print);
	else
		put_str(s, "an anchor this line could not format");

	put_str(s, "\n");
}

fzn_trust_err_t fzn_trust_print(const fzn_trust_t *trust, char *out, size_t cap,
                                size_t *len_out, fzn_trust_line_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_trust_line_t said = FZN_TRUST_LINE_NONE;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_TRUST_LINE_NONE;

	if (!out || !len_out || !state_out)
		return FZN_TRUST_ERR_MALFORMED;

	if (trust) {
		/* ALL FOUR NAMED, NO `default:`. A default over an enum is what
		 * mapped FZN_TRUST_SELF onto "no anchor" in the first draft --
		 * see the header. Naming them means a fifth source added later
		 * is a compiler warning rather than a silent absence. */
		switch (trust->source) {
		case FZN_TRUST_PINNED:
			said = FZN_TRUST_LINE_PINNED;
			break;
		case FZN_TRUST_ADOPTED:
			said = FZN_TRUST_LINE_ADOPTED;
			break;
		case FZN_TRUST_SELF:
			said = FZN_TRUST_LINE_SELF;
			break;
		case FZN_TRUST_NONE:
			said = FZN_TRUST_LINE_NONE;
			break;
		}
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, trust, said);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_TRUST_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, trust, said);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_TRUST_OK;
}
