#include "state_print.h"

#include "../constant_time/constant_time.h"
#include "../trust/trust.h"

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

static void render(struct sink *s, fzn_state_cell_t state, const fzn_state_entry_t *row)
{
	char print[FZN_TRUST_FINGERPRINT_LEN];

	switch (state) {
	case FZN_STATE_CELL_UNREADABLE:
		put_str(s, "cannot be read\n");
		return;
	case FZN_STATE_CELL_NEVER_SET:
		put_str(s, "nobody has set this\n");
		return;
	case FZN_STATE_CELL_CLEARED:
		/* SOMEBODY'S DOING, not an absence. `fzn_state_get` cannot say
		 * this and a report must. */
		put_str(s, "cleared -- it was set and taken back by ");
		break;
	default:
		put_str(s, "set by ");
		break;
	}

	if (fzn_trust_fingerprint(row->issuer, print, sizeof(print)) == FZN_TRUST_OK)
		put_str(s, print);
	else
		put_str(s, "an issuer this line could not format");

	put_str(s, " at ");
	put_u64(s, row->seq);
	put_str(s, "\n");
}

fzn_state_err_t fzn_state_print(const fzn_state_t *st,
                                const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind,
                                char *out, size_t cap, size_t *len_out,
                                fzn_state_cell_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_state_cell_t said = FZN_STATE_CELL_UNREADABLE;
	const fzn_state_entry_t *row = NULL;
	size_t i;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_STATE_CELL_UNREADABLE;

	if (!out || !len_out || !state_out || !subject)
		return FZN_STATE_ERR_MALFORMED;

	if (fzn_state_sound(st)) {
		/* THE VALUE IS THE LIBRARY'S ANSWER. Everything below is about
		 * the ABSENCE, so the presence is not second-guessed. */
		row = fzn_state_get(st, subject, kind);
		if (row) {
			said = FZN_STATE_CELL_SET;
		} else {
			/* AND HERE IS WHERE THIS LOOKS PAST THE ACCESSOR. `get`
			 * answers NULL for a tombstone and for a subject nobody
			 * set, so that code taking a decision cannot act
			 * differently on the two. A REPORT must: one is
			 * unconfigured and the other is somebody's doing. */
			for (i = 0; i < st->used; i++) {
				if (st->entries[i].kind != kind)
					continue;
				if (!fzn_ct_memeq(st->entries[i].subject, subject,
				                  FZN_SUBJECT_LEN))
					continue;
				row = &st->entries[i];
				break;
			}
			said = row ? FZN_STATE_CELL_CLEARED : FZN_STATE_CELL_NEVER_SET;
		}
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said, row);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_STATE_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said, row);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_STATE_OK;
}
