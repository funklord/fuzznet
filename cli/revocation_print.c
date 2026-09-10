#include "revocation_print.h"

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

static void render(struct sink *s, fzn_revocations_state_t state, size_t in_force,
                   size_t withdrawn)
{
	switch (state) {
	case FZN_REVOCATIONS_UNREADABLE:
		/* NOT A COUNT. Saying "none" here would be the fail-open
		 * answer: it claims every capability is fine when the truth is
		 * that this host cannot say. */
		put_str(s, "the store cannot be read -- it counts more entries than it holds");
		break;
	case FZN_REVOCATIONS_NONE:
		put_str(s, "no revocation has been heard of");
		break;
	case FZN_REVOCATIONS_HOLDING:
		put_u64(s, (uint64_t)in_force);
		put_str(s, " in force");
		if (withdrawn > 0u) {
			/* SAID SEPARATELY AND ALWAYS. A restored capability is
			 * what somebody is looking for when a peer says they
			 * were cut off and are not any more, and it is
			 * invisible in a total. */
			put_str(s, "; ");
			put_u64(s, (uint64_t)withdrawn);
			put_str(s, " since withdrawn, so those work again");
		}
		break;
	}

	put_str(s, "\n");
}

fzn_chain_err_t fzn_revocation_print(const fzn_revocation_store_t *store, char *out,
                                     size_t cap, size_t *len_out,
                                     fzn_revocations_state_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_revocations_state_t said = FZN_REVOCATIONS_UNREADABLE;
	size_t in_force = 0;
	size_t withdrawn = 0;
	size_t i;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_REVOCATIONS_UNREADABLE;

	if (!out || !len_out || !state_out)
		return FZN_CHAIN_ERR_MALFORMED;

	/* THE LIBRARY'S ANSWER. A NULL store is SOUND -- it holds nothing,
	 * which is a fact rather than a fault -- so the pointer is checked
	 * separately from the soundness. sec 183. */
	if (fzn_revocation_store_sound(store)) {
		if (!store) {
			said = FZN_REVOCATIONS_NONE;
		} else {
			for (i = 0; i < store->used; i++) {
				/* THE ENTRY'S ACTION, NOT ITS PRESENCE. */
				if (store->entries[i].withdrawn)
					withdrawn++;
				else
					in_force++;
			}
			said = store->used == 0u ? FZN_REVOCATIONS_NONE
			                         : FZN_REVOCATIONS_HOLDING;
		}
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said, in_force, withdrawn);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_CHAIN_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said, in_force, withdrawn);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_CHAIN_OK;
}
