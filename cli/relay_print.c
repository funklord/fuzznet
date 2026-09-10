/* See relay_print.h. */

#include "relay_print.h"

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

/* The row an operator would change, or NULL when the table does not name this
 * subsystem at all.
 *
 * A SUBSYSTEM WITH NO ROW IS NOT THE SAME AS ONE WITH A CEILING OF ZERO, and
 * the line says which: the first is governed by the fallback and the second
 * by a decision somebody wrote down. An operator looking for the row to edit
 * needs to know whether there is one. */
static const fzn_relay_policy_t *row_for(const fzn_relay_policy_t *policy, size_t len,
                                         uint16_t service)
{
	size_t i;

	if (!policy)
		return NULL;
	for (i = 0; i < len; i++) {
		if (policy[i].service == service)
			return &policy[i];
	}
	return NULL;
}

static void render(struct sink *s, fzn_relay_line_t state, uint16_t service, uint8_t budget,
                   const fzn_relay_policy_t *row)
{
	/*
	 * THE VERDICT LEADS, sec 207, and every line names the subsystem --
	 * "this host refuses that" without saying which leaves an operator to
	 * find the row themselves, and the row is what they will change.
	 *
	 * ALL SIX NAMED, NO `default:`.
	 */
	switch (state) {
	case FZN_RELAY_LINE_NONE:
		put_str(s, "cannot say -- there is no relay decision to report on\n");
		return;
	case FZN_RELAY_LINE_CARRIED:
		put_str(s, "carrying subsystem ");
		put_u64(s, service);
		put_str(s, " with ");
		put_u64(s, budget);
		put_str(s, " hops of budget left\n");
		return;
	case FZN_RELAY_LINE_ENDED:
		/* ORDINARY, AND NOT ABOUT THIS HOST. relay.h's words. */
		put_str(s, "subsystem ");
		put_u64(s, service);
		put_str(s, ": the frame's budget is spent, which is where a frame ordinarily "
		           "stops and says nothing about this host\n");
		return;
	case FZN_RELAY_LINE_REFUSED:
		/* THE ONE SOMEBODY CHOSE, and the line has to say so or a policy
		 * nobody meant to write looks like ordinary traffic ending. */
		put_str(s, "REFUSING subsystem ");
		put_u64(s, service);
		put_str(s, " by this host's own policy");
		if (row)
			put_str(s, ", whose ceiling for it is zero");
		else
			put_str(s, ", which has no row of its own and takes the fallback");
		put_str(s, " -- the frame could have been carried and was not\n");
		return;
	case FZN_RELAY_LINE_FOREIGN:
		put_str(s, "cannot read the budget of this frame: too short, or a version "
		           "this host does not know, which is a version difference rather "
		           "than a decision\n");
		return;
	case FZN_RELAY_LINE_LOCAL:
		put_str(s, "PROBLEM -- this program asked for something impossible while "
		           "relaying, which is a bug in it rather than a condition of the "
		           "network\n");
		return;
	}
}

fzn_relay_err_t fzn_relay_print(const fzn_relay_policy_t *policy, size_t policy_len,
                                uint16_t service, fzn_relay_err_t err, uint8_t budget,
                                char *out, size_t cap, size_t *len_out,
                                fzn_relay_line_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_relay_line_t said = FZN_RELAY_LINE_NONE;
	const fzn_relay_policy_t *row;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_RELAY_LINE_NONE;

	if (!out || !len_out || !state_out)
		return FZN_RELAY_ERR_MALFORMED;

	row = row_for(policy, policy_len, service);

	switch (err) {
	case FZN_RELAY_OK:
		said = FZN_RELAY_LINE_CARRIED;
		break;
	case FZN_RELAY_ERR_EXHAUSTED:
		said = FZN_RELAY_LINE_ENDED;
		break;
	case FZN_RELAY_ERR_REFUSED:
		said = FZN_RELAY_LINE_REFUSED;
		break;
	case FZN_RELAY_ERR_SHAPE:
		said = FZN_RELAY_LINE_FOREIGN;
		break;
	case FZN_RELAY_ERR_MALFORMED:
		said = FZN_RELAY_LINE_LOCAL;
		break;
	}
	/* NO `default:` ABOVE, so a code added to relay.h fails to compile
	 * here rather than rendering as "cannot say". */

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said, service, budget, row);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_RELAY_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said, service, budget, row);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_RELAY_OK;
}
