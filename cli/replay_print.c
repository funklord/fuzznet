/* See replay_print.h. */

#include "replay_print.h"

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

static void render(struct sink *s, fzn_replay_line_t state, size_t used, size_t capacity,
                   size_t due)
{
	/*
	 * THE VERDICT LEADS, on sec 207's rule. Here it leads for a second
	 * reason too: the two FULL lines differ in what a person must DO, and
	 * a line that opened with three numbers would put the instruction
	 * behind them.
	 *
	 * ALL FIVE NAMED, NO `default:`.
	 */
	switch (state) {
	case FZN_REPLAY_LINE_NONE:
		/* NOT "0 OF 0". A window whose fields disagree has no
		 * occupancy to report, and a pair of zeroes would read as an
		 * idle host rather than an unreadable one. */
		put_str(s, "cannot say -- there is no replay window to read\n");
		return;
	case FZN_REPLAY_LINE_EMPTY:
		/* NOT "KEEPING UP". Nothing recorded is a host that has
		 * admitted no frame, which is a different thing from one whose
		 * window is turning over healthily. */
		put_str(s, "nothing recorded, ");
		put_size(s, capacity);
		put_str(s, " slots free\n");
		return;
	case FZN_REPLAY_LINE_HOLDING:
		put_str(s, "holding ");
		put_size(s, used);
		put_str(s, " of ");
		put_size(s, capacity);
		put_str(s, ", ");
		put_size(s, due);
		put_str(s, " ready to expire\n");
		return;
	case FZN_REPLAY_LINE_FULL_UNPRUNED:
		/* THE FIX IS A CALLER. This window prunes only when asked, and
		 * `frame/freshness.h` says so: "nothing here prunes on its
		 * own". */
		put_str(s, "REFUSING FRESH FRAMES -- full at ");
		put_size(s, capacity);
		put_str(s, " with ");
		put_size(s, due);
		put_str(s, " already expired, so nothing is calling expire\n");
		return;
	case FZN_REPLAY_LINE_FULL_LIVE:
		/* THE FIX IS THE SIZING FORMULA. Every entry is still live, so
		 * expiring reclaims nothing and a bigger array is the only
		 * thing that helps. */
		put_str(s, "REFUSING FRESH FRAMES -- full at ");
		put_size(s, capacity);
		put_str(s, " and every entry still live, so the capacity is below what this "
		           "horizon implies\n");
		return;
	}
}

fzn_fresh_err_t fzn_replay_print(const fzn_replay_window_t *window, uint64_t now, char *out,
                                 size_t cap, size_t *len_out, fzn_replay_line_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_replay_line_t said = FZN_REPLAY_LINE_NONE;
	size_t used = 0u;
	size_t capacity = 0u;
	size_t due = 0u;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_REPLAY_LINE_NONE;

	if (!out || !len_out || !state_out)
		return FZN_FRESH_ERR_MALFORMED;

	/* A WINDOW WHOSE FIELDS DISAGREE IS NONE, not an occupancy. Both
	 * `fzn_replay_expire` and `fzn_replay_expirable` refuse to walk one, so
	 * a count drawn from it would be invented rather than measured -- and
	 * the pair of zeroes it would print reads as an idle host. */
	if (window && window->entries && window->capacity && window->used <= window->capacity) {
		used = window->used;
		capacity = window->capacity;
		due = fzn_replay_expirable(window, now);

		if (used == 0u)
			said = FZN_REPLAY_LINE_EMPTY;
		else if (used < capacity)
			said = FZN_REPLAY_LINE_HOLDING;
		else if (due)
			said = FZN_REPLAY_LINE_FULL_UNPRUNED;
		else
			said = FZN_REPLAY_LINE_FULL_LIVE;
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said, used, capacity, due);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_FRESH_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said, used, capacity, due);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_FRESH_OK;
}
