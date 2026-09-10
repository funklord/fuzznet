#include "sweep_print.h"

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

/* Each reason named, never summed. sweep.h keeps its counters apart because
 * each calls for a different action: retention is this host's own policy,
 * shared and last_copy are guards refusing, absent is nothing to do. */
static void reasons(struct sink *s, const fzn_catalog_sweep_plan_t *plan)
{
	int first = 1;

	if (plan->retained > 0u) {
		put_u64(s, (uint64_t)plan->retained);
		put_str(s, " retained by policy");
		first = 0;
	}
	if (plan->shared > 0u) {
		if (!first)
			put_str(s, ", ");
		put_u64(s, (uint64_t)plan->shared);
		put_str(s, " shared with a retained node");
		first = 0;
	}
	if (plan->last_copy > 0u) {
		if (!first)
			put_str(s, ", ");
		put_u64(s, (uint64_t)plan->last_copy);
		put_str(s, " the last known copy -- needs more replicas, not more sweeping");
		first = 0;
	}
	if (plan->absent > 0u) {
		if (!first)
			put_str(s, ", ");
		put_u64(s, (uint64_t)plan->absent);
		put_str(s, " not held here");
	}
}

static void render(struct sink *s, const fzn_catalog_sweep_plan_t *plan,
                   fzn_sweep_state_t state, size_t done, size_t total, int truncated)
{
	switch (state) {
	case FZN_SWEEP_NOTHING_CAPTURED:
		put_str(s, "nothing captured -- no sweep has been planned");
		put_str(s, "\n");
		return;
	case FZN_SWEEP_EMPTY:
		put_str(s, "nothing to remove");
		break;
	case FZN_SWEEP_HELD_BACK:
		put_str(s, "nothing will be removed: ");
		reasons(s, plan);
		break;
	case FZN_SWEEP_READY:
		put_u64(s, (uint64_t)plan->planned);
		put_str(s, " to remove, not started");
		break;
	case FZN_SWEEP_RUNNING:
		put_str(s, "removing ");
		put_u64(s, (uint64_t)done);
		put_str(s, " of ");
		put_u64(s, (uint64_t)total);
		break;
	case FZN_SWEEP_DONE:
		put_str(s, "removed ");
		put_u64(s, (uint64_t)total);
		break;
	}

	if (truncated)
		/* WHATEVER ELSE IS TRUE. Every count above understates. */
		put_str(s, "; the plan ran out of rows, so these counts are short");

	put_str(s, "\n");
}

fzn_catalog_err_t fzn_sweep_print(const fzn_catalog_sweep_plan_t *plan,
                                  const fzn_catalog_sweep_t *job, char *out, size_t cap,
                                  size_t *len_out, fzn_sweep_state_t *state_out,
                                  int *truncated_out)
{
	struct sink measure;
	struct sink write;
	fzn_sweep_state_t said = FZN_SWEEP_NOTHING_CAPTURED;
	size_t done = 0;
	size_t total = 0;
	int truncated = 0;
	int running = 0;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_SWEEP_NOTHING_CAPTURED;
	if (truncated_out)
		*truncated_out = 0;

	if (!out || !len_out || !state_out || !truncated_out)
		return FZN_CATALOG_ERR_MALFORMED;

	if (plan) {
		truncated = plan->truncated > 0u;

		/* READ, NEVER ADVANCED. sec 181: `_advance` is called after the
		 * bytes are gone, so reporting must not call it. */
		if (job && fzn_catalog_sweep_progress(job, &done, &total) == FZN_CATALOG_OK)
			running = 1;

		if (plan->planned == 0u) {
			/* THE PAIR sweep.h KEEPS ITS COUNTERS APART FOR. */
			said = (plan->retained > 0u || plan->shared > 0u ||
			        plan->last_copy > 0u)
			               ? FZN_SWEEP_HELD_BACK
			               : FZN_SWEEP_EMPTY;
		} else if (!running) {
			said = FZN_SWEEP_READY;
		} else {
			said = done < total ? FZN_SWEEP_RUNNING : FZN_SWEEP_DONE;
		}
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, plan, said, done, total, truncated);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_CATALOG_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, plan, said, done, total, truncated);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;
	*truncated_out = truncated;

	return FZN_CATALOG_OK;
}
