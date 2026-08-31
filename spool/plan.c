/* See plan.h. Policy over a bitmap: no allocation, no I/O, no wire format. */

#include "plan.h"

/* `spool.c` keeps its own copy of this; it is four lines and duplicating it
 * is cheaper than exporting a bit accessor from a module whose bitmap is
 * deliberately the caller's. */
static int bit_get(const uint8_t *map, uint64_t index)
{
	return (map[index >> 3] >> (index & 7u)) & 1u;
}

/* Appends a run, splitting it so no range exceeds `limit`. Returns 0 when the
 * caller's array is full, which is a stop rather than an error -- a partial
 * plan is a legitimate answer and the caller can ask again. */
static int emit(fzn_spool_range_t *out, size_t cap, size_t *count, uint64_t first,
                uint64_t run, uint64_t limit)
{
	while (run > 0u) {
		uint64_t take = run < limit ? run : limit;

		if (*count >= cap)
			return 0;
		out[*count].first = first;
		out[*count].count = take;
		(*count)++;
		first += take;
		run -= take;
	}
	return 1;
}

fzn_spool_err_t fzn_spool_plan_want(const fzn_spool_t *spool, uint64_t from,
                                    uint64_t max_per_range, fzn_spool_range_t *out, size_t cap,
                                    size_t *count)
{
	uint64_t step, run_first = 0, run = 0;

	if (!spool || !spool->present || !out || !count)
		return FZN_SPOOL_ERR_MALFORMED;
	/* ZERO IS REFUSED RATHER THAN MEANING UNLIMITED. A caller that forgot
	 * to set a bound must not get "no bound" -- `record/sync.h` refuses a
	 * zero `max_per_request` for the same reason, and this file inherits
	 * the rule rather than re-deciding it. */
	if (max_per_range == 0u)
		return FZN_SPOOL_ERR_MALFORMED;
	/* A START PAST THE BLOB IS REFUSED RATHER THAN WRAPPED TO ZERO. A
	 * playhead outside the content is a caller that has lost track of
	 * where it is, and silently answering as though it had asked from the
	 * beginning would hand a video player the wrong part of the film and
	 * look like it worked. */
	if (spool->leaves == 0u || from >= spool->leaves)
		return FZN_SPOOL_ERR_MALFORMED;

	*count = 0;
	for (step = 0; step < spool->leaves; step++) {
		uint64_t i = from + step;

		if (i >= spool->leaves)
			i -= spool->leaves;

		if (!bit_get(spool->present, i)) {
			/* A RUN NEVER CROSSES THE WRAP. The last leaf and leaf
			 * zero are not contiguous, so a range spanning them
			 * would name a span the peer reads as something else
			 * entirely -- and would ask for leaves in between that
			 * this store already holds. Closing the run at index
			 * zero is what keeps a range meaning what it says. */
			if (run > 0u && i == 0u) {
				if (!emit(out, cap, count, run_first, run, max_per_range))
					return FZN_SPOOL_OK;
				run = 0;
			}
			if (run == 0u)
				run_first = i;
			run++;
			continue;
		}
		if (run > 0u && !emit(out, cap, count, run_first, run, max_per_range))
			return FZN_SPOOL_OK;
		run = 0;
	}
	/* The run still open when the walk completes. Written outside the loop
	 * because the loop only closes a run when it meets a leaf it HAS, and
	 * a store missing the leaves before `from` never does -- which is the
	 * ordinary case at the start of a transfer, not an edge one. */
	if (run > 0u)
		(void)emit(out, cap, count, run_first, run, max_per_range);

	return FZN_SPOOL_OK;
}

fzn_spool_err_t fzn_spool_plan_offer(const fzn_spool_t *spool, const fzn_spool_range_t *want,
                                     size_t want_count, uint64_t max_leaves,
                                     fzn_spool_range_t *out, size_t cap, size_t *count)
{
	size_t w;
	uint64_t budget;

	if (!spool || !spool->present || !out || !count)
		return FZN_SPOOL_ERR_MALFORMED;
	if (max_leaves == 0u)
		return FZN_SPOOL_ERR_MALFORMED;
	/* `want` may be NULL only when there is nothing to read from it. A
	 * non-zero count over a null pointer is a caller bug and is refused
	 * rather than read. */
	if (!want && want_count > 0u)
		return FZN_SPOOL_ERR_MALFORMED;

	*count = 0;
	budget = max_leaves;

	/* AND A WANT THAT NAMES NOTHING FALLS STRAIGHT OUT WITH NOTHING. There
	 * is no special case for it below and there does not need to be -- the
	 * loop runs zero times -- but it is the whole of `record/sync`'s
	 * measured defect, so it is named here rather than left to be inferred
	 * from the loop bound by whoever edits this next. */
	if (want_count > FZN_SPOOL_MAX_WANT)
		want_count = FZN_SPOOL_MAX_WANT;

	for (w = 0; w < want_count && budget > 0u; w++) {
		uint64_t first = want[w].first;
		uint64_t left;
		uint64_t i, run_first = 0, run = 0;

		/* NO EXPLICIT TEST FOR A ZERO-LENGTH RANGE, and its absence is
		 * measured rather than an oversight: `left` below becomes zero
		 * for one, so the inner loop does not run and nothing is
		 * emitted. Adding the test changes no result -- mutation
		 * confirmed it -- and a guard that cannot fail is how it stops
		 * being possible to see which guards matter. The BEHAVIOUR is
		 * still asserted in plan_test.c, because it is a rule a later
		 * rewrite must not lose even though this shape gets it free. */
		if (first >= spool->leaves)
			continue;
		/* CLIPPED, NOT REFUSED. A peer naming a trillion leaves costs
		 * a comparison rather than an error path, which is the same
		 * trade `fzn_spool_open` makes for its ceiling. */
		left = spool->leaves - first;
		if (want[w].count < left)
			left = want[w].count;

		for (i = 0; i < left && budget > 0u; i++) {
			if (bit_get(spool->present, first + i)) {
				if (run == 0u)
					run_first = first + i;
				run++;
				budget--;
				continue;
			}
			if (run > 0u && !emit(out, cap, count, run_first, run, max_leaves))
				return FZN_SPOOL_OK;
			run = 0;
		}
		if (run > 0u && !emit(out, cap, count, run_first, run, max_leaves))
			return FZN_SPOOL_OK;
	}

	return FZN_SPOOL_OK;
}
