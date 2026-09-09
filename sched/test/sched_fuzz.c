/*
 * A fuzz harness for sched/sched.c: is the link it chooses the cheapest one
 * that qualifies?
 *
 * WHY, GIVEN sched_test.c EXISTS. Eleven calls to `fzn_sched_select` and
 * EVERY ONE OF THEM OVER A PAIR. With two candidates, "the cheapest that
 * qualifies" is the comparison the code makes, so the test and the code agree
 * by construction; a tie among three, or a minimum that is neither first nor
 * last, is not expressible. It is fuzzypickles' question of 2026-09-05 --
 * what value is every fixture on the same side of? -- and the answer here is
 * the size of the candidate set.
 *
 * THE MODEL IS AN INDEPENDENT ARGMIN. This file computes each candidate's
 * cost with its own saturating sum, written from what `sched.h` describes --
 * a weighted sum of metric, latency and loss, lower is better, a weight of
 * zero ignoring its component -- and then finds the minimum over the
 * candidates that pass the hard constraints. A model that called
 * `fzn_sched_cost` to decide what the cost should be would agree with the
 * module always, including when both are wrong.
 *
 * WHY THAT ARITHMETIC IS WORTH TWO IMPLEMENTATIONS: the module's one
 * recorded defect was exactly here. sched.c carries the measurement -- with a
 * weight of 4294967295 on the metric, a link declaring metric and latency
 * both at 4294967295 cost ZERO, the cheapest value representable, and was
 * chosen over a link costing 1 ms. Widening the multiplies was not enough
 * because the SUM was a bare `+=`. So the weights and the metrics here are
 * drawn to include their extremes rather than plausible values.
 *
 * FIVE PROPERTIES.
 *
 *   1. THE COST IS THE MODEL'S COST, for every candidate and class.
 *   2. THE CHOSEN LINK QUALIFIES -- `fzn_sched_admits` says yes about it.
 *   3. IT IS A CHEAPEST QUALIFYING LINK, by the model's own minimum.
 *   4. TIES GO TO THE LOWEST INDEX, which is what makes a scheduler
 *      reproducible: `sched.h` says a choice that wandered between identical
 *      candidates would make a network's behaviour unrepeatable for no gain.
 *   5. THE FILTER IS NOT A PENALTY. Which candidates qualify must not change
 *      when only the weights do -- sched.c's own words, and the failure it
 *      names is a large enough weight elsewhere bringing back a link that
 *      failed a hard constraint.
 *
 * AND WHEN NOTHING QUALIFIES it must say so and leave `chosen` alone, rather
 * than falling back to a link the class refused.
 */

#include "../sched.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

/* Below this the floors are cleared by a single lucky case. */
#define FUZZ_MIN_CASES 1000u

/* Sets of one to this many. One is worth reaching: a single candidate is the
 * case where a wrong argmin cannot be seen at all. */
#define LINKS_MAX 8u

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

/* A value that is small, or a boundary, or anything at all -- so the extremes
 * the recorded defect needed are reached rather than approached. */
static uint32_t draw_u32(uint32_t *state)
{
	switch (next(state) % 8u) {
	case 0:
		return 0u;
	case 1:
		return 1u;
	case 2:
		return UINT32_MAX;
	case 3:
		return UINT32_MAX - 1u;
	case 4:
		return next(state) % 4u;
	case 5:
		return next(state) % 2000u;
	default:
		return next(state);
	}
}

/* THIS FILE'S OWN SATURATING SUM. `sched.h` says the weights need no
 * particular scale, so a sum of three u32-by-u32 products can exceed 64 bits
 * and must land on the largest representable cost rather than wrapping to a
 * small one. */
static uint64_t model_add(uint64_t a, uint64_t b)
{
	return a > UINT64_MAX - b ? UINT64_MAX : a + b;
}

static uint64_t model_cost(const fzn_sched_candidate_t *l, const fzn_class_t *w)
{
	uint64_t c = 0;

	c = model_add(c, (uint64_t)w->weight_metric * (uint64_t)l->metric);
	c = model_add(c, (uint64_t)w->weight_latency * (uint64_t)l->latency_ms);
	c = model_add(c, (uint64_t)w->weight_loss * (uint64_t)l->loss_permille);
	return c;
}

/* Whether a link passes the class's hard constraints, decided here from what
 * `sched.h` states: a constraint of zero means no constraint, and a link the
 * consumer has marked unusable is not a candidate at all. */
static int model_admits(const fzn_sched_candidate_t *l, const fzn_class_t *w)
{
	if (!l->usable)
		return 0;
	if (w->max_latency_ms != 0u && l->latency_ms > w->max_latency_ms)
		return 0;
	if (w->max_loss_permille != 0u && l->loss_permille > w->max_loss_permille)
		return 0;
	if (w->min_mtu != 0u && l->mtu < w->min_mtu)
		return 0;
	return 1;
}

struct coverage {
	unsigned long none_qualified;
	unsigned long chose;
	unsigned long ties;
	unsigned long middle;
	unsigned long singletons;
	unsigned long saturated;
	unsigned long filtered_some;
};

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	fzn_sched_candidate_t links[LINKS_MAX];
	fzn_class_t wanted;
	size_t count, i, chosen = (size_t)-1, want_best = 0;
	uint64_t best = UINT64_MAX;
	int any = 0, tied = 0;
	fzn_sched_err_t err;

	count = 1u + (size_t)(next(&state) % LINKS_MAX);
	for (i = 0; i < count; i++) {
		links[i].id = (uint32_t)i + 1u;
		links[i].metric = draw_u32(&state);
		links[i].latency_ms = draw_u32(&state);
		links[i].loss_permille = (uint16_t)next(&state);
		links[i].mtu = draw_u32(&state);
		/* Mostly up, because a table of dead links asks nothing. */
		links[i].usable = (next(&state) % 8u) != 0u;

		/* AND SOMETIMES A DUPLICATE OF AN EARLIER LINK, because two
		 * candidates at the same cost is the state the lowest-index
		 * rule exists for and independent draws almost never produce
		 * it: 22 ties in 2000 cases, against a floor of 100, which is
		 * what the floor is for. Two links measuring identically is
		 * also what a real table looks like when both are idle. */
		if (i > 0u && (next(&state) % 3u) == 0u) {
			uint32_t keep_id = links[i].id;

			links[i] = links[next(&state) % i];
			links[i].id = keep_id;
		}
	}

	/* A constraint of zero is "no constraint", so zero has to be common or
	 * every case is filtered down to nothing. */
	wanted.max_latency_ms = (next(&state) % 2u) ? 0u : draw_u32(&state);
	wanted.max_loss_permille = (next(&state) % 2u) ? 0u : (uint16_t)next(&state);
	wanted.min_mtu = (next(&state) % 2u) ? 0u : draw_u32(&state);
	wanted.weight_metric = draw_u32(&state);
	wanted.weight_latency = draw_u32(&state);
	wanted.weight_loss = draw_u32(&state);

	if (count == 1u)
		cov->singletons++;

	/* PROPERTY 1 and the model's own argmin, in one pass. */
	for (i = 0; i < count; i++) {
		uint64_t mine = model_cost(&links[i], &wanted);
		uint64_t theirs = fzn_sched_cost(&links[i], &wanted);
		int admits_theirs = fzn_sched_admits(&links[i], &wanted) ? 1 : 0;
		int admits_mine = model_admits(&links[i], &wanted);

		if (mine != theirs) {
			printf("  MODEL: link %zu costs %llu here and %llu there\n", i,
			       (unsigned long long)mine, (unsigned long long)theirs);
			return 1;
		}
		if (mine == UINT64_MAX)
			cov->saturated++;
		if (admits_mine != admits_theirs) {
			printf("  MODEL: link %zu qualifies here (%d) and there (%d)\n", i,
			       admits_mine, admits_theirs);
			return 1;
		}
		if (!admits_mine)
			continue;
		if (!any || mine < best) {
			best = mine;
			want_best = i;
			any = 1;
			tied = 0;
		} else if (mine == best) {
			tied = 1;
		}
	}
	if (!any)
		cov->none_qualified++;
	if (tied)
		cov->ties++;
	if (any && want_best > 0u && want_best + 1u < count)
		cov->middle++;
	{
		size_t skipped = 0;

		for (i = 0; i < count; i++) {
			if (!model_admits(&links[i], &wanted))
				skipped++;
		}
		if (skipped > 0u && skipped < count)
			cov->filtered_some++;
	}

	err = fzn_sched_select(links, count, &wanted, &chosen);

	if (!any) {
		if (err != FZN_SCHED_ERR_NONE) {
			printf("  MODEL: nothing qualified and select answered %s\n",
			       fzn_sched_err_str(err));
			return 1;
		}
		if (chosen != (size_t)-1) {
			printf("  MODEL: select wrote a choice while answering NONE, so a "
			       "caller reading it uses a link this class refused\n");
			return 1;
		}
		return 0;
	}

	if (err != FZN_SCHED_OK) {
		printf("  MODEL: %zu link(s) qualified and select answered %s\n", count,
		       fzn_sched_err_str(err));
		return 1;
	}
	if (chosen >= count) {
		printf("  MODEL: select chose index %zu of %zu\n", chosen, count);
		return 1;
	}
	/* PROPERTY 2. */
	if (!fzn_sched_admits(&links[chosen], &wanted)) {
		printf("  MODEL: the chosen link does not satisfy the class's hard "
		       "constraints\n");
		return 1;
	}
	/* PROPERTY 3. */
	if (fzn_sched_cost(&links[chosen], &wanted) != best) {
		printf("  MODEL: the chosen link costs %llu and a qualifying one costs "
		       "%llu\n",
		       (unsigned long long)fzn_sched_cost(&links[chosen], &wanted),
		       (unsigned long long)best);
		return 1;
	}
	/* PROPERTY 4: among the cheapest, the earliest. */
	if (chosen != want_best) {
		printf("  MODEL: index %zu was chosen where %zu is the first qualifying "
		       "link at that cost, so identical candidates do not give identical "
		       "answers\n",
		       chosen, want_best);
		return 1;
	}
	cov->chose++;

	/*
	 * PROPERTY 5: THE FILTER IS NOT A PENALTY.
	 *
	 * sched.c says a link failing a hard constraint is skipped entirely
	 * rather than scored badly, because scoring it would let a large enough
	 * weight elsewhere bring it back. So which links qualify must not move
	 * when only the weights do -- asked by replacing the weights with new
	 * draws and requiring every verdict to be unchanged.
	 */
	{
		fzn_class_t reweighted = wanted;

		reweighted.weight_metric = draw_u32(&state);
		reweighted.weight_latency = draw_u32(&state);
		reweighted.weight_loss = draw_u32(&state);
		for (i = 0; i < count; i++) {
			if (!fzn_sched_admits(&links[i], &wanted)
			    != !fzn_sched_admits(&links[i], &reweighted)) {
				printf("  MODEL: link %zu changed whether it qualifies when "
				       "only the weights changed, so a hard constraint is "
				       "being scored rather than enforced\n",
				       i);
				return 1;
			}
		}
	}

	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0 };

	for (i = 0; i < size; i++)
		seed = (seed * 31u) + data[i];
	if (seed == 0u)
		seed = 1u;
	(void)fuzz_one(seed, &cov);
	return 0;
}
#else

static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long f = cases / per;

	return f == 0u ? 1u : f;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0 };
	unsigned long c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("sched_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will "
		       "not report success. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("sched_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* FLOORS ON STATES. A run that never saw a tie has not tested the rule
	 * that makes this scheduler reproducible; one that never chose a link
	 * in the MIDDLE of its set has tested an argmin two candidates could
	 * satisfy; one that never saturated a cost has not been near the
	 * arithmetic this module's only recorded defect lived in; and one where
	 * the filter never excluded some-but-not-all has not asked whether it
	 * is a filter. */
	if (cov.chose < floor_of(cases, 2u) || cov.none_qualified < floor_of(cases, 20u)
	    || cov.ties < floor_of(cases, 20u) || cov.middle < floor_of(cases, 8u)
	    || cov.singletons < floor_of(cases, 20u) || cov.saturated < floor_of(cases, 20u)
	    || cov.filtered_some < floor_of(cases, 8u)) {
		printf("sched_fuzz: REACHED TOO LITTLE -- %lu chose, %lu none qualified, %lu "
		       "ties, %lu chose from the middle, %lu singletons, %lu saturated "
		       "costs, %lu partly filtered in %lu cases.\n",
		       cov.chose, cov.none_qualified, cov.ties, cov.middle, cov.singletons,
		       cov.saturated, cov.filtered_some, cases);
		return 1;
	}

	printf("sched_fuzz: %lu cases, %lu chose, %lu none qualified, %lu ties, %lu from "
	       "the middle, %lu singletons, %lu saturated costs, %lu partly filtered, the "
	       "choice was a cheapest qualifying link throughout\n",
	       cases, cov.chose, cov.none_qualified, cov.ties, cov.middle, cov.singletons,
	       cov.saturated, cov.filtered_some);
	return 0;
}
#endif
