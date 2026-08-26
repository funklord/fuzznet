/* See sched.h. */

#include "sched.h"

int fzn_sched_admits(const fzn_link_t *link, const fzn_class_t *class)
{
	if (!link || !class)
		return 0;
	if (!link->usable)
		return 0;

	/* Zero means unconstrained, for each of the three. A class that cares
	 * about nothing admits every usable link, which is the right answer for
	 * traffic with no deadline. */
	if (class->max_latency_ms != 0 && link->latency_ms > class->max_latency_ms)
		return 0;
	if (class->max_loss_permille != 0 && link->loss_permille > class->max_loss_permille)
		return 0;
	if (class->min_mtu != 0 && link->mtu < class->min_mtu)
		return 0;

	return 1;
}

uint64_t fzn_sched_cost(const fzn_link_t *link, const fzn_class_t *class)
{
	uint64_t cost = 0;

	if (!link || !class)
		return UINT64_MAX;

	/* Widened before multiplying. Two uint32 weights against a uint32
	 * latency overflow 32 bits easily, and a wrapped cost would make a bad
	 * link look excellent -- which is the failure mode a scheduler must not
	 * have, since it would be chosen consistently and look deliberate. */
	cost += (uint64_t)class->weight_metric * (uint64_t)link->metric;
	cost += (uint64_t)class->weight_latency * (uint64_t)link->latency_ms;
	cost += (uint64_t)class->weight_loss * (uint64_t)link->loss_permille;

	return cost;
}

fzn_sched_err_t fzn_sched_select(const fzn_link_t *links, size_t link_count,
                                  const fzn_class_t *class, size_t *chosen)
{
	size_t best = 0;
	uint64_t best_cost = 0;
	int found = 0;

	if (!links || !class || !chosen || link_count == 0)
		return FZN_SCHED_ERR_MALFORMED;

	for (size_t i = 0; i < link_count; i++) {
		uint64_t cost;

		/* THE FILTER IS NOT A PENALTY. A link that fails a hard
		 * constraint is skipped entirely rather than scored badly:
		 * scoring it would let a large enough weight elsewhere bring it
		 * back, which is exactly the "wrong kind of helpful" this
		 * module refuses. */
		if (!fzn_sched_admits(&links[i], class))
			continue;

		cost = fzn_sched_cost(&links[i], class);
		/* Strictly less than, so a tie leaves the earlier candidate in
		 * place and the same inputs always give the same answer. */
		if (!found || cost < best_cost) {
			best = i;
			best_cost = cost;
			found = 1;
		}
	}

	if (!found)
		return FZN_SCHED_ERR_NONE;

	*chosen = best;
	return FZN_SCHED_OK;
}

const char *fzn_sched_err_str(fzn_sched_err_t err)
{
	switch (err) {
	case FZN_SCHED_OK:
		return "ok";
	case FZN_SCHED_ERR_MALFORMED:
		return "malformed argument";
	case FZN_SCHED_ERR_NONE:
		return "no link satisfies this class";
	}

	return "unknown";
}
