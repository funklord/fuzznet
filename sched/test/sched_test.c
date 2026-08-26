/* Two links and two classes giving opposite answers.
 *
 * That is the test this module exists to pass, and fuzzypickles' own header
 * says why: "a max-importance message wants the link most likely to arrive,
 * which may be the slowest. A fire-and-forget voice frame wants the fastest
 * link and is happily dropped. Do not collapse these into one number." A
 * scheduler that scored links once and reused the score would give the same
 * answer to both, and would be wrong for one of them every time.
 *
 * The other case that matters is a class nothing satisfies. A link too slow
 * for a deadline is not a worse choice, it is not a choice, and returning the
 * least-bad survivor would be the wrong kind of helpful.
 */

#include "../sched.h"

#include <stdio.h>

static int failures;
static int checks;

static void expect(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

static void expect_err(fzn_sched_err_t got, fzn_sched_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		printf("  FAIL: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_sched_err_str(got),
		       fzn_sched_err_str(want));
	}
}

int main(void)
{
	/* FAST is quick and lossy: a radio. SURE is slow and reliable: a
	 * store-and-forward path. Neither is better; it depends who is asking. */
	static const fzn_sched_candidate_t LINKS[2] = {
		{ .id = 1, .metric = 10, .latency_ms = 20, .loss_permille = 150, .mtu = 1500,
		  .usable = 1 },
		{ .id = 2, .metric = 10, .latency_ms = 4000, .loss_permille = 1, .mtu = 1500,
		  .usable = 1 },
	};
	const size_t FAST = 0, SURE = 1;

	/* A voice frame: cares only about latency, and is happy to lose some. */
	static const fzn_class_t VOICE = { .max_latency_ms = 200,
		                           .weight_metric = 0,
		                           .weight_latency = 10,
		                           .weight_loss = 0 };
	/* A configuration change: must arrive, and can wait. */
	static const fzn_class_t IMPORTANT = { .max_loss_permille = 50,
		                               .weight_metric = 0,
		                               .weight_latency = 0,
		                               .weight_loss = 100 };

	size_t chosen = 99;

	/* THE CENTREPIECE. Same two links, two classes, opposite answers. */
	expect_err(fzn_sched_select(LINKS, 2, &VOICE, &chosen), FZN_SCHED_OK, "choosing for voice");
	expect(chosen == FAST, "voice must take the fast link");

	expect_err(fzn_sched_select(LINKS, 2, &IMPORTANT, &chosen), FZN_SCHED_OK,
	           "choosing for a configuration change");
	expect(chosen == SURE, "an important message must take the reliable link");

	/* And the reason it is not one number: each class EXCLUDED the other's
	 * choice on a hard constraint, rather than merely scoring it lower. */
	expect(!fzn_sched_admits(&LINKS[SURE], &VOICE), "the slow link cannot carry voice at all");
	expect(!fzn_sched_admits(&LINKS[FAST], &IMPORTANT),
	       "the lossy link cannot carry an important message at all");

	/* NOTHING QUALIFIES IS A REAL ANSWER. */
	{
		static const fzn_class_t IMPOSSIBLE = { .max_latency_ms = 1,
			                                .weight_latency = 1 };

		expect_err(fzn_sched_select(LINKS, 2, &IMPOSSIBLE, &chosen), FZN_SCHED_ERR_NONE,
		           "a class nothing can satisfy");
	}

	/* A DOWN LINK IS NOT A CANDIDATE, whatever its numbers say. */
	{
		fzn_sched_candidate_t pair[2] = { LINKS[FAST], LINKS[SURE] };
		static const fzn_class_t ANY = { .weight_latency = 1 };

		pair[0].usable = 0;
		expect_err(fzn_sched_select(pair, 2, &ANY, &chosen), FZN_SCHED_OK,
		           "one link down, one up");
		expect(chosen == 1, "the usable one must be chosen even though it is slower");

		pair[1].usable = 0;
		expect_err(fzn_sched_select(pair, 2, &ANY, &chosen), FZN_SCHED_ERR_NONE,
		           "every link down");
	}

	/* MTU IS A HARD CONSTRAINT TOO: a link that cannot carry the datagram
	 * is not a slower way to send it. */
	{
		fzn_sched_candidate_t small = LINKS[FAST];
		static const fzn_class_t BIG = { .min_mtu = 1400, .weight_latency = 1 };

		small.mtu = 576;
		expect(!fzn_sched_admits(&small, &BIG), "a link below the required MTU");
		expect(fzn_sched_admits(&LINKS[FAST], &BIG), "and one above it");
	}

	/* AN UNCONSTRAINED CLASS ADMITS EVERY USABLE LINK, which is the right
	 * answer for traffic with no deadline rather than a missing check. */
	{
		static const fzn_class_t NOTHING_MATTERS = { 0, 0, 0, 0, 0, 0 };

		expect(fzn_sched_admits(&LINKS[FAST], &NOTHING_MATTERS), "an unconstrained class");
		expect(fzn_sched_admits(&LINKS[SURE], &NOTHING_MATTERS), "admits both");
		/* Every cost is zero, so the tie must go to the first -- the
		 * same inputs always giving the same answer. */
		expect_err(fzn_sched_select(LINKS, 2, &NOTHING_MATTERS, &chosen), FZN_SCHED_OK,
		           "selecting with all weights zero");
		expect(chosen == 0, "a tie must go to the lowest index, reproducibly");
	}

	/* COST WIDENS BEFORE MULTIPLYING. A wrapped cost would make a terrible
	 * link look excellent, and it would be chosen consistently and look
	 * deliberate. */
	{
		fzn_sched_candidate_t huge = { .id = 3,
			            .metric = 4000000000u,
			            .latency_ms = 4000000000u,
			            .loss_permille = 1000,
			            .mtu = 1500,
			            .usable = 1 };
		static const fzn_class_t HEAVY = { .weight_metric = 1000,
			                           .weight_latency = 1000,
			                           .weight_loss = 1000 };
		uint64_t cost = fzn_sched_cost(&huge, &HEAVY);

		expect(cost > 0xffffffffu, "a large cost must not have wrapped into 32 bits");
	}

	/* AND THE SUM MUST NOT WRAP EITHER, which is a different check from the
	 * one above and is the one that was missing.
	 *
	 * The case above passes with weights of 1000: three products of about
	 * 4e12 sum to 8e12, nowhere near the top of a uint64. It exercises the
	 * widening of each MULTIPLY, which was always correct, and it sat under
	 * a comment describing the failure as though the whole cost were
	 * covered. The accumulation was a bare `+=` and this suite was green.
	 *
	 * Measured against the code before the fix: this link cost **zero** --
	 * the cheapest value representable -- and was selected over a link of
	 * 1 ms. Both halves are asserted, because a cost that saturates but a
	 * selection that still picked the wrong link would be no better. */
	{
		fzn_sched_candidate_t pair[2] = {
			{ .id = 1,
			  .metric = 4294967295u,
			  .latency_ms = 4294967295u,
			  .loss_permille = 1,
			  .mtu = 1500,
			  .usable = 1 },
			{ .id = 2,
			  .metric = 1,
			  .latency_ms = 1,
			  .loss_permille = 0,
			  .mtu = 1500,
			  .usable = 1 },
		};
		/* Inside the contract: sched.h states the weights need no
		 * particular scale, and every hard constraint is unset here, so
		 * the admission filter offers no protection. */
		static const fzn_class_t CRUSHING = { .weight_metric = 4294967295u,
			                              .weight_latency = 2,
			                              .weight_loss = 1 };
		size_t worst = 99;

		expect(fzn_sched_cost(&pair[0], &CRUSHING) > fzn_sched_cost(&pair[1], &CRUSHING),
		       "a link costing four billion ms must not come out cheaper than one "
		       "costing 1 ms");
		expect_err(fzn_sched_select(pair, 2, &CRUSHING, &worst), FZN_SCHED_OK,
		           "selecting between a terrible link and a good one");
		expect(worst == 1, "the terrible link was chosen over the good one");
	}

	/* Arguments. */
	expect_err(fzn_sched_select(NULL, 2, &VOICE, &chosen), FZN_SCHED_ERR_MALFORMED,
	           "a null link array");
	expect_err(fzn_sched_select(LINKS, 0, &VOICE, &chosen), FZN_SCHED_ERR_MALFORMED,
	           "no links at all");
	expect_err(fzn_sched_select(LINKS, 2, NULL, &chosen), FZN_SCHED_ERR_MALFORMED,
	           "a null class");
	expect_err(fzn_sched_select(LINKS, 2, &VOICE, NULL), FZN_SCHED_ERR_MALFORMED,
	           "nowhere to answer");
	expect(!fzn_sched_admits(NULL, &VOICE), "a null link admits nothing");
	expect(!fzn_sched_admits(&LINKS[0], NULL), "a null class admits nothing");
	expect(fzn_sched_cost(NULL, &VOICE) == UINT64_MAX, "a null link costs the most");
	expect(fzn_sched_cost(&LINKS[0], NULL) == UINT64_MAX, "as does a null class");

	printf("sched_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
