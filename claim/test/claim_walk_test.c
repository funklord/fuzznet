/*
 * Every sequence of claim operations and backend answers, to a depth.
 *
 * WHY EXHAUSTIVE. This is two operations over a seam with three answers for
 * one of them and two for the other -- five steps -- so every sequence of
 * five is 3125 walks and runs in less time than drawing random ones would.
 * `trust/test/trust_walk_test.c` makes the same trade for the same reason: a
 * harness reports what it happened to reach, and this reports that there is
 * nothing else to reach.
 *
 * THE SEAM IS PART OF THE STATE, which is what makes this worth walking at
 * all rather than testing by hand. `fzn_claim_take` asks the backend and then
 * reads `held_out` to tell contention from breakage, so the same operation
 * has three outcomes depending on an answer the test chooses -- and the
 * sequences that matter are the ones where those interleave.
 *
 * THE PROPERTY THAT NEEDS NO MODEL, and the exception that is the point:
 *
 *   - every refusal from `fzn_claim_take` leaves the object byte-identical.
 *     A claim that moved on a refusal would have this process believing
 *     something about ownership that nothing established.
 *
 *   - `fzn_claim_release` IS DIFFERENT ON PURPOSE. It clears `held` before
 *     asking the backend and leaves it cleared even when the backend
 *     refuses, and `claim.c` says why: "a process that believes it owns
 *     state the kernel may have handed on ... Of the two wrong answers,
 *     refusing to act is the one that cannot desynchronise a ratchet."
 *
 * SO THE SECOND IS PINNED RATHER THAN ASSERTED AWAY. It is sec 243's shape:
 * a reader meeting a failed release that still cleared the flag would
 * reasonably call it a bug, and "fixing" it puts this process back in the
 * state the comment rules out. **THIS TEST IS EXPECTED TO FAIL THE DAY
 * SOMEBODY MAKES A FAILED RELEASE KEEP THE CLAIM**, which is its purpose.
 */

#include "../claim.h"

#include <stdio.h>
#include <string.h>

/* NO `CHECK` MACRO. Every assertion here has a SEQUENCE to report, and a
 * failure naming a line number would leave a reader to work out which of 3125
 * walks it was -- `trust_walk_test.c`'s reason. */
static int failures;
static int checks;

/* The seam's answers, chosen per step by the walk. */
static int seam_take_result;
static int seam_held_out;
static int seam_release_result;

static int seam_take(void *ctx, int *held_out)
{
	(void)ctx;
	*held_out = seam_held_out;
	return seam_take_result;
}

static int seam_release(void *ctx)
{
	(void)ctx;
	return seam_release_result;
}

static const fzn_claim_ops_t OPS = { seam_take, seam_release, NULL };

/* Five (operation, answer) steps. */
#define STEPS 5u
#define DEPTH 5u

struct model {
	int held;
};

static const char *step_name(unsigned step)
{
	switch (step) {
	case 0:
		return "take=got";
	case 1:
		return "take=held";
	case 2:
		return "take=broken";
	case 3:
		return "release=ok";
	default:
		return "release=fails";
	}
}

/* Sets the seam for this step and returns what the call must answer, moving
 * the model. WRITTEN FROM claim.h AND claim.c's stated reasons, not from
 * reading the branch order. */
static fzn_claim_err_t model_step(struct model *m, unsigned step)
{
	if (step <= 2u) {
		/* take */
		seam_take_result = (step == 0u) ? 1 : 0;
		seam_held_out = (step == 1u) ? 1 : 0;
		seam_release_result = 1;

		/* TAKING ONE THIS PROCESS ALREADY HOLDS IS A LOST TRACK, not a
		 * no-op: claim.c says a per-open-file-description lock would
		 * report success for a second take and leave the caller
		 * believing two takes need two releases. */
		if (m->held)
			return FZN_CLAIM_ERR_STATE;
		if (step == 0u) {
			m->held = 1;
			return FZN_CLAIM_OK;
		}
		return (step == 1u) ? FZN_CLAIM_ERR_HELD : FZN_CLAIM_ERR_BACKEND;
	}

	/* release */
	seam_take_result = 1;
	seam_held_out = 0;
	seam_release_result = (step == 3u) ? 1 : 0;

	if (!m->held)
		return FZN_CLAIM_ERR_STATE;

	/* CLEARED WHETHER OR NOT THE BACKEND SUCCEEDS. */
	m->held = 0;
	return (step == 3u) ? FZN_CLAIM_OK : FZN_CLAIM_ERR_BACKEND;
}

static fzn_claim_err_t real_step(fzn_claim_t *c, unsigned step)
{
	return step <= 2u ? fzn_claim_take(c) : fzn_claim_release(c);
}

/* How many walks reached each verdict, so a run that exercised one arm and
 * called itself exhaustive says so. */
static unsigned long saw_ok, saw_state, saw_held, saw_backend, saw_failed_release;

static int walk(void)
{
	unsigned long combos = 1u;
	unsigned i;
	char trail[256];

	for (i = 0; i < DEPTH; i++)
		combos *= STEPS;

	for (unsigned long c = 0; c < combos; c++) {
		unsigned long rest = c;
		unsigned seq[DEPTH];
		fzn_claim_t claim;
		struct model m;
		size_t at = 0u;

		/* ZEROED BEFORE INIT so the padding this struct carries is
		 * deterministic and `memcmp` below means what it says. sec 259
		 * is where that lesson was paid for. */
		memset(&claim, 0, sizeof(claim));
		if (fzn_claim_init(&claim, &OPS) != FZN_CLAIM_OK) {
			fprintf(stderr, "  FAIL claim_walk_test.c: init refused\n");
			failures++;
			checks++;
			return 1;
		}
		m.held = 0;
		trail[0] = '\0';

		for (i = 0; i < DEPTH; i++) {
			seq[i] = (unsigned)(rest % STEPS);
			rest /= STEPS;
		}

		for (i = 0; i < DEPTH; i++) {
			fzn_claim_t before = claim;
			struct model expected = m;
			fzn_claim_err_t want, got;

			at += (size_t)snprintf(trail + at, sizeof(trail) - at, "%s%s",
			                       at ? " " : "", step_name(seq[i]));

			want = model_step(&expected, seq[i]);
			got = real_step(&claim, seq[i]);
			checks++;

			if (want != got) {
				fprintf(stderr,
				        "  FAIL claim_walk_test.c: after [%s] the model says "
				        "%s and the module says %s\n",
				        trail, fzn_claim_err_str(want),
				        fzn_claim_err_str(got));
				failures++;
				return 1;
			}

			/*
			 * A REFUSED TAKE MOVES NOTHING, and a refused release
			 * moves `held` on purpose. Asserting the second rather
			 * than exempting it is what makes it a decision
			 * somebody has to come here to change.
			 */
			checks++;
			if (seq[i] <= 2u && got != FZN_CLAIM_OK) {
				if (memcmp(&before, &claim, sizeof(claim)) != 0) {
					fprintf(stderr,
					        "  FAIL claim_walk_test.c: [%s] was refused "
					        "with %s and changed the claim\n",
					        trail, fzn_claim_err_str(got));
					failures++;
					return 1;
				}
			} else if (seq[i] > 2u && got == FZN_CLAIM_ERR_BACKEND) {
				if (fzn_claim_held(&claim)) {
					fprintf(stderr,
					        "  FAIL claim_walk_test.c: [%s] failed to "
					        "release and this object still believes it "
					        "holds the claim, which claim.c rules out "
					        "as the answer that can desynchronise a "
					        "ratchet\n",
					        trail);
					failures++;
					return 1;
				}
				saw_failed_release++;
			}

			m = expected;

			checks++;
			if (!fzn_claim_held(&claim) != !m.held) {
				fprintf(stderr,
				        "  FAIL claim_walk_test.c: after [%s] the claim says "
				        "held=%d and should be %d\n",
				        trail, fzn_claim_held(&claim), m.held);
				failures++;
				return 1;
			}

			if (got == FZN_CLAIM_OK)
				saw_ok++;
			else if (got == FZN_CLAIM_ERR_STATE)
				saw_state++;
			else if (got == FZN_CLAIM_ERR_HELD)
				saw_held++;
			else if (got == FZN_CLAIM_ERR_BACKEND)
				saw_backend++;
		}
	}
	return 0;
}

int main(void)
{
	if (walk()) {
		printf("claim_walk_test: %d checks, %d failure(s)\n", checks, failures);
		return 1;
	}

	/* EVERY ARM WAS REACHED, or the walk proved less than it claims. */
	if (!saw_ok || !saw_state || !saw_held || !saw_backend || !saw_failed_release) {
		printf("claim_walk_test: REACHED TOO LITTLE -- %lu ok, %lu lost-track, %lu "
		       "held elsewhere, %lu backend, %lu failed releases\n",
		       saw_ok, saw_state, saw_held, saw_backend, saw_failed_release);
		return 1;
	}

	printf("claim_walk_test: %d checks, %d failure(s); every sequence of %u steps "
	       "agreed (%lu ok, %lu lost-track, %lu held elsewhere, %lu backend, %lu "
	       "failed releases)\n",
	       checks, failures, DEPTH, saw_ok, saw_state, saw_held, saw_backend,
	       saw_failed_release);
	return failures == 0 ? 0 : 1;
}
