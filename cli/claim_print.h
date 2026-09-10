/*
 * Whether this process owns the identity, and what to tell a person when it
 * does not.
 *
 * project.md sec 251. `claim.h` draws the line this exists to carry, in its
 * own words about FZN_CLAIM_ERR_HELD:
 *
 *   AN ANSWER RATHER THAN A FAULT -- it is the expected result for every
 *   process but one, and a caller that logs it as an error will fill a log
 *   on a working host.
 *
 * A consumer that shows a user "could not start: error -2" when the honest
 * sentence is "another window of this application has it, which is normal"
 * has turned the working case into an alarm. That is the same mistake
 * `cli/authz_print` names for an unspelled policy and `cli/trust_print` for
 * an absent anchor, and it is worse here because the reader is a person
 * deciding whether their data is broken.
 *
 * FOUR ANSWERS, FOUR THINGS TO DO:
 *
 *     this process owns it       nothing; go on
 *     this process let go        nothing; another may take it now
 *     another process owns it    nothing; read the shared store and submit
 *                                through the owner, which is the design
 *     the backend could not say  an operator: the store cannot arbitrate
 *                                ownership at all, so it is unusable
 *     the caller lost track      a bug in the consumer, not the host
 *
 * The third and fourth are collapsed by no wording and separated by no return
 * value a person sees: FZN_CLAIM_ERR_BACKEND and FZN_CLAIM_ERR_STATE are both
 * negative integers to whoever is reading a dialog.
 *
 * MALFORMED AND STATE SHARE A LINE, on sec 201's rule. A null argument and a
 * release without a take are both the consumer having lost track of which
 * process it is in, the person reading cannot act on either, and splitting
 * them would be a distinction drawn for the code's benefit on a surface the
 * code does not read.
 *
 * IT READS AND DOES NOT DECIDE. Nothing here takes or releases anything, and
 * the answer comes from the caller rather than from a second attempt --
 * `cli/sched_print`'s reason: a printer that tried the claim itself would be
 * reporting on an attempt the consumer never made, and on a claim this one
 * might have taken.
 *
 * `FZN_CLAIM_LINE_NONE` IS ZERO.
 */

#ifndef FZN_CLI_CLAIM_PRINT_H
#define FZN_CLI_CLAIM_PRINT_H

#include "../claim/claim.h"

#include <stddef.h>

typedef enum fzn_claim_line {
	/* No claim, or a code this does not understand. */
	FZN_CLAIM_LINE_NONE = 0,
	/* This process holds it. */
	FZN_CLAIM_LINE_OWNED = 1,
	/* Another process holds it, and everything is working. */
	FZN_CLAIM_LINE_ELSEWHERE = 2,
	/* The backend could not arbitrate at all. The one that needs somebody
	 * to look at the host. */
	FZN_CLAIM_LINE_UNARBITRATED = 3,
	/* The consumer asked for something its own state contradicts. */
	FZN_CLAIM_LINE_MISUSE = 4,
	/* This process gave it up and nobody is known to hold it now.
	 *
	 * SEPARATE FROM ELSEWHERE, because "somebody else has it" and "I let
	 * go of it" are different facts and only the first is a reason this
	 * process cannot write. The first draft of this file folded them
	 * together -- a release returns OK and leaves the claim unheld, so the
	 * OK arm reported that another process owned it, which is a sentence
	 * about a host nobody had asked about. */
	FZN_CLAIM_LINE_RELEASED = 5
} fzn_claim_line_t;

/* Room for the longest of the five lines. */
#define FZN_CLAIM_PRINT_MAX 200u

/*
 * Render what `err` said about `claim`.
 *
 * `err` is what `fzn_claim_take` or `fzn_claim_release` returned. `claim` may
 * be NULL, which is FZN_CLAIM_LINE_NONE whatever `err` says -- there is
 * nothing to report on.
 *
 * AN OK IS READ AGAINST `fzn_claim_held` RATHER THAN TRUSTED. A release
 * returns OK and leaves the claim unheld, and a take returns OK and leaves it
 * held, so the code alone does not say which way round the caller is. Asking
 * the claim is what lets one line serve both calls -- and the unheld OK is
 * RELEASED rather than ELSEWHERE, because this process letting go says
 * nothing about whether anybody else has picked it up.
 *
 * `state_out` is REQUIRED.
 */
fzn_claim_err_t fzn_claim_print(const fzn_claim_t *claim, fzn_claim_err_t err, char *out,
                                size_t cap, size_t *len_out, fzn_claim_line_t *state_out);

#endif /* FZN_CLI_CLAIM_PRINT_H */
