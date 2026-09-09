/*
 * Which link this class got, or why traffic is being dropped.
 *
 * project.md sec 247. `sched.h` states the consequence that makes this worth
 * a line: "When nothing survives, `FZN_SCHED_ERR_NONE` is the answer and the
 * caller drops. Falling back to the least-bad survivor would be the wrong
 * kind of helpful." So a consumer holding that error is about to discard
 * somebody's traffic, and the only thing it has to explain that with is an
 * error code shared by every reason.
 *
 * THE REASONS WANT DIFFERENT ACTIONS, which is why they are separate states
 * rather than one wording:
 *
 *     every link down          the consumer's own links, not this class
 *     all too slow             raise max_latency_ms, or accept the delay
 *     all too lossy            raise max_loss_permille
 *     all too small            lower min_mtu, or fragment
 *     excluded for different   NO single change admits anything -- the
 *     reasons                  nearest thing to a fix is more links
 *
 * The last is the one a per-constraint message cannot say and the one a
 * reader most needs, because it is the case where every obvious remedy is
 * wrong. It is the same shape `cli/reasm_print` takes for a full table: three
 * causes, three actions, and a line that says which.
 *
 * IT READS AND DOES NOT DECIDE. Nothing here selects; `fzn_sched_select` is
 * called by the caller and its answer is passed in, so a report cannot
 * disagree with the choice that was actually made.
 *
 * WHY THE CALLER PASSES THE ANSWER IN rather than this calling select itself:
 * a consumer has already chosen by the time it wants to explain, and a
 * printer that selected again would be a second selection that could differ
 * -- on a table another thread had touched, or simply because the caller used
 * a different class. A report about a choice nobody made is worse than no
 * report.
 *
 * `FZN_SCHED_LINE_NONE` IS ZERO.
 */

#ifndef FZN_CLI_SCHED_PRINT_H
#define FZN_CLI_SCHED_PRINT_H

#include "../sched/sched.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_sched_line {
	/* No links, no class, or an answer that is neither OK nor NONE. */
	FZN_SCHED_LINE_NONE = 0,
	/* A link was chosen. */
	FZN_SCHED_LINE_CHOSEN = 1,
	/* Nothing qualified and no link was usable at all: every one is down.
	 * The class is not the problem and changing it will not help. */
	FZN_SCHED_LINE_NOTHING_UP = 2,
	/* Nothing qualified, links were up, and every exclusion was latency. */
	FZN_SCHED_LINE_TOO_SLOW = 3,
	/* ... loss. */
	FZN_SCHED_LINE_TOO_LOSSY = 4,
	/* ... MTU. */
	FZN_SCHED_LINE_TOO_SMALL = 5,
	/* Nothing qualified and the exclusions differ, so no single change to
	 * the class admits any link. Kept apart from the three above because
	 * each of those names a fix and this one has none to name. */
	FZN_SCHED_LINE_NO_SINGLE_FIX = 6
} fzn_sched_line_t;

/* Room for the longest of the seven lines, with three counts spelled out. */
#define FZN_SCHED_PRINT_MAX 300u

/*
 * Render the answer `fzn_sched_select` gave.
 *
 * `err` and `chosen` are what that call returned and wrote; `links`,
 * `link_count` and `wanted` are what it was given. Passing a different table
 * describes a selection that did not happen, which no signature can prevent
 * and this comment can at least name.
 *
 * `links` may be NULL or `link_count` zero, which is FZN_SCHED_LINE_NONE --
 * the same answer as a `wanted` of NULL, because a report with no candidates
 * and one with no class are equally unable to say anything.
 *
 * AN `err` THIS DOES NOT UNDERSTAND IS `NONE` RATHER THAN A GUESS.
 * FZN_SCHED_ERR_MALFORMED means the caller's own arguments were wrong and
 * says nothing about the links, so there is no reason to report on them.
 *
 * `state_out` is REQUIRED.
 */
fzn_sched_err_t fzn_sched_print(const fzn_sched_candidate_t *links, size_t link_count,
                                const fzn_class_t *wanted, fzn_sched_err_t err, size_t chosen,
                                char *out, size_t cap, size_t *len_out,
                                fzn_sched_line_t *state_out);

#endif /* FZN_CLI_SCHED_PRINT_H */
