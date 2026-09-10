/*
 * Why a frame stopped here, and whether this host chose it.
 *
 * project.md sec 256. `wire/relay.h` spends a paragraph on the distinction
 * this exists to carry, and says what collapsing it costs:
 *
 *   EXHAUSTED says the frame has travelled as far as it was sent to travel,
 *   which is every frame's ordinary end and says nothing about this host;
 *   REFUSED says this host declined a subsystem it could have carried, which
 *   is a policy decision somebody made and may want to see counted, logged or
 *   reconsidered. Collapsing them would make a misconfigured policy
 *   indistinguishable from normal traffic reaching the end of its budget.
 *
 * Two negative integers, and an operator watching traffic stop cannot tell
 * which of those is happening. That is the question this answers -- **is my
 * own policy doing this** -- and it is the one a person asks first.
 *
 * SIX STATES:
 *
 *     carried        forwarded, with the budget that survived the clamp
 *     ended          the frame ran out. Ordinary, and not about this host
 *     REFUSED        this host does not carry that subsystem, by a policy
 *                    somebody wrote and can change
 *     foreign        not a frame this host can read the budget of, which is
 *                    a version difference rather than a decision
 *     local          the caller asked for something impossible
 *
 * A ZERO CEILING AND AN EXHAUSTED BUDGET ARE THE SAME NUMBER, and relay.h
 * says the status deliberately is not: `fzn_relay_budget` with an `allowed`
 * of zero answers OK with a budget of zero, while a policy `fallback` of zero
 * answers REFUSED. The frame stops either way and the reason a person acts on
 * is different, which is exactly what a surface is for.
 *
 * IT NAMES THE SUBSYSTEM AND THE CEILING, because "this host refuses that"
 * without saying which subsystem or what the ceiling is leaves an operator to
 * find the policy row themselves. The row is what they will change.
 *
 * IT READS AND DOES NOT DECIDE. Nothing here relays, clamps or spends, and
 * the verdict comes from the caller's own call rather than a second one --
 * `cli/sched_print`'s reason: a printer that asked again would be reporting
 * on an attempt the consumer never made.
 *
 * `FZN_RELAY_LINE_NONE` IS ZERO.
 */

#ifndef FZN_CLI_RELAY_PRINT_H
#define FZN_CLI_RELAY_PRINT_H

#include "../wire/relay.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_relay_line {
	/* No policy, or a code this does not understand. */
	FZN_RELAY_LINE_NONE = 0,
	/* Forwarded. */
	FZN_RELAY_LINE_CARRIED = 1,
	/* The budget ran out: the frame's ordinary end. */
	FZN_RELAY_LINE_ENDED = 2,
	/* This host declined a subsystem it could have carried. */
	FZN_RELAY_LINE_REFUSED = 3,
	/* Not a frame whose budget this host can read. */
	FZN_RELAY_LINE_FOREIGN = 4,
	/* The caller asked for something impossible. */
	FZN_RELAY_LINE_LOCAL = 5
} fzn_relay_line_t;

/* Room for the longest of the six lines, with a subsystem and a ceiling. */
#define FZN_RELAY_PRINT_MAX 300u

/*
 * Render what `err` said about a frame for `service`.
 *
 * `policy` and `policy_len` are the table the call was given, so that a
 * refusal can name the ceiling the operator will change; they may be NULL and
 * zero, in which case the line says which subsystem was refused and not what
 * permits it. `budget` is what `fzn_relay_budget_policy` wrote and is read
 * only when `err` is FZN_RELAY_OK.
 *
 * `state_out` is REQUIRED.
 */
fzn_relay_err_t fzn_relay_print(const fzn_relay_policy_t *policy, size_t policy_len,
                                uint16_t service, fzn_relay_err_t err, uint8_t budget,
                                char *out, size_t cap, size_t *len_out,
                                fzn_relay_line_t *state_out);

#endif /* FZN_CLI_RELAY_PRINT_H */
