/*
 * What is about to be taken off this host, how far it has got, and -- when
 * nothing is going -- why nothing is going.
 *
 * project.md sec 194. `gui/sweep_view` is the same facts for a screen, and
 * since sec 193 that widget SHOWS THIS FILE'S LINE rather than composing its
 * own. The rule that section states is why they arrived together: a printer
 * written for a fact a widget already shows re-creates sec 168's duplication
 * unless the widget changes in the same commit.
 *
 * THE STATE GOES OUT OF BAND, on sec 191's argument. A host reclaiming disk
 * unattended is exactly the case where somebody has written a monitoring
 * script, and a script must not read the sentence.
 *
 * `FZN_SWEEP_NOTHING_CAPTURED` IS ZERO, so a caller that ignores the state,
 * or reads it after a refusal, is told nobody has asked rather than that
 * nothing needs doing. Those are different and only one of them is safe to
 * act on.
 *
 * HELD BACK IS NOT EMPTY, which is `catalog/sweep.h`'s own requirement and
 * the reason its counters are kept apart: "a sweep held back by the last-copy
 * guard would be indistinguishable from a catalogue with nothing to sweep --
 * and those want opposite responses". On a screen that is a person misreading
 * a zero. In an alerting rule it is a host whose disk cannot be reclaimed
 * reporting the same as one with nothing to reclaim, and the second is fine
 * while the first needs more replicas.
 *
 * TRUNCATION IS ITS OWN OUT-PARAMETER because it is orthogonal to the state:
 * a plan can be READY and short at the same time, and "short" means every
 * count beside it understates. sweep.h: a sweep that silently held some of
 * them "would leave a consumer believing it had reclaimed what it had not".
 */

#ifndef FZN_CLI_SWEEP_PRINT_H
#define FZN_CLI_SWEEP_PRINT_H

#include "../catalog/sweep.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_sweep_state {
	FZN_SWEEP_NOTHING_CAPTURED = 0,
	FZN_SWEEP_HELD_BACK = 1,
	FZN_SWEEP_EMPTY = 2,
	FZN_SWEEP_READY = 3,
	FZN_SWEEP_RUNNING = 4,
	FZN_SWEEP_DONE = 5
} fzn_sweep_state_t;

/* Room for the longest line this writes. */
#define FZN_SWEEP_PRINT_MAX 320u

/*
 * Render one plan, and the job carrying it out if there is one.
 *
 * `plan` may be NULL, which is FZN_SWEEP_NOTHING_CAPTURED -- a consumer that
 * has not run `fzn_catalog_sweep_capture` has not asked the question, which
 * is not the same as having asked and been told nothing.
 *
 * `job` may be NULL: a plan is worth reporting before anybody begins.
 *
 * `state_out` and `truncated_out` are both REQUIRED, on
 * `fzn_manifest_deficit`'s argument for its own `dropped`.
 *
 * NOTHING HERE MUTATES. `fzn_catalog_sweep_advance` is called AFTER bytes are
 * gone, so a reporter that advanced a cursor would record a removal that
 * never happened -- sec 181's rule, and it applies to a printer exactly as it
 * applies to a widget.
 */
fzn_catalog_err_t fzn_sweep_print(const fzn_catalog_sweep_plan_t *plan,
                                  const fzn_catalog_sweep_t *job, char *out, size_t cap,
                                  size_t *len_out, fzn_sweep_state_t *state_out,
                                  int *truncated_out);

#endif /* FZN_CLI_SWEEP_PRINT_H */
