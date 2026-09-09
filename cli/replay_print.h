/*
 * How full this host's replay window is, and -- when it is full -- which of
 * the two fixes it needs.
 *
 * project.md sec 229. `frame/freshness.h` is the model, and it asked for this
 * line before anything could produce it: a full window "means either that
 * nobody is expiring or that the capacity is below the arrival rate the
 * horizon implies", and "those want different fixes and the value says
 * neither".
 *
 * A FULL WINDOW IS AN EMERGENCY AND DOES NOT LOOK LIKE ONE. The window
 * refuses rather than evicting, deliberately -- evicting would let an
 * attacker flush it and replay what they recorded -- so a host in this state
 * is REFUSING FRESH FRAMES. It is not corrupt, it is not crashing, and the
 * only thing that says so is a return value handed to a caller that may do
 * nothing with it.
 *
 * FIVE STATES, NAMED, NO `default:`, and FULL is TWO of them rather than one
 * with two wordings. That is the opposite call from `cli/manifest_print`,
 * where a floor of three and a floor of zero share a state because a caller
 * does the same thing about both. Here the two causes want DIFFERENT ACTIONS
 * -- call expire, or raise the capacity -- so they are different states.
 *
 * IT READS AND DOES NOT DECIDE. Nothing here expires, admits or resizes, and
 * `fzn_replay_expirable` exists precisely so that counting what expiry would
 * reclaim does not reclaim it.
 *
 * `FZN_REPLAY_LINE_NONE` IS ZERO.
 */

#ifndef FZN_CLI_REPLAY_PRINT_H
#define FZN_CLI_REPLAY_PRINT_H

#include "../frame/freshness.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_replay_line {
	/* No window, or one whose own fields disagree. */
	FZN_REPLAY_LINE_NONE = 0,
	/* Nothing recorded. A host that has admitted no frame yet, which is
	 * not the same as one that is keeping up. */
	FZN_REPLAY_LINE_EMPTY = 1,
	/* Recording, with room. */
	FZN_REPLAY_LINE_HOLDING = 2,
	/* Full, and entries are already past their expiry: nothing is calling
	 * `fzn_replay_expire`. The fix is a caller, not a bigger array. */
	FZN_REPLAY_LINE_FULL_UNPRUNED = 3,
	/* Full of entries that are all still live: the capacity is below what
	 * this horizon implies. The fix is the sizing formula at the top of
	 * `frame/freshness.h`, not a call. */
	FZN_REPLAY_LINE_FULL_LIVE = 4
} fzn_replay_line_t;

/* Room for the longest of the five lines, with three counts spelled out. */
#define FZN_REPLAY_PRINT_MAX 200u

/*
 * Render one window against `now`.
 *
 * `window` may be NULL, which is FZN_REPLAY_LINE_NONE.
 *
 * `now` is the caller's clock, in the units the window was sized in, and it
 * is what makes the two FULL states distinguishable: an entry is reclaimable
 * exactly when `expires_at <= now`, the same boundary `fzn_replay_expire`
 * draws.
 *
 * `state_out` is REQUIRED. The two FULL states are the whole content here,
 * and a caller that cannot see which it has is back to the value that "says
 * neither".
 */
fzn_fresh_err_t fzn_replay_print(const fzn_replay_window_t *window, uint64_t now, char *out,
                                 size_t cap, size_t *len_out, fzn_replay_line_t *state_out);

#endif /* FZN_CLI_REPLAY_PRINT_H */
