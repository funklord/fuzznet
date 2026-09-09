/*
 * How full this host's reassembly table is and, when it is full, which of
 * three fixes it needs.
 *
 * project.md sec 230. `chunk/reassembly.h` names the problem on
 * FZN_REASM_ERR_FULL itself, and names it as a MISREADING somebody has
 * already had:
 *
 *   "IT NO LONGER MEANS 'live, unexpired' ... A slot may be HANDED --
 *   completed and waiting on the caller to release it, which the sweep must
 *   not take ... Both are live and neither is reclaimable by waiting, so a
 *   consumer reading the old wording would conclude that TIME ALONE FIXES A
 *   FULL TABLE. Releasing what it holds is the other half."
 *
 * So a full table has three causes and they want three different actions:
 *
 *   slots past their deadline    call `fzn_reasm_expire`
 *   slots handed and not released   the CONSUMER is leaking them
 *   slots live, held and unexpired  `capacity` or `per_sender_max` is small
 *
 * The middle one is a bug in the consumer that never self-corrects, and
 * `reassembly.h` says exhaustion is the deliberate, honest symptom of it:
 * "A caller that never releases now exhausts the table and sees FULL. That is
 * the honest failure and it is the smaller harm." A line that cannot tell it
 * from a sizing problem sends somebody to enlarge a table that will fill
 * again.
 *
 * NO NEW ACCESSOR WAS NEEDED, and that is worth saying because the two
 * printers before this one each closed a library gap. `fzn_partial_t` is a
 * public type with `live`, `handed` and `expires_at` on it, so a consumer
 * COULD write this walk. What it would have to get right is the
 * classification -- which is the thing the header says a consumer gets
 * wrong -- so this does it once, in the module's own terms.
 *
 * IT READS AND DOES NOT DECIDE. Nothing here expires, releases or resizes.
 *
 * `FZN_REASM_LINE_NONE` IS ZERO.
 */

#ifndef FZN_CLI_REASM_PRINT_H
#define FZN_CLI_REASM_PRINT_H

#include "../chunk/reassembly.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_reasm_line {
	/* No table, or one whose own fields disagree. */
	FZN_REASM_LINE_NONE = 0,
	/* Nothing half-finished. */
	FZN_REASM_LINE_EMPTY = 1,
	/* Holding, with room. */
	FZN_REASM_LINE_HOLDING = 2,
	/* Full, and slots are handed to the caller and not released. The fix
	 * is the consumer's, and it is a leak rather than a size. */
	FZN_REASM_LINE_FULL_HANDED = 3,
	/* Full, with slots past their deadline: nothing is calling
	 * `fzn_reasm_expire`. */
	FZN_REASM_LINE_FULL_UNSWEPT = 4,
	/* Full of slots that are live, unexpired and unhanded. Time will not
	 * fix this one and neither will releasing: the bounds are too small
	 * for the traffic. */
	FZN_REASM_LINE_FULL_LIVE = 5
} fzn_reasm_line_t;

/* Room for the longest of the six lines, with three counts spelled out. */
#define FZN_REASM_PRINT_MAX 200u

/*
 * Render one table against `now`.
 *
 * `table` may be NULL, which is FZN_REASM_LINE_NONE.
 *
 * `now` is the caller's clock. A slot is reclaimable exactly when
 * `live && !handed && expires_at <= now`, which is the condition
 * `fzn_reasm_expire` sweeps on -- drawing a different one would describe a
 * table that call would not produce.
 *
 * WHEN SEVERAL CAUSES APPLY, THE MOST ACTIONABLE WINS: handed before
 * unswept, unswept before live. A leak never self-corrects, a missed sweep
 * is one call, and a sizing problem is a restart -- so the order is by how
 * much of the table the reader can get back and how soon.
 *
 * `state_out` is REQUIRED.
 */
fzn_reasm_err_t fzn_reasm_print(const fzn_reasm_t *table, uint64_t now, char *out, size_t cap,
                                size_t *len_out, fzn_reasm_line_t *state_out);

#endif /* FZN_CLI_REASM_PRINT_H */
