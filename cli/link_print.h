/*
 * What paths this host has, which of them it may use, and -- the part that
 * needs saying out loud -- which of the numbers are measurements and which
 * are still the far end's claim.
 *
 * project.md sec 202. `gui/link_view` is the same facts for a screen and
 * shows this file's line as its summary, per sec 193 and sec 194: the widget
 * adds the per-link table its medium affords and restates none of the
 * sentence above it.
 *
 * A PRIOR IS NOT A MEASUREMENT, and nothing in `fzn_link_entry_t` says which
 * one you are looking at. `link.h` seeds the estimate with the declared
 * metric deliberately -- the alternative "has to answer 'what latency does an
 * unmeasured link have?' and the honest answer, zero, makes a link nobody has
 * ever used look infinitely fast and win every selection in `sched/`". That
 * fixes SELECTION and leaves REPORTING exposed: a link registered a second
 * ago and a link measured a thousand times both render as a latency in
 * milliseconds, and only `observations` tells them apart. An operator reading
 * "12 ms" off a link nobody has ever sent a packet on is reading a stranger's
 * assertion in the typeface of evidence.
 *
 * ALL DOWN IS NOT EMPTY. A host with no links registered has not been told
 * about a path; a host whose every link is marked unusable has been told and
 * has switched them off. The first wants configuration, the second wants
 * whatever took the interfaces down, and a summary that reported both as "no
 * usable link" would send an operator to the wrong half of the system.
 *
 * `FZN_LINK_LINE_NONE` IS ZERO, on sec 191's argument, and the enum ascends
 * with how much a caller may rely on: `>= FZN_LINK_LINE_UNMEASURED` is "there
 * is a path to try" and `== FZN_LINK_LINE_MEASURED` is "and there is evidence
 * about it". A caller that ignores the state entirely, or reads it after a
 * refusal, is told this host has no path -- which is the reading that fails
 * closed.
 *
 * THE COUNT OF UNMEASURED LINKS GOES OUT OF BAND SEPARATELY, because it is
 * orthogonal to the state and the state hides it. A table is
 * FZN_LINK_LINE_MEASURED as soon as ONE usable link has an observation, while
 * three others sit at their declared priors -- and `sched/` will choose one of
 * those three the moment its declared metric beats the measured one, which is
 * the hazard `link.h` describes arriving by the door it left open. A caller
 * watching only the state cannot see it.
 *
 * NOTHING HERE IS THE CHOICE. `sched/` chooses, from a snapshot `link/`
 * produces; this renders what the table holds. In particular it reports on
 * the WHOLE table, while a consumer's `sched` sees only as much of it as its
 * snapshot bound allowed -- so a line here can name a healthy link that
 * `fzn_link_snapshot` is permanently dropping. That mismatch is the
 * consumer's to notice and is worth knowing before reading a disagreement
 * between this line and a selection as a defect in either.
 */

#ifndef FZN_CLI_LINK_PRINT_H
#define FZN_CLI_LINK_PRINT_H

#include "../link/link.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_link_line {
	/* No link registered. Nobody has told this host about a path. */
	FZN_LINK_LINE_NONE = 0,
	/* Links exist and every one is marked unusable. */
	FZN_LINK_LINE_ALL_DOWN = 1,
	/* A usable link exists and no link has ever been observed, so every
	 * number on the line is a declaration rather than evidence. */
	FZN_LINK_LINE_UNMEASURED = 2,
	/* At least one usable link carries observations. */
	FZN_LINK_LINE_MEASURED = 3
} fzn_link_line_t;

/* Room for the longest line this writes. */
#define FZN_LINK_PRINT_MAX 320u

/*
 * Render one link table.
 *
 * `table` may be NULL, which is FZN_LINK_LINE_NONE: a consumer that has not
 * built a table has no path, and that is the same answer as a table with
 * nothing in it. Unlike sec 194's sweep plan there is no third reading here,
 * because a table is not the result of asking a question -- it is the
 * question's subject, and an absent one holds no links in either case.
 *
 * `state_out` and `unmeasured_out` are both REQUIRED, on
 * `fzn_manifest_deficit`'s argument for its own `dropped`: an out-parameter a
 * caller may omit is one every caller omits, and both of these carry a
 * distinction the sentence cannot be parsed for.
 *
 * `unmeasured_out` counts USABLE links with no observations -- the ones
 * `sched/` may still choose on a stranger's word. Unusable links are excluded
 * because nothing will choose them, so a count including them would rise when
 * an operator switched a bad path off.
 *
 * NOTHING HERE MUTATES, sec 181: a reporter that recorded an observation
 * would move an estimate nobody measured.
 */
fzn_link_err_t fzn_link_print(const fzn_link_table_t *table, char *out, size_t cap,
                              size_t *len_out, fzn_link_line_t *state_out,
                              size_t *unmeasured_out);

#endif /* FZN_CLI_LINK_PRINT_H */
