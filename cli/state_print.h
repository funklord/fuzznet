/*
 * What this host currently believes about one subject -- and, when it
 * believes nothing, whether that is because nobody ever said or because
 * somebody took it back.
 *
 * project.md sec 197. `gui/state_view` is the same facts for a screen and
 * shows this file's line; both changed in one commit on sec 193's rule.
 *
 * THIS LOOKS PAST `fzn_state_get`, DELIBERATELY, AND SO DOES THE WIDGET.
 * That accessor answers NULL for a tombstone and for a subject nothing ever
 * set, and state.h says why: "a caller asking what a subject says must not
 * have to know that this file remembers who unset it."
 *
 * Right for code taking a DECISION, which cannot act differently on the two
 * without inviting a bug. Wrong for a REPORT. "Nobody configured this" and
 * "somebody revoked it, and here is who" are the two answers to "why will
 * this host not do what I asked", and they call for opposite next steps --
 * set it, or find out who unset it and why.
 *
 * So sec 165's rule is followed for the VALUE and knowingly stepped past for
 * the ABSENCE, exactly as sec 184 argued for the widget. The library is not
 * wrong and neither is this; they have different callers.
 *
 * `FZN_STATE_CELL_UNREADABLE` IS ZERO. A caller that ignores the state, or
 * reads it after a refusal, is told the state could not be read rather than
 * that the subject is simply unset -- which would be the fail-open answer,
 * since "unset" invites writing and "unreadable" does not.
 */

#ifndef FZN_CLI_STATE_PRINT_H
#define FZN_CLI_STATE_PRINT_H

#include "../state/state.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_state_cell {
	FZN_STATE_CELL_UNREADABLE = 0,
	FZN_STATE_CELL_CLEARED = 1,
	FZN_STATE_CELL_NEVER_SET = 2,
	FZN_STATE_CELL_SET = 3
} fzn_state_cell_t;

/* Room for the longest line: a fingerprint, a verdict and a sequence. */
#define FZN_STATE_PRINT_MAX 192u

/*
 * Render one cell.
 *
 * `st` may be NULL, which is FZN_STATE_CELL_UNREADABLE -- a caller holding no
 * state cannot say what a subject says, and reporting that as "unset" would
 * invite writing over something nobody has looked at.
 *
 * `state_out` is REQUIRED.
 */
fzn_state_err_t fzn_state_print(const fzn_state_t *st,
                                const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind,
                                char *out, size_t cap, size_t *len_out,
                                fzn_state_cell_t *state_out);

#endif /* FZN_CLI_STATE_PRINT_H */
