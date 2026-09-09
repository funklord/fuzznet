/*
 * Whether one peer has acknowledged the version of a subject this host holds.
 *
 * project.md sec 227. `record/ledger.h` is the model, and it is the mirror of
 * `cli/manifest_print`: that one says what THIS host is missing, this one says
 * what SOMEBODY ELSE has confirmed receiving.
 *
 * THE TWO ZEROES ARE THE WHOLE PROBLEM. `fzn_ledger_confirmed` returns a
 * version and `fzn_ledger_count` returns a count, and both answer ZERO for a
 * table nobody can walk as well as for an honest empty one. `fzn_ledger_behind`
 * answers "behind" for both as well -- deliberately, because that is the
 * direction that costs a retransmission rather than a delivery. Every one of
 * those is right for a caller deciding whether to send. None of them can tell
 * a person which of two very different things is true:
 *
 *   - this peer has never acknowledged this subject, on a ledger that works;
 *   - this ledger cannot be read, so EVERY peer answers that way and nothing
 *     on this screen is evidence.
 *
 * `fzn_ledger_sound` was added for exactly this and is asked first.
 *
 * IT READS AND DOES NOT DECIDE. Nothing here confirms, sends or plans.
 *
 * `FZN_LEDGER_LINE_NONE` IS ZERO.
 */

#ifndef FZN_CLI_LEDGER_PRINT_H
#define FZN_CLI_LEDGER_PRINT_H

#include "../record/ledger.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_ledger_line {
	/* No ledger, or a caller that passed nothing. */
	FZN_LEDGER_LINE_NONE = 0,
	/* A ledger whose own fields disagree. Nothing derived from it is
	 * evidence, and this is the state that shared a zero with the next
	 * one until `fzn_ledger_sound` existed. */
	FZN_LEDGER_LINE_UNREADABLE = 1,
	/* Readable, and this peer has never acknowledged this subject. The
	 * ledger's own words for its zero: "the absence of a question". */
	FZN_LEDGER_LINE_UNKNOWN = 2,
	/* Readable, acknowledged, and older than what this host holds. */
	FZN_LEDGER_LINE_BEHIND = 3,
	/* Readable, and acknowledged at the version asked about or better. */
	FZN_LEDGER_LINE_CURRENT = 4
} fzn_ledger_line_t;

/* Room for the longest of the five lines, both versions spelled in full. */
#define FZN_LEDGER_PRINT_MAX 160u

/*
 * Render what `peer` has confirmed about `subject`, against the version this
 * host holds.
 *
 * `ledger` may be NULL, which is FZN_LEDGER_LINE_NONE.
 *
 * `current` is what this host has, and it is what makes BEHIND and CURRENT
 * different states rather than one number on a line. Passing zero is legal and
 * means "I hold nothing for this subject", which no peer can be behind.
 *
 * `state_out` is REQUIRED, on the argument `record/sync.h` makes for
 * `fzn_sync_digest`'s: an optional out-parameter is one every caller ignores,
 * and the difference between an unknown peer and an unreadable table is the
 * whole content here.
 */
fzn_ledger_err_t fzn_ledger_print(const fzn_ledger_t *ledger,
                                  const uint8_t peer[FZN_PUBKEY_LEN],
                                  const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind,
                                  uint64_t current, char *out, size_t cap, size_t *len_out,
                                  fzn_ledger_line_t *state_out);

#endif /* FZN_CLI_LEDGER_PRINT_H */
