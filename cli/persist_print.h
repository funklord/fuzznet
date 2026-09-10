/*
 * What happened when this host tried to read its own stored state.
 *
 * project.md sec 253. `persist.h` names the distinction that matters and
 * leaves it to a caller:
 *
 *   Nothing stored under that slot. An ordinary state on first run, and its
 *   own code so a caller can tell it from a backend failure -- which is the
 *   distinction that decides whether to mint a fresh prekey or to stop and
 *   shout.
 *
 * THIS IS THE MOMENT A CONSUMER IS MOST LIKELY TO GET WRONG, because it is
 * the first thing that happens: a program starting up, reading its identity,
 * and telling a person what it found. Four codes reach it and the words a
 * person needs are not in any of them.
 *
 * NOTHING STORED IS TWO DIFFERENT EVENTS, and only the caller can say which:
 *
 *     first run          routine; mint and carry on
 *     it has run before  something removed this host's stored state, which
 *                        is data loss and nobody else will report it
 *
 * `had_stored` is that context. A CALLER PASSING IT WRONG TURNS DATA LOSS
 * INTO A ROUTINE LINE, which is worth saying plainly: this is the one
 * argument here that the library cannot check, and it is the one that
 * decides whether a person is told anything at all.
 *
 * AND A CORRUPT FILE IS NOT AN ATTACK. `persist.h` says so -- "a peer cannot
 * reach these bytes, so this is a corrupt or foreign file rather than an
 * attack" -- and a line that does not say it leaves somebody who has just
 * been told their identity is corrupt assuming the worst thing it could
 * mean. It is refused rather than repaired, which the line also has to
 * carry, because the file is still there and a person may want it.
 *
 * IT READS AND DOES NOT DECIDE. Nothing here loads, mints or repairs
 * anything; the verdict comes from the caller's own call.
 *
 * `FZN_PERSIST_LINE_NONE` IS ZERO.
 */

#ifndef FZN_CLI_PERSIST_PRINT_H
#define FZN_CLI_PERSIST_PRINT_H

#include "../persist/persist.h"

#include <stddef.h>

typedef enum fzn_persist_line {
	/* A slot this does not know, or a code it does not understand. */
	FZN_PERSIST_LINE_NONE = 0,
	/* Read back. */
	FZN_PERSIST_LINE_LOADED = 1,
	/* Nothing stored, and the caller says this host has not stored yet. */
	FZN_PERSIST_LINE_FRESH = 2,
	/* Nothing stored, and the caller says it has. Data loss. */
	FZN_PERSIST_LINE_LOST = 3,
	/* Stored bytes that are not this shape or version: corrupt or
	 * foreign, refused rather than repaired, and not an attack. */
	FZN_PERSIST_LINE_CORRUPT = 4,
	/* The store itself could not be read. */
	FZN_PERSIST_LINE_UNAVAILABLE = 5,
	/* The caller asked for something impossible. */
	FZN_PERSIST_LINE_LOCAL = 6
} fzn_persist_line_t;

/* Room for the longest of the seven lines, with the longest slot name. */
#define FZN_PERSIST_PRINT_MAX 300u

/*
 * Render what `err` said about `slot`.
 *
 * `had_stored` is nonzero when this host has stored that slot before, which
 * only the caller knows. It is read ONLY when `err` is
 * FZN_PERSIST_ERR_ABSENT; for every other code the answer does not depend on
 * it.
 *
 * `state_out` is REQUIRED.
 */
fzn_persist_err_t fzn_persist_print(fzn_persist_slot_t slot, fzn_persist_err_t err,
                                    int had_stored, char *out, size_t cap, size_t *len_out,
                                    fzn_persist_line_t *state_out);

#endif /* FZN_CLI_PERSIST_PRINT_H */
