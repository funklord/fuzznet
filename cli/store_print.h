/*
 * What a record store answered, and whether anybody should act on it.
 *
 * project.md sec 258. `record/store.h` keeps five codes apart and names the
 * cost of collapsing two of them:
 *
 *   ABSENT ... AN ANSWER RATHER THAN A FAULT: it is what a reader gets for
 *   everything the owner has not fetched yet, which on a busy host is most of
 *   what it asks for.
 *
 *   BACKEND ... Kept apart from ABSENT because "not held" is normal and "the
 *   store is broken" is not, and a caller that treated a broken store as an
 *   empty one would REFETCH THE WORLD.
 *
 * That last is a concrete operational harm, not a tidiness argument: a host
 * whose store has stopped answering would ask the network for everything it
 * already has.
 *
 * FIVE ANSWERS, AND THE LAST TWO ARE NOT THE SAME KIND OF WRONG:
 *
 *     held           returned
 *     not held       ordinary, and most of what a busy reader asks
 *     unreadable     the store is broken -- do NOT treat it as empty
 *     damaged        what came back is not a record: a truncated write or a
 *                    file somebody edited. This record, not the store
 *     MISPLACED      what came back IS a record and is not the one asked
 *                    for. The store's index disagrees with its contents
 *
 * MISPLACED IS THE ONE NOBODY EXPECTS. A store that answers with the wrong
 * record has not failed to find something -- it has found the wrong thing and
 * said nothing, and `record/store.h` checks it before any signature for that
 * reason. A line that folded it into "damaged" would describe a filing
 * problem as a corruption one and send somebody to the wrong file.
 *
 * IT READS AND DOES NOT DECIDE. Nothing here fetches, retries or repairs, and
 * the verdict comes from the caller's own call rather than a second one --
 * `cli/sched_print`'s reason.
 *
 * `FZN_RECORD_STORE_LINE_NONE` IS ZERO.
 */

#ifndef FZN_CLI_STORE_PRINT_H
#define FZN_CLI_STORE_PRINT_H

#include "../record/store.h"

#include <stddef.h>

typedef enum fzn_record_store_line {
	/* A code this does not understand. */
	FZN_RECORD_STORE_LINE_NONE = 0,
	/* The record came back. */
	FZN_RECORD_STORE_LINE_HELD = 1,
	/* Not held: ordinary, and most of what a busy reader asks for. */
	FZN_RECORD_STORE_LINE_NOT_HELD = 2,
	/* The store could not answer. Not an empty store. */
	FZN_RECORD_STORE_LINE_UNREADABLE = 3,
	/* What came back is not a record. */
	FZN_RECORD_STORE_LINE_DAMAGED = 4,
	/* What came back is a record, and the wrong one. */
	FZN_RECORD_STORE_LINE_MISPLACED = 5,
	/* The caller asked for something impossible. */
	FZN_RECORD_STORE_LINE_LOCAL = 6
} fzn_record_store_line_t;

/* Room for the longest of the seven lines. */
#define FZN_RECORD_STORE_PRINT_MAX 300u

/*
 * Render what `err` said.
 *
 * NONZERO ON SUCCESS, as `cli/peer_print` does: this printer cannot borrow
 * the store's own error type for its status without saying "that record is
 * absent" to mean "your buffer was too small".
 *
 * `state_out` is REQUIRED.
 */
int fzn_record_store_print(fzn_record_store_err_t err, char *out, size_t cap,
                           size_t *len_out, fzn_record_store_line_t *state_out);

#endif /* FZN_CLI_STORE_PRINT_H */
