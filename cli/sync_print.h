/*
 * Whether this host is up to date with one peer, as a line a daemon can
 * print and a health check can branch on.
 *
 * project.md sec 191. `gui/sync_view` is the same two facts for a screen;
 * this is `cli/log_print`'s shape for the same reason that one exists -- a
 * daemon with no display still has to answer "are we synced" to whoever asks.
 *
 * IT WRITES INTO A CALLER'S BUFFER AND PRINTS NOTHING. No allocation and no
 * stdio, as everywhere here.
 *
 * IT REPORTS THE STATE OUT OF BAND, AND THAT IS THE POINT OF THE EXTRA
 * PARAMETER. A health check must not have to read the sentence to find out
 * what happened: sec 168 established that a consumer parsing another
 * component's output is "a parser of a format, which is a new thing to get
 * wrong rather than one thing fewer", and a status line is exactly the format
 * somebody would parse. So the words are for a person and `state_out` is for
 * a program, and neither reads the other's.
 *
 * "UP TO DATE" AND "CANNOT SAY" ARE DIFFERENT STATES AND BOTH REPORT ZERO
 * MISSING. That is `chain/manifest.h`'s design and `gui/sync_view`'s central
 * guard, and it matters more here: a health check that treated a zero as
 * healthy would report a host that cannot measure its own deficit as green,
 * which is the fail-open manifest.h was written to remove. A caller switching
 * on `state_out` cannot make that mistake by accident; one grepping the line
 * for a number can.
 *
 * IT REFUSES RATHER THAN TRUNCATES, in `fzn_log_print`'s vocabulary:
 * FZN_MANIFEST_ERR_MALFORMED for a buffer too small, with `*len_out` set to
 * what was needed. A status line cut in half is a status nobody can act on.
 */

#ifndef FZN_CLI_SYNC_PRINT_H
#define FZN_CLI_SYNC_PRINT_H

#include "../chain/manifest.h"

#include <stddef.h>
#include <stdint.h>

/*
 * What this host can say about a peer.
 *
 * UNMEASURED is first deliberately: it is the value a caller gets from a
 * zeroed struct, so a program that forgets to read `state_out` at all sees
 * the conservative answer rather than the reassuring one.
 */
typedef enum fzn_sync_state {
	FZN_SYNC_UNMEASURED = 0,
	FZN_SYNC_UP_TO_DATE = 1,
	FZN_SYNC_BEHIND = 2
} fzn_sync_state_t;

/* Room for the longest line this writes: three counts and the words between
 * them, sized from the constants rather than measured. */
#define FZN_SYNC_PRINT_MAX 192u

/*
 * Render one peer's sync position.
 *
 * `out` receives a NUL-terminated line of `*len_out` bytes not counting the
 * NUL, ending in a newline. `state_out` is required -- passing NULL is
 * FZN_MANIFEST_ERR_MALFORMED, on `fzn_manifest_deficit`'s argument for its
 * own `dropped`: "an optional out-parameter is one every caller ignores", and
 * this is the one a health check must not ignore.
 *
 * A NULL state or an unfollowed issuer is FZN_SYNC_UNMEASURED and not an
 * error: `fzn_manifest_overflowed` already treats them as "cannot say", and
 * that is an answer rather than a fault.
 */
fzn_manifest_err_t fzn_sync_print(const fzn_manifest_state_t *state,
                                  const uint8_t issuer[FZN_PUBKEY_LEN], char *out,
                                  size_t cap, size_t *len_out,
                                  fzn_sync_state_t *state_out);

#endif /* FZN_CLI_SYNC_PRINT_H */
