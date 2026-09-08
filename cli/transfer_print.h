/*
 * Whether a blob is still arriving, how far it has got, and -- when nothing
 * is outstanding -- which of the three reasons that is.
 *
 * project.md sec 195. `gui/transfer_view` is the same facts for a screen and
 * SHOWS THIS FILE'S LINE, both changed in one commit on sec 193's rule.
 *
 * THREE CONDITIONS READ `in_flight == 0` AND THEY ARE NOT ONE THING. sec 179:
 * not started, stalled and complete all have nothing outstanding, and they
 * are exactly the three a person -- or an alerting rule -- looking at a
 * stopped transfer needs separated. A script told only the count would page
 * somebody about a finished download and ignore a stuck one.
 *
 * THE STATE GOES OUT OF BAND, on sec 191's argument, and
 * `FZN_TRANSFER_NOTHING` is zero: a caller that ignores it, or reads it after
 * a refusal, is told it was given nothing rather than told everything is
 * fine.
 *
 * A PASSED DEADLINE IS RECLAIMABLE, NOT FAILED. The range returns to the
 * want-list and the bytes are not lost, so reporting it as an error would
 * make a routine consequence of a lossy transport into something somebody
 * has to act on -- which is how a field stops being read.
 *
 * NOTHING HERE MUTATES. `fzn_transfer_expire` reclaims assignments and
 * returns how many it took; a reporter that called it would take a peer's
 * outstanding ranges back as a side effect of somebody asking for status.
 * sec 179's rule, and it binds a printer exactly as it binds a widget.
 */

#ifndef FZN_CLI_TRANSFER_PRINT_H
#define FZN_CLI_TRANSFER_PRINT_H

#include "../spool/spool.h"
#include "../spool/transfer.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_transfer_state {
	FZN_TRANSFER_NOTHING = 0,
	FZN_TRANSFER_STALLED = 1,
	FZN_TRANSFER_IDLE = 2,
	FZN_TRANSFER_WORKING = 3,
	FZN_TRANSFER_COMPLETE = 4
} fzn_transfer_state_t;

/* Room for the longest line this writes. */
#define FZN_TRANSFER_PRINT_MAX 224u

/*
 * Render one blob's assembly.
 *
 * `spool` may be NULL, which is FZN_TRANSFER_NOTHING. `transfer` may be NULL:
 * a blob being assembled by something other than this scheduler still has a
 * position worth reporting.
 *
 * `now` is the caller's clock, used ONLY to say how many outstanding
 * assignments have passed their deadline and never to reclaim one.
 *
 * `state_out` is REQUIRED, on `fzn_manifest_deficit`'s argument for its own
 * `dropped`.
 */
fzn_transfer_err_t fzn_transfer_print(const fzn_spool_t *spool,
                                      const fzn_transfer_t *transfer, uint64_t now,
                                      char *out, size_t cap, size_t *len_out,
                                      fzn_transfer_state_t *state_out);

#endif /* FZN_CLI_TRANSFER_PRINT_H */
