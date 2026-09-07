/*
 * A log as terminal text, so a daemon with no screen can still show one.
 *
 * project.md sec 167. sec 141 put a log in a widget; this is the same two
 * facts -- what is held and what is gone -- for a consumer that has a pipe
 * instead. `cli/qr_print.h` is the precedent and this follows its shape.
 *
 * IT WRITES INTO A CALLER'S BUFFER AND PRINTS NOTHING. No allocation and no
 * stdio, as everywhere here, so the same bytes serve a terminal, a log file
 * and a socket.
 *
 * IT TAKES A JOURNAL, exactly as `fzn_log_get` and `gui/log_view` do, and
 * for the reason log.h gives: the position "is a parameter rather than a
 * second call the caller is trusted to remember". `log/log.h` evicts by
 * design -- losing its oldest entries is its normal condition -- and without
 * a journal there is no telling an entry retention ate from one that has yet
 * to arrive. **A viewer that lists what it holds and stops has silently
 * thrown away the most important thing the module knows.**
 *
 * EVERY BODY GOES THROUGH `fzn_log_body_text`, AND ON A TERMINAL THAT IS NOT
 * TIDINESS. log.h makes the argument for any viewer: a body is opaque bytes,
 * so one carrying a newline and a plausible sequence number would draw a
 * SECOND entry that no issuer ever signed. Here the second half of that
 * argument becomes the sharper one. A widget handed an escape byte displays
 * something wrong; a TERMINAL handed one OBEYS it -- it can clear the
 * screen, move the cursor over the summary that says entries were evicted,
 * recolour, or redefine what the next keystroke sends. The escaping is the
 * only thing between a signed body and the reader's terminal, and it is why
 * this file has no path that writes body bytes.
 *
 * ONE ENTRY PER LINE, OLDEST FIRST, as `fzn_log_read_since` returns them and
 * for its stated reason: `fzn_journal_admit` advances by one and refuses a
 * jump, so newest-first is an order a receiver could not admit. A reader
 * piping this into `tail` gets the newest at the bottom, which is where a
 * terminal reader looks.
 *
 * THE SUMMARY COMES FIRST, and that is a choice a pipe forces. A widget can
 * put the summary above a scrolling list and have it stay visible; a stream
 * cannot, so the fact that matters -- how much is missing -- goes where it
 * will not be scrolled off by the entries it describes.
 *
 * IT REFUSES RATHER THAN TRUNCATES, in `fzn_log_body_text`'s own vocabulary:
 * FZN_LOG_ERR_MALFORMED for a buffer that cannot hold the result, with
 * `*len_out` set to what was needed so a caller can size and retry. A log cut
 * off mid-line is a line that says something other than what was signed, and
 * a summary cut off is a loss report that lost part of itself.
 */

#ifndef FZN_CLI_LOG_PRINT_H
#define FZN_CLI_LOG_PRINT_H

#include "../log/log.h"
#include "../record/journal.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Room for one entry line: a uint64 sequence, two spaces, the widest a body
 * can render to, and a newline. Sized from the constants rather than
 * measured, so it cannot drift when FZN_RECORD_BODY_MAX moves.
 */
#define FZN_LOG_PRINT_ROW_MAX (20u + 2u + FZN_LOG_TEXT_MAX + 1u)

/* Room for the summary line, which names at most three uint64 values and the
 * words between them. */
#define FZN_LOG_PRINT_SUMMARY_MAX 128u

/* The largest window this will render in one call.
 *
 * A viewer is not a synchroniser: it shows a screenful and SAYS it is a
 * screenful, rather than pulling a whole log through a buffer because it
 * could. `gui/log_view.cpp` takes the same number for the same reason. A
 * larger `rows` is FZN_LOG_ERR_MALFORMED rather than a silent clamp, because
 * a clamp is the unmarked shortening this module refuses everywhere else. */
#define FZN_LOG_PRINT_WINDOW_MAX 256u

/* Room for a whole rendering of `rows` entries. A caller sizing to this
 * always fits, so there is no truncation path to get wrong. */
#define FZN_LOG_PRINT_MAX(rows) \
	(FZN_LOG_PRINT_SUMMARY_MAX + (size_t)(rows) * FZN_LOG_PRINT_ROW_MAX + 1u)

/*
 * Render one issuer's stream out of `log`, judged against `journal`.
 *
 * `out` receives a NUL-terminated string of `*len_out` bytes not counting the
 * NUL. Nothing is written unless the whole thing fits.
 *
 * `rows` is how many entries to show, newest-biased in the sense that a log
 * holding more than `rows` is reported as such in the summary rather than
 * silently shortened. Zero is legitimate and asks for the summary alone --
 * "how much have I lost" without the content, which is the question a health
 * check asks.
 *
 * A BODY THAT WILL NOT RENDER GETS A LINE SAYING SO, never a skipped line.
 * A row missing from a list is indistinguishable from a record that was
 * never appended, which is the same reason the widget says it.
 *
 * FZN_LOG_ERR_MALFORMED for a null argument, or a buffer too small -- with
 * `*len_out` set to the size needed in the second case and left at zero in
 * the first, because a caller cannot retry its way out of a null pointer.
 */
fzn_log_err_t fzn_log_print(const fzn_log_t *log, const fzn_journal_t *journal,
                            const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                            size_t rows, char *out, size_t cap, size_t *len_out);

#endif /* FZN_CLI_LOG_PRINT_H */
