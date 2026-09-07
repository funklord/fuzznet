/*
 * One stream's position, and whether the table it lives in has stopped
 * accepting peers.
 *
 * project.md sec 192. `gui/journal_view` is the same facts for a screen;
 * this is `cli/log_print`'s shape for a host with no display.
 *
 * TWO STATES, AND A HEALTH CHECK NEEDS THE SECOND EVEN WHEN IT ASKED ABOUT
 * THE FIRST. That is the whole reason this reports what it does. sec 186:
 * a full journal refuses every issuer it has not met, and NO SINGLE ROW
 * REVEALS IT -- the peer being turned away has no row at all, and every row
 * that exists still looks healthy. So a caller asking about one stream gets
 * the table's condition whether or not it thought to ask.
 *
 * BOTH GO OUT OF BAND, on sec 191's argument: a monitoring script must not
 * read the sentence to find out what happened, and a status line is exactly
 * the format somebody would otherwise parse. The words are for a person.
 *
 * `FZN_JOURNAL_STREAM_UNTRACKED` AND `..._TABLE_FULL` ARE THE ZERO VALUES OF
 * THEIR ENUMS, so a caller that ignores an out-parameter, or reads one after
 * a refusal, sees the answer that asks for attention rather than the one that
 * grants it. sec 191 made the same choice and for the same reason.
 *
 * IT REFUSES RATHER THAN TRUNCATES, with `*len_out` set to what was needed.
 */

#ifndef FZN_CLI_JOURNAL_PRINT_H
#define FZN_CLI_JOURNAL_PRINT_H

#include "../record/journal.h"

#include <stddef.h>
#include <stdint.h>

/*
 * What this host can say about the stream asked about.
 *
 * UNTRACKED and FRESH are the pair sec 186 exists for: `fzn_journal_next`
 * answers 1 for both, and only one of them is listening.
 */
typedef enum fzn_journal_stream_state {
	FZN_JOURNAL_STREAM_UNTRACKED = 0,
	FZN_JOURNAL_STREAM_FRESH = 1,
	FZN_JOURNAL_STREAM_TRACKING = 2,
	FZN_JOURNAL_STREAM_EXHAUSTED = 3,
	FZN_JOURNAL_STREAM_UNREADABLE = 4
} fzn_journal_stream_state_t;

/*
 * What this host can say about the table, independent of any stream.
 *
 * FULL first, because it is the conservative answer and because it is the one
 * a caller most needs to have not missed.
 */
typedef enum fzn_journal_table_state {
	FZN_JOURNAL_TABLE_FULL = 0,
	FZN_JOURNAL_TABLE_ROOM = 1,
	FZN_JOURNAL_TABLE_UNREADABLE = 2
} fzn_journal_table_state_t;

/* Room for the longest line this writes. */
#define FZN_JOURNAL_PRINT_MAX 256u

/*
 * Render one stream's position and the table's condition.
 *
 * `out` receives a NUL-terminated line ending in a newline. Both state
 * out-parameters are REQUIRED, on `fzn_manifest_deficit`'s argument that an
 * optional one is one every caller ignores -- and the table's is the one a
 * caller did not think to ask for, so making it optional would be making it
 * absent.
 */
fzn_journal_err_t fzn_journal_print(const fzn_journal_t *journal,
                                    const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                                    char *out, size_t cap, size_t *len_out,
                                    fzn_journal_stream_state_t *stream_out,
                                    fzn_journal_table_state_t *table_out);

#endif /* FZN_CLI_JOURNAL_PRINT_H */
