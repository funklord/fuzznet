/* Gathering a host's log across an estate. sec 463, the last step of sec
 * 456's order: a troubleshooter asks a host for a program's lines in a time
 * window, or for an entry and everything it caused, and reads them as the
 * host wrote them. POSIX, built with FZN_LOG_FILE; packed segments are read
 * when FZN_LOG_PACK is built too.
 *
 * THE MESSAGES are `log/gather.situ`'s, version 4: a QUERY naming the
 * program, the window, an optional substring and a cursor, and a page of
 * LINES with the cursor to go on from.
 *
 * AN ENTRY AND EVERYTHING IT CAUSED IS A SUBSTRING. Every name of an
 * instance ends in its `PID@START#POS` field (sec 456), so matching it
 * returns the entry itself and every line whose cause or origin names it --
 * on this host. Asking each host of the estate in turn reads the work from
 * every end, which is what causes on the wire were for (sec 462).
 *
 * WHAT IS READ: the program's current file and its closed segments, packed
 * or not, oldest first, header and trailer lines left out. A segment closed
 * before the window begins is skipped unread; within one, every line is
 * filtered, since instances writing one file interleave and lines are only
 * roughly in order.
 *
 * WHO MAY ASK IS THE CALLER'S TO DECIDE, not this module's. The holder's
 * rule (sec 428) is that a log is host-private unless configured otherwise,
 * through the scope vocabulary; fuzznetd answers members only, and only when
 * it was told `--log-scope=estate` (sec 463).
 */

#ifndef FZN_LOG_GATHER_H
#define FZN_LOG_GATHER_H

#include <stddef.h>
#include <stdint.h>

#include "entry.h"

#define FZN_GATHER_VERSION 4u
#define FZN_GATHER_QUERY 1u
#define FZN_GATHER_LINES 2u
#define FZN_GATHER_MATCH_MAX 64u
/* A query at its longest. */
#define FZN_GATHER_QUERY_MAX (2u + 32u + 1u + FZN_ENTRY_WORD_MAX + 1u + FZN_GATHER_MATCH_MAX)
/* A page's head: version, type, done, cursor, count. */
#define FZN_GATHER_LINES_HEAD 21u

typedef enum fzn_gather_err {
	FZN_GATHER_OK = 0,
	FZN_GATHER_ERR_MALFORMED = -1, /* a null, a message that is not one */
	FZN_GATHER_ERR_NO_ANSWER = -2, /* the host did not answer */
	FZN_GATHER_ERR_REFUSED = -3,   /* it answered with something else */
	FZN_GATHER_ERR_FILE = -4       /* the log directory would not read */
} fzn_gather_err_t;

const char *fzn_gather_err_str(fzn_gather_err_t err);

typedef struct fzn_gather_query {
	uint64_t since_us;
	uint64_t until_us;
	uint64_t cursor_key;
	uint64_t cursor_off;
	char program[FZN_ENTRY_WORD_MAX + 1u];
	char match[FZN_GATHER_MATCH_MAX + 1u]; /* "" for every line */
} fzn_gather_query_t;

fzn_gather_err_t fzn_gather_query_encode(const fzn_gather_query_t *q, uint8_t *out, size_t cap,
                                         size_t *len);

/* THE HOST'S ANSWER: a query read from `request` answered from the log in
 * `dir`, as many whole lines as fit `reply_cap`. 0 when `request` is not a
 * gather query, so a caller dispatching on the first byte falls through. A
 * line too long for an empty page is passed over rather than stalling the
 * cursor. */
size_t fzn_gather_answer(const char *dir, const uint8_t *request, size_t request_len,
                         uint8_t *reply, size_t reply_cap);

/* How the troubleshooter asks: send `request`, fill `reply`. */
typedef int (*fzn_gather_ask_t)(void *ctx, const uint8_t *request, size_t request_len,
                                uint8_t *reply, size_t reply_cap, size_t *reply_len);

/* Each line, without its newline, NUL-terminated for the call. */
typedef void (*fzn_gather_line_fn)(void *ctx, const char *line, size_t len);

/* THE TROUBLESHOOTER: every page of `q` from the host `ask` reaches, each
 * line handed to `each`, at most `pages_max` pages. `*lines` counts them. */
fzn_gather_err_t fzn_gather_fetch(fzn_gather_ask_t ask, void *ask_ctx,
                                  const fzn_gather_query_t *q, size_t pages_max,
                                  fzn_gather_line_fn each, void *each_ctx, size_t *lines);

#endif /* FZN_LOG_GATHER_H */
