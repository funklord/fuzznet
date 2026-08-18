/* Bounded newline-delimited framing, which is the half of a text protocol
 * that is this library's.
 *
 * sec 9 puts encoding, framing, authentication and encryption here, and sec 5 keeps
 * command vocabularies out. A line is the boundary between those two: this
 * module says where one request ends and never what it means. What arrives on
 * the far side is a consumer's JSON, and its parser is the consumer's.
 *
 * WHY IT IS NEEDED RATHER THAN CONVENIENT. raidcfgd adopts netcfgd's
 * newline-delimited JSON and records the cost in the same breath: a JSON
 * parser is a larger and more interesting attack surface than a fixed binary
 * frame, and **the mitigations are not optional extras of that choice, they
 * are the other half of it** -- "a hard bound on framing, and both parsers
 * fuzzed". This is the framing bound. Handing a consumer an unbounded line is
 * handing it the choice of how much memory a stranger may make it hold.
 *
 * NOTHING IS ALLOCATED. The caller owns the buffer and its size is the bound,
 * which is the same arrangement `chunk/reassembly.h` uses: a limit somebody
 * chose deliberately beats one this library guessed.
 *
 * AN OVER-LONG LINE ENDS THE CONNECTION, and does not resynchronise. Skipping
 * to the next newline and carrying on is the obvious recovery and it is
 * wrong here. raidcfgd's shape has a remote client behind an unprivileged
 * bridge that links this library, so the bytes on a local socket may have
 * come from somewhere else entirely -- and a reader that resynchronises lets
 * whoever produced the over-long line choose where the next request begins.
 * That is request smuggling, and the peer holding the socket is not
 * necessarily the party that would benefit from it. Refusing costs a
 * connection; resynchronising costs the boundary between two of them.
 */

#ifndef FZN_LINE_H
#define FZN_LINE_H

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_line_err {
	FZN_LINE_OK = 0,
	FZN_LINE_ERR_MALFORMED = -1,
	/* A line reached the end of the buffer without a newline. Sticky: the
	 * reader refuses everything afterwards, because there is no safe way
	 * back. Drop the connection. */
	FZN_LINE_ERR_OVERLONG = -2,
} fzn_line_err_t;

typedef struct fzn_line {
	uint8_t *buf;
	size_t cap;
	size_t used;
	/* How much of `buf` has already been handed out. Compaction is
	 * deferred so that a returned line stays readable until the next call,
	 * which is what the promise on `fzn_line_next` means. */
	size_t start;
	/* Set once and never cleared. See the header comment: a reader that
	 * recovered from this would be choosing a request boundary on behalf
	 * of whoever overflowed it. */
	int refusing;
} fzn_line_t;

/* Point a reader at caller-owned storage. `cap` is the longest line that will
 * be accepted, and a line exactly that long is fine -- the newline is not
 * kept, so it does not need room of its own. */
fzn_line_err_t fzn_line_init(fzn_line_t *reader, uint8_t *buf, size_t cap);

/* Add bytes as they arrive. Returns FZN_LINE_ERR_OVERLONG once a line has
 * outgrown the buffer, and keeps returning it.
 *
 * Bytes are taken whole or not at all: a push that would overflow is refused
 * without consuming any of it, so a caller cannot half-append a read. */
fzn_line_err_t fzn_line_push(fzn_line_t *reader, const uint8_t *bytes, size_t len);

/* Take the next complete line, if the reader holds one.
 *
 * Returns 1 and points `line`/`line_len` at it, or 0 when no newline has
 * arrived yet. The line does not include the newline, and it stays valid only
 * until the next call -- what follows it is shifted down over it.
 *
 * An empty line is a line, reported with `*line_len == 0`. Whether an empty
 * request is an error is the consumer's question, and answering it here would
 * be this module deciding something about a vocabulary. */
int fzn_line_next(fzn_line_t *reader, const uint8_t **line, size_t *line_len);

#endif /* FZN_LINE_H */
