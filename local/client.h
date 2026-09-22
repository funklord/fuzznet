/* Talking to a fuzznet daemon over its local socket: connect, ask, read one
 * line back.
 *
 * WHY THIS IS HERE AND NOT IN EACH CONSUMER. `local/socket.h` has listen,
 * accept and close and had no connect at all, so every consumer that wants to
 * ask its own daemon a question writes the same forty lines: open an
 * AF_UNIX stream, connect, compose `verb SP argument LF`, write it all,
 * read until a newline under a timeout, and bound what arrives. raidcfgd has
 * one already (`src/daemon_source.cpp`); fuzzypickles and netcfgd will each
 * write one. The copyright holder settled 2026-09-22 that network code two
 * consumers would duplicate belongs in fuzznet, and this is that shape
 * exactly.
 *
 * THE COMPOSING IS THE POINT, more than the socket. `fzn_client_compose`
 * writes the grammar `fzn_vocabulary_split` parses -- one verb, one space,
 * the rest untouched -- so the two halves of one wire format are stated once
 * and cannot drift. A consumer that wrote its own would be writing the
 * server's grammar from memory, and the failure is silent: a line the server
 * takes for something else.
 *
 * IT INTERPRETS NOTHING THAT COMES BACK. A reply is bytes with a length,
 * handed to the caller as the daemon wrote them. What a reply MEANS is not
 * settled here yet -- see `project.md` sec 364 -- and a client that invented
 * a meaning would be deciding it by being first.
 */

#ifndef FZN_CLIENT_H
#define FZN_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "vocabulary.h"

typedef enum fzn_client_err {
	FZN_CLIENT_OK = 0,
	/* A null pointer, a zero-length verb, or a buffer with no room. */
	FZN_CLIENT_ERR_MALFORMED = -1,
	/* The path is not one this library will use -- `fzn_socket_path_ok`
	 * decides, and it is asked BEFORE the socket is created so a bad path
	 * costs no descriptor. */
	FZN_CLIENT_ERR_PATH = -2,
	/* Nothing is listening, or the kernel refused the connection. Distinct
	 * from IO because it is the ordinary "the daemon is not running" case
	 * and a caller usually reports it differently from a failure mid-talk. */
	FZN_CLIENT_ERR_CONNECT = -3,
	/* A read or write failed, or the daemon closed without answering. */
	FZN_CLIENT_ERR_IO = -4,
	/* The daemon accepted the request and said nothing in time. Separate
	 * from IO for the same reason CONNECT is: a timeout says the daemon is
	 * there and busy or wedged, which is a different thing to report than a
	 * socket that broke. */
	FZN_CLIENT_ERR_TIMEOUT = -5,
	/* The request would exceed FZN_REQUEST_MAX, or the verb exceeds
	 * FZN_VERB_MAX. Refused here rather than sent, because the server
	 * answers an overlong line with a DENIAL -- so a client that let it go
	 * would turn its own framing mistake into what reads like an access
	 * decision. */
	FZN_CLIENT_ERR_REQUEST_TOO_LONG = -6,
	/* The reply did not fit the caller's buffer. The bytes read so far are
	 * NOT returned: a prefix of a reply is a different reply, which is the
	 * refusal `fzn_node_status_line` and the verb bound both already make. */
	FZN_CLIENT_ERR_REPLY_TOO_LONG = -7
} fzn_client_err_t;

/* A short name for a `fzn_client_err_t`, for a log line or a message to a
 * user. NEVER NULL, including for a value that is not one of the enumerators,
 * so a caller may pass the result straight to a printf. */
const char *fzn_client_err_str(fzn_client_err_t err);

/* Compose a request line into `out`, terminator included, and report its
 * length. PURE: no socket, so the grammar is testable without a daemon, and
 * `client_test` round-trips it through `fzn_vocabulary_split` rather than
 * comparing against a second copy of the format written in the test.
 *
 * `verb` is bytes and a length rather than an `fzn_verb_t` so that a
 * consumer's own verb composes exactly as one of fuzznet's -- sec 298's
 * bypass-until-gained has to work here too, or a consumer with a verb of its
 * own is back to writing the line itself.
 *
 * A NULL `arg` with a zero length writes `verb LF`. A NON-null `arg` of zero
 * length writes `verb SP LF`, which is a caller asking for the empty subject
 * and is a different request -- `fzn_vocabulary_split` tells them apart and
 * so must this.
 *
 * Refuses a verb that is empty, longer than FZN_VERB_MAX, or that contains a
 * space or a newline: the first would parse as a shorter verb with an
 * argument, and the second would make one request line into two. A caller
 * cannot be allowed to smuggle either past a table that bounds verbs. */
fzn_client_err_t fzn_client_compose(uint8_t *out, size_t cap, size_t *out_len,
                                    const uint8_t *verb, size_t verb_len,
                                    const uint8_t *arg, size_t arg_len);

/* Connect to a daemon's socket. `*out_fd` is set only on OK, and the caller
 * closes it with `fzn_client_close`. */
fzn_client_err_t fzn_client_connect(const char *path, int *out_fd);

/* Compose and send one request. Writes the whole line or reports IO: a
 * partial request is a line the server will read as a different one. */
fzn_client_err_t fzn_client_send(int fd, const uint8_t *verb, size_t verb_len,
                                 const uint8_t *arg, size_t arg_len);

/* The same for one of fuzznet's own verbs, so a caller need not spell it.
 * FZN_VERB_NONE is refused -- it names nothing to send. */
fzn_client_err_t fzn_client_send_verb(int fd, fzn_verb_t verb,
                                      const uint8_t *arg, size_t arg_len);

/* Read one reply line into `reply`, terminator stripped, under a receive
 * timeout so a daemon that says nothing cannot wedge the caller. A zero
 * `timeout_ms` waits forever, which is what a caller with its own poll loop
 * wants and is not the default anyone should reach for. */
fzn_client_err_t fzn_client_recv(int fd, uint8_t *reply, size_t cap,
                                 size_t *reply_len, unsigned timeout_ms);

void fzn_client_close(int fd);

#endif /* FZN_CLIENT_H */
