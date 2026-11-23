/*
 * A procedure called in binary on the local leg: fuzznet secs 1410-1411,
 * its messages node/rrpc_local.situ's.
 *
 * The text `call NAME [ARGS]` escapes a procedure's answer onto one local
 * reply line of FZN_REPLY_MAX bytes, three bytes for each byte past ASCII,
 * so a binary answer of 21 kB -- raidcfgd's RAID status -- took up to 64
 * pages, a connection each. Here a caller sends FZN_CMD_RRPC `call` (128)
 * with the name and the arguments as bytes, and the node answers `part`
 * (129) messages, the answer's bytes in order, and then a STATUS: ok once
 * all of it is sent, or why not.
 *
 * WHO MAY CALL, and which procedure runs, are the daemon's, as on the text
 * path: this file reads the request, hands the name and arguments to `run`,
 * and writes what `run` answers.
 */
#ifndef FZN_NODE_RRPC_BINARY_H
#define FZN_NODE_RRPC_BINARY_H

#include <stddef.h>
#include <stdint.h>

#include "../wire/status.h"

/* The most answer bytes a `part` carries: FZN_LOCAL_BINARY_MAX, the most a
 * framed local message holds, less the part's two bytes of head. */
#define FZN_NODE_RRPC_PART_MAX (0x1fffu - 2u)

/* Each answer message, whole, for the caller to frame and write; nonzero
 * when it was written. */
typedef int (*fzn_node_rrpc_put_t)(void *ctx, const uint8_t *msg, size_t len);

/* THE PROCEDURE RUN: `name` (1 to FZN_RRPC_NAME_MAX of a-z and 0-9, checked
 * before it is called) with `args`, its answer written into `answer`, at
 * most `cap` bytes. Returns the answer's length and FZN_STATUS_OK in
 * `*status`, or 0 and the reason -- FZN_STATUS_UNSUPPORTED for no such
 * procedure, FZN_STATUS_DENIED, FZN_STATUS_ERROR -- with `*why` the words
 * said beside it, or NULL. An empty answer is length 0 and ok. */
typedef size_t (*fzn_node_rrpc_run_t)(void *ctx, const uint8_t *name, size_t name_len, const uint8_t *args,
                                      size_t args_len, uint8_t *answer, size_t cap, fzn_status_t *status,
                                      const char **why);

/* THE NAME MSG CALLS, borrowed from MSG: 1 when MSG is a call whose name
 * `call NAME` would take, 0 otherwise. What the daemon judges a caller by
 * who is not the node's own user, as the text verb is judged (sec 1416). */
int fzn_node_rrpc_binary_name(const uint8_t *msg, size_t len, const uint8_t **name, size_t *name_len);

/* Answers MSG, a FZN_CMD_RRPC `call`, through `put`, running the procedure
 * through `run` with `room` bytes of `answer` for what it says: 1 once
 * answered, every refusal included, and 0 when a message could not be
 * written. */
int fzn_node_rrpc_binary(const uint8_t *msg, size_t len, fzn_node_rrpc_run_t run, void *run_ctx, uint8_t *answer,
                         size_t room, fzn_node_rrpc_put_t put, void *put_ctx);

#endif /* FZN_NODE_RRPC_BINARY_H */
