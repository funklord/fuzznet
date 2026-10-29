/*
 * REQUESTS AWAITED BY THE LOOP, project.md sec 636: the first stage of the
 * resumable round the holder chose, 2026-10-16.
 *
 * WHY. A round asks its peers one request at a time and waits on each --
 * `fzn_caller_recv`, up to three seconds -- and while it waits this host
 * answers nobody: sec 424's "a fetch blocks the loop". Hosts mid-round
 * block on each other, and rounds of five hosts started together ran to
 * forty seconds (sec 635).
 *
 * WHAT. A request is SENT and RECORDED here, with what to do with its
 * answer; the loop polls the asking sockets beside the serving ones
 * (`fzn_node_state_t.asks`), hands each answer to its callback, and fails
 * one past its deadline. The asker has returned long before -- its state
 * is whatever it gave the callback, never its stack.
 *
 * NOT YET USED BY EVERY ASKER: a round converted to this answers while it
 * waits only if nothing it does still waits the old way. Sec 636 says
 * which are converted.
 */
#ifndef FZN_NODE_ASKS_H
#define FZN_NODE_ASKS_H

#include <stddef.h>
#include <stdint.h>

#include "caller.h"

#define FZN_NODE_ASKS_MAX 64u

/* AN ANSWER, or with `reply` NULL none -- the deadline passed, or the
 * request was cancelled. `reply` is borrowed for the call. */
typedef void (*fzn_node_answered_fn)(void *ctx, const uint8_t *reply, size_t reply_len);

typedef struct fzn_node_ask {
	fzn_caller_t *caller;
	uint32_t msg;
	uint64_t deadline_ms;
	fzn_node_answered_fn done;
	void *ctx;
	int used;
	/* RESENT WITHIN THE WAIT, sec 737: a copy of what `fzn_node_asks_send`
	 * sent, sent again by `fzn_node_asks_expire` each FZN_CALLER_RESEND_MS
	 * the ask stays unanswered, FZN_CALLER_RESENDS times at most. NULL for
	 * an ask only awaited here, whose request is its sender's to resend. */
	uint8_t *request;
	size_t request_len;
	uint64_t expires_at;
	uint64_t resend_at_ms;
	unsigned resends;
	/* RESENT BY ITS ASKER, sec 756, when set: called in place of the
	 * caller's own resend, at the same times and as often -- a request
	 * carried by a relay is sent again through the relay, which only its
	 * asker can do. */
	void (*again)(void *ctx);
	void *again_ctx;
} fzn_node_ask_t;

typedef struct fzn_node_asks {
	/* ENTRIES, not `slots`: Qt defines `slots` as a macro, and this header
	 * reaches a Qt consumer through `node/admin.h` (raidcfgd's bridge, inbox
	 * 20261023T2023Z). */
	fzn_node_ask_t entries[FZN_NODE_ASKS_MAX];
	/* Where answers are put together: the caller's, lent for the call. */
	uint8_t *reply;
	size_t reply_cap;
	/* Milliseconds, for deadlines. */
	uint64_t (*clock_ms)(void);
} fzn_node_asks_t;

void fzn_node_asks_init(fzn_node_asks_t *asks, uint8_t *reply, size_t reply_cap,
                        uint64_t (*clock_ms)(void));

/* SEND `request` through `caller`, its frame valid until `expires_at`
 * (seconds), and record it: `done` is called with its answer, or with
 * NULL `timeout_ms` from now. 0 when it could not be sent or the table is
 * full -- `done` is then never called. */
int fzn_node_asks_send(fzn_node_asks_t *asks, fzn_caller_t *caller, const uint8_t *request,
                       size_t request_len, uint64_t expires_at, unsigned timeout_ms,
                       fzn_node_answered_fn done, void *ctx);

/* AWAIT THE ANSWER TO `msg`, a message the caller sent itself -- sealed
 * for one host and handed to another to relay, sec 622 -- arriving at
 * `caller`: `done` called with it, or with NULL `timeout_ms` from now. 0
 * when the table is full -- `done` is then never called. */
int fzn_node_asks_await(fzn_node_asks_t *asks, fzn_caller_t *caller, uint32_t msg,
                        unsigned timeout_ms, fzn_node_answered_fn done, void *ctx);

/* AS `fzn_node_asks_await`, RESENT by `again(again_ctx)` each
 * FZN_CALLER_RESEND_MS it stays unanswered, FZN_CALLER_RESENDS times at
 * most, as a request this table sent is (sec 756). */
int fzn_node_asks_await_again(fzn_node_asks_t *asks, fzn_caller_t *caller, uint32_t msg,
                              unsigned timeout_ms, fzn_node_answered_fn done, void *ctx,
                              void (*again)(void *again_ctx), void *again_ctx);
/* The distinct sockets awaited, into `fds`, `cap` of them: their count. */
size_t fzn_node_asks_fds(const fzn_node_asks_t *asks, int *fds, size_t cap);

/* SOCKET `fd` IS READABLE: every answer waiting on it read, each handed to
 * its request's callback. How many were answered. */
size_t fzn_node_asks_ready(fzn_node_asks_t *asks, int fd);

/* EVERY REQUEST PAST ITS DEADLINE failed, its callback told so. How many. */
size_t fzn_node_asks_expire(fzn_node_asks_t *asks);

/* EVERY REQUEST THROUGH `caller` failed now: before its socket closes. */
size_t fzn_node_asks_cancel(fzn_node_asks_t *asks, const fzn_caller_t *caller);

/* How many requests are awaited. */
size_t fzn_node_asks_pending(const fzn_node_asks_t *asks);

#endif /* FZN_NODE_ASKS_H */
