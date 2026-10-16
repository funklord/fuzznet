/*
 * A CONVERSATION WITH ONE PEER, awaited by the loop: project.md sec 636,
 * the resumable round. An exchange written as steps -- a request, its
 * answer, the next request -- is run here over `node/asks.h`: each request
 * sent and recorded, the loop going on answering others, and the step
 * called with the answer when it comes. One conversation per peer, many
 * at once, so a round asks its peers together rather than one after
 * another, each costing a timeout when it does not answer.
 *
 * THE STEP owns everything the exchange knows; the conversation holds only
 * where to send and the buffer the next request is written into. It says
 * 1 with the next request in `request` and its length in `*request_len`,
 * or 0 when the exchange is over, its outcome kept by the step itself. An
 * unanswered request is the step called with `reply` NULL; it ends the
 * exchange or asks again, as it chooses.
 *
 * `over` is called once, when the step says it is done or a request could
 * not be sent; the conversation is free again before it is called.
 */
#ifndef FZN_NODE_TALK_H
#define FZN_NODE_TALK_H

#include <stddef.h>
#include <stdint.h>

#include "asks.h"

typedef int (*fzn_node_talk_step_fn)(void *ctx, const uint8_t *reply, size_t reply_len,
                                     uint8_t *request, size_t cap, size_t *request_len);
typedef void (*fzn_node_talk_over_fn)(void *ctx);

typedef struct fzn_node_talk {
	fzn_node_asks_t *asks;
	fzn_caller_t *caller;
	uint64_t expires_at;   /* each request's frame, seconds */
	unsigned timeout_ms;   /* each answer's wait */
	fzn_node_talk_step_fn step;
	fzn_node_talk_over_fn over;
	void *ctx;
	uint8_t *request;      /* the step's, written into for each request */
	size_t cap;
	size_t sent;           /* requests sent, the first counted */
	int live;
} fzn_node_talk_t;

/* START: send `request_len` bytes already in `request` -- the exchange's
 * first request, written by its begin -- and carry the conversation on
 * from each answer. 0 when it could not be sent; `over` is then never
 * called and the conversation is not live. */
int fzn_node_talk_start(fzn_node_talk_t *talk, fzn_node_asks_t *asks, fzn_caller_t *caller,
                        uint64_t expires_at, unsigned timeout_ms, fzn_node_talk_step_fn step,
                        fzn_node_talk_over_fn over, void *ctx, uint8_t *request, size_t cap,
                        size_t request_len);

#endif /* FZN_NODE_TALK_H */
