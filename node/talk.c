/* A conversation with one peer, awaited by the loop: project.md sec 636, and
 * the header. */
#include "talk.h"

static void answered(void *ctx, const uint8_t *reply, size_t reply_len);

static void end(fzn_node_talk_t *talk)
{
	talk->live = 0;
	talk->over(talk->ctx);
}

/* THE STEP AGAIN, with `reply` or NULL; the next request out, or the end. */
static void go_on(fzn_node_talk_t *talk, const uint8_t *reply, size_t reply_len)
{
	size_t len = 0;

	if (!talk->step(talk->ctx, reply, reply_len, talk->request, talk->cap, &len)) {
		end(talk);
		return;
	}
	if (len > talk->cap
	    || !fzn_node_asks_send(talk->asks, talk->caller, talk->request, len, talk->expires_at,
	                           talk->timeout_ms, answered, talk)) {
		/* NOT SENT: the step told, as for an answer that never came, and
		 * the conversation over whatever it says -- a request that cannot
		 * leave now will not leave by asking again at once. */
		size_t ignored = 0;

		(void)talk->step(talk->ctx, NULL, 0, talk->request, talk->cap, &ignored);
		end(talk);
		return;
	}
	talk->sent++;
}

static void answered(void *ctx, const uint8_t *reply, size_t reply_len)
{
	fzn_node_talk_t *talk = ctx;

	if (talk->live)
		go_on(talk, reply, reply_len);
}

int fzn_node_talk_start(fzn_node_talk_t *talk, fzn_node_asks_t *asks, fzn_caller_t *caller,
                        uint64_t expires_at, unsigned timeout_ms, fzn_node_talk_step_fn step,
                        fzn_node_talk_over_fn over, void *ctx, uint8_t *request, size_t cap,
                        size_t request_len)
{
	if (!talk || talk->live || !asks || !caller || !step || !over || !request
	    || request_len > cap)
		return 0;
	talk->asks = asks;
	talk->caller = caller;
	talk->expires_at = expires_at;
	talk->timeout_ms = timeout_ms;
	talk->step = step;
	talk->over = over;
	talk->ctx = ctx;
	talk->request = request;
	talk->cap = cap;
	talk->sent = 0;
	if (!fzn_node_asks_send(asks, caller, request, request_len, expires_at, timeout_ms,
	                        answered, talk))
		return 0;
	talk->sent = 1;
	talk->live = 1;
	return 1;
}
