/* Requests awaited by the loop: project.md sec 636, and the header. */
#include "asks.h"

#include <string.h>

void fzn_node_asks_init(fzn_node_asks_t *asks, uint8_t *reply, size_t reply_cap,
                        uint64_t (*clock_ms)(void))
{
	if (!asks)
		return;
	memset(asks, 0, sizeof(*asks));
	asks->reply = reply;
	asks->reply_cap = reply_cap;
	asks->clock_ms = clock_ms;
}

int fzn_node_asks_await(fzn_node_asks_t *asks, fzn_caller_t *caller, uint32_t msg,
                        unsigned timeout_ms, fzn_node_answered_fn done, void *ctx)
{
	size_t i;

	if (!asks || !caller || !done || !asks->clock_ms || !asks->reply)
		return 0;
	for (i = 0; i < FZN_NODE_ASKS_MAX && asks->slots[i].used; i++)
		;
	if (i == FZN_NODE_ASKS_MAX)
		return 0;
	asks->slots[i].caller = caller;
	asks->slots[i].msg = msg;
	asks->slots[i].deadline_ms = asks->clock_ms() + timeout_ms;
	asks->slots[i].done = done;
	asks->slots[i].ctx = ctx;
	asks->slots[i].used = 1;
	return 1;
}

int fzn_node_asks_send(fzn_node_asks_t *asks, fzn_caller_t *caller, const uint8_t *request,
                       size_t request_len, uint64_t expires_at, unsigned timeout_ms,
                       fzn_node_answered_fn done, void *ctx)
{
	uint32_t msg = 0;

	/* ROOM FIRST: a request sent with nowhere to await its answer would be
	 * answered to nobody. */
	if (!asks || !caller || !request || !done || !asks->clock_ms || !asks->reply
	    || fzn_node_asks_pending(asks) == FZN_NODE_ASKS_MAX
	    || fzn_caller_send(caller, request, request_len, expires_at, &msg) != FZN_CALLER_OK)
		return 0;
	return fzn_node_asks_await(asks, caller, msg, timeout_ms, done, ctx);
}

size_t fzn_node_asks_fds(const fzn_node_asks_t *asks, int *fds, size_t cap)
{
	size_t i, k, n = 0;

	if (!asks || !fds)
		return 0;
	for (i = 0; i < FZN_NODE_ASKS_MAX && n < cap; i++) {
		if (!asks->slots[i].used || asks->slots[i].caller->fd < 0)
			continue;
		for (k = 0; k < n && fds[k] != asks->slots[i].caller->fd; k++)
			;
		if (k == n)
			fds[n++] = asks->slots[i].caller->fd;
	}
	return n;
}

/* A SLOT'S END: freed first, so a callback that asks again finds room. */
static void finish(fzn_node_ask_t *slot, const uint8_t *reply, size_t len)
{
	fzn_node_answered_fn done = slot->done;
	void *ctx = slot->ctx;

	slot->used = 0;
	done(ctx, reply, len);
}

size_t fzn_node_asks_ready(fzn_node_asks_t *asks, int fd)
{
	fzn_caller_t *caller = NULL;
	size_t i, answered = 0, len = 0;
	uint32_t msg = 0;

	if (!asks)
		return 0;
	for (i = 0; i < FZN_NODE_ASKS_MAX && !caller; i++)
		if (asks->slots[i].used && asks->slots[i].caller->fd == fd)
			caller = asks->slots[i].caller;
	if (!caller)
		return 0;
	/* EVERY ANSWER WAITING, read without waiting for more: a datagram the
	 * caller skips -- a stranger's, a late one -- costs nothing. */
	while (fzn_caller_recv_any(caller, &msg, asks->reply, asks->reply_cap, &len, 1u)
	       == FZN_CALLER_OK) {
		for (i = 0; i < FZN_NODE_ASKS_MAX; i++)
			if (asks->slots[i].used && asks->slots[i].caller == caller
			    && asks->slots[i].msg == msg) {
				finish(&asks->slots[i], asks->reply, len);
				answered++;
				break;
			}
	}
	return answered;
}

size_t fzn_node_asks_expire(fzn_node_asks_t *asks)
{
	size_t i, failed = 0;
	uint64_t now;

	if (!asks || !asks->clock_ms)
		return 0;
	now = asks->clock_ms();
	for (i = 0; i < FZN_NODE_ASKS_MAX; i++)
		if (asks->slots[i].used && asks->slots[i].deadline_ms <= now) {
			/* ITS REPLY FORGOTTEN WITH IT, sec 708: held part way it would
			 * keep its slot, and a caller of one slot refused the next. */
			fzn_caller_forget(asks->slots[i].caller, asks->slots[i].msg);
			finish(&asks->slots[i], NULL, 0);
			failed++;
		}
	return failed;
}

size_t fzn_node_asks_cancel(fzn_node_asks_t *asks, const fzn_caller_t *caller)
{
	size_t i, failed = 0;

	if (!asks)
		return 0;
	for (i = 0; i < FZN_NODE_ASKS_MAX; i++)
		if (asks->slots[i].used && asks->slots[i].caller == caller) {
			fzn_caller_forget(caller, asks->slots[i].msg);
			finish(&asks->slots[i], NULL, 0);
			failed++;
		}
	return failed;
}

size_t fzn_node_asks_pending(const fzn_node_asks_t *asks)
{
	size_t i, n = 0;

	if (!asks)
		return 0;
	for (i = 0; i < FZN_NODE_ASKS_MAX; i++)
		n += asks->slots[i].used != 0;
	return n;
}
