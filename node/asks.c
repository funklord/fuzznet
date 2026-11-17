/* Requests awaited by the loop: project.md sec 636, and the header.
 *
 * THE RESEND SCHEDULE IS SITU'S, sec 1227: the generated driver for
 * `wire/frame.situ`'s `reply_to` holds each exchange's wait, its resends and
 * the sooner schedule once part of its reply is in (sec 1168), stated in the
 * schema rather than in this file. What stays here is what only this table
 * knows: the reply is matched after it is opened, so the driver never sees
 * it and is told `end`; a resend is sealed afresh, or is the asker's own
 * (`again`), or asks only for the missing pieces (sec 1214); and no resend
 * goes out within half a part interval of the end, a margin situ does not
 * state (its 26.1042). */
#include "asks.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "../wire/generated/frame_drive.h"

/* THE NUMBERS ARE ONE: the schema states them, and `fzn_caller_ask`, which
 * waits in place rather than through this table, still reads caller.h's. */
_Static_assert(SITU_REPLY_TO_RESEND_MS == FZN_CALLER_RESEND_MS, "the schema's resend interval is caller.h's");
_Static_assert(SITU_REPLY_TO_RETRIES == FZN_CALLER_RESENDS, "the schema's resends are caller.h's");
_Static_assert(SITU_REPLY_TO_RESEND_PART_MS == FZN_CALLER_RESEND_PART_MS,
               "the schema's part interval is caller.h's");
_Static_assert(SITU_REPLY_TO_RETRIES_PART == FZN_CALLER_RESENDS_PART, "the schema's part resends are caller.h's");

/* THE DRIVER, in the table's opaque words. */
struct drive_state {
	situ_drive_reply_to_t drive;
	situ_drive_reply_to_slot_t slots[FZN_NODE_ASKS_MAX];
	situ_conv_reply_to_slot_t keys[FZN_NODE_ASKS_MAX];
};
_Static_assert(sizeof(struct drive_state) <= sizeof(((fzn_node_asks_t *)0)->drive),
               "FZN_NODE_ASKS_DRIVE_WORDS is too small for the driver");
_Static_assert(_Alignof(struct drive_state) <= _Alignof(uint64_t), "the driver needs a wider alignment");

static situ_drive_reply_to_t *drive_of(fzn_node_asks_t *asks)
{
	return &((struct drive_state *)(void *)asks->drive)->drive;
}

static const situ_drive_reply_to_t *drive_seen(const fzn_node_asks_t *asks)
{
	return &((const struct drive_state *)(const void *)asks->drive)->drive;
}

/* AN EXCHANGE'S ID IS ITS ENTRY'S PLACE, one up: the driver's table keys a
 * request by its frame's `msg`, which two callers may share, and this table
 * matches by caller and `msg` itself -- so the frame the driver records is
 * a blank one, and the id is what tells the exchanges apart. */
static uint32_t id_of(const fzn_node_asks_t *asks, const fzn_node_ask_t *e)
{
	return (uint32_t)(e - asks->entries) + 1u;
}

static fzn_node_ask_t *entry_by_id(fzn_node_asks_t *asks, uint32_t id)
{
	if (id == 0u || id > FZN_NODE_ASKS_MAX || !asks->entries[id - 1u].used)
		return NULL;
	return &asks->entries[id - 1u];
}

static uint8_t blank_frame[SITU_FZN_FRAME_SIZE_MIN];

/* NOTHING IS SUBMITTED AS IT STANDS: every send goes through `resend`. */
static situ_err_t submit_nothing(void *ctx, const uint8_t *data, uint32_t len)
{
	(void)ctx;
	(void)data;
	(void)len;
	return SITU_OK;
}

static int want_instead(fzn_node_ask_t *e);

/* PART OF ITS REPLY IN, told to the driver, which then resends sooner and
 * more (sec 1168); telling it again changes nothing. */
static void tell_part(fzn_node_asks_t *asks, fzn_node_ask_t *e, uint64_t now)
{
	if (fzn_caller_holds_part(e->caller, e->msg))
		(void)situ_drive_reply_to_part_held(drive_of(asks), id_of(asks, e), (uint32_t)now);
}

/* A RESEND DUE, by the driver's schedule. */
static situ_err_t resend(void *ctx, uint32_t id, const uint8_t *data, uint32_t len)
{
	fzn_node_asks_t *asks = ctx;
	fzn_node_ask_t *e = entry_by_id(asks, id);

	(void)data;
	(void)len;
	if (!e)
		return SITU_ERR_CONSTRAINT;
	/* NOT INTO THE LAST HALF PART INTERVAL: an answer to it could not come
	 * back in time. The driver counts it all the same; nothing follows it. */
	if (asks->stepping_ms + FZN_CALLER_RESEND_PART_MS / 2u >= e->deadline_ms)
		return SITU_OK;
	if (e->again)
		e->again(e->again_ctx);
	else if (e->request && !want_instead(e))
		(void)fzn_caller_resend(e->caller, e->request, e->request_len, e->expires_at, e->msg);
	return SITU_OK;
}

/* A SLOT'S END: freed first, so a callback that asks again finds room. */
static void finish(fzn_node_ask_t *slot, const uint8_t *reply, size_t len)
{
	fzn_node_answered_fn done = slot->done;
	void *ctx = slot->ctx;

	free(slot->request);
	slot->request = NULL;
	slot->used = 0;
	done(ctx, reply, len);
}

/* PAST ITS WAIT, by the driver, which has dropped it already. */
static void expired(void *ctx, uint32_t id)
{
	fzn_node_asks_t *asks = ctx;
	fzn_node_ask_t *e = entry_by_id(asks, id);

	if (!e)
		return;
	/* ITS REPLY FORGOTTEN WITH IT, sec 708: held part way it would keep its
	 * slot, and a caller of one slot refused the next. */
	fzn_caller_forget(e->caller, e->msg);
	finish(e, NULL, 0);
}

/* ENDED HERE -- answered, or cancelled -- and so ended in the driver. */
static void end(fzn_node_asks_t *asks, fzn_node_ask_t *e, const uint8_t *reply, size_t len)
{
	(void)situ_drive_reply_to_end(drive_of(asks), id_of(asks, e));
	finish(e, reply, len);
}

void fzn_node_asks_init(fzn_node_asks_t *asks, uint8_t *reply, size_t reply_cap,
                        uint64_t (*clock_ms)(void))
{
	struct drive_state *d;
	situ_io_t io;

	if (!asks)
		return;
	memset(asks, 0, sizeof(*asks));
	asks->reply = reply;
	asks->reply_cap = reply_cap;
	asks->clock_ms = clock_ms;
	d = (struct drive_state *)(void *)asks->drive;
	io.submit = submit_nothing;
	io.ctx = asks;
	situ_drive_reply_to_init(&d->drive, d->slots, d->keys, FZN_NODE_ASKS_MAX, io, SITU_REPLY_TO_TIMEOUT_MS,
	                         SITU_REPLY_TO_RETRIES, SITU_REPLY_TO_RESEND_MS, SITU_REPLY_TO_RESEND_PART_MS,
	                         SITU_REPLY_TO_RETRIES_PART);
	situ_drive_reply_to_on_resend(&d->drive, resend);
	situ_drive_reply_to_on_expire(&d->drive, expired);
}

/* AN EXCHANGE RECORDED, `timeout_ms` its wait: resent by the schedule when
 * RESENDS, else only awaited. Its entry, or NULL with the table full. */
static fzn_node_ask_t *track(fzn_node_asks_t *asks, fzn_caller_t *caller, uint32_t msg, unsigned timeout_ms,
                             fzn_node_answered_fn done, void *ctx, int resends)
{
	situ_drive_reply_to_policy_t policy;
	situ_msg_t frame;
	situ_view_t view;
	fzn_node_ask_t *e;
	uint64_t now;
	size_t i;

	for (i = 0; i < FZN_NODE_ASKS_MAX && asks->entries[i].used; i++)
		;
	if (i == FZN_NODE_ASKS_MAX)
		return NULL;
	e = &asks->entries[i];
	now = asks->clock_ms();
	policy.timeout_ms = timeout_ms;
	policy.retries = resends ? SITU_REPLY_TO_RETRIES : 0u;
	policy.resend_ms = SITU_REPLY_TO_RESEND_MS;
	policy.resend_part_ms = SITU_REPLY_TO_RESEND_PART_MS;
	policy.retries_part = resends ? SITU_REPLY_TO_RETRIES_PART : 0u;
	situ_msg_init(&frame, blank_frame, (uint32_t)sizeof(blank_frame));
	if (situ_fzn_frame_view(&frame, 0u, (uint32_t)sizeof(blank_frame), &view) != SITU_OK
	    || situ_drive_reply_to_track_with(drive_of(asks), view, blank_frame, (uint32_t)sizeof(blank_frame),
	                                      id_of(asks, e), (uint32_t)now, &policy)
	               != SITU_OK)
		return NULL;
	e->caller = caller;
	e->msg = msg;
	e->deadline_ms = now + timeout_ms;
	e->done = done;
	e->ctx = ctx;
	e->request = NULL;
	e->request_len = 0;
	e->again = NULL;
	e->again_ctx = NULL;
	e->wanted = 0;
	e->missing_at_want = 0;
	e->used = 1;
	/* PART OF ITS REPLY IN ALREADY -- a relayed request's, which another
	 * host sent before this one awaited it -- puts it on the sooner
	 * schedule from the start. */
	tell_part(asks, e, now);
	return e;
}

int fzn_node_asks_await(fzn_node_asks_t *asks, fzn_caller_t *caller, uint32_t msg,
                        unsigned timeout_ms, fzn_node_answered_fn done, void *ctx)
{
	if (!asks || !caller || !done || !asks->clock_ms || !asks->reply)
		return 0;
	return track(asks, caller, msg, timeout_ms, done, ctx, 0) != NULL;
}

int fzn_node_asks_await_again(fzn_node_asks_t *asks, fzn_caller_t *caller, uint32_t msg,
                              unsigned timeout_ms, fzn_node_answered_fn done, void *ctx,
                              void (*again)(void *again_ctx), void *again_ctx)
{
	fzn_node_ask_t *e;

	if (!asks || !caller || !done || !again || !asks->clock_ms || !asks->reply
	    || (e = track(asks, caller, msg, timeout_ms, done, ctx, 1)) == NULL)
		return 0;
	e->again = again;
	e->again_ctx = again_ctx;
	return 1;
}

int fzn_node_asks_send(fzn_node_asks_t *asks, fzn_caller_t *caller, const uint8_t *request,
                       size_t request_len, uint64_t expires_at, unsigned timeout_ms,
                       fzn_node_answered_fn done, void *ctx)
{
	uint32_t msg = 0;
	uint8_t *kept;
	fzn_node_ask_t *e;

	/* ROOM FIRST: a request sent with nowhere to await its answer would be
	 * answered to nobody. */
	if (!asks || !caller || !request || !done || !asks->clock_ms || !asks->reply
	    || fzn_node_asks_pending(asks) == FZN_NODE_ASKS_MAX
	    || fzn_caller_send(caller, request, request_len, expires_at, &msg) != FZN_CALLER_OK)
		return 0;
	/* KEPT TO SEND AGAIN, sec 737. Without the memory it is awaited all the
	 * same, only not resent. */
	kept = request_len ? malloc(request_len) : NULL;
	if ((e = track(asks, caller, msg, timeout_ms, done, ctx, kept != NULL)) == NULL) {
		free(kept);
		return 0;
	}
	if (kept) {
		memcpy(kept, request, request_len);
		e->request = kept;
		e->request_len = request_len;
		e->expires_at = expires_at;
	}
	return 1;
}

size_t fzn_node_asks_fds(const fzn_node_asks_t *asks, int *fds, size_t cap)
{
	size_t i, k, n = 0;

	if (!asks || !fds)
		return 0;
	for (i = 0; i < FZN_NODE_ASKS_MAX && n < cap; i++) {
		if (!asks->entries[i].used || asks->entries[i].caller->fd < 0)
			continue;
		for (k = 0; k < n && fds[k] != asks->entries[i].caller->fd; k++)
			;
		if (k == n)
			fds[n++] = asks->entries[i].caller->fd;
	}
	return n;
}

/* EVERY EXCHANGE THROUGH `only` -- or through any, with NULL -- whose reply
 * is part in, told so. */
static void parts_held(fzn_node_asks_t *asks, const fzn_caller_t *only, uint64_t now)
{
	size_t i;

	for (i = 0; i < FZN_NODE_ASKS_MAX; i++)
		if (asks->entries[i].used && (!only || asks->entries[i].caller == only))
			tell_part(asks, &asks->entries[i], now);
}

size_t fzn_node_asks_ready(fzn_node_asks_t *asks, int fd)
{
	fzn_caller_t *caller = NULL;
	size_t i, answered = 0, len = 0;
	uint32_t msg = 0;

	if (!asks)
		return 0;
	for (i = 0; i < FZN_NODE_ASKS_MAX && !caller; i++)
		if (asks->entries[i].used && asks->entries[i].caller->fd == fd)
			caller = asks->entries[i].caller;
	if (!caller)
		return 0;
	/* EVERY ANSWER WAITING, read without waiting for more: a datagram the
	 * caller skips -- a stranger's, a late one -- costs nothing. */
	while (fzn_caller_recv_any(caller, &msg, asks->reply, asks->reply_cap, &len, 1u)
	       == FZN_CALLER_OK) {
		for (i = 0; i < FZN_NODE_ASKS_MAX; i++)
			if (asks->entries[i].used && asks->entries[i].caller == caller
			    && asks->entries[i].msg == msg) {
				end(asks, &asks->entries[i], asks->reply, len);
				answered++;
				break;
			}
	}
	/* AND A PIECE THAT CAME WITHOUT ITS WHOLE, so the next wake is the
	 * sooner schedule's. */
	if (asks->clock_ms)
		parts_held(asks, caller, asks->clock_ms());
	return answered;
}

/* THE MISSING PIECES ASKED FOR IN PLACE OF A WHOLE RESEND, sec 1214, once
 * part of the reply is in: 1 when a want went. Not after a want that
 * brought nothing, which the whole resend follows. */
static int want_instead(fzn_node_ask_t *e)
{
	size_t missing, asked = 0;

	if (!fzn_caller_holds_part(e->caller, e->msg))
		return 0;
	missing = fzn_caller_missing(e->caller, e->msg);
	if (e->wanted && missing >= e->missing_at_want) {
		e->wanted = 0;
		return 0;
	}
	if (fzn_caller_want(e->caller, e->msg, e->expires_at, &asked) != FZN_CALLER_OK) {
		e->wanted = 0;
		return 0;
	}
	e->wanted = 1;
	e->missing_at_want = asked;
	return 1;
}

size_t fzn_node_asks_expire(fzn_node_asks_t *asks)
{
	uint32_t next = 0, gone = 0;
	uint64_t now;

	if (!asks || !asks->clock_ms)
		return 0;
	now = asks->clock_ms();
	asks->stepping_ms = now;
	parts_held(asks, NULL, now);
	/* RESENT WHAT IS DUE, and failed what is past its wait -- each through
	 * the hooks above, by the driver's schedule. */
	(void)situ_drive_reply_to_step(drive_of(asks), (uint32_t)now, &next, &gone);
	return gone;
}

size_t fzn_node_asks_cancel(fzn_node_asks_t *asks, const fzn_caller_t *caller)
{
	size_t i, failed = 0;

	if (!asks)
		return 0;
	for (i = 0; i < FZN_NODE_ASKS_MAX; i++)
		if (asks->entries[i].used && asks->entries[i].caller == caller) {
			fzn_caller_forget(asks->entries[i].caller, asks->entries[i].msg);
			end(asks, &asks->entries[i], NULL, 0);
			failed++;
		}
	return failed;
}

long fzn_node_asks_due_in(const fzn_node_asks_t *asks)
{
	const situ_drive_reply_to_t *d;
	uint32_t now, soonest = 0, left;
	int any = 0;
	uint32_t i;

	if (!asks || !asks->clock_ms)
		return -1;
	now = (uint32_t)asks->clock_ms();
	d = drive_seen(asks);
	/* THE DRIVER'S NEXT DEADLINE -- a resend due, or a wait's end -- as
	 * `_step` would say it, read without stepping. */
	for (i = 0; i < d->cap; i++) {
		if (!d->slots[i].live)
			continue;
		left = (uint32_t)(now - d->slots[i].deadline_ms) < 0x80000000u ? 0u : d->slots[i].deadline_ms - now;
		if (!any || left < soonest)
			soonest = left;
		any = 1;
	}
	if (!any)
		return -1;
	return soonest > (uint32_t)LONG_MAX ? LONG_MAX : (long)soonest;
}

size_t fzn_node_asks_pending(const fzn_node_asks_t *asks)
{
	size_t i, n = 0;

	if (!asks)
		return 0;
	for (i = 0; i < FZN_NODE_ASKS_MAX; i++)
		n += asks->entries[i].used != 0;
	return n;
}
