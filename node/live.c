/* A call's words and its table. node/live.h says what and why. */
#include "live.h"

#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "../wire/bytes.h"
#include "../wire/generated/call.h"
#include "../wire/generated/call_build.h"

int fzn_live_is_word(const uint8_t *bytes, size_t len)
{
	return bytes && len >= FZN_LIVE_HEAD_LEN && bytes[0] == FZN_CMD_CALL;
}

/* THE BODY'S SIZE FOR A KIND whose body is fixed, from the schema: the message's
 * whole length must be its head and this, nothing after it. */
static size_t fixed_body(fzn_live_kind_t kind)
{
	switch (kind) {
	case FZN_LIVE_RING:
		return FZN_CALL_RING_SIZE_MAX;
	case FZN_LIVE_REPORT:
		return FZN_CALL_REPORT_SIZE_MAX;
	case FZN_LIVE_PARTICIPANT:
		return FZN_CALL_PARTICIPANT_SIZE_MAX;
	default:
		return FZN_CALL_NOTHING_SIZE_MAX;
	}
}

/* READ BY THE READER node/call.situ GENERATES, sec 1068: its view and its
 * validation say what the bytes are, where this file once counted offsets by
 * hand. What the schema cannot say yet stays here: a piece within its pieces,
 * and a fixed body's message carrying nothing after it. */
int fzn_live_read(const uint8_t *bytes, size_t len, fzn_live_word_t *out)
{
	situ_msg_t msg;
	situ_view_t v, b;

	if (!out || !fzn_live_is_word(bytes, len) || len > UINT32_MAX)
		return 0;
	situ_msg_init(&msg, (uint8_t *)(uintptr_t)bytes, (uint32_t)len);
	if (fzn_call_message_view(&msg, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_call_message_validate(v) != SITU_OK)
		return 0;
	memset(out, 0, sizeof(*out));
	out->kind = (fzn_live_kind_t)fzn_call_message_kind_get(v);
	memcpy(out->call, fzn_call_message_call_ptr(v), FZN_LIVE_CALL_LEN);
	if (out->kind != FZN_LIVE_FRAME && len != FZN_LIVE_HEAD_LEN + fixed_body(out->kind))
		return 0;
	switch (out->kind) {
	case FZN_LIVE_RING:
		if (fzn_call_message_body_ring_view(v, &b) != SITU_OK)
			return 0;
		out->kinds = fzn_call_ring_kinds_get(b);
		out->whom = fzn_call_ring_whom_ptr(b);
		return 1;
	case FZN_LIVE_ANSWER:
	case FZN_LIVE_DECLINE:
	case FZN_LIVE_HANGUP:
	case FZN_LIVE_RINGING:
	case FZN_LIVE_NO_ANSWER:
	case FZN_LIVE_BUSY:
	case FZN_LIVE_ANSWERED_ELSEWHERE:
	case FZN_LIVE_DECLINED_ELSEWHERE:
		return 1;
	case FZN_LIVE_REPORT:
		if (fzn_call_message_body_report_view(v, &b) != SITU_OK)
			return 0;
		out->stream = fzn_call_report_stream_get(b);
		out->received = fzn_call_report_received_get(b);
		out->lost = fzn_call_report_lost_get(b);
		out->jitter_ms = fzn_call_report_jitter_ms_get(b);
		out->last_at_ms = fzn_call_report_last_at_ms_get(b);
		out->held_ms = fzn_call_report_held_ms_get(b);
		return 1;
	case FZN_LIVE_PARTICIPANT:
		if (fzn_call_message_body_participant_view(v, &b) != SITU_OK)
			return 0;
		out->from = fzn_call_participant_index_get(b);
		out->whom = fzn_call_participant_whom_ptr(b);
		return 1;
	case FZN_LIVE_FRAME:
		if (fzn_call_message_body_frame_view(v, &b) != SITU_OK)
			return 0;
		out->stream = fzn_call_frame_stream_get(b);
		out->from = fzn_call_frame_from_get(b);
		out->seq = fzn_call_frame_seq_get(b);
		out->at_ms = fzn_call_frame_at_ms_get(b);
		out->piece = fzn_call_frame_piece_get(b);
		out->pieces = fzn_call_frame_pieces_get(b);
		out->media = fzn_call_frame_media_ptr(b);
		out->media_len = fzn_call_frame_media_len(b);
		return out->piece < out->pieces;
	default:
		return 0;
	}
}

/* WRITTEN BY THE BUILDERS node/call.situ GENERATES, sec 1083, as it is read by
 * its reader (sec 1068): the arm's body built in place after the head, the head
 * set through the message's own setters, and the whole validated -- no offset
 * counted here. What the schema cannot say stays: a piece within its pieces, and
 * media with no bytes behind it. */
size_t fzn_live_write(const fzn_live_word_t *w, uint8_t *out, size_t cap)
{
	const uint32_t at = FZN_CALL_MESSAGE_SIZE_MIN;
	uint32_t body = 0, room;
	situ_err_t err = SITU_OK;
	situ_msg_t msg;
	situ_view_t v;

	if (!w || !out || cap < at || cap > UINT32_MAX)
		return 0;
	room = (uint32_t)cap - at;
	switch (w->kind) {
	case FZN_LIVE_RING:
		if (!w->whom)
			return 0;
		err = fzn_call_ring_build(out + at, room, w->kinds, w->whom, &body);
		break;
	case FZN_LIVE_ANSWER:
	case FZN_LIVE_DECLINE:
	case FZN_LIVE_HANGUP:
	case FZN_LIVE_RINGING:
	case FZN_LIVE_NO_ANSWER:
	case FZN_LIVE_BUSY:
	case FZN_LIVE_ANSWERED_ELSEWHERE:
	case FZN_LIVE_DECLINED_ELSEWHERE:
		break;
	case FZN_LIVE_FRAME:
		if (w->piece >= w->pieces || (w->media_len && !w->media) || w->media_len > UINT32_MAX)
			return 0;
		err = fzn_call_frame_build(out + at, room, w->stream, w->from, w->seq, w->at_ms, w->piece,
		                           w->pieces, w->media, (uint32_t)w->media_len, &body);
		break;
	case FZN_LIVE_REPORT:
		err = fzn_call_report_build(out + at, room, w->stream, w->received, w->lost, w->jitter_ms,
		                            w->last_at_ms, w->held_ms, &body);
		break;
	case FZN_LIVE_PARTICIPANT:
		if (!w->whom)
			return 0;
		err = fzn_call_participant_build(out + at, room, w->from, w->whom, &body);
		break;
	default:
		return 0;
	}
	if (err != SITU_OK)
		return 0;
	situ_msg_init(&msg, out, at + body);
	if (fzn_call_message_view(&msg, 0u, at + body, &v) != SITU_OK)
		return 0;
	fzn_call_message_cmd_set(v, FZN_CMD_CALL);
	fzn_call_message_kind_set(&msg, v, (fzn_call_kind_t)w->kind);
	if (fzn_call_message_view(&msg, 0u, at + body, &v) != SITU_OK)
		return 0;
	memcpy(fzn_call_message_call_ptr(v), w->call, FZN_LIVE_CALL_LEN);
	if (fzn_call_message_validate(v) != SITU_OK)
		return 0;
	return at + body;
}

void fzn_live_count(fzn_live_stats_t *st, uint32_t seq, uint32_t at_ms, uint64_t now_ms)
{
	int64_t transit, d;

	if (!st)
		return;
	st->received++;
	if (!st->started) {
		st->started = 1;
		st->highest = seq;
	} else if (seq > st->highest) {
		st->lost += seq - st->highest - 1u;
		st->highest = seq;
	} else if (st->lost) {
		/* LATE, filling a gap counted lost. */
		st->lost--;
	}
	transit = (int64_t)(now_ms & 0xffffffffu) - (int64_t)at_ms;
	if (st->received > 1u) {
		d = transit - st->last_transit;
		if (d < 0)
			d = -d;
		/* J += (|D| - J) / 16, kept times 16. */
		st->jitter16 = (uint32_t)((int64_t)st->jitter16 + d - (int64_t)((st->jitter16 + 8u) / 16u));
	}
	st->last_transit = transit;
	st->last_at = at_ms;
	st->last_arrival_ms = now_ms;
}

fzn_live_call_t *fzn_live_find(fzn_live_calls_t *t, const uint8_t call[FZN_LIVE_CALL_LEN])
{
	size_t i;

	if (!t || !call)
		return NULL;
	for (i = 0; i < t->cap; i++)
		if (t->rows[i].used && memcmp(t->rows[i].call, call, FZN_LIVE_CALL_LEN) == 0)
			return &t->rows[i];
	return NULL;
}

fzn_live_call_t *fzn_live_open(fzn_live_calls_t *t, const uint8_t call[FZN_LIVE_CALL_LEN])
{
	fzn_live_call_t *c, *more;
	size_t i, cap;

	if (!t || !call)
		return NULL;
	if ((c = fzn_live_find(t, call)) != NULL)
		return c;
	for (i = 0; i < FZN_LIVE_ENDED; i++)
		if (memcmp(t->ended[i], call, FZN_LIVE_CALL_LEN) == 0)
			return NULL;
	for (i = 0; i < t->cap && t->rows[i].used; i++)
		;
	if (i == t->cap) {
		cap = t->cap ? t->cap * 2u : 8u;
		if (!(more = realloc(t->rows, cap * sizeof(*more))))
			return NULL;
		memset(more + t->cap, 0, (cap - t->cap) * sizeof(*more));
		t->rows = more;
		t->cap = cap;
	}
	c = &t->rows[i];
	memset(c, 0, sizeof(*c));
	memcpy(c->call, call, FZN_LIVE_CALL_LEN);
	c->used = 1;
	t->n++;
	return c;
}

void fzn_live_end(fzn_live_calls_t *t, fzn_live_call_t *c)
{
	if (!t || !c || !c->used)
		return;
	memcpy(t->ended[t->ended_next], c->call, FZN_LIVE_CALL_LEN);
	t->ended_next = (t->ended_next + 1u) % FZN_LIVE_ENDED;
	memset(c, 0, sizeof(*c));
	t->n--;
}

size_t fzn_live_expire(fzn_live_calls_t *t, uint64_t now_s,
                       void (*gone)(void *ctx, const fzn_live_call_t *c), void *ctx)
{
	size_t i, n = 0;

	if (!t)
		return 0;
	for (i = 0; i < t->cap; i++) {
		fzn_live_call_t *c = &t->rows[i];
		uint64_t limit = c->state == FZN_LIVE_UP ? FZN_LIVE_IDLE_S
		                 : c->ring_s                ? c->ring_s
		                                            : FZN_LIVE_RING_S;
		uint64_t from = c->state == FZN_LIVE_UP ? c->heard_s : c->since_s;

		if (!c->used || now_s < from + limit)
			continue;
		if (gone)
			gone(ctx, c);
		fzn_live_end(t, c);
		n++;
	}
	return n;
}

void fzn_live_release(fzn_live_calls_t *t)
{
	if (!t)
		return;
	free(t->rows);
	t->rows = NULL;
	t->cap = t->n = 0;
}
