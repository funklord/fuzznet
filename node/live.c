/* A call's words and its table. node/live.h says what and why. */
#include "live.h"

#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "../wire/bytes.h"

int fzn_live_is_word(const uint8_t *bytes, size_t len)
{
	return bytes && len >= FZN_LIVE_HEAD_LEN && bytes[0] == FZN_TYPES_VERSION_SHARED
	       && bytes[1] == FZN_TYPE_LIVE;
}

int fzn_live_read(const uint8_t *bytes, size_t len, fzn_live_word_t *out)
{
	const uint8_t *at;

	if (!out || !fzn_live_is_word(bytes, len))
		return 0;
	memset(out, 0, sizeof(*out));
	out->kind = (fzn_live_kind_t)bytes[2];
	memcpy(out->call, bytes + 3, FZN_LIVE_CALL_LEN);
	at = bytes + FZN_LIVE_HEAD_LEN;
	switch (out->kind) {
	case FZN_LIVE_RING:
		if (len != FZN_LIVE_RING_LEN)
			return 0;
		out->kinds = at[0];
		out->whom = at + 1;
		return out->kinds != 0u
		       && (out->kinds & (uint8_t) ~(FZN_LIVE_AUDIO | FZN_LIVE_VIDEO)) == 0u;
	case FZN_LIVE_ANSWER:
	case FZN_LIVE_DECLINE:
	case FZN_LIVE_HANGUP:
		return len == FZN_LIVE_HEAD_LEN;
	case FZN_LIVE_REPORT:
		if (len != FZN_LIVE_REPORT_LEN)
			return 0;
		out->stream = at[0];
		out->received = fzn_get_be32(at + 1);
		out->lost = fzn_get_be32(at + 5);
		out->jitter_ms = fzn_get_be16(at + 9);
		return 1;
	case FZN_LIVE_MEMBER:
		if (len != FZN_LIVE_MEMBER_LEN)
			return 0;
		out->from = fzn_get_be16(at);
		out->whom = at + 2;
		return out->from != 0u;
	case FZN_LIVE_FRAME:
		if (len < FZN_LIVE_FRAME_HEAD_LEN)
			return 0;
		out->stream = at[0];
		out->from = fzn_get_be16(at + 1);
		out->seq = fzn_get_be32(at + 3);
		out->at_ms = fzn_get_be32(at + 7);
		out->piece = fzn_get_be16(at + 11);
		out->pieces = fzn_get_be16(at + 13);
		out->media = bytes + FZN_LIVE_FRAME_HEAD_LEN;
		out->media_len = len - FZN_LIVE_FRAME_HEAD_LEN;
		return out->pieces != 0u && out->piece < out->pieces;
	}
	return 0;
}

size_t fzn_live_write(const fzn_live_word_t *w, uint8_t *out, size_t cap)
{
	size_t len;

	if (!w || !out)
		return 0;
	switch (w->kind) {
	case FZN_LIVE_RING:
		len = FZN_LIVE_RING_LEN;
		if (!w->whom || !w->kinds
		    || (w->kinds & (uint8_t) ~(FZN_LIVE_AUDIO | FZN_LIVE_VIDEO)) != 0u)
			return 0;
		break;
	case FZN_LIVE_ANSWER:
	case FZN_LIVE_DECLINE:
	case FZN_LIVE_HANGUP:
		len = FZN_LIVE_HEAD_LEN;
		break;
	case FZN_LIVE_FRAME:
		if (!w->pieces || w->piece >= w->pieces || (w->media_len && !w->media))
			return 0;
		len = FZN_LIVE_FRAME_HEAD_LEN + w->media_len;
		break;
	case FZN_LIVE_REPORT:
		len = FZN_LIVE_REPORT_LEN;
		break;
	case FZN_LIVE_MEMBER:
		if (!w->whom || !w->from)
			return 0;
		len = FZN_LIVE_MEMBER_LEN;
		break;
	default:
		return 0;
	}
	if (len > cap)
		return 0;
	out[0] = FZN_TYPES_VERSION_SHARED;
	out[1] = FZN_TYPE_LIVE;
	out[2] = (uint8_t)w->kind;
	memcpy(out + 3, w->call, FZN_LIVE_CALL_LEN);
	if (w->kind == FZN_LIVE_RING) {
		out[FZN_LIVE_HEAD_LEN] = w->kinds;
		memcpy(out + FZN_LIVE_HEAD_LEN + 1u, w->whom, FZN_PUBKEY_LEN);
	} else if (w->kind == FZN_LIVE_FRAME) {
		uint8_t *at = out + FZN_LIVE_HEAD_LEN;

		at[0] = w->stream;
		fzn_put_be16(at + 1, w->from);
		fzn_put_be32(at + 3, w->seq);
		fzn_put_be32(at + 7, w->at_ms);
		fzn_put_be16(at + 11, w->piece);
		fzn_put_be16(at + 13, w->pieces);
		if (w->media_len)
			memcpy(out + FZN_LIVE_FRAME_HEAD_LEN, w->media, w->media_len);
	} else if (w->kind == FZN_LIVE_MEMBER) {
		fzn_put_be16(out + FZN_LIVE_HEAD_LEN, w->from);
		memcpy(out + FZN_LIVE_HEAD_LEN + 2u, w->whom, FZN_PUBKEY_LEN);
	} else if (w->kind == FZN_LIVE_REPORT) {
		uint8_t *at = out + FZN_LIVE_HEAD_LEN;

		at[0] = w->stream;
		fzn_put_be32(at + 1, w->received);
		fzn_put_be32(at + 5, w->lost);
		fzn_put_be16(at + 9, w->jitter_ms);
	}
	return len;
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
		uint64_t limit = c->state == FZN_LIVE_UP ? FZN_LIVE_IDLE_S : FZN_LIVE_RING_S;
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
