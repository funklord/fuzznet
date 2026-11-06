/* A bearer's pieces, and SLIP. net/bearer.h says why. */

#include "bearer.h"

#include <string.h>

size_t fzn_bearer_pieces(size_t len, size_t unit)
{
	size_t room, n;

	if (!len || len > FZN_BEARER_FRAME_MAX || unit < FZN_BEARER_UNIT_MIN
	    || unit > FZN_BEARER_UNIT_MAX)
		return 0;
	room = unit - FZN_BEARER_HEAD_LEN;
	n = (len + room - 1u) / room;
	return n <= FZN_BEARER_PIECES_MAX ? n : 0u;
}

int fzn_bearer_send(const fzn_bearer_t *b, uint16_t id, const uint8_t *frame, size_t len)
{
	uint8_t piece[FZN_BEARER_UNIT_MAX];
	size_t n, i, room, at = 0;

	if (!b || !b->send || !frame || !(n = fzn_bearer_pieces(len, b->unit)))
		return 0;
	room = b->unit - FZN_BEARER_HEAD_LEN;
	for (i = 0; i < n; i++, at += room) {
		size_t part = len - at < room ? len - at : room;

		piece[0] = (uint8_t)(id >> 8);
		piece[1] = (uint8_t)id;
		piece[2] = (uint8_t)i;
		piece[3] = (uint8_t)n;
		memcpy(piece + FZN_BEARER_HEAD_LEN, frame + at, part);
		if (!b->send(b->ctx, piece, FZN_BEARER_HEAD_LEN + part))
			return 0;
	}
	return 1;
}

/* THE SLOT FOR `id`, begun if it must be: a free one, or else the oldest's. */
static fzn_bearer_slot_t *slot_for(fzn_bearer_join_t *j, uint16_t id, uint8_t count)
{
	fzn_bearer_slot_t *s, *chosen = NULL;
	size_t i;

	for (i = 0; i < j->n_held; i++) {
		s = &j->held[i];
		if (s->count && s->id == id && s->count == count)
			return s;
		if (!chosen || (chosen->count && (!s->count || j->age - s->age > j->age - chosen->age)))
			chosen = s;
	}
	if (chosen) {
		memset(chosen->seen, 0, sizeof(chosen->seen));
		chosen->id = id;
		chosen->count = count;
		chosen->got = 0;
		chosen->len = 0;
		chosen->age = j->age++;
	}
	return chosen;
}

size_t fzn_bearer_take(fzn_bearer_join_t *j, const uint8_t *unit, size_t len,
                       const uint8_t **frame)
{
	fzn_bearer_slot_t *s;
	size_t room, part, at, whole;
	uint16_t id;
	uint8_t index, count;

	if (!j || !j->held || !j->n_held || !unit || !frame || len <= FZN_BEARER_HEAD_LEN
	    || len > j->unit || j->unit < FZN_BEARER_UNIT_MIN || j->unit > FZN_BEARER_UNIT_MAX)
		return 0;
	room = j->unit - FZN_BEARER_HEAD_LEN;
	part = len - FZN_BEARER_HEAD_LEN;
	id = (uint16_t)(((uint16_t)unit[0] << 8) | unit[1]);
	index = unit[2];
	count = unit[3];
	at = (size_t)index * room;
	/* ALL BUT THE LAST FILLS ITS ROOM, so a piece's place is its index. */
	if (!count || count > FZN_BEARER_PIECES_MAX || index >= count
	    || (index + 1u < count && part != room) || at + part > FZN_BEARER_FRAME_MAX)
		return 0;
	if (!(s = slot_for(j, id, count)))
		return 0;
	if (s->seen[index / 8u] & (1u << (index % 8u)))
		return 0;
	s->seen[index / 8u] |= (uint8_t)(1u << (index % 8u));
	memcpy(s->bytes + at, unit + FZN_BEARER_HEAD_LEN, part);
	if (index + 1u == count)
		s->len = at + part;
	if (++s->got < count)
		return 0;
	whole = s->len;
	s->count = 0;
	*frame = s->bytes;
	return whole;
}

size_t fzn_slip_encode(const uint8_t *in, size_t len, uint8_t *out, size_t cap)
{
	size_t i, w = 0;

	if ((!in && len) || !out || cap < 2u)
		return 0;
	out[w++] = FZN_SLIP_END;
	for (i = 0; i < len; i++) {
		if (w + 3u > cap)
			return 0;
		if (in[i] == FZN_SLIP_END) {
			out[w++] = FZN_SLIP_ESC;
			out[w++] = FZN_SLIP_ESC_END;
		} else if (in[i] == FZN_SLIP_ESC) {
			out[w++] = FZN_SLIP_ESC;
			out[w++] = FZN_SLIP_ESC_ESC;
		} else {
			out[w++] = in[i];
		}
	}
	out[w++] = FZN_SLIP_END;
	return w;
}

size_t fzn_slip_feed(fzn_slip_reader_t *r, uint8_t byte)
{
	size_t done;

	if (byte == FZN_SLIP_END) {
		done = r->overrun ? 0u : r->len;
		r->len = 0;
		r->overrun = 0;
		r->escaped = 0;
		return done;
	}
	if (r->overrun)
		return 0;
	if (r->escaped) {
		r->escaped = 0;
		if (byte == FZN_SLIP_ESC_END) {
			byte = FZN_SLIP_END;
		} else if (byte == FZN_SLIP_ESC_ESC) {
			byte = FZN_SLIP_ESC;
		} else {
			r->overrun = 1;
			return 0;
		}
	} else if (byte == FZN_SLIP_ESC) {
		r->escaped = 1;
		return 0;
	}
	if (r->len == r->cap) {
		r->overrun = 1;
		return 0;
	}
	r->buffer[r->len++] = byte;
	return 0;
}
