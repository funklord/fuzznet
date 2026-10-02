/* See ring.h. */

#include "ring.h"

#include <string.h>

const char *fzn_ring_err_str(fzn_ring_err_t err)
{
	switch (err) {
	case FZN_RING_OK:
		return "ok";
	case FZN_RING_ERR_MALFORMED:
		return "malformed";
	}
	return "unknown";
}

void fzn_ring_init(fzn_ring_t *ring)
{
	if (ring)
		memset(ring, 0, sizeof(*ring));
}

/* Copy out of and into the ring at a logical offset from `start`, round. */
static void read_at(const fzn_ring_t *ring, size_t off, uint8_t *to, size_t n)
{
	size_t at = (ring->start + off) % FZN_RING_BYTES, first = FZN_RING_BYTES - at;

	if (first > n)
		first = n;
	memcpy(to, ring->bytes + at, first);
	memcpy(to + first, ring->bytes, n - first);
}

static void write_at(fzn_ring_t *ring, size_t off, const uint8_t *from, size_t n)
{
	size_t at = (ring->start + off) % FZN_RING_BYTES, first = FZN_RING_BYTES - at;

	if (first > n)
		first = n;
	memcpy(ring->bytes + at, from, first);
	memcpy(ring->bytes, from + first, n - first);
}

static size_t length_at(const fzn_ring_t *ring, size_t off)
{
	uint8_t p[2];

	read_at(ring, off, p, 2u);
	return ((size_t)p[0] << 8) | p[1];
}

/* The oldest record goes. */
static void evict(fzn_ring_t *ring)
{
	size_t n = 2u + length_at(ring, 0u);

	ring->start = (ring->start + n) % FZN_RING_BYTES;
	ring->used -= n;
	ring->held--;
	ring->evicted++;
}

static void keep(fzn_ring_t *ring, const uint8_t *record, size_t len)
{
	uint8_t p[2];

	while (FZN_RING_BYTES - ring->used < 2u + len)
		evict(ring);
	p[0] = (uint8_t)(len >> 8);
	p[1] = (uint8_t)len;
	write_at(ring, ring->used, p, 2u);
	write_at(ring, ring->used + 2u, record, len);
	ring->used += 2u + len;
	ring->held++;
}

fzn_ring_err_t fzn_ring_put(fzn_ring_t *ring, const fzn_entry_t *entry)
{
	uint8_t record[FZN_ENTRY_RECORD_MAX];
	size_t len = 0;

	if (!ring || fzn_entry_pack(entry, record, sizeof(record), &len) != FZN_ENTRY_OK)
		return FZN_RING_ERR_MALFORMED;
	keep(ring, record, len);
	return FZN_RING_OK;
}

size_t fzn_ring_walk(const fzn_ring_t *ring, fzn_ring_each_fn each, void *ctx)
{
	uint8_t record[FZN_ENTRY_RECORD_MAX];
	size_t off = 0, n = 0;

	if (!ring || !each)
		return 0;
	while (off < ring->used) {
		size_t len = length_at(ring, off);
		fzn_entry_t e;

		read_at(ring, off + 2u, record, len);
		/* EVERY RECORD WAS PACKED HERE, so one that will not unpack is a
		 * ring somebody wrote over; the walk stops rather than guess. */
		if (fzn_entry_unpack(record, len, &e) != FZN_ENTRY_OK)
			break;
		each(ctx, &e);
		off += 2u + len;
		n++;
	}
	return n;
}

void fzn_ring_spans(const fzn_ring_t *ring, const uint8_t **first, size_t *first_len,
                    const uint8_t **second, size_t *second_len)
{
	size_t tail;

	if (!ring || !first || !first_len || !second || !second_len)
		return;
	tail = FZN_RING_BYTES - ring->start;
	*first = ring->bytes + ring->start;
	if (ring->used <= tail) {
		*first_len = ring->used;
		*second = ring->bytes;
		*second_len = 0;
	} else {
		*first_len = tail;
		*second = ring->bytes;
		*second_len = ring->used - tail;
	}
}

fzn_ring_err_t fzn_ring_load(fzn_ring_t *ring, const uint8_t *dump, size_t len)
{
	size_t off = 0;

	if (!ring || (!dump && len) || len > FZN_RING_BYTES)
		return FZN_RING_ERR_MALFORMED;
	fzn_ring_init(ring);
	while (off < len) {
		size_t n;
		fzn_entry_t e;

		if (len - off < 2u)
			goto bad;
		n = ((size_t)dump[off] << 8) | dump[off + 1u];
		if (len - off - 2u < n || fzn_entry_unpack(dump + off + 2u, n, &e) != FZN_ENTRY_OK)
			goto bad;
		keep(ring, dump + off + 2u, n);
		off += 2u + n;
	}
	return FZN_RING_OK;
bad:
	fzn_ring_init(ring);
	return FZN_RING_ERR_MALFORMED;
}
