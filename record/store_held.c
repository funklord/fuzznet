/* The record store's delta. record/store_held.h says what and why. */

#include "store_held.h"

#include "../fault/fault.h"

#include <stdlib.h>
#include <string.h>

typedef struct fzn_record_held_row {
	struct fzn_record_held_row *chain, *older, *newer;
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t seq;
	size_t len;
	uint8_t bytes[];
} row_t;

static size_t bucket_of(const uint8_t *issuer, uint32_t stream, uint64_t seq)
{
	return ((size_t)issuer[0] * 31u + (size_t)stream * 131u + (size_t)seq * 2654435761u)
	       % FZN_RECORD_HELD_BUCKETS;
}

static row_t *find(const fzn_record_held_t *h, const uint8_t *issuer, uint32_t stream, uint64_t seq)
{
	row_t *r;

	for (r = h->buckets[bucket_of(issuer, stream, seq)]; r; r = r->chain)
		if (r->seq == seq && r->stream == stream && memcmp(r->issuer, issuer, FZN_PUBKEY_LEN) == 0)
			return r;
	return NULL;
}

static void drop_row(fzn_record_held_t *h, row_t *r)
{
	row_t **at = &h->buckets[bucket_of(r->issuer, r->stream, r->seq)];

	while (*at != r)
		at = &(*at)->chain;
	*at = r->chain;
	if (r->older)
		r->older->newer = r->newer;
	else
		h->oldest = r->newer;
	if (r->newer)
		r->newer->older = r->older;
	else
		h->newest = r->older;
	h->rows--;
	h->bytes -= r->len;
	if (h->release)
		h->release(r);
	else
		free(r);
}

/* THE OLDEST RECORD OF A STREAM THAT MAY GO. 0 when there is none. */
static int shed_one(fzn_record_held_t *h)
{
	row_t *r;

	for (r = h->oldest; r; r = r->newer)
		if (r->stream != FZN_RECORD_HELD_KEPT_STREAM) {
			drop_row(h, r);
			h->dropped++;
			return 1;
		}
	return 0;
}

static int hold(fzn_record_held_t *h, const uint8_t *issuer, uint32_t stream, uint64_t seq,
                const uint8_t *bytes, size_t len)
{
	row_t *r;
	size_t b;

	if (find(h, issuer, stream, seq))
		return 1;
	if (stream != FZN_RECORD_HELD_KEPT_STREAM)
		while (h->bytes + len > h->budget)
			if (!shed_one(h)) {
				h->refused++;
				return 0;
			}
	while (!FZN_FAULT_RAM()
	       || !(r = h->alloc ? h->alloc(sizeof(*r) + len) : malloc(sizeof(*r) + len)))
		if (!shed_one(h)) {
			h->refused++;
			return 0;
		}
	memset(r, 0, sizeof(*r));
	memcpy(r->issuer, issuer, FZN_PUBKEY_LEN);
	r->stream = stream;
	r->seq = seq;
	r->len = len;
	memcpy(r->bytes, bytes, len);
	b = bucket_of(issuer, stream, seq);
	r->chain = h->buckets[b];
	h->buckets[b] = r;
	r->older = h->newest;
	if (h->newest)
		h->newest->newer = r;
	else
		h->oldest = r;
	h->newest = r;
	h->rows++;
	h->bytes += len;
	return 1;
}

static int held_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                    const uint8_t *bytes, size_t len)
{
	fzn_record_held_t *h = ctx;

	if (!h->stuck) {
		if (h->base->put(h->base->ctx, issuer, stream, seq, bytes, len))
			return 1;
		h->stuck = 1;
	}
	return hold(h, issuer, stream, seq, bytes, len);
}

static int held_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                    uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	fzn_record_held_t *h = ctx;
	const row_t *r = find(h, issuer, stream, seq);

	if (!r)
		return h->base->get(h->base->ctx, issuer, stream, seq, out, cap, len_out, found_out);
	if (r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len_out = r->len;
	if (found_out)
		*found_out = 1;
	return 1;
}

static int held_cut(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t from,
                    uint64_t below)
{
	fzn_record_held_t *h = ctx;
	row_t *r = h->oldest;

	while (r) {
		row_t *next = r->newer;

		if (r->stream == stream && r->seq >= from && r->seq < below
		    && memcmp(r->issuer, issuer, FZN_PUBKEY_LEN) == 0)
			drop_row(h, r);
		r = next;
	}
	return h->base->cut ? h->base->cut(h->base->ctx, issuer, stream, from, below) : 0;
}

void fzn_record_held_init(fzn_record_held_t *h, const fzn_record_store_ops_t *base, size_t budget)
{
	memset(h, 0, sizeof(*h));
	h->base = base;
	h->budget = budget ? budget : FZN_RECORD_HELD_BUDGET_DEFAULT;
	h->ops.put = held_put;
	h->ops.get = held_get;
	h->ops.ctx = h;
	h->ops.cut = base->cut ? held_cut : NULL;
}

size_t fzn_record_held_flush(fzn_record_held_t *h)
{
	size_t done = 0;

	while (h->oldest) {
		row_t *r = h->oldest;

		if (!h->base->put(h->base->ctx, r->issuer, r->stream, r->seq, r->bytes, r->len)) {
			h->stuck = 1;
			return done;
		}
		drop_row(h, r);
		done++;
	}
	h->stuck = 0;
	return done;
}

void fzn_record_held_free(fzn_record_held_t *h)
{
	while (h->oldest)
		drop_row(h, h->oldest);
}
