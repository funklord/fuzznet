/* The buffered delta. persist/delta.h says what and why. */

#include "delta.h"

#include <stdlib.h>
#include <string.h>

typedef struct fzn_persist_delta_row {
	struct fzn_persist_delta_row *chain;
	struct fzn_persist_delta_row *older, *newer;
	fzn_persist_slot_t slot;
	int has_subject;
	int gone; /* a remove: the store's row reads as absent */
	uint8_t subject[FZN_PUBKEY_LEN];
	size_t len;
	uint8_t bytes[];
} row_t;

static void *take(const fzn_persist_delta_t *d, size_t len)
{
	return d->alloc ? d->alloc(len) : malloc(len);
}

static void give(const fzn_persist_delta_t *d, void *at)
{
	if (d->release)
		d->release(at);
	else
		free(at);
}

static size_t bucket_of(fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t h = (size_t)slot * 2654435761u;

	/* A SUBJECT IS A KEY OR A HASH: its first bytes spread well enough. */
	if (subject)
		h ^= ((size_t)subject[0] << 16) ^ ((size_t)subject[1] << 8) ^ subject[2]
		     ^ ((size_t)subject[FZN_PUBKEY_LEN - 1u] << 4);
	return h % FZN_PERSIST_DELTA_BUCKETS;
}

static row_t *find(const fzn_persist_delta_t *d, fzn_persist_slot_t slot, const uint8_t *subject)
{
	row_t *r;

	for (r = d->buckets[bucket_of(slot, subject)]; r; r = r->chain)
		if (r->slot == slot && r->has_subject == (subject != NULL)
		    && (!subject || memcmp(r->subject, subject, FZN_PUBKEY_LEN) == 0))
			return r;
	return NULL;
}

/* `r` out of the table and the order, and let go. */
static void drop_row(fzn_persist_delta_t *d, row_t *r)
{
	row_t **at = &d->buckets[bucket_of(r->slot, r->has_subject ? r->subject : NULL)];

	while (*at != r)
		at = &(*at)->chain;
	*at = r->chain;
	if (r->older)
		r->older->newer = r->newer;
	else
		d->oldest = r->newer;
	if (r->newer)
		r->newer->older = r->older;
	else
		d->newest = r->older;
	d->rows--;
	d->bytes -= r->len;
	give(d, r);
}

/* ONE ROW SHED to make room for a row of `rank`: the lowest rank held below it,
 * oldest first. 0 when none is. */
static int shed_one(fzn_persist_delta_t *d, fzn_rank_t rank)
{
	row_t *r, *chosen = NULL;
	fzn_rank_t least = rank;

	for (r = d->oldest; r; r = r->newer) {
		fzn_rank_t k = fzn_persist_slot_rank(r->slot);

		if (k < least && k < FZN_RANK_CONTROL) {
			least = k;
			chosen = r;
		}
	}
	if (!chosen)
		return 0;
	drop_row(d, chosen);
	d->dropped++;
	return 1;
}

/* KEEP (slot, subject) = `bytes`, or as removed: the newest of a key replaces
 * the last and goes to the end of the order. 0 when it could not be kept. */
static int hold(fzn_persist_delta_t *d, fzn_persist_slot_t slot, const uint8_t *subject,
                const uint8_t *bytes, size_t len, int gone)
{
	fzn_rank_t rank = fzn_persist_slot_rank(slot);
	row_t *r, *was = find(d, slot, subject);
	size_t b;

	if (rank < FZN_RANK_CONTROL) {
		size_t freed = was ? was->len : 0u;

		while (d->bytes - freed + len > d->budget) {
			if (!shed_one(d, rank)) {
				d->refused++;
				return 0;
			}
			/* THE ROW BEING REPLACED MAY BE THE ONE SHED. */
			was = find(d, slot, subject);
			freed = was ? was->len : 0u;
		}
	}
	while (!(r = take(d, sizeof(*r) + len)))
		if (!shed_one(d, FZN_RANK_IDENTITY + 1)) {
			d->refused++;
			return 0;
		}
	was = find(d, slot, subject);
	if (was)
		drop_row(d, was);
	memset(r, 0, sizeof(*r));
	r->slot = slot;
	r->has_subject = subject != NULL;
	if (subject)
		memcpy(r->subject, subject, FZN_PUBKEY_LEN);
	r->gone = gone;
	r->len = len;
	if (len)
		memcpy(r->bytes, bytes, len);
	b = bucket_of(slot, subject);
	r->chain = d->buckets[b];
	d->buckets[b] = r;
	r->older = d->newest;
	if (d->newest)
		d->newest->newer = r;
	else
		d->oldest = r;
	d->newest = r;
	d->rows++;
	d->bytes += len;
	return 1;
}

static int delta_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                      size_t cap, size_t *len)
{
	fzn_persist_delta_t *d = ctx;
	row_t *r = find(d, slot, subject);

	if (!r)
		return d->base->load(d->base->ctx, slot, subject, out, cap, len);
	if (r->gone || r->len > cap)
		return 0;
	if (r->len)
		memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int delta_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                      const uint8_t *bytes, size_t len)
{
	fzn_persist_delta_t *d = ctx;

	if (!d->stuck) {
		/* A ROW HERE IS NEWER THAN THE STORE'S, and this newer still. */
		if (d->base->save(d->base->ctx, slot, subject, bytes, len)) {
			row_t *r = find(d, slot, subject);

			if (r)
				drop_row(d, r);
			return 1;
		}
		d->stuck = 1;
	}
	return hold(d, slot, subject, bytes, len, 0);
}

static int delta_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	fzn_persist_delta_t *d = ctx;

	if (!d->stuck && d->base->remove) {
		if (d->base->remove(d->base->ctx, slot, subject)) {
			row_t *r = find(d, slot, subject);

			if (r)
				drop_row(d, r);
			return 1;
		}
		d->stuck = 1;
	}
	return hold(d, slot, subject, NULL, 0u, 1);
}

static int delta_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	fzn_persist_delta_t *d = ctx;
	const row_t *r;
	size_t n = 0, i, kept = 0;

	if (!d->base->list || !d->base->list(d->base->ctx, slot, out, max, &n))
		return 0;
	for (i = 0; i < n; i++) {
		const uint8_t *s = out + i * FZN_PUBKEY_LEN;
		const row_t *held = find(d, slot, s);

		if (held && held->gone)
			continue;
		memmove(out + kept * FZN_PUBKEY_LEN, s, FZN_PUBKEY_LEN);
		kept++;
	}
	for (r = d->oldest; r; r = r->newer) {
		int listed = 0;

		if (r->slot != slot || r->gone || !r->has_subject)
			continue;
		for (i = 0; i < kept && !listed; i++)
			listed = memcmp(out + i * FZN_PUBKEY_LEN, r->subject, FZN_PUBKEY_LEN) == 0;
		if (listed)
			continue;
		/* TRUNCATION IS A FAILURE, by the ops' own rule. */
		if (kept == max)
			return 0;
		memcpy(out + kept * FZN_PUBKEY_LEN, r->subject, FZN_PUBKEY_LEN);
		kept++;
	}
	*count = kept;
	return 1;
}

struct walk {
	fzn_persist_delta_t *d;
	fzn_persist_slot_t slot;
	int (*fn)(void *arg, const uint8_t subject[FZN_PUBKEY_LEN]);
	void *arg;
	int stopped;
};

/* A SUBJECT OF THE STORE'S: not one removed here, and not one this delta will
 * walk itself. */
static int walked(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	struct walk *w = arg;

	if (find(w->d, w->slot, subject))
		return 1;
	if (!w->fn(w->arg, subject)) {
		w->stopped = 1;
		return 0;
	}
	return 1;
}

static int delta_each(void *ctx, fzn_persist_slot_t slot,
                      int (*fn)(void *arg, const uint8_t subject[FZN_PUBKEY_LEN]), void *arg)
{
	fzn_persist_delta_t *d = ctx;
	struct walk w;
	const row_t *r;

	w.d = d;
	w.slot = slot;
	w.fn = fn;
	w.arg = arg;
	w.stopped = 0;
	if (!fzn_persist_each(d->base, slot, walked, &w))
		return 0;
	if (w.stopped)
		return 1;
	for (r = d->oldest; r; r = r->newer)
		if (r->slot == slot && !r->gone && r->has_subject && !fn(arg, r->subject))
			break;
	return 1;
}

void fzn_persist_delta_init(fzn_persist_delta_t *d, const fzn_persist_ops_t *base, size_t budget,
                            fzn_persist_ops_t *ops)
{
	memset(d, 0, sizeof(*d));
	d->base = base;
	d->budget = budget ? budget : FZN_PERSIST_DELTA_BUDGET_DEFAULT;
	memset(ops, 0, sizeof(*ops));
	ops->load = delta_load;
	ops->save = delta_save;
	ops->list = delta_list;
	ops->remove = delta_remove;
	ops->ctx = d;
	ops->each = delta_each;
}

size_t fzn_persist_delta_flush(fzn_persist_delta_t *d)
{
	size_t done = 0;

	while (d->oldest) {
		row_t *r = d->oldest;
		const uint8_t *subject = r->has_subject ? r->subject : NULL;
		int wrote;

		wrote = r->gone ? !d->base->remove || d->base->remove(d->base->ctx, r->slot, subject)
		                : d->base->save(d->base->ctx, r->slot, subject, r->bytes, r->len);
		if (!wrote) {
			d->stuck = 1;
			return done;
		}
		drop_row(d, r);
		d->flushed++;
		done++;
	}
	d->stuck = 0;
	return done;
}

void fzn_persist_delta_hold(fzn_persist_delta_t *d)
{
	d->stuck = 1;
}

void fzn_persist_delta_status(const fzn_persist_delta_t *d, fzn_persist_delta_status_t *out)
{
	out->stuck = d->stuck;
	out->rows = d->rows;
	out->bytes = d->bytes;
	out->budget = d->budget;
	out->dropped = d->dropped;
	out->refused = d->refused;
	out->flushed = d->flushed;
}

void fzn_persist_delta_free(fzn_persist_delta_t *d)
{
	while (d->oldest)
		drop_row(d, d->oldest);
}
