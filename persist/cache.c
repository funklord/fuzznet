/* See cache.h. */

#include "cache.h"

#include "../fault/fault.h"

#include <stdlib.h>
#include <string.h>

typedef struct fzn_persist_cache_row {
	struct fzn_persist_cache_row *chain;
	uint8_t subject[FZN_PUBKEY_LEN];
	size_t len;
	uint8_t bytes[];
} row_t;

/* A FILL THAT COULD NOT FINISH is not tried on every walk: it costs what it saves. */
#define REST_AFTER_A_FAILED_FILL 1024u

static void *take(const fzn_persist_cache_t *c, size_t len)
{
	if (!FZN_FAULT_RAM())
		return NULL;
	return c->alloc ? c->alloc(len) : malloc(len);
}

static void give(const fzn_persist_cache_t *c, void *at)
{
	if (c->release)
		c->release(at);
	else
		free(at);
}

/* A subject is a key or a hash, so its own bytes spread it. */
static size_t bucket_of(const uint8_t *subject)
{
	return ((size_t)subject[0] | ((size_t)subject[1] << 8)) % FZN_PERSIST_CACHE_BUCKETS;
}

static row_t *find(const fzn_persist_cache_t *c, const uint8_t *subject)
{
	row_t *r;

	if (!c->buckets)
		return NULL;
	for (r = c->buckets[bucket_of(subject)]; r; r = r->chain)
		if (memcmp(r->subject, subject, FZN_PUBKEY_LEN) == 0)
			return r;
	return NULL;
}

static void forget(fzn_persist_cache_t *c, const uint8_t *subject)
{
	row_t **at;

	if (!c->buckets)
		return;
	for (at = &c->buckets[bucket_of(subject)]; *at; at = &(*at)->chain)
		if (memcmp((*at)->subject, subject, FZN_PUBKEY_LEN) == 0) {
			row_t *r = *at;

			*at = r->chain;
			c->bytes -= r->len;
			give(c, r);
			c->rows--;
			return;
		}
}

/* `bytes` as the row of `subject`. 0, with the row forgotten and the cache no longer
 * whole, when there is no room or it will not fit. */
static int keep(fzn_persist_cache_t *c, const uint8_t *subject, const uint8_t *bytes, size_t len)
{
	row_t *r;
	size_t b;

	if (!c->buckets)
		return 0;
	/* A NEW ROW EACH TIME, as a row's length is its own. */
	forget(c, subject);
	if (len > FZN_PERSIST_CACHE_ROW_MAX || c->bytes + len > c->budget
	    || !(r = take(c, sizeof(*r) + len))) {
		c->whole = 0;
		return 0;
	}
	b = bucket_of(subject);
	memcpy(r->subject, subject, FZN_PUBKEY_LEN);
	if (len)
		memcpy(r->bytes, bytes, len);
	r->len = len;
	r->chain = c->buckets[b];
	c->buckets[b] = r;
	c->rows++;
	c->bytes += len;
	return 1;
}

static int cache_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                      size_t cap, size_t *len)
{
	fzn_persist_cache_t *c = ctx;
	const row_t *r;

	if (slot != c->slot || !subject)
		return c->base->load(c->base->ctx, slot, subject, out, cap, len);
	r = find(c, subject);
	if (r) {
		if (r->len > cap)
			return 0;
		if (r->len)
			memcpy(out, r->bytes, r->len);
		*len = r->len;
		return 1;
	}
	if (c->whole)
		return 0;
	c->misses++;
	return c->base->load(c->base->ctx, slot, subject, out, cap, len);
}

static int cache_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                      const uint8_t *bytes, size_t len)
{
	fzn_persist_cache_t *c = ctx;

	if (!c->base->save(c->base->ctx, slot, subject, bytes, len)) {
		/* WHAT THE STORE HOLDS NOW IS ITS OWN TO SAY. */
		if (slot == c->slot && subject) {
			forget(c, subject);
			c->whole = 0;
		}
		return 0;
	}
	if (slot == c->slot) {
		c->changes++;
		if (subject && c->buckets)
			(void)keep(c, subject, bytes, len);
	}
	return 1;
}

static int cache_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	fzn_persist_cache_t *c = ctx;

	if (!c->base->remove || !c->base->remove(c->base->ctx, slot, subject)) {
		if (slot == c->slot && subject) {
			forget(c, subject);
			c->whole = 0;
		}
		return 0;
	}
	if (slot == c->slot) {
		c->changes++;
		if (subject)
			forget(c, subject);
	}
	return 1;
}


/* A ROW OF THE STORE'S, read in on the first walk. One that will not read is not
 * walked past here: its caller is told of it, and the cache is not whole. */
struct filling {
	fzn_persist_cache_t *c;
	int ok;
};

static int filled(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	struct filling *f = arg;
	static uint8_t bytes[FZN_PERSIST_CACHE_ROW_MAX];
	size_t len = 0;

	if (!f->c->base->load(f->c->base->ctx, f->c->slot, subject, bytes, sizeof(bytes), &len)
	    || !keep(f->c, subject, bytes, len))
		f->ok = 0;
	return 1;
}

static int fill(fzn_persist_cache_t *c)
{
	struct filling f;

	if (!c->buckets) {
		size_t size = FZN_PERSIST_CACHE_BUCKETS * sizeof(*c->buckets);

		c->buckets = take(c, size);
		if (!c->buckets)
			return 0;
		memset(c->buckets, 0, size);
	}
	f.c = c;
	f.ok = 1;
	if (!fzn_persist_each(c->base, c->slot, filled, &f))
		f.ok = 0;
	c->whole = f.ok;
	if (!f.ok)
		c->rest = REST_AFTER_A_FAILED_FILL;
	return f.ok;
}

/* The slot held whole, by a fill if it is time for one. */
static int held_whole(fzn_persist_cache_t *c)
{
	if (c->whole)
		return 1;
	if (c->rest) {
		c->rest--;
		return 0;
	}
	return fill(c);
}

static int cache_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	fzn_persist_cache_t *c = ctx;
	size_t b, n = 0;

	if (slot != c->slot || !held_whole(c))
		return c->base->list && c->base->list(c->base->ctx, slot, out, max, count);
	/* TRUNCATION IS A FAILURE, by the ops' own rule. */
	if (c->rows > max)
		return 0;
	for (b = 0; b < FZN_PERSIST_CACHE_BUCKETS; b++) {
		const row_t *r;

		for (r = c->buckets[b]; r; r = r->chain)
			memcpy(out + (n++) * FZN_PUBKEY_LEN, r->subject, FZN_PUBKEY_LEN);
	}
	*count = n;
	return 1;
}

static int cache_each(void *ctx, fzn_persist_slot_t slot,
                      int (*fn)(void *arg, const uint8_t subject[FZN_PUBKEY_LEN]), void *arg)
{
	fzn_persist_cache_t *c = ctx;
	size_t b;

	if (slot != c->slot || !held_whole(c))
		return fzn_persist_each(c->base, slot, fn, arg);
	c->walks++;
	for (b = 0; b < FZN_PERSIST_CACHE_BUCKETS; b++) {
		const row_t *r;

		for (r = c->buckets[b]; r; r = r->chain)
			if (!fn(arg, r->subject))
				return 1;
	}
	return 1;
}

void fzn_persist_cache_drop(fzn_persist_cache_t *c)
{
	size_t b;

	if (!c || !c->buckets)
		return;
	for (b = 0; b < FZN_PERSIST_CACHE_BUCKETS; b++)
		while (c->buckets[b]) {
			row_t *r = c->buckets[b];

			c->buckets[b] = r->chain;
			give(c, r);
		}
	give(c, c->buckets);
	c->buckets = NULL;
	c->rows = 0;
	c->bytes = 0;
	c->whole = 0;
	c->rest = 0;
}

/* WHERE A SLOT STANDS, sec 971: the store beneath's, as every write goes
 * through to it. */
static uint64_t cache_stamp(void *ctx, fzn_persist_slot_t slot)
{
	const fzn_persist_cache_t *c = ctx;

	return c && c->base && c->base->stamp ? c->base->stamp(c->base->ctx, slot) : 0;
}

void fzn_persist_cache_init(fzn_persist_cache_t *c, const fzn_persist_ops_t *base,
                            fzn_persist_slot_t slot, fzn_persist_ops_t *ops)
{
	memset(c, 0, sizeof(*c));
	c->base = base;
	c->slot = slot;
	c->budget = FZN_PERSIST_CACHE_BUDGET_DEFAULT;
	memset(ops, 0, sizeof(*ops));
	ops->load = cache_load;
	ops->save = cache_save;
	ops->list = cache_list;
	ops->remove = cache_remove;
	ops->ctx = c;
	ops->each = cache_each;
	ops->stamp = cache_stamp;
}
