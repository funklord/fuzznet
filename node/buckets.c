/* See buckets.h. Rows are `node/buckets.situ`'s. */

#include "buckets.h"

#include "../wire/bytes.h"

#include <stdlib.h>
#include <string.h>

#define VERSION 1u
/* fzn_buckets_bucket */
#define B_KIND 1u
#define B_SUBJECT 2u
#define B_MONTH (B_SUBJECT + FZN_PUBKEY_LEN)
#define B_COUNT (B_MONTH + 4u)
#define B_SUM (B_COUNT + 8u)
#define B_LEN (B_SUM + FZN_BUCKETS_ID_LEN)
/* fzn_buckets_gone */
#define G_LEN (B_MONTH + 4u)
/* fzn_buckets_item */
#define I_INDEXED (B_MONTH + 4u)
#define I_LEN (I_INDEXED + 1u)
#define I_ITEM (I_LEN + 2u)
#define CHUNK_BYTES (FZN_BUCKETS_CHUNK * FZN_BUCKETS_ID_LEN)

const char *fzn_buckets_err_str(fzn_buckets_err_t err)
{
	switch (err) {
	case FZN_BUCKETS_OK:
		return "ok";
	case FZN_BUCKETS_MALFORMED:
		return "malformed";
	case FZN_BUCKETS_BACKEND:
		return "the store would not list, load or keep";
	case FZN_BUCKETS_FULL:
		return "more buckets of the kind than are listed";
	case FZN_BUCKETS_GONE:
		return "the bucket was let go here";
	case FZN_BUCKETS_ABSENT:
		return "no such item here";
	}
	return "unknown";
}

static int ready(const fzn_buckets_t *b, fzn_buckets_kind_t kind)
{
	return b && b->store && b->store->load && b->store->save && b->hash && b->hash->hash
	       && (unsigned)kind < FZN_BUCKETS_KINDS;
}

int fzn_buckets_id(const fzn_hash_ops_t *hash, const uint8_t *item, size_t len,
                   uint8_t id[FZN_BUCKETS_ID_LEN])
{
	return hash && hash->hash && item && len && id
	       && hash->hash(hash->ctx, id, FZN_BUCKETS_ID_LEN, item, len);
}

/* A row's place: a domain, the kind, then `key` (a subject or an id), and
 * the month and a number where the row has them. */
static int row_of(const fzn_buckets_t *b, const char *domain, fzn_buckets_kind_t kind,
                  const uint8_t key[32], int with_month, uint32_t month, int with_n, uint32_t n,
                  uint8_t row[FZN_PUBKEY_LEN])
{
	uint8_t in[32u + 1u + 32u + 4u + 4u];
	size_t at = strlen(domain);

	if (at > 32u)
		return 0;
	memcpy(in, domain, at);
	in[at++] = (uint8_t)kind;
	memcpy(in + at, key, 32u);
	at += 32u;
	if (with_month) {
		fzn_put_be32(in + at, month);
		at += 4u;
	}
	if (with_n) {
		fzn_put_be32(in + at, n);
		at += 4u;
	}
	return b->hash->hash(b->hash->ctx, row, FZN_PUBKEY_LEN, in, at);
}

static void put_head(uint8_t *at, fzn_buckets_kind_t kind, const uint8_t subject[FZN_PUBKEY_LEN],
                     uint32_t month)
{
	at[0] = VERSION;
	at[B_KIND] = (uint8_t)kind;
	memcpy(at + B_SUBJECT, subject, FZN_PUBKEY_LEN);
	fzn_put_be32(at + B_MONTH, month);
}

/* WHAT A ROW SAYS IT IS: this version, this kind, and -- where the caller
 * names them -- this subject and month. */
static int head_is(const uint8_t *row, size_t len, size_t min, fzn_buckets_kind_t kind,
                   const uint8_t *subject, int with_month, uint32_t month)
{
	return len >= min && row[0] == VERSION && row[B_KIND] == (uint8_t)kind
	       && (!subject || memcmp(row + B_SUBJECT, subject, FZN_PUBKEY_LEN) == 0)
	       && (!with_month || fzn_get_be32(row + B_MONTH) == month);
}

/* The bucket's row, read: 1 held, 0 not held, -1 the store failed or the
 * row is not this bucket's. */
static int bucket_load(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                       const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month,
                       uint8_t bytes[B_LEN])
{
	uint8_t row[FZN_PUBKEY_LEN];
	size_t len = 0;

	if (!row_of(b, "fuzznet.bucket", kind, subject, 1, month, 0, 0u, row))
		return -1;
	if (!b->store->load(b->store->ctx, FZN_PERSIST_BUCKET, row, bytes, B_LEN, &len))
		return 0;
	return len == B_LEN && head_is(bytes, len, B_LEN, kind, subject, 1, month) ? 1 : -1;
}

static int digest_of(const fzn_buckets_t *b, const uint8_t bytes[B_LEN],
                     uint8_t digest[FZN_BUCKETS_ID_LEN])
{
	static const char DOMAIN[] = "fuzznet.bucket.digest";
	uint8_t in[sizeof(DOMAIN) - 1u + B_LEN - 1u];

	memcpy(in, DOMAIN, sizeof(DOMAIN) - 1u);
	memcpy(in + sizeof(DOMAIN) - 1u, bytes + 1u, B_LEN - 1u);
	return b->hash->hash(b->hash->ctx, digest, FZN_BUCKETS_ID_LEN, in, sizeof(in));
}

static int fill(const fzn_buckets_t *b, const uint8_t bytes[B_LEN], fzn_bucket_t *out)
{
	memcpy(out->subject, bytes + B_SUBJECT, FZN_PUBKEY_LEN);
	out->month = fzn_get_be32(bytes + B_MONTH);
	out->count = fzn_get_be64(bytes + B_COUNT);
	return digest_of(b, bytes, out->digest);
}

int fzn_buckets_gone(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                     const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month)
{
	uint8_t row[FZN_PUBKEY_LEN], bytes[G_LEN];
	size_t len = 0;

	return ready(b, kind) && subject
	       && row_of(b, "fuzznet.bucket.gone", kind, subject, 1, month, 0, 0u, row)
	       && b->store->load(b->store->ctx, FZN_PERSIST_BUCKET_IDS, row, bytes, sizeof(bytes),
	                         &len)
	       && len == G_LEN && head_is(bytes, len, G_LEN, kind, subject, 1, month);
}

/* The item row of `id`, read into `out` (I_ITEM + FZN_BUCKETS_ITEM_MAX):
 * its length, or 0 when absent or not this kind's. */
static size_t item_load(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                        const uint8_t id[FZN_BUCKETS_ID_LEN], uint8_t *out)
{
	uint8_t row[FZN_PUBKEY_LEN];
	size_t len = 0, n;

	if (!row_of(b, "fuzznet.bucket.item", kind, id, 0, 0u, 0, 0u, row)
	    || !b->store->load(b->store->ctx, FZN_PERSIST_BUCKET_ITEM, row, out,
	                       I_ITEM + FZN_BUCKETS_ITEM_MAX, &len)
	    || !head_is(out, len, I_ITEM + 1u, kind, NULL, 0, 0u) || out[I_INDEXED] > 1u)
		return 0;
	n = ((size_t)out[I_LEN] << 8) | out[I_LEN + 1u];
	return n >= 1u && n <= FZN_BUCKETS_ITEM_MAX && len == I_ITEM + n ? len : 0;
}

static int item_save(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                     const uint8_t id[FZN_BUCKETS_ID_LEN], const uint8_t *bytes, size_t len)
{
	uint8_t row[FZN_PUBKEY_LEN];

	return row_of(b, "fuzznet.bucket.item", kind, id, 0, 0u, 0, 0u, row)
	       && b->store->save(b->store->ctx, FZN_PERSIST_BUCKET_ITEM, row, bytes, len);
}

/* Chunk `c` of a bucket's ids, into `out` (CHUNK_BYTES): its length in
 * bytes, or -1. */
static long chunk_load(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                       const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month, uint32_t c,
                       uint8_t out[CHUNK_BYTES])
{
	uint8_t row[FZN_PUBKEY_LEN];
	size_t len = 0;

	if (!row_of(b, "fuzznet.bucket.ids", kind, subject, 1, month, 1, c, row)
	    || !b->store->load(b->store->ctx, FZN_PERSIST_BUCKET_IDS, row, out, CHUNK_BYTES, &len)
	    || len % FZN_BUCKETS_ID_LEN != 0u)
		return -1;
	return (long)len;
}

/* sum += id, modulo 2^256. */
static void sum_add(uint8_t sum[FZN_BUCKETS_ID_LEN], const uint8_t id[FZN_BUCKETS_ID_LEN])
{
	unsigned carry = 0;
	size_t i;

	for (i = FZN_BUCKETS_ID_LEN; i > 0u; i--) {
		unsigned v = (unsigned)sum[i - 1u] + id[i - 1u] + carry;

		sum[i - 1u] = (uint8_t)v;
		carry = v >> 8;
	}
}

fzn_buckets_err_t fzn_buckets_add(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                  const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month,
                                  const uint8_t *item, size_t len, int *added)
{
	static uint8_t row_bytes[I_ITEM + FZN_BUCKETS_ITEM_MAX];
	uint8_t id[FZN_BUCKETS_ID_LEN], bucket[B_LEN], chunk[CHUNK_BYTES], row[FZN_PUBKEY_LEN];
	uint64_t count;
	size_t in_chunk;
	int held, indexed = 0;

	if (added)
		*added = 0;
	if (!ready(b, kind) || !subject || !item || len == 0u || len > FZN_BUCKETS_ITEM_MAX
	    || !fzn_buckets_id(b->hash, item, len, id))
		return FZN_BUCKETS_MALFORMED;
	if (fzn_buckets_gone(b, kind, subject, month))
		return FZN_BUCKETS_GONE;
	/* TAKEN AND INDEXED ALREADY: nothing to do. Saved but not indexed --
	 * a crash between the two -- is indexed now. */
	if (item_load(b, kind, id, row_bytes) && row_bytes[I_INDEXED] == 1u)
		return FZN_BUCKETS_OK;
	held = bucket_load(b, kind, subject, month, bucket);
	if (held < 0)
		return FZN_BUCKETS_BACKEND;
	if (!held) {
		memset(bucket, 0, sizeof(bucket));
		put_head(bucket, kind, subject, month);
	}
	count = fzn_get_be64(bucket + B_COUNT);
	if (count / FZN_BUCKETS_CHUNK >= UINT32_MAX)
		return FZN_BUCKETS_FULL;
	/* THE BYTES, THEN THE ID AND COUNT, THEN THE MARK. A crash before the
	 * count leaves an item no listing names, taken again next time -- its
	 * id written over, since a chunk is read only as far as the count. One
	 * after the count, before the mark, leaves its id the last counted,
	 * which this finds rather than counting it twice. */
	put_head(row_bytes, kind, subject, month);
	row_bytes[I_INDEXED] = 0u;
	row_bytes[I_LEN] = (uint8_t)(len >> 8);
	row_bytes[I_LEN + 1u] = (uint8_t)len;
	memcpy(row_bytes + I_ITEM, item, len);
	if (!item_save(b, kind, id, row_bytes, I_ITEM + len))
		return FZN_BUCKETS_BACKEND;
	if (count > 0u) {
		size_t last = (size_t)((count - 1u) % FZN_BUCKETS_CHUNK);
		long n = chunk_load(b, kind, subject, month, (uint32_t)((count - 1u) / FZN_BUCKETS_CHUNK),
		                    chunk);

		if (n < (long)((last + 1u) * FZN_BUCKETS_ID_LEN))
			return FZN_BUCKETS_BACKEND;
		indexed = memcmp(chunk + last * FZN_BUCKETS_ID_LEN, id, FZN_BUCKETS_ID_LEN) == 0;
	}
	if (!indexed) {
		in_chunk = (size_t)(count % FZN_BUCKETS_CHUNK);
		/* The chunk being filled is the one just read, unless the last id
		 * closed it. */
		if (in_chunk == 0u)
			memset(chunk, 0, sizeof(chunk));
		memcpy(chunk + in_chunk * FZN_BUCKETS_ID_LEN, id, FZN_BUCKETS_ID_LEN);
		if (!row_of(b, "fuzznet.bucket.ids", kind, subject, 1, month, 1,
		            (uint32_t)(count / FZN_BUCKETS_CHUNK), row)
		    || !b->store->save(b->store->ctx, FZN_PERSIST_BUCKET_IDS, row, chunk,
		                       (in_chunk + 1u) * FZN_BUCKETS_ID_LEN))
			return FZN_BUCKETS_BACKEND;
		fzn_put_be64(bucket + B_COUNT, count + 1u);
		sum_add(bucket + B_SUM, id);
		if (!row_of(b, "fuzznet.bucket", kind, subject, 1, month, 0, 0u, row)
		    || !b->store->save(b->store->ctx, FZN_PERSIST_BUCKET, row, bucket, B_LEN))
			return FZN_BUCKETS_BACKEND;
	}
	row_bytes[I_INDEXED] = 1u;
	if (!item_save(b, kind, id, row_bytes, I_ITEM + len))
		return FZN_BUCKETS_BACKEND;
	if (added)
		*added = 1;
	return FZN_BUCKETS_OK;
}

int fzn_buckets_has(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                    const uint8_t id[FZN_BUCKETS_ID_LEN])
{
	static uint8_t bytes[I_ITEM + FZN_BUCKETS_ITEM_MAX];

	return ready(b, kind) && id && item_load(b, kind, id, bytes) && bytes[I_INDEXED] == 1u;
}

fzn_buckets_err_t fzn_buckets_item(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                   const uint8_t id[FZN_BUCKETS_ID_LEN], uint8_t *out,
                                   size_t cap, size_t *len, uint8_t subject[FZN_PUBKEY_LEN],
                                   uint32_t *month)
{
	static uint8_t bytes[I_ITEM + FZN_BUCKETS_ITEM_MAX];
	size_t n;

	if (!ready(b, kind) || !id || !out || !len)
		return FZN_BUCKETS_MALFORMED;
	*len = 0;
	n = item_load(b, kind, id, bytes);
	if (!n || bytes[I_INDEXED] != 1u)
		return FZN_BUCKETS_ABSENT;
	n -= I_ITEM;
	if (n > cap)
		return FZN_BUCKETS_MALFORMED;
	memcpy(out, bytes + I_ITEM, n);
	*len = n;
	if (subject)
		memcpy(subject, bytes + B_SUBJECT, FZN_PUBKEY_LEN);
	if (month)
		*month = fzn_get_be32(bytes + B_MONTH);
	return FZN_BUCKETS_OK;
}

fzn_buckets_err_t fzn_buckets_bucket(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                     const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month,
                                     fzn_bucket_t *out)
{
	uint8_t bytes[B_LEN];
	int held;

	if (!ready(b, kind) || !subject || !out)
		return FZN_BUCKETS_MALFORMED;
	held = bucket_load(b, kind, subject, month, bytes);
	if (held < 0)
		return FZN_BUCKETS_BACKEND;
	if (!held) {
		memset(bytes, 0, sizeof(bytes));
		put_head(bytes, kind, subject, month);
	}
	return fill(b, bytes, out) ? FZN_BUCKETS_OK : FZN_BUCKETS_BACKEND;
}

static int by_place(const void *a, const void *c)
{
	const fzn_bucket_t *x = (const fzn_bucket_t *)a, *y = (const fzn_bucket_t *)c;
	int d = memcmp(x->subject, y->subject, FZN_PUBKEY_LEN);

	if (d)
		return d;
	return x->month < y->month ? -1 : x->month > y->month;
}

fzn_buckets_err_t fzn_buckets_list(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                   fzn_bucket_t *out, size_t max, size_t *count)
{
	static uint8_t rows[FZN_BUCKETS_MAX * FZN_PUBKEY_LEN];
	size_t n = 0, i, held = 0;

	if (count)
		*count = 0;
	if (!ready(b, kind) || !b->store->list || !out || !count || max > FZN_BUCKETS_MAX)
		return FZN_BUCKETS_MALFORMED;
	/* A LIST THAT DOES NOT FIT FAILS, by the persist ops' own rule. */
	if (!b->store->list(b->store->ctx, FZN_PERSIST_BUCKET, rows, FZN_BUCKETS_MAX, &n))
		return FZN_BUCKETS_FULL;
	for (i = 0; i < n; i++) {
		uint8_t bytes[B_LEN];
		size_t len = 0;

		if (!b->store->load(b->store->ctx, FZN_PERSIST_BUCKET, rows + i * FZN_PUBKEY_LEN, bytes,
		                    sizeof(bytes), &len))
			return FZN_BUCKETS_BACKEND;
		/* ANOTHER KIND'S, OR NOT A BUCKET: passed over. A gone bucket's row
		 * left by a crash part way through its drop is not offered. */
		if (len != B_LEN || !head_is(bytes, len, B_LEN, kind, NULL, 0, 0u)
		    || fzn_buckets_gone(b, kind, bytes + B_SUBJECT, fzn_get_be32(bytes + B_MONTH)))
			continue;
		if (held >= max)
			return FZN_BUCKETS_FULL;
		if (!fill(b, bytes, &out[held++]))
			return FZN_BUCKETS_BACKEND;
	}
	qsort(out, held, sizeof(*out), by_place);
	*count = held;
	return FZN_BUCKETS_OK;
}

fzn_buckets_err_t fzn_buckets_ids(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                  const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month,
                                  uint64_t from, uint8_t (*ids)[FZN_BUCKETS_ID_LEN], size_t max,
                                  size_t *count, uint64_t *total)
{
	uint8_t bucket[B_LEN], chunk[CHUNK_BYTES];
	uint64_t n, at;
	size_t got = 0;
	int held;

	if (count)
		*count = 0;
	if (total)
		*total = 0;
	if (!ready(b, kind) || !subject || !ids || !count || !total)
		return FZN_BUCKETS_MALFORMED;
	held = bucket_load(b, kind, subject, month, bucket);
	if (held < 0)
		return FZN_BUCKETS_BACKEND;
	if (!held || fzn_buckets_gone(b, kind, subject, month))
		return FZN_BUCKETS_OK;
	n = fzn_get_be64(bucket + B_COUNT);
	*total = n;
	for (at = from; at < n && got < max;) {
		uint32_t c = (uint32_t)(at / FZN_BUCKETS_CHUNK);
		long len = chunk_load(b, kind, subject, month, c, chunk);
		size_t k = (size_t)(at % FZN_BUCKETS_CHUNK);

		if (len < 0)
			return FZN_BUCKETS_BACKEND;
		for (; k * FZN_BUCKETS_ID_LEN < (size_t)len && at < n && got < max; k++, at++)
			memcpy(ids[got++], chunk + k * FZN_BUCKETS_ID_LEN, FZN_BUCKETS_ID_LEN);
		if (k * FZN_BUCKETS_ID_LEN >= (size_t)len && k < FZN_BUCKETS_CHUNK && at < n)
			return FZN_BUCKETS_BACKEND; /* a chunk shorter than the count says */
	}
	*count = got;
	return FZN_BUCKETS_OK;
}

fzn_buckets_err_t fzn_buckets_drop(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                   const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month)
{
	uint8_t row[FZN_PUBKEY_LEN], gone[G_LEN], bucket[B_LEN], chunk[CHUNK_BYTES];
	uint64_t n, c;
	int held;

	if (!ready(b, kind) || !subject || !b->store->remove)
		return FZN_BUCKETS_MALFORMED;
	put_head(gone, kind, subject, month);
	if (!row_of(b, "fuzznet.bucket.gone", kind, subject, 1, month, 0, 0u, row)
	    || !b->store->save(b->store->ctx, FZN_PERSIST_BUCKET_IDS, row, gone, sizeof(gone)))
		return FZN_BUCKETS_BACKEND;
	held = bucket_load(b, kind, subject, month, bucket);
	if (held < 0)
		return FZN_BUCKETS_BACKEND;
	if (!held)
		return FZN_BUCKETS_OK;
	n = fzn_get_be64(bucket + B_COUNT);
	for (c = 0; c * FZN_BUCKETS_CHUNK < n; c++) {
		long len = chunk_load(b, kind, subject, month, (uint32_t)c, chunk);
		size_t k;

		if (len < 0)
			return FZN_BUCKETS_BACKEND;
		for (k = 0; k * FZN_BUCKETS_ID_LEN < (size_t)len; k++)
			if (!row_of(b, "fuzznet.bucket.item", kind, chunk + k * FZN_BUCKETS_ID_LEN, 0, 0u,
			            0, 0u, row)
			    || !b->store->remove(b->store->ctx, FZN_PERSIST_BUCKET_ITEM, row))
				return FZN_BUCKETS_BACKEND;
		if (!row_of(b, "fuzznet.bucket.ids", kind, subject, 1, month, 1, (uint32_t)c, row)
		    || !b->store->remove(b->store->ctx, FZN_PERSIST_BUCKET_IDS, row))
			return FZN_BUCKETS_BACKEND;
	}
	return row_of(b, "fuzznet.bucket", kind, subject, 1, month, 0, 0u, row)
	               && b->store->remove(b->store->ctx, FZN_PERSIST_BUCKET, row)
	               ? FZN_BUCKETS_OK
	               : FZN_BUCKETS_BACKEND;
}
