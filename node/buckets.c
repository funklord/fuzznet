/* See buckets.h. Rows are `node/buckets_row.situ`'s, written by the
 * builders situ generates from it and read through its views and
 * `validate` (sec 1382); the offsets below are only for the sizes of the
 * buffers that hold them. */

#include "buckets.h"
#include "../wire/generated/buckets_row.h"
#include "../wire/generated/buckets_row_build.h"

#include "../wire/bytes.h"

#include <stdlib.h>
#include <stdint.h>
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
/* fzn_buckets_ref, sec 570: the same head, then the size and the ref. */
#define REF_VERSION 2u
/* fzn_buckets_let_go, sec 572: the head alone. */
#define LET_GO_VERSION 3u
#define L_LEN (I_INDEXED + 1u)
#define R_SIZE (I_INDEXED + 1u)
#define R_LEN (R_SIZE + 8u)
#define R_REF (R_LEN + 2u)
#define ROW_MAX (I_ITEM + FZN_BUCKETS_ITEM_MAX)
/* fzn_buckets_byref, sec 571. */
#define BR_ID 2u
#define BR_SIZE (BR_ID + FZN_BUCKETS_ID_LEN)
#define BR_LEN (BR_SIZE + 8u)
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
	case FZN_BUCKETS_LARGE:
		return "the item is kept by its kind, not in a row";
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

/* A BUCKET'S ROW, its count nought and its sum zero, built. */
static void bucket_new(uint8_t bytes[B_LEN], fzn_buckets_kind_t kind,
                       const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month)
{
	static const uint8_t zero[FZN_BUCKETS_ID_LEN];
	uint32_t wrote = 0;

	memset(bytes, 0, B_LEN);
	(void)fzn_buckets_row_fzn_buckets_bucket_build(bytes, B_LEN, VERSION, (fzn_buckets_row_fzn_buckets_kind_t)kind,
	                                               subject, month, 0u, zero, &wrote);
}

/* A BUCKET'S ROW, VIEWED, for its count and sum. */
static situ_view_t bucket_view(uint8_t bytes[B_LEN], situ_msg_t *m)
{
	situ_view_t v;

	situ_msg_init(m, bytes, B_LEN);
	(void)fzn_buckets_row_fzn_buckets_bucket_view(m, 0u, &v);
	return v;
}

static uint64_t bucket_count(uint8_t bytes[B_LEN])
{
	situ_msg_t m;

	return fzn_buckets_row_fzn_buckets_bucket_count_get(bucket_view(bytes, &m));
}

/* WHAT A BUCKET'S OR A GONE ROW SAYS IT IS, read as the schema says: the
 * row whole, this kind, and -- where the caller names them -- this subject
 * and month. */
static int bucket_is(uint8_t *row, size_t len, fzn_buckets_kind_t kind, const uint8_t *subject,
                     int with_month, uint32_t month)
{
	situ_msg_t m;
	situ_view_t v;

	if (len != B_LEN)
		return 0;
	situ_msg_init(&m, row, (uint32_t)len);
	return fzn_buckets_row_fzn_buckets_bucket_view(&m, 0u, &v) == SITU_OK
	       && fzn_buckets_row_fzn_buckets_bucket_validate(v) == SITU_OK
	       && fzn_buckets_row_fzn_buckets_bucket_kind_get(v) == (fzn_buckets_row_fzn_buckets_kind_t)kind
	       && (!subject || memcmp(fzn_buckets_row_fzn_buckets_bucket_subject_ptr(v), subject, FZN_PUBKEY_LEN) == 0)
	       && (!with_month || fzn_buckets_row_fzn_buckets_bucket_month_get(v) == month);
}

static int gone_is(uint8_t *row, size_t len, fzn_buckets_kind_t kind, const uint8_t subject[FZN_PUBKEY_LEN],
                   uint32_t month)
{
	situ_msg_t m;
	situ_view_t v;

	if (len != G_LEN)
		return 0;
	situ_msg_init(&m, row, (uint32_t)len);
	return fzn_buckets_row_fzn_buckets_gone_view(&m, 0u, &v) == SITU_OK
	       && fzn_buckets_row_fzn_buckets_gone_validate(v) == SITU_OK
	       && fzn_buckets_row_fzn_buckets_gone_kind_get(v) == (fzn_buckets_row_fzn_buckets_kind_t)kind
	       && memcmp(fzn_buckets_row_fzn_buckets_gone_subject_ptr(v), subject, FZN_PUBKEY_LEN) == 0
	       && fzn_buckets_row_fzn_buckets_gone_month_get(v) == month;
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
	return bucket_is(bytes, len, kind, subject, 1, month) ? 1 : -1;
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

static int fill(const fzn_buckets_t *b, uint8_t bytes[B_LEN], fzn_bucket_t *out)
{
	situ_msg_t m;
	situ_view_t v = bucket_view(bytes, &m);

	memcpy(out->subject, fzn_buckets_row_fzn_buckets_bucket_subject_ptr(v), FZN_PUBKEY_LEN);
	out->month = fzn_buckets_row_fzn_buckets_bucket_month_get(v);
	out->count = fzn_buckets_row_fzn_buckets_bucket_count_get(v);
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
	       && gone_is(bytes, len, kind, subject, month);
}

/* An item's row, read: what it is (1 an item, 2 a ref, 3 let go), its
 * mark, head, and the item's bytes or the ref and size. Pointers into the
 * buffer it was read into. */
typedef struct row_read {
	int what;
	uint8_t indexed;
	const uint8_t *subject;
	uint32_t month;
	const uint8_t *data;
	size_t data_len;
	uint64_t size;
} row_read_t;

/* ONE ROW READ AS THE SCHEMA SAYS, sec 1382: its version names which of
 * the three it is, and that one's `required`, view and `validate` take it
 * -- every byte accounted for, the lengths and the mark in bounds; a ref of
 * size nought, which the schema does not refuse, the codec's. 0 for none
 * of them, or another kind's. */
static int row_read(uint8_t *bytes, size_t len, fzn_buckets_kind_t kind, row_read_t *r)
{
	situ_msg_t m;
	situ_view_t v;
	uint32_t need = 0;

	memset(r, 0, sizeof(*r));
	if (len < 1u || len > ROW_MAX)
		return 0;
	situ_msg_init(&m, bytes, (uint32_t)len);
	if (bytes[0] == VERSION) {
		if (fzn_buckets_row_fzn_buckets_item_required(bytes, (uint32_t)len, &need) != SITU_OK || need != len
		    || fzn_buckets_row_fzn_buckets_item_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
		    || fzn_buckets_row_fzn_buckets_item_validate(v) != SITU_OK
		    || fzn_buckets_row_fzn_buckets_item_kind_get(v) != (fzn_buckets_row_fzn_buckets_kind_t)kind)
			return 0;
		r->what = 1;
		r->indexed = fzn_buckets_row_fzn_buckets_item_indexed_get(v);
		r->subject = fzn_buckets_row_fzn_buckets_item_subject_ptr(v);
		r->month = fzn_buckets_row_fzn_buckets_item_month_get(v);
		r->data = fzn_buckets_row_fzn_buckets_item_item_ptr(v);
		r->data_len = fzn_buckets_row_fzn_buckets_item_len_get(v);
		return 1;
	}
	if (bytes[0] == REF_VERSION) {
		if (fzn_buckets_row_fzn_buckets_ref_required(bytes, (uint32_t)len, &need) != SITU_OK || need != len
		    || fzn_buckets_row_fzn_buckets_ref_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
		    || fzn_buckets_row_fzn_buckets_ref_validate(v) != SITU_OK
		    || fzn_buckets_row_fzn_buckets_ref_kind_get(v) != (fzn_buckets_row_fzn_buckets_kind_t)kind
		    || fzn_buckets_row_fzn_buckets_ref_size_get(v) < 1u)
			return 0;
		r->what = 2;
		r->indexed = fzn_buckets_row_fzn_buckets_ref_indexed_get(v);
		r->subject = fzn_buckets_row_fzn_buckets_ref_subject_ptr(v);
		r->month = fzn_buckets_row_fzn_buckets_ref_month_get(v);
		r->data = fzn_buckets_row_fzn_buckets_ref_ref_ptr(v);
		r->data_len = fzn_buckets_row_fzn_buckets_ref_len_get(v);
		r->size = fzn_buckets_row_fzn_buckets_ref_size_get(v);
		return 2;
	}
	if (bytes[0] == LET_GO_VERSION) {
		if (len != L_LEN || fzn_buckets_row_fzn_buckets_let_go_view(&m, 0u, &v) != SITU_OK
		    || fzn_buckets_row_fzn_buckets_let_go_validate(v) != SITU_OK
		    || fzn_buckets_row_fzn_buckets_let_go_kind_get(v) != (fzn_buckets_row_fzn_buckets_kind_t)kind)
			return 0;
		r->what = 3;
		r->indexed = fzn_buckets_row_fzn_buckets_let_go_indexed_get(v);
		r->subject = fzn_buckets_row_fzn_buckets_let_go_subject_ptr(v);
		r->month = fzn_buckets_row_fzn_buckets_let_go_month_get(v);
		return 3;
	}
	return 0;
}

/* THE MARK SET on a row of any of the three, by its own view. */
static void set_indexed(uint8_t *bytes, size_t len, uint8_t indexed)
{
	situ_msg_t m;
	situ_view_t v;

	situ_msg_init(&m, bytes, (uint32_t)len);
	if (bytes[0] == VERSION && fzn_buckets_row_fzn_buckets_item_view(&m, 0u, (uint32_t)len, &v) == SITU_OK)
		fzn_buckets_row_fzn_buckets_item_indexed_set(v, indexed);
	else if (bytes[0] == REF_VERSION && fzn_buckets_row_fzn_buckets_ref_view(&m, 0u, (uint32_t)len, &v) == SITU_OK)
		fzn_buckets_row_fzn_buckets_ref_indexed_set(v, indexed);
	else if (bytes[0] == LET_GO_VERSION && fzn_buckets_row_fzn_buckets_let_go_view(&m, 0u, &v) == SITU_OK)
		fzn_buckets_row_fzn_buckets_let_go_indexed_set(v, indexed);
}

/* THE ROW OF `id`, read into `out` (ROW_MAX) and parsed into `r`: 1 an
 * item held in it, 2 a ref to one its kind keeps (sec 570), 3 one let go
 * (sec 572), 0 none or not this kind's; its length into `*len`. */
static int row_load(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                    const uint8_t id[FZN_BUCKETS_ID_LEN], uint8_t *out, size_t *len, row_read_t *r)
{
	uint8_t row[FZN_PUBKEY_LEN];

	*len = 0;
	memset(r, 0, sizeof(*r));
	if (!row_of(b, "fuzznet.bucket.item", kind, id, 0, 0u, 0, 0u, row)
	    || !b->store->load(b->store->ctx, FZN_PERSIST_BUCKET_ITEM, row, out, ROW_MAX, len))
		return 0;
	return row_read(out, *len, kind, r);
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

/* TAKE `id` UNDER (kind, subject, month), its row -- an item or a ref,
 * its mark at I_INDEXED -- in `row_bytes`. */
static fzn_buckets_err_t take(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                              const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month,
                              const uint8_t id[FZN_BUCKETS_ID_LEN], uint8_t *row_bytes,
                              size_t row_len, int *added)
{
	static uint8_t held_row[ROW_MAX];
	uint8_t bucket[B_LEN], chunk[CHUNK_BYTES], row[FZN_PUBKEY_LEN];
	uint64_t count;
	size_t in_chunk, held_len = 0;
	int held, indexed = 0;
	row_read_t was;

	if (fzn_buckets_gone(b, kind, subject, month))
		return FZN_BUCKETS_GONE;
	/* TAKEN AND INDEXED ALREADY: nothing to do. Saved but not indexed --
	 * a crash between the two -- is indexed now. LET GO AND TAKEN AGAIN --
	 * its kind found the same bytes again, a file back where it was -- is
	 * restored where it stands, its id counted already (sec 572). Only a
	 * kind's own keeping comes here for such an id: a let-go id is held, so
	 * nothing fetches or is pushed it. */
	switch (row_load(b, kind, id, held_row, &held_len, &was)) {
	case 3:
		if (was.indexed != 1u)
			break;
		set_indexed(row_bytes, row_len, 1u);
		if (!item_save(b, kind, id, row_bytes, row_len))
			return FZN_BUCKETS_BACKEND;
		if (added)
			*added = 1;
		return FZN_BUCKETS_OK;
	case 1:
	case 2:
		if (was.indexed == 1u)
			return FZN_BUCKETS_OK;
		break;
	default:
		break;
	}
	held = bucket_load(b, kind, subject, month, bucket);
	if (held < 0)
		return FZN_BUCKETS_BACKEND;
	if (!held)
		bucket_new(bucket, kind, subject, month);
	count = bucket_count(bucket);
	if (count / FZN_BUCKETS_CHUNK >= UINT32_MAX)
		return FZN_BUCKETS_FULL;
	/* THE ROW, THEN THE ID AND COUNT, THEN THE MARK. A crash before the
	 * count leaves an item no listing names, taken again next time -- its
	 * id written over, since a chunk is read only as far as the count. One
	 * after the count, before the mark, leaves its id the last counted,
	 * which this finds rather than counting it twice. */
	set_indexed(row_bytes, row_len, 0u);
	if (!item_save(b, kind, id, row_bytes, row_len))
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
		{
			situ_msg_t m;
			situ_view_t v = bucket_view(bucket, &m);

			fzn_buckets_row_fzn_buckets_bucket_count_set(v, count + 1u);
			sum_add(fzn_buckets_row_fzn_buckets_bucket_sum_ptr(v), id);
		}
		if (!row_of(b, "fuzznet.bucket", kind, subject, 1, month, 0, 0u, row)
		    || !b->store->save(b->store->ctx, FZN_PERSIST_BUCKET, row, bucket, B_LEN))
			return FZN_BUCKETS_BACKEND;
	}
	set_indexed(row_bytes, row_len, 1u);
	if (!item_save(b, kind, id, row_bytes, row_len))
		return FZN_BUCKETS_BACKEND;
	if (added)
		*added = 1;
	return FZN_BUCKETS_OK;
}

fzn_buckets_err_t fzn_buckets_add(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                  const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month,
                                  const uint8_t *item, size_t len, int *added)
{
	static uint8_t row_bytes[ROW_MAX];
	uint8_t id[FZN_BUCKETS_ID_LEN];
	uint32_t wrote = 0;

	if (added)
		*added = 0;
	if (!ready(b, kind) || !subject || !item || len == 0u || len > FZN_BUCKETS_ITEM_MAX
	    || !fzn_buckets_id(b->hash, item, len, id)
	    || fzn_buckets_row_fzn_buckets_item_build(row_bytes, ROW_MAX, VERSION, (fzn_buckets_row_fzn_buckets_kind_t)kind,
	                                              subject, month, 0u, item, (uint32_t)len, &wrote)
	               != SITU_OK)
		return FZN_BUCKETS_MALFORMED;
	return take(b, kind, subject, month, id, row_bytes, wrote, added);
}

fzn_buckets_err_t fzn_buckets_add_ref(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                      const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month,
                                      const uint8_t id[FZN_BUCKETS_ID_LEN], uint64_t size,
                                      const uint8_t *ref, size_t ref_len, int *added)
{
	uint8_t row_bytes[R_REF + FZN_BUCKETS_REF_MAX];
	fzn_buckets_err_t err;
	uint32_t wrote = 0;

	if (added)
		*added = 0;
	if (!ready(b, kind) || !subject || !id || !ref || ref_len == 0u
	    || ref_len > FZN_BUCKETS_REF_MAX || size == 0u || size > FZN_BUCKETS_LARGE_MAX
	    || fzn_buckets_row_fzn_buckets_ref_build(row_bytes, (uint32_t)sizeof(row_bytes), REF_VERSION,
	                                             (fzn_buckets_row_fzn_buckets_kind_t)kind, subject, month, 0u, size,
	                                             ref, (uint32_t)ref_len, &wrote)
	               != SITU_OK)
		return FZN_BUCKETS_MALFORMED;
	err = take(b, kind, subject, month, id, row_bytes, wrote, added);
	if (err != FZN_BUCKETS_OK)
		return err;
	/* AND WHAT THE REF WAS TAKEN AS, so a scan knows the file. sec 571. */
	{
		uint8_t key[FZN_BUCKETS_ID_LEN], row[FZN_PUBKEY_LEN], br[BR_LEN];
		uint32_t br_len = 0;

		if (fzn_buckets_row_fzn_buckets_byref_build(br, BR_LEN, VERSION, (fzn_buckets_row_fzn_buckets_kind_t)kind, id,
		                                            size, &br_len)
		            != SITU_OK
		    || !b->hash->hash(b->hash->ctx, key, sizeof(key), ref, ref_len)
		    || !row_of(b, "fuzznet.bucket.byref", kind, key, 0, 0u, 0, 0u, row)
		    || !b->store->save(b->store->ctx, FZN_PERSIST_BUCKET_IDS, row, br, sizeof(br)))
			return FZN_BUCKETS_BACKEND;
	}
	return FZN_BUCKETS_OK;
}

fzn_buckets_err_t fzn_buckets_by_ref(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                     const uint8_t *ref, size_t ref_len,
                                     uint8_t id[FZN_BUCKETS_ID_LEN], uint64_t *size)
{
	uint8_t key[FZN_BUCKETS_ID_LEN], row[FZN_PUBKEY_LEN], br[BR_LEN];
	size_t len = 0;
	situ_msg_t m;
	situ_view_t v;

	if (!ready(b, kind) || !ref || ref_len == 0u || ref_len > FZN_BUCKETS_REF_MAX || !id
	    || !size)
		return FZN_BUCKETS_MALFORMED;
	if (!b->hash->hash(b->hash->ctx, key, sizeof(key), ref, ref_len)
	    || !row_of(b, "fuzznet.bucket.byref", kind, key, 0, 0u, 0, 0u, row))
		return FZN_BUCKETS_BACKEND;
	if (!b->store->load(b->store->ctx, FZN_PERSIST_BUCKET_IDS, row, br, sizeof(br), &len) || len != BR_LEN)
		return FZN_BUCKETS_ABSENT;
	/* READ AS THE SCHEMA SAYS, sec 1382. */
	situ_msg_init(&m, br, BR_LEN);
	if (fzn_buckets_row_fzn_buckets_byref_view(&m, 0u, &v) != SITU_OK
	    || fzn_buckets_row_fzn_buckets_byref_validate(v) != SITU_OK
	    || fzn_buckets_row_fzn_buckets_byref_kind_get(v) != (fzn_buckets_row_fzn_buckets_kind_t)kind)
		return FZN_BUCKETS_ABSENT;
	memcpy(id, fzn_buckets_row_fzn_buckets_byref_id_ptr(v), FZN_BUCKETS_ID_LEN);
	*size = fzn_buckets_row_fzn_buckets_byref_size_get(v);
	return FZN_BUCKETS_OK;
}

int fzn_buckets_has(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                    const uint8_t id[FZN_BUCKETS_ID_LEN])
{
	static uint8_t bytes[ROW_MAX];
	size_t len = 0;
	row_read_t r;

	return ready(b, kind) && id && row_load(b, kind, id, bytes, &len, &r) && r.indexed == 1u;
}

fzn_buckets_err_t fzn_buckets_item(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                   const uint8_t id[FZN_BUCKETS_ID_LEN], uint8_t *out,
                                   size_t cap, size_t *len, uint8_t subject[FZN_PUBKEY_LEN],
                                   uint32_t *month)
{
	static uint8_t bytes[ROW_MAX];
	size_t n = 0;
	row_read_t r;
	int what;

	if (!ready(b, kind) || !id || !out || !len)
		return FZN_BUCKETS_MALFORMED;
	*len = 0;
	what = row_load(b, kind, id, bytes, &n, &r);
	/* LET GO, it is served as not held: what a node holding none of it
	 * would answer. */
	if (!what || what == 3 || r.indexed != 1u)
		return FZN_BUCKETS_ABSENT;
	if (subject)
		memcpy(subject, r.subject, FZN_PUBKEY_LEN);
	if (month)
		*month = r.month;
	if (what == 2)
		return FZN_BUCKETS_LARGE;
	if (r.data_len > cap)
		return FZN_BUCKETS_MALFORMED;
	memcpy(out, r.data, r.data_len);
	*len = r.data_len;
	return FZN_BUCKETS_OK;
}

fzn_buckets_err_t fzn_buckets_ref(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                  const uint8_t id[FZN_BUCKETS_ID_LEN],
                                  uint8_t ref[FZN_BUCKETS_REF_MAX], size_t *ref_len,
                                  uint64_t *size)
{
	static uint8_t bytes[ROW_MAX];
	size_t n = 0;
	row_read_t r;

	if (!ready(b, kind) || !id || !ref || !ref_len || !size)
		return FZN_BUCKETS_MALFORMED;
	*ref_len = 0;
	*size = 0;
	if (row_load(b, kind, id, bytes, &n, &r) != 2 || r.indexed != 1u)
		return FZN_BUCKETS_ABSENT;
	*ref_len = r.data_len;
	memcpy(ref, r.data, r.data_len);
	*size = r.size;
	return FZN_BUCKETS_OK;
}

fzn_buckets_err_t fzn_buckets_let_go(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                     const uint8_t id[FZN_BUCKETS_ID_LEN])
{
	static uint8_t bytes[ROW_MAX];
	uint8_t gone[L_LEN];
	size_t n = 0;
	row_read_t r;
	uint32_t wrote = 0;
	int what;

	if (!ready(b, kind) || !id)
		return FZN_BUCKETS_MALFORMED;
	what = row_load(b, kind, id, bytes, &n, &r);
	if (!what || r.indexed != 1u)
		return FZN_BUCKETS_ABSENT;
	if (what == 3)
		return FZN_BUCKETS_OK;
	/* THE HEAD KEPT, the bytes or the ref gone: its id stays counted. */
	if (fzn_buckets_row_fzn_buckets_let_go_build(gone, L_LEN, LET_GO_VERSION, (fzn_buckets_row_fzn_buckets_kind_t)kind,
	                                             r.subject, r.month, 1u, &wrote)
	    != SITU_OK)
		return FZN_BUCKETS_BACKEND;
	return item_save(b, kind, id, gone, L_LEN) ? FZN_BUCKETS_OK : FZN_BUCKETS_BACKEND;
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
		bucket_new(bytes, kind, subject, month);
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

/* ONE WALK OF THE BUCKET ROWS, sec 791: each of `kind` held and not gone,
 * into `*out` -- room `*room`, grown when `grow` -- through the store's
 * walk, so no buffer of every row's name bounds how many there are. */
typedef struct listing {
	const fzn_buckets_t *b;
	fzn_buckets_kind_t kind;
	fzn_bucket_t **out;
	size_t *room;
	int grow;
	size_t held;
	fzn_buckets_err_t err;
} listing_t;

static int list_one(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	listing_t *l = (listing_t *)arg;
	uint8_t bytes[B_LEN];
	size_t len = 0;

	if (!l->b->store->load(l->b->store->ctx, FZN_PERSIST_BUCKET, subject, bytes, sizeof(bytes),
	                       &len)) {
		l->err = FZN_BUCKETS_BACKEND;
		return 0;
	}
	/* ANOTHER KIND'S, OR NOT A BUCKET: passed over. A gone bucket's row
	 * left by a crash part way through its drop is not offered. */
	if (!bucket_is(bytes, len, l->kind, NULL, 0, 0u))
		return 1;
	{
		situ_msg_t m;
		situ_view_t v = bucket_view(bytes, &m);

		if (fzn_buckets_gone(l->b, l->kind, fzn_buckets_row_fzn_buckets_bucket_subject_ptr(v),
		                     fzn_buckets_row_fzn_buckets_bucket_month_get(v)))
			return 1;
	}
	if (l->held >= *l->room) {
		size_t want = *l->room ? 2u * *l->room : 64u;
		fzn_bucket_t *more;

		if (!l->grow || want < *l->room || want > SIZE_MAX / sizeof(fzn_bucket_t)
		    || !(more = realloc(*l->out, want * sizeof(fzn_bucket_t)))) {
			l->err = FZN_BUCKETS_FULL;
			return 0;
		}
		*l->out = more;
		*l->room = want;
	}
	if (!fill(l->b, bytes, &(*l->out)[l->held])) {
		l->err = FZN_BUCKETS_BACKEND;
		return 0;
	}
	l->held++;
	return 1;
}

/* THE SLOT'S ROWS, each to `list_one`: through the store's walk, or, for
 * a backend without one, its list into a room of FZN_PERSIST_EACH_FALLBACK
 * as `fzn_persist_each` gives -- not called, so this module links without
 * the persist module's own. */
static int each_row(const fzn_persist_ops_t *ops, listing_t *l)
{
	static uint8_t room[FZN_PERSIST_EACH_FALLBACK * FZN_PUBKEY_LEN];
	size_t found = 0, i;

	if (ops->each)
		return ops->each(ops->ctx, FZN_PERSIST_BUCKET, list_one, l);
	if (!ops->list || !ops->list(ops->ctx, FZN_PERSIST_BUCKET, room, FZN_PERSIST_EACH_FALLBACK,
	                             &found))
		return 0;
	for (i = 0; i < found; i++)
		if (!list_one(l, room + i * FZN_PUBKEY_LEN))
			break;
	return 1;
}

static fzn_buckets_err_t list_rows(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                   fzn_bucket_t **out, size_t *room, int grow, size_t *count)
{
	listing_t l;

	memset(&l, 0, sizeof(l));
	l.b = b;
	l.kind = kind;
	l.out = out;
	l.room = room;
	l.grow = grow;
	l.err = FZN_BUCKETS_OK;
	if (!each_row(b->store, &l))
		return l.err != FZN_BUCKETS_OK ? l.err : FZN_BUCKETS_BACKEND;
	if (l.err != FZN_BUCKETS_OK)
		return l.err;
	if (l.held)
		qsort(*out, l.held, sizeof(**out), by_place);
	*count = l.held;
	return FZN_BUCKETS_OK;
}

fzn_buckets_err_t fzn_buckets_list(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                   fzn_bucket_t *out, size_t max, size_t *count)
{
	size_t room = max;

	if (count)
		*count = 0;
	if (!ready(b, kind) || !out || !count)
		return FZN_BUCKETS_MALFORMED;
	/* A LIST THAT DOES NOT FIT FAILS, by the persist ops' own rule. */
	return list_rows(b, kind, &out, &room, 0, count);
}

fzn_buckets_err_t fzn_buckets_list_all(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                       fzn_bucket_t **list, size_t *room, size_t *count)
{
	if (count)
		*count = 0;
	if (!ready(b, kind) || !list || !room || !count || (!*list && *room))
		return FZN_BUCKETS_MALFORMED;
	return list_rows(b, kind, list, room, 1, count);
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
	n = bucket_count(bucket);
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
	{
		uint32_t wrote = 0;

		if (fzn_buckets_row_fzn_buckets_gone_build(gone, G_LEN, VERSION, (fzn_buckets_row_fzn_buckets_kind_t)kind,
		                                           subject, month, &wrote)
		    != SITU_OK)
			return FZN_BUCKETS_MALFORMED;
	}
	if (!row_of(b, "fuzznet.bucket.gone", kind, subject, 1, month, 0, 0u, row)
	    || !b->store->save(b->store->ctx, FZN_PERSIST_BUCKET_IDS, row, gone, sizeof(gone)))
		return FZN_BUCKETS_BACKEND;
	held = bucket_load(b, kind, subject, month, bucket);
	if (held < 0)
		return FZN_BUCKETS_BACKEND;
	if (!held)
		return FZN_BUCKETS_OK;
	n = bucket_count(bucket);
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
