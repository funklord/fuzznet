/* See index.h. */

#include "index.h"

#include <string.h>

/* Big-endian u32, the endianness catalog/attribute.situ declares, in the
 * width the two counts need: a shard count is a property of a register's
 * size and 65535 shards is only 67 million entries at the default floor. */
static void put_u32(uint8_t *p, size_t v)
{
	p[0] = (uint8_t)((v >> 24) & 0xffu);
	p[1] = (uint8_t)((v >> 16) & 0xffu);
	p[2] = (uint8_t)((v >> 8) & 0xffu);
	p[3] = (uint8_t)(v & 0xffu);
}

static size_t get_u32(const uint8_t *p)
{
	return ((size_t)p[0] << 24) | ((size_t)p[1] << 16)
	       | ((size_t)p[2] << 8) | (size_t)p[3];
}

/* Does `v` fit the four-byte field? On a 32-bit host every size_t does, and
 * the comparison is written so that says so rather than warning. */
static int fits_u32(size_t v)
{
	return (uint64_t)v <= 0xffffffffu;
}

fzn_catalog_err_t fzn_catalog_index_encode(const fzn_catalog_index_t *ix,
                                           uint8_t *out, size_t cap,
                                           size_t *len_out)
{
	if (!ix || !out || !len_out)
		return FZN_CATALOG_ERR_MALFORMED;
	/* An index over no shards routes nothing, and a floor of zero makes
	 * C26's claim about an empty anonymity set. */
	if (ix->floor == 0 || ix->shards == 0)
		return FZN_CATALOG_ERR_MALFORMED;
	if (!fits_u32(ix->floor) || !fits_u32(ix->shards))
		return FZN_CATALOG_ERR_RANGE;
	if (cap < FZN_CATALOG_INDEX_HEAD_LEN)
		return FZN_CATALOG_ERR_RANGE;
	if (FZN_CATALOG_INDEX_HEAD_LEN > (size_t)FZN_RECORD_BODY_MAX)
		return FZN_CATALOG_ERR_RANGE;

	out[0] = (uint8_t)FZN_CATALOG_OBJECT_INDEX;
	put_u32(&out[1], ix->floor);
	put_u32(&out[5], ix->shards);
	memcpy(&out[9], ix->root.b, FZN_CATALOG_INDEX_ROOT_LEN);
	*len_out = FZN_CATALOG_INDEX_HEAD_LEN;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_index_decode(const uint8_t *body, size_t body_len,
                                           fzn_catalog_index_t *out)
{
	fzn_catalog_index_t ix;

	if (!body || !out)
		return FZN_CATALOG_ERR_MALFORMED;
	if (body_len < FZN_CATALOG_INDEX_HEAD_LEN)
		return FZN_CATALOG_ERR_MALFORMED;
	/* A TRAILING BYTE IS REFUSED, not ignored: the signature is over these
	 * bytes, and two spellings of one index would let a peer re-sign a
	 * different one. */
	if (body_len != FZN_CATALOG_INDEX_HEAD_LEN)
		return FZN_CATALOG_ERR_MALFORMED;
	if (body[0] != (uint8_t)FZN_CATALOG_OBJECT_INDEX)
		return FZN_CATALOG_ERR_MALFORMED;

	ix.floor = get_u32(&body[1]);
	ix.shards = get_u32(&body[5]);
	if (ix.floor == 0 || ix.shards == 0)
		return FZN_CATALOG_ERR_MALFORMED;
	/* A count whose blob could not be addressed here is refused at the
	 * head, so a caller never reaches the multiplication with it. */
	{
		size_t unused;

		if (fzn_catalog_index_body_len(ix.shards, &unused)
		    != FZN_CATALOG_OK)
			return FZN_CATALOG_ERR_RANGE;
	}
	memcpy(ix.root.b, &body[9], FZN_CATALOG_INDEX_ROOT_LEN);
	*out = ix;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_index_body_len(size_t shards, size_t *len_out)
{
	if (!len_out)
		return FZN_CATALOG_ERR_MALFORMED;
	if (shards == 0)
		return FZN_CATALOG_ERR_MALFORMED;
	/* GUARD THE MULTIPLICATION, NOT THE RESULT. The count arrives over the
	 * wire, and on a 32-bit host a peer naming 2^26 shards would wrap the
	 * length to something small and plausible -- which cannot be detected
	 * afterwards, because the wrapped value is a legal size_t. */
	if (shards > (size_t)-1 / FZN_CATALOG_INDEX_ENTRY_LEN)
		return FZN_CATALOG_ERR_RANGE;
	*len_out = shards * FZN_CATALOG_INDEX_ENTRY_LEN;
	return FZN_CATALOG_OK;
}

/* Strictly ascending, which is what makes a range able to name one blob. */
static int key_before(const uint8_t *a, const uint8_t *b)
{
	return memcmp(a, b, FZN_CATALOG_SHARD_KEY_LEN) < 0;
}

fzn_catalog_err_t fzn_catalog_index_body_encode(const fzn_catalog_shard_t *plan,
                                                const fzn_catalog_blob_root_t *roots,
                                                size_t count, uint8_t *out,
                                                size_t cap, size_t *len_out)
{
	size_t need, i;
	fzn_catalog_err_t r;

	if (!plan || !roots || !out || !len_out)
		return FZN_CATALOG_ERR_MALFORMED;
	r = fzn_catalog_index_body_len(count, &need);
	if (r != FZN_CATALOG_OK)
		return r;
	if (cap < need)
		return FZN_CATALOG_ERR_RANGE;

	/* CHECKED BEFORE ANYTHING IS WRITTEN, so a refused call leaves no
	 * half-built index -- and checked at all because ranges that overlap
	 * cannot say which blob holds a key, which is silent. */
	for (i = 1; i < count; i++) {
		if (!key_before(plan[i - 1u].first.b, plan[i].first.b))
			return FZN_CATALOG_ERR_MALFORMED;
	}

	for (i = 0; i < count; i++) {
		uint8_t *e = &out[i * FZN_CATALOG_INDEX_ENTRY_LEN];

		memcpy(e, plan[i].first.b, FZN_CATALOG_SHARD_KEY_LEN);
		memcpy(&e[FZN_CATALOG_SHARD_KEY_LEN], roots[i].b,
		       FZN_CATALOG_INDEX_ROOT_LEN);
	}
	*len_out = need;
	return FZN_CATALOG_OK;
}

int fzn_catalog_index_body_ok(const uint8_t *body, size_t body_len, size_t expect)
{
	size_t entries, i;

	if (!body || body_len == 0)
		return 0;
	if (body_len % FZN_CATALOG_INDEX_ENTRY_LEN != 0)
		return 0;
	entries = body_len / FZN_CATALOG_INDEX_ENTRY_LEN;
	if (expect != 0 && entries != expect)
		return 0;
	for (i = 1; i < entries; i++) {
		if (!key_before(&body[(i - 1u) * FZN_CATALOG_INDEX_ENTRY_LEN],
		                &body[i * FZN_CATALOG_INDEX_ENTRY_LEN]))
			return 0;
	}
	return 1;
}

fzn_catalog_err_t fzn_catalog_index_entry_at(const uint8_t *body, size_t body_len,
                                             size_t i,
                                             fzn_catalog_shard_key_t *first_out,
                                             fzn_catalog_blob_root_t *root_out)
{
	const uint8_t *e;

	if (!body)
		return FZN_CATALOG_ERR_MALFORMED;
	if (body_len % FZN_CATALOG_INDEX_ENTRY_LEN != 0)
		return FZN_CATALOG_ERR_RANGE;
	if (i >= body_len / FZN_CATALOG_INDEX_ENTRY_LEN)
		return FZN_CATALOG_ERR_RANGE;

	e = &body[i * FZN_CATALOG_INDEX_ENTRY_LEN];
	if (first_out)
		memcpy(first_out->b, e, FZN_CATALOG_SHARD_KEY_LEN);
	if (root_out)
		memcpy(root_out->b, &e[FZN_CATALOG_SHARD_KEY_LEN],
		       FZN_CATALOG_INDEX_ROOT_LEN);
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_index_lookup(const uint8_t *body, size_t body_len,
                                           const fzn_catalog_shard_key_t *key,
                                           size_t *index_out)
{
	size_t entries, lo, hi;

	if (!body || !key || !index_out)
		return FZN_CATALOG_ERR_MALFORMED;
	if (body_len == 0)
		return FZN_CATALOG_ERR_ABSENT;
	if (body_len % FZN_CATALOG_INDEX_ENTRY_LEN != 0)
		return FZN_CATALOG_ERR_RANGE;
	entries = body_len / FZN_CATALOG_INDEX_ENTRY_LEN;

	/* The last entry whose first key is <= `key`, or entry 0 when the key
	 * is below every start -- the ranges together cover the whole key
	 * space, so there is no "before the index" to report. */
	lo = 0;
	hi = entries;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2u;

		if (key_before(key->b, &body[mid * FZN_CATALOG_INDEX_ENTRY_LEN]))
			hi = mid;
		else
			lo = mid + 1u;
	}
	*index_out = lo == 0 ? 0 : lo - 1u;
	return FZN_CATALOG_OK;
}
