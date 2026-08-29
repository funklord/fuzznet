/* See spool.h. */

#include "spool.h"

#include <string.h>

/*
 * A leaf's byte offset. Every leaf but the last is exactly
 * FZN_BLOB_SEALED_MAX, so the store is a flat array and an index is
 * arithmetic rather than a lookup.
 *
 * THE LAST LEAF IS SHORT AND STILL OCCUPIES A FULL SLOT. Packing it tightly
 * would save at most 1055 bytes and would make every offset depend on
 * knowing the blob's exact length, which a receiver does not have until the
 * last leaf arrives -- so an out-of-order transfer could not place anything
 * until it had the end. A fixed stride is what makes arrival order free.
 */
static uint64_t offset_of(uint64_t index)
{
	return index * (uint64_t)FZN_BLOB_SEALED_MAX;
}

static int bit_get(const uint8_t *map, uint64_t index)
{
	return (map[index >> 3] >> (index & 7u)) & 1u;
}

static void bit_set(uint8_t *map, uint64_t index)
{
	map[index >> 3] = (uint8_t)(map[index >> 3] | (1u << (index & 7u)));
}

fzn_spool_err_t fzn_spool_open(fzn_spool_t *spool, const uint8_t root[FZN_BLOB_HASH_LEN],
                               uint64_t leaves, uint8_t *present, size_t present_len,
                               const fzn_spool_ops_t *ops)
{
	uint64_t i;

	if (!spool || !root || !present || !ops || !ops->read_at || !ops->write_at)
		return FZN_SPOOL_ERR_MALFORMED;
	if (leaves == 0u)
		return FZN_SPOOL_ERR_MALFORMED;
	/* CHECKED BEFORE ANYTHING IS TOUCHED. `leaves` is a peer's number in
	 * every interesting case, and the bitmap it implies is the thing that
	 * would be allocated -- so the ceiling is a refusal here rather than
	 * an allocation failure later. */
	if (leaves > (uint64_t)FZN_SPOOL_MAX_LEAVES)
		return FZN_SPOOL_ERR_TOO_LARGE;
	if (present_len < FZN_SPOOL_BITMAP_LEN(leaves))
		return FZN_SPOOL_ERR_MALFORMED;

	memcpy(spool->root, root, FZN_BLOB_HASH_LEN);
	spool->leaves = leaves;
	spool->present = present;
	spool->present_len = present_len;
	spool->ops = ops;

	/*
	 * COUNTED FROM THE BITS RATHER THAN TAKEN FROM A CALLER, which is the
	 * resume path's one safety property. A caller restoring a bitmap and a
	 * count from separate places can restore a torn pair -- a count saying
	 * complete over a bitmap that is not -- and this module would then
	 * report a blob finished that has holes in it. Recounting costs one
	 * pass over at most 512 KiB and removes the disagreement.
	 *
	 * Bits past `leaves` in the final byte are IGNORED rather than
	 * cleared: a caller's buffer is the caller's, and clearing would write
	 * into memory this function was only lent.
	 */
	spool->have = 0u;
	for (i = 0; i < leaves; i++)
		if (bit_get(present, i))
			spool->have++;

	return FZN_SPOOL_OK;
}

fzn_spool_err_t fzn_spool_place(fzn_spool_t *spool, const fzn_hash_ops_t *hash, uint64_t index,
                                const uint8_t *sealed, size_t sealed_len,
                                const uint8_t *proof, unsigned proof_len)
{
	uint8_t leaf_hash[FZN_BLOB_HASH_LEN];

	if (!spool || !spool->ops || !sealed)
		return FZN_SPOOL_ERR_MALFORMED;
	if (index >= spool->leaves)
		return FZN_SPOOL_ERR_TOO_LARGE;
	if (sealed_len == 0u || sealed_len > FZN_BLOB_SEALED_MAX)
		return FZN_SPOOL_ERR_UNVERIFIED;

	/* A DUPLICATE IS ACCEPTED AND NOT REWRITTEN. Duplicates are ordinary
	 * on a lossy transport, and rewriting turns each one into disk
	 * traffic. Checked before verifying, because re-verifying a leaf this
	 * store already proved is work a flood would happily buy. */
	if (bit_get(spool->present, index))
		return FZN_SPOOL_OK;

	/*
	 * VERIFIED BEFORE A BYTE IS WRITTEN, which is what makes this safe to
	 * point at a stranger. A store that placed first and checked later
	 * would let anybody fill a disk with bytes that fail to assemble
	 * later -- and "later" is after the disk is full.
	 *
	 * The verifier is KEYLESS, so a relay holding no content key runs this
	 * unchanged. That is the property `blob/`'s ciphertext-over-plaintext
	 * ordering exists for, and this is the first caller to need it.
	 */
	if (fzn_blob_leaf_hash(hash, sealed, sealed_len, leaf_hash) != FZN_BLOB_OK)
		return FZN_SPOOL_ERR_UNVERIFIED;
	if (fzn_blob_proof_verify(hash, leaf_hash, index, spool->leaves, proof, proof_len,
	                          spool->root) != FZN_BLOB_OK)
		return FZN_SPOOL_ERR_UNVERIFIED;

	if (!spool->ops->write_at(spool->ops->ctx, offset_of(index), sealed, sealed_len))
		return FZN_SPOOL_ERR_BACKEND;

	/* THE BIT IS SET AFTER THE WRITE SUCCEEDS, never before. A bit set
	 * over a failed write is a hole the store will never fill again,
	 * because `next_missing` skips it and nothing re-requests it -- a
	 * transfer that reports complete and produces a corrupt blob. */
	bit_set(spool->present, index);
	spool->have++;

	/* Synced once at completion rather than per leaf: a fsync per 1 KiB
	 * would make a transfer disk-bound, and a partial spool is recoverable
	 * by construction since the bitmap says what is missing. */
	if (spool->have == spool->leaves && spool->ops->sync)
		(void)spool->ops->sync(spool->ops->ctx);

	return FZN_SPOOL_OK;
}

fzn_spool_err_t fzn_spool_read(const fzn_spool_t *spool, uint64_t index, uint8_t *out,
                               size_t cap, size_t *len)
{
	size_t want;

	if (!spool || !spool->ops || !out || !len)
		return FZN_SPOOL_ERR_MALFORMED;
	if (index >= spool->leaves)
		return FZN_SPOOL_ERR_TOO_LARGE;
	if (!bit_get(spool->present, index))
		return FZN_SPOOL_ERR_ABSENT;

	/* THE STRIDE IS READ, NOT THE LEAF'S OWN LENGTH, because a store does
	 * not know it -- the sealed length lives in the blob's own framing and
	 * the last leaf is short. A caller reading a full slot gets the
	 * trailing bytes of the slot with it and `fzn_blob_leaf_open` refuses
	 * a length that is not the one it sealed. That is a real edge and it
	 * is the caller's to resolve with the length it requested, which is
	 * why this reports what it read rather than pretending to know. */
	want = cap < FZN_BLOB_SEALED_MAX ? cap : FZN_BLOB_SEALED_MAX;
	if (!spool->ops->read_at(spool->ops->ctx, offset_of(index), out, want))
		return FZN_SPOOL_ERR_BACKEND;

	*len = want;
	return FZN_SPOOL_OK;
}

int fzn_spool_has(const fzn_spool_t *spool, uint64_t index)
{
	if (!spool || index >= spool->leaves)
		return 0;
	return bit_get(spool->present, index);
}

int fzn_spool_complete(const fzn_spool_t *spool)
{
	/* ASKED OF THE COUNT, WHICH `open` RECOMPUTED FROM THE BITS. A
	 * completeness answer taken from a stored number is one a torn resume
	 * can forge. */
	return spool && spool->leaves > 0u && spool->have == spool->leaves;
}

fzn_spool_err_t fzn_spool_next_missing(const fzn_spool_t *spool, uint64_t from, uint64_t *out)
{
	uint64_t i;

	if (!spool || !out)
		return FZN_SPOOL_ERR_MALFORMED;

	for (i = from; i < spool->leaves; i++) {
		if (!bit_get(spool->present, i)) {
			*out = i;
			return FZN_SPOOL_OK;
		}
	}
	return FZN_SPOOL_ERR_ABSENT;
}

/* See spool.h. No `default:`, so -Wswitch names a code added and not
 * rendered here. */
const char *fzn_spool_err_str(fzn_spool_err_t err)
{
	switch (err) {
	case FZN_SPOOL_OK:
		return "ok";
	case FZN_SPOOL_ERR_MALFORMED:
		return "malformed argument";
	case FZN_SPOOL_ERR_TOO_LARGE:
		return "past the leaf ceiling this store will assemble";
	case FZN_SPOOL_ERR_UNVERIFIED:
		return "the leaf does not verify against the root";
	case FZN_SPOOL_ERR_BACKEND:
		return "the storage backend refused";
	case FZN_SPOOL_ERR_ABSENT:
		return "this store does not hold that leaf";
	}

	return "unknown";
}
