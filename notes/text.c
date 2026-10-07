/* See text.h. */

#include "text.h"

_Static_assert(FZN_NOTE_PAYLOAD_MAX == FZN_NOTE_TEXT_MAX,
               "a note's payload is one blob, and its ceiling is a blob's");

#include "../constant_time/constant_time.h"

#include <string.h>

_Static_assert(FZN_NOTE_TEXT_MAX % FZN_BLOB_LEAF_SIZE == 0u,
               "the text bound is not a whole number of leaves");
_Static_assert(FZN_NOTE_TEXT_LEAVES_MAX <= FZN_SPOOL_MAX_LEAVES,
               "a note's text is past what a spool will assemble");

/* Seal leaf `index` of `text` into `out`. */
static int seal_leaf(const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                     const uint8_t key[FZN_BLOB_KEY_LEN], const uint8_t *text, size_t len,
                     uint64_t index, uint8_t out[FZN_BLOB_SEALED_MAX], size_t *out_len)
{
	size_t at = (size_t)index * FZN_BLOB_LEAF_SIZE;
	size_t take = len - at < FZN_BLOB_LEAF_SIZE ? len - at : FZN_BLOB_LEAF_SIZE;

	return fzn_blob_leaf_seal(hash, aead, key, index, text + at, take, out, FZN_BLOB_SEALED_MAX,
	                          out_len) == FZN_BLOB_OK;
}

fzn_note_err_t fzn_note_text_seal(const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                  const fzn_random_ops_t *rng, const uint8_t *text, size_t len,
                                  const fzn_spool_ops_t *ops, uint8_t *present,
                                  size_t present_len, fzn_spool_t *spool,
                                  fzn_note_blob_ref_t *ref)
{
	uint8_t hashes[FZN_NOTE_TEXT_LEAVES_MAX][FZN_BLOB_HASH_LEN];
	uint8_t sealed[FZN_BLOB_SEALED_MAX], proof[FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
	uint8_t key[FZN_BLOB_KEY_LEN], root[FZN_BLOB_HASH_LEN];
	fzn_blob_tree_t tree;
	uint64_t leaves = 0, i;
	size_t last = 0, sealed_len = 0;
	unsigned siblings = 0;

	if (!hash || !hash->hash || !aead || !rng || !rng->fill || !text || !ops || !present
	    || !spool || !ref)
		return FZN_NOTE_ERR_NULL;
	if (len == 0u || len > FZN_NOTE_TEXT_MAX)
		return FZN_NOTE_ERR_LEN;
	if (present_len < FZN_NOTE_TEXT_PRESENT_LEN)
		return FZN_NOTE_ERR_CAPACITY;
	if (fzn_blob_geometry(len, &leaves, &last) != FZN_BLOB_OK || leaves == 0u
	    || leaves > FZN_NOTE_TEXT_LEAVES_MAX)
		return FZN_NOTE_ERR_LEN;
	/* A FRESH KEY: one key over two texts breaks the AEAD (text.h). */
	if (!rng->fill(rng->ctx, key, sizeof(key)))
		return FZN_NOTE_ERR_CRYPTO;

	/* THE ROOT, from every leaf's hash -- which the proofs below need
	 * again, so they are kept. */
	fzn_blob_tree_init(&tree);
	for (i = 0; i < leaves; i++)
		if (!seal_leaf(hash, aead, key, text, len, i, sealed, &sealed_len)
		    || fzn_blob_leaf_hash(hash, sealed, sealed_len, hashes[i]) != FZN_BLOB_OK
		    || fzn_blob_tree_push(hash, &tree, hashes[i]) != FZN_BLOB_OK)
			goto crypto;
	if (fzn_blob_tree_root(hash, &tree, root) != FZN_BLOB_OK)
		goto crypto;

	/* EVERY LEAF PLACED AS A STRANGER'S WOULD BE: through the spool's own
	 * verification against the root, so a sealing bug cannot write a
	 * leaf that would not prove. */
	memset(present, 0, present_len);
	if (fzn_spool_open(spool, root, leaves, present, present_len, ops) != FZN_SPOOL_OK)
		goto store;
	for (i = 0; i < leaves; i++) {
		if (!seal_leaf(hash, aead, key, text, len, i, sealed, &sealed_len)
		    || fzn_blob_proof_build(hash, (const uint8_t *)hashes, leaves, i, proof,
		                            sizeof(proof), &siblings) != FZN_BLOB_OK)
			goto crypto;
		if (fzn_spool_place(spool, hash, i, sealed, sealed_len, proof, siblings)
		    != FZN_SPOOL_OK)
			goto store;
	}

	memcpy(ref->root, root, sizeof(root));
	memcpy(ref->key, key, sizeof(key));
	ref->length = len;
	fzn_wipe(key, sizeof(key));
	return FZN_NOTE_OK;
crypto:
	fzn_wipe(key, sizeof(key));
	return FZN_NOTE_ERR_CRYPTO;
store:
	fzn_wipe(key, sizeof(key));
	return FZN_NOTE_ERR_STORE;
}

fzn_note_err_t fzn_note_text_open(const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                  const fzn_spool_t *spool, const fzn_note_blob_ref_t *ref,
                                  uint8_t *out, size_t out_cap, size_t *out_len)
{
	uint8_t sealed[FZN_BLOB_SEALED_MAX];
	uint64_t leaves = 0, i;
	size_t last = 0, at = 0;

	if (!hash || !aead || !spool || !ref || !out || !out_len)
		return FZN_NOTE_ERR_NULL;
	if (ref->length == 0u || ref->length > FZN_NOTE_TEXT_MAX)
		return FZN_NOTE_ERR_LEN;
	/* THE SPOOL MUST HOLD THIS BLOB: its root, and the leaf count the
	 * length implies -- the count is bound into the root (blob.h), so a
	 * length the root does not commit to is another blob. */
	if (fzn_blob_geometry(ref->length, &leaves, &last) != FZN_BLOB_OK
	    || !fzn_ct_memeq(spool->root, ref->root, FZN_BLOB_HASH_LEN) || spool->leaves != leaves)
		return FZN_NOTE_ERR_MISMATCH;
	if (!fzn_spool_complete(spool))
		return FZN_NOTE_ERR_ABSENT;
	if (out_cap < ref->length)
		return FZN_NOTE_ERR_CAPACITY;
	for (i = 0; i < leaves; i++) {
		size_t read_len = 0, plain_len = 0;
		/* THE LEAF'S OWN LENGTH, from the geometry: a spool reads back
		 * a whole slot, zero-filled past a short last leaf, and leaves
		 * the length to the caller (spool.h). */
		size_t sealed_len = (i + 1u == leaves ? last : (size_t)FZN_BLOB_LEAF_SIZE)
		                    + FZN_BLOB_LEAF_OVERHEAD;

		if (fzn_spool_read(spool, i, sealed, sizeof(sealed), &read_len) != FZN_SPOOL_OK
		    || read_len < sealed_len)
			return FZN_NOTE_ERR_STORE;
		if (fzn_blob_leaf_open(hash, aead, ref->key, i, sealed, sealed_len, out + at,
		                       out_cap - at, &plain_len) != FZN_BLOB_OK)
			return FZN_NOTE_ERR_CRYPTO;
		at += plain_len;
	}
	/* THE LENGTH THE NOTE STATES, by construction: every leaf opened at the
	 * length the geometry of ref->length gives it, so they sum to it. */
	*out_len = at;
	return FZN_NOTE_OK;
}

fzn_note_text_state_t fzn_note_text_state(const fzn_note_blob_ref_t *ref,
                                          const fzn_spool_t *spool)
{
	uint64_t leaves = 0;
	size_t last = 0;

	if (!ref || ref->length == 0u || ref->length > FZN_NOTE_TEXT_MAX
	    || fzn_blob_geometry(ref->length, &leaves, &last) != FZN_BLOB_OK)
		return FZN_NOTE_TEXT_BROKEN;
	if (!spool || !fzn_ct_memeq(spool->root, ref->root, FZN_BLOB_HASH_LEN)
	    || spool->leaves != leaves || !fzn_spool_complete(spool))
		return FZN_NOTE_TEXT_PENDING;
	return FZN_NOTE_TEXT_HERE;
}
