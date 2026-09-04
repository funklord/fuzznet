/* See disclose.h. */

#include "disclose.h"

#include <string.h>

_Static_assert(FZN_DISCLOSE_SALT_LEN == 16u, "the salt length has moved; every peer must agree");
_Static_assert(FZN_DISCLOSE_MAX_LEN == FZN_DISCLOSE_SALT_LEN + FZN_DISCLOSE_MAX_FIELD,
               "a committed field is a salt and a field and nothing else");

fzn_disclose_err_t fzn_disclose_commit(const fzn_random_ops_t *rng, const uint8_t *field,
                                       size_t field_len, uint8_t *out, size_t out_cap,
                                       size_t *out_len)
{
	if (!out || !out_len)
		return FZN_DISCLOSE_ERR_MALFORMED;
	if (!field && field_len != 0)
		return FZN_DISCLOSE_ERR_MALFORMED;
	if (field_len > FZN_DISCLOSE_MAX_FIELD)
		return FZN_DISCLOSE_ERR_MALFORMED;
	if (out_cap < FZN_DISCLOSE_SALT_LEN + field_len)
		return FZN_DISCLOSE_ERR_MALFORMED;
	if (!rng || !rng->fill)
		return FZN_DISCLOSE_ERR_NO_SALT;

	/* THE SALT FIRST, AND THE REFUSAL BEFORE THE FIELD IS COPIED. An
	 * entropy source that cannot answer must leave the caller's buffer as
	 * it found it -- `wire/seal.c` records the same order for the same
	 * reason, having once returned an error with the capability already
	 * copied in. Here the residue would be the field itself, which is the
	 * thing being committed. */
	if (!rng->fill(rng->ctx, out, FZN_DISCLOSE_SALT_LEN))
		return FZN_DISCLOSE_ERR_NO_SALT;

	/* A ZERO-LENGTH FIELD IS A FIELD. It commits to "this one is empty",
	 * which is a statement a sender may want to make and which the salt
	 * still hides: without one, every empty field in every statement would
	 * share a leaf hash and be recognisable at a glance. */
	if (field_len != 0)
		memcpy(out + FZN_DISCLOSE_SALT_LEN, field, field_len);

	*out_len = FZN_DISCLOSE_SALT_LEN + field_len;
	return FZN_DISCLOSE_OK;
}

/* Shared by the three readers below: what makes a buffer a committed field.
 * One place, so that a length rule cannot be enforced in two of them and
 * forgotten in the third. */
static int committed_shape(const uint8_t *committed, size_t committed_len)
{
	if (!committed)
		return 0;
	if (committed_len < FZN_DISCLOSE_SALT_LEN)
		return 0;
	return committed_len <= FZN_DISCLOSE_MAX_LEN;
}

fzn_disclose_err_t fzn_disclose_leaf(const fzn_hash_ops_t *hash, const uint8_t *committed,
                                     size_t committed_len, uint8_t out[FZN_BLOB_HASH_LEN])
{
	if (!out)
		return FZN_DISCLOSE_ERR_MALFORMED;
	if (!hash || !hash->hash)
		return FZN_DISCLOSE_ERR_HASH;
	if (!committed_shape(committed, committed_len))
		return FZN_DISCLOSE_ERR_SHAPE;

	/* THE WHOLE COMMITTED FIELD IS HASHED, salt included, which is what
	 * makes the leaf unguessable. Hashing only the field would put the
	 * convention back where sec 72 found it. */
	if (fzn_blob_leaf_hash(hash, committed, committed_len, out) != FZN_BLOB_OK)
		return FZN_DISCLOSE_ERR_HASH;

	return FZN_DISCLOSE_OK;
}

fzn_disclose_err_t fzn_disclose_field(const uint8_t *committed, size_t committed_len,
                                      const uint8_t **field_out, size_t *field_len_out)
{
	if (!field_out || !field_len_out)
		return FZN_DISCLOSE_ERR_MALFORMED;

	*field_out = NULL;
	*field_len_out = 0;

	if (!committed_shape(committed, committed_len))
		return FZN_DISCLOSE_ERR_SHAPE;

	*field_out = committed + FZN_DISCLOSE_SALT_LEN;
	*field_len_out = committed_len - FZN_DISCLOSE_SALT_LEN;
	return FZN_DISCLOSE_OK;
}

fzn_disclose_err_t fzn_disclose_verify(const fzn_hash_ops_t *hash, const uint8_t *committed,
                                       size_t committed_len, uint64_t index,
                                       uint64_t field_count, const uint8_t *siblings,
                                       unsigned sibling_count,
                                       const uint8_t root[FZN_BLOB_HASH_LEN],
                                       const uint8_t **field_out, size_t *field_len_out)
{
	uint8_t leaf[FZN_BLOB_HASH_LEN];
	fzn_disclose_err_t err;

	if (!field_out || !field_len_out)
		return FZN_DISCLOSE_ERR_MALFORMED;

	/* CLEARED BEFORE ANYTHING CAN REFUSE, so a caller that reads the
	 * outputs without reading the status gets nothing rather than the last
	 * field it verified. `record/sync.c` records the same rule and the
	 * incident behind it -- a reused plan returning 0x33 as a count. */
	*field_out = NULL;
	*field_len_out = 0;

	if (!root)
		return FZN_DISCLOSE_ERR_MALFORMED;

	err = fzn_disclose_leaf(hash, committed, committed_len, leaf);
	if (err != FZN_DISCLOSE_OK)
		return err;

	/* THE PROOF BEFORE THE FIELD IS HANDED BACK, which is the point of
	 * this function existing rather than a caller pairing the two calls
	 * itself. A caller that read the field first and checked afterwards
	 * would be one `if` away from acting on an unverified field, and that
	 * `if` is exactly the one somebody omits. */
	if (fzn_blob_proof_verify(hash, leaf, index, field_count, siblings, sibling_count,
	                          root) != FZN_BLOB_OK)
		return FZN_DISCLOSE_ERR_PROOF;

	return fzn_disclose_field(committed, committed_len, field_out, field_len_out);
}

const char *fzn_disclose_err_str(fzn_disclose_err_t err)
{
	switch (err) {
	case FZN_DISCLOSE_OK:
		return "ok";
	case FZN_DISCLOSE_ERR_MALFORMED:
		return "malformed argument";
	case FZN_DISCLOSE_ERR_SHAPE:
		return "not a committed field";
	case FZN_DISCLOSE_ERR_NO_SALT:
		return "no entropy for a salt";
	case FZN_DISCLOSE_ERR_HASH:
		return "hash refused or absent";
	case FZN_DISCLOSE_ERR_PROOF:
		return "the field is not in that root";
	}

	return "unknown";
}
