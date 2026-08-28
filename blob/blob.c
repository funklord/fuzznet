/* See blob.h. */

#include "blob.h"

#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#include <string.h>

/*
 * Domain separation, and there are three labels because there are three
 * things being hashed that must never be confusable.
 *
 * THE LEAF AND NODE PREFIXES ARE THE SECOND-PREIMAGE DEFENCE and are one
 * byte each rather than a label, because they are prepended to every node in
 * a tree that may have a billion of them. An interior node hashes 64 bytes,
 * which is a perfectly good sealed leaf of that length -- so without the
 * prefixes a shallower tree's root can be presented as a deeper tree's leaf
 * and the root still matches. The keyless verifier is the one that would
 * accept it, and the keyless verifier is what strangers use.
 *
 * They are 0x00 and 0x01, which is what RFC 6962 chose for the same problem,
 * and this library is not going to invent a third convention for a solved
 * one.
 *
 * THE KEY LABEL IS SIXTEEN BYTES like session/commitment.c's two, and for
 * the same reason: it is prepended to a derivation whose other inputs are
 * fixed-length, so nothing else in this protocol can produce the same input.
 * It is a THIRD label rather than a reuse of the root label, because a blob
 * leaf key and a session key are different keys and a transcript that
 * happened to coincide would otherwise derive both.
 */
#define FZN_BLOB_LEAF_PREFIX 0x00u
#define FZN_BLOB_NODE_PREFIX 0x01u

static const char FZN_BLOB_KEY_LABEL[16] = "fuzznet-blob-v1\0";

_Static_assert(sizeof(FZN_BLOB_KEY_LABEL) == 16,
               "the blob key label must be the fixed width the derivation assumes");
_Static_assert(FZN_BLOB_LEAF_PREFIX != FZN_BLOB_NODE_PREFIX,
               "the leaf and node prefixes must differ or the tree is second-preimage weak");

/* The derivation produces both halves in one hash, so the buffer is their
 * sum. Asserted against the two constants rather than written as 48. */
#define FZN_BLOB_DERIVED_LEN (FZN_AEAD_KEY_LEN + FZN_COMMITMENT_LEN)

/*
 * The nonce.
 *
 * DERIVED FROM THE INDEX ALONE, and it is safe here for one reason only: the
 * content key is used for exactly one blob, so each (key, index) pair occurs
 * once. blob.h says this at the caller and it is repeated here because this
 * is the line that would be read by somebody adding a second use of a key.
 *
 * The high bytes are zero rather than a counter over something else, and the
 * index goes in big-endian at the END, so the nonce is a plain 24-byte
 * big-endian integer. Nothing depends on the layout beyond its being
 * injective in the index, but a nonce whose bytes have to be explained is
 * one somebody eventually re-derives differently.
 */
static void nonce_for_index(uint64_t index, uint8_t out[FZN_AEAD_NONCE_LEN])
{
	memset(out, 0, FZN_AEAD_NONCE_LEN);
	fzn_put_be64(out + FZN_AEAD_NONCE_LEN - 8u, index);
}

fzn_blob_err_t fzn_blob_derive_leaf(const fzn_hash_ops_t *hash,
                                     const uint8_t content_key[FZN_BLOB_KEY_LEN],
                                     uint64_t index, uint8_t aead_key_out[FZN_AEAD_KEY_LEN],
                                     uint8_t commitment_out[FZN_COMMITMENT_LEN])
{
	uint8_t input[sizeof(FZN_BLOB_KEY_LABEL) + FZN_BLOB_KEY_LEN + 8u];
	uint8_t derived[FZN_BLOB_DERIVED_LEN];
	fzn_blob_err_t err = FZN_BLOB_OK;

	if (!hash || !hash->hash || !content_key || !aead_key_out || !commitment_out)
		return FZN_BLOB_ERR_MALFORMED;

	memcpy(input, FZN_BLOB_KEY_LABEL, sizeof(FZN_BLOB_KEY_LABEL));
	memcpy(input + sizeof(FZN_BLOB_KEY_LABEL), content_key, FZN_BLOB_KEY_LEN);
	fzn_put_be64(input + sizeof(FZN_BLOB_KEY_LABEL) + FZN_BLOB_KEY_LEN, index);

	if (!hash->hash(hash->ctx, derived, sizeof(derived), input, sizeof(input))) {
		err = FZN_BLOB_ERR_HASH;
		goto out;
	}

	/* Written only once the hash has succeeded, so a refused derivation
	 * cannot leave half a key where a later line will use it. */
	memcpy(aead_key_out, derived, FZN_AEAD_KEY_LEN);
	memcpy(commitment_out, derived + FZN_AEAD_KEY_LEN, FZN_COMMITMENT_LEN);

out:
	fzn_wipe(derived, sizeof(derived));
	fzn_wipe(input, sizeof(input));
	return err;
}

fzn_blob_err_t fzn_blob_leaf_seal(const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                   const uint8_t content_key[FZN_BLOB_KEY_LEN], uint64_t index,
                                   const uint8_t *plain, size_t plain_len, uint8_t *out,
                                   size_t out_cap, size_t *out_len)
{
	uint8_t key[FZN_AEAD_KEY_LEN];
	uint8_t commitment[FZN_COMMITMENT_LEN];
	uint8_t nonce[FZN_AEAD_NONCE_LEN];
	fzn_blob_err_t err;

	if (!hash || !aead || !aead->seal || !content_key || !plain || !out || !out_len)
		return FZN_BLOB_ERR_MALFORMED;
	/* NEVER EMPTY, including the final leaf. An empty last leaf would give
	 * one file two encodings -- with and without it -- and therefore two
	 * ids, which is the one thing content addressing may not have. */
	if (plain_len == 0 || plain_len > FZN_BLOB_LEAF_SIZE)
		return FZN_BLOB_ERR_MALFORMED;
	if (out_cap < plain_len + FZN_BLOB_LEAF_OVERHEAD)
		return FZN_BLOB_ERR_MALFORMED;

	err = fzn_blob_derive_leaf(hash, content_key, index, key, commitment);
	if (err != FZN_BLOB_OK)
		return err;

	memcpy(out, commitment, FZN_COMMITMENT_LEN);
	memcpy(out + FZN_COMMITMENT_LEN, plain, plain_len);
	nonce_for_index(index, nonce);

	/* THE COMMITMENT IS THE AAD as well as being carried in the clear.
	 * Without that a peer could swap one leaf's commitment for another's
	 * and the AEAD would not notice, leaving the commitment check
	 * comparing two things the sender never bound together. */
	aead->seal(aead->ctx, key, nonce, out, FZN_COMMITMENT_LEN, out + FZN_COMMITMENT_LEN,
	           plain_len, out + FZN_COMMITMENT_LEN + plain_len);

	*out_len = plain_len + FZN_BLOB_LEAF_OVERHEAD;

	fzn_wipe(key, sizeof(key));
	return FZN_BLOB_OK;
}

fzn_blob_err_t fzn_blob_leaf_open(const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                   const uint8_t content_key[FZN_BLOB_KEY_LEN], uint64_t index,
                                   const uint8_t *sealed, size_t sealed_len, uint8_t *out,
                                   size_t out_cap, size_t *out_len)
{
	uint8_t key[FZN_AEAD_KEY_LEN];
	uint8_t commitment[FZN_COMMITMENT_LEN];
	uint8_t nonce[FZN_AEAD_NONCE_LEN];
	size_t plain_len;
	fzn_blob_err_t err;

	if (!hash || !aead || !aead->open || !content_key || !sealed || !out || !out_len)
		return FZN_BLOB_ERR_MALFORMED;
	/* A PEER'S BYTES, so an impossible length is SHAPE and not MALFORMED.
	 * The distinction is the caller's: one is a bug here, the other is a
	 * stranger and is expected. */
	if (sealed_len <= FZN_BLOB_LEAF_OVERHEAD || sealed_len > FZN_BLOB_SEALED_MAX)
		return FZN_BLOB_ERR_SHAPE;

	plain_len = sealed_len - FZN_BLOB_LEAF_OVERHEAD;
	if (out_cap < plain_len)
		return FZN_BLOB_ERR_MALFORMED;

	err = fzn_blob_derive_leaf(hash, content_key, index, key, commitment);
	if (err != FZN_BLOB_OK)
		return err;

	/* BEFORE THE AEAD, and in constant time. A plain AEAD is
	 * non-committing: a ciphertext can be crafted to open validly under
	 * two keys, and a leaf that means two things is not content-addressed.
	 * Checking after would still refuse the frame, but only for whichever
	 * key the attacker did not choose. */
	if (!fzn_ct_memeq(sealed, commitment, FZN_COMMITMENT_LEN)) {
		fzn_wipe(key, sizeof(key));
		return FZN_BLOB_ERR_COMMITMENT;
	}

	memcpy(out, sealed + FZN_COMMITMENT_LEN, plain_len);
	nonce_for_index(index, nonce);

	if (!aead->open(aead->ctx, key, nonce, sealed, FZN_COMMITMENT_LEN, out, plain_len,
	                sealed + FZN_COMMITMENT_LEN + plain_len)) {
		/* The caller's buffer holds ciphertext the AEAD refused. Wiped
		 * rather than left, because a caller that ignores the return
		 * value must not find plausible-looking bytes there. */
		fzn_wipe(out, plain_len);
		fzn_wipe(key, sizeof(key));
		return FZN_BLOB_ERR_AUTH;
	}

	*out_len = plain_len;
	fzn_wipe(key, sizeof(key));
	return FZN_BLOB_OK;
}

fzn_blob_err_t fzn_blob_leaf_hash(const fzn_hash_ops_t *hash, const uint8_t *sealed,
                                   size_t sealed_len, uint8_t out[FZN_BLOB_HASH_LEN])
{
	uint8_t input[1u + FZN_BLOB_SEALED_MAX];

	if (!hash || !hash->hash || !sealed || !out)
		return FZN_BLOB_ERR_MALFORMED;
	if (sealed_len == 0 || sealed_len > FZN_BLOB_SEALED_MAX)
		return FZN_BLOB_ERR_SHAPE;

	input[0] = FZN_BLOB_LEAF_PREFIX;
	memcpy(input + 1u, sealed, sealed_len);

	if (!hash->hash(hash->ctx, out, FZN_BLOB_HASH_LEN, input, 1u + sealed_len))
		return FZN_BLOB_ERR_HASH;
	return FZN_BLOB_OK;
}

fzn_blob_err_t fzn_blob_node_hash(const fzn_hash_ops_t *hash,
                                   const uint8_t left[FZN_BLOB_HASH_LEN],
                                   const uint8_t right[FZN_BLOB_HASH_LEN],
                                   uint8_t out[FZN_BLOB_HASH_LEN])
{
	uint8_t input[1u + (2u * FZN_BLOB_HASH_LEN)];

	if (!hash || !hash->hash || !left || !right || !out)
		return FZN_BLOB_ERR_MALFORMED;

	input[0] = FZN_BLOB_NODE_PREFIX;
	memcpy(input + 1u, left, FZN_BLOB_HASH_LEN);
	memcpy(input + 1u + FZN_BLOB_HASH_LEN, right, FZN_BLOB_HASH_LEN);

	if (!hash->hash(hash->ctx, out, FZN_BLOB_HASH_LEN, input, sizeof(input)))
		return FZN_BLOB_ERR_HASH;
	return FZN_BLOB_OK;
}

void fzn_blob_tree_init(fzn_blob_tree_t *tree)
{
	if (!tree)
		return;
	memset(tree, 0, sizeof(*tree));
}

fzn_blob_err_t fzn_blob_tree_push(const fzn_hash_ops_t *hash, fzn_blob_tree_t *tree,
                                   const uint8_t leaf_hash[FZN_BLOB_HASH_LEN])
{
	fzn_blob_err_t err;

	if (!hash || !tree || !leaf_hash)
		return FZN_BLOB_ERR_MALFORMED;
	if (tree->leaves >= FZN_BLOB_MAX_LEAVES)
		return FZN_BLOB_ERR_FULL;
	if (tree->depth >= FZN_BLOB_MAX_DEPTH)
		return FZN_BLOB_ERR_FULL;

	memcpy(tree->stack[tree->depth], leaf_hash, FZN_BLOB_HASH_LEN);
	tree->level[tree->depth] = 0u;
	tree->depth++;

	/* FOLD WHILE THE TOP TWO ARE THE SAME HEIGHT, which is a binary
	 * counter: pushing 2^k leaves leaves exactly one entry, and n leaves
	 * leave one entry per set bit of n. That is the invariant `root`
	 * relies on, and it is why the stack cannot exceed the depth bound.
	 *
	 * The two entries are combined LEFT-then-RIGHT in stack order, which
	 * is what makes the result agree with the recursive definition in the
	 * test rather than mirroring it. */
	while (tree->depth >= 2u
	       && tree->level[tree->depth - 1u] == tree->level[tree->depth - 2u]) {
		err = fzn_blob_node_hash(hash, tree->stack[tree->depth - 2u],
		                         tree->stack[tree->depth - 1u],
		                         tree->stack[tree->depth - 2u]);
		if (err != FZN_BLOB_OK)
			return err;
		tree->level[tree->depth - 2u] = (uint8_t)(tree->level[tree->depth - 2u] + 1u);
		tree->depth--;
	}

	tree->leaves++;
	return FZN_BLOB_OK;
}

fzn_blob_err_t fzn_blob_tree_root(const fzn_hash_ops_t *hash, const fzn_blob_tree_t *tree,
                                   uint8_t root_out[FZN_BLOB_HASH_LEN])
{
	uint8_t acc[FZN_BLOB_HASH_LEN];
	unsigned i;
	fzn_blob_err_t err;

	if (!hash || !tree || !root_out)
		return FZN_BLOB_ERR_MALFORMED;
	/* NO LEAVES, NO ROOT. An empty blob is deliberately not addressable:
	 * the hash of nothing would give every empty file one id, shared with
	 * a tree nobody built, and there is no content to serve under it. */
	if (tree->depth == 0u)
		return FZN_BLOB_ERR_MALFORMED;

	/* FOLDED FROM THE TOP DOWN, right to left, because the stack is
	 * strictly decreasing in height: the rightmost entries are the
	 * shallowest, and an incomplete tree hangs its short subtrees on the
	 * right. Folding the other way would build a different tree over the
	 * same leaves for every n that is not a power of two. */
	memcpy(acc, tree->stack[tree->depth - 1u], FZN_BLOB_HASH_LEN);
	for (i = tree->depth - 1u; i > 0u; i--) {
		err = fzn_blob_node_hash(hash, tree->stack[i - 1u], acc, acc);
		if (err != FZN_BLOB_OK)
			return err;
	}

	memcpy(root_out, acc, FZN_BLOB_HASH_LEN);
	return FZN_BLOB_OK;
}

/*
 * The size of the left subtree of a tree over `n` leaves: the largest power
 * of two strictly less than n.
 *
 * THIS IS THE SHAPE, and it is the one thing the streaming builder and the
 * proof functions have to agree about. RFC 6962's definition, chosen for the
 * same reason the prefixes are: a solved problem with an interoperable
 * answer.
 */
static uint64_t split_at(uint64_t n)
{
	uint64_t k = 1u;

	while ((k << 1) < n)
		k <<= 1;
	return k;
}

/*
 * The root over `leaf_hashes[lo .. lo + n)`, computed by pushing them into a
 * streaming tree.
 *
 * BUILT ON `fzn_blob_tree_push` RATHER THAN ON ITS OWN RECURSION, so that
 * this library has exactly ONE definition of the tree's shape. A second
 * recursive one would agree today and be free to drift, and the whole
 * apparatus of proofs is worthless the moment the prover and the builder
 * disagree about what the tree is.
 *
 * It costs O(n) per level and so O(n log n) for a whole proof. That is the
 * seeder's cost, paid once per request, over hashes it already holds -- and
 * the alternative is caching interior nodes, which is a store rather than a
 * hash function and belongs to stage 2 if it is ever measured to matter.
 */
static fzn_blob_err_t subtree_root(const fzn_hash_ops_t *hash, const uint8_t *leaf_hashes,
                                    uint64_t lo, uint64_t n, uint8_t out[FZN_BLOB_HASH_LEN])
{
	fzn_blob_tree_t tree;
	uint64_t i;
	fzn_blob_err_t err;

	if (n == 0u)
		return FZN_BLOB_ERR_MALFORMED;

	fzn_blob_tree_init(&tree);
	for (i = 0u; i < n; i++) {
		err = fzn_blob_tree_push(hash, &tree,
		                         leaf_hashes + ((size_t)(lo + i) * FZN_BLOB_HASH_LEN));
		if (err != FZN_BLOB_OK)
			return err;
	}
	return fzn_blob_tree_root(hash, &tree, out);
}

fzn_blob_err_t fzn_blob_proof_build(const fzn_hash_ops_t *hash, const uint8_t *leaf_hashes,
                                     uint64_t leaf_count, uint64_t index, uint8_t *out,
                                     size_t out_cap, unsigned *out_count)
{
	/* The subtree currently under consideration, as [lo, lo + n). */
	uint64_t lo = 0u;
	uint64_t n = leaf_count;
	unsigned count = 0u;
	fzn_blob_err_t err;

	if (!hash || !leaf_hashes || !out || !out_count)
		return FZN_BLOB_ERR_MALFORMED;
	if (leaf_count == 0u || leaf_count > FZN_BLOB_MAX_LEAVES || index >= leaf_count)
		return FZN_BLOB_ERR_MALFORMED;

	/* DESCENDS RATHER THAN RECURSES, so the depth bound is a loop bound
	 * and there is no stack to overflow. Each step halves n, so it runs
	 * at most FZN_BLOB_MAX_DEPTH times and the guard below is a backstop
	 * against a future change rather than a live possibility. */
	while (n > 1u) {
		uint64_t k = split_at(n);
		uint8_t sibling[FZN_BLOB_HASH_LEN];

		if (count >= FZN_BLOB_MAX_DEPTH)
			return FZN_BLOB_ERR_SHAPE;
		if (out_cap < ((size_t)count + 1u) * FZN_BLOB_HASH_LEN)
			return FZN_BLOB_ERR_MALFORMED;

		if (index - lo < k) {
			/* In the left subtree; the sibling is the right one. */
			err = subtree_root(hash, leaf_hashes, lo + k, n - k, sibling);
			n = k;
		} else {
			err = subtree_root(hash, leaf_hashes, lo, k, sibling);
			lo += k;
			n -= k;
		}
		if (err != FZN_BLOB_OK)
			return err;

		memcpy(out + ((size_t)count * FZN_BLOB_HASH_LEN), sibling, FZN_BLOB_HASH_LEN);
		count++;
	}

	*out_count = count;
	return FZN_BLOB_OK;
}

fzn_blob_err_t fzn_blob_proof_verify(const fzn_hash_ops_t *hash,
                                      const uint8_t leaf_hash[FZN_BLOB_HASH_LEN], uint64_t index,
                                      uint64_t leaf_count, const uint8_t *siblings,
                                      unsigned sibling_count,
                                      const uint8_t root[FZN_BLOB_HASH_LEN])
{
	uint8_t acc[FZN_BLOB_HASH_LEN];
	uint64_t path[FZN_BLOB_MAX_DEPTH];
	unsigned depth = 0u;
	uint64_t lo = 0u;
	uint64_t n = leaf_count;
	unsigned i;
	fzn_blob_err_t err;

	if (!hash || !leaf_hash || !root)
		return FZN_BLOB_ERR_MALFORMED;
	if (leaf_count == 0u || leaf_count > FZN_BLOB_MAX_LEAVES || index >= leaf_count)
		return FZN_BLOB_ERR_MALFORMED;
	if (sibling_count > FZN_BLOB_MAX_DEPTH)
		return FZN_BLOB_ERR_SHAPE;
	if (sibling_count > 0u && !siblings)
		return FZN_BLOB_ERR_MALFORMED;

	/* THE DESCENT IS COMPUTED FROM leaf_count AND index, NOT READ FROM THE
	 * PROOF. `leaf_count` is part of the claim being verified: the shape
	 * of a tree over n leaves depends on n, so a verifier that took the
	 * path from the prover's framing would accept a leaf from a
	 * differently-shaped tree carrying the same siblings.
	 *
	 * `path[d]` records, for each level, whether the leaf was on the left
	 * (0) or the right (1), so the climb below combines in the right
	 * order. Recording it costs 40 words and removes the alternative,
	 * which is deriving left/right from the index a second time and
	 * getting it subtly different. */
	while (n > 1u) {
		uint64_t k = split_at(n);

		if (depth >= FZN_BLOB_MAX_DEPTH)
			return FZN_BLOB_ERR_SHAPE;
		if (index - lo < k) {
			path[depth] = 0u;
			n = k;
		} else {
			path[depth] = 1u;
			lo += k;
			n -= k;
		}
		depth++;
	}

	/* EXACTLY AS MANY SIBLINGS AS THE TREE HAS LEVELS. A proof with too
	 * few is short of the root; one with too many climbs past it. Either
	 * is a refusal rather than something to tolerate, because a verifier
	 * that accepts a different count accepts a different tree. */
	if (sibling_count != depth)
		return FZN_BLOB_ERR_PROOF;

	memcpy(acc, leaf_hash, FZN_BLOB_HASH_LEN);
	for (i = depth; i > 0u; i--) {
		const uint8_t *sib = siblings + ((size_t)(i - 1u) * FZN_BLOB_HASH_LEN);

		if (path[i - 1u] == 0u)
			err = fzn_blob_node_hash(hash, acc, sib, acc);
		else
			err = fzn_blob_node_hash(hash, sib, acc, acc);
		if (err != FZN_BLOB_OK)
			return err;
	}

	/* Constant time, though the root is public: the habit is what keeps
	 * `constant_time.h`'s point legible, and a comparison that is careful
	 * everywhere says nothing about which ones matter. This one is here
	 * because it is a hash comparison in a verifier, which is the shape
	 * that matters elsewhere. */
	return fzn_ct_memeq(acc, root, FZN_BLOB_HASH_LEN) ? FZN_BLOB_OK : FZN_BLOB_ERR_PROOF;
}

/* See blob.h.
 *
 * No `default:` label, so `-Wswitch` names a code added to the enum and not
 * rendered here; the fallback after the switch catches a value that is not
 * an enumerator at all, which came from a cast or from the wire. */
const char *fzn_blob_err_str(fzn_blob_err_t err)
{
	switch (err) {
	case FZN_BLOB_OK:
		return "ok";
	case FZN_BLOB_ERR_MALFORMED:
		return "malformed argument";
	case FZN_BLOB_ERR_HASH:
		return "hash or aead refused or absent";
	case FZN_BLOB_ERR_SHAPE:
		return "not this shape";
	case FZN_BLOB_ERR_COMMITMENT:
		return "key commitment mismatch";
	case FZN_BLOB_ERR_AUTH:
		return "authentication failed";
	case FZN_BLOB_ERR_PROOF:
		return "inclusion proof does not reach the root";
	case FZN_BLOB_ERR_FULL:
		return "tree is full";
	}

	return "unknown";
}
