/* A fuzz harness for the blob path: sealing, opening, the streaming tree and
 * inclusion proofs.
 *
 * WHAT IS HOSTILE HERE IS THE PROOF VERIFIER AND `fzn_blob_leaf_open`, and
 * they are hostile in a way the rest of this library is not. Every other
 * decoder here reads bytes from a peer this host has some relationship with;
 * a blob is served BY STRANGERS BY DESIGN -- that is the whole point of a
 * keyless verifier -- so a proof is a hostile input from someone with no
 * standing at all, and the module has to be correct against bytes chosen to
 * break it rather than merely malformed.
 *
 * TWO ORACLES, and they answer different questions.
 *
 *   - The ROOT oracle is `reference_root`: RFC 6962's recursive definition,
 *     which the streaming builder must equal for every leaf count. That is
 *     the same second implementation blob_test.c uses, run here against
 *     counts and orders nobody chose.
 *   - The PROOF oracle is stronger and is the reason this file exists: for
 *     any (index, leaf_count), THE ONLY SIBLING SEQUENCE THAT MAY VERIFY IS
 *     THE ONE `fzn_blob_proof_build` PRODUCES. So every accepted proof is
 *     compared against the built one, and a proof that verifies while
 *     differing from it is a forgery the harness reports rather than a
 *     coincidence it tolerates.
 *
 * That second oracle is what a spot invariant cannot give. "The verifier did
 * not crash" is satisfied by a verifier that accepts everything, and a
 * content-addressed store whose verifier accepts everything is a store that
 * serves whatever it was handed.
 */

#include "../blob.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

/* Below this a run cannot clear its own coverage floors honestly -- every
 * floor is reachable by a single lucky case -- so it refuses rather than
 * reporting a success that means nothing. Same reasoning, and the same
 * number, as the other harnesses here. */
#define FUZZ_MIN_CASES 1000u

/* The largest tree a case builds. Small on purpose: the shapes that break a
 * Merkle implementation are the incomplete ones, and they are all reachable
 * under 40 leaves. A larger bound would spend the run's time on complete
 * subtrees that differ from each other in nothing. */
#define MAX_LEAVES 40u

/* ---- stubs ------------------------------------------------------------ */

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	h ^= (uint64_t)out_len;
	h *= 0x100000001b3ull;
	for (i = 0; i < in_len; i++) {
		h ^= in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
	return 1;
}

static void stream(const uint8_t *key, const uint8_t *nonce, uint8_t *text, size_t len)
{
	uint64_t h = 0x243f6a8885a308d3ull;
	size_t i;

	for (i = 0; i < FZN_AEAD_KEY_LEN; i++) {
		h ^= key[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_AEAD_NONCE_LEN; i++) {
		h ^= nonce[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < len; i++) {
		h ^= (uint64_t)i;
		h *= 0x100000001b3ull;
		text[i] ^= (uint8_t)(h >> 24);
	}
}

static void tag_over(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad,
                     size_t aad_len, const uint8_t *text, size_t text_len,
                     uint8_t tag[FZN_AEAD_TAG_LEN])
{
	uint64_t h = 0xff51afd7ed558ccdull;
	size_t i;

	for (i = 0; i < FZN_AEAD_KEY_LEN; i++) {
		h ^= key[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_AEAD_NONCE_LEN; i++) {
		h ^= nonce[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < aad_len; i++) {
		h ^= aad[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < text_len; i++) {
		h ^= text[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_AEAD_TAG_LEN; i++) {
		h ^= (uint64_t)i + 0x2545f4914f6cdd1dull;
		h *= 0x100000001b3ull;
		tag[i] = (uint8_t)(h >> 40);
	}
}

static void stub_seal(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
                      const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad,
                      size_t aad_len, uint8_t *text, size_t text_len,
                      uint8_t tag[FZN_AEAD_TAG_LEN])
{
	(void)ctx;
	stream(key, nonce, text, text_len);
	tag_over(key, nonce, aad, aad_len, text, text_len, tag);
}

static int stub_open(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
                     const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad,
                     size_t aad_len, uint8_t *text, size_t text_len,
                     const uint8_t tag[FZN_AEAD_TAG_LEN])
{
	uint8_t want[FZN_AEAD_TAG_LEN];

	(void)ctx;
	tag_over(key, nonce, aad, aad_len, text, text_len, want);
	if (memcmp(want, tag, FZN_AEAD_TAG_LEN) != 0)
		return 0;
	stream(key, nonce, text, text_len);
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };
static const fzn_aead_ops_t AEAD = { stub_seal, stub_open, NULL };

/* ---- the oracle ------------------------------------------------------- */

static void reference_root(const uint8_t *leaves, uint64_t n, uint8_t out[FZN_BLOB_HASH_LEN])
{
	uint8_t left[FZN_BLOB_HASH_LEN];
	uint8_t right[FZN_BLOB_HASH_LEN];
	uint64_t k = 1u;

	if (n == 1u) {
		memcpy(out, leaves, FZN_BLOB_HASH_LEN);
		return;
	}
	while ((k << 1) < n)
		k <<= 1;
	reference_root(leaves, k, left);
	reference_root(leaves + ((size_t)k * FZN_BLOB_HASH_LEN), n - k, right);
	(void)fzn_blob_node_hash(&HASH, left, right, out);
}

struct coverage {
	unsigned long trees;
	unsigned long incomplete;
	unsigned long proofs_ok;
	unsigned long proofs_refused;
	unsigned long leaves_sealed;
	unsigned long opens_refused;
	unsigned long short_leaves;
	unsigned long forged_shapes;
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

/* One case. Returns non-zero when an invariant broke, having printed which. */
static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	uint8_t leaves[MAX_LEAVES * FZN_BLOB_HASH_LEN];
	uint8_t sealed[FZN_BLOB_SEALED_MAX];
	uint8_t plain[FZN_BLOB_LEAF_SIZE];
	uint8_t back[FZN_BLOB_LEAF_SIZE];
	uint8_t key[FZN_BLOB_KEY_LEN];
	uint8_t want[FZN_BLOB_HASH_LEN];
	uint8_t got[FZN_BLOB_HASH_LEN];
	uint8_t siblings[FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
	uint8_t offered[FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
	fzn_blob_tree_t tree;
	uint64_t n;
	uint64_t i;
	uint64_t index;
	unsigned count = 0;
	unsigned offered_count;
	size_t plain_len;
	size_t sealed_len = 0;
	size_t back_len = 0;

	n = 1u + (next(&state) % MAX_LEAVES);
	for (i = 0; i < sizeof(key); i++)
		key[i] = (uint8_t)next(&state);

	/* THE LEAVES ARE REAL SEALED BYTES, not filler. A harness that hashed
	 * random 32-byte strings would exercise the tree and never the seam
	 * between sealing and hashing -- which is where a length or an
	 * overhead constant goes wrong. */
	fzn_blob_tree_init(&tree);
	for (i = 0; i < n; i++) {
		plain_len = 1u + (size_t)(next(&state) % FZN_BLOB_LEAF_SIZE);
		if (plain_len < FZN_BLOB_LEAF_SIZE)
			cov->short_leaves++;
		for (size_t j = 0; j < plain_len; j++)
			plain[j] = (uint8_t)next(&state);

		if (fzn_blob_leaf_seal(&HASH, &AEAD, key, i, plain, plain_len, sealed,
		                       sizeof(sealed), &sealed_len) != FZN_BLOB_OK) {
			printf("  INVARIANT: sealing leaf %llu of %llu refused\n",
			       (unsigned long long)i, (unsigned long long)n);
			return 1;
		}
		cov->leaves_sealed++;

		if (fzn_blob_leaf_open(&HASH, &AEAD, key, i, sealed, sealed_len, back,
		                       sizeof(back), &back_len) != FZN_BLOB_OK
		    || back_len != plain_len || memcmp(back, plain, plain_len) != 0) {
			printf("  INVARIANT: a leaf this library sealed does not open\n");
			return 1;
		}

		/* A LEAF NEVER OPENS AT ANOTHER INDEX, which is the property
		 * that makes reordering a blob impossible rather than merely
		 * detectable at the root. */
		if (i > 0u
		    && fzn_blob_leaf_open(&HASH, &AEAD, key, i - 1u, sealed, sealed_len, back,
		                          sizeof(back), &back_len) == FZN_BLOB_OK) {
			printf("  INVARIANT: leaf %llu opened at index %llu\n",
			       (unsigned long long)i, (unsigned long long)(i - 1u));
			return 1;
		}
		if (i > 0u)
			cov->opens_refused++;

		if (fzn_blob_leaf_hash(&HASH, sealed, sealed_len,
		                       leaves + ((size_t)i * FZN_BLOB_HASH_LEN)) != FZN_BLOB_OK) {
			printf("  INVARIANT: hashing a sealed leaf refused\n");
			return 1;
		}
		if (fzn_blob_tree_push(&HASH, &tree,
		                       leaves + ((size_t)i * FZN_BLOB_HASH_LEN)) != FZN_BLOB_OK) {
			printf("  INVARIANT: pushing leaf %llu refused\n", (unsigned long long)i);
			return 1;
		}
	}

	cov->trees++;
	if ((n & (n - 1u)) != 0u)
		cov->incomplete++;

	reference_root(leaves, n, want);
	if (fzn_blob_tree_root(&HASH, &tree, got) != FZN_BLOB_OK
	    || memcmp(want, got, FZN_BLOB_HASH_LEN) != 0) {
		printf("  INVARIANT: the streaming root and the definition disagree at "
		       "%llu leaves\n", (unsigned long long)n);
		return 1;
	}

	index = next(&state) % n;
	if (fzn_blob_proof_build(&HASH, leaves, n, index, siblings, sizeof(siblings), &count)
	    != FZN_BLOB_OK) {
		printf("  INVARIANT: building a proof for leaf %llu of %llu refused\n",
		       (unsigned long long)index, (unsigned long long)n);
		return 1;
	}
	if (fzn_blob_proof_verify(&HASH, leaves + ((size_t)index * FZN_BLOB_HASH_LEN), index, n,
	                          siblings, count, want) != FZN_BLOB_OK) {
		printf("  INVARIANT: a built proof does not verify\n");
		return 1;
	}
	cov->proofs_ok++;

	/* THE FORGERY ATTEMPT, and it is the point of the file. A sibling
	 * sequence chosen by the generator is offered against the real root.
	 * The only sequence that may verify is the built one -- anything else
	 * accepted is a second proof for the same leaf, which is a forgery
	 * whatever the arithmetic says. */
	offered_count = (unsigned)(next(&state) % (FZN_BLOB_MAX_DEPTH + 2u));
	for (i = 0; i < (uint64_t)offered_count * FZN_BLOB_HASH_LEN && i < sizeof(offered); i++)
		offered[i] = (uint8_t)next(&state);

	/* Half the time, start from the real proof and bend one byte, which
	 * reaches the near misses a fully random sequence never will: a
	 * generator that only ever offers noise tests the length check and
	 * nothing below it. */
	if ((next(&state) & 1u) != 0u && count > 0u) {
		offered_count = count;
		memcpy(offered, siblings, (size_t)count * FZN_BLOB_HASH_LEN);
		i = next(&state) % ((uint64_t)count * FZN_BLOB_HASH_LEN);
		offered[i] = (uint8_t)(offered[i] ^ (1u << (next(&state) % 8u)));
	}

	if (offered_count <= FZN_BLOB_MAX_DEPTH) {
		/* THE OFFERED PROOF IS PLACED FLUSH AGAINST THE END OF THE
		 * BUFFER, so that a verifier reading one sibling too many runs
		 * off the array and a sanitizer says so.
		 *
		 * Found by mutating the verifier. `sibling_count != depth` is
		 * not only a strictness check: the climb indexes
		 * `siblings[depth - 1]` downwards, so a proof SHORTER than the
		 * tree is deep reads past whatever the caller passed. Relaxing
		 * it to `sibling_count > depth` left this harness reporting no
		 * invariant broken -- because the buffer was always the
		 * maximum size, and a read past the offered proof landed in
		 * the same array. The harness could not express the fault.
		 *
		 * Flush placement costs one pointer and makes the over-read a
		 * real one. It is the same instrument as a guard page and
		 * needs no allocator, which this tree does not use. */
		uint8_t *at_edge = offered + sizeof(offered)
		                   - ((size_t)offered_count * FZN_BLOB_HASH_LEN);
		int accepted;
		int is_the_built_one;

		memmove(at_edge, offered, (size_t)offered_count * FZN_BLOB_HASH_LEN);
		accepted = fzn_blob_proof_verify(&HASH,
		                                 leaves + ((size_t)index * FZN_BLOB_HASH_LEN),
		                                 index, n, at_edge, offered_count, want)
		           == FZN_BLOB_OK;
		is_the_built_one = (offered_count == count)
		                   && memcmp(at_edge, siblings,
		                             (size_t)count * FZN_BLOB_HASH_LEN) == 0;

		if (accepted && !is_the_built_one) {
			printf("  INVARIANT: a sibling sequence other than the built proof "
			       "verified for leaf %llu of %llu\n", (unsigned long long)index,
			       (unsigned long long)n);
			return 1;
		}
		if (!accepted)
			cov->proofs_refused++;
		if (!is_the_built_one)
			cov->forged_shapes++;
	}

	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0 };

	for (i = 0; i < size; i++)
		seed = (seed * 31u) + data[i];
	if (seed == 0u)
		seed = 1u;
	(void)fuzz_one(seed, &cov);
	return 0;
}
#else

/* A floor that never returns zero, so lowering CASES cannot silently switch
 * the coverage checks off -- which is exactly what somebody does when a run
 * is slow, and exactly when a harness stops proving what it says. */
static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long f = cases / per;

	return f == 0u ? 1u : f;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned long c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}

	if (cases < FUZZ_MIN_CASES) {
		printf("blob_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will "
		       "not report success -- every coverage floor below that is cleared by "
		       "a single lucky hit. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("blob_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* THE FLOORS ARE ON STATES, NOT ON CALLS. A run that built only
	 * complete trees has not tested the fold at all; one that never
	 * offered a sequence differing from the built proof has not tested
	 * the forgery invariant, however many proofs it verified; and one
	 * whose leaves were all full length never exercised the short final
	 * leaf, which is the only place a length is not a constant. */
	if (cov.incomplete < floor_of(cases, 4u) || cov.proofs_ok < floor_of(cases, 2u)
	    || cov.proofs_refused < floor_of(cases, 4u) || cov.forged_shapes < floor_of(cases, 4u)
	    || cov.short_leaves < floor_of(cases, 4u) || cov.opens_refused < floor_of(cases, 4u)) {
		printf("blob_fuzz: REACHED TOO LITTLE -- %lu trees, %lu incomplete, "
		       "%lu proofs verified, %lu refused, %lu forged shapes, %lu short "
		       "leaves, %lu cross-index opens refused in %lu cases.\n",
		       cov.trees, cov.incomplete, cov.proofs_ok, cov.proofs_refused,
		       cov.forged_shapes, cov.short_leaves, cov.opens_refused, cases);
		return 1;
	}

	printf("blob_fuzz: %lu cases, %lu trees (%lu incomplete), %lu leaves sealed "
	       "(%lu short), %lu cross-index opens refused, %lu proofs verified, "
	       "%lu refused, %lu forged shapes, no invariant broken\n",
	       cases, cov.trees, cov.incomplete, cov.leaves_sealed, cov.short_leaves,
	       cov.opens_refused, cov.proofs_ok, cov.proofs_refused, cov.forged_shapes);
	return 0;
}
#endif
