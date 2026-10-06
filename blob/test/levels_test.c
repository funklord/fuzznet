/* Tests for blob/levels.c: a blob's tree kept outside memory. sec 490.
 *
 * THE ORACLE IS `fzn_blob_span_proof_build` over the same leaf hashes in an
 * array -- the builder every receiver's proofs have been checked against
 * since sec 103 -- so a proof read from the levels must be byte for byte the
 * one the array gives, for every canonical span of every tree size tried.
 * The two share the descent; what differs, and what is being tested, is
 * where each subtree's root comes from: hashed from the array, or read from
 * the levels where it is perfect and folded where it is not.
 *
 * THE STUB HASH IS A MIXING FUNCTION, as blob_test.c's is: what is asked is
 * whether the right bytes reached the right call, not whether the hash is a
 * hash.
 */

#include "../levels.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL levels_test.c:%d: %s\n", __LINE__, what);       \
		}                                                                              \
	} while (0)

static int mix(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint32_t h = 2166136261u ^ (uint32_t)out_len;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++)
		h = (h ^ in[i]) * 16777619u;
	for (i = 0; i < out_len; i++) {
		h = (h ^ (uint32_t)i) * 16777619u;
		out[i] = (uint8_t)(h >> 13);
	}
	/* NONZERO ON SUCCESS, as the seam's real ops return. */
	return 1;
}

static const fzn_hash_ops_t HASH = { mix, NULL };

/* LEVELS IN A BUFFER, with a write that can be made to refuse. */
#define MAX_LEAVES 1100u
static uint8_t store[2u * MAX_LEAVES * FZN_BLOB_HASH_LEN];
static uint64_t high;
static int refuse_reads;

static int mem_read(void *ctx, uint64_t offset, uint8_t *out, size_t len)
{
	(void)ctx;
	if (refuse_reads || offset + len > sizeof(store))
		return 0;
	memcpy(out, store + offset, len);
	return 1;
}

static int mem_write(void *ctx, uint64_t offset, const uint8_t *in, size_t len)
{
	(void)ctx;
	if (offset + len > sizeof(store))
		return 0;
	memcpy(store + offset, in, len);
	if (offset + len > high)
		high = offset + len;
	return 1;
}

static const fzn_blob_levels_io_t IO = { mem_read, mem_write, NULL };
static uint8_t leaf_hashes[MAX_LEAVES][FZN_BLOB_HASH_LEN];

/* Every canonical span of a tree of `n` leaves -- or, past `every`, those of
 * count 1 and of each power of two at every start -- compared with the
 * array's proof. Returns the spans compared, 0 on the first difference. */
static size_t compare(uint64_t n, uint64_t every)
{
	static uint8_t a[FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN], b[sizeof(a)];
	fzn_blob_levels_builder_t builder;
	fzn_blob_levels_t levels = { &HASH, &IO, n };
	uint64_t i, first, count;
	size_t compared = 0;

	for (i = 0; i < n; i++)
		mix(NULL, leaf_hashes[i], FZN_BLOB_HASH_LEN, (const uint8_t *)&i, sizeof(i));
	memset(store, 0, sizeof(store));
	high = 0;
	if (fzn_blob_levels_begin(&builder, n) != FZN_BLOB_OK)
		return 0;
	for (i = 0; i < n; i++)
		if (fzn_blob_levels_push(&HASH, &builder, &IO, leaf_hashes[i]) != FZN_BLOB_OK)
			return 0;
	/* EXACTLY THE BYTES STATED, and no node past them. */
	if (high != fzn_blob_levels_bytes(n))
		return 0;
	for (first = 0; first < n; first++)
		for (count = 1; count <= n - first; count++) {
			unsigned ca = 0, cb = 0;

			if (n > every && count != 1u && (count & (count - 1u)) != 0u)
				continue;
			if (!fzn_blob_span_is_canonical(n, first, count))
				continue;
			if (fzn_blob_span_proof_build(&HASH, (const uint8_t *)leaf_hashes, n, first,
			                              count, a, sizeof(a), &ca) != FZN_BLOB_OK
			    || fzn_blob_levels_span_proof(&levels, first, count, b, sizeof(b), &cb)
			               != FZN_BLOB_OK
			    || ca != cb || memcmp(a, b, (size_t)ca * FZN_BLOB_HASH_LEN) != 0)
				return 0;
			compared++;
		}
	/* THE APEX OVER EVERYTHING, and each leaf as level 0 holds it. */
	{
		uint8_t whole[FZN_BLOB_HASH_LEN], read[FZN_BLOB_HASH_LEN];

		if (fzn_blob_span_root(&HASH, (const uint8_t *)leaf_hashes, n, whole) != FZN_BLOB_OK
		    || fzn_blob_levels_subtree(&levels, 0, n, read) != FZN_BLOB_OK
		    || memcmp(whole, read, sizeof(whole)) != 0
		    || fzn_blob_levels_leaf(&levels, n - 1u, read) != FZN_BLOB_OK
		    || memcmp(read, leaf_hashes[n - 1u], sizeof(read)) != 0)
			return 0;
	}
	return compared;
}

int main(void)
{
	static const uint64_t LARGER[] = { 255, 256, 257, 511, 1000, 1023, 1024, 1025 };
	fzn_blob_levels_builder_t builder;
	fzn_blob_levels_t levels = { &HASH, &IO, 5 };
	uint8_t out[FZN_BLOB_HASH_LEN];
	uint64_t n;
	size_t i, total = 0;
	int all = 1;

	/* EVERY CANONICAL SPAN of every tree of 1 to 130 leaves. */
	for (n = 1; n <= 130u && all; n++) {
		size_t c = compare(n, 130u);

		all = c != 0u;
		total += c;
	}
	CHECK(all, "a proof read from the levels differs from the array's, for a tree of 1 to 130");
	CHECK(total > 5000u, "fewer spans compared than the trees hold");
	for (i = 0, all = 1; i < sizeof(LARGER) / sizeof(LARGER[0]) && all; i++)
		all = compare(LARGER[i], 130u) != 0u;
	CHECK(all, "a leaf's or a power-of-two span's proof differs, for a tree up to 1025");

	CHECK(fzn_blob_levels_bytes(1) == FZN_BLOB_HASH_LEN
	              && fzn_blob_levels_bytes(5) == (5u + 2u + 1u) * FZN_BLOB_HASH_LEN
	              && fzn_blob_levels_bytes(0) == 0u
	              && fzn_blob_levels_bytes(FZN_BLOB_MAX_LEAVES + 1u) == 0u,
	      "the levels' size is not the perfect nodes of every level");

	/* REFUSALS: past the count begun with, a read refused, a range out. */
	CHECK(fzn_blob_levels_begin(&builder, 1) == FZN_BLOB_OK
	              && fzn_blob_levels_push(&HASH, &builder, &IO, leaf_hashes[0]) == FZN_BLOB_OK
	              && fzn_blob_levels_push(&HASH, &builder, &IO, leaf_hashes[1])
	                         == FZN_BLOB_ERR_FULL,
	      "a leaf past the count begun with was taken");
	(void)compare(5, 130u);
	refuse_reads = 1;
	CHECK(fzn_blob_levels_subtree(&levels, 0, 4, out) == FZN_BLOB_ERR_IO,
	      "a read the storage refused was not said");
	refuse_reads = 0;
	CHECK(fzn_blob_levels_subtree(&levels, 3, 3, out) == FZN_BLOB_ERR_MALFORMED
	              && fzn_blob_levels_leaf(&levels, 5, out) == FZN_BLOB_ERR_MALFORMED,
	      "a range past the leaves was read");

	if (failures) {
		fprintf(stderr, "levels_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("levels_test: all %d checks passed\n", checks);
	return 0;
}
