/* Tests for spool/spool.c: placing verified leaves, and resuming.
 *
 * THE BACKEND HERE COUNTS AND CAN REFUSE, which is what lets this file ask
 * the two questions that matter and which a round trip cannot: does an
 * unverified leaf reach the disk at all, and does a failed write leave the
 * bitmap claiming a leaf is present. Both are silent in a working run and
 * both turn a transfer into a corrupt blob rather than an error.
 */

#include "../spool.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL spool_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)
#define REQUIRE(cond, ...)                                   \
	do {                                                 \
		int require_ok = (cond) ? 1 : 0;             \
		check_at(require_ok, __LINE__, __VA_ARGS__); \
		if (!require_ok)                             \
			return;                              \
	} while (0)

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

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

/* ---- a backend that counts, and can be made to refuse ------------------ */

#define TEST_LEAVES 6u

static struct {
	uint8_t bytes[TEST_LEAVES * FZN_BLOB_SEALED_MAX];
	unsigned writes;
	unsigned reads;
	int refuse_writes;
} disk;

static int mem_read(void *ctx, uint64_t off, uint8_t *out, size_t len)
{
	(void)ctx;
	if (off + len > sizeof(disk.bytes))
		return 0;
	disk.reads++;
	memcpy(out, disk.bytes + off, len);
	return 1;
}

static int mem_write(void *ctx, uint64_t off, const uint8_t *bytes, size_t len)
{
	(void)ctx;
	if (disk.refuse_writes)
		return 0;
	if (off + len > sizeof(disk.bytes))
		return 0;
	disk.writes++;
	memcpy(disk.bytes + off, bytes, len);
	return 1;
}

static int mem_sync(void *ctx)
{
	(void)ctx;
	return 1;
}

static const fzn_spool_ops_t OPS = { mem_read, mem_write, mem_sync, NULL };

/* ---- a real little blob ----------------------------------------------- */

static uint8_t sealed[TEST_LEAVES][FZN_BLOB_SEALED_MAX];
static size_t sealed_len[TEST_LEAVES];
static uint8_t leaf_hash[TEST_LEAVES][FZN_BLOB_HASH_LEN];
static uint8_t root[FZN_BLOB_HASH_LEN];
static uint8_t proof[TEST_LEAVES][FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
static unsigned proof_len[TEST_LEAVES];

/* Leaves are plain bytes here rather than AEAD output: the store verifies
 * against the tree and never opens anything, so what it holds only has to be
 * a leaf the tree commits to. `blob/test/blob_test.c` is where sealing is
 * exercised. */
static int build_blob(void)
{
	fzn_blob_tree_t tree;
	unsigned i;

	fzn_blob_tree_init(&tree);
	for (i = 0; i < TEST_LEAVES; i++) {
		size_t j;

		/* ONE LEAF IS FULL-LENGTH, deliberately. A slot is
		 * FZN_BLOB_SEALED_MAX wide and a short leaf has its tail
		 * filled, so a fixture whose leaves are ALL short cannot tell
		 * the fill apart from the leaf write -- and one whose leaves
		 * are all full cannot see the fill at all. The mixture is what
		 * lets the write counts below discriminate. */
		sealed_len[i] = (i == 2u) ? (size_t)FZN_BLOB_SEALED_MAX : 64u + i;
		for (j = 0; j < sealed_len[i]; j++)
			sealed[i][j] = (uint8_t)((i * 37u) + j + 1u);
		if (fzn_blob_leaf_hash(&HASH, sealed[i], sealed_len[i], leaf_hash[i])
		    != FZN_BLOB_OK)
			return 0;
		if (fzn_blob_tree_push(&HASH, &tree, leaf_hash[i]) != FZN_BLOB_OK)
			return 0;
	}
	if (fzn_blob_tree_root(&HASH, &tree, root) != FZN_BLOB_OK)
		return 0;
	for (i = 0; i < TEST_LEAVES; i++) {
		if (fzn_blob_proof_build(&HASH, leaf_hash[0], TEST_LEAVES, i, proof[i],
		                         sizeof(proof[i]), &proof_len[i]) != FZN_BLOB_OK)
			return 0;
	}
	return 1;
}

/* Derived from the fixture rather than written out, so that changing a
 * leaf's length cannot leave a hand-typed constant asserting the old shape:
 * one write for the leaf, and a second only where the slot needs filling. */
static unsigned expected_writes(unsigned upto)
{
	unsigned i, n = 0;

	for (i = 0; i < upto; i++)
		n += (sealed_len[i] < FZN_BLOB_SEALED_MAX) ? 2u : 1u;
	return n;
}

static void reset(fzn_spool_t *spool, uint8_t *map, size_t map_len)
{
	memset(&disk, 0, sizeof(disk));
	memset(map, 0, map_len);
	(void)fzn_spool_open(spool, root, TEST_LEAVES, map, map_len, &OPS);
}

/* ---- the cases -------------------------------------------------------- */

static void test_leaves_arrive_in_any_order(void)
{
	fzn_spool_t spool;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];
	static const unsigned ORDER[TEST_LEAVES] = { 4u, 0u, 5u, 2u, 1u, 3u };
	unsigned n;

	REQUIRE(build_blob(), "the blob fixture does not build");
	reset(&spool, map, sizeof(map));

	/* OUT OF ORDER IS THE ORDINARY CASE, not an edge one -- a datagram
	 * transport delivers however it likes, and a store that needed order
	 * would have to buffer everything until the gaps closed. */
	for (n = 0; n < TEST_LEAVES; n++) {
		unsigned i = ORDER[n];

		CHECK(fzn_spool_place(&spool, &HASH, i, sealed[i], sealed_len[i], proof[i],
		                      proof_len[i]) == FZN_SPOOL_OK,
		      "placing leaf %u out of order was refused", i);
		CHECK(fzn_spool_has(&spool, i), "leaf %u is not recorded as present", i);
	}
	CHECK(fzn_spool_complete(&spool), "the blob is not complete after every leaf arrived");
	CHECK(disk.writes == expected_writes(TEST_LEAVES), "%u writes for %u leaves, expected %u",
	      disk.writes, (unsigned)TEST_LEAVES, expected_writes(TEST_LEAVES));
}

static void test_an_unverified_leaf_never_reaches_the_disk(void)
{
	fzn_spool_t spool;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];
	uint8_t forged[FZN_BLOB_SEALED_MAX];

	REQUIRE(build_blob(), "the blob fixture does not build");
	reset(&spool, map, sizeof(map));

	memset(forged, 0xEE, sizeof(forged));

	/* THE PROPERTY THAT MAKES THIS SAFE TO POINT AT A STRANGER. A store
	 * that wrote first and verified later would let anyone fill a disk
	 * with bytes that fail to assemble -- and "later" is after the disk
	 * is full. Asserted on the WRITE COUNT rather than on the return
	 * code, because a refusal that had already written is still a
	 * refusal. */
	CHECK(fzn_spool_place(&spool, &HASH, 2u, forged, 64u, proof[2], proof_len[2])
	              == FZN_SPOOL_ERR_UNVERIFIED,
	      "a leaf that does not verify was accepted");
	CHECK(disk.writes == 0u,
	      "an unverified leaf reached the disk: %u write(s), so a stranger can fill it",
	      disk.writes);
	CHECK(!fzn_spool_has(&spool, 2u), "an unverified leaf was recorded as present");

	/* A GENUINE LEAF AT THE WRONG INDEX IS ALSO UNVERIFIED, which is the
	 * reordering a content-addressed store must refuse rather than
	 * merely notice at the end. */
	CHECK(fzn_spool_place(&spool, &HASH, 3u, sealed[2], sealed_len[2], proof[2],
	                      proof_len[2]) == FZN_SPOOL_ERR_UNVERIFIED,
	      "a genuine leaf placed at another index was accepted");
	CHECK(disk.writes == 0u, "a misplaced leaf reached the disk");
}

static void test_a_failed_write_does_not_claim_the_leaf(void)
{
	fzn_spool_t spool;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];
	uint64_t missing = 0;

	REQUIRE(build_blob(), "the blob fixture does not build");
	reset(&spool, map, sizeof(map));

	disk.refuse_writes = 1;
	CHECK(fzn_spool_place(&spool, &HASH, 1u, sealed[1], sealed_len[1], proof[1],
	                      proof_len[1]) == FZN_SPOOL_ERR_BACKEND,
	      "a refused write was reported as success");

	/* THE BIT MUST NOT BE SET. A bit over a failed write is a hole the
	 * store will never fill: `next_missing` skips it, nothing re-requests
	 * it, and the transfer reports complete over a corrupt blob. */
	CHECK(!fzn_spool_has(&spool, 1u),
	      "a leaf whose write failed is recorded as present, so it will never be "
	      "re-requested and the blob will complete corrupt");
	CHECK(fzn_spool_next_missing(&spool, 0, &missing) == FZN_SPOOL_OK && missing == 0u,
	      "the gap walk lost track after a failed write");

	disk.refuse_writes = 0;
	CHECK(fzn_spool_place(&spool, &HASH, 1u, sealed[1], sealed_len[1], proof[1],
	                      proof_len[1]) == FZN_SPOOL_OK,
	      "the retry after a transient failure was refused");
	CHECK(fzn_spool_has(&spool, 1u), "the retry did not take");
}

static void test_a_duplicate_is_free(void)
{
	fzn_spool_t spool;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];

	REQUIRE(build_blob(), "the blob fixture does not build");
	reset(&spool, map, sizeof(map));

	/* LEAF 2, the full-length one, so that "one write" means the leaf and
	 * nothing else -- with a short leaf this would be two and the
	 * duplicate check below would be reading a number it had to explain. */
	CHECK(fzn_spool_place(&spool, &HASH, 2u, sealed[2], sealed_len[2], proof[2],
	                      proof_len[2]) == FZN_SPOOL_OK, "the first placement refused");
	CHECK(disk.writes == 1u, "the first placement did not write");
	CHECK(fzn_spool_place(&spool, &HASH, 2u, sealed[2], sealed_len[2], proof[2],
	                      proof_len[2]) == FZN_SPOOL_OK, "a duplicate was refused");
	/* Duplicates are ordinary on a lossy transport. Rewriting would turn
	 * every one into disk traffic, and re-verifying would let a flood buy
	 * the hashing. */
	CHECK(disk.writes == 1u, "a duplicate was written again: %u writes", disk.writes);
	CHECK(spool.have == 1u, "a duplicate was counted twice");

	/* A SHORT LEAF TAKES TWO WRITES AND ITS DUPLICATE TAKES NONE. Both
	 * halves matter: the first says the slot is filled at all, the second
	 * that a flood of duplicates cannot buy the extra write either. */
	CHECK(fzn_spool_place(&spool, &HASH, 0u, sealed[0], sealed_len[0], proof[0],
	                      proof_len[0]) == FZN_SPOOL_OK, "a short leaf was refused");
	CHECK(disk.writes == 3u, "a short leaf did not fill its slot: %u writes", disk.writes);
	CHECK(fzn_spool_place(&spool, &HASH, 0u, sealed[0], sealed_len[0], proof[0],
	                      proof_len[0]) == FZN_SPOOL_OK, "a short duplicate was refused");
	CHECK(disk.writes == 3u, "a short duplicate was written again: %u writes", disk.writes);
}

static void test_resume_recounts_from_the_bits(void)
{
	fzn_spool_t first, resumed;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];
	uint64_t missing = 0;

	REQUIRE(build_blob(), "the blob fixture does not build");
	reset(&first, map, sizeof(map));

	CHECK(fzn_spool_place(&first, &HASH, 0u, sealed[0], sealed_len[0], proof[0],
	                      proof_len[0]) == FZN_SPOOL_OK, "refused");
	CHECK(fzn_spool_place(&first, &HASH, 3u, sealed[3], sealed_len[3], proof[3],
	                      proof_len[3]) == FZN_SPOOL_OK, "refused");

	/* THE RESUME PATH: the same bitmap, a fresh spool, no stored count.
	 * `open` recomputes `have` from the bits, so a torn pair -- a count
	 * saying complete over a bitmap that is not -- cannot be restored. */
	REQUIRE(fzn_spool_open(&resumed, root, TEST_LEAVES, map, sizeof(map), &OPS)
	                == FZN_SPOOL_OK, "resuming refused");
	CHECK(resumed.have == 2u, "the resumed spool counted %llu leaves, wanted 2",
	      (unsigned long long)resumed.have);
	CHECK(fzn_spool_has(&resumed, 0u) && fzn_spool_has(&resumed, 3u),
	      "the resumed spool lost what the bitmap said it had");
	CHECK(!fzn_spool_complete(&resumed), "a partial spool reported complete");

	/* And the gaps are walkable without asking about every index. */
	CHECK(fzn_spool_next_missing(&resumed, 0, &missing) == FZN_SPOOL_OK && missing == 1u,
	      "the first gap is %llu, wanted 1", (unsigned long long)missing);
	CHECK(fzn_spool_next_missing(&resumed, 4u, &missing) == FZN_SPOOL_OK && missing == 4u,
	      "the walk skipped a gap at 4");
}

static void test_the_ceiling_is_refused_before_anything_is_touched(void)
{
	fzn_spool_t spool;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];

	REQUIRE(build_blob(), "the blob fixture does not build");

	/* A PEER'S NUMBER, refused at open rather than at the first write, so
	 * a claimed blob of a trillion leaves costs a comparison instead of a
	 * bitmap. */
	CHECK(fzn_spool_open(&spool, root, (uint64_t)FZN_SPOOL_MAX_LEAVES + 1u, map,
	                     sizeof(map), &OPS) == FZN_SPOOL_ERR_TOO_LARGE,
	      "a blob past the ceiling was opened");
	CHECK(fzn_spool_open(&spool, root, 0, map, sizeof(map), &OPS) == FZN_SPOOL_ERR_MALFORMED,
	      "a blob of no leaves was opened");
	/* A bitmap too small for the blob it is asked to track is the caller's
	 * bug and must not be written past. */
	CHECK(fzn_spool_open(&spool, root, TEST_LEAVES, map, 0, &OPS) == FZN_SPOOL_ERR_MALFORMED,
	      "a bitmap too small for the blob was accepted");

	reset(&spool, map, sizeof(map));
	CHECK(fzn_spool_place(&spool, &HASH, TEST_LEAVES, sealed[0], sealed_len[0], proof[0],
	                      proof_len[0]) == FZN_SPOOL_ERR_TOO_LARGE,
	      "a leaf index past the blob was accepted");

	/* THE OTHER NUMBER A PEER CHOOSES, and it had no test. The index
	 * ceiling above is driven; the LENGTH ceiling beside it was not, even
	 * though `sealed_len` arrives on the wire exactly as `index` does. A
	 * length of zero and a length past what a leaf can be are both refused
	 * before the hash seam is called, which is the same argument the index
	 * check is made on -- a peer's number should cost a comparison. */
	CHECK(fzn_spool_place(&spool, &HASH, 0u, sealed[0], 0u, proof[0],
	                      proof_len[0]) == FZN_SPOOL_ERR_UNVERIFIED,
	      "a leaf claiming no bytes was accepted");
	CHECK(fzn_spool_place(&spool, &HASH, 0u, sealed[0],
	                      (size_t)FZN_BLOB_SEALED_MAX + 1u, proof[0],
	                      proof_len[0]) == FZN_SPOOL_ERR_UNVERIFIED,
	      "a leaf longer than a leaf can be was accepted");
	/* AND NEITHER CLAIMED THE SLOT. A refusal that marked the bitmap would
	 * lose the leaf for good, since a spool never asks twice. */
	CHECK(fzn_spool_has(&spool, 0u) == 0,
	      "a refused length still claimed the leaf");
}

/* THE TERMINAL ANSWER, which the header describes and nothing drove.
 * `spool.h` says `fzn_spool_next_missing` returns FZN_SPOOL_ERR_ABSENT "when
 * there are none left, which is how a caller walks" the gaps -- so it is the
 * loop condition of every consumer that fetches a blob, and every existing
 * test stopped while a gap remained. A walk whose termination is untested is
 * a walk nobody has seen end. */
static void test_the_walk_over_gaps_ends(void)
{
	fzn_spool_t spool;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];
	uint64_t want = 0u;
	unsigned i, seen = 0u;

	REQUIRE(build_blob(), "the blob fixture does not build");
	reset(&spool, map, sizeof(map));

	/* Walk from empty to full, following the module's own answer rather
	 * than counting independently -- if `next_missing` is wrong about
	 * which leaf is absent, this loop stops early or never stops. */
	while (fzn_spool_next_missing(&spool, 0u, &want) == FZN_SPOOL_OK) {
		REQUIRE(want < TEST_LEAVES, "a gap outside the blob was named");
		CHECK(fzn_spool_place(&spool, &HASH, (uint64_t)want, sealed[want],
		                      sealed_len[want], proof[want],
		                      proof_len[want]) == FZN_SPOOL_OK,
		      "the leaf the walk named was refused");
		seen++;
		if (seen > TEST_LEAVES)
			break;
	}
	CHECK(seen == TEST_LEAVES,
	      "the walk did not name every leaf exactly once");
	CHECK(fzn_spool_complete(&spool) == 1,
	      "the blob is not complete after the walk filled it");

	/* AND NOW THE ANSWER THE HEADER PROMISES. */
	want = 0xdeadbeefu;
	CHECK(fzn_spool_next_missing(&spool, 0u, &want) == FZN_SPOOL_ERR_ABSENT,
	      "a complete spool still reported a gap");

	/* Also from a start past the last gap, which is the other way a caller
	 * reaches the end -- resuming a walk rather than beginning one. */
	reset(&spool, map, sizeof(map));
	for (i = 0; i < TEST_LEAVES; i++)
		REQUIRE(fzn_spool_place(&spool, &HASH, i, sealed[i], sealed_len[i],
		                        proof[i], proof_len[i]) == FZN_SPOOL_OK,
		        "filling for the resume case");
	CHECK(fzn_spool_next_missing(&spool, TEST_LEAVES - 1u, &want) ==
	      FZN_SPOOL_ERR_ABSENT,
	      "a walk resumed past the last gap reported one");
}

/* Out-of-range reads and queries, which the two accessors refuse and nothing
 * asked them to. `place` has its ceiling tested above; these two share the
 * bound and did not. */
static void test_an_index_past_the_blob_is_refused(void)
{
	fzn_spool_t spool;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES) + 1u];
	uint8_t back[FZN_BLOB_SEALED_MAX];
	size_t back_len = 0u;

	REQUIRE(build_blob(), "the blob fixture does not build");
	reset(&spool, map, FZN_SPOOL_BITMAP_LEN(TEST_LEAVES));

	CHECK(fzn_spool_read(&spool, TEST_LEAVES, back, sizeof(back), &back_len) ==
	      FZN_SPOOL_ERR_TOO_LARGE,
	      "reading past the blob was accepted");
	CHECK(fzn_spool_has(&spool, TEST_LEAVES) == 0,
	      "a leaf past the blob was reported present");

	/* AND ONE FAR ENOUGH PAST TO LEAVE THE BITMAP, which the line above
	 * is not.
	 *
	 * TEST_LEAVES is 6 and the bitmap is one byte, so `bit_get(map, 6)`
	 * reads `map[0] >> 6` -- inside the array, zero after `reset`, and the
	 * assertion above passes with the bound deleted. Measured 2026-09-03:
	 * it left the whole suite green.
	 *
	 * Index 8 is the first that addresses a second byte. The array carries
	 * one, set to 0xff AFTER `reset` has zeroed the map, so the answer
	 * without the bound is 1 rather than whatever the stack held -- a
	 * caught mutation rather than a coin toss. `present` is a buffer the
	 * caller lends, and this bound is the only thing keeping `bit_get`
	 * inside it. */
	map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)] = 0xffu;
	CHECK(fzn_spool_has(&spool, 8u) == 0,
	      "an index past the end of the caller's bitmap was answered from the "
	      "byte after it rather than refused");
	CHECK(map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)] == 0xffu,
	      "the answer disturbed the byte after the caller's bitmap");
}

/* A SHORT READ STAYS INSIDE THE BUFFER IT WAS GIVEN.
 *
 * `cap` is the caller's buffer and `want = cap < FZN_BLOB_SEALED_MAX ? ...`
 * is the only thing bounding the write. Every `fzn_spool_read` call in the
 * tree -- three here and two in spool_file_test.c -- passes
 * `cap == FZN_BLOB_SEALED_MAX`, which is exactly the value at which dropping
 * the `cap` term changes nothing. Measured 2026-09-03: it left the suite
 * green, and a relay asking for a short read got a full 1056-byte slot.
 *
 * THE BUFFER IS FULL-SIZED AND THE CAP IS NOT, so a sabotaged run overwrites
 * the tail of a buffer that is genuinely there rather than smashing this
 * function's frame. What is asserted is that the bytes past `cap` are
 * untouched -- which is the promise, and is not the same as "it did not
 * crash". */
static void test_a_short_read_stays_inside_the_callers_buffer(void)
{
	fzn_spool_t spool;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];
	uint8_t out[FZN_BLOB_SEALED_MAX];
	const size_t cap = 64u;
	size_t len = 0u;

	REQUIRE(build_blob(), "the blob fixture does not build");
	reset(&spool, map, sizeof(map));
	CHECK(fzn_spool_place(&spool, &HASH, 0u, sealed[0], sealed_len[0], proof[0],
	                      proof_len[0]) == FZN_SPOOL_OK,
	      "the fixture could not place leaf 0, so the read below proves nothing");

	memset(out, 0xa5u, sizeof(out));
	CHECK(fzn_spool_read(&spool, 0u, out, cap, &len) == FZN_SPOOL_OK,
	      "a read bounded by the caller's own buffer was refused");
	CHECK(len == cap, "a read of %zu bytes was reported for a cap of %zu", len, cap);
	CHECK(out[cap] == 0xa5u,
	      "a read wrote past the cap it was given, so the caller's buffer size is "
	      "not what bounds it");
}

static void test_a_leaf_reads_back(void)
{
	fzn_spool_t spool;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];
	uint8_t out[FZN_BLOB_SEALED_MAX];
	size_t len = 0;

	REQUIRE(build_blob(), "the blob fixture does not build");
	reset(&spool, map, sizeof(map));

	CHECK(fzn_spool_read(&spool, 0u, out, sizeof(out), &len) == FZN_SPOOL_ERR_ABSENT,
	      "reading a leaf this store does not hold reported success");
	CHECK(fzn_spool_place(&spool, &HASH, 0u, sealed[0], sealed_len[0], proof[0],
	                      proof_len[0]) == FZN_SPOOL_OK, "refused");
	CHECK(fzn_spool_read(&spool, 0u, out, sizeof(out), &len) == FZN_SPOOL_OK,
	      "reading a leaf this store holds refused");
	/* A relay serving this on hands back what it stored, and the caller's
	 * own length is what bounds the leaf -- see spool.h. */
	CHECK(memcmp(out, sealed[0], sealed_len[0]) == 0, "the leaf did not survive the store");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_leaves_arrive_in_any_order();
	test_an_unverified_leaf_never_reaches_the_disk();
	test_a_failed_write_does_not_claim_the_leaf();
	test_a_duplicate_is_free();
	test_resume_recounts_from_the_bits();
	test_the_ceiling_is_refused_before_anything_is_touched();
	test_the_walk_over_gaps_ends();
	test_an_index_past_the_blob_is_refused();
	test_a_short_read_stays_inside_the_callers_buffer();
	test_a_leaf_reads_back();
	test_the_suite_can_tell_pass_from_fail();

	printf("spool_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
