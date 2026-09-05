/* Tests for spool/scrub.c.
 *
 * THE CORRUPTION CASE IS THE ONLY ONE THAT MATTERS, and every other case
 * here would pass against a scrub that always answers "fine". So each clean
 * assertion is paired with a dirty one over the same fixture, and the dirty
 * one carries a control that the corruption actually reached the bytes the
 * scrub reads -- a test that flips a byte the store never looks at reports a
 * working scrub and a broken one identically.
 *
 * The second load-bearing case is BLAST RADIUS. A scrub that drops the whole
 * blob on one bad byte passes any test that only asks "did it notice", so
 * the neighbours of a corrupted cell are asserted intact.
 */

#include "../plan.h"
#include "../scrub.h"

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
	fprintf(stderr, "  FAIL scrub_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

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

/* Three whole cells, so a corrupted one has neighbours to leave alone. */
#define LEAVES 192u
#define CELLS_EXPECTED 3u

static uint8_t sealed[LEAVES][FZN_BLOB_SEALED_MAX];
static size_t sealed_len[LEAVES];
static uint8_t leaf_hash[LEAVES][FZN_BLOB_HASH_LEN];
static uint8_t root[FZN_BLOB_HASH_LEN];
static uint8_t proof[LEAVES][FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
static unsigned proof_len[LEAVES];

static int build_blob(void)
{
	fzn_blob_tree_t tree;
	unsigned i;

	fzn_blob_tree_init(&tree);
	for (i = 0; i < LEAVES; i++) {
		size_t j;

		sealed_len[i] = 40u + (i % 23u) * 5u;
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
	for (i = 0; i < LEAVES; i++) {
		if (fzn_blob_proof_build(&HASH, leaf_hash[0], LEAVES, i, proof[i],
		                         sizeof(proof[i]), &proof_len[i]) != FZN_BLOB_OK)
			return 0;
	}
	return 1;
}

static uint8_t disk[LEAVES * FZN_BLOB_SEALED_MAX];

static int disk_read(void *c, uint64_t o, uint8_t *b, size_t n)
{
	(void)c;
	if (o + n > sizeof(disk))
		return 0;
	memcpy(b, disk + o, n);
	return 1;
}

static int disk_write(void *c, uint64_t o, const uint8_t *b, size_t n)
{
	(void)c;
	if (o + n > sizeof(disk))
		return 0;
	memcpy(disk + o, b, n);
	return 1;
}

static const fzn_spool_ops_t OPS = { disk_read, disk_write, NULL, NULL };

static fzn_spool_t spool;
static uint8_t map[FZN_SPOOL_BITMAP_LEN(LEAVES)];
static fzn_scrub_t scrub;
static uint8_t roots[FZN_SCRUB_MAX_CELLS(LEAVES) * FZN_BLOB_HASH_LEN];
static uint8_t seals[FZN_SCRUB_SEALED_LEN(FZN_SCRUB_MAX_CELLS(LEAVES))];

static int place_range(uint64_t first, uint64_t count)
{
	uint64_t i;

	for (i = 0; i < count; i++) {
		if (fzn_spool_place(&spool, &HASH, first + i, sealed[first + i],
		                    sealed_len[first + i], proof[first + i], proof_len[first + i])
		    != FZN_SPOOL_OK)
			return 0;
	}
	return 1;
}

static int fresh(uint64_t fill_from, uint64_t fill_count)
{
	memset(map, 0, sizeof(map));
	memset(disk, 0, sizeof(disk));
	if (fzn_spool_open(&spool, root, LEAVES, map, sizeof(map), &OPS) != FZN_SPOOL_OK)
		return 0;
	if (fill_count > 0u && !place_range(fill_from, fill_count))
		return 0;
	return fzn_scrub_open(&scrub, &spool, roots, FZN_SCRUB_MAX_CELLS(LEAVES), seals,
	                      sizeof(seals)) == FZN_SCRUB_OK;
}

/* Seals every cell it can, looping until the pass wraps. */
static uint64_t seal_all(void)
{
	uint64_t total = 0u, got = 0u;
	int guard;

	for (guard = 0; guard < 64; guard++) {
		fzn_scrub_err_t err = fzn_scrub_seal(&scrub, &HASH, 1u, &got);

		total += got;
		if (err == FZN_SCRUB_DONE)
			return total;
		if (err != FZN_SCRUB_OK)
			return total;
	}
	return total;
}

static fzn_scrub_err_t step_all(uint64_t *checked, uint64_t *dropped)
{
	uint64_t c = 0u, d = 0u, ct = 0u, dt = 0u;
	fzn_scrub_err_t err = FZN_SCRUB_OK;
	int guard;

	for (guard = 0; guard < 64; guard++) {
		err = fzn_scrub_step(&scrub, &HASH, 1u, &c, &d);
		ct += c;
		dt += d;
		if (err != FZN_SCRUB_OK)
			break;
	}
	*checked = ct;
	*dropped = dt;
	return err;
}

/* ---- the grid ---------------------------------------------------------- */

/* The bound in the header is a claim about every blob size, not about this
 * fixture, so it is checked over every size up to a few thousand rather than
 * at the one number the tests happen to use. */
static void test_the_cell_bound_holds_at_every_size(void)
{
	uint64_t n;
	int over = 0;
	uint64_t worst_n = 0, worst_slack = 999u;

	for (n = 1u; n <= 4096u; n++) {
		uint64_t cells = fzn_scrub_cells(n);
		uint64_t bound = FZN_SCRUB_MAX_CELLS(n);

		if (cells > bound) {
			over++;
			if (over == 1)
				CHECK(0, "%llu leaves decompose into %llu cells, bound says %llu",
				      (unsigned long long)n, (unsigned long long)cells,
				      (unsigned long long)bound);
		}
		if (bound - cells < worst_slack) {
			worst_slack = bound - cells;
			worst_n = n;
		}
	}
	CHECK(over == 0, "%d sizes exceeded the cell bound", over);
	/* A bound with slack everywhere is a bound nobody has tested against
	 * its tightest case: this reports where it comes closest, so a change
	 * to the decomposition shows up as a number moving rather than as
	 * silence. */
	CHECK(worst_slack <= 7u, "the bound's tightest point is %llu spare at %llu leaves",
	      (unsigned long long)worst_slack, (unsigned long long)worst_n);
	CHECK(fzn_scrub_cells(LEAVES) == CELLS_EXPECTED, "%llu leaves gave %llu cells, not %u",
	      (unsigned long long)LEAVES, (unsigned long long)fzn_scrub_cells(LEAVES),
	      CELLS_EXPECTED);
	CHECK(fzn_scrub_cells(0u) == 0u, "an empty blob has cells");
}

/* ---- the clean pass, which proves nothing on its own -------------------- */

static void test_a_whole_blob_seals_and_verifies(void)
{
	uint64_t sealed_now, checked = 0u, dropped = 0u;

	CHECK(fresh(0u, LEAVES), "the fixture did not fill");
	sealed_now = seal_all();
	CHECK(sealed_now == CELLS_EXPECTED, "%llu cells sealed, not %u",
	      (unsigned long long)sealed_now, CELLS_EXPECTED);
	CHECK(step_all(&checked, &dropped) == FZN_SCRUB_DONE, "the pass did not finish");
	CHECK(checked == CELLS_EXPECTED, "%llu cells checked, not %u",
	      (unsigned long long)checked, CELLS_EXPECTED);
	CHECK(dropped == 0u, "%llu cells dropped from an intact blob",
	      (unsigned long long)dropped);
	CHECK(spool.have == LEAVES, "an intact blob lost leaves: %llu of %u",
	      (unsigned long long)spool.have, LEAVES);
	/* Sealing again seals nothing: a cell already sealed is left alone. */
	CHECK(seal_all() == 0u, "a second sealing pass re-sealed cells");
}

/* ---- the one that matters ---------------------------------------------- */

static void test_a_rotted_byte_drops_its_cell_and_only_its_cell(void)
{
	uint64_t checked = 0u, dropped = 0u;
	uint8_t back[FZN_BLOB_SEALED_MAX];
	size_t back_len = 0u;
	const uint64_t victim = 70u; /* inside cell 1 of three */
	uint64_t i;

	CHECK(fresh(0u, LEAVES), "the fixture did not fill");
	CHECK(seal_all() == CELLS_EXPECTED, "the fixture did not seal");
	CHECK(step_all(&checked, &dropped) == FZN_SCRUB_DONE && dropped == 0u,
	      "the fixture was not clean before corruption");

	/* Rot, straight into the backend behind the store's back. */
	disk[victim * FZN_BLOB_SEALED_MAX + 3u] ^= 0x40u;

	/* THE CONTROL. If the flip landed somewhere the store never reads,
	 * everything below passes against a scrub that does nothing. */
	CHECK(fzn_spool_read(&spool, victim, back, sizeof(back), &back_len) == FZN_SPOOL_OK,
	      "the victim leaf could not be read back");
	CHECK(back_len == (size_t)FZN_BLOB_SEALED_MAX,
	      "the store returned %zu bytes, not a whole slot", back_len);
	CHECK(memcmp(back, sealed[victim], sealed_len[victim]) != 0,
	      "the corruption did not reach the bytes the store reads");

	CHECK(step_all(&checked, &dropped) == FZN_SCRUB_DONE, "the pass did not finish");
	CHECK(checked == CELLS_EXPECTED, "%llu cells checked, not %u",
	      (unsigned long long)checked, CELLS_EXPECTED);
	CHECK(dropped == 1u, "%llu cells dropped, not 1", (unsigned long long)dropped);

	/* BLAST RADIUS. Exactly the victim's cell went, and its neighbours
	 * stayed -- a scrub that drops the blob passes every assertion above. */
	CHECK(spool.have == LEAVES - FZN_SCRUB_CELL, "%llu leaves left, not %u",
	      (unsigned long long)spool.have, LEAVES - FZN_SCRUB_CELL);
	for (i = 0; i < FZN_SCRUB_CELL; i++)
		CHECK(!fzn_spool_has(&spool, FZN_SCRUB_CELL + i),
		      "leaf %llu of the rotted cell survived",
		      (unsigned long long)(FZN_SCRUB_CELL + i));
	CHECK(fzn_spool_has(&spool, FZN_SCRUB_CELL - 1u), "the cell before was dropped too");
	CHECK(fzn_spool_has(&spool, 2u * FZN_SCRUB_CELL), "the cell after was dropped too");
}

/* Repair is the want-list, and nothing else. */
static void test_a_dropped_cell_returns_to_the_want_list(void)
{
	fzn_spool_range_t want[8];
	size_t count = 0u;
	uint64_t checked = 0u, dropped = 0u;

	CHECK(fresh(0u, LEAVES), "the fixture did not fill");
	CHECK(seal_all() == CELLS_EXPECTED, "the fixture did not seal");
	CHECK(fzn_spool_plan_want(&spool, 0u, FZN_SCRUB_CELL, want, 8u, &count) == FZN_SPOOL_OK,
	      "the planner failed on a complete blob");
	CHECK(count == 0u, "a complete blob wanted %zu ranges", count);

	disk[70u * FZN_BLOB_SEALED_MAX + 3u] ^= 0x40u;
	CHECK(step_all(&checked, &dropped) == FZN_SCRUB_DONE && dropped == 1u,
	      "the rot was not caught");

	CHECK(fzn_spool_plan_want(&spool, 0u, FZN_SCRUB_CELL, want, 8u, &count) == FZN_SPOOL_OK,
	      "the planner failed after a drop");
	CHECK(count == 1u, "%zu ranges wanted after one dropped cell, not 1", count);
	CHECK(want[0].first == FZN_SCRUB_CELL && want[0].count == FZN_SCRUB_CELL,
	      "the want is %llu+%llu, not %u+%u", (unsigned long long)want[0].first,
	      (unsigned long long)want[0].count, FZN_SCRUB_CELL, FZN_SCRUB_CELL);
	/* And the seal went with the leaves, so the cell is resealed from
	 * bytes a peer proved rather than from the rotted ones. */
	CHECK(seal_all() == 0u, "a cell with missing leaves was resealed");
}

/* ---- partial blobs ------------------------------------------------------ */

static void test_a_partial_blob_seals_only_whole_cells(void)
{
	uint64_t checked = 0u, dropped = 0u;

	/* Cell 0 whole, cell 1 half, cell 2 absent. */
	CHECK(fresh(0u, FZN_SCRUB_CELL + 30u), "the fixture did not fill");
	CHECK(seal_all() == 1u, "a partial blob sealed something other than its one whole cell");
	CHECK(step_all(&checked, &dropped) == FZN_SCRUB_DONE, "the pass did not finish");
	CHECK(checked == 1u, "%llu cells checked, not 1", (unsigned long long)checked);
	CHECK(dropped == 0u, "an intact partial blob lost a cell");

	/* Completing the second cell makes it sealable, with no special case. */
	CHECK(place_range(FZN_SCRUB_CELL + 30u, FZN_SCRUB_CELL - 30u), "filling cell 1 failed");
	CHECK(seal_all() == 1u, "the newly complete cell did not seal");
}

/* ---- guards ------------------------------------------------------------- */

static void test_every_guard_refuses_its_own_argument(void)
{
	uint64_t out = 0u;

	CHECK(fresh(0u, LEAVES), "the fixture did not fill");

	CHECK(fzn_scrub_open(NULL, &spool, roots, 8u, seals, sizeof(seals))
	              == FZN_SCRUB_ERR_MALFORMED,
	      "open took a null scrub");
	CHECK(fzn_scrub_open(&scrub, NULL, roots, 8u, seals, sizeof(seals))
	              == FZN_SCRUB_ERR_MALFORMED,
	      "open took a null spool");
	CHECK(fzn_scrub_open(&scrub, &spool, NULL, 8u, seals, sizeof(seals))
	              == FZN_SCRUB_ERR_MALFORMED,
	      "open took a null roots array");
	CHECK(fzn_scrub_open(&scrub, &spool, roots, 8u, NULL, sizeof(seals))
	              == FZN_SCRUB_ERR_MALFORMED,
	      "open took a null seal bitmap");
	/* An array too small for the grid, which is the caller error that
	 * would otherwise be a write past the end. */
	CHECK(fzn_scrub_open(&scrub, &spool, roots, CELLS_EXPECTED - 1u, seals, sizeof(seals))
	              == FZN_SCRUB_ERR_MALFORMED,
	      "open took a roots array too small for the grid");
	CHECK(fzn_scrub_open(&scrub, &spool, roots, FZN_SCRUB_MAX_CELLS(LEAVES), seals, 0u)
	              == FZN_SCRUB_ERR_MALFORMED,
	      "open took a seal bitmap too small for the grid");

	CHECK(fresh(0u, LEAVES), "the fixture did not reopen");
	CHECK(fzn_scrub_seal(&scrub, &HASH, 0u, &out) == FZN_SCRUB_ERR_MALFORMED,
	      "a zero limit was read as no bound");
	CHECK(fzn_scrub_step(&scrub, &HASH, 0u, &out, NULL) == FZN_SCRUB_ERR_MALFORMED,
	      "a zero limit was read as no bound");
	CHECK(fzn_scrub_seal(NULL, &HASH, 1u, &out) == FZN_SCRUB_ERR_MALFORMED,
	      "seal took a null scrub");
	CHECK(fzn_scrub_step(&scrub, NULL, 1u, &out, NULL) == FZN_SCRUB_ERR_MALFORMED,
	      "step took null hash ops");
	CHECK(fzn_scrub_err_str(FZN_SCRUB_ERR_BACKEND) != NULL, "err_str returned null");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	if (failures == before + 1) {
		failures = before;
		return;
	}
	fprintf(stderr, "  the positive control did not register\n");
	failures = before + 1;
}

int main(void)
{
	if (!build_blob()) {
		fprintf(stderr, "scrub_test: the fixture did not build\n");
		return 1;
	}

	test_the_cell_bound_holds_at_every_size();
	test_a_whole_blob_seals_and_verifies();
	test_a_rotted_byte_drops_its_cell_and_only_its_cell();
	test_a_dropped_cell_returns_to_the_want_list();
	test_a_partial_blob_seals_only_whole_cells();
	test_every_guard_refuses_its_own_argument();
	test_the_suite_can_tell_pass_from_fail();

	printf("scrub_test: %d checks, %d failures\n", checks, failures);
	return failures != 0;
}
