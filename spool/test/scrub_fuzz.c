/*
 * A fuzz harness for spool/scrub.c: does it find every corruption, and only
 * the corruptions?
 *
 * WHY THIS ONE. `scrub` is the module that exists to notice that stored
 * bytes are no longer the bytes that were verified. project.md sec 102 lists
 * it as the piece with no equivalent anywhere, and until now the only thing
 * asking whether it works was `scrub_test.c`, which flips one bit in one leaf
 * of one arrangement. A detector tested on one instance of the thing it
 * detects is a detector nobody has measured.
 *
 * TWO PROPERTIES, AND THE SECOND IS NOT DECORATION.
 *
 *   1. DETECTION IS COMPLETE. Every sealed cell whose stored bytes differ
 *      from what they were at sealing loses its leaves on the next full
 *      pass. A miss is silent data loss that the host goes on believing in.
 *
 *   2. AND NOTHING ELSE IS TOUCHED. A cell whose bytes did not change keeps
 *      its leaves. A false positive is not a harmless extra check: it
 *      discards bytes that were fine and asks a peer to send them again, so
 *      a scrub that dropped everything would satisfy property 1 perfectly.
 *
 * They are asserted as ONE SET EQUALITY, because that is what makes each of
 * them able to fail: "the cells that lost their leaves" must be exactly "the
 * sealed cells whose slot bytes changed".
 *
 * OBSERVED THROUGH THE PUBLIC API. Whether a cell is still sealed is asked
 * as `fzn_spool_has` over its leaves, not by reading the seal bitmap: the
 * bitmap's layout is the module's, and a model that read it would be
 * agreeing with the implementation about the thing it is checking. What a
 * consumer sees is which leaves are back on the want-list, and that is what
 * this compares.
 *
 * THE CELL DECOMPOSITION IS THIS FILE'S OWN, derived from what `scrub.h`
 * says -- full cells of FZN_SCRUB_CELL, then a tail of one cell per set bit
 * below it -- rather than copied from `scrub.c`. It is checked against
 * `fzn_scrub_cells` on every run, so the two implementations meeting is
 * itself one of the assertions rather than an assumption.
 *
 * WHAT THE HASH SEAM IS. A stub, as everywhere else in this suite. The
 * property is about the module's bookkeeping, not about a hash: a real hash
 * would make a collision astronomically unlikely and a stub makes it merely
 * unlikely, and neither is what is on trial.
 */

#include "../scrub.h"

#include "../../blob/blob.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

/* Below this the floors are cleared by a single lucky case. Same number and
 * same reasoning as the other harnesses here. */
#define FUZZ_MIN_CASES 1000u

/* 200 leaves is 64 + 64 + 64 + 8: three full cells and a tail, so the
 * short-cell path is reachable rather than merely possible. `scrub_test`
 * chose it for that reason and records why. */
#define LEAVES 200u

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

static uint8_t sealed[LEAVES][FZN_BLOB_SEALED_MAX];
static size_t sealed_len[LEAVES];
static uint8_t leaf_hash[LEAVES][FZN_BLOB_HASH_LEN];
static uint8_t root[FZN_BLOB_HASH_LEN];
static uint8_t proof[LEAVES][FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
static unsigned proof_len[LEAVES];

static uint8_t disk[LEAVES * FZN_BLOB_SEALED_MAX];
static uint8_t before[LEAVES * FZN_BLOB_SEALED_MAX];

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

/* This file's own decomposition, from what scrub.h describes. Checked
 * against `fzn_scrub_cells` below rather than assumed to agree. */
static uint64_t model_cell_len(uint64_t first)
{
	uint64_t rem = LEAVES - first;
	uint64_t len;

	if (rem >= FZN_SCRUB_CELL)
		return FZN_SCRUB_CELL;
	/* The highest power of two not above what is left: one cell per set
	 * bit of the remainder, taken from the top. */
	len = 1u;
	while (len * 2u <= rem)
		len *= 2u;
	return len;
}

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

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

struct coverage {
	unsigned long sealed_all;
	unsigned long partial;
	unsigned long dropped_any;
	unsigned long dropped_tail;
	unsigned long untouched;
	unsigned long multi_cell;
};

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	uint64_t first, i, cells = 0u, expect_sealed = 0u, dropped_cells = 0u;
	uint64_t checked = 0u, dropped = 0u, verified = 0u, total = 0u;
	unsigned keep_one_in;
	int placed[LEAVES];
	unsigned bytes_to_rot;

	memset(map, 0, sizeof(map));
	memset(disk, 0, sizeof(disk));
	if (fzn_spool_open(&spool, root, LEAVES, map, sizeof(map), &OPS) != FZN_SPOOL_OK) {
		printf("  INVARIANT: the spool would not open\n");
		return 1;
	}
	if (fzn_scrub_open(&scrub, &spool, roots, FZN_SCRUB_MAX_CELLS(LEAVES), seals,
	                   sizeof(seals)) != FZN_SCRUB_OK) {
		printf("  INVARIANT: the scrub would not open\n");
		return 1;
	}

	/* MOSTLY WHOLE, SOMETIMES HOLED. A blob with no whole cell seals
	 * nothing and asks no question, so the common case is everything
	 * placed and the holes are the variety. */
	keep_one_in = (next(&state) % 4u) == 0u ? 3u + (next(&state) % 40u) : 0u;
	for (i = 0; i < LEAVES; i++) {
		placed[i] = keep_one_in == 0u || (next(&state) % keep_one_in) != 0u;
		if (!placed[i])
			continue;
		if (fzn_spool_place(&spool, &HASH, i, sealed[i], sealed_len[i], proof[i],
		                    proof_len[i]) != FZN_SPOOL_OK) {
			printf("  INVARIANT: a leaf this blob committed to was refused\n");
			return 1;
		}
	}

	/* THE DECOMPOSITION, and whether the module agrees about how many. */
	for (first = 0u; first < LEAVES; first += model_cell_len(first))
		cells++;
	if (cells != fzn_scrub_cells(LEAVES)) {
		printf("  MODEL: this file decomposes %llu leaves into %llu cells and the "
		       "module says %llu, so one of the two is not the canonical "
		       "decomposition\n",
		       (unsigned long long)LEAVES, (unsigned long long)cells,
		       (unsigned long long)fzn_scrub_cells(LEAVES));
		return 1;
	}

	/* Seal until a pass seals nothing, in random bites. */
	for (i = 0; i < 64u; i++) {
		uint64_t did = 0u;
		fzn_scrub_err_t err = fzn_scrub_seal(&scrub, &HASH,
		                                     1u + (next(&state) % 80u), &did);

		if (err != FZN_SCRUB_OK && err != FZN_SCRUB_DONE) {
			printf("  INVARIANT: sealing refused: %s\n", fzn_scrub_err_str(err));
			return 1;
		}
		if (err == FZN_SCRUB_DONE && did == 0u)
			break;
	}

	/* WHAT SHOULD BE SEALED IS WHAT IS WHOLE, decided from this file's own
	 * record of what it placed. */
	for (first = 0u; first < LEAVES; first += model_cell_len(first)) {
		uint64_t len = model_cell_len(first);
		int whole = 1;

		for (i = 0; i < len; i++) {
			if (!placed[first + i])
				whole = 0;
		}
		if (whole)
			expect_sealed++;
	}
	if (fzn_scrub_progress(&scrub, &verified, &total) != FZN_SCRUB_OK) {
		printf("  INVARIANT: progress was refused\n");
		return 1;
	}
	if (total != cells || verified != expect_sealed) {
		printf("  MODEL: %llu of %llu cells are whole and the scrub reports %llu of "
		       "%llu sealed\n",
		       (unsigned long long)expect_sealed, (unsigned long long)cells,
		       (unsigned long long)verified, (unsigned long long)total);
		return 1;
	}
	if (expect_sealed == cells)
		cov->sealed_all++;
	else
		cov->partial++;

	/* ROT, straight into the backend behind the store's back. */
	memcpy(before, disk, sizeof(disk));
	bytes_to_rot = (next(&state) % 8u) == 0u ? 0u : 1u + (next(&state) % 6u);
	for (i = 0; i < bytes_to_rot; i++) {
		size_t at = (size_t)(next(&state) % (uint32_t)sizeof(disk));

		disk[at] ^= (uint8_t)(1u << (next(&state) % 8u));
	}

	/* ACCUMULATED, BECAUSE EACH CALL REPORTS ITS OWN. `out_checked` and
	 * `out_dropped` are what THIS call did, so reading the last one and
	 * calling it the pass total was this harness's first bug -- it fired
	 * on case 91 and it was mine, not the module's. */
	for (i = 0; i < 64u; i++) {
		uint64_t did = 0u, saw = 0u;
		fzn_scrub_err_t err = fzn_scrub_step(&scrub, &HASH,
		                                     1u + (next(&state) % 80u), &saw, &did);

		if (err != FZN_SCRUB_OK && err != FZN_SCRUB_DONE) {
			printf("  INVARIANT: a step refused: %s\n", fzn_scrub_err_str(err));
			return 1;
		}
		checked += saw;
		dropped += did;
		if (err == FZN_SCRUB_DONE)
			break;
	}

	/*
	 * THE SET EQUALITY. For every cell: it should have lost its leaves
	 * exactly when it was sealed AND its slot bytes changed.
	 */
	for (first = 0u; first < LEAVES; first += model_cell_len(first)) {
		uint64_t len = model_cell_len(first);
		int whole = 1, rotted, gone = 1, kept = 1;

		for (i = 0; i < len; i++) {
			if (!placed[first + i])
				whole = 0;
		}
		rotted = memcmp(disk + first * FZN_BLOB_SEALED_MAX,
		                before + first * FZN_BLOB_SEALED_MAX,
		                (size_t)len * FZN_BLOB_SEALED_MAX) != 0;

		for (i = 0; i < len; i++) {
			if (fzn_spool_has(&spool, first + i))
				gone = 0;
			else if (placed[first + i])
				kept = 0;
		}

		if (whole && rotted) {
			if (!gone) {
				printf("  MODEL: cell at leaf %llu was sealed, its stored "
				       "bytes changed, and it still holds leaves -- a host "
				       "goes on believing bytes it was never given\n",
				       (unsigned long long)first);
				return 1;
			}
			dropped_cells++;
			if (len < FZN_SCRUB_CELL)
				cov->dropped_tail++;
		} else if (!kept) {
			printf("  MODEL: cell at leaf %llu lost leaves it should have kept "
			       "(sealed=%d, bytes changed=%d) -- a scrub that discards "
			       "sound bytes asks a peer to send them again\n",
			       (unsigned long long)first, whole, rotted);
			return 1;
		}
	}

	if (dropped != dropped_cells) {
		printf("  MODEL: the step reports %llu cells dropped and %llu cells lost "
		       "their leaves\n",
		       (unsigned long long)dropped, (unsigned long long)dropped_cells);
		return 1;
	}
	if (dropped_cells > 0u) {
		cov->dropped_any++;
		if (dropped_cells > 1u)
			cov->multi_cell++;
	} else {
		cov->untouched++;
	}

	/* AND PROGRESS FOLLOWS THE REPAIR. */
	if (fzn_scrub_progress(&scrub, &verified, &total) != FZN_SCRUB_OK) {
		printf("  INVARIANT: progress was refused after a step\n");
		return 1;
	}
	if (verified != expect_sealed - dropped_cells) {
		printf("  MODEL: %llu sealed after %llu of %llu were repaired\n",
		       (unsigned long long)verified, (unsigned long long)dropped_cells,
		       (unsigned long long)expect_sealed);
		return 1;
	}

	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0 };

	if (!build_blob())
		return 0;
	for (i = 0; i < size; i++)
		seed = (seed * 31u) + data[i];
	if (seed == 0u)
		seed = 1u;
	(void)fuzz_one(seed, &cov);
	return 0;
}
#else

static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long f = cases / per;

	return f == 0u ? 1u : f;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov = { 0, 0, 0, 0, 0, 0 };
	unsigned long c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("scrub_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will "
		       "not report success. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}
	if (!build_blob()) {
		printf("scrub_fuzz: the blob would not build, so nothing below ran\n");
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("scrub_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* FLOORS ON STATES. A run that never corrupted a sealed cell has not
	 * tested detection; one that never left a cell alone has not tested
	 * that sound bytes survive; and one that never dropped the short tail
	 * cell has tested only the arithmetic that is a multiple of 64. */
	if (cov.dropped_any < floor_of(cases, 4u) || cov.untouched < floor_of(cases, 8u)
	    || cov.dropped_tail < floor_of(cases, 50u) || cov.partial < floor_of(cases, 20u)
	    || cov.sealed_all < floor_of(cases, 4u) || cov.multi_cell < floor_of(cases, 50u)) {
		printf("scrub_fuzz: REACHED TOO LITTLE -- %lu with a drop, %lu untouched, "
		       "%lu tail drops, %lu partial blobs, %lu fully sealed, %lu multi-cell "
		       "drops in %lu cases.\n",
		       cov.dropped_any, cov.untouched, cov.dropped_tail, cov.partial,
		       cov.sealed_all, cov.multi_cell, cases);
		return 1;
	}

	printf("scrub_fuzz: %lu cases, %lu with a drop, %lu untouched, %lu tail drops, "
	       "%lu partial blobs, %lu fully sealed, %lu multi-cell drops, detection "
	       "exact throughout\n",
	       cases, cov.dropped_any, cov.untouched, cov.dropped_tail, cov.partial,
	       cov.sealed_all, cov.multi_cell);
	return 0;
}
#endif
