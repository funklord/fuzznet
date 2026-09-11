/*
 * A fuzz harness for catalog/copy.c's want walk, and a fourth kind of
 * instrument.
 *
 * sec 271 set three side by side: properties where no oracle exists, an
 * oracle where the question has one right answer, and call-sequence
 * invariants where the subject is a protocol. This subject has a fourth
 * shape. A want list IS a function of the catalogue, so an oracle is
 * possible in principle -- and it would need a model of retention, of the
 * holdings seam and of inline content, which is most of copy.c rewritten in
 * the test. What `copy.h` gives instead is better: things the answer must
 * NOT depend on, and a bound it must satisfy.
 *
 *   1. THE FILING HAS NO PART IN IT. "a catalogue with no filing root at all
 *      produces exactly the same want list". So compute the list, then give
 *      the catalogue a filing root and file nodes under it, then compute
 *      again -- byte for byte the same, or filing has leaked into a decision
 *      that sec 154 says is not its business.
 *
 *   2. `written + truncated` SIZES AN ARRAY THAT IS CERTAINLY BIG ENOUGH.
 *      The header says so and says why it may be bigger than needed, so the
 *      harness walks a second time into exactly that size and requires the
 *      truncation to be gone.
 *
 *   3. AND IT IS AN UPPER BOUND, NOT A COUNT -- pinned, not asserted away.
 *      Deduplication compares against what has been WRITTEN, so two
 *      references to one blob arriving after the array filled are two
 *      truncations rather than one duplicate. The tempting assertion is
 *      `written + truncated == distinct blobs` and it is FALSE. This asserts
 *      the inequality the header states, which is sec 243's shape: a
 *      documented non-property, made executable so that a change making it
 *      exact has to come here and say so.
 *
 *   4. WITH ROOM, NO BLOB IS EMITTED TWICE. Deduplication is the thing the
 *      bound above is loose about, so it is worth asserting where it is
 *      tight.
 */

#include "../copy.h"
#include "../sweep.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

#define NODES 6u
#define ROWS 8u
#define ENTRIES 6u
#define HOLDS 6u
#define BLOBS 8u
#define ROOTS 3u

static const fzn_catalog_resolve_ops_t ADD_WINS = { fzn_catalog_add_wins, NULL };
static const fzn_catalog_content_ops_t HELD_WINS = { fzn_catalog_content_held_wins, NULL };
static uint8_t ALICE[FZN_PUBKEY_LEN];

struct store {
	uint8_t held_mask;
};

static int store_holds(void *ctx, const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t len)
{
	const struct store *s = ctx;

	(void)len;
	return (s->held_mask >> (root[0] % 8u)) & 1u;
}

struct coverage {
	unsigned long wanted_some;
	unsigned long wanted_none;
	unsigned long truncated;
	unsigned long bound_was_loose;
	unsigned long filed_something;
	unsigned long busy_refused;
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

static fzn_catalog_id_t id_of(unsigned which)
{
	fzn_catalog_id_t out;

	memset(&out, 0, sizeof(out));
	out.b[0] = (uint8_t)(which + 1u);
	return out;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	fzn_catalog_edge_t rows[ROWS];
	fzn_catalog_entry_t entries[ENTRIES];
	fzn_catalog_hold_t holds[HOLDS];
	fzn_catalog_blob_t first[BLOBS], second[BLOBS], sized[BLOBS];
	fzn_catalog_copy_t plan, plan2, plan3;
	fzn_catalog_t cat;
	struct store store;
	fzn_catalog_holdings_ops_t held;
	unsigned i, j, n, cap;

	memset(ALICE, 0xa1, sizeof(ALICE));
	store.held_mask = (uint8_t)(next(&state) & 0xffu);
	held.holds = store_holds;
	held.ctx = &store;

	memset(rows, 0, sizeof(rows));
	memset(entries, 0, sizeof(entries));
	memset(holds, 0, sizeof(holds));
	if (fzn_catalog_init(&cat, rows, ROWS, &ADD_WINS) != FZN_CATALOG_OK ||
	    fzn_catalog_content_init(&cat, entries, ENTRIES, &HELD_WINS) != FZN_CATALOG_OK ||
	    fzn_catalog_hold_init(&cat, holds, HOLDS) != FZN_CATALOG_OK ||
	    fzn_catalog_retain_all(&cat, 1) != FZN_CATALOG_OK)
		return 1;

	n = 1u + (next(&state) % NODES);
	for (i = 0; i < n; i++) {
		fzn_catalog_entry_t e;
		uint8_t root_seed = (uint8_t)(0xb0u + (next(&state) % ROOTS));

		memset(&e, 0, sizeof(e));
		e.id = id_of(i);
		e.kind = FZN_CATALOG_CONTENT_BLOB;
		memset(e.root, (int)root_seed, sizeof(e.root));
		e.blob_len = 100u + i;
		memcpy(e.issuer, ALICE, FZN_PUBKEY_LEN);
		e.seq = 1;
		if (fzn_catalog_content_set(&cat, &e) != FZN_CATALOG_OK)
			break;
		if ((next(&state) % 4u) == 0u) {
			fzn_catalog_id_t node = id_of(i);

			if (fzn_catalog_retain(&cat, &node, FZN_CATALOG_RETAIN_DROP) !=
			    FZN_CATALOG_OK)
				return 1;
		}
	}

	/* MEMBERSHIP AS WELL AS CONTENT, because a filing is a subset of the
	 * membership -- `fzn_catalog_file_under` refuses an edge that does not
	 * exist, so a fixture of content alone can never file anything and the
	 * invariance check below would compare two identical unfiled walks.
	 * The coverage floor caught that: `filed 0` in 2000 cases. */
	for (i = 1; i < n && i < NODES; i++) {
		fzn_catalog_id_t parent = id_of(0), child = id_of(i);

		if (fzn_catalog_assert(&cat, &parent, &child, ALICE, 1, 1) != FZN_CATALOG_OK)
			break;
	}

	/* A CAPACITY THAT BINDS. The want list is at most ROOTS blobs, so a
	 * capacity drawn from 1..BLOBS almost never truncates -- 59 of 2000,
	 * under the floor. Drawn from 1..ROOTS it binds often, which is the
	 * state the sizing claim is about. Reaching the state beats lowering
	 * the floor to what the fixture happened to produce. */
	cap = 1u + (next(&state) % ROOTS);
	memset(&plan, 0, sizeof(plan));
	if (fzn_catalog_copy_want(&cat, &held, 1000u, first, cap, &plan) != FZN_CATALOG_OK) {
		printf("  MODEL: a want walk was refused on an unheld catalogue\n");
		return 1;
	}

	if (plan.truncated > 0u)
		cov->truncated++;

	/* 4. NO BLOB TWICE, where there was room for all of them.
	 *
	 * THE FIRST DRAFT ASSERTED `written + truncated >= distinct blobs in
	 * the catalogue` HERE AND THAT IS WRONG: a want list holds blobs this
	 * host does NOT hold, so the content table is not its denominator.
	 * Computing the right one needs a model of retention, holdings and
	 * inline content -- which is copy.c rewritten in the test. The sizing
	 * claim is checked below instead, where the header actually makes it:
	 * a second walk into that size does not truncate. */
	if (plan.truncated == 0u) {
		for (i = 0; i < plan.written; i++)
			for (j = i + 1u; j < plan.written; j++)
				if (memcmp(first[i].root, first[j].root,
				           sizeof(first[i].root)) == 0) {
					printf("  MODEL: blob %u and %u are the same root in a "
					       "walk with room to spare\n", i, j);
					return 1;
				}
	}

	/* 2. A SECOND WALK INTO written + truncated MUST NOT TRUNCATE. */
	{
		size_t want = plan.written + plan.truncated;

		if (want > 0u && want <= BLOBS) {
			memset(&plan3, 0, sizeof(plan3));
			if (fzn_catalog_copy_want(&cat, &held, 1000u, sized, want, &plan3) !=
			    FZN_CATALOG_OK) {
				printf("  MODEL: the sized walk was refused\n");
				return 1;
			}
			if (plan3.truncated != 0u) {
				printf("  MODEL: a walk into written + truncated = %zu still "
				       "truncated %zu, so the header's sizing does not hold\n",
				       want, plan3.truncated);
				return 1;
			}
			/* AND IT IS A BOUND RATHER THAN A COUNT, which is
			 * observable without modelling anything: the sized
			 * walk may write FEWER than the size it was given.
			 * copy.h says why -- deduplication compares against
			 * what has been written, so two references to one blob
			 * arriving after the array filled are two truncations
			 * and not one duplicate. Counted, never required. */
			if (plan3.written > want) {
				printf("  MODEL: the sized walk wrote %zu into an array of "
				       "%zu\n", plan3.written, want);
				return 1;
			}
			if (plan3.written < want)
				cov->bound_was_loose++;
		}
	}

	/* 1. THE FILING HAS NO PART IN IT. */
	{
		fzn_catalog_id_t root = id_of(0);
		int filed = 0;

		if (fzn_catalog_filing_root(&cat, &root) == FZN_CATALOG_OK) {
			for (i = 1; i < n && i < NODES; i++) {
				fzn_catalog_id_t child = id_of(i);

				if (fzn_catalog_file_under(&cat, &root, &child) == FZN_CATALOG_OK)
					filed = 1;
			}
		}
		if (filed)
			cov->filed_something++;

		memset(&plan2, 0, sizeof(plan2));
		if (fzn_catalog_copy_want(&cat, &held, 1000u, second, cap, &plan2) !=
		    FZN_CATALOG_OK) {
			printf("  MODEL: the want walk was refused after filing\n");
			return 1;
		}
		if (plan2.written != plan.written || plan2.truncated != plan.truncated ||
		    memcmp(first, second, sizeof(fzn_catalog_blob_t) * plan.written) != 0) {
			printf("  MODEL: filing the nodes changed the want list -- copy.h says "
			       "a catalogue with no filing root at all produces exactly the "
			       "same one\n");
			return 1;
		}
	}

	/* BUSY WHILE ANY JOB HOLDS IT. */
	{
		fzn_catalog_sweep_t job;
		fzn_catalog_sweep_plan_t splan;
		fzn_catalog_removal_t removals[4];
		fzn_catalog_witness_ops_t none = { NULL, NULL };
		fzn_catalog_blob_t third[BLOBS];
		fzn_catalog_copy_t plan4;

		memset(&splan, 0, sizeof(splan));
		if (fzn_catalog_sweep_capture(&cat, &held, &none, 0, 1000u, &job, removals, 4,
		                              &splan) == FZN_CATALOG_OK &&
		    fzn_catalog_sweep_begin(&cat, &job) == FZN_CATALOG_OK) {
			memset(&plan4, 0, sizeof(plan4));
			if (fzn_catalog_copy_want(&cat, &held, 1000u, third, BLOBS, &plan4) !=
			    FZN_CATALOG_ERR_BUSY) {
				printf("  MODEL: a want list was computed while a sweep held the "
				       "catalogue, so it asks for bytes being deleted\n");
				return 1;
			}
			cov->busy_refused++;
			while (fzn_catalog_sweep_advance(&job) == FZN_CATALOG_OK)
				;
			(void)fzn_catalog_sweep_end(&cat, &job);
		}
	}

	if (plan.written > 0u)
		cov->wanted_some++;
	else
		cov->wanted_none++;
	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0 };

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
		printf("copy_fuzz: %lu cases is below FUZZ_MIN_CASES (%u).\n", cases,
		       (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("copy_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* `bound_was_loose` HAS NO FLOOR, deliberately, and is printed. It
	 * counts the walks where written + truncated exceeded the distinct
	 * blobs -- the looseness copy.h documents. Requiring it would make the
	 * suite fail the day somebody makes the sizing exact, which is a change
	 * that should come to this file and argue rather than break it. Same
	 * reasoning as catalog_fuzz's divergence counter, sec 243. */
	if (cov.wanted_some < floor_of(cases, 4u) || cov.wanted_none < floor_of(cases, 50u)
	    || cov.truncated < floor_of(cases, 20u) || cov.filed_something < floor_of(cases, 4u)
	    || cov.busy_refused < floor_of(cases, 20u)) {
		printf("copy_fuzz: REACHED TOO LITTLE -- %lu wanted something, %lu wanted "
		       "nothing, %lu truncated, %lu filed, %lu busy refusals, in %lu "
		       "cases.\n",
		       cov.wanted_some, cov.wanted_none, cov.truncated, cov.filed_something,
		       cov.busy_refused, cases);
		return 1;
	}

	printf("copy_fuzz: %lu cases, %lu wanted something, %lu wanted nothing, %lu "
	       "truncated, %lu where the sizing bound was loose, %lu filed, %lu busy "
	       "refusals, and filing never moved a want list\n",
	       cases, cov.wanted_some, cov.wanted_none, cov.truncated, cov.bound_was_loose,
	       cov.filed_something, cov.busy_refused);
	return 0;
}
#endif
