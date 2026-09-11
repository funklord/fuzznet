/*
 * A fuzz harness for catalog/sweep.c: the PROTOCOL, not the plan.
 *
 * WHAT THIS IS FOR, and it is a third kind after sec 269 and sec 270. That
 * pair were about a data structure: one had no oracle and could only assert
 * properties, the other had one and caught everything. This subject is
 * neither -- it is a six-call protocol with a lock, a cursor and a refusal,
 * over a path that DELETES BYTES, and what a random sequence of calls finds
 * is an ordering fault rather than a wrong answer.
 *
 * `sweep.h` states its own invariants, so they are what this asserts:
 *
 *   ROWS ARE SORTED BY NODE ID  -- "the order is the same on every machine
 *   and after every restart ... That is what lets the cursor be a count."
 *
 *   THE CURSOR IS A COUNT      -- `at` answers FZN_CATALOG_ERR_ABSENT
 *   exactly when the cursor is past the last removal, and `progress` must
 *   agree with how many times `advance` has been called.
 *
 *   `begin` IS IDEMPOTENT      -- "a restart calls it again on a job it has
 *   loaded from disk".
 *
 *   `end` REFUSES WHILE WORK REMAINS -- so a consumer cannot abandon a sweep
 *   and leave the catalogue unlocked with its own record discarded.
 *
 *   BUSY WHILE HELD            -- nothing may change the catalogue while the
 *   job holds it, which is what stops the list moving under a count.
 *
 * WHAT IT DELIBERATELY DOES NOT MODEL is which nodes the plan chooses.
 * `sweep_test.c` owns that -- the last-copy guard, the shared blob, the
 * witness seam that cannot answer -- and it needs a model of retention,
 * holdings and witnesses to say anything. The protocol is sound or not
 * independently of what the plan contains, and mixing the two would make a
 * harness that fails for two unrelated reasons.
 */

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
#define REMOVALS 6u

static const fzn_catalog_resolve_ops_t ADD_WINS = { fzn_catalog_add_wins, NULL };
static const fzn_catalog_content_ops_t HELD_WINS = { fzn_catalog_content_held_wins, NULL };
static uint8_t ALICE[FZN_PUBKEY_LEN];

struct store {
	unsigned others;
};

static int store_holds(void *ctx, const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t len)
{
	(void)ctx; (void)root; (void)len;
	return 1;
}

static size_t store_others(void *ctx, const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t len)
{
	struct store *s = ctx;

	(void)root; (void)len;
	return s->others;
}

struct coverage {
	unsigned long planned_some;
	unsigned long planned_none;
	unsigned long truncated;
	unsigned long end_refused;
	unsigned long busy_refused;
	unsigned long rebegun;
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
	fzn_catalog_removal_t removals[REMOVALS];
	fzn_catalog_removal_t seen[REMOVALS];
	fzn_catalog_sweep_t job;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_t cat;
	struct store store;
	fzn_catalog_holdings_ops_t held;
	fzn_catalog_witness_ops_t witness;
	size_t done = 0, total = 0, at_step, cap;
	unsigned i, n;
	fzn_catalog_err_t err;

	memset(ALICE, 0xa1, sizeof(ALICE));
	store.others = next(&state) % 3u;
	held.holds = store_holds;
	held.ctx = &store;
	witness.others = store_others;
	witness.ctx = &store;

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

		memset(&e, 0, sizeof(e));
		e.id = id_of(i);
		e.kind = FZN_CATALOG_CONTENT_BLOB;
		/* SOME NODES SHARE A BLOB, which is what makes a plan hold one
		 * back, so the fixture reaches both sides of that. */
		memset(e.root, (int)(0xb0u + (next(&state) % 3u)), sizeof(e.root));
		e.blob_len = 100u + i;
		memcpy(e.issuer, ALICE, FZN_PUBKEY_LEN);
		e.seq = 1;
		if (fzn_catalog_content_set(&cat, &e) != FZN_CATALOG_OK)
			break;
		if ((next(&state) % 2u) == 0u) {
			fzn_catalog_id_t node = id_of(i);

			if (fzn_catalog_retain(&cat, &node, FZN_CATALOG_RETAIN_DROP) !=
			    FZN_CATALOG_OK)
				return 1;
		}
	}

	/* A CAPACITY THAT SOMETIMES TRUNCATES, because sweep.h says a short
	 * list is counted rather than refused and that asymmetry is worth
	 * reaching. */
	cap = 1u + (next(&state) % REMOVALS);
	memset(&plan, 0, sizeof(plan));
	err = fzn_catalog_sweep_capture(&cat, &held, &witness, next(&state) % 2u, 1000u,
	                                &job, removals, cap, &plan);
	if (err != FZN_CATALOG_OK) {
		printf("  MODEL: capture refused with %s on an unlocked catalogue\n",
		       fzn_catalog_err_str(err));
		return 1;
	}
	if (plan.truncated)
		cov->truncated++;

	/* SORTED BY NODE ID. sweep.h says this is what lets the cursor be a
	 * count, so it is the invariant the rest of the protocol rests on. */
	for (i = 1; i < plan.planned && i < cap; i++) {
		if (memcmp(&removals[i - 1u].node, &removals[i].node,
		           sizeof(removals[i].node)) >= 0) {
			printf("  MODEL: removal %u is not after removal %u by node id, so "
			       "the cursor is not a count and a restart cannot resume\n",
			       i, i - 1u);
			return 1;
		}
	}
	memcpy(seen, removals, sizeof(seen));

	if (fzn_catalog_sweep_begin(&cat, &job) != FZN_CATALOG_OK) {
		printf("  MODEL: begin refused on a fresh job\n");
		return 1;
	}
	/* IDEMPOTENT, because a restart calls it again on a job read off disk. */
	if (fzn_catalog_sweep_begin(&cat, &job) != FZN_CATALOG_OK) {
		printf("  MODEL: begin is not idempotent, so a resumed job cannot take "
		       "the catalogue it already holds\n");
		return 1;
	}
	cov->rebegun++;

	/* NOTHING MAY CHANGE THE CATALOGUE WHILE THE JOB HOLDS IT. */
	{
		fzn_catalog_id_t p = id_of(0), c = id_of(1);

		if (fzn_catalog_assert(&cat, &p, &c, ALICE, 9, 1) != FZN_CATALOG_ERR_BUSY) {
			printf("  MODEL: the catalogue accepted an assertion while a sweep "
			       "held it, so the list can move under the cursor\n");
			return 1;
		}
		cov->busy_refused++;
	}

	if (fzn_catalog_sweep_progress(&job, &done, &total) != FZN_CATALOG_OK) {
		printf("  MODEL: progress refused while the job was held\n");
		return 1;
	}
	if (done != 0u) {
		printf("  MODEL: a fresh job reports %zu steps done\n", done);
		return 1;
	}

	for (at_step = 0; at_step < total; at_step++) {
		fzn_catalog_removal_t out;
		size_t d2, t2;

		memset(&out, 0, sizeof(out));
		if (fzn_catalog_sweep_at(&job, &out) != FZN_CATALOG_OK) {
			printf("  MODEL: at() refused at step %zu of %zu\n", at_step, total);
			return 1;
		}
		/* THE LIST DOES NOT MOVE. What the cursor hands back at step k
		 * must be the row capture wrote at k, or the decision was not
		 * taken once. */
		if (memcmp(&out, &seen[at_step], sizeof(out)) != 0) {
			printf("  MODEL: step %zu handed back a different removal than "
			       "capture planned\n", at_step);
			return 1;
		}
		/* END REFUSES WHILE WORK REMAINS. */
		if (fzn_catalog_sweep_end(&cat, &job) != FZN_CATALOG_ERR_BUSY) {
			printf("  MODEL: end released the catalogue with %zu of %zu steps "
			       "left, discarding what the consumer meant to remove\n",
			       total - at_step, total);
			return 1;
		}
		cov->end_refused++;
		if (fzn_catalog_sweep_advance(&job) != FZN_CATALOG_OK) {
			printf("  MODEL: advance refused at step %zu of %zu\n", at_step, total);
			return 1;
		}
		if (fzn_catalog_sweep_progress(&job, &d2, &t2) != FZN_CATALOG_OK ||
		    d2 != at_step + 1u || t2 != total) {
			printf("  MODEL: after %zu advances progress says %zu of %zu\n",
			       at_step + 1u, d2, t2);
			return 1;
		}
	}

	/* PAST THE LAST REMOVAL, which is how a caller knows it is finished. */
	{
		fzn_catalog_removal_t out;

		if (fzn_catalog_sweep_at(&job, &out) != FZN_CATALOG_ERR_ABSENT) {
			printf("  MODEL: at() did not report the work finished after %zu "
			       "steps\n", total);
			return 1;
		}
	}

	if (fzn_catalog_sweep_end(&cat, &job) != FZN_CATALOG_OK) {
		printf("  MODEL: end refused with no work left\n");
		return 1;
	}

	/* AND THE CATALOGUE IS GIVEN BACK. */
	{
		fzn_catalog_id_t p = id_of(0), c = id_of(2);

		if (fzn_catalog_assert(&cat, &p, &c, ALICE, 9, 1) == FZN_CATALOG_ERR_BUSY) {
			printf("  MODEL: the catalogue is still held after end\n");
			return 1;
		}
	}

	if (total > 0u)
		cov->planned_some++;
	else
		cov->planned_none++;
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
		printf("sweep_fuzz: %lu cases is below FUZZ_MIN_CASES (%u).\n", cases,
		       (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("sweep_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* A RUN THAT PLANNED NOTHING EVERY TIME would exercise begin, end and
	 * the lock and never the cursor, and every assertion about a step would
	 * be over an empty loop -- which is the vacuous pass this suite keeps
	 * meeting. The end-refusal floor is the one that matters: it fires only
	 * inside the step loop. */
	if (cov.planned_some < floor_of(cases, 4u) || cov.planned_none < floor_of(cases, 50u)
	    || cov.end_refused < floor_of(cases, 4u) || cov.busy_refused < floor_of(cases, 2u)
	    || cov.truncated < floor_of(cases, 50u)) {
		printf("sweep_fuzz: REACHED TOO LITTLE -- %lu planned something, %lu "
		       "planned nothing, %lu end refusals, %lu busy refusals, %lu "
		       "truncated, in %lu cases.\n",
		       cov.planned_some, cov.planned_none, cov.end_refused,
		       cov.busy_refused, cov.truncated, cases);
		return 1;
	}

	printf("sweep_fuzz: %lu cases, %lu planned something, %lu planned nothing, %lu "
	       "end refusals while work remained, %lu assertions refused as busy, %lu "
	       "truncated plans, and the protocol held throughout\n",
	       cases, cov.planned_some, cov.planned_none, cov.end_refused,
	       cov.busy_refused, cov.truncated);
	return 0;
}
#endif
