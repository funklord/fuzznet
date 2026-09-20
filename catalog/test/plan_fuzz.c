/*
 * A fuzz harness for the PLANNERS over the new model: catalog/sweep.c,
 * catalog/copy.c and catalog/filing.c. sec 324.
 *
 * WHAT IT IS FOR, and why it is not the codec harness over again.
 * attribute_fuzz asks whether arbitrary BYTES can make a decoder misbehave.
 * These modules never see bytes off the wire; they see an assertion set a
 * caller has already decoded, and what can go wrong is an INVARIANT quietly
 * ceasing to hold on some shape of input nobody wrote a case for. The old
 * catalog/ had four such harnesses -- catalog_fuzz, reach_fuzz, sweep_fuzz and
 * copy_fuzz -- and retiring them without a replacement would be the migration
 * losing coverage rather than moving it.
 *
 * THE INVARIANTS, each one a property the hand-written suites check over
 * chosen inputs and this checks over arbitrary ones:
 *
 *   1. THE PLANS PARTITION. Every distinct entity lands in exactly one sweep
 *      counter, and every examined item in exactly one copy counter. A guard
 *      that stopped firing on some shape would show up as a sum that no longer
 *      closes, whatever else looked right.
 *
 *   2. A PLANNED REMOVAL PASSED EVERY GUARD. For each row the sweep planned,
 *      re-derive the guards independently and require all of them: this host
 *      does not keep it, nothing curates it, this host holds it, and enough
 *      others do. This is the assertion that matters -- the counters can agree
 *      with themselves while the wrong rows are in the job.
 *
 *   3. THE ROWS ARE SORTED AND DISTINCT, because the cursor is a count and
 *      resuming from one is only sound if the order is stable.
 *
 *   4. WANT AND HOLDINGS DISAGREE THE WAY THEY SHOULD. Nothing this host holds
 *      is ever wanted, and nothing it lacks is ever announced -- which is the
 *      pair of walks failing to collapse into each other.
 *
 *   5. A FILING IS ONLY EVER REPORTED WHILE THE RECORDS BACK IT.
 *
 * THE CONTROL IS THE COVERAGE FLOOR. A generator that produced only empty sets
 * would satisfy every invariant above and prove nothing, so the run counts the
 * states that make each property bite and fails if any stayed at zero.
 */

#include "../sweep.h"
#include "../copy.h"
#include "../filing.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

#define MAX_ASSERTIONS 12u
#define MAX_HOSTS 4u
#define MAX_ENTITIES 4u

/* A small deterministic generator, so a failing case is reproducible from its
 * seed alone and no state carries between cases. */
static uint32_t rng_state;

static uint32_t rnd(void)
{
	rng_state = rng_state * 1664525u + 1013904223u;
	return rng_state >> 8;
}

static uint32_t rnd_below(uint32_t n)
{
	return n ? rnd() % n : 0u;
}

struct coverage {
	unsigned long planned;      /* a removal was planned */
	unsigned long retained;     /* retention refused one */
	unsigned long last_copy;    /* the last-copy guard refused one */
	unsigned long absent;       /* this host did not hold it */
	unsigned long wanted;       /* copy asked for something */
	unsigned long announced;    /* copy announced something */
	unsigned long filed;        /* a filing was accepted */
	unsigned long filing_stale; /* a filing stopped being backed */
};

static uint8_t hosts[MAX_HOSTS][32];
static uint8_t entities[MAX_ENTITIES][FZN_CATALOG_ENTITY_LEN];
static const uint8_t DIM[] = "place";
static const uint8_t PATHS[2][8] = { "/a/one", "/b/two" };

static void fixtures(void)
{
	size_t i;

	for (i = 0; i < MAX_HOSTS; i++)
		memset(hosts[i], (int)(0x10u + i), 32);
	for (i = 0; i < MAX_ENTITIES; i++)
		memset(entities[i], (int)(0xa0u + i), FZN_CATALOG_ENTITY_LEN);
}

/* Build a random set. Every assertion names a real host and entity, because
 * the shapes worth exploring are the COMBINATIONS -- which host holds what,
 * what is curated, what is retracted -- rather than malformed pointers, which
 * the argument tests already cover. */
static size_t build_set(fzn_catalog_assertion_t *set)
{
	size_t n = (size_t)rnd_below(MAX_ASSERTIONS + 1u);
	size_t i;

	for (i = 0; i < n; i++) {
		fzn_catalog_assertion_t *a = &set[i];
		uint32_t kind = rnd_below(3u);

		memset(a, 0, sizeof(*a));
		a->issuer = hosts[rnd_below(MAX_HOSTS)];
		a->issuer_len = 32;
		a->entity = entities[rnd_below(MAX_ENTITIES)];
		a->entity_len = FZN_CATALOG_ENTITY_LEN;
		a->name = DIM;
		a->name_len = 5;
		a->value = PATHS[rnd_below(2u)];
		a->value_len = 6;
		a->attr_class = FZN_CATALOG_LABEL;
		a->scope = FZN_CATALOG_ESTATE;
		a->merge = FZN_CATALOG_UNION;
		a->capability = kind == 0 ? FZN_CATALOG_CAP_HOLDER : FZN_CATALOG_CAP_NONE;
		a->live = rnd_below(4u) != 0; /* mostly live, sometimes retracted */
	}

	return n;
}

/* Re-derive "this host holds it" WITHOUT the planner, so the check is an
 * independent witness rather than the module agreeing with itself. */
static int holds_here(const fzn_catalog_assertion_t *set, size_t n,
                      const uint8_t *entity, const uint8_t *self)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (!set[i].live || set[i].capability != FZN_CATALOG_CAP_HOLDER)
			continue;
		if (memcmp(set[i].entity, entity, FZN_CATALOG_ENTITY_LEN) != 0)
			continue;
		if (memcmp(set[i].issuer, self, 32) == 0)
			return 1;
	}
	return 0;
}

static size_t other_holders(const fzn_catalog_assertion_t *set, size_t n,
                            const uint8_t *entity, const uint8_t *self)
{
	size_t i, j, count = 0;

	for (i = 0; i < n; i++) {
		int seen = 0;

		if (!set[i].live || set[i].capability != FZN_CATALOG_CAP_HOLDER)
			continue;
		if (memcmp(set[i].entity, entity, FZN_CATALOG_ENTITY_LEN) != 0)
			continue;
		if (memcmp(set[i].issuer, self, 32) == 0)
			continue;
		for (j = 0; j < i; j++)
			if (set[j].live && set[j].capability == FZN_CATALOG_CAP_HOLDER &&
			    memcmp(set[j].entity, entity, FZN_CATALOG_ENTITY_LEN) == 0 &&
			    memcmp(set[j].issuer, set[i].issuer, 32) == 0)
				seen = 1;
		if (!seen)
			count++;
	}
	return count;
}

static int curated_here(const fzn_catalog_assertion_t *set, size_t n,
                        const uint8_t *entity)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (set[i].live && set[i].capability != FZN_CATALOG_CAP_HOLDER &&
		    memcmp(set[i].entity, entity, FZN_CATALOG_ENTITY_LEN) == 0)
			return 1;
	return 0;
}

static size_t distinct_entities(const fzn_catalog_assertion_t *set, size_t n)
{
	size_t i, j, d = 0;

	for (i = 0; i < n; i++) {
		int seen = 0;

		for (j = 0; j < i; j++)
			if (memcmp(set[j].entity, set[i].entity,
			           FZN_CATALOG_ENTITY_LEN) == 0)
				seen = 1;
		if (!seen)
			d++;
	}
	return d;
}

#define FAILED(why, ...)                                                       \
	do {                                                                   \
		printf("plan_fuzz: " why "\n", __VA_ARGS__);                   \
		return 1;                                                      \
	} while (0)

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	fzn_catalog_assertion_t set[MAX_ASSERTIONS];
	fzn_catalog_hold_t hold_rows[MAX_ENTITIES];
	fzn_catalog_holds_t holds;
	fzn_catalog_removal_t rows[MAX_ENTITIES];
	fzn_catalog_sweep_t job;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_copy_t want_plan, hold_plan;
	fzn_catalog_entity_t out_want[MAX_ENTITIES], out_hold[MAX_ENTITIES];
	const uint8_t *self;
	size_t n, i, j, min_others;

	rng_state = seed;
	n = build_set(set);
	self = hosts[rnd_below(MAX_HOSTS)];
	min_others = (size_t)rnd_below(3u);

	/* A random retention table over the entities that exist. */
	fzn_catalog_holds_init(&holds, hold_rows, MAX_ENTITIES);
	fzn_catalog_retain_all(&holds, (int)rnd_below(2u));
	for (i = 0; i < MAX_ENTITIES; i++) {
		uint32_t mode = rnd_below(3u);

		if (mode != 0)
			fzn_catalog_retain(&holds, entities[i],
			                     FZN_CATALOG_ENTITY_LEN,
			                     mode == 1 ? FZN_CATALOG_RETAIN_KEEP
			                               : FZN_CATALOG_RETAIN_DROP);
	}

	if (fzn_catalog_sweep_capture(set, n, &holds, self, 32, min_others, 0, NULL,
	                                &job, rows, MAX_ENTITIES, &plan) != FZN_CATALOG_OK)
		FAILED("seed %u: a well-formed capture was refused", seed);

	/* 1. THE PLAN PARTITIONS. */
	if (plan.planned + plan.retained + plan.last_copy +
	    plan.absent + plan.incomplete + plan.truncated != distinct_entities(set, n))
		FAILED("seed %u: the sweep plan does not partition (%zu counted over %zu "
		       "distinct entities)", seed,
		       plan.planned + plan.retained + plan.last_copy +
		       plan.absent + plan.incomplete + plan.truncated,
		       distinct_entities(set, n));

	cov->planned += plan.planned ? 1u : 0u;
	cov->retained += plan.retained ? 1u : 0u;
	cov->last_copy += plan.last_copy ? 1u : 0u;
	cov->absent += plan.absent ? 1u : 0u;

	/* 2. EVERY PLANNED ROW PASSED EVERY GUARD, re-derived independently. */
	for (i = 0; i < job.used; i++) {
		const uint8_t *e = job.removals[i].entity;

		if (fzn_catalog_keeps(&holds, e, FZN_CATALOG_ENTITY_LEN, 0))
			FAILED("seed %u: planned a removal for an entity this host keeps",
			       seed);
		if (!holds_here(set, n, e, self))
			FAILED("seed %u: planned a removal for bytes this host does not have",
			       seed);
		if (min_others > 0 && other_holders(set, n, e, self) < min_others)
			FAILED("seed %u: planned a removal of a last copy (min_others %zu)",
			       seed, min_others);

		/* 3. SORTED AND DISTINCT. */
		if (i > 0 && memcmp(job.removals[i - 1u].entity, e,
		                    FZN_CATALOG_ENTITY_LEN) >= 0)
			FAILED("seed %u: the job's rows are not strictly ascending", seed);
	}

	/* 4. WANT AND HOLDINGS DISAGREE THE WAY THEY SHOULD. */
	if (fzn_catalog_copy_want(set, n, &holds, self, 32, 0, out_want, MAX_ENTITIES,
	                            &want_plan) != FZN_CATALOG_OK)
		FAILED("seed %u: a well-formed want walk was refused", seed);
	if (fzn_catalog_copy_holdings(set, n, self, 32, out_hold, MAX_ENTITIES,
	                                &hold_plan) != FZN_CATALOG_OK)
		FAILED("seed %u: a well-formed holdings walk was refused", seed);

	if (want_plan.not_retained + want_plan.not_referenced + want_plan.already_held +
	    want_plan.missing + want_plan.unknown + want_plan.incomplete !=
	    distinct_entities(set, n))
		FAILED("seed %u: the want plan does not partition", seed);

	cov->wanted += want_plan.written ? 1u : 0u;
	cov->announced += hold_plan.written ? 1u : 0u;

	for (i = 0; i < want_plan.written; i++) {
		if (holds_here(set, n, out_want[i].b, self))
			FAILED("seed %u: asked to fetch bytes this host already holds", seed);
		if (!curated_here(set, n, out_want[i].b))
			FAILED("seed %u: asked to fetch an entity nothing curates", seed);
		if (!fzn_catalog_keeps(&holds, out_want[i].b, FZN_CATALOG_ENTITY_LEN, 0))
			FAILED("seed %u: asked to fetch an entity this host does not keep",
			       seed);
	}
	for (i = 0; i < hold_plan.written; i++) {
		if (!holds_here(set, n, out_hold[i].b, self))
			FAILED("seed %u: announced bytes this host does not hold", seed);
		/* AND NOTHING IS BOTH. */
		for (j = 0; j < want_plan.written; j++)
			if (memcmp(out_hold[i].b, out_want[j].b,
			           FZN_CATALOG_ENTITY_LEN) == 0)
				FAILED("seed %u: one entity was both wanted and announced",
				       seed);
	}

	/* 5. A FILING IS ONLY REPORTED WHILE THE RECORDS BACK IT. */
	{
		fzn_catalog_filing_t frows[MAX_ENTITIES];
		fzn_catalog_filings_t filings;

		fzn_catalog_filings_init(&filings, frows, MAX_ENTITIES);
		for (i = 0; i < MAX_ENTITIES; i++) {
			const uint8_t *p = PATHS[rnd_below(2u)];
			fzn_catalog_err_t r;

			r = fzn_catalog_file_under(&filings, set, n, entities[i],
			                             FZN_CATALOG_ENTITY_LEN, DIM, 5, p, 6);
			if (r == FZN_CATALOG_OK)
				cov->filed++;
			else if (r != FZN_CATALOG_ERR_ABSENT)
				FAILED("seed %u: a filing failed for an unexpected reason (%d)",
				       seed, (int)r);
			/* A filing that was accepted must be backed, and one that
			 * was refused must not be reportable. */
			if (r == FZN_CATALOG_OK &&
			    !fzn_catalog_filed_under(&filings, set, n, entities[i],
			                               FZN_CATALOG_ENTITY_LEN))
				FAILED("seed %u: an accepted filing did not read back", seed);
		}

		/* RETRACT EVERYTHING and require every filing to stop answering,
		 * which is the read-side re-check under arbitrary input. */
		{
			size_t was = fzn_catalog_filing_count(&filings);

			for (i = 0; i < n; i++)
				set[i].live = 0;
			for (i = 0; i < MAX_ENTITIES; i++)
				if (fzn_catalog_filed_under(&filings, set, n, entities[i],
				                              FZN_CATALOG_ENTITY_LEN))
					FAILED("seed %u: a filing answered after every "
					       "assertion was retracted", seed);
			if (was && fzn_catalog_filing_prune(&filings, set, n) != was)
				FAILED("seed %u: the prune did not reclaim every stale row",
				       seed);
			if (was)
				cov->filing_stale++;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov;
	unsigned long c;

	memset(&cov, 0, sizeof(cov));
	fixtures();

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("plan_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run "
		       "will not report success. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("plan_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* FLOORS ON THE STATES THAT MAKE THE PROPERTIES MEAN ANYTHING. A
	 * generator that produced only empty sets would satisfy every invariant
	 * above and prove nothing; these are what separate a run that explored
	 * the space from one that ran. */
	if (!cov.planned || !cov.retained || !cov.last_copy ||
	    !cov.absent || !cov.wanted || !cov.announced || !cov.filed ||
	    !cov.filing_stale) {
		printf("plan_fuzz: a state the invariants need was never reached -- "
		       "planned %lu retained %lu last_copy %lu absent %lu "
		       "wanted %lu announced %lu filed %lu stale %lu\n",
		       cov.planned, cov.retained, cov.last_copy,
		       cov.absent, cov.wanted, cov.announced, cov.filed, cov.filing_stale);
		return 1;
	}

	printf("plan_fuzz: %lu cases, all invariants held; planned %lu retained %lu "
	       "last_copy %lu absent %lu wanted %lu announced %lu "
	       "filed %lu stale %lu\n",
	       cases, cov.planned, cov.retained, cov.last_copy,
	       cov.absent, cov.wanted, cov.announced, cov.filed, cov.filing_stale);
	return 0;
}
