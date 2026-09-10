/*
 * A fuzz harness for link/link.c: is a snapshot the first N links, every
 * time, whatever has happened to them?
 *
 * WHY THIS ONE. `link.h` describes a permanent starvation and does not
 * apologise for it:
 *
 *   this table never reorders: entries are appended and never removed, so
 *   the links past the bound are the same links every call, and they are the
 *   most recently registered ones. A consumer can be told the network is
 *   down while a healthy link sits one index past the end, FOR EVER, and it
 *   never gathers evidence on that link either because nothing is ever sent
 *   on it.
 *
 * `link_test.c` checks the bound with two links and a cap of one. What it
 * does not check is the FOR EVER: that the same links are dropped on every
 * call, and that nothing a consumer can do to a starved link -- an ack, a
 * loss, marking it usable -- brings it into view.
 *
 * THIS PINS THAT AS THE DESIGN. It is `catalog`'s remove-does-not-commute
 * shape from sec 243: a limit somebody could meet, read as a defect, and
 * "fix" -- and the two obvious fixes are both worse than the behaviour. Any
 * rotation makes `sched`'s choice depend on when it was asked, and any
 * reordering breaks the cursor `link_test` relies on. **THIS HARNESS IS
 * EXPECTED TO FAIL THE DAY SOMEBODY ADDS ROTATION**, which is its purpose:
 * the change has to come here and say so.
 *
 * THE MODEL IS REGISTRATION ORDER, kept in this file. `fzn_link_snapshot`
 * fills from the table's own array, so a model that asked the table what
 * order it was in would agree with it always.
 *
 * FOUR PROPERTIES.
 *
 *   1. A snapshot of cap C is the first min(C, registered) links, by id, in
 *      the order they were registered.
 *   2. `dropped` is exactly what did not fit, so a consumer is never left to
 *      infer it from a short return.
 *   3. THE SAME CALL TWICE GIVES THE SAME ANSWER, which is the "for ever".
 *   4. Observations do not reorder. An ack, a loss or a usability change on
 *      any link -- starved or not -- leaves the snapshot's membership
 *      identical.
 */

#include "../link.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

/* Below this the floors are cleared by a single lucky case. */
#define FUZZ_MIN_CASES 1000u

/* The table's own capacity, and the most a case will register. */
#define LINKS_MAX 12u

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

struct coverage {
	unsigned long starved;
	unsigned long fitted;
	unsigned long observed_a_starved_link;
	unsigned long full_table;
	unsigned long empty;
};

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	fzn_link_entry_t entries[LINKS_MAX];
	fzn_link_table_t table;
	fzn_sched_candidate_t snap[LINKS_MAX];
	fzn_sched_candidate_t again[LINKS_MAX];
	uint32_t order[LINKS_MAX]; /* this file's own record of registration order */
	size_t registered = 0u;
	size_t cap, n, n2, i;
	size_t dropped = 99u, dropped2 = 99u;

	if (fzn_link_table_init(&table, entries, LINKS_MAX) != FZN_LINK_OK) {
		printf("  INVARIANT: the table would not init\n");
		return 1;
	}

	/* Register a few, with ids that are not their index so a snapshot
	 * cannot look right by accident. */
	registered = (size_t)(next(&state) % (LINKS_MAX + 1u));
	for (i = 0; i < registered; i++) {
		uint32_t id = 100u + (uint32_t)i * 7u;

		if (fzn_link_register(&table, id, 1u + (next(&state) % 50u),
		                      10u + (next(&state) % 400u),
		                      (uint16_t)(next(&state) % 200u),
		                      500u + (next(&state) % 1000u)) != FZN_LINK_OK) {
			printf("  INVARIANT: registering link %zu was refused\n", i);
			return 1;
		}
		order[i] = id;
	}
	if (registered == 0u)
		cov->empty++;
	if (registered == LINKS_MAX)
		cov->full_table++;

	/* ZEROED BEFORE EACH CALL, because these are compared with `memcmp`
	 * below and `fzn_sched_candidate_t` has padding: two bytes after
	 * `loss_permille`, which the compiler is free to leave as whatever the
	 * stack held. The first run of this harness failed on case 0 comparing
	 * those bytes, and the module was right. */
	memset(snap, 0, sizeof(snap));
	memset(again, 0, sizeof(again));

	cap = (size_t)(next(&state) % (LINKS_MAX + 1u));
	n = fzn_link_snapshot(&table, snap, cap, &dropped);

	/* PROPERTY 1: the first min(cap, registered), in registration order. */
	{
		size_t want = cap < registered ? cap : registered;

		if (n != want) {
			printf("  MODEL: a snapshot with room for %zu over %zu links returned "
			       "%zu\n",
			       cap, registered, n);
			return 1;
		}
		for (i = 0; i < n; i++) {
			if (snap[i].id != order[i]) {
				printf("  MODEL: snapshot slot %zu holds link %u and "
				       "registration order says %u, so the table reordered "
				       "-- which is what sched's cursor relies on not "
				       "happening\n",
				       i, snap[i].id, order[i]);
				return 1;
			}
		}
		/* PROPERTY 2. */
		if (dropped != registered - want) {
			printf("  MODEL: %zu links did not fit and %zu were reported\n",
			       registered - want, dropped);
			return 1;
		}
		if (dropped > 0u)
			cov->starved++;
		else
			cov->fitted++;
	}

	/*
	 * PROPERTY 3: THE SAME ANSWER AGAIN. This is the "for ever" -- a
	 * starved link is starved on every call, not merely on this one.
	 */
	memset(again, 0, sizeof(again));
	n2 = fzn_link_snapshot(&table, again, cap, &dropped2);
	if (n2 != n || dropped2 != dropped
	    || memcmp(snap, again, n * sizeof(snap[0])) != 0) {
		printf("  MODEL: two identical snapshots differ, so which links a consumer "
		       "sees depends on when it asked\n");
		return 1;
	}

	/*
	 * PROPERTY 4: NOTHING A CONSUMER DOES TO A LINK BRINGS IT INTO VIEW.
	 *
	 * The header's sharpest sentence is that a starved link "never gathers
	 * evidence ... because nothing is ever sent on it" -- so the case worth
	 * driving is a consumer that DOES gather evidence on one anyway, by
	 * hand, and finds it still invisible.
	 */
	if (registered > 0u) {
		size_t victim = (size_t)(next(&state) % registered);
		uint32_t id = order[victim];
		size_t n3;
		size_t dropped3 = 99u;

		if (fzn_link_observe_ack(&table, id, 1u + (next(&state) % 20u), 1000u)
		    != FZN_LINK_OK) {
			printf("  INVARIANT: an ack on a registered link was refused\n");
			return 1;
		}
		if (fzn_link_observe_loss(&table, id, 1001u) != FZN_LINK_OK) {
			printf("  INVARIANT: a loss on a registered link was refused\n");
			return 1;
		}
		if (fzn_link_set_usable(&table, id, 1) != FZN_LINK_OK) {
			printf("  INVARIANT: marking a registered link usable was refused\n");
			return 1;
		}
		if (victim >= n && dropped > 0u)
			cov->observed_a_starved_link++;

		memset(again, 0, sizeof(again));
		n3 = fzn_link_snapshot(&table, again, cap, &dropped3);
		if (n3 != n || dropped3 != dropped) {
			printf("  MODEL: observing a link changed how many a snapshot "
			       "returns\n");
			return 1;
		}
		for (i = 0; i < n3; i++) {
			if (again[i].id != snap[i].id) {
				printf("  MODEL: observing link %u moved link %u out of slot "
				       "%zu, so a measurement reordered the table\n",
				       id, snap[i].id, i);
				return 1;
			}
		}
	}

	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0 };

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
	struct coverage cov = { 0, 0, 0, 0, 0 };
	unsigned long c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("link_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will "
		       "not report success. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("link_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* FLOORS ON STATES. A run where everything always fitted has not
	 * touched the starvation this file exists for, and one that never
	 * observed a STARVED link has not asked the header's sharpest
	 * sentence. */
	if (cov.starved < floor_of(cases, 4u) || cov.fitted < floor_of(cases, 4u)
	    || cov.observed_a_starved_link < floor_of(cases, 20u)
	    || cov.full_table < floor_of(cases, 50u) || cov.empty < floor_of(cases, 50u)) {
		printf("link_fuzz: REACHED TOO LITTLE -- %lu starved, %lu fitted, %lu "
		       "observed a starved link, %lu full tables, %lu empty in %lu cases.\n",
		       cov.starved, cov.fitted, cov.observed_a_starved_link, cov.full_table,
		       cov.empty, cases);
		return 1;
	}

	printf("link_fuzz: %lu cases, %lu starved, %lu fitted, %lu observed a starved "
	       "link, %lu full tables, %lu empty, every snapshot was the first N in "
	       "registration order\n",
	       cases, cov.starved, cov.fitted, cov.observed_a_starved_link, cov.full_table,
	       cov.empty);
	return 0;
}
#endif
