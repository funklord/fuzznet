/*
 * A fuzz harness for catalog/catalog.c: what survives being told in a
 * different order?
 *
 * WHY THIS ONE. `catalog.h` argues at length that its merge rule converges
 * across issuers -- "two hosts adding a member agree whatever order the
 * assertions arrive in" -- and sec 243 tested that with TWO assertions in
 * opposite orders. Two is where an order-dependence is least likely to show.
 * It also pinned the limit, at three: with an unlink in the set, whether it
 * applies depends on which link the table holds when it arrives, so the
 * membership answer CAN differ by order and `catalog.h` says why that is the
 * chosen design rather than a defect.
 *
 * So this asserts two properties and is careful about which is which.
 *
 *   1. LINKS ALONE CONVERGE. Over a set of assertions that are all
 *      `present`, every permutation must agree on every edge. This is the
 *      property the header claims, asked at up to ten assertions across
 *      three issuers rather than at two.
 *
 *   2. THE EDGE SET CONVERGES WHATEVER THE MIX. With unlinks in the set,
 *      membership may differ -- sec 243 -- but WHICH edges the table holds
 *      may not: an assertion about an unknown edge adds it, and the resolver
 *      chooses between two answers for an edge rather than removing one. So
 *      `fzn_catalog_edge_of` must be non-NULL for exactly the asserted pairs
 *      in every order, even where `fzn_catalog_linked` disagrees.
 *
 * THE SECOND IS THE ONE WORTH HAVING, because it is the property that
 * separates the documented divergence from a real one. A defect that lost an
 * edge, or invented one, would show up here while every membership answer
 * stayed plausible.
 *
 * CAPACITY IS THE WHOLE UNIVERSE, deliberately. With a table too small to
 * hold every asserted pair, which edges fit is a function of arrival order
 * and property 2 would be false by construction -- FZN_CATALOG_ERR_FULL is
 * `catalog_test.c`'s subject and not this one's.
 */

#include "../catalog.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

/* Below this the floors are cleared by a single lucky case. Same number and
 * reasoning as the other harnesses here. */
#define FUZZ_MIN_CASES 1000u

#define PARENTS 3u
#define CHILDREN 4u
#define ISSUERS 3u
#define EDGES (PARENTS * CHILDREN)
#define MAX_ASSERTIONS 10u

struct assertion {
	uint8_t parent;
	uint8_t child;
	uint8_t issuer;
	uint64_t seq;
	int present;
};

struct coverage {
	unsigned long links_only;
	unsigned long with_unlink;
	unsigned long same_issuer_again;
	unsigned long cross_issuer;
	unsigned long stale_reported;
	unsigned long membership_differed;
	unsigned long oracle_checked;
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

static void id_of(fzn_catalog_id_t *out, uint8_t which)
{
	memset(out, 0, sizeof(*out));
	out->b[0] = which;
	out->b[1] = (uint8_t)(which ^ 0x5au);
}

static void key_of(uint8_t out[FZN_PUBKEY_LEN], uint8_t which)
{
	memset(out, (int)(0xa0u + which), FZN_PUBKEY_LEN);
}

/* FILE SCOPE, and the first draft got this wrong in the way this tree has a
 * section about. `fzn_catalog_init` KEEPS the pointer it is given, so a
 * compound literal in the call -- which was the first version -- dies when
 * the function returns and leaves the catalogue reading a resolver off a
 * dead frame. It segfaulted on case 0. sec 86 is the same fault found by
 * AddressSanitizer in a test that had passed `make check` a dozen times;
 * here it was loud because the frame was reused immediately. */
static const fzn_catalog_resolve_ops_t ADD_WINS = { fzn_catalog_add_wins, NULL };

/* Apply a set in the given order, and report whether the run was clean. */
static int apply(fzn_catalog_t *cat, fzn_catalog_edge_t *edges,
                 const struct assertion *set, const uint8_t *order, unsigned n,
                 struct coverage *cov, int count_stale)
{
	unsigned i;

	memset(edges, 0, sizeof(*edges) * EDGES);
	if (fzn_catalog_init(cat, edges, EDGES, &ADD_WINS) != FZN_CATALOG_OK)
		return 0;

	for (i = 0; i < n; i++) {
		const struct assertion *a = &set[order[i]];
		fzn_catalog_id_t parent, child;
		uint8_t issuer[FZN_PUBKEY_LEN];
		fzn_catalog_err_t err;

		id_of(&parent, a->parent);
		id_of(&child, (uint8_t)(PARENTS + a->child));
		key_of(issuer, a->issuer);

		err = fzn_catalog_assert(cat, &parent, &child, issuer, a->seq, a->present);
		if (err != FZN_CATALOG_OK && err != FZN_CATALOG_ERR_STALE) {
			printf("  MODEL: assert %u of %u answered %s, and the table has "
			       "room for every pair this case can name\n",
			       i, n, fzn_catalog_err_str(err));
			return 0;
		}
		if (err == FZN_CATALOG_ERR_STALE && count_stale)
			cov->stale_reported++;
	}
	return 1;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	struct assertion set[MAX_ASSERTIONS];
	uint8_t first[MAX_ASSERTIONS], second[MAX_ASSERTIONS];
	fzn_catalog_edge_t edges_a[EDGES], edges_b[EDGES];
	fzn_catalog_t a, b;
	unsigned n, i, p, c;
	int links_only = 1, saw_same_issuer = 0, saw_cross = 0, differed = 0;

	n = 2u + (next(&state) % (MAX_ASSERTIONS - 1u));
	for (i = 0; i < n; i++) {
		set[i].parent = (uint8_t)(next(&state) % PARENTS);
		set[i].child = (uint8_t)(next(&state) % CHILDREN);
		set[i].issuer = (uint8_t)(next(&state) % ISSUERS);
		/* A SMALL RANGE, so supersession by sequence actually happens.
		 * Drawn from the whole 64-bit range it never would. */
		set[i].seq = 1u + (next(&state) % 3u);
		set[i].present = (next(&state) % 4u) != 0u;
		if (!set[i].present)
			links_only = 0;
	}
	for (i = 0; i < n; i++)
		for (unsigned j = i + 1u; j < n; j++) {
			if (set[i].parent == set[j].parent && set[i].child == set[j].child) {
				if (set[i].issuer == set[j].issuer)
					saw_same_issuer = 1;
				else
					saw_cross = 1;
			}
		}

	for (i = 0; i < n; i++)
		first[i] = (uint8_t)i;
	memcpy(second, first, sizeof(second));
	/* TWO ORDERS, and the second is shuffled rather than reversed: a
	 * reversal is one permutation of n! and the pair that disagrees need
	 * not be the pair at the ends. */
	for (i = n; i > 1u; i--) {
		unsigned j = next(&state) % i;
		uint8_t t = second[i - 1u];

		second[i - 1u] = second[j];
		second[j] = t;
	}

	if (!apply(&a, edges_a, set, first, n, cov, 1))
		return 1;
	if (!apply(&b, edges_b, set, second, n, cov, 0))
		return 1;

	for (p = 0; p < PARENTS; p++)
		for (c = 0; c < CHILDREN; c++) {
			fzn_catalog_id_t parent, child;
			const fzn_catalog_edge_t *e_a;
			int held_a, held_b, has_a, has_b;
			unsigned speakers = 0, ties = 0, k;
			uint64_t best_seq = 0;
			int best_present = 0, seen = 0;
			uint8_t who = 0;

			id_of(&parent, (uint8_t)p);
			id_of(&child, (uint8_t)(PARENTS + c));

			has_a = fzn_catalog_edge_of(&a, &parent, &child) != NULL;
			has_b = fzn_catalog_edge_of(&b, &parent, &child) != NULL;
			if (has_a != has_b) {
				printf("  MODEL: edge (%u,%u) is held in one order and not the "
				       "other -- the SET of edges must not depend on arrival "
				       "order, whatever the membership answer is\n", p, c);
				return 1;
			}

			/* AN ORACLE, for the one shape whose outcome the rule
			 * fixes regardless of order: an edge ONE issuer speaks
			 * about, with no two statements sharing a sequence.
			 * `fzn_catalog_add_wins` gives that issuer's later
			 * statement, so the answer is its highest sequence --
			 * computed here from the SET rather than read from the
			 * catalogue.
			 *
			 * The ties are excluded because `offered->seq >
			 * held->seq` keeps what is held on equality, so two
			 * statements at one sequence resolve by arrival and the
			 * outcome is genuinely order-dependent. That is the
			 * rule working; it is simply not a case an oracle can
			 * predict. */
			for (k = 0; k < n; k++) {
				if (set[k].parent != p || set[k].child != c)
					continue;
				if (!seen) {
					seen = 1;
					who = set[k].issuer;
				} else if (set[k].issuer != who) {
					speakers = 2;
				}
				for (unsigned q = 0; q < k; q++)
					if (set[q].parent == p && set[q].child == c &&
					    set[q].seq == set[k].seq)
						ties = 1;
				if (set[k].seq > best_seq) {
					best_seq = set[k].seq;
					best_present = set[k].present;
				}
			}
			e_a = fzn_catalog_edge_of(&a, &parent, &child);
			if (seen && speakers < 2u && !ties && e_a) {
				cov->oracle_checked++;
				if (e_a->seq != best_seq ||
				    (e_a->present ? 1 : 0) != (best_present ? 1 : 0)) {
					printf("  MODEL: edge (%u,%u) has one issuer and no tied "
					       "sequences, so it must hold that issuer's highest "
					       "-- seq %llu present %d, and the set's highest is "
					       "seq %llu present %d\n",
					       p, c, (unsigned long long)e_a->seq, e_a->present,
					       (unsigned long long)best_seq, best_present);
					return 1;
				}
			}

			held_a = fzn_catalog_linked(&a, &parent, &child);
			held_b = fzn_catalog_linked(&b, &parent, &child);
			if (held_a != held_b) {
				if (links_only) {
					printf("  MODEL: edge (%u,%u) is linked in one order and "
					       "not the other, with no unlink in the set -- "
					       "catalog.h says two hosts adding a member agree "
					       "whatever the order\n", p, c);
					return 1;
				}
				differed = 1;
			}
		}

	if (links_only)
		cov->links_only++;
	else
		cov->with_unlink++;
	if (saw_same_issuer)
		cov->same_issuer_again++;
	if (saw_cross)
		cov->cross_issuer++;
	if (differed)
		cov->membership_differed++;
	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0 };

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
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0 };
	unsigned long c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("catalog_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run "
		       "will not report success. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("catalog_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* FLOORS ON THE STATES THAT MAKE THE PROPERTIES MEAN ANYTHING. A run
	 * with no link-only set has not tested convergence; one with no unlink
	 * has not tested that the edge set survives them; one where no two
	 * assertions ever name the same edge has tested no resolution at all.
	 *
	 * `membership_differed` HAS NO FLOOR ON PURPOSE. It counts the sec 243
	 * divergence, which is a documented non-property: requiring it to
	 * happen would make this suite fail the day somebody implements an
	 * OR-Set, which is exactly the change sec 243 wants brought here to be
	 * argued rather than broken. It is printed so the number is visible. */
	if (cov.links_only < floor_of(cases, 20u) || cov.with_unlink < floor_of(cases, 4u)
	    || cov.same_issuer_again < floor_of(cases, 20u)
	    || cov.cross_issuer < floor_of(cases, 20u)
	    || cov.stale_reported < floor_of(cases, 20u)
	    || cov.oracle_checked < floor_of(cases, 4u)) {
		printf("catalog_fuzz: REACHED TOO LITTLE -- %lu link-only, %lu with an "
		       "unlink, %lu re-asserted by one issuer, %lu contested across "
		       "issuers, %lu stale answers, %lu oracle checks in %lu cases.\n",
		       cov.links_only, cov.with_unlink, cov.same_issuer_again,
		       cov.cross_issuer, cov.stale_reported, cov.oracle_checked, cases);
		return 1;
	}

	printf("catalog_fuzz: %lu cases, %lu link-only (all converged), %lu with an "
	       "unlink, %lu re-asserted by one issuer, %lu contested across issuers, "
	       "%lu stale, %lu single-issuer edges matched the oracle, %lu where "
	       "membership differed by order and the edge set did not\n",
	       cases, cov.links_only, cov.with_unlink, cov.same_issuer_again,
	       cov.cross_issuer, cov.stale_reported, cov.oracle_checked,
	       cov.membership_differed);
	return 0;
}
#endif
