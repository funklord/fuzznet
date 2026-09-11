/*
 * A fuzz harness for catalog/reach.c, against a BFS written here.
 *
 * WHY THIS ONE IS DIFFERENT FROM `catalog_fuzz.c`. That one could only
 * assert PROPERTIES -- convergence, and a set that must not depend on order
 * -- because the merge rule's answer for a contested edge is order-dependent
 * by design and no oracle can predict it. sec 269 records what that cost: a
 * first draft whose two true properties discriminated almost nothing.
 *
 * Reachability has no such problem. "Which nodes do the roots reach" is a
 * question with ONE right answer for a given set of edges, and a breadth-
 * first search over an adjacency matrix is a completely separate way to get
 * it -- different code, different data structure, written from `reach.h`'s
 * sentence rather than from `reach.c`. That is the independent witness
 * `evidence.md` asks for and the strongest instrument available here.
 *
 * WHAT THE MODEL FOLLOWS, and it is `reach.h`'s own definition: a linked
 * edge. An edge asserted absent is a row in the table and NOT a path -- so
 * the model walks `fzn_catalog_linked` rather than the edge list, and a
 * tombstone leaves its nodes known and unreached.
 *
 * THE FRONTIER IS BUILT TO BE ACCEPTED, because a refusal is not the subject
 * here. Every issuer that asserted anything is vouched for at or above its
 * highest sequence, which is what `reach.h` demands; `reach_test.c` owns the
 * refusals, and this harness asserts it was NOT refused so that a case which
 * silently stopped answering cannot pass as agreement.
 */

#include "../reach.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

#define NODES 7u
#define ISSUERS 2u
#define MAX_EDGES 16u
#define MAX_ROOTS 2u

static const fzn_catalog_resolve_ops_t ADD_WINS = { fzn_catalog_add_wins, NULL };

struct coverage {
	unsigned long some_unreachable;
	unsigned long none_unreachable;
	unsigned long with_tombstone;
	unsigned long multi_root;
	unsigned long cycles;
	unsigned long refused_unknown_root;
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

static void id_of(fzn_catalog_id_t *out, unsigned which)
{
	memset(out, 0, sizeof(*out));
	out->b[0] = (uint8_t)(which + 1u);
	out->b[1] = (uint8_t)((which + 1u) ^ 0x5au);
}

static void key_of(uint8_t out[FZN_PUBKEY_LEN], unsigned which)
{
	memset(out, (int)(0xa0u + which), FZN_PUBKEY_LEN);
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	fzn_catalog_edge_t storage[MAX_EDGES];
	fzn_catalog_t cat;
	fzn_catalog_frontier_t frontier[ISSUERS];
	fzn_catalog_id_t roots[MAX_ROOTS], scratch[NODES], out[NODES];
	fzn_catalog_reach_t plan;
	uint64_t highest[ISSUERS];
	unsigned char adj[NODES][NODES];
	unsigned char known[NODES], reached[NODES];
	unsigned char is_root[NODES];
	unsigned queue[NODES];
	unsigned n, i, j, k, head = 0, tail = 0, root_count, model_unreachable = 0;
	unsigned model_reachable = 0, model_known = 0, tombstones = 0;
	int unknown_root = 0;
	fzn_catalog_err_t err;

	memset(adj, 0, sizeof(adj));
	memset(known, 0, sizeof(known));
	memset(reached, 0, sizeof(reached));
	memset(is_root, 0, sizeof(is_root));
	memset(highest, 0, sizeof(highest));
	memset(storage, 0, sizeof(storage));

	if (fzn_catalog_init(&cat, storage, MAX_EDGES, &ADD_WINS) != FZN_CATALOG_OK)
		return 1;

	n = 1u + (next(&state) % MAX_EDGES);
	for (i = 0; i < n; i++) {
		unsigned p = next(&state) % NODES;
		unsigned c = next(&state) % NODES;
		unsigned who = next(&state) % ISSUERS;
		uint64_t seq = 1u + (next(&state) % 4u);
		int present = (next(&state) % 4u) != 0u;
		fzn_catalog_id_t parent, child;
		uint8_t issuer[FZN_PUBKEY_LEN];

		if (p == c)
			continue;       /* a set cannot contain itself; refused */
		id_of(&parent, p);
		id_of(&child, c);
		key_of(issuer, who);
		err = fzn_catalog_assert(&cat, &parent, &child, issuer, seq, present);
		if (err != FZN_CATALOG_OK && err != FZN_CATALOG_ERR_STALE) {
			if (err == FZN_CATALOG_ERR_FULL)
				break;
			printf("  MODEL: assert answered %s\n", fzn_catalog_err_str(err));
			return 1;
		}
		if (seq > highest[who])
			highest[who] = seq;
	}

	/* THE MODEL READS THE CATALOGUE BACK rather than replaying the set:
	 * which edges survived the merge is catalog.c's business and sec 269's
	 * subject, not this harness's. What is on trial is the WALK over
	 * whatever the table ended up holding. */
	for (i = 0; i < NODES; i++)
		for (j = 0; j < NODES; j++) {
			fzn_catalog_id_t parent, child;

			if (i == j)
				continue;
			id_of(&parent, i);
			id_of(&child, j);
			if (fzn_catalog_edge_of(&cat, &parent, &child) == NULL)
				continue;
			/* A TOMBSTONE MAKES NEITHER END A KNOWN NODE, which
			 * reach.c decides in `candidate` by skipping an edge
			 * that is not present, and reach.h does not say. The
			 * behaviour is right -- a node mentioned only in an
			 * unlink has no live membership, and `unreachable`
			 * proposes DELETIONS, so proposing it would be acting
			 * on a row that says "not a member". The model had it
			 * wrong until the implementation settled it. */
			if (fzn_catalog_linked(&cat, &parent, &child)) {
				known[i] = known[j] = 1;
				adj[i][j] = 1;
			} else {
				tombstones++;
			}
		}

	root_count = 1u + (next(&state) % MAX_ROOTS);
	for (i = 0; i < root_count; i++) {
		unsigned r = next(&state) % NODES;

		id_of(&roots[i], r);
		is_root[r] = 1;
		if (known[r] && !reached[r]) {
			reached[r] = 1;
			queue[tail++] = r;
		}
	}

	while (head < tail) {
		unsigned at = queue[head++];

		for (j = 0; j < NODES; j++)
			if (adj[at][j] && !reached[j]) {
				reached[j] = 1;
				queue[tail++] = j;
			}
	}

	for (i = 0; i < NODES; i++) {
		if (!known[i])
			continue;
		model_known++;
		if (reached[i])
			model_reachable++;
		else
			model_unreachable++;
	}

	for (i = 0; i < ISSUERS; i++) {
		key_of(frontier[i].issuer, i);
		frontier[i].received = highest[i] + 1u;
	}

	for (i = 0; i < root_count; i++) {
		unsigned which = (unsigned)(roots[i].b[0] - 1u);

		if (which < NODES && !known[which])
			unknown_root = 1;
	}

	memset(&plan, 0, sizeof(plan));
	err = fzn_catalog_unreachable(&cat, roots, root_count, frontier, ISSUERS,
	                              scratch, NODES, out, NODES, &plan);

	/* A ROOT THE CATALOGUE DOES NOT KNOW IS REFUSED, and the harness asks
	 * for that rather than avoiding it. reach.c checks the roots before the
	 * frontier and says why: a walk from a node it has never heard of
	 * reaches nothing and "would otherwise propose everything", which is a
	 * proposal to delete the whole catalogue. The first draft here treated
	 * the refusal as a defect -- the model was wrong and the library's own
	 * comment said so. */
	if (unknown_root) {
		if (err != FZN_CATALOG_ERR_ABSENT) {
			printf("  MODEL: a root this catalogue has never heard of was walked "
			       "from rather than refused -- answered %s\n",
			       fzn_catalog_err_str(err));
			return 1;
		}
		cov->refused_unknown_root++;
		return 0;
	}

	if (err != FZN_CATALOG_OK) {
		/* NOT A RESULT, AND NOT IGNORED. Every root is known and every
		 * issuer that asserted is vouched for above its highest
		 * sequence, so a refusal here is either a defect or a fixture
		 * that has stopped asking the question -- and the second is how
		 * a harness quietly agrees with nothing. */
		printf("  MODEL: the walk refused with %s, and every root is known and "
		       "every issuer vouched for\n", fzn_catalog_err_str(err));
		return 1;
	}

	if (plan.unreachable != model_unreachable || plan.reachable != model_reachable) {
		printf("  MODEL: the walk says %zu reachable and %zu not; a breadth-first "
		       "search over the same edges says %u and %u\n",
		       plan.reachable, plan.unreachable, model_reachable, model_unreachable);
		return 1;
	}
	if (fzn_catalog_nodes(&cat) != model_known) {
		printf("  MODEL: the catalogue counts %zu known nodes and the model counts "
		       "%u\n", fzn_catalog_nodes(&cat), model_known);
		return 1;
	}

	/* AND WHICH ONES, not merely how many. Two sets of equal size can
	 * disagree about every member. */
	for (i = 0; i < plan.unreachable && i < NODES; i++) {
		unsigned which = NODES;

		for (j = 0; j < NODES; j++) {
			fzn_catalog_id_t node;

			id_of(&node, j);
			if (memcmp(&node, &out[i], sizeof(node)) == 0) {
				which = j;
				break;
			}
		}
		if (which == NODES) {
			printf("  MODEL: the walk named a node the fixture never built\n");
			return 1;
		}
		if (reached[which] || !known[which]) {
			printf("  MODEL: the walk calls node %u unreachable; the search "
			       "reaches it\n", which);
			return 1;
		}
	}

	if (model_unreachable > 0u)
		cov->some_unreachable++;
	else
		cov->none_unreachable++;
	if (tombstones > 0u)
		cov->with_tombstone++;
	if (root_count > 1u)
		cov->multi_root++;
	for (i = 0; i < NODES; i++)
		for (j = 0; j < NODES; j++)
			if (adj[i][j] && adj[j][i]) {
				cov->cycles++;
				i = j = NODES;
			}
	(void)k;
	(void)is_root;
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
		printf("reach_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run "
		       "will not report success. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("reach_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	if (cov.some_unreachable < floor_of(cases, 4u)
	    || cov.none_unreachable < floor_of(cases, 20u)
	    || cov.with_tombstone < floor_of(cases, 4u)
	    || cov.multi_root < floor_of(cases, 4u)
	    || cov.cycles < floor_of(cases, 50u)
	    || cov.refused_unknown_root < floor_of(cases, 50u)) {
		printf("reach_fuzz: REACHED TOO LITTLE -- %lu with something unreachable, "
		       "%lu with nothing, %lu with a tombstone, %lu multi-root, %lu with a "
		       "cycle, %lu refused for an unknown root, in %lu cases.\n",
		       cov.some_unreachable, cov.none_unreachable, cov.with_tombstone,
		       cov.multi_root, cov.cycles, cov.refused_unknown_root, cases);
		return 1;
	}

	printf("reach_fuzz: %lu cases, %lu with something unreachable, %lu with "
	       "nothing, %lu with a tombstone, %lu multi-root, %lu with a cycle, %lu "
	       "refused for an unknown root, and a breadth-first search agreed on the "
	       "rest\n",
	       cases, cov.some_unreachable, cov.none_unreachable, cov.with_tombstone,
	       cov.multi_root, cov.cycles, cov.refused_unknown_root);
	return 0;
}
#endif
