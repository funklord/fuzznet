/* Does the vocabulary bound answer the same thing whatever order the table is
 * in, and does it ever admit what it should not?
 *
 * WHY A HARNESS AND NOT MORE ASSERTIONS. `vocabulary_test.c` checks order
 * independence with one table, built by hand, whose two rules were chosen to
 * expose the early-return bug. That is exactly one permutation of one table
 * against one peer -- and the property is about ALL of them. A consumer writes
 * its table in whatever order reads well, so the order is not something this
 * library gets to influence and not something a hand-picked case can cover.
 *
 * So: a random peer, a random table, a random verb, and the verdict computed
 * over every permutation the input asks for. Two things are asserted, and the
 * second is the one a single-module test cannot reach:
 *
 *   - **A MODEL.** Membership is recomputed here, independently -- a verb is
 *     admitted exactly when some rule names it for a group the peer is KNOWN
 *     to hold. Written out rather than asking the module, since a checker that
 *     asked `vocabulary.c` whether `vocabulary.c` was right would agree with
 *     it always.
 *   - **PERMUTATION INVARIANCE.** The same peer, verb and rules in a shuffled
 *     order must give the same verdict. This is the property the early-return
 *     bug violated, and it is a security property rather than a tidiness one:
 *     a verdict that depends on table order is one a consumer changes by
 *     reformatting.
 *
 * And the direction that matters, asserted separately because it is the one
 * that costs something: MEMBER is never returned for a peer whose groups could
 * not be read. UNKNOWN and NOT_MEMBER both deny, so confusing those two is a
 * quality-of-message problem; admitting on an unreadable group list is the
 * failure raidcfgd's requirement is about.
 */

#include "../vocabulary.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define MAX_RULES 6
#define MAX_VERBS 4

/* A small, fixed verb set, so that collisions between the asked verb and the
 * table's are common rather than astronomically rare. */
static const uint8_t VERB_A[] = "status";
static const uint8_t VERB_B[] = "monitor";
static const uint8_t VERB_C[] = "destroy";
static const uint8_t VERB_D[] = "statuses"; /* shares a prefix with VERB_A */

static const uint8_t *const VERBS[MAX_VERBS] = { VERB_A, VERB_B, VERB_C, VERB_D };
static const size_t VERB_LENS[MAX_VERBS] = { sizeof(VERB_A) - 1u, sizeof(VERB_B) - 1u,
	                                     sizeof(VERB_C) - 1u, sizeof(VERB_D) - 1u };

struct coverage {
	unsigned long admitted;
	unsigned long refused;
	unsigned long unknown;
};

/* The model: an independent answer to the same question. */
static fzn_peer_verdict_t model(const fzn_peer_t *peer, const uint8_t *verb, size_t verb_len,
                                const fzn_verb_rule_t *rules, size_t rule_count)
{
	int matched = 0;
	int unknown = 0;

	if (verb_len == 0 || verb_len > FZN_VERB_MAX)
		return FZN_PEER_NOT_MEMBER;

	for (size_t i = 0; i < rule_count; i++) {
		if (rules[i].verb_len != verb_len)
			continue;
		if (memcmp(rules[i].verb, verb, verb_len) != 0)
			continue;

		matched = 1;
		if (peer->primary_gid == rules[i].gid)
			return FZN_PEER_MEMBER;
		if (!peer->groups_known) {
			unknown = 1;
			continue;
		}
		for (size_t g = 0; g < peer->group_count; g++) {
			if (peer->groups[g] == rules[i].gid)
				return FZN_PEER_MEMBER;
		}
	}

	if (!matched)
		return FZN_PEER_NOT_MEMBER;
	return unknown ? FZN_PEER_UNKNOWN : FZN_PEER_NOT_MEMBER;
}

static uint32_t next(uint32_t *state)
{
	*state = (*state * 1103515245u) + 12345u;
	return (*state >> 16) & 0xffffu;
}

static int fuzz_one(const uint8_t *data, size_t len, struct coverage *cov)
{
	fzn_peer_t peer;
	fzn_verb_rule_t rules[MAX_RULES], shuffled[MAX_RULES];
	size_t rule_count;
	const uint8_t *verb;
	size_t verb_len;
	fzn_peer_verdict_t got, want, again;
	uint32_t state;

	if (len < 8)
		return 0;

	memset(&peer, 0, sizeof(peer));
	peer.groups_known = (data[0] & 1u) ? 1 : 0;
	peer.primary_gid = (uint32_t)(data[1] % 4u);
	peer.group_count = (size_t)(data[2] % 4u);
	for (size_t i = 0; i < peer.group_count; i++)
		peer.groups[i] = (uint32_t)(data[(3u + i) % len] % 4u);

	rule_count = (size_t)(data[3] % (MAX_RULES + 1u));
	for (size_t i = 0; i < rule_count; i++) {
		size_t pick = (size_t)(data[(4u + i) % len] % MAX_VERBS);

		rules[i].gid = (uint32_t)(data[(5u + i) % len] % 4u);
		rules[i].verb = VERBS[pick];
		rules[i].verb_len = VERB_LENS[pick];
	}

	{
		size_t pick = (size_t)(data[6] % MAX_VERBS);

		verb = VERBS[pick];
		verb_len = VERB_LENS[pick];
	}

	got = fzn_vocabulary_admit(&peer, verb, verb_len, rules, rule_count);
	want = model(&peer, verb, verb_len, rules, rule_count);
	if (got != want) {
		printf("  MODEL: verdict %d, model says %d\n", (int)got, (int)want);
		return 1;
	}

	/* THE DIRECTION THAT COSTS SOMETHING. */
	/* `rules[0]` is deliberately not consulted here. An earlier version
	 * guarded on it, which reads as a cheap early-out and is unsound: it
	 * indexes the table before anything has established the table is not
	 * empty. The loop below is the whole check and needs no help. */
	if (got == FZN_PEER_MEMBER && !peer.groups_known) {
		int held_primary = 0;

		for (size_t i = 0; i < rule_count; i++) {
			if (rules[i].verb_len == verb_len &&
			    memcmp(rules[i].verb, verb, verb_len) == 0 &&
			    peer.primary_gid == rules[i].gid)
				held_primary = 1;
		}
		if (!held_primary) {
			printf("  ADMIT: a verb was admitted for a peer whose groups could "
			       "not be read\n");
			return 1;
		}
	}

	/* PERMUTATION INVARIANCE, over a shuffle the input chooses. */
	memcpy(shuffled, rules, sizeof(rules));
	state = (uint32_t)data[7] + 1u;
	for (size_t i = rule_count; i > 1; i--) {
		size_t j = (size_t)(next(&state) % i);
		fzn_verb_rule_t t = shuffled[i - 1u];

		shuffled[i - 1u] = shuffled[j];
		shuffled[j] = t;
	}
	again = fzn_vocabulary_admit(&peer, verb, verb_len, shuffled, rule_count);
	if (again != got) {
		printf("  ORDER: %d before the shuffle, %d after -- the verdict depends on "
		       "how a consumer ordered its table\n",
		       (int)got, (int)again);
		return 1;
	}

	switch (got) {
	case FZN_PEER_MEMBER:
		cov->admitted++;
		break;
	case FZN_PEER_UNKNOWN:
		cov->unknown++;
		break;
	default:
		cov->refused++;
		break;
	}
	return 0;
}


/* THE FLOOR A COUNTER MUST CLEAR, AND IT IS NEVER ZERO.
 *
 * These floors were written as `floor_of(cases, 200u)` directly. Integer division
 * makes that ZERO for any run under 200 cases, and `unsigned < 0` is never
 * true -- so every coverage floor in this file switched itself off silently,
 * exactly when somebody lowered CASES. Which is precisely what one does when
 * running under a sanitizer, the case the Makefile advertises.
 *
 * Measured before this: `make fuzz CASES=199` exited 0 with chain_fuzz
 * reporting "0 delegated", the counter whose own comment says a run without
 * it "proves less than it says". At CASES=1 it reported 0 accepted and 0
 * delegated and still passed.
 *
 * One is the weakest honest floor: a harness that reached the interesting
 * path zero times out of one case has still reached it zero times. */
static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long n = cases / per;

	return n != 0ul ? n : 1ul;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov = { 0, 0, 0 };
	uint8_t buf[16];

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}

	for (unsigned long c = 0; c < cases; c++) {
		uint32_t state = (uint32_t)c + 1u;
		size_t len = (size_t)(next(&state) % (sizeof(buf) + 1u));

		for (size_t i = 0; i < len; i++)
			buf[i] = (uint8_t)next(&state);

		if (fuzz_one(buf, len, &cov)) {
			printf("vocabulary_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* All three verdicts must occur. A run that never admitted anything
	 * would satisfy every invariant above by never reaching the case they
	 * are about. */
	if (cov.admitted < floor_of(cases, 200u) || cov.refused < floor_of(cases, 200u) ||
	    cov.unknown < floor_of(cases, 200u)) {
		printf("vocabulary_fuzz: REACHED TOO LITTLE -- %lu admitted, %lu refused, "
		       "%lu unknown in %lu cases.\n",
		       cov.admitted, cov.refused, cov.unknown, cases);
		return 1;
	}

	printf("vocabulary_fuzz: %lu cases, %lu admitted, %lu refused, %lu unknown, "
	       "order never mattered\n",
	       cases, cov.admitted, cov.refused, cov.unknown);
	return 0;
}
