/*
 * A fuzz harness for the distribution planner.
 *
 * WHY THIS ONE. `fzn_sync_plan_offer` and `fzn_sync_plan_fetch` take
 * `theirs` -- A PEER'S DIGEST -- and that is the most attacker-shaped input in
 * this library. The peer chooses how many positions to send, what is in them,
 * whether they repeat, and in what order. Nothing about the argument is
 * verified, because there is nothing to verify: a digest is a claim, not a
 * signed object.
 *
 * It is also the surface with the worst history here, which is what earns it a
 * harness rather than another round of unit cases. Two defects, both recorded
 * in `sync.c` at the lines that carry them:
 *
 *   THE AMPLIFIER. `fzn_sync_plan_offer` read an absent position as a position
 *   of zero, so a digest containing NOTHING asked for everything -- measured
 *   at 64 ranges over 32,768 records, from a message with no content in it.
 *
 *   THE ORDERING. `theirs_for` kept the LAST matching position rather than the
 *   largest, under a comment claiming exactly the property that does not give.
 *   With two entries for one stream the PEER chose the answer by putting one
 *   of them last.
 *
 * SO THE PROPERTIES ARE MODEL PROPERTIES, and three of them are those defects
 * stated as invariants that cannot be satisfied by accident:
 *
 *   1. ORDER INDEPENDENCE. Permuting `theirs` must not change the plan. This
 *      is the ordering defect directly: it is the one thing a peer must not be
 *      able to influence by choosing an order.
 *   2. DUPLICATE INDEPENDENCE. Repeating a position must not change the plan.
 *      A peer that sends one stream five times must not get five slots.
 *   3. NO AMPLIFICATION. `request_count` is bounded by THIS HOST'S journal,
 *      never by `their_count`. A digest of a thousand phantom issuers must
 *      produce no more ranges than a digest of one.
 *
 * And four that are ordinary bounds, checked because a planner that reports
 * every bound is what `sync.h` promises and a promise nobody checks decays:
 *
 *   4. `request_count <= out_cap`, and nothing written past it.
 *   5. Over the cap, `positions_ignored` accounts for exactly the excess.
 *   6. A refusal clears the plan -- the 0x33 incident, where a reused plan
 *      came back from a refused call with request_count 3689348814741910323.
 *   7. Every range is inside what the journal and the peer actually claim:
 *      `from >= 1`, `count >= 1`, `count <= max_per_request`.
 *
 * THE PLAN IS COMPARED AS A SET, not as an array, because the order of the
 * plan is this host's journal order and permuting the PEER's positions must
 * not disturb it -- but comparing arrays would also fail if the planner
 * legitimately reordered, and that is not the property being asserted. A
 * set comparison fails only when the CONTENT differs.
 */

#include "../sync.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

/* Small enough that collisions between issuers are common -- a planner that
 * mixes two issuers up needs them to be confusable before it can. */
#define ISSUERS 4u
#define STREAMS 3u
#define JOURNAL_CAP 8u
#define THEIRS_CAP 16u

/* SMALLER THAN THE JOURNAL ON PURPOSE. `request_count` is bounded by
 * `journal.used`, so with an `out_cap` of 8 over a journal of 8 the truncation
 * path is unreachable and the harness reported 0 truncations while its own
 * header claimed to check that a bound is reported rather than dropped.
 * Measured before it was fixed, which is why the floors below now require it:
 * a counter nobody floors is a path nobody exercises. */
#define OUT_CAP 4u

struct coverage {
	unsigned long planned;
	unsigned long empty_plan;
	unsigned long truncated;
	unsigned long unknown;
	unsigned long ignored;
	unsigned long duplicates_sent;
	unsigned long refused;
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

static void issuer_bytes(uint8_t out[FZN_PUBKEY_LEN], unsigned which)
{
	size_t i;

	out[0] = (uint8_t)which;
	for (i = 1; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(which * 37u + i);
}

/* OVER THE EXAMINATION CAP, which is 1024 and therefore not reachable from a
 * stack array sized for the ordinary case. Static because 1032 positions is
 * about 45 KiB and this library's own rule is that nothing allocates; a file
 * scope array costs the harness's image rather than its stack, and the
 * alternative was leaving `positions_ignored` at zero for ever. */
static fzn_sync_position_t crowd[FZN_SYNC_MAX_POSITIONS + 8u];

/* A request is compared by its whole content, so a planner that got an issuer
 * or a stream wrong fails even when the counts agree. */
static int same_request(const fzn_sync_request_t *a, const fzn_sync_request_t *b)
{
	return a->stream == b->stream && a->from == b->from && a->count == b->count
	       && memcmp(a->issuer, b->issuer, FZN_PUBKEY_LEN) == 0;
}

/* Set equality, both directions, with multiplicity. Written out rather than
 * sorted because a comparator over four fields is more code than this and has
 * its own way of being wrong. */
static int same_plan(const fzn_sync_request_t *a, size_t an, const fzn_sync_request_t *b,
                     size_t bn)
{
	unsigned char used[OUT_CAP];
	size_t i, j;

	if (an != bn)
		return 0;
	memset(used, 0, sizeof(used));
	for (i = 0; i < an; i++) {
		int matched = 0;

		for (j = 0; j < bn; j++) {
			if (used[j] || !same_request(&a[i], &b[j]))
				continue;
			used[j] = 1;
			matched = 1;
			break;
		}
		if (!matched)
			return 0;
	}
	return 1;
}

/* Does `theirs` mention this (issuer, stream)? An independent walk, because a
 * model that asked `sync.c` would agree with it always, including when both
 * are wrong -- which is what `evidence.md` means by one witness twice. */
static int mentioned(const fzn_sync_position_t *theirs, size_t look,
                     const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream)
{
	size_t i;

	for (i = 0; i < look; i++) {
		if (theirs[i].stream == stream
		    && memcmp(theirs[i].issuer, issuer, FZN_PUBKEY_LEN) == 0)
			return 1;
	}
	return 0;
}

/* Does the journal follow this (issuer, stream)? */
static int followed(const fzn_journal_t *journal, const uint8_t issuer[FZN_PUBKEY_LEN],
                    uint32_t stream)
{
	size_t i;

	for (i = 0; i < journal->used; i++) {
		if (journal->entries[i].stream == stream
		    && memcmp(journal->entries[i].issuer, issuer, FZN_PUBKEY_LEN) == 0)
			return 1;
	}
	return 0;
}

/*
 * THE AMPLIFIER, STATED AS A MODEL. This is the check the harness was missing:
 * with only order-independence, duplicate-independence and bounds, restoring
 * the 2026 amplifier -- `fzn_sync_plan_offer` reading an absent position as a
 * position of zero -- SURVIVED 20000 cases. It had to, because offering from
 * zero for an unmentioned stream does not raise `request_count` above
 * `journal.used`: there are at most that many streams to offer. The harm is
 * the VOLUME of each range, not the number of them, and no bound could see it.
 *
 * So the rule is modelled instead, in the words `sync.c` uses at the line it
 * lives on: an absent position is not a position of zero. For an OFFER, a
 * stream the peer did not mention produces no range and is COUNTED; for a
 * FETCH, `unknown_issuers` counts the peer's positions this host does not
 * follow, which is the mirror rule and a different quantity.
 */
static int unknown_agrees(int offer, const fzn_journal_t *journal,
                          const fzn_sync_position_t *theirs, size_t their_count,
                          const fzn_sync_request_t *out, const fzn_sync_plan_t *plan)
{
	size_t look = their_count < FZN_SYNC_MAX_POSITIONS ? their_count
	                                                   : FZN_SYNC_MAX_POSITIONS;
	size_t want = 0;
	size_t i;

	if (offer) {
		for (i = 0; i < journal->used; i++) {
			if (!mentioned(theirs, look, journal->entries[i].issuer,
			               journal->entries[i].stream))
				want++;
		}
		/* AND NOTHING UNMENTIONED IS OFFERED. The count alone would
		 * pass a planner that counted correctly and offered anyway. */
		for (i = 0; i < plan->request_count; i++) {
			if (!mentioned(theirs, look, out[i].issuer, out[i].stream))
				return 0;
		}
	} else {
		for (i = 0; i < look; i++) {
			if (!followed(journal, theirs[i].issuer, theirs[i].stream))
				want++;
		}
	}

	return plan->unknown_issuers == want;
}

static int ranges_sane(const fzn_sync_request_t *out, const fzn_sync_plan_t *plan,
                       uint64_t max_per_request, size_t out_cap)
{
	size_t i;

	if (plan->request_count > out_cap)
		return 0;
	for (i = 0; i < plan->request_count; i++) {
		/* Sequence zero is reserved -- `fzn_record_open` refuses it by
		 * name -- so a range starting there is one the peer can never
		 * satisfy. */
		if (out[i].from == 0u)
			return 0;
		if (out[i].count == 0u)
			return 0;
		if (out[i].count > max_per_request)
			return 0;
	}
	return 1;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed ? seed : 1u;
	fzn_journal_t journal;
	fzn_journal_entry_t entries[JOURNAL_CAP];
	fzn_sync_position_t theirs[THEIRS_CAP];
	fzn_sync_position_t shuffled[THEIRS_CAP];
	fzn_sync_position_t doubled[THEIRS_CAP * 2u];
	fzn_sync_request_t out[OUT_CAP], out2[OUT_CAP];
	fzn_sync_plan_t plan, plan2;
	size_t their_count = next(&state) % (THEIRS_CAP + 1u);
	/* HALF THE CASES FILL THE JOURNAL, because truncation needs more
	 * matching entries than `out_cap` and a uniform draw over 0..8 reached
	 * it only 102 times in 20000 -- below its own floor. The other half
	 * stays uniform so an empty and a nearly-empty journal are still
	 * ordinary rather than rare. */
	size_t mine = (next(&state) % 2u) ? JOURNAL_CAP
	                                  : (next(&state) % (JOURNAL_CAP + 1u));
	uint64_t max_per_request = 1u + (next(&state) % 64u);
	int offer = (next(&state) % 2u) == 0u;
	size_t i;
	size_t doubled_count = 0;

	if (fzn_journal_init(&journal, entries, JOURNAL_CAP) != FZN_JOURNAL_OK)
		return 1;

	for (i = 0; i < mine; i++) {
		uint8_t who[FZN_PUBKEY_LEN];
		uint32_t stream = next(&state) % STREAMS;
		uint64_t at = next(&state) % 40u;

		issuer_bytes(who, next(&state) % ISSUERS);
		/* Anchor at zero to follow, then admit up to `at` so the entry
		 * has a real position rather than a poked one. */
		if (fzn_journal_anchor(&journal, who, stream, 0) == FZN_JOURNAL_OK) {
			uint64_t s;

			for (s = 1; s <= at; s++)
				(void)fzn_journal_admit(&journal, who, stream, s);
		}
	}

	for (i = 0; i < their_count; i++) {
		issuer_bytes(theirs[i].issuer, next(&state) % ISSUERS);
		theirs[i].stream = next(&state) % STREAMS;
		theirs[i].received = next(&state) % 60u;
	}

	/* ONE CASE IN SIXTEEN SENDS MORE THAN THE EXAMINATION CAP, so the
	 * `positions_ignored` path is reached rather than merely described.
	 * The excess is accounted for exactly, which is the promise `sync.h`
	 * makes about that field. */
	if ((next(&state) % 16u) == 0u) {
		size_t n = FZN_SYNC_MAX_POSITIONS + 1u + (next(&state) % 8u);

		for (i = 0; i < n; i++) {
			issuer_bytes(crowd[i].issuer, (unsigned)(i % ISSUERS));
			crowd[i].stream = (uint32_t)(i % STREAMS);
			crowd[i].received = (uint64_t)(i % 60u);
		}
		memset(&plan, 0x33, sizeof(plan));
		memset(out, 0, sizeof(out));
		if ((offer ? fzn_sync_plan_offer : fzn_sync_plan_fetch)(
		            &journal, crowd, n, max_per_request, out, OUT_CAP, &plan)
		    != FZN_SYNC_OK)
			return 1;
		if (plan.positions_ignored != n - FZN_SYNC_MAX_POSITIONS)
			return 1;
		if (plan.request_count > journal.used || plan.request_count > OUT_CAP)
			return 1;
		cov->ignored++;
		return 0;
	}

	memset(&plan, 0x33, sizeof(plan));
	memset(out, 0, sizeof(out));
	if ((offer ? fzn_sync_plan_offer : fzn_sync_plan_fetch)(
	            &journal, theirs, their_count, max_per_request, out, OUT_CAP, &plan)
	    != FZN_SYNC_OK)
		return 1;

	if (!ranges_sane(out, &plan, max_per_request, OUT_CAP))
		return 1;

	/* NO AMPLIFICATION: bounded by this host's journal, never by the peer's
	 * count. This is the property the offer amplifier violated. */
	if (plan.request_count > journal.used)
		return 1;

	if (!unknown_agrees(offer, &journal, theirs, their_count, out, &plan))
		return 1;

	if (plan.request_count == 0u)
		cov->empty_plan++;
	else
		cov->planned++;
	if (plan.truncated)
		cov->truncated++;
	if (plan.unknown_issuers)
		cov->unknown++;
	if (plan.positions_ignored)
		cov->ignored++;

	/* 1. ORDER INDEPENDENCE. */
	memcpy(shuffled, theirs, their_count * sizeof(theirs[0]));
	for (i = their_count; i > 1u; i--) {
		size_t j = next(&state) % i;
		fzn_sync_position_t tmp = shuffled[i - 1u];

		shuffled[i - 1u] = shuffled[j];
		shuffled[j] = tmp;
	}
	memset(&plan2, 0x33, sizeof(plan2));
	memset(out2, 0, sizeof(out2));
	if ((offer ? fzn_sync_plan_offer : fzn_sync_plan_fetch)(
	            &journal, shuffled, their_count, max_per_request, out2, OUT_CAP, &plan2)
	    != FZN_SYNC_OK)
		return 1;
	if (!same_plan(out, plan.request_count, out2, plan2.request_count))
		return 1;
	if (plan2.unknown_issuers != plan.unknown_issuers)
		return 1;

	/* 2. DUPLICATE INDEPENDENCE: every position sent twice must give the
	 * same plan. A peer repeating one stream must not get two slots. */
	if (their_count > 0u && their_count <= THEIRS_CAP) {
		for (i = 0; i < their_count; i++) {
			doubled[doubled_count++] = theirs[i];
			doubled[doubled_count++] = theirs[i];
		}
		cov->duplicates_sent++;
		memset(&plan2, 0x33, sizeof(plan2));
		memset(out2, 0, sizeof(out2));
		if ((offer ? fzn_sync_plan_offer : fzn_sync_plan_fetch)(
		            &journal, doubled, doubled_count, max_per_request, out2, OUT_CAP,
		            &plan2)
		    != FZN_SYNC_OK)
			return 1;
		if (!same_plan(out, plan.request_count, out2, plan2.request_count))
			return 1;
	}

	/* 6. A REFUSAL CLEARS THE PLAN. `max_per_request` of zero is refused,
	 * and a caller reusing one plan per round must not read last round's
	 * numbers after it. */
	memset(&plan2, 0x33, sizeof(plan2));
	if ((offer ? fzn_sync_plan_offer : fzn_sync_plan_fetch)(
	            &journal, theirs, their_count, 0, out2, OUT_CAP, &plan2)
	    != FZN_SYNC_ERR_MALFORMED)
		return 1;
	if (plan2.request_count || plan2.unknown_issuers || plan2.truncated
	    || plan2.positions_ignored)
		return 1;
	cov->refused++;

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
		printf("sync_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will "
		       "not report success -- every coverage floor below that is cleared by "
		       "a single lucky hit. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("sync_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* FLOORS ON STATES. A run that never truncated has not tested that a
	 * bound is reported rather than dropped; one that never met an unknown
	 * issuer has not tested that an absent position is not a position of
	 * zero, which is the amplifier's own rule. */
	if (cov.planned < floor_of(cases, 4u) || cov.empty_plan < floor_of(cases, 8u)
	    || cov.unknown < floor_of(cases, 8u) || cov.duplicates_sent < floor_of(cases, 4u)
	    || cov.refused < floor_of(cases, 2u) || cov.truncated < floor_of(cases, 100u)
	    || cov.ignored < floor_of(cases, 50u)) {
		printf("sync_fuzz: REACHED TOO LITTLE -- %lu planned, %lu empty, %lu "
		       "truncated, %lu unknown, %lu ignored, %lu duplicated, %lu refused "
		       "in %lu cases.\n",
		       cov.planned, cov.empty_plan, cov.truncated, cov.unknown, cov.ignored,
		       cov.duplicates_sent, cov.refused, cases);
		return 1;
	}

	printf("sync_fuzz: %lu cases, %lu planned, %lu empty, %lu truncated, %lu unknown, "
	       "%lu ignored, %lu duplicated, %lu refused; order and duplicates changed "
	       "nothing\n",
	       cases, cov.planned, cov.empty_plan, cov.truncated, cov.unknown, cov.ignored,
	       cov.duplicates_sent, cov.refused);
	return 0;
}
#endif
