/*
 * A fuzz harness for ratchet/ratchet.c: does a jump land where stepping
 * lands, from anywhere, over any distance, with any cap?
 *
 * WHY, GIVEN ratchet_test.c ALREADY ASKS THAT. It asks it once, from
 * sequence ZERO, jumping to 5, with room for 8 skipped keys. Every fixture in
 * that file initialises a chain at zero -- which is the question fuzzypickles
 * put to this tree on 2026-09-05: what value is every fixture on the same
 * side of? Here it is the starting position. A receiver's chain is at zero
 * exactly once and spends the rest of its life somewhere else, so the case
 * the suite covers is the one case that only happens at the beginning.
 *
 * THE ORACLE IS STEPPING ONE AT A TIME, as it is there: a table of the
 * message key and chain key at every position, built with
 * `fzn_ratchet_derive` in a loop written here. A fast-forward compared
 * against itself would agree always, including when both are wrong.
 *
 * FOUR PROPERTIES.
 *
 *   1. A JUMP LANDS WHERE STEPPING LANDS. The message key, the chain key and
 *      the sequence after `advance(from, target)` are the oracle's at
 *      `target`, whatever `from` was.
 *
 *   2. THE SKIPPED KEYS ARE THE ONES JUMPED OVER, oldest first, and
 *      `kept + dropped` is the number of positions between `from` and
 *      `target`. A cap that cuts them must report the remainder rather than
 *      leaving a caller to infer it -- `ratchet.h` cites
 *      `fzn_manifest_deficit` for that shape.
 *
 *   3. THE PATH DOES NOT MATTER. Advancing a to c directly, and a to b then
 *      b to c, leave identical chains and agree on the key at c. This is the
 *      one a receiver actually leans on, because frames arrive in whatever
 *      order the network chose, and it is the property no fixture starting
 *      at zero can ask.
 *
 *   4. A REFUSAL WRITES NOTHING. `to` is untouched by a behind target, an
 *      in-place call, or a jump past the bound, so a refused advance cannot
 *      leave a caller holding a position that is neither the old one nor a
 *      usable new one.
 *
 * WHAT IT DOES NOT TEST is the property `ratchet_test.c` opens by saying
 * cannot be tested: that a compromised chain key does not yield the keys
 * before it. A stub hash makes that meaningless and a real one makes it
 * unfalsifiable in finite time. This harness is about the bookkeeping.
 */

#include "../ratchet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

/* Below this the floors are cleared by a single lucky case. */
#define FUZZ_MIN_CASES 1000u

/* The oracle covers positions 0..ORACLE_MAX-1. Small on purpose: the
 * bound is 100000 derivations and a harness that walked it per case would
 * measure the machine rather than the module. `ratchet_test.c` covers the
 * bound itself with one deliberate case. */
#define ORACLE_MAX 96u

/* Room for every key a jump inside the oracle could skip. */
#define SKIP_MAX ORACLE_MAX

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	if (!out || !in)
		return 0;
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

/* A seam that runs out part-way, so a refusal can happen AFTER the module has
 * started work.
 *
 * WITHOUT IT PROPERTY 4 HAD ONE REACHABLE SHAPE. Both refusals the harness
 * could produce -- a behind target and a jump past the bound -- return before
 * `work = *from` is even reached, so a module that wrote its destination
 * early would satisfy every assertion. Measured: that sabotage SURVIVED 2000
 * cases, which is sec 228's lesson arriving in a new module. The one refusal
 * that lands mid-jump is a failing hash. */
static int hash_budget;

static int budgeted_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in,
                         size_t in_len)
{
	if (hash_budget <= 0)
		return 0;
	hash_budget--;
	return stub_hash(ctx, out, out_len, in, in_len);
}

static const fzn_hash_ops_t FLAKY = { budgeted_hash, NULL };

/* The oracle: `mk[i]` is the message key for sequence i, and `ck[i]` is the
 * chain key a chain holds when its `seq` is i. */
static uint8_t ck[ORACLE_MAX + 1u][FZN_CHAIN_KEY_LEN];
static uint8_t mk[ORACLE_MAX][FZN_MESSAGE_KEY_LEN];

static int build_oracle(const uint8_t seed_key[FZN_CHAIN_KEY_LEN])
{
	unsigned i;

	memcpy(ck[0], seed_key, FZN_CHAIN_KEY_LEN);
	for (i = 0; i < ORACLE_MAX; i++) {
		if (fzn_ratchet_derive(&HASH, ck[i], mk[i], ck[i + 1u]) != FZN_RATCHET_OK)
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
	unsigned long from_nonzero;
	unsigned long jumps;
	unsigned long adjacent;
	unsigned long capped;
	unsigned long exact_cap;
	unsigned long behind;
	unsigned long split_paths;
	unsigned long partway;
};

/* Asserts properties 1 and 2 for one advance, against the oracle. Returns 0
 * on agreement. */
static int landed_right(const fzn_ratchet_chain_t *before, uint64_t target,
                        const uint8_t *got_mk, const fzn_ratchet_chain_t *after,
                        const uint8_t *skipped, size_t kept, size_t dropped, size_t cap)
{
	uint64_t jumped = target - before->seq;
	uint64_t i;

	if (memcmp(got_mk, mk[target], FZN_MESSAGE_KEY_LEN) != 0) {
		printf("  MODEL: jumping from %llu to %llu gave a message key stepping does "
		       "not produce\n",
		       (unsigned long long)before->seq, (unsigned long long)target);
		return 1;
	}
	if (memcmp(after->key, ck[target + 1u], FZN_CHAIN_KEY_LEN) != 0) {
		printf("  MODEL: the chain key after reaching %llu is not the one stepping "
		       "leaves\n",
		       (unsigned long long)target);
		return 1;
	}
	if (after->seq != target + 1u) {
		printf("  MODEL: the chain is at %llu after reaching %llu\n",
		       (unsigned long long)after->seq, (unsigned long long)target);
		return 1;
	}
	if (kept + dropped != jumped) {
		printf("  MODEL: %llu positions were jumped and %zu + %zu were accounted "
		       "for -- a caller cannot tell how many keys it did not get\n",
		       (unsigned long long)jumped, kept, dropped);
		return 1;
	}
	if (kept > cap) {
		printf("  MODEL: %zu skipped keys were written into room for %zu\n", kept,
		       cap);
		return 1;
	}
	for (i = 0; i < kept; i++) {
		if (memcmp(skipped + i * FZN_MESSAGE_KEY_LEN, mk[before->seq + i],
		           FZN_MESSAGE_KEY_LEN) != 0) {
			printf("  MODEL: skipped key %llu is not the key for sequence %llu, "
			       "so a caller retaining them decrypts the wrong messages\n",
			       (unsigned long long)i,
			       (unsigned long long)(before->seq + i));
			return 1;
		}
	}
	return 0;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	uint8_t seed_key[FZN_CHAIN_KEY_LEN];
	uint8_t skipped[SKIP_MAX][FZN_MESSAGE_KEY_LEN];
	uint8_t direct_mk[FZN_MESSAGE_KEY_LEN], step_mk[FZN_MESSAGE_KEY_LEN];
	fzn_ratchet_chain_t at, moved, split, mid;
	uint64_t from, middle, target;
	size_t kept = 99u, dropped = 99u, cap;
	unsigned i;

	for (i = 0; i < FZN_CHAIN_KEY_LEN; i++)
		seed_key[i] = (uint8_t)next(&state);
	if (!build_oracle(seed_key)) {
		printf("  INVARIANT: the oracle would not build\n");
		return 1;
	}

	/* A CHAIN SOMEWHERE ALONG ITS LIFE, which is the case the suite's
	 * fixtures cannot reach. */
	from = next(&state) % (ORACLE_MAX - 2u);
	/* IN ORDER IS THE COMMON CASE ON THE WIRE, so it is the common case
	 * here: a third of the time the next sequence, the rest a jump. The
	 * first version drew the target uniformly and reached the adjacent
	 * case 4.5% of the time -- the floors below caught that, which is what
	 * they are for. */
	if ((next(&state) % 3u) == 0u) {
		target = from + 1u;
	} else {
		target = from + 1u + (next(&state) % (ORACLE_MAX - 1u - from));
		if (target >= ORACLE_MAX)
			target = ORACLE_MAX - 1u;
	}
	/* AT LEAST ONE, because `skipped_out` and `skipped_count` must be both
	 * given or both absent -- `!skipped_count != !skipped_out` is
	 * MALFORMED -- and a cap of zero with a count pointer is the misuse
	 * this harness made first. The caller-wants-none path is asked below,
	 * with all three absent, as the property it is.
	 *
	 * A SHORT CAP IS DRAWN AGAINST THE JUMP rather than against the
	 * oracle, or it is almost never short: a cap uniform in 1..96 against
	 * a jump that is usually smaller than that capped 7% of the time. Here
	 * a third of the time it is deliberately too small. */
	if ((next(&state) % 3u) == 0u && target > from + 1u)
		cap = 1u + (size_t)(next(&state) % (uint32_t)(target - from));
	else
		cap = SKIP_MAX;

	fzn_ratchet_init(&at, ck[from], from);
	if (from > 0u)
		cov->from_nonzero++;
	if (target == from + 1u)
		cov->adjacent++;
	else
		cov->jumps++;

	memset(&moved, 0x5a, sizeof(moved));
	{
		fzn_ratchet_err_t err = fzn_ratchet_advance(&HASH, &at, target, direct_mk,
		                                           &moved, skipped[0], cap, &kept,
		                                           &dropped);

		/* THE CODE, NOT JUST THE REFUSAL. A line that says an advance
		 * was refused and not which way cannot be diagnosed, which is
		 * the first thing this harness taught its author. */
		if (err != FZN_RATCHET_OK) {
			printf("  INVARIANT: an advance from %llu to %llu with cap %zu was "
			       "refused: %d\n",
			       (unsigned long long)from, (unsigned long long)target, cap,
			       (int)err);
			return 1;
		}
	}
	if (landed_right(&at, target, direct_mk, &moved, skipped[0], kept, dropped, cap))
		return 1;

	/*
	 * AND ASKING FOR THE SKIPPED KEYS MUST NOT CHANGE WHERE THE CHAIN
	 * LANDS. A caller that does not want them passes NULL for all three,
	 * and `ratchet.h` says they are simply lost -- so the same advance
	 * must produce the same message key and the same chain either way. It
	 * is the cheapest property here and the one a reader would assume
	 * without checking.
	 */
	{
		fzn_ratchet_chain_t quiet;
		uint8_t quiet_mk[FZN_MESSAGE_KEY_LEN];

		memset(&quiet, 0x6b, sizeof(quiet));
		if (fzn_ratchet_advance(&HASH, &at, target, quiet_mk, &quiet, NULL, 0u, NULL,
		                        NULL) != FZN_RATCHET_OK) {
			printf("  INVARIANT: the same advance was refused when the skipped "
			       "keys were not wanted\n");
			return 1;
		}
		if (memcmp(quiet_mk, direct_mk, FZN_MESSAGE_KEY_LEN) != 0
		    || memcmp(&quiet, &moved, sizeof(quiet)) != 0) {
			printf("  MODEL: wanting the skipped keys changed where the chain "
			       "landed\n");
			return 1;
		}
	}
	if (dropped > 0u)
		cov->capped++;
	if (kept == cap && cap > 0u)
		cov->exact_cap++;

	/*
	 * PROPERTY 3: THE PATH DOES NOT MATTER.
	 *
	 * Only askable when there is somewhere to stop on the way, and it is
	 * the property a receiver leans on -- frames arrive in the order the
	 * network chose, so a chain reaches a position by whatever route the
	 * traffic took.
	 */
	if (target > from + 1u) {
		middle = from + 1u + (next(&state) % (target - from - 1u));
		fzn_ratchet_init(&split, ck[from], from);
		memset(&mid, 0xa5, sizeof(mid));
		if (fzn_ratchet_advance(&HASH, &split, middle, step_mk, &mid, NULL, 0u, NULL,
		                        NULL) != FZN_RATCHET_OK) {
			printf("  INVARIANT: the first leg of a split path was refused\n");
			return 1;
		}
		split = mid;
		memset(&mid, 0x3c, sizeof(mid));
		if (fzn_ratchet_advance(&HASH, &split, target, step_mk, &mid, NULL, 0u, NULL,
		                        NULL) != FZN_RATCHET_OK) {
			printf("  INVARIANT: the second leg of a split path was refused\n");
			return 1;
		}
		if (memcmp(step_mk, direct_mk, FZN_MESSAGE_KEY_LEN) != 0
		    || memcmp(&mid, &moved, sizeof(mid)) != 0) {
			printf("  MODEL: reaching %llu through %llu left a different chain "
			       "than reaching it directly, so a receiver's keys depend on "
			       "the order its frames arrived in\n",
			       (unsigned long long)target, (unsigned long long)middle);
			return 1;
		}
		cov->split_paths++;
	}

	/*
	 * PROPERTY 4: A REFUSAL WRITES NOTHING. Asked of the chain the
	 * successful advance produced, so the position being protected is a
	 * real one rather than a fresh struct.
	 */
	{
		fzn_ratchet_chain_t guard;
		fzn_ratchet_chain_t untouched;

		memset(&guard, 0x77, sizeof(guard));
		untouched = guard;
		if (fzn_ratchet_advance(&HASH, &moved, moved.seq - 1u, direct_mk, &guard, NULL,
		                        0u, NULL, NULL) != FZN_RATCHET_ERR_BEHIND) {
			printf("  MODEL: a target the chain has already passed was not "
			       "refused as behind\n");
			return 1;
		}
		if (memcmp(&guard, &untouched, sizeof(guard)) != 0) {
			printf("  MODEL: a refused advance wrote to its destination, leaving "
			       "a position that is neither the old one nor a usable new "
			       "one\n");
			return 1;
		}
		cov->behind++;

		if (fzn_ratchet_advance(&HASH, &moved, moved.seq + FZN_RATCHET_MAX_ADVANCE
		                                              + 1u,
		                        direct_mk, &guard, NULL, 0u, NULL, NULL)
		    != FZN_RATCHET_ERR_TOO_FAR) {
			printf("  MODEL: a jump past the bound was not refused as too far\n");
			return 1;
		}
		if (memcmp(&guard, &untouched, sizeof(guard)) != 0) {
			printf("  MODEL: a jump refused as too far still wrote its "
			       "destination\n");
			return 1;
		}

		/*
		 * AND A REFUSAL THAT LANDS MID-JUMP, which is the only one that
		 * happens after the module has begun deriving. Both refusals
		 * above return before it touches anything, so without this the
		 * property is a claim about two paths that could not break it.
		 */
		if (target > from + 1u) {
			fzn_ratchet_chain_t part;
			fzn_ratchet_err_t err;

			memset(&part, 0x2d, sizeof(part));
			untouched = part;
			/* Enough derivations to start and not to finish. */
			hash_budget = (int)(target - from) - 1;
			err = fzn_ratchet_advance(&FLAKY, &at, target, direct_mk, &part, NULL,
			                          0u, NULL, NULL);
			if (err != FZN_RATCHET_ERR_HASH) {
				printf("  MODEL: a hash that ran out part-way was reported "
				       "as %d rather than a hash failure\n",
				       (int)err);
				return 1;
			}
			if (memcmp(&part, &untouched, sizeof(part)) != 0) {
				printf("  MODEL: an advance abandoned part-way wrote its "
				       "destination, so a caller holds a position that is "
				       "neither the old one nor a usable new one\n");
				return 1;
			}
			cov->partway++;
		}
	}

	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0 };

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
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned long c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("ratchet_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run "
		       "will not report success. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("ratchet_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* FLOORS ON STATES. A run that never started away from zero has tested
	 * what ratchet_test.c already tests; one that never split a path has
	 * not asked the property this file exists for; one that never filled a
	 * cap exactly has not touched the boundary between kept and dropped. */
	if (cov.from_nonzero < floor_of(cases, 2u) || cov.jumps < floor_of(cases, 2u)
	    || cov.adjacent < floor_of(cases, 20u) || cov.capped < floor_of(cases, 8u)
	    || cov.exact_cap < floor_of(cases, 100u) || cov.behind < floor_of(cases, 2u)
	    || cov.split_paths < floor_of(cases, 2u)
	    || cov.partway < floor_of(cases, 2u)) {
		printf("ratchet_fuzz: REACHED TOO LITTLE -- %lu from a moved chain, %lu "
		       "jumps, %lu adjacent, %lu capped, %lu exactly at the cap, %lu "
		       "behind, %lu split paths, %lu abandoned part-way in %lu cases.\n",
		       cov.from_nonzero, cov.jumps, cov.adjacent, cov.capped, cov.exact_cap,
		       cov.behind, cov.split_paths, cov.partway, cases);
		return 1;
	}

	printf("ratchet_fuzz: %lu cases, %lu from a moved chain, %lu jumps, %lu adjacent, "
	       "%lu capped, %lu exactly at the cap, %lu behind, %lu split paths, %lu "
	       "abandoned part-way, every jump landed where stepping lands\n",
	       cases, cov.from_nonzero, cov.jumps, cov.adjacent, cov.capped, cov.exact_cap,
	       cov.behind, cov.split_paths, cov.partway);
	return 0;
}
#endif
