/* A fuzz harness for the split/reassemble contract.
 *
 * This is the only place two of this library's modules have to agree with
 * each other, and it is therefore the only coupling that can fail while
 * both halves pass their own suites. chunk/test/split_test.c covers it
 * with ten hand-picked sizes and two payload limits, which is the thinnest
 * evidence in the tree for the strongest coupling in it.
 *
 * MODEL-BASED, and the model is a prediction rather than a re-derivation:
 * every order completes. A last chunk may be short, so it cannot set the
 * stride, and an arrival that begins with it is parked rather than guessed
 * at, and placed once a piece that is not the last sets the stride
 * (project.md sec 737). Until then such an arrival was refused, and this
 * predicted a message completes if and only if the first piece offered is
 * not the last of a multi-piece one -- held both ways, a completion that
 * should not have happened as much a failure as a refusal. Now a run that
 * does not complete is the failure, in whatever order its pieces came, and
 * the orders that begin with the last piece are counted so the parked path
 * is known to have run.
 *
 * On completion the reassembled bytes must equal the original exactly. That
 * is the property the two modules exist to preserve between them, and it is
 * checked over permutations rather than over the in-order case a unit test
 * naturally writes.
 */

#include "../reassembly.h"
#include "../split.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* How long a half-finished message may hold a slot. Generous, because what
 * these cases test is the bound EXISTING -- a zero expiry no longer means
 * for ever -- rather than any particular value of it. */
#define REASM_MAX_HOLD 1000000u

#define FUZZ_DEFAULT_CASES 20000u

/* THE FLOOR BELOW WHICH THIS HARNESS REFUSES TO REPORT SUCCESS AT ALL.
 *
 * `floor_of` below was fixed to never return zero, which closed CASES=1: a run
 * that demanded nothing could no longer pass by demanding nothing. It did not
 * close the case above it. A floor of ONE is cleared by luck -- the rarest
 * branch these harnesses reach occurs about once in 130 cases, so a 199-case
 * run hits it once and every counter then reports a real, honest, meaningless
 * number. Measured before this: `receive_fuzz 199` and `peer_fuzz 199` both
 * exited 0 with plausible counts.
 *
 * So this is a bound on the RUN rather than on the counters, and it lives in
 * the harness rather than in the Makefile deliberately. The Makefile is not
 * what somebody runs when they are chasing a crash under a sanitizer -- they
 * run this binary directly, with a small number, and read the exit code. A
 * bound that exists only in the thing that invokes the binary is not a bound
 * on the binary.
 *
 * 1000 is chosen against the floors themselves, which ask for one occurrence
 * per 200 cases: below that, every floor in this file collapses to the single
 * hit luck supplies. A run under it is not a shorter version of the campaign,
 * it is a different and much weaker claim, so it is refused rather than
 * reported. */
#define FUZZ_MIN_CASES 1000u
#define SLOT_BYTES 2048
#define MAX_TOTAL 1024
#define CANARY 16
#define CANARY_BYTE 0x7e

struct arena {
	uint8_t front[CANARY];
	uint8_t buf[SLOT_BYTES];
	uint8_t back[CANARY];
};

struct coverage {
	unsigned long planned;
	unsigned long completed;
	unsigned long parked_first_last;
	unsigned long multi_piece;
};

static int canaries_intact(const struct arena *a)
{
	for (size_t i = 0; i < CANARY; i++) {
		if (a->front[i] != CANARY_BYTE || a->back[i] != CANARY_BYTE)
			return 0;
	}
	return 1;
}

static int fuzz_one(const uint8_t *data, size_t len, struct coverage *cov)
{
	struct arena arena;
	fzn_partial_t slot;
	fzn_reasm_t table;
	fzn_partial_t *done = NULL;
	fzn_split_t plan;
	static uint8_t payload[MAX_TOTAL];
	uint16_t order[FZN_REASM_MAX_CHUNKS];
	uint8_t sender[FZN_SENDER_LEN];
	size_t total, max_payload;

	if (len < 4)
		return 0;

	/* Both drawn from the input, so the edges nobody thinks to write --
	 * an exact multiple, a remainder of one, a single piece, a stride of
	 * one byte -- are reached by exhaustion rather than by imagination. */
	total = 1u + (((size_t)data[0] << 8 | data[1]) % MAX_TOTAL);
	max_payload = 1u + (data[2] % 64u);

	for (size_t i = 0; i < total; i++)
		payload[i] = (uint8_t)(i * 31u + 7u);
	memset(sender, 0xa1, sizeof(sender));

	if (fzn_split_plan(total, max_payload, &plan) != FZN_SPLIT_OK)
		return 0; /* refused for size; split_test covers that path */
	if (plan.buffer_needed > SLOT_BYTES)
		return 0;
	cov->planned++;
	if (plan.chunks > 1)
		cov->multi_piece++;

	memset(&arena, CANARY_BYTE, sizeof(arena));
	if (fzn_reasm_slot_init(&slot, arena.buf, SLOT_BYTES) != FZN_REASM_OK)
		return 0;
	if (fzn_reasm_init(&table, &slot, 1, 1, REASM_MAX_HOLD) != FZN_REASM_OK)
		return 0;

	/* A permutation driven by the input. Fisher-Yates with the swap index
	 * drawn from the remaining bytes, so the identity order, the reverse,
	 * and everything between all occur. */
	for (uint16_t i = 0; i < plan.chunks; i++)
		order[i] = i;
	for (uint16_t i = plan.chunks; i > 1; i--) {
		size_t src = 3u + ((size_t)i % (len - 3u > 0 ? len - 3u : 1u));
		uint16_t j = (uint16_t)(data[src % len] % i);
		uint16_t t = order[i - 1u];

		order[i - 1u] = order[j];
		order[j] = t;
	}

	/* THE PARKED PATH, counted: a multi-piece message offered last piece
	 * first. */
	if (plan.chunks > 1 && order[0] + 1u == plan.chunks)
		cov->parked_first_last++;

	for (uint16_t k = 0; k < plan.chunks; k++) {
		size_t offset, plen;

		if (fzn_split_at(&plan, order[k], &offset, &plen) != FZN_SPLIT_OK) {
			printf("  MODEL: split refused its own piece %u of %u\n", order[k],
			       plan.chunks);
			return 1;
		}
		(void)fzn_reasm_accept(&table, sender, 1, order[k], plan.chunks,
		                       payload + offset, plen, 0, 100, &done);

		if (!canaries_intact(&arena)) {
			printf("  MODEL: a write landed outside the slot buffer\n");
			return 1;
		}
	}

	if (!done) {
		printf("  MODEL: %zu bytes in %u pieces did not complete (first offered %u)\n",
		       total, plan.chunks, order[0]);
		return 1;
	}

	if (done) {
		cov->completed++;
		if (done->bytes != total) {
			printf("  MODEL: reassembled %zu bytes, sent %zu\n", done->bytes, total);
			return 1;
		}
		if (memcmp(done->buf, payload, total) != 0) {
			printf("  MODEL: reassembled bytes differ from what was split\n");
			return 1;
		}
	}

	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct coverage cov = { 0, 0, 0, 0 };

	(void)fuzz_one(data, size, &cov);
	return 0;
}
#else

static uint32_t next(uint32_t *state)
{
	*state = (*state * 1103515245u) + 12345u;
	return (*state >> 16) & 0xffffu;
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
	struct coverage cov = { 0, 0, 0, 0 };
	uint8_t buf[64];

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}

	if (cases < FUZZ_MIN_CASES) {
		printf("roundtrip_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will "
		       "not report success -- every coverage floor below that is "
		       "cleared by a single lucky hit. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (unsigned long c = 0; c < cases; c++) {
		uint32_t state = (uint32_t)c + 1u;
		size_t len = 4u + (size_t)(next(&state) % (sizeof(buf) - 3u));

		for (size_t i = 0; i < len; i++)
			buf[i] = (uint8_t)next(&state);

		if (fuzz_one(buf, len, &cov)) {
			printf("roundtrip_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* Multi-piece messages and the parked order must both occur. A
	 * run of single-piece messages would round-trip perfectly and test
	 * none of the stride arithmetic this file is about. */
	/* `parked_first_last` (`refused_first_last` until sec 737) was once
	 * floored at one, which a single lucky case satisfies. Observed 1794
	 * in 20000, so a fraction floor leaves ample margin and actually
	 * notices the path going away. `planned` was counted and not floored
	 * at all. */
	if (cov.completed < floor_of(cases, 200u) || cov.multi_piece < floor_of(cases, 200u) ||
	    cov.parked_first_last < floor_of(cases, 200u) || cov.planned < floor_of(cases, 200u)) {
		printf("roundtrip_fuzz: REACHED TOO LITTLE -- %lu planned, %lu completed, "
		       "%lu multi-piece, %lu parked-order in %lu cases.\n",
		       cov.planned, cov.completed, cov.multi_piece, cov.parked_first_last,
		       cases);
		return 1;
	}

	printf("roundtrip_fuzz: %lu cases, %lu planned, %lu completed, %lu multi-piece, "
	       "%lu parked-order, bytes identical throughout\n",
	       cases, cov.planned, cov.completed, cov.multi_piece, cov.parked_first_last);
	return 0;
}
#endif
