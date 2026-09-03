/* Does the constant-time comparison actually depend on nothing secret?
 *
 * `constant_time.h` states the property -- "constant time in the LENGTH and
 * in the DATA" -- and sec 4.4a says this library owes it to consumers and
 * must not leave it to them. Until this file existed, **nothing tested it**.
 * The five cases in `chain/test/chain_test.c` test that the comparison
 * gives the right ANSWER, which a plain memcmp would pass identically.
 *
 * The other witness is `make codegencheck`, and `tool/codegen_gate.py` is
 * explicit that it is "a tripwire rather than a proof": it counts branches
 * in the emitted object, so it notices a rewrite that obviously reintroduces
 * one and cannot speak for the property itself.
 *
 * HOW THIS IS DIFFERENT. Memcheck tracks definedness per bit and reports any
 * conditional jump, or any memory address, computed from data it considers
 * undefined. So marking the two buffers undefined turns valgrind into a
 * secret-dependence detector: it is not measuring time and does not have to,
 * because a comparison whose control flow never touches the data cannot vary
 * with it. That is the property, checked directly, rather than a symptom of
 * it counted in an object file. The technique is Langley's ctgrind.
 *
 * WHY THIS ONE FUNCTION IS THE WHOLE SCOPE, and it is not a shortcut: every
 * secret comparison in this library routes through `fzn_ct_memeq`. Capability
 * ids and grantee keys in `chain/chain.c` and `chain/revocation.c`, the
 * commitment in `wire/seal.c`, the verb in `local/vocabulary.c`, and
 * `session/commitment.c`'s check. Checking the primitive checks all of them,
 * which is the argument for having a primitive at all.
 *
 * `fzn_commitment_check` is deliberately NOT tested here, and the reason is
 * worth stating rather than leaving as an omission. It selects an enum from
 * the comparison's result, and that result is the DECLASSIFICATION BOUNDARY
 * -- accept-or-reject is published the moment it is returned, so branching on
 * it leaks nothing. Valgrind cannot see that boundary, so including the
 * function would report a branch that is correct and teach whoever met the
 * report to add a suppression. A check whose output has to be explained away
 * is one nobody will keep believing.
 *
 * WITHOUT VALGRIND this still builds and still runs, with the two macros as
 * no-ops, and is then an ordinary correctness test. That is deliberate: the
 * file must not be one that only exists under a tool most machines have not
 * installed. `make ctcheck` is what rebuilds it with the client requests
 * live.
 */

#include "../constant_time.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef FZN_HAVE_VALGRIND
#include <valgrind/memcheck.h>
#define FZN_SECRET(p, n)     VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define FZN_DECLASSIFY(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#define FZN_SECRET(p, n)     ((void)(p), (void)(n))
#define FZN_DECLASSIFY(p, n) ((void)(p), (void)(n))
#endif

#define FZN_SECRET_LEN 32u

static int failures;
static int checks;

static void expect(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "  FAIL: %s\n", what);
	}
}

/* The comparison under test, with both inputs secret and the ANSWER made
 * public again.
 *
 * `r` is volatile so that the result reaches memory, which is what the
 * client request addresses -- a value the compiler kept in a register has no
 * address to declassify, and the branch in `expect` would then be reported
 * as a leak the function does not have. That would be a false positive
 * arriving through the test's own construction rather than through the code
 * it is testing.
 *
 * The buffers are declassified on the way out so the next case starts from a
 * known state instead of inheriting the previous one's poison. */
static int compare_secret(const uint8_t *a, const uint8_t *b, size_t len)
{
	volatile int r;

	FZN_SECRET(a, len);
	FZN_SECRET(b, len);
	r = fzn_ct_memeq(a, b, len);
	FZN_DECLASSIFY((void *)&r, sizeof(r));
	FZN_DECLASSIFY(a, len);
	FZN_DECLASSIFY(b, len);
	return r;
}

/* THE POSITIVE CONTROL, and the reason it is in this file rather than in
 * somebody's memory of a sabotage they once ran.
 *
 * A clean memcheck run and a memcheck that was never able to say anything
 * look exactly alike -- the build lost the client requests, the binary was
 * stale, valgrind ran a different program. So `make ctcheck` runs the same
 * binary twice: once as itself, which must be clean, and once here, which
 * must be REPORTED. A run that cannot produce a finding cannot be evidence
 * of the absence of one.
 *
 * memcmp is the honest control because it is exactly what this library would
 * have used if `constant_time/` did not exist: it returns at the first byte
 * that differs, so its control flow reads the secret. */
static int compare_leaky(const uint8_t *a, const uint8_t *b, size_t len)
{
	volatile int r;

	FZN_SECRET(a, len);
	FZN_SECRET(b, len);
	r = memcmp(a, b, len) == 0;
	FZN_DECLASSIFY((void *)&r, sizeof(r));
	FZN_DECLASSIFY(a, len);
	FZN_DECLASSIFY(b, len);
	return r;
}

/* fzn_wipe, which this file tests because it is the other thing
 * `constant_time/` exports and it has the same shape of hazard: correct code
 * whose absence looks exactly like its presence.
 *
 * The erasure itself cannot be tested from outside the function -- a caller
 * that reads the buffer afterwards sees zeroes whether the stores survived
 * or the compiler kept a copy elsewhere. What is testable is that it wipes
 * WHAT IT WAS ASKED TO and nothing else, that a partial wipe leaves the tail
 * alone, and that the NULL and zero-length cases the header promises are
 * really harmless. That the stores survive optimisation is `make
 * codegencheck`'s question, and it now asks it of the caller. */
static void check_wipe(void)
{
	uint8_t buf[16];
	int intact = 1;

	memset(buf, 0xA5, sizeof(buf));
	fzn_wipe(buf, sizeof(buf));
	for (size_t i = 0; i < sizeof(buf); i++)
		if (buf[i] != 0)
			intact = 0;
	expect(intact, "fzn_wipe left a byte unerased");

	/* A bounded wipe stops where it was told. A wipe that ran past its
	 * length would pass every test that only looked at the erased part,
	 * which is why the tail is what is checked here. */
	memset(buf, 0xA5, sizeof(buf));
	fzn_wipe(buf, 4);
	intact = (buf[0] == 0 && buf[3] == 0 && buf[4] == 0xA5 &&
	          buf[sizeof(buf) - 1] == 0xA5);
	expect(intact, "fzn_wipe did not stop at its length");

	/* The two the header promises are harmless. Reaching them at all is
	 * the test; a crash is the failure. */
	fzn_wipe(NULL, 16);
	fzn_wipe(buf, 0);
	expect(buf[sizeof(buf) - 1] == 0xA5, "a zero-length wipe erased something");

	/* THE SAME PROMISE FOR THE COMPARISON, and the header states it: a
	 * NULL side answers "not equal" rather than crashing, because every
	 * caller here is asking an authorization question and the safe reply
	 * to one with a missing operand is no.
	 *
	 * NOTHING IN THIS TREE HELD IT. The commit that added the guard added
	 * it to constant_time.c and constant_time.h and to no test file at
	 * all; its message records "NULL compares without crashing", measured
	 * by hand, once. Measured again 2026-09-03 by deleting the guard: the
	 * suite stayed green apart from the crash.
	 *
	 * A CRASH IS THE DETECTION, AND THAT IS INHERENT rather than a
	 * weakness here. The guard exists to stop a dereference, so the only
	 * difference between having it and not is whether the process
	 * survives: the `len == 0` case answers the same either way, because
	 * an empty loop leaves the accumulator at zero. Said plainly so that
	 * the next reader does not go hunting for a stronger assertion than
	 * this can carry. */
	expect(fzn_ct_memeq(NULL, buf, sizeof(buf)) == 0,
	       "a comparison with no left operand did not answer not-equal");
	expect(fzn_ct_memeq(buf, NULL, sizeof(buf)) == 0,
	       "a comparison with no right operand did not answer not-equal");
	expect(fzn_ct_memeq(NULL, NULL, 0) == 1,
	       "an empty comparison of two absent buffers did not answer equal");
}

int main(int argc, char **argv)
{
	uint8_t a[FZN_SECRET_LEN], same[FZN_SECRET_LEN];
	uint8_t last[FZN_SECRET_LEN], first[FZN_SECRET_LEN];
	int leaky = (argc > 1 && strcmp(argv[1], "--leaky") == 0);
	int (*compare)(const uint8_t *, const uint8_t *, size_t);

	for (size_t i = 0; i < FZN_SECRET_LEN; i++)
		a[i] = (uint8_t)(i * 7u + 1u);
	memcpy(same, a, sizeof(a));
	memcpy(last, a, sizeof(a));
	memcpy(first, a, sizeof(a));
	last[FZN_SECRET_LEN - 1u] ^= 0x80u;
	first[0] ^= 0x01u;

	compare = leaky ? compare_leaky : compare_secret;

	/* Both outcomes, and both ENDS of the buffer. A comparison that stops
	 * early is fastest when the first byte differs and slowest when only
	 * the last does, so those are the two cases whose control flow differs
	 * most -- which makes them the ones most likely to make memcheck speak
	 * if anything is going to. */
	expect(compare(a, same, sizeof(a)) != 0, "equal buffers reported different");
	expect(compare(a, last, sizeof(a)) == 0, "a difference in the last byte was missed");
	expect(compare(a, first, sizeof(a)) == 0, "a difference in the first byte was missed");
	expect(compare(a, same, 0) != 0, "a zero-length comparison was not trivially equal");

	check_wipe();

	printf("secret_flow_test: %d checks, %d failure(s)%s\n", checks, failures,
	       leaky ? " [--leaky: the positive control, which must be REPORTED]" : "");
	return failures == 0 ? 0 : 1;
}
