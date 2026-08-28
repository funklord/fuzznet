/* Reassembly under a COVERAGE-GUIDED fuzzer, which is a different instrument
 * from the harness beside it.
 *
 * `reassembly_fuzz.c` generates chunk sequences from a PRNG and checks them
 * against a model. That finds what random generation reaches, and the shape
 * of what it generates is decided in advance by whoever wrote the generator.
 * libFuzzer decides nothing in advance: it keeps inputs that reach new edges
 * and mutates those, so it walks into states nobody thought to describe --
 * a quota refusal arriving between two chunks of a message that then
 * completes, say.
 *
 * WHAT IT FOUND: nothing, over 1.5 million executions under the address and
 * undefined-behaviour sanitizers, reaching 209 of 400 instrumented edges with
 * a 292-unit corpus. That is worth recording as a measurement rather than a
 * habit, and the coverage number is the part that makes it worth anything --
 * see below.
 *
 * THE FIRST RUN OF THIS HARNESS WAS WORTHLESS AND LOOKED BETTER. It called
 * `fzn_reasm_init` before `fzn_reasm_slot_init`, and init verifies that every
 * slot already has its buffer -- `reassembly.h` says so plainly. So every
 * execution returned at the first line. It reported 61 MILLION runs, half a
 * million per second, and zero crashes; the tells were `cov: 8` and
 * `new_units_added: 0`, not the crash count. A fuzzer that never grows its
 * corpus is not fuzzing. **Read the coverage, not the clean bill.**
 *
 * That is why the setup calls below trap rather than returning quietly: a
 * harness whose subject failed to initialise should be loud, not fast.
 *
 * DUAL MODE. Built with -DFZN_LIBFUZZER it is a libFuzzer target; built
 * plainly it is an ordinary test that replays inputs -- the files named on
 * argv, or a handful of built-in ones. That is what lets it live in
 * TEST_SRCS and be run by `make test` on a machine with no clang, and it is
 * what makes a crash found later reproducible by committing one file.
 */

#include "../reassembly.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* How long a half-finished message may hold a slot. Generous, because what
 * these cases test is the bound EXISTING -- a zero expiry no longer means
 * for ever -- rather than any particular value of it. */
#define REASM_MAX_HOLD 1000000u

#define SLOTS  4
#define BUFCAP 4096

struct cursor {
	const uint8_t *p;
	size_t n, i;
};

static uint8_t take8(struct cursor *c)
{
	return c->i < c->n ? c->p[c->i++] : 0u;
}

static uint16_t take16(struct cursor *c)
{
	uint16_t hi = take8(c);

	return (uint16_t)((hi << 8) | take8(c));
}

static uint32_t take32(struct cursor *c)
{
	uint32_t hi = take16(c);

	return (hi << 16) | take16(c);
}

/* One input drives a sequence of operations against one table. Returns
 * non-zero if an invariant broke, which only the plain-mode main reports --
 * under libFuzzer the traps below abort first, which is what it watches for. */
static int drive(const uint8_t *data, size_t size)
{
	fzn_reasm_t table;
	fzn_partial_t slots[SLOTS];
	static uint8_t bufs[SLOTS][BUFCAP];
	uint8_t sender[FZN_SENDER_LEN];
	uint8_t payload[512];
	struct cursor c = { data, size, 0 };
	uint64_t now = 0;

	/* BUFFERS FIRST. See the header comment: the other order makes every
	 * run a no-op that reports as a pass. */
	for (size_t i = 0; i < SLOTS; i++)
		if (fzn_reasm_slot_init(&slots[i], bufs[i], BUFCAP) != FZN_REASM_OK)
			return 1;
	if (fzn_reasm_init(&table, slots, SLOTS, 2, REASM_MAX_HOLD) != FZN_REASM_OK)
		return 1;

	while (c.i < c.n) {
		uint8_t op = take8(&c);
		uint32_t msg;
		uint16_t index, chunks;
		size_t len;
		uint64_t expires;
		fzn_partial_t *done = NULL;

		if ((op & 3u) == 0u) {
			now += take8(&c);
			(void)fzn_reasm_expire(&table, now);
			continue;
		}

		memset(sender, take8(&c), sizeof(sender));
		msg = take32(&c);
		index = take16(&c);
		chunks = take16(&c);
		len = take8(&c) % (sizeof(payload) + 1u);
		expires = now + take8(&c);

		for (size_t i = 0; i < len; i++)
			payload[i] = take8(&c);

		if (fzn_reasm_accept(&table, sender, msg, index, chunks, payload, len, expires,
		                     now, &done) == FZN_REASM_OK &&
		    done) {
			/* A message reported complete must BE complete. This is
			 * the invariant the guided search is hunting for a way
			 * around; everything else is the sanitizers' business. */
			if (done->arrived != done->chunks)
				return 1;
			fzn_reasm_release(done);
		}
	}

	return 0;
}

#ifdef FZN_LIBFUZZER

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (drive(data, size))
		__builtin_trap();
	return 0;
}

#else

/* Built-in inputs, so a plain `make test` exercises this file rather than
 * merely compiling it. Short and hand-written to reach a completion, a
 * conflicting repeat and a quota refusal; the guided run is where breadth
 * comes from. A crash the fuzzer ever finds is added here as bytes. */
static const uint8_t CASE_COMPLETE[] = { 0x01, 0x07, 0, 0, 0, 1, 0, 0, 0, 2, 4, 5, 1, 2, 3, 4,
	                                 0x01, 0x07, 0, 0, 0, 1, 0, 1, 0, 2, 4, 5, 5, 6, 7, 8 };
static const uint8_t CASE_CONFLICT[] = { 0x01, 0x09, 0, 0, 0, 2, 0, 0, 0, 2, 2, 9, 1, 2,
	                                 0x01, 0x09, 0, 0, 0, 2, 0, 0, 0, 2, 2, 9, 3, 4 };
static const uint8_t CASE_QUOTA[] = { 0x01, 0x11, 0, 0, 0, 1, 0, 0, 0, 4, 1, 9, 1,
	                              0x01, 0x11, 0, 0, 0, 2, 0, 0, 0, 4, 1, 9, 2,
	                              0x01, 0x11, 0, 0, 0, 3, 0, 0, 0, 4, 1, 9, 3 };
static const uint8_t CASE_EXPIRE[] = { 0x00, 0xff, 0x01, 0x22, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 7,
	                               0x00, 0xff };

int main(int argc, char **argv)
{
	static uint8_t buf[65536];
	int failures = 0;
	int cases = 0;

	if (argc > 1) {
		/* Replay mode: every file named is an input. This is how a
		 * corpus unit that once crashed becomes a regression test. */
		for (int i = 1; i < argc; i++) {
			FILE *f = fopen(argv[i], "rb");
			size_t n;

			if (!f) {
				fprintf(stderr, "  FAIL: cannot open %s\n", argv[i]);
				failures++;
				continue;
			}
			n = fread(buf, 1, sizeof(buf), f);
			fclose(f);
			cases++;
			if (drive(buf, n)) {
				fprintf(stderr, "  FAIL: %s broke an invariant\n", argv[i]);
				failures++;
			}
		}
	} else {
		const uint8_t *builtin[] = { CASE_COMPLETE, CASE_CONFLICT, CASE_QUOTA,
			                     CASE_EXPIRE };
		const size_t sizes[] = { sizeof(CASE_COMPLETE), sizeof(CASE_CONFLICT),
			                 sizeof(CASE_QUOTA), sizeof(CASE_EXPIRE) };

		for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
			cases++;
			if (drive(builtin[i], sizes[i])) {
				fprintf(stderr, "  FAIL: built-in case %zu broke an invariant\n", i);
				failures++;
			}
		}
	}

	printf("reassembly_guided: %d case(s), %d failure(s)\n", cases, failures);
	return failures == 0 ? 0 : 1;
}

#endif
