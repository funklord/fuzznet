/* A fuzz harness for the /proc status parser.
 *
 * Every other parser in this library has one, and this is the only one that
 * reads TEXT. project.md sec 4.1 makes fuzzability a design property, and
 * `fzn_peer_groups_parse` is the shape that most rewards it: a scan for a
 * key, a bounded loop over decimal fields, and a fixed output array.
 *
 * WHAT IT ASSERTS is the contract rather than the absence of a crash,
 * because the failure that matters here is not an overrun. It is a PARTIAL
 * ANSWER REPORTED AS A COMPLETE ONE -- a list that parsed some of a line
 * and said `groups_known`, which then answers "not a member" definitely and
 * wrongly. sec 2 is explicit that "could not tell" and "none" must stay
 * distinguishable, and this is where an input nobody thought of would blur
 * them.
 *
 * So after every call, over arbitrary bytes:
 *
 *   - the output array's canary is intact;
 *   - `group_count` is zero whenever `groups_known` is zero, so an unknown
 *     list can never leave a count a caller might read;
 *   - `group_count` never exceeds FZN_PEER_MAX_GROUPS;
 *   - the return value and `groups_known` agree, so the two ways of asking
 *     cannot disagree;
 *   - and when a list IS known, every group in it is re-derived from the
 *     input independently and compared -- which is what catches a partial
 *     parse that reported success.
 *
 * The independent re-derivation is a second implementation of the scan,
 * deliberately, for the reason chain_fuzz gives: a model that asked the
 * parser what it had parsed would agree with it always.
 *
 * Bounded and seeded like the others, and it counts what it reached: inputs
 * that parse successfully must actually occur, or the run is exercising the
 * refusal path alone and proves nothing about the accepting one.
 */

#include "../peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
#define CANARY 16
#define CANARY_BYTE 0x7e

struct arena {
	fzn_peer_t peer;
	uint8_t back[CANARY];
};

struct coverage {
	unsigned long known;
	unsigned long unknown;
	unsigned long nonempty;
};

/* Independently: find a line starting `Groups:` and read its decimal
 * fields, refusing everything the parser is documented to refuse. Returns
 * -1 for "could not tell", otherwise the count, filling `out`. */
static int model(const char *text, size_t len, uint32_t *out, size_t cap)
{
	static const char key[] = "Groups:";
	const size_t keylen = sizeof(key) - 1;
	size_t i, end, n = 0;

	if (!text || len == 0)
		return -1;

	for (i = 0; i + keylen <= len; i++) {
		if ((i == 0 || text[i - 1] == '\n') && memcmp(text + i, key, keylen) == 0)
			break;
	}
	if (i + keylen > len)
		return -1;

	i += keylen;
	for (end = i; end < len && text[end] != '\n'; end++)
		;

	while (i < end) {
		uint64_t v = 0;
		int digits = 0;

		while (i < end && (text[i] == ' ' || text[i] == '\t'))
			i++;
		if (i >= end)
			break;
		while (i < end && text[i] >= '0' && text[i] <= '9') {
			v = v * 10u + (uint64_t)(text[i] - '0');
			if (v > 0xffffffffu)
				return -1;
			digits++;
			i++;
		}
		if (digits == 0)
			return -1;
		if (n == cap)
			return -1;
		out[n++] = (uint32_t)v;
	}

	return (int)n;
}

static int fuzz_one(const uint8_t *data, size_t len, struct coverage *cov)
{
	struct arena a;
	uint32_t expect[FZN_PEER_MAX_GROUPS];
	int want, got;

	memset(&a, CANARY_BYTE, sizeof(a));
	memset(&a.peer, 0, sizeof(a.peer));

	/* Half the cases parse into a struct that already holds a KNOWN list,
	 * because a caller reusing one is the only way a stale `group_count`
	 * on the could-not-tell path is observable -- and the first version
	 * of this harness always started from a zeroed struct, so a planted
	 * bug that left the count behind survived it. */
	if ((len & 1u) != 0) {
		static const char primer[] = "Groups:\t20 24 103\n";
		(void)fzn_peer_groups_parse(primer, sizeof(primer) - 1, &a.peer);
	}

	got = fzn_peer_groups_parse((const char *)data, len, &a.peer);

	for (size_t i = 0; i < CANARY; i++) {
		if (a.back[i] != CANARY_BYTE) {
			printf("  MODEL: a write landed past the peer struct\n");
			return 1;
		}
	}

	if (got != 0 && got != 1) {
		printf("  MODEL: parse returned %d, which is neither 0 nor 1\n", got);
		return 1;
	}
	if ((got == 1) != (a.peer.groups_known != 0)) {
		printf("  MODEL: return value and groups_known disagree\n");
		return 1;
	}
	if (a.peer.group_count > FZN_PEER_MAX_GROUPS) {
		printf("  MODEL: group_count %zu past the bound\n", a.peer.group_count);
		return 1;
	}
	if (!a.peer.groups_known && a.peer.group_count != 0) {
		printf("  MODEL: an unknown list left a count of %zu behind\n",
		       a.peer.group_count);
		return 1;
	}

	want = model((const char *)data, len, expect, FZN_PEER_MAX_GROUPS);

	if (want < 0) {
		if (a.peer.groups_known) {
			printf("  MODEL: parser reported a KNOWN list where the rules say "
			       "could-not-tell\n");
			return 1;
		}
		cov->unknown++;
		return 0;
	}

	if (!a.peer.groups_known) {
		printf("  MODEL: parser said could-not-tell for a line the rules accept\n");
		return 1;
	}
	if (a.peer.group_count != (size_t)want) {
		printf("  MODEL: parsed %zu groups, the rules say %d\n", a.peer.group_count,
		       want);
		return 1;
	}
	for (int i = 0; i < want; i++) {
		if (a.peer.groups[i] != expect[i]) {
			printf("  MODEL: group %d is %u, the rules say %u\n", i,
			       a.peer.groups[i], expect[i]);
			return 1;
		}
	}

	cov->known++;
	if (want > 0)
		cov->nonempty++;
	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct coverage cov = { 0, 0, 0 };

	(void)fuzz_one(data, size, &cov);
	return 0;
}
#else

static uint32_t next(uint32_t *state)
{
	*state = (*state * 1103515245u) + 12345u;
	return (*state >> 16) & 0xffffu;
}

/* Random bytes essentially never contain "Groups:", so a uniform generator
 * would test the could-not-tell path forty thousand times and the accepting
 * path never. The same failure the reassembly harness was rebuilt for. Most
 * cases are therefore grown from a plausible status file and then corrupted. */
static size_t shape(uint32_t *st, uint8_t *buf, size_t cap)
{
	static const char *lines[] = {
		"Name:\tcat\n", "Umask:\t0022\n", "Ngid:\t0\n", "Gid:\t1000 1000\n",
		"Groups:\t20 24 103 1000 \n", "Groups:\t\n", "Groups:\n",
		"Groups:\t20 24 banana\n", "NStgid:\t1\n",
		/* Reaches the two bounds the first version of this generator
		 * never produced, and whose checks three planted bugs
		 * therefore survived: more groups than FZN_PEER_MAX_GROUPS,
		 * and a decimal past 32 bits. A generator that cannot build
		 * the input a check rejects cannot test that check. */
		"Groups:\t1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 "
		"24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 "
		"47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69\n",
		"Groups:\t20 4294967296\n",
		"Groups:\t99999999999999999999\n",
	};
	size_t n = 0;
	int lines_wanted = (int)(next(st) % 5u) + 1;

	for (int i = 0; i < lines_wanted; i++) {
		const char *l = lines[next(st) % (sizeof(lines) / sizeof(lines[0]))];
		size_t l_len = strlen(l);

		if (n + l_len >= cap)
			break;
		memcpy(buf + n, l, l_len);
		n += l_len;
	}

	/* Corrupt a byte most of the time, so the shapes above are a starting
	 * point rather than the whole input space. */
	if (n > 0 && (next(st) & 3u) != 0)
		buf[next(st) % n] = (uint8_t)next(st);

	return n;
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
	uint8_t buf[256];

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}

	if (cases < FUZZ_MIN_CASES) {
		printf("peer_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will "
		       "not report success -- every coverage floor below that is "
		       "cleared by a single lucky hit. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (unsigned long c = 0; c < cases; c++) {
		uint32_t state = (uint32_t)c + 1u;
		size_t len;

		if ((c & 7u) == 0) {
			len = (size_t)(next(&state) % (sizeof(buf) + 1u));
			for (size_t i = 0; i < len; i++)
				buf[i] = (uint8_t)next(&state);
		} else {
			len = shape(&state, buf, sizeof(buf));
		}

		if (fuzz_one(buf, len, &cov)) {
			printf("peer_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* Both outcomes must occur, and a non-empty list among them. A run
	 * that only ever refused would report success against a parser that
	 * refused everything. */
	if (cov.known < floor_of(cases, 200u) || cov.unknown < floor_of(cases, 200u) ||
	    cov.nonempty < floor_of(cases, 200u)) {
		printf("peer_fuzz: REACHED TOO LITTLE -- %lu known, %lu unknown, %lu with "
		       "groups, in %lu cases.\n",
		       cov.known, cov.unknown, cov.nonempty, cases);
		return 1;
	}

	printf("peer_fuzz: %lu cases, %lu known, %lu could-not-tell, %lu with groups, "
	       "model agreed throughout\n",
	       cases, cov.known, cov.unknown, cov.nonempty);
	return 0;
}
#endif
