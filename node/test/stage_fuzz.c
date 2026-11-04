/*
 * A fuzz harness for a stage and its confirm, `node/stage.c`, sec 873: an
 * object any host of the estate may put in its stream, held by every
 * other, whose revert is applied at its deadline with nobody asking.
 *
 * THE LIE IS SIGNED, as in setting_fuzz: a bent body is signed again by
 * whatever key its setter field now names, since a refusal at the signature
 * would test that check and none before it. What a stage carries as its
 * revert is a setting, and setting_fuzz bends those; here it is bytes.
 *
 * THE PROPERTIES:
 *   1. ROUND TRIP: a stage and a confirm open with every field as issued.
 *   2. ONE ENCODING: a bent body, signed, that opens is exactly what
 *      issuing its opened fields writes, so a confirm carries no revert or
 *      deadline, and a stage carries both.
 *   3. NOT A BYTE PAST ITS END: each open reads a copy that ends where an
 *      unreadable page begins, and an opened revert lies within it.
 *
 * FLOORS: a run in which no bent stage opened, no bent confirm opened, or
 * none was refused has not tested what it claims.
 */

#include "../stage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 2000u

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL stage_fuzz.c: case %lu: %s\n", c, what);
}

static uint64_t state = 0x3c6ef372fe94f82bull;

static uint64_t next(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return state;
}

/* ---- a signature, stubbed: which key signed, not the curve -------------- */

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t key, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull ^ key;
	size_t i;

	for (i = 0; i < len; i++)
		h = (h ^ msg[i]) * 0x100000001b3ull;
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static uint8_t signing_as;

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	(void)ctx;
	mac(sig, signing_as, msg, len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pk[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pk[0], msg, len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };

/* ---- the lie ----------------------------------------------------------- */

/* Bend `b`, `len` bytes of `cap`, and return its new length; never the
 * bytes unchanged. */
static size_t bend(uint8_t *b, size_t len, size_t cap)
{
	static uint8_t was[FZN_STAGE_MAX + 64u];
	size_t k, i, j;
	uint8_t t;

	memcpy(was, b, len);
	switch (next() % 6u) {
	case 1:
		if (len)
			return (size_t)(next() % len);
		break;
	case 2:
		if (len < cap) {
			for (k = 1u + next() % 4u; k > 0u && len < cap; k--)
				b[len++] = (uint8_t)next();
			return len;
		}
		break;
	case 3:
		if (len >= 2u) {
			i = next() % len;
			j = next() % len;
			if (b[i] != b[j]) {
				t = b[i];
				b[i] = b[j];
				b[j] = t;
				return len;
			}
		}
		break;
	case 4:
		/* THE ACT TURNED, or the deadline and length zeroed: what makes a
		 * stage a confirm. */
		if (len >= FZN_STAGE_HEAD) {
			b[2u + FZN_PUBKEY_LEN] ^= 3u;
			return len;
		}
		break;
	case 5:
		if (len >= FZN_STAGE_HEAD) {
			memset(b + FZN_STAGE_HEAD - 10u, 0, 10u);
			return FZN_STAGE_HEAD;
		}
		break;
	default:
		break;
	}
	for (k = 1u + next() % 2u; k > 0u && len; k--)
		b[next() % len] ^= (uint8_t)(1u << (next() % 8u));
	if (len && memcmp(b, was, len) == 0)
		b[next() % len] ^= 0x01u;
	return len;
}

/* ---- the page an over-read meets ---------------------------------------- */

static uint8_t *guarded_end;

static void guard(void)
{
	long page = sysconf(_SC_PAGESIZE);
	uint8_t *map;

	if (page <= 0 || (size_t)page < FZN_STAGE_MAX + 64u)
		abort();
	map = mmap(NULL, 2u * (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	           -1, 0);
	if (map == MAP_FAILED || mprotect(map + page, (size_t)page, PROT_NONE) != 0)
		abort();
	guarded_end = map + page;
}

static int open_exact(const uint8_t *bytes, size_t len, fzn_stage_t *out)
{
	memcpy(guarded_end - len, bytes, len);
	return fzn_stage_open(guarded_end - len, len, &SIGN, out);
}

int main(int argc, char **argv)
{
	static uint8_t made[FZN_STAGE_MAX], bent[FZN_STAGE_MAX + 64u], back[FZN_STAGE_MAX];
	static uint8_t revert[FZN_STAGE_REVERT_MAX];
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long stages = 0, confirms = 0, refused = 0;

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES)
		cases = FUZZ_MIN_CASES;
	guard();

	for (c = 0; c < cases; c++) {
		uint8_t setter[FZN_PUBKEY_LEN], token[FZN_STAGE_TOKEN_LEN];
		uint8_t act = (next() & 1u) ? FZN_STAGE_ACT_STAGE : FZN_STAGE_ACT_CONFIRM;
		uint64_t deadline = act == FZN_STAGE_ACT_STAGE ? 1u + (next() >> (1u + next() % 62u)) : 0u;
		size_t revert_len = act == FZN_STAGE_ACT_STAGE ? 1u + (size_t)(next() % FZN_STAGE_REVERT_MAX)
		                                               : 0u;
		size_t len = 0, n, back_len = 0, i;
		fzn_stage_t s;

		for (i = 0; i < sizeof(setter); i++)
			setter[i] = (uint8_t)next();
		for (i = 0; i < sizeof(token); i++)
			token[i] = (uint8_t)next();
		for (i = 0; i < revert_len; i++)
			revert[i] = (uint8_t)next();

		/* 1: ROUND TRIP. */
		signing_as = setter[0];
		if (!fzn_stage_issue(setter, &SIGN, act, token, deadline, revert_len ? revert : NULL,
		                     revert_len, made, &len)) {
			fail("a stage of every field in range would not issue", c);
			continue;
		}
		if (!open_exact(made, len, &s) || s.act != act
		    || memcmp(s.setter, setter, sizeof(setter)) != 0
		    || memcmp(s.token, token, sizeof(token)) != 0 || s.deadline_ms != deadline
		    || s.revert_len != revert_len
		    || (revert_len && memcmp(s.revert, revert, revert_len) != 0))
			fail("an issued stage did not open as issued", c);

		/* 2 and 3: THE BODY BENT, THEN SIGNED by whoever it now names. */
		memcpy(bent, made, len - FZN_SIG_LEN);
		n = bend(bent, len - FZN_SIG_LEN, sizeof(bent) - FZN_SIG_LEN);
		if (n > FZN_STAGE_OFF_SETTER)
			mac(bent + n, bent[FZN_STAGE_OFF_SETTER], bent, n);
		n += FZN_SIG_LEN;
		if (!open_exact(bent, n, &s)) {
			refused++;
			continue;
		}
		if (s.act == FZN_STAGE_ACT_STAGE)
			stages++;
		else
			confirms++;
		if (s.revert_len
		    && (s.revert < guarded_end - n || s.revert + s.revert_len > guarded_end))
			fail("a bent stage's revert lies outside its bytes", c);
		signing_as = s.setter[0];
		if (!fzn_stage_issue(s.setter, &SIGN, s.act, s.token, s.deadline_ms, s.revert,
		                     s.revert_len, back, &back_len))
			fail("a bent stage opened with fields its issue refuses", c);
		else if (back_len != n || memcmp(back, guarded_end - n, n) != 0)
			fail("a bent stage opened that is not the one encoding of its fields", c);
	}

	if (stages == 0u || confirms == 0u || refused == 0u)
		fail("FLOOR: no bent stage opened, no bent confirm opened, or none was refused", cases);
	printf("stage_fuzz: %lu cases, bent opened %lu stages %lu confirms, %lu refused, %d "
	       "failure(s)\n",
	       cases, stages, confirms, refused, failures);
	return failures ? 1 : 0;
}
