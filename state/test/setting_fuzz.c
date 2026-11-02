/*
 * A fuzz harness for a signed setting, `state/setting.c`: one cell of the
 * estate's configuration, sec 540, as it reaches a host from another of
 * the estate's -- sec 689's journey 1. Both shapes: the plain one, and the
 * one stating its setter's rank (sec 728), which came after the harnesses
 * that open settings in passing.
 *
 * THE LIE IS SIGNED. A bent setting whose signature no longer holds is
 * refused at the last check, and a harness that only bent the bytes would
 * test that check and nothing before it. So the body is bent and then
 * signed again, by whatever key its setter field now names: what a key the
 * estate trusts can send, which is the case the shape checks are for.
 *
 * THE PROPERTIES:
 *   1. ROUND TRIP: a setting issued in either shape opens with every field
 *      as issued, its rank -1 for the plain shape.
 *   2. ONE ENCODING: a bent body, signed, that opens is exactly what
 *      issuing its opened fields writes, in the shape its rank says. So
 *      every opened key and value is one `fzn_setting_issue` accepts, and
 *      no two byte strings open as one setting.
 *   3. NOT A BYTE PAST ITS END: each open reads a copy that ends where an
 *      unreadable page begins, so an over-read faults in any build.
 *
 * FLOORS: a run in which no bent body opened, none was refused for its
 * shape, or none opened in each shape, has not tested what it claims.
 */

#include "../setting.h"

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
		fprintf(stderr, "  FAIL setting_fuzz.c: case %lu: %s\n", c, what);
}

static uint64_t state = 0xbb67ae8584caa73bull;

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
	static uint8_t was[FZN_SETTING_MAX + 64u];
	size_t k, i, j;
	uint8_t t;

	memcpy(was, b, len);
	switch (next() % 5u) {
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
		if (len >= 8u) {
			i = next() % (len - 4u);
			for (j = 0; j < 4u && i + j + 4u < len && b[i + j] == b[i + j + 4u]; j++)
				;
			if (j < 4u && i + j + 4u < len) {
				memmove(b + i + 4u, b + i, len - i - 4u);
				return len;
			}
		}
		break;
	case 4:
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

	if (page <= 0 || (size_t)page < FZN_SETTING_MAX + 64u)
		abort();
	map = mmap(NULL, 2u * (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	           -1, 0);
	if (map == MAP_FAILED || mprotect(map + page, (size_t)page, PROT_NONE) != 0)
		abort();
	guarded_end = map + page;
}

static fzn_setting_err_t open_exact(const uint8_t *bytes, size_t len, fzn_setting_t *out)
{
	memcpy(guarded_end - len, bytes, len);
	return fzn_setting_open(guarded_end - len, len, &SIGN, out);
}

/* ---- what is made ------------------------------------------------------- */

static const char KEY_CHARS[] = "abcdefghijklmnopqrstuvwxyz0123456789._/-";

/* `s` issued again from its fields, in the shape its rank says. */
static fzn_setting_err_t again(const fzn_setting_t *s, uint8_t *out, size_t *out_len)
{
	signing_as = s->setter[0];
	if (s->rank < 0)
		return fzn_setting_issue(s->setter, &SIGN, s->scope, s->about, s->version, s->key,
		                         s->key_len, s->set, s->value, s->value_len, out, out_len);
	return fzn_setting_issue_ranked(s->setter, &SIGN, s->scope, s->about, s->version, s->key,
	                                s->key_len, s->set, s->value, s->value_len,
	                                (fzn_setting_rank_t)s->rank, out, out_len);
}

int main(int argc, char **argv)
{
	static uint8_t made[FZN_SETTING_MAX], bent[FZN_SETTING_MAX + 64u], back[FZN_SETTING_MAX];
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long opened = 0, shape_refused = 0, opened_plain = 0, opened_ranked = 0;

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES)
		cases = FUZZ_MIN_CASES;
	guard();

	for (c = 0; c < cases; c++) {
		uint8_t setter[FZN_PUBKEY_LEN], about[FZN_SUBJECT_LEN], key[FZN_SETTING_KEY_MAX];
		uint8_t value[FZN_SETTING_VALUE_MAX];
		fzn_scope_t scope = (next() & 1u) ? FZN_SCOPE_ESTATE : FZN_SCOPE_HOST;
		uint64_t version = next() >> (next() % 64u);
		size_t key_len = 1u + (size_t)(next() % FZN_SETTING_KEY_MAX);
		size_t value_len = (size_t)(next() % (FZN_SETTING_VALUE_MAX + 1u));
		int set = (int)(next() % 4u != 0u), ranked = (int)(next() & 1u);
		fzn_setting_rank_t rank = (fzn_setting_rank_t)(next() % FZN_SETTING_RANKS);
		size_t len = 0, n, back_len = 0, i;
		fzn_setting_t s;
		fzn_setting_err_t err;

		for (i = 0; i < sizeof(setter); i++)
			setter[i] = (uint8_t)next();
		for (i = 0; i < sizeof(about); i++)
			about[i] = (uint8_t)next();
		for (i = 0; i < key_len; i++)
			key[i] = (uint8_t)KEY_CHARS[next() % (sizeof(KEY_CHARS) - 1u)];
		if (!set)
			value_len = 0;
		for (i = 0; i < value_len; i++)
			value[i] = (uint8_t)(0x20u + next() % 0x5fu);

		/* 1: ROUND TRIP. */
		signing_as = setter[0];
		err = ranked ? fzn_setting_issue_ranked(setter, &SIGN, scope, about, version, key,
		                                        key_len, set, value, value_len, rank, made, &len)
		             : fzn_setting_issue(setter, &SIGN, scope, about, version, key, key_len, set,
		                                 value, value_len, made, &len);
		if (err != FZN_SETTING_OK) {
			fail("a setting of every field in range would not issue", c);
			continue;
		}
		if (open_exact(made, len, &s) != FZN_SETTING_OK
		    || memcmp(s.setter, setter, sizeof(setter)) != 0 || s.scope != scope
		    || memcmp(s.about, about, sizeof(about)) != 0 || s.version != version
		    || s.key_len != key_len || memcmp(s.key, key, key_len) != 0 || s.set != set
		    || s.value_len != value_len || (value_len && memcmp(s.value, value, value_len) != 0)
		    || s.rank != (ranked ? (int)rank : -1))
			fail("an issued setting did not open as issued", c);

		/* 2 and 3: THE BODY BENT, THEN SIGNED by whoever it now names. */
		memcpy(bent, made, len - FZN_SIG_LEN);
		n = bend(bent, len - FZN_SIG_LEN, sizeof(bent) - FZN_SIG_LEN);
		if (n > FZN_SETTING_OFF_SETTER)
			mac(bent + n, bent[FZN_SETTING_OFF_SETTER], bent, n);
		n += FZN_SIG_LEN;
		err = open_exact(bent, n, &s);
		if (err == FZN_SETTING_ERR_SHAPE)
			shape_refused++;
		if (err != FZN_SETTING_OK)
			continue;
		opened++;
		if (s.rank < 0)
			opened_plain++;
		else
			opened_ranked++;
		if (again(&s, back, &back_len) != FZN_SETTING_OK)
			fail("a bent setting opened with fields its issue refuses", c);
		else if (back_len != n || memcmp(back, guarded_end - n, n) != 0)
			fail("a bent setting opened that is not the one encoding of its fields", c);
	}

	if (opened == 0u || shape_refused == 0u)
		fail("FLOOR: no bent setting opened, or none was refused for its shape", cases);
	if (opened_plain == 0u || opened_ranked == 0u)
		fail("FLOOR: no bent setting opened in one of the two shapes", cases);
	printf("setting_fuzz: %lu cases, %lu bent opened (%lu plain, %lu ranked), %lu refused for "
	       "shape, %d failure(s)\n",
	       cases, opened, opened_plain, opened_ranked, shape_refused, failures);
	return failures ? 1 : 0;
}
