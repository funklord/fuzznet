/* Tests for session/agree.c: the rotation discipline and the refusals.
 *
 * THE SEAM IS STUBBED HERE AND THE REAL X25519 IS TESTED SEPARATELY, in
 * session/test/agree_monocypher_test.c, which is gated on the binding being
 * built. What this file asks is what the seam owes regardless of algorithm:
 * that a rotation destroys what it replaces, that a wiped secret refuses
 * rather than agreeing with zeroes, and that a refusing binding is carried
 * out rather than swallowed.
 */

#include "../agree.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL agree_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)
#define REQUIRE(cond, ...)                                   \
	do {                                                 \
		int require_ok = (cond) ? 1 : 0;             \
		check_at(require_ok, __LINE__, __VA_ARGS__); \
		if (!require_ok)                             \
			return;                              \
	} while (0)

/* A toy agreement: public = secret reversed and xored, shared = a mix of
 * both. Not Diffie-Hellman and not commutative -- it does not need to be.
 * What every case here asks is whether the right bytes reached the right
 * call, and for that the stub must depend on every input byte. */
static int stub_public_of(void *ctx, uint8_t out[FZN_AGREE_PUBLIC_LEN],
                          const uint8_t secret[FZN_AGREE_SECRET_LEN])
{
	unsigned i;

	(void)ctx;
	for (i = 0; i < FZN_AGREE_PUBLIC_LEN; i++)
		out[i] = (uint8_t)(secret[FZN_AGREE_SECRET_LEN - 1u - i] ^ 0x5au);
	return 1;
}

static int stub_agree(void *ctx, uint8_t out[FZN_AGREE_SHARED_LEN],
                      const uint8_t secret[FZN_AGREE_SECRET_LEN],
                      const uint8_t peer[FZN_AGREE_PUBLIC_LEN])
{
	unsigned i;

	(void)ctx;
	for (i = 0; i < FZN_AGREE_SHARED_LEN; i++)
		out[i] = (uint8_t)(secret[i] + peer[i]);
	return 1;
}

/* Refuses, as a binding must when a peer key is degenerate. */
static int refusing_agree(void *ctx, uint8_t out[FZN_AGREE_SHARED_LEN],
                          const uint8_t secret[FZN_AGREE_SECRET_LEN],
                          const uint8_t peer[FZN_AGREE_PUBLIC_LEN])
{
	unsigned i;

	(void)ctx;
	(void)secret;
	(void)peer;
	/* WRITES BEFORE REFUSING, on purpose. A real binding computes into
	 * the caller's buffer and only then discovers the result is
	 * degenerate, so the seam must not leave those bytes behind. */
	for (i = 0; i < FZN_AGREE_SHARED_LEN; i++)
		out[i] = 0xcc;
	return 0;
}

static int refusing_public(void *ctx, uint8_t out[FZN_AGREE_PUBLIC_LEN],
                           const uint8_t secret[FZN_AGREE_SECRET_LEN])
{
	(void)ctx;
	(void)out;
	(void)secret;
	return 0;
}

static const fzn_agree_ops_t OPS = { stub_public_of, stub_agree, NULL };
static const fzn_agree_ops_t DEGENERATE = { stub_public_of, refusing_agree, NULL };
static const fzn_agree_ops_t NO_PUBLIC = { refusing_public, stub_agree, NULL };

static void fill(uint8_t *p, size_t n, uint8_t seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(seed + (i * 11u));
}

/* ---- the cases -------------------------------------------------------- */

static void test_an_empty_secret_offers_nothing(void)
{
	fzn_agree_secret_t sk;
	uint8_t shared[FZN_AGREE_SHARED_LEN];
	uint8_t peer[FZN_AGREE_PUBLIC_LEN];

	memset(&sk, 0, sizeof(sk));
	fill(peer, sizeof(peer), 0x11);

	/* NULL rather than a key of zeroes, which is `fzn_trust_root`'s shape
	 * and for the same reason: an absent key that reads as a key is one
	 * every attacker can also produce. */
	CHECK(fzn_agree_secret_public(&sk) == NULL, "an uninstalled secret offered a public key");
	CHECK(fzn_agree_shared(&sk, &OPS, peer, shared) == FZN_AGREE_ERR_ABSENT,
	      "an uninstalled secret agreed with a peer");
}

static void test_installing_keeps_the_public_half(void)
{
	fzn_agree_secret_t sk;
	uint8_t secret[FZN_AGREE_SECRET_LEN];
	uint8_t want[FZN_AGREE_PUBLIC_LEN];

	memset(&sk, 0, sizeof(sk));
	fill(secret, sizeof(secret), 0x21);
	REQUIRE(stub_public_of(NULL, want, secret) == 1, "the stub refused");

	REQUIRE(fzn_agree_secret_install(&sk, &OPS, secret) == FZN_AGREE_OK, "install refused");
	REQUIRE(fzn_agree_secret_public(&sk) != NULL, "install left no public key");
	CHECK(memcmp(fzn_agree_secret_public(&sk), want, FZN_AGREE_PUBLIC_LEN) == 0,
	      "the public key is not the one derived from the secret");
	CHECK(fzn_agree_secret_generation(&sk) == 0u, "a first install is not generation 0");
}

static void test_a_rotation_destroys_what_it_replaces(void)
{
	fzn_agree_secret_t sk;
	uint8_t first[FZN_AGREE_SECRET_LEN];
	uint8_t second[FZN_AGREE_SECRET_LEN];
	uint8_t peer[FZN_AGREE_PUBLIC_LEN];
	uint8_t before[FZN_AGREE_SHARED_LEN];
	uint8_t after[FZN_AGREE_SHARED_LEN];

	memset(&sk, 0, sizeof(sk));
	fill(first, sizeof(first), 0x31);
	fill(second, sizeof(second), 0x41);
	fill(peer, sizeof(peer), 0x51);

	REQUIRE(fzn_agree_secret_install(&sk, &OPS, first) == FZN_AGREE_OK, "install refused");
	REQUIRE(fzn_agree_shared(&sk, &OPS, peer, before) == FZN_AGREE_OK, "agree refused");

	REQUIRE(fzn_agree_secret_install(&sk, &OPS, second) == FZN_AGREE_OK, "rotate refused");
	CHECK(fzn_agree_secret_generation(&sk) == 1u, "a rotation did not advance the generation");
	REQUIRE(fzn_agree_shared(&sk, &OPS, peer, after) == FZN_AGREE_OK, "agree refused");

	/* THE PROPERTY THE WHOLE TYPE EXISTS FOR. After rotation the struct
	 * agrees as the NEW secret and there is no path back to the old one:
	 * everything sealed under a session derived from `first` is
	 * unrecoverable from this struct. A rotation that kept the old bytes
	 * would pass every other case in this file. */
	CHECK(memcmp(before, after, FZN_AGREE_SHARED_LEN) != 0,
	      "after rotating, the struct still agrees as the old secret");
	CHECK(memcmp(&sk.secret, first, FZN_AGREE_SECRET_LEN) != 0,
	      "the previous secret is still in the struct after a rotation");
}

static void test_a_wipe_forgets_and_refuses(void)
{
	fzn_agree_secret_t sk;
	uint8_t secret[FZN_AGREE_SECRET_LEN];
	uint8_t peer[FZN_AGREE_PUBLIC_LEN];
	uint8_t shared[FZN_AGREE_SHARED_LEN];
	size_t i;
	int all_zero = 1;

	memset(&sk, 0, sizeof(sk));
	fill(secret, sizeof(secret), 0x61);
	fill(peer, sizeof(peer), 0x71);
	REQUIRE(fzn_agree_secret_install(&sk, &OPS, secret) == FZN_AGREE_OK, "install refused");

	fzn_agree_secret_wipe(&sk);
	for (i = 0; i < FZN_AGREE_SECRET_LEN; i++)
		if (sk.secret[i] != 0u)
			all_zero = 0;
	CHECK(all_zero, "a wiped secret is still in the struct");
	CHECK(fzn_agree_secret_public(&sk) == NULL, "a wiped secret still offers a public key");
	/* AND IT REFUSES RATHER THAN AGREEING WITH ZEROES. X25519 over a zero
	 * scalar is a defined operation with a useless result, so without the
	 * live flag this would derive a session key from nothing and look
	 * like it worked. */
	CHECK(fzn_agree_shared(&sk, &OPS, peer, shared) == FZN_AGREE_ERR_ABSENT,
	      "a wiped secret agreed with a peer");
}

static void test_a_degenerate_peer_key_is_refused_and_leaves_nothing(void)
{
	fzn_agree_secret_t sk;
	uint8_t secret[FZN_AGREE_SECRET_LEN];
	uint8_t peer[FZN_AGREE_PUBLIC_LEN];
	uint8_t shared[FZN_AGREE_SHARED_LEN];
	size_t i;
	int all_zero = 1;

	memset(&sk, 0, sizeof(sk));
	fill(secret, sizeof(secret), 0x81);
	fill(peer, sizeof(peer), 0x91);
	REQUIRE(fzn_agree_secret_install(&sk, &OPS, secret) == FZN_AGREE_OK, "install refused");

	memset(shared, 0x33, sizeof(shared));
	CHECK(fzn_agree_shared(&sk, &DEGENERATE, peer, shared) == FZN_AGREE_ERR_DEGENERATE,
	      "a binding that refused was reported as success");

	/* THE BINDING WROTE BEFORE IT REFUSED, which is what a real one does:
	 * it computes into the caller's buffer and only then finds the result
	 * degenerate. A caller that ignores the return value must not find an
	 * attacker-chosen constant sitting there ready to be hashed into a
	 * transcript. */
	for (i = 0; i < FZN_AGREE_SHARED_LEN; i++)
		if (shared[i] != 0u)
			all_zero = 0;
	CHECK(all_zero, "a refused agreement left bytes in the caller's buffer");
}

static void test_a_refusing_public_leaves_the_old_secret_alone(void)
{
	fzn_agree_secret_t sk;
	uint8_t first[FZN_AGREE_SECRET_LEN];
	uint8_t second[FZN_AGREE_SECRET_LEN];
	uint8_t peer[FZN_AGREE_PUBLIC_LEN];
	uint8_t before[FZN_AGREE_SHARED_LEN];
	uint8_t after[FZN_AGREE_SHARED_LEN];

	memset(&sk, 0, sizeof(sk));
	fill(first, sizeof(first), 0xa1);
	fill(second, sizeof(second), 0xb1);
	fill(peer, sizeof(peer), 0xc1);
	REQUIRE(fzn_agree_secret_install(&sk, &OPS, first) == FZN_AGREE_OK, "install refused");
	REQUIRE(fzn_agree_shared(&sk, &OPS, peer, before) == FZN_AGREE_OK, "agree refused");

	/* A ROTATION THAT FAILS MUST NOT DESTROY. The public half is derived
	 * BEFORE anything is wiped, so a binding that refuses leaves the host
	 * holding the secret it had -- rather than a wiped struct and no
	 * replacement, which is a host that cannot decrypt its own queued
	 * traffic because a key derivation failed. */
	CHECK(fzn_agree_secret_install(&sk, &NO_PUBLIC, second) == FZN_AGREE_ERR_OPS,
	      "a refusing derivation was reported as success");
	REQUIRE(fzn_agree_shared(&sk, &OPS, peer, after) == FZN_AGREE_OK,
	        "the struct stopped working after a refused rotation");
	CHECK(memcmp(before, after, FZN_AGREE_SHARED_LEN) == 0,
	      "a refused rotation changed the installed secret");
	CHECK(fzn_agree_secret_generation(&sk) == 0u,
	      "a refused rotation advanced the generation");
}

static void test_every_guard_refuses_its_own_argument(void)
{
	fzn_agree_secret_t sk;
	uint8_t buf[FZN_AGREE_SECRET_LEN];

	memset(&sk, 0, sizeof(sk));
	fill(buf, sizeof(buf), 0xd1);

	CHECK(fzn_agree_secret_install(NULL, &OPS, buf) == FZN_AGREE_ERR_MALFORMED, "null secret");
	CHECK(fzn_agree_secret_install(&sk, &OPS, NULL) == FZN_AGREE_ERR_MALFORMED, "null bytes");
	CHECK(fzn_agree_secret_install(&sk, NULL, buf) == FZN_AGREE_ERR_OPS, "null ops");
	CHECK(fzn_agree_shared(NULL, &OPS, buf, buf) == FZN_AGREE_ERR_MALFORMED, "null secret");
	CHECK(fzn_agree_shared(&sk, &OPS, NULL, buf) == FZN_AGREE_ERR_MALFORMED, "null peer");
	CHECK(fzn_agree_shared(&sk, &OPS, buf, NULL) == FZN_AGREE_ERR_MALFORMED, "null out");
	CHECK(fzn_agree_shared(&sk, NULL, buf, buf) == FZN_AGREE_ERR_OPS, "null ops");
	CHECK(fzn_agree_secret_public(NULL) == NULL, "null accessor");
	CHECK(fzn_agree_secret_generation(NULL) == 0u, "null generation");
	fzn_agree_secret_wipe(NULL);

	CHECK(strcmp(fzn_agree_err_str(FZN_AGREE_OK), "ok") == 0, "ok does not render");
	CHECK(strcmp(fzn_agree_err_str((fzn_agree_err_t)91), "unknown") == 0,
	      "a value that is not an enumerator does not render as unknown");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_an_empty_secret_offers_nothing();
	test_installing_keeps_the_public_half();
	test_a_rotation_destroys_what_it_replaces();
	test_a_wipe_forgets_and_refuses();
	test_a_degenerate_peer_key_is_refused_and_leaves_nothing();
	test_a_refusing_public_leaves_the_old_secret_alone();
	test_every_guard_refuses_its_own_argument();
	test_the_suite_can_tell_pass_from_fail();

	printf("agree_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
