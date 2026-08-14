/* Tests for frame/freshness.c.
 *
 * Deterministic throughout: `now` is a parameter, nonces are constructed,
 * and the window is caller-owned storage. Nothing here can pass on a quiet
 * machine and fail on a loaded one, which is the property sec 4.3's rules
 * most need -- they are about a clock, and a test of a clock that reads one
 * is a race.
 */

#include "../freshness.h"

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
	printf("  FAIL freshness_test.c:%d: ", line);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

static void nonce_of(uint8_t out[FZN_NONCE_LEN], uint8_t seed)
{
	memset(out, seed, FZN_NONCE_LEN);
}

/* ---- expiry, which is sec 4.3 ---------------------------------------- */

static void test_command_expiry_is_mandatory(void)
{
	CHECK(fzn_freshness_check(2000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_OK,
	      "a live command was refused");
	CHECK(fzn_freshness_check(1000, FZN_FRAME_COMMAND, 2000) == FZN_FRESH_ERR_EXPIRED,
	      "an expired command was accepted");

	/* The half an implementation forgets. Refusing a passed expiry while
	 * accepting an absent one exempts anybody who omits the field. */
	CHECK(fzn_freshness_check(0, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_ERR_NO_EXPIRY,
	      "a command carrying no expiry at all was accepted");

	/* Exactly at the boundary is expired: sec 4.3 wants a receiver to
	 * refuse one that HAS PASSED, and a command whose last valid instant
	 * is now has no valid instant left. */
	CHECK(fzn_freshness_check(1000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_ERR_EXPIRED,
	      "a command expiring exactly now was accepted");
}

static void test_grants_do_not_expire_by_default(void)
{
	CHECK(fzn_freshness_check(0, FZN_FRAME_GRANT, 999999) == FZN_FRESH_OK,
	      "a grant with no expiry was refused -- authority ended by a clock");
	CHECK(fzn_freshness_check(2000, FZN_FRAME_GRANT, 1000) == FZN_FRESH_OK,
	      "a live time-boxed grant was refused");
	CHECK(fzn_freshness_check(1000, FZN_FRAME_GRANT, 2000) == FZN_FRESH_ERR_EXPIRED,
	      "a grant that states an expiry was not held to it");
}

/* ---- the window ------------------------------------------------------- */

static void test_replay_is_refused(void)
{
	fzn_replay_entry_t storage[4];
	fzn_replay_window_t w;
	uint8_t a[FZN_NONCE_LEN], b[FZN_NONCE_LEN];

	nonce_of(a, 0xa1);
	nonce_of(b, 0xb2);
	CHECK(fzn_replay_init(&w, storage, 4) == FZN_FRESH_OK, "init failed");

	CHECK(fzn_replay_admit(&w, a, 2000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_OK,
	      "a fresh nonce was refused");
	CHECK(fzn_replay_admit(&w, a, 2000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_ERR_REPLAY,
	      "the same nonce was accepted twice");
	CHECK(fzn_replay_admit(&w, b, 2000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_OK,
	      "a different nonce was refused");
	CHECK(w.used == 2, "used %zu, wanted 2", w.used);
}

static void test_expiry_bounds_the_memory(void)
{
	fzn_replay_entry_t storage[4];
	fzn_replay_window_t w;
	uint8_t a[FZN_NONCE_LEN];

	/* The design claim in one test: a nonce is remembered only until its
	 * own expiry passes, and after that the slot comes back. */
	nonce_of(a, 0xa1);
	fzn_replay_init(&w, storage, 4);
	fzn_replay_admit(&w, a, 2000, FZN_FRAME_COMMAND, 1000);
	CHECK(w.used == 1, "nonce was not recorded");

	CHECK(fzn_replay_expire(&w, 2500) == 1, "an expired entry was not reclaimed");
	CHECK(w.used == 0, "used %zu after expiry, wanted 0", w.used);

	/* And replaying it now fails on freshness rather than on memory --
	 * which is why forgetting it was safe. */
	CHECK(fzn_replay_admit(&w, a, 2000, FZN_FRAME_COMMAND, 2500) == FZN_FRESH_ERR_EXPIRED,
	      "a forgotten but expired nonce was accepted");
}

static void test_a_full_window_refuses_rather_than_evicting(void)
{
	fzn_replay_entry_t storage[2];
	fzn_replay_window_t w;
	uint8_t a[FZN_NONCE_LEN], b[FZN_NONCE_LEN], c[FZN_NONCE_LEN];

	nonce_of(a, 0xa1);
	nonce_of(b, 0xb2);
	nonce_of(c, 0xc3);
	fzn_replay_init(&w, storage, 2);

	CHECK(fzn_replay_admit(&w, a, 9000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_OK, "first");
	CHECK(fzn_replay_admit(&w, b, 9000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_OK, "second");
	CHECK(fzn_replay_admit(&w, c, 9000, FZN_FRAME_COMMAND, 1000) ==
	              FZN_FRESH_ERR_WINDOW_FULL,
	      "a full window admitted a third live entry");

	/* The point of refusing: the oldest entry must STILL be remembered,
	 * so it cannot be replayed. An evicting window would have dropped `a`
	 * to make room, and `a` would be accepted again here -- which is the
	 * attack, since the attacker chose the traffic that filled it. */
	CHECK(fzn_replay_admit(&w, a, 9000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_ERR_REPLAY,
	      "the oldest entry was evicted, reopening it to replay");
}

static void test_a_refused_frame_costs_no_slot(void)
{
	fzn_replay_entry_t storage[2];
	fzn_replay_window_t w;
	uint8_t a[FZN_NONCE_LEN];

	/* Otherwise a stranger fills the window with rubbish that was going
	 * to be refused anyway -- the denial of service the bound exists to
	 * prevent, introduced by the bound. */
	nonce_of(a, 0xa1);
	fzn_replay_init(&w, storage, 2);

	CHECK(fzn_replay_admit(&w, a, 500, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_ERR_EXPIRED,
	      "an expired frame was admitted");
	CHECK(w.used == 0, "an expired frame occupied a slot");

	CHECK(fzn_replay_admit(&w, a, 0, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_ERR_NO_EXPIRY,
	      "a command with no expiry was admitted");
	CHECK(w.used == 0, "a refused frame occupied a slot");
}

static void test_grants_are_not_recorded(void)
{
	fzn_replay_entry_t storage[2];
	fzn_replay_window_t w;
	uint8_t a[FZN_NONCE_LEN];

	/* A grant with no expiry has nothing to be remembered until, and
	 * recording one would fill the window with entries that never
	 * expire -- the unbounded set this design exists to avoid. */
	nonce_of(a, 0xa1);
	fzn_replay_init(&w, storage, 2);

	CHECK(fzn_replay_admit(&w, a, 0, FZN_FRAME_GRANT, 1000) == FZN_FRESH_OK,
	      "an unexpiring grant was refused");
	CHECK(w.used == 0, "an unexpiring grant occupied a slot forever");
	CHECK(fzn_replay_admit(&w, a, 0, FZN_FRAME_GRANT, 1000) == FZN_FRESH_OK,
	      "re-presenting a grant was treated as a replay");
}

static void test_bad_arguments(void)
{
	fzn_replay_entry_t storage[2];
	fzn_replay_window_t w;
	uint8_t a[FZN_NONCE_LEN];

	nonce_of(a, 0xa1);
	CHECK(fzn_replay_init(&w, storage, 0) == FZN_FRESH_ERR_MALFORMED,
	      "a zero-capacity window was accepted, and would accept everything");
	CHECK(fzn_replay_init(&w, NULL, 2) == FZN_FRESH_ERR_MALFORMED, "null storage accepted");
	CHECK(fzn_replay_init(NULL, storage, 2) == FZN_FRESH_ERR_MALFORMED,
	      "null window accepted");

	fzn_replay_init(&w, storage, 2);
	CHECK(fzn_replay_admit(&w, NULL, 2000, FZN_FRAME_COMMAND, 1000) ==
	              FZN_FRESH_ERR_MALFORMED,
	      "a null nonce was admitted");
	CHECK(fzn_replay_expire(NULL, 1000) == 0, "expire on a null window did not return 0");
}

/* The positive control. Nearly every case above asserts a refusal, and a
 * fzn_replay_admit that refused everything would satisfy them; this is what
 * separates working code from a stub that says no. */
static void test_the_suite_can_tell_pass_from_fail(void)
{
	fzn_replay_entry_t storage[2];
	fzn_replay_window_t w;
	uint8_t a[FZN_NONCE_LEN];

	nonce_of(a, 0x5e);
	fzn_replay_init(&w, storage, 2);
	CHECK(fzn_replay_admit(&w, a, 2000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_OK,
	      "the positive control fails, so every refusal above proves nothing");
	CHECK(fzn_freshness_check(2000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_OK,
	      "the freshness positive control fails");
}

int main(void)
{
	test_command_expiry_is_mandatory();
	test_grants_do_not_expire_by_default();
	test_replay_is_refused();
	test_expiry_bounds_the_memory();
	test_a_full_window_refuses_rather_than_evicting();
	test_a_refused_frame_costs_no_slot();
	test_grants_are_not_recorded();
	test_bad_arguments();
	test_the_suite_can_tell_pass_from_fail();

	printf("freshness_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
