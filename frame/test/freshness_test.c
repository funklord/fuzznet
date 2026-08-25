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

/* The sweep runs on calls that return early, which is what
 * `freshness.h`'s "reclaimed on every call" means and what the placement of
 * `fzn_replay_expire` above the early returns is for.
 *
 * THE SCENARIO IS THE ONE THE HEADER NAMES: traffic made entirely of grants,
 * or entirely of stale commands. Both return before anything is recorded, so
 * a sweep placed below them never runs, and a window filled earlier keeps
 * dead entries for ever -- the bound turning into the leak it exists to
 * prevent.
 *
 * `freshness_fuzz` already catches this, on case 25, through the invariant
 * that every live entry is unexpired. This is a second witness at the named
 * scenario rather than a new one: a fuzz failure reports a case number, and
 * the unit suite is what somebody reads first. Neither replaces the other. */
static void test_the_sweep_runs_on_calls_that_return_early(void)
{
	fzn_replay_entry_t storage[4];
	fzn_replay_window_t w;
	uint8_t a[FZN_NONCE_LEN], b[FZN_NONCE_LEN];

	nonce_of(a, 0xa1);
	nonce_of(b, 0xb2);

	/* Two entries that will be dead by t=3000. */
	fzn_replay_init(&w, storage, 4);
	CHECK(fzn_replay_admit(&w, a, 2000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_OK,
	      "the first entry was refused");
	CHECK(fzn_replay_admit(&w, b, 2000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_OK,
	      "the second entry was refused");
	CHECK(w.used == 2, "the window did not record both");

	/* A GRANT, which returns before recording anything. */
	CHECK(fzn_replay_admit(&w, a, 0, FZN_FRAME_GRANT, 3000) == FZN_FRESH_OK,
	      "an unexpiring grant was refused");
	CHECK(w.used == 0,
	      "a grant returned early without sweeping, so traffic made entirely of "
	      "grants leaves dead entries holding slots for ever");

	/* And the other early return: a stale command. */
	fzn_replay_init(&w, storage, 4);
	CHECK(fzn_replay_admit(&w, a, 2000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_OK,
	      "the setup entry was refused");
	CHECK(w.used == 1, "the window did not record it");
	CHECK(fzn_replay_admit(&w, b, 2500, FZN_FRAME_COMMAND, 3000) == FZN_FRESH_ERR_EXPIRED,
	      "a stale command was admitted");
	CHECK(w.used == 0,
	      "a stale command returned early without sweeping, so traffic made "
	      "entirely of stale commands does the same");
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

/* A window whose `used` exceeds its `capacity`.
 *
 * THE ONE THAT WRITES. `fzn_replay_expire` compacts in place with
 * `entries[kept] = entries[i]` over a range bounded by `used`, so a corrupt
 * count reads outside the array and can write outside it too -- and the append
 * in `fzn_replay_admit` tested `used == capacity`, which a count past capacity
 * sails through on its way to writing at `entries[used]`.
 *
 * Both entry points are checked, because the sweep REFUSING is not the same as
 * the sweep repairing: admit calls expire first, expire now declines to touch
 * a bad window, and admit would then have scanned the bad range anyway. A
 * guard at one entry point is not a guard at the other. */
static void test_a_window_whose_fields_disagree_is_refused(void)
{
	fzn_replay_window_t w;
	fzn_replay_entry_t storage[4];
	uint8_t nonce[FZN_NONCE_LEN];

	memset(nonce, 0x11, sizeof(nonce));
	CHECK(fzn_replay_init(&w, storage, 4) == FZN_FRESH_OK, "init refused");
	CHECK(fzn_replay_admit(&w, nonce, 2000, FZN_FRAME_COMMAND, 1000) == FZN_FRESH_OK,
	      "the setup nonce was refused");

	w.used = 5; /* one past the storage it was given */
	CHECK(fzn_replay_expire(&w, 1000) == 0,
	      "the sweep compacted a window whose count is past its capacity");
	CHECK(w.used == 5, "the sweep rewrote `used` on a window it should not have touched");
	CHECK(fzn_replay_admit(&w, nonce, 2000, FZN_FRAME_COMMAND, 1000) ==
	              FZN_FRESH_ERR_MALFORMED,
	      "a corrupt window was scanned and appended to");

	/* A full window is still full rather than malformed: the check must
	 * discriminate between `used == capacity`, which is a real state, and
	 * `used > capacity`, which is not.
	 *
	 * FILLED PROPERLY RATHER THAN BY SETTING `used`, which is how the first
	 * version of this got it wrong. Assigning `used = 4` to a window
	 * holding one real entry leaves three slots of uninitialised stack that
	 * the sweep then reads as expiry times, so what came back depended on
	 * whatever was in them. The bug was in the assertion, and a test whose
	 * setup is itself undefined proves nothing about the code. */
	CHECK(fzn_replay_init(&w, storage, 4) == FZN_FRESH_OK, "re-init refused");
	for (uint8_t i = 0; i < 4; i++) {
		memset(nonce, (int)(0x30u + i), sizeof(nonce));
		CHECK(fzn_replay_admit(&w, nonce, 5000, FZN_FRAME_COMMAND, 1000) ==
		              FZN_FRESH_OK,
		      "filling the window was refused at entry %u", i);
	}
	CHECK(w.used == 4, "the window holds %zu after four admissions", w.used);
	memset(nonce, 0x3f, sizeof(nonce));
	CHECK(fzn_replay_admit(&w, nonce, 5000, FZN_FRAME_COMMAND, 1000) ==
	              FZN_FRESH_ERR_WINDOW_FULL,
	      "a legitimately full window was reported malformed");
}

/* Both entry points, one argument at a time. See chain_test.c's equivalent
 * for the reasoning. */
static void test_every_guard_refuses_its_own_argument(void)
{
	fzn_replay_window_t w, no_entries;
	fzn_replay_entry_t storage[4];
	uint8_t nonce[FZN_NONCE_LEN];

	memset(nonce, 0x11, sizeof(nonce));
	CHECK(fzn_replay_init(&w, storage, 4) == FZN_FRESH_OK, "init refused");
	no_entries = w;
	no_entries.entries = NULL;

	CHECK(fzn_replay_expire(NULL, 100) == 0, "a null window was swept");
	CHECK(fzn_replay_expire(&no_entries, 100) == 0, "a window with no entries was swept");

	CHECK(fzn_replay_admit(NULL, nonce, 200, FZN_FRAME_COMMAND, 100) ==
	              FZN_FRESH_ERR_MALFORMED,
	      "a null window was admitted to");
	CHECK(fzn_replay_admit(&no_entries, nonce, 200, FZN_FRAME_COMMAND, 100) ==
	              FZN_FRESH_ERR_MALFORMED,
	      "a window with no entries was admitted to");
	CHECK(fzn_replay_admit(&w, NULL, 200, FZN_FRAME_COMMAND, 100) ==
	              FZN_FRESH_ERR_MALFORMED,
	      "a null nonce was admitted");

	CHECK(fzn_replay_init(NULL, storage, 4) == FZN_FRESH_ERR_MALFORMED, "a null window");
	CHECK(fzn_replay_init(&w, NULL, 4) == FZN_FRESH_ERR_MALFORMED, "null storage");
	CHECK(fzn_replay_init(&w, storage, 0) == FZN_FRESH_ERR_MALFORMED, "zero capacity");
}

int main(void)
{
	test_command_expiry_is_mandatory();
	test_grants_do_not_expire_by_default();
	test_replay_is_refused();
	test_expiry_bounds_the_memory();
	test_a_full_window_refuses_rather_than_evicting();
	test_a_refused_frame_costs_no_slot();
	test_the_sweep_runs_on_calls_that_return_early();
	test_grants_are_not_recorded();
	test_bad_arguments();
	test_the_suite_can_tell_pass_from_fail();

	test_a_window_whose_fields_disagree_is_refused();

	test_every_guard_refuses_its_own_argument();

	printf("freshness_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
