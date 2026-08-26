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

/* The horizon every case below runs under, unless it says otherwise.
 *
 * Wide enough that no case written before the horizon existed changes its
 * answer -- the widest expiry any of them states is `now + 8000` -- so a
 * failure in one of those is a failure in what it was already testing rather
 * than a horizon refusal wearing its name. The cases that are ABOUT the
 * horizon set their own. */
#define AHEAD 10000u

static void nonce_of(uint8_t out[FZN_NONCE_LEN], uint8_t seed)
{
	memset(out, seed, FZN_NONCE_LEN);
}

/* ---- expiry, which is sec 4.3 ---------------------------------------- */

static void test_command_expiry_is_mandatory(void)
{
	CHECK(fzn_freshness_check(2000, FZN_EXPIRY_REQUIRED, 1000, AHEAD) == FZN_FRESH_OK,
	      "a live command was refused");
	CHECK(fzn_freshness_check(1000, FZN_EXPIRY_REQUIRED, 2000, AHEAD) == FZN_FRESH_ERR_EXPIRED,
	      "an expired command was accepted");

	/* The half an implementation forgets. Refusing a passed expiry while
	 * accepting an absent one exempts anybody who omits the field. */
	CHECK(fzn_freshness_check(0, FZN_EXPIRY_REQUIRED, 1000, AHEAD) == FZN_FRESH_ERR_NO_EXPIRY,
	      "a command carrying no expiry at all was accepted");

	/* Exactly at the boundary is expired: sec 4.3 wants a receiver to
	 * refuse one that HAS PASSED, and a command whose last valid instant
	 * is now has no valid instant left. */
	CHECK(fzn_freshness_check(1000, FZN_EXPIRY_REQUIRED, 1000, AHEAD) == FZN_FRESH_ERR_EXPIRED,
	      "a command expiring exactly now was accepted");
}

static void test_grants_do_not_expire_by_default(void)
{
	CHECK(fzn_freshness_check(0, FZN_EXPIRY_OPTIONAL, 999999, AHEAD) == FZN_FRESH_OK,
	      "a grant with no expiry was refused -- authority ended by a clock");
	CHECK(fzn_freshness_check(2000, FZN_EXPIRY_OPTIONAL, 1000, AHEAD) == FZN_FRESH_OK,
	      "a live time-boxed grant was refused");
	CHECK(fzn_freshness_check(1000, FZN_EXPIRY_OPTIONAL, 2000, AHEAD) == FZN_FRESH_ERR_EXPIRED,
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
	CHECK(fzn_replay_init(&w, storage, 4, AHEAD) == FZN_FRESH_OK, "init failed");

	CHECK(fzn_replay_admit(&w, a, 2000, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_OK,
	      "a fresh nonce was refused");
	CHECK(fzn_replay_admit(&w, a, 2000, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_ERR_REPLAY,
	      "the same nonce was accepted twice");
	CHECK(fzn_replay_admit(&w, b, 2000, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_OK,
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
	fzn_replay_init(&w, storage, 4, AHEAD);
	fzn_replay_admit(&w, a, 2000, FZN_EXPIRY_REQUIRED, 1000);
	CHECK(w.used == 1, "nonce was not recorded");

	CHECK(fzn_replay_expire(&w, 2500) == 1, "an expired entry was not reclaimed");
	CHECK(w.used == 0, "used %zu after expiry, wanted 0", w.used);

	/* And replaying it now fails on freshness rather than on memory --
	 * which is why forgetting it was safe. */
	CHECK(fzn_replay_admit(&w, a, 2000, FZN_EXPIRY_REQUIRED, 2500) == FZN_FRESH_ERR_EXPIRED,
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
	fzn_replay_init(&w, storage, 2, AHEAD);

	CHECK(fzn_replay_admit(&w, a, 9000, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_OK, "first");
	CHECK(fzn_replay_admit(&w, b, 9000, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_OK, "second");
	CHECK(fzn_replay_admit(&w, c, 9000, FZN_EXPIRY_REQUIRED, 1000) ==
	              FZN_FRESH_ERR_WINDOW_FULL,
	      "a full window admitted a third live entry");

	/* The point of refusing: the oldest entry must STILL be remembered,
	 * so it cannot be replayed. An evicting window would have dropped `a`
	 * to make room, and `a` would be accepted again here -- which is the
	 * attack, since the attacker chose the traffic that filled it. */
	CHECK(fzn_replay_admit(&w, a, 9000, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_ERR_REPLAY,
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
	fzn_replay_init(&w, storage, 2, AHEAD);

	CHECK(fzn_replay_admit(&w, a, 500, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_ERR_EXPIRED,
	      "an expired frame was admitted");
	CHECK(w.used == 0, "an expired frame occupied a slot");

	CHECK(fzn_replay_admit(&w, a, 0, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_ERR_NO_EXPIRY,
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
	fzn_replay_init(&w, storage, 4, AHEAD);
	CHECK(fzn_replay_admit(&w, a, 2000, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_OK,
	      "the first entry was refused");
	CHECK(fzn_replay_admit(&w, b, 2000, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_OK,
	      "the second entry was refused");
	CHECK(w.used == 2, "the window did not record both");

	/* A GRANT, which returns before recording anything. */
	CHECK(fzn_replay_admit(&w, a, 0, FZN_EXPIRY_OPTIONAL, 3000) == FZN_FRESH_OK,
	      "an unexpiring grant was refused");
	CHECK(w.used == 0,
	      "a grant returned early without sweeping, so traffic made entirely of "
	      "grants leaves dead entries holding slots for ever");

	/* And the other early return: a stale command. */
	fzn_replay_init(&w, storage, 4, AHEAD);
	CHECK(fzn_replay_admit(&w, a, 2000, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_OK,
	      "the setup entry was refused");
	CHECK(w.used == 1, "the window did not record it");
	CHECK(fzn_replay_admit(&w, b, 2500, FZN_EXPIRY_REQUIRED, 3000) == FZN_FRESH_ERR_EXPIRED,
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
	fzn_replay_init(&w, storage, 2, AHEAD);

	CHECK(fzn_replay_admit(&w, a, 0, FZN_EXPIRY_OPTIONAL, 1000) == FZN_FRESH_OK,
	      "an unexpiring grant was refused");
	CHECK(w.used == 0, "an unexpiring grant occupied a slot forever");
	CHECK(fzn_replay_admit(&w, a, 0, FZN_EXPIRY_OPTIONAL, 1000) == FZN_FRESH_OK,
	      "re-presenting a grant was treated as a replay");
}

static void test_bad_arguments(void)
{
	fzn_replay_entry_t storage[2];
	fzn_replay_window_t w;
	uint8_t a[FZN_NONCE_LEN];

	nonce_of(a, 0xa1);
	CHECK(fzn_replay_init(&w, storage, 0, AHEAD) == FZN_FRESH_ERR_MALFORMED,
	      "a zero-capacity window was accepted, and would accept everything");
	CHECK(fzn_replay_init(&w, NULL, 2, AHEAD) == FZN_FRESH_ERR_MALFORMED, "null storage accepted");
	CHECK(fzn_replay_init(NULL, storage, 2, AHEAD) == FZN_FRESH_ERR_MALFORMED,
	      "null window accepted");

	fzn_replay_init(&w, storage, 2, AHEAD);
	CHECK(fzn_replay_admit(&w, NULL, 2000, FZN_EXPIRY_REQUIRED, 1000) ==
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
	fzn_replay_init(&w, storage, 2, AHEAD);
	CHECK(fzn_replay_admit(&w, a, 2000, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_OK,
	      "the positive control fails, so every refusal above proves nothing");
	CHECK(fzn_freshness_check(2000, FZN_EXPIRY_REQUIRED, 1000, AHEAD) == FZN_FRESH_OK,
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
	CHECK(fzn_replay_init(&w, storage, 4, AHEAD) == FZN_FRESH_OK, "init refused");
	CHECK(fzn_replay_admit(&w, nonce, 2000, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_OK,
	      "the setup nonce was refused");

	w.used = 5; /* one past the storage it was given */
	CHECK(fzn_replay_expire(&w, 1000) == 0,
	      "the sweep compacted a window whose count is past its capacity");
	CHECK(w.used == 5, "the sweep rewrote `used` on a window it should not have touched");
	CHECK(fzn_replay_admit(&w, nonce, 2000, FZN_EXPIRY_REQUIRED, 1000) ==
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
	CHECK(fzn_replay_init(&w, storage, 4, AHEAD) == FZN_FRESH_OK, "re-init refused");
	for (uint8_t i = 0; i < 4; i++) {
		memset(nonce, (int)(0x30u + i), sizeof(nonce));
		CHECK(fzn_replay_admit(&w, nonce, 5000, FZN_EXPIRY_REQUIRED, 1000) ==
		              FZN_FRESH_OK,
		      "filling the window was refused at entry %u", i);
	}
	CHECK(w.used == 4, "the window holds %zu after four admissions", w.used);
	memset(nonce, 0x3f, sizeof(nonce));
	CHECK(fzn_replay_admit(&w, nonce, 5000, FZN_EXPIRY_REQUIRED, 1000) ==
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
	CHECK(fzn_replay_init(&w, storage, 4, AHEAD) == FZN_FRESH_OK, "init refused");
	no_entries = w;
	no_entries.entries = NULL;

	CHECK(fzn_replay_expire(NULL, 100) == 0, "a null window was swept");
	CHECK(fzn_replay_expire(&no_entries, 100) == 0, "a window with no entries was swept");

	CHECK(fzn_replay_admit(NULL, nonce, 200, FZN_EXPIRY_REQUIRED, 100) ==
	              FZN_FRESH_ERR_MALFORMED,
	      "a null window was admitted to");
	CHECK(fzn_replay_admit(&no_entries, nonce, 200, FZN_EXPIRY_REQUIRED, 100) ==
	              FZN_FRESH_ERR_MALFORMED,
	      "a window with no entries was admitted to");
	CHECK(fzn_replay_admit(&w, NULL, 200, FZN_EXPIRY_REQUIRED, 100) ==
	              FZN_FRESH_ERR_MALFORMED,
	      "a null nonce was admitted");

	CHECK(fzn_replay_init(NULL, storage, 4, AHEAD) == FZN_FRESH_ERR_MALFORMED, "a null window");
	CHECK(fzn_replay_init(&w, NULL, 4, AHEAD) == FZN_FRESH_ERR_MALFORMED, "null storage");
	CHECK(fzn_replay_init(&w, storage, 0, AHEAD) == FZN_FRESH_ERR_MALFORMED, "zero capacity");
}

/* ---- the horizon ------------------------------------------------------- */

/* An expiry further out than this receiver will remember a nonce for.
 *
 * THE DEFECT THIS EXISTS FOR, measured before the horizon was written: with
 * only `expires_at <= now` between a frame and a slot, `expires_at =
 * UINT64_MAX` pinned one for ever. 4096 forged frames filled a 4096-entry
 * window, a sweep a hundred years later dropped none of them, and every
 * genuine frame after that was FZN_FRESH_ERR_WINDOW_FULL. The refusal is
 * correct on purpose -- see `test_a_full_window_refuses_rather_than_evicting`
 * -- so nothing ended the outage. */
static void test_the_horizon_refuses_an_expiry_it_cannot_remember(void)
{
	CHECK(fzn_freshness_check(1000 + AHEAD + 1, FZN_EXPIRY_REQUIRED, 1000, AHEAD) ==
	              FZN_FRESH_ERR_HORIZON,
	      "an expiry one tick past the horizon was admitted");

	/* A century out, which is what a forgery looks like rather than what a
	 * slow link looks like. */
	CHECK(fzn_freshness_check(1000ull + 100ull * 365ull * 24ull * 3600ull,
	                          FZN_EXPIRY_REQUIRED, 1000, AHEAD) == FZN_FRESH_ERR_HORIZON,
	      "an expiry a century out was admitted, so one frame pins a slot for a century");

	/* The value that made the wedge free, and the one that would overflow
	 * `now + max_ahead` if the horizon were computed without care. */
	CHECK(fzn_freshness_check(UINT64_MAX, FZN_EXPIRY_REQUIRED, 1000, AHEAD) ==
	              FZN_FRESH_ERR_HORIZON,
	      "an expiry of UINT64_MAX was admitted");

	/* ITS OWN CODE, not EXPIRED. "Your command is stale" and "your expiry
	 * is further out than I will remember a nonce for" are different faults
	 * in different places, and a receiver that cannot tell them apart
	 * cannot tell a slow link from an attack. */
	CHECK(fzn_freshness_check(UINT64_MAX, FZN_EXPIRY_REQUIRED, 1000, AHEAD) !=
	              FZN_FRESH_ERR_EXPIRED,
	      "the horizon refusal is reported as an expired command");
	CHECK(strcmp(fzn_fresh_err_str(FZN_FRESH_ERR_HORIZON),
	             fzn_fresh_err_str(FZN_FRESH_ERR_EXPIRED)) != 0,
	      "the horizon and expired refusals render as the same text");
	CHECK(strcmp(fzn_fresh_err_str(FZN_FRESH_ERR_HORIZON), "unknown") != 0,
	      "the horizon code has no rendering of its own");
}

/* NOT KEYED ON THE RULE, and this is the half a reader expects to be there.
 *
 * `fzn_replay_admit` records anything carrying a nonzero expiry, branching on
 * `expires_at` and not on `kind` -- so an OPTIONAL frame with a far-future
 * expiry pins a slot by exactly the route a REQUIRED one does. A horizon that
 * applied to commands alone would have left the wedge open under a different
 * label. */
static void test_the_horizon_does_not_care_which_rule_applies(void)
{
	fzn_replay_entry_t storage[2];
	fzn_replay_window_t w;
	uint8_t a[FZN_NONCE_LEN];

	CHECK(fzn_freshness_check(UINT64_MAX, FZN_EXPIRY_OPTIONAL, 1000, AHEAD) ==
	              FZN_FRESH_ERR_HORIZON,
	      "an optional frame with a far-future expiry escaped the horizon, so the "
	      "optional path wedges the window just as the required path did");

	/* And an absent expiry stays outside the horizon entirely: nothing is
	 * remembered for it, so there is nothing to bound, and sec 4.3's grant
	 * rule is untouched. */
	CHECK(fzn_freshness_check(0, FZN_EXPIRY_OPTIONAL, 1000, AHEAD) == FZN_FRESH_OK,
	      "the horizon swallowed a grant carrying no expiry, ending authority by a clock");

	nonce_of(a, 0xa1);
	fzn_replay_init(&w, storage, 2, AHEAD);
	CHECK(fzn_replay_admit(&w, a, UINT64_MAX, FZN_EXPIRY_OPTIONAL, 1000) ==
	              FZN_FRESH_ERR_HORIZON,
	      "the window admitted an optional frame beyond the horizon");
	CHECK(w.used == 0, "a frame refused at the horizon occupied a slot");
}

/* THE POSITIVE CONTROL FOR EVERY REFUSAL ABOVE. Without it a horizon of zero
 * -- refuse everything that states an expiry -- satisfies all of them.
 *
 * It is also the off-by-one, in the accepting direction. `now + max_ahead` is
 * the last instant this receiver sized itself to remember, and a sender that
 * computes its expiry from the agreed lifetime hits it exactly whenever the
 * clocks agree; comparing `>=` would refuse that ordinary case and leave the
 * horizon usable only by senders that undershoot it. */
static void test_an_expiry_exactly_on_the_horizon_is_admitted(void)
{
	fzn_replay_entry_t storage[2];
	fzn_replay_window_t w;
	uint8_t a[FZN_NONCE_LEN];

	CHECK(fzn_freshness_check(1000 + AHEAD, FZN_EXPIRY_REQUIRED, 1000, AHEAD) == FZN_FRESH_OK,
	      "an expiry exactly on the horizon was refused");
	CHECK(fzn_freshness_check(1000 + AHEAD, FZN_EXPIRY_OPTIONAL, 1000, AHEAD) == FZN_FRESH_OK,
	      "an optional expiry exactly on the horizon was refused");
	CHECK(fzn_freshness_check(1000 + AHEAD - 1, FZN_EXPIRY_REQUIRED, 1000, AHEAD) ==
	              FZN_FRESH_OK,
	      "an expiry one tick inside the horizon was refused");

	nonce_of(a, 0xa1);
	fzn_replay_init(&w, storage, 2, AHEAD);
	CHECK(fzn_replay_admit(&w, a, 1000 + AHEAD, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_OK,
	      "the window refused an expiry exactly on its own horizon");
	CHECK(w.used == 1, "an admitted frame was not recorded");
}

/* The whole point of the horizon in one case: a window that fills DRAINS.
 *
 * THE CONTROL IS THE SECOND HALF, and without it this is satisfied by a
 * window that empties itself for any reason at all. So the same full window
 * is offered a frame twice -- once without moving the clock, which must still
 * be FZN_FRESH_ERR_WINDOW_FULL, and once after the horizon has passed, which
 * must be admitted. What separates them is only the clock. */
static void test_a_full_window_drains_once_the_horizon_passes(void)
{
	fzn_replay_entry_t storage[4];
	fzn_replay_window_t w;
	uint8_t n[FZN_NONCE_LEN];

	CHECK(fzn_replay_init(&w, storage, 4, 100) == FZN_FRESH_OK, "init refused");
	for (uint8_t i = 0; i < 4; i++) {
		nonce_of(n, (uint8_t)(0x40u + i));
		CHECK(fzn_replay_admit(&w, n, 1100, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_OK,
		      "filling the window was refused at entry %u", i);
	}
	CHECK(w.used == 4, "the window holds %zu after four admissions", w.used);

	nonce_of(n, 0x99);
	CHECK(fzn_replay_admit(&w, n, 1100, FZN_EXPIRY_REQUIRED, 1000) ==
	              FZN_FRESH_ERR_WINDOW_FULL,
	      "the window was not full, so the drain below proves nothing");

	/* THE CONTROL. Same window, same frame, clock unmoved. */
	CHECK(fzn_replay_admit(&w, n, 1100, FZN_EXPIRY_REQUIRED, 1000) ==
	              FZN_FRESH_ERR_WINDOW_FULL,
	      "a full window let something in without the clock moving");

	/* Past the horizon every entry was admitted under. Because the horizon
	 * bounds how far ahead an expiry may be, this instant is guaranteed to
	 * exist -- which is what the wedge took away: with UINT64_MAX allowed,
	 * there was no `now` at which the window drained. */
	CHECK(fzn_replay_admit(&w, n, 1300, FZN_EXPIRY_REQUIRED, 1201) == FZN_FRESH_OK,
	      "the window was still full past the horizon, so the outage never ends");
	CHECK(w.used == 1, "the drained window holds %zu, wanted 1", w.used);
}

/* The wedge itself, small enough to read: forged frames must no longer be
 * able to take slots the sweep can never reclaim. */
static void test_a_forged_expiry_cannot_pin_a_slot(void)
{
	fzn_replay_entry_t storage[2];
	fzn_replay_window_t w;
	uint8_t n[FZN_NONCE_LEN];

	CHECK(fzn_replay_init(&w, storage, 2, 100) == FZN_FRESH_OK, "init refused");
	for (uint8_t i = 0; i < 8; i++) {
		nonce_of(n, (uint8_t)(0xf0u + i));
		CHECK(fzn_replay_admit(&w, n, UINT64_MAX, FZN_EXPIRY_REQUIRED, 1000) ==
		              FZN_FRESH_ERR_HORIZON,
		      "a forged far-future expiry was admitted at frame %u", i);
	}
	CHECK(w.used == 0, "%zu slot(s) pinned by frames nothing can reclaim", w.used);

	/* And the receiver still works, which is the fault the wedge produced:
	 * not a replay, an outage. */
	nonce_of(n, 0x01);
	CHECK(fzn_replay_admit(&w, n, 1050, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_OK,
	      "a genuine frame was refused after a burst of forgeries");
}

/* An entry expiring exactly at `now` must lose its slot.
 *
 * The sweep's boundary has to be the freshness check's: `fzn_freshness_check`
 * calls `expires_at <= now` EXPIRED, so an entry at exactly `now` would be
 * refused on freshness anyway and holding it is memory spent on nothing. A
 * sweep dropping only `< now` keeps every entry one tick longer than the
 * horizon it was admitted under, which is the sizing formula quietly being
 * wrong by one. */
static void test_an_entry_expiring_exactly_now_loses_its_slot(void)
{
	fzn_replay_entry_t storage[2];
	fzn_replay_window_t w;
	uint8_t a[FZN_NONCE_LEN];

	nonce_of(a, 0xa1);
	CHECK(fzn_replay_init(&w, storage, 2, AHEAD) == FZN_FRESH_OK, "init refused");
	CHECK(fzn_replay_admit(&w, a, 2000, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_OK,
	      "the setup entry was refused");

	/* One tick early it must still be held, or the case below passes for
	 * a sweep that drops everything. */
	CHECK(fzn_replay_expire(&w, 1999) == 0, "an unexpired entry was reclaimed early");
	CHECK(w.used == 1, "used %zu at one tick before expiry, wanted 1", w.used);

	CHECK(fzn_replay_expire(&w, 2000) == 1,
	      "an entry expiring exactly now kept its slot, so the sweep and the "
	      "freshness check disagree about the boundary");
	CHECK(w.used == 0, "used %zu after the boundary sweep, wanted 0", w.used);
}

/* A horizon of 0 is a caller who forgot the field, not a caller asking for no
 * horizon. Reading it the other way would make the unbounded window -- the
 * exact state the wedge above needs -- the one somebody gets by accident,
 * which is `chunk/reassembly.h`'s own argument against `per_sender_max == 0`. */
static void test_a_window_with_no_horizon_is_refused(void)
{
	fzn_replay_entry_t storage[2];
	fzn_replay_window_t w;
	uint8_t a[FZN_NONCE_LEN];

	CHECK(fzn_replay_init(&w, storage, 2, 0) == FZN_FRESH_ERR_MALFORMED,
	      "a window with no horizon was created, and it accepts a century-out expiry");

	/* MALFORMED rather than HORIZON, and the difference is where the fault
	 * is: there is no valid call with a horizon of 0, so it is the argument
	 * that is wrong and not the frame. */
	CHECK(fzn_freshness_check(2000, FZN_EXPIRY_REQUIRED, 1000, 0) == FZN_FRESH_ERR_MALFORMED,
	      "a freshness check with no horizon answered about the frame");
	CHECK(fzn_freshness_check(0, FZN_EXPIRY_OPTIONAL, 1000, 0) == FZN_FRESH_ERR_MALFORMED,
	      "a freshness check with no horizon answered about a grant");

	/* A window a test built by hand rather than through the initialiser --
	 * which freshness.h invites, since a window is a VALUE -- reaches
	 * `fzn_replay_admit` with `max_ahead` zero, and must be refused there
	 * too. A guard at one entry point is not a guard at the other. */
	nonce_of(a, 0xa1);
	memset(&w, 0, sizeof(w));
	w.entries = storage;
	w.capacity = 2;
	CHECK(fzn_replay_admit(&w, a, 2000, FZN_EXPIRY_REQUIRED, 1000) == FZN_FRESH_ERR_MALFORMED,
	      "a hand-built window with no horizon admitted a frame");
	CHECK(w.used == 0, "a refused frame occupied a slot");
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

	test_the_horizon_refuses_an_expiry_it_cannot_remember();
	test_the_horizon_does_not_care_which_rule_applies();
	test_an_expiry_exactly_on_the_horizon_is_admitted();
	test_a_full_window_drains_once_the_horizon_passes();
	test_a_forged_expiry_cannot_pin_a_slot();
	test_an_entry_expiring_exactly_now_loses_its_slot();
	test_a_window_with_no_horizon_is_refused();

	test_a_window_whose_fields_disagree_is_refused();

	test_every_guard_refuses_its_own_argument();

	printf("freshness_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
