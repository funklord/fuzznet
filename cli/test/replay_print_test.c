/* Tests for cli/replay_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is that a full window is an emergency that
 * does not look like one, and that its two causes want opposite fixes.
 * `frame/freshness.h` says both: the window "refuses rather than evicting"
 * so a host in this state is REFUSING FRESH FRAMES, and a full one "means
 * either that nobody is expiring or that the capacity is below the arrival
 * rate the horizon implies -- those want different fixes and the value says
 * neither".
 *
 * So the cases below hold the window FULL in both senses -- same `used`, same
 * `capacity`, same return value from every other accessor -- and require the
 * lines and the states to differ. `fzn_replay_expirable` is what makes that
 * possible without expiring anything, which is the whole reason it exists.
 */

#include "../replay_print.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL replay_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_replay_entry_t ENTRIES[2];

/* Fill the window with `n` entries, `expired` of which are already past
 * `now = 100`. Built directly, as `cli/test/revocation_print_test.c` builds
 * its store: what is tested here is the rendering of a window, and driving
 * admit to reach one is `frame/test/freshness_test.c`'s job. */
static int window_of(fzn_replay_window_t *w, size_t n, size_t expired)
{
	size_t i;

	memset(ENTRIES, 0, sizeof(ENTRIES));
	if (fzn_replay_init(w, ENTRIES, 2u, 1000u) != FZN_FRESH_OK)
		return 0;
	for (i = 0; i < n && i < 2u; i++) {
		memset(ENTRIES[i].nonce, (int)(0x30u + i), FZN_NONCE_LEN);
		/* 100 is `now` in every case below. `> now` KEEPS, so 100
		 * itself is expired and 101 is live -- the same boundary
		 * `fzn_replay_expire` draws. */
		ENTRIES[i].expires_at = (i < expired) ? 100u : 500u;
	}
	w->used = n < 2u ? n : 2u;
	return 1;
}

static size_t line_of(const fzn_replay_window_t *w, uint64_t now, char *out,
                      fzn_replay_line_t *said)
{
	size_t len = 99;

	*said = (fzn_replay_line_t)-1;
	CHECK(fzn_replay_print(w, now, out, FZN_REPLAY_PRINT_MAX, &len, said) == FZN_FRESH_OK,
	      "rendering refused a window it should have printed");
	return len;
}

int main(void)
{
	fzn_replay_window_t w;
	char line[FZN_REPLAY_PRINT_MAX];
	char unpruned[FZN_REPLAY_PRINT_MAX];
	char live[FZN_REPLAY_PRINT_MAX];
	fzn_replay_line_t said;
	size_t len = 0;

	/* ---- NO WINDOW AT ALL is not an idle host. */
	len = line_of(NULL, 100u, line, &said);
	CHECK(said == FZN_REPLAY_LINE_NONE, "a NULL window was given an occupancy");
	CHECK(len > 0 && line[len] == '\0', "the line is not terminated at its length");
	CHECK(strstr(line, "cannot say") != NULL, "a host with no window did not say so");
	CHECK(strstr(line, "0 of 0") == NULL,
	      "a window that cannot be read printed an occupancy, which reads as an idle "
	      "host rather than an unreadable one");

	/* ---- NOTHING RECORDED. */
	CHECK(window_of(&w, 0u, 0u), "the fixture does not build");
	len = line_of(&w, 100u, line, &said);
	CHECK(said == FZN_REPLAY_LINE_EMPTY, "an empty window was not EMPTY");
	CHECK(strstr(line, "nothing recorded") != NULL, "the line does not say it is empty");

	/* ---- HOLDING, with room. */
	CHECK(window_of(&w, 1u, 0u), "the fixture does not build");
	len = line_of(&w, 100u, line, &said);
	CHECK(said == FZN_REPLAY_LINE_HOLDING, "a window with room was not HOLDING");
	CHECK(strstr(line, "holding 1 of 2") != NULL, "the line does not carry the occupancy");
	CHECK(strstr(line, "REFUSING") == NULL, "a window with room claimed to be refusing");

	/* ---- FULL, WITH ENTRIES ALREADY EXPIRED: nobody is calling expire. */
	CHECK(window_of(&w, 2u, 1u), "the fixture does not build");
	CHECK(fzn_replay_expirable(&w, 100u) == 1u,
	      "the fixture does not put an expired entry in a full window, so it tests "
	      "nothing");
	len = line_of(&w, 100u, unpruned, &said);
	CHECK(said == FZN_REPLAY_LINE_FULL_UNPRUNED,
	      "a full window holding expired entries was not reported as unpruned");
	CHECK(strstr(unpruned, "REFUSING FRESH FRAMES") != NULL,
	      "the line does not say the host is refusing fresh frames, which is what a "
	      "full window MEANS and what no return value carries");
	CHECK(strstr(unpruned, "calling expire") != NULL,
	      "the line does not name the fix, which is a caller rather than a bigger array");

	/* ---- FULL OF LIVE ENTRIES: the capacity is too small. Same `used`,
	 * same `capacity`, and the opposite fix. */
	CHECK(window_of(&w, 2u, 0u), "the fixture does not build");
	CHECK(fzn_replay_expirable(&w, 100u) == 0u,
	      "the fixture leaves something to expire, so the two full states are not held "
	      "apart by what this case varies");
	len = line_of(&w, 100u, live, &said);
	CHECK(said == FZN_REPLAY_LINE_FULL_LIVE,
	      "a full window of live entries was not reported as undersized");
	CHECK(strstr(live, "REFUSING FRESH FRAMES") != NULL,
	      "the line does not say the host is refusing fresh frames");
	CHECK(strstr(live, "capacity is below") != NULL,
	      "the line does not name the fix, which is the sizing formula rather than a "
	      "call");
	CHECK(strcmp(live, unpruned) != 0,
	      "two full windows wanting opposite fixes produced the same sentence, which is "
	      "the state the return value already leaves a caller in");

	/* ---- AND EXPIRING NOTHING IS NOT A SIDE EFFECT. The count above was
	 * taken by a printer, and a printer that expired what it counted would
	 * change the thing it was describing.
	 *
	 * THE COMPILER ALREADY HOLDS THIS, so the assertion cannot fail while
	 * `fzn_replay_expirable` and `fzn_replay_print` take a
	 * `const fzn_replay_window_t *` -- a sabotage for it was written and
	 * reported NOT-BUILT. It stays as a tripwire for the plausible future
	 * edit that widens either signature, which is the day it starts being
	 * able to fail. sec 229. */
	CHECK(window_of(&w, 2u, 1u), "the fixture does not build");
	len = line_of(&w, 100u, line, &said);
	CHECK(w.used == 2u,
	      "rendering a window reclaimed an entry, so a report changed what it described");

	/* ---- A WINDOW WHOSE FIELDS DISAGREE. Not reachable through `_init`. */
	CHECK(window_of(&w, 2u, 0u), "the fixture does not build");
	w.used = w.capacity + 1u;
	len = line_of(&w, 100u, line, &said);
	CHECK(said == FZN_REPLAY_LINE_NONE,
	      "a window whose count exceeds its array was given an occupancy to believe");
	CHECK(fzn_replay_expirable(&w, 100u) == 0u,
	      "expirable walked a window whose fields disagree");

	/* ---- THE OPERANDS. */
	CHECK(window_of(&w, 1u, 0u), "the fixture does not build");
	CHECK(fzn_replay_print(&w, 100u, NULL, sizeof(line), &len, &said)
	              == FZN_FRESH_ERR_MALFORMED, "printing accepted a null buffer");
	CHECK(fzn_replay_print(&w, 100u, line, sizeof(line), NULL, &said)
	              == FZN_FRESH_ERR_MALFORMED, "printing accepted a null length");
	CHECK(fzn_replay_print(&w, 100u, line, sizeof(line), &len, NULL)
	              == FZN_FRESH_ERR_MALFORMED,
	      "printing accepted a null state out-parameter, which is the required half");

	/* ---- A BUFFER TOO SMALL REPORTS WHAT IT NEEDED AND WRITES NOTHING. */
	said = FZN_REPLAY_LINE_HOLDING;
	len = 0;
	CHECK(fzn_replay_print(&w, 100u, line, 4u, &len, &said) == FZN_FRESH_ERR_MALFORMED,
	      "a four-byte buffer took a line");
	CHECK(len > 4u, "the refusal does not say how much room the line needed");
	CHECK(said == FZN_REPLAY_LINE_NONE,
	      "a refused render left a verdict behind, which a caller would read as one");

	printf("replay_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
