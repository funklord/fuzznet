/* Replay defence under a coverage-guided fuzzer, against the property the
 * module exists to provide.
 *
 * THE ORACLE: no nonce is admitted twice while its first admission is still
 * live. That is what a replay window is for, and a failure here is an
 * accepted replay -- sec 4.3's whole subject. Two more of that section's
 * rules are checked alongside, because both are cheap and both fail open if
 * they ever break: a command carrying no expiry must be refused, and an
 * expiry already passed must be refused.
 *
 * RE-ADMISSION AFTER EXPIRY IS NOT A BUG, and the oracle is written to say
 * so. The window is bounded and expiry is what bounds it; once an entry has
 * expired the same nonce may legitimately be admitted again. The check is
 * therefore against the previous admission's expiry rather than against
 * having-been-seen, which is the difference between testing the design and
 * testing an assumption about it.
 *
 * `now` ONLY MOVES FORWARD. A fuzzer handed a free-running clock will step it
 * backwards and manufacture "replays" that no receiver could experience, so
 * the harness accumulates deltas instead. A false positive costs more than a
 * missed path here: it is the report nobody trusts twice.
 *
 * Nonces are one byte expanded to fill the field, for the reason
 * chain_guided.c gives at length -- 24 bytes drawn from fuzzer input never
 * collide, so no nonce is ever offered twice, so the code this file exists to
 * exercise is never reached and the campaign reports clean for ever.
 *
 * THE HORIZON IS THE FOURTH RULE CHECKED, and it is here rather than only in
 * the unit suite because it is the one a fuzzer can attack directly: an
 * admitted expiry further ahead than MAX_AHEAD is a slot no sweep can ever
 * reclaim, which is how a full window became a permanent outage before the
 * horizon existed. MAX_AHEAD is 128 against a generator whose expiries run to
 * `now + 255`, so both sides of the boundary are ordinary input rather than a
 * corner the fuzzer has to be lucky to find.
 */

#include "../freshness.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WINDOW_CAP 8
#define SEEN_MAX   256
#define MAX_AHEAD  128

struct cursor {
	const uint8_t *p;
	size_t n, i;
};

static uint8_t take8(struct cursor *c)
{
	return c->i < c->n ? c->p[c->i++] : 0u;
}

/* What the harness believes the window should hold: for each one-byte nonce,
 * the expiry of its most recent successful admission, or 0 for never. */
struct seen {
	uint64_t expires_at[SEEN_MAX];
	int admitted[SEEN_MAX];
};

static int drive(const uint8_t *data, size_t size)
{
	fzn_replay_window_t window;
	fzn_replay_entry_t entries[WINDOW_CAP];
	uint8_t nonce[FZN_NONCE_LEN];
	struct cursor c = { data, size, 0 };
	struct seen seen;
	uint64_t now = 1;

	if (fzn_replay_init(&window, entries, WINDOW_CAP, MAX_AHEAD) != FZN_FRESH_OK)
		return 1;
	memset(&seen, 0, sizeof(seen));

	while (c.i < c.n) {
		uint8_t op = take8(&c);
		uint8_t id;
		uint64_t expires;
		fzn_expiry_rule_t kind;
		fzn_fresh_err_t err;

		if ((op & 7u) == 0u) {
			now += take8(&c);
			(void)fzn_replay_expire(&window, now);
			continue;
		}

		id = take8(&c);
		/* Zero means no expiry, which is a case worth reaching rather
		 * than an accident to avoid. */
		expires = take8(&c);
		if (expires != 0u)
			expires += now;
		kind = (op & 8u) ? FZN_EXPIRY_OPTIONAL : FZN_EXPIRY_REQUIRED;

		memset(nonce, id, sizeof(nonce));
		err = fzn_replay_admit(&window, nonce, expires, kind, now);

		if (err != FZN_FRESH_OK) {
			now += (op >> 4) & 1u;
			continue;
		}

		/* sec 4.3: a command with no expiry must never be admitted. */
		if (kind == FZN_EXPIRY_REQUIRED && expires == FZN_NO_EXPIRY)
			return 1;
		/* nor one whose expiry has passed. */
		if (expires != FZN_NO_EXPIRY && expires <= now)
			return 1;
		/* nor one further ahead than this receiver will remember a nonce
		 * for. An entry admitted past the horizon is a slot the sweep can
		 * never reclaim, so the window fills and never drains -- and the
		 * refusal for a full window is deliberate, which is what made the
		 * outage permanent. Subtraction rather than `now + MAX_AHEAD`
		 * because the line above has already established `expires > now`
		 * and this way nothing can overflow. */
		if (expires != FZN_NO_EXPIRY && expires - now > MAX_AHEAD)
			return 1;
		/* THE REPLAY ORACLE, and it applies only to frames that STATE an
		 * expiry.
		 *
		 * The first version of this asserted the property for every
		 * admitted frame and fired within seconds. The code was right and
		 * the oracle was wrong: `fzn_replay_admit` returns OK for
		 * `expires_at == 0` without consulting the window at all, and
		 * says why -- a grant may legitimately carry no expiry, there is
		 * nothing to remember it until, re-presenting one is how a chain
		 * is verified rather than an attack, and recording them would
		 * build exactly the unbounded set this design avoids.
		 *
		 * Nor is it a hole. A stranger replaying a recorded command
		 * cannot turn it into an unexpiring grant: `expires_at` and
		 * `kind` are both inside the authenticated head, so changing
		 * either invalidates the tag.
		 *
		 * So the property is narrower than "no nonce twice", and stating
		 * it correctly is most of the work: **a nonce carrying a stated
		 * expiry, once admitted, must not be admitted again while that
		 * expiry is live.** */
		if (expires != FZN_NO_EXPIRY && seen.admitted[id] &&
		    seen.expires_at[id] != FZN_NO_EXPIRY && seen.expires_at[id] > now)
			return 1;

		if (expires != FZN_NO_EXPIRY) {
			seen.admitted[id] = 1;
			seen.expires_at[id] = expires;
		}
		now += (op >> 4) & 1u;
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

/* One admission, the same nonce offered again while live, and a window
 * driven past its capacity. */
static const uint8_t CASE_ADMIT[] = { 0x01, 0x11, 0x20, 0x01, 0x12, 0x20 };
static const uint8_t CASE_REPLAY[] = { 0x01, 0x11, 0x20, 0x01, 0x11, 0x20, 0x01, 0x11, 0x20 };
static const uint8_t CASE_FULL[] = { 0x01, 0x01, 0x40, 0x01, 0x02, 0x40, 0x01, 0x03, 0x40,
	                             0x01, 0x04, 0x40, 0x01, 0x05, 0x40, 0x01, 0x06, 0x40,
	                             0x01, 0x07, 0x40, 0x01, 0x08, 0x40, 0x01, 0x09, 0x40 };
static const uint8_t CASE_EXPIRY[] = { 0x01, 0x11, 0x02, 0x00, 0xff, 0x01, 0x11, 0x02 };
static const uint8_t CASE_NOEXPIRY[] = { 0x01, 0x11, 0x00, 0x09, 0x12, 0x00 };
/* An expiry of 0xff, which is past MAX_AHEAD and must be refused, followed by
 * the same nonce at an expiry inside it -- which must then be admitted,
 * because a frame refused at the horizon may not have cost a slot or been
 * recorded as seen. Both halves matter: the first alone is satisfied by a
 * receiver that refuses everything. */
static const uint8_t CASE_HORIZON[] = { 0x01, 0x11, 0xff, 0x01, 0x11, 0x20 };

int main(int argc, char **argv)
{
	static uint8_t buf[65536];
	int failures = 0, cases = 0;

	if (argc > 1) {
		for (int i = 1; i < argc; i++) {
			FILE *f = fopen(argv[i], "rb");
			size_t n;

			if (!f) {
				printf("  FAIL: cannot open %s\n", argv[i]);
				failures++;
				continue;
			}
			n = fread(buf, 1, sizeof(buf), f);
			fclose(f);
			cases++;
			if (drive(buf, n)) {
				printf("  FAIL: %s -- a replay or stale frame was admitted\n",
				       argv[i]);
				failures++;
			}
		}
	} else {
		const uint8_t *builtin[] = { CASE_ADMIT, CASE_REPLAY, CASE_FULL, CASE_EXPIRY,
			                     CASE_NOEXPIRY, CASE_HORIZON };
		const size_t sizes[] = { sizeof(CASE_ADMIT), sizeof(CASE_REPLAY),
			                 sizeof(CASE_FULL), sizeof(CASE_EXPIRY),
			                 sizeof(CASE_NOEXPIRY), sizeof(CASE_HORIZON) };

		/* Sized from the array rather than the literal 5 it used to be:
		 * adding a case above and not the count here is a case that never
		 * runs and reports nothing. */
		for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
			cases++;
			if (drive(builtin[i], sizes[i])) {
				printf("  FAIL: built-in case %zu admitted what it should not\n",
				       i);
				failures++;
			}
		}
	}

	printf("freshness_guided: %d case(s), %d failure(s)\n", cases, failures);
	return failures == 0 ? 0 : 1;
}

#endif
