/* A fuzz harness for expiry and the replay window.
 *
 * project.md sec 4.4a is why this one matters: "replay is a configuration
 * change, so freshness is load-bearing rather than hygienic". A replayed
 * command is a router reconfigured a second time by somebody who recorded
 * the first, so a hole here is not a duplicated message.
 *
 * The window has caller-owned storage, so it gets a canary like the
 * reassembly harness. But its real invariants are about the SET it
 * maintains, and they are checked exhaustively after every call rather than
 * sampled:
 *
 *   - the window never holds more than its capacity;
 *   - no two live entries share a nonce, or the set has stopped being one;
 *   - every live entry is unexpired, since an expired one is memory held
 *     for nothing and the bound depends on their leaving;
 *   - a nonce admitted at `now` is refused if offered again at the same
 *     `now` -- the security property in one line, over arbitrary input.
 *
 * Bounded and seeded as the other harnesses are, and it counts what it
 * reached for the reason recorded against chunk/test/reassembly_fuzz.c: a
 * generator that stops producing acceptable input reports success exactly
 * as loudly as one that works.
 */

#include "../freshness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define WINDOW 8
#define CANARY 16
#define CANARY_BYTE 0x7e

struct arena {
	uint8_t front[CANARY];
	fzn_replay_entry_t entries[WINDOW];
	uint8_t back[CANARY];
};

struct coverage {
	unsigned long admitted;
	unsigned long replayed;
	unsigned long expired;
};

static int canaries_intact(const struct arena *a)
{
	for (size_t i = 0; i < CANARY; i++) {
		if (a->front[i] != CANARY_BYTE || a->back[i] != CANARY_BYTE)
			return 0;
	}
	return 1;
}

static const char *invariants(const struct arena *a, const fzn_replay_window_t *w, uint64_t now)
{
	if (!canaries_intact(a))
		return "a write landed outside the window's storage";
	if (w->used > w->capacity)
		return "the window holds more than its capacity";

	for (size_t i = 0; i < w->used; i++) {
		if (w->entries[i].expires_at <= now)
			return "an expired entry survived, so the bound does not shrink";
		for (size_t k = i + 1; k < w->used; k++) {
			if (memcmp(w->entries[i].nonce, w->entries[k].nonce, FZN_NONCE_LEN) == 0)
				return "two live entries share a nonce";
		}
	}
	return NULL;
}

static int fuzz_one(const uint8_t *data, size_t len, struct coverage *cov)
{
	struct arena arena;
	fzn_replay_window_t w;
	size_t pos = 0;
	uint64_t now = 0;

	memset(&arena, CANARY_BYTE, sizeof(arena));
	memset(arena.entries, 0, sizeof(arena.entries));
	if (fzn_replay_init(&w, arena.entries, WINDOW) != FZN_FRESH_OK)
		return 0;

	while (pos + 4 <= len) {
		uint8_t nonce[FZN_NONCE_LEN];
		uint64_t expires;
		fzn_frame_kind_t kind;
		fzn_fresh_err_t err;
		const char *broke;

		/* Nonces from a small set so that a REPLAY actually happens --
		 * with 24 random bytes it essentially never would, and the one
		 * property this file exists to check would be unreachable. */
		memset(nonce, data[pos] & 0x07u, FZN_NONCE_LEN);
		/* Time moves forward sometimes, which is what makes entries
		 * expire and the window drain. */
		now += (data[pos + 1] & 0x03u) * 10u;
		expires = ((data[pos + 2] & 0x0fu) == 0) ? 0u : now + (data[pos + 2] * 3u);
		kind = (data[pos + 3] & 1u) ? FZN_FRAME_COMMAND : FZN_FRAME_GRANT;
		pos += 4;

		err = fzn_replay_admit(&w, nonce, expires, kind, now);

		broke = invariants(&arena, &w, now);
		if (broke) {
			printf("  INVARIANT: %s\n", broke);
			return 1;
		}

		if (err == FZN_FRESH_OK) {
			cov->admitted++;

			/* The security property, over arbitrary input: what
			 * was just admitted and recorded must not be admitted
			 * again at the same instant. A grant with no expiry is
			 * deliberately not recorded, so it is exempt -- that
			 * is freshness.h's rule, not a hole. */
			if (expires != 0) {
				if (fzn_replay_admit(&w, nonce, expires, kind, now) !=
				    FZN_FRESH_ERR_REPLAY) {
					printf("  INVARIANT: a nonce was admitted twice at "
					       "the same instant\n");
					return 1;
				}
			}
		} else if (err == FZN_FRESH_ERR_REPLAY) {
			cov->replayed++;
		} else if (err == FZN_FRESH_ERR_EXPIRED || err == FZN_FRESH_ERR_NO_EXPIRY) {
			cov->expired++;

			/* A refused frame must never have cost a slot. */
			for (size_t i = 0; i < w.used; i++) {
				if (memcmp(w.entries[i].nonce, nonce, FZN_NONCE_LEN) == 0 &&
				    w.entries[i].expires_at == expires) {
					printf("  INVARIANT: a refused frame occupied a "
					       "slot\n");
					return 1;
				}
			}
		}
	}

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

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov = { 0, 0, 0 };
	uint8_t buf[128];

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}

	for (unsigned long c = 0; c < cases; c++) {
		uint32_t state = (uint32_t)c + 1u;
		size_t len = (size_t)(next(&state) % (sizeof(buf) + 1u));

		for (size_t i = 0; i < len; i++)
			buf[i] = (uint8_t)next(&state);

		if (fuzz_one(buf, len, &cov)) {
			printf("freshness_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* A replay has to actually occur, or the property this file is about
	 * was never exercised. That is the whole lesson of the reassembly
	 * harness: reaching nothing and finding nothing look identical. */
	if (cov.admitted < cases / 200u || cov.replayed < cases / 200u) {
		printf("freshness_fuzz: REACHED TOO LITTLE -- %lu admitted, %lu replays in "
		       "%lu cases. A run with no replay in it does not test replay.\n",
		       cov.admitted, cov.replayed, cases);
		return 1;
	}

	printf("freshness_fuzz: %lu cases, %lu admitted, %lu replays, %lu stale, "
	       "no invariant broken\n",
	       cases, cov.admitted, cov.replayed, cov.expired);
	return 0;
}
#endif
