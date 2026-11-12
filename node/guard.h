/*
 * A GUARD AGAINST HAMMERING, project.md sec 1074, the holder's: who may ask
 * again how soon -- a caller ringing, first -- by the standard means, a token
 * bucket a key and an escalating block.
 *
 * A KEY HAS A BUCKET of `burst` tokens; each ask takes one, and one more is
 * earned each `refill_ms`, up to `burst`. An ask with no token is refused. A key
 * refused again while refused is BLOCKED for a period that doubles with each
 * offence, from `refill_ms` to `block_max_ms`, fail2ban's way; a key quiet for
 * `block_max_ms` begins again clean. Keyed by who asks, a user's key, not where
 * from, so changing host or address does not escape it.
 *
 * SAID ONCE: `*first` is 1 the first time a key is refused after it was
 * admitted, for one log line rather than one per ask.
 *
 * THE TABLE IS THE CALLER'S, of any size (sec 704), and GROWN, NOT FULL (sec
 * 753, the holder's sec 1047 on caps): before an ask, a caller finding
 * `fzn_guard_full` grows its rows and hands them back by `fzn_guard_rows`. Only
 * where it cannot -- out of memory -- does an ask give way the least recently
 * seen key that is not blocked; never a blocked one, which would set it free.
 */
#ifndef FZN_NODE_GUARD_H
#define FZN_NODE_GUARD_H

#include <stddef.h>
#include <stdint.h>

#define FZN_GUARD_KEY_LEN 32u

typedef enum fzn_guard_verdict {
	FZN_GUARD_ADMIT = 0,
	FZN_GUARD_REFUSED = 1, /* no token now */
	FZN_GUARD_BLOCKED = 2  /* refused while refused: blocked a while */
} fzn_guard_verdict_t;

typedef struct fzn_guard_slot {
	uint8_t key[FZN_GUARD_KEY_LEN];
	uint64_t tokens_at_ms;  /* when its tokens were last counted up */
	uint64_t seen_ms;       /* when it last asked */
	uint64_t blocked_until_ms;
	uint32_t tokens;
	uint32_t offences;      /* blocks in a row, the period's doubling */
	int refused, used;
} fzn_guard_slot_t;

typedef struct fzn_guard {
	fzn_guard_slot_t *rows;
	size_t cap;
	size_t used;            /* rows holding a key */
	uint64_t refused_total; /* every refusal, for a count to read */
} fzn_guard_t;

void fzn_guard_init(fzn_guard_t *g, fzn_guard_slot_t *rows, size_t cap);

/* EVERY ROW HOLDS A KEY: the caller grows them before the next ask. */
int fzn_guard_full(const fzn_guard_t *g);

/* THE ROWS GROWN to `cap`: `rows` holds the first `g->cap` as they were (a
 * realloc), the rest are cleared here. A smaller `cap` is refused, 0. */
int fzn_guard_rows(fzn_guard_t *g, fzn_guard_slot_t *rows, size_t cap);

/* AN ASK BY `key` at `now_ms`, held to `burst` tokens earned one a `refill_ms`
 * and blocks doubling to `block_max_ms`. `*first` as above; may be NULL. */
fzn_guard_verdict_t fzn_guard_ask(fzn_guard_t *g, const uint8_t key[FZN_GUARD_KEY_LEN],
                                  uint64_t now_ms, uint32_t burst, uint64_t refill_ms,
                                  uint64_t block_max_ms, int *first);

#endif /* FZN_NODE_GUARD_H */
