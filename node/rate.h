/*
 * HOW OFTEN A VALUE IS STORED OR CARRIED, bounded however it is declared, sec
 * 1034, the holder's: "a built in protection model for not storing nor
 * distributing a value too often even if misconfigured." A gate, keyed by the
 * value's name, that a writer offers each new value to before storing or
 * sending it.
 *
 * A FEW AT ONCE, THEN ONE A WINDOW: a name may pass FZN_RATE_NAME_BURST values in
 * quick succession, and earns one more each window it is not used, up to that
 * many -- so a person or a script setting a value and then changing or clearing
 * it is answered at once, as before, and only a rate kept up is held. Measured
 * first without it: eight live scripts that set a cell twice in a second were
 * answered `ok held` (sec 1037).
 *
 * COALESCED, NEVER QUEUED: a value offered past that is held, the newest standing
 * in for every one before it, and handed back as the name earns its next pass
 * (`fzn_rate_due`). So a button pressed a thousand times a second is stored once
 * a window, with the last press, and nothing grows.
 *
 * CEILINGS KEPT WHATEVER IS DECLARED: a name's window is never shorter than
 * FZN_RATE_FLOOR_MS, and across every name at most FZN_RATE_BURST values pass
 * in any FZN_RATE_BURST_MS -- so a schema entry, a rule or a caller asking for
 * 0 is held to the floor, and many names written at once cannot make up in
 * number what each is denied in rate.
 *
 * SAID ONCE: the first time a name is held after passing freely, `*first` says
 * so, and not again until it passes freely once more -- for its writer to log
 * one line, rather than one per write, so the log that reports a flood is not
 * flooded by it.
 *
 * THE TABLE IS THE CALLER'S, of any size (sec 704); a full one gives way its
 * least recently offered name with nothing held.
 */
#ifndef FZN_NODE_RATE_H
#define FZN_NODE_RATE_H

#include <stddef.h>
#include <stdint.h>

#define FZN_RATE_FLOOR_MS 1000u
#define FZN_RATE_NAME_BURST 4u
#define FZN_RATE_BURST 64u
#define FZN_RATE_BURST_MS 1000u
#define FZN_RATE_KEY_MAX 160u
#define FZN_RATE_VALUE_MAX 320u

typedef enum fzn_rate_verdict {
	FZN_RATE_REFUSED = -1, /* malformed, or no room: the writer goes on as before */
	FZN_RATE_NOW = 0,      /* store or send it now */
	FZN_RATE_HELD = 1      /* held: the newest of its window, handed back by `fzn_rate_due` */
} fzn_rate_verdict_t;

typedef struct fzn_rate_slot {
	uint8_t key[FZN_RATE_KEY_MAX];
	size_t key_len;
	uint8_t value[FZN_RATE_VALUE_MAX];
	size_t value_len;
	uint64_t passed_ms; /* when a value of it last passed */
	uint64_t earned_ms; /* when its passes were last counted up */
	unsigned passes;    /* passes it has in hand, to FZN_RATE_NAME_BURST */
	uint64_t window_ms; /* its window, floor applied */
	uint64_t offered_ms;
	unsigned long held; /* values coalesced since it last passed */
	int pending, used;
	int said; /* its holding said, until a value passes freely again */
} fzn_rate_slot_t;

typedef struct fzn_rate {
	fzn_rate_slot_t *rows;
	size_t cap;
	uint64_t burst_from_ms;
	unsigned burst_used;
} fzn_rate_t;

void fzn_rate_init(fzn_rate_t *r, fzn_rate_slot_t *rows, size_t cap);

/* OFFER `value` of `key`, whose declared window is `every_ms`, at `now_ms`:
 * NOW to store it, HELD when it is held -- `*first` 1 when this name has just
 * begun to be held, for one line to be said. */
fzn_rate_verdict_t fzn_rate_offer(fzn_rate_t *r, const uint8_t *key, size_t key_len,
                                  const uint8_t *value, size_t value_len, uint64_t every_ms,
                                  uint64_t now_ms, int *first);

/* THE HELD VALUES WHOSE WINDOW HAS PASSED at `now_ms`, of names beginning
 * `prefix` -- one kind's, where one gate serves several -- each handed to `due`
 * once and counted as passed: how many. A burst already spent holds them to the
 * next pass. */
size_t fzn_rate_due(fzn_rate_t *r, uint64_t now_ms, const uint8_t *prefix, size_t prefix_len,
                    void (*due)(void *ctx, const uint8_t *key, size_t key_len,
                                const uint8_t *value, size_t value_len, unsigned long held),
                    void *ctx);

#endif /* FZN_NODE_RATE_H */
