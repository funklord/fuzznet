/*
 * SYNC-LOAD, project.md sec 966, the holder's 2026-11-09: a telltale of an
 * estate set to sync more than it can carry, so its user is told to write
 * better rules and priorities rather than finding out by what never came.
 *
 * WHAT IT COUNTS: the queues of what waits to cross -- files wanted and not
 * whole, the bytes they still lack, the asks still out when a round ends --
 * and the round itself, how long it took against how often one begins. Each
 * is sampled once a round, at its end, and kept for the last
 * FZN_SYNC_LOAD_SAMPLES rounds.
 *
 * WHAT IT SAYS: per queue its value now, its peak and mean over the window,
 * and whether it is GROWING -- the window full, the last sample above the
 * first, rising at half the steps or more, and no fall of more than a
 * quarter between -- which is a queue that rounds do not drain. And one value, the LOAD: the last round's length as
 * a share of the period, in per cent, at 100 rounds running back to back.
 * The VERDICT is `ok`, `busy` (the load at 100 or over through the window)
 * or `growing` (a queue growing), the last first.
 *
 * Telemetry in memory: a restart begins again. Nothing here reads a clock.
 */
#ifndef FZN_NODE_SYNC_LOAD_H
#define FZN_NODE_SYNC_LOAD_H

#include <stddef.h>
#include <stdint.h>

#define FZN_SYNC_LOAD_SAMPLES 16u

typedef enum fzn_sync_queue {
	FZN_SYNC_QUEUE_FILES = 0,  /* files wanted, not whole */
	FZN_SYNC_QUEUE_FILE_BYTES, /* the bytes the wanted files are long */
	FZN_SYNC_QUEUE_ASKS,       /* asks still out at a round's end */
	FZN_SYNC_QUEUE_ROUND_MS,   /* how long the round took */
	FZN_SYNC_QUEUES
} fzn_sync_queue_t;

typedef enum fzn_sync_verdict {
	FZN_SYNC_LOAD_OK = 0,
	FZN_SYNC_LOAD_BUSY = 1,
	FZN_SYNC_LOAD_GROWING = 2
} fzn_sync_verdict_t;

typedef struct fzn_sync_load {
	uint64_t samples[FZN_SYNC_QUEUES][FZN_SYNC_LOAD_SAMPLES];
	uint32_t load[FZN_SYNC_LOAD_SAMPLES]; /* per cent, each round */
	size_t n, at;                         /* samples held; where the next goes */
} fzn_sync_load_t;

typedef struct fzn_sync_stat {
	uint64_t now, peak, mean;
	int growing;
} fzn_sync_stat_t;

/* The queue's name as `get sync-load` says it. */
const char *fzn_sync_queue_name(fzn_sync_queue_t q);
const char *fzn_sync_verdict_name(fzn_sync_verdict_t v);

/* A ROUND'S END: each queue's length `values[FZN_SYNC_QUEUES]`, and the
 * round's period in ms (0 for none, its load then 0). */
void fzn_sync_load_sample(fzn_sync_load_t *s, const uint64_t values[FZN_SYNC_QUEUES],
                          uint64_t period_ms);

/* Queue `q` over the window. All 0 before a sample. */
fzn_sync_stat_t fzn_sync_load_stat(const fzn_sync_load_t *s, fzn_sync_queue_t q);

/* The last round's load, per cent. */
uint32_t fzn_sync_load_now(const fzn_sync_load_t *s);

/* The verdict; `*why` (may be NULL) the queue growing, or ROUND_MS when
 * busy. */
fzn_sync_verdict_t fzn_sync_load_verdict(const fzn_sync_load_t *s, fzn_sync_queue_t *why);

/* `get sync-load`: `ok LOAD VERDICT NAME,NOW,PEAK,MEAN,TREND ...\n`, TREND
 * `growing` or `steady`, into `out`; its length, 0 if it did not fit. */
size_t fzn_sync_load_say(const fzn_sync_load_t *s, char *out, size_t cap);

#endif
