/*
 * THE BUFFERED DELTA: a store that goes on working when its disk will not,
 * project.md sec 917. The holder, 2026-11-06: fuzznet "must remain functional
 * even in the most extreme cases like disk full and memory reaching full".
 *
 * A LAYER OVER ANY `fzn_persist_ops_t`, with the same ops, so nothing above it
 * knows. A save or a remove goes to the store beneath; one it refuses is kept
 * here, in RAM, and from then on reads see this delta first and the store
 * after it. `fzn_persist_delta_flush` writes the delta back, oldest first, once
 * the store takes writes again.
 *
 * A DELTA OF ROWS, NOT A QUEUE OF COMMANDS. Commands would have to be run again
 * later, against a later state, and be judged again: a grant replayed after a
 * revocation it preceded. A row is a result, already judged, and the newest of
 * a key replaces the last, so a host saving one setting a thousand times holds
 * one row. What a flush writes is what the store would have held.
 *
 * WHAT GOES WHEN RAM RUNS SHORT: `fzn_persist_slot_rank`, lowest rank first and
 * oldest first within it. `budget` binds what can be shed. A row of rank
 * FZN_RANK_CONTROL or above goes in whatever the budget says, and is refused
 * only when the allocator refuses, because losing it costs a host its standing
 * and a row is small. A row given up is lost: reads fall back to the store's
 * older value, or to none, and `dropped` counts it.
 *
 * A STORE REFUSED ONCE IS LEFT ALONE until a flush finds it writable, so a full
 * disk costs one failed write a round rather than one each save. Rows are
 * flushed in the order they came, so a store that fills again partway holds a
 * prefix of them, as it would have.
 *
 * NOT DURABLE, and that is the bargain: a host stopped with rows here loses
 * them. `fzn_persist_delta_status` says how many, and a daemon says so.
 */
#ifndef FZN_PERSIST_DELTA_H
#define FZN_PERSIST_DELTA_H

#include <stddef.h>
#include <stdint.h>

#include "persist.h"

/* What a host may hold for a store that will not write, by default. */
#define FZN_PERSIST_DELTA_BUDGET_DEFAULT (32u * 1024u * 1024u)
#define FZN_PERSIST_DELTA_BUCKETS 4096u

struct fzn_persist_delta_row;

typedef struct fzn_persist_delta {
	const fzn_persist_ops_t *base;
	size_t budget;
	/* The allocator, so a test can make it refuse. NULL: malloc and free. */
	void *(*alloc)(size_t len);
	void (*release)(void *at);
	/* What is held, and the order it came in. */
	struct fzn_persist_delta_row *buckets[FZN_PERSIST_DELTA_BUCKETS];
	struct fzn_persist_delta_row *oldest, *newest;
	size_t rows, bytes;
	unsigned long dropped, refused, flushed;
	int stuck; /* the store beneath refused, and has not been asked since */
} fzn_persist_delta_t;

/* A delta over `base`, its ops into `ops`, `budget` bytes of what can be shed; 0
 * for the default. `d` must outlive `ops`. */
void fzn_persist_delta_init(fzn_persist_delta_t *d, const fzn_persist_ops_t *base, size_t budget,
                            fzn_persist_ops_t *ops);

/* WRITE WHAT IS HELD to the store beneath, oldest first, stopping at the first
 * it refuses. How many rows went; `fzn_persist_delta_status` says what is left. */
size_t fzn_persist_delta_flush(fzn_persist_delta_t *d);

/* The store beneath is believed not to take writes: every save stays here. */
void fzn_persist_delta_hold(fzn_persist_delta_t *d);

typedef struct fzn_persist_delta_status {
	int stuck;
	size_t rows, bytes, budget;
	unsigned long dropped, refused, flushed;
} fzn_persist_delta_status_t;

void fzn_persist_delta_status(const fzn_persist_delta_t *d, fzn_persist_delta_status_t *out);

/* Everything held let go, for a host stopping. */
void fzn_persist_delta_free(fzn_persist_delta_t *d);

#endif /* FZN_PERSIST_DELTA_H */
