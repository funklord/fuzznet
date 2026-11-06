/*
 * ONE SLOT'S ROWS HELD IN RAM, over any `fzn_persist_ops_t`, project.md sec 926. A
 * slot of one file a row is walked by opening every file, and a contact is found by
 * name by walking them: 1600 opens an `add contact` at 800 contacts, so adding them
 * was quadratic in system calls (fuzzypickles' 20261106T1420Z).
 *
 * THE FIRST WALK OF THE SLOT READS EVERY ROW; from then on a load, a walk and a miss
 * touch no disk. A save or a remove goes to the store beneath first, and the row
 * here follows only what it took, so this never says what the store does not hold.
 * A row that will not read, or no memory for one, leaves the cache not whole, and
 * what it lacks is asked of the store as before. So it can be slower, and not wrong.
 *
 * THIS PROCESS IS THE STORE'S ONLY WRITER, which the claim makes so (`claim/`), and a
 * follower writes nothing. It goes beneath `persist/delta.h`: a row the disk refused
 * is the delta's, and a row the delta gives up was never here.
 */
#ifndef FZN_PERSIST_CACHE_H
#define FZN_PERSIST_CACHE_H

#include <stddef.h>
#include <stdint.h>

#include "persist.h"

#define FZN_PERSIST_CACHE_BUCKETS 16384u
/* A row past this is not held, and leaves the slot not whole. */
#define FZN_PERSIST_CACHE_ROW_MAX 4096u
/* What one slot may hold. Past it the rest is asked of the store. */
#define FZN_PERSIST_CACHE_BUDGET_DEFAULT (64u * 1024u * 1024u)

struct fzn_persist_cache_row;

typedef struct fzn_persist_cache {
	const fzn_persist_ops_t *base;
	fzn_persist_slot_t slot;
	void *(*alloc)(size_t len); /* NULL: malloc and free, so a test can refuse */
	void (*release)(void *at);
	struct fzn_persist_cache_row **buckets; /* made at the first walk */
	size_t rows, bytes, budget;
	int whole; /* every row of the slot is here, so a miss is an absence */
	unsigned rest; /* walks to leave to the store, after a fill that could not finish */
	unsigned long walks, misses;
	uint64_t changes; /* saves and removes of the slot, so a list can tell it is current */
} fzn_persist_cache_t;

/* A cache of `slot` over `base`, its ops into `ops`. `c` must outlive `ops`. */
void fzn_persist_cache_init(fzn_persist_cache_t *c, const fzn_persist_ops_t *base,
                            fzn_persist_slot_t slot, fzn_persist_ops_t *ops);

/* Everything held let go; the next walk reads the store again. */
void fzn_persist_cache_drop(fzn_persist_cache_t *c);

#endif /* FZN_PERSIST_CACHE_H */
