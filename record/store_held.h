/*
 * THE RECORD STORE'S DELTA: `persist/delta.h` for the journal, project.md sec
 * 917. The journal is how a host's settings, grants, rules and revocations
 * travel, so it is the last thing that may stop for want of a disk.
 *
 * OVER ANY `fzn_record_store_ops_t`, with the same ops. A record the store
 * beneath will not take is kept here, reads see it first, and
 * `fzn_record_held_flush` writes it back, oldest first, once the store will.
 * Records are signed and never change, so this is a list, with no newest to
 * replace an older.
 *
 * WHAT GOES WHEN RAM RUNS SHORT: past `budget`, the oldest record of any stream
 * but the journal's own, FZN_RECORD_HELD_KEPT_STREAM. A record given up leaves a
 * hole a peer fills, as a record cut does. The journal's stream is never given
 * up here, and only the allocator refuses it.
 */
#ifndef FZN_RECORD_STORE_HELD_H
#define FZN_RECORD_STORE_HELD_H

#include <stddef.h>
#include <stdint.h>

#include "store.h"

#define FZN_RECORD_HELD_BUDGET_DEFAULT (32u * 1024u * 1024u)
#define FZN_RECORD_HELD_BUCKETS 1024u
/* `FZN_NODE_JOURNAL_STREAM`, where a host's acts go; record_held_test pins it. */
#define FZN_RECORD_HELD_KEPT_STREAM 1u

struct fzn_record_held_row;

typedef struct fzn_record_held {
	const fzn_record_store_ops_t *base;
	fzn_record_store_ops_t ops;
	size_t budget;
	void *(*alloc)(size_t len); /* NULL: malloc and free */
	void (*release)(void *at);
	struct fzn_record_held_row *buckets[FZN_RECORD_HELD_BUCKETS];
	struct fzn_record_held_row *oldest, *newest;
	size_t rows, bytes;
	unsigned long dropped, refused;
	int stuck;
} fzn_record_held_t;

/* A delta over `base`, `budget` bytes, 0 for the default. Its ops are `h->ops`,
 * and `h` must not move. */
void fzn_record_held_init(fzn_record_held_t *h, const fzn_record_store_ops_t *base, size_t budget);

/* WRITE WHAT IS HELD to the store beneath, oldest first, stopping at the first
 * it refuses. How many went. */
size_t fzn_record_held_flush(fzn_record_held_t *h);

void fzn_record_held_free(fzn_record_held_t *h);

#endif /* FZN_RECORD_STORE_HELD_H */
