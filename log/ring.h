/* The flight recorder: every entry a process makes, debug included, kept in
 * 256 KiB as performant records and written out when somebody needs it.
 * sec 457, sec 428's ring.
 *
 * WHERE THE NOISE GOES CHEAPLY. An entry is put here as a record -- fixed
 * fields, no formatting, no escaping (`log/entry.situ`) -- whatever level the
 * process's files keep, so the minutes before an error are there in full
 * when the error is. The oldest whole records are evicted to make room, and
 * counted.
 *
 * WRITTEN OUT ON AN ERROR, ON A CRASH, OR ON REQUEST (sec 428), and the crash
 * is what shapes the dump. A signal handler may call `write()` and little
 * else -- no formatting, no allocation, no lock -- so the dump is the ring's
 * own bytes: `fzn_ring_spans` gives at most two spans that, written in order,
 * are a sequence of length-prefixed records, oldest first. Nothing is
 * computed to produce it. `fzn_ring_load` reads such a dump back, and a
 * request that is not a crash can walk the records instead.
 *
 * A DUMP IS:
 *
 *     ( len u16 big-endian | record[len] ) ...      oldest first
 *
 * The holder set the size, 256 KiB a process (sec 428). It is one object a
 * process keeps for its life, so it is static rather than on a stack.
 */

#ifndef FZN_LOG_RING_H
#define FZN_LOG_RING_H

#include <stddef.h>
#include <stdint.h>

#include "entry.h"

#define FZN_RING_BYTES (256u * 1024u)

typedef enum fzn_ring_err {
	FZN_RING_OK = 0,
	FZN_RING_ERR_MALFORMED = -1 /* a null, an entry that is not one, a dump that is not one */
} fzn_ring_err_t;

const char *fzn_ring_err_str(fzn_ring_err_t err);

typedef struct fzn_ring {
	uint8_t bytes[FZN_RING_BYTES];
	size_t start; /* the oldest record's length prefix */
	size_t used;  /* bytes held, from `start` round */
	size_t held;  /* records held */
	uint64_t evicted;
} fzn_ring_t;

void fzn_ring_init(fzn_ring_t *ring);

/* Keep `entry`, evicting the oldest records until it fits. MALFORMED for
 * an entry the classic line would refuse; nothing is evicted then. */
fzn_ring_err_t fzn_ring_put(fzn_ring_t *ring, const fzn_entry_t *entry);

/* Each record, oldest first, unpacked; the entry is valid during the call.
 * How many were walked. */
typedef void (*fzn_ring_each_fn)(void *ctx, const fzn_entry_t *entry);
size_t fzn_ring_walk(const fzn_ring_t *ring, fzn_ring_each_fn each, void *ctx);

/* THE DUMP, for a crash handler: the held bytes as at most two spans, the
 * second empty unless the ring has wrapped. Computes nothing, takes no lock,
 * so a handler may call it and `write()` the spans. */
void fzn_ring_spans(const fzn_ring_t *ring, const uint8_t **first, size_t *first_len,
                    const uint8_t **second, size_t *second_len);

/* A dump read back into `ring`, which is reset first. Every record must
 * unpack, and the dump must end on a record's end. */
fzn_ring_err_t fzn_ring_load(fzn_ring_t *ring, const uint8_t *dump, size_t len);

#endif /* FZN_LOG_RING_H */
