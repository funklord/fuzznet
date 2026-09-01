/* Declared beside the binding, as local/peer.h declares peer_linux.c's. */
#ifndef FZN_RANDOM_SYSTEM_H
#define FZN_RANDOM_SYSTEM_H

#include "random.h"

/* Point `ops` at the system entropy source. On a platform without one, `fill`
 * is left null and every nonce request fails -- deliberately.
 *
 * NOT FOR A CONSUMER WHOSE PLATFORM LAYER OWNS I/O, and the name does not say
 * so. This calls `getrandom(2)`. Linking it puts a syscall inside whatever
 * library links it, which is exactly what a consumer that keeps I/O in its
 * hosts and feeds its core bytes must not have -- and it would COMPILE, pass
 * every test on a Linux developer machine, and fail on the target where the
 * host supplies the source.
 *
 * Reported by fuzzypickles 2026-09-01, who reached for it by name and caught
 * it with `nm` rather than with a test. `fzn_random_ops_t` carries a `ctx`
 * precisely so a consumer can bridge its own source in a few lines; do that
 * instead, and use this only where the library IS the platform layer -- this
 * tree's own tests and a consumer with no host boundary.
 *
 * WHEN BRIDGING, CONVERT THE RETURN VALUE EXPLICITLY. `fill` returns 1 only
 * when every byte came from the source, which is the opposite of the
 * 0-means-success convention much of C uses and which a consumer's own
 * entropy callback may well follow. Forwarding a foreign value unchanged
 * reports success as failure on the good path and, worse, a nonzero failure
 * as truth. `random.h` states the convention; this says where it bites. */
void fzn_random_system_init(fzn_random_ops_t *ops);

#endif /* FZN_RANDOM_SYSTEM_H */
