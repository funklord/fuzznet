/* Declared beside the binding, as local/peer.h declares peer_linux.c's. */
#ifndef FZN_RANDOM_SYSTEM_H
#define FZN_RANDOM_SYSTEM_H

#include "random.h"

/* Point `ops` at the system entropy source. On a platform without one, `fill`
 * is left null and every nonce request fails -- deliberately. */
void fzn_random_system_init(fzn_random_ops_t *ops);

#endif /* FZN_RANDOM_SYSTEM_H */
