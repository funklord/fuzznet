/* Declared beside the binding, as session/aead_monocypher.h is. */
#ifndef FZN_AGREE_MONOCYPHER_H
#define FZN_AGREE_MONOCYPHER_H

#include "agree.h"

/* Point `ops` at X25519. No state, so `ctx` is null. */
void fzn_agree_monocypher_init(fzn_agree_ops_t *ops);

#endif /* FZN_AGREE_MONOCYPHER_H */
