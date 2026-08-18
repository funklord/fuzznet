/* Declared beside the binding, as chain/sign_monocypher.h is. */
#ifndef FZN_AEAD_MONOCYPHER_H
#define FZN_AEAD_MONOCYPHER_H

#include "aead.h"

/* Point `ops` at XChaCha20-Poly1305. No state: Monocypher is stateless here,
 * so `ctx` is null and nothing needs to outlive the call. */
void fzn_aead_monocypher_init(fzn_aead_ops_t *ops);

#endif /* FZN_AEAD_MONOCYPHER_H */
