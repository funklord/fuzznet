/* The Monocypher binding for commitment.h's hash seam.
 *
 * project.md sec 4.5 vendors Monocypher once and binds it as an extern
 * rather than wrapping it, which is the same boundary chain/sign_monocypher
 * draws for signatures. BLAKE2b is the right primitive for this and not an
 * arbitrary choice: it takes an OUTPUT LENGTH as a parameter, which is what
 * makes "derive 48 bytes and split them" one call rather than a
 * construction. It is also what fuzzypickles' equivalent uses, so the two
 * agree without having to be reconciled.
 *
 * Optional to build, like the signer, because Monocypher is not vendored
 * here yet -- sec 7 says a submodule and sec 10 has not reached that step.
 * Set MONOCYPHER_DIR to build it; without it the key schedule still builds
 * and its whole suite still runs against the stub, which is the property
 * the vtable exists to give.
 */

#ifndef FZN_HASH_MONOCYPHER_H
#define FZN_HASH_MONOCYPHER_H

#include "commitment.h"

/* Point `ops` at BLAKE2b. Stateless -- there is no context to outlive
 * anything, so unlike the signer this takes no state parameter and holds no
 * key. The key material passes through as transcript bytes and is wiped by
 * the caller in commitment.c. */
void fzn_hash_monocypher_init(fzn_hash_ops_t *ops);

#endif /* FZN_HASH_MONOCYPHER_H */
