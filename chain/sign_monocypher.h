/* The Monocypher binding for chain.h's signer seam.
 *
 * project.md sec 4.5 vendors Monocypher once here rather than three times,
 * and sec 6 binds it to situ as an EXTERN CODEC rather than wrapping it.
 * This is the same boundary for signatures: chain.c names the operation and
 * the implementation is supplied, so nothing in chain.c includes a crypto
 * header or knows what a key is.
 *
 * SEPARATE FILE, AND OPTIONAL TO BUILD, on purpose. Monocypher is not
 * vendored here yet -- sec 7 says a submodule, sec 10 has not reached that
 * step, and adding a dependency is not a thing to do in passing. Set
 * MONOCYPHER_DIR to build this; without it the rest of the library builds
 * and its tests run, which is the property the vtable exists to give.
 *
 * It is also where the secret key lives, and that placement is the point.
 * chain.h has no secret-key parameter anywhere, because sec 3 has fuzznet
 * linked by an unprivileged bridge that never runs in the process holding a
 * user's private keys. A signer that owns its key can be this file, or a
 * socket to another process, or hardware -- and chain.c cannot tell.
 */

#ifndef FZN_SIGN_MONOCYPHER_H
#define FZN_SIGN_MONOCYPHER_H

#include "chain.h"

/* Ed25519, which is what fuzzypickles already uses (crypto_eddsa_sign and
 * crypto_eddsa_check in its identity.c), so the two agree without having to
 * be reconciled -- the same argument sec 4.5 makes for Monocypher itself. */
#define FZN_SECRET_KEY_LEN 64

typedef struct fzn_sign_monocypher {
	/* Zeroed, and `can_sign` clear, for a verify-only signer -- which is
	 * what a receiving bridge wants: it checks chains all day and mints
	 * nothing, so it should never hold a key at all. */
	uint8_t secret_key[FZN_SECRET_KEY_LEN];
	int can_sign;
} fzn_sign_monocypher_t;

/* Point `ops` at this state. `state` must outlive `ops`, since ops holds it
 * as its context -- no allocation happens here or anywhere in this library. */
void fzn_sign_monocypher_init(fzn_sign_ops_t *ops, fzn_sign_monocypher_t *state);

/* Wipe the secret key. Calls Monocypher's own crypto_wipe rather than
 * memset, because a memset over a buffer that is never read again is
 * exactly what a compiler is entitled to delete -- and does, at -Os. */
void fzn_sign_monocypher_wipe(fzn_sign_monocypher_t *state);

#endif /* FZN_SIGN_MONOCYPHER_H */
