/* Where a nonce comes from -- the assumption this library had been making of
 * its callers without saying so.
 *
 * `frame/freshness.h` and `session/aead_monocypher.c` both explain that 24
 * bytes is what makes a RANDOM nonce safe without a counter negotiated per
 * session, which is the reason sec 13 can have a self-contained frame at all.
 * Neither of them, nor anything else here, produced one. The design rested on
 * every consumer getting randomness right on their own, and never asked them
 * to.
 *
 * WHY THAT IS NOT A SMALL GAP. Reusing a nonce under one key with
 * XChaCha20-Poly1305 does not degrade the seal, it removes it: two frames
 * under the same key and nonce leak the XOR of their plaintexts, and the
 * Poly1305 key with them, which is forgery for everything that follows. It is
 * the one caller mistake this library cannot detect at the receiver -- the
 * replay window catches a repeated frame, not a repeated nonce on different
 * frames.
 *
 * A SEAM, like the signer and the hash, for the same reason: a consumer that
 * has already vendored an entropy source should use it, and one that has not
 * gets `session/random_linux.c`. What the seam adds over calling `getrandom`
 * directly is the rule below, which is where this goes wrong in practice.
 *
 * ALL OR NOTHING, AND NEVER A FALLBACK. `fill` returns success only if every
 * byte asked for was written from the source. A short read is a failure, not
 * a smaller nonce; a failed source is a refusal, not a reason to reach for
 * something weaker. Software that quietly degrades to a predictable nonce is
 * worse than software that stops, because it keeps working and nobody looks
 * at it again.
 */

#ifndef FZN_RANDOM_H
#define FZN_RANDOM_H

#include <stddef.h>
#include <stdint.h>

#include "aead.h" /* FZN_AEAD_NONCE_LEN */

/* Fill `len` bytes. Returns 1 only when all of them came from the source, and
 * 0 otherwise -- in which case `out` must be treated as unusable, whatever it
 * happens to contain. */
typedef struct fzn_random_ops {
	int (*fill)(void *ctx, uint8_t *out, size_t len);
	void *ctx;
} fzn_random_ops_t;

/* A nonce for one frame. Thin over `fill`, and worth existing because it is
 * where the length is stated once instead of at every call site: a nonce
 * short by a byte is a nonce with a predictable byte, and the mistake is
 * invisible at the point it is made. */
int fzn_nonce_next(const fzn_random_ops_t *rng, uint8_t out[FZN_AEAD_NONCE_LEN]);

#endif /* FZN_RANDOM_H */
