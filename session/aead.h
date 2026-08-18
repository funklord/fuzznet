/* The AEAD seam -- sec 4.5's one crypto dependency, behind a vtable.
 *
 * The same shape as `chain.h`'s signer and `commitment.h`'s hash, and for the
 * same reason: this library names the operation and a consumer supplies the
 * implementation, so nothing here forces Monocypher on a project that has
 * already vendored something else. `session/aead_monocypher.c` is the binding
 * this tree ships, built only when MONOCYPHER_DIR names a checkout.
 *
 * NOT situ's tier-1 codec ABI, and that is a finding rather than a
 * preference. `wire/frame.situ` declares `impl fzn_aead extern
 * "fzn_aead_xchacha20poly1305"`, and situ's tier-1 shape (its sec 13.2a) is
 *
 *     situ_err_t x_decode(const uint8_t *in, uint32_t in_len,
 *                         uint8_t *out, uint32_t out_cap, uint32_t *out_len);
 *
 * -- no key, no nonce, no associated data. An AEAD needs all three, and the
 * schema even states `sealed(fzn_aead, nonce = head.nonce)`, so the nonce is
 * something the compiler knows and does not pass. Threading a key through a
 * global to satisfy that signature would put mutable state in the one seam
 * where it must not be, so this seam takes them as arguments and the extern
 * symbol stays unbound. Reported to situ; see project.md sec 6.
 *
 * Nothing is lost by it, because the generated code never calls the codec:
 * situ's contribution to the sealed region is the LAYOUT and the GATE --
 * `situ_fzn_frame_tag_covered()` says what to authenticate and
 * `situ_fzn_frame_sealed_open()` refuses to hand out an interior view until
 * something says the tag verified. `wire/seal.c` is what joins the two.
 */

#ifndef FZN_AEAD_H
#define FZN_AEAD_H

#include <stddef.h>
#include <stdint.h>

#include "commitment.h" /* FZN_AEAD_KEY_LEN */

#define FZN_AEAD_NONCE_LEN 24
#define FZN_AEAD_TAG_LEN   16

/* Seal and open, in place over a caller's buffer.
 *
 * `aad` is authenticated and not encrypted; `text` is both. The tag is
 * written to, or read from, `tag` rather than appended -- the frame puts it
 * at a fixed offset that situ's layout chose, not immediately after the
 * ciphertext, and an implementation that appended would be writing outside
 * the region it was given.
 *
 * `open` returns 0 on a tag that does not verify, and must not write `text`
 * in that case. Monocypher's `crypto_aead_unlock` already has that property;
 * an implementation that decrypted first and checked afterwards would hand
 * this library unauthenticated plaintext, which is the single thing the gate
 * above it exists to prevent.
 */
typedef struct fzn_aead_ops {
	void (*seal)(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
	             const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad, size_t aad_len,
	             uint8_t *text, size_t text_len, uint8_t tag[FZN_AEAD_TAG_LEN]);
	int (*open)(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
	            const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad, size_t aad_len,
	            uint8_t *text, size_t text_len, const uint8_t tag[FZN_AEAD_TAG_LEN]);
	void *ctx;
} fzn_aead_ops_t;

#endif /* FZN_AEAD_H */
