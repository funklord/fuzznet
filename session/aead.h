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
 * symbol stays unbound FOR NOW rather than permanently: situ's scope is
 * eventually to cover protocol needs whole, layered and nested cryptographic
 * contexts included, and a project supplying its own routines with them. This
 * vtable is what that would bind to. Reported to situ; see project.md sec 6.
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
 *
 * `seal` RETURNS NONZERO ON SUCCESS AND 0 ON FAILURE, the same way round as
 * every other seam here. It returned `void` until 2026-09-04, and the change
 * is the copyright holder's decision recorded in project.md sec 85.
 *
 * WHY IT COULD NOT STAY VOID. Both callers copy the plaintext into the
 * caller's buffer and encrypt IN PLACE -- `text` is read and written, so this
 * seam is in place by signature -- which means a `seal` that did nothing left
 * the plaintext exactly where the ciphertext was going, and neither caller
 * could tell. `fzn_seal_build` finalised the tag and returned FZN_SEAL_OK;
 * `fzn_blob_leaf_seal` set `*out_len` and returned FZN_BLOB_OK. Probed with a
 * `seal` whose body was `(void)` casts and nothing else, the frame went out
 * with its payload and its capability in the clear.
 *
 * It was not a live defect: Monocypher's `crypto_aead_lock` returns void and
 * cannot fail, and it is what all three consumers use. The seam exists so
 * that they need not, and a token that is absent, a key handle that has
 * expired or a hardware engine returning an error are all things a
 * consumer's own backend does and the old signature could not express.
 *
 * WHAT A CALLER GETS ON A REFUSAL, and the two differ because ownership
 * differs. `fzn_seal_build` COPIED the plaintext in, so it owns the cleanup
 * and wipes the whole frame before returning FZN_SEAL_ERR_AEAD.
 * `fzn_seal_close` seals a buffer the CALLER already wrote, so it refuses
 * without wiping -- the plaintext there is the caller's own, in the caller's
 * buffer, and destroying it would be this library disposing of something it
 * never put there. A caller of `fzn_seal_close` that ignores the return
 * transmits its own plaintext, which is the one case this seam cannot fix
 * for anybody. `fzn_blob_leaf_seal` is `build`'s shape: it copies in, so it
 * wipes.
  */
typedef struct fzn_aead_ops {
	int (*seal)(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
	            const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad, size_t aad_len,
	            uint8_t *text, size_t text_len, uint8_t tag[FZN_AEAD_TAG_LEN]);
	int (*open)(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
	            const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad, size_t aad_len,
	            uint8_t *text, size_t text_len, const uint8_t tag[FZN_AEAD_TAG_LEN]);
	void *ctx;
} fzn_aead_ops_t;

#endif /* FZN_AEAD_H */
