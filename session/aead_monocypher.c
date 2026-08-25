/* XChaCha20-Poly1305, from Monocypher. See session/aead.h for the seam.
 *
 * 24-byte nonce, which is why XChaCha rather than ChaCha: sec 13 has a frame
 * that must be self-contained, so it cannot negotiate a counter per session,
 * and 24 bytes is what makes a random nonce safe without one.
 *
 * Monocypher's `crypto_aead_unlock` verifies before it writes, which is the
 * property session/aead.h requires rather than merely prefers. It is not
 * re-checked here because it cannot be: the only way to observe it is to
 * corrupt a tag and look at the output buffer, which is what
 * session/test/aead_monocypher_test.c does.
 */

#include "aead.h"

#include "monocypher.h"

static void mono_seal(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
                      const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad,
                      size_t aad_len, uint8_t *text, size_t text_len,
                      uint8_t tag[FZN_AEAD_TAG_LEN])
{
	(void)ctx;
	crypto_aead_lock(text, tag, key, nonce, aad, aad_len, text, text_len);
}

static int mono_open(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
                     const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad,
                     size_t aad_len, uint8_t *text, size_t text_len,
                     const uint8_t tag[FZN_AEAD_TAG_LEN])
{
	(void)ctx;
	return crypto_aead_unlock(text, tag, key, nonce, aad, aad_len, text, text_len) == 0;
}

void fzn_aead_monocypher_init(fzn_aead_ops_t *ops)
{
	if (!ops)
		return;

	ops->seal = mono_seal;
	ops->open = mono_open;
	ops->ctx = NULL;
}
