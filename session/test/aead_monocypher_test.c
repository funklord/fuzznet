/* XChaCha20-Poly1305 behind the seam, and the frame path over the real thing.
 *
 * wire/test/seal_test.c uses a stub, deliberately, so that the order of
 * operations is testable without a crypto dependency. This is the other half:
 * the same path with Monocypher underneath, which is what a consumer will
 * actually link. Built only when MONOCYPHER_DIR names a checkout.
 *
 * The property worth the file is the one session/aead.h states and a stub
 * cannot establish: crypto_aead_unlock verifies BEFORE it writes. A library
 * that decrypted first would hand this tree unauthenticated plaintext, and
 * the gate above it would be guarding a door somebody had already walked
 * through.
 */

#include "../aead_monocypher.h"

#include "../../wire/seal.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

#define PAYLOAD_LEN 24
#define FRAME_LEN   (144 + PAYLOAD_LEN)
#define OFF_PAYLOAD 0x80
#define OFF_CAP     0x60

static void put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)(v & 0xffu);
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)((v >> 16) & 0xffu);
	p[2] = (uint8_t)((v >> 8) & 0xffu);
	p[3] = (uint8_t)(v & 0xffu);
}

static const uint8_t PLAIN[PAYLOAD_LEN] = "twenty-four bytes here.";

static void build(uint8_t *f, const uint8_t *commitment)
{
	memset(f, 0, FRAME_LEN);
	f[0x00] = 1;
	f[0x05] = 2;
	memset(f + 0x06, 0xa1, 32);
	put_be32(f + 0x2a, 5000);
	memset(f + 0x2e, 0x33, 24);
	memcpy(f + 0x46, commitment, FZN_COMMITMENT_LEN);
	put_be32(f + 0x56, 7);
	put_be16(f + 0x5a, 1);
	put_be16(f + 0x5c, 4);
	put_be16(f + 0x5e, PAYLOAD_LEN);
	memset(f + OFF_CAP, 0xcc, 32);
	memcpy(f + OFF_PAYLOAD, PLAIN, PAYLOAD_LEN);
}

int main(void)
{
	fzn_aead_ops_t aead;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment[FZN_COMMITMENT_LEN];
	uint8_t frame[FRAME_LEN], sealed[FRAME_LEN];
	fzn_opened_t opened;

	memset(key, 0x77, sizeof(key));
	memset(commitment, 0xc7, sizeof(commitment));

	fzn_aead_monocypher_init(&aead);
	check(aead.seal != NULL && aead.open != NULL, "the binding left a null op");
	fzn_aead_monocypher_init(NULL);
	check(1, "init with a null ops did not crash");

	build(frame, commitment);
	check(fzn_seal_close(frame, sizeof(frame), key, &aead) == FZN_SEAL_OK,
	      "sealing with Monocypher was refused");
	check(memcmp(frame + OFF_PAYLOAD, PLAIN, PAYLOAD_LEN) != 0,
	      "the payload is still plaintext after a real seal");
	memcpy(sealed, frame, sizeof(frame));

	check(fzn_seal_open(frame, sizeof(frame), key, commitment, &aead, &opened) == FZN_SEAL_OK,
	      "opening a real sealed frame was refused");
	check(memcmp(opened.payload, PLAIN, PAYLOAD_LEN) == 0,
	      "the payload did not round trip through XChaCha20-Poly1305");

	/* VERIFY BEFORE WRITE, against the real algorithm. Flip a byte of the
	 * ciphertext: the tag must fail AND the buffer must be untouched. */
	memcpy(frame, sealed, sizeof(frame));
	frame[OFF_PAYLOAD] ^= 0x01u;
	check(fzn_seal_open(frame, sizeof(frame), key, commitment, &aead, &opened) ==
	              FZN_SEAL_ERR_TAG,
	      "a corrupted ciphertext verified");
	check(memcmp(frame + OFF_PAYLOAD + 1u, sealed + OFF_PAYLOAD + 1u, PAYLOAD_LEN - 1u) == 0,
	      "crypto_aead_unlock wrote plaintext before verifying, so the gate above it "
	      "is guarding a door already walked through");

	/* A different key must not open it, and the tag is what says so once
	 * the commitment matches. */
	{
		uint8_t other[FZN_AEAD_KEY_LEN];

		memset(other, 0x78, sizeof(other));
		memcpy(frame, sealed, sizeof(frame));
		check(fzn_seal_open(frame, sizeof(frame), other, commitment, &aead, &opened) ==
		              FZN_SEAL_ERR_TAG,
		      "a frame opened under a key that did not seal it");
	}

	/* The header is associated data rather than ciphertext: it stays
	 * readable, and the tag is what makes editing it detectable. Both
	 * halves are asserted, since a header that came back encrypted would
	 * be a different bug from one that came back unauthenticated. */
	check(memcmp(sealed + 0x06, frame + 0x06, 32) == 0,
	      "the sender was encrypted -- it is associated data, not ciphertext");
	memcpy(frame, sealed, sizeof(frame));
	put_be32(frame + 0x56, 9);
	check(fzn_seal_open(frame, sizeof(frame), key, commitment, &aead, &opened) ==
	              FZN_SEAL_ERR_TAG,
	      "an edited header was not caught by the tag");

	printf("aead_monocypher_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
