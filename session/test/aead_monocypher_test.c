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
 *
 * A PUBLISHED VECTOR RUNS FIRST, AND IT IS A DIFFERENT KIND OF EVIDENCE FROM
 * EVERYTHING BELOW IT. Every other case in this file seals with this binding
 * and opens with the same binding, so a pair that is SELF-CONSISTENT AND
 * WRONG TOGETHER -- a block counter off by one, the two halves of the 24-byte
 * nonce swapped, an associated-data length absorbed in the wrong order --
 * round-trips perfectly and says nothing. Every assertion below would stay
 * green while the bytes on the wire were not XChaCha20-Poly1305 at all, and
 * the consumer who had vendored a real one would find that out in production.
 *
 * draft-irtf-cfrg-xchacha-03 appendix A.1 is the outside answer, and both
 * directions run through `fzn_aead_ops_t` rather than through Monocypher
 * directly, because the seam is what a consumer calls:
 *
 *   - SEAL: this binding over the draft's key, nonce, associated data and
 *     plaintext must reproduce the draft's ciphertext and tag byte for byte.
 *   - OPEN: this binding over the draft's key, nonce, associated data,
 *     CIPHERTEXT and TAG must return the draft's plaintext and accept.
 *
 * THE OPEN DIRECTION STAYS EVEN THOUGH THE SEAL DIRECTION LOOKS LIKE IT
 * COVERS THE SAME GROUND. It is the only case in the file that accepts bytes
 * this tree did not produce: a tag computed by somebody else, over a
 * ciphertext computed by somebody else. That is precisely what an
 * encrypt/decrypt pair which is wrong together cannot satisfy.
 *
 * AND THE VECTOR IS SHOWN TO DISCRIMINATE RATHER THAN ASSUMED TO, which is
 * what the perturbation case is for. A frozen array that nothing compares, or
 * compares wrongly, sits in a suite looking exactly like evidence. One byte
 * of the associated data is flipped and the unlock must refuse; the byte is
 * put back and it must accept again. The restore is not tidiness -- it is
 * what attributes the refusal to the flipped byte rather than to anything
 * else in the call.
 *
 * THE HASH IS THE REAL BINDING TOO, session/hash_monocypher.h, and that is
 * forced rather than chosen. `fzn_seal_open` derives a frame's commitment
 * from the commitment key and the frame's own nonce rather than taking a
 * finished one, so a stub hash here would leave this file running the real
 * AEAD behind a fake derivation -- which is the arrangement seal_test.c
 * already covers, and the one this file exists not to be.
 */

#include "../aead_monocypher.h"
#include "../hash_monocypher.h"

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

/* Offsets from wire/frame.situ.map, as in seal_test.c and for the same
 * reason: a test that asked the generated code where a field lives could not
 * catch the generated code being wrong about it. */
#define OFF_VERSION 0x00
#define OFF_KIND    0x05
#define OFF_SENDER  0x06
#define OFF_EXPIRES 0x26
#define OFF_NONCE   0x2e
#define OFF_COMMIT  0x46
#define OFF_MSG     0x56
#define OFF_INDEX   0x5a
#define OFF_CHUNKS  0x5c
#define OFF_LENGTH  0x5e
#define OFF_CAP     0x60
#define OFF_PAYLOAD 0x80

#define PAYLOAD_LEN 24
#define FRAME_LEN   (144 + PAYLOAD_LEN)

/* The two seams, at file scope because `build` below derives a commitment and
 * so needs the hash and the key it is derived from. */
static fzn_hash_ops_t hash;
static uint8_t commitment_key[FZN_COMMITMENT_KEY_LEN];

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

/* A frame with its header filled and its sealed region still plaintext.
 *
 * THE COMMITMENT IS DERIVED HERE, from the fixed nonce written the line
 * above, exactly as seal_test.c's builder does it. A hand-built frame
 * carrying any other 16 bytes is one `fzn_seal_open` refuses before it
 * reaches the tag, so every case below that is about the AEAD would then be
 * passing for the wrong reason -- and the AEAD is this file's whole
 * subject. */
static void build(uint8_t *f)
{
	memset(f, 0, FRAME_LEN);
	f[OFF_VERSION] = 1;
	f[OFF_KIND] = 2; /* chunk */
	memset(f + OFF_SENDER, 0xa1, 32);
	put_be32(f + OFF_EXPIRES + 4, 5000); /* u64, big-endian low word */
	memset(f + OFF_NONCE, 0x33, 24);
	fzn_commitment_for_nonce(&hash, commitment_key, f + OFF_NONCE, f + OFF_COMMIT);
	put_be32(f + OFF_MSG, 7);
	put_be16(f + OFF_INDEX, 1);
	put_be16(f + OFF_CHUNKS, 4);
	put_be16(f + OFF_LENGTH, PAYLOAD_LEN);
	memset(f + OFF_CAP, 0xcc, 32);
	memcpy(f + OFF_PAYLOAD, PLAIN, PAYLOAD_LEN);
}

/* draft-irtf-cfrg-xchacha-03, appendix A.1. Frozen, compared with memcmp, and
 * NEVER RECOMPUTED FROM ANYTHING IN THIS TREE -- a vector this build could
 * derive would be this build agreeing with itself, which is the exact failure
 * the header above says these arrays exist to close.
 *
 *   key        808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
 *   nonce      404142434445464748494a4b4c4d4e4f5051525354555657
 *   aad        50515253c0c1c2c3c4c5c6c7
 *   ciphertext bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
 *              731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
 *              2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
 *              21f9664c97637da9768812f615c68b13b52e
 *   tag        c0875924c1c7987947deafd8780acf49
 *
 * The plaintext is the draft's sentence, 114 ASCII bytes with NO TRAILING
 * NUL. The array is declared at exactly that length, so C drops the
 * terminator and a sentence of any other length stops the build rather than
 * zero-padding quietly into the comparison. */
#define VECTOR_TEXT_LEN 114
#define VECTOR_AAD_LEN  12

static const uint8_t VECTOR_KEY[FZN_AEAD_KEY_LEN] = {
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
};

static const uint8_t VECTOR_NONCE[FZN_AEAD_NONCE_LEN] = {
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
};

static const uint8_t VECTOR_AAD[VECTOR_AAD_LEN] = {
	0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
	0xc4, 0xc5, 0xc6, 0xc7,
};

static const uint8_t VECTOR_PLAIN[VECTOR_TEXT_LEN] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only "
        "one tip for the future, sunscreen would be it.";

static const uint8_t VECTOR_CIPHER[VECTOR_TEXT_LEN] = {
	0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b,
	0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9, 0x39,
	0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc,
	0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39, 0x6c, 0xbb,
	0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44,
	0x0b, 0xf3, 0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39,
	0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16,
	0xcb, 0x96, 0xb7, 0x2e, 0x12, 0x13, 0xb4, 0x52,
	0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45,
	0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e,
	0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f,
	0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9,
	0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9,
	0x76, 0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13,
	0xb5, 0x2e,
};

static const uint8_t VECTOR_TAG[FZN_AEAD_TAG_LEN] = {
	0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79,
	0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf, 0x49,
};

/* Both directions of the draft's vector, through the seam a consumer calls. */
static void vector(const fzn_aead_ops_t *aead)
{
	uint8_t text[VECTOR_TEXT_LEN];
	uint8_t aad[VECTOR_AAD_LEN];
	uint8_t tag[FZN_AEAD_TAG_LEN];

	memcpy(text, VECTOR_PLAIN, sizeof(text));
	memset(tag, 0, sizeof(tag));
	aead->seal(aead->ctx, VECTOR_KEY, VECTOR_NONCE, VECTOR_AAD, sizeof(VECTOR_AAD), text,
	           sizeof(text), tag);
	check(memcmp(text, VECTOR_CIPHER, sizeof(text)) == 0,
	      "sealing the draft's plaintext did not reproduce the draft's ciphertext");
	check(memcmp(tag, VECTOR_TAG, sizeof(tag)) == 0,
	      "sealing the draft's plaintext did not reproduce the draft's tag");

	/* THE DIRECTION A SELF-CONSISTENT PAIR CANNOT SURVIVE: bytes this tree
	 * never produced, under a tag this tree never computed. */
	memcpy(text, VECTOR_CIPHER, sizeof(text));
	check(aead->open(aead->ctx, VECTOR_KEY, VECTOR_NONCE, VECTOR_AAD, sizeof(VECTOR_AAD),
	                 text, sizeof(text), VECTOR_TAG) != 0,
	      "the draft's own ciphertext under the draft's own tag was refused");
	check(memcmp(text, VECTOR_PLAIN, sizeof(text)) == 0,
	      "the draft's ciphertext did not open to the draft's plaintext");

	/* THE VECTOR IS SHOWN TO DISCRIMINATE. Flip one byte of the associated
	 * data and the unlock must refuse. */
	memcpy(aad, VECTOR_AAD, sizeof(aad));
	aad[0] ^= 0x01u;
	memcpy(text, VECTOR_CIPHER, sizeof(text));
	check(aead->open(aead->ctx, VECTOR_KEY, VECTOR_NONCE, aad, sizeof(aad), text,
	                 sizeof(text), VECTOR_TAG) == 0,
	      "one flipped byte of associated data still verified");
	check(memcmp(text, VECTOR_CIPHER, sizeof(text)) == 0,
	      "a refused unlock wrote over the ciphertext it was given");

	/* Put it back, and require acceptance again -- which is what says the
	 * refusal above was the flipped byte's rather than something else in
	 * the call. */
	aad[0] ^= 0x01u;
	memcpy(text, VECTOR_CIPHER, sizeof(text));
	check(aead->open(aead->ctx, VECTOR_KEY, VECTOR_NONCE, aad, sizeof(aad), text,
	                 sizeof(text), VECTOR_TAG) != 0,
	      "the restored associated data did not verify, so the refusal above cannot be "
	      "attributed to the flipped byte");
}

int main(void)
{
	fzn_aead_ops_t aead;
	uint8_t key[FZN_AEAD_KEY_LEN];
	uint8_t frame[FRAME_LEN], sealed[FRAME_LEN];
	fzn_opened_t opened;

	memset(key, 0x77, sizeof(key));
	memset(commitment_key, 0x5b, sizeof(commitment_key));

	fzn_aead_monocypher_init(&aead);
	check(aead.seal != NULL && aead.open != NULL, "the binding left a null op");
	fzn_aead_monocypher_init(NULL);
	check(1, "init with a null ops did not crash");

	/* The real BLAKE2b rather than a stub -- see the header comment. */
	fzn_hash_monocypher_init(&hash);
	check(hash.hash != NULL, "the hash binding left a null op");

	vector(&aead);

	build(frame);
	check(fzn_seal_close(frame, sizeof(frame), key, &aead) == FZN_SEAL_OK,
	      "sealing with Monocypher was refused");
	check(memcmp(frame + OFF_PAYLOAD, PLAIN, PAYLOAD_LEN) != 0,
	      "the payload is still plaintext after a real seal");
	memcpy(sealed, frame, sizeof(frame));

	check(fzn_seal_open(frame, sizeof(frame), key, commitment_key, &hash, &aead, &opened) ==
	              FZN_SEAL_OK,
	      "opening a real sealed frame was refused");
	check(memcmp(opened.payload, PLAIN, PAYLOAD_LEN) == 0,
	      "the payload did not round trip through XChaCha20-Poly1305");

	/* VERIFY BEFORE WRITE, against the real algorithm. Flip a byte of the
	 * ciphertext: the tag must fail AND the buffer must be untouched. */
	memcpy(frame, sealed, sizeof(frame));
	frame[OFF_PAYLOAD] ^= 0x01u;
	check(fzn_seal_open(frame, sizeof(frame), key, commitment_key, &hash, &aead, &opened) ==
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
		check(fzn_seal_open(frame, sizeof(frame), other, commitment_key, &hash, &aead,
		                    &opened) == FZN_SEAL_ERR_TAG,
		      "a frame opened under a key that did not seal it");
	}

	/* And the commitment the real BLAKE2b derived is a function of the
	 * commitment key rather than a constant this file could have written by
	 * hand: another commitment key must be refused ABOVE the tag. Without
	 * this, a derivation that returned the same 16 bytes for everything
	 * would leave every case in the file green. */
	{
		uint8_t other_commitment_key[FZN_COMMITMENT_KEY_LEN];

		memset(other_commitment_key, 0x11, sizeof(other_commitment_key));
		memcpy(frame, sealed, sizeof(frame));
		check(fzn_seal_open(frame, sizeof(frame), key, other_commitment_key, &hash, &aead,
		                    &opened) == FZN_SEAL_ERR_COMMITMENT,
		      "a frame whose commitment this key does not derive was not refused");
	}

	/* The header is associated data rather than ciphertext: it stays
	 * readable, and the tag is what makes editing it detectable. Both
	 * halves are asserted, since a header that came back encrypted would
	 * be a different bug from one that came back unauthenticated. */
	check(memcmp(sealed + OFF_SENDER, frame + OFF_SENDER, 32) == 0,
	      "the sender was encrypted -- it is associated data, not ciphertext");
	memcpy(frame, sealed, sizeof(frame));
	put_be32(frame + OFF_MSG, 9);
	check(fzn_seal_open(frame, sizeof(frame), key, commitment_key, &hash, &aead, &opened) ==
	              FZN_SEAL_ERR_TAG,
	      "an edited header was not caught by the tag");

	printf("aead_monocypher_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
