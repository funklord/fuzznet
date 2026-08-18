/* The open/seal path -- sec 10 step 2, which this file is the evidence for.
 *
 * A STUB AEAD, not Monocypher, and deliberately. chain_test.c does the same
 * with its signer: what is under test here is the ORDER of operations and the
 * gate discipline, not the cryptography, and a stub makes every case
 * reproducible from this source alone. `session/tests/aead_monocypher_test.c`
 * exercises the real algorithm, and only when MONOCYPHER_DIR names a checkout.
 *
 * The stub models the one property session/aead.h requires of a real
 * implementation: it verifies before it writes. An implementation that
 * decrypted first and checked afterwards would hand this library
 * unauthenticated plaintext, so a stub that did the same would test a
 * discipline the real seam does not have.
 */

#include "../seal.h"

#include "../../session/random.h"

#include "frame.h"

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

/* A transform with the shape of an AEAD and none of the strength: the text is
 * XORed with a byte derived from the key, and the tag is a checksum over the
 * key, nonce, associated data and ciphertext. Enough to be wrong when any of
 * those change, which is what the cases below ask of it. */
static void stub_tag(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad,
                     size_t aad_len, const uint8_t *text, size_t text_len,
                     uint8_t out[FZN_AEAD_TAG_LEN])
{
	uint8_t acc[FZN_AEAD_TAG_LEN];

	memset(acc, 0, sizeof(acc));
	for (size_t i = 0; i < FZN_AEAD_KEY_LEN; i++)
		acc[i % FZN_AEAD_TAG_LEN] = (uint8_t)(acc[i % FZN_AEAD_TAG_LEN] ^ key[i]);
	for (size_t i = 0; i < FZN_AEAD_NONCE_LEN; i++)
		acc[i % FZN_AEAD_TAG_LEN] = (uint8_t)(acc[i % FZN_AEAD_TAG_LEN] + nonce[i]);
	for (size_t i = 0; i < aad_len; i++)
		acc[i % FZN_AEAD_TAG_LEN] = (uint8_t)(acc[i % FZN_AEAD_TAG_LEN] * 31u + aad[i]);
	for (size_t i = 0; i < text_len; i++)
		acc[i % FZN_AEAD_TAG_LEN] = (uint8_t)(acc[i % FZN_AEAD_TAG_LEN] * 17u + text[i]);
	memcpy(out, acc, FZN_AEAD_TAG_LEN);
}

static void stub_seal(void *ctx, const uint8_t *key, const uint8_t *nonce, const uint8_t *aad,
                      size_t aad_len, uint8_t *text, size_t text_len, uint8_t *tag)
{
	(void)ctx;
	for (size_t i = 0; i < text_len; i++)
		text[i] = (uint8_t)(text[i] ^ key[i % FZN_AEAD_KEY_LEN]);
	stub_tag(key, nonce, aad, aad_len, text, text_len, tag);
}

static int stub_open(void *ctx, const uint8_t *key, const uint8_t *nonce, const uint8_t *aad,
                     size_t aad_len, uint8_t *text, size_t text_len, const uint8_t *tag)
{
	uint8_t want[FZN_AEAD_TAG_LEN];

	(void)ctx;
	stub_tag(key, nonce, aad, aad_len, text, text_len, want);
	/* VERIFY BEFORE WRITING, which is the contract. */
	if (memcmp(want, tag, FZN_AEAD_TAG_LEN) != 0)
		return 0;
	for (size_t i = 0; i < text_len; i++)
		text[i] = (uint8_t)(text[i] ^ key[i % FZN_AEAD_KEY_LEN]);
	return 1;
}

/* Entropy stubs for the send path: one that counts so nonces are known and
 * distinct, one that refuses so the no-nonce path is reachable. */
static int counting_fill(void *ctx, uint8_t *out, size_t len)
{
	unsigned *n = (unsigned *)ctx;

	for (size_t i = 0; i < len; i++)
		out[i] = (uint8_t)(*n * 7u + i);
	(*n)++;
	return 1;
}

static int refusing_fill(void *ctx, uint8_t *out, size_t len)
{
	(void)ctx;
	(void)out;
	(void)len;
	return 0;
}

/* Offsets from wire/frame.situ.map, as in generated_test.c and for the same
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
#define FRAME_MIN   144

#define PAYLOAD_LEN 24
#define FRAME_LEN   (FRAME_MIN + PAYLOAD_LEN)

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
static const uint8_t CAP[32] = "a capability identifier, 32 by.";

/* A frame with its header filled and its sealed region still plaintext. */
static void build(uint8_t *f, const uint8_t *commitment)
{
	memset(f, 0, FRAME_LEN);
	f[OFF_VERSION] = 1;
	f[OFF_KIND] = 2; /* chunk */
	memset(f + OFF_SENDER, 0xa1, 32);
	put_be32(f + OFF_EXPIRES + 4, 5000); /* u64, big-endian low word */
	memset(f + OFF_NONCE, 0x33, 24);
	memcpy(f + OFF_COMMIT, commitment, FZN_COMMITMENT_LEN);
	put_be32(f + OFF_MSG, 7);
	put_be16(f + OFF_INDEX, 1);
	put_be16(f + OFF_CHUNKS, 4);
	put_be16(f + OFF_LENGTH, PAYLOAD_LEN);
	memcpy(f + OFF_CAP, CAP, 32);
	memcpy(f + OFF_PAYLOAD, PLAIN, PAYLOAD_LEN);
}

int main(void)
{
	fzn_aead_ops_t aead = { stub_seal, stub_open, NULL };
	uint8_t key[FZN_AEAD_KEY_LEN], commitment[FZN_COMMITMENT_LEN];
	uint8_t frame[FRAME_LEN], sealed[FRAME_LEN];
	fzn_opened_t opened;

	memset(key, 0x77, sizeof(key));
	memset(commitment, 0xc7, sizeof(commitment));

	/* THE ROUND TRIP. */
	build(frame, commitment);
	check(fzn_seal_close(frame, sizeof(frame), key, &aead) == FZN_SEAL_OK,
	      "sealing a well-formed frame was refused");
	check(memcmp(frame + OFF_PAYLOAD, PLAIN, PAYLOAD_LEN) != 0,
	      "the payload is still plaintext after sealing");
	check(memcmp(frame + OFF_CAP, CAP, 32) != 0,
	      "the capability is still plaintext after sealing -- it is inside the seal");
	memcpy(sealed, frame, sizeof(frame));

	check(fzn_seal_open(frame, sizeof(frame), key, commitment, &aead, &opened) == FZN_SEAL_OK,
	      "opening the frame we just sealed was refused");
	check(opened.payload_len == PAYLOAD_LEN, "payload length came back wrong");
	check(memcmp(opened.payload, PLAIN, PAYLOAD_LEN) == 0, "the payload did not round trip");
	check(memcmp(opened.capability, CAP, 32) == 0, "the capability did not round trip");
	check(opened.msg == 7 && opened.index == 1 && opened.chunks == 4,
	      "the decoded header fields came back wrong");
	check(opened.kind == 2, "kind came back wrong");
	check(opened.expires_at == 5000, "expires_at came back wrong");
	check(opened.sender[0] == 0xa1 && opened.nonce[0] == 0x33,
	      "sender or nonce point at the wrong place");

	/* A TAG THAT DOES NOT VERIFY, and the property that matters: the
	 * plaintext must not have been written. A real AEAD that decrypted
	 * first and checked afterwards would pass the error check below and
	 * fail this one. */
	memcpy(frame, sealed, sizeof(frame));
	frame[FRAME_LEN - 1] ^= 0x01u;
	check(fzn_seal_open(frame, sizeof(frame), key, commitment, &aead, &opened) ==
	              FZN_SEAL_ERR_TAG,
	      "a frame with a corrupted tag was opened");
	check(memcmp(frame + OFF_PAYLOAD, sealed + OFF_PAYLOAD, PAYLOAD_LEN) == 0,
	      "a refused frame was decrypted in place anyway");
	check(opened.payload == NULL && opened.payload_len == 0,
	      "a refused open left pointers in the caller's struct");

	/* THE HEADER IS AUTHENTICATED. It is not encrypted, so it can be
	 * edited in flight; the tag is what makes that detectable. */
	memcpy(frame, sealed, sizeof(frame));
	put_be32(frame + OFF_MSG, 9);
	check(fzn_seal_open(frame, sizeof(frame), key, commitment, &aead, &opened) ==
	              FZN_SEAL_ERR_TAG,
	      "a frame whose header was edited in flight opened anyway");

	/* THE WRONG KEY IS ANSWERED BY THE COMMITMENT, before a decryption is
	 * spent, and with an error of its own. A receiver that has rotated its
	 * key needs to know that rather than to go hunting an attacker. */
	{
		uint8_t other_commitment[FZN_COMMITMENT_LEN];

		memset(other_commitment, 0x11, sizeof(other_commitment));
		memcpy(frame, sealed, sizeof(frame));
		check(fzn_seal_open(frame, sizeof(frame), key, other_commitment, &aead,
		                    &opened) == FZN_SEAL_ERR_COMMITMENT,
		      "a frame committing to a different key was not refused as such");
		check(memcmp(frame, sealed, sizeof(frame)) == 0,
		      "the frame was touched before the commitment was checked");
	}

	/* SHAPE, from the schema's own validator rather than restated here. */
	memcpy(frame, sealed, sizeof(frame));
	frame[OFF_VERSION] = 2;
	check(fzn_seal_open(frame, sizeof(frame), key, commitment, &aead, &opened) ==
	              FZN_SEAL_ERR_SHAPE,
	      "a frame with an unknown version reached the cryptography");
	memcpy(frame, sealed, sizeof(frame));
	put_be16(frame + OFF_CHUNKS, 0);
	check(fzn_seal_open(frame, sizeof(frame), key, commitment, &aead, &opened) ==
	              FZN_SEAL_ERR_SHAPE,
	      "a frame claiming zero chunks reached the cryptography");
	memcpy(frame, sealed, sizeof(frame));
	put_be16(frame + OFF_INDEX, 4);
	check(fzn_seal_open(frame, sizeof(frame), key, commitment, &aead, &opened) ==
	              FZN_SEAL_ERR_SHAPE,
	      "a frame whose index is past its own chunk count reached the cryptography");

	check(fzn_seal_open(frame, 4, key, commitment, &aead, &opened) == FZN_SEAL_ERR_SHAPE,
	      "a four-byte frame was accepted");

	/* Arguments. */
	check(fzn_seal_open(NULL, sizeof(frame), key, commitment, &aead, &opened) ==
	              FZN_SEAL_ERR_MALFORMED, "a null frame");
	check(fzn_seal_open(frame, sizeof(frame), NULL, commitment, &aead, &opened) ==
	              FZN_SEAL_ERR_MALFORMED, "a null key");
	check(fzn_seal_open(frame, sizeof(frame), key, NULL, &aead, &opened) ==
	              FZN_SEAL_ERR_MALFORMED, "a null commitment");
	check(fzn_seal_open(frame, sizeof(frame), key, commitment, NULL, &opened) ==
	              FZN_SEAL_ERR_MALFORMED, "a null aead");
	check(fzn_seal_open(frame, sizeof(frame), key, commitment, &aead, NULL) ==
	              FZN_SEAL_ERR_MALFORMED, "a null out");
	{
		fzn_aead_ops_t no_open = { stub_seal, NULL, NULL };
		fzn_aead_ops_t no_seal = { NULL, stub_open, NULL };

		check(fzn_seal_open(frame, sizeof(frame), key, commitment, &no_open, &opened) ==
		              FZN_SEAL_ERR_MALFORMED, "an aead that cannot open");
		check(fzn_seal_close(frame, sizeof(frame), key, &no_seal) == FZN_SEAL_ERR_MALFORMED,
		      "an aead that cannot seal");
	}
	/* A length that will not fit the u32 the layout addresses with. Refused
	 * before anything reads the buffer, which is why passing a size larger
	 * than the array is safe here and nowhere else in this file. */
	check(fzn_seal_open(frame, (size_t)UINT32_MAX + 1u, key, commitment, &aead, &opened) ==
	              FZN_SEAL_ERR_SHAPE,
	      "a frame length past UINT32_MAX was accepted");
	check(fzn_seal_close(frame, (size_t)UINT32_MAX + 1u, key, &aead) == FZN_SEAL_ERR_SHAPE,
	      "sealing a frame length past UINT32_MAX was accepted");

	check(fzn_seal_close(NULL, sizeof(frame), key, &aead) == FZN_SEAL_ERR_MALFORMED,
	      "sealing a null frame");
	check(fzn_seal_close(frame, sizeof(frame), key, NULL) == FZN_SEAL_ERR_MALFORMED,
	      "sealing with a null aead");
	check(fzn_seal_close(frame, sizeof(frame), NULL, &aead) == FZN_SEAL_ERR_MALFORMED,
	      "sealing with a null key");
	build(frame, commitment);
	frame[OFF_VERSION] = 3;
	check(fzn_seal_close(frame, sizeof(frame), key, &aead) == FZN_SEAL_ERR_SHAPE,
	      "sealing a frame the schema refuses");

	/* THE SEND PATH, whose order is the library's rather than a document's.
	 * A counting source stands in for entropy so the nonces are known and
	 * the assertions can be about the order rather than about randomness. */
	{
		unsigned counter = 0;
		fzn_random_ops_t rng = { counting_fill, &counter };
		fzn_random_ops_t no_rng = { refusing_fill, NULL };
		uint8_t built[FRAME_LEN], again[FRAME_LEN];
		size_t built_len = 0, again_len = 0;
		fzn_send_t what;

		memset(&what, 0, sizeof(what));
		what.sender = sealed + OFF_SENDER;
		what.capability = CAP;
		what.payload = PLAIN;
		what.payload_len = PAYLOAD_LEN;
		what.expires_at = 5000;
		what.msg = 7;
		what.index = 1;
		what.chunks = 4;
		what.kind = 2;

		check(fzn_seal_build(built, sizeof(built), &built_len, &what, key, commitment,
		                     &rng, &aead) == FZN_SEAL_OK,
		      "building a frame was refused");
		check(built_len == FRAME_LEN,
		      "a built frame is not the overhead plus the payload");

		/* It opens, which is the round trip the send path exists for. */
		check(fzn_seal_open(built, built_len, key, commitment, &aead, &opened) ==
		              FZN_SEAL_OK,
		      "a frame this library built could not be opened by it");
		check(memcmp(opened.payload, PLAIN, PAYLOAD_LEN) == 0,
		      "the payload did not survive build and open");
		check(memcmp(opened.capability, CAP, 32) == 0,
		      "the capability did not survive build and open");
		check(opened.msg == 7 && opened.index == 1 && opened.chunks == 4 &&
		              opened.kind == 2 && opened.expires_at == 5000,
		      "a header field did not survive build and open");

		/* A FRESH NONCE PER FRAME, which is the trap this call exists to
		 * close. Two frames built from identical arguments must differ,
		 * and must differ in the nonce specifically -- not merely in the
		 * ciphertext, which would also change if the nonce were reused
		 * but something else moved. */
		check(fzn_seal_build(again, sizeof(again), &again_len, &what, key, commitment,
		                     &rng, &aead) == FZN_SEAL_OK,
		      "building a second frame was refused");
		check(memcmp(built + OFF_NONCE, again + OFF_NONCE, FZN_AEAD_NONCE_LEN) != 0,
		      "two frames built from identical arguments carry the same nonce, which "
		      "is the one sender mistake a receiver cannot catch");
		check(memcmp(built, again, FRAME_LEN) != 0,
		      "two frames built from identical arguments are byte-identical");

		/* NO NONCE, NO FRAME. A source that cannot answer must leave the
		 * caller's buffer untouched rather than produce something
		 * sealed under a predictable one. */
		memset(again, 0xee, sizeof(again));
		check(fzn_seal_build(again, sizeof(again), &again_len, &what, key, commitment,
		                     &no_rng, &aead) == FZN_SEAL_ERR_NO_NONCE,
		      "a frame was built without a nonce");
		{
			int untouched = 1;

			for (size_t i = 0; i < sizeof(again); i++)
				untouched = untouched && again[i] == 0xee;
			check(untouched, "a refused build left a half-written frame in the buffer");
		}

		/* Capacity, which a sender gets wrong by forgetting the
		 * overhead rather than by miscounting the payload. */
		check(fzn_seal_build(built, FRAME_LEN - 1u, &built_len, &what, key, commitment,
		                     &rng, &aead) == FZN_SEAL_ERR_CAPACITY,
		      "a frame was built into a buffer one byte short");
		check(FZN_SEAL_OVERHEAD == 144u, "the advertised overhead is not the real one");

		/* A shape the schema refuses must be refused before the tag is
		 * spent, on the way out as well as on the way in. */
		what.chunks = 0;
		check(fzn_seal_build(built, sizeof(built), &built_len, &what, key, commitment,
		                     &rng, &aead) == FZN_SEAL_ERR_SHAPE,
		      "a frame claiming zero chunks was built and sealed");
		what.chunks = 4;
		what.index = 9;
		check(fzn_seal_build(built, sizeof(built), &built_len, &what, key, commitment,
		                     &rng, &aead) == FZN_SEAL_ERR_SHAPE,
		      "a frame whose index is past its chunk count was built and sealed");
		what.index = 1;

		/* Arguments. */
		check(fzn_seal_build(NULL, sizeof(built), &built_len, &what, key, commitment,
		                     &rng, &aead) == FZN_SEAL_ERR_MALFORMED, "a null frame");
		check(fzn_seal_build(built, sizeof(built), NULL, &what, key, commitment, &rng,
		                     &aead) == FZN_SEAL_ERR_MALFORMED, "a null length out");
		check(fzn_seal_build(built, sizeof(built), &built_len, NULL, key, commitment,
		                     &rng, &aead) == FZN_SEAL_ERR_MALFORMED, "a null send struct");
		check(fzn_seal_build(built, sizeof(built), &built_len, &what, key, commitment,
		                     NULL, &aead) == FZN_SEAL_ERR_MALFORMED, "a null rng");
		what.payload = NULL;
		check(fzn_seal_build(built, sizeof(built), &built_len, &what, key, commitment,
		                     &rng, &aead) == FZN_SEAL_ERR_MALFORMED,
		      "a null payload with a non-zero length");
	}

	printf("seal_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
