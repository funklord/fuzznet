/* The open/seal path -- sec 10 step 2, which this file is the evidence for.
 *
 * A STUB AEAD, not Monocypher, and deliberately. chain_test.c does the same
 * with its signer: what is under test here is the ORDER of operations and the
 * gate discipline, not the cryptography, and a stub makes every case
 * reproducible from this source alone. `session/test/aead_monocypher_test.c`
 * exercises the real algorithm, and only when MONOCYPHER_DIR names a checkout.
 *
 * The stub models the one property session/aead.h requires of a real
 * implementation: it verifies before it writes. An implementation that
 * decrypted first and checked afterwards would hand this library
 * unauthenticated plaintext, so a stub that did the same would test a
 * discipline the real seam does not have.
 */

#include "../seal.h"

#include "../relay.h"

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
 * those change, which is what the cases below ask of it.
 *
 * THE KEY IS FOLDED IN WITH A MULTIPLY, NOT AN XOR, AND THAT IS THE POINT.
 *
 * This loop used to read `acc[i % FZN_AEAD_TAG_LEN] ^= key[i]`, folding 32 key
 * bytes into 16 accumulator slots by XOR -- so slot n received key[n] and
 * key[n + 16] and nothing else, and any key whose two halves are equal
 * cancelled to zero. The suite's key is `memset(key, 0x77, 32)`, which is
 * exactly such a key. Measured before the fix: `tag(0x77 x 32)` and
 * `tag(0x78 x 32)` were byte-identical, and opening a frame sealed under
 * 0x77 with an all-0x99 key returned FZN_SEAL_OK and handed back a payload
 * decrypted under the wrong key.
 *
 * A stub AEAD that is blind to the key cannot fail for a wrong key, so the
 * seam's only real secret was untested. Multiplying the accumulator before
 * adding, and mixing the index in, makes each byte's contribution depend on
 * where it sits: two halves no longer cancel. It is still not a MAC and does
 * not need to be -- what had to go is the structural cancellation.
 *
 * `sim/test/network_test.c`'s `stub_tag` does not share the fault: it runs a
 * single order-dependent 32-bit accumulator over all 32 key bytes.
 */
static void stub_tag(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad,
                     size_t aad_len, const uint8_t *text, size_t text_len,
                     uint8_t out[FZN_AEAD_TAG_LEN])
{
	uint8_t acc[FZN_AEAD_TAG_LEN];

	memset(acc, 0, sizeof(acc));
	for (size_t i = 0; i < FZN_AEAD_KEY_LEN; i++)
		acc[i % FZN_AEAD_TAG_LEN] =
		        (uint8_t)(acc[i % FZN_AEAD_TAG_LEN] * 31u + key[i] + (uint8_t)i);
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

/* THE SAME AEAD, COUNTING ITS OPENS.
 *
 * `seal.h` claims FZN_SEAL_ERR_COMMITMENT is reached with the cryptography
 * never running, and the whole of finding 3 rests on that: a verdict produced
 * before the AEAD is a verdict produced from bytes an attacker may rewrite. A
 * counter is what turns the claim into something the suite can fail on --
 * checking only the error code would be satisfied by an implementation that
 * decrypted first and reported the mismatch afterwards, which is exactly the
 * shape that would make the error trustworthy and the advice wrong. */
static unsigned aead_opens;

static int counting_open(void *ctx, const uint8_t *key, const uint8_t *nonce,
                         const uint8_t *aad, size_t aad_len, uint8_t *text, size_t text_len,
                         const uint8_t *tag)
{
	aead_opens++;
	return stub_open(ctx, key, nonce, aad, aad_len, text, text_len, tag);
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

/* Whether `needle` appears anywhere in `hay`. Used to prove a refused build
 * left no plaintext behind, so it searches the whole buffer rather than the
 * offset the field would have occupied -- a wipe that moved the bytes instead
 * of clearing them would pass an offset check. */
static int find_bytes(const uint8_t *hay, size_t hay_len, const uint8_t *needle, size_t needle_len)
{
	if (needle_len == 0 || hay_len < needle_len)
		return 0;

	for (size_t i = 0; i + needle_len <= hay_len; i++) {
		if (memcmp(hay + i, needle, needle_len) == 0)
			return 1;
	}

	return 0;
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

	/* THE COMMITMENT VERDICT IS ONE AN ON-PATH ATTACKER CHOOSES, and this is
	 * the case that shows it rather than the one above.
	 *
	 * The block above passes a different commitment ARGUMENT, which is a
	 * receiver holding the wrong key. This flips a byte of the commitment
	 * IN THE FRAME, which is a stranger with no key at all: `commitment` is
	 * a plaintext header field and the check that reads it runs before the
	 * AEAD, so one flipped byte per datagram makes a healthy receiver
	 * report that its key does not match.
	 *
	 * The counter is the point. A consumer may only ever act on the RATE of
	 * these -- see `seal.h` -- and the reason is precisely that nothing
	 * cryptographic has run by the time the verdict exists. `aead_opens`
	 * asserts that, and the unflipped frame below is the positive control:
	 * a counter that stays at zero because nothing ever calls the AEAD
	 * would pass the first half and prove nothing. */
	{
		fzn_aead_ops_t counted = { stub_seal, counting_open, NULL };

		memcpy(frame, sealed, sizeof(frame));
		frame[OFF_COMMIT + 3] ^= 0x01u; /* frame offset 0x49 */
		aead_opens = 0;
		check(fzn_seal_open(frame, sizeof(frame), key, commitment, &counted, &opened) ==
		              FZN_SEAL_ERR_COMMITMENT,
		      "a flipped commitment byte did not produce the commitment verdict");
		check(aead_opens == 0,
		      "the commitment verdict cost a decryption, so it is not the pre-tag "
		      "verdict seal.h describes");

		memcpy(frame, sealed, sizeof(frame));
		aead_opens = 0;
		check(fzn_seal_open(frame, sizeof(frame), key, commitment, &counted, &opened) ==
		              FZN_SEAL_OK,
		      "the counting aead could not open an untouched frame");
		check(aead_opens == 1,
		      "the counting aead was never called, so the zero above was vacuous");
	}

	/* AND THE WRONG KEY WITH THE RIGHT COMMITMENT, which is the case the
	 * commitment cannot answer and the one that reaches the cryptography.
	 *
	 * The commitment check above refuses a frame that says it was sealed
	 * under some other key -- but it is a field in the frame, compared
	 * against a field the caller supplies, and neither is derived from the
	 * key material. An attacker replaying a frame verbatim to a receiver
	 * that has rotated its key presents the RIGHT commitment; so does a
	 * receiver that has muddled two sessions' keys. Nothing but the tag
	 * stands between that and a decryption.
	 *
	 * Until this case existed the suite had no wrong-key check at all: the
	 * FZN_SEAL_ERR_COMMITMENT case above passes a wrong COMMITMENT, which
	 * is refused before the AEAD is ever called. So the stub's key-blind
	 * tag went unnoticed, and would have gone on doing so.
	 *
	 * Both halves are asserted. The code alone would be satisfied by an
	 * implementation that decrypted first and reported the error
	 * afterwards, which is the one thing session/aead.h forbids. */
	{
		uint8_t other_key[FZN_AEAD_KEY_LEN];

		memset(other_key, 0x99, sizeof(other_key));
		memcpy(frame, sealed, sizeof(frame));
		memset(&opened, 0xee, sizeof(opened));
		check(fzn_seal_open(frame, sizeof(frame), other_key, commitment, &aead,
		                    &opened) == FZN_SEAL_ERR_TAG,
		      "a frame opened under a completely different key was not refused by "
		      "the tag");
		check(memcmp(frame, sealed, sizeof(frame)) == 0,
		      "a frame refused under the wrong key was decrypted in place anyway");
		check(find_bytes(frame, sizeof(frame), PLAIN, PAYLOAD_LEN) == 0,
		      "the payload turned up as plaintext after opening under the wrong key");
		check(opened.payload == NULL && opened.payload_len == 0,
		      "an open refused for the wrong key left pointers in the caller's "
		      "struct");
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
		/* The overhead is checked in wire/test/constants_test.c, against
		 * SITU_FZN_FRAME_SIZE_MIN rather than against the literal 144 that
		 * used to sit here and could not tell the two apart. */

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
		check(fzn_seal_build(built, sizeof(built), &built_len, &what, NULL, commitment,
		                     &rng, &aead) == FZN_SEAL_ERR_MALFORMED, "a null key");
		check(fzn_seal_build(built, sizeof(built), &built_len, &what, key, NULL,
		                     &rng, &aead) == FZN_SEAL_ERR_MALFORMED, "a null commitment");
		check(fzn_seal_build(built, sizeof(built), &built_len, &what, key, commitment,
		                     &rng, NULL) == FZN_SEAL_ERR_MALFORMED, "a null aead");

		/* THE TWO INSIDE THE SEND STRUCT, which the matrix above cannot
		 * reach by passing NULL for an argument. Both were unexercised
		 * until now -- branch coverage put `!what->sender` and
		 * `!what->capability` at zero -- so two terms of a nine-term guard
		 * had never once decided anything.
		 *
		 * They matter more than the plain arguments, not less. A null
		 * `key` or `aead` fails immediately at the first use; `sender` and
		 * `capability` are memcpy sources much further down, past the
		 * nonce draw and the memset, so without the guard the failure is a
		 * read from a null pointer in the middle of a half-built frame
		 * rather than a refusal before one exists. */
		what.sender = NULL;
		check(fzn_seal_build(built, sizeof(built), &built_len, &what, key, commitment,
		                     &rng, &aead) == FZN_SEAL_ERR_MALFORMED, "a null sender");
		what.sender = sealed + OFF_SENDER;

		what.capability = NULL;
		check(fzn_seal_build(built, sizeof(built), &built_len, &what, key, commitment,
		                     &rng, &aead) == FZN_SEAL_ERR_MALFORMED, "a null capability");
		what.capability = CAP;

		what.payload = NULL;
		check(fzn_seal_build(built, sizeof(built), &built_len, &what, key, commitment,
		                     &rng, &aead) == FZN_SEAL_ERR_MALFORMED,
		      "a null payload with a non-zero length");
		what.payload = PLAIN;

		/* A REFUSED BUILD MUST NOT LEAVE THE INTERIOR AS PLAINTEXT.
		 *
		 * Sealing happens in place, so the capability and payload are
		 * copied into the caller's buffer in the clear before the seal
		 * runs. Every shape refusal surfaces from `fzn_seal_close`,
		 * which is after that copy -- so a refused build used to return
		 * with the 32-byte capability sitting verbatim in the buffer and
		 * the tag all zeroes. A caller reusing the buffer, or ignoring
		 * the return, holds or transmits it.
		 *
		 * `index` past `chunks` is used as the trigger because it is a
		 * pure shape fault: the arguments are all valid pointers, so
		 * nothing is refused before the interior is written. */
		{
			uint16_t good_index = what.index;

			memset(built, 0xee, sizeof(built));
			what.index = 5;
			what.chunks = 2;
			check(fzn_seal_build(built, sizeof(built), &built_len, &what, key,
			                     commitment, &rng, &aead) != FZN_SEAL_OK,
			      "an index past chunks was accepted");
			check(find_bytes(built, sizeof(built), CAP, sizeof(CAP)) == 0,
			      "a refused build left the capability in the caller's buffer "
			      "as plaintext");
			check(find_bytes(built, sizeof(built), PLAIN, PAYLOAD_LEN) == 0,
			      "a refused build left the payload in the caller's buffer "
			      "as plaintext");
			what.index = good_index;
			what.chunks = 1;
		}

		/* AND THE FRAME TOO SHORT TO BE ONE, which is the other branch
		 * coverage found at zero: `situ_fzn_frame_view` refusing inside
		 * `views()`. Every other refusal in the open path happens to a
		 * frame that is at least frame-shaped, so nothing had ever handed
		 * it something smaller than the fixed part. */
		{
			uint8_t stub[FZN_SEAL_OVERHEAD - 1];
			fzn_opened_t opened;

			memset(stub, 0, sizeof(stub));
			stub[0] = 1;
			check(fzn_seal_open(stub, sizeof(stub), key, commitment, &aead,
			                    &opened) == FZN_SEAL_ERR_SHAPE,
			      "a frame shorter than the fixed part was not refused");
		}
	}

	/* THE PAYLOAD BOUND, AND WHAT A REFUSAL COSTS THE CALLER.
	 *
	 * `fzn_seal_build` used to bound the payload at UINT16_MAX, which only
	 * made its cast to `uint16_t` safe. Anything between that and the
	 * schema's 1024 was refused further down by
	 * `situ_fzn_frame_sealed_open` -- after the `memset` had written the
	 * whole frame's worth of zeroes into the caller's buffer. Measured at
	 * the time: a 2000-byte payload returned FZN_SEAL_ERR_SHAPE having
	 * modified 2144 bytes it was refusing to fill.
	 *
	 * Both halves are checked here because fixing either alone would look
	 * like success: the bound could be enforced late and still return the
	 * right code, and the buffer could be spared by a check that let the
	 * wrong sizes through. */
	{
		unsigned counter = 0;
		fzn_random_ops_t rng = { counting_fill, &counter };
		static uint8_t big[FZN_SEAL_OVERHEAD + 4096];
		static uint8_t payload[4096];
		size_t wrote = 0;
		fzn_send_t what;
		const size_t bound = SITU_FZN_FRAME_SIZE_MAX - SITU_FZN_FRAME_SIZE_MIN;
		size_t touched = 0;

		memset(payload, 0xC3, sizeof(payload));
		memset(&what, 0, sizeof(what));
		what.sender = sealed + OFF_SENDER;
		what.capability = CAP;
		what.payload = payload;
		what.chunks = 1;

		/* Exactly the bound must build; one past it must not. A test that
		 * only refused something far too large would pass with the bound
		 * set anywhere above it. */
		what.payload_len = bound;
		check(fzn_seal_build(big, sizeof(big), &wrote, &what, key, commitment, &rng,
		                     &aead) == FZN_SEAL_OK,
		      "the largest payload the schema allows was refused");

		what.payload_len = bound + 1u;
		memset(big, 0x5A, sizeof(big));
		check(fzn_seal_build(big, sizeof(big), &wrote, &what, key, commitment, &rng,
		                     &aead) == FZN_SEAL_ERR_SHAPE,
		      "a payload one byte past the schema's bound was accepted");

		for (size_t i = 0; i < sizeof(big); i++)
			if (big[i] != 0x5A)
				touched++;
		check(touched == 0, "a refused build wrote into the caller's buffer");
	}

	/* TRAILING UNAUTHENTICATED BYTES, WHICH USED TO OPEN.
	 *
	 * The tag covers `head` and the sealed region and stops at the tag, so
	 * bytes appended AFTER the tag are outside every span `fzn_seal_open`
	 * computes: the cryptography verifies happily around them and cannot be
	 * the thing that objects. Measured before the check existed: this exact
	 * 168-byte frame, handed in at every length from 169 to 168 + 4096,
	 * returned FZN_SEAL_OK with `payload_len` unchanged.
	 *
	 * `wire/frame.situ` says `require canonical(fzn_frame)`, which situc
	 * checks at codegen time and which never reached the C -- so the suite
	 * was green on a schema requirement the runtime did not keep. What it
	 * costs is not a decryption but an IDENTITY: anything keyed on the
	 * datagram rather than on the frame inside it -- a dedup cache, a
	 * forwarding relay, one capture compared against another -- sees a
	 * single frame wearing as many identities as an attacker cares to
	 * append, at no cost and with no key.
	 *
	 * THE UNPADDED FRAME IS CHECKED FIRST AND IN THE SAME BLOCK. "It was
	 * refused" is satisfied by an implementation that refuses everything,
	 * and the sweep below would then pass for the wrong reason. */
	{
		static uint8_t padded[FRAME_LEN + 4096];
		fzn_opened_t padded_opened;
		size_t accepted = 0;

		memcpy(padded, sealed, FRAME_LEN);
		check(fzn_seal_open(padded, FRAME_LEN, key, commitment, &aead, &padded_opened) ==
		              FZN_SEAL_OK,
		      "the unpadded frame stopped opening");
		check(padded_opened.payload_len == PAYLOAD_LEN &&
		              memcmp(padded_opened.payload, PLAIN, PAYLOAD_LEN) == 0,
		      "the unpadded frame no longer round trips");

		/* Every length, not a sample: a bound written one byte wrong would
		 * pass a check that compared against a single padded size. */
		for (size_t extra = 1; extra <= 4096; extra++) {
			memcpy(padded, sealed, FRAME_LEN);
			memset(padded + FRAME_LEN, 0x5A, extra);
			if (fzn_seal_open(padded, FRAME_LEN + extra, key, commitment, &aead,
			                  &padded_opened) != FZN_SEAL_ERR_SHAPE)
				accepted++;
		}
		check(accepted == 0,
		      "a frame with bytes appended after its tag was opened rather than "
		      "refused as a shape");

		/* AND THE SEND SIDE, which shares `views()` with the open side. A
		 * caller sealing over a padded buffer would otherwise produce a
		 * frame every receiver now refuses, and learn about it from
		 * somebody else's logs. */
		build(padded, commitment);
		memset(padded + FRAME_LEN, 0x5A, 8);
		check(fzn_seal_close(padded, FRAME_LEN + 8, key, &aead) == FZN_SEAL_ERR_SHAPE,
		      "sealing over a buffer longer than the frame it holds was accepted");
	}

	/* THE SEAL -> RELAY -> OPEN ROUND TRIP, WHICH COULD NOT BE WRITTEN
	 * UNTIL `fzn_send.hops` EXISTED.
	 *
	 * `fzn_seal_build` memset the frame and wrote only `version`, and
	 * `fzn_send_t` had no hop field, so every frame this library could
	 * build carried `hops_left = 0`: `fzn_relay_budget` answered 0 and
	 * `fzn_relay_spend` answered EXHAUSTED, always. Writing this round trip
	 * meant poking `frame[1]` by hand -- the raw-offset knowledge `seal.h`
	 * exists to spare a consumer -- so it was never written, and the
	 * property it proves went unasserted in a tree that depends on it.
	 *
	 * THE PROPERTY: the tag excludes `hop` and nothing but `hop`, so a
	 * relay may spend the whole budget in flight and the frame still opens
	 * with its interior byte-identical. That is what makes `relay.h`
	 * possible at all. A schema revision pulling `hop` inside the
	 * authenticated region would make `fzn_relay_spend` corrupt every frame
	 * it touched -- and before this block the whole suite would have stayed
	 * green while it did, because relaying and sealing were only ever
	 * tested apart. */
	{
		unsigned counter = 0;
		fzn_random_ops_t rng = { counting_fill, &counter };
		uint8_t hopped[FRAME_LEN];
		size_t hopped_len = 0;
		uint8_t budget = 0xee;
		fzn_send_t what;
		fzn_opened_t after;
		int spent_all = 1, walked_down = 1;

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

		/* ZERO FIRST, because it is what a `memset` leaves behind and so
		 * what every caller written before the field existed passes. It
		 * must mean "not offered for relaying" and must not mean "the
		 * default budget": the second reading would turn those callers
		 * into traffic sources without one of them changing a line. */
		what.hops = 0;
		check(fzn_seal_build(hopped, sizeof(hopped), &hopped_len, &what, key, commitment,
		                     &rng, &aead) == FZN_SEAL_OK,
		      "building a frame with no hop budget was refused");
		check(fzn_relay_budget(hopped, hopped_len, FZN_RELAY_MAX_HOPS, &budget) ==
		                      FZN_RELAY_OK &&
		              budget == 0,
		      "a frame built with hops = 0 offered a budget anyway");
		check(fzn_relay_spend(hopped, hopped_len, FZN_RELAY_MAX_HOPS) ==
		              FZN_RELAY_ERR_EXHAUSTED,
		      "a frame built with hops = 0 was forwardable");
		check(fzn_seal_open(hopped, hopped_len, key, commitment, &aead, &after) ==
		              FZN_SEAL_OK,
		      "a frame with no hop budget stopped opening -- zero costs reach, not "
		      "delivery");

		/* A BUDGET STATED THROUGH THE PUBLIC API AND READ BACK THROUGH IT.
		 * No `frame[1]` anywhere in this block, which is the half of the
		 * finding a raw-offset assertion could not have shown. */
		what.hops = FZN_RELAY_MAX_HOPS;
		check(fzn_seal_build(hopped, sizeof(hopped), &hopped_len, &what, key, commitment,
		                     &rng, &aead) == FZN_SEAL_OK,
		      "building a relayable frame was refused");
		check(fzn_relay_budget(hopped, hopped_len, FZN_RELAY_MAX_HOPS, &budget) ==
		                      FZN_RELAY_OK &&
		              budget == FZN_RELAY_MAX_HOPS,
		      "a budget the sender stated did not reach the frame");

		/* SPEND THE LOT, checking the budget after every hop rather than
		 * only at the end. A spend that RAISED the budget, or that
		 * underflowed past zero, would still leave a plausible-looking
		 * number at the end of a loop that only counted iterations. */
		for (unsigned i = FZN_RELAY_MAX_HOPS; i > 0; i--) {
			uint8_t left = 0xee;

			if (fzn_relay_spend(hopped, hopped_len, FZN_RELAY_MAX_HOPS) !=
			    FZN_RELAY_OK)
				spent_all = 0;
			if (fzn_relay_budget(hopped, hopped_len, FZN_RELAY_MAX_HOPS, &left) !=
			            FZN_RELAY_OK ||
			    left != (uint8_t)(i - 1u))
				walked_down = 0;
		}
		check(spent_all, "a hop was refused before the stated budget ran out");
		check(walked_down,
		      "a spend must leave exactly one less -- neither raising the budget nor "
		      "underflowing past zero");
		check(fzn_relay_spend(hopped, hopped_len, FZN_RELAY_MAX_HOPS) ==
		              FZN_RELAY_ERR_EXHAUSTED,
		      "a ninth hop was granted on an eight-hop budget");
		check(fzn_relay_budget(hopped, hopped_len, FZN_RELAY_MAX_HOPS, &budget) ==
		                      FZN_RELAY_OK &&
		              budget == 0,
		      "a refused spend underflowed the budget it refused");

		/* THE POSITIVE CONTROL, and the assertion this whole block exists
		 * for. After the entire budget has been spent in flight the frame
		 * must STILL open, and the interior must come back byte-identical
		 * -- otherwise "the relay did not break it" is satisfied by a
		 * build that never worked. */
		{
			fzn_seal_err_t reopened;

			memset(&after, 0xee, sizeof(after));
			reopened = fzn_seal_open(hopped, hopped_len, key, commitment, &aead,
			                         &after);
			check(reopened == FZN_SEAL_OK,
			      "a frame relayed its full budget no longer opens -- the tag "
			      "covers `hop`, which it must not");
			/* THE THREE BELOW ARE GUARDED ON THAT VERDICT, and the guard
			 * is not decoration. `fzn_seal_open` zeroes `out` before it
			 * refuses, so `after.payload` is NULL on any failure and a
			 * memcmp through it takes the process down -- after the line
			 * above has printed its FAIL but before the run can report a
			 * count. A test that crashes is a test that names its reason
			 * to nobody, which is the whole value of the message. */
			check(reopened == FZN_SEAL_OK && after.payload_len == PAYLOAD_LEN &&
			              memcmp(after.payload, PLAIN, PAYLOAD_LEN) == 0,
			      "the payload did not survive eight hops byte-identical");
			check(reopened == FZN_SEAL_OK &&
			              memcmp(after.capability, CAP, sizeof(CAP)) == 0,
			      "the capability did not survive eight hops byte-identical");
			check(reopened == FZN_SEAL_OK && after.msg == 7 && after.index == 1 &&
			              after.chunks == 4 && after.kind == 2 &&
			              after.expires_at == 5000,
			      "a header field did not survive eight hops");
		}

		/* WHERE THE TAG'S COVERAGE BEGINS, PROBED FROM BOTH SIDES.
		 *
		 * The round trip above shows the budget byte is outside it. This
		 * shows the boundary is where the schema puts it and not one byte
		 * either way: offset 4 is the last byte of `hop`, and corrupting
		 * it is answered by the hop validator as a shape rather than by
		 * the tag; offset 5 is the first authenticated byte, and
		 * corrupting it is answered by the tag and by nothing before it.
		 *
		 * `kind` at offset 5 is flipped from 2 to 3, both of which
		 * `situ_fzn_kind_is_known` accepts, so the frame passes validation
		 * and the answer can only have come from the cryptography. A flip
		 * producing an unknown kind would return SHAPE and prove nothing
		 * about coverage. */
		{
			uint8_t probe[FRAME_LEN];
			size_t probe_len = 0;

			check(fzn_seal_build(probe, sizeof(probe), &probe_len, &what, key,
			                     commitment, &rng, &aead) == FZN_SEAL_OK,
			      "building the coverage probe was refused");
			probe[4] ^= 0x7Fu;
			check(fzn_seal_open(probe, probe_len, key, commitment, &aead, &after) ==
			              FZN_SEAL_ERR_SHAPE,
			      "the last byte of `hop` was answered by the tag, so the tag "
			      "covers more than it should");

			check(fzn_seal_build(probe, sizeof(probe), &probe_len, &what, key,
			                     commitment, &rng, &aead) == FZN_SEAL_OK,
			      "rebuilding the coverage probe was refused");
			probe[5] ^= 0x01u;
			check(fzn_seal_open(probe, probe_len, key, commitment, &aead, &after) ==
			              FZN_SEAL_ERR_TAG,
			      "the first authenticated byte was not answered by the tag, so "
			      "the tag covers less than it should");
		}

		/* A BUDGET THIS LIBRARY WOULD NOT FORWARD IS REFUSED, and refused
		 * before the buffer is touched. Accepting it would tell the caller
		 * it had sent a frame with a reach of 200 when `fzn_relay_budget`
		 * clamps it to 8 at the first honest host. Exactly the ceiling
		 * must build and one past it must not: a check that only refused
		 * something far too large would pass with the bound set anywhere
		 * above it. */
		{
			size_t wrote = 0;
			size_t touched = 0;

			what.hops = FZN_RELAY_MAX_HOPS;
			check(fzn_seal_build(hopped, sizeof(hopped), &wrote, &what, key,
			                     commitment, &rng, &aead) == FZN_SEAL_OK,
			      "the largest budget this library forwards was refused");

			what.hops = FZN_RELAY_MAX_HOPS + 1u;
			memset(hopped, 0xee, sizeof(hopped));
			check(fzn_seal_build(hopped, sizeof(hopped), &wrote, &what, key,
			                     commitment, &rng, &aead) == FZN_SEAL_ERR_MALFORMED,
			      "a budget past what this library will forward was accepted");
			for (size_t i = 0; i < sizeof(hopped); i++)
				if (hopped[i] != 0xee)
					touched++;
			check(touched == 0,
			      "a build refused for its hop budget wrote into the caller's "
			      "buffer");
		}
	}

	printf("seal_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
