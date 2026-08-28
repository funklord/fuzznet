/* ONE WHOLE SEALED FRAME, FROZEN -- the send path's output compared against
 * bytes this tree did not produce first.
 *
 * WHAT IT ADDS OVER EVERYTHING ELSE IN THE SUITE. wire/test/seal_test.c
 * builds and opens with a stub AEAD, so it can say the ORDER is right and
 * nothing about the bytes. session/test/aead_monocypher_test.c runs the real
 * algorithm against draft-irtf-cfrg-xchacha-03 appendix A.1, so it can say
 * XChaCha20-Poly1305 is XChaCha20-Poly1305 -- over the draft's own key, nonce
 * and associated data, which is not a frame. Neither of them pins what this
 * library puts ON THE WIRE: the field order, the endianness, which span the
 * tag covers, where the commitment comes from. A consumer parsing our
 * datagrams cares about exactly that, and until this file nothing would have
 * noticed a change to it as long as both halves of our own round trip moved
 * together.
 *
 * WHY A VECTOR IS POSSIBLE AT ALL, AND WHY IT COSTS NOTHING. `fzn_seal_build`
 * draws its own nonce and refuses to take one from a caller -- a nonce a
 * caller supplied is a nonce a caller can repeat, and see session/random.h
 * for what repeating one under XChaCha20-Poly1305 removes. It draws it
 * through `fzn_random_ops_t`, the library's own entropy seam, so a test may
 * hand in a fill that answers with fixed bytes and get a reproducible frame
 * WITHOUT the API growing a way to supply a nonce. The seam is what makes
 * this vector expressible; the property it exists to protect is untouched.
 *
 * PROVENANCE, WHICH IS THE WHOLE REASON THESE BYTES ARE EVIDENCE. They were
 * produced by the fuzzypickles consumer session, against fuzznet 76a3485 with
 * Monocypher 4.0.3, from the inputs stated below and no others. They were
 * then reproduced here, in this tree, byte for byte, before being committed.
 * Two builds that were written separately and agree is a different claim from
 * one build agreeing with itself: a frame this file recomputed from the code
 * beside it would freeze whatever that code currently does, including
 * whatever it does wrong. So the array is NEVER regenerated from a run. If it
 * disagrees with the code, one of them has changed and which one is a real
 * question -- do not settle it by pasting a fresh dump in here.
 *
 * GATED ON MONOCYPHER because it needs the real AEAD and the real BLAKE2b. A
 * stub of either produces a different 168 bytes, so there is nothing for the
 * ungated suite to compare.
 */

#include "../seal.h"

#include "../../session/aead_monocypher.h"
#include "../../session/hash_monocypher.h"
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
		fprintf(stderr, "  FAIL: %s\n", what);
	}
}

#define PAYLOAD_LEN 24
#define FRAME_LEN   (FZN_SEAL_OVERHEAD + PAYLOAD_LEN)

/* THE FIELD DECODE, so that the array below is understood rather than merely
 * frozen. Offsets are into the frame, from wire/frame.situ.map.
 *
 *   [0..4]     hop, SITU_FZN_HOP_SIZE_FIXED == 5. PLAINTEXT, and OUTSIDE the
 *              tag -- [0] version 1, [1] hops_left 3.
 *   [5]        kind
 *   [6..37]    sender, 32
 *   [38..45]   expires_at, 8, big-endian
 *   [46..69]   nonce, 24 -- TRANSMITTED rather than derived, and here it is
 *              exactly the fixed fill, which is what makes this reproducible
 *   [70..85]   commitment, 16 -- DERIVED per frame from the commitment key
 *              and the nonce above, never supplied by a caller
 *   [86..89]   msg    [90..91] index    [92..93] chunks    [94..95] length 24
 *
 * [5..95] is the head, 91 bytes == SITU_FZN_HEAD_SIZE_FIXED, and it is the
 * AEAD's associated data.
 *
 *   [96..127]  sealed capability, 32
 *   [128..151] sealed payload, 24
 *   [152..167] tag, 16
 *
 * 5 + 91 + 32 + 24 + 16 = 168 == FZN_SEAL_OVERHEAD + 24.
 */
#define OFF_HOPS_LEFT 1
#define OFF_TAG       152

/* The two sizes the arithmetic above rests on, pinned rather than assumed. */
_Static_assert(SITU_FZN_HOP_SIZE_FIXED == 5, "the hop is no longer 5 bytes");
_Static_assert(SITU_FZN_HEAD_SIZE_FIXED == 91, "the head is no longer 91 bytes");
_Static_assert(FRAME_LEN == 168, "a 24-byte payload no longer makes a 168-byte frame");

/* THE INPUTS, all fixed. The frame below is a function of these and nothing
 * else -- no clock, no entropy, no state carried from a previous call. */
static const uint8_t KEY[FZN_AEAD_KEY_LEN] = {
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
};

static const uint8_t COMMITMENT_KEY[FZN_COMMITMENT_KEY_LEN] = {
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
	0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
};

static const uint8_t SENDER[32] = {
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
};

static const uint8_t CAPABILITY[32] = {
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
};

/* Declared at exactly PAYLOAD_LEN, so C drops the terminator and a sentence
 * of any other length stops the build rather than padding quietly into the
 * comparison -- the same trick session/test/aead_monocypher_test.c uses for
 * the draft's plaintext, and for the same reason. */
static const uint8_t PAYLOAD[PAYLOAD_LEN] = "fuzzypickles golden vec1";

static const uint64_t EXPIRES_AT = 0x0000000155aa77ffull;

/* The entropy seam, answering with fixed bytes.
 *
 * THIS IS NOT A WAY TO SUPPLY A NONCE and could not be made into one. It is
 * the SOURCE `fzn_seal_build` draws from, so what a caller controls here is
 * where randomness comes from -- which is the thing a consumer was always
 * going to choose, and the reason session/random.h is a seam at all. The
 * nonce is still drawn by the library, still once per frame, and still
 * refused rather than weakened when the source says no. */
static int fixed_fill(void *ctx, uint8_t *out, size_t len)
{
	(void)ctx;
	for (size_t i = 0; i < len; i++)
		out[i] = (uint8_t)(0xa0u + i);
	return 1;
}

/* THE GOLDEN FRAME. See the provenance paragraph at the top of this file:
 * these bytes came from another tree's build first, and are never to be
 * refreshed from a run of this one. */
static const uint8_t GOLDEN[FRAME_LEN] = {
	0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x90, 0x91,
	0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
	0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1,
	0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
	0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0x00, 0x00,
	0x00, 0x01, 0x55, 0xaa, 0x77, 0xff, 0xa0, 0xa1,
	0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
	0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1,
	0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0x2e, 0x2b,
	0xab, 0x62, 0x3e, 0xaf, 0x67, 0x50, 0x87, 0x60,
	0xb0, 0x37, 0x46, 0x1b, 0x32, 0x47, 0x11, 0x22,
	0x33, 0x44, 0x00, 0x02, 0x00, 0x05, 0x00, 0x18,
	0xb5, 0x3a, 0xbc, 0x58, 0x3d, 0xfa, 0xdf, 0x29,
	0xe1, 0xb3, 0x44, 0x80, 0x4a, 0xae, 0xc6, 0x81,
	0x8e, 0xa2, 0x61, 0xcc, 0x2a, 0x40, 0xd5, 0x66,
	0x07, 0x98, 0x18, 0xd2, 0x16, 0xc6, 0x23, 0xc2,
	0x93, 0xf4, 0x0f, 0x03, 0xc4, 0x18, 0x1c, 0xab,
	0x86, 0x8d, 0x2f, 0x49, 0x84, 0xd7, 0xb7, 0xac,
	0x76, 0xcb, 0xff, 0xf3, 0x2b, 0x44, 0xab, 0xb8,
	0xed, 0x7b, 0x54, 0xf2, 0x04, 0x81, 0x3f, 0x2a,
	0x59, 0x67, 0x1a, 0xd7, 0x6f, 0xc1, 0xf3, 0xcb,
};

int main(void)
{
	fzn_aead_ops_t aead;
	fzn_hash_ops_t hash;
	fzn_random_ops_t rng = { fixed_fill, NULL };
	fzn_send_t what;
	fzn_opened_t opened;
	uint8_t built[FRAME_LEN];
	uint8_t work[FRAME_LEN];
	size_t built_len = 0;
	fzn_seal_err_t verdict;

	fzn_aead_monocypher_init(&aead);
	fzn_hash_monocypher_init(&hash);
	check(aead.seal != NULL && aead.open != NULL && hash.hash != NULL,
	      "a binding left a null op, so nothing below is about the real algorithm");

	memset(&what, 0, sizeof(what));
	what.sender = SENDER;
	what.capability = CAPABILITY;
	what.payload = PAYLOAD;
	what.payload_len = PAYLOAD_LEN;
	what.expires_at = EXPIRES_AT;
	what.msg = 0x11223344u;
	what.index = 2;
	what.chunks = 5;
	what.kind = 1;
	what.hops = 3;

	/* 1. THE FRAME THIS TREE BUILDS IS THE FRAME THE OTHER TREE BUILT. */
	verdict = fzn_seal_build(built, sizeof(built), &built_len, &what, KEY, COMMITMENT_KEY,
	                         &hash, &rng, &aead);
	check(verdict == FZN_SEAL_OK, "building the golden frame was refused");
	check(built_len == FRAME_LEN, "a built frame is not the overhead plus the payload");
	check(built_len == (size_t)FZN_SEAL_OVERHEAD + PAYLOAD_LEN,
	      "FZN_SEAL_OVERHEAD no longer describes what a build costs");
	check(verdict == FZN_SEAL_OK && memcmp(built, GOLDEN, FRAME_LEN) == 0,
	      "the frame this build produced is not the golden vector -- something the wire "
	      "depends on has moved");

	/* 2. AND IT OPENS. On a copy, because opening decrypts in place. */
	memcpy(work, built, sizeof(work));
	verdict = fzn_seal_open(work, sizeof(work), KEY, COMMITMENT_KEY, &hash, &aead, &opened);
	check(verdict == FZN_SEAL_OK, "the golden frame could not be opened");
	check(verdict == FZN_SEAL_OK && opened.payload_len == PAYLOAD_LEN &&
	              memcmp(opened.payload, PAYLOAD, PAYLOAD_LEN) == 0,
	      "the golden frame did not open to its own payload");

	/* 3. THE OPEN LEG IS A CHECK RATHER THAN A MIRROR OF THE SEAL. Flip one
	 * byte of the tag and it must refuse. Without this, case 2 would be
	 * satisfied by an open that verified nothing at all. */
	memcpy(work, built, sizeof(work));
	work[OFF_TAG] ^= 0x01u;
	check(fzn_seal_open(work, sizeof(work), KEY, COMMITMENT_KEY, &hash, &aead, &opened) ==
	              FZN_SEAL_ERR_TAG,
	      "a frame with one flipped tag byte still opened");

	/* 4. THE HOP IS OUTSIDE THE AUTHENTICATED SPAN.
	 *
	 * `fzn_hop.hops_left` sits before the head precisely so that a relay can
	 * decrement it without a key -- wire/relay.h, and `frame.situ` says
	 * `require no_tag_invalidation(fzn_frame.hop.hops_left)`, which is why
	 * situ generates no coverage-aware setter for it. If the AEAD's
	 * associated data ever widened to take in the hop, every relayed frame
	 * would start failing its tag at the second host.
	 *
	 * THIS IS NOT THE ONLY PLACE THAT SAYS SO, and the first draft of this
	 * comment claimed it was. wire/test/seal_test.c already has the positive
	 * control -- spend the whole budget in flight, then require the frame to
	 * open with its interior byte-identical -- and its message names the
	 * same fault. Measured rather than assumed: widening the associated data
	 * in `wire/seal.c` to `SITU_FZN_HEAD_SIZE_FIXED + SITU_FZN_HOP_SIZE_FIXED`
	 * turns four of seal_test.c's assertions red as well as the two below.
	 *
	 * What this one adds is the REAL AEAD and a FROZEN frame. seal_test.c
	 * runs a stub whose seal and open share one span computation, and it
	 * compares against a frame it built moments earlier; here Poly1305 is
	 * the thing being asked, over 168 bytes whose layout another tree fixed.
	 * Modest, and worth having beside case 1 -- the vector pins where every
	 * field sits, and this pins which of them the tag reaches.
	 *
	 * `hops_left` specifically, byte 1, because that is the field a relay
	 * actually rewrites. A spare byte elsewhere in the hop would prove
	 * something narrower than the property worth having. */
	memcpy(work, built, sizeof(work));
	work[OFF_HOPS_LEFT] = 1;
	verdict = fzn_seal_open(work, sizeof(work), KEY, COMMITMENT_KEY, &hash, &aead, &opened);
	check(verdict == FZN_SEAL_OK,
	      "decrementing hops_left invalidated the tag, so a relay cannot forward a frame "
	      "without the key -- the hop has fallen inside the authenticated span");
	check(verdict == FZN_SEAL_OK && opened.payload_len == PAYLOAD_LEN &&
	              memcmp(opened.payload, PAYLOAD, PAYLOAD_LEN) == 0,
	      "a frame whose hops_left was rewritten did not open to its own payload");

	printf("golden_frame_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
