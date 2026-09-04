/* THE TAMPER HARNESS, GENERATED FROM THE SCHEMA RATHER THAN WRITTEN OUT.
 *
 * `situc gen-tamper wire/frame.situ` emits `wire/generated/frame_tamper.h`,
 * which flips every byte the schema declares tag-covered and every byte of
 * the tag, one at a time, restoring each flip before the next, and requires
 * OUR verifier to refuse every one. It returns SITU_OK, or
 * SITU_ERR_CONSTRAINT with `*failed_at` naming a byte that was wrongly
 * accepted.
 *
 * WHY THIS EXISTS BESIDE THE HAND-WRITTEN CASES RATHER THAN INSTEAD OF THEM.
 * wire/test/seal_test.c flips a tag byte and a header byte; those are SAMPLES,
 * chosen by whoever wrote them, and a sample cannot notice a field that was
 * added to the schema afterwards or a span that moved under it. This tree has
 * already spent a day on hand-written coverage it had got wrong -- the stub
 * AEAD whose key fold cancelled for the suite's own key, so that a frame
 * sealed under one key opened under another and every case in the file was
 * passing for the wrong reason. What the generator gives is EXHAUSTIVENESS
 * over the schema's own declared coverage, recomputed from `frame.situ` every
 * time `make schema` runs, so the set of bytes asserted about moves when the
 * layout moves.
 *
 * WHAT IT DOES NOT COVER, AND WHERE THAT HALF LIVES. gen-tamper also has a
 * converse half -- bytes OUTSIDE the covered span must NOT change the answer
 * -- and it emits that only for a fixed layout. `fzn_frame` is variable
 * length (`payload[head.length]`), so the emitted harness above is the
 * coverage half alone: the five hop bytes are simply left alone, never
 * flipped, and nothing here says a relay can still rewrite `hops_left`.
 * THAT PROPERTY IS ASSERTED BY HAND, IN TWO PLACES, AND STAYS THERE:
 * wire/test/seal_test.c spends the whole hop budget between build and open
 * and requires the frame to open with its interior byte-identical, and
 * wire/test/golden_frame_test.c rewrites byte 1 of the frozen vector under
 * the real AEAD and requires FZN_SEAL_OK. Do not read a green run of this
 * file as covering the hop.
 *
 * UNGATED, AND THE STUB SUSTAINS IT. The verifier below is `fzn_seal_open`
 * driven through the same stub AEAD and stub hash `wire/test/seal_test.c`
 * uses, so this runs on every `make test` rather than only where
 * MONOCYPHER_DIR names a checkout. That was worth checking rather than
 * assuming: the harness asks that EVERY covered byte reach the tag, which is
 * a stronger demand than any single case in seal_test.c makes of the same
 * stub. `stub_tag` folds each associated-data byte in with `acc = acc * 31 +
 * byte` and each ciphertext byte with `acc = acc * 17 + byte`; both
 * multipliers are odd, so each step is injective modulo 256 and a difference
 * introduced at any byte survives to the tag. Measured, not reasoned: the
 * harness returns SITU_OK over all 163 flips.
 *
 * THE LYING VERIFIER IS A PERMANENT CASE HERE, not something somebody ran
 * once. SITU_OK from a harness nobody has watched fail is exactly the vacuous
 * pass this harness exists to prevent, so case 3 hands it a verifier that
 * restores one covered byte before opening and requires SITU_ERR_CONSTRAINT
 * with `failed_at` naming that byte and no other.
 */

#include "../seal.h"

#include "frame.h"
#include "frame_tamper.h"

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

/* THE SAME STUB AEAD AND STUB HASH AS wire/test/seal_test.c, deliberately
 * rather than by accident, and copied rather than shared.
 *
 * What is under test here is which bytes reach the tag, not the
 * cryptography -- `session/test/aead_monocypher_test.c` and
 * `wire/test/golden_frame_test.c` run the real algorithm. A stub of a
 * DIFFERENT shape would make this file's verdict a statement about that
 * stub instead of about `fzn_seal_open`'s spans, so it is the same one.
 *
 * The multiply-then-add fold is load-bearing and is why seal_test.c's
 * comment on it is worth reading before touching this: an earlier version
 * XORed the key into 16 accumulator slots, which cancelled for any key
 * whose halves were equal -- including the suite's own -- and left the AEAD
 * seam blind to its only secret. Each byte's contribution has to depend on
 * where it sits.
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

static int stub_seal(void *ctx, const uint8_t *key, const uint8_t *nonce, const uint8_t *aad,
                     size_t aad_len, uint8_t *text, size_t text_len, uint8_t *tag)
{
	(void)ctx;
	for (size_t i = 0; i < text_len; i++)
		text[i] = (uint8_t)(text[i] ^ key[i % FZN_AEAD_KEY_LEN]);
	stub_tag(key, nonce, aad, aad_len, text, text_len, tag);
	return 1;
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

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint32_t acc = 0x9e3779b9u;

	(void)ctx;
	for (size_t i = 0; i < in_len; i++)
		acc = (acc ^ in[i]) * 16777619u + (uint32_t)i;
	for (size_t i = 0; i < out_len; i++) {
		acc = acc * 1103515245u + 12345u;
		out[i] = (uint8_t)(acc >> 24);
	}
	return 1;
}

/* Offsets from wire/frame.situ.map, as in seal_test.c and generated_test.c
 * and for the same reason: a test that asked the generated code where a
 * field lives could not catch the generated code being wrong about it. */
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
#define FRAME_LEN   (FZN_SEAL_OVERHEAD + PAYLOAD_LEN)

/* WHAT THE HARNESS SHOULD FLIP, stated here so a green run is a claim about a
 * number rather than about a loop nobody sized. The covered span runs from
 * the head to the tag -- 91 head plus 32 capability plus 24 payload -- and
 * the tag's own 16 bytes are walked separately by the generated code.
 *
 * Written as arithmetic over the generated sizes rather than as 147, so that
 * a schema change moves them together. Asserted against what
 * `situ_fzn_frame_tag_covered` actually reports in case 1 below, which is the
 * point: two ways of saying where the tag reaches, and the case fails if they
 * disagree. */
#define COVERED_AT   SITU_FZN_HOP_SIZE_FIXED
#define COVERED_LEN  (SITU_FZN_HEAD_SIZE_FIXED + 32u + PAYLOAD_LEN)
#define OFF_TAG      (COVERED_AT + COVERED_LEN)

/* One entry call plus one call per flip. A harness whose covered span came
 * back as zero would return SITU_OK having asked nothing, which is the
 * failure mode this file is about; counting the verifier's calls is what
 * makes that impossible to mistake for a pass. */
#define EXPECT_CALLS (1u + COVERED_LEN + SITU_FZN_FRAME_TAG_COUNT)

/* The byte the lying verifier ignores in case 3. Inside the payload, so it is
 * a byte the AEAD covers as ciphertext rather than as associated data -- the
 * half a verifier is likelier to get wrong, since the associated data is
 * spelled out as a span and the ciphertext is whatever is left. */
#define LIE_AT 130

_Static_assert(SITU_FZN_HOP_SIZE_FIXED == 5, "the hop is no longer 5 bytes");
_Static_assert(SITU_FZN_HEAD_SIZE_FIXED == 91, "the head is no longer 91 bytes");
_Static_assert(FRAME_LEN == 168, "a 24-byte payload no longer makes a 168-byte frame");
_Static_assert(COVERED_LEN == 147, "the covered span is no longer 147 bytes");
_Static_assert(OFF_TAG == 152, "the tag no longer starts at byte 152");
_Static_assert(EXPECT_CALLS == 164, "163 flips plus the entry call is no longer 164");
_Static_assert(LIE_AT >= OFF_PAYLOAD && LIE_AT < OFF_TAG,
               "the byte the control ignores is no longer inside the payload");

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

static uint8_t key[FZN_AEAD_KEY_LEN];
static uint8_t commitment_key[FZN_COMMITMENT_KEY_LEN];
static fzn_hash_ops_t hash = { stub_hash, NULL };
static fzn_aead_ops_t aead = { stub_seal, stub_open, NULL };

static const uint8_t PLAIN[PAYLOAD_LEN] = "twenty-four bytes here.";
static const uint8_t CAP[32] = "a capability identifier, 32 by.";

/* A frame with its header filled and its sealed region still plaintext. The
 * commitment is derived here because `fzn_seal_open` derives it too and
 * refuses a mismatch before the AEAD ever runs -- a frame carrying any other
 * 16 bytes would be refused for a reason that has nothing to do with the
 * tag, and every flip below would then be passing for the wrong reason. */
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
	memcpy(f + OFF_CAP, CAP, 32);
	memcpy(f + OFF_PAYLOAD, PLAIN, PAYLOAD_LEN);
}

/* WHAT THE HARNESS CALLS. `ignore_at` is what makes the control a control:
 * where it is not negative, that byte is restored from the untampered frame
 * before the open, so the verifier is blind to exactly one covered byte. */
struct verifier {
	unsigned calls;
	int ignore_at;
	const uint8_t *pristine;
};

/* ON A COPY, WHICH IS NOT AN OPTIMISATION. `fzn_seal_open` decrypts in place
 * on success, so a verifier handed the harness's own buffer would leave the
 * sealed region as plaintext behind it and the very next flip would be made
 * to a frame that no longer seals. The harness restores the byte it flipped
 * and nothing else; keeping its buffer untouched is this function's job. */
static int verify_frame(situ_view_t view, void *ctx)
{
	struct verifier *v = (struct verifier *)ctx;
	uint8_t work[FRAME_LEN];
	fzn_opened_t opened;

	v->calls++;
	if (view.base == NULL || view.limit != FRAME_LEN)
		return 0;

	memcpy(work, view.base, FRAME_LEN);
	if (v->ignore_at >= 0)
		work[v->ignore_at] = v->pristine[v->ignore_at];

	return fzn_seal_open(work, sizeof(work), key, commitment_key, &hash, &aead, &opened) ==
	       FZN_SEAL_OK;
}

int main(void)
{
	uint8_t frame[FRAME_LEN], sealed[FRAME_LEN];
	struct verifier v;
	situ_msg_t msg;
	situ_view_t view;
	uint32_t at = 0, span = 0, failed_at = 0;
	situ_err_t verdict;

	memset(key, 0x77, sizeof(key));
	memset(commitment_key, 0x5b, sizeof(commitment_key));

	build(frame);
	check(fzn_seal_close(frame, sizeof(frame), key, &aead) == FZN_SEAL_OK,
	      "sealing the frame the harness runs over was refused");
	memcpy(sealed, frame, sizeof(sealed));

	/* 1. THE GEOMETRY THE HARNESS WILL WALK, asserted before it walks it.
	 *
	 * The constants above are arithmetic over the generated sizes; this is
	 * what the generated coverage function reports. Two derivations of one
	 * number, and a disagreement between them means the harness below is
	 * flipping a set of bytes nobody in this file described. */
	situ_msg_init(&msg, frame, (uint32_t)sizeof(frame));
	check(situ_fzn_frame_view(&msg, 0u, (uint32_t)sizeof(frame), &view) == SITU_OK,
	      "the sealed frame is not a frame situ will take a view of");
	check(situ_fzn_frame_tag_covered(view, &at, &span) == SITU_OK,
	      "situ would not say which bytes the tag covers");
	check(at == COVERED_AT && span == COVERED_LEN,
	      "the covered span situ reports is not the one this file describes");

	/* 2. THE HARNESS ITSELF: every covered byte, and every tag byte, must
	 * change `fzn_seal_open`'s answer. */
	v.calls = 0;
	v.ignore_at = -1;
	v.pristine = sealed;
	verdict = situ_fzn_frame_tamper(frame, (uint32_t)sizeof(frame), verify_frame, &v,
	                                &failed_at);
	check(verdict == SITU_OK,
	      "a covered byte was flipped and fzn_seal_open still opened the frame");
	if (verdict == SITU_ERR_CONSTRAINT)
		printf("  (the byte it accepted was %u)\n", (unsigned)failed_at);
	check(v.calls == EXPECT_CALLS,
	      "the harness did not make one verification per covered byte plus one per tag "
	      "byte -- a span of the wrong size would return SITU_OK having asked nothing");
	check(memcmp(frame, sealed, sizeof(frame)) == 0,
	      "the harness left the frame changed, so every case after it is about a "
	      "different frame");

	/* 3. THE LYING VERIFIER. Without this, case 2 is a pass nobody has
	 * watched fail -- which is the exact failure the harness exists to
	 * catch, and reproducing it here would be absurd.
	 *
	 * `failed_at` must name LIE_AT and not merely be non-zero: a harness
	 * that reported the first byte of the span whatever went wrong would
	 * satisfy a weaker check and tell a debugger nothing. It is the first
	 * byte the verifier wrongly accepts, so the walk stops there and the
	 * call count is fixed too. */
	v.calls = 0;
	v.ignore_at = LIE_AT;
	v.pristine = sealed;
	failed_at = 0;
	verdict = situ_fzn_frame_tamper(frame, (uint32_t)sizeof(frame), verify_frame, &v,
	                                &failed_at);
	check(verdict == SITU_ERR_CONSTRAINT,
	      "a verifier blind to one covered byte was not caught by the harness");
	check(verdict == SITU_ERR_CONSTRAINT && failed_at == LIE_AT,
	      "the harness caught a blind verifier and named the wrong byte");
	check(v.calls == 1u + (LIE_AT - COVERED_AT) + 1u,
	      "the harness did not stop at the first byte it wrongly accepted");
	check(memcmp(frame, sealed, sizeof(frame)) == 0,
	      "the harness left the frame changed after refusing it");

	/* 4. AND IT REFUSES A FRAME THAT DID NOT VERIFY ON ENTRY, rather than
	 * walking one and reporting on flips of a frame that was already
	 * broken. SITU_ERR_TAG is a different verdict from SITU_OK and from
	 * SITU_ERR_CONSTRAINT, so a caller can tell "your frame is wrong" from
	 * "your verifier is wrong". */
	memcpy(frame, sealed, sizeof(frame));
	frame[FRAME_LEN - 1] ^= 0x01u;
	v.calls = 0;
	v.ignore_at = -1;
	v.pristine = sealed;
	check(situ_fzn_frame_tamper(frame, (uint32_t)sizeof(frame), verify_frame, &v,
	                            &failed_at) == SITU_ERR_TAG,
	      "the harness walked a frame its own verifier would not open");
	check(v.calls == 1u, "the harness kept flipping after the entry check failed");

	printf("tamper_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
