/* A known-answer test for the BLAKE2b binding, and a derivation through it.
 *
 * Built only when MONOCYPHER_DIR is set. It exists for the reason
 * chain/tests/sign_monocypher_test.c exists: commitment_test.c drives every
 * path in the key schedule with a stub, and a stub proves the LOGIC and
 * nothing about the binding. A seam that has only ever had a fake behind it
 * is a seam nobody has checked.
 *
 * TWO KINDS OF EVIDENCE HERE, and they are not interchangeable:
 *
 *   - The 64-byte case is a PUBLISHED VECTOR, RFC 7693 Appendix A's
 *     BLAKE2b-512 of "abc". It is an independent check: it can tell that
 *     this binding computes BLAKE2b rather than merely computing something
 *     repeatable. Nothing in this tree could have produced it.
 *   - The 48-byte case is a PINNED OBSERVATION, taken from this build. It
 *     cannot tell whether the answer is right -- only whether it has
 *     changed. That is worth having, because 48 is the length the key
 *     schedule actually asks for and BLAKE2b's digest length lives in its
 *     parameter block, so a 48-byte digest is a different function from a
 *     truncated 64-byte one and the published vector says nothing about it.
 *
 * Saying which is which matters more than having both. A pinned observation
 * presented as a known-answer test is a test that agrees with whatever the
 * code did on the day it was written.
 */

#include "../hash_monocypher.h"

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

static int equals(const uint8_t *got, const char *hex, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		unsigned int b;

		if (sscanf(hex + 2 * i, "%2x", &b) != 1)
			return 0;
		if (got[i] != (uint8_t)b)
			return 0;
	}
	return 1;
}

/* RFC 7693 Appendix A. */
static const char BLAKE2B_512_ABC[] =
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";

/* Observed from this build, pinned against change rather than checked
 * against an authority. See the header comment. */
static const char BLAKE2B_384_ABC[] =
        "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6"
        "c66ba83be64b302d7cba6ce15bb556f4";

int main(void)
{
	fzn_hash_ops_t ops;
	uint8_t out[64];
	uint8_t key_a[FZN_AEAD_KEY_LEN], commit_a[FZN_COMMITMENT_LEN];
	uint8_t key_b[FZN_AEAD_KEY_LEN], commit_b[FZN_COMMITMENT_LEN];
	uint8_t transcript[96];

	fzn_hash_monocypher_init(&ops);
	check(ops.hash != NULL, "init left the hash unset");

	/* The independent check. */
	memset(out, 0, sizeof(out));
	check(ops.hash(ops.ctx, out, 64, (const uint8_t *)"abc", 3) != 0, "hashing refused");
	check(equals(out, BLAKE2B_512_ABC, 64),
	      "BLAKE2b-512(\"abc\") does not match RFC 7693 -- this is not BLAKE2b");

	/* The pinned one, at the length the key schedule uses. */
	memset(out, 0, sizeof(out));
	check(ops.hash(ops.ctx, out, FZN_DERIVED_LEN, (const uint8_t *)"abc", 3) != 0,
	      "hashing 48 bytes refused");
	check(equals(out, BLAKE2B_384_ABC, FZN_DERIVED_LEN),
	      "the 48-byte digest changed from what this build produced");

	/* A 48-byte digest is NOT the first 48 bytes of a 64-byte one. If it
	 * were, the length would not be in the parameter block and the pin
	 * above would be redundant with the vector. */
	check(!equals(out, BLAKE2B_512_ABC, FZN_DERIVED_LEN),
	      "the 48-byte digest is a prefix of the 64-byte one, which BLAKE2b "
	      "does not do -- the output length is being ignored");

	/* Lengths Monocypher will not produce are refused rather than passed
	 * through to an assertion inside the library. */
	check(ops.hash(ops.ctx, out, 0, (const uint8_t *)"abc", 3) == 0, "a zero length passed");
	check(ops.hash(ops.ctx, out, 65, (const uint8_t *)"abc", 3) == 0, "a 65-byte length passed");
	check(ops.hash(ops.ctx, NULL, 32, (const uint8_t *)"abc", 3) == 0, "a null output passed");

	/* And a real derivation end to end: deterministic, and one flipped
	 * bit of transcript moves both halves. commitment_test asserts this
	 * against a stub; here it is against BLAKE2b. */
	memset(transcript, 0x5a, sizeof(transcript));
	check(fzn_commitment_derive(&ops, transcript, sizeof(transcript), key_a, commit_a) ==
	              FZN_COMMITMENT_OK,
	      "deriving with real BLAKE2b failed");
	check(fzn_commitment_derive(&ops, transcript, sizeof(transcript), key_b, commit_b) ==
	              FZN_COMMITMENT_OK,
	      "second derivation failed");
	check(memcmp(key_a, key_b, sizeof(key_a)) == 0, "derivation is not deterministic");
	check(memcmp(commit_a, commit_b, sizeof(commit_a)) == 0,
	      "commitment is not deterministic");

	transcript[0] ^= 0x01;
	check(fzn_commitment_derive(&ops, transcript, sizeof(transcript), key_b, commit_b) ==
	              FZN_COMMITMENT_OK,
	      "third derivation failed");
	check(memcmp(key_a, key_b, sizeof(key_a)) != 0, "a flipped bit left the key unchanged");
	check(memcmp(commit_a, commit_b, sizeof(commit_a)) != 0,
	      "a flipped bit left the commitment unchanged -- it is not binding the key");
	check(fzn_commitment_check(commit_a, commit_b) == FZN_COMMITMENT_ERR_MISMATCH,
	      "two different commitments compared equal");
	check(fzn_commitment_check(commit_a, commit_a) == FZN_COMMITMENT_OK,
	      "a commitment did not match itself");

	printf("hash_monocypher_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
