/* Tests for session/commitment.c.
 *
 * The properties worth checking here are not "does it produce bytes" but
 * the two that make the construction key-committing at all: that key and
 * commitment come from ONE derivation over the SAME input, and that a
 * changed transcript changes both. A module that derived them separately
 * would pass a test that only compared a commitment to itself.
 */

#include "../commitment.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	printf("  FAIL commitment_test.c:%d: ", line);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* A stub hash. Not cryptographic and not pretending to be: it is a
 * deterministic mixing function whose only required property is that
 * different inputs give different outputs often enough for these tests to
 * mean something. The real one arrives with Monocypher behind the same
 * vtable, exactly as the signer does.
 *
 * It counts calls, because "one hash, not two" is the load-bearing claim in
 * this module and a claim about call counts that nothing counts is a
 * comment. */
struct stub {
	int calls;
	size_t last_in_len;
	size_t last_out_len;
	int refuse;
};

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	struct stub *s = (struct stub *)ctx;
	uint32_t acc = 0x9e3779b9u;

	s->calls++;
	s->last_in_len = in_len;
	s->last_out_len = out_len;
	if (s->refuse)
		return 0;

	for (size_t i = 0; i < in_len; i++)
		acc = (acc ^ in[i]) * 16777619u + (uint32_t)i;
	for (size_t i = 0; i < out_len; i++) {
		acc = acc * 1103515245u + 12345u;
		out[i] = (uint8_t)(acc >> 24);
	}
	return 1;
}

static void ops_init(fzn_hash_ops_t *ops, struct stub *s)
{
	memset(s, 0, sizeof(*s));
	ops->hash = stub_hash;
	ops->ctx = s;
}

static void test_one_derivation_produces_both(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment[FZN_COMMITMENT_LEN];
	static const uint8_t transcript[64] = { 1, 2, 3 };

	/* The claim the whole construction rests on: both outputs come from a
	 * single hash over a single input. Two calls would mean the commitment
	 * accompanies the key rather than binding it. */
	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive(&ops, transcript, sizeof(transcript), key, commitment) ==
	              FZN_COMMITMENT_OK,
	      "derivation failed");
	CHECK(s.calls == 1, "hashed %d times, wanted exactly 1", s.calls);
	CHECK(s.last_out_len == FZN_DERIVED_LEN, "asked for %zu bytes, wanted %d",
	      s.last_out_len, FZN_DERIVED_LEN);

	/* And the label is really prepended, so the hash saw more than the
	 * transcript. */
	CHECK(s.last_in_len > sizeof(transcript),
	      "hashed %zu bytes for a %zu-byte transcript -- the domain label is missing",
	      s.last_in_len, sizeof(transcript));
}

static void test_a_changed_transcript_changes_both(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key_a[FZN_AEAD_KEY_LEN], commit_a[FZN_COMMITMENT_LEN];
	uint8_t key_b[FZN_AEAD_KEY_LEN], commit_b[FZN_COMMITMENT_LEN];
	uint8_t transcript[64];

	/* If one bit of the key material moved and the commitment did not,
	 * the commitment would not be binding it. */
	memset(transcript, 0xa5, sizeof(transcript));
	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive(&ops, transcript, sizeof(transcript), key_a, commit_a) ==
	              FZN_COMMITMENT_OK,
	      "first derivation failed");

	transcript[31] ^= 0x01;
	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive(&ops, transcript, sizeof(transcript), key_b, commit_b) ==
	              FZN_COMMITMENT_OK,
	      "second derivation failed");

	CHECK(memcmp(key_a, key_b, sizeof(key_a)) != 0,
	      "one bit of transcript left the key unchanged");
	CHECK(memcmp(commit_a, commit_b, sizeof(commit_a)) != 0,
	      "one bit of transcript left the COMMITMENT unchanged -- it is not binding");
}

static void test_key_and_commitment_do_not_overlap(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment[FZN_COMMITMENT_LEN];
	static const uint8_t transcript[64] = { 7 };

	/* The commitment is the tail of the derivation, not a slice of the
	 * key. Publishing bytes of the key in the frame header would be the
	 * worst possible way to get this wrong, and it would still pass a
	 * test that only checked the commitment matched. */
	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive(&ops, transcript, sizeof(transcript), key, commitment) ==
	              FZN_COMMITMENT_OK,
	      "derivation failed");

	for (size_t i = 0; i + FZN_COMMITMENT_LEN <= FZN_AEAD_KEY_LEN; i++) {
		CHECK(memcmp(key + i, commitment, FZN_COMMITMENT_LEN) != 0,
		      "the commitment appears inside the key at offset %zu -- the frame "
		      "would publish key material",
		      i);
	}
}

static void test_check_is_a_real_comparison(void)
{
	uint8_t a[FZN_COMMITMENT_LEN], b[FZN_COMMITMENT_LEN];

	memset(a, 0x11, sizeof(a));
	memcpy(b, a, sizeof(b));

	CHECK(fzn_commitment_check(a, b) == FZN_COMMITMENT_OK, "equal commitments mismatched");

	b[FZN_COMMITMENT_LEN - 1] ^= 0x01;
	CHECK(fzn_commitment_check(a, b) == FZN_COMMITMENT_ERR_MISMATCH,
	      "a difference in the LAST byte was missed");

	memcpy(b, a, sizeof(b));
	b[0] ^= 0x80;
	CHECK(fzn_commitment_check(a, b) == FZN_COMMITMENT_ERR_MISMATCH,
	      "a difference in the first byte was missed");

	CHECK(fzn_commitment_check(NULL, b) == FZN_COMMITMENT_ERR_MALFORMED, "null derived");
	CHECK(fzn_commitment_check(a, NULL) == FZN_COMMITMENT_ERR_MALFORMED, "null received");
}

static void test_a_refused_hash_writes_nothing(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment[FZN_COMMITMENT_LEN];
	uint8_t key_before[FZN_AEAD_KEY_LEN], commit_before[FZN_COMMITMENT_LEN];
	static const uint8_t transcript[64] = { 3 };

	/* Half a key is worse than no key: a caller that ignored the error
	 * would encrypt under whatever was in the buffer. */
	memset(key, 0xcd, sizeof(key));
	memset(commitment, 0xcd, sizeof(commitment));
	memcpy(key_before, key, sizeof(key));
	memcpy(commit_before, commitment, sizeof(commitment));

	ops_init(&ops, &s);
	s.refuse = 1;
	CHECK(fzn_commitment_derive(&ops, transcript, sizeof(transcript), key, commitment) ==
	              FZN_COMMITMENT_ERR_HASH,
	      "a refusing hash was reported as success");
	CHECK(memcmp(key, key_before, sizeof(key)) == 0, "a refused derivation wrote a key");
	CHECK(memcmp(commitment, commit_before, sizeof(commitment)) == 0,
	      "a refused derivation wrote a commitment");
}

static void test_bad_arguments(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment[FZN_COMMITMENT_LEN];
	static const uint8_t transcript[64] = { 5 };
	static const uint8_t huge[1] = { 0 };

	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive(NULL, transcript, sizeof(transcript), key, commitment) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "null ops accepted");
	CHECK(fzn_commitment_derive(&ops, NULL, 8, key, commitment) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "null transcript accepted");
	CHECK(fzn_commitment_derive(&ops, transcript, 0, key, commitment) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "an empty transcript was hashed");
	CHECK(fzn_commitment_derive(&ops, huge, 100000, key, commitment) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "a transcript past the bound was hashed, overrunning the buffer");
	CHECK(fzn_commitment_derive(&ops, transcript, sizeof(transcript), NULL, commitment) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "null key output accepted");
	CHECK(fzn_commitment_derive(&ops, transcript, sizeof(transcript), key, NULL) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "null commitment output accepted");
	CHECK(s.calls == 0, "hashed %d times for arguments it had already refused", s.calls);

	{
		fzn_hash_ops_t no_fn = { NULL, NULL };
		CHECK(fzn_commitment_derive(&no_fn, transcript, sizeof(transcript), key,
		                            commitment) == FZN_COMMITMENT_ERR_MALFORMED,
		      "ops with a null hash function accepted");
	}
}

/* The positive control: most cases above assert a refusal or a difference,
 * and a derive that always failed would satisfy them. */
static void test_the_suite_can_tell_pass_from_fail(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment[FZN_COMMITMENT_LEN];
	static const uint8_t transcript[64] = { 9 };

	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive(&ops, transcript, sizeof(transcript), key, commitment) ==
	              FZN_COMMITMENT_OK,
	      "the positive control fails, so every refusal above proves nothing");
}

int main(void)
{
	test_one_derivation_produces_both();
	test_a_changed_transcript_changes_both();
	test_key_and_commitment_do_not_overlap();
	test_check_is_a_real_comparison();
	test_a_refused_hash_writes_nothing();
	test_bad_arguments();
	test_the_suite_can_tell_pass_from_fail();

	printf("commitment_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
