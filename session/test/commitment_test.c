/* Tests for session/commitment.c.
 *
 * The properties worth checking here are not "does it produce bytes" but the
 * ones the construction rests on, and there are now four rather than two:
 *
 *   - key and commitment key come from ONE derivation over the SAME input,
 *     and a changed transcript moves both;
 *   - THE COMMITMENT CHANGES WITH THE NONCE. This is the finding the module
 *     was rewritten for -- a commitment derived from the transcript alone is
 *     a constant per (sender, receiver) pair sitting in a cleartext header
 *     beside `sender[32]`, which hands the social graph to anyone who
 *     forwards a datagram. Two frames of one pair must not carry the same
 *     commitment;
 *   - THE KEY DOES NOT CHANGE WITH THE NONCE. Two peers derive the same key
 *     having seen different nonces, or none yet, so a nonce reaching the
 *     root derivation is the mistake that breaks the protocol silently in
 *     one direction and loudly in the other;
 *   - the two derivations cannot be made to hash the same bytes, which is
 *     what the domain labels are for and is not an abstract worry -- see
 *     test_the_labels_cannot_collide, which builds the collision.
 *
 * Every case below has been shown to FAIL for the reason it names, by
 * mutating session/commitment.c and rebuilding this binary specifically. A
 * test nobody has watched go red is a comment.
 */

#include "../commitment.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* The domain labels are static to commitment.c, so their LENGTH is checked
 * here rather than their contents: every assertion about what a derivation
 * hashed is stated as a length, and this is the one number that has to
 * agree. If commitment.c changes a label's size, this constant is what says
 * so -- which is better than the old test's `in_len > transcript_len`, a
 * condition a one-byte label satisfies. */
#define LABEL_LEN 16

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

/* Room for the largest input either derivation can present: the root's is a
 * label plus commitment.c's 512-byte transcript bound. Bounded and checked
 * rather than trusted, so a derivation that grew its input past this is a
 * loud truncation here instead of a silent overrun. */
#define STUB_IN_MAX 640

/* A stub hash. Not cryptographic and not pretending to be: it is a
 * deterministic mixing function whose only required property is that
 * different inputs give different outputs often enough for these tests to
 * mean something. The real one arrives with Monocypher behind the same
 * vtable, exactly as the signer does.
 *
 * It records the last input as well as counting calls. Counting is what
 * holds "one hash, not two" for the root; RECORDING is what holds "the
 * nonce is not in there", which cannot be asked of a call count and is the
 * property that keeps two peers able to talk. */
struct stub {
	int calls;
	size_t last_in_len;
	size_t last_out_len;
	uint8_t last_in[STUB_IN_MAX];
	size_t last_in_kept;
	int refuse;
};

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	struct stub *s = (struct stub *)ctx;
	uint32_t acc = 0x9e3779b9u;

	s->calls++;
	s->last_in_len = in_len;
	s->last_out_len = out_len;
	s->last_in_kept = in_len < STUB_IN_MAX ? in_len : STUB_IN_MAX;
	memcpy(s->last_in, in, s->last_in_kept);
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

/* Does `hay` contain `needle` anywhere? Used to ask whether a nonce reached
 * an input it must not reach, which a length check alone cannot answer -- a
 * derivation that swapped 24 transcript bytes for the nonce would keep the
 * length and lose the protocol. */
static int contains(const uint8_t *hay, size_t hay_len, const uint8_t *needle, size_t needle_len)
{
	if (needle_len == 0 || hay_len < needle_len)
		return 0;

	for (size_t i = 0; i + needle_len <= hay_len; i++) {
		if (memcmp(hay + i, needle, needle_len) == 0)
			return 1;
	}
	return 0;
}

/* A nonce with a shape nothing else in these tests has, so that finding it
 * inside a hashed input means it was really put there. */
static void nonce_fill(uint8_t nonce[FZN_COMMITMENT_NONCE_LEN], uint8_t seed)
{
	for (size_t i = 0; i < FZN_COMMITMENT_NONCE_LEN; i++)
		nonce[i] = (uint8_t)(0xf0u ^ (seed * 31u) ^ (i * 7u));
}

static void test_the_root_is_one_hash_over_the_transcript(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment_key[FZN_COMMITMENT_KEY_LEN];
	static const uint8_t transcript[64] = { 1, 2, 3 };

	/* The claim the whole construction rests on: the AEAD key and the
	 * commitment key come from a single hash over a single input. Two calls
	 * would mean the commitment key accompanies the AEAD key rather than
	 * being bound to it, and a second key matching a given commitment would
	 * stop being a second-preimage problem. */
	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive_root(&ops, transcript, sizeof(transcript), key,
	                                 commitment_key) == FZN_COMMITMENT_OK,
	      "root derivation failed");
	CHECK(s.calls == 1, "hashed %d times, wanted exactly 1", s.calls);
	CHECK(s.last_out_len == FZN_DERIVED_LEN, "asked for %zu bytes, wanted %d", s.last_out_len,
	      FZN_DERIVED_LEN);

	/* The label is really prepended, and the input is EXACTLY label plus
	 * transcript -- no room for anything else to have been slipped in. */
	CHECK(s.last_in_len == LABEL_LEN + sizeof(transcript),
	      "hashed %zu bytes for a %zu-byte transcript, wanted %zu -- the domain label is "
	      "missing, or something else got into the root input",
	      s.last_in_len, sizeof(transcript), LABEL_LEN + sizeof(transcript));
}

static void test_the_key_never_sees_the_nonce(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment_key[FZN_COMMITMENT_KEY_LEN];
	uint8_t nonce[FZN_COMMITMENT_NONCE_LEN];
	static const uint8_t transcript[64] = { 4, 4, 4 };

	/* THE MISTAKE THIS EXISTS TO CATCH is mixing the nonce into the root as
	 * well as into the commitment, which is what somebody extending this
	 * reaches for. It does not break anything a single process can see: one
	 * host derives, seals, and its own tests pass. It breaks the protocol,
	 * because the two peers hold different nonces and would derive
	 * different keys -- and the symptom is every frame failing to open,
	 * a long way from the line that caused it.
	 *
	 * The declaration has no nonce parameter, so the mutation has to be
	 * made inside commitment.c. Asked as a length, and then as a search:
	 * a derivation that swapped 24 bytes of transcript for the nonce would
	 * keep the length. */
	nonce_fill(nonce, 1);
	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive_root(&ops, transcript, sizeof(transcript), key,
	                                 commitment_key) == FZN_COMMITMENT_OK,
	      "root derivation failed");
	CHECK(s.last_in_len == LABEL_LEN + sizeof(transcript),
	      "the root hashed %zu bytes, wanted %zu -- something beyond the label and the "
	      "transcript is in the key's input",
	      s.last_in_len, LABEL_LEN + sizeof(transcript));
	CHECK(!contains(s.last_in, s.last_in_kept, nonce, sizeof(nonce)),
	      "a nonce is inside the ROOT input -- two peers with different nonces would derive "
	      "different keys and never talk");
}

static void test_two_peers_derive_one_key(void)
{
	fzn_hash_ops_t ops_a, ops_b;
	struct stub sa, sb;
	uint8_t key_a[FZN_AEAD_KEY_LEN], ck_a[FZN_COMMITMENT_KEY_LEN];
	uint8_t key_b[FZN_AEAD_KEY_LEN], ck_b[FZN_COMMITMENT_KEY_LEN];
	uint8_t nonce_a[FZN_COMMITMENT_NONCE_LEN], nonce_b[FZN_COMMITMENT_NONCE_LEN];
	uint8_t commit_a[FZN_COMMITMENT_LEN], commit_b[FZN_COMMITMENT_LEN];
	uint8_t commit_a_at_b[FZN_COMMITMENT_LEN];
	static const uint8_t transcript[64] = { 6, 5, 4 };

	/* THE POSITIVE CONTROL FOR THE WHOLE CHANGE, and mandatory: without it
	 * "the commitments differ" is satisfied by a function returning
	 * garbage. Two peers hash one transcript, each holding its own nonce
	 * and neither having seen the other's. They must reach the same AEAD
	 * key, and each must be able to compute the OTHER's commitment from the
	 * nonce that arrived in the frame -- which is what makes the frame
	 * checkable before decryption and is what sec 4.7 step 3 needs. */
	nonce_fill(nonce_a, 2);
	nonce_fill(nonce_b, 3);
	CHECK(memcmp(nonce_a, nonce_b, sizeof(nonce_a)) != 0,
	      "the two nonces are equal, so this case proves nothing");

	ops_init(&ops_a, &sa);
	ops_init(&ops_b, &sb);
	CHECK(fzn_commitment_derive_root(&ops_a, transcript, sizeof(transcript), key_a, ck_a) ==
	              FZN_COMMITMENT_OK,
	      "peer A's root derivation failed");
	CHECK(fzn_commitment_derive_root(&ops_b, transcript, sizeof(transcript), key_b, ck_b) ==
	              FZN_COMMITMENT_OK,
	      "peer B's root derivation failed");

	CHECK(memcmp(key_a, key_b, sizeof(key_a)) == 0,
	      "two peers hashing one transcript derived DIFFERENT AEAD keys -- nothing they send "
	      "each other will ever open");
	CHECK(memcmp(ck_a, ck_b, sizeof(ck_a)) == 0,
	      "two peers hashing one transcript derived different commitment keys, so neither can "
	      "check the other's frames");

	CHECK(fzn_commitment_for_nonce(&ops_a, ck_a, nonce_a, commit_a) == FZN_COMMITMENT_OK,
	      "peer A could not commit to its own nonce");
	CHECK(fzn_commitment_for_nonce(&ops_b, ck_b, nonce_b, commit_b) == FZN_COMMITMENT_OK,
	      "peer B could not commit to its own nonce");

	/* B receives A's frame, and recomputes A's commitment from the nonce in
	 * the header. This is the receive path in two lines. */
	CHECK(fzn_commitment_for_nonce(&ops_b, ck_b, nonce_a, commit_a_at_b) == FZN_COMMITMENT_OK,
	      "peer B could not commit to peer A's nonce");
	CHECK(memcmp(commit_a, commit_a_at_b, sizeof(commit_a)) == 0,
	      "peer B derived a different commitment for peer A's own nonce, so a good frame "
	      "would be refused before decryption");
	CHECK(fzn_commitment_check(commit_a_at_b, commit_a) == FZN_COMMITMENT_OK,
	      "the constant-time check disagreed with memcmp on identical commitments");

	/* And the keys are still what they were: deriving commitments changed
	 * nothing about the key, which is the property a merged
	 * one-function-does-both design would lose. */
	CHECK(memcmp(key_a, key_b, sizeof(key_a)) == 0,
	      "the AEAD keys diverged once each peer committed to its own nonce");
}

static void test_the_same_nonce_reproduces_the_commitment(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment_key[FZN_COMMITMENT_KEY_LEN];
	uint8_t nonce[FZN_COMMITMENT_NONCE_LEN];
	uint8_t first[FZN_COMMITMENT_LEN], second[FZN_COMMITMENT_LEN];
	static const uint8_t transcript[64] = { 8, 8 };

	/* The other mandatory positive control: same transcript, same nonce,
	 * same commitment EXACTLY. If this fails nothing downstream is
	 * checkable at all -- a receiver would refuse every honest frame -- and
	 * "the commitments differ" below would be satisfied by noise. */
	nonce_fill(nonce, 4);
	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive_root(&ops, transcript, sizeof(transcript), key,
	                                 commitment_key) == FZN_COMMITMENT_OK,
	      "root derivation failed");
	CHECK(fzn_commitment_for_nonce(&ops, commitment_key, nonce, first) == FZN_COMMITMENT_OK,
	      "first commitment failed");
	CHECK(fzn_commitment_for_nonce(&ops, commitment_key, nonce, second) == FZN_COMMITMENT_OK,
	      "second commitment failed");
	CHECK(memcmp(first, second, sizeof(first)) == 0,
	      "one commitment key and one nonce gave two different commitments -- nothing is "
	      "checkable");
}

static void test_the_nonce_makes_the_commitment_unlinkable(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment_key[FZN_COMMITMENT_KEY_LEN];
	uint8_t nonce[FZN_COMMITMENT_NONCE_LEN];
	uint8_t seen[8][FZN_COMMITMENT_LEN];
	static const uint8_t transcript[64] = { 9, 9, 9 };

	/* THE FINDING, asserted directly. One pair, one transcript, one key,
	 * eight frames: eight DIFFERENT commitments. When the commitment was
	 * derived from the transcript alone these were eight copies of one
	 * 16-byte value, in the clear, beside `sender[32]` -- a per-pair
	 * identifier on every datagram, which is the social graph for anyone on
	 * the path, relays included.
	 *
	 * Pairwise rather than adjacent: a derivation that alternated between
	 * two answers would pass a check that only compared neighbours. */
	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive_root(&ops, transcript, sizeof(transcript), key,
	                                 commitment_key) == FZN_COMMITMENT_OK,
	      "root derivation failed");

	for (size_t i = 0; i < 8; i++) {
		nonce_fill(nonce, (uint8_t)(10u + i));
		CHECK(fzn_commitment_for_nonce(&ops, commitment_key, nonce, seen[i]) ==
		              FZN_COMMITMENT_OK,
		      "commitment %zu failed", i);
	}

	for (size_t i = 0; i < 8; i++) {
		for (size_t j = i + 1; j < 8; j++) {
			CHECK(memcmp(seen[i], seen[j], FZN_COMMITMENT_LEN) != 0,
			      "frames %zu and %zu of one pair carry the SAME commitment -- it is a "
			      "per-pair constant in a cleartext header again, which is the leak "
			      "this module was rewritten to close",
			      i, j);
		}
	}
}

static void test_the_per_frame_hash_reads_label_key_and_nonce(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment_key[FZN_COMMITMENT_KEY_LEN];
	uint8_t nonce[FZN_COMMITMENT_NONCE_LEN], commitment[FZN_COMMITMENT_LEN];
	static const uint8_t transcript[64] = { 11 };
	const size_t want = LABEL_LEN + FZN_COMMITMENT_KEY_LEN + FZN_COMMITMENT_NONCE_LEN;

	/* The shape of the per-frame input, stated as a length and as a search.
	 * The length catches material added or dropped -- including the label,
	 * whose absence is what test_the_labels_cannot_collide then makes
	 * dangerous. The search catches a nonce replaced by padding of the same
	 * size, which the length cannot see and which would restore the
	 * per-pair constant exactly. */
	nonce_fill(nonce, 5);
	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive_root(&ops, transcript, sizeof(transcript), key,
	                                 commitment_key) == FZN_COMMITMENT_OK,
	      "root derivation failed");

	ops_init(&ops, &s);
	CHECK(fzn_commitment_for_nonce(&ops, commitment_key, nonce, commitment) ==
	              FZN_COMMITMENT_OK,
	      "commitment failed");
	CHECK(s.calls == 1, "the per-frame derivation hashed %d times, wanted exactly 1", s.calls);
	CHECK(s.last_out_len == FZN_COMMITMENT_LEN, "asked for %zu bytes, wanted %d",
	      s.last_out_len, FZN_COMMITMENT_LEN);
	CHECK(s.last_in_len == want, "the per-frame derivation hashed %zu bytes, wanted %zu",
	      s.last_in_len, want);
	CHECK(contains(s.last_in, s.last_in_kept, nonce, sizeof(nonce)),
	      "the NONCE is not in the per-frame input -- the commitment is a constant per pair "
	      "again");
	CHECK(contains(s.last_in, s.last_in_kept, commitment_key, FZN_COMMITMENT_KEY_LEN),
	      "the commitment key is not in the per-frame input, so the commitment binds no key");
}

static void test_the_labels_cannot_collide(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment_key[FZN_COMMITMENT_KEY_LEN];
	uint8_t nonce[FZN_COMMITMENT_NONCE_LEN], commitment[FZN_COMMITMENT_LEN];
	uint8_t key_again[FZN_AEAD_KEY_LEN], ck_again[FZN_COMMITMENT_KEY_LEN];
	uint8_t forged[FZN_COMMITMENT_KEY_LEN + FZN_COMMITMENT_NONCE_LEN];
	static const uint8_t transcript[64] = { 12 };

	/* WHAT THE LABELS PREVENT, built rather than described. Strip them and
	 * the root hashes `transcript` while the per-frame hash hashes
	 * `commitment_key | nonce`. Those are both just bytes, so a peer
	 * persuaded to use a transcript equal to some pair's commitment key and
	 * nonce derives an AEAD KEY whose first 16 bytes are exactly that
	 * pair's published commitment -- the cleartext header publishing key
	 * material, which is the worst way to get this wrong.
	 *
	 * Two distinct labels of one length, both at offset zero, make the two
	 * input spaces disjoint and the collision unreachable. This case goes
	 * red if either label is removed, and equally if they are made equal.
	 *
	 * It needs the stub hash to be the same function for both derivations,
	 * which it is -- that is the point: the labels do the separating, not
	 * the primitive. */
	nonce_fill(nonce, 6);
	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive_root(&ops, transcript, sizeof(transcript), key,
	                                 commitment_key) == FZN_COMMITMENT_OK,
	      "root derivation failed");
	CHECK(fzn_commitment_for_nonce(&ops, commitment_key, nonce, commitment) ==
	              FZN_COMMITMENT_OK,
	      "commitment failed");

	memcpy(forged, commitment_key, FZN_COMMITMENT_KEY_LEN);
	memcpy(forged + FZN_COMMITMENT_KEY_LEN, nonce, FZN_COMMITMENT_NONCE_LEN);

	CHECK(fzn_commitment_derive_root(&ops, forged, sizeof(forged), key_again, ck_again) ==
	              FZN_COMMITMENT_OK,
	      "derivation over the crafted transcript failed");
	CHECK(memcmp(key_again, commitment, FZN_COMMITMENT_LEN) != 0,
	      "a transcript of `commitment key | nonce` derived an AEAD key beginning with that "
	      "pair's published commitment -- the two derivations are hashing the same bytes, so "
	      "a domain label is missing or the two are the same label");
}

static void test_a_changed_transcript_changes_both(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key_a[FZN_AEAD_KEY_LEN], ck_a[FZN_COMMITMENT_KEY_LEN];
	uint8_t key_b[FZN_AEAD_KEY_LEN], ck_b[FZN_COMMITMENT_KEY_LEN];
	uint8_t commit_a[FZN_COMMITMENT_LEN], commit_b[FZN_COMMITMENT_LEN];
	uint8_t nonce[FZN_COMMITMENT_NONCE_LEN];
	uint8_t transcript[64];

	/* If one bit of the key material moved and the commitment did not, the
	 * commitment would not be binding the key. Held with the nonce FIXED,
	 * so the only thing that moved is the transcript -- otherwise the
	 * commitment changing would prove nothing about binding. */
	memset(transcript, 0xa5, sizeof(transcript));
	nonce_fill(nonce, 7);

	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive_root(&ops, transcript, sizeof(transcript), key_a, ck_a) ==
	              FZN_COMMITMENT_OK,
	      "first derivation failed");
	CHECK(fzn_commitment_for_nonce(&ops, ck_a, nonce, commit_a) == FZN_COMMITMENT_OK,
	      "first commitment failed");

	transcript[31] ^= 0x01;
	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive_root(&ops, transcript, sizeof(transcript), key_b, ck_b) ==
	              FZN_COMMITMENT_OK,
	      "second derivation failed");
	CHECK(fzn_commitment_for_nonce(&ops, ck_b, nonce, commit_b) == FZN_COMMITMENT_OK,
	      "second commitment failed");

	CHECK(memcmp(key_a, key_b, sizeof(key_a)) != 0,
	      "one bit of transcript left the key unchanged");
	CHECK(memcmp(ck_a, ck_b, sizeof(ck_a)) != 0,
	      "one bit of transcript left the COMMITMENT KEY unchanged");
	CHECK(memcmp(commit_a, commit_b, sizeof(commit_a)) != 0,
	      "one bit of transcript left the COMMITMENT unchanged at a fixed nonce -- it is not "
	      "binding the key");
}

static void test_no_output_carries_key_material(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment_key[FZN_COMMITMENT_KEY_LEN];
	uint8_t nonce[FZN_COMMITMENT_NONCE_LEN], commitment[FZN_COMMITMENT_LEN];
	static const uint8_t transcript[64] = { 7 };

	/* The commitment travels in the clear, so it must not be a slice of
	 * anything secret. Publishing bytes of the AEAD key in the frame header
	 * would be the worst possible way to get this wrong, and it would still
	 * pass a test that only checked the commitment matched. The commitment
	 * key is checked too, because it is now the material the commitment is
	 * an image of, and an implementation that returned a prefix of it
	 * instead of hashing would look perfectly correct from outside. */
	nonce_fill(nonce, 8);
	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive_root(&ops, transcript, sizeof(transcript), key,
	                                 commitment_key) == FZN_COMMITMENT_OK,
	      "root derivation failed");
	CHECK(fzn_commitment_for_nonce(&ops, commitment_key, nonce, commitment) ==
	              FZN_COMMITMENT_OK,
	      "commitment failed");

	for (size_t i = 0; i + FZN_COMMITMENT_LEN <= FZN_AEAD_KEY_LEN; i++) {
		CHECK(memcmp(key + i, commitment, FZN_COMMITMENT_LEN) != 0,
		      "the commitment appears inside the AEAD key at offset %zu -- the frame "
		      "would publish key material",
		      i);
	}
	for (size_t i = 0; i + FZN_COMMITMENT_LEN <= FZN_COMMITMENT_KEY_LEN; i++) {
		CHECK(memcmp(commitment_key + i, commitment, FZN_COMMITMENT_LEN) != 0,
		      "the commitment appears inside the COMMITMENT KEY at offset %zu -- the "
		      "frame would publish the long-lived material it is derived from",
		      i);
	}
	CHECK(memcmp(key, commitment_key, FZN_COMMITMENT_KEY_LEN) != 0,
	      "the AEAD key and the commitment key are the same bytes, so committing to one "
	      "commits to the other");
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
	uint8_t key[FZN_AEAD_KEY_LEN], commitment_key[FZN_COMMITMENT_KEY_LEN];
	uint8_t key_before[FZN_AEAD_KEY_LEN], ck_before[FZN_COMMITMENT_KEY_LEN];
	uint8_t nonce[FZN_COMMITMENT_NONCE_LEN];
	uint8_t commitment[FZN_COMMITMENT_LEN], commit_before[FZN_COMMITMENT_LEN];
	static const uint8_t transcript[64] = { 3 };

	/* Half a key is worse than no key: a caller that ignored the error
	 * would encrypt under whatever was in the buffer. The same holds for a
	 * half-written commitment, which would go into a frame header and be
	 * refused by a peer who is behaving correctly. */
	memset(key, 0xcd, sizeof(key));
	memset(commitment_key, 0xcd, sizeof(commitment_key));
	memcpy(key_before, key, sizeof(key));
	memcpy(ck_before, commitment_key, sizeof(commitment_key));

	ops_init(&ops, &s);
	s.refuse = 1;
	CHECK(fzn_commitment_derive_root(&ops, transcript, sizeof(transcript), key,
	                                 commitment_key) == FZN_COMMITMENT_ERR_HASH,
	      "a refusing hash was reported as success");
	CHECK(memcmp(key, key_before, sizeof(key)) == 0, "a refused derivation wrote a key");
	CHECK(memcmp(commitment_key, ck_before, sizeof(commitment_key)) == 0,
	      "a refused derivation wrote a commitment key");

	nonce_fill(nonce, 9);
	memset(commitment, 0xcd, sizeof(commitment));
	memcpy(commit_before, commitment, sizeof(commitment));
	ops_init(&ops, &s);
	s.refuse = 1;
	CHECK(fzn_commitment_for_nonce(&ops, ck_before, nonce, commitment) ==
	              FZN_COMMITMENT_ERR_HASH,
	      "a refusing hash was reported as success by the per-frame derivation");
	CHECK(memcmp(commitment, commit_before, sizeof(commitment)) == 0,
	      "a refused per-frame derivation wrote a commitment");
}

static void test_bad_arguments(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment_key[FZN_COMMITMENT_KEY_LEN];
	uint8_t nonce[FZN_COMMITMENT_NONCE_LEN], commitment[FZN_COMMITMENT_LEN];
	static const uint8_t transcript[64] = { 5 };
	static const uint8_t huge[1] = { 0 };

	nonce_fill(nonce, 10);
	memset(commitment_key, 0x77, sizeof(commitment_key));

	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive_root(NULL, transcript, sizeof(transcript), key,
	                                 commitment_key) == FZN_COMMITMENT_ERR_MALFORMED,
	      "null ops accepted");
	CHECK(fzn_commitment_derive_root(&ops, NULL, 8, key, commitment_key) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "null transcript accepted");
	CHECK(fzn_commitment_derive_root(&ops, transcript, 0, key, commitment_key) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "an empty transcript was hashed");
	CHECK(fzn_commitment_derive_root(&ops, huge, 100000, key, commitment_key) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "a transcript past the bound was hashed, overrunning the buffer");
	CHECK(fzn_commitment_derive_root(&ops, transcript, sizeof(transcript), NULL,
	                                 commitment_key) == FZN_COMMITMENT_ERR_MALFORMED,
	      "null key output accepted");
	CHECK(fzn_commitment_derive_root(&ops, transcript, sizeof(transcript), key, NULL) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "null commitment key output accepted");

	CHECK(fzn_commitment_for_nonce(NULL, commitment_key, nonce, commitment) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "null ops accepted by the per-frame derivation");
	CHECK(fzn_commitment_for_nonce(&ops, NULL, nonce, commitment) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "null commitment key accepted");
	CHECK(fzn_commitment_for_nonce(&ops, commitment_key, NULL, commitment) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "NULL NONCE ACCEPTED -- the one argument whose absence would restore the leak");
	CHECK(fzn_commitment_for_nonce(&ops, commitment_key, nonce, NULL) ==
	              FZN_COMMITMENT_ERR_MALFORMED,
	      "null commitment output accepted");

	CHECK(s.calls == 0, "hashed %d times for arguments it had already refused", s.calls);

	{
		fzn_hash_ops_t no_fn = { NULL, NULL };
		CHECK(fzn_commitment_derive_root(&no_fn, transcript, sizeof(transcript), key,
		                                 commitment_key) == FZN_COMMITMENT_ERR_MALFORMED,
		      "ops with a null hash function accepted");
		CHECK(fzn_commitment_for_nonce(&no_fn, commitment_key, nonce, commitment) ==
		              FZN_COMMITMENT_ERR_MALFORMED,
		      "ops with a null hash function accepted by the per-frame derivation");
	}
}

/* The positive control: most cases above assert a refusal or a difference,
 * and a derive that always failed would satisfy them. */
static void test_the_suite_can_tell_pass_from_fail(void)
{
	fzn_hash_ops_t ops;
	struct stub s;
	uint8_t key[FZN_AEAD_KEY_LEN], commitment_key[FZN_COMMITMENT_KEY_LEN];
	uint8_t nonce[FZN_COMMITMENT_NONCE_LEN], commitment[FZN_COMMITMENT_LEN];
	static const uint8_t transcript[64] = { 9 };

	nonce_fill(nonce, 11);
	ops_init(&ops, &s);
	CHECK(fzn_commitment_derive_root(&ops, transcript, sizeof(transcript), key,
	                                 commitment_key) == FZN_COMMITMENT_OK,
	      "the positive control fails, so every refusal above proves nothing");
	CHECK(fzn_commitment_for_nonce(&ops, commitment_key, nonce, commitment) ==
	              FZN_COMMITMENT_OK,
	      "the per-frame positive control fails, so every difference above proves nothing");
}

int main(void)
{
	test_the_root_is_one_hash_over_the_transcript();
	test_the_key_never_sees_the_nonce();
	test_two_peers_derive_one_key();
	test_the_same_nonce_reproduces_the_commitment();
	test_the_nonce_makes_the_commitment_unlinkable();
	test_the_per_frame_hash_reads_label_key_and_nonce();
	test_the_labels_cannot_collide();
	test_a_changed_transcript_changes_both();
	test_no_output_carries_key_material();
	test_check_is_a_real_comparison();
	test_a_refused_hash_writes_nothing();
	test_bad_arguments();
	test_the_suite_can_tell_pass_from_fail();

	printf("commitment_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
