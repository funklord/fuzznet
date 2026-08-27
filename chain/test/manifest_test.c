/* Tests for chain/manifest.c: the manifest's canonical encoding, following an
 * issuer, admitting a manifest, and the deficit table it fills.
 *
 * STAGE 1 OF project.md sec 13d, AND THE ABSENCE OF A GATE IS PART OF WHAT IS
 * TESTED. Nothing here refuses a chain and nothing here should: the whole
 * point of the split is that a host can SAY what it is missing before anybody
 * decides what to do about it. `fzn_chain_verify` is untouched, and the one
 * case below that reaches it asserts that a full deficit table changes its
 * answer not at all.
 *
 * THE STUB ANSWERS OVER THE MESSAGE, for the reason chain/test/chain_test.c
 * and revocation_test.c give at length: a verifier whose verdict does not
 * depend on the bytes makes "this field is inside the signed range" a
 * question with no observable answer. It also records WHICH KEY it was given,
 * because a manifest verified under anything but its own issuer field stops
 * being that key's statement about itself, and the return code cannot tell
 * the two apart.
 */

#include "../manifest.h"

/* THE TETHER, and it is the only reason this file reaches outside `chain/`.
 *
 * FZN_MANIFEST_MAX_PAIRS is arithmetic against the largest message this
 * library will reassemble, and `chain/` must not include `chunk/` -- that
 * independence is why sec 13d chose to name the pair rather than hash the
 * triple. So the constant is repeated in manifest.h and checked here, which
 * is the arrangement `chunk/split.h` uses for FZN_SPLIT_MAX_PAYLOAD against
 * the generated schema and `record/test/record_test.c` for FZN_RECORD_MAX_LEN
 * against the payload ceiling. The tether is `make test`, not `make`. */
#include "../../chunk/reassembly.h"
#include "../../chunk/split.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define FZN_REASSEMBLED_MAX ((size_t)FZN_SPLIT_MAX_PAYLOAD * (size_t)FZN_REASM_MAX_CHUNKS)

_Static_assert(FZN_MANIFEST_LEN(FZN_MANIFEST_MAX_PAIRS) <= FZN_REASSEMBLED_MAX,
                "the largest manifest does not fit the largest message reassembly will take");
_Static_assert(FZN_MANIFEST_LEN(FZN_MANIFEST_MAX_PAIRS + 1u) > FZN_REASSEMBLED_MAX,
                "FZN_MANIFEST_MAX_PAIRS is below the ceiling, so it is not the ceiling");

/* And the single-frame figure, which is the number a consumer feels. */
_Static_assert(FZN_MANIFEST_LEN(14) <= FZN_SPLIT_MAX_PAYLOAD,
                "fourteen pairs no longer fit one frame");
_Static_assert(FZN_MANIFEST_LEN(15) > FZN_SPLIT_MAX_PAYLOAD,
                "fifteen pairs fit one frame, so the halving the pair form cost is wrong");

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
	printf("  FAIL manifest_test.c:%d: ", line);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* How many verifications this file can record the key of. */
#define MAX_KEYS_SEEN 8

/* The same toy MAC revocation_test.c uses, and the same argument for it: what
 * a test signer owes this suite is an answer that depends on every byte of
 * the message and on who signed. Identity is the key's first byte, and every
 * key here carries its seed there -- see `expand`. */
static void mac(uint8_t out[FZN_SIG_LEN], uint8_t identity, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull;

	h ^= (uint64_t)identity;
	h *= 0x100000001b3ull;
	for (size_t i = 0; i < len; i++) {
		h ^= (uint64_t)msg[i];
		h *= 0x100000001b3ull;
	}
	for (size_t i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i + 1u;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

typedef struct stub {
	int calls;
	int can_sign;
	uint8_t identity;

	/* WHICH KEY EACH VERIFICATION USED, recorded in order. A manifest
	 * verified under anything but the issuer it names is not that key's
	 * statement about itself, and the return code is identical either way
	 * -- only the key tells them apart. */
	size_t keys_seen;
	uint8_t key_seen[MAX_KEYS_SEEN][FZN_PUBKEY_LEN];

	/* THE LONGEST MESSAGE VERIFIED, which is how the signed range's END is
	 * observable. A manifest's body length depends on its count, so a
	 * signature computed over the header alone would still verify against
	 * a signer that made the same mistake -- and this suite's signer is
	 * the same function. The length is recorded so a case can assert the
	 * range covered every pair. */
	size_t last_msg_len;
} stub_t;

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	stub_t *s = (stub_t *)ctx;
	uint8_t want[FZN_SIG_LEN];

	if (!msg || msg_len == 0) {
		printf("  FAIL: verifier called with an empty signed region\n");
		failures++;
		return 0;
	}

	if (s->keys_seen < MAX_KEYS_SEEN) {
		memcpy(s->key_seen[s->keys_seen], pubkey, FZN_PUBKEY_LEN);
		s->keys_seen++;
	}
	s->calls++;
	s->last_msg_len = msg_len;

	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	stub_t *s = (stub_t *)ctx;

	if (!msg || msg_len == 0) {
		printf("  FAIL: signer called with an empty region\n");
		failures++;
		return 0;
	}
	if (!s->can_sign)
		return 0;
	mac(sig, s->identity, msg, msg_len);
	return 1;
}

/* Distinct 32-byte values, built from a single seed byte so a failure message
 * can name them. Byte 0 is the seed -- the stub derives identity from
 * `pubkey[0]` -- and every later byte varies with its position, so that a
 * length constant in the module under test is observable at all.
 *
 * Byte 0 being the seed also fixes the SORT ORDER: two values with different
 * seeds compare in seed order, which is what lets a case below build an
 * ascending pair set by naming seeds. */
static void expand(uint8_t *out, size_t len, uint8_t seed)
{
	out[0] = seed;
	for (size_t i = 1; i < len; i++)
		out[i] = (uint8_t)(seed ^ (uint8_t)i);
}

/* The same value with only its LAST byte changed -- the pair that decides a
 * comparison's LENGTH.
 *
 * project.md sec 11 carries the rule and this tree paid a day for it: values
 * that differ in their first byte cannot tell a one-byte comparison from a
 * thirty-two-byte one, and every value here shares a thirty-one byte prefix
 * with its near miss. One pair settles every truncation from one to
 * thirty-one at once. Identity is untouched, so a near miss can still be
 * signed and verified and reach the comparison under test. */
static void expand_near(uint8_t *out, size_t len, uint8_t seed)
{
	expand(out, len, seed);
	out[len - 1] = (uint8_t)(out[len - 1] ^ 0xffu);
}

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	expand(out, FZN_PUBKEY_LEN, seed);
}

static void key_near(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	expand_near(out, FZN_PUBKEY_LEN, seed);
}

static void capability_id(uint8_t out[FZN_CAP_ID_LEN], uint8_t seed)
{
	expand(out, FZN_CAP_ID_LEN, seed);
}

static void capability_id_near(uint8_t out[FZN_CAP_ID_LEN], uint8_t seed)
{
	expand_near(out, FZN_CAP_ID_LEN, seed);
}

/* The suite's own ordering, written out rather than borrowed, so that a
 * mutation of `pair_cmp` in the module under test does not silently move the
 * fixtures with it. */
static int suite_pair_cmp(const fzn_manifest_pair_t *a, const fzn_manifest_pair_t *b)
{
	int cmp = memcmp(a->capability, b->capability, FZN_CAP_ID_LEN);

	if (cmp != 0)
		return cmp;
	return memcmp(a->grantee, b->grantee, FZN_PUBKEY_LEN);
}

static void sort_pairs(fzn_manifest_pair_t *pairs, size_t n)
{
	for (size_t i = 1; i < n; i++) {
		fzn_manifest_pair_t hold = pairs[i];
		size_t j = i;

		while (j > 0 && suite_pair_cmp(&pairs[j - 1u], &hold) > 0) {
			pairs[j] = pairs[j - 1u];
			j--;
		}
		pairs[j] = hold;
	}
}

/* Lay out a manifest WITHOUT the encoder's canonicality checks, and sign it.
 *
 * `fzn_manifest_encode` refuses a pair set that is out of order, which is
 * correct and is tested -- and it means the only way to present `open` with a
 * genuinely signed non-canonical manifest is to write the bytes here. A test
 * that could not build one could not tell a refusal from an absent check. */
static size_t build_raw(uint8_t *out, uint8_t identity, const uint8_t issuer[FZN_PUBKEY_LEN],
                        const fzn_manifest_pair_t *pairs, size_t count)
{
	uint8_t *at = out + FZN_MANIFEST_OFF_PAIRS;

	out[FZN_MANIFEST_OFF_VERSION] = 1u;
	out[FZN_MANIFEST_OFF_OBJECT] = 4u;
	memcpy(out + FZN_MANIFEST_OFF_ISSUER, issuer, FZN_PUBKEY_LEN);
	fzn_put_be16(out + FZN_MANIFEST_OFF_COUNT, (uint16_t)count);
	for (size_t i = 0; i < count; i++) {
		memcpy(at, pairs[i].capability, FZN_CAP_ID_LEN);
		memcpy(at + FZN_CAP_ID_LEN, pairs[i].grantee, FZN_PUBKEY_LEN);
		at += FZN_MANIFEST_PAIR_LEN;
	}
	mac(out + FZN_MANIFEST_BODY_LEN(count), identity, out, FZN_MANIFEST_BODY_LEN(count));
	return FZN_MANIFEST_LEN(count);
}

/* Room for four pairs is what nearly every case here wants; the two that want
 * more say so. */
#define FIXTURE_PAIRS 4
#define FIXTURE_BYTES FZN_MANIFEST_LEN(FIXTURE_PAIRS)

struct fixture {
	fzn_revocation_store_t store;
	fzn_revocation_t entries[8];
	fzn_manifest_state_t manifest;
	fzn_manifest_issuer_t issuers[2];
	fzn_manifest_deficit_t deficit[4];
	uint8_t root[FZN_PUBKEY_LEN];
	stub_t stub;
	fzn_sign_ops_t sign;
};

static void fixture_init(struct fixture *f)
{
	memset(f, 0, sizeof(*f));
	fzn_revocation_store_init(&f->store, f->entries, 8);
	fzn_manifest_init(&f->manifest, f->issuers, 2, f->deficit, 4);
	key(f->root, 0);
	f->stub.can_sign = 1;
	f->sign.verify = stub_verify;
	f->sign.sign = stub_sign;
	f->sign.ctx = &f->stub;
}

static void stub_reset(stub_t *s)
{
	s->calls = 0;
	s->keys_seen = 0;
	s->last_msg_len = 0;
	memset(s->key_seen, 0, sizeof(s->key_seen));
}

static void pair_of(fzn_manifest_pair_t *p, uint8_t cap_seed, uint8_t grantee_seed)
{
	capability_id(p->capability, cap_seed);
	key(p->grantee, grantee_seed);
}

/* Put a real, signed revocation into the store, so that the manifest derived
 * from it names something. */
static void revoke(struct fixture *f, const uint8_t issuer[FZN_PUBKEY_LEN],
                   const uint8_t capability[FZN_CAP_ID_LEN],
                   const uint8_t grantee[FZN_PUBKEY_LEN])
{
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t rec;

	f->stub.identity = issuer[0];
	if (fzn_revocation_issue(issuer, capability, grantee, 1000, &f->sign, bytes) !=
	    FZN_CHAIN_OK) {
		printf("  FAIL: the fixture could not issue a revocation\n");
		failures++;
		return;
	}
	if (fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK) {
		printf("  FAIL: the fixture issued a revocation that will not open\n");
		failures++;
		return;
	}
	if (fzn_revocation_admit(&f->store, rec, issuer, &f->sign, NULL) != FZN_CHAIN_OK) {
		printf("  FAIL: the fixture's revocation was refused\n");
		failures++;
	}
	stub_reset(&f->stub);
}

/* ---- the layout ------------------------------------------------------- */

static void test_layout_and_round_trip(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES], again[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_manifest_pair_t pairs[2];
	uint8_t issuer[FZN_PUBKEY_LEN];
	size_t len = 0, again_len = 0;
	const uint8_t *at;
	size_t signed_len;

	CHECK(FZN_MANIFEST_PAIR_LEN == 64u, "a pair is %zu bytes, the table says 64",
	      FZN_MANIFEST_PAIR_LEN);
	CHECK(FZN_MANIFEST_HEADER_LEN == 36u, "the header is %u bytes, the table says 36",
	      (unsigned)FZN_MANIFEST_HEADER_LEN);
	CHECK(FZN_MANIFEST_MIN_LEN == 100u, "an empty manifest is %zu bytes, wanted 100",
	      FZN_MANIFEST_MIN_LEN);
	CHECK(FZN_MANIFEST_LEN(14) == 996u, "fourteen pairs is %zu bytes, wanted 996",
	      FZN_MANIFEST_LEN(14));
	CHECK(FZN_MANIFEST_LEN(15) == 1060u, "fifteen pairs is %zu bytes, wanted 1060",
	      FZN_MANIFEST_LEN(15));

	fixture_init(&f);
	key(issuer, 0);
	pair_of(&pairs[0], 0x10, 5);
	pair_of(&pairs[1], 0x20, 6);

	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, pairs, 2, &len) ==
	              FZN_MANIFEST_OK,
	      "encoding a two-pair manifest failed");
	CHECK(len == FZN_MANIFEST_LEN(2), "encoded %zu bytes, wanted %zu", len,
	      FZN_MANIFEST_LEN(2));
	CHECK(bytes[FZN_MANIFEST_OFF_VERSION] == 1u, "version byte is %u, wanted 1",
	      bytes[FZN_MANIFEST_OFF_VERSION]);
	CHECK(bytes[FZN_MANIFEST_OFF_OBJECT] == 4u,
	      "object byte is %u, wanted FZN_OBJECT_MANIFEST", bytes[FZN_MANIFEST_OFF_OBJECT]);
	/* Big-endian, spelled out rather than only round-tripped through this
	 * library's own accessors -- which would pass just as happily on bytes
	 * nobody else can read. */
	CHECK(bytes[FZN_MANIFEST_OFF_COUNT] == 0x00u && bytes[FZN_MANIFEST_OFF_COUNT + 1u] == 2u,
	      "count is not big-endian");

	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");
	CHECK(fzn_manifest_count(rec) == 2, "count reads back as %zu", fzn_manifest_count(rec));
	CHECK(fzn_ct_memeq(fzn_manifest_issuer(rec), issuer, FZN_PUBKEY_LEN),
	      "issuer did not survive the round trip");
	CHECK(fzn_ct_memeq(fzn_manifest_capability(rec, 0), pairs[0].capability, FZN_CAP_ID_LEN) &&
	              fzn_ct_memeq(fzn_manifest_grantee(rec, 0), pairs[0].grantee,
	                           FZN_PUBKEY_LEN),
	      "pair 0 did not survive the round trip");
	CHECK(fzn_ct_memeq(fzn_manifest_capability(rec, 1), pairs[1].capability, FZN_CAP_ID_LEN) &&
	              fzn_ct_memeq(fzn_manifest_grantee(rec, 1), pairs[1].grantee,
	                           FZN_PUBKEY_LEN),
	      "pair 1 did not survive the round trip");

	/* The signed range is the whole body and stops where the signature
	 * begins -- which for a variable-length object is the assertion that
	 * says every pair is covered rather than only the header. */
	fzn_manifest_signed_bytes(rec, &at, &signed_len);
	CHECK(at == bytes,
	      "the signed range does not begin at the manifest's first byte, so the version "
	      "and object tags are outside it and separate nothing");
	CHECK(signed_len == FZN_MANIFEST_BODY_LEN(2),
	      "the signed range is %zu bytes rather than %zu, so some pair is unprotected",
	      signed_len, FZN_MANIFEST_BODY_LEN(2));
	CHECK(fzn_manifest_signature(rec) == bytes + signed_len,
	      "the signature does not begin where the body ends");

	/* open -> re-encode reproduces the bytes, which is the half that says
	 * the accessors and the encoder describe one layout. */
	{
		fzn_manifest_pair_t read_back[2];

		for (size_t i = 0; i < 2; i++) {
			memcpy(read_back[i].capability, fzn_manifest_capability(rec, i),
			       FZN_CAP_ID_LEN);
			memcpy(read_back[i].grantee, fzn_manifest_grantee(rec, i),
			       FZN_PUBKEY_LEN);
		}
		CHECK(fzn_manifest_encode(again, sizeof(again), fzn_manifest_issuer(rec),
		                          read_back, fzn_manifest_count(rec),
		                          &again_len) == FZN_MANIFEST_OK,
		      "re-encoding from the accessors failed");
		CHECK(again_len == len && memcmp(again, bytes, FZN_MANIFEST_BODY_LEN(2)) == 0,
		      "re-encoding what the accessors read did not reproduce the signed bytes");
	}
}

/* THE OBJECT TAG IS INSIDE THE SIGNED RANGE, PROVED BY CONSTRUCTION.
 *
 * evidence.md is explicit that a field inside a signed range cannot be tested
 * by mutating it on the wire: the mutation breaks the signature too, so the
 * assertion passes with the decoder's own check deleted entirely and the
 * rejection comes from the signature either way. What separates the two is
 * construction -- the encoder writes the tag into the transcript, so the same
 * body under a different tag must produce a DIFFERENT signature. If the tag
 * were outside the range the two would be identical and a signature made over
 * a revocation would verify as a manifest. */
static void test_the_object_tag_is_in_the_transcript(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	uint8_t as_manifest[FZN_SIG_LEN], as_revocation[FZN_SIG_LEN];
	fzn_manifest_pair_t pairs[1];
	uint8_t issuer[FZN_PUBKEY_LEN];
	size_t len = 0;

	fixture_init(&f);
	key(issuer, 0);
	pair_of(&pairs[0], 0x10, 5);
	f.stub.identity = 0;

	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, pairs, 1, &len) ==
	              FZN_MANIFEST_OK,
	      "the control could not be encoded");
	mac(as_manifest, 0, bytes, FZN_MANIFEST_BODY_LEN(1));

	bytes[FZN_MANIFEST_OFF_OBJECT] = 2u; /* FZN_OBJECT_REVOCATION */
	mac(as_revocation, 0, bytes, FZN_MANIFEST_BODY_LEN(1));

	CHECK(memcmp(as_manifest, as_revocation, FZN_SIG_LEN) != 0,
	      "one key signing the same body under two object tags produced the same "
	      "signature, so the tag is outside the transcript and separates nothing");

	/* And a manifest of one pair is exactly the length of a record with an
	 * eight-byte body, which is why the tag has to be there. */
	CHECK(FZN_MANIFEST_LEN(1) == 164u,
	      "a one-pair manifest is %zu bytes; the collision this tag exists for was "
	      "measured at 164",
	      FZN_MANIFEST_LEN(1));
}

static void test_open_refuses_what_is_not_our_shape(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_manifest_pair_t pairs[2];
	uint8_t issuer[FZN_PUBKEY_LEN];
	size_t len = 0;

	fixture_init(&f);
	key(issuer, 0);
	pair_of(&pairs[0], 0x10, 5);
	pair_of(&pairs[1], 0x20, 6);
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, pairs, 2, &len) ==
	              FZN_MANIFEST_OK,
	      "the fixture could not encode a manifest");

	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "the positive control does not open, so every refusal below proves nothing");

	CHECK(fzn_manifest_open(bytes, len - 1u, &rec) == FZN_MANIFEST_ERR_SHAPE,
	      "a manifest one byte short was accepted");
	CHECK(fzn_manifest_open(bytes, len + 1u, &rec) == FZN_MANIFEST_ERR_SHAPE,
	      "a manifest with a trailing byte was accepted, so the length is not exact");
	CHECK(fzn_manifest_open(bytes, FZN_MANIFEST_MIN_LEN - 1u, &rec) ==
	              FZN_MANIFEST_ERR_SHAPE,
	      "a buffer too short to hold a count was accepted");

	/* AND A BUFFER TOO SHORT TO HOLD THE COUNT FIELD AT ALL, which is a
	 * different check from the one above even though both answer SHAPE.
	 *
	 * No length below FZN_MANIFEST_MIN_LEN can equal FZN_MANIFEST_LEN(n)
	 * for any n, so the exact-length test refuses every short buffer on
	 * its own -- AFTER reading two bytes at offset 34 that nobody wrote.
	 * The floor is therefore MEMORY SAFETY rather than a verdict, and
	 * deleting it leaves this suite green on a plain build. It was proved
	 * by deleting it and running `make test SANITIZE=1`, where this case
	 * reports a stack-buffer-overflow read in `fzn_manifest_open`. */
	{
		uint8_t two[2] = { 1u, 4u };

		CHECK(fzn_manifest_open(two, sizeof(two), &rec) == FZN_MANIFEST_ERR_SHAPE,
		      "a two-byte buffer was accepted as a manifest");
	}

	bytes[FZN_MANIFEST_OFF_VERSION] = 2u;
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_ERR_SHAPE,
	      "a manifest claiming version 2 was accepted");
	bytes[FZN_MANIFEST_OFF_VERSION] = 1u;

	/* THE DOMAIN SEPARATION EARNING ITS PLACE, and this is the object that
	 * makes wire/bytes.h's argument concrete: a one-pair manifest and a
	 * record with an eight-byte body are both 164 bytes, signed by the
	 * same key through the same seam. */
	bytes[FZN_MANIFEST_OFF_OBJECT] = 2u;
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_ERR_SHAPE,
	      "an otherwise valid manifest tagged as a revocation was accepted as a "
	      "manifest");
	bytes[FZN_MANIFEST_OFF_OBJECT] = 4u;
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "putting the object byte back did not restore the control");

	/* A count that disagrees with the buffer. Both directions, because a
	 * check that only refuses the larger one lets a manifest carry a pair
	 * nobody signed for. */
	fzn_put_be16(bytes + FZN_MANIFEST_OFF_COUNT, 3u);
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_ERR_SHAPE,
	      "a manifest claiming more pairs than its length holds was accepted");
	fzn_put_be16(bytes + FZN_MANIFEST_OFF_COUNT, 1u);
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_ERR_SHAPE,
	      "a manifest claiming fewer pairs than its length holds was accepted, so a "
	      "pair rode along outside the signed range");
	fzn_put_be16(bytes + FZN_MANIFEST_OFF_COUNT, 2u);

	CHECK(fzn_manifest_open(NULL, len, &rec) == FZN_MANIFEST_ERR_MALFORMED, "null bytes");
	CHECK(fzn_manifest_open(bytes, len, NULL) == FZN_MANIFEST_ERR_MALFORMED, "null out");

	/* count = 0 IS A REAL STATEMENT. A key that has revoked nothing must
	 * be able to say so, or "I have revoked nothing" and "I am not talking
	 * to you" become the same message. */
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, NULL, 0, &len) ==
	              FZN_MANIFEST_OK,
	      "an empty manifest could not be encoded");
	CHECK(len == FZN_MANIFEST_MIN_LEN, "an empty manifest is %zu bytes", len);
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "an empty manifest was refused");
	CHECK(fzn_manifest_count(rec) == 0, "an empty manifest reports %zu pairs",
	      fzn_manifest_count(rec));
}

/* THE PAIR CEILING, WHICH IS THE ONLY CHECK THAT NEEDS A REAL BUFFER.
 *
 * `count > FZN_MANIFEST_MAX_PAIRS` and `len != FZN_MANIFEST_LEN(count)` both
 * answer SHAPE, so a small over-count is refused by whichever runs first and
 * the two are indistinguishable. The only input that tells them apart is one
 * where the length AGREES with an over-large count -- which is 262180 bytes,
 * and is why this case carries a quarter-megabyte of static and the others do
 * not.
 *
 * Both sides are asserted. The refusal at 4095 means nothing without 4094
 * opening, and 4094 opening is also the assertion that the largest manifest
 * this library will carry is one it will actually read. */
static uint8_t huge[FZN_MANIFEST_LEN(FZN_MANIFEST_MAX_PAIRS + 1u)];

static void test_the_pair_ceiling_is_a_ceiling(void)
{
	fzn_manifest_record_t rec;
	uint8_t issuer[FZN_PUBKEY_LEN];

	key(issuer, 0);
	memset(huge, 0, sizeof(huge));
	huge[FZN_MANIFEST_OFF_VERSION] = 1u;
	huge[FZN_MANIFEST_OFF_OBJECT] = 4u;
	memcpy(huge + FZN_MANIFEST_OFF_ISSUER, issuer, FZN_PUBKEY_LEN);

	/* Ascending by construction, so the ordering check cannot be what
	 * refuses either case. */
	for (size_t i = 0; i <= FZN_MANIFEST_MAX_PAIRS; i++)
		fzn_put_be32(huge + FZN_MANIFEST_OFF_PAIRS + FZN_MANIFEST_PAIR_LEN * i,
		             (uint32_t)i);

	fzn_put_be16(huge + FZN_MANIFEST_OFF_COUNT, (uint16_t)(FZN_MANIFEST_MAX_PAIRS + 1u));
	CHECK(fzn_manifest_open(huge, FZN_MANIFEST_LEN(FZN_MANIFEST_MAX_PAIRS + 1u), &rec) ==
	              FZN_MANIFEST_ERR_SHAPE,
	      "a manifest of %u pairs, whose length agrees with its count, was accepted -- "
	      "so the ceiling is not enforced and a peer sets the work",
	      (unsigned)FZN_MANIFEST_MAX_PAIRS + 1u);

	fzn_put_be16(huge + FZN_MANIFEST_OFF_COUNT, (uint16_t)FZN_MANIFEST_MAX_PAIRS);
	/* The count is read only if the open succeeded. An accessor over a
	 * view `open` refused is undefined -- manifest.h says so -- and a
	 * control that dereferences one turns a failed control into a crash,
	 * which is a failure nobody can read a name off. */
	if (fzn_manifest_open(huge, FZN_MANIFEST_LEN(FZN_MANIFEST_MAX_PAIRS), &rec) ==
	    FZN_MANIFEST_OK) {
		CHECK(fzn_manifest_count(rec) == FZN_MANIFEST_MAX_PAIRS,
		      "a full manifest reports %zu pairs", fzn_manifest_count(rec));
	} else {
		CHECK(0,
		      "the largest manifest this library will carry does not open, so the "
		      "refusal above proves nothing");
	}
}

/* PAIRS ASCENDING AND DUPLICATE-FREE, AND THE NEAR MISS IS WHAT DECIDES IT.
 *
 * One set must have one encoding or the determinism the absent timestamp buys
 * evaporates; it also refuses a manifest padded to inflate its transfer, and
 * makes a merge a merge-sort rather than a quadratic scan.
 *
 * THE ASCENDING CASE IS THE ONE THAT DISCRIMINATES, and getting that round
 * the right way took thinking about. A DESCENDING near-miss pair is refused
 * by a full comparison (out of order) and by a truncated one (equal, so a
 * duplicate) alike -- the test passes either way and proves nothing. An
 * ASCENDING near-miss pair must be ACCEPTED, and a truncated comparison sees
 * two equal pairs and refuses it. So the positive is the probe here and the
 * negatives are its controls. */
static void test_the_ordering_reads_the_whole_pair(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_manifest_pair_t pairs[2], swapped[2];
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint8_t cap[FZN_CAP_ID_LEN], near_cap[FZN_CAP_ID_LEN];
	uint8_t grantee[FZN_PUBKEY_LEN], near_grantee[FZN_PUBKEY_LEN];
	size_t len;

	fixture_init(&f);
	key(issuer, 0);
	capability_id(cap, 0x10);
	capability_id_near(near_cap, 0x10);
	key(grantee, 5);
	key_near(near_grantee, 5);

	/* THE FIXTURE PROPERTY, ASSERTED FIRST. Everything below is worthless
	 * if the two values differ anywhere a short comparison would reach. */
	CHECK(memcmp(cap, near_cap, FZN_CAP_ID_LEN - 1u) == 0 &&
	              cap[FZN_CAP_ID_LEN - 1u] != near_cap[FZN_CAP_ID_LEN - 1u],
	      "the two capabilities do not agree on every byte but the last, so they do "
	      "not decide a comparison's length");
	CHECK(memcmp(grantee, near_grantee, FZN_PUBKEY_LEN - 1u) == 0 &&
	              grantee[FZN_PUBKEY_LEN - 1u] != near_grantee[FZN_PUBKEY_LEN - 1u],
	      "the two grantees do not agree on every byte but the last");

	/* TWO GRANTEES UNDER ONE CAPABILITY, differing only in the last byte.
	 * Sorted, so the manifest is canonical and must be accepted. */
	memcpy(pairs[0].capability, cap, FZN_CAP_ID_LEN);
	memcpy(pairs[0].grantee, grantee, FZN_PUBKEY_LEN);
	memcpy(pairs[1].capability, cap, FZN_CAP_ID_LEN);
	memcpy(pairs[1].grantee, near_grantee, FZN_PUBKEY_LEN);
	sort_pairs(pairs, 2);

	f.stub.identity = 0;
	len = build_raw(bytes, 0, issuer, pairs, 2);
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "two GRANTEES differing only in their last byte were refused as one pair "
	      "repeated: the ordering comparison reads a prefix, so a manifest naming two "
	      "hosts cannot be expressed");

	/* And the same two the wrong way round must be refused, or the check
	 * above is satisfied by a module that does not order anything. */
	swapped[0] = pairs[1];
	swapped[1] = pairs[0];
	len = build_raw(bytes, 0, issuer, swapped, 2);
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_ERR_SHAPE,
	      "a descending pair set was accepted, so one set has many encodings");

	/* TWO CAPABILITIES UNDER ONE GRANTEE, the same way round. */
	memcpy(pairs[0].capability, cap, FZN_CAP_ID_LEN);
	memcpy(pairs[0].grantee, grantee, FZN_PUBKEY_LEN);
	memcpy(pairs[1].capability, near_cap, FZN_CAP_ID_LEN);
	memcpy(pairs[1].grantee, grantee, FZN_PUBKEY_LEN);
	sort_pairs(pairs, 2);

	len = build_raw(bytes, 0, issuer, pairs, 2);
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "two CAPABILITIES differing only in their last byte were refused as one pair "
	      "repeated");

	swapped[0] = pairs[1];
	swapped[1] = pairs[0];
	len = build_raw(bytes, 0, issuer, swapped, 2);
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_ERR_SHAPE,
	      "a descending capability pair set was accepted");

	/* AND AN EXACT DUPLICATE, which is the padding attack: an issuer that
	 * may repeat one pair can sign a maximally expensive statement
	 * carrying one fact. */
	pairs[1] = pairs[0];
	len = build_raw(bytes, 0, issuer, pairs, 2);
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_ERR_SHAPE,
	      "a manifest naming one pair twice was accepted");
}

static void test_encode_refuses_what_open_would(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_pair_t pairs[2];
	uint8_t issuer[FZN_PUBKEY_LEN];
	size_t len = 0;

	fixture_init(&f);
	key(issuer, 0);
	pair_of(&pairs[0], 0x20, 5);
	pair_of(&pairs[1], 0x10, 6); /* descending */

	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, pairs, 2, &len) ==
	              FZN_MANIFEST_ERR_SHAPE,
	      "the encoder produced a manifest its own parser refuses, which is a second "
	      "encoding waiting to be found by somebody else's decoder");

	pairs[1] = pairs[0];
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, pairs, 2, &len) ==
	              FZN_MANIFEST_ERR_SHAPE,
	      "the encoder produced a manifest naming one pair twice");

	/* And the ordered version goes through, so the two refusals above are
	 * about the order rather than about the call. */
	pair_of(&pairs[0], 0x10, 5);
	pair_of(&pairs[1], 0x20, 6);
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, pairs, 2, &len) ==
	              FZN_MANIFEST_OK,
	      "an ordered pair set was refused, so the control fails");

	CHECK(fzn_manifest_encode(bytes, FZN_MANIFEST_LEN(2) - 1u, issuer, pairs, 2, &len) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "encoding into a buffer one byte short was accepted");
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, pairs,
	                          (size_t)FZN_MANIFEST_MAX_PAIRS + 1u,
	                          &len) == FZN_MANIFEST_ERR_SHAPE,
	      "encoding past the pair ceiling was accepted");
	CHECK(fzn_manifest_encode(NULL, sizeof(bytes), issuer, pairs, 2, &len) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "encoding into a null buffer");
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), NULL, pairs, 2, &len) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "encoding with a null issuer");
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, NULL, 2, &len) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "encoding a nonzero count from a null pair array");
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, pairs, 2, NULL) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "encoding with nowhere to report the length");
}

/* ---- issuing, which is the half an honest implementation cannot lie in -- */

static void test_issue_derives_from_the_issuers_own_store(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	uint8_t other[FZN_PUBKEY_LEN];
	uint8_t cap_a[FZN_CAP_ID_LEN], cap_b[FZN_CAP_ID_LEN], cap_c[FZN_CAP_ID_LEN];
	uint8_t g5[FZN_PUBKEY_LEN], g6[FZN_PUBKEY_LEN];
	size_t len = 0;

	fixture_init(&f);
	key(other, 7);
	capability_id(cap_a, 0x10);
	capability_id(cap_b, 0x20);
	capability_id(cap_c, 0x30);
	key(g5, 5);
	key(g6, 6);

	/* Inserted out of order on purpose: the manifest's order is the
	 * canonical one, not the store's. */
	revoke(&f, f.root, cap_c, g5);
	revoke(&f, f.root, cap_a, g6);
	revoke(&f, f.root, cap_b, g5);
	/* And one from a different issuer, which must not appear: a manifest
	 * is a statement about what THAT key has issued. */
	revoke(&f, other, cap_a, g5);
	CHECK(f.store.used == 4, "the fixture stored %zu revocations, wanted 4", f.store.used);

	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "issuing a manifest from the store failed");
	CHECK(len == FZN_MANIFEST_LEN(3), "issued %zu bytes, wanted %zu for three pairs", len,
	      FZN_MANIFEST_LEN(3));
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "the issued manifest will not open, so its pairs are not in canonical order");
	CHECK(fzn_manifest_count(rec) == 3,
	      "the manifest names %zu pairs; another issuer's revocation was included",
	      fzn_manifest_count(rec));
	CHECK(fzn_ct_memeq(fzn_manifest_capability(rec, 0), cap_a, FZN_CAP_ID_LEN) &&
	              fzn_ct_memeq(fzn_manifest_capability(rec, 1), cap_b, FZN_CAP_ID_LEN) &&
	              fzn_ct_memeq(fzn_manifest_capability(rec, 2), cap_c, FZN_CAP_ID_LEN),
	      "the issued manifest is in the store's order rather than sorted");
	CHECK(fzn_ct_memeq(fzn_manifest_issuer(rec), f.root, FZN_PUBKEY_LEN),
	      "the issued manifest names somebody else as its issuer");

	/* The other issuer's own manifest names exactly its own one pair,
	 * which is the same property from the other side. */
	f.stub.identity = 7;
	CHECK(fzn_manifest_issue(other, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "issuing the other issuer's manifest failed");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");
	CHECK(fzn_manifest_count(rec) == 1,
	      "the other issuer's manifest names %zu pairs, wanted 1", fzn_manifest_count(rec));

	/* A KEY THAT HAS REVOKED NOTHING MUST BE ABLE TO SAY SO. Both spellings
	 * of "nothing": a store that holds no entry for it, and no store at
	 * all. */
	{
		uint8_t quiet[FZN_PUBKEY_LEN];

		key(quiet, 9);
		f.stub.identity = 9;
		CHECK(fzn_manifest_issue(quiet, &f.store, &f.sign, bytes, sizeof(bytes),
		                         &len) == FZN_MANIFEST_OK,
		      "a key with nothing in the store could not issue a manifest");
		CHECK(len == FZN_MANIFEST_MIN_LEN, "it is %zu bytes rather than empty", len);
		CHECK(fzn_manifest_issue(quiet, NULL, &f.sign, bytes, sizeof(bytes), &len) ==
		              FZN_MANIFEST_OK,
		      "a key with no store at all could not issue a manifest");
		CHECK(len == FZN_MANIFEST_MIN_LEN, "it is %zu bytes rather than empty", len);
	}
}

/* A CORRUPT STORE MUST NOT BECOME A SIGNED CLAIM OF INNOCENCE.
 *
 * An unreadable store yields no matching entries, and no entries is a signed
 * statement that this key has revoked nothing -- published under the issuer's
 * own signature and indistinguishable from the truth at every receiver. */
static void test_issue_refuses_a_store_it_cannot_read(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	uint8_t cap[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN];
	size_t len = 0;

	fixture_init(&f);
	capability_id(cap, 0x10);
	key(grantee, 5);
	revoke(&f, f.root, cap, grantee);

	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK && len == FZN_MANIFEST_LEN(1),
	      "the control fails, so the refusal below proves nothing");

	f.store.used = f.store.capacity + 1u;
	len = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "a corrupt store produced a signed manifest, which is this key swearing it "
	      "has revoked nothing");
	CHECK(len == 0, "a refused issue reported a length");
}

/* TWO ENCODES OF ONE SET ARE THE SAME BYTES, which is what the absent
 * `issued_at` buys and is the reason sec 13b's first answer -- the revoking
 * key is REPLICATED across a user's hosts -- costs nothing here. Two holders
 * with the same view produce identical bytes without either being told what
 * the other did. */
static void test_issuing_is_deterministic(void)
{
	struct fixture a, b;
	static uint8_t first[FIXTURE_BYTES], second[FIXTURE_BYTES];
	uint8_t cap_a[FZN_CAP_ID_LEN], cap_b[FZN_CAP_ID_LEN], cap_c[FZN_CAP_ID_LEN];
	uint8_t g5[FZN_PUBKEY_LEN], g6[FZN_PUBKEY_LEN];
	size_t first_len = 0, second_len = 0;

	capability_id(cap_a, 0x10);
	capability_id(cap_b, 0x20);
	capability_id(cap_c, 0x30);
	key(g5, 5);
	key(g6, 6);

	fixture_init(&a);
	revoke(&a, a.root, cap_a, g5);
	revoke(&a, a.root, cap_b, g6);
	revoke(&a, a.root, cap_c, g5);

	/* The same three, learned in a different order, which is what two
	 * hosts of one user actually experience. */
	fixture_init(&b);
	revoke(&b, b.root, cap_c, g5);
	revoke(&b, b.root, cap_a, g5);
	revoke(&b, b.root, cap_b, g6);

	a.stub.identity = 0;
	b.stub.identity = 0;
	CHECK(fzn_manifest_issue(a.root, &a.store, &a.sign, first, sizeof(first), &first_len) ==
	              FZN_MANIFEST_OK,
	      "the first manifest could not be issued");
	CHECK(fzn_manifest_issue(b.root, &b.store, &b.sign, second, sizeof(second),
	                         &second_len) == FZN_MANIFEST_OK,
	      "the second manifest could not be issued");

	CHECK(first_len == second_len && memcmp(first, second, first_len) == 0,
	      "two holders of one key with the same view produced different bytes, so a "
	      "manifest is not a function of the set it names");
	CHECK(first_len == FZN_MANIFEST_LEN(3), "the manifests are %zu bytes", first_len);
}

/* ---- following, which is a decision -------------------------------- */

static void test_following_is_deliberate(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	uint8_t near_root[FZN_PUBKEY_LEN], other[FZN_PUBKEY_LEN], third[FZN_PUBKEY_LEN];
	uint8_t cap[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN];
	size_t len = 0;

	fixture_init(&f);
	key_near(near_root, 0);
	key(other, 7);
	key(third, 8);
	capability_id(cap, 0x10);
	key(grantee, 5);

	revoke(&f, f.root, cap, grantee);
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "the fixture could not issue a manifest");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");
	stub_reset(&f.stub);

	/* UNFOLLOWED IS REFUSED, AND REFUSED BEFORE THE SIGNATURE. A stranger
	 * must not be able to spend a verification, and the answer must not
	 * depend on what the manifest is signed with. */
	CHECK(fzn_manifest_admit(&f.manifest, &f.store, rec, &f.sign) ==
	              FZN_MANIFEST_ERR_UNKNOWN_ISSUER,
	      "a manifest from an issuer nobody follows was admitted");
	CHECK(f.stub.calls == 0,
	      "a signature was verified for an issuer already refused, so a stranger can "
	      "spend a verification per datagram");

	/* A key one byte from a followed one is not that key. */
	CHECK(fzn_manifest_follow(&f.manifest, near_root) == FZN_MANIFEST_OK, "follow near");
	stub_reset(&f.stub);
	CHECK(fzn_manifest_admit(&f.manifest, &f.store, rec, &f.sign) ==
	              FZN_MANIFEST_ERR_UNKNOWN_ISSUER,
	      "a manifest whose issuer matches a followed key only in its first byte was "
	      "admitted");

	CHECK(fzn_manifest_follow(&f.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	stub_reset(&f.stub);
	CHECK(fzn_manifest_admit(&f.manifest, &f.store, rec, &f.sign) == FZN_MANIFEST_OK,
	      "a followed issuer's manifest was refused, so the refusals above prove "
	      "nothing");
	CHECK(f.stub.calls == 1, "verified %d times, wanted 1", f.stub.calls);

	/* VERIFIED UNDER THE RECORD'S OWN ISSUER, which the count cannot see.
	 * Verified under the grantee instead, a revoked device is asked to
	 * vouch for the statement that revokes it. */
	CHECK(f.stub.keys_seen == 1 &&
	              fzn_ct_memeq(f.stub.key_seen[0], fzn_manifest_issuer(rec),
	                           FZN_PUBKEY_LEN),
	      "the manifest was not verified under the key it names as its issuer");
	CHECK(!fzn_ct_memeq(fzn_manifest_issuer(rec), fzn_manifest_grantee(rec, 0),
	                    FZN_PUBKEY_LEN),
	      "the fixture's issuer and first grantee are the same key, so the check above "
	      "proves nothing");
	/* And the range covered every pair rather than only the header. */
	CHECK(f.stub.last_msg_len == FZN_MANIFEST_BODY_LEN(1),
	      "the verified range was %zu bytes rather than %zu, so a pair is outside it",
	      f.stub.last_msg_len, FZN_MANIFEST_BODY_LEN(1));

	/* FOLLOWING TWICE IS INERT. A consumer that re-follows on reconnect is
	 * behaving correctly. */
	CHECK(fzn_manifest_follow(&f.manifest, f.root) == FZN_MANIFEST_OK,
	      "following an issuer twice was an error");
	CHECK(f.manifest.issuer_used == 2, "following twice took a third slot: %zu used",
	      f.manifest.issuer_used);

	/* AND THE TABLE IS BOUNDED, refused rather than evicted: dropping an
	 * issuer forgets its deficit, and a forgotten deficit is a host that
	 * looks complete. */
	CHECK(fzn_manifest_follow(&f.manifest, other) == FZN_MANIFEST_ERR_FULL,
	      "a full issuer table accepted a third issuer");
	CHECK(fzn_manifest_follow(&f.manifest, third) == FZN_MANIFEST_ERR_FULL, "and a fourth");
	CHECK(fzn_manifest_overflowed(&f.manifest, f.root) == 0,
	      "a full issuer table evicted the first issuer");
}

/* ---- the deficit ------------------------------------------------------ */

static void test_the_deficit_is_what_this_host_lacks(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_manifest_pair_t want[4];
	uint8_t cap_a[FZN_CAP_ID_LEN], cap_b[FZN_CAP_ID_LEN];
	uint8_t g5[FZN_PUBKEY_LEN], g6[FZN_PUBKEY_LEN];
	size_t len = 0, dropped = 99;

	capability_id(cap_a, 0x10);
	capability_id(cap_b, 0x20);
	key(g5, 5);
	key(g6, 6);

	/* The issuer's own view: two revocations, so a two-pair manifest. */
	fixture_init(&f);
	revoke(&f, f.root, cap_a, g5);
	revoke(&f, f.root, cap_b, g6);
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "issue");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");

	/* THE FRESH JOINER: a host that knows of no revocations at all. NULL is
	 * the same answer `fzn_chain_verify` takes for "none known". */
	{
		struct fixture joiner;

		fixture_init(&joiner);
		CHECK(fzn_manifest_follow(&joiner.manifest, f.root) == FZN_MANIFEST_OK,
		      "follow");
		CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec, &joiner.sign) ==
		              FZN_MANIFEST_OK,
		      "a fresh joiner refused a manifest");
		CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 2,
		      "a host holding no revocations reports a deficit of %zu, wanted 2",
		      fzn_manifest_pending(&joiner.manifest, f.root));
		CHECK(fzn_manifest_overflowed(&joiner.manifest, f.root) == 0,
		      "a deficit that fitted was reported as under-reported");

		dropped = 99;
		CHECK(fzn_manifest_deficit(&joiner.manifest, f.root, want, 4, &dropped) == 2 &&
		              dropped == 0,
		      "the deficit report does not name both pairs");
		CHECK(fzn_ct_memeq(want[0].capability, cap_a, FZN_CAP_ID_LEN) &&
		              fzn_ct_memeq(want[1].capability, cap_b, FZN_CAP_ID_LEN),
		      "the deficit report names the wrong pairs");

		/* Admitting the same manifest again must not double it: it is
		 * a set, and hearing it twice is what carriage looks like when
		 * it works. */
		CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec, &joiner.sign) ==
		              FZN_MANIFEST_OK,
		      "the second admission was an error");
		CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 2,
		      "hearing the same manifest twice doubled the deficit to %zu",
		      fzn_manifest_pending(&joiner.manifest, f.root));

		/* A REPORT THAT DOES NOT FIT SAYS SO, which is what makes
		 * `dropped` required rather than optional. */
		dropped = 99;
		CHECK(fzn_manifest_deficit(&joiner.manifest, f.root, want, 1, &dropped) == 1 &&
		              dropped == 1,
		      "a deficit report that did not fit reported %zu dropped", dropped);
		CHECK(fzn_manifest_deficit(&joiner.manifest, f.root, want, 4, NULL) == 0,
		      "a deficit report with nowhere to say what did not fit wrote anyway");
	}

	/* AND A HOST THAT ALREADY HOLDS ONE OF THEM records only the other,
	 * which is the property that keeps this table sized by the DEFICIT
	 * rather than by the revocation history. */
	{
		struct fixture partial;

		fixture_init(&partial);
		revoke(&partial, partial.root, cap_a, g5);
		CHECK(fzn_manifest_follow(&partial.manifest, f.root) == FZN_MANIFEST_OK,
		      "follow");
		CHECK(fzn_manifest_admit(&partial.manifest, &partial.store, rec,
		                         &partial.sign) == FZN_MANIFEST_OK,
		      "admit");
		CHECK(fzn_manifest_pending(&partial.manifest, f.root) == 1,
		      "a host holding one of the two reports a deficit of %zu, wanted 1",
		      fzn_manifest_pending(&partial.manifest, f.root));
		dropped = 99;
		CHECK(fzn_manifest_deficit(&partial.manifest, f.root, want, 4, &dropped) == 1 &&
		              fzn_ct_memeq(want[0].capability, cap_b, FZN_CAP_ID_LEN),
		      "the pair this host already holds is the one it says it lacks");
	}
}

/* THE NEAR MISS THROUGH THE DEFICIT TABLE, which is a different comparison
 * from the ordering one and fails in a different direction.
 *
 * `deficit_holds` decides whether a pair is already recorded. A prefix
 * comparison reports the second of two near-miss pairs as already there and
 * DROPS it -- the host then reports a smaller deficit than it has, which is
 * the fail-open direction and the one with no alarm attached to it. */
static void test_the_deficit_reads_the_whole_field(void)
{
	struct fixture f, joiner;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	uint8_t cap[FZN_CAP_ID_LEN], near_cap[FZN_CAP_ID_LEN];
	uint8_t grantee[FZN_PUBKEY_LEN], near_grantee[FZN_PUBKEY_LEN];
	size_t len = 0;

	capability_id(cap, 0x10);
	capability_id_near(near_cap, 0x10);
	key(grantee, 5);
	key_near(near_grantee, 5);

	CHECK(memcmp(cap, near_cap, FZN_CAP_ID_LEN - 1u) == 0 &&
	              cap[FZN_CAP_ID_LEN - 1u] != near_cap[FZN_CAP_ID_LEN - 1u],
	      "the two capabilities do not share a thirty-one byte prefix");
	CHECK(memcmp(grantee, near_grantee, FZN_PUBKEY_LEN - 1u) == 0 &&
	              grantee[FZN_PUBKEY_LEN - 1u] != near_grantee[FZN_PUBKEY_LEN - 1u],
	      "the two grantees do not share a thirty-one byte prefix");

	/* Four pairs from two capabilities and two grantees, each differing
	 * from its sibling only in the last byte. */
	fixture_init(&f);
	revoke(&f, f.root, cap, grantee);
	revoke(&f, f.root, cap, near_grantee);
	revoke(&f, f.root, near_cap, grantee);
	revoke(&f, f.root, near_cap, near_grantee);
	CHECK(f.store.used == 4,
	      "the store holds %zu of four revocations that differ only in a last byte, so "
	      "the fixture cannot tell the four apart either",
	      f.store.used);

	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "issue");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "the manifest of four near-miss pairs will not open");
	CHECK(fzn_manifest_count(rec) == 4, "it names %zu pairs, wanted 4",
	      fzn_manifest_count(rec));

	fixture_init(&joiner);
	CHECK(fzn_manifest_follow(&joiner.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec, &joiner.sign) == FZN_MANIFEST_OK,
	      "admit");
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 4,
	      "the deficit holds %zu of four pairs that differ only in a last byte: a "
	      "comparison that reads a prefix reports a genuine gap as already listed and "
	      "drops it, so this host says it is missing less than it is",
	      fzn_manifest_pending(&joiner.manifest, f.root));

	/* AND SETTLING ONE SETTLES EXACTLY ONE. The same comparison decides
	 * which entry a stored revocation removes, and a prefix match there
	 * deletes a gap nobody filled. */
	{
		uint8_t rev[FZN_REVOCATION_LEN];
		fzn_revocation_record_t r;

		joiner.stub.identity = 0;
		CHECK(fzn_revocation_issue(f.root, cap, grantee, 1000, &joiner.sign, rev) ==
		              FZN_CHAIN_OK,
		      "issue");
		CHECK(fzn_revocation_open(rev, FZN_REVOCATION_LEN, &r) == FZN_CHAIN_OK, "open");
		CHECK(fzn_revocation_admit(&joiner.store, r, f.root, &joiner.sign,
		                           &joiner.manifest) == FZN_CHAIN_OK,
		      "admit");
		CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 3,
		      "one revocation settled the deficit down to %zu, wanted 3",
		      fzn_manifest_pending(&joiner.manifest, f.root));
	}
}

/* ---- the sticky flag, which is not optional --------------------------- */

/* Without it a dropped pair makes a host look MORE complete than it is -- a
 * second silent fail-open on top of the one this whole exercise exists to
 * close. sec 13d says so twice.
 *
 * Three things are asserted, and the third is the one sec 13d's wording does
 * not reach: the flag SETS when a pair is dropped, it STAYS set while there
 * is still no room, and a REPLAYED OLDER MANIFEST cannot clear it. */
static void test_the_overflow_flag_is_sticky(void)
{
	struct fixture f;
	fzn_manifest_state_t small;
	fzn_manifest_issuer_t issuers[1];
	fzn_manifest_deficit_t deficit[2];
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	uint8_t caps[4][FZN_CAP_ID_LEN];
	uint8_t grantee[FZN_PUBKEY_LEN];
	size_t len = 0, dropped = 99;
	fzn_manifest_pair_t want[4];

	key(grantee, 5);
	for (uint8_t i = 0; i < 4; i++)
		capability_id(caps[i], (uint8_t)(0x10u + i * 0x10u));

	fixture_init(&f);
	for (uint8_t i = 0; i < 4; i++)
		revoke(&f, f.root, caps[i], grantee);
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "issue");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");
	CHECK(fzn_manifest_count(rec) == 4, "the fixture manifest names %zu pairs",
	      fzn_manifest_count(rec));

	/* A host with room for two of the four. */
	CHECK(fzn_manifest_init(&small, issuers, 1, deficit, 2) == FZN_MANIFEST_OK, "init");
	CHECK(fzn_manifest_follow(&small, f.root) == FZN_MANIFEST_OK, "follow");

	CHECK(fzn_manifest_admit(&small, NULL, rec, &f.sign) == FZN_MANIFEST_ERR_DEFICIT_FULL,
	      "a manifest whose pairs did not fit was admitted without complaint");
	CHECK(small.deficit_used == 2,
	      "the table holds %zu entries; admission stopped at the pair that would not "
	      "fit instead of recording the ones that would",
	      small.deficit_used);
	CHECK(fzn_manifest_overflowed(&small, f.root) == 1,
	      "a pair was dropped and this host still reports its deficit as sound, which "
	      "makes it look MORE complete than it is");
	CHECK(fzn_manifest_pending(&small, f.root) == 2, "pending is %zu",
	      fzn_manifest_pending(&small, f.root));

	/* STICKY: re-admitting while there is still no room must not clear
	 * it. */
	CHECK(fzn_manifest_admit(&small, NULL, rec, &f.sign) == FZN_MANIFEST_ERR_DEFICIT_FULL,
	      "the second admission reported success with the table still full");
	CHECK(fzn_manifest_overflowed(&small, f.root) == 1,
	      "re-admitting the same manifest into a still-full table cleared the flag");

	/* A ROLLBACK MUST NOT CLEAR IT EITHER, and this is the case "clears
	 * only when every pair lands" does not reach on its own. Last year's
	 * manifest names a subset; every pair of it is already listed, nothing
	 * is dropped, and a host that read only that would declare itself
	 * sound with two pairs still missing. */
	{
		static uint8_t older[FIXTURE_BYTES];
		fzn_manifest_record_t old_rec;
		fzn_manifest_pair_t two[2];
		size_t old_len;

		dropped = 99;
		CHECK(fzn_manifest_deficit(&small, f.root, want, 4, &dropped) == 2 &&
		              dropped == 0,
		      "the two recorded pairs could not be read back");
		two[0] = want[0];
		two[1] = want[1];
		sort_pairs(two, 2);
		old_len = build_raw(older, 0, f.root, two, 2);
		CHECK(fzn_manifest_open(older, old_len, &old_rec) == FZN_MANIFEST_OK,
		      "the older manifest will not open");

		CHECK(fzn_manifest_admit(&small, NULL, old_rec, &f.sign) == FZN_MANIFEST_OK,
		      "an older manifest naming only pairs already listed was refused");
		CHECK(fzn_manifest_overflowed(&small, f.root) == 1,
		      "a REPLAYED OLDER MANIFEST cleared the overflow flag: this host now "
		      "reports a sound deficit while two pairs it was told about are "
		      "still missing, and a carrier needs no key to arrange it");
	}

	/* AND IT CLEARS WHEN EVERY PAIR LANDS. The two recorded gaps are
	 * settled by real revocations, which frees the slots, and the current
	 * manifest then fits. */
	{
		struct fixture side;
		uint8_t rev[FZN_REVOCATION_LEN];
		fzn_revocation_record_t r;

		fixture_init(&side);
		side.stub.identity = 0;
		for (size_t i = 0; i < 2; i++) {
			CHECK(fzn_revocation_issue(f.root, want[i].capability, want[i].grantee,
			                           1000, &side.sign, rev) == FZN_CHAIN_OK,
			      "issue");
			CHECK(fzn_revocation_open(rev, FZN_REVOCATION_LEN, &r) == FZN_CHAIN_OK,
			      "open");
			CHECK(fzn_revocation_admit(&side.store, r, f.root, &side.sign,
			                           &small) == FZN_CHAIN_OK,
			      "admit");
		}
		CHECK(small.deficit_used == 0, "the settled pairs left %zu entries behind",
		      small.deficit_used);
		CHECK(fzn_manifest_overflowed(&small, f.root) == 1,
		      "draining the table cleared the flag on its own; only a re-admission "
		      "that names everything can say the deficit is complete again");

		CHECK(fzn_manifest_admit(&small, &side.store, rec, &side.sign) ==
		              FZN_MANIFEST_OK,
		      "the full manifest still did not fit after two pairs were settled");
		CHECK(small.deficit_used == 2, "it recorded %zu of the two still missing",
		      small.deficit_used);
		CHECK(fzn_manifest_overflowed(&small, f.root) == 0,
		      "an admission in which every pair landed did not clear the flag, so "
		      "the flag can never be cleared and stops meaning anything");
	}
}

/* ---- what a corrupt store does to the question ------------------------ */

static void test_a_corrupt_store_is_refused_rather_than_believed(void)
{
	struct fixture f, joiner;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	uint8_t cap[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN];
	size_t len = 0;

	capability_id(cap, 0x10);
	key(grantee, 5);

	fixture_init(&f);
	revoke(&f, f.root, cap, grantee);
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "issue");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");

	fixture_init(&joiner);
	CHECK(fzn_manifest_follow(&joiner.manifest, f.root) == FZN_MANIFEST_OK, "follow");

	/* `fzn_revocation_covers` answers 1 -- REVOKED -- for a store it
	 * cannot scan, because denying is the safe reply to an authorization
	 * question. Read here as "we already hold this", that same 1 makes
	 * every pair look satisfied and the deficit comes out EMPTY, and this
	 * host reports itself complete. A conservative answer to one question
	 * is a wrong answer to another. */
	joiner.store.used = joiner.store.capacity + 1u;
	CHECK(fzn_manifest_admit(&joiner.manifest, &joiner.store, rec, &joiner.sign) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "a manifest was admitted against a store nobody can read");
	CHECK(joiner.manifest.deficit_used == 0, "it recorded something anyway");
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 0,
	      "a refused admission left a deficit behind");

	/* And with the store readable again the same manifest DOES record a
	 * deficit, so the refusal above is about the store and not about this
	 * manifest. */
	joiner.store.used = 0;
	CHECK(fzn_manifest_admit(&joiner.manifest, &joiner.store, rec, &joiner.sign) ==
	              FZN_MANIFEST_OK,
	      "the control fails, so the refusal above proves nothing");
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 1,
	      "the readable store recorded no deficit, so a corrupt store and an empty one "
	      "are indistinguishable here");
}

/* ---- signature reuse: one mutation per field -------------------------- */

/* Each case takes a genuinely issued manifest, rewrites ONE thing in place,
 * and leaves the signature bytes untouched -- so the only thing left that can
 * refuse is the signed range. Every case states its positive control and
 * asserts the signature was not altered. */
static void assert_signature_kept(const uint8_t *forged, const uint8_t *genuine, size_t body,
                                  const char *what)
{
	check_at(memcmp(forged + body, genuine + body, FZN_SIG_LEN) == 0, __LINE__,
	         "%s: the case altered the signature, so it is not signature reuse", what);
}

static void test_a_forged_pair_is_refused(void)
{
	struct fixture f, joiner;
	static uint8_t bytes[FIXTURE_BYTES], genuine[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	uint8_t cap[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN], victim[FZN_PUBKEY_LEN];
	size_t len = 0;

	capability_id(cap, 0x10);
	key(grantee, 5);
	key(victim, 9);

	fixture_init(&f);
	revoke(&f, f.root, cap, grantee);
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "issue");
	memcpy(genuine, bytes, len);

	fixture_init(&joiner);
	CHECK(fzn_manifest_follow(&joiner.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");
	CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec, &joiner.sign) == FZN_MANIFEST_OK,
	      "pair: the control fails, so the refusal below proves nothing");

	/* THE GRANTEE. A carrier replays a genuine manifest with the named
	 * host rewritten, and the victim's host records a deficit against a
	 * revocation nobody issued -- which, once stage 2's gate exists,
	 * refuses every chain that key appears in. */
	fixture_init(&joiner);
	CHECK(fzn_manifest_follow(&joiner.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	memcpy(bytes + FZN_MANIFEST_OFF_PAIRS + FZN_CAP_ID_LEN, victim, FZN_PUBKEY_LEN);
	assert_signature_kept(bytes, genuine, FZN_MANIFEST_BODY_LEN(1), "grantee");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");
	stub_reset(&joiner.stub);
	CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec, &joiner.sign) ==
	              FZN_MANIFEST_ERR_SIGNATURE,
	      "a GRANTEE was rewritten on a genuinely signed manifest and it was admitted: "
	      "a carrier can name any host it likes as one this issuer revoked");
	CHECK(joiner.stub.calls == 1, "grantee: refused before the signature was reached");
	CHECK(joiner.manifest.deficit_used == 0, "grantee: the forged pair was recorded");

	/* THE CAPABILITY, on the same argument. */
	memcpy(bytes, genuine, len);
	capability_id(bytes + FZN_MANIFEST_OFF_PAIRS, 0xff);
	assert_signature_kept(bytes, genuine, FZN_MANIFEST_BODY_LEN(1), "capability");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");
	stub_reset(&joiner.stub);
	CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec, &joiner.sign) ==
	              FZN_MANIFEST_ERR_SIGNATURE,
	      "a CAPABILITY was rewritten on a genuinely signed manifest and it was "
	      "admitted");
	CHECK(joiner.stub.calls == 1, "capability: refused before the signature was reached");

	/* THE ISSUER, and it needs the care revocation_test.c's equivalent
	 * does: rewriting it to some other key is refused by the follow check,
	 * which says nothing about whether the field is signed. So the rewrite
	 * lands past the first byte -- the stub's identity is unchanged, so
	 * the same signer is asked -- and the new value is followed. */
	memcpy(bytes, genuine, len);
	bytes[FZN_MANIFEST_OFF_ISSUER + 1u] ^= 0x5au;
	assert_signature_kept(bytes, genuine, FZN_MANIFEST_BODY_LEN(1), "issuer");
	fixture_init(&joiner);
	CHECK(fzn_manifest_follow(&joiner.manifest, bytes + FZN_MANIFEST_OFF_ISSUER) ==
	              FZN_MANIFEST_OK,
	      "follow the rewritten issuer");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");
	stub_reset(&joiner.stub);
	CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec, &joiner.sign) ==
	              FZN_MANIFEST_ERR_SIGNATURE,
	      "an ISSUER was rewritten on a genuinely signed manifest, with the new value "
	      "followed, and it was admitted: the field is outside the signed range");
	CHECK(joiner.stub.calls == 1,
	      "issuer: refused after %d verifications -- it must be the signature that "
	      "refused, not the follow check",
	      joiner.stub.calls);
}

/* TRUNCATION, WHICH IS HOW THE COUNT IS TESTED AT ALL.
 *
 * `count` cannot be rewritten in place: open insists the length agrees with
 * it, so any change refuses as SHAPE and says nothing about the signature. A
 * carrier's real move is to present a PREFIX of a genuine manifest -- the
 * first pair, with count set to 1 and the signature copied down -- which is a
 * perfectly well-shaped manifest. It must fail the signature, and that is
 * what says count and the pairs are inside the signed range. */
static void test_a_truncated_manifest_is_refused(void)
{
	struct fixture f, joiner;
	static uint8_t bytes[FIXTURE_BYTES], cut[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	uint8_t cap_a[FZN_CAP_ID_LEN], cap_b[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN];
	size_t len = 0;

	capability_id(cap_a, 0x10);
	capability_id(cap_b, 0x20);
	key(grantee, 5);

	fixture_init(&f);
	revoke(&f, f.root, cap_a, grantee);
	revoke(&f, f.root, cap_b, grantee);
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK && len == FZN_MANIFEST_LEN(2),
	      "issue");

	fixture_init(&joiner);
	CHECK(fzn_manifest_follow(&joiner.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");
	CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec, &joiner.sign) == FZN_MANIFEST_OK,
	      "truncation: the control fails, so the refusal below proves nothing");

	/* Header, first pair, count of one, and the genuine signature. */
	memcpy(cut, bytes, FZN_MANIFEST_BODY_LEN(1));
	fzn_put_be16(cut + FZN_MANIFEST_OFF_COUNT, 1u);
	memcpy(cut + FZN_MANIFEST_BODY_LEN(1), bytes + FZN_MANIFEST_BODY_LEN(2), FZN_SIG_LEN);

	fixture_init(&joiner);
	CHECK(fzn_manifest_follow(&joiner.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	CHECK(fzn_manifest_open(cut, FZN_MANIFEST_LEN(1), &rec) == FZN_MANIFEST_OK,
	      "the truncated manifest is not even well shaped, so nothing below is about "
	      "the signature");
	stub_reset(&joiner.stub);
	CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec, &joiner.sign) ==
	              FZN_MANIFEST_ERR_SIGNATURE,
	      "a PREFIX of a genuine manifest was admitted as a whole one: a carrier can "
	      "drop the pairs it does not want a host to learn about and the host cannot "
	      "tell");
	CHECK(joiner.stub.calls == 1, "truncation: the signature was never checked");
	CHECK(joiner.manifest.deficit_used == 0, "truncation: it recorded something anyway");
}

/* ---- what stage 1 deliberately does NOT do ---------------------------- */

/* NO GATE. sec 13d splits the work so that stage 1 breaks nothing, and this
 * is that claim as an assertion rather than a sentence: a host whose deficit
 * table says it is missing a revocation, and whose overflow flag is set,
 * verifies exactly what it verified before. Stage 2 is where that changes,
 * and it waits on the copyright holder. */
static void test_stage_one_does_not_gate(void)
{
	struct fixture f, joiner;
	static uint8_t bytes[FIXTURE_BYTES];
	uint8_t hop_bytes[FZN_HOP_LEN];
	fzn_manifest_record_t rec;
	fzn_chain_hop_t hops[1];
	fzn_chain_t out;
	uint8_t cap[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN];
	size_t len = 0;

	capability_id(cap, 0x10);
	key(grantee, 5);

	fixture_init(&f);
	revoke(&f, f.root, cap, grantee);
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "issue");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");

	fixture_init(&joiner);
	joiner.stub.identity = 0;
	CHECK(fzn_chain_mint(joiner.root, grantee, cap, 1000, FZN_NO_EXPIRY, 0, &joiner.sign,
	                     hop_bytes) == FZN_CHAIN_OK,
	      "minting the hop this case is about failed");
	CHECK(fzn_hop_open(hop_bytes, FZN_HOP_LEN, &hops[0]) == FZN_CHAIN_OK, "open");
	CHECK(fzn_chain_verify(hops, 1, joiner.root, cap, 2000, &joiner.sign, &joiner.store,
	                       &out) == FZN_CHAIN_OK,
	      "an unrevoked chain was refused before any manifest arrived");

	CHECK(fzn_manifest_follow(&joiner.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	CHECK(fzn_manifest_admit(&joiner.manifest, &joiner.store, rec, &joiner.sign) ==
	              FZN_MANIFEST_OK,
	      "admit");
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 1,
	      "this host does not know it is missing anything, so the check below is about "
	      "nothing");

	CHECK(fzn_chain_verify(hops, 1, joiner.root, cap, 2000, &joiner.sign, &joiner.store,
	                       &out) == FZN_CHAIN_OK,
	      "a known deficit changed what fzn_chain_verify answers -- stage 1 is not "
	      "supposed to gate, and stage 2 is blocked on the copyright holder");
}

/* ---- the revocation side of the seam ---------------------------------- */

static void test_a_revocation_settles_what_it_covers(void)
{
	struct fixture f, joiner;
	static uint8_t bytes[FIXTURE_BYTES];
	uint8_t rev[2][FZN_REVOCATION_LEN];
	fzn_manifest_record_t rec;
	fzn_revocation_record_t batch[2];
	uint8_t cap_a[FZN_CAP_ID_LEN], cap_b[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN];
	fzn_chain_err_t err = FZN_CHAIN_OK;
	size_t len = 0, n;

	capability_id(cap_a, 0x10);
	capability_id(cap_b, 0x20);
	key(grantee, 5);

	fixture_init(&f);
	revoke(&f, f.root, cap_a, grantee);
	revoke(&f, f.root, cap_b, grantee);
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "issue");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");

	fixture_init(&joiner);
	joiner.stub.identity = 0;
	CHECK(fzn_manifest_follow(&joiner.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	CHECK(fzn_manifest_admit(&joiner.manifest, &joiner.store, rec, &joiner.sign) ==
	              FZN_MANIFEST_OK,
	      "admit");
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 2, "pending is %zu",
	      fzn_manifest_pending(&joiner.manifest, f.root));

	CHECK(fzn_revocation_issue(f.root, cap_a, grantee, 1000, &joiner.sign, rev[0]) ==
	              FZN_CHAIN_OK,
	      "issue");
	CHECK(fzn_revocation_issue(f.root, cap_b, grantee, 1000, &joiner.sign, rev[1]) ==
	              FZN_CHAIN_OK,
	      "issue");
	CHECK(fzn_revocation_open(rev[0], FZN_REVOCATION_LEN, &batch[0]) == FZN_CHAIN_OK,
	      "open");
	CHECK(fzn_revocation_open(rev[1], FZN_REVOCATION_LEN, &batch[1]) == FZN_CHAIN_OK,
	      "open");

	/* NULL PRESERVES TODAY'S BEHAVIOUR EXACTLY, which is what makes the
	 * parameter optional rather than a break. */
	CHECK(fzn_revocation_admit(&joiner.store, batch[0], f.root, &joiner.sign, NULL) ==
	              FZN_CHAIN_OK,
	      "admit with no manifest state");
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 2,
	      "a NULL manifest state settled a deficit anyway, so the parameter is not "
	      "optional and every existing caller has changed behaviour");

	/* THE ALREADY-HELD PATH DRAINS TOO, or a host that received the
	 * revocation before wiring up its manifest reports a gap it has
	 * filled, for ever. */
	CHECK(fzn_revocation_admit(&joiner.store, batch[0], f.root, &joiner.sign,
	                           &joiner.manifest) == FZN_CHAIN_OK,
	      "re-admitting a revocation already held was an error");
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 1,
	      "a revocation this host already held did not settle the deficit naming it, "
	      "so the two arrival orders do not converge");

	/* AND THE BATCH PATH, which is the call carriage actually arrives
	 * through. */
	/* Two, not one: the first is already held, and `fzn_revocation_merge`
	 * counts an already-held record as admitted because hearing it twice
	 * is what carriage looks like when it works. */
	n = fzn_revocation_merge(&joiner.store, batch, 2, f.root, &joiner.sign, &err,
	                         &joiner.manifest);
	CHECK(n == 2 && err == FZN_CHAIN_OK, "merge admitted %zu, err %d", n, (int)err);
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 0,
	      "a merge left %zu pairs outstanding, so the drain is wired to the path "
	      "consumers use least",
	      fzn_manifest_pending(&joiner.manifest, f.root));
	CHECK(fzn_manifest_overflowed(&joiner.manifest, f.root) == 0,
	      "settling every pair reported the deficit as under-reported");
}

/* ---- arguments and the state's own integrity -------------------------- */

static void test_every_guard_refuses_its_own_argument(void)
{
	struct fixture f;
	fzn_manifest_state_t s;
	fzn_manifest_pair_t want[2];
	uint8_t other[FZN_PUBKEY_LEN];
	size_t dropped = 99;

	fixture_init(&f);
	key(other, 7);

	CHECK(fzn_manifest_init(NULL, f.issuers, 2, f.deficit, 4) == FZN_MANIFEST_ERR_MALFORMED,
	      "a null state was initialised");
	CHECK(fzn_manifest_init(&s, NULL, 2, f.deficit, 4) == FZN_MANIFEST_ERR_MALFORMED,
	      "null issuers");
	CHECK(fzn_manifest_init(&s, f.issuers, 0, f.deficit, 4) == FZN_MANIFEST_ERR_MALFORMED,
	      "a zero-capacity issuer table was accepted, and would follow nothing");
	CHECK(fzn_manifest_init(&s, f.issuers, 2, NULL, 4) == FZN_MANIFEST_ERR_MALFORMED,
	      "null deficit");
	CHECK(fzn_manifest_init(&s, f.issuers, 2, f.deficit, 0) == FZN_MANIFEST_ERR_MALFORMED,
	      "a zero-capacity deficit table was accepted, and would record nothing while "
	      "reporting success");

	CHECK(fzn_manifest_follow(NULL, f.root) == FZN_MANIFEST_ERR_MALFORMED, "a null state");
	CHECK(fzn_manifest_follow(&f.manifest, NULL) == FZN_MANIFEST_ERR_MALFORMED,
	      "a null issuer");

	/* A view that was never opened. MALFORMED rather than SHAPE: nothing
	 * about any bytes is wrong, the caller skipped fzn_manifest_open. */
	{
		fzn_manifest_record_t unopened;
		fzn_sign_ops_t no_verify = f.sign;

		unopened.base = NULL;
		unopened.len = 0;
		CHECK(fzn_manifest_admit(&f.manifest, &f.store, unopened, &f.sign) ==
		              FZN_MANIFEST_ERR_MALFORMED,
		      "a manifest that was never opened was accepted");
		CHECK(fzn_manifest_admit(NULL, &f.store, unopened, &f.sign) ==
		              FZN_MANIFEST_ERR_MALFORMED,
		      "admitting into a null state");
		no_verify.verify = NULL;
		CHECK(fzn_manifest_admit(&f.manifest, &f.store, unopened, &no_verify) ==
		              FZN_MANIFEST_ERR_MALFORMED,
		      "admitting with a signer that cannot verify");
		CHECK(fzn_manifest_admit(&f.manifest, &f.store, unopened, NULL) ==
		              FZN_MANIFEST_ERR_MALFORMED,
		      "admitting with a null signer");
	}

	CHECK(fzn_manifest_satisfy(NULL, f.root, f.root, f.root) == 0, "satisfy on a null state");
	CHECK(fzn_manifest_satisfy(&f.manifest, NULL, f.root, f.root) == 0, "a null issuer");
	CHECK(fzn_manifest_satisfy(&f.manifest, f.root, NULL, f.root) == 0, "a null capability");
	CHECK(fzn_manifest_satisfy(&f.manifest, f.root, f.root, NULL) == 0, "a null grantee");

	CHECK(fzn_manifest_pending(NULL, f.root) == 0, "pending on a null state");
	CHECK(fzn_manifest_pending(&f.manifest, NULL) == 0, "pending for a null issuer");

	/* THE ONE PREDICATE THAT ANSWERS THE OTHER WAY ROUND. An absent state,
	 * an unreadable one and an issuer nobody follows are the same fact:
	 * this host cannot say what it is missing from that key. Reporting
	 * that as sound is the fail-open this module exists to remove. */
	CHECK(fzn_manifest_overflowed(NULL, f.root) == 1,
	      "a null state reported its deficit as sound");
	CHECK(fzn_manifest_overflowed(&f.manifest, NULL) == 1, "a null issuer");
	CHECK(fzn_manifest_overflowed(&f.manifest, other) == 1,
	      "an issuer nobody follows was reported as measured");
	CHECK(fzn_manifest_follow(&f.manifest, other) == FZN_MANIFEST_OK, "follow");
	CHECK(fzn_manifest_overflowed(&f.manifest, other) == 0,
	      "a followed issuer with nothing dropped was reported as under-reported, so "
	      "the answer above is not about being followed");

	dropped = 99;
	CHECK(fzn_manifest_deficit(NULL, f.root, want, 2, &dropped) == 0 && dropped == 0,
	      "deficit on a null state");
	dropped = 99;
	CHECK(fzn_manifest_deficit(&f.manifest, NULL, want, 2, &dropped) == 0 && dropped == 0,
	      "deficit for a null issuer");
	dropped = 99;
	CHECK(fzn_manifest_deficit(&f.manifest, f.root, NULL, 2, &dropped) == 0 &&
	              dropped == 0,
	      "deficit into a null array with room claimed");
	CHECK(fzn_manifest_deficit(&f.manifest, f.root, want, 2, NULL) == 0,
	      "deficit with no way to report what did not fit");

	CHECK(fzn_manifest_issue(NULL, &f.store, &f.sign, (uint8_t *)want, sizeof(want),
	                         &dropped) == FZN_MANIFEST_ERR_MALFORMED,
	      "issuing with a null issuer");
	CHECK(fzn_manifest_issue(f.root, &f.store, NULL, (uint8_t *)want, sizeof(want),
	                         &dropped) == FZN_MANIFEST_ERR_MALFORMED,
	      "issuing with a null signer");
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, NULL, sizeof(want), &dropped) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "issuing into a null buffer");
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, (uint8_t *)want, sizeof(want),
	                         NULL) == FZN_MANIFEST_ERR_MALFORMED,
	      "issuing with nowhere to report the length");
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, (uint8_t *)want,
	                         FZN_MANIFEST_MIN_LEN - 1u,
	                         &dropped) == FZN_MANIFEST_ERR_MALFORMED,
	      "issuing into a buffer too small for an empty manifest");
}

/* A state whose `used` exceeds its capacity. Every entry point judges it,
 * rather than one of them judging it for the rest: `used` bounds a loop over
 * an array, and a count past the array describes entries that cannot be
 * scanned. */
static void test_a_state_whose_fields_disagree_is_refused(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_manifest_pair_t want[2];
	uint8_t cap[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN];
	size_t len = 0, dropped = 99;

	capability_id(cap, 0x10);
	key(grantee, 5);

	fixture_init(&f);
	revoke(&f, f.root, cap, grantee);
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "issue");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");
	CHECK(fzn_manifest_follow(&f.manifest, f.root) == FZN_MANIFEST_OK, "follow");

	f.manifest.deficit_used = f.manifest.deficit_capacity + 1u;
	CHECK(fzn_manifest_admit(&f.manifest, NULL, rec, &f.sign) == FZN_MANIFEST_ERR_MALFORMED,
	      "a corrupt state accepted a manifest");
	CHECK(fzn_manifest_pending(&f.manifest, f.root) == 0,
	      "a corrupt state was scanned to answer pending");
	CHECK(fzn_manifest_overflowed(&f.manifest, f.root) == 1,
	      "a corrupt state reported its deficit as sound");
	dropped = 99;
	CHECK(fzn_manifest_deficit(&f.manifest, f.root, want, 2, &dropped) == 0 && dropped == 0,
	      "a corrupt state was scanned to report a deficit");
	CHECK(fzn_manifest_satisfy(&f.manifest, f.root, cap, grantee) == 0,
	      "a corrupt state was written to");
	CHECK(fzn_manifest_follow(&f.manifest, grantee) == FZN_MANIFEST_ERR_MALFORMED,
	      "a corrupt state followed another issuer");

	f.manifest.deficit_used = 0;
	f.manifest.issuer_used = f.manifest.issuer_capacity + 1u;
	CHECK(fzn_manifest_admit(&f.manifest, NULL, rec, &f.sign) == FZN_MANIFEST_ERR_MALFORMED,
	      "a state with a corrupt issuer count accepted a manifest");
	CHECK(fzn_manifest_overflowed(&f.manifest, f.root) == 1,
	      "a state with a corrupt issuer count reported its deficit as sound");
}

/* Positive control: most cases above assert a refusal, and a module that
 * refused everything would satisfy them. */
static void test_the_suite_can_tell_pass_from_fail(void)
{
	struct fixture f, joiner;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	uint8_t cap[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN];
	size_t len = 0;

	capability_id(cap, 0x10);
	key(grantee, 5);

	fixture_init(&f);
	revoke(&f, f.root, cap, grantee);
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "the positive control cannot issue, so every refusal above proves nothing");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "the positive control does not open");

	fixture_init(&joiner);
	CHECK(fzn_manifest_follow(&joiner.manifest, f.root) == FZN_MANIFEST_OK,
	      "the positive control cannot follow");
	CHECK(fzn_manifest_admit(&joiner.manifest, &joiner.store, rec, &joiner.sign) ==
	              FZN_MANIFEST_OK,
	      "the positive control fails, so every refusal above proves nothing");
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 1,
	      "the positive control recorded no deficit");
}

int main(void)
{
	test_layout_and_round_trip();
	test_the_object_tag_is_in_the_transcript();
	test_open_refuses_what_is_not_our_shape();
	test_the_pair_ceiling_is_a_ceiling();
	test_the_ordering_reads_the_whole_pair();
	test_encode_refuses_what_open_would();
	test_issue_derives_from_the_issuers_own_store();
	test_issue_refuses_a_store_it_cannot_read();
	test_issuing_is_deterministic();
	test_following_is_deliberate();
	test_the_deficit_is_what_this_host_lacks();
	test_the_deficit_reads_the_whole_field();
	test_the_overflow_flag_is_sticky();
	test_a_corrupt_store_is_refused_rather_than_believed();
	test_a_forged_pair_is_refused();
	test_a_truncated_manifest_is_refused();
	test_stage_one_does_not_gate();
	test_a_revocation_settles_what_it_covers();
	test_every_guard_refuses_its_own_argument();
	test_a_state_whose_fields_disagree_is_refused();
	test_the_suite_can_tell_pass_from_fail();

	printf("manifest_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
