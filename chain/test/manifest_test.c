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

/* For FZN_RECORD_MIN_LEN and _MAX_LEN: the collision the object tag exists
 * to separate is against a RECORD, so the claim is checked against record.h
 * rather than against a number copied out of it. */
#include "../../record/record.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define FZN_REASSEMBLED_MAX ((size_t)FZN_SPLIT_MAX_PAYLOAD * (size_t)FZN_REASM_MAX_CHUNKS)

/* SPELLED WITH THE PUBLIC CONSTANT, not with the expression behind it.
 *
 * This read `FZN_MANIFEST_LEN(FZN_MANIFEST_MAX_PAIRS)`, which is what
 * manifest.h defines FZN_MANIFEST_MAX_LEN to be -- so the check recomputed
 * the value and the constant a consumer actually sizes a buffer with was
 * never the subject of anything. Redefining it wrongly left every assertion
 * here passing. `record/` does not have that gap: record.c and
 * record_test.c both assert FZN_RECORD_MAX_LEN itself.
 *
 * Naming the constant here is not tautological the way asserting it equals
 * its own definition would be. It is checked against a bound from another
 * module -- what reassembly will carry -- so a wrong definition fails,
 * which is the whole of what a consumer needs from it. */
_Static_assert(FZN_MANIFEST_MAX_LEN <= FZN_REASSEMBLED_MAX,
                "the largest manifest does not fit the largest message reassembly will take");
_Static_assert(FZN_MANIFEST_LEN(FZN_MANIFEST_MAX_PAIRS + 1u) > FZN_REASSEMBLED_MAX,
                "FZN_MANIFEST_MAX_PAIRS is below the ceiling, so it is not the ceiling");

/* And the single-frame figure, which is the number a consumer feels. */
_Static_assert(FZN_MANIFEST_LEN(9) <= FZN_SPLIT_MAX_PAYLOAD,
                "nine entries no longer fit one frame");
_Static_assert(FZN_MANIFEST_LEN(10) > FZN_SPLIT_MAX_PAYLOAD,
                "ten entries fit one frame, so the entry is not the size the "
                "header says it is");

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif


/* A HASH FOR RECORD IDENTITY. `fzn_revocation_admit` needs one to compute
 * what a withdrawal targets and what a reissue supersedes; this is the same
 * FNV expansion `mac` above uses, over the whole record. Deterministic and
 * dependent on every input byte, which is all identity comparison asks of
 * it -- a collision here would make two different records one record, so the
 * property under test is that different bytes give different answers rather
 * than anything cryptographic. */
static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in,
                     size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	if (!out || !in || out_len == 0)
		return 0;
	for (i = 0; i < in_len; i++) {
		h ^= (uint64_t)in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 1u;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
	return 1;
}

static const fzn_hash_ops_t HASH_OPS = { stub_hash, NULL };

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL manifest_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
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
		fprintf(stderr, "  FAIL: verifier called with an empty signed region\n");
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
		fprintf(stderr, "  FAIL: signer called with an empty region\n");
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

static void capability_id(fzn_cap_id_t *out, uint8_t seed)
{
	expand(out->b, FZN_CAP_ID_LEN, seed);
}

static void capability_id_near(fzn_cap_id_t *out, uint8_t seed)
{
	expand_near(out->b, FZN_CAP_ID_LEN, seed);
}

/* The suite's own ordering, written out rather than borrowed, so that a
 * mutation of `pair_cmp` in the module under test does not silently move the
 * fixtures with it. */
static int suite_pair_cmp(const fzn_manifest_pair_t *a, const fzn_manifest_pair_t *b)
{
	int cmp = memcmp(a->capability.b, b->capability.b, FZN_CAP_ID_LEN);

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
	out[FZN_MANIFEST_OFF_OBJECT] = (uint8_t)FZN_OBJECT_MANIFEST;
	memcpy(out + FZN_MANIFEST_OFF_ISSUER, issuer, FZN_PUBKEY_LEN);
	fzn_put_be16(out + FZN_MANIFEST_OFF_COUNT, (uint16_t)count);
	for (size_t i = 0; i < count; i++) {
		memcpy(at, pairs[i].capability.b, FZN_CAP_ID_LEN);
		memcpy(at + FZN_CAP_ID_LEN, pairs[i].grantee, FZN_PUBKEY_LEN);
		/* THE ID AND THE STATE ARE WRITTEN TOO, and this helper wrote
		 * neither when an entry was 64 bytes. Left as whatever `out`
		 * held, the state byte would usually be refused by `open` --
		 * so every case built here would have been passing for the
		 * wrong reason, testing the state check rather than the
		 * canonicality it was written for. */
		memset(at + FZN_MANIFEST_OFF_ENTRY_ID, 0, FZN_REVOCATION_ID_LEN);
		at[FZN_MANIFEST_OFF_ENTRY_ID] = (uint8_t)(i + 1u);
		at[FZN_MANIFEST_OFF_ENTRY_STATE] = (uint8_t)FZN_MANIFEST_REVOKED;
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

/* THE SUITE STILL BUILDS PAIRS AND THE ENCODER NOW TAKES ENTRIES, so this
 * adapts between them at the call rather than every fixture growing two
 * fields it does not care about. Most cases here are about ordering,
 * canonicality and lengths -- properties of the KEY -- and rewriting them
 * to carry an id and a state would bury what each is testing.
 *
 * The id is derived from the index so that two entries are never
 * accidentally identical, and the state is REVOKED, which is what a case
 * that says nothing about state should mean. Cases that are about the state
 * set it themselves.
 *
 * A FILE-SCOPE BUFFER because the result is used immediately as an argument
 * and nothing here is concurrent; the bound is asserted rather than assumed,
 * since a silent truncation would hand the encoder fewer entries than the
 * count says and the failure would land inside the library. */
/* Sized to the ceiling plus one, because a case that checks the ceiling is
 * enforced has to be able to ASK for one more than it. */
static fzn_manifest_entry_t ENTRY_BUF[FZN_MANIFEST_MAX_PAIRS + 1u];

static const fzn_manifest_entry_t *as_entries(const fzn_manifest_pair_t *src, size_t n)
{
	size_t i;

	if (n > (sizeof(ENTRY_BUF) / sizeof(ENTRY_BUF[0]))) {
		fprintf(stderr, "  FAIL: as_entries asked for %zu, buffer holds %zu\n",
		        n, (size_t)(sizeof(ENTRY_BUF) / sizeof(ENTRY_BUF[0])));
		failures++;
		return NULL;
	}
	for (i = 0; i < n; i++) {
		ENTRY_BUF[i].pair = src[i];
		memset(ENTRY_BUF[i].id, 0, sizeof(ENTRY_BUF[i].id));
		ENTRY_BUF[i].id[0] = (uint8_t)(i + 1u);
		ENTRY_BUF[i].state = (uint8_t)FZN_MANIFEST_REVOKED;
	}
	return ENTRY_BUF;
}

static void pair_of(fzn_manifest_pair_t *p, uint8_t cap_seed, uint8_t grantee_seed)
{
	capability_id(&p->capability, cap_seed);
	key(p->grantee, grantee_seed);
}

/* Put a real, signed revocation into the store, so that the manifest derived
 * from it names something. */
/* Revoke at a stated instant, so that two hosts can revoke the SAME pair and
 * produce DIFFERENT records. `revoke` below fixes the instant at 1000, which
 * is right for every case that wants one record and is exactly what makes the
 * "different records" row of `fzn_manifest_admit`'s decision table
 * unreachable. */
static void revoke_at(struct fixture *f, const uint8_t issuer[FZN_PUBKEY_LEN],
                      const fzn_cap_id_t *capability,
                      const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t issued_at)
{
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t rec;

	f->stub.identity = issuer[0];
	if (fzn_revocation_issue(issuer, capability, grantee, issued_at, &f->sign, bytes) !=
	    FZN_CHAIN_OK) {
		fprintf(stderr, "  FAIL: the fixture could not issue a revocation\n");
		failures++;
		return;
	}
	if (fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK) {
		fprintf(stderr, "  FAIL: the fixture issued a revocation that will not open\n");
		failures++;
		return;
	}
	if (fzn_revocation_admit(&f->store, fzn_revocation_offer_root(rec), issuer, &f->sign,
	                         &HASH_OPS, NULL) != FZN_CHAIN_OK) {
		fprintf(stderr, "  FAIL: the fixture could not admit a revocation\n");
		failures++;
	}
}

static void revoke(struct fixture *f, const uint8_t issuer[FZN_PUBKEY_LEN],
                   const fzn_cap_id_t *capability,
                   const uint8_t grantee[FZN_PUBKEY_LEN])
{
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t rec;

	f->stub.identity = issuer[0];
	if (fzn_revocation_issue(issuer, capability, grantee, 1000, &f->sign, bytes) !=
	    FZN_CHAIN_OK) {
		fprintf(stderr, "  FAIL: the fixture could not issue a revocation\n");
		failures++;
		return;
	}
	if (fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK) {
		fprintf(stderr, "  FAIL: the fixture issued a revocation that will not open\n");
		failures++;
		return;
	}
	if (fzn_revocation_admit(&f->store, fzn_revocation_offer_root(rec), issuer, &f->sign, &HASH_OPS,
	                         NULL) != FZN_CHAIN_OK) {
		fprintf(stderr, "  FAIL: the fixture's revocation was refused\n");
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

	CHECK(FZN_MANIFEST_KEY_LEN == 64u, "a key is %zu bytes, the table says 64",
	      FZN_MANIFEST_KEY_LEN);
	CHECK(FZN_MANIFEST_PAIR_LEN == 97u, "an entry is %zu bytes, the table says 97",
	      FZN_MANIFEST_PAIR_LEN);
	/* THE KEY IS A PREFIX OF THE ENTRY, which is what one comparison
	 * orders both the wire form and the caller's struct by. */
	CHECK(FZN_MANIFEST_OFF_ENTRY_ID == FZN_MANIFEST_KEY_LEN &&
	              FZN_MANIFEST_OFF_ENTRY_STATE ==
	                      FZN_MANIFEST_KEY_LEN + FZN_REVOCATION_ID_LEN,
	      "the entry's id and state are not where the table puts them");
	CHECK(FZN_MANIFEST_HEADER_LEN == 36u, "the header is %u bytes, the table says 36",
	      (unsigned)FZN_MANIFEST_HEADER_LEN);
	CHECK(FZN_MANIFEST_MIN_LEN == 100u, "an empty manifest is %zu bytes, wanted 100",
	      FZN_MANIFEST_MIN_LEN);
	CHECK(FZN_MANIFEST_LEN(9) == 973u, "nine entries is %zu bytes, wanted 973",
	      FZN_MANIFEST_LEN(9));
	CHECK(FZN_MANIFEST_LEN(10) == 1070u, "ten entries is %zu bytes, wanted 1070",
	      FZN_MANIFEST_LEN(10));

	fixture_init(&f);
	key(issuer, 0);
	pair_of(&pairs[0], 0x10, 5);
	pair_of(&pairs[1], 0x20, 6);

	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, as_entries(pairs, 2), 2, &len) ==
	              FZN_MANIFEST_OK,
	      "encoding a two-pair manifest failed");
	CHECK(len == FZN_MANIFEST_LEN(2), "encoded %zu bytes, wanted %zu", len,
	      FZN_MANIFEST_LEN(2));
	CHECK(bytes[FZN_MANIFEST_OFF_VERSION] == 1u, "version byte is %u, wanted 1",
	      bytes[FZN_MANIFEST_OFF_VERSION]);
	CHECK(bytes[FZN_MANIFEST_OFF_OBJECT] == 131u,
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
	CHECK(fzn_ct_memeq(fzn_manifest_capability(rec, 0), pairs[0].capability.b, FZN_CAP_ID_LEN) &&
	              fzn_ct_memeq(fzn_manifest_grantee(rec, 0), pairs[0].grantee,
	                           FZN_PUBKEY_LEN),
	      "pair 0 did not survive the round trip");
	CHECK(fzn_ct_memeq(fzn_manifest_capability(rec, 1), pairs[1].capability.b, FZN_CAP_ID_LEN) &&
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
			memcpy(read_back[i].capability.b, fzn_manifest_capability(rec, i),
			       FZN_CAP_ID_LEN);
			memcpy(read_back[i].grantee, fzn_manifest_grantee(rec, i),
			       FZN_PUBKEY_LEN);
		}
		CHECK(fzn_manifest_encode(again, sizeof(again), fzn_manifest_issuer(rec), as_entries(read_back, fzn_manifest_count(rec)), fzn_manifest_count(rec),
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
	uint8_t issuer[FZN_PUBKEY_LEN];
	fzn_manifest_pair_t pairs[1];
	size_t len = 0;

	fixture_init(&f);
	key(issuer, 0);
	pair_of(&pairs[0], 0x10, 5);
	f.stub.identity = 0;

	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, as_entries(pairs, 1), 1, &len) ==
	              FZN_MANIFEST_OK,
	      "the control could not be encoded");
	mac(as_manifest, 0, bytes, FZN_MANIFEST_BODY_LEN(1));

	bytes[FZN_MANIFEST_OFF_OBJECT] = 129u; /* FZN_OBJECT_REVOCATION */
	mac(as_revocation, 0, bytes, FZN_MANIFEST_BODY_LEN(1));

	CHECK(memcmp(as_manifest, as_revocation, FZN_SIG_LEN) != 0,
	      "one key signing the same body under two object tags produced the same "
	      "signature, so the tag is outside the transcript and separates nothing");

	/* AND THE COLLISION IS STILL THERE, which is why the tag has to be.
	 *
	 * It used to be exact and arithmetical: a one-pair manifest was 164
	 * bytes and so was a record with an eight-byte body. The entry grew to
	 * 97, so a one-entry manifest is 197 -- a different number and the
	 * same hazard, because 197 is inside a record's range too. The
	 * property was never "these two constants are equal"; it is that one
	 * key signs both objects through one seam and their lengths overlap,
	 * so nothing but the tag separates them.
	 *
	 * Asserted as the range test it always was, rather than re-pinning a
	 * number that moves whenever an entry does. */
	CHECK(FZN_MANIFEST_LEN(1) == 197u,
	      "a one-entry manifest is %zu bytes, wanted 197", FZN_MANIFEST_LEN(1));
	CHECK(FZN_MANIFEST_LEN(1) >= FZN_RECORD_MIN_LEN &&
	              FZN_MANIFEST_LEN(1) <= FZN_RECORD_MAX_LEN,
	      "a one-entry manifest at %zu bytes no longer collides with any record "
	      "length, so this case has stopped demonstrating what the tag is for",
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
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, as_entries(pairs, 2), 2, &len) ==
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
	bytes[FZN_MANIFEST_OFF_OBJECT] = (uint8_t)FZN_OBJECT_REVOCATION;
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_ERR_SHAPE,
	      "an otherwise valid manifest tagged as a revocation was accepted as a "
	      "manifest");
	bytes[FZN_MANIFEST_OFF_OBJECT] = (uint8_t)FZN_OBJECT_MANIFEST;
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
	huge[FZN_MANIFEST_OFF_OBJECT] = (uint8_t)FZN_OBJECT_MANIFEST;
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
	fzn_cap_id_t cap, near_cap;
	uint8_t grantee[FZN_PUBKEY_LEN], near_grantee[FZN_PUBKEY_LEN];
	size_t len;

	fixture_init(&f);
	key(issuer, 0);
	capability_id(&cap, 0x10);
	capability_id_near(&near_cap, 0x10);
	key(grantee, 5);
	key_near(near_grantee, 5);

	/* THE FIXTURE PROPERTY, ASSERTED FIRST. Everything below is worthless
	 * if the two values differ anywhere a short comparison would reach. */
	CHECK(memcmp(cap.b, near_cap.b, FZN_CAP_ID_LEN - 1u) == 0 &&
	              cap.b[FZN_CAP_ID_LEN - 1u] != near_cap.b[FZN_CAP_ID_LEN - 1u],
	      "the two capabilities do not agree on every byte but the last, so they do "
	      "not decide a comparison's length");
	CHECK(memcmp(grantee, near_grantee, FZN_PUBKEY_LEN - 1u) == 0 &&
	              grantee[FZN_PUBKEY_LEN - 1u] != near_grantee[FZN_PUBKEY_LEN - 1u],
	      "the two grantees do not agree on every byte but the last");

	/* TWO GRANTEES UNDER ONE CAPABILITY, differing only in the last byte.
	 * Sorted, so the manifest is canonical and must be accepted. */
	memcpy(pairs[0].capability.b, cap.b, FZN_CAP_ID_LEN);
	memcpy(pairs[0].grantee, grantee, FZN_PUBKEY_LEN);
	memcpy(pairs[1].capability.b, cap.b, FZN_CAP_ID_LEN);
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
	memcpy(pairs[0].capability.b, cap.b, FZN_CAP_ID_LEN);
	memcpy(pairs[0].grantee, grantee, FZN_PUBKEY_LEN);
	memcpy(pairs[1].capability.b, near_cap.b, FZN_CAP_ID_LEN);
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

	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, as_entries(pairs, 2), 2, &len) ==
	              FZN_MANIFEST_ERR_SHAPE,
	      "the encoder produced a manifest its own parser refuses, which is a second "
	      "encoding waiting to be found by somebody else's decoder");

	pairs[1] = pairs[0];
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, as_entries(pairs, 2), 2, &len) ==
	              FZN_MANIFEST_ERR_SHAPE,
	      "the encoder produced a manifest naming one pair twice");

	/* And the ordered version goes through, so the two refusals above are
	 * about the order rather than about the call. */
	pair_of(&pairs[0], 0x10, 5);
	pair_of(&pairs[1], 0x20, 6);
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, as_entries(pairs, 2), 2, &len) ==
	              FZN_MANIFEST_OK,
	      "an ordered pair set was refused, so the control fails");

	CHECK(fzn_manifest_encode(bytes, FZN_MANIFEST_LEN(2) - 1u, issuer, as_entries(pairs, 2), 2, &len) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "encoding into a buffer one byte short was accepted");
	/* THE ARRAY IS TWO ENTRIES AND THE COUNT IS PAST THE CEILING, which is
	 * deliberate and safe: `fzn_manifest_encode` refuses the count before
	 * it reads a single entry. Handing `as_entries` the oversized count
	 * instead made it read 2702 entries out of a two-entry fixture, and
	 * this case segfaulted -- the adapter was the thing at fault, not the
	 * encoder, and a case that crashes proves nothing about the ceiling. */
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, as_entries(pairs, 2),
	                          (size_t)FZN_MANIFEST_MAX_PAIRS + 1u,
	                          &len) == FZN_MANIFEST_ERR_SHAPE,
	      "encoding past the pair ceiling was accepted");
	CHECK(fzn_manifest_encode(NULL, sizeof(bytes), issuer, as_entries(pairs, 2), 2, &len) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "encoding into a null buffer");
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), NULL, as_entries(pairs, 2), 2, &len) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "encoding with a null issuer");
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, NULL, 2, &len) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "encoding a nonzero count from a null pair array");
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, as_entries(pairs, 2), 2, NULL) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "encoding with nowhere to report the length");
}

/* ---- issuing, which is the half an honest implementation cannot lie in -- */

/* Revoke, then withdraw, leaving the entry in the store saying the opposite.
 * Returns 0 if any step failed, so a caller can stop rather than assert
 * against a fixture that did not build. */
static int revoke_then_withdraw(struct fixture *f, const uint8_t issuer[FZN_PUBKEY_LEN],
                                const fzn_cap_id_t *capability,
                                const uint8_t grantee[FZN_PUBKEY_LEN])
{
	uint8_t bytes[FZN_REVOCATION_LEN], wd[FZN_REVOCATION_LEN];
	uint8_t id[FZN_REVOCATION_ID_LEN];
	fzn_revocation_record_t rec;

	f->stub.identity = issuer[0];
	if (fzn_revocation_issue(issuer, capability, grantee, 1000, &f->sign, bytes) !=
	    FZN_CHAIN_OK)
		return 0;
	if (fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
		return 0;
	if (!stub_hash(NULL, id, sizeof(id), bytes, FZN_REVOCATION_LEN))
		return 0;
	stub_reset(&f->stub);
	if (fzn_revocation_admit(&f->store, fzn_revocation_offer_root(rec), issuer, &f->sign,
	                         &HASH_OPS, NULL) != FZN_CHAIN_OK)
		return 0;

	f->stub.identity = issuer[0];
	if (fzn_revocation_issue_withdrawal(issuer, capability, grantee, 2000, id, &f->sign,
	                                    wd) != FZN_CHAIN_OK)
		return 0;
	if (fzn_revocation_open(wd, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
		return 0;
	stub_reset(&f->stub);
	return fzn_revocation_admit(&f->store, fzn_revocation_offer_root(rec), issuer,
	                            &f->sign, &HASH_OPS, NULL) == FZN_CHAIN_OK;
}

/* THE STATE BYTE HAS EXACTLY TWO VALUES, and a third is refused rather than
 * read as one of them.
 *
 * The same rule this parser applies to trailing bytes and for the same
 * reason: a decoder that ignores what it does not understand is a second
 * encoding waiting to be found by somebody else's. It also earns the
 * accessor its shape -- `fzn_manifest_is_withdrawn` tests one value and
 * trusts the complement, which is only sound because everything else was
 * refused here. */
static void test_a_state_byte_has_two_values(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_manifest_pair_t pairs[1];
	uint8_t issuer[FZN_PUBKEY_LEN];
	size_t len = 0, at;

	fixture_init(&f);
	key(issuer, 0);
	pair_of(&pairs[0], 0x10, 5);
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, as_entries(pairs, 1), 1,
	                          &len) == FZN_MANIFEST_OK,
	      "the control manifest could not be encoded");
	at = FZN_MANIFEST_OFF_PAIRS + FZN_MANIFEST_OFF_ENTRY_STATE;

	bytes[at] = (uint8_t)FZN_MANIFEST_REVOKED;
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK &&
	              !fzn_manifest_is_withdrawn(rec, 0),
	      "a revoked entry did not open, so the refusals below prove nothing");
	bytes[at] = (uint8_t)FZN_MANIFEST_WITHDRAWN;
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK &&
	              fzn_manifest_is_withdrawn(rec, 0),
	      "a withdrawn entry did not open");

	/* Every other value, not one sample: a check that tried only 2 would
	 * pass against a parser that refused 2 and admitted 200. */
	{
		unsigned v;

		for (v = 2u; v < 256u; v++) {
			bytes[at] = (uint8_t)v;
			if (fzn_manifest_open(bytes, len, &rec) != FZN_MANIFEST_ERR_SHAPE) {
				CHECK(0, "a state byte of %u was accepted", v);
				break;
			}
		}
	}

	/* AND THE ENCODER REFUSES WHAT THE PARSER WOULD, which is this
	 * object's standing rule. */
	{
		fzn_manifest_entry_t bad;

		bad.pair = pairs[0];
		memset(bad.id, 0, sizeof(bad.id));
		bad.state = 7u;
		CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, &bad, 1, &len) ==
		              FZN_MANIFEST_ERR_SHAPE,
		      "the encoder emitted a state byte its own parser refuses");
	}
}

/* ORDERING AND DEDUPLICATION ARE ON THE KEY, NOT THE ENTRY.
 *
 * One issuer has exactly one opinion about one pair. Two entries naming the
 * same pair and differing only in what they say about it are two
 * contradictory opinions, and a comparison over the whole entry would sort
 * them apart and admit both -- leaving a receiver to pick. The near-miss is
 * what decides it: the two entries below are identical for 64 bytes and
 * differ in the 65th onward. */
static void test_two_opinions_about_one_pair_are_refused(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_manifest_entry_t two[2];
	uint8_t issuer[FZN_PUBKEY_LEN];
	size_t len = 0;

	fixture_init(&f);
	key(issuer, 0);
	pair_of(&two[0].pair, 0x10, 5);
	memset(two[0].id, 0x11, sizeof(two[0].id));
	two[0].state = (uint8_t)FZN_MANIFEST_REVOKED;
	two[1] = two[0];
	memset(two[1].id, 0x22, sizeof(two[1].id));
	two[1].state = (uint8_t)FZN_MANIFEST_WITHDRAWN;

	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, two, 2, &len) ==
	              FZN_MANIFEST_ERR_SHAPE,
	      "one pair with two different states was encoded, so an issuer can say a "
	      "pair is both revoked and restored in one signed statement");

	/* THE CONTROL: the same two entries with different pairs encode, so
	 * the refusal above is the duplicate key and not the differing
	 * state. */
	pair_of(&two[1].pair, 0x20, 5);
	CHECK(fzn_manifest_encode(bytes, sizeof(bytes), issuer, two, 2, &len) ==
	              FZN_MANIFEST_OK && fzn_manifest_open(bytes, len, &rec) ==
	              FZN_MANIFEST_OK,
	      "two entries differing in pair AND state were refused, so the refusal "
	      "above is about the state rather than the duplicate");

	/* AND THE SAME QUESTION ASKED OF THE PARSER, which is a DIFFERENT
	 * comparison and was the one under test all along.
	 *
	 * The encoder refuses the duplicate through `pair_struct_cmp` over the
	 * caller's struct; `open` refuses it through `pair_cmp` over the wire.
	 * Measured: widening `pair_cmp` to the whole entry left everything
	 * above green, because the encoder had already refused and the parser
	 * was never asked. So the bytes are laid out by hand -- the only way
	 * to present `open` with two entries sharing a key. */
	{
		fzn_manifest_pair_t same[2];
		uint8_t *second;

		pair_of(&same[0], 0x10, 5);
		same[1] = same[0];
		len = build_raw(bytes, 0, issuer, same, 2);
		second = bytes + FZN_MANIFEST_OFF_PAIRS + FZN_MANIFEST_PAIR_LEN;
		second[FZN_MANIFEST_OFF_ENTRY_ID] = 0xee;
		second[FZN_MANIFEST_OFF_ENTRY_STATE] = (uint8_t)FZN_MANIFEST_WITHDRAWN;
		CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_ERR_SHAPE,
		      "a manifest naming one pair twice, revoked and withdrawn, was "
		      "opened -- so an issuer can say both in one signed statement and "
		      "a receiver has to pick");
	}
}

/* A MANIFEST NAMES A WITHDRAWN PAIR AND SAYS SO, which reverses what this
 * case asserted earlier today.
 *
 * While an entry carried no state, publishing a withdrawn pair would have
 * told every receiver to revoke a pair the issuer had restored -- so `issue`
 * skipped it, and this case demanded that. The entry carries its state now,
 * and skipping is what leaves every other host revoked for ever: sec 57
 * records why absence cannot carry a withdrawal, since a manifest has
 * nothing monotonic in it and an old one replayed would un-revoke whatever
 * the issuer added since.
 *
 * THE CONTROL IS THE PAIR THAT IS STILL REVOKED, in the same manifest. Both
 * are named; they differ in one byte and in the id beside it, and a reader
 * that ignored the state would act on them identically. */
static void test_a_manifest_names_a_withdrawn_pair_as_withdrawn(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_cap_id_t cap_a, cap_b;
	uint8_t g5[FZN_PUBKEY_LEN];
	size_t len = 0, i, live = 0, gone = 0;

	fixture_init(&f);
	capability_id(&cap_a, 0x10);
	capability_id(&cap_b, 0x20);
	key(g5, 5);
	revoke(&f, f.root, &cap_a, g5);
	CHECK(revoke_then_withdraw(&f, f.root, &cap_b, g5),
	      "the fixture could not revoke and withdraw");
	CHECK(f.store.used == 2, "the store holds %zu entries, wanted 2", f.store.used);

	f.stub.identity = f.root[0];
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "issuing over a store holding a withdrawal was refused");
	CHECK(len == FZN_MANIFEST_LEN(2),
	      "the manifest is %zu bytes, wanted both pairs at %zu -- a withdrawn pair "
	      "that is not named cannot travel, so every other host stays revoked",
	      len, FZN_MANIFEST_LEN(2));

	if (fzn_manifest_open(bytes, len, &rec) != FZN_MANIFEST_OK) {
		CHECK(0, "the manifest will not open");
		return;
	}
	for (i = 0; i < fzn_manifest_count(rec); i++) {
		if (fzn_manifest_is_withdrawn(rec, i))
			gone++;
		else
			live++;
	}
	CHECK(live == 1 && gone == 1,
	      "the manifest names %zu revoked and %zu withdrawn, wanted one of each",
	      live, gone);

	/* THE STATE TRAVELS WITH THE RIGHT PAIR, not merely somewhere in the
	 * object. Entries are sorted by key, and 0x10 sorts before 0x20. */
	CHECK(fzn_ct_memeq(fzn_manifest_capability(rec, 0)->b, cap_a.b, FZN_CAP_ID_LEN) &&
	              !fzn_manifest_is_withdrawn(rec, 0),
	      "the still-revoked pair is not first and revoked");
	CHECK(fzn_ct_memeq(fzn_manifest_capability(rec, 1)->b, cap_b.b, FZN_CAP_ID_LEN) &&
	              fzn_manifest_is_withdrawn(rec, 1),
	      "the withdrawn pair is not second and withdrawn");

	/* AND THE ID IS THE ONE THE STORE HOLDS, which is what a receiver
	 * matches its own revocation against. Read from the store rather than
	 * recomputed, because recomputing it here would be this suite agreeing
	 * with itself. */
	for (i = 0; i < f.store.used; i++) {
		if (!fzn_ct_memeq(f.store.entries[i].capability.b, cap_b.b, FZN_CAP_ID_LEN))
			continue;
		CHECK(memcmp(fzn_manifest_id(rec, 1), f.store.entries[i].id,
		             FZN_REVOCATION_ID_LEN) == 0,
		      "the withdrawn entry names an id the store does not hold, so a "
		      "receiver cannot match its own revocation against it");
	}
}

/* THE DEFICIT ASKS A REPLICATION QUESTION, NOT AN AUTHORIZATION ONE.
 *
 * A peer that has not heard a withdrawal keeps naming the pair in its
 * manifest. If the completeness predicate were `fzn_revocation_covers`, that
 * pair would read as missing: the consumer would fetch the revocation,
 * admission would recognise the stale copy and store nothing, and the next
 * comparison would report it missing again -- for ever, against every peer
 * behind. `fzn_revocation_known` answers that the history is already here.
 *
 * Measured: with the predicate switched back, the rest of this suite stayed
 * green and only this case fails. */
static void test_a_withdrawn_pair_is_not_a_deficit(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_cap_id_t cap;
	uint8_t g5[FZN_PUBKEY_LEN];
	size_t len = 0;

	fixture_init(&f);
	capability_id(&cap, 0x10);
	key(g5, 5);

	CHECK(revoke_then_withdraw(&f, f.root, &cap, g5),
	      "the fixture could not revoke and withdraw");
	CHECK(fzn_revocation_covers(&f.store, f.root, &cap, g5) == 0,
	      "the pair is still revoked, so this case is not testing a withdrawal");

	/* THE PEER STILL HOLDS THE REVOCATION, so its manifest names the pair.
	 * Built from a second store rather than by hand, so the bytes are one
	 * this library really produces. */
	{
		struct fixture peer;

		fixture_init(&peer);
		revoke(&peer, peer.root, &cap, g5);
		peer.stub.identity = peer.root[0];
		CHECK(fzn_manifest_issue(peer.root, &peer.store, &peer.sign, bytes,
		                         sizeof(bytes), &len) == FZN_MANIFEST_OK &&
		              len == FZN_MANIFEST_LEN(1),
		      "the peer could not issue a manifest naming the pair");
	}
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");

	CHECK(fzn_manifest_follow(&f.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	stub_reset(&f.stub);
	CHECK(fzn_manifest_admit(&f.manifest, &f.store, rec, &f.sign) == FZN_MANIFEST_OK,
	      "the peer's manifest was refused");
	{
		fzn_manifest_pair_t out[4];
		size_t dropped = 0;
		size_t n = fzn_manifest_deficit(&f.manifest, f.root, out, 4, &dropped);

		CHECK(n == 0,
		      "a pair this host has withdrawn was reported as missing (%zu "
		      "entries), so every comparison with a peer that is behind asks "
		      "for it again", n);
	}
}

static void test_issue_derives_from_the_issuers_own_store(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	uint8_t other[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap_a, cap_b, cap_c;
	uint8_t g5[FZN_PUBKEY_LEN], g6[FZN_PUBKEY_LEN];
	size_t len = 0;

	fixture_init(&f);
	key(other, 7);
	capability_id(&cap_a, 0x10);
	capability_id(&cap_b, 0x20);
	capability_id(&cap_c, 0x30);
	key(g5, 5);
	key(g6, 6);

	/* Inserted out of order on purpose: the manifest's order is the
	 * canonical one, not the store's. */
	revoke(&f, f.root, &cap_c, g5);
	revoke(&f, f.root, &cap_a, g6);
	revoke(&f, f.root, &cap_b, g5);
	/* And one from a different issuer, which must not appear: a manifest
	 * is a statement about what THAT key has issued. */
	revoke(&f, other, &cap_a, g5);
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
	CHECK(fzn_ct_memeq(fzn_manifest_capability(rec, 0), cap_a.b, FZN_CAP_ID_LEN) &&
	              fzn_ct_memeq(fzn_manifest_capability(rec, 1), cap_b.b, FZN_CAP_ID_LEN) &&
	              fzn_ct_memeq(fzn_manifest_capability(rec, 2), cap_c.b, FZN_CAP_ID_LEN),
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
/* A SIGNER THAT REFUSES MUST LEAVE NOTHING A READER WOULD OPEN.
 *
 * `fzn_manifest_issue` lays the body down before it signs, so a caller who
 * ignored the return code would otherwise hold a well-formed manifest
 * carrying whatever the buffer had in it. manifest.c clears the record on
 * that path, and until now nothing here held it to that: sabotaging the
 * `memset` away left all 63 binaries green.
 *
 * chain_test.c has this case for `fzn_chain_mint` and has had it for some
 * time -- same guard, same comment, same shape -- which is what makes the
 * gap a test gap rather than a design question. The stub has carried a
 * `can_sign` flag the whole time; `fixture_init` sets it to 1 and nothing
 * ever set it to 0, so the refusal branch was unreachable from this file.
 *
 * THE BUFFER IS DIRTIED FIRST, and that is the whole test. Against a zeroed
 * buffer the guard is indistinguishable from its own absence, because the
 * bytes it writes are the bytes already there -- so a version of this case
 * that skipped the memset below would pass with the clear deleted and prove
 * nothing. */
static void test_a_refusing_signer_leaves_no_manifest_behind(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_cap_id_t cap_a;
	uint8_t g5[FZN_PUBKEY_LEN];
	size_t len = 0;

	fixture_init(&f);
	capability_id(&cap_a, 0x10);
	key(g5, 5);
	revoke(&f, f.root, &cap_a, g5);

	/* The positive control: with a willing signer this same call produces
	 * a manifest that opens. Without it, the refusal below is satisfied by
	 * an issue that never worked in the first place. */
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "the control manifest was not issued, so the refusal proves nothing");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "the control manifest will not open, so the refusal proves nothing");

	f.stub.identity = 0;
	f.stub.can_sign = 0;
	memset(bytes, 0xab, sizeof(bytes));
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_ERR_SIGNATURE,
	      "a refusing signer still produced a manifest");
	CHECK(fzn_manifest_open(bytes, FZN_MANIFEST_LEN(1), &rec) != FZN_MANIFEST_OK,
	      "a refused issue left something that opens as a manifest");
}

static void test_issue_refuses_a_store_it_cannot_read(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	size_t len = 0;

	fixture_init(&f);
	capability_id(&cap, 0x10);
	key(grantee, 5);
	revoke(&f, f.root, &cap, grantee);

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

/* THE CEILING `fzn_manifest_issue` KEEPS IS ITS OWN, AND NOTHING HERE REACHED
 * IT.
 *
 * `test_the_pair_ceiling_is_a_ceiling` above holds `fzn_manifest_open` to
 * FZN_MANIFEST_MAX_PAIRS, which is a bound on what a PEER may make this host
 * carry. The bound inside `issue` is a different question wearing the same
 * number: how large a manifest this host may make of its OWN store. A peer
 * cannot set that, so refusing a peer's does not cover it, and the largest
 * store anywhere in this file held eight.
 *
 * THE FAILURE IT PREVENTS IS SILENT. Deleting the guard does not overflow
 * `out` -- the `out_cap` case below is what catches that -- it writes a count
 * of 4095 into the sixteen-bit field and signs it, producing a manifest that
 * no receiver's `open` will accept, from the one function that is meant to be
 * unable to lie. The issuer learns nothing; every receiver refuses.
 *
 * THE STORE IS BUILT THROUGH `fzn_revocation_admit` RATHER THAN FILLED IN.
 * Every entry arrived as a signed record through the public door, so the
 * ceiling is shown to bound reachable behaviour rather than a struct a test
 * assembled. That distinction earns its cost here and does not below, where
 * the state under test is one `admit` cannot produce at all.
 *
 * DESCENDING ARRIVAL is deliberate twice over: it puts every insertion at
 * position 0, which makes this the only case in the file that moves a full
 * tail, and it is the cheap order -- ascending would run the position scan to
 * its end 4095 times.
 *
 * `out_cap` IS FZN_MANIFEST_MAX_LEN, AND THAT IS THE WHOLE TEST rather than a
 * detail. A larger buffer makes the guard unobservable: with it deleted the
 * loop simply runs on, writes a count of 4095, and the `fzn_manifest_open`
 * this function performs on its own bytes refuses it -- same error, same
 * absent manifest, nothing to see. The first version of this case used
 * `sizeof(huge)` and passed with the guard cut out.
 *
 * At exactly MAX_LEN the two answers diverge, and the divergence is the point
 * of the guard. A consumer that sized `out` to the largest manifest this
 * library carries has a CORRECT buffer and a store that has outgrown what can
 * be said in one; SHAPE tells it so, while the `out_cap` line reached in the
 * guard's absence answers MALFORMED and sends it to grow a buffer that is
 * already at the ceiling. */
static fzn_revocation_store_t crowd_store;
static fzn_revocation_t crowd_entries[FZN_MANIFEST_MAX_PAIRS + 1u];

static void test_issue_stops_at_its_own_pair_ceiling(void)
{
	struct fixture f;
	fzn_manifest_record_t rec;
	size_t len = 0;

	fixture_init(&f);
	fzn_revocation_store_init(&crowd_store, crowd_entries,
	                          (size_t)FZN_MANIFEST_MAX_PAIRS + 1u);

	for (size_t i = 0; i <= FZN_MANIFEST_MAX_PAIRS; i++) {
		uint8_t bytes[FZN_REVOCATION_LEN];
		fzn_revocation_record_t r;
		fzn_cap_id_t cap;
		uint8_t grantee[FZN_PUBKEY_LEN];

		capability_id(&cap, 0x40);
		fzn_put_be16(cap.b, (uint16_t)(FZN_MANIFEST_MAX_PAIRS - i));
		key(grantee, 5);

		f.stub.identity = f.root[0];
		if (fzn_revocation_issue(f.root, &cap, grantee, 1000, &f.sign, bytes) !=
		            FZN_CHAIN_OK ||
		    fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &r) != FZN_CHAIN_OK ||
		    fzn_revocation_admit(&crowd_store, fzn_revocation_offer_root(r), f.root,
		                         &f.sign, &HASH_OPS, NULL) != FZN_CHAIN_OK) {
			CHECK(0, "the fixture could not admit entry %zu of %u", i,
			      (unsigned)FZN_MANIFEST_MAX_PAIRS + 1u);
			return;
		}
		stub_reset(&f.stub);
	}
	CHECK(crowd_store.used == (size_t)FZN_MANIFEST_MAX_PAIRS + 1u,
	      "the store holds %zu entries and wanted %u, so the fixture deduplicated and "
	      "the ceiling is not what either call below reaches",
	      crowd_store.used, (unsigned)FZN_MANIFEST_MAX_PAIRS + 1u);

	/* THE CONTROL, and it is what makes the refusal mean the ceiling: one
	 * entry fewer, the same store, the same buffer, the same call. */
	crowd_store.used = FZN_MANIFEST_MAX_PAIRS;
	f.stub.identity = f.root[0];
	CHECK(fzn_manifest_issue(f.root, &crowd_store, &f.sign, huge, FZN_MANIFEST_MAX_LEN,
	                         &len) == FZN_MANIFEST_OK,
	      "a store holding exactly the ceiling could not be issued into a buffer of "
	      "exactly FZN_MANIFEST_MAX_LEN, so the refusal below proves nothing");
	CHECK(len == FZN_MANIFEST_MAX_LEN,
	      "the full manifest is %zu bytes rather than %zu, so it is not the largest "
	      "one this library will carry", len, (size_t)FZN_MANIFEST_MAX_LEN);
	if (fzn_manifest_open(huge, len, &rec) == FZN_MANIFEST_OK) {
		CHECK(fzn_manifest_count(rec) == FZN_MANIFEST_MAX_PAIRS,
		      "the full manifest names %zu pairs rather than %u",
		      fzn_manifest_count(rec), (unsigned)FZN_MANIFEST_MAX_PAIRS);
	} else {
		CHECK(0, "the largest manifest this issuer can derive does not open, so the "
		         "refusal below proves nothing");
	}

	crowd_store.used = (size_t)FZN_MANIFEST_MAX_PAIRS + 1u;
	len = 0;
	f.stub.identity = f.root[0];
	CHECK(fzn_manifest_issue(f.root, &crowd_store, &f.sign, huge, FZN_MANIFEST_MAX_LEN,
	                         &len) == FZN_MANIFEST_ERR_SHAPE,
	      "a store one entry past the ceiling did not answer SHAPE against a buffer "
	      "of exactly FZN_MANIFEST_MAX_LEN -- MALFORMED here blames a buffer that is "
	      "already as large as this library will carry");
	CHECK(len == 0, "a refused issue reported a length");
}

/* AN `out_cap` THAT FITS THE FIRST PAIRS AND NOT THE LAST.
 *
 * `fzn_manifest_issue` checks `out_cap` twice: once against
 * FZN_MANIFEST_MIN_LEN before it starts, which
 * `test_every_guard_refuses_its_own_argument` covers, and once per pair as
 * the count grows -- which nothing covered. The second is the one that stops
 * the insertion sort writing past the buffer, and it is the only guard a
 * caller has: how many entries the store holds for this issuer is not a
 * number the caller passed in, so a buffer sized for the estate as it was is
 * how this is reached in practice rather than by mistake.
 *
 * THE CONTROL IS ONE PAIR LARGER, so the refusal is the bound landing in the
 * right place rather than a small buffer failing for any reason. */
static void test_issue_refuses_an_output_too_small_for_the_store(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_cap_id_t cap_a, cap_b, cap_c;
	uint8_t g5[FZN_PUBKEY_LEN];
	size_t len = 0;

	fixture_init(&f);
	capability_id(&cap_a, 0x10);
	capability_id(&cap_b, 0x20);
	capability_id(&cap_c, 0x30);
	key(g5, 5);
	revoke(&f, f.root, &cap_a, g5);
	revoke(&f, f.root, &cap_b, g5);
	revoke(&f, f.root, &cap_c, g5);

	f.stub.identity = f.root[0];
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, FZN_MANIFEST_LEN(3),
	                         &len) == FZN_MANIFEST_OK,
	      "three pairs will not fit a buffer sized for three, so the refusal below "
	      "proves nothing");
	CHECK(len == FZN_MANIFEST_LEN(3), "it is %zu bytes rather than %zu", len,
	      FZN_MANIFEST_LEN(3));

	/* Room for two against a store holding three -- and comfortably past
	 * FZN_MANIFEST_MIN_LEN, so the opening guard cannot be what refuses. */
	len = 0;
	f.stub.identity = f.root[0];
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, FZN_MANIFEST_LEN(2),
	                         &len) == FZN_MANIFEST_ERR_MALFORMED,
	      "a buffer sized for two pairs took a store holding three");
	CHECK(len == 0, "a refused issue reported a length");
}

/* THE DUPLICATE `issue` SKIPS IS ONE ITS OWN STORE SAYS CANNOT BE THERE.
 *
 * manifest.c states the case and why it is handled anyway: a pair emitted
 * twice is a manifest signed by this issuer that no receiver's `open` will
 * accept, produced by the one function meant to be unable to lie. The skip
 * costs a comparison the position search was doing regardless.
 *
 * IT CANNOT BE REACHED THROUGH `fzn_revocation_admit`, AND THAT IS WHY THE
 * ENTRIES ARE WRITTEN IN DIRECTLY rather than a reason to leave it untested.
 * `store_sound` is the whole of what this module asks about a store, and a
 * store holding one pair twice satisfies it -- `used` is within `capacity`
 * and `entries` is not NULL. So the state is inside what the module accepts,
 * and what it does with it is exactly the open question. The alternative,
 * treating "admit cannot produce this" as coverage, is the reasoning that
 * left the guard unexecuted while the comment above it explained itself.
 *
 * THE CONTROL MAKES THE DUPLICATE DISTINCT IN ITS LAST BYTE, which is two
 * assertions in one: three pairs out means the missing second above was the
 * skip and not an entry lost elsewhere, and it means the skip compared all
 * sixty-four bytes rather than a prefix. */
static void test_issue_skips_a_duplicate_the_store_should_not_hold(void)
{
	struct fixture f;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	size_t len = 0;

	fixture_init(&f);
	f.store.used = 3;
	capability_id(&f.entries[0].capability, 0x10);
	key(f.entries[0].grantee, 5);
	memcpy(f.entries[0].issuer, f.root, FZN_PUBKEY_LEN);
	f.entries[1] = f.entries[0]; /* the duplicate, byte for byte */
	capability_id(&f.entries[2].capability, 0x20);
	key(f.entries[2].grantee, 5);
	memcpy(f.entries[2].issuer, f.root, FZN_PUBKEY_LEN);

	f.stub.identity = f.root[0];
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "a store holding one pair twice could not be issued at all");
	CHECK(len == FZN_MANIFEST_LEN(2),
	      "it is %zu bytes rather than the %zu the two distinct pairs take", len,
	      FZN_MANIFEST_LEN(2));
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "the manifest a duplicated store produced will not open, which is the "
	      "failure the skip exists to prevent");

	fixture_init(&f);
	f.store.used = 3;
	capability_id(&f.entries[0].capability, 0x10);
	key(f.entries[0].grantee, 5);
	memcpy(f.entries[0].issuer, f.root, FZN_PUBKEY_LEN);
	f.entries[1] = f.entries[0];
	capability_id_near(&f.entries[1].capability, 0x10);
	capability_id(&f.entries[2].capability, 0x20);
	key(f.entries[2].grantee, 5);
	memcpy(f.entries[2].issuer, f.root, FZN_PUBKEY_LEN);

	len = 0;
	f.stub.identity = f.root[0];
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	                      FZN_MANIFEST_OK &&
	              len == FZN_MANIFEST_LEN(3),
	      "three pairs differing only in one byte produced %zu bytes rather than %zu, "
	      "so the skip above is not what removed the second", len,
	      FZN_MANIFEST_LEN(3));
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
	fzn_cap_id_t cap_a, cap_b, cap_c;
	uint8_t g5[FZN_PUBKEY_LEN], g6[FZN_PUBKEY_LEN];
	size_t first_len = 0, second_len = 0;

	capability_id(&cap_a, 0x10);
	capability_id(&cap_b, 0x20);
	capability_id(&cap_c, 0x30);
	key(g5, 5);
	key(g6, 6);

	fixture_init(&a);
	revoke(&a, a.root, &cap_a, g5);
	revoke(&a, a.root, &cap_b, g6);
	revoke(&a, a.root, &cap_c, g5);

	/* The same three, learned in a different order, which is what two
	 * hosts of one user actually experience. */
	fixture_init(&b);
	revoke(&b, b.root, &cap_c, g5);
	revoke(&b, b.root, &cap_a, g5);
	revoke(&b, b.root, &cap_b, g6);

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
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	size_t len = 0;

	fixture_init(&f);
	key_near(near_root, 0);
	key(other, 7);
	key(third, 8);
	capability_id(&cap, 0x10);
	key(grantee, 5);

	revoke(&f, f.root, &cap, grantee);
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
	fzn_cap_id_t cap_a, cap_b;
	uint8_t g5[FZN_PUBKEY_LEN], g6[FZN_PUBKEY_LEN];
	size_t len = 0, dropped = 99;

	capability_id(&cap_a, 0x10);
	capability_id(&cap_b, 0x20);
	key(g5, 5);
	key(g6, 6);

	/* The issuer's own view: two revocations, so a two-pair manifest. */
	fixture_init(&f);
	revoke(&f, f.root, &cap_a, g5);
	revoke(&f, f.root, &cap_b, g6);
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
		CHECK(fzn_ct_memeq(want[0].capability.b, cap_a.b, FZN_CAP_ID_LEN) &&
		              fzn_ct_memeq(want[1].capability.b, cap_b.b, FZN_CAP_ID_LEN),
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
		revoke(&partial, partial.root, &cap_a, g5);
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
		              fzn_ct_memeq(want[0].capability.b, cap_b.b, FZN_CAP_ID_LEN),
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
	fzn_cap_id_t cap, near_cap;
	uint8_t grantee[FZN_PUBKEY_LEN], near_grantee[FZN_PUBKEY_LEN];
	size_t len = 0;

	capability_id(&cap, 0x10);
	capability_id_near(&near_cap, 0x10);
	key(grantee, 5);
	key_near(near_grantee, 5);

	CHECK(memcmp(cap.b, near_cap.b, FZN_CAP_ID_LEN - 1u) == 0 &&
	              cap.b[FZN_CAP_ID_LEN - 1u] != near_cap.b[FZN_CAP_ID_LEN - 1u],
	      "the two capabilities do not share a thirty-one byte prefix");
	CHECK(memcmp(grantee, near_grantee, FZN_PUBKEY_LEN - 1u) == 0 &&
	              grantee[FZN_PUBKEY_LEN - 1u] != near_grantee[FZN_PUBKEY_LEN - 1u],
	      "the two grantees do not share a thirty-one byte prefix");

	/* Four pairs from two capabilities and two grantees, each differing
	 * from its sibling only in the last byte. */
	fixture_init(&f);
	revoke(&f, f.root, &cap, grantee);
	revoke(&f, f.root, &cap, near_grantee);
	revoke(&f, f.root, &near_cap, grantee);
	revoke(&f, f.root, &near_cap, near_grantee);
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
		CHECK(fzn_revocation_issue(f.root, &cap, grantee, 1000, &joiner.sign, rev) ==
		              FZN_CHAIN_OK,
		      "issue");
		CHECK(fzn_revocation_open(rev, FZN_REVOCATION_LEN, &r) == FZN_CHAIN_OK, "open");
		CHECK(fzn_revocation_admit(&joiner.store, fzn_revocation_offer_root(r), f.root, &joiner.sign, &HASH_OPS,
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
	fzn_cap_id_t caps[4];
	uint8_t grantee[FZN_PUBKEY_LEN];
	size_t len = 0, dropped = 99;
	fzn_manifest_pair_t want[4];

	key(grantee, 5);
	for (uint8_t i = 0; i < 4; i++)
		capability_id(&caps[i], (uint8_t)(0x10u + i * 0x10u));

	fixture_init(&f);
	for (uint8_t i = 0; i < 4; i++)
		revoke(&f, f.root, &caps[i], grantee);
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
			CHECK(fzn_revocation_issue(f.root, &want[i].capability, want[i].grantee,
			                           1000, &side.sign, rev) == FZN_CHAIN_OK,
			      "issue");
			CHECK(fzn_revocation_open(rev, FZN_REVOCATION_LEN, &r) == FZN_CHAIN_OK,
			      "open");
			CHECK(fzn_revocation_admit(&side.store, fzn_revocation_offer_root(r), f.root, &side.sign, &HASH_OPS,
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
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	size_t len = 0;

	capability_id(&cap, 0x10);
	key(grantee, 5);

	fixture_init(&f);
	revoke(&f, f.root, &cap, grantee);
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
	uint8_t grantee[FZN_PUBKEY_LEN], victim[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	size_t len = 0;

	capability_id(&cap, 0x10);
	key(grantee, 5);
	key(victim, 9);

	fixture_init(&f);
	revoke(&f, f.root, &cap, grantee);
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
	capability_id((fzn_cap_id_t *)(bytes + FZN_MANIFEST_OFF_PAIRS), 0xff);
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
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap_a, cap_b;
	size_t len = 0;

	capability_id(&cap_a, 0x10);
	capability_id(&cap_b, 0x20);
	key(grantee, 5);

	fixture_init(&f);
	revoke(&f, f.root, &cap_a, grantee);
	revoke(&f, f.root, &cap_b, grantee);
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

/* ---- the gate, and what opens it -------------------------------------- */

/* WHICH STATE GATES AND WHICH DOES NOT. This test carries both halves of sec
 * 13d's split, because the pair is what the gate means: passing no state
 * changes nothing, and passing a state that reports a deficit against THIS
 * chain's grantor refuses. project.md sec 58 records the decision and the
 * scoping that makes it safe.
 *
 * THE HEADING AND THIS COMMENT BOTH SAID STAGE 2 WAS UNBUILT AND WAITING ON
 * THE COPYRIGHT HOLDER, for a day after it was built and while the function
 * below was already asserting the gate -- the function was renamed and its
 * comment was not. project.md sec 59 records the sweep that found it and the
 * three places in that document which said the same thing. */
static void test_stage_two_gates_on_this_chains_grantors(void)
{
	struct fixture f, joiner;
	static uint8_t bytes[FIXTURE_BYTES];
	uint8_t hop_bytes[FZN_HOP_LEN];
	fzn_manifest_record_t rec;
	fzn_chain_hop_t hops[1];
	fzn_chain_t out;
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	size_t len = 0;

	capability_id(&cap, 0x10);
	key(grantee, 5);

	fixture_init(&f);
	revoke(&f, f.root, &cap, grantee);
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len) ==
	              FZN_MANIFEST_OK,
	      "issue");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");

	fixture_init(&joiner);
	joiner.stub.identity = 0;
	CHECK(fzn_chain_mint(joiner.root, grantee, &cap, 1000, FZN_NO_EXPIRY, 0, &joiner.sign,
	                     hop_bytes) == FZN_CHAIN_OK,
	      "minting the hop this case is about failed");
	CHECK(fzn_hop_open(hop_bytes, FZN_HOP_LEN, &hops[0]) == FZN_CHAIN_OK, "open");
	CHECK(fzn_chain_verify(hops, 1, joiner.root, &cap, 2000, &joiner.sign, &joiner.store, NULL,
	                       &out) == FZN_CHAIN_OK,
	      "an unrevoked chain was refused before any manifest arrived");

	CHECK(fzn_manifest_follow(&joiner.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	CHECK(fzn_manifest_admit(&joiner.manifest, &joiner.store, rec, &joiner.sign) ==
	              FZN_MANIFEST_OK,
	      "admit");
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 1,
	      "this host does not know it is missing anything, so the check below is about "
	      "nothing");

	/* STAGE 1 STILL DOES NOT GATE ON ITS OWN. Passing no state is passing
	 * no knowledge, and a host that follows nobody has no grounds to
	 * believe it is behind. */
	CHECK(fzn_chain_verify(hops, 1, joiner.root, &cap, 2000, &joiner.sign, &joiner.store,
	                       NULL, &out) == FZN_CHAIN_OK,
	      "a known deficit changed what fzn_chain_verify answers with no manifest "
	      "state passed, so the gate is not the state's to open");

	/* AND STAGE 2 DOES. This assertion is the one that changed when the
	 * gate landed; it read that a deficit must change nothing, with
	 * "stage 2 is blocked on the copyright holder" beside it. */
	CHECK(fzn_chain_verify(hops, 1, joiner.root, &cap, 2000, &joiner.sign, &joiner.store,
	                       &joiner.manifest, &out) == FZN_CHAIN_ERR_INCOMPLETE,
	      "a host that knows it is missing revocations from this chain's grantor "
	      "verified the chain anyway, which is the defect sec 13d names: it cannot "
	      "tell 'nothing was revoked' from 'I am missing the revocations'");

	/* THE SCOPING, WHICH IS WHAT MAKES THE GATE SAFE TO HAVE. A deficit
	 * about an unrelated issuer says nothing about this chain. Without
	 * this the gate is sec 13d's "returning device refuses all", which
	 * together with the clock finding describes a brick. */
	{
		struct fixture other, host;
		static uint8_t other_bytes[FIXTURE_BYTES];
		fzn_manifest_record_t other_rec;
		uint8_t stranger[FZN_PUBKEY_LEN];
		size_t other_len = 0;

		key(stranger, 7);
		fixture_init(&other);
		revoke(&other, stranger, &cap, grantee);
		other.stub.identity = stranger[0];
		CHECK(fzn_manifest_issue(stranger, &other.store, &other.sign, other_bytes,
		                         sizeof(other_bytes), &other_len) ==
		              FZN_MANIFEST_OK,
		      "a stranger could not state its own revocations");
		CHECK(fzn_manifest_open(other_bytes, other_len, &other_rec) ==
		              FZN_MANIFEST_OK, "open");

		fixture_init(&host);
		host.stub.identity = 0;
		CHECK(fzn_manifest_follow(&host.manifest, stranger) == FZN_MANIFEST_OK,
		      "following the stranger was refused");
		CHECK(fzn_manifest_admit(&host.manifest, &host.store, other_rec,
		                         &host.sign) == FZN_MANIFEST_OK,
		      "the stranger's manifest was refused");
		CHECK(fzn_manifest_pending(&host.manifest, stranger) == 1,
		      "this host does not know it is missing the stranger's revocation, "
		      "so the check below is about nothing");
		CHECK(fzn_manifest_pending(&host.manifest, host.root) == 0,
		      "it also thinks it is missing something from the chain's grantor, "
		      "so a refusal below would not show the scoping");

		CHECK(fzn_chain_verify(hops, 1, host.root, &cap, 2000, &host.sign,
		                       &host.store, &host.manifest, &out) == FZN_CHAIN_OK,
		      "a deficit about an issuer that grants nothing in this chain "
		      "refused it, so the gate is unscoped and a returning device "
		      "refuses everything until it has caught up on everybody");
	}
}

/* ---- the revocation side of the seam ---------------------------------- */

static void test_a_revocation_settles_what_it_covers(void)
{
	struct fixture f, joiner;
	static uint8_t bytes[FIXTURE_BYTES];
	uint8_t rev[2][FZN_REVOCATION_LEN];
	fzn_manifest_record_t rec;
	fzn_revocation_record_t batch[2];
	fzn_revocation_offer_t offers[2];
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap_a, cap_b;
	fzn_chain_err_t err = FZN_CHAIN_OK;
	size_t len = 0, n;

	capability_id(&cap_a, 0x10);
	capability_id(&cap_b, 0x20);
	key(grantee, 5);

	fixture_init(&f);
	revoke(&f, f.root, &cap_a, grantee);
	revoke(&f, f.root, &cap_b, grantee);
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

	CHECK(fzn_revocation_issue(f.root, &cap_a, grantee, 1000, &joiner.sign, rev[0]) ==
	              FZN_CHAIN_OK,
	      "issue");
	CHECK(fzn_revocation_issue(f.root, &cap_b, grantee, 1000, &joiner.sign, rev[1]) ==
	              FZN_CHAIN_OK,
	      "issue");
	CHECK(fzn_revocation_open(rev[0], FZN_REVOCATION_LEN, &batch[0]) == FZN_CHAIN_OK,
	      "open");
	CHECK(fzn_revocation_open(rev[1], FZN_REVOCATION_LEN, &batch[1]) == FZN_CHAIN_OK,
	      "open");

	/* NULL PRESERVES TODAY'S BEHAVIOUR EXACTLY, which is what makes the
	 * parameter optional rather than a break. */
	CHECK(fzn_revocation_admit(&joiner.store, fzn_revocation_offer_root(batch[0]), f.root,
	                           &joiner.sign, &HASH_OPS, NULL) ==
	              FZN_CHAIN_OK,
	      "admit with no manifest state");
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 2,
	      "a NULL manifest state settled a deficit anyway, so the parameter is not "
	      "optional and every existing caller has changed behaviour");

	/* THE ALREADY-HELD PATH DRAINS TOO, or a host that received the
	 * revocation before wiring up its manifest reports a gap it has
	 * filled, for ever. */
	CHECK(fzn_revocation_admit(&joiner.store, fzn_revocation_offer_root(batch[0]), f.root,
	                           &joiner.sign, &HASH_OPS,
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
	offers[0] = fzn_revocation_offer_root(batch[0]);
	offers[1] = fzn_revocation_offer_root(batch[1]);
	n = fzn_revocation_merge(&joiner.store, offers, 2, f.root, &joiner.sign, &HASH_OPS, &err,
	                         &joiner.manifest);
	CHECK(n == 2 && err == FZN_CHAIN_OK, "merge admitted %zu, err %d", n, (int)err);
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 0,
	      "a merge left %zu pairs outstanding, so the drain is wired to the path "
	      "consumers use least",
	      fzn_manifest_pending(&joiner.manifest, f.root));
	CHECK(fzn_manifest_overflowed(&joiner.manifest, f.root) == 0,
	      "settling every pair reported the deficit as under-reported");
}

/* ---- the branches where this host is ahead ---------------------------- */

/* A HOST THAT HAS RECORDED A PAIR AS MISSING AND THEN HEARD THE WITHDRAWAL
 * FIRST, which is the arrangement all three legs below need and which nothing
 * in this tree built.
 *
 * The manifest is admitted against an EMPTY store, so the pair is recorded as
 * missing rather than skipped: `fzn_manifest_admit` treats a held record with
 * the same id as being ahead, and a host that already holds the withdrawal
 * would therefore record no deficit at all. The withdrawal lands second, as a
 * tombstone, which `revocation.h` calls ordinary rather than exceptional on a
 * mesh.
 *
 * Returns nonzero on success, so a caller stops rather than asserting against
 * a fixture that never built -- and the last check is part of the setup and
 * not decoration: a tombstone that drained the deficit by itself would leave
 * every leg below asserting about an empty table. */
/*
 * TWO HOSTS REVOKED THE SAME PAIR INDEPENDENTLY, so the ids differ.
 *
 * Found 2026-09-04 by measurement, not by reading. `fzn_manifest_admit` has a
 * three-row decision table written out in a comment, and one of its rows --
 *
 *     different records  -- neither of us can tell who is ahead from hashes
 *                           alone, so ask; admission sorts it out
 *
 * -- had never been exercised: `memcmp(mine, theirs) != 0` was taken 0% of
 * 4790 evaluations. Every existing case revokes at the fixed instant 1000, so
 * two hosts revoking one pair always produced byte-identical records and the
 * ids always matched.
 *
 * WHY THE ROW MATTERS. Two hosts revoking the same grant independently is an
 * ordinary network event, not a corner: a stolen device gets revoked by
 * whoever notices first, and a second holder who has not heard yet revokes it
 * too. If this host read "different id" as "I am ahead", it would never fetch
 * the record it lacks -- and the one it lacks might be the withdrawal, or a
 * later revocation covering more than its own does.
 *
 * THE CONTROL IS THE SAME TEST WITH ONE NUMBER CHANGED. Revoking at the same
 * instant makes the ids identical and this host IS ahead, so no deficit is
 * recorded. Without it, a deficit of one would be consistent with the
 * comparison never running at all.
 */
/*
 * BOTH SIDES WITHDREW, which is the first row of `fzn_manifest_admit`'s
 * decision table and the one branch of it nothing reached.
 *
 * Sec 81 measured `!mine_withdrawn` as evaluated 1480 times across the suite
 * and true every time, then declined the test: *"it needs a fixture where
 * both sides withdraw the same underlying revocation, which is more machinery
 * than the finding currently justifies."*
 *
 * **`revoke_then_withdraw` was already in this file, forty lines up.** The
 * estimate was made without looking, and it was the third cost judgement of
 * that day to come out wrong in the same direction -- see sec 90. The fixture
 * is two calls.
 *
 * WHAT THE ROW SAYS. Both hosts hold the same revocation and both have
 * withdrawn it, so their records agree completely and neither is behind. This
 * host is AHEAD in the table's sense -- there is nothing to fetch -- and must
 * record no deficit. Getting it wrong would re-record the pair on every
 * comparison with every peer, which is the re-fetch loop the drain exists to
 * stop, on the pairs most likely to be compared: the settled ones.
 */
static void test_both_sides_withdrew_the_same_revocation(void)
{
	struct fixture f;
	struct fixture peer;
	fzn_cap_id_t cap;
	uint8_t grantee[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_MANIFEST_MAX_LEN];
	size_t len = 0;
	fzn_manifest_record_t rec;
	fzn_manifest_pair_t out[4];
	size_t dropped = 0;

	memset(&cap, 0x81, sizeof(cap));
	memset(grantee, 0x82, sizeof(grantee));

	/* ---- both withdrew: nothing to fetch, so nothing to record ----- */
	fixture_init(&f);
	CHECK(revoke_then_withdraw(&f, f.root, &cap, grantee),
	      "this host could not revoke and withdraw");

	fixture_init(&peer);
	memcpy(peer.root, f.root, sizeof(peer.root));
	CHECK(revoke_then_withdraw(&peer, peer.root, &cap, grantee),
	      "the peer could not revoke and withdraw");
	peer.stub.identity = peer.root[0];
	CHECK(fzn_manifest_issue(peer.root, &peer.store, &peer.sign, bytes, sizeof(bytes),
	                         &len) == FZN_MANIFEST_OK,
	      "the peer could not issue a manifest naming the withdrawn pair");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "the peer's manifest did not open");
	CHECK(fzn_manifest_follow(&f.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	stub_reset(&f.stub);
	CHECK(fzn_manifest_admit(&f.manifest, &f.store, rec, &f.sign) == FZN_MANIFEST_OK,
	      "the peer's manifest was refused");
	CHECK(fzn_manifest_deficit(&f.manifest, f.root, out, 4, &dropped) == 0,
	      "both sides have withdrawn the same revocation and this host still asked "
	      "for it -- which is the re-fetch loop the drain exists to stop, on the "
	      "pairs most likely to be compared");

	/* ---- the control: only the PEER withdrew ----------------------- *
	 *
	 * Then they hold something this host does not, `mine_withdrawn` is
	 * false, and the deficit must be recorded. Without this the zero above
	 * is consistent with a comparison that records nothing at all. */
	fixture_init(&f);
	revoke(&f, f.root, &cap, grantee);

	fixture_init(&peer);
	memcpy(peer.root, f.root, sizeof(peer.root));
	CHECK(revoke_then_withdraw(&peer, peer.root, &cap, grantee),
	      "the peer could not revoke and withdraw for the control");
	peer.stub.identity = peer.root[0];
	CHECK(fzn_manifest_issue(peer.root, &peer.store, &peer.sign, bytes, sizeof(bytes),
	                         &len) == FZN_MANIFEST_OK,
	      "the peer could not issue the control manifest");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "the control manifest did not open");
	CHECK(fzn_manifest_follow(&f.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	stub_reset(&f.stub);
	CHECK(fzn_manifest_admit(&f.manifest, &f.store, rec, &f.sign) == FZN_MANIFEST_OK,
	      "the control manifest was refused");
	dropped = 0;
	CHECK(fzn_manifest_deficit(&f.manifest, f.root, out, 4, &dropped) == 1,
	      "the peer holds a withdrawal this host does not and it was not asked for, "
	      "so the zero above says nothing about mine_withdrawn");
}

static void test_two_hosts_revoked_the_same_pair_and_disagree(void)
{
	struct fixture f;
	struct fixture peer;
	fzn_cap_id_t cap;
	uint8_t grantee[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_MANIFEST_MAX_LEN];
	size_t len = 0;
	fzn_manifest_record_t rec;
	fzn_manifest_pair_t out[4];
	size_t dropped = 0;

	memset(&cap, 0x71, sizeof(cap));
	memset(grantee, 0x72, sizeof(grantee));

	/* ---- the ids DIFFER: this host cannot tell, so it must ask ----- */
	fixture_init(&f);
	revoke_at(&f, f.root, &cap, grantee, 1000);

	fixture_init(&peer);
	memcpy(peer.root, f.root, sizeof(peer.root));
	revoke_at(&peer, peer.root, &cap, grantee, 2000);
	peer.stub.identity = peer.root[0];
	CHECK(fzn_manifest_issue(peer.root, &peer.store, &peer.sign, bytes, sizeof(bytes),
	                         &len) == FZN_MANIFEST_OK,
	      "the peer could not issue a manifest, so nothing below is tested");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "the peer's manifest did not open");
	CHECK(fzn_manifest_follow(&f.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	stub_reset(&f.stub);
	CHECK(fzn_manifest_admit(&f.manifest, &f.store, rec, &f.sign) == FZN_MANIFEST_OK,
	      "the peer's manifest was refused");
	CHECK(fzn_manifest_deficit(&f.manifest, f.root, out, 4, &dropped) == 1,
	      "two hosts hold DIFFERENT records for one pair and this host did not ask "
	      "-- so a revocation it does not have is one it will never fetch");

	/* ---- the ids MATCH: this host is ahead and must not ask -------- */
	fixture_init(&f);
	revoke_at(&f, f.root, &cap, grantee, 1000);

	fixture_init(&peer);
	memcpy(peer.root, f.root, sizeof(peer.root));
	revoke_at(&peer, peer.root, &cap, grantee, 1000);
	peer.stub.identity = peer.root[0];
	CHECK(fzn_manifest_issue(peer.root, &peer.store, &peer.sign, bytes, sizeof(bytes),
	                         &len) == FZN_MANIFEST_OK,
	      "the peer could not issue the control manifest");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK,
	      "the control manifest did not open");
	CHECK(fzn_manifest_follow(&f.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	stub_reset(&f.stub);
	CHECK(fzn_manifest_admit(&f.manifest, &f.store, rec, &f.sign) == FZN_MANIFEST_OK,
	      "the control manifest was refused");
	dropped = 0;
	CHECK(fzn_manifest_deficit(&f.manifest, f.root, out, 4, &dropped) == 0,
	      "the two records are identical here, so this host is ahead and asking for "
	      "it again is the re-fetch loop the drain exists to stop");
}

static int host_ahead_of_its_deficit(struct fixture *host, fzn_manifest_record_t man,
                                     const uint8_t issuer[FZN_PUBKEY_LEN],
                                     const fzn_cap_id_t *capability,
                                     const uint8_t grantee[FZN_PUBKEY_LEN],
                                     const uint8_t target[FZN_REVOCATION_ID_LEN])
{
	uint8_t wd[FZN_REVOCATION_LEN];
	fzn_revocation_record_t rec;

	fixture_init(host);
	host->stub.identity = 0;
	if (fzn_manifest_follow(&host->manifest, issuer) != FZN_MANIFEST_OK)
		return 0;
	if (fzn_manifest_admit(&host->manifest, &host->store, man, &host->sign) !=
	    FZN_MANIFEST_OK)
		return 0;
	if (fzn_manifest_pending(&host->manifest, issuer) != 1)
		return 0;

	host->stub.identity = issuer[0];
	if (fzn_revocation_issue_withdrawal(issuer, capability, grantee, 2000, target,
	                                    &host->sign, wd) != FZN_CHAIN_OK)
		return 0;
	stub_reset(&host->stub);
	if (fzn_revocation_open(wd, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
		return 0;
	if (fzn_revocation_admit(&host->store, fzn_revocation_offer_root(rec), issuer,
	                         &host->sign, &HASH_OPS, NULL) != FZN_CHAIN_OK)
		return 0;
	return fzn_manifest_pending(&host->manifest, issuer) == 1;
}

/* THE DEFICIT DRAINS ON THE PATHS WHERE THIS HOST IS AHEAD, and none of the
 * three was held until this test.
 *
 * `fzn_revocation_admit` calls `fzn_manifest_satisfy` from five places.
 * `test_a_revocation_settles_what_it_covers` above reaches two of them -- an
 * entry already held and a fresh append -- plus the merge that wraps them.
 * The other three fire only when the store holds a WITHDRAWN entry for the
 * pair beside a live deficit, which no fixture built. Measured rather than
 * inferred: replacing `manifest` with NULL at each of the five calls in turn
 * and running the whole suite left it GREEN for these three. project.md sec
 * 60.
 *
 * WHY THIS IS WORSE THAN A DEFICIT THAT MERELY LINGERS. `manifest.c` states
 * the rule the drains implement -- "asking when I am in fact ahead fetches a
 * record that is refused as stale or unchained, and without the drain this
 * entry would be re-recorded on every comparison and re-fetched for ever".
 * Since the stage-2 gate landed that is not a wasted round trip:
 * `fzn_manifest_pending` never returns to zero, so this host refuses every
 * chain that issuer grants in, permanently and with no way out. It is sec
 * 13d's brick, reached by a route nobody costed -- and reached by a host
 * doing everything right.
 *
 * AND `test_a_withdrawn_pair_is_not_a_deficit` IS NOT IN CONFLICT WITH THIS.
 * It runs the ordinary order -- revoke, withdraw, then meet a peer that is
 * behind -- where the ids match, this host reads as ahead, and no deficit is
 * recorded at all. That is why these branches look unreachable and why
 * nothing built a fixture for them: they need the withdrawal to have arrived
 * FIRST, before there was anything to compare it against.
 *
 * EACH LEG REBUILDS THE FIXTURE, because each one drains the deficit it was
 * given and re-admitting the manifest cannot restore it: by then this host
 * holds the record the manifest names, so the comparison correctly finds
 * nothing missing. */
static void test_the_withdrawal_paths_drain_the_deficit(void)
{
	struct fixture peer, host;
	static uint8_t bytes[FIXTURE_BYTES];
	uint8_t rev[FZN_REVOCATION_LEN], other[FZN_REVOCATION_LEN];
	uint8_t id[FZN_REVOCATION_ID_LEN];
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_revocation_record_t rec, orec;
	fzn_manifest_record_t man;
	fzn_cap_id_t cap;
	size_t len = 0;

	capability_id(&cap, 0x10);
	key(grantee, 5);

	/* The peer holds one revocation of the pair and states it. Minted here
	 * rather than through `revoke` because both sides need the BYTES: the
	 * peer to store them, this host to name their hash in a withdrawal and
	 * to be handed them back in leg 1. */
	fixture_init(&peer);
	peer.stub.identity = peer.root[0];
	CHECK(fzn_revocation_issue(peer.root, &cap, grantee, 1000, &peer.sign, rev) ==
	              FZN_CHAIN_OK,
	      "the peer could not issue the revocation this test is about");
	stub_reset(&peer.stub);
	CHECK(fzn_revocation_open(rev, FZN_REVOCATION_LEN, &rec) == FZN_CHAIN_OK,
	      "the peer's revocation will not open");
	CHECK(stub_hash(NULL, id, sizeof(id), rev, FZN_REVOCATION_LEN),
	      "the fixture could not hash the record");
	CHECK(fzn_revocation_admit(&peer.store, fzn_revocation_offer_root(rec), peer.root,
	                           &peer.sign, &HASH_OPS, NULL) == FZN_CHAIN_OK,
	      "the peer's own store refused its revocation");
	peer.stub.identity = 0;
	CHECK(fzn_manifest_issue(peer.root, &peer.store, &peer.sign, bytes, sizeof(bytes),
	                         &len) == FZN_MANIFEST_OK,
	      "the peer could not state what it holds revoked");
	CHECK(fzn_manifest_open(bytes, len, &man) == FZN_MANIFEST_OK,
	      "the peer's manifest will not open");
	CHECK(fzn_manifest_count(man) == 1 && !fzn_manifest_is_withdrawn(man, 0),
	      "the peer's manifest does not name the pair as revoked, so it is not the "
	      "behind-peer this test needs");

	/* LEG 1: THE STALE COPY. The peer relays the very record this host
	 * withdrew, and will keep doing so, as will every peer that has not
	 * heard the withdrawal. It is ignored rather than refused -- nothing
	 * is wrong, a peer is behind -- and the deficit must drain anyway. */
	CHECK(host_ahead_of_its_deficit(&host, man, peer.root, &cap, grantee, id),
	      "the fixture for the stale-copy leg did not build, so the check below "
	      "is about nothing");
	CHECK(fzn_revocation_admit(&host.store, fzn_revocation_offer_root(rec), peer.root,
	                           &host.sign, &HASH_OPS, &host.manifest) == FZN_CHAIN_OK,
	      "a stale copy of a withdrawn revocation was refused rather than ignored");
	CHECK(fzn_revocation_covers(&host.store, peer.root, &cap, grantee) == 0,
	      "the stale copy re-revoked the pair, so this leg took some other branch "
	      "than the one it names");
	CHECK(fzn_manifest_pending(&host.manifest, peer.root) == 0,
	      "a stale copy left the deficit standing, so this host asks the same peer "
	      "for the same record for ever -- and with the stage-2 gate it refuses "
	      "that issuer's chains for as long as it does");

	/* LEG 2: AN UN-CHAINED RE-REVOCATION. A peer that never heard the
	 * withdrawal issues a fresh revocation of the pair, so it names
	 * nothing and is refused by the chaining rule. Refused, and the
	 * deficit still drains: this host is ahead of the record it just
	 * turned down, and asking again would ask the same question for
	 * ever. */
	CHECK(host_ahead_of_its_deficit(&host, man, peer.root, &cap, grantee, id),
	      "the fixture for the un-chained leg did not build");
	peer.stub.identity = peer.root[0];
	CHECK(fzn_revocation_issue(peer.root, &cap, grantee, 3000, &peer.sign, other) ==
	              FZN_CHAIN_OK,
	      "the peer could not issue a second revocation of the pair");
	stub_reset(&peer.stub);
	CHECK(fzn_revocation_open(other, FZN_REVOCATION_LEN, &orec) == FZN_CHAIN_OK,
	      "the second revocation will not open");
	CHECK(fzn_revocation_admit(&host.store, fzn_revocation_offer_root(orec), peer.root,
	                           &host.sign, &HASH_OPS,
	                           &host.manifest) == FZN_CHAIN_ERR_UNKNOWN_TARGET,
	      "an un-chained revocation over a withdrawal was admitted, so this leg is "
	      "not exercising the refusal it is named for");
	CHECK(fzn_manifest_pending(&host.manifest, peer.root) == 0,
	      "a refused un-chained record left the deficit standing, so the refusal "
	      "and the re-fetch chase each other for ever");

	/* LEG 3: A CHAINED REISSUE, which is the one that changes the store.
	 * The issuer revokes the pair again and names the record it is
	 * superseding, so the withdrawal is lifted -- and the deficit is
	 * settled by the ordinary meaning of settled, since this host now
	 * holds what the manifest named. */
	CHECK(host_ahead_of_its_deficit(&host, man, peer.root, &cap, grantee, id),
	      "the fixture for the chained leg did not build");
	peer.stub.identity = peer.root[0];
	CHECK(fzn_revocation_reissue(peer.root, &cap, grantee, 3000, id, &peer.sign,
	                             other) == FZN_CHAIN_OK,
	      "the peer could not chain a reissue to the record it supersedes");
	stub_reset(&peer.stub);
	CHECK(fzn_revocation_open(other, FZN_REVOCATION_LEN, &orec) == FZN_CHAIN_OK,
	      "the chained reissue will not open");
	CHECK(fzn_revocation_admit(&host.store, fzn_revocation_offer_root(orec), peer.root,
	                           &host.sign, &HASH_OPS, &host.manifest) == FZN_CHAIN_OK,
	      "a reissue chained to the record the withdrawal named was refused");
	CHECK(fzn_revocation_covers(&host.store, peer.root, &cap, grantee) == 1,
	      "the pair is not revoked after a chained reissue, so this leg took some "
	      "other branch than the one it names");
	CHECK(fzn_manifest_pending(&host.manifest, peer.root) == 0,
	      "a chained reissue that lifted the withdrawal left the deficit standing");
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

	CHECK(fzn_manifest_satisfy(NULL, f.root, &(fzn_cap_id_t){ { 0 } }, f.root) == 0, "satisfy on a null state");
	CHECK(fzn_manifest_satisfy(&f.manifest, NULL, &(fzn_cap_id_t){ { 0 } }, f.root) == 0, "a null issuer");
	CHECK(fzn_manifest_satisfy(&f.manifest, f.root, NULL, f.root) == 0, "a null capability");
	CHECK(fzn_manifest_satisfy(&f.manifest, f.root, &(fzn_cap_id_t){ { 0 } }, NULL) == 0, "a null grantee");

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
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	size_t len = 0, dropped = 99;

	capability_id(&cap, 0x10);
	key(grantee, 5);

	fixture_init(&f);
	revoke(&f, f.root, &cap, grantee);
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
	CHECK(fzn_manifest_satisfy(&f.manifest, f.root, &cap, grantee) == 0,
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
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	size_t len = 0;

	capability_id(&cap, 0x10);
	key(grantee, 5);

	fixture_init(&f);
	revoke(&f, f.root, &cap, grantee);
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

/* THE DEFICIT REPORT, RESUMED, which is what makes it a fetch path.
 *
 * `fzn_manifest_deficit`'s own comment names the hazard this closes: "the
 * scan runs in table order, so a host that overflows drops the same pairs
 * every round and never asks for them at all". A frame holds about ten pairs
 * and a returning host's deficit is a year of them, so the plain call hands
 * back the same prefix for ever and the tail is never requested -- the host
 * converges on what it could already see and stalls on the rest.
 *
 * THE PROPERTY IS COVERAGE, NOT ORDER. With a window smaller than the
 * deficit, feeding `next` back in must sweep every pair in
 * ceil(total / out_cap) calls and then start again. The test asserts that by
 * marking off which pairs it has seen and requiring a full set -- asserting a
 * particular sequence would pin the table's admission order, which the header
 * says nothing may depend on.
 */
/* TWO ISSUERS IN ONE TABLE, WHICH NOTHING HAD EVER PUT THERE.
 *
 * Every existing deficit test follows exactly one issuer, so the filter in
 * `fzn_manifest_deficit_from` -- the skip that decides whether an entry
 * belongs to the issuer being asked about -- has only ever seen entries that
 * match. Both its arms, the counting skip and the writing skip, were dark.
 *
 * A host following two issuers is the ordinary case rather than an exotic
 * one: an estate root and a delegated signer, or two estates sharing a host.
 * If that filter compared the wrong operand, or a truncated key, this host's
 * request to a peer would name another issuer's pending revocations -- asking
 * for what it does not need and, worse, reporting a deficit as satisfied when
 * the pairs that satisfied it belonged to somebody else.
 *
 * The two issuers get DIFFERENT numbers of pairs on purpose. Equal counts
 * would let a filter that ignores the issuer entirely still produce the right
 * total for each, which is the shape of an assertion that cannot fail. */
static void test_the_deficit_report_separates_two_issuers(void)
{
	struct fixture a, b, joiner;
	static uint8_t bytes_a[FIXTURE_BYTES], bytes_b[FIXTURE_BYTES];
	fzn_manifest_record_t rec_a, rec_b;
	fzn_manifest_pair_t got[4];
	fzn_cap_id_t cap[3];
	uint8_t grantee[3][FZN_PUBKEY_LEN];
	size_t len_a = 0, len_b = 0, dropped = 0, next = 0, n, i;

	for (i = 0; i < 3; i++) {
		capability_id(&cap[i], (uint8_t)(0xa0u + i));
		key(grantee[i], (uint8_t)(0xb0u + i));
	}

	/* Issuer A revokes one pair; issuer B revokes two. */
	fixture_init(&a);
	key(a.root, 0x11);
	revoke(&a, a.root, &cap[0], grantee[0]);
	a.stub.identity = a.root[0];
	CHECK(fzn_manifest_issue(a.root, &a.store, &a.sign, bytes_a, sizeof(bytes_a),
	                         &len_a) == FZN_MANIFEST_OK, "issuing A's manifest");
	CHECK(fzn_manifest_open(bytes_a, len_a, &rec_a) == FZN_MANIFEST_OK, "opening A");

	fixture_init(&b);
	key(b.root, 0x22);
	revoke(&b, b.root, &cap[1], grantee[1]);
	revoke(&b, b.root, &cap[2], grantee[2]);
	b.stub.identity = b.root[0];
	CHECK(fzn_manifest_issue(b.root, &b.store, &b.sign, bytes_b, sizeof(bytes_b),
	                         &len_b) == FZN_MANIFEST_OK, "issuing B's manifest");
	CHECK(fzn_manifest_open(bytes_b, len_b, &rec_b) == FZN_MANIFEST_OK, "opening B");

	/* One host follows both and admits both, so its deficit table holds
	 * three entries belonging to two different issuers. */
	fixture_init(&joiner);
	CHECK(fzn_manifest_follow(&joiner.manifest, a.root) == FZN_MANIFEST_OK,
	      "following A");
	CHECK(fzn_manifest_follow(&joiner.manifest, b.root) == FZN_MANIFEST_OK,
	      "following B");
	joiner.stub.identity = a.root[0];
	CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec_a, &joiner.sign) ==
	      FZN_MANIFEST_OK, "admitting A's manifest");
	joiner.stub.identity = b.root[0];
	CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec_b, &joiner.sign) ==
	      FZN_MANIFEST_OK, "admitting B's manifest");

	CHECK(fzn_manifest_pending(&joiner.manifest, a.root) == 1,
	      "A's deficit is not one");
	CHECK(fzn_manifest_pending(&joiner.manifest, b.root) == 2,
	      "B's deficit is not two");

	/* ASKED FOR A, ANSWERED ABOUT A. The array is larger than either
	 * answer, so a filter that ignored the issuer would return all three
	 * and this would catch it on the count alone. */
	memset(got, 0, sizeof(got));
	next = 0;
	n = fzn_manifest_deficit_from(&joiner.manifest, a.root, 0, got, 4, &dropped,
	                              &next);
	CHECK(n == 1, "asking about A returned %zu pairs, wanted one", n);
	CHECK(dropped == 0, "A's answer dropped something with room to spare");
	CHECK(fzn_ct_memeq(got[0].grantee, grantee[0], FZN_PUBKEY_LEN),
	      "asking about A returned a pair that is not A's");

	/* And about B, which has a different number -- so neither answer can
	 * be right by accident. */
	memset(got, 0, sizeof(got));
	next = 0;
	n = fzn_manifest_deficit_from(&joiner.manifest, b.root, 0, got, 4, &dropped,
	                              &next);
	CHECK(n == 2, "asking about B returned %zu pairs, wanted two", n);
	for (i = 0; i < n; i++)
		CHECK(!fzn_ct_memeq(got[i].grantee, grantee[0], FZN_PUBKEY_LEN),
		      "asking about B returned A's pair");
}

static void test_the_deficit_report_resumes_and_covers_everything(void)
{
	struct fixture f, joiner;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_manifest_pair_t window[2];
	fzn_cap_id_t cap[4];
	uint8_t grantee[4][FZN_PUBKEY_LEN];
	size_t len = 0, dropped = 0, next = 0, calls;
	int seen[4] = { 0, 0, 0, 0 };
	size_t i, j;

	/* Four revocations from one issuer, so the manifest names four pairs
	 * and the deficit table -- which holds exactly four -- fills without
	 * overflowing. An overflow here would make the sweep incomplete for a
	 * reason that is not the one under test. */
	fixture_init(&f);
	for (i = 0; i < 4; i++) {
		capability_id(&cap[i], (uint8_t)(0x40u + i));
		key(grantee[i], (uint8_t)(0x50u + i));
		revoke(&f, f.root, &cap[i], grantee[i]);
	}
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len)
	              == FZN_MANIFEST_OK, "issue");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");

	fixture_init(&joiner);
	CHECK(fzn_manifest_follow(&joiner.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec, &joiner.sign) == FZN_MANIFEST_OK,
	      "admit");
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 4,
	      "the deficit is %zu, wanted four", fzn_manifest_pending(&joiner.manifest, f.root));
	CHECK(fzn_manifest_overflowed(&joiner.manifest, f.root) == 0, "the table overflowed");

	/* THE PLAIN CALL CANNOT DO THIS, and showing it is what makes the new
	 * function an argument rather than an assertion: asked twice for two
	 * pairs, it returns the same two, for ever. */
	{
		fzn_manifest_pair_t a[2], b[2];
		size_t da = 0, db = 0;

		CHECK(fzn_manifest_deficit(&joiner.manifest, f.root, a, 2, &da) == 2, "two");
		CHECK(fzn_manifest_deficit(&joiner.manifest, f.root, b, 2, &db) == 2, "again");
		CHECK(memcmp(a, b, sizeof(a)) == 0,
		      "the plain report returned different pairs on an unchanged table, "
		      "so the hazard this test exists for is not real");
		CHECK(da == 2 && db == 2, "the pairs that did not fit were not counted");
	}

	next = 0;
	for (calls = 0; calls < 2; calls++) {
		size_t got = fzn_manifest_deficit_from(&joiner.manifest, f.root, next, window,
		                                       2, &dropped, &next);

		CHECK(got == 2, "a full window returned %zu pairs, wanted 2", got);
		CHECK(dropped == 2, "the pairs outside the window were not counted");
		for (i = 0; i < got; i++)
			for (j = 0; j < 4; j++)
				if (fzn_ct_memeq(window[i].capability.b, cap[j].b,
				                 FZN_CAP_ID_LEN))
					seen[j]++;
	}
	for (j = 0; j < 4; j++)
		CHECK(seen[j] == 1, "pair %zu was returned %d times in a full sweep, wanted once",
		      j, seen[j]);

	/* AND IT WRAPS. A fetch path that went quiet after one lap would stall
	 * a host whose peer did not hold the pairs it asked for first. */
	CHECK(next == 0, "the cursor did not wrap to the start after a full sweep");
	CHECK(fzn_manifest_deficit_from(&joiner.manifest, f.root, next, window, 2, &dropped,
	                                &next) == 2,
	      "the report went quiet after one lap");

	{
		fzn_manifest_pair_t a[4], b[4];
		size_t da = 0, db = 0;

		CHECK(fzn_manifest_deficit(&joiner.manifest, f.root, a, 4, &da) == 4, "plain");
		CHECK(fzn_manifest_deficit_from(&joiner.manifest, f.root, 0, b, 4, &db, NULL)
		              == 4, "from zero");
		CHECK(memcmp(a, b, sizeof(a)) == 0 && da == db,
		      "from = 0 does not agree with the plain call");
	}

	/* A cursor past the end is reduced rather than refused: a caller that
	 * kept one across a drain must not fall off the table. */
	CHECK(fzn_manifest_deficit_from(&joiner.manifest, f.root, 9999u, window, 2, &dropped,
	                                &next) == 2,
	      "a cursor past the end returned nothing");

	CHECK(fzn_manifest_deficit_from(&joiner.manifest, f.root, 0, window, 2, NULL, &next)
	              == 0, "a missing dropped counter was not refused");
	CHECK(fzn_manifest_deficit_from(&joiner.manifest, f.root, 0, window, 2, &dropped, NULL)
	              == 2, "a NULL cursor was refused");
	CHECK(fzn_manifest_deficit_from(NULL, f.root, 0, window, 2, &dropped, &next) == 0,
	      "a NULL state reported a deficit");
}

/* THE RECOVERY LOOP CONVERGES, which is the claim the cursor exists to
 * support and is not the same claim as the cursor working.
 *
 * `test_the_deficit_report_resumes_and_covers_everything` proves the function:
 * a full sweep names every pair once and wraps. This proves SUFFICIENCY --
 * that a host far behind, asking a peer in frame-sized windows, actually
 * reaches a zero deficit. That is `evidence.md`'s correct-function-versus-
 * working-feature split, and project.md sec 47 needs the second one: a fetch
 * path that plans perfectly and never converges heals nothing.
 *
 * THE PEER IS DELIBERATELY PARTIAL, and that is the whole design of this
 * case. It does not hold the two pairs the plain report would hand back
 * first. With `fzn_manifest_deficit` the host asks for those two for ever,
 * is answered "no" for ever, and never asks about the pairs the peer DOES
 * hold -- a live host, a willing peer, and no progress. The cursor is what
 * turns that into convergence, so the test asserts the deficit drains to
 * exactly what the peer could not supply, and no further.
 */
static void test_the_recovery_loop_drains_what_a_partial_peer_can_supply(void)
{
	struct fixture f, joiner;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_manifest_pair_t window[2];
	fzn_cap_id_t cap[4];
	uint8_t grantee[4][FZN_PUBKEY_LEN];
	uint8_t rev[4][FZN_REVOCATION_LEN];
	size_t len = 0, dropped = 0, next = 0;
	unsigned round;
	size_t i, j;

	fixture_init(&f);
	for (i = 0; i < 4; i++) {
		capability_id(&cap[i], (uint8_t)(0x70u + i));
		key(grantee[i], (uint8_t)(0x80u + i));
		revoke(&f, f.root, &cap[i], grantee[i]);
	}
	f.stub.identity = 0;
	CHECK(fzn_manifest_issue(f.root, &f.store, &f.sign, bytes, sizeof(bytes), &len)
	              == FZN_MANIFEST_OK, "issue");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");

	fixture_init(&joiner);
	joiner.stub.identity = 0;
	CHECK(fzn_manifest_follow(&joiner.manifest, f.root) == FZN_MANIFEST_OK, "follow");
	CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec, &joiner.sign) == FZN_MANIFEST_OK,
	      "admit");
	CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 4, "the deficit is not four");

	/* The revocation records the PEER holds. The library's store keeps the
	 * triple and not the signed bytes, so re-serving one is the consumer's
	 * storage -- which is why these live in the test rather than being read
	 * back out of `f.store`. */
	for (i = 0; i < 4; i++)
		CHECK(fzn_revocation_issue(f.root, &cap[i], grantee[i], 1000, &joiner.sign,
		                           rev[i]) == FZN_CHAIN_OK, "issue revocation");

	/* WHICH TWO THE PEER LACKS is decided by asking the plain report what it
	 * would hand back first, rather than by picking indices -- the table's
	 * admission order is not something a test may assume, and choosing by
	 * hand would make this case depend on it. */
	{
		fzn_manifest_pair_t first[2];
		size_t d0 = 0;
		int peer_has[4] = { 1, 1, 1, 1 };

		CHECK(fzn_manifest_deficit(&joiner.manifest, f.root, first, 2, &d0) == 2,
		      "the plain report did not name two pairs");
		for (i = 0; i < 2; i++)
			for (j = 0; j < 4; j++)
				if (fzn_ct_memeq(first[i].capability.b, cap[j].b,
				                 FZN_CAP_ID_LEN))
					peer_has[j] = 0;

		/* Rounds of ask-and-answer. Four rounds is more than the two a
		 * full sweep needs, so a loop that converges has room to and one
		 * that stalls has run out of excuses. */
		next = 0;
		for (round = 0; round < 4u; round++) {
			size_t got = fzn_manifest_deficit_from(&joiner.manifest, f.root, next,
			                                       window, 2, &dropped, &next);

			for (i = 0; i < got; i++) {
				fzn_revocation_record_t r;

				for (j = 0; j < 4; j++) {
					if (!fzn_ct_memeq(window[i].capability.b, cap[j].b,
					                  FZN_CAP_ID_LEN))
						continue;
					if (!peer_has[j])
						continue;
					CHECK(fzn_revocation_open(rev[j], FZN_REVOCATION_LEN, &r)
					              == FZN_CHAIN_OK, "open");
					CHECK(fzn_revocation_admit(&joiner.store,
					                           fzn_revocation_offer_root(r),
					                           f.root, &joiner.sign, &HASH_OPS,
					                           &joiner.manifest)
					              == FZN_CHAIN_OK, "admit");
				}
			}
		}

		/* EXACTLY WHAT THE PEER COULD NOT SUPPLY, and no more. Two is the
		 * right answer: it says the loop got everything obtainable and
		 * did not invent progress on what it could not obtain. */
		CHECK(fzn_manifest_pending(&joiner.manifest, f.root) == 2,
		      "the deficit drained to %zu, wanted the two the peer lacked",
		      fzn_manifest_pending(&joiner.manifest, f.root));

		/* AND THE TWO LEFT ARE THE TWO THE PEER LACKED, not two others --
		 * without this the count above is satisfied by a loop that
		 * fetched the wrong pair and left a right one behind. */
		{
			fzn_manifest_pair_t left[4];
			size_t dl = 0, n;

			n = fzn_manifest_deficit(&joiner.manifest, f.root, left, 4, &dl);
			CHECK(n == 2 && dl == 0, "the remaining deficit does not fit in four");
			for (i = 0; i < n; i++)
				for (j = 0; j < 4; j++)
					if (fzn_ct_memeq(left[i].capability.b, cap[j].b,
					                 FZN_CAP_ID_LEN))
						CHECK(peer_has[j] == 0,
						      "a pair the peer held was left outstanding");
		}
	}
}

/* THE SERVE SIDE, AND THE ROUND TRIP THAT MAKES IT A PAIR.
 *
 * `fzn_manifest_deficit_from` turns this host's deficit into a request;
 * `fzn_manifest_plan_offer` turns a peer's request into an answer. Either
 * alone is half a fetch path, so the case that matters is one host's want
 * list handed to another host's store -- which is what a fetch actually is
 * and what neither function's own test can show.
 */
static void test_a_want_list_is_answered_by_a_peer_that_holds_some(void)
{
	struct fixture holder, joiner;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_manifest_pair_t want[4];
	fzn_manifest_deficit_t asks[4];
	fzn_manifest_offer_t plan;
	fzn_cap_id_t cap[4];
	uint8_t grantee[4][FZN_PUBKEY_LEN];
	uint8_t holds[4];
	size_t len = 0, dropped = 0, n, i;

	/* The holder issued four revocations and holds all four. */
	fixture_init(&holder);
	for (i = 0; i < 4; i++) {
		capability_id(&cap[i], (uint8_t)(0xb0u + i));
		key(grantee[i], (uint8_t)(0xc0u + i));
		revoke(&holder, holder.root, &cap[i], grantee[i]);
	}
	holder.stub.identity = 0;
	CHECK(fzn_manifest_issue(holder.root, &holder.store, &holder.sign, bytes,
	                         sizeof(bytes), &len) == FZN_MANIFEST_OK, "issue");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");

	/* The joiner follows, admits the manifest, holds none of them. */
	fixture_init(&joiner);
	joiner.stub.identity = 0;
	CHECK(fzn_manifest_follow(&joiner.manifest, holder.root) == FZN_MANIFEST_OK, "follow");
	CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec, &joiner.sign) == FZN_MANIFEST_OK,
	      "admit");
	CHECK(fzn_manifest_pending(&joiner.manifest, holder.root) == 4, "deficit is not four");

	/* THE REQUEST: the joiner's deficit, as it would go on the wire. */
	n = fzn_manifest_deficit(&joiner.manifest, holder.root, want, 4, &dropped);
	CHECK(n == 4 && dropped == 0, "the joiner's request does not name four pairs");
	for (i = 0; i < 4; i++) {
		memcpy(asks[i].issuer, holder.root, FZN_PUBKEY_LEN);
		asks[i].capability = want[i].capability;
		memcpy(asks[i].grantee, want[i].grantee, FZN_PUBKEY_LEN);
	}

	/* THE ANSWER: the holder's store against that request. */
	memset(holds, 0xee, sizeof(holds));
	CHECK(fzn_manifest_plan_offer(&holder.store, asks, 4, holds, 4, &plan)
	              == FZN_MANIFEST_OK, "the holder refused a well-formed request");
	CHECK(plan.held == 4 && plan.examined == 4 && plan.truncated == 0,
	      "the holder holds %zu of four, examined %zu", plan.held, plan.examined);
	for (i = 0; i < 4; i++)
		CHECK(holds[i] == 1u, "want %zu was not offered by a host that holds it", i);

	/* A HOST THAT HOLDS NOTHING ANSWERS NOTHING, which is the control: without
	 * it every check above is satisfied by a function that always says 1. */
	memset(holds, 0xee, sizeof(holds));
	CHECK(fzn_manifest_plan_offer(&joiner.store, asks, 4, holds, 4, &plan)
	              == FZN_MANIFEST_OK, "the joiner refused a well-formed request");
	CHECK(plan.held == 0 && plan.examined == 4,
	      "a host holding none of them offered %zu", plan.held);
	for (i = 0; i < 4; i++)
		CHECK(holds[i] == 0u, "want %zu was offered by a host that lacks it", i);

	/* A PARTIAL HOLDER, since that is the real case and the one the loop
	 * test already showed converging: drop one pair from the holder's store
	 * by asking about a pair nobody issued. */
	{
		fzn_manifest_deficit_t mixed[2];
		uint8_t two[2];

		mixed[0] = asks[0];
		mixed[1] = asks[1];
		capability_id(&mixed[1].capability, 0xfeu); /* never revoked */
		CHECK(fzn_manifest_plan_offer(&holder.store, mixed, 2, two, 2, &plan)
		              == FZN_MANIFEST_OK, "the mixed request was refused");
		CHECK(plan.held == 1 && two[0] == 1u && two[1] == 0u,
		      "a partial holder did not answer one of two");
	}

	/* THE THREE RULES A SERVE PATH OWES, since the peer picks the number. */
	CHECK(fzn_manifest_plan_offer(&holder.store, asks, 0, holds, 4, &plan)
	              == FZN_MANIFEST_OK && plan.held == 0 && plan.examined == 0,
	      "a request naming nothing did not get nothing");
	CHECK(fzn_manifest_plan_offer(&holder.store, asks, 4, holds, 0, &plan)
	              == FZN_MANIFEST_ERR_MALFORMED,
	      "a zero capacity was read as unlimited rather than refused");
	CHECK(fzn_manifest_plan_offer(&holder.store, asks, 4, holds, 2, &plan)
	              == FZN_MANIFEST_OK && plan.examined == 2 && plan.truncated == 1,
	      "a request past the ceiling was not clipped and reported");

	/* AN UNSOUND STORE IS REFUSED, NOT ANSWERED -- the polarity that differs
	 * from `fzn_revocation_covers`, whose 1 for an unscannable store would
	 * make this promise every pair the peer named. */
	{
		fzn_revocation_store_t broken = holder.store;

		broken.used = broken.capacity + 1u;
		CHECK(fzn_manifest_plan_offer(&broken, asks, 4, holds, 4, &plan)
		              == FZN_MANIFEST_ERR_MALFORMED,
		      "a corrupt store answered instead of being refused");
		CHECK(plan.held == 0, "a refused offer still reported holdings");
	}

	CHECK(fzn_manifest_plan_offer(&holder.store, asks, 4, holds, 4, NULL)
	              == FZN_MANIFEST_ERR_MALFORMED, "a null plan was not refused");
}

/* THE WHOLE LOOP, ACROSS TWO PEERS NEITHER OF WHICH HOLDS EVERYTHING.
 *
 * The two tests above each use ONE peer: one proves the cursor sweeps, one
 * proves a want list is answered. Both are single-peer cases, and a network
 * is not -- the reason a host asks more than one peer is that no single peer
 * has the whole set, which is exactly the case neither test covers.
 *
 * WHAT IT DOES NOT TEST IS THE CURSOR, and the first draft of this comment
 * claimed it did. Measured: disabling the cursor -- `from = 0` on every call
 * -- leaves this case GREEN and fails only the sweep test above.
 *
 * The reason is worth keeping, because it is why a fetch loop is easier to
 * get right than it looks: **admitting a revocation DRAINS the deficit**, so
 * the table shrinks under a fixed window and the next call sees new pairs
 * anyway. The cursor earns its place where nothing drains -- a peer that
 * holds none of what it was asked for, which is the case the sweep test
 * builds deliberately. Here every pair is held by one of the two peers, so
 * something drains every round and the window advances by consumption rather
 * than by the cursor.
 *
 * So this test proves the PAIR converges across peers, and the sweep test
 * proves the cursor covers a deficit nothing is draining. Two properties,
 * two tests, and the comment said one of them twice until it was checked.
 */
static void test_two_partial_peers_between_them_complete_the_set(void)
{
	struct fixture issuer, a, b, joiner;
	static uint8_t bytes[FIXTURE_BYTES];
	fzn_manifest_record_t rec;
	fzn_cap_id_t cap[4];
	uint8_t grantee[4][FZN_PUBKEY_LEN];
	uint8_t rev[4][FZN_REVOCATION_LEN];
	fzn_manifest_pair_t window[2];
	fzn_manifest_deficit_t asks[2];
	fzn_manifest_offer_t plan;
	uint8_t holds[2];
	size_t len = 0, dropped = 0, next = 0, i, j;
	unsigned round;

	/* The issuer revokes four. */
	fixture_init(&issuer);
	for (i = 0; i < 4; i++) {
		capability_id(&cap[i], (uint8_t)(0xd0u + i));
		key(grantee[i], (uint8_t)(0xe0u + i));
		revoke(&issuer, issuer.root, &cap[i], grantee[i]);
	}
	issuer.stub.identity = 0;
	CHECK(fzn_manifest_issue(issuer.root, &issuer.store, &issuer.sign, bytes,
	                         sizeof(bytes), &len) == FZN_MANIFEST_OK, "issue");
	CHECK(fzn_manifest_open(bytes, len, &rec) == FZN_MANIFEST_OK, "open");
	for (i = 0; i < 4; i++)
		CHECK(fzn_revocation_issue(issuer.root, &cap[i], grantee[i], 1000,
		                           &issuer.sign, rev[i]) == FZN_CHAIN_OK, "issue rev");

	/* TWO PEERS SPLITTING THE SET, and neither can finish the joiner alone. */
	fixture_init(&a);
	fixture_init(&b);
	a.stub.identity = 0;
	b.stub.identity = 0;
	for (i = 0; i < 2; i++)
		revoke(&a, issuer.root, &cap[i], grantee[i]);
	for (i = 2; i < 4; i++)
		revoke(&b, issuer.root, &cap[i], grantee[i]);

	fixture_init(&joiner);
	joiner.stub.identity = 0;
	CHECK(fzn_manifest_follow(&joiner.manifest, issuer.root) == FZN_MANIFEST_OK, "follow");
	CHECK(fzn_manifest_admit(&joiner.manifest, NULL, rec, &joiner.sign) == FZN_MANIFEST_OK,
	      "admit");
	CHECK(fzn_manifest_pending(&joiner.manifest, issuer.root) == 4, "deficit is not four");

	/* Alternate peers, two wants at a time, feeding the cursor back. Six
	 * rounds is three laps of a four-pair deficit at a window of two, which
	 * is more than convergence needs and less than a loop that stalls would
	 * survive. */
	for (round = 0; round < 6u; round++) {
		struct fixture *peer = (round & 1u) ? &b : &a;
		size_t got = fzn_manifest_deficit_from(&joiner.manifest, issuer.root, next,
		                                       window, 2, &dropped, &next);

		if (got == 0)
			break;
		for (i = 0; i < got; i++) {
			memcpy(asks[i].issuer, issuer.root, FZN_PUBKEY_LEN);
			asks[i].capability = window[i].capability;
			memcpy(asks[i].grantee, window[i].grantee, FZN_PUBKEY_LEN);
		}
		CHECK(fzn_manifest_plan_offer(&peer->store, asks, got, holds, 2, &plan)
		              == FZN_MANIFEST_OK, "a peer refused a well-formed request");

		for (i = 0; i < got; i++) {
			fzn_revocation_record_t r;

			if (!holds[i])
				continue;
			for (j = 0; j < 4; j++) {
				if (!fzn_ct_memeq(asks[i].capability.b, cap[j].b, FZN_CAP_ID_LEN))
					continue;
				CHECK(fzn_revocation_open(rev[j], FZN_REVOCATION_LEN, &r)
				              == FZN_CHAIN_OK, "open rev");
				CHECK(fzn_revocation_admit(&joiner.store,
				                           fzn_revocation_offer_root(r),
				                           issuer.root, &joiner.sign, &HASH_OPS,
				                           &joiner.manifest) == FZN_CHAIN_OK,
				      "admit rev");
			}
		}
	}

	/* THE PROPERTY: neither peer could finish it and together they did. */
	CHECK(fzn_manifest_pending(&joiner.manifest, issuer.root) == 0,
	      "the deficit is %zu after alternating two partial peers, wanted zero",
	      fzn_manifest_pending(&joiner.manifest, issuer.root));

	/* AND THE CONTROL, without which the above is satisfied by one peer
	 * having held everything: each peer alone leaves two outstanding. */
	{
		struct fixture solo;
		size_t d2 = 0, n2 = 0;
		fzn_manifest_pair_t all[4];

		fixture_init(&solo);
		solo.stub.identity = 0;
		CHECK(fzn_manifest_follow(&solo.manifest, issuer.root) == FZN_MANIFEST_OK,
		      "follow");
		CHECK(fzn_manifest_admit(&solo.manifest, NULL, rec, &solo.sign)
		              == FZN_MANIFEST_OK, "admit");
		n2 = fzn_manifest_deficit(&solo.manifest, issuer.root, all, 4, &d2);
		CHECK(n2 == 4, "the solo joiner does not lack four");
		{
			fzn_manifest_deficit_t four[4];
			uint8_t h4[4];

			for (i = 0; i < 4; i++) {
				memcpy(four[i].issuer, issuer.root, FZN_PUBKEY_LEN);
				four[i].capability = all[i].capability;
				memcpy(four[i].grantee, all[i].grantee, FZN_PUBKEY_LEN);
			}
			CHECK(fzn_manifest_plan_offer(&a.store, four, 4, h4, 4, &plan)
			              == FZN_MANIFEST_OK && plan.held == 2,
			      "peer A alone offered %zu of four, wanted two", plan.held);
			CHECK(fzn_manifest_plan_offer(&b.store, four, 4, h4, 4, &plan)
			              == FZN_MANIFEST_OK && plan.held == 2,
			      "peer B alone offered %zu of four, wanted two", plan.held);
		}
	}
}

int main(void)
{
	test_layout_and_round_trip();
	test_the_object_tag_is_in_the_transcript();
	test_open_refuses_what_is_not_our_shape();
	test_the_pair_ceiling_is_a_ceiling();
	test_the_ordering_reads_the_whole_pair();
	test_encode_refuses_what_open_would();
	test_a_state_byte_has_two_values();
	test_two_opinions_about_one_pair_are_refused();
	test_a_manifest_names_a_withdrawn_pair_as_withdrawn();
	test_a_withdrawn_pair_is_not_a_deficit();
	test_issue_derives_from_the_issuers_own_store();
	test_issue_refuses_a_store_it_cannot_read();
	test_issue_stops_at_its_own_pair_ceiling();
	test_issue_refuses_an_output_too_small_for_the_store();
	test_issue_skips_a_duplicate_the_store_should_not_hold();
	test_a_refusing_signer_leaves_no_manifest_behind();
	test_issuing_is_deterministic();
	test_following_is_deliberate();
	test_the_deficit_is_what_this_host_lacks();
	test_the_deficit_report_separates_two_issuers();
	test_the_deficit_report_resumes_and_covers_everything();
	test_the_recovery_loop_drains_what_a_partial_peer_can_supply();
	test_a_want_list_is_answered_by_a_peer_that_holds_some();
	test_two_partial_peers_between_them_complete_the_set();
	test_the_deficit_reads_the_whole_field();
	test_the_overflow_flag_is_sticky();
	test_a_corrupt_store_is_refused_rather_than_believed();
	test_a_forged_pair_is_refused();
	test_a_truncated_manifest_is_refused();
	test_stage_two_gates_on_this_chains_grantors();
	test_a_revocation_settles_what_it_covers();
	test_the_withdrawal_paths_drain_the_deficit();
	test_every_guard_refuses_its_own_argument();
	test_a_state_whose_fields_disagree_is_refused();
	test_two_hosts_revoked_the_same_pair_and_disagree();
	test_both_sides_withdrew_the_same_revocation();
	test_the_suite_can_tell_pass_from_fail();

	printf("manifest_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
