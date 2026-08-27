/* Tests for chain/revocation.c: the record's canonical encoding, admission,
 * and that the store's contents are directly usable by fzn_chain_verify --
 * which is the reason the store keeps verified `fzn_revocation_t` rather
 * than the records it was given.
 *
 * THE STUB ANSWERS OVER THE MESSAGE NOW (2026-08-27), for the reason
 * chain/test/chain_test.c gives at length. A record used to carry decoded
 * fields beside an opaque signed region nothing compared them with, and
 * `fzn_revocation_admit` verified the region and then stored the FIELDS -- so
 * one genuine root-signed revocation could be replayed with `grantee`
 * rewritten to any host an attacker cared to name. Permanently, because
 * nothing here evicts or expires. A stub that threw the message away could
 * not see it.
 */

#include "../revocation.h"

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
	printf("  FAIL revocation_test.c:%d: ", line);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* How many verifications this file can record the key of. The longest case
 * here merges a handful of records, one verification each. */
#define MAX_KEYS_SEEN 8

/* The same toy MAC chain_test.c uses, and the same argument for it: what a
 * test signer owes this suite is an answer that depends on every byte of the
 * message and on who signed. Identity is the key's first byte, and every key
 * here carries its seed there -- see `expand`. */
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

	/* WHICH KEY EACH VERIFICATION USED, recorded in order.
	 *
	 * This stub opened `(void)pubkey;` and threw the key away, so the suite
	 * could count verifications but not see WHOSE signature was checked.
	 * revocation.c verifies under the record's issuer; mutating that to its
	 * grantee -- the party being revoked rather than the party revoking --
	 * lets a device sign its own revocation record, or refuse to, and this
	 * file was green on it. The issuer check above the verification pins
	 * the issuer to the root, so the return code and the call count are
	 * identical under the mutation: only the key tells them apart. */
	size_t keys_seen;
	uint8_t key_seen[MAX_KEYS_SEEN][FZN_PUBKEY_LEN];
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

/* Distinct 32-byte values, built from a single seed byte so a failure
 * message can name them.
 *
 * BYTE 0 IS THE SEED AND EVERY LATER BYTE VARIES WITH ITS POSITION. It used
 * to be thirty-two copies of the seed, and that left every length constant
 * in `chain/revocation.c` unobservable: a value of one repeated byte
 * answers any prefix exactly as it answers the whole, so `same()`'s three
 * comparisons could each be cut to a single byte and this file -- and the
 * rest of the suite, fuzz campaigns included -- stayed green.
 *
 * Byte 0 stays the seed because the stub above derives identity from
 * `pubkey[0]`. */
static void expand(uint8_t *out, size_t len, uint8_t seed)
{
	out[0] = seed;
	for (size_t i = 1; i < len; i++)
		out[i] = (uint8_t)(seed ^ (uint8_t)i);
}

/* The same value with only its LAST byte changed -- the pair that decides a
 * comparison's LENGTH.
 *
 * Position-varying values are not enough on their own: two built from equal
 * seeds are equal in every byte, so a truncated comparison still answers
 * what a full one would. A near miss agrees on every byte a short read
 * reaches and differs on one it does not, which settles every truncation
 * from one byte to thirty-one at once. Identity is untouched, so a near
 * miss can still be signed and verified and reach the comparison under
 * test. */
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

struct fixture {
	fzn_revocation_store_t store;
	fzn_revocation_t entries[4];
	uint8_t root[FZN_PUBKEY_LEN];
	stub_t stub;
	fzn_sign_ops_t sign;
};

static void fixture_init(struct fixture *f)
{
	memset(f, 0, sizeof(*f));
	fzn_revocation_store_init(&f->store, f->entries, 4);
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
	memset(s->key_seen, 0, sizeof(s->key_seen));
}

/* Issue a real, signed revocation into `bytes` and open a view over it.
 *
 * THE FIXTURES BUILD REAL RECORDS NOW. They used to fill a struct and point
 * every one of them at a single shared `REGION` string literal, which was
 * possible only because nothing related a record's bytes to its fields --
 * the design defect wearing its test-suite costume. */
static void issue_keys(struct fixture *f, uint8_t *bytes, fzn_revocation_record_t *view,
                       const uint8_t *issuer_key, const uint8_t *capability,
                       const uint8_t *grantee_key)
{
	f->stub.identity = issuer_key[0];

	if (fzn_revocation_issue(issuer_key, capability, grantee_key, 1000, &f->sign, bytes) !=
	    FZN_CHAIN_OK) {
		printf("  FAIL: the fixture could not issue a revocation\n");
		failures++;
		return;
	}
	if (fzn_revocation_open(bytes, FZN_REVOCATION_LEN, view) != FZN_CHAIN_OK) {
		printf("  FAIL: the fixture issued a record that will not open\n");
		failures++;
	}
	stub_reset(&f->stub);
}

/* The same, named by seed, which is what nearly every case here wants. */
static void issue(struct fixture *f, uint8_t *bytes, fzn_revocation_record_t *view,
                  uint8_t issuer, uint8_t cap, uint8_t grantee)
{
	uint8_t issuer_key[FZN_PUBKEY_LEN], grantee_key[FZN_PUBKEY_LEN];
	uint8_t capability[FZN_CAP_ID_LEN];

	key(issuer_key, issuer);
	key(grantee_key, grantee);
	capability_id(capability, cap);
	issue_keys(f, bytes, view, issuer_key, capability, grantee_key);
}

/* ---- the layout ------------------------------------------------------- */

static void test_layout_and_round_trip(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN], again[FZN_REVOCATION_LEN];
	fzn_revocation_record_t rec;
	uint8_t issuer[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN], cap[FZN_CAP_ID_LEN];

	CHECK(FZN_REVOCATION_BODY_LEN == 106u, "revocation body is %u bytes, the table says 106",
	      (unsigned)FZN_REVOCATION_BODY_LEN);
	CHECK(FZN_REVOCATION_LEN == 170u, "revocation is %u bytes, the table says 170",
	      (unsigned)FZN_REVOCATION_LEN);
	CHECK(FZN_REV_OFF_SIGNATURE == FZN_REVOCATION_BODY_LEN,
	      "the signature does not begin where the body ends");

	fixture_init(&f);
	key(issuer, 0);
	key(grantee, 5);
	capability_id(cap, 0xc0);

	CHECK(fzn_revocation_encode(bytes, issuer, cap, grantee, 0x0102030405060708ull) ==
	              FZN_CHAIN_OK,
	      "encoding a revocation failed");
	CHECK(bytes[FZN_REV_OFF_VERSION] == 1u, "version byte is %u, wanted 1",
	      bytes[FZN_REV_OFF_VERSION]);
	CHECK(bytes[FZN_REV_OFF_OBJECT] == 2u,
	      "object byte is %u, wanted FZN_OBJECT_REVOCATION", bytes[FZN_REV_OFF_OBJECT]);
	/* Big-endian, spelled out rather than only round-tripped through this
	 * library's own accessors -- which would pass just as happily on bytes
	 * nobody else can read. */
	CHECK(bytes[FZN_REV_OFF_ISSUED_AT] == 0x01u && bytes[FZN_REV_OFF_ISSUED_AT + 7u] == 0x08u,
	      "issued_at is not big-endian");

	/* encode -> open -> read reproduces the fields... */
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &rec) == FZN_CHAIN_OK, "open");
	CHECK(fzn_ct_memeq(fzn_revocation_issuer(rec), issuer, FZN_PUBKEY_LEN),
	      "issuer did not survive the round trip");
	CHECK(fzn_ct_memeq(fzn_revocation_grantee(rec), grantee, FZN_PUBKEY_LEN),
	      "grantee did not survive the round trip");
	CHECK(fzn_ct_memeq(fzn_revocation_capability(rec), cap, FZN_CAP_ID_LEN),
	      "capability did not survive the round trip");
	CHECK(fzn_revocation_issued_at(rec) == 0x0102030405060708ull,
	      "issued_at did not survive the round trip");

	/* ...and open -> re-encode reproduces the bytes, which is the half
	 * that says the accessors and the encoder describe one layout. */
	CHECK(fzn_revocation_encode(again, fzn_revocation_issuer(rec),
	                            fzn_revocation_capability(rec), fzn_revocation_grantee(rec),
	                            fzn_revocation_issued_at(rec)) == FZN_CHAIN_OK,
	      "re-encoding from the accessors failed");
	CHECK(memcmp(again, bytes, FZN_REVOCATION_BODY_LEN) == 0,
	      "re-encoding what the accessors read did not reproduce the signed bytes");
}

static void test_open_refuses_what_is_not_our_shape(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t rec;

	fixture_init(&f);
	issue(&f, bytes, &rec, 0, 0xc0, 5);

	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &rec) == FZN_CHAIN_OK,
	      "the positive control does not open, so every refusal below proves nothing");

	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN - 1u, &rec) == FZN_CHAIN_ERR_SHAPE,
	      "a record one byte short was accepted");
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN + 1u, &rec) == FZN_CHAIN_ERR_SHAPE,
	      "a record with a trailing byte was accepted, so the length is not exact");

	bytes[FZN_REV_OFF_VERSION] = 2u;
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &rec) == FZN_CHAIN_ERR_SHAPE,
	      "a record claiming version 2 was accepted");
	bytes[FZN_REV_OFF_VERSION] = 1u;

	/* THE DOMAIN SEPARATION EARNING ITS PLACE. One root key signs hops and
	 * revocations through the same seam, so without this byte -- inside
	 * the signed range -- a signature made for one could be presented as
	 * the other wherever the encodings can be made to collide. */
	bytes[FZN_REV_OFF_OBJECT] = 1u;
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &rec) == FZN_CHAIN_ERR_SHAPE,
	      "an otherwise valid revocation tagged as a hop was accepted as a revocation");
	bytes[FZN_REV_OFF_OBJECT] = 2u;
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &rec) == FZN_CHAIN_OK,
	      "putting the object byte back did not restore the control");

	CHECK(fzn_revocation_open(NULL, FZN_REVOCATION_LEN, &rec) == FZN_CHAIN_ERR_MALFORMED,
	      "null bytes");
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, NULL) == FZN_CHAIN_ERR_MALFORMED,
	      "null out");
}

/* ---- admission -------------------------------------------------------- */

static void test_admits_a_signed_revocation(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;
	uint8_t grantee[FZN_PUBKEY_LEN];

	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);
	key(grantee, 5);

	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK,
	      "a properly signed revocation was refused");
	CHECK(f.store.used == 1, "used %zu, wanted 1", f.store.used);
	CHECK(fzn_revocation_covers(&f.store, fzn_revocation_issuer(r),
	                            fzn_revocation_capability(r), fzn_revocation_grantee(r)),
	      "the store does not report what it just admitted");
	CHECK(f.stub.calls == 1, "verified %d times, wanted 1", f.stub.calls);

	/* UNDER THE ISSUER'S KEY, which is the property the count cannot see.
	 *
	 * A revocation is the root saying "this grantee is done". Verified
	 * under the grantee instead, the revoked device is the one asked to
	 * vouch for its own revocation -- so it can withhold the signature and
	 * stay authorised, which is the whole failure revocation exists to
	 * prevent. */
	CHECK(f.stub.keys_seen == 1, "recorded %zu keys, wanted 1", f.stub.keys_seen);
	CHECK(f.stub.keys_seen == 1 && fzn_ct_memeq(f.stub.key_seen[0],
	                                            fzn_revocation_issuer(r), FZN_PUBKEY_LEN),
	      "the revocation was not verified under its issuer's key");
	/* And the fixture must be able to tell the two apart, or the check
	 * above is satisfied by a record whose issuer is its own grantee. */
	CHECK(!fzn_ct_memeq(fzn_revocation_issuer(r), fzn_revocation_grantee(r), FZN_PUBKEY_LEN),
	      "the fixture's issuer and grantee are the same key, so the check above "
	      "proves nothing");
}

static void test_a_carrier_cannot_invent_one(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;

	/* The whole reason a revocation is signed. Carried on contact means
	 * the peer handing it over is not the issuer, so a record from
	 * anybody but the root is refused however well-formed it looks -- and
	 * this one is genuinely signed by that peer, which is the point. */
	fixture_init(&f);
	issue(&f, bytes, &r, 7, 0xc0, 5); /* issued by some peer, not the root */

	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_ERR_WRONG_ROOT,
	      "a revocation issued by a carrier was accepted");
	CHECK(f.store.used == 0, "it was recorded anyway");
	CHECK(f.stub.calls == 0, "a signature was verified for an issuer already refused");

	/* And a forged signature under the right issuer is refused too. */
	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);
	bytes[FZN_REV_OFF_SIGNATURE] ^= 0x01u;
	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a revocation with a bad signature was accepted");
	CHECK(f.store.used == 0, "it was recorded anyway");
}

static void test_hearing_it_twice_is_not_an_error(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;

	/* Two peers both telling you is what carried-on-contact looks like
	 * every time it works. A caller treating the second as a failure
	 * would alarm on the system behaving correctly. */
	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);

	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK, "first");
	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK,
	      "hearing the same revocation twice was an error");
	CHECK(f.store.used == 1, "the duplicate took a second slot");
}

static void test_a_full_store_refuses_and_does_not_evict(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;

	/* Unlike the replay window, this refusal fails OPEN. Nothing is
	 * evicted, because a revocation that lapses un-revokes a device and
	 * every entry is protecting against something. */
	fixture_init(&f);
	for (uint8_t i = 0; i < 4; i++) {
		issue(&f, bytes, &r, 0, 0xc0, (uint8_t)(10 + i));
		CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK,
		      "filling entry %u", i);
	}

	issue(&f, bytes, &r, 0, 0xc0, 99);
	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_ERR_STORE_FULL,
	      "a full store admitted a fifth revocation");

	/* The first entry must still be there -- an evicting store would have
	 * silently un-revoked it. */
	{
		uint8_t cap[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN];

		capability_id(cap, 0xc0);
		key(grantee, 10);
		CHECK(fzn_revocation_covers(&f.store, f.root, cap, grantee),
		      "a full store evicted an earlier revocation, un-revoking a device");
	}
}

static void test_merge_keeps_going_past_a_bad_record(void)
{
	struct fixture f;
	uint8_t bytes[3][FZN_REVOCATION_LEN];
	fzn_revocation_record_t batch[3];
	fzn_chain_err_t err = FZN_CHAIN_OK;
	size_t n;

	/* One forged record must not stop a host learning the genuine ones
	 * beside it, or appending rubbish to a batch becomes a free way to
	 * suppress revocation. */
	fixture_init(&f);
	issue(&f, bytes[0], &batch[0], 0, 0xc0, 1);
	issue(&f, bytes[1], &batch[1], 7, 0xc0, 2); /* forged: wrong issuer */
	issue(&f, bytes[2], &batch[2], 0, 0xc0, 3);

	n = fzn_revocation_merge(&f.store, batch, 3, f.root, &f.sign, &err);
	CHECK(n == 2, "admitted %zu of a 3-record batch, wanted 2", n);
	CHECK(err == FZN_CHAIN_ERR_WRONG_ROOT, "the first failure was not reported back");
	CHECK(fzn_revocation_covers(&f.store, fzn_revocation_issuer(batch[2]),
	                            fzn_revocation_capability(batch[2]),
	                            fzn_revocation_grantee(batch[2])),
	      "a record after the bad one was skipped");

	/* A clean batch reports FZN_CHAIN_OK. */
	fixture_init(&f);
	issue(&f, bytes[1], &batch[1], 0, 0xc0, 2);
	n = fzn_revocation_merge(&f.store, batch, 3, f.root, &f.sign, &err);
	CHECK(n == 3 && err == FZN_CHAIN_OK, "a clean batch reported %zu admitted, err %d",
	      n, (int)err);
}

static void test_the_store_feeds_chain_verify_directly(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN], hop_bytes[FZN_HOP_LEN];
	fzn_revocation_record_t r;
	fzn_chain_hop_t hops[1];
	fzn_chain_t out;
	uint8_t cap[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN];

	/* The reason the store keeps verified fzn_revocation_t rather than
	 * the records: `entries` and `used` go straight into chain verify,
	 * with no conversion step for the two to disagree about. */
	fixture_init(&f);
	capability_id(cap, 0xc0);
	key(grantee, 5);

	f.stub.identity = 0;
	CHECK(fzn_chain_mint(f.root, grantee, cap, 1000, FZN_NO_EXPIRY, 0, &f.sign,
	                     hop_bytes) == FZN_CHAIN_OK,
	      "minting the hop this case revokes failed");
	CHECK(fzn_hop_open(hop_bytes, FZN_HOP_LEN, &hops[0]) == FZN_CHAIN_OK, "open");

	CHECK(fzn_chain_verify(hops, 1, f.root, cap, 2000, &f.sign, f.store.entries,
	                       f.store.used, &out) == FZN_CHAIN_OK,
	      "an unrevoked chain was refused with an empty store");

	issue(&f, bytes, &r, 0, 0xc0, 5);
	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK, "admit");
	CHECK(fzn_chain_verify(hops, 1, f.root, cap, 2000, &f.sign, f.store.entries,
	                       f.store.used, &out) == FZN_CHAIN_ERR_REVOKED,
	      "chain verify did not see the revocation the store had admitted");
}

/* AN ENTRY ANSWERS FOR THE ISSUER THAT SIGNED IT, AND FOR NO OTHER ROOT.
 *
 * What this protects. A host that anchors more than one root holds one
 * store, and an entry used to be `{capability, grantee}` alone -- the issuer
 * was verified on admission and then discarded, `fzn_revocation_covers` took
 * no root at all, and `fzn_chain_verify` takes `root` and the entries array
 * as independent parameters with nothing comparing them. So root B's
 * revocation answered a question about root A's realm, and any anchored peer
 * could disconnect any key in any other peer's tree. That is sec 4.2's own
 * named failure mode -- "inventing revocations is a denial of service
 * against exactly the hosts an attacker wants disconnected" -- closed for
 * unsigned revocations and open for cross-root ones, because the signature
 * was being checked against the wrong question.
 *
 * It is not theoretical: fuzzypickles is multi-root by design, its User
 * realm and its TOFU-pinned Registered realm being different keys.
 *
 * Every case elsewhere in this file uses ONE root, in both directions, which
 * is why the whole suite was green on it.
 *
 * Both directions are asserted. Under B the answer must still be `revoked`,
 * or this case is satisfied by a store that simply lost the entry. */
static void test_one_roots_revocation_does_not_answer_for_another(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN], hop_bytes[FZN_HOP_LEN];
	fzn_revocation_record_t r;
	fzn_chain_hop_t hops[1];
	fzn_chain_t out;
	uint8_t root_b[FZN_PUBKEY_LEN], cap[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN];

	fixture_init(&f); /* f.root is root A */
	key(root_b, 7);
	capability_id(cap, 0xc0);
	key(grantee, 5);

	/* B revokes, and B is entitled to: the record is admitted against B's
	 * own root, which is correct on B's terms and is the whole point --
	 * nothing here is forged. */
	issue(&f, bytes, &r, 7, 0xc0, 5);
	CHECK(fzn_revocation_admit(&f.store, r, root_b, &f.sign) == FZN_CHAIN_OK,
	      "B's own revocation was refused under B's own root");

	CHECK(fzn_revocation_covers(&f.store, root_b, cap, grantee) == 1,
	      "the store lost B's revocation, so the refusal below is not evidence");
	CHECK(fzn_revocation_covers(&f.store, f.root, cap, grantee) == 0,
	      "root B's revocation answered a question about root A's realm");

	/* And the consequence end to end, since a store's contents go straight
	 * into fzn_chain_verify beside a root nothing used to relate them to. */
	f.stub.identity = 0;
	CHECK(fzn_chain_mint(f.root, grantee, cap, 1000, FZN_NO_EXPIRY, 0, &f.sign,
	                     hop_bytes) == FZN_CHAIN_OK,
	      "minting the hop A granted failed");
	CHECK(fzn_hop_open(hop_bytes, FZN_HOP_LEN, &hops[0]) == FZN_CHAIN_OK, "open");
	CHECK(fzn_chain_verify(hops, 1, f.root, cap, 2000, &f.sign, f.store.entries,
	                       f.store.used, &out) == FZN_CHAIN_OK,
	      "B revoked a key in A's realm, so any anchored peer can disconnect any host");
}

/* EVERY COMPARISON IN `same()` READS THE WHOLE FIELD, and until this nothing
 * in the tree could tell whether one did.
 *
 * A comparison's LENGTH is not decided by values that differ in their first
 * byte, and every value this file built was thirty-two copies of one seed.
 * Measured against the tree as it stood: cutting all three of `same()`'s
 * comparisons to a single byte left `make test` green, 200000 fuzz cases
 * included.
 *
 * A near miss -- the same value with only its last byte changed -- is what
 * decides a length, and one pair settles every truncation from one byte to
 * thirty-one at once.
 *
 * BOTH DIRECTIONS ARE ASSERTED, because `same()` is read as two different
 * questions and a short comparison fails a different way in each. Through
 * `fzn_revocation_covers` it answers "is this revoked?", and reporting a
 * near miss as a match refuses a chain nobody revoked. Through
 * `fzn_revocation_admit` it answers "do we hold this already?", and
 * reporting a near miss as a match makes a genuine revocation return
 * FZN_CHAIN_OK and be DROPPED -- the fail-open direction, and the one with
 * no alarm attached to it, since "already held" is what success looks like
 * every time carriage works. */
static void test_a_comparison_reads_the_whole_field(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;
	uint8_t cap[FZN_CAP_ID_LEN], near_cap[FZN_CAP_ID_LEN];
	uint8_t grantee[FZN_PUBKEY_LEN], near_grantee[FZN_PUBKEY_LEN];
	uint8_t near_root[FZN_PUBKEY_LEN];

	fixture_init(&f);
	capability_id(cap, 0xc0);
	capability_id_near(near_cap, 0xc0);
	key(grantee, 5);
	key_near(near_grantee, 5);
	key_near(near_root, 0);

	issue(&f, bytes, &r, 0, 0xc0, 5);
	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK,
	      "the setup record was refused, so nothing below proves anything");
	CHECK(fzn_revocation_covers(&f.store, f.root, cap, grantee) == 1,
	      "covers: the control fails, so the three legs below prove nothing");

	CHECK(fzn_revocation_covers(&f.store, near_root, cap, grantee) == 0,
	      "an ISSUER matching the entry only in its first byte was reported revoked");
	CHECK(fzn_revocation_covers(&f.store, f.root, near_cap, grantee) == 0,
	      "a CAPABILITY matching the entry only in its first byte was reported revoked");
	CHECK(fzn_revocation_covers(&f.store, f.root, cap, near_grantee) == 0,
	      "a GRANTEE matching the entry only in its first byte was reported revoked");

	/* THE ADMISSION SIDE. The root revokes host 5 and then revokes a
	 * second host whose key differs from host 5's only in its last byte.
	 * That is two revocations, and a store holding one of them has
	 * silently dropped a real one. */
	issue_keys(&f, bytes, &r, f.root, cap, near_grantee);
	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK,
	      "the second revocation was refused");
	CHECK(f.store.used == 2,
	      "the store holds %zu entries after two different revocations: a duplicate "
	      "test that reads a prefix reports a genuine revocation as already held and "
	      "drops it, which un-revokes a device and logs nothing",
	      f.store.used);
	CHECK(fzn_revocation_covers(&f.store, f.root, cap, near_grantee) == 1,
	      "the second revocation is not in the store it reported admitting");

	/* And the same with the CAPABILITY as the byte that differs. */
	issue_keys(&f, bytes, &r, f.root, near_cap, grantee);
	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK,
	      "the third revocation was refused");
	CHECK(f.store.used == 3,
	      "the store holds %zu entries after three different revocations", f.store.used);

	/* THE ROOT PIN, which reads the whole key for the same reason. A
	 * record issued by a key one byte from the root is not the root's. */
	fixture_init(&f);
	issue_keys(&f, bytes, &r, near_root, cap, grantee);
	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_ERR_WRONG_ROOT,
	      "a record whose issuer matches the pinned root only in its first byte was "
	      "admitted");
	CHECK(f.store.used == 0, "it was recorded anyway");
}

/* ---- signature reuse: one mutation per field -------------------------- */

/* Each case takes a genuinely issued record, rewrites ONE field in place,
 * and leaves the 64 signature bytes byte-identical -- exactly what the old
 * design permitted, because the fields it stored were a separate struct
 * nothing compared with the signed bytes.
 *
 * Every case states its positive control, asserts the signature was not
 * touched, and asserts the verification was reached, for the reasons
 * chain_test.c's equivalent block sets out. */
static void assert_signature_kept(const uint8_t *forged, const uint8_t *genuine, const char *what)
{
	check_at(memcmp(forged + FZN_REV_OFF_SIGNATURE, genuine + FZN_REV_OFF_SIGNATURE,
	                FZN_SIG_LEN) == 0,
	         __LINE__, "%s: the case altered the signature, so it is not signature reuse",
	         what);
}

/* GRANTEE, and it is the headline for this module. The root revokes host 5.
 * An attacker replays that genuine record with the grantee rewritten to host
 * 9 and disconnects a host nobody revoked -- permanently, since the store
 * never evicts and nothing expires. */
static void test_forged_grantee_is_refused(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN], genuine[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;
	uint8_t victim[FZN_PUBKEY_LEN], cap[FZN_CAP_ID_LEN];

	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);
	memcpy(genuine, bytes, FZN_REVOCATION_LEN);
	capability_id(cap, 0xc0);
	key(victim, 9);

	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK,
	      "grantee: the control fails, so the refusal below proves nothing");

	fixture_init(&f);
	memcpy(bytes + FZN_REV_OFF_GRANTEE, victim, FZN_PUBKEY_LEN);
	assert_signature_kept(bytes, genuine, "grantee");
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &r) == FZN_CHAIN_OK, "open");
	stub_reset(&f.stub);

	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "GRANTEE was rewritten on a genuinely signed revocation and it was admitted: "
	      "an attacker gets a permanent forged revocation against any host it names");
	CHECK(f.stub.calls == 1, "grantee: refused before the signature was reached");
	CHECK(f.store.used == 0, "grantee: the forged record was recorded anyway");
	CHECK(fzn_revocation_covers(&f.store, f.root, cap, victim) == 0,
	      "grantee: a host nobody revoked is reported as revoked");
}

/* CAPABILITY. Capabilities are independent rather than a ladder, so
 * rewriting this field turns a revocation of one into a revocation of
 * another -- against a host that really was revoked, of something it should
 * have kept. */
static void test_forged_capability_is_refused(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN], genuine[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;

	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);
	memcpy(genuine, bytes, FZN_REVOCATION_LEN);

	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK,
	      "capability: the control fails, so the refusal below proves nothing");

	fixture_init(&f);
	capability_id(bytes + FZN_REV_OFF_CAPABILITY, 0xff);
	assert_signature_kept(bytes, genuine, "capability");
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &r) == FZN_CHAIN_OK, "open");
	stub_reset(&f.stub);

	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "CAPABILITY was rewritten on a genuinely signed revocation and it was "
	      "admitted: one revocation withdraws whatever an attacker chooses");
	CHECK(f.stub.calls == 1, "capability: refused before the signature was reached");
	CHECK(f.store.used == 0, "capability: the forged record was recorded anyway");
}

/* ISSUER, and it needs the same care chain_test.c's grantor case does.
 *
 * The issuer is both pinned against the root AND used as the verifying key,
 * so rewriting it to a different key would be refused by the pin -- and a
 * refusal that comes from the pin says nothing about whether the field is
 * signed. So the rewrite lands on a byte other than the first, and the root
 * is pinned to the rewritten value. The stub's identity is the key's first
 * byte, unchanged, so the same signer is asked and the only thing left that
 * can refuse is the message. */
static void test_forged_issuer_is_refused(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN], genuine[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;

	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);
	memcpy(genuine, bytes, FZN_REVOCATION_LEN);

	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK,
	      "issuer: the control fails, so the refusal below proves nothing");

	fixture_init(&f);
	bytes[FZN_REV_OFF_ISSUER + 1u] ^= 0x5au;
	memcpy(f.root, bytes + FZN_REV_OFF_ISSUER, FZN_PUBKEY_LEN);
	assert_signature_kept(bytes, genuine, "issuer");
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &r) == FZN_CHAIN_OK, "open");
	stub_reset(&f.stub);

	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "ISSUER was rewritten on a genuinely signed revocation, with the root pinned "
	      "to the new value, and it was admitted: the field is outside the signed range");
	CHECK(f.stub.calls == 1,
	      "issuer: refused after %d verifications -- it must be the signature that "
	      "refused, not the issuer pin",
	      f.stub.calls);
	CHECK(f.store.used == 0, "issuer: the forged record was recorded anyway");
}

/* ISSUED_AT. Nothing here reads it, which is precisely why it belongs in
 * this list: its only protection is the signature, so a binding written to
 * cover "the fields that matter" leaves it out and nothing else notices. A
 * record whose date can be rewritten is a record whose ordering against
 * anything else is a fiction. */
static void test_forged_issued_at_is_refused(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN], genuine[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;

	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);
	memcpy(genuine, bytes, FZN_REVOCATION_LEN);

	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK,
	      "issued_at: the control fails, so the refusal below proves nothing");
	CHECK(fzn_revocation_issued_at(r) == 1000, "issued_at: the control is not 1000");

	fixture_init(&f);
	fzn_put_be64(bytes + FZN_REV_OFF_ISSUED_AT, 9999u);
	assert_signature_kept(bytes, genuine, "issued_at");
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &r) == FZN_CHAIN_OK, "open");
	stub_reset(&f.stub);

	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "ISSUED_AT was rewritten on a genuinely signed revocation and it was "
	      "admitted: a record can be re-dated at will");
	CHECK(f.stub.calls == 1, "issued_at: refused before the signature was reached");
	CHECK(f.store.used == 0, "issued_at: the forged record was recorded anyway");
}

static void test_signed_bytes_are_the_whole_body(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;
	const uint8_t *at;
	size_t len;

	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);
	fzn_revocation_signed_bytes(r, &at, &len);

	CHECK(at == bytes,
	      "the signed range does not begin at the record's first byte, so the version "
	      "and object tags are outside it and separate nothing");
	CHECK(len == FZN_REVOCATION_BODY_LEN,
	      "the signed range is %zu bytes rather than %u, so some field at the end of "
	      "the body is unprotected",
	      len, (unsigned)FZN_REVOCATION_BODY_LEN);
	CHECK(at + len == bytes + FZN_REV_OFF_SIGNATURE,
	      "the signed range does not stop where the signature begins");
}

/* ---- arguments and the store's own integrity -------------------------- */

static void test_bad_arguments(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;
	fzn_revocation_store_t s;

	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);

	CHECK(fzn_revocation_store_init(&s, f.entries, 0) == FZN_CHAIN_ERR_MALFORMED,
	      "a zero-capacity store was accepted, and would record nothing");
	CHECK(fzn_revocation_store_init(&s, NULL, 4) == FZN_CHAIN_ERR_MALFORMED, "null entries");
	CHECK(fzn_revocation_admit(&f.store, r, f.root, NULL) == FZN_CHAIN_ERR_MALFORMED,
	      "a null signer was accepted");
	CHECK(fzn_revocation_covers(NULL, fzn_revocation_issuer(r),
	                            fzn_revocation_capability(r),
	                            fzn_revocation_grantee(r)) == 0,
	      "covers on a null store did not answer no");

	/* A view that was never opened. MALFORMED rather than SHAPE: nothing
	 * about any bytes is wrong, the caller skipped fzn_revocation_open. */
	{
		fzn_revocation_record_t unopened;

		unopened.base = NULL;
		CHECK(fzn_revocation_admit(&f.store, unopened, f.root, &f.sign) ==
		              FZN_CHAIN_ERR_MALFORMED,
		      "a record that was never opened was accepted");
	}

	/* Issuing refuses the same way it verifies. */
	{
		uint8_t k[FZN_PUBKEY_LEN];

		key(k, 1);
		CHECK(fzn_revocation_issue(NULL, k, k, 1, &f.sign, bytes) ==
		              FZN_CHAIN_ERR_MALFORMED,
		      "issuing with a null issuer");
		CHECK(fzn_revocation_issue(k, NULL, k, 1, &f.sign, bytes) ==
		              FZN_CHAIN_ERR_MALFORMED,
		      "issuing with a null capability");
		CHECK(fzn_revocation_issue(k, k, NULL, 1, &f.sign, bytes) ==
		              FZN_CHAIN_ERR_MALFORMED,
		      "issuing with a null grantee");
		CHECK(fzn_revocation_issue(k, k, k, 1, NULL, bytes) == FZN_CHAIN_ERR_MALFORMED,
		      "issuing with a null signer");
		CHECK(fzn_revocation_issue(k, k, k, 1, &f.sign, NULL) == FZN_CHAIN_ERR_MALFORMED,
		      "issuing into a null buffer");
		CHECK(fzn_revocation_encode(NULL, k, k, k, 1) == FZN_CHAIN_ERR_MALFORMED,
		      "encoding into a null buffer");

		/* A signer that refuses leaves nothing that opens behind. */
		f.stub.can_sign = 0;
		memset(bytes, 0xab, sizeof(bytes));
		CHECK(fzn_revocation_issue(k, k, k, 1, &f.sign, bytes) ==
		              FZN_CHAIN_ERR_CHAIN_INVALID,
		      "a refusing signer still produced a record");
		CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &r) == FZN_CHAIN_ERR_SHAPE,
		      "a refused issue left something that opens as a revocation");
	}
}

static void test_merge_bad_arguments(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;
	fzn_chain_err_t err;

	/* Added because coverage said nothing reached them: the guard in
	 * fzn_revocation_merge was the only unexecuted code in the library,
	 * three lines of 41 in this file. `admit` had its bad arguments
	 * tested and `merge` did not, which is the shape a gap takes when
	 * two functions are written together and only one is thought about
	 * twice. */
	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);

	err = FZN_CHAIN_OK;
	CHECK(fzn_revocation_merge(NULL, &r, 1, f.root, &f.sign, &err) == 0,
	      "merge into a null store did not admit zero");
	CHECK(err == FZN_CHAIN_ERR_MALFORMED, "merge into a null store did not report why");

	err = FZN_CHAIN_OK;
	CHECK(fzn_revocation_merge(&f.store, NULL, 3, f.root, &f.sign, &err) == 0,
	      "merge of a null batch with a nonzero count admitted something");
	CHECK(err == FZN_CHAIN_ERR_MALFORMED, "merge of a null batch did not report why");
	CHECK(f.store.used == 0, "a refused merge recorded something");

	/* A null `err` must be tolerated, since it is the caller's option
	 * and the guard writes through it. */
	CHECK(fzn_revocation_merge(NULL, &r, 1, f.root, &f.sign, NULL) == 0,
	      "merge with a null err pointer did not return zero");

	/* An empty batch is not an error: a peer with nothing to tell us is
	 * the ordinary case, not a malformed one. */
	err = FZN_CHAIN_ERR_MALFORMED;
	CHECK(fzn_revocation_merge(&f.store, NULL, 0, f.root, &f.sign, &err) == 0,
	      "an empty batch admitted something");
	CHECK(err == FZN_CHAIN_OK, "an empty batch was reported as an error");
}

/* THE FIRST failure, not the last, and not merely "a" failure.
 *
 * fzn_revocation_merge keeps the first error and reports it once the batch is
 * done. Every test above put exactly ONE bad record in a batch, which cannot
 * tell the first from the last -- the branch that skips the assignment on a
 * second failure had never run. So a batch with two failures OF DIFFERENT
 * KINDS is the only way the claim is observable.
 *
 * It matters because the two errors mean different things to a caller. A
 * forged record says somebody is lying to you; a full store says you may be
 * missing revocations you were told about. Reporting the last one would let a
 * sender who appends rubbish choose which of those a host sees. */
static void test_merge_reports_the_first_failure_not_the_last(void)
{
	struct fixture f;
	uint8_t bytes[6][FZN_REVOCATION_LEN];
	fzn_revocation_record_t batch[6];
	fzn_chain_err_t err = FZN_CHAIN_OK;
	size_t n;

	fixture_init(&f); /* four entries of room */
	issue(&f, bytes[0], &batch[0], 7, 0xc0, 1); /* forged: wrong issuer */
	for (uint8_t i = 1; i < 6; i++)
		issue(&f, bytes[i], &batch[i], 0, 0xc0, (uint8_t)(i + 1u));

	n = fzn_revocation_merge(&f.store, batch, 6, f.root, &f.sign, &err);
	CHECK(n == 4, "admitted %zu of five genuine records into a store of four", n);
	CHECK(err == FZN_CHAIN_ERR_WRONG_ROOT,
	      "reported %d; the first failure was WRONG_ROOT and the later one was a "
	      "full store, so this is the last error rather than the first",
	      (int)err);

	/* The reverse order, so the test cannot pass by preferring WRONG_ROOT
	 * over STORE_FULL for some reason other than order. */
	fixture_init(&f);
	for (uint8_t i = 0; i < 5; i++)
		issue(&f, bytes[i], &batch[i], 0, 0xc0, (uint8_t)(i + 1u));
	issue(&f, bytes[5], &batch[5], 7, 0xc0, 9); /* forged, last */

	n = fzn_revocation_merge(&f.store, batch, 6, f.root, &f.sign, &err);
	CHECK(n == 4, "admitted %zu with the forged record last", n);
	CHECK(err == FZN_CHAIN_ERR_STORE_FULL,
	      "reported %d; the store filled before the forged record was reached, so "
	      "STORE_FULL is the first failure here",
	      (int)err);
}

/* A caller that does not want the error. `err` is optional and every test
 * above passed one, so the branch that skips writing it had never run -- and
 * an unguarded store through a null pointer is not a thing to discover from a
 * consumer's crash report. */
static void test_merge_without_an_error_out(void)
{
	struct fixture f;
	uint8_t bytes[2][FZN_REVOCATION_LEN];
	fzn_revocation_record_t batch[2];
	size_t n;

	fixture_init(&f);
	issue(&f, bytes[0], &batch[0], 0, 0xc0, 1);
	issue(&f, bytes[1], &batch[1], 7, 0xc0, 2); /* forged, so there IS an error to drop */

	n = fzn_revocation_merge(&f.store, batch, 2, f.root, &f.sign, NULL);
	CHECK(n == 1, "admitted %zu with no error pointer, wanted 1", n);

	/* And the malformed path, which writes through the same pointer. */
	n = fzn_revocation_merge(NULL, batch, 2, f.root, &f.sign, NULL);
	CHECK(n == 0, "a null store with no error pointer admitted %zu", n);
}

/* A store whose `used` exceeds its `capacity`.
 *
 * `used` bounds a loop over `entries`, and the append writes at
 * `entries[used]` behind a test that was `used == capacity`. The refusal is
 * "revoked" rather than "not revoked" deliberately: this answers an
 * authorization question, and a store nobody can read is not evidence that a
 * capability is still good. */
static void test_a_store_whose_fields_disagree_denies(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;

	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 1);
	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK,
	      "the setup record was refused");

	f.store.used = 5; /* one past the four entries it was given */
	CHECK(fzn_revocation_covers(&f.store, fzn_revocation_issuer(r),
	                            fzn_revocation_capability(r),
	                            fzn_revocation_grantee(r)) == 1,
	      "a corrupt store was scanned");

	/* A capability the store never held must also come back covered: the
	 * answer is about the store being unreadable, not about this record. */
	{
		uint8_t other_cap[FZN_CAP_ID_LEN], other_grantee[FZN_PUBKEY_LEN];

		capability_id(other_cap, 0xc1);
		key(other_grantee, 9);
		CHECK(fzn_revocation_covers(&f.store, f.root, other_cap, other_grantee) == 1,
		      "a corrupt store answered `not revoked`, which is the fail-open "
		      "direction");
	}

	/* And nothing is appended to it. */
	CHECK(f.store.used == 5, "a corrupt store was written to");
}

/* Both guard chains, one argument at a time. See chain_test.c's equivalent
 * for why the dull version is worth having: the first null in each chain was
 * tested and the rest rode along, and a chain missing one term reads exactly
 * like one that is not. */
static void test_every_guard_refuses_its_own_argument(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;
	fzn_sign_ops_t no_verify;
	fzn_revocation_store_t no_entries;

	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 1);
	no_verify = f.sign;
	no_verify.verify = NULL;
	no_entries = f.store;
	no_entries.entries = NULL;

	CHECK(fzn_revocation_covers(NULL, fzn_revocation_issuer(r),
	                            fzn_revocation_capability(r),
	                            fzn_revocation_grantee(r)) == 0,
	      "a null store");
	CHECK(fzn_revocation_covers(&no_entries, fzn_revocation_issuer(r),
	                            fzn_revocation_capability(r),
	                            fzn_revocation_grantee(r)) == 0,
	      "a store with no entries");
	CHECK(fzn_revocation_covers(&f.store, NULL, fzn_revocation_capability(r),
	                            fzn_revocation_grantee(r)) == 0,
	      "a null issuer");
	CHECK(fzn_revocation_covers(&f.store, fzn_revocation_issuer(r), NULL,
	                            fzn_revocation_grantee(r)) == 0,
	      "a null capability");
	CHECK(fzn_revocation_covers(&f.store, fzn_revocation_issuer(r),
	                            fzn_revocation_capability(r), NULL) == 0,
	      "a null grantee");

	CHECK(fzn_revocation_admit(NULL, r, f.root, &f.sign) == FZN_CHAIN_ERR_MALFORMED,
	      "admitting into a null store");
	CHECK(fzn_revocation_admit(&no_entries, r, f.root, &f.sign) == FZN_CHAIN_ERR_MALFORMED,
	      "admitting into a store with no entries");
	CHECK(fzn_revocation_admit(&f.store, r, NULL, &f.sign) == FZN_CHAIN_ERR_MALFORMED,
	      "admitting against a null root");
	CHECK(fzn_revocation_admit(&f.store, r, f.root, NULL) == FZN_CHAIN_ERR_MALFORMED,
	      "admitting with a null signer");
	CHECK(fzn_revocation_admit(&f.store, r, f.root, &no_verify) == FZN_CHAIN_ERR_MALFORMED,
	      "admitting with a signer that cannot verify");
}

static void test_a_corrupt_store_refuses_rather_than_swallowing(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;
	size_t used_before;

	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 1);

	/* `fzn_revocation_covers` answers "is this revoked?" and says YES for a
	 * corrupt store, because denying is the safe reply to an authorization
	 * question. `fzn_revocation_admit` asks a different question, and it
	 * read that same yes as "we hold it already" -- returning OK, recording
	 * nothing, and never reaching STORE_FULL. revocation.h calls failing to
	 * record the failure that fails OPEN, so this suppressed the one alarm
	 * that exists for it.
	 *
	 * Both halves are asserted, because a version that refused AFTER
	 * appending would pass on the return value alone. */
	f.store.used = f.store.capacity + 1u;
	used_before = f.store.used;
	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_ERR_MALFORMED,
	      "a corrupt store accepted a revocation");
	CHECK(f.store.used == used_before, "a refused admit moved the store's count");
	CHECK(fzn_revocation_covers(&f.store, fzn_revocation_issuer(r),
	                            fzn_revocation_capability(r),
	                            fzn_revocation_grantee(r)) == 1,
	      "a corrupt store must still deny, which is the other question");
}

/* Positive control: most cases above assert a refusal, and an admit that
 * refused everything would satisfy them. */
static void test_the_suite_can_tell_pass_from_fail(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;

	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);
	CHECK(fzn_revocation_admit(&f.store, r, f.root, &f.sign) == FZN_CHAIN_OK,
	      "the positive control fails, so every refusal above proves nothing");
}

int main(void)
{
	test_layout_and_round_trip();
	test_open_refuses_what_is_not_our_shape();
	test_admits_a_signed_revocation();
	test_a_carrier_cannot_invent_one();
	test_hearing_it_twice_is_not_an_error();
	test_a_full_store_refuses_and_does_not_evict();
	test_merge_keeps_going_past_a_bad_record();
	test_the_store_feeds_chain_verify_directly();
	test_one_roots_revocation_does_not_answer_for_another();
	test_a_comparison_reads_the_whole_field();
	test_forged_grantee_is_refused();
	test_forged_capability_is_refused();
	test_forged_issuer_is_refused();
	test_forged_issued_at_is_refused();
	test_signed_bytes_are_the_whole_body();
	test_bad_arguments();
	test_merge_bad_arguments();
	test_merge_reports_the_first_failure_not_the_last();
	test_merge_without_an_error_out();
	test_a_store_whose_fields_disagree_denies();
	test_every_guard_refuses_its_own_argument();
	test_a_corrupt_store_refuses_rather_than_swallowing();
	test_the_suite_can_tell_pass_from_fail();

	printf("revocation_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
