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
	fprintf(stderr, "  FAIL revocation_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
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
		fprintf(stderr, "  FAIL: verifier called with an empty signed region\n");
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
		fprintf(stderr, "  FAIL: signer called with an empty region\n");
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

static void capability_id(fzn_cap_id_t *out, uint8_t seed)
{
	expand(out->b, FZN_CAP_ID_LEN, seed);
}

static void capability_id_near(fzn_cap_id_t *out, uint8_t seed)
{
	expand_near(out->b, FZN_CAP_ID_LEN, seed);
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
                       const uint8_t *issuer_key, const fzn_cap_id_t *capability,
                       const uint8_t *grantee_key)
{
	f->stub.identity = issuer_key[0];

	if (fzn_revocation_issue(issuer_key, capability, grantee_key, 1000, &f->sign, bytes) !=
	    FZN_CHAIN_OK) {
		fprintf(stderr, "  FAIL: the fixture could not issue a revocation\n");
		failures++;
		return;
	}
	if (fzn_revocation_open(bytes, FZN_REVOCATION_LEN, view) != FZN_CHAIN_OK) {
		fprintf(stderr, "  FAIL: the fixture issued a record that will not open\n");
		failures++;
	}
	stub_reset(&f->stub);
}

/* A batch of ROOT-ISSUED offers over records the fixtures built.
 *
 * `fzn_revocation_merge` takes offers rather than records (2026-08-28),
 * because each member of a batch may be issued by a different key and so may
 * need a different chain. The cases below are the old world -- every record
 * the root's -- so they say so once, here, rather than at every call. The
 * grantor-issued cases build their offers by hand, which is the point of
 * them. */
static void offers_from(fzn_revocation_offer_t *out, const fzn_revocation_record_t *recs,
                        size_t count)
{
	for (size_t i = 0; i < count; i++)
		out[i] = fzn_revocation_offer_root(recs[i]);
}

/* The same, named by seed, which is what nearly every case here wants. */
static void issue(struct fixture *f, uint8_t *bytes, fzn_revocation_record_t *view,
                  uint8_t issuer, uint8_t cap, uint8_t grantee)
{
	uint8_t issuer_key[FZN_PUBKEY_LEN], grantee_key[FZN_PUBKEY_LEN];
	fzn_cap_id_t capability;

	key(issuer_key, issuer);
	key(grantee_key, grantee);
	capability_id(&capability, cap);
	issue_keys(f, bytes, view, issuer_key, &capability, grantee_key);
}

/* Mint one hop, signed by `grantor_seed`, and open a view over it.
 *
 * `fzn_chain_mint` is used for EVERY hop rather than `fzn_chain_delegate`
 * for the later ones, and the difference matters to what these cases can
 * build: mint signs a hop with whatever grantor it is handed and asks
 * nothing about the chain behind it, so a fixture can assemble a chain of
 * any depth without first holding one. Delegate would re-verify at each
 * step, which is a different function's contract and not what is under test
 * here. */
static void mint_hop(struct fixture *f, uint8_t *bytes, fzn_chain_hop_t *hop,
                     uint8_t grantor_seed, uint8_t grantee_seed, const fzn_cap_id_t *capability,
                     uint64_t issued_at, uint64_t expires_at, int delegable)
{
	uint8_t grantor[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN];

	key(grantor, grantor_seed);
	key(grantee, grantee_seed);
	f->stub.identity = grantor_seed;

	if (fzn_chain_mint(grantor, grantee, capability, issued_at, expires_at, delegable,
	                   &f->sign, bytes) != FZN_CHAIN_OK) {
		fprintf(stderr, "  FAIL: the fixture could not mint a hop\n");
		failures++;
		return;
	}
	if (fzn_hop_open(bytes, FZN_HOP_LEN, hop) != FZN_CHAIN_OK) {
		fprintf(stderr, "  FAIL: the fixture minted a hop that will not open\n");
		failures++;
	}
	stub_reset(&f->stub);
}

/* ---- the layout ------------------------------------------------------- */

static void test_layout_and_round_trip(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN], again[FZN_REVOCATION_LEN];
	fzn_revocation_record_t rec;
	uint8_t issuer[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;

	CHECK(FZN_REVOCATION_BODY_LEN == 106u, "revocation body is %u bytes, the table says 106",
	      (unsigned)FZN_REVOCATION_BODY_LEN);
	CHECK(FZN_REVOCATION_LEN == 170u, "revocation is %u bytes, the table says 170",
	      (unsigned)FZN_REVOCATION_LEN);
	CHECK(FZN_REV_OFF_SIGNATURE == FZN_REVOCATION_BODY_LEN,
	      "the signature does not begin where the body ends");

	fixture_init(&f);
	key(issuer, 0);
	key(grantee, 5);
	capability_id(&cap, 0xc0);

	CHECK(fzn_revocation_encode(bytes, issuer, &cap, grantee, 0x0102030405060708ull) ==
	              FZN_CHAIN_OK,
	      "encoding a revocation failed");
	CHECK(bytes[FZN_REV_OFF_VERSION] == 1u, "version byte is %u, wanted 1",
	      bytes[FZN_REV_OFF_VERSION]);
	CHECK(bytes[FZN_REV_OFF_OBJECT] == 129u,
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
	CHECK(fzn_ct_memeq(fzn_revocation_capability(rec), cap.b, FZN_CAP_ID_LEN),
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
	bytes[FZN_REV_OFF_OBJECT] = (uint8_t)FZN_OBJECT_HOP;
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &rec) == FZN_CHAIN_ERR_SHAPE,
	      "an otherwise valid revocation tagged as a hop was accepted as a revocation");
	bytes[FZN_REV_OFF_OBJECT] = (uint8_t)FZN_OBJECT_REVOCATION;
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

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_OK,
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

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_ERR_WRONG_ROOT,
	      "a revocation issued by a carrier was accepted");
	CHECK(f.store.used == 0, "it was recorded anyway");
	CHECK(f.stub.calls == 0, "a signature was verified for an issuer already refused");

	/* And a forged signature under the right issuer is refused too. */
	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);
	bytes[FZN_REV_OFF_SIGNATURE] ^= 0x01u;
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_ERR_CHAIN_INVALID,
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

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_OK, "first");
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_OK,
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
		CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
		                           NULL) == FZN_CHAIN_OK,
		      "filling entry %u", i);
	}

	issue(&f, bytes, &r, 0, 0xc0, 99);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_ERR_STORE_FULL,
	      "a full store admitted a fifth revocation");

	/* The first entry must still be there -- an evicting store would have
	 * silently un-revoked it. */
	{
		uint8_t grantee[FZN_PUBKEY_LEN];
		fzn_cap_id_t cap;

		capability_id(&cap, 0xc0);
		key(grantee, 10);
		CHECK(fzn_revocation_covers(&f.store, f.root, &cap, grantee),
		      "a full store evicted an earlier revocation, un-revoking a device");
	}
}

static void test_merge_keeps_going_past_a_bad_record(void)
{
	struct fixture f;
	uint8_t bytes[3][FZN_REVOCATION_LEN];
	fzn_revocation_record_t batch[3];
	fzn_revocation_offer_t offers[3];
	fzn_chain_err_t err = FZN_CHAIN_OK;
	size_t n;

	/* One forged record must not stop a host learning the genuine ones
	 * beside it, or appending rubbish to a batch becomes a free way to
	 * suppress revocation. */
	fixture_init(&f);
	issue(&f, bytes[0], &batch[0], 0, 0xc0, 1);
	issue(&f, bytes[1], &batch[1], 7, 0xc0, 2); /* forged: wrong issuer */
	issue(&f, bytes[2], &batch[2], 0, 0xc0, 3);

	offers_from(offers, batch, 3);
	n = fzn_revocation_merge(&f.store, offers, 3, f.root, &f.sign, &err, NULL);
	CHECK(n == 2, "admitted %zu of a 3-record batch, wanted 2", n);
	CHECK(err == FZN_CHAIN_ERR_WRONG_ROOT, "the first failure was not reported back");
	CHECK(fzn_revocation_covers(&f.store, fzn_revocation_issuer(batch[2]),
	                            fzn_revocation_capability(batch[2]),
	                            fzn_revocation_grantee(batch[2])),
	      "a record after the bad one was skipped");

	/* A clean batch reports FZN_CHAIN_OK. */
	fixture_init(&f);
	issue(&f, bytes[1], &batch[1], 0, 0xc0, 2);
	offers_from(offers, batch, 3);
	n = fzn_revocation_merge(&f.store, offers, 3, f.root, &f.sign, &err, NULL);
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
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;

	/* The reason the store keeps verified fzn_revocation_t rather than
	 * the records: `entries` and `used` go straight into chain verify,
	 * with no conversion step for the two to disagree about. */
	fixture_init(&f);
	capability_id(&cap, 0xc0);
	key(grantee, 5);

	f.stub.identity = 0;
	CHECK(fzn_chain_mint(f.root, grantee, &cap, 1000, FZN_NO_EXPIRY, 0, &f.sign,
	                     hop_bytes) == FZN_CHAIN_OK,
	      "minting the hop this case revokes failed");
	CHECK(fzn_hop_open(hop_bytes, FZN_HOP_LEN, &hops[0]) == FZN_CHAIN_OK, "open");

	CHECK(fzn_chain_verify(hops, 1, f.root, &cap, 2000, &f.sign, &f.store, &out) == FZN_CHAIN_OK,
	      "an unrevoked chain was refused with an empty store");

	issue(&f, bytes, &r, 0, 0xc0, 5);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "admit");
	CHECK(fzn_chain_verify(hops, 1, f.root, &cap, 2000, &f.sign, &f.store, &out) == FZN_CHAIN_ERR_REVOKED,
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
	uint8_t root_b[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;

	fixture_init(&f); /* f.root is root A */
	key(root_b, 7);
	capability_id(&cap, 0xc0);
	key(grantee, 5);

	/* B revokes, and B is entitled to: the record is admitted against B's
	 * own root, which is correct on B's terms and is the whole point --
	 * nothing here is forged. */
	issue(&f, bytes, &r, 7, 0xc0, 5);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), root_b, &f.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "B's own revocation was refused under B's own root");

	CHECK(fzn_revocation_covers(&f.store, root_b, &cap, grantee) == 1,
	      "the store lost B's revocation, so the refusal below is not evidence");
	CHECK(fzn_revocation_covers(&f.store, f.root, &cap, grantee) == 0,
	      "root B's revocation answered a question about root A's realm");

	/* And the consequence end to end, since the store goes straight into
	 * fzn_chain_verify beside a root nothing used to relate them to. */
	f.stub.identity = 0;
	CHECK(fzn_chain_mint(f.root, grantee, &cap, 1000, FZN_NO_EXPIRY, 0, &f.sign,
	                     hop_bytes) == FZN_CHAIN_OK,
	      "minting the hop A granted failed");
	CHECK(fzn_hop_open(hop_bytes, FZN_HOP_LEN, &hops[0]) == FZN_CHAIN_OK, "open");
	CHECK(fzn_chain_verify(hops, 1, f.root, &cap, 2000, &f.sign, &f.store, &out) == FZN_CHAIN_OK,
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
	fzn_cap_id_t cap, near_cap;
	uint8_t grantee[FZN_PUBKEY_LEN], near_grantee[FZN_PUBKEY_LEN];
	uint8_t near_root[FZN_PUBKEY_LEN];

	fixture_init(&f);
	capability_id(&cap, 0xc0);
	capability_id_near(&near_cap, 0xc0);
	key(grantee, 5);
	key_near(near_grantee, 5);
	key_near(near_root, 0);

	issue(&f, bytes, &r, 0, 0xc0, 5);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "the setup record was refused, so nothing below proves anything");
	CHECK(fzn_revocation_covers(&f.store, f.root, &cap, grantee) == 1,
	      "covers: the control fails, so the three legs below prove nothing");

	CHECK(fzn_revocation_covers(&f.store, near_root, &cap, grantee) == 0,
	      "an ISSUER matching the entry only in its first byte was reported revoked");
	CHECK(fzn_revocation_covers(&f.store, f.root, &near_cap, grantee) == 0,
	      "a CAPABILITY matching the entry only in its first byte was reported revoked");
	CHECK(fzn_revocation_covers(&f.store, f.root, &cap, near_grantee) == 0,
	      "a GRANTEE matching the entry only in its first byte was reported revoked");

	/* THE ADMISSION SIDE. The root revokes host 5 and then revokes a
	 * second host whose key differs from host 5's only in its last byte.
	 * That is two revocations, and a store holding one of them has
	 * silently dropped a real one. */
	issue_keys(&f, bytes, &r, f.root, &cap, near_grantee);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "the second revocation was refused");
	CHECK(f.store.used == 2,
	      "the store holds %zu entries after two different revocations: a duplicate "
	      "test that reads a prefix reports a genuine revocation as already held and "
	      "drops it, which un-revokes a device and logs nothing",
	      f.store.used);
	CHECK(fzn_revocation_covers(&f.store, f.root, &cap, near_grantee) == 1,
	      "the second revocation is not in the store it reported admitting");

	/* And the same with the CAPABILITY as the byte that differs. */
	issue_keys(&f, bytes, &r, f.root, &near_cap, grantee);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "the third revocation was refused");
	CHECK(f.store.used == 3,
	      "the store holds %zu entries after three different revocations", f.store.used);

	/* THE ROOT PIN, which reads the whole key for the same reason. A
	 * record issued by a key one byte from the root is not the root's. */
	fixture_init(&f);
	issue_keys(&f, bytes, &r, near_root, &cap, grantee);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_ERR_WRONG_ROOT,
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
	uint8_t victim[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;

	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);
	memcpy(genuine, bytes, FZN_REVOCATION_LEN);
	capability_id(&cap, 0xc0);
	key(victim, 9);

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "grantee: the control fails, so the refusal below proves nothing");

	fixture_init(&f);
	memcpy(bytes + FZN_REV_OFF_GRANTEE, victim, FZN_PUBKEY_LEN);
	assert_signature_kept(bytes, genuine, "grantee");
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &r) == FZN_CHAIN_OK, "open");
	stub_reset(&f.stub);

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "GRANTEE was rewritten on a genuinely signed revocation and it was admitted: "
	      "an attacker gets a permanent forged revocation against any host it names");
	CHECK(f.stub.calls == 1, "grantee: refused before the signature was reached");
	CHECK(f.store.used == 0, "grantee: the forged record was recorded anyway");
	CHECK(fzn_revocation_covers(&f.store, f.root, &cap, victim) == 0,
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

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "capability: the control fails, so the refusal below proves nothing");

	fixture_init(&f);
	capability_id((fzn_cap_id_t *)(bytes + FZN_REV_OFF_CAPABILITY), 0xff);
	assert_signature_kept(bytes, genuine, "capability");
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &r) == FZN_CHAIN_OK, "open");
	stub_reset(&f.stub);

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_ERR_CHAIN_INVALID,
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

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "issuer: the control fails, so the refusal below proves nothing");

	fixture_init(&f);
	bytes[FZN_REV_OFF_ISSUER + 1u] ^= 0x5au;
	memcpy(f.root, bytes + FZN_REV_OFF_ISSUER, FZN_PUBKEY_LEN);
	assert_signature_kept(bytes, genuine, "issuer");
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &r) == FZN_CHAIN_OK, "open");
	stub_reset(&f.stub);

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_ERR_CHAIN_INVALID,
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

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "issued_at: the control fails, so the refusal below proves nothing");
	CHECK(fzn_revocation_issued_at(r) == 1000, "issued_at: the control is not 1000");

	fixture_init(&f);
	fzn_put_be64(bytes + FZN_REV_OFF_ISSUED_AT, 9999u);
	assert_signature_kept(bytes, genuine, "issued_at");
	CHECK(fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &r) == FZN_CHAIN_OK, "open");
	stub_reset(&f.stub);

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_ERR_CHAIN_INVALID,
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
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, NULL,
	                           NULL) == FZN_CHAIN_ERR_MALFORMED,
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
		CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(unopened), f.root, &f.sign,
		                           NULL) ==
		              FZN_CHAIN_ERR_MALFORMED,
		      "a record that was never opened was accepted");
	}

	/* Issuing refuses the same way it verifies. */
	{
		uint8_t k[FZN_PUBKEY_LEN];

		key(k, 1);
		CHECK(fzn_revocation_issue(NULL, &(fzn_cap_id_t){ { 0 } }, k, 1, &f.sign, bytes) ==
		              FZN_CHAIN_ERR_MALFORMED,
		      "issuing with a null issuer");
		CHECK(fzn_revocation_issue(k, NULL, k, 1, &f.sign, bytes) ==
		              FZN_CHAIN_ERR_MALFORMED,
		      "issuing with a null capability");
		CHECK(fzn_revocation_issue(k, &(fzn_cap_id_t){ { 0 } }, NULL, 1, &f.sign, bytes) ==
		              FZN_CHAIN_ERR_MALFORMED,
		      "issuing with a null grantee");
		CHECK(fzn_revocation_issue(k, &(fzn_cap_id_t){ { 0 } }, k, 1, NULL, bytes) == FZN_CHAIN_ERR_MALFORMED,
		      "issuing with a null signer");
		CHECK(fzn_revocation_issue(k, &(fzn_cap_id_t){ { 0 } }, k, 1, &f.sign, NULL) == FZN_CHAIN_ERR_MALFORMED,
		      "issuing into a null buffer");
		CHECK(fzn_revocation_encode(NULL, k, &(fzn_cap_id_t){ { 0 } }, k, 1) == FZN_CHAIN_ERR_MALFORMED,
		      "encoding into a null buffer");

		/* A signer that refuses leaves nothing that opens behind. */
		f.stub.can_sign = 0;
		memset(bytes, 0xab, sizeof(bytes));
		CHECK(fzn_revocation_issue(k, &(fzn_cap_id_t){ { 0 } }, k, 1, &f.sign, bytes) ==
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
	fzn_revocation_offer_t one;
	fzn_chain_err_t err;

	/* Added because coverage said nothing reached them: the guard in
	 * fzn_revocation_merge was the only unexecuted code in the library,
	 * three lines of 41 in this file. `admit` had its bad arguments
	 * tested and `merge` did not, which is the shape a gap takes when
	 * two functions are written together and only one is thought about
	 * twice. */
	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);
	one = fzn_revocation_offer_root(r);

	err = FZN_CHAIN_OK;
	CHECK(fzn_revocation_merge(NULL, &one, 1, f.root, &f.sign, &err, NULL) == 0,
	      "merge into a null store did not admit zero");
	CHECK(err == FZN_CHAIN_ERR_MALFORMED, "merge into a null store did not report why");

	err = FZN_CHAIN_OK;
	CHECK(fzn_revocation_merge(&f.store, NULL, 3, f.root, &f.sign, &err, NULL) == 0,
	      "merge of a null batch with a nonzero count admitted something");
	CHECK(err == FZN_CHAIN_ERR_MALFORMED, "merge of a null batch did not report why");
	CHECK(f.store.used == 0, "a refused merge recorded something");

	/* A null `err` must be tolerated, since it is the caller's option
	 * and the guard writes through it. */
	CHECK(fzn_revocation_merge(NULL, &one, 1, f.root, &f.sign, NULL, NULL) == 0,
	      "merge with a null err pointer did not return zero");

	/* An empty batch is not an error: a peer with nothing to tell us is
	 * the ordinary case, not a malformed one. */
	err = FZN_CHAIN_ERR_MALFORMED;
	CHECK(fzn_revocation_merge(&f.store, NULL, 0, f.root, &f.sign, &err, NULL) == 0,
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
	fzn_revocation_offer_t offers[6];
	fzn_chain_err_t err = FZN_CHAIN_OK;
	size_t n;

	fixture_init(&f); /* four entries of room */
	issue(&f, bytes[0], &batch[0], 7, 0xc0, 1); /* forged: wrong issuer */
	for (uint8_t i = 1; i < 6; i++)
		issue(&f, bytes[i], &batch[i], 0, 0xc0, (uint8_t)(i + 1u));

	offers_from(offers, batch, 6);
	n = fzn_revocation_merge(&f.store, offers, 6, f.root, &f.sign, &err, NULL);
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

	offers_from(offers, batch, 6);
	n = fzn_revocation_merge(&f.store, offers, 6, f.root, &f.sign, &err, NULL);
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
	fzn_revocation_offer_t offers[2];
	size_t n;

	fixture_init(&f);
	issue(&f, bytes[0], &batch[0], 0, 0xc0, 1);
	issue(&f, bytes[1], &batch[1], 7, 0xc0, 2); /* forged, so there IS an error to drop */

	offers_from(offers, batch, 2);
	n = fzn_revocation_merge(&f.store, offers, 2, f.root, &f.sign, NULL, NULL);
	CHECK(n == 1, "admitted %zu with no error pointer, wanted 1", n);

	/* And the malformed path, which writes through the same pointer. */
	n = fzn_revocation_merge(NULL, offers, 2, f.root, &f.sign, NULL, NULL);
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
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "the setup record was refused");

	f.store.used = 5; /* one past the four entries it was given */
	CHECK(fzn_revocation_covers(&f.store, fzn_revocation_issuer(r),
	                            fzn_revocation_capability(r),
	                            fzn_revocation_grantee(r)) == 1,
	      "a corrupt store was scanned");

	/* A capability the store never held must also come back covered: the
	 * answer is about the store being unreadable, not about this record. */
	{
		uint8_t other_grantee[FZN_PUBKEY_LEN];
		fzn_cap_id_t other_cap;

		capability_id(&other_cap, 0xc1);
		key(other_grantee, 9);
		CHECK(fzn_revocation_covers(&f.store, f.root, &other_cap, other_grantee) == 1,
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

	CHECK(fzn_revocation_admit(NULL, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_ERR_MALFORMED,
	      "admitting into a null store");
	CHECK(fzn_revocation_admit(&no_entries, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_ERR_MALFORMED,
	      "admitting into a store with no entries");
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), NULL, &f.sign,
	                           NULL) == FZN_CHAIN_ERR_MALFORMED,
	      "admitting against a null root");
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, NULL,
	                           NULL) == FZN_CHAIN_ERR_MALFORMED,
	      "admitting with a null signer");
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &no_verify,
	                           NULL) == FZN_CHAIN_ERR_MALFORMED,
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
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_ERR_MALFORMED,
	      "a corrupt store accepted a revocation");
	CHECK(f.store.used == used_before, "a refused admit moved the store's count");
	CHECK(fzn_revocation_covers(&f.store, fzn_revocation_issuer(r),
	                            fzn_revocation_capability(r),
	                            fzn_revocation_grantee(r)) == 1,
	      "a corrupt store must still deny, which is the other question");
}

/* ---- the admission bound, once grantors may revoke (2026-08-28) -------- */

/* project.md sec 13c is the design, and its reframing is what these cases
 * are about: the old root check did TWO jobs -- authorisation and an
 * admission bound -- and only the bound is left here, because what is
 * HONOURED is decided by `fzn_revocation_covers_chain` at verification time.
 * So the rule is deliberately coarse: admit a revocation from a key if and
 * only if `fzn_chain_delegate` would let that key grant the thing it is
 * withdrawing. */

/* The ordinary case, and its two boundaries. */
static void test_a_grantor_may_revoke_its_descendant(void)
{
	struct fixture f;
	uint8_t hop_bytes[FZN_HOP_LEN], bytes[FZN_REVOCATION_LEN];
	uint8_t issuer[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	fzn_chain_hop_t hop;
	fzn_revocation_record_t r;

	fixture_init(&f);
	capability_id(&cap, 0xc0);
	key(issuer, 1);
	key(grantee, 2);

	/* The root grants the capability to key 1, delegably. */
	mint_hop(&f, hop_bytes, &hop, 0, 1, &cap, 1000, FZN_NO_EXPIRY, 1);

	/* Key 1 withdraws it from key 2, and presents the chain that makes it
	 * an ancestor. */
	issue_keys(&f, bytes, &r, issuer, &cap, grantee);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, &hop, 1), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_OK,
	      "a delegable grantor could not withdraw a capability from its descendant");
	CHECK(f.store.used == 1, "used %zu after one grantor revocation, wanted 1",
	      f.store.used);
	CHECK(fzn_revocation_covers(&f.store, issuer, &cap, grantee) == 1,
	      "the entry does not answer under the ISSUER that signed it, so the store "
	      "has recorded somebody else as the revoker");

	/* THE SAME RECORD WITH NO CHAIN IS THE OLD WORLD, UNCHANGED. An offer
	 * of `hop_count == 0` says root-issued, and a record from anybody else
	 * is refused exactly as every admission before 2026-08-28 refused it. */
	fixture_init(&f);
	issue_keys(&f, bytes, &r, issuer, &cap, grantee);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_ERR_WRONG_ROOT,
	      "a non-root record with no chain was admitted, so hop_count == 0 no longer "
	      "means what it meant");
	CHECK(f.store.used == 0, "it was recorded anyway");
}

/* `delegable` IS NOT DECORATION, and this is the case that says so.
 *
 * A key can only be an ancestor if it appears as some hop's grantor, and
 * `fzn_chain_verify` refuses any such hop whose predecessor was not
 * `delegable`. So a non-delegable holder's revocations can never be
 * honoured, and admitting them is pure waste -- which excludes every leaf in
 * an estate, most keys, from spending a table that never evicts. */
static void test_a_non_delegable_holder_may_not_revoke(void)
{
	struct fixture f;
	uint8_t hop_bytes[FZN_HOP_LEN], bytes[FZN_REVOCATION_LEN];
	uint8_t issuer[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	fzn_chain_hop_t hop;
	fzn_revocation_record_t r;

	fixture_init(&f);
	capability_id(&cap, 0xc0);
	key(issuer, 1);
	key(grantee, 2);
	issue_keys(&f, bytes, &r, issuer, &cap, grantee);

	/* The control: the same everything, delegable. */
	mint_hop(&f, hop_bytes, &hop, 0, 1, &cap, 1000, FZN_NO_EXPIRY, 1);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, &hop, 1), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_OK,
	      "the control fails, so the refusal below proves nothing");

	fixture_init(&f);
	issue_keys(&f, bytes, &r, issuer, &cap, grantee);
	mint_hop(&f, hop_bytes, &hop, 0, 1, &cap, 1000, FZN_NO_EXPIRY, 0);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, &hop, 1), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_ERR_NOT_DELEGABLE,
	      "a holder that may not delegate was allowed to revoke, so it can spend the "
	      "store with revocations nothing will ever honour");
	CHECK(f.store.used == 0, "it was recorded anyway");
}

/* THE CHAIN HAS TO BE THE ISSUER'S OWN, FOR THE CAPABILITY BEING WITHDRAWN,
 * AND ROOTED AT THE PIN. Three ways of presenting somebody else's standing,
 * and each has to be refused separately: a chain that verifies perfectly is
 * not evidence about whoever hands it over. */
static void test_the_chain_offered_must_be_the_issuers_own(void)
{
	struct fixture f;
	uint8_t hop_bytes[FZN_HOP_LEN], bytes[FZN_REVOCATION_LEN];
	fzn_cap_id_t cap, other_cap;
	uint8_t issuer[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN], stranger[FZN_PUBKEY_LEN];
	fzn_chain_hop_t hop;
	fzn_revocation_record_t r;

	capability_id(&cap, 0xc0);
	capability_id(&other_cap, 0xff);
	key(issuer, 1);
	key(grantee, 2);
	key(stranger, 9);

	/* SOMEBODY ELSE'S CHAIN. The chain is the root's grant to key 1 and
	 * verifies; the record is signed by key 9, which the chain never
	 * mentions. */
	fixture_init(&f);
	issue_keys(&f, bytes, &r, stranger, &cap, grantee);
	mint_hop(&f, hop_bytes, &hop, 0, 1, &cap, 1000, FZN_NO_EXPIRY, 1);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, &hop, 1), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a key revoked under a chain granted to somebody else, so any published "
	      "chain is standing for anybody who copies it");
	CHECK(f.store.used == 0, "it was recorded anyway");

	/* THE WRONG CAPABILITY. Key 1 holds a delegable grant of `other_cap`
	 * and withdraws `cap`, which it was never given. Capabilities are
	 * independent rather than a ladder, so holding one is no standing over
	 * another. */
	fixture_init(&f);
	issue_keys(&f, bytes, &r, issuer, &cap, grantee);
	mint_hop(&f, hop_bytes, &hop, 0, 1, &other_cap, 1000, FZN_NO_EXPIRY, 1);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, &hop, 1), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a grant of one capability bought the standing to withdraw another");
	CHECK(f.store.used == 0, "it was recorded anyway");

	/* A CHAIN ROOTED SOMEWHERE ELSE, which gets its own code because on a
	 * shared network it is an ordinary event rather than an attack. */
	fixture_init(&f);
	issue_keys(&f, bytes, &r, issuer, &cap, grantee);
	mint_hop(&f, hop_bytes, &hop, 9, 1, &cap, 1000, FZN_NO_EXPIRY, 1);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, &hop, 1), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_ERR_WRONG_ROOT,
	      "a chain under a foreign root bought standing in this realm");
	CHECK(f.store.used == 0, "it was recorded anyway");
}

/* THE ISSUER-AGAINST-CHAIN-GRANTEE COMPARISON READS THE WHOLE KEY.
 *
 * project.md sec 11's rule, applied to the comparison introduced above. The
 * near miss is a genuinely usable identity here: `key_near` leaves byte 0
 * alone, and byte 0 is what the stub signs and verifies under, so the record
 * really is signed by the key it names and reaches this comparison rather
 * than being turned away at the signature.
 *
 * A short read here fails OPEN in the worst way available to this function:
 * a key one byte from a delegable holder gets that holder's standing, and
 * every revocation it cares to sign enters a table nothing evicts. */
static void test_the_issuer_comparison_reads_the_whole_key(void)
{
	struct fixture f;
	uint8_t hop_bytes[FZN_HOP_LEN], bytes[FZN_REVOCATION_LEN];
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	uint8_t exact[FZN_PUBKEY_LEN], near[FZN_PUBKEY_LEN];
	fzn_chain_hop_t hop;
	fzn_revocation_record_t r;

	capability_id(&cap, 0xc0);
	key(grantee, 2);
	key(exact, 1);
	key_near(near, 1);

	CHECK(memcmp(exact, near, FZN_PUBKEY_LEN - 1u) == 0,
	      "the near miss does not share a prefix with the key it near-misses, so it "
	      "decides no comparison length");
	CHECK(exact[FZN_PUBKEY_LEN - 1u] != near[FZN_PUBKEY_LEN - 1u],
	      "the near miss is the same value, so it is a second copy of the control");
	CHECK(exact[0] == near[0],
	      "the near miss carries a different identity, so it would be turned away at "
	      "the signature rather than at the comparison under test");

	fixture_init(&f);
	issue_keys(&f, bytes, &r, exact, &cap, grantee);
	mint_hop(&f, hop_bytes, &hop, 0, 1, &cap, 1000, FZN_NO_EXPIRY, 1);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, &hop, 1), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_OK,
	      "the control fails, so the refusal below proves nothing");

	fixture_init(&f);
	issue_keys(&f, bytes, &r, near, &cap, grantee);
	mint_hop(&f, hop_bytes, &hop, 0, 1, &cap, 1000, FZN_NO_EXPIRY, 1);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, &hop, 1), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a key matching the chain's grantee only in its first byte was given that "
	      "grantee's standing to revoke");
	CHECK(f.store.used == 0, "it was recorded anyway");
}

/* ADMISSION IS CLOCK-BLIND, AND A MAGIC VALUE IS DOING THE WORK.
 *
 * `fzn_revocation_admit` takes no `now`, so no caller can supply one, and it
 * verifies the issuer's chain at `now = 0`. That refuses nothing only
 * because FZN_NO_EXPIRY IS ZERO: `fzn_chain_verify` reads an expiry as
 * `if (expires_at != FZN_NO_EXPIRY) { ... if (expires_at <= now) EXPIRED; }`,
 * so the one value that could satisfy `<= 0` is the one the outer test has
 * already excluded.
 *
 * It matters because refusing a revocation on the REVOKER'S OWN expiry would
 * silently re-connect a revoked device: the grant lapses, the withdrawal
 * stops being admissible, and the host it was withdrawn from is authorised
 * again with nothing logged. A withdrawal is a thing already done, not a
 * standing claim.
 *
 * The control is the same chain verified at a real clock, which must say
 * EXPIRED -- otherwise the fixture is not an expired grant and the case
 * below is about nothing. */
static void test_admission_is_clock_blind(void)
{
	struct fixture f;
	uint8_t hop_bytes[FZN_HOP_LEN], bytes[FZN_REVOCATION_LEN];
	uint8_t issuer[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	fzn_chain_hop_t hop;
	fzn_revocation_record_t r;
	fzn_chain_t out;

	CHECK(FZN_NO_EXPIRY == 0u,
	      "FZN_NO_EXPIRY is not zero, so verifying at now = 0 expires every hop that "
	      "sets an expiry and admission has stopped being clock-blind");

	fixture_init(&f);
	capability_id(&cap, 0xc0);
	key(issuer, 1);
	key(grantee, 2);
	issue_keys(&f, bytes, &r, issuer, &cap, grantee);

	/* A grant that ran out long ago. */
	mint_hop(&f, hop_bytes, &hop, 0, 1, &cap, 100, 200, 1);
	CHECK(fzn_chain_verify(&hop, 1, f.root, &cap, 2000, &f.sign, NULL, &out) ==
	              FZN_CHAIN_ERR_EXPIRED,
	      "the fixture's grant has not expired at a real clock, so the case below is "
	      "about nothing");
	stub_reset(&f.stub);

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, &hop, 1), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_OK,
	      "a revocation was refused because the REVOKER'S own grant had lapsed, "
	      "which silently re-connects the device it was withdrawn from");
	CHECK(f.store.used == 1, "used %zu, wanted 1", f.store.used);
}

/* ADMISSION IS REVOCATION-BLIND, AND THE STORE IS THEREFORE ORDER-FREE.
 *
 * project.md sec 13b records what this protects: a standalone revocation
 * carries no sequence, revocation is monotone, and merge is set union, so
 * any number of holders of one replicated key may emit concurrently and
 * every host converges. That is a CRDT and it is exactly what a replicated
 * revoking key needs.
 *
 * Verifying the issuer's chain against the caller's store would end it. The
 * root's withdrawal from key 1 makes key 1's chain REVOKED, so a host that
 * heard the root first would refuse key 1's own earlier revocation and a
 * host that heard them the other way would hold both. Two honest hosts, the
 * same facts, different contents.
 *
 * The two orders are run into two stores and compared as SETS, which is the
 * property being claimed. */
static void test_admission_is_revocation_blind_and_order_free(void)
{
	struct fixture first, second;
	uint8_t hop_bytes[FZN_HOP_LEN];
	uint8_t root_bytes[FZN_REVOCATION_LEN], grantor_bytes[FZN_REVOCATION_LEN];
	uint8_t issuer[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	fzn_chain_hop_t hop;
	fzn_revocation_record_t from_root, from_grantor;
	fzn_revocation_offer_t root_offer, grantor_offer;

	fixture_init(&first);
	capability_id(&cap, 0xc0);
	key(issuer, 1);
	key(grantee, 2);

	mint_hop(&first, hop_bytes, &hop, 0, 1, &cap, 1000, FZN_NO_EXPIRY, 1);
	/* The root withdraws the capability from key 1 -- the revoker. */
	issue_keys(&first, root_bytes, &from_root, first.root, &cap, issuer);
	/* And key 1 withdraws it from key 2, which is what the root's entry
	 * would make inadmissible if admission could see it. */
	issue_keys(&first, grantor_bytes, &from_grantor, issuer, &cap, grantee);

	root_offer = fzn_revocation_offer_root(from_root);
	grantor_offer = fzn_revocation_offer_chain(from_grantor, &hop, 1);

	fixture_init(&second);

	CHECK(fzn_revocation_admit(&first.store, root_offer, first.root, &first.sign, NULL) ==
	              FZN_CHAIN_OK,
	      "the root's own withdrawal was refused");
	CHECK(fzn_revocation_admit(&first.store, grantor_offer, first.root, &first.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "a grantor's revocation became inadmissible once the ROOT had revoked that "
	      "grantor, so admission is reading the store and the contents now depend on "
	      "which peer spoke first");

	CHECK(fzn_revocation_admit(&second.store, grantor_offer, second.root, &second.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "the grantor's revocation was refused in the other order");
	CHECK(fzn_revocation_admit(&second.store, root_offer, second.root, &second.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "the root's withdrawal was refused in the other order");

	CHECK(first.store.used == 2 && second.store.used == 2,
	      "the two orders left %zu and %zu entries, so the store is not a set",
	      first.store.used, second.store.used);
	CHECK(fzn_revocation_covers(&first.store, first.root, &cap, issuer) == 1 &&
	              fzn_revocation_covers(&second.store, second.root, &cap, issuer) == 1,
	      "the root's withdrawal is missing from one of the two orders");
	CHECK(fzn_revocation_covers(&first.store, issuer, &cap, grantee) == 1 &&
	              fzn_revocation_covers(&second.store, issuer, &cap, grantee) == 1,
	      "the grantor's withdrawal is missing from one of the two orders, so a host "
	      "that heard the root first has forgotten a fact the other holds");
}

/* THE STORE IS NOT A CACHE OF "THIS ISSUER CHECKED OUT ONCE".
 *
 * Skipping the chain walk for a triple already held looks free -- the store
 * cannot change, so what is there to decide? -- and it makes the ANSWER
 * depend on whether this host happened to see the record before. That is the
 * order dependence the two invariants above exist to prevent, reached from a
 * third side, and project.md sec 13c names it as a temptation to refuse.
 *
 * So the same record is offered twice: first with the chain that entitles
 * it, then with one that does not. The second must be refused even though
 * the entry is sitting in the store. */
static void test_the_store_is_not_a_cache(void)
{
	struct fixture f;
	uint8_t good_hop[FZN_HOP_LEN], bad_hop[FZN_HOP_LEN], bytes[FZN_REVOCATION_LEN];
	uint8_t issuer[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	fzn_chain_hop_t good, bad;
	fzn_revocation_record_t r;

	fixture_init(&f);
	capability_id(&cap, 0xc0);
	key(issuer, 1);
	key(grantee, 2);
	issue_keys(&f, bytes, &r, issuer, &cap, grantee);
	mint_hop(&f, good_hop, &good, 0, 1, &cap, 1000, FZN_NO_EXPIRY, 1);
	mint_hop(&f, bad_hop, &bad, 0, 1, &cap, 1000, FZN_NO_EXPIRY, 0);

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, &good, 1), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_OK,
	      "the control fails, so the refusal below proves nothing");
	CHECK(f.store.used == 1, "used %zu, wanted 1", f.store.used);

	/* Hearing it again with the same standing is still success -- two
	 * peers both telling you is what carriage looks like when it works. */
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, &good, 1), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_OK,
	      "re-admitting a revocation already held was an error");

	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, &bad, 1), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_ERR_NOT_DELEGABLE,
	      "an unentitled offer was accepted because its triple was already in the "
	      "store, so the store is being used as a cache of who checked out");
	CHECK(f.store.used == 1, "the refused offer changed the store");
}

/* A CHAIN AT THE CEILING CAN NEVER MAKE ITS HOLDER AN ANCESTOR.
 *
 * FZN_CHAIN_MAX_HOPS bounds a chain, so a key at the end of a full one has
 * no room for the hop that would put it above somebody. Its revocations
 * could never be honoured, which is the same waste argument `delegable`
 * carries, and it is the same refusal `fzn_chain_delegate` makes for the
 * same reason.
 *
 * The control is the same chain one hop shorter, which must be admitted --
 * otherwise this passes because the fixture cannot build a long chain at
 * all. */
static void test_a_chain_at_the_ceiling_cannot_revoke(void)
{
	struct fixture f;
	uint8_t hop_bytes[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	uint8_t bytes[FZN_REVOCATION_LEN];
	uint8_t issuer[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	fzn_revocation_record_t r;

	fixture_init(&f);
	capability_id(&cap, 0xc0);
	key(grantee, 0x40);

	for (uint8_t i = 0; i < (uint8_t)FZN_CHAIN_MAX_HOPS; i++)
		mint_hop(&f, hop_bytes[i], &hops[i], i, (uint8_t)(i + 1u), &cap, 1000,
		         FZN_NO_EXPIRY, 1);

	/* One hop short of the ceiling: the last grantee still has room to be
	 * somebody's grantor, so its withdrawal is worth recording. */
	key(issuer, (uint8_t)(FZN_CHAIN_MAX_HOPS - 1u));
	issue_keys(&f, bytes, &r, issuer, &cap, grantee);
	CHECK(fzn_revocation_admit(&f.store,
	                           fzn_revocation_offer_chain(r, hops, FZN_CHAIN_MAX_HOPS - 1u),
	                           f.root, &f.sign, NULL) == FZN_CHAIN_OK,
	      "the control fails, so the refusal below proves nothing");

	fixture_init(&f);
	key(issuer, (uint8_t)FZN_CHAIN_MAX_HOPS);
	issue_keys(&f, bytes, &r, issuer, &cap, grantee);
	CHECK(fzn_revocation_admit(&f.store,
	                           fzn_revocation_offer_chain(r, hops, FZN_CHAIN_MAX_HOPS),
	                           f.root, &f.sign, NULL) == FZN_CHAIN_ERR_MALFORMED,
	      "a key at the end of a full chain was allowed to spend the store on "
	      "revocations no chain could ever honour");
	CHECK(f.store.used == 0, "it was recorded anyway");
}

/* ONE SIGNATURE STANDS IN FRONT OF SEVEN.
 *
 * A chain may carry FZN_CHAIN_MAX_HOPS - 1 hops, so checking standing before
 * the record's own signature would let one unsigned scrap of bytes with a
 * long chain stapled to it buy seven signature verifications -- a receiver's
 * CPU for the price of a datagram, which project.md sec 4.4a's threat model
 * is explicit about.
 *
 * The count is what makes it observable: a refused record must cost exactly
 * one verification, its own. */
static void test_a_forged_record_costs_one_verification(void)
{
	struct fixture f;
	uint8_t hop_bytes[3][FZN_HOP_LEN], bytes[FZN_REVOCATION_LEN];
	uint8_t issuer[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	fzn_chain_hop_t hops[3];
	fzn_revocation_record_t r;

	fixture_init(&f);
	capability_id(&cap, 0xc0);
	key(issuer, 3);
	key(grantee, 0x40);

	for (uint8_t i = 0; i < 3u; i++)
		mint_hop(&f, hop_bytes[i], &hops[i], i, (uint8_t)(i + 1u), &cap, 1000,
		         FZN_NO_EXPIRY, 1);

	issue_keys(&f, bytes, &r, issuer, &cap, grantee);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, hops, 3), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_OK,
	      "the control fails, so the count below is a count of nothing");
	CHECK(f.stub.calls == 4,
	      "an admitted three-hop offer cost %d verifications, wanted 4 -- the "
	      "record's own and one per hop",
	      f.stub.calls);

	fixture_init(&f);
	issue_keys(&f, bytes, &r, issuer, &cap, grantee);
	bytes[FZN_REV_OFF_SIGNATURE] ^= 0x01u;
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_chain(r, hops, 3), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a record with a broken signature was admitted");
	CHECK(f.stub.calls == 1,
	      "a forged record with a three-hop chain stapled to it cost %d "
	      "verifications, wanted 1 -- the chain is being walked before the record's "
	      "own signature is checked",
	      f.stub.calls);
}

/* An offer that names a chain it does not carry. `hop_count == 0` with a
 * stale `hops` is harmless and is what the root path uses; a count without
 * an array is a read through a pointer nobody set, and it is the caller's
 * bug rather than a peer's bytes. */
static void test_an_offer_that_names_a_chain_it_does_not_carry(void)
{
	struct fixture f;
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t r;
	fzn_revocation_offer_t offer;

	fixture_init(&f);
	issue(&f, bytes, &r, 0, 0xc0, 5);

	offer = fzn_revocation_offer_chain(r, NULL, 2);
	CHECK(fzn_revocation_admit(&f.store, offer, f.root, &f.sign, NULL) ==
	              FZN_CHAIN_ERR_MALFORMED,
	      "an offer with a hop count and no hops was walked");
	CHECK(f.store.used == 0, "it was recorded anyway");
	CHECK(f.stub.calls == 0, "it spent a verification on it");

	/* And the constructors agree about what they build, which is what
	 * keeps a caller from assembling half an offer. */
	CHECK(fzn_revocation_offer_root(r).hop_count == 0 &&
	              fzn_revocation_offer_root(r).hops == NULL,
	      "a root offer carries a chain");
	offer = fzn_revocation_offer_chain(r, NULL, 0);
	CHECK(fzn_revocation_admit(&f.store, offer, f.root, &f.sign, NULL) == FZN_CHAIN_OK,
	      "a chain offer of zero hops is not the root path, so the two spellings of "
	      "'no chain' disagree");
}

/* A BATCH MAY CARRY MORE THAN ONE ISSUER, which is the whole reason
 * `fzn_revocation_merge` takes offers rather than records. A batch of
 * records with one chain beside it could only ever have carried the
 * standing of one key. */
static void test_a_batch_carries_each_issuers_own_chain(void)
{
	struct fixture f;
	uint8_t hop_bytes[FZN_HOP_LEN];
	uint8_t bytes[3][FZN_REVOCATION_LEN];
	uint8_t issuer[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	uint8_t other[FZN_PUBKEY_LEN];
	fzn_chain_hop_t hop;
	fzn_revocation_record_t recs[3];
	fzn_revocation_offer_t batch[3];
	fzn_chain_err_t err = FZN_CHAIN_OK;
	size_t n;

	fixture_init(&f);
	capability_id(&cap, 0xc0);
	key(issuer, 1);
	key(grantee, 2);
	key(other, 5);
	mint_hop(&f, hop_bytes, &hop, 0, 1, &cap, 1000, FZN_NO_EXPIRY, 1);

	issue_keys(&f, bytes[0], &recs[0], f.root, &cap, other);   /* the root's */
	issue_keys(&f, bytes[1], &recs[1], issuer, &cap, grantee); /* a grantor's */
	issue_keys(&f, bytes[2], &recs[2], other, &cap, grantee);  /* nobody's */

	batch[0] = fzn_revocation_offer_root(recs[0]);
	batch[1] = fzn_revocation_offer_chain(recs[1], &hop, 1);
	batch[2] = fzn_revocation_offer_root(recs[2]);

	n = fzn_revocation_merge(&f.store, batch, 3, f.root, &f.sign, &err, NULL);
	CHECK(n == 2, "a mixed batch admitted %zu, wanted 2", n);
	CHECK(err == FZN_CHAIN_ERR_WRONG_ROOT, "the batch reported %d, wanted WRONG_ROOT",
	      (int)err);
	CHECK(fzn_revocation_covers(&f.store, f.root, &cap, other) == 1,
	      "the root's record did not reach the store");
	CHECK(fzn_revocation_covers(&f.store, issuer, &cap, grantee) == 1,
	      "the grantor's record did not reach the store, so a batch cannot carry a "
	      "second issuer's standing");
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
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root, &f.sign,
	                           NULL) == FZN_CHAIN_OK,
	      "the positive control fails, so every refusal above proves nothing");
}

/* A FUNCTION WITH NO DIRECT TEST, and its guards are the reason it exists.
 *
 * `fzn_revocation_covers_chain` is reached by this suite only through
 * `fzn_chain_verify`, which hands it a store it just validated, a hop array
 * it just parsed and a count it already bounded -- so not one of its own
 * argument guards has ever fired. Its header names the caller they are for:
 * "a consumer doing its own walk", holding a chain it parsed itself. That
 * consumer is precisely the one this suite never plays.
 *
 * The three answers are the header's, and they are NOT all the same answer,
 * which is why each needs driving separately: a null store revokes nothing,
 * a CORRUPT store revokes everything, and a question with no subject -- no
 * hops, no capability, a zero or oversized count -- revokes nothing, because
 * the question is absent rather than the answer permissive. Getting the
 * corrupt case backwards would be a store that cannot be read silently
 * authorising every hop in a chain. */
static void test_the_chain_walk_answers_its_own_guards(void)
{
	fzn_revocation_store_t store;
	fzn_revocation_t storage[2];
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	fzn_cap_id_t cap;
	uint8_t revoked[FZN_CHAIN_MAX_HOPS];
	size_t i;

	memset(&cap, 0x21, sizeof(cap));
	memset(hops, 0, sizeof(hops));
	CHECK(fzn_revocation_store_init(&store, storage, 2) == FZN_CHAIN_OK,
	      "store init refused");

	/* A NULL STORE REVOKES NOTHING -- what a consumer holding none relies
	 * on, and the answer `fzn_chain_verify` is built around. */
	memset(revoked, 0xff, sizeof(revoked));
	fzn_revocation_covers_chain(NULL, hops, 2u, &cap, revoked);
	for (i = 0; i < 2u; i++)
		CHECK(revoked[i] == 0u,
		      "a null store revoked hop %u", (unsigned)i);

	/* A CORRUPT STORE REVOKES EVERY HOP. `used` past `capacity` is a store
	 * whose entries cannot be scanned, and entries that cannot be read may
	 * hold the answer -- so denying is the safe reply to an authorisation
	 * question. This is the one answer that must NOT be the permissive
	 * one, and the direction a mistake would go unnoticed. */
	{
		fzn_revocation_store_t broken = store;

		broken.used = broken.capacity + 1u;
		memset(revoked, 0u, sizeof(revoked));
		fzn_revocation_covers_chain(&broken, hops, 2u, &cap, revoked);
		for (i = 0; i < 2u; i++)
			CHECK(revoked[i] == 1u,
			      "a store that cannot be scanned left hop %u authorised",
			      (unsigned)i);
	}

	/* A QUESTION WITH NO SUBJECT REVOKES NOTHING, and each way of having
	 * no subject is its own guard. */
	memset(revoked, 0xff, sizeof(revoked));
	fzn_revocation_covers_chain(&store, NULL, 2u, &cap, revoked);
	CHECK(revoked[0] == 0u, "a walk with no hops revoked one");

	memset(revoked, 0xff, sizeof(revoked));
	fzn_revocation_covers_chain(&store, hops, 0u, &cap, revoked);
	CHECK(revoked[0] == 0u, "a walk of zero hops revoked one");

	/* ONE PAST THE CEILING, which is a peer's number in a consumer that
	 * parsed the chain itself -- the exact caller the guard is for. */
	memset(revoked, 0xff, sizeof(revoked));
	fzn_revocation_covers_chain(&store, hops, FZN_CHAIN_MAX_HOPS + 1u, &cap,
	                            revoked);
	CHECK(revoked[0] == 0u, "a walk past the hop ceiling revoked one");

	memset(revoked, 0xff, sizeof(revoked));
	fzn_revocation_covers_chain(&store, hops, 2u, NULL, revoked);
	CHECK(revoked[0] == 0u, "a walk with no capability revoked one");

	/* A NULL OUTPUT HAS NOWHERE TO WRITE AN ANSWER, so it writes none --
	 * and must not fall over trying. */
	fzn_revocation_covers_chain(&store, hops, 2u, &cap, NULL);
	CHECK(1, "a walk with nowhere to answer returned");
}

/* THE CEILING, ASKED OF A STORE THAT HAS SOMETHING TO SAY.
 *
 * The case above drives `hop_count` one past FZN_CHAIN_MAX_HOPS and CANNOT
 * FAIL. Its store is freshly initialised, so `used` is zero, and the entry
 * loop the ceiling stands in front of never runs: nothing is written and
 * `revoked[0] == 0` holds whether the guard is there or not. Measured
 * 2026-09-03 with `sabotage.py --probe` -- removing the ceiling term leaves
 * the whole suite green.
 *
 * That is this file's own warning turned on itself. The case is headed "a
 * function with no direct test, and its guards are the reason it exists",
 * and it drives five guards that way; four of them refuse before the loop
 * and are held. This one only bites at the loop, so an empty store hides it.
 *
 * ONE ADMITTED ENTRY IS THE WHOLE DIFFERENCE. With `used == 1` the walk
 * runs, and an oversized count then reads `hops[]` and writes `revoked[]`
 * past the end of both -- on the authorisation path, in a consumer that
 * parsed the chain itself, which is the caller the guard's own comment
 * names and the one `fzn_chain_verify` never plays.
 *
 * THE ARRAYS CARRY ONE SLOT MORE THAN THE CEILING, so a sabotaged run is
 * measuring the library rather than wandering off the test's own stack.
 * `revoked[FZN_CHAIN_MAX_HOPS]` is a canary: the function clears exactly
 * FZN_CHAIN_MAX_HOPS bytes, so nothing legitimate reaches it.
 *
 * EVERY SLOT HOLDS A REAL OPENED HOP, the same one. Zeroed views would make
 * `fzn_hop_grantor` a pointer into nothing the moment the guard came out,
 * and a case whose sabotaged form dies on its own fixture has measured the
 * fixture. */
static void test_the_hop_ceiling_gates_a_walk_that_would_answer(void)
{
	struct fixture f;
	uint8_t hop_bytes[FZN_HOP_LEN], bytes[FZN_REVOCATION_LEN];
	fzn_chain_hop_t one, hops[FZN_CHAIN_MAX_HOPS + 1u];
	uint8_t revoked[FZN_CHAIN_MAX_HOPS + 1u];
	fzn_revocation_record_t r;
	fzn_cap_id_t cap;
	size_t i;

	fixture_init(&f);
	capability_id(&cap, 0xc0);

	/* The root grants to key 1, then withdraws it from key 1. */
	mint_hop(&f, hop_bytes, &one, 0, 1, &cap, 1000, FZN_NO_EXPIRY, 1);
	issue(&f, bytes, &r, 0, 0xc0, 1);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_OK,
	      "the fixture's revocation was refused, so nothing below is asking a "
	      "store that can answer");
	CHECK(f.store.used == 1, "the store holds %zu entries, wanted 1", f.store.used);

	for (i = 0; i < FZN_CHAIN_MAX_HOPS + 1u; i++)
		hops[i] = one;

	/* THE POSITIVE CONTROL. Without it the refusal below is satisfied by a
	 * store that answers nothing to any question, which is exactly how the
	 * case above came to prove nothing. */
	memset(revoked, 0u, sizeof(revoked));
	revoked[FZN_CHAIN_MAX_HOPS] = 0xa5u;
	fzn_revocation_covers_chain(&f.store, hops, 1u, &cap, revoked);
	CHECK(revoked[0] == 1u,
	      "a one-hop chain was not revoked by an entry naming its grantor, its "
	      "capability and its grantee -- so this store answers nothing and the "
	      "ceiling case below would pass against silence");
	CHECK(revoked[FZN_CHAIN_MAX_HOPS] == 0xa5u,
	      "a walk of one hop wrote past FZN_CHAIN_MAX_HOPS");

	/* ONE PAST THE CEILING: the store that just revoked must now say
	 * nothing, and must not have read or written to say it. */
	memset(revoked, 0u, sizeof(revoked));
	revoked[FZN_CHAIN_MAX_HOPS] = 0xa5u;
	fzn_revocation_covers_chain(&f.store, hops, FZN_CHAIN_MAX_HOPS + 1u, &cap,
	                            revoked);
	CHECK(revoked[0] == 0u,
	      "a walk past the hop ceiling answered rather than refusing, so a peer's "
	      "count decides how far this reads");
	CHECK(revoked[FZN_CHAIN_MAX_HOPS] == 0xa5u,
	      "a walk past the hop ceiling wrote past the end of the caller's array");
}

/* A KEY THAT GRANTS TWICE IS ENTITLED FROM ITS FIRST APPEARANCE.
 *
 * `covers_chain` takes the SMALLEST `j` whose grantor is the entry's issuer,
 * and its comment calls that "the whole of the entitlement rule": a key is an
 * ancestor of every hop after where it grants and of nothing before it, so a
 * key deep in one branch must not reach back and withdraw the root's own
 * grant at hop 0. The `break` is what makes it the smallest.
 *
 * NO CASE IN THIS TREE BUILT A CHAIN WITH A REPEATED GRANTOR. Every fixture
 * here seeds grantor `i` and grantee `i + 1`, and `chain_fuzz` cannot make
 * one either -- a chain that verifies must be linked, so its grantors are
 * pairwise distinct by construction. With every grantor unique, smallest and
 * largest are the same `j` and the `break` is invisible. Measured 2026-09-03:
 * deleting it left the whole suite green.
 *
 * THE DIRECTION OF THE FAILURE IS FAIL-OPEN. Taking the last appearance
 * instead of the first moves entitlement later in the chain, so the hops
 * between the two appearances stop being revoked -- a chain that re-uses a
 * key escapes a withdrawal that should bite it.
 *
 * Hop 1 sits between the two appearances and names a different grantee, so
 * it is NOT revoked either way. It is there to prove the walk is selecting
 * on the grantee rather than painting everything from `first` onward. */
static void test_a_repeated_grantor_is_entitled_from_its_first_hop(void)
{
	struct fixture f;
	uint8_t hop_bytes[3][FZN_HOP_LEN], bytes[FZN_REVOCATION_LEN];
	fzn_chain_hop_t hops[3];
	uint8_t revoked[FZN_CHAIN_MAX_HOPS];
	fzn_revocation_record_t r;
	fzn_cap_id_t cap;

	fixture_init(&f);
	capability_id(&cap, 0xc0);

	/* The root grants to key 2, somebody else grants to key 3, and the
	 * root grants to key 2 again. Only `covers_chain` reads this array and
	 * it does not check linkage, which is what lets a case build the shape
	 * a verified chain cannot. */
	mint_hop(&f, hop_bytes[0], &hops[0], 0, 2, &cap, 1000, FZN_NO_EXPIRY, 1);
	mint_hop(&f, hop_bytes[1], &hops[1], 9, 3, &cap, 1000, FZN_NO_EXPIRY, 1);
	mint_hop(&f, hop_bytes[2], &hops[2], 0, 2, &cap, 1000, FZN_NO_EXPIRY, 1);

	issue(&f, bytes, &r, 0, 0xc0, 2);
	CHECK(fzn_revocation_admit(&f.store, fzn_revocation_offer_root(r), f.root,
	                           &f.sign, NULL) == FZN_CHAIN_OK,
	      "the fixture's revocation was refused, so nothing below is asking a "
	      "store that can answer");

	memset(revoked, 0u, sizeof(revoked));
	fzn_revocation_covers_chain(&f.store, hops, 3u, &cap, revoked);

	CHECK(revoked[0] == 1u,
	      "the root's withdrawal did not reach hop 0, so entitlement was taken "
	      "from the key's LAST appearance and the hops before it escaped");
	CHECK(revoked[2] == 1u,
	      "the root's withdrawal did not reach hop 2, so the control fails and "
	      "the check above proves nothing");
	CHECK(revoked[1] == 0u,
	      "a hop naming a different grantee was revoked, so the walk paints "
	      "every hop from the first rather than selecting on the grantee");
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
	test_a_grantor_may_revoke_its_descendant();
	test_a_non_delegable_holder_may_not_revoke();
	test_the_chain_offered_must_be_the_issuers_own();
	test_the_issuer_comparison_reads_the_whole_key();
	test_admission_is_clock_blind();
	test_admission_is_revocation_blind_and_order_free();
	test_the_store_is_not_a_cache();
	test_a_chain_at_the_ceiling_cannot_revoke();
	test_a_forged_record_costs_one_verification();
	test_an_offer_that_names_a_chain_it_does_not_carry();
	test_a_batch_carries_each_issuers_own_chain();
	test_the_chain_walk_answers_its_own_guards();
	test_the_hop_ceiling_gates_a_walk_that_would_answer();
	test_a_repeated_grantor_is_entitled_from_its_first_hop();
	test_the_suite_can_tell_pass_from_fail();

	printf("revocation_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
