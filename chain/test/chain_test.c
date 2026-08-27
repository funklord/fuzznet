/* Tests for chain/chain.c.
 *
 * No framework, because there is nothing to justify one yet and a vendored
 * test dependency is a dependency. The whole file is deterministic: the
 * clock is a parameter and signatures are a stub, so there is nothing here
 * that can pass on a quiet machine and fail on a loaded one.
 *
 * THE STUB ANSWERS OVER THE MESSAGE NOW, NOT ONLY OVER THE KEY (2026-08-27),
 * and that is what this file is mostly about.
 *
 * Every signature stub in this tree opened `(void)msg;` and threw the bytes
 * away. A stub that ignores what it is asked to authenticate makes "is this
 * field inside the signed range?" a question with no observable answer -- so
 * the whole suite was green against a `fzn_chain_verify` that verified a
 * signature over one set of bytes and then decided every policy question
 * from a set of struct fields nothing had compared with them. chain.h
 * carries the reproduction; a single-hop chain was a total authorization
 * bypass.
 *
 * `stub_verify` is now a keyed MAC: it recomputes `mac(identity, msg)` and
 * compares. So a hop whose bytes are rewritten fails, and one whose bytes
 * are untouched passes, which is what makes the mutation cases below
 * something other than decoration.
 *
 * It still counts its calls and records which key each one used. Counting is
 * not decoration either -- chain.h claims the cheap structural checks run
 * BEFORE any signature verification, and a claim about ordering that nothing
 * measures is a comment.
 */

#include "../chain.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

/* A function rather than a multi-line macro body, so its arguments have
 * types -- a stray comma in a macro call becomes another argument rather
 * than an error.
 *
 * The format attribute is what makes that worth anything. A vprintf wrapper
 * is opaque to -Wformat without it, so `%zu` against an int would compile
 * silently here where the same mistake in a direct printf would not.
 * Confirmed by making one deliberately and watching it warn. */
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
	printf("  FAIL chain_test.c:%d: ", line);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* ---- the signature stub ---------------------------------------------- */

/* A toy MAC over (identity, message). Not cryptography and not pretending to
 * be: what a test signer owes this suite is that its answer DEPENDS ON EVERY
 * BYTE of the message and on who signed, so that rewriting a field is
 * visible and leaving it alone is not.
 *
 * Identity is the key's first byte. Every key here is 32 copies of one seed
 * (see `key`), so that byte IS the identity -- the same idiom the fuzz
 * harnesses beside this file use. */
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
	int fail_on_call; /* 1-based call number to refuse whatever the bytes say */
	int signs;        /* how many times sign was asked */
	int can_sign;     /* whether it agrees to */
	uint8_t identity; /* who this signer signs as */

	/* WHICH KEY EACH HOP WAS VERIFIED UNDER, recorded in order.
	 *
	 * Every signature stub in this tree opened `(void)pubkey;` and threw
	 * the key away, so the suite could count verifications and see their
	 * order but not see WHOSE signature was being checked. That left the
	 * single most damaging mutation in this module invisible: verifying a
	 * hop under `hop->grantee` instead of `hop->grantor` accepts a chain
	 * containing no root signature at all -- a total authorization bypass
	 * -- and chain_test, chain_fuzz and chain_guided were all green on it.
	 * Verifying every hop under the pinned root passes them too.
	 *
	 * Recording the key costs one memcpy per call and turns both into
	 * ordinary failures. */
	size_t keys_seen;
	uint8_t key_seen[FZN_CHAIN_MAX_HOPS][FZN_PUBKEY_LEN];
} stub_t;

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	stub_t *s = (stub_t *)ctx;
	uint8_t want[FZN_SIG_LEN];

	/* The module promises never to hand a verifier an empty region; a
	 * stub that quietly accepted one would hide that. */
	if (!msg || msg_len == 0) {
		printf("  FAIL: verifier called with an empty signed region\n");
		failures++;
		return 0;
	}

	if (s->keys_seen < FZN_CHAIN_MAX_HOPS) {
		memcpy(s->key_seen[s->keys_seen], pubkey, FZN_PUBKEY_LEN);
		s->keys_seen++;
	}

	s->calls++;
	if (s->fail_on_call && s->calls == s->fail_on_call)
		return 0;

	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

/* The signer takes no key, which is the property worth having: this module
 * has no secret-key parameter anywhere. What it does have is an IDENTITY,
 * because a signer that signed as nobody could not produce a signature a
 * keyed verifier would accept -- and a suite whose signer and verifier do
 * not agree about who is who proves nothing about either. */
static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	stub_t *s = (stub_t *)ctx;

	if (!msg || msg_len == 0) {
		printf("  FAIL: signer called with an empty region\n");
		failures++;
		return 0;
	}

	s->signs++;
	if (!s->can_sign)
		return 0;
	mac(sig, s->identity, msg, msg_len);
	return 1;
}

/* ---- fixtures --------------------------------------------------------- */

/* Distinct 32-byte values, built from a single byte so a failure message
 * can name them. Key 0 is the root by convention in these tests. */
static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	memset(out, seed, FZN_PUBKEY_LEN);
}

struct fixture {
	uint8_t bytes[2][FZN_HOP_LEN];
	fzn_chain_hop_t hops[2];
	uint8_t root[FZN_PUBKEY_LEN];
	uint8_t cap[FZN_CAP_ID_LEN];
	stub_t stub;
	fzn_sign_ops_t sign;
	fzn_chain_t out;
};

/* Zero the counters without disturbing the signer's identity or its
 * willingness to sign. Setting a fixture up costs signatures, and a test
 * asserting "it signed nothing" or "it verified nothing" is asking about
 * what the CASE did, not about what building it did. */
static void stub_reset(stub_t *s)
{
	s->calls = 0;
	s->fail_on_call = 0;
	s->signs = 0;
	s->keys_seen = 0;
	memset(s->key_seen, 0, sizeof(s->key_seen));
}

/* Mint a real hop into `out`, signed as `grantor_seed`.
 *
 * THE FIXTURES BUILD REAL HOPS NOW. They used to share one `REGION` string
 * literal across every hop in the file -- which was possible only because
 * nothing related a hop's bytes to its fields, and is the design defect
 * wearing its test-suite costume. */
static fzn_chain_err_t mint_hop(struct fixture *f, uint8_t *out, uint8_t grantor_seed,
                                uint8_t grantee_seed, uint8_t cap_seed, uint64_t issued_at,
                                uint64_t expires_at, int delegable)
{
	uint8_t grantor[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN], cap[FZN_CAP_ID_LEN];

	key(grantor, grantor_seed);
	key(grantee, grantee_seed);
	memset(cap, cap_seed, FZN_CAP_ID_LEN);
	f->stub.identity = grantor_seed;

	return fzn_chain_mint(grantor, grantee, cap, issued_at, expires_at, delegable,
	                      &f->sign, out);
}

/* Encode and sign a hop WITHOUT going through fzn_chain_mint.
 *
 * Narrowly for the objects mint refuses to make -- a grant that expires
 * before it was issued -- because a verifier's refusal of one has to be
 * testable even though the minter will not produce it. Everything else in
 * this file mints. */
static void forge_dates(struct fixture *f, uint8_t *out, uint8_t grantor_seed,
                        uint8_t grantee_seed, uint8_t cap_seed, uint64_t issued_at,
                        uint64_t expires_at)
{
	uint8_t grantor[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN], cap[FZN_CAP_ID_LEN];

	(void)f;
	key(grantor, grantor_seed);
	key(grantee, grantee_seed);
	memset(cap, cap_seed, FZN_CAP_ID_LEN);
	fzn_hop_encode(out, grantor, grantee, cap, issued_at, expires_at, 1);
	mac(out + FZN_HOP_OFF_SIGNATURE, grantor_seed, out, FZN_HOP_BODY_LEN);
}

static void fixture_open(struct fixture *f, size_t i)
{
	if (fzn_hop_open(f->bytes[i], FZN_HOP_LEN, &f->hops[i]) != FZN_CHAIN_OK) {
		printf("  FAIL: the fixture built a hop that will not open\n");
		failures++;
	}
}

/* A two-hop chain: root(0) -> host(1) -> agent(2), capability 0xc0.
 *
 * Hop 0 must say `delegable` for hop 1 to exist at all, which is the rule
 * asserting itself in the fixture: a chain assembled without thinking about
 * delegation does not verify. */
static void fixture_init(struct fixture *f)
{
	memset(f, 0, sizeof(*f));
	key(f->root, 0);
	memset(f->cap, 0xc0, FZN_CAP_ID_LEN);
	f->stub.can_sign = 1;
	f->sign.verify = stub_verify;
	f->sign.sign = stub_sign;
	f->sign.ctx = &f->stub;

	if (mint_hop(f, f->bytes[0], 0, 1, 0xc0, 1000, FZN_NO_EXPIRY, 1) != FZN_CHAIN_OK ||
	    mint_hop(f, f->bytes[1], 1, 2, 0xc0, 1000, FZN_NO_EXPIRY, 0) != FZN_CHAIN_OK) {
		printf("  FAIL: the fixture could not mint its own chain\n");
		failures++;
	}
	fixture_open(f, 0);
	fixture_open(f, 1);
	stub_reset(&f->stub);
}

static fzn_chain_err_t run(struct fixture *f, uint64_t now, const fzn_revocation_t *revs,
                           size_t nrevs)
{
	return fzn_chain_verify(f->hops, 2, f->root, f->cap, now, &f->sign, revs, nrevs,
	                        &f->out);
}

static fzn_chain_err_t run_one(struct fixture *f, uint64_t now)
{
	return fzn_chain_verify(f->hops, 1, f->root, f->cap, now, &f->sign, NULL, 0, &f->out);
}

/* ---- the layout ------------------------------------------------------- */

/* The numbers the header's table states, asserted rather than assumed.
 *
 * A layout change is a mechanical change to something already deployed, and
 * evidence.md asks one to carry a proof. Here the invariant is the table
 * itself: these constants and this byte order are what a second
 * implementation would be written from, so a silent change to either is a
 * signature nobody else can check. */
static void test_layout_is_the_one_the_header_describes(void)
{
	uint8_t buf[FZN_HOP_LEN];
	uint8_t grantor[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN], cap[FZN_CAP_ID_LEN];

	CHECK(FZN_HOP_BODY_LEN == 115u, "hop body is %u bytes, the table says 115",
	      (unsigned)FZN_HOP_BODY_LEN);
	CHECK(FZN_HOP_LEN == 179u, "hop is %u bytes, the table says 179", (unsigned)FZN_HOP_LEN);
	CHECK(FZN_HOP_OFF_SIGNATURE == FZN_HOP_BODY_LEN,
	      "the signature does not begin where the body ends");
	CHECK(FZN_HOP_OFF_DELEGABLE + 1u == FZN_HOP_BODY_LEN,
	      "delegable is not the last byte of the body, so the body has a hole in it");

	key(grantor, 0x11);
	key(grantee, 0x22);
	memset(cap, 0x33, sizeof(cap));
	CHECK(fzn_hop_encode(buf, grantor, grantee, cap, 0x0102030405060708ull,
	                     0x1112131415161718ull, 1) == FZN_CHAIN_OK,
	      "encoding a hop failed");

	CHECK(buf[FZN_HOP_OFF_VERSION] == 1u, "version byte is %u, wanted 1",
	      buf[FZN_HOP_OFF_VERSION]);
	CHECK(buf[FZN_HOP_OFF_OBJECT] == 1u, "object byte is %u, wanted FZN_OBJECT_HOP",
	      buf[FZN_HOP_OFF_OBJECT]);

	/* BIG-ENDIAN, spelled out. wire/bytes.h says network order is the only
	 * thing every implementation agrees on without being told; a test that
	 * only round-trips through this library's own accessors would pass
	 * just as happily on little-endian bytes nobody else can read. */
	CHECK(buf[FZN_HOP_OFF_ISSUED_AT] == 0x01u && buf[FZN_HOP_OFF_ISSUED_AT + 7u] == 0x08u,
	      "issued_at is not big-endian: first byte %02x, last %02x",
	      buf[FZN_HOP_OFF_ISSUED_AT], buf[FZN_HOP_OFF_ISSUED_AT + 7u]);
	CHECK(buf[FZN_HOP_OFF_EXPIRES_AT] == 0x11u && buf[FZN_HOP_OFF_EXPIRES_AT + 7u] == 0x18u,
	      "expires_at is not big-endian");
	CHECK(buf[FZN_HOP_OFF_DELEGABLE] == 1u, "delegable encoded as %u, wanted 1",
	      buf[FZN_HOP_OFF_DELEGABLE]);

	/* And a non-canonical "true" is normalised rather than written out,
	 * so the encoder cannot produce bytes its own parser refuses. */
	CHECK(fzn_hop_encode(buf, grantor, grantee, cap, 1, 2, 7) == FZN_CHAIN_OK, "encode");
	CHECK(buf[FZN_HOP_OFF_DELEGABLE] == 1u,
	      "delegable = 7 was written out as %u rather than normalised to 1",
	      buf[FZN_HOP_OFF_DELEGABLE]);
}

/* The round-trip property a layout change owes, in both directions.
 *
 * encode -> open -> read must reproduce every field, and open -> re-encode
 * must reproduce every byte. The second is the one that matters: it says the
 * accessors and the encoder describe the same layout, so a signature made
 * over what the encoder wrote is a signature over what the accessors read.
 * If those two ever disagreed, every policy decision in this module would be
 * taken from bytes the signature did not cover -- which is precisely the
 * defect this design replaced, reappearing inside one file instead of
 * between two structs. */
static void test_encode_open_round_trip(void)
{
	struct fixture f;
	uint8_t again[FZN_HOP_LEN];
	fzn_chain_hop_t hop;

	fixture_init(&f);
	CHECK(mint_hop(&f, f.bytes[0], 0, 1, 0xc0, 1234, 5678, 1) == FZN_CHAIN_OK, "mint");
	CHECK(fzn_hop_open(f.bytes[0], FZN_HOP_LEN, &hop) == FZN_CHAIN_OK, "open");

	{
		uint8_t grantor[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN], cap[FZN_CAP_ID_LEN];

		key(grantor, 0);
		key(grantee, 1);
		memset(cap, 0xc0, sizeof(cap));
		CHECK(fzn_ct_memeq(fzn_hop_grantor(hop), grantor, FZN_PUBKEY_LEN),
		      "grantor did not survive the round trip");
		CHECK(fzn_ct_memeq(fzn_hop_grantee(hop), grantee, FZN_PUBKEY_LEN),
		      "grantee did not survive the round trip");
		CHECK(fzn_ct_memeq(fzn_hop_capability(hop), cap, FZN_CAP_ID_LEN),
		      "capability did not survive the round trip");
	}
	CHECK(fzn_hop_issued_at(hop) == 1234, "issued_at read back as %llu, wanted 1234",
	      (unsigned long long)fzn_hop_issued_at(hop));
	CHECK(fzn_hop_expires_at(hop) == 5678, "expires_at read back as %llu, wanted 5678",
	      (unsigned long long)fzn_hop_expires_at(hop));
	CHECK(fzn_hop_delegable(hop) == 1, "delegable read back as %d, wanted 1",
	      fzn_hop_delegable(hop));

	/* The other direction: what the accessors say, re-encoded, is the
	 * signed region byte for byte. */
	CHECK(fzn_hop_encode(again, fzn_hop_grantor(hop), fzn_hop_grantee(hop),
	                     fzn_hop_capability(hop), fzn_hop_issued_at(hop),
	                     fzn_hop_expires_at(hop), fzn_hop_delegable(hop)) == FZN_CHAIN_OK,
	      "re-encoding from the accessors failed");
	CHECK(memcmp(again, f.bytes[0], FZN_HOP_BODY_LEN) == 0,
	      "re-encoding what the accessors read did not reproduce the signed bytes");

	/* And the range that gets signed is the whole body from its first
	 * byte -- version and object tag included, which is what makes the
	 * domain separation worth having. */
	{
		const uint8_t *at;
		size_t len;

		fzn_hop_signed_bytes(hop, &at, &len);
		CHECK(at == f.bytes[0], "the signed range does not start at the first byte");
		CHECK(len == FZN_HOP_BODY_LEN, "the signed range is %zu bytes, wanted %u", len,
		      (unsigned)FZN_HOP_BODY_LEN);
	}

	/* An unsigned encode leaves no stale signature behind. */
	CHECK(fzn_hop_encode(again, fzn_hop_grantor(hop), fzn_hop_grantee(hop),
	                     fzn_hop_capability(hop), 1, 2, 0) == FZN_CHAIN_OK, "encode");
	{
		uint8_t zero[FZN_SIG_LEN];

		memset(zero, 0, sizeof(zero));
		CHECK(memcmp(again + FZN_HOP_OFF_SIGNATURE, zero, FZN_SIG_LEN) == 0,
		      "encode left something in the signature it did not write");
	}
}

/* PARSE CHECKS LAYOUT. Each of these is a shape fault rather than a caller
 * bug, which is why FZN_CHAIN_ERR_SHAPE exists: bytes from a peer that are
 * the wrong length are the ordinary hostile input this library refuses, and
 * a receiver logging them as its own defect would be looking in the wrong
 * place.
 *
 * The positive control is stated rather than implied: the same bytes, with
 * the byte in question left alone, open cleanly. Without it "the parser
 * refuses X" is satisfied by a parser that refuses everything. */
static void test_open_refuses_what_is_not_our_shape(void)
{
	struct fixture f;
	uint8_t buf[FZN_HOP_LEN];
	fzn_chain_hop_t hop;

	fixture_init(&f);
	memcpy(buf, f.bytes[0], FZN_HOP_LEN);

	CHECK(fzn_hop_open(buf, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK,
	      "the positive control does not open, so every refusal below proves nothing");

	CHECK(fzn_hop_open(buf, FZN_HOP_LEN - 1u, &hop) == FZN_CHAIN_ERR_SHAPE,
	      "a hop one byte short was accepted");
	CHECK(fzn_hop_open(buf, FZN_HOP_LEN + 1u, &hop) == FZN_CHAIN_ERR_SHAPE,
	      "a hop with a trailing byte was accepted, so the length is not exact");
	CHECK(fzn_hop_open(buf, 0, &hop) == FZN_CHAIN_ERR_SHAPE, "an empty hop was accepted");

	buf[FZN_HOP_OFF_VERSION] = 2u;
	CHECK(fzn_hop_open(buf, FZN_HOP_LEN, &hop) == FZN_CHAIN_ERR_SHAPE,
	      "a hop claiming version 2 was accepted");
	buf[FZN_HOP_OFF_VERSION] = 1u;
	CHECK(fzn_hop_open(buf, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK,
	      "putting the version back did not restore the control");

	/* THE OBJECT BYTE EARNING ITS PLACE. One root key signs hops and
	 * revocations through the same seam; the tag inside the signed range
	 * is what stops a signature made for one being presented as the other.
	 * A hop that says it is a revocation is not a hop. */
	buf[FZN_HOP_OFF_OBJECT] = 2u;
	CHECK(fzn_hop_open(buf, FZN_HOP_LEN, &hop) == FZN_CHAIN_ERR_SHAPE,
	      "an otherwise valid hop tagged as a revocation was accepted as a hop");
	buf[FZN_HOP_OFF_OBJECT] = 1u;

	/* NON-CANONICAL `delegable`. Any nonzero byte would mean the same
	 * thing to a lenient reader, and then one grant has 255 spellings,
	 * each with a different signature, and two implementations that both
	 * "work" produce hops the other rejects. */
	buf[FZN_HOP_OFF_DELEGABLE] = 2u;
	CHECK(fzn_hop_open(buf, FZN_HOP_LEN, &hop) == FZN_CHAIN_ERR_SHAPE,
	      "delegable = 2 was accepted, so the encoding is not canonical");
	buf[FZN_HOP_OFF_DELEGABLE] = 0xffu;
	CHECK(fzn_hop_open(buf, FZN_HOP_LEN, &hop) == FZN_CHAIN_ERR_SHAPE,
	      "delegable = 255 was accepted");
	buf[FZN_HOP_OFF_DELEGABLE] = 1u;
	CHECK(fzn_hop_open(buf, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK,
	      "delegable = 1 was refused, so the canonicality check is too wide");
	buf[FZN_HOP_OFF_DELEGABLE] = 0u;
	CHECK(fzn_hop_open(buf, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK, "delegable = 0 was refused");

	/* A null is the caller's bug, not a peer's bytes. */
	CHECK(fzn_hop_open(NULL, FZN_HOP_LEN, &hop) == FZN_CHAIN_ERR_MALFORMED, "null bytes");
	CHECK(fzn_hop_open(buf, FZN_HOP_LEN, NULL) == FZN_CHAIN_ERR_MALFORMED, "null out");
}

/* ---- the cases -------------------------------------------------------- */

static void test_accepts_a_good_chain(void)
{
	struct fixture f;
	fixture_init(&f);

	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_OK, "a good two-hop chain was refused");
	CHECK(f.out.hop_count == 2, "hop_count %zu, wanted 2", f.out.hop_count);
	CHECK(f.out.expires_at == FZN_NO_EXPIRY, "an unexpiring chain reported an expiry");
	CHECK(fzn_ct_memeq(f.out.grantee, fzn_hop_grantee(f.hops[1]), FZN_PUBKEY_LEN),
	      "grantee is not the last hop's");
	CHECK(fzn_ct_memeq(f.out.root, f.root, FZN_PUBKEY_LEN), "root not reported back");
	CHECK(f.stub.calls == 2, "verified %d signatures, wanted 2", f.stub.calls);

	/* EACH HOP UNDER ITS OWN GRANTOR, which is the property that makes a
	 * chain a chain. Asserted by key rather than by call count: the counts
	 * above are satisfied by a verifier handed the wrong key twice.
	 *
	 * Both mutations this catches are total bypasses. Under
	 * `hop->grantee`, every hop verifies its own self-assertion and a chain
	 * containing no root signature is accepted. Under the pinned root, an
	 * attacker who can get the root to sign anything once can graft it
	 * anywhere. */
	CHECK(f.stub.keys_seen == 2, "recorded %zu keys, wanted 2", f.stub.keys_seen);
	CHECK(f.stub.keys_seen == 2 && fzn_ct_memeq(f.stub.key_seen[0],
	                                            fzn_hop_grantor(f.hops[0]), FZN_PUBKEY_LEN),
	      "hop 0 was not verified under its own grantor");
	CHECK(f.stub.keys_seen == 2 && fzn_ct_memeq(f.stub.key_seen[1],
	                                            fzn_hop_grantor(f.hops[1]), FZN_PUBKEY_LEN),
	      "hop 1 was not verified under its own grantor");
	/* And the two keys must differ, or the check above is satisfied by a
	 * chain whose hops happen to share a grantor. */
	CHECK(!fzn_ct_memeq(f.stub.key_seen[0], f.stub.key_seen[1], FZN_PUBKEY_LEN),
	      "the fixture verifies both hops under one key, so the check above proves "
	      "nothing");
}

static void test_root_is_pinned_not_adopted(void)
{
	struct fixture f;
	fixture_init(&f);
	key(f.root, 9); /* a perfectly valid chain, rooted at someone else */

	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_ERR_WRONG_ROOT, "a foreign root was adopted");
	CHECK(f.stub.calls == 0, "spent %d verifications on a foreign root", f.stub.calls);
}

static void test_broken_linkage(void)
{
	struct fixture f;
	fixture_init(&f);
	/* Hop 1 granted by somebody who was never granted anything. Minted
	 * genuinely by key 7, so its own signature is perfectly good and the
	 * only thing wrong with the chain is the join. */
	CHECK(mint_hop(&f, f.bytes[1], 7, 2, 0xc0, 1000, FZN_NO_EXPIRY, 0) == FZN_CHAIN_OK,
	      "mint");
	fixture_open(&f, 1);
	stub_reset(&f.stub);

	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_ERR_CHAIN_INVALID, "a broken link was accepted");
	CHECK(f.stub.calls == 0, "verified signatures on a chain that does not link");
}

/* THE CALL COUNTS BELOW ARE THE ORDERING CLAIM, NOT DECORATION. chain.h
 * lists six checks and says the order puts the cheap structural refusals
 * before any signature verification -- a denial-of-service property, since a
 * stranger's malformed chain must not cost a receiver the expensive part. */
static void test_capability_must_match_every_hop(void)
{
	struct fixture f;
	fixture_init(&f);
	CHECK(mint_hop(&f, f.bytes[1], 1, 2, 0xc1, 1000, FZN_NO_EXPIRY, 0) == FZN_CHAIN_OK,
	      "mint");
	fixture_open(&f, 1);
	stub_reset(&f.stub);

	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a chain that changes capability half way was accepted");
	CHECK(f.stub.calls == 0, "spent verifications on a spliced capability");
}

static void test_expiry_is_enforced_when_set(void)
{
	struct fixture f;
	fixture_init(&f);
	CHECK(mint_hop(&f, f.bytes[1], 1, 2, 0xc0, 1000, 1500, 0) == FZN_CHAIN_OK, "mint");
	fixture_open(&f, 1);
	stub_reset(&f.stub);

	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_ERR_EXPIRED, "an expired hop was accepted");
	CHECK(f.stub.calls == 0, "spent verifications on an expired hop");
	CHECK(run(&f, 1400, NULL, 0) == FZN_CHAIN_OK, "a live hop was refused");
	CHECK(f.out.expires_at == 1500, "expiry %llu, wanted 1500",
	      (unsigned long long)f.out.expires_at);

	/* THE BOUNDARY, WHICH MUST FAIL CLOSED. `expires_at == now` is the one
	 * instant the two readings disagree about, and it was tested at 1400
	 * and 2000 -- either side of it, never on it. Relaxing `<=` to `<` was
	 * caught by nothing in the tree.
	 *
	 * Closed is the right direction because an expiry is a statement about
	 * when authority ENDS, and a grant that ended this second has ended. */
	CHECK(run(&f, 1500, NULL, 0) == FZN_CHAIN_ERR_EXPIRED,
	      "a hop expiring exactly now was accepted");
	CHECK(run(&f, 1499, NULL, 0) == FZN_CHAIN_OK,
	      "a hop expiring next second was refused, so the boundary moved");
}

static void test_expiry_is_the_weakest_link(void)
{
	struct fixture f;

	fixture_init(&f);
	CHECK(mint_hop(&f, f.bytes[0], 0, 1, 0xc0, 1000, 9000, 1) == FZN_CHAIN_OK, "mint");
	CHECK(mint_hop(&f, f.bytes[1], 1, 2, 0xc0, 1000, 5000, 0) == FZN_CHAIN_OK, "mint");
	fixture_open(&f, 0);
	fixture_open(&f, 1);
	stub_reset(&f.stub);

	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_OK, "a live chain was refused");
	CHECK(f.out.expires_at == 5000, "expiry %llu, wanted the soonest (5000)",
	      (unsigned long long)f.out.expires_at);

	/* And an unlimited hop must not win the minimum by being smaller. */
	fixture_init(&f);
	CHECK(mint_hop(&f, f.bytes[1], 1, 2, 0xc0, 1000, 5000, 0) == FZN_CHAIN_OK, "mint");
	fixture_open(&f, 1);
	stub_reset(&f.stub);
	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_OK, "a live chain was refused");
	CHECK(f.out.expires_at == 5000, "an unlimited hop won the minimum");
}

static void test_expiry_before_issue_is_malformed_not_expired(void)
{
	struct fixture f;

	fixture_init(&f);
	/* Signed directly, because fzn_chain_mint refuses to make one -- see
	 * `forge_dates`. The verifier must still refuse it, since a peer's
	 * minter is not ours. */
	forge_dates(&f, f.bytes[0], 0, 1, 0xc0, 5000, 4000);
	fixture_open(&f, 0);
	stub_reset(&f.stub);

	CHECK(run(&f, 1000, NULL, 0) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a grant that expired before it was issued was treated as merely expired");
}

static void test_revocation_kills_a_middle_hop(void)
{
	struct fixture f;
	fzn_revocation_t rev;

	/* The case that matters: revoke the INTERMEDIATE host, not the
	 * grantee at the end. A stolen device that delegated onward before it
	 * was revoked must not survive by hiding behind what it granted. */
	fixture_init(&f);
	memset(&rev, 0, sizeof(rev));
	memset(rev.capability, 0xc0, FZN_CAP_ID_LEN);
	key(rev.grantee, 1); /* hop 0's grantee -- the middle of the chain */
	/* NAMED RATHER THAN LEFT ZERO. An entry says who withdrew it, and only
	 * the root does today, so every revocation this file builds is the
	 * root's. The fixture's root happens to be 32 zero bytes, so a
	 * `memset` alone would match by accident and go on matching until
	 * somebody changed the root -- an agreement is not a check. */
	memcpy(rev.issuer, f.root, FZN_PUBKEY_LEN);

	CHECK(run(&f, 2000, &rev, 1) == FZN_CHAIN_ERR_REVOKED,
	      "revoking the middle of a chain did not kill what it granted");
	CHECK(f.stub.calls == 0, "spent verifications on a revoked chain");

	/* And revoking the end works too, which is the ordinary case. */
	fixture_init(&f);
	key(rev.grantee, 2);
	CHECK(run(&f, 2000, &rev, 1) == FZN_CHAIN_ERR_REVOKED, "revoking the grantee had no effect");
}

static void test_revocation_is_per_capability(void)
{
	struct fixture f;
	fzn_revocation_t rev;

	/* Capabilities are independent rather than a ladder (sec 4.2), so
	 * revoking one from a key must leave the others alone. */
	fixture_init(&f);
	memset(&rev, 0, sizeof(rev));
	memset(rev.capability, 0xff, FZN_CAP_ID_LEN); /* a different capability */
	key(rev.grantee, 2);
	memcpy(rev.issuer, f.root, FZN_PUBKEY_LEN);

	CHECK(run(&f, 2000, &rev, 1) == FZN_CHAIN_OK,
	      "revoking one capability withdrew an unrelated one");
}

/* The other axis of the same question, and the one that was missing.
 *
 * A revocation names a capability AND a grantee. The case above varies the
 * capability and holds the grantee; nothing varied the grantee, so a
 * `hop_is_revoked` that compared the capability alone -- withdrawing a
 * capability from EVERY key the moment it is withdrawn from one -- passed
 * the whole suite. That is a denial of service against every host sharing a
 * capability with a revoked one, delivered by a single legitimate
 * revocation.
 *
 * The positive leg is asserted alongside, so this cannot pass by the
 * revocation matching nothing at all. */
static void test_revocation_is_per_grantee(void)
{
	struct fixture f;
	fzn_revocation_t rev;

	fixture_init(&f);
	memset(&rev, 0, sizeof(rev));
	memcpy(rev.capability, f.cap, FZN_CAP_ID_LEN); /* the capability in use */
	key(rev.grantee, 7);                           /* but somebody else's key */
	memcpy(rev.issuer, f.root, FZN_PUBKEY_LEN);

	CHECK(run(&f, 2000, &rev, 1) == FZN_CHAIN_OK,
	      "revoking a capability from one key withdrew it from another");

	/* And revoking it from the key actually in the chain must bite, or the
	 * check above is satisfied by a revocation that matches nobody. */
	memcpy(rev.grantee, fzn_hop_grantee(f.hops[1]), FZN_PUBKEY_LEN);
	CHECK(run(&f, 2000, &rev, 1) == FZN_CHAIN_ERR_REVOKED,
	      "revoking the chain's own grantee did not bite");
}

/* The third axis, and it is the one that was missing entirely.
 *
 * An entry also names an ISSUER, because the store it comes from may hold
 * entries from more than one -- a host anchoring two roots keeps one store.
 * Until this, `hop_is_revoked` compared the capability and the grantee and
 * nothing else, so a revocation issued by a root that has nothing to do with
 * this chain killed it: any anchored peer could disconnect any key in any
 * other peer's realm. chain/test/revocation_test.c carries the same defect
 * end to end, from a record that is genuinely signed.
 *
 * The positive leg is asserted alongside, on the same reasoning as the two
 * cases above -- otherwise a revocation matching nobody would satisfy it. */
static void test_revocation_is_per_issuer(void)
{
	struct fixture f;
	fzn_revocation_t rev;

	fixture_init(&f);
	memset(&rev, 0, sizeof(rev));
	memcpy(rev.capability, f.cap, FZN_CAP_ID_LEN);
	memcpy(rev.grantee, fzn_hop_grantee(f.hops[1]), FZN_PUBKEY_LEN);
	key(rev.issuer, 7); /* a root this chain was never rooted at */

	CHECK(run(&f, 2000, &rev, 1) == FZN_CHAIN_OK,
	      "a revocation from a foreign root killed a chain in another root's realm");

	memcpy(rev.issuer, f.root, FZN_PUBKEY_LEN);
	CHECK(run(&f, 2000, &rev, 1) == FZN_CHAIN_ERR_REVOKED,
	      "the pinned root's own revocation did not bite");
}

static void test_a_bad_signature_is_refused(void)
{
	struct fixture f;

	/* A tampered signature, which is now a real one: the bytes are checked
	 * rather than a stub being told to say no. */
	fixture_init(&f);
	f.bytes[1][FZN_HOP_OFF_SIGNATURE] ^= 0x01u;
	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_ERR_CHAIN_INVALID, "a bad signature was accepted");
	CHECK(f.stub.calls == 2, "stopped before reaching hop 1's signature");

	fixture_init(&f);
	f.bytes[0][FZN_HOP_OFF_SIGNATURE + 3u] ^= 0x80u;
	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a bad root signature was accepted");
	CHECK(f.stub.calls == 1, "kept verifying after hop 0 failed");

	/* And a signature that is merely somebody else's -- the same bytes a
	 * different identity would have produced -- is refused, which is the
	 * key half of the seam rather than the message half. */
	fixture_init(&f);
	mac(f.bytes[0] + FZN_HOP_OFF_SIGNATURE, 9u, f.bytes[0], FZN_HOP_BODY_LEN);
	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a hop signed by the wrong identity was accepted");
}

static void test_bounds(void)
{
	struct fixture f;
	static uint8_t many_bytes[FZN_CHAIN_MAX_HOPS + 1][FZN_HOP_LEN];
	fzn_chain_hop_t many[FZN_CHAIN_MAX_HOPS + 1];

	fixture_init(&f);
	CHECK(fzn_chain_verify(f.hops, 0, f.root, f.cap, 2000, &f.sign, NULL, 0, &f.out) ==
	              FZN_CHAIN_ERR_MALFORMED,
	      "a zero-hop chain was not refused");

	for (size_t i = 0; i < FZN_CHAIN_MAX_HOPS + 1u; i++) {
		CHECK(mint_hop(&f, many_bytes[i], (uint8_t)i, (uint8_t)(i + 1), 0xc0, 1000,
		               FZN_NO_EXPIRY, 1) == FZN_CHAIN_OK,
		      "minting filler hop %zu", i);
		CHECK(fzn_hop_open(many_bytes[i], FZN_HOP_LEN, &many[i]) == FZN_CHAIN_OK,
		      "opening filler hop %zu", i);
	}
	stub_reset(&f.stub);
	CHECK(fzn_chain_verify(many, FZN_CHAIN_MAX_HOPS + 1u, f.root, f.cap, 2000, &f.sign,
	                       NULL, 0, &f.out) == FZN_CHAIN_ERR_MALFORMED,
	      "a chain past FZN_CHAIN_MAX_HOPS was not refused");
	CHECK(f.stub.calls == 0, "spent verifications on an over-long chain");

	fixture_init(&f);
	CHECK(fzn_chain_verify(NULL, 2, f.root, f.cap, 2000, &f.sign, NULL, 0, &f.out) ==
	              FZN_CHAIN_ERR_MALFORMED,
	      "null hops accepted");
	CHECK(fzn_chain_verify(f.hops, 2, f.root, f.cap, 2000, &f.sign, NULL, 3, &f.out) ==
	              FZN_CHAIN_ERR_MALFORMED,
	      "a nonzero revocation count with a null list was accepted");

	/* A view that was never opened. It is MALFORMED rather than SHAPE:
	 * nothing about any bytes is wrong, the caller skipped fzn_hop_open. */
	fixture_init(&f);
	f.hops[1].base = NULL;
	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_ERR_MALFORMED,
	      "a hop that was never opened passed");
	CHECK(f.stub.calls == 0, "dereferenced its way into verifying an unopened hop");
}

static void test_out_is_untouched_on_failure(void)
{
	struct fixture f;
	fzn_chain_t before;

	fixture_init(&f);
	memset(&f.out, 0xab, sizeof(f.out));
	before = f.out;
	f.bytes[0][FZN_HOP_OFF_SIGNATURE] ^= 0x01u;

	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_ERR_CHAIN_INVALID, "expected a refusal");
	CHECK(memcmp(&before, &f.out, sizeof(before)) == 0,
	      "a rejected chain wrote something into *out");
}

static void test_ct_memeq(void)
{
	uint8_t a[4] = { 1, 2, 3, 4 };
	uint8_t b[4] = { 1, 2, 3, 4 };
	uint8_t c[4] = { 1, 2, 3, 5 };
	uint8_t d[4] = { 9, 2, 3, 4 };

	CHECK(fzn_ct_memeq(a, b, 4), "equal buffers reported different");
	CHECK(!fzn_ct_memeq(a, c, 4), "a difference in the last byte was missed");
	CHECK(!fzn_ct_memeq(a, d, 4), "a difference in the first byte was missed");
	CHECK(fzn_ct_memeq(a, c, 3), "a length-limited comparison read past its length");
	CHECK(fzn_ct_memeq(a, d, 0), "a zero-length comparison was not trivially equal");
}

static void test_delegation_needs_permission_not_just_possession(void)
{
	struct fixture f;

	/* The lesson fuzzypickles paid for, in this library's vocabulary: a
	 * host that holds a capability must not be able to hand it on merely
	 * by holding it. Mint hop 0 without the bit and hop 1 becomes a
	 * delegation nobody authorised. */
	fixture_init(&f);
	CHECK(mint_hop(&f, f.bytes[0], 0, 1, 0xc0, 1000, FZN_NO_EXPIRY, 0) == FZN_CHAIN_OK,
	      "mint");
	fixture_open(&f, 0);
	stub_reset(&f.stub);

	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a chain continued past a hop that was not delegable");
	CHECK(f.stub.calls == 0, "verified signatures on an unauthorised delegation");
}

/* ---- signature reuse: one mutation per field -------------------------- */

/* THE DEFECT THIS FILE EXISTS TO KEEP CLOSED.
 *
 * Each case below takes a genuinely minted hop, rewrites ONE field in place,
 * and leaves the 64 signature bytes byte-identical -- which is exactly what
 * the old design permitted, because the fields it decided from were a
 * separate struct nothing compared with the signed bytes.
 *
 * Three things make each case worth its lines, and all three are stated in
 * the case rather than left to this comment:
 *
 *   - THE POSITIVE CONTROL. The same object with the field left alone,
 *     verified by the same stub, must return OK. Without it, "signature
 *     reuse is refused" is satisfied by a verifier that refuses everything.
 *   - THE SIGNATURE IS UNCHANGED, asserted rather than assumed, or the case
 *     is testing a corrupted signature instead of a rewritten field.
 *   - THE VERIFICATION WAS REACHED, by call count, so the refusal is the
 *     signature's and not some earlier structural check answering by
 *     accident with the same code.
 *
 * ONE PER FIELD, deliberately. A single "delete the binding" mutation is
 * satisfied by a binding that covers one field, and the field that would
 * have been covered is whichever the author thought of first. */

/* Assert the attack kept the signature, which is what makes it an attack. */
static void assert_signature_kept(const uint8_t *forged, const uint8_t *genuine, const char *what)
{
	check_at(memcmp(forged + FZN_HOP_OFF_SIGNATURE, genuine + FZN_HOP_OFF_SIGNATURE,
	                FZN_SIG_LEN) == 0,
	         __LINE__, "%s: the case altered the signature, so it is not signature reuse",
	         what);
}

/* DELEGABLE FIRST, because it is the sharpest.
 *
 * Host 1 is given a grant it may NOT pass on. It flips one byte -- the
 * signature and every other byte of hop 0 untouched -- and then mints a hop
 * of its own, signed with its own key, which it is perfectly entitled to do.
 * The result is a delegation nobody authorised, built out of a grant the
 * attacker was legitimately given. */
static void test_forged_delegable_is_refused(void)
{
	struct fixture f;
	uint8_t genuine[FZN_HOP_LEN];

	fixture_init(&f);
	CHECK(mint_hop(&f, f.bytes[0], 0, 1, 0xc0, 1000, FZN_NO_EXPIRY, 0) == FZN_CHAIN_OK,
	      "mint");
	memcpy(genuine, f.bytes[0], FZN_HOP_LEN);
	fixture_open(&f, 0);
	stub_reset(&f.stub);

	/* The positive control: the hop as minted, alone, is a good chain. */
	CHECK(run_one(&f, 2000) == FZN_CHAIN_OK,
	      "delegable: the control fails, so the refusal below proves nothing");
	CHECK(f.stub.calls == 1, "delegable: the control did not reach the signature");

	/* Now the forgery: 0 becomes 1, and host 1 grants onward. */
	f.bytes[0][FZN_HOP_OFF_DELEGABLE] = 1u;
	assert_signature_kept(f.bytes[0], genuine, "delegable");
	CHECK(mint_hop(&f, f.bytes[1], 1, 3, 0xc0, 1000, FZN_NO_EXPIRY, 0) == FZN_CHAIN_OK,
	      "delegable: the attacker could not mint its own hop");
	fixture_open(&f, 0);
	fixture_open(&f, 1);
	stub_reset(&f.stub);

	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "DELEGABLE was rewritten from 0 to 1 on a genuinely signed hop and the chain "
	      "was accepted: an attacker can delegate what nobody authorised");
	CHECK(f.stub.calls == 1,
	      "delegable: refused after %d verifications; hop 0's signature is what must "
	      "have refused it",
	      f.stub.calls);

	/* And the same two-hop chain with the bit genuinely set verifies, so
	 * the refusal above is about the forged byte rather than about the
	 * shape of a two-hop chain. */
	fixture_init(&f);
	CHECK(mint_hop(&f, f.bytes[0], 0, 1, 0xc0, 1000, FZN_NO_EXPIRY, 1) == FZN_CHAIN_OK,
	      "mint");
	CHECK(mint_hop(&f, f.bytes[1], 1, 3, 0xc0, 1000, FZN_NO_EXPIRY, 0) == FZN_CHAIN_OK,
	      "mint");
	fixture_open(&f, 0);
	fixture_open(&f, 1);
	stub_reset(&f.stub);
	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_OK,
	      "delegable: the second control fails, so the refusal above may be about "
	      "something other than the bit");
}

/* GRANTEE. The headline of the reproduction in chain.h: an attacker rewrites
 * the grantee of a genuine root-signed hop to their own key and is
 * authorised for a capability nobody granted them. */
static void test_forged_grantee_is_refused(void)
{
	struct fixture f;
	uint8_t genuine[FZN_HOP_LEN];
	uint8_t attacker[FZN_PUBKEY_LEN];

	fixture_init(&f);
	memcpy(genuine, f.bytes[0], FZN_HOP_LEN);

	CHECK(run_one(&f, 2000) == FZN_CHAIN_OK,
	      "grantee: the control fails, so the refusal below proves nothing");
	CHECK(fzn_ct_memeq(f.out.grantee, fzn_hop_grantee(f.hops[0]), FZN_PUBKEY_LEN),
	      "grantee: the control did not report the hop's own grantee");

	key(attacker, 0xee);
	memcpy(f.bytes[0] + FZN_HOP_OFF_GRANTEE, attacker, FZN_PUBKEY_LEN);
	assert_signature_kept(f.bytes[0], genuine, "grantee");
	fixture_open(&f, 0);
	stub_reset(&f.stub);

	CHECK(run_one(&f, 2000) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "GRANTEE was rewritten to the attacker's key on a genuinely signed hop and "
	      "the chain was accepted: a total authorization bypass");
	CHECK(f.stub.calls == 1, "grantee: refused before the signature was reached");
	CHECK(!fzn_ct_memeq(f.out.grantee, attacker, FZN_PUBKEY_LEN),
	      "grantee: the attacker's key was reported as authorised");
}

/* CAPABILITY. Verified against the capability the forged bytes now name, so
 * that step 2 -- every hop names the capability asked for -- passes and the
 * refusal has to come from the signature. Asking for the ORIGINAL capability
 * would be refused by the cheap check and would say nothing about whether
 * the field is signed. */
static void test_forged_capability_is_refused(void)
{
	struct fixture f;
	uint8_t genuine[FZN_HOP_LEN];

	fixture_init(&f);
	memcpy(genuine, f.bytes[0], FZN_HOP_LEN);

	CHECK(run_one(&f, 2000) == FZN_CHAIN_OK,
	      "capability: the control fails, so the refusal below proves nothing");

	memset(f.bytes[0] + FZN_HOP_OFF_CAPABILITY, 0xff, FZN_CAP_ID_LEN);
	memset(f.cap, 0xff, FZN_CAP_ID_LEN);
	assert_signature_kept(f.bytes[0], genuine, "capability");
	fixture_open(&f, 0);
	stub_reset(&f.stub);

	CHECK(run_one(&f, 2000) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "CAPABILITY was rewritten on a genuinely signed hop and the chain was "
	      "accepted: a grant for one capability becomes a grant for any");
	CHECK(f.stub.calls == 1, "capability: refused before the signature was reached");
}

/* ISSUED_AT. It constrains nothing on its own -- which is the point: its
 * only protection is the signature, so a binding that covers "the fields
 * that matter" leaves it out and nothing else in this suite notices. It
 * matters because it is what a later expiry is measured against, and because
 * a grant that can be back-dated is a grant whose history is a fiction. */
static void test_forged_issued_at_is_refused(void)
{
	struct fixture f;
	uint8_t genuine[FZN_HOP_LEN];

	fixture_init(&f);
	memcpy(genuine, f.bytes[0], FZN_HOP_LEN);

	CHECK(run_one(&f, 2000) == FZN_CHAIN_OK,
	      "issued_at: the control fails, so the refusal below proves nothing");
	CHECK(fzn_hop_issued_at(f.hops[0]) == 1000, "issued_at: the control is not 1000");

	fzn_put_be64(f.bytes[0] + FZN_HOP_OFF_ISSUED_AT, 9999u);
	assert_signature_kept(f.bytes[0], genuine, "issued_at");
	fixture_open(&f, 0);
	stub_reset(&f.stub);

	CHECK(run_one(&f, 2000) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "ISSUED_AT was rewritten on a genuinely signed hop and the chain was "
	      "accepted: a grant can be re-dated at will");
	CHECK(f.stub.calls == 1, "issued_at: refused before the signature was reached");
}

/* EXPIRES_AT. The attack is to rewrite a time-boxed grant into a permanent
 * one by writing FZN_NO_EXPIRY over the expiry -- which is zero, so it is
 * also the value a truncating or forgetful encoder produces. */
static void test_forged_expires_at_is_refused(void)
{
	struct fixture f;
	uint8_t genuine[FZN_HOP_LEN];

	fixture_init(&f);
	CHECK(mint_hop(&f, f.bytes[0], 0, 1, 0xc0, 1000, 1500, 1) == FZN_CHAIN_OK, "mint");
	memcpy(genuine, f.bytes[0], FZN_HOP_LEN);
	fixture_open(&f, 0);
	stub_reset(&f.stub);

	/* The control, twice: live before the expiry, refused after it. */
	CHECK(run_one(&f, 1400) == FZN_CHAIN_OK,
	      "expires_at: the control fails, so the refusal below proves nothing");
	CHECK(run_one(&f, 2000) == FZN_CHAIN_ERR_EXPIRED,
	      "expires_at: the grant did not expire, so there is nothing to forge past");

	fzn_put_be64(f.bytes[0] + FZN_HOP_OFF_EXPIRES_AT, FZN_NO_EXPIRY);
	assert_signature_kept(f.bytes[0], genuine, "expires_at");
	fixture_open(&f, 0);
	stub_reset(&f.stub);

	CHECK(run_one(&f, 2000) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "EXPIRES_AT was rewritten to FZN_NO_EXPIRY on a genuinely signed hop and the "
	      "chain was accepted: an expired grant becomes a permanent one");
	CHECK(f.stub.calls == 1, "expires_at: refused before the signature was reached");
}

/* GRANTOR, and it needs the one piece of care in this suite.
 *
 * The verifying key is READ OUT OF the grantor field, so rewriting it to a
 * different key changes both the message and the key the signature is
 * checked against -- and a refusal could then be either. That would leave
 * "grantor is inside the signed range" untested by a case that appears to
 * test it.
 *
 * So the rewrite lands on a byte OTHER than the first, and the root is
 * pinned to the rewritten value. The stub's identity is the key's first
 * byte, which is unchanged, so the verifier is asked about the same signer
 * and the pinning check passes. The only thing left that can refuse is the
 * message, which is what this case is about. */
static void test_forged_grantor_is_refused(void)
{
	struct fixture f;
	uint8_t genuine[FZN_HOP_LEN];

	fixture_init(&f);
	memcpy(genuine, f.bytes[0], FZN_HOP_LEN);

	CHECK(run_one(&f, 2000) == FZN_CHAIN_OK,
	      "grantor: the control fails, so the refusal below proves nothing");

	f.bytes[0][FZN_HOP_OFF_GRANTOR + 1u] ^= 0x5au;
	memcpy(f.root, f.bytes[0] + FZN_HOP_OFF_GRANTOR, FZN_PUBKEY_LEN);
	assert_signature_kept(f.bytes[0], genuine, "grantor");
	fixture_open(&f, 0);
	stub_reset(&f.stub);

	CHECK(run_one(&f, 2000) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "GRANTOR was rewritten on a genuinely signed hop, with the root pinned to "
	      "the new value, and the chain was accepted: the field is outside the "
	      "signed range");
	CHECK(f.stub.calls == 1,
	      "grantor: refused after %d verifications -- it must be the signature that "
	      "refused, not the root pin",
	      f.stub.calls);
	CHECK(f.stub.keys_seen == 1 &&
	              fzn_ct_memeq(f.stub.key_seen[0], f.root, FZN_PUBKEY_LEN),
	      "grantor: the verifier was handed a key other than the rewritten grantor, so "
	      "this case is measuring the key rather than the message");
}

/* The range itself, asserted directly rather than only through its effects.
 *
 * Every case above goes red when the signed range stops covering its field,
 * which is how they were shown to be able to fail. This says the same thing
 * once and in one place, so that a shortened range is a named failure rather
 * than six confusing ones. */
static void test_signed_bytes_are_the_whole_body(void)
{
	struct fixture f;
	const uint8_t *at;
	size_t len;

	fixture_init(&f);
	fzn_hop_signed_bytes(f.hops[0], &at, &len);

	CHECK(at == f.bytes[0],
	      "the signed range does not begin at the hop's first byte, so the version and "
	      "object tags are outside it and separate nothing");
	CHECK(len == FZN_HOP_BODY_LEN,
	      "the signed range is %zu bytes rather than %u, so some field at the end of "
	      "the body is unprotected",
	      len, (unsigned)FZN_HOP_BODY_LEN);
	CHECK(at + len == f.bytes[0] + FZN_HOP_OFF_SIGNATURE,
	      "the signed range does not stop where the signature begins");
}

/* ---- minting, delegation and the container ---------------------------- */

static void test_mint(void)
{
	struct fixture f;
	uint8_t bytes[FZN_HOP_LEN];
	fzn_chain_hop_t hop;
	fzn_chain_t out;
	uint8_t grantee[FZN_PUBKEY_LEN];

	fixture_init(&f);
	key(grantee, 1);
	f.stub.identity = 0;

	CHECK(fzn_chain_mint(f.root, grantee, f.cap, 1000, FZN_NO_EXPIRY, 1, &f.sign, bytes) ==
	              FZN_CHAIN_OK,
	      "minting hop 0 failed");
	CHECK(f.stub.signs == 1, "signed %d times, wanted 1", f.stub.signs);
	CHECK(fzn_hop_open(bytes, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK,
	      "a minted hop does not open, so minting and parsing disagree");
	CHECK(fzn_ct_memeq(fzn_hop_grantor(hop), f.root, FZN_PUBKEY_LEN),
	      "grantor is not the root");
	CHECK(fzn_hop_delegable(hop) == 1, "the delegable flag was not carried");

	/* The minted hop must be something the verifier accepts, or minting
	 * and verifying disagree about what a chain is -- which is the bug
	 * this pairing exists to catch, and which is now a claim about bytes
	 * rather than about two structs agreeing. */
	CHECK(fzn_chain_verify(&hop, 1, f.root, f.cap, 2000, &f.sign, NULL, 0, &out) == FZN_CHAIN_OK,
	      "a freshly minted hop does not verify");
	CHECK(out.hop_count == 1, "hop_count %zu, wanted 1", out.hop_count);

	/* A grant that expires before it was issued is refused where it is
	 * made, not at the far end of a network. */
	fixture_init(&f);
	f.stub.identity = 0;
	CHECK(fzn_chain_mint(f.root, grantee, f.cap, 5000, 4000, 0, &f.sign, bytes) ==
	              FZN_CHAIN_ERR_CHAIN_INVALID,
	      "minted a grant that expired before it was issued");
	CHECK(f.stub.signs == 0, "signed a grant it had already decided to refuse");

	/* No signer, no hop. */
	fixture_init(&f);
	f.sign.sign = NULL;
	CHECK(fzn_chain_mint(f.root, grantee, f.cap, 1000, FZN_NO_EXPIRY, 0, &f.sign, bytes) ==
	              FZN_CHAIN_ERR_MALFORMED,
	      "minted without a signer");

	/* A signer that refuses is a refusal, and it must not leave a
	 * half-made hop behind: the encode happens before the signing, so a
	 * caller ignoring the return code would otherwise hold something that
	 * opens cleanly and carries a zero signature. */
	fixture_init(&f);
	f.stub.can_sign = 0;
	memset(bytes, 0xab, sizeof(bytes));
	CHECK(fzn_chain_mint(f.root, grantee, f.cap, 1000, FZN_NO_EXPIRY, 0, &f.sign, bytes) ==
	              FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a refusing signer still produced a hop");
	CHECK(fzn_hop_open(bytes, FZN_HOP_LEN, &hop) == FZN_CHAIN_ERR_SHAPE,
	      "a refused mint left something that opens as a hop");
}

static void test_delegate(void)
{
	struct fixture f;
	uint8_t bytes[FZN_HOP_LEN];
	fzn_chain_hop_t hop;
	uint8_t grantee[FZN_PUBKEY_LEN];

	key(grantee, 3);

	/* The last hop has to permit it. The fixture leaves it closed, which
	 * is the default doing its job -- re-minting hop 1 WITH the bit is the
	 * difference between a chain that may be extended and one that may
	 * not. The signer then has to be the chain's current grantee, key 2,
	 * because a keyed verifier will not accept anybody else's signature. */
	fixture_init(&f);
	CHECK(mint_hop(&f, f.bytes[1], 1, 2, 0xc0, 1000, FZN_NO_EXPIRY, 1) == FZN_CHAIN_OK,
	      "mint");
	fixture_open(&f, 1);
	stub_reset(&f.stub);
	f.stub.identity = 2;
	CHECK(fzn_chain_delegate(f.hops, 2, f.root, f.cap, 2000, grantee, FZN_NO_EXPIRY, 0,
	                         &f.sign, NULL, 0, bytes) == FZN_CHAIN_OK,
	      "delegating from a good chain failed");
	CHECK(fzn_hop_open(bytes, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK, "the new hop does not open");
	CHECK(fzn_ct_memeq(fzn_hop_grantor(hop), fzn_hop_grantee(f.hops[1]), FZN_PUBKEY_LEN),
	      "the new hop's grantor is not the chain's current grantee");
	CHECK(fzn_hop_delegable(hop) == 0,
	      "delegation permission was granted when it was not asked for");

	/* And the extended chain verifies end to end, which is the whole
	 * point: a delegation nobody can verify is not a delegation. */
	{
		fzn_chain_hop_t three[3];
		fzn_chain_t out;

		three[0] = f.hops[0];
		three[1] = f.hops[1];
		three[2] = hop;
		stub_reset(&f.stub);
		CHECK(fzn_chain_verify(three, 3, f.root, f.cap, 2000, &f.sign, NULL, 0, &out) ==
		              FZN_CHAIN_OK,
		      "the chain a delegation produced does not verify");
		CHECK(fzn_ct_memeq(out.grantee, grantee, FZN_PUBKEY_LEN),
		      "the extended chain does not authorise the new grantee");
	}

	/* The last hop is not delegable: valid chain, holder does hold it,
	 * and it still may not pass it on. Its own error. */
	fixture_init(&f);
	f.stub.identity = 2;
	CHECK(fzn_chain_delegate(f.hops, 2, f.root, f.cap, 2000, grantee, FZN_NO_EXPIRY, 0,
	                         &f.sign, NULL, 0, bytes) == FZN_CHAIN_ERR_NOT_DELEGABLE,
	      "delegated from a chain that does not permit it");
	CHECK(f.stub.signs == 0, "signed a hop it was not entitled to make");

	/* Expiry is capped at what the grantor has left, and asking for none
	 * does not widen it -- the easy mistake, since FZN_NO_EXPIRY is zero
	 * and reads as "unset". */
	fixture_init(&f);
	CHECK(mint_hop(&f, f.bytes[1], 1, 2, 0xc0, 1000, 5000, 1) == FZN_CHAIN_OK, "mint");
	fixture_open(&f, 1);
	stub_reset(&f.stub);
	f.stub.identity = 2;
	CHECK(fzn_chain_delegate(f.hops, 2, f.root, f.cap, 2000, grantee, 9000, 0, &f.sign,
	                         NULL, 0, bytes) == FZN_CHAIN_OK,
	      "delegating within a time-boxed chain failed");
	CHECK(fzn_hop_open(bytes, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK, "open");
	CHECK(fzn_hop_expires_at(hop) == 5000, "expiry %llu, wanted the grantor's 5000",
	      (unsigned long long)fzn_hop_expires_at(hop));

	f.stub.identity = 2;
	CHECK(fzn_chain_delegate(f.hops, 2, f.root, f.cap, 2000, grantee, FZN_NO_EXPIRY, 0,
	                         &f.sign, NULL, 0, bytes) == FZN_CHAIN_OK,
	      "delegating without asking for an expiry failed");
	CHECK(fzn_hop_open(bytes, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK, "open");
	CHECK(fzn_hop_expires_at(hop) == 5000, "asking for no expiry escaped the grantor's cap");

	/* And a SHORTER expiry than the chain's is kept, not widened to it.
	 * The cap is a ceiling rather than an assignment: a host issuing a
	 * deliberately time-boxed sub-grant must get the box it asked for.
	 * Added because branch coverage showed this direction of the cap had
	 * never been taken -- every test asked for more time than it had, and
	 * none asked for less. */
	f.stub.identity = 2;
	CHECK(fzn_chain_delegate(f.hops, 2, f.root, f.cap, 2000, grantee, 3000, 0, &f.sign,
	                         NULL, 0, bytes) == FZN_CHAIN_OK,
	      "delegating a shorter grant failed");
	CHECK(fzn_hop_open(bytes, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK, "open");
	CHECK(fzn_hop_expires_at(hop) == 3000, "expiry %llu, wanted the requested 3000 -- the "
	                                       "cap widened a deliberately shorter grant",
	      (unsigned long long)fzn_hop_expires_at(hop));

	/* Defence in depth: the chain is re-verified, so a revoked or broken
	 * one cannot be the base of something that looks freshly minted. */
	fixture_init(&f);
	CHECK(mint_hop(&f, f.bytes[1], 1, 2, 0xc0, 1000, FZN_NO_EXPIRY, 1) == FZN_CHAIN_OK,
	      "mint");
	fixture_open(&f, 1);
	stub_reset(&f.stub);
	f.stub.identity = 2;
	{
		fzn_revocation_t rev;

		memset(&rev, 0, sizeof(rev));
		memset(rev.capability, 0xc0, FZN_CAP_ID_LEN);
		key(rev.grantee, 1);
		memcpy(rev.issuer, f.root, FZN_PUBKEY_LEN);
		CHECK(fzn_chain_delegate(f.hops, 2, f.root, f.cap, 2000, grantee, FZN_NO_EXPIRY,
		                         0, &f.sign, &rev, 1, bytes) == FZN_CHAIN_ERR_REVOKED,
		      "delegated from a revoked chain");
		CHECK(f.stub.signs == 0, "signed a hop resting on a revoked chain");
	}

	/* Depth is bounded, so delegation cannot build something no verifier
	 * would accept. */
	{
		static uint8_t full_bytes[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
		fzn_chain_hop_t full[FZN_CHAIN_MAX_HOPS];

		fixture_init(&f);
		for (size_t i = 0; i < FZN_CHAIN_MAX_HOPS; i++) {
			CHECK(mint_hop(&f, full_bytes[i], (uint8_t)i, (uint8_t)(i + 1), 0xc0,
			               1000, FZN_NO_EXPIRY, 1) == FZN_CHAIN_OK,
			      "minting filler hop %zu", i);
			CHECK(fzn_hop_open(full_bytes[i], FZN_HOP_LEN, &full[i]) == FZN_CHAIN_OK,
			      "opening filler hop %zu", i);
		}
		stub_reset(&f.stub);
		CHECK(fzn_chain_delegate(full, FZN_CHAIN_MAX_HOPS, f.root, f.cap, 2000, grantee,
		                         FZN_NO_EXPIRY, 0, &f.sign, NULL, 0,
		                         bytes) == FZN_CHAIN_ERR_MALFORMED,
		      "extended a chain already at the depth ceiling");
	}
}

/* The container: a chain has to reach another host somehow, and three
 * consumers inventing three framings is how one protocol becomes several. */
static void test_container_round_trip(void)
{
	struct fixture f;
	uint8_t buf[FZN_CHAIN_MAX_LEN];
	fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];
	fzn_chain_t out;
	size_t len = 0, n = 0;

	fixture_init(&f);
	CHECK(fzn_chain_pack(f.hops, 2, buf, sizeof(buf), &len) == FZN_CHAIN_OK,
	      "packing a two-hop chain failed");
	CHECK(len == FZN_CHAIN_HEADER_LEN + 2u * FZN_HOP_LEN, "packed %zu bytes, wanted %u",
	      len, (unsigned)(FZN_CHAIN_HEADER_LEN + 2u * FZN_HOP_LEN));
	CHECK(buf[0] == 1u, "container version byte is %u, wanted 1", buf[0]);
	CHECK(buf[1] == 2u, "container hop count is %u, wanted 2", buf[1]);

	CHECK(fzn_chain_open(buf, len, opened, &n) == FZN_CHAIN_OK, "opening the container failed");
	CHECK(n == 2, "opened %zu hops, wanted 2", n);
	CHECK(n == 2 && memcmp(opened[0].base, f.bytes[0], FZN_HOP_LEN) == 0,
	      "hop 0 did not survive the container");
	CHECK(n == 2 && memcmp(opened[1].base, f.bytes[1], FZN_HOP_LEN) == 0,
	      "hop 1 did not survive the container");

	/* And what came out of the container verifies, which is the property
	 * worth having -- a framing that loses a byte is a framing that turns
	 * every chain into a bad signature. */
	stub_reset(&f.stub);
	CHECK(fzn_chain_verify(opened, n, f.root, f.cap, 2000, &f.sign, NULL, 0, &out) ==
	              FZN_CHAIN_OK,
	      "a chain that went through the container does not verify");
}

static void test_container_open_refuses(void)
{
	struct fixture f;
	uint8_t buf[FZN_CHAIN_MAX_LEN + 1];
	fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];
	size_t len = 0, n = 0;

	fixture_init(&f);
	CHECK(fzn_chain_pack(f.hops, 2, buf, sizeof(buf), &len) == FZN_CHAIN_OK, "pack");
	CHECK(fzn_chain_open(buf, len, opened, &n) == FZN_CHAIN_OK,
	      "the control does not open, so every refusal below proves nothing");

	CHECK(fzn_chain_open(buf, 1, opened, &n) == FZN_CHAIN_ERR_SHAPE,
	      "a container shorter than its own header was accepted");
	CHECK(fzn_chain_open(buf, len - 1u, opened, &n) == FZN_CHAIN_ERR_SHAPE,
	      "a container one byte short was accepted");
	buf[len] = 0;
	CHECK(fzn_chain_open(buf, len + 1u, opened, &n) == FZN_CHAIN_ERR_SHAPE,
	      "a container with a trailing byte was accepted, and ignoring what you do not "
	      "understand is how one encoding becomes several");

	buf[0] = 2u;
	CHECK(fzn_chain_open(buf, len, opened, &n) == FZN_CHAIN_ERR_SHAPE,
	      "a container claiming version 2 was accepted");
	buf[0] = 1u;

	/* THE COUNT CASES HAVE TO CARRY A MATCHING LENGTH, and the first
	 * version of them did not. Rewriting the count byte on a two-hop
	 * container leaves a length that no longer matches, so the length
	 * check refuses it and the count check could have been deleted with
	 * nothing noticing. Measured: removing `n > FZN_CHAIN_MAX_HOPS`
	 * altogether left this file green. A check whose passing condition
	 * includes the failure is worse than no check, because it is quoted
	 * as evidence afterwards. */
	buf[0] = 1u;
	buf[1] = 0u;
	CHECK(fzn_chain_open(buf, FZN_CHAIN_HEADER_LEN, opened, &n) == FZN_CHAIN_ERR_SHAPE,
	      "a container claiming zero hops, with a length that matches that claim, was "
	      "accepted");
	buf[1] = 2u;

	/* A hop inside it that will not open takes the container with it. */
	buf[FZN_CHAIN_HEADER_LEN + FZN_HOP_OFF_DELEGABLE] = 2u;
	CHECK(fzn_chain_open(buf, len, opened, &n) == FZN_CHAIN_ERR_SHAPE,
	      "a container carrying a non-canonical hop was accepted");
	buf[FZN_CHAIN_HEADER_LEN + FZN_HOP_OFF_DELEGABLE] = 1u;
	CHECK(fzn_chain_open(buf, len, opened, &n) == FZN_CHAIN_OK, "putting it back failed");

	CHECK(fzn_chain_open(NULL, len, opened, &n) == FZN_CHAIN_ERR_MALFORMED, "null bytes");
	CHECK(fzn_chain_open(buf, len, NULL, &n) == FZN_CHAIN_ERR_MALFORMED, "null out");
	CHECK(fzn_chain_open(buf, len, opened, NULL) == FZN_CHAIN_ERR_MALFORMED, "null count");

	/* One hop past the ceiling, with a length that agrees -- so the only
	 * thing left that can refuse it is the ceiling itself. `too_many` is
	 * one entry longer than the API's array on purpose: under the mutation
	 * that deletes the ceiling, this must fail as an assertion rather than
	 * by writing past the end of the caller's array, and a case that can
	 * only fail by corrupting memory is not a case that fails for the
	 * reason it names. */
	{
		static uint8_t over[FZN_CHAIN_HEADER_LEN + (FZN_CHAIN_MAX_HOPS + 1u) * FZN_HOP_LEN];
		fzn_chain_hop_t too_many[FZN_CHAIN_MAX_HOPS + 1u];

		over[0] = 1u;
		over[1] = FZN_CHAIN_MAX_HOPS + 1u;
		for (size_t i = 0; i < FZN_CHAIN_MAX_HOPS + 1u; i++)
			memcpy(over + FZN_CHAIN_HEADER_LEN + i * FZN_HOP_LEN, f.bytes[0],
			       FZN_HOP_LEN);
		CHECK(fzn_chain_open(over, sizeof(over), too_many, &n) == FZN_CHAIN_ERR_SHAPE,
		      "a container of %u hops, whose length agrees with its own count, was "
		      "accepted past the FZN_CHAIN_MAX_HOPS ceiling",
		      (unsigned)FZN_CHAIN_MAX_HOPS + 1u);
	}

	CHECK(fzn_chain_pack(f.hops, 2, buf, FZN_HOP_LEN, &len) == FZN_CHAIN_ERR_MALFORMED,
	      "packed into a buffer that could not hold it");
	CHECK(fzn_chain_pack(f.hops, 0, buf, sizeof(buf), &len) == FZN_CHAIN_ERR_MALFORMED,
	      "packed a chain of no hops");
	CHECK(fzn_chain_pack(f.hops, FZN_CHAIN_MAX_HOPS + 1u, buf, sizeof(buf), &len) ==
	              FZN_CHAIN_ERR_MALFORMED,
	      "packed a chain past the ceiling");
	CHECK(fzn_chain_pack(NULL, 2, buf, sizeof(buf), &len) == FZN_CHAIN_ERR_MALFORMED,
	      "packed a null hop array");
	CHECK(fzn_chain_pack(f.hops, 2, NULL, sizeof(buf), &len) == FZN_CHAIN_ERR_MALFORMED,
	      "packed into a null buffer");
	CHECK(fzn_chain_pack(f.hops, 2, buf, sizeof(buf), NULL) == FZN_CHAIN_ERR_MALFORMED,
	      "packed with nowhere to report the length");
	{
		fzn_chain_hop_t unopened[2];

		unopened[0] = f.hops[0];
		unopened[1].base = NULL;
		CHECK(fzn_chain_pack(unopened, 2, buf, sizeof(buf), &len) ==
		              FZN_CHAIN_ERR_MALFORMED,
		      "packed a view that was never opened");
	}
}

/* Every pointer of every public entry point, refused one at a time.
 *
 * WHY THIS IS WORTH THIRTY DULL ASSERTIONS. Each guard is an `||` chain, and
 * branch coverage said most of the sub-conditions had never been taken -- the
 * first null in each chain was tested and the rest rode along. A chain that
 * looks complete and is missing one term reads exactly like one that is not,
 * and the missing term is a null dereference in a library whose callers are
 * other projects.
 *
 * The other reason is what these gaps were costing. Nearly every unexercised
 * branch in this tree was one of these, so `make coverage` printed a wall of
 * known-defensive gaps -- and two real defects sat in the middle of it for
 * weeks without anyone reading far enough to notice. Closing them is not
 * about the percentage; it is so that the next branch which has never gone
 * both ways is worth looking at. */
static void test_every_guard_refuses_its_own_argument(void)
{
	struct fixture f;
	uint8_t bytes[FZN_HOP_LEN];
	fzn_sign_ops_t no_verify, no_sign;
	uint8_t grantee[FZN_PUBKEY_LEN];

	fixture_init(&f);
	key(grantee, 9);
	no_verify = f.sign;
	no_verify.verify = NULL;
	no_sign = f.sign;
	no_sign.sign = NULL;

#define REFUSED(call, what) \
	CHECK((call) == FZN_CHAIN_ERR_MALFORMED, "%s was accepted", what)

	/* fzn_chain_verify */
	REFUSED(fzn_chain_verify(NULL, 1, f.root, f.cap, 100, &f.sign, NULL, 0, &f.out),
	        "a null hop array");
	REFUSED(fzn_chain_verify(f.hops, 1, NULL, f.cap, 100, &f.sign, NULL, 0, &f.out),
	        "a null root");
	REFUSED(fzn_chain_verify(f.hops, 1, f.root, NULL, 100, &f.sign, NULL, 0, &f.out),
	        "a null capability");
	REFUSED(fzn_chain_verify(f.hops, 1, f.root, f.cap, 100, NULL, NULL, 0, &f.out),
	        "a null signer");
	REFUSED(fzn_chain_verify(f.hops, 1, f.root, f.cap, 100, &no_verify, NULL, 0, &f.out),
	        "a signer with no verify function");
	REFUSED(fzn_chain_verify(f.hops, 1, f.root, f.cap, 100, &f.sign, NULL, 0, NULL),
	        "a null out");

	/* A view that was never opened, which is the guard that replaced the
	 * old "a hop with no signed region". */
	{
		fzn_chain_hop_t unopened;

		unopened.base = NULL;
		REFUSED(fzn_chain_verify(&unopened, 1, f.root, f.cap, 100, &f.sign, NULL, 0,
		                         &f.out),
		        "a hop that was never opened");
	}

	/* fzn_hop_encode */
	{
		uint8_t k[FZN_PUBKEY_LEN];

		key(k, 1);
		REFUSED(fzn_hop_encode(NULL, k, k, k, 1, 2, 0), "encoding into a null buffer");
		REFUSED(fzn_hop_encode(bytes, NULL, k, k, 1, 2, 0), "encoding a null grantor");
		REFUSED(fzn_hop_encode(bytes, k, NULL, k, 1, 2, 0), "encoding a null grantee");
		REFUSED(fzn_hop_encode(bytes, k, k, NULL, 1, 2, 0), "encoding a null capability");
	}

	/* fzn_chain_mint, which reaches the signing guard chain. */
	fixture_init(&f);
	REFUSED(fzn_chain_mint(NULL, grantee, f.cap, 1, 100, 0, &f.sign, bytes),
	        "minting with a null root");
	REFUSED(fzn_chain_mint(f.root, NULL, f.cap, 1, 100, 0, &f.sign, bytes),
	        "minting with a null grantee");
	REFUSED(fzn_chain_mint(f.root, grantee, NULL, 1, 100, 0, &f.sign, bytes),
	        "minting with a null capability");
	REFUSED(fzn_chain_mint(f.root, grantee, f.cap, 1, 100, 0, NULL, bytes),
	        "minting with a null signer");
	REFUSED(fzn_chain_mint(f.root, grantee, f.cap, 1, 100, 0, &no_sign, bytes),
	        "minting with a signer that cannot sign");
	REFUSED(fzn_chain_mint(f.root, grantee, f.cap, 1, 100, 0, &f.sign, NULL),
	        "minting into a null buffer");

	/* fzn_chain_delegate */
	REFUSED(fzn_chain_delegate(NULL, 1, f.root, f.cap, 100, grantee, 200, 0, &f.sign, NULL,
	                           0, bytes),
	        "delegating from a null chain");
	REFUSED(fzn_chain_delegate(f.hops, 1, f.root, f.cap, 100, NULL, 200, 0, &f.sign, NULL,
	                           0, bytes),
	        "delegating to a null grantee");
	REFUSED(fzn_chain_delegate(f.hops, 1, f.root, f.cap, 100, grantee, 200, 0, NULL, NULL,
	                           0, bytes),
	        "delegating with a null signer");
	REFUSED(fzn_chain_delegate(f.hops, 1, f.root, f.cap, 100, grantee, 200, 0, &no_verify,
	                           NULL, 0, bytes),
	        "delegating with a signer that cannot verify");
	REFUSED(fzn_chain_delegate(f.hops, 1, f.root, f.cap, 100, grantee, 200, 0, &f.sign,
	                           NULL, 0, NULL),
	        "delegating into a null buffer");

#undef REFUSED
}

/* The negative control. Every case above asserts that something bad is
 * refused, and a fzn_chain_verify that returned an error unconditionally
 * would pass nearly all of them. test_accepts_a_good_chain is the guard
 * against that, and this says so out loud rather than leaving it implied --
 * a suite with no positive case is one that cannot tell working code from
 * a stub. */
static void test_the_suite_can_tell_pass_from_fail(void)
{
	struct fixture f;
	fixture_init(&f);
	CHECK(run(&f, 2000, NULL, 0) == FZN_CHAIN_OK,
	      "the positive control fails, so every refusal above proves nothing");
}

int main(void)
{
	test_layout_is_the_one_the_header_describes();
	test_encode_open_round_trip();
	test_open_refuses_what_is_not_our_shape();
	test_accepts_a_good_chain();
	test_root_is_pinned_not_adopted();
	test_broken_linkage();
	test_capability_must_match_every_hop();
	test_expiry_is_enforced_when_set();
	test_expiry_is_the_weakest_link();
	test_expiry_before_issue_is_malformed_not_expired();
	test_revocation_kills_a_middle_hop();
	test_revocation_is_per_capability();
	test_revocation_is_per_grantee();
	test_revocation_is_per_issuer();
	test_a_bad_signature_is_refused();
	test_delegation_needs_permission_not_just_possession();
	test_forged_delegable_is_refused();
	test_forged_grantee_is_refused();
	test_forged_capability_is_refused();
	test_forged_issued_at_is_refused();
	test_forged_expires_at_is_refused();
	test_forged_grantor_is_refused();
	test_signed_bytes_are_the_whole_body();
	test_mint();
	test_delegate();
	test_container_round_trip();
	test_container_open_refuses();
	test_bounds();
	test_out_is_untouched_on_failure();
	test_ct_memeq();
	test_every_guard_refuses_its_own_argument();
	test_the_suite_can_tell_pass_from_fail();

	printf("chain_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
