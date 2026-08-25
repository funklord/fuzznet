/* Tests for chain/chain.c.
 *
 * No framework, because there is nothing to justify one yet and a vendored
 * test dependency is a dependency. The whole file is deterministic: the
 * clock is a parameter and signatures are a stub, so there is nothing here
 * that can pass on a quiet machine and fail on a loaded one.
 *
 * The stub verifier is what makes this possible, and it counts its calls as
 * well as answering. Counting is not decoration -- chain.h claims the cheap
 * structural checks run BEFORE any signature verification, and a claim
 * about ordering that nothing measures is a comment. `expect_calls` is how
 * that claim is held to.
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

typedef struct stub {
	int calls;
	int answer;      /* what verify returns */
	int fail_on_call; /* 1-based call number to fail, or 0 for none */
	int signs;       /* how many times sign was asked */
	int can_sign;    /* whether it agrees to */
} stub_t;

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	stub_t *s = (stub_t *)ctx;

	(void)pubkey;
	(void)sig;

	/* The module promises never to hand a verifier an empty region; a
	 * stub that quietly accepted one would hide that. */
	if (!msg || msg_len == 0) {
		printf("  FAIL: verifier called with an empty signed region\n");
		failures++;
	}

	s->calls++;
	if (s->fail_on_call && s->calls == s->fail_on_call)
		return 0;
	return s->answer;
}

/* The signer takes no key, which is the property worth having: this module
 * has no secret-key parameter anywhere, so a test signer is a counter. */
static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	stub_t *s = (stub_t *)ctx;

	if (!msg || msg_len == 0) {
		printf("  FAIL: signer called with an empty region\n");
		failures++;
	}

	s->signs++;
	if (!s->can_sign)
		return 0;
	memset(sig, 0x5a, FZN_SIG_LEN);
	return 1;
}

/* ---- fixtures --------------------------------------------------------- */

static const uint8_t REGION[] = "signed bytes -- opaque to this module";

/* Distinct 32-byte values, built from a single byte so a failure message
 * can name them. Key 0 is the root by convention in these tests. */
static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	memset(out, seed, FZN_PUBKEY_LEN);
}

static void hop_init(fzn_chain_hop_t *hop, uint8_t grantor, uint8_t grantee, uint8_t cap)
{
	memset(hop, 0, sizeof(*hop));
	key(hop->grantor, grantor);
	key(hop->grantee, grantee);
	memset(hop->capability, cap, FZN_CAP_ID_LEN);
	hop->issued_at = 1000;
	hop->expires_at = FZN_NO_EXPIRY;
	hop->signed_region = REGION;
	hop->signed_region_len = sizeof(REGION) - 1;
}

/* A two-hop chain: root(0) -> host(1) -> agent(2), capability 0xc0.
 *
 * Hop 0 must say `delegable` for hop 1 to exist at all, which is the new
 * rule asserting itself in the fixture: a chain assembled without thinking
 * about delegation does not verify. */
static void chain_init(fzn_chain_hop_t hops[2])
{
	hop_init(&hops[0], 0, 1, 0xc0);
	hops[0].delegable = 1;
	hop_init(&hops[1], 1, 2, 0xc0);
}

struct fixture {
	fzn_chain_hop_t hops[2];
	uint8_t root[FZN_PUBKEY_LEN];
	uint8_t cap[FZN_CAP_ID_LEN];
	stub_t stub;
	fzn_sign_ops_t sign;
	fzn_chain_t out;
};

static void fixture_init(struct fixture *f)
{
	memset(f, 0, sizeof(*f));
	chain_init(f->hops);
	key(f->root, 0);
	memset(f->cap, 0xc0, FZN_CAP_ID_LEN);
	f->stub.answer = 1;
	f->stub.can_sign = 1;
	f->sign.verify = stub_verify;
	f->sign.sign = stub_sign;
	f->sign.ctx = &f->stub;
}

static fzn_err_t run(struct fixture *f, uint64_t now, const fzn_revocation_t *revs, size_t nrevs)
{
	return fzn_chain_verify(f->hops, 2, f->root, f->cap, now, &f->sign, revs, nrevs, &f->out);
}

/* ---- the cases -------------------------------------------------------- */

static void test_accepts_a_good_chain(void)
{
	struct fixture f;
	fixture_init(&f);

	CHECK(run(&f, 2000, NULL, 0) == FZN_OK, "a good two-hop chain was refused");
	CHECK(f.out.hop_count == 2, "hop_count %zu, wanted 2", f.out.hop_count);
	CHECK(f.out.expires_at == FZN_NO_EXPIRY, "an unexpiring chain reported an expiry");
	CHECK(fzn_ct_memeq(f.out.grantee, f.hops[1].grantee, FZN_PUBKEY_LEN),
	      "grantee is not the last hop's");
	CHECK(fzn_ct_memeq(f.out.root, f.root, FZN_PUBKEY_LEN), "root not reported back");
	CHECK(f.stub.calls == 2, "verified %d signatures, wanted 2", f.stub.calls);
}

static void test_root_is_pinned_not_adopted(void)
{
	struct fixture f;
	fixture_init(&f);
	key(f.root, 9); /* a perfectly valid chain, rooted at someone else */

	CHECK(run(&f, 2000, NULL, 0) == FZN_ERR_WRONG_ROOT, "a foreign root was adopted");
	CHECK(f.stub.calls == 0, "spent %d verifications on a foreign root", f.stub.calls);
}

static void test_broken_linkage(void)
{
	struct fixture f;
	fixture_init(&f);
	key(f.hops[1].grantor, 7); /* not hop 0's grantee */

	CHECK(run(&f, 2000, NULL, 0) == FZN_ERR_CHAIN_INVALID, "a broken link was accepted");
	CHECK(f.stub.calls == 0, "verified signatures on a chain that does not link");
}

/* THE CALL COUNTS BELOW ARE THE ORDERING CLAIM, NOT DECORATION. chain.h
 * lists six checks and says the order puts the cheap structural refusals
 * before any signature verification -- a denial-of-service property, since a
 * stranger's malformed chain must not cost a receiver the expensive part.
 *
 * Four of the six measured it: a foreign root, a broken link, an over-long
 * chain and an unauthorised delegation each assert zero calls. The spliced
 * capability, the expired hop and the revoked hop asserted only their error
 * code, so half the claim was the comment this file's own header warns
 * about. Added 2026-08-19; all three were already true. */
static void test_capability_must_match_every_hop(void)
{
	struct fixture f;
	fixture_init(&f);
	memset(f.hops[1].capability, 0xc1, FZN_CAP_ID_LEN);

	CHECK(run(&f, 2000, NULL, 0) == FZN_ERR_CHAIN_INVALID,
	      "a chain that changes capability half way was accepted");
	CHECK(f.stub.calls == 0, "spent verifications on a spliced capability");
}

static void test_expiry_is_enforced_when_set(void)
{
	struct fixture f;
	fixture_init(&f);
	f.hops[1].expires_at = 1500;

	CHECK(run(&f, 2000, NULL, 0) == FZN_ERR_EXPIRED, "an expired hop was accepted");
	CHECK(f.stub.calls == 0, "spent verifications on an expired hop");
	CHECK(run(&f, 1400, NULL, 0) == FZN_OK, "a live hop was refused");
	CHECK(f.out.expires_at == 1500, "expiry %llu, wanted 1500",
	      (unsigned long long)f.out.expires_at);
}

static void test_expiry_is_the_weakest_link(void)
{
	struct fixture f;
	fixture_init(&f);
	f.hops[0].expires_at = 9000;
	f.hops[1].expires_at = 5000;

	CHECK(run(&f, 2000, NULL, 0) == FZN_OK, "a live chain was refused");
	CHECK(f.out.expires_at == 5000, "expiry %llu, wanted the soonest (5000)",
	      (unsigned long long)f.out.expires_at);

	/* And an unlimited hop must not win the minimum by being smaller. */
	fixture_init(&f);
	f.hops[0].expires_at = FZN_NO_EXPIRY;
	f.hops[1].expires_at = 5000;
	CHECK(run(&f, 2000, NULL, 0) == FZN_OK, "a live chain was refused");
	CHECK(f.out.expires_at == 5000, "an unlimited hop won the minimum");
}

static void test_expiry_before_issue_is_malformed_not_expired(void)
{
	struct fixture f;
	fixture_init(&f);
	f.hops[0].issued_at = 5000;
	f.hops[0].expires_at = 4000;

	CHECK(run(&f, 1000, NULL, 0) == FZN_ERR_CHAIN_INVALID,
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

	CHECK(run(&f, 2000, &rev, 1) == FZN_ERR_REVOKED,
	      "revoking the middle of a chain did not kill what it granted");
	CHECK(f.stub.calls == 0, "spent verifications on a revoked chain");

	/* And revoking the end works too, which is the ordinary case. */
	fixture_init(&f);
	key(rev.grantee, 2);
	CHECK(run(&f, 2000, &rev, 1) == FZN_ERR_REVOKED, "revoking the grantee had no effect");
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

	CHECK(run(&f, 2000, &rev, 1) == FZN_OK,
	      "revoking one capability withdrew an unrelated one");
}

static void test_a_bad_signature_is_refused(void)
{
	struct fixture f;

	fixture_init(&f);
	f.stub.fail_on_call = 2; /* the second hop's */
	CHECK(run(&f, 2000, NULL, 0) == FZN_ERR_CHAIN_INVALID, "a bad signature was accepted");

	fixture_init(&f);
	f.stub.fail_on_call = 1;
	CHECK(run(&f, 2000, NULL, 0) == FZN_ERR_CHAIN_INVALID, "a bad root signature was accepted");
	CHECK(f.stub.calls == 1, "kept verifying after hop 0 failed");
}

static void test_bounds(void)
{
	struct fixture f;
	fzn_chain_hop_t many[FZN_CHAIN_MAX_HOPS + 1];

	fixture_init(&f);
	CHECK(fzn_chain_verify(f.hops, 0, f.root, f.cap, 2000, &f.sign, NULL, 0, &f.out) ==
	              FZN_ERR_MALFORMED,
	      "a zero-hop chain was not refused");

	for (size_t i = 0; i < FZN_CHAIN_MAX_HOPS + 1; i++)
		hop_init(&many[i], (uint8_t)i, (uint8_t)(i + 1), 0xc0);
	CHECK(fzn_chain_verify(many, FZN_CHAIN_MAX_HOPS + 1, f.root, f.cap, 2000, &f.sign, NULL,
	                       0, &f.out) == FZN_ERR_MALFORMED,
	      "a chain past FZN_CHAIN_MAX_HOPS was not refused");
	CHECK(f.stub.calls == 0, "spent verifications on an over-long chain");

	fixture_init(&f);
	CHECK(fzn_chain_verify(NULL, 2, f.root, f.cap, 2000, &f.sign, NULL, 0, &f.out) ==
	              FZN_ERR_MALFORMED,
	      "null hops accepted");
	CHECK(fzn_chain_verify(f.hops, 2, f.root, f.cap, 2000, &f.sign, NULL, 3, &f.out) ==
	              FZN_ERR_MALFORMED,
	      "a nonzero revocation count with a null list was accepted");

	fixture_init(&f);
	f.hops[1].signed_region_len = 0;
	CHECK(run(&f, 2000, NULL, 0) == FZN_ERR_MALFORMED, "a hop with no signed region passed");
}

static void test_out_is_untouched_on_failure(void)
{
	struct fixture f;
	fzn_chain_t before;

	fixture_init(&f);
	memset(&f.out, 0xab, sizeof(f.out));
	before = f.out;
	f.stub.fail_on_call = 1;

	CHECK(run(&f, 2000, NULL, 0) == FZN_ERR_CHAIN_INVALID, "expected a refusal");
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
	 * by holding it. Clear the bit on hop 0 and hop 1 becomes a
	 * delegation nobody authorised. */
	fixture_init(&f);
	f.hops[0].delegable = 0;

	CHECK(run(&f, 2000, NULL, 0) == FZN_ERR_CHAIN_INVALID,
	      "a chain continued past a hop that was not delegable");
	CHECK(f.stub.calls == 0, "verified signatures on an unauthorised delegation");

	/* And the default is closed: a zeroed hop is not delegable. */
	fixture_init(&f);
	memset(&f.hops[0].delegable, 0, sizeof(f.hops[0].delegable));
	CHECK(run(&f, 2000, NULL, 0) == FZN_ERR_CHAIN_INVALID,
	      "a hop left at its zero value permitted delegation");
}

static void test_mint(void)
{
	struct fixture f;
	fzn_chain_hop_t hop;
	fzn_chain_t out;
	uint8_t grantee[FZN_PUBKEY_LEN];
	static const uint8_t region[] = "hop 0 as the schema lays it out";

	fixture_init(&f);
	key(grantee, 1);

	CHECK(fzn_chain_mint(f.root, grantee, f.cap, 1000, FZN_NO_EXPIRY, 1, region,
	                     sizeof(region) - 1, &f.sign, &hop) == FZN_OK,
	      "minting hop 0 failed");
	CHECK(f.stub.signs == 1, "signed %d times, wanted 1", f.stub.signs);
	CHECK(fzn_ct_memeq(hop.grantor, f.root, FZN_PUBKEY_LEN), "grantor is not the root");
	CHECK(hop.delegable == 1, "the delegable flag was not carried");

	/* The minted hop must be something the verifier accepts, or minting
	 * and verifying disagree about what a chain is -- which is the bug
	 * this pairing exists to catch. */
	CHECK(fzn_chain_verify(&hop, 1, f.root, f.cap, 2000, &f.sign, NULL, 0, &out) == FZN_OK,
	      "a freshly minted hop does not verify");
	CHECK(out.hop_count == 1, "hop_count %zu, wanted 1", out.hop_count);

	/* A grant that expires before it was issued is refused where it is
	 * made, not at the far end of a network. */
	fixture_init(&f);
	CHECK(fzn_chain_mint(f.root, grantee, f.cap, 5000, 4000, 0, region, sizeof(region) - 1,
	                     &f.sign, &hop) == FZN_ERR_CHAIN_INVALID,
	      "minted a grant that expired before it was issued");
	CHECK(f.stub.signs == 0, "signed a grant it had already decided to refuse");

	/* No signer, no hop. */
	fixture_init(&f);
	f.sign.sign = NULL;
	CHECK(fzn_chain_mint(f.root, grantee, f.cap, 1000, FZN_NO_EXPIRY, 0, region,
	                     sizeof(region) - 1, &f.sign, &hop) == FZN_ERR_MALFORMED,
	      "minted without a signer");

	/* A signer that refuses is a refusal, not a hop with rubbish in it. */
	fixture_init(&f);
	f.stub.can_sign = 0;
	CHECK(fzn_chain_mint(f.root, grantee, f.cap, 1000, FZN_NO_EXPIRY, 0, region,
	                     sizeof(region) - 1, &f.sign, &hop) == FZN_ERR_CHAIN_INVALID,
	      "a refusing signer still produced a hop");
}

static void test_delegate(void)
{
	struct fixture f;
	fzn_chain_hop_t hop;
	uint8_t grantee[FZN_PUBKEY_LEN];
	static const uint8_t region[] = "the new hop as the schema lays it out";

	key(grantee, 3);

	/* The last hop has to permit it. The fixture leaves it closed, which
	 * is the default doing its job -- this line is the difference between
	 * a chain that may be extended and one that may not. */
	fixture_init(&f);
	f.hops[1].delegable = 1;
	CHECK(fzn_chain_delegate(f.hops, 2, f.root, f.cap, 2000, grantee, FZN_NO_EXPIRY, 0,
	                         region, sizeof(region) - 1, &f.sign, NULL, 0,
	                         &hop) == FZN_OK,
	      "delegating from a good chain failed");
	CHECK(fzn_ct_memeq(hop.grantor, f.hops[1].grantee, FZN_PUBKEY_LEN),
	      "the new hop's grantor is not the chain's current grantee");
	CHECK(hop.delegable == 0, "delegation permission was granted when it was not asked for");

	/* The last hop is not delegable: valid chain, holder does hold it,
	 * and it still may not pass it on. Its own error. */
	fixture_init(&f);
	f.hops[1].delegable = 0;
	CHECK(fzn_chain_delegate(f.hops, 2, f.root, f.cap, 2000, grantee, FZN_NO_EXPIRY, 0,
	                         region, sizeof(region) - 1, &f.sign, NULL, 0, &hop) ==
	              FZN_ERR_NOT_DELEGABLE,
	      "delegated from a chain that does not permit it");
	CHECK(f.stub.signs == 0, "signed a hop it was not entitled to make");

	/* Expiry is capped at what the grantor has left, and asking for none
	 * does not widen it -- the easy mistake, since FZN_NO_EXPIRY is zero
	 * and reads as "unset". */
	fixture_init(&f);
	f.hops[1].delegable = 1;
	f.hops[1].expires_at = 5000;
	CHECK(fzn_chain_delegate(f.hops, 2, f.root, f.cap, 2000, grantee, 9000, 0, region,
	                         sizeof(region) - 1, &f.sign, NULL, 0, &hop) == FZN_OK,
	      "delegating within a time-boxed chain failed");
	CHECK(hop.expires_at == 5000, "expiry %llu, wanted the grantor's 5000",
	      (unsigned long long)hop.expires_at);

	fixture_init(&f);
	f.hops[1].delegable = 1;
	f.hops[1].expires_at = 5000;
	CHECK(fzn_chain_delegate(f.hops, 2, f.root, f.cap, 2000, grantee, FZN_NO_EXPIRY, 0,
	                         region, sizeof(region) - 1, &f.sign, NULL, 0, &hop) == FZN_OK,
	      "delegating without asking for an expiry failed");
	CHECK(hop.expires_at == 5000, "asking for no expiry escaped the grantor's cap");

	/* And a SHORTER expiry than the chain's is kept, not widened to it.
	 * The cap is a ceiling rather than an assignment: a host issuing a
	 * deliberately time-boxed sub-grant must get the box it asked for.
	 * Added because branch coverage showed this direction of the cap had
	 * never been taken -- every test asked for more time than it had, and
	 * none asked for less. */
	fixture_init(&f);
	f.hops[1].delegable = 1;
	f.hops[1].expires_at = 5000;
	CHECK(fzn_chain_delegate(f.hops, 2, f.root, f.cap, 2000, grantee, 3000, 0, region,
	                         sizeof(region) - 1, &f.sign, NULL, 0, &hop) == FZN_OK,
	      "delegating a shorter grant failed");
	CHECK(hop.expires_at == 3000, "expiry %llu, wanted the requested 3000 -- the cap "
	                              "widened a deliberately shorter grant",
	      (unsigned long long)hop.expires_at);

	/* Defence in depth: the chain is re-verified, so a revoked or broken
	 * one cannot be the base of something that looks freshly minted. */
	fixture_init(&f);
	f.hops[1].delegable = 1;
	{
		fzn_revocation_t rev;
		memset(&rev, 0, sizeof(rev));
		memset(rev.capability, 0xc0, FZN_CAP_ID_LEN);
		key(rev.grantee, 1);
		CHECK(fzn_chain_delegate(f.hops, 2, f.root, f.cap, 2000, grantee, FZN_NO_EXPIRY,
		                         0, region, sizeof(region) - 1, &f.sign, &rev, 1,
		                         &hop) == FZN_ERR_REVOKED,
		      "delegated from a revoked chain");
		CHECK(f.stub.signs == 0, "signed a hop resting on a revoked chain");
	}

	/* Depth is bounded, so delegation cannot build something no verifier
	 * would accept. */
	{
		fzn_chain_hop_t full[FZN_CHAIN_MAX_HOPS];
		fixture_init(&f);
		for (size_t i = 0; i < FZN_CHAIN_MAX_HOPS; i++) {
			hop_init(&full[i], (uint8_t)i, (uint8_t)(i + 1), 0xc0);
			full[i].delegable = 1;
		}
		CHECK(fzn_chain_delegate(full, FZN_CHAIN_MAX_HOPS, f.root, f.cap, 2000, grantee,
		                         FZN_NO_EXPIRY, 0, region, sizeof(region) - 1, &f.sign,
		                         NULL, 0, &hop) == FZN_ERR_MALFORMED,
		      "extended a chain already at the depth ceiling");
	}
}

/* The negative control. Every case above asserts that something bad is
 * refused, and a fzn_chain_verify that returned an error unconditionally
 * would pass nearly all of them. test_accepts_a_good_chain is the guard
 * against that, and this says so out loud rather than leaving it implied --
 * a suite with no positive case is one that cannot tell working code from
 * a stub. */
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
 * both ways is worth looking at.
 *
 * `signed_region_len == 0` is here too, and is not a null check: it is the
 * one term in these chains that describes a value rather than a pointer, and
 * it had never been taken either. A hop with a region but no length would be
 * signed over nothing. */
static void test_every_guard_refuses_its_own_argument(void)
{
	struct fixture f;
	fzn_chain_hop_t hop;
	fzn_sign_ops_t no_verify, no_sign;
	uint8_t grantee[FZN_PUBKEY_LEN];

	fixture_init(&f);
	key(grantee, 9);
	no_verify = f.sign;
	no_verify.verify = NULL;
	no_sign = f.sign;
	no_sign.sign = NULL;

#define REFUSED(call, what) \
	CHECK((call) == FZN_ERR_MALFORMED, "%s was accepted", what)

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

	/* A hop whose signed region is absent or empty. Not a null-pointer
	 * guard: a region with a zero length is signed over nothing. */
	fixture_init(&f);
	f.hops[0].signed_region = NULL;
	REFUSED(fzn_chain_verify(f.hops, 1, f.root, f.cap, 100, &f.sign, NULL, 0, &f.out),
	        "a hop with no signed region");
	fixture_init(&f);
	f.hops[0].signed_region_len = 0;
	REFUSED(fzn_chain_verify(f.hops, 1, f.root, f.cap, 100, &f.sign, NULL, 0, &f.out),
	        "a hop whose signed region is empty");

	/* fzn_chain_mint, which reaches the signing guard chain. */
	fixture_init(&f);
	REFUSED(fzn_chain_mint(NULL, grantee, f.cap, 1, 100, 0, REGION, sizeof(REGION) - 1,
	                       &f.sign, &hop),
	        "minting with a null root");
	REFUSED(fzn_chain_mint(f.root, NULL, f.cap, 1, 100, 0, REGION, sizeof(REGION) - 1,
	                       &f.sign, &hop),
	        "minting with a null grantee");
	REFUSED(fzn_chain_mint(f.root, grantee, NULL, 1, 100, 0, REGION, sizeof(REGION) - 1,
	                       &f.sign, &hop),
	        "minting with a null capability");
	REFUSED(fzn_chain_mint(f.root, grantee, f.cap, 1, 100, 0, NULL, sizeof(REGION) - 1,
	                       &f.sign, &hop),
	        "minting with a null signed region");
	REFUSED(fzn_chain_mint(f.root, grantee, f.cap, 1, 100, 0, REGION, 0, &f.sign, &hop),
	        "minting over an empty signed region");
	REFUSED(fzn_chain_mint(f.root, grantee, f.cap, 1, 100, 0, REGION, sizeof(REGION) - 1,
	                       NULL, &hop),
	        "minting with a null signer");
	REFUSED(fzn_chain_mint(f.root, grantee, f.cap, 1, 100, 0, REGION, sizeof(REGION) - 1,
	                       &no_sign, &hop),
	        "minting with a signer that cannot sign");
	REFUSED(fzn_chain_mint(f.root, grantee, f.cap, 1, 100, 0, REGION, sizeof(REGION) - 1,
	                       &f.sign, NULL),
	        "minting into a null hop");

	/* fzn_chain_delegate */
	REFUSED(fzn_chain_delegate(NULL, 1, f.root, f.cap, 100, grantee, 200, 0, REGION,
	                           sizeof(REGION) - 1, &f.sign, NULL, 0, &hop),
	        "delegating from a null chain");
	REFUSED(fzn_chain_delegate(f.hops, 1, f.root, f.cap, 100, NULL, 200, 0, REGION,
	                           sizeof(REGION) - 1, &f.sign, NULL, 0, &hop),
	        "delegating to a null grantee");
	REFUSED(fzn_chain_delegate(f.hops, 1, f.root, f.cap, 100, grantee, 200, 0, REGION,
	                           sizeof(REGION) - 1, NULL, NULL, 0, &hop),
	        "delegating with a null signer");
	REFUSED(fzn_chain_delegate(f.hops, 1, f.root, f.cap, 100, grantee, 200, 0, REGION,
	                           sizeof(REGION) - 1, &no_verify, NULL, 0, &hop),
	        "delegating with a signer that cannot verify");
	REFUSED(fzn_chain_delegate(f.hops, 1, f.root, f.cap, 100, grantee, 200, 0, REGION,
	                           sizeof(REGION) - 1, &f.sign, NULL, 0, NULL),
	        "delegating into a null hop");

#undef REFUSED
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	struct fixture f;
	fixture_init(&f);
	CHECK(run(&f, 2000, NULL, 0) == FZN_OK,
	      "the positive control fails, so every refusal above proves nothing");
}

int main(void)
{
	test_accepts_a_good_chain();
	test_root_is_pinned_not_adopted();
	test_broken_linkage();
	test_capability_must_match_every_hop();
	test_expiry_is_enforced_when_set();
	test_expiry_is_the_weakest_link();
	test_expiry_before_issue_is_malformed_not_expired();
	test_revocation_kills_a_middle_hop();
	test_revocation_is_per_capability();
	test_a_bad_signature_is_refused();
	test_delegation_needs_permission_not_just_possession();
	test_mint();
	test_delegate();
	test_bounds();
	test_out_is_untouched_on_failure();
	test_ct_memeq();
	test_every_guard_refuses_its_own_argument();
	test_the_suite_can_tell_pass_from_fail();

	printf("chain_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
