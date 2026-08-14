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

/* A two-hop chain: root(0) -> host(1) -> agent(2), capability 0xc0. */
static void chain_init(fzn_chain_hop_t hops[2])
{
	hop_init(&hops[0], 0, 1, 0xc0);
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
	f->sign.verify = stub_verify;
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

static void test_capability_must_match_every_hop(void)
{
	struct fixture f;
	fixture_init(&f);
	memset(f.hops[1].capability, 0xc1, FZN_CAP_ID_LEN);

	CHECK(run(&f, 2000, NULL, 0) == FZN_ERR_CHAIN_INVALID,
	      "a chain that changes capability half way was accepted");
}

static void test_expiry_is_enforced_when_set(void)
{
	struct fixture f;
	fixture_init(&f);
	f.hops[1].expires_at = 1500;

	CHECK(run(&f, 2000, NULL, 0) == FZN_ERR_EXPIRED, "an expired hop was accepted");
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
	test_bounds();
	test_out_is_untouched_on_failure();
	test_ct_memeq();
	test_the_suite_can_tell_pass_from_fail();

	printf("chain_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
