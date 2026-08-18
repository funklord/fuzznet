/* Tests for chain/revocation.c, including that the store's contents are
 * directly usable by fzn_chain_verify -- which is the reason the store keeps
 * verified `fzn_revocation_t` rather than the records it was given. */

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

typedef struct stub {
	int calls;
	int answer;
} stub_t;

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	stub_t *s = (stub_t *)ctx;

	(void)pubkey;
	(void)sig;
	(void)msg;
	(void)msg_len;
	s->calls++;
	return s->answer;
}

static const uint8_t REGION[] = "a revocation as the schema lays it out";

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	memset(out, seed, FZN_PUBKEY_LEN);
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
	f->stub.answer = 1;
	f->sign.verify = stub_verify;
	f->sign.ctx = &f->stub;
}

static void record_of(fzn_revocation_record_t *r, uint8_t issuer, uint8_t cap, uint8_t grantee)
{
	memset(r, 0, sizeof(*r));
	key(r->issuer, issuer);
	memset(r->capability, cap, FZN_CAP_ID_LEN);
	key(r->grantee, grantee);
	r->issued_at = 1000;
	r->signed_region = REGION;
	r->signed_region_len = sizeof(REGION) - 1;
}

static void test_admits_a_signed_revocation(void)
{
	struct fixture f;
	fzn_revocation_record_t r;

	fixture_init(&f);
	record_of(&r, 0, 0xc0, 5);

	CHECK(fzn_revocation_admit(&f.store, &r, f.root, &f.sign) == FZN_OK,
	      "a properly signed revocation was refused");
	CHECK(f.store.used == 1, "used %zu, wanted 1", f.store.used);
	CHECK(fzn_revocation_covers(&f.store, r.capability, r.grantee),
	      "the store does not report what it just admitted");
	CHECK(f.stub.calls == 1, "verified %d times, wanted 1", f.stub.calls);
}

static void test_a_carrier_cannot_invent_one(void)
{
	struct fixture f;
	fzn_revocation_record_t r;

	/* The whole reason a revocation is signed. Carried on contact means
	 * the peer handing it over is not the issuer, so a record from
	 * anybody but the root is refused however well-formed it looks. */
	fixture_init(&f);
	record_of(&r, 7, 0xc0, 5); /* issued by some peer, not the root */

	CHECK(fzn_revocation_admit(&f.store, &r, f.root, &f.sign) == FZN_ERR_WRONG_ROOT,
	      "a revocation issued by a carrier was accepted");
	CHECK(f.store.used == 0, "it was recorded anyway");
	CHECK(f.stub.calls == 0, "a signature was verified for an issuer already refused");

	/* And a forged signature under the right issuer is refused too. */
	fixture_init(&f);
	record_of(&r, 0, 0xc0, 5);
	f.stub.answer = 0;
	CHECK(fzn_revocation_admit(&f.store, &r, f.root, &f.sign) == FZN_ERR_CHAIN_INVALID,
	      "a revocation with a bad signature was accepted");
	CHECK(f.store.used == 0, "it was recorded anyway");
}

static void test_hearing_it_twice_is_not_an_error(void)
{
	struct fixture f;
	fzn_revocation_record_t r;

	/* Two peers both telling you is what carried-on-contact looks like
	 * every time it works. A caller treating the second as a failure
	 * would alarm on the system behaving correctly. */
	fixture_init(&f);
	record_of(&r, 0, 0xc0, 5);

	CHECK(fzn_revocation_admit(&f.store, &r, f.root, &f.sign) == FZN_OK, "first");
	CHECK(fzn_revocation_admit(&f.store, &r, f.root, &f.sign) == FZN_OK,
	      "hearing the same revocation twice was an error");
	CHECK(f.store.used == 1, "the duplicate took a second slot");
}

static void test_a_full_store_refuses_and_does_not_evict(void)
{
	struct fixture f;
	fzn_revocation_record_t r;

	/* Unlike the replay window, this refusal fails OPEN. Nothing is
	 * evicted, because a revocation that lapses un-revokes a device and
	 * every entry is protecting against something. */
	fixture_init(&f);
	for (uint8_t i = 0; i < 4; i++) {
		record_of(&r, 0, 0xc0, (uint8_t)(10 + i));
		CHECK(fzn_revocation_admit(&f.store, &r, f.root, &f.sign) == FZN_OK,
		      "filling entry %u", i);
	}

	record_of(&r, 0, 0xc0, 99);
	CHECK(fzn_revocation_admit(&f.store, &r, f.root, &f.sign) == FZN_ERR_STORE_FULL,
	      "a full store admitted a fifth revocation");

	/* The first entry must still be there -- an evicting store would have
	 * silently un-revoked it. */
	{
		uint8_t cap[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN];
		memset(cap, 0xc0, sizeof(cap));
		key(grantee, 10);
		CHECK(fzn_revocation_covers(&f.store, cap, grantee),
		      "a full store evicted an earlier revocation, un-revoking a device");
	}
}

static void test_merge_keeps_going_past_a_bad_record(void)
{
	struct fixture f;
	fzn_revocation_record_t batch[3];
	fzn_err_t err = FZN_OK;
	size_t n;

	/* One forged record must not stop a host learning the genuine ones
	 * beside it, or appending rubbish to a batch becomes a free way to
	 * suppress revocation. */
	fixture_init(&f);
	record_of(&batch[0], 0, 0xc0, 1);
	record_of(&batch[1], 7, 0xc0, 2); /* forged: wrong issuer */
	record_of(&batch[2], 0, 0xc0, 3);

	n = fzn_revocation_merge(&f.store, batch, 3, f.root, &f.sign, &err);
	CHECK(n == 2, "admitted %zu of a 3-record batch, wanted 2", n);
	CHECK(err == FZN_ERR_WRONG_ROOT, "the first failure was not reported back");
	CHECK(fzn_revocation_covers(&f.store, batch[2].capability, batch[2].grantee),
	      "a record after the bad one was skipped");

	/* A clean batch reports FZN_OK. */
	fixture_init(&f);
	record_of(&batch[1], 0, 0xc0, 2);
	n = fzn_revocation_merge(&f.store, batch, 3, f.root, &f.sign, &err);
	CHECK(n == 3 && err == FZN_OK, "a clean batch reported %zu admitted, err %d",
	      n, (int)err);
}

static void test_the_store_feeds_chain_verify_directly(void)
{
	struct fixture f;
	fzn_revocation_record_t r;
	fzn_chain_hop_t hops[1];
	fzn_chain_t out;
	uint8_t cap[FZN_CAP_ID_LEN];

	/* The reason the store keeps verified fzn_revocation_t rather than
	 * the records: `entries` and `used` go straight into chain verify,
	 * with no conversion step for the two to disagree about. */
	fixture_init(&f);
	memset(cap, 0xc0, sizeof(cap));

	memset(&hops[0], 0, sizeof(hops[0]));
	key(hops[0].grantor, 0);
	key(hops[0].grantee, 5);
	memcpy(hops[0].capability, cap, FZN_CAP_ID_LEN);
	hops[0].issued_at = 1000;
	hops[0].signed_region = REGION;
	hops[0].signed_region_len = sizeof(REGION) - 1;

	CHECK(fzn_chain_verify(hops, 1, f.root, cap, 2000, &f.sign, f.store.entries,
	                       f.store.used, &out) == FZN_OK,
	      "an unrevoked chain was refused with an empty store");

	record_of(&r, 0, 0xc0, 5);
	CHECK(fzn_revocation_admit(&f.store, &r, f.root, &f.sign) == FZN_OK, "admit");
	CHECK(fzn_chain_verify(hops, 1, f.root, cap, 2000, &f.sign, f.store.entries,
	                       f.store.used, &out) == FZN_ERR_REVOKED,
	      "chain verify did not see the revocation the store had admitted");
}

static void test_bad_arguments(void)
{
	struct fixture f;
	fzn_revocation_record_t r;
	fzn_revocation_store_t s;

	fixture_init(&f);
	record_of(&r, 0, 0xc0, 5);

	CHECK(fzn_revocation_store_init(&s, f.entries, 0) == FZN_ERR_MALFORMED,
	      "a zero-capacity store was accepted, and would record nothing");
	CHECK(fzn_revocation_store_init(&s, NULL, 4) == FZN_ERR_MALFORMED, "null entries");
	CHECK(fzn_revocation_admit(&f.store, &r, f.root, NULL) == FZN_ERR_MALFORMED,
	      "a null signer was accepted");
	CHECK(fzn_revocation_covers(NULL, r.capability, r.grantee) == 0,
	      "covers on a null store did not answer no");

	r.signed_region_len = 0;
	CHECK(fzn_revocation_admit(&f.store, &r, f.root, &f.sign) == FZN_ERR_MALFORMED,
	      "a record with no signed region was accepted");
}

static void test_merge_bad_arguments(void)
{
	struct fixture f;
	fzn_revocation_record_t r;
	fzn_err_t err;

	/* Added because coverage said nothing reached them: the guard in
	 * fzn_revocation_merge was the only unexecuted code in the library,
	 * three lines of 41 in this file. `admit` had its bad arguments
	 * tested and `merge` did not, which is the shape a gap takes when
	 * two functions are written together and only one is thought about
	 * twice. */
	fixture_init(&f);
	record_of(&r, 0, 0xc0, 5);

	err = FZN_OK;
	CHECK(fzn_revocation_merge(NULL, &r, 1, f.root, &f.sign, &err) == 0,
	      "merge into a null store did not admit zero");
	CHECK(err == FZN_ERR_MALFORMED, "merge into a null store did not report why");

	err = FZN_OK;
	CHECK(fzn_revocation_merge(&f.store, NULL, 3, f.root, &f.sign, &err) == 0,
	      "merge of a null batch with a nonzero count admitted something");
	CHECK(err == FZN_ERR_MALFORMED, "merge of a null batch did not report why");
	CHECK(f.store.used == 0, "a refused merge recorded something");

	/* A null `err` must be tolerated, since it is the caller's option
	 * and the guard writes through it. */
	CHECK(fzn_revocation_merge(NULL, &r, 1, f.root, &f.sign, NULL) == 0,
	      "merge with a null err pointer did not return zero");

	/* An empty batch is not an error: a peer with nothing to tell us is
	 * the ordinary case, not a malformed one. */
	err = FZN_ERR_MALFORMED;
	CHECK(fzn_revocation_merge(&f.store, NULL, 0, f.root, &f.sign, &err) == 0,
	      "an empty batch admitted something");
	CHECK(err == FZN_OK, "an empty batch was reported as an error");
}

/* Positive control: most cases above assert a refusal, and an admit that
 * refused everything would satisfy them. */
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
	fzn_revocation_record_t batch[6];
	fzn_err_t err = FZN_OK;
	size_t n;

	fixture_init(&f); /* four entries of room */
	record_of(&batch[0], 7, 0xc0, 1); /* forged: wrong issuer */
	for (uint8_t i = 1; i < 6; i++)
		record_of(&batch[i], 0, 0xc0, (uint8_t)(i + 1u)); /* genuine, distinct */

	n = fzn_revocation_merge(&f.store, batch, 6, f.root, &f.sign, &err);
	CHECK(n == 4, "admitted %zu of five genuine records into a store of four", n);
	CHECK(err == FZN_ERR_WRONG_ROOT,
	      "reported %d; the first failure was WRONG_ROOT and the later one was a "
	      "full store, so this is the last error rather than the first",
	      (int)err);

	/* The reverse order, so the test cannot pass by preferring WRONG_ROOT
	 * over STORE_FULL for some reason other than order. */
	fixture_init(&f);
	for (uint8_t i = 0; i < 5; i++)
		record_of(&batch[i], 0, 0xc0, (uint8_t)(i + 1u));
	record_of(&batch[5], 7, 0xc0, 9); /* forged, last */

	n = fzn_revocation_merge(&f.store, batch, 6, f.root, &f.sign, &err);
	CHECK(n == 4, "admitted %zu with the forged record last", n);
	CHECK(err == FZN_ERR_STORE_FULL,
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
	fzn_revocation_record_t batch[2];
	size_t n;

	fixture_init(&f);
	record_of(&batch[0], 0, 0xc0, 1);
	record_of(&batch[1], 7, 0xc0, 2); /* forged, so there IS an error to drop */

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
	fzn_revocation_record_t r;

	fixture_init(&f);
	record_of(&r, 0, 0xc0, 1);
	CHECK(fzn_revocation_admit(&f.store, &r, f.root, &f.sign) == FZN_OK,
	      "the setup record was refused");

	f.store.used = 5; /* one past the four entries it was given */
	CHECK(fzn_revocation_covers(&f.store, r.capability, r.grantee) == 1,
	      "a corrupt store was scanned");

	/* A capability the store never held must also come back covered: the
	 * answer is about the store being unreadable, not about this record. */
	{
		fzn_revocation_record_t other;

		record_of(&other, 0, 0xc1, 9);
		CHECK(fzn_revocation_covers(&f.store, other.capability, other.grantee) == 1,
		      "a corrupt store answered `not revoked`, which is the fail-open "
		      "direction");
	}

	/* And nothing is appended to it. */
	CHECK(f.store.used == 5, "a corrupt store was written to");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	struct fixture f;
	fzn_revocation_record_t r;

	fixture_init(&f);
	record_of(&r, 0, 0xc0, 5);
	CHECK(fzn_revocation_admit(&f.store, &r, f.root, &f.sign) == FZN_OK,
	      "the positive control fails, so every refusal above proves nothing");
}

int main(void)
{
	test_admits_a_signed_revocation();
	test_a_carrier_cannot_invent_one();
	test_hearing_it_twice_is_not_an_error();
	test_a_full_store_refuses_and_does_not_evict();
	test_merge_keeps_going_past_a_bad_record();
	test_the_store_feeds_chain_verify_directly();
	test_bad_arguments();
	test_merge_bad_arguments();
	test_merge_reports_the_first_failure_not_the_last();
	test_merge_without_an_error_out();
	test_a_store_whose_fields_disagree_denies();
	test_the_suite_can_tell_pass_from_fail();

	printf("revocation_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
