/* Authenticity, and the order the checks run in.
 *
 * The ordering matters for the same reason sec 4.7's does: a cheap refusal
 * must not cost a signature verification, or a stranger sending rubbish makes
 * the receiver do public-key arithmetic on demand. The stub below counts
 * calls, so the test observes the order rather than asserting it in a
 * comment.
 */

#include "../record.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void expect_err(fzn_record_err_t got, fzn_record_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		printf("  FAIL: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_record_err_str(got),
		       fzn_record_err_str(want));
	}
}

static void expect(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

struct stub {
	int answer;
	unsigned calls;
};

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	struct stub *s = (struct stub *)ctx;

	(void)pubkey;
	(void)msg;
	(void)msg_len;
	(void)sig;
	s->calls++;
	return s->answer;
}

static const uint8_t REGION[] = "the bytes a signature covers";

int main(void)
{
	static uint8_t big[FZN_RECORD_BODY_MAX + 1u];
	struct stub stub = { 1, 0 };
	fzn_sign_ops_t sign = { stub_verify, NULL, &stub };
	fzn_sign_ops_t no_verify = { NULL, NULL, &stub };
	fzn_record_t rec;
	uint8_t body[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	unsigned before;

	memset(&rec, 0, sizeof(rec));
	memset(rec.issuer, 0x21, sizeof(rec.issuer));
	memset(rec.subject, 0x22, sizeof(rec.subject));
	rec.kind = 7;
	rec.seq = 1;
	rec.issued_at = 1000;
	rec.body = body;
	rec.body_len = sizeof(body);
	rec.signed_region = REGION;
	rec.signed_region_len = sizeof(REGION) - 1u;

	expect_err(fzn_record_verify(&rec, &sign), FZN_RECORD_OK, "a well-formed record");

	/* Arguments. */
	expect_err(fzn_record_verify(NULL, &sign), FZN_RECORD_ERR_MALFORMED, "a null record");
	expect_err(fzn_record_verify(&rec, NULL), FZN_RECORD_ERR_MALFORMED, "null sign ops");
	expect_err(fzn_record_verify(&rec, &no_verify), FZN_RECORD_ERR_MALFORMED,
	           "sign ops with no verify");

	{
		fzn_record_t bad = rec;

		bad.signed_region = NULL;
		expect_err(fzn_record_verify(&bad, &sign), FZN_RECORD_ERR_MALFORMED,
		           "no signed region");
		bad = rec;
		bad.signed_region_len = 0;
		expect_err(fzn_record_verify(&bad, &sign), FZN_RECORD_ERR_MALFORMED,
		           "an empty signed region");
		bad = rec;
		bad.body = NULL;
		expect_err(fzn_record_verify(&bad, &sign), FZN_RECORD_ERR_MALFORMED,
		           "a null body of non-zero length");

		/* A body of zero length with a null pointer is legitimate: a
		 * statement whose meaning is entirely in `kind` and `subject`
		 * carries nothing else. */
		bad = rec;
		bad.body = NULL;
		bad.body_len = 0;
		expect_err(fzn_record_verify(&bad, &sign), FZN_RECORD_OK, "a record with no body");

		bad = rec;
		bad.body = big;
		bad.body_len = sizeof(big);
		expect_err(fzn_record_verify(&bad, &sign), FZN_RECORD_ERR_BODY_TOO_LARGE,
		           "a body past the bound");

		/* Exactly the bound must pass, or the check is off by one and
		 * a test that only refused something far too large would miss
		 * it. */
		bad = rec;
		bad.body = big;
		bad.body_len = FZN_RECORD_BODY_MAX;
		expect_err(fzn_record_verify(&bad, &sign), FZN_RECORD_OK, "a body at the bound");
	}

	/* THE ORDER. Sequence zero is refused without spending a signature
	 * check, which the counter observes. */
	{
		fzn_record_t zero = rec;

		zero.seq = 0;
		before = stub.calls;
		expect_err(fzn_record_verify(&zero, &sign), FZN_RECORD_ERR_SEQ_ZERO,
		           "sequence zero");
		expect(stub.calls == before,
		       "a record refused for its sequence still cost a signature check");
	}

	/* And a bad signature is a bad signature, not a malformed record. */
	stub.answer = 0;
	before = stub.calls;
	expect_err(fzn_record_verify(&rec, &sign), FZN_RECORD_ERR_UNSIGNED, "a forged record");
	expect(stub.calls == before + 1u, "the signature was not actually checked");

	printf("record_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
