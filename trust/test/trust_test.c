/* Trust on FIRST use, with the emphasis on first.
 *
 * The case that matters is the second key. TOFU's entire security content is
 * that the anchor is adopted once: a module that let a later key replace it
 * would be trust on every use, which is no trust at all, and the failure
 * would be silent -- a host quietly following whoever spoke to it most
 * recently.
 */

#include "../trust.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void expect(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

static void expect_err(fzn_trust_err_t got, fzn_trust_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		printf("  FAIL: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_trust_err_str(got),
		       fzn_trust_err_str(want));
	}
}

int main(void)
{
	fzn_trust_t t;
	uint8_t first[FZN_PUBKEY_LEN], second[FZN_PUBKEY_LEN], nearly[FZN_PUBKEY_LEN];

	memset(first, 0x11, sizeof(first));
	memset(second, 0x22, sizeof(second));
	memset(nearly, 0x11, sizeof(nearly));
	nearly[FZN_PUBKEY_LEN - 1u] = 0x12; /* differs in the last byte only */

	/* EMPTY FAILS CLOSED. A root of zeroes is a key an attacker can also
	 * produce, so an unset anchor must be NULL rather than zeroed. */
	fzn_trust_init(&t);
	expect(fzn_trust_root(&t) == NULL, "an unanchored trust must offer no root");
	expect(fzn_trust_source_of(&t) == FZN_TRUST_NONE, "and no source");
	expect(fzn_trust_adopted_at(&t) == 0, "and no moment of adoption");

	/* AND ANCHORING ZEROES IS REFUSED, which is the half the paragraph
	 * above argued for and did not test.
	 *
	 * The guard was on `source`, not on the bytes: a caller anchoring from
	 * a join message it parsed only partly, whose root field was never
	 * filled, got a permanent successful anchor to a key nobody holds --
	 * permanent, because the next anchor is then refused as ANCHORED. And
	 * `fzn_trust_root` handed those zeroes to `fzn_chain_verify` as a real
	 * root, which is exactly what this module says it exists to prevent.
	 *
	 * Both entry points, because they are two doors to one rule. */
	{
		uint8_t zeroes[FZN_PUBKEY_LEN];

		memset(zeroes, 0, sizeof(zeroes));
		expect_err(fzn_trust_adopt(&t, zeroes, 1), FZN_TRUST_ERR_MALFORMED,
		           "adopting a root of zeroes");
		expect_err(fzn_trust_pin(&t, zeroes), FZN_TRUST_ERR_MALFORMED,
		           "pinning a root of zeroes");
		expect(fzn_trust_root(&t) == NULL, "a refused anchor left a root behind");
		expect(fzn_trust_source_of(&t) == FZN_TRUST_NONE,
		       "a refused anchor recorded a source");
		/* The control: a key differing from zero in ONE byte is fine, so
		 * the refusal is about emptiness rather than about the shape of
		 * the check. */
		zeroes[FZN_PUBKEY_LEN - 1u] = 0x01;
		expect_err(fzn_trust_adopt(&t, zeroes, 1), FZN_TRUST_OK,
		           "a key that is nearly zero was refused");
		fzn_trust_init(&t);
	}

	/* FIRST USE. */
	expect_err(fzn_trust_adopt(&t, first, 4242), FZN_TRUST_OK, "adopting on first contact");
	expect(fzn_trust_root(&t) != NULL, "an anchored trust offers a root");
	expect(memcmp(fzn_trust_root(&t), first, FZN_PUBKEY_LEN) == 0, "and it is the one adopted");
	expect(fzn_trust_source_of(&t) == FZN_TRUST_ADOPTED, "recorded as adopted, not pinned");
	expect(fzn_trust_adopted_at(&t) == 4242, "and when");

	/* THE SAME KEY AGAIN IS AN ECHO, not a fault: a join repeated, a
	 * bundle delivered twice. */
	expect_err(fzn_trust_adopt(&t, first, 9999), FZN_TRUST_ERR_UNCHANGED,
	           "adopting the same root again");
	expect(fzn_trust_adopted_at(&t) == 4242, "an echo must not restamp the moment");

	/* A DIFFERENT KEY IS REFUSED. This is the whole of "first use". */
	expect_err(fzn_trust_adopt(&t, second, 5000), FZN_TRUST_ERR_ANCHORED,
	           "a second, different root");
	expect(memcmp(fzn_trust_root(&t), first, FZN_PUBKEY_LEN) == 0,
	       "the refused adoption must not have changed the anchor");

	/* Including one that differs in a single byte, which is the shape an
	 * attacker probing the comparison would send. */
	expect_err(fzn_trust_adopt(&t, nearly, 5001), FZN_TRUST_ERR_ANCHORED,
	           "a root differing in one byte");
	expect(memcmp(fzn_trust_root(&t), first, FZN_PUBKEY_LEN) == 0,
	       "and still unchanged");

	/* PINNING IS REFUSED OVER AN EXISTING ANCHOR TOO. An operator who must
	 * re-anchor makes a new one, on the reasoning journal.h gives about
	 * never rewinding. */
	expect_err(fzn_trust_pin(&t, second), FZN_TRUST_ERR_ANCHORED,
	           "pinning over an adopted anchor");

	/* THE OTHER ORDER: pinned first, and adoption cannot then override. A
	 * configured root must not be replaceable by whoever speaks first. */
	{
		fzn_trust_t p;

		fzn_trust_init(&p);
		expect_err(fzn_trust_pin(&p, first), FZN_TRUST_OK, "pinning a configured root");
		expect(fzn_trust_source_of(&p) == FZN_TRUST_PINNED, "recorded as pinned");
		expect(fzn_trust_adopted_at(&p) == 0, "a pinned root has no adoption moment");
		expect_err(fzn_trust_adopt(&p, second, 1), FZN_TRUST_ERR_ANCHORED,
		           "adopting over a configured root");
		expect(memcmp(fzn_trust_root(&p), first, FZN_PUBKEY_LEN) == 0,
		       "the configured root stands");
	}

	/* Arguments. */
	expect_err(fzn_trust_adopt(NULL, first, 1), FZN_TRUST_ERR_MALFORMED, "a null trust");
	expect_err(fzn_trust_adopt(&t, NULL, 1), FZN_TRUST_ERR_MALFORMED, "a null root");
	expect_err(fzn_trust_pin(NULL, first), FZN_TRUST_ERR_MALFORMED, "pinning into nothing");
	expect(fzn_trust_root(NULL) == NULL, "a null trust offers no root");
	expect(fzn_trust_source_of(NULL) == FZN_TRUST_NONE, "a null trust has no source");
	expect(fzn_trust_adopted_at(NULL) == 0, "a null trust has no moment");
	fzn_trust_init(NULL); /* must not crash */

	printf("trust_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
