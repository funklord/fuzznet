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

/*
 * A FAILURE NAMES ITS FILE AND LINE, as every other suite in this tree does.
 *
 * It did not until 2026-09-06, and the cost was not cosmetic. `tool/sabotage.py`
 * reports one failure line per sabotage and had no way to tell this suite's
 * output from any other's, so breaking `trust/trust.c` was reported through
 * `persist_test.c` -- which reads as though trust's own suite did not hold its
 * own guard. It does, and is the first to say so. A test that does not name
 * itself cannot be credited with what it catches. project.md sec 139.
 */
static void expect_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "  FAIL trust_test.c:%d: %s\n", line, what);
	}
}

static void expect_err_at(fzn_trust_err_t got, fzn_trust_err_t want, int line,
                          const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		fprintf(stderr, "  FAIL trust_test.c:%d: %s -- got \"%s\", wanted \"%s\"\n", line,
		        what, fzn_trust_err_str(got), fzn_trust_err_str(want));
	}
}

#define expect(ok, what) expect_at((ok) ? 1 : 0, __LINE__, (what))
#define expect_err(got, want, what) expect_err_at((got), (want), __LINE__, (what))

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
	expect(fzn_trust_root(&t) && memcmp(fzn_trust_root(&t), first, FZN_PUBKEY_LEN) == 0,
	       "and it is the one adopted");
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
	expect(fzn_trust_root(&t) && memcmp(fzn_trust_root(&t), first, FZN_PUBKEY_LEN) == 0,
	       "the refused adoption must not have changed the anchor");

	/* Including one that differs in a single byte, which is the shape an
	 * attacker probing the comparison would send. */
	expect_err(fzn_trust_adopt(&t, nearly, 5001), FZN_TRUST_ERR_ANCHORED,
	           "a root differing in one byte");
	expect(fzn_trust_root(&t) && memcmp(fzn_trust_root(&t), first, FZN_PUBKEY_LEN) == 0,
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
		expect(fzn_trust_root(&p) && memcmp(fzn_trust_root(&p), first, FZN_PUBKEY_LEN) == 0,
		       "the configured root stands");
	}

	/*
	 * THE SELF-ROOT, AND THE ASYMMETRY THAT MAKES IT WORTH HAVING.
	 * project.md sec 136. A node alone anchors to its own key, so the
	 * window in which whoever answers first becomes the root never opens
	 * -- and an operator may still join it to a real estate.
	 */
	{
		fzn_trust_t s;

		fzn_trust_init(&s);
		expect_err(fzn_trust_self(&s, first), FZN_TRUST_OK, "a node may root itself");
		expect(fzn_trust_source_of(&s) == FZN_TRUST_SELF, "recorded as self");
		expect(fzn_trust_adopted_at(&s) == 0, "a self root has no adoption moment");
		expect(fzn_trust_root(&s) && memcmp(fzn_trust_root(&s), first, FZN_PUBKEY_LEN) == 0,
		       "a self root offers its own key");

		/* THE CASE THE WHOLE THING EXISTS FOR: adopting over a self
		 * root is refused, so a self-rooted node cannot be taken by
		 * trust on first use the way an unanchored one can. */
		expect_err(fzn_trust_adopt(&s, second, 1), FZN_TRUST_ERR_ANCHORED,
		           "adopting over a self root");
		expect(fzn_trust_source_of(&s) == FZN_TRUST_SELF, "and the self root stands");

		/* Nor may a second self root displace the first. */
		expect_err(fzn_trust_self(&s, second), FZN_TRUST_ERR_ANCHORED,
		           "re-rooting to another key");

		/* THE JOIN, which is the one permitted replacement. */
		expect_err(fzn_trust_pin(&s, second), FZN_TRUST_OK, "an operator may join it");
		expect(fzn_trust_source_of(&s) == FZN_TRUST_PINNED, "and it becomes pinned");
		expect(fzn_trust_root(&s) && memcmp(fzn_trust_root(&s), second, FZN_PUBKEY_LEN) == 0,
		       "the joined root is the one pinned");

		/* AND THE JOIN IS NOT REVERSIBLE, which is what stops the
		 * permission being a way back out: once pinned, everything is
		 * refused again. Without this the self-root would be a
		 * permanent hole rather than a starting state. */
		expect_err(fzn_trust_self(&s, first), FZN_TRUST_ERR_ANCHORED,
		           "rooting to self after a join");
		expect_err(fzn_trust_pin(&s, first), FZN_TRUST_ERR_ANCHORED,
		           "pinning over a pinned root");
		expect_err(fzn_trust_adopt(&s, first, 1), FZN_TRUST_ERR_ANCHORED,
		           "adopting over a pinned root");

		/* An echo is still an echo. */
		expect_err(fzn_trust_pin(&s, second), FZN_TRUST_ERR_UNCHANGED,
		           "pinning the root it already has");
	}

	/* A self root is refused the same zero key everything else is. */
	{
		fzn_trust_t z;
		uint8_t zeroes[FZN_PUBKEY_LEN];

		memset(zeroes, 0, sizeof(zeroes));
		fzn_trust_init(&z);
		expect_err(fzn_trust_self(&z, zeroes), FZN_TRUST_ERR_MALFORMED,
		           "rooting to a key of zeroes");
		expect_err(fzn_trust_self(NULL, first), FZN_TRUST_ERR_MALFORMED,
		           "rooting into nothing");
		expect_err(fzn_trust_self(&z, NULL), FZN_TRUST_ERR_MALFORMED, "a null own key");
	}

	/* Arguments. */
	expect_err(fzn_trust_adopt(NULL, first, 1), FZN_TRUST_ERR_MALFORMED, "a null trust");
	expect_err(fzn_trust_adopt(&t, NULL, 1), FZN_TRUST_ERR_MALFORMED, "a null root");
	expect_err(fzn_trust_pin(NULL, first), FZN_TRUST_ERR_MALFORMED, "pinning into nothing");
	expect(fzn_trust_root(NULL) == NULL, "a null trust offers no root");
	expect(fzn_trust_source_of(NULL) == FZN_TRUST_NONE, "a null trust has no source");
	expect(fzn_trust_adopted_at(NULL) == 0, "a null trust has no moment");
	fzn_trust_init(NULL); /* must not crash */

	/*
	 * THE POSITIVE CONTROL, WHICH THIS SUITE DID NOT HAVE until
	 * 2026-09-06. Every other suite here carries one and this one was
	 * counting checks nobody had seen fail -- so a run reporting
	 * "48 checks, 0 failures" was evidence that 48 things ran, and not
	 * that any of them could have said otherwise. project.md sec 139.
	 */
	{
		int before = failures;

		expect_at(0, __LINE__, "deliberate");
		expect(failures == before + 1, "a failing check must be counted");
		failures = before;
		checks -= 1;
	}

	printf("trust_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
