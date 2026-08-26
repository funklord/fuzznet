/* Reception, ordering and finalisation, which are three questions and not one.
 *
 * The cases below are chosen for what each would cost if it went the other
 * way, rather than for coverage: a journal that accepts a jump loses a
 * record nobody can later notice is missing; one that accepts a re-anchor
 * backwards readmits everything between; one that lets a sibling confirm what
 * it never received reports itself up to date on statements nobody sent.
 */

#include "../journal.h"

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

static void expect_err(fzn_journal_err_t got, fzn_journal_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		printf("  FAIL: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_journal_err_str(got),
		       fzn_journal_err_str(want));
	}
}

static void identity(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	memset(out, seed, FZN_PUBKEY_LEN);
}

int main(void)
{
	fzn_journal_t j;
	fzn_journal_entry_t entries[3];
	uint8_t alice[FZN_PUBKEY_LEN], bob[FZN_PUBKEY_LEN], carol[FZN_PUBKEY_LEN];
	uint8_t dave[FZN_PUBKEY_LEN];

	identity(alice, 0x0a);
	identity(bob, 0x0b);
	identity(carol, 0x0c);
	identity(dave, 0x0d);

	expect_err(fzn_journal_init(NULL, entries, 3), FZN_JOURNAL_ERR_MALFORMED, "a null journal");
	expect_err(fzn_journal_init(&j, NULL, 3), FZN_JOURNAL_ERR_MALFORMED, "null entries");
	expect_err(fzn_journal_init(&j, entries, 0), FZN_JOURNAL_ERR_MALFORMED, "zero capacity");
	expect_err(fzn_journal_init(&j, entries, 3), FZN_JOURNAL_OK, "a well-formed journal");

	/* AN UNKNOWN ISSUER STARTS AT ONE, and anything else is a gap rather
	 * than a beginning. A stranger opening at a large sequence would
	 * otherwise suppress every real record below it. */
	expect_err(fzn_journal_admit(&j, alice, 5), FZN_JOURNAL_ERR_GAP,
	           "an unknown issuer opening at 5");
	expect(fzn_journal_next(&j, alice) == 1, "the wanted sequence for an unseen issuer");
	expect_err(fzn_journal_admit(&j, alice, 1), FZN_JOURNAL_OK, "an issuer opening at 1");
	expect(fzn_journal_next(&j, alice) == 2, "the wanted sequence after one record");

	expect_err(fzn_journal_admit(&j, alice, 2), FZN_JOURNAL_OK, "the next in order");
	expect_err(fzn_journal_admit(&j, alice, 2), FZN_JOURNAL_ERR_DUPLICATE, "the same again");
	expect_err(fzn_journal_admit(&j, alice, 1), FZN_JOURNAL_ERR_DUPLICATE, "an older one");
	expect_err(fzn_journal_admit(&j, alice, 4), FZN_JOURNAL_ERR_GAP, "one too far ahead");
	expect(fzn_journal_next(&j, alice) == 3, "a refused record did not move the position");
	expect_err(fzn_journal_admit(&j, alice, 3), FZN_JOURNAL_OK, "the gap filled");

	/* ANCHORING is the deliberate version of the jump refused above. */
	expect_err(fzn_journal_anchor(&j, bob, 100), FZN_JOURNAL_OK, "anchoring a new issuer");
	expect(fzn_journal_next(&j, bob) == 101, "the wanted sequence after anchoring");
	expect_err(fzn_journal_admit(&j, bob, 101), FZN_JOURNAL_OK, "continuing from an anchor");
	expect_err(fzn_journal_anchor(&j, bob, 50), FZN_JOURNAL_ERR_DUPLICATE,
	           "an anchor moving backwards");
	expect(fzn_journal_next(&j, bob) == 102, "the refused anchor did not rewind");

	/* FINALISATION. Received and applied are different numbers. */
	expect_err(fzn_journal_confirm(&j, carol, 1), FZN_JOURNAL_ERR_UNKNOWN_ISSUER,
	           "confirming for an issuer never heard from");
	expect(fzn_journal_pending(&j, alice) == 3, "three received and none applied");
	expect_err(fzn_journal_confirm(&j, alice, 9), FZN_JOURNAL_ERR_NOT_RECEIVED,
	           "confirming past what arrived");
	expect_err(fzn_journal_confirm(&j, alice, 2), FZN_JOURNAL_OK, "confirming two of three");
	expect(fzn_journal_pending(&j, alice) == 1, "one still pending");
	expect_err(fzn_journal_confirm(&j, alice, 2), FZN_JOURNAL_ERR_DUPLICATE,
	           "confirming the same twice");
	expect_err(fzn_journal_confirm(&j, alice, 3), FZN_JOURNAL_OK, "confirming the rest");
	expect(fzn_journal_pending(&j, alice) == 0, "nothing pending once applied");

	/* FULL IS REFUSED, NOT MADE ROOM IN. Three entries, three issuers, and
	 * a fourth that must not displace one -- because forgetting an issuer
	 * readmits everything it ever sent. */
	expect_err(fzn_journal_admit(&j, carol, 1), FZN_JOURNAL_OK, "the third issuer");
	expect_err(fzn_journal_admit(&j, dave, 1), FZN_JOURNAL_ERR_FULL, "a fourth issuer");
	expect(fzn_journal_next(&j, alice) == 4, "a full journal did not forget the first");
	expect_err(fzn_journal_anchor(&j, dave, 7), FZN_JOURNAL_ERR_FULL,
	           "anchoring a fourth issuer");

	/* THE GUARDS EVERY ENTRY POINT NEEDS. `used` past `capacity` is a
	 * corrupt journal, and each function that scans must refuse it rather
	 * than trusting whichever one was called first -- the same argument
	 * frame/freshness.c makes for checking at each entry point that reads
	 * `used`, not at one of them. */
	{
		fzn_journal_t corrupt = j;

		corrupt.used = corrupt.capacity + 1u;
		expect_err(fzn_journal_admit(&corrupt, alice, 4), FZN_JOURNAL_ERR_MALFORMED,
		           "admitting into a corrupt journal");
		expect_err(fzn_journal_anchor(&corrupt, alice, 9), FZN_JOURNAL_ERR_MALFORMED,
		           "anchoring in a corrupt journal");
		expect_err(fzn_journal_confirm(&corrupt, alice, 1), FZN_JOURNAL_ERR_MALFORMED,
		           "confirming in a corrupt journal");
		expect(fzn_journal_next(&corrupt, alice) == 1,
		       "a corrupt journal should ask from the beginning");
		expect(fzn_journal_pending(&corrupt, alice) == 0,
		       "a corrupt journal should report nothing pending");
	}

	expect_err(fzn_journal_admit(&j, alice, 0), FZN_JOURNAL_ERR_MALFORMED, "sequence zero");
	expect_err(fzn_journal_anchor(&j, alice, 0), FZN_JOURNAL_ERR_MALFORMED,
	           "anchoring at zero");
	expect_err(fzn_journal_admit(&j, NULL, 1), FZN_JOURNAL_ERR_MALFORMED, "a null issuer");
	expect(fzn_journal_next(&j, NULL) == 1, "a null issuer wants the beginning");
	expect(fzn_journal_pending(&j, NULL) == 0, "a null issuer has nothing pending");
	expect(fzn_journal_pending(&j, dave) == 0, "an unknown issuer has nothing pending");

	printf("journal_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
