/* Reception, ordering and finalisation, which are three questions and not one.
 *
 * The cases below are chosen for what each would cost if it went the other
 * way, rather than for coverage: a journal that accepts a jump loses a
 * record nobody can later notice is missing; one that accepts a re-anchor
 * backwards readmits everything between; one that lets a sibling confirm what
 * it never received reports itself up to date on statements nobody sent.
 */

#include "../journal.h"

#include <stdint.h>
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

	/* ADMITTING DOES NOT ADOPT. An unknown issuer is refused whatever
	 * sequence it opens at -- 1 included, which used to open a stream
	 * implicitly.
	 *
	 * That shortcut was safe when a position was per ISSUER, since the key
	 * space was the set of keys an attacker holds. `stream` is a uint32 the
	 * issuer picks, which multiplied that space by 2^32: one authorised key
	 * filled a journal with streams nobody chose and locked out every other
	 * issuer permanently, since there is no forget.
	 *
	 * Both sequences are asserted, because a rule that refused only the
	 * large one is the rule this file used to hold. */
	expect_err(fzn_journal_admit(&j, alice, 0, 5), FZN_JOURNAL_ERR_UNKNOWN_ISSUER,
	           "an unknown issuer opening at 5");
	expect_err(fzn_journal_admit(&j, alice, 0, 1), FZN_JOURNAL_ERR_UNKNOWN_ISSUER,
	           "an unknown issuer opening at 1");
	expect(fzn_journal_next(&j, alice, 0) == 1, "the wanted sequence for an unseen issuer");
	expect(fzn_journal_pending(&j, alice, 0) == 0, "a refused issuer left no entry");

	/* Following one is deliberate, and then it behaves as before. */
	expect_err(fzn_journal_anchor(&j, alice, 0, 0), FZN_JOURNAL_OK,
	           "following an issuer from the beginning");
	expect_err(fzn_journal_admit(&j, alice, 0, 1), FZN_JOURNAL_OK, "an issuer opening at 1");
	expect(fzn_journal_next(&j, alice, 0) == 2, "the wanted sequence after one record");

	expect_err(fzn_journal_admit(&j, alice, 0, 2), FZN_JOURNAL_OK, "the next in order");
	expect_err(fzn_journal_admit(&j, alice, 0, 2), FZN_JOURNAL_ERR_DUPLICATE, "the same again");
	expect_err(fzn_journal_admit(&j, alice, 0, 1), FZN_JOURNAL_ERR_DUPLICATE, "an older one");
	expect_err(fzn_journal_admit(&j, alice, 0, 4), FZN_JOURNAL_ERR_GAP, "one too far ahead");
	expect(fzn_journal_next(&j, alice, 0) == 3, "a refused record did not move the position");
	expect_err(fzn_journal_admit(&j, alice, 0, 3), FZN_JOURNAL_OK, "the gap filled");

	/* ANCHORING is the deliberate version of the jump refused above. */
	expect_err(fzn_journal_anchor(&j, bob, 0, 100), FZN_JOURNAL_OK, "anchoring a new issuer");
	expect(fzn_journal_next(&j, bob, 0) == 101, "the wanted sequence after anchoring");
	expect_err(fzn_journal_admit(&j, bob, 0, 101), FZN_JOURNAL_OK, "continuing from an anchor");
	expect_err(fzn_journal_anchor(&j, bob, 0, 50), FZN_JOURNAL_ERR_DUPLICATE,
	           "an anchor moving backwards");
	expect(fzn_journal_next(&j, bob, 0) == 102, "the refused anchor did not rewind");

	/* FINALISATION. Received and applied are different numbers. */
	expect_err(fzn_journal_confirm(&j, carol, 0, 1), FZN_JOURNAL_ERR_UNKNOWN_ISSUER,
	           "confirming for an issuer never heard from");
	expect(fzn_journal_pending(&j, alice, 0) == 3, "three received and none applied");
	expect_err(fzn_journal_confirm(&j, alice, 0, 9), FZN_JOURNAL_ERR_NOT_RECEIVED,
	           "confirming past what arrived");
	expect_err(fzn_journal_confirm(&j, alice, 0, 2), FZN_JOURNAL_OK, "confirming two of three");
	expect(fzn_journal_pending(&j, alice, 0) == 1, "one still pending");
	expect_err(fzn_journal_confirm(&j, alice, 0, 2), FZN_JOURNAL_ERR_DUPLICATE,
	           "confirming the same twice");
	expect_err(fzn_journal_confirm(&j, alice, 0, 3), FZN_JOURNAL_OK, "confirming the rest");
	expect(fzn_journal_pending(&j, alice, 0) == 0, "nothing pending once applied");

	/* FULL IS REFUSED, NOT MADE ROOM IN. Three entries, three issuers, and
	 * a fourth that must not displace one -- because forgetting an issuer
	 * readmits everything it ever sent. */
	expect_err(fzn_journal_anchor(&j, carol, 0, 0), FZN_JOURNAL_OK, "the third issuer");
	expect_err(fzn_journal_admit(&j, carol, 0, 1), FZN_JOURNAL_OK, "the third issuer's first");
	expect_err(fzn_journal_admit(&j, dave, 0, 1), FZN_JOURNAL_ERR_UNKNOWN_ISSUER,
	           "a fourth issuer, unfollowed");
	expect(fzn_journal_next(&j, alice, 0) == 4, "a full journal did not forget the first");
	expect_err(fzn_journal_anchor(&j, dave, 0, 7), FZN_JOURNAL_ERR_FULL,
	           "anchoring a fourth issuer");

	/* FOLLOWING AN ISSUER BEFORE HEARING FROM IT. A fresh journal, so the
	 * full-journal refusal above does not get in the way. */
	{
		fzn_journal_t fresh;
		fzn_journal_entry_t fe[2];

		fzn_journal_init(&fresh, fe, 2);
		expect(fzn_journal_next(&fresh, dave, 0) == 1, "an unfollowed issuer wants one");
		expect_err(fzn_journal_anchor(&fresh, dave, 0, 0), FZN_JOURNAL_OK,
		           "following an issuer from the beginning");
		expect(fzn_journal_next(&fresh, dave, 0) == 1, "following changes nothing held");
		expect(fzn_journal_pending(&fresh, dave, 0) == 0, "nothing received, nothing pending");
		expect_err(fzn_journal_anchor(&fresh, dave, 0, 0), FZN_JOURNAL_ERR_DUPLICATE,
		           "following twice is an echo");
		expect_err(fzn_journal_admit(&fresh, dave, 0, 1), FZN_JOURNAL_OK,
		           "the first record from a followed issuer");
		expect(fzn_journal_next(&fresh, dave, 0) == 2, "and the position advances");
	}

	/* THE GUARDS EVERY ENTRY POINT NEEDS. `used` past `capacity` is a
	 * corrupt journal, and each function that scans must refuse it rather
	 * than trusting whichever one was called first -- the same argument
	 * frame/freshness.c makes for checking at each entry point that reads
	 * `used`, not at one of them. */
	{
		fzn_journal_t corrupt = j;

		corrupt.used = corrupt.capacity + 1u;
		expect_err(fzn_journal_admit(&corrupt, alice, 0, 4), FZN_JOURNAL_ERR_MALFORMED,
		           "admitting into a corrupt journal");
		expect_err(fzn_journal_anchor(&corrupt, alice, 0, 9), FZN_JOURNAL_ERR_MALFORMED,
		           "anchoring in a corrupt journal");
		expect_err(fzn_journal_confirm(&corrupt, alice, 0, 1), FZN_JOURNAL_ERR_MALFORMED,
		           "confirming in a corrupt journal");
		expect(fzn_journal_next(&corrupt, alice, 0) == 1,
		       "a corrupt journal should ask from the beginning");
		expect(fzn_journal_pending(&corrupt, alice, 0) == 0,
		       "a corrupt journal should report nothing pending");
	}

	expect_err(fzn_journal_admit(&j, alice, 0, 0), FZN_JOURNAL_ERR_MALFORMED, "sequence zero");

	/* ANCHORING AT ZERO IS FOLLOW-FROM-THE-BEGINNING, not a malformed
	 * call. It is the state a host is in when it has decided to care about
	 * an issuer and received nothing yet, and `record/sync.h` requires it
	 * before it will fetch: without it a whole network converges on
	 * nothing, which is how this was found. */
	expect_err(fzn_journal_anchor(&j, alice, 0, 0), FZN_JOURNAL_ERR_DUPLICATE,
	           "anchoring at zero an issuer already followed");
	expect_err(fzn_journal_admit(&j, NULL, 0, 1), FZN_JOURNAL_ERR_MALFORMED, "a null issuer");
	expect(fzn_journal_next(&j, NULL, 0) == 1, "a null issuer wants the beginning");
	expect(fzn_journal_pending(&j, NULL, 0) == 0, "a null issuer has nothing pending");
	expect(fzn_journal_pending(&j, dave, 0) == 0, "an unknown issuer has nothing pending");

	/* TWO STREAMS FROM ONE ISSUER ARE INDEPENDENT, which is the whole
	 * reason the field exists. A recipient entitled to one and not the
	 * other keeps a contiguous position in what it may see; before this,
	 * admitting 1 then 3 from one issuer answered "ahead of what is held"
	 * and the journal wanted 2 for ever -- a record nobody would send it. */
	{
		fzn_journal_t two;
		fzn_journal_entry_t te[2];

		fzn_journal_init(&two, te, 2);
		/* Each stream is followed on its own -- which is the property
		 * under test stated one layer up: if a stream were not its own
		 * key, one anchor would open both. */
		expect_err(fzn_journal_anchor(&two, alice, 7, 0), FZN_JOURNAL_OK,
		           "following stream seven");
		expect_err(fzn_journal_anchor(&two, alice, 9, 0), FZN_JOURNAL_OK,
		           "following stream nine");
		expect_err(fzn_journal_admit(&two, alice, 7, 1), FZN_JOURNAL_OK,
		           "stream seven, first record");
		expect_err(fzn_journal_admit(&two, alice, 9, 1), FZN_JOURNAL_OK,
		           "stream nine, first record, same issuer");
		expect(fzn_journal_next(&two, alice, 7) == 2, "stream seven wants its own next");
		expect(fzn_journal_next(&two, alice, 9) == 2, "and stream nine wants its own");
		expect_err(fzn_journal_admit(&two, alice, 7, 2), FZN_JOURNAL_OK,
		           "advancing one stream");
		expect(fzn_journal_next(&two, alice, 9) == 2,
		       "must not have advanced the other");
		expect_err(fzn_journal_admit(&two, alice, 9, 3), FZN_JOURNAL_ERR_GAP,
		           "and each stream keeps its own gap");
	}

	/* AN EXHAUSTED STREAM MUST NOT ANSWER WITH THE RESERVED SEQUENCE.
	 * `fzn_journal_next` returned `received + 1`, which is zero once a
	 * stream has reached the top -- and zero is the one value
	 * `fzn_record_open` refuses by name, so the journal was answering
	 * "what should I ask for next" with the single sequence its own library
	 * rejects. Two public calls and no corruption reach it. */
	{
		fzn_journal_t top;
		fzn_journal_entry_t te[1];

		fzn_journal_init(&top, te, 1);
		expect_err(fzn_journal_anchor(&top, alice, 4, UINT64_MAX), FZN_JOURNAL_OK,
		           "anchoring at the top of the sequence space");
		expect(fzn_journal_next(&top, alice, 4) != 0,
		       "an exhausted stream answered with the reserved sequence zero");
		expect(fzn_journal_next(&top, alice, 4) == UINT64_MAX,
		       "an exhausted stream must say so rather than wrapping");
		/* The value it gives back must itself be inadmissible, or the
		 * advice would merely move the problem to the next call. */
		expect_err(fzn_journal_admit(&top, alice, 4, UINT64_MAX),
		           FZN_JOURNAL_ERR_DUPLICATE,
		           "the exhausted answer must not be admissible");
	}

	/* TWO ISSUERS AGREEING ON EVERY BYTE BUT THE LAST.
	 *
	 * `identity()` gives every issuer in this file a distinct first byte,
	 * so a comparison of ONE byte separates any two of them exactly as
	 * well as a comparison of thirty-two. Measured before this case
	 * existed: truncating `find`'s `fzn_ct_memeq` to 1 left THIS FILE at
	 * 66 checks and zero failures. `record/test/sync_test.c` caught it --
	 * a different module's test, reporting "one position produced more
	 * than one request" -- which is how it came to be recorded as
	 * covered. "The suite catches it" and "this module's test catches it"
	 * are different claims and the first reads like the second.
	 *
	 * WHAT FAILS OPEN IS TWO ISSUERS SHARING ONE POSITION. `find` keys on
	 * (issuer, stream), so a short comparison makes one issuer's sequence
	 * answer for another's: admitting a record from the twin advances the
	 * first twin's position, and the first twin's genuine next record is
	 * then refused as a duplicate, for ever. That is the journal
	 * refusing a real record on the strength of a stranger's, and
	 * nothing reports it. */
	{
		fzn_journal_t tj;
		fzn_journal_entry_t tentries[4];
		uint8_t twin_a[FZN_PUBKEY_LEN], twin_b[FZN_PUBKEY_LEN];

		identity(twin_a, 0x5a);
		memcpy(twin_b, twin_a, sizeof(twin_b));
		twin_b[FZN_PUBKEY_LEN - 1u] ^= 0x01u;

		expect(memcmp(twin_a, twin_b, FZN_PUBKEY_LEN - 1u) == 0,
		       "the twins must agree on every byte but the last");
		expect(memcmp(twin_a, twin_b, FZN_PUBKEY_LEN) != 0,
		       "the twins must differ somewhere, or nothing here can fail");

		expect_err(fzn_journal_init(&tj, tentries, 4), FZN_JOURNAL_OK, "a journal for twins");
		expect_err(fzn_journal_anchor(&tj, twin_a, 0, 0), FZN_JOURNAL_OK,
		           "following the first twin");
		expect_err(fzn_journal_anchor(&tj, twin_b, 0, 0), FZN_JOURNAL_OK,
		           "following the second twin");

		expect_err(fzn_journal_admit(&tj, twin_a, 0, 1), FZN_JOURNAL_OK,
		           "the first twin's first record");
		expect(fzn_journal_next(&tj, twin_b, 0) == 1u,
		       "admitting the first twin's record advanced the SECOND twin's "
		       "position -- the issuer comparison is not reading the whole key");
		expect_err(fzn_journal_admit(&tj, twin_b, 0, 1), FZN_JOURNAL_OK,
		           "the second twin's own first record was refused as a duplicate "
		           "of the first twin's");
		expect(fzn_journal_next(&tj, twin_a, 0) == 2u,
		       "the first twin's position is not its own");
	}

	printf("journal_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
