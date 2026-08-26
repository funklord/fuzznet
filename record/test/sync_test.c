/* Comparing two hosts' positions, which is the whole of the distribution
 * decision.
 *
 * The cases are chosen for what each would cost. A comparison that requested
 * from an issuer nobody chose lets one peer populate every journal in the
 * network. One that truncated silently leaves a range nobody asks for again.
 * One that ignored `max_per_request` turns "send me everything from 1" into a
 * request a stranger can make of every host at once.
 */

#include "../sync.h"

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

static void identity(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	memset(out, seed, FZN_PUBKEY_LEN);
}

/* Advance a journal to `to` for `issuer`, from nothing. */
static void seed_journal(fzn_journal_t *j, const uint8_t *issuer, uint64_t to)
{
	if (to == 0)
		return;
	if (fzn_journal_anchor(j, issuer, 0, to) != FZN_JOURNAL_OK)
		printf("  (seed failed)\n");
}

int main(void)
{
	fzn_journal_t mine;
	fzn_journal_entry_t entries[4];
	fzn_sync_position_t theirs[4], digest[4];
	fzn_sync_request_t out[4];
	fzn_sync_plan_t plan;
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN], c[FZN_PUBKEY_LEN];

	identity(a, 0xa1);
	identity(b, 0xb2);
	identity(c, 0xc3);

	fzn_journal_init(&mine, entries, 4);
	seed_journal(&mine, a, 10);
	seed_journal(&mine, b, 5);

	/* THE DIGEST is what this host tells a peer. */
	expect(fzn_sync_digest(&mine, digest, 4) == 2, "the digest should hold both issuers");
	expect(fzn_sync_digest(&mine, digest, 1) == 1, "the digest must respect its bound");
	expect(fzn_sync_digest(NULL, digest, 4) == 0, "a null journal yields no digest");

	/* FETCH: they are ahead on A, level on B, and follow C which we do not. */
	memcpy(theirs[0].issuer, a, FZN_PUBKEY_LEN);
	theirs[0].stream = 0;
	theirs[0].received = 14;
	memcpy(theirs[1].issuer, b, FZN_PUBKEY_LEN);
	theirs[1].stream = 0;
	theirs[1].received = 5;
	memcpy(theirs[2].issuer, c, FZN_PUBKEY_LEN);
	theirs[2].stream = 0;
	theirs[2].received = 99;

	expect(fzn_sync_plan_fetch(&mine, theirs, 3, 100, out, 4, &plan) == FZN_SYNC_OK,
	       "a well-formed fetch plan");
	expect(plan.request_count == 1, "only the issuer they are ahead on should be requested");
	expect(memcmp(out[0].issuer, a, FZN_PUBKEY_LEN) == 0, "the request names the right issuer");
	expect(out[0].from == 11, "the request starts after what is held");
	expect(out[0].count == 4, "the request covers the whole gap");
	expect(plan.unknown_issuers == 1, "an issuer we do not follow should be counted");
	expect(plan.truncated == 0, "nothing should have been truncated");

	/* AN UNFOLLOWED ISSUER IS NEVER REQUESTED, however far ahead they are.
	 * This is the check that matters most in the file. */
	for (size_t i = 0; i < plan.request_count; i++)
		expect(memcmp(out[i].issuer, c, FZN_PUBKEY_LEN) != 0,
		       "an issuer nobody chose was requested anyway");

	/* THE WINDOW BOUNDS EACH RANGE. */
	expect(fzn_sync_plan_fetch(&mine, theirs, 3, 2, out, 4, &plan) == FZN_SYNC_OK,
	       "a bounded fetch plan");
	expect(out[0].count == 2, "max_per_request must bound the range");
	expect(out[0].from == 11, "a bounded request still starts after what is held");

	/* TRUNCATION IS COUNTED. One slot, two issuers to fetch. */
	{
		fzn_journal_t small;
		fzn_journal_entry_t se[2];
		fzn_sync_position_t ahead[2];

		fzn_journal_init(&small, se, 2);
		seed_journal(&small, a, 1);
		seed_journal(&small, b, 1);
		memcpy(ahead[0].issuer, a, FZN_PUBKEY_LEN);
		ahead[0].stream = 0;
	ahead[0].received = 9;
		memcpy(ahead[1].issuer, b, FZN_PUBKEY_LEN);
		ahead[1].stream = 0;
	ahead[1].received = 9;

		expect(fzn_sync_plan_fetch(&small, ahead, 2, 100, out, 1, &plan) == FZN_SYNC_OK,
		       "a fetch plan that cannot fit");
		expect(plan.request_count == 1, "one request fitted");
		expect(plan.truncated == 1, "the range that did not fit must be counted");
	}

	/* OFFER is the mirror, and an issuer they have never seen is offered. */
	expect(fzn_sync_plan_offer(&mine, theirs, 3, 100, out, 4, &plan) == FZN_SYNC_OK,
	       "a well-formed offer plan");
	expect(plan.request_count == 0, "we are behind on A and level on B, so nothing to offer");

	{
		fzn_sync_position_t behind[1];

		memcpy(behind[0].issuer, a, FZN_PUBKEY_LEN);
		behind[0].stream = 0;
	behind[0].received = 3;

		expect(fzn_sync_plan_offer(&mine, behind, 1, 100, out, 4, &plan) == FZN_SYNC_OK,
		       "an offer to a peer that is behind");
		expect(plan.request_count == 2, "A's gap and B, which they have never seen");
		expect(plan.unknown_issuers == 1, "B is unknown to them");

		/* Nothing is offered from before the beginning. */
		for (size_t i = 0; i < plan.request_count; i++)
			expect(out[i].from >= 1, "an offer must start at one or later");
	}

	/* Arguments. */
	expect(fzn_sync_plan_fetch(NULL, theirs, 3, 100, out, 4, &plan) == FZN_SYNC_ERR_MALFORMED,
	       "a null journal");
	expect(fzn_sync_plan_fetch(&mine, NULL, 3, 100, out, 4, &plan) == FZN_SYNC_ERR_MALFORMED,
	       "null positions with a non-zero count");
	expect(fzn_sync_plan_fetch(&mine, theirs, 3, 0, out, 4, &plan) == FZN_SYNC_ERR_MALFORMED,
	       "a zero window, which must not mean unlimited");
	expect(fzn_sync_plan_fetch(&mine, theirs, 3, 100, NULL, 4, &plan) ==
	               FZN_SYNC_ERR_MALFORMED,
	       "nowhere to put the requests");
	expect(fzn_sync_plan_fetch(&mine, theirs, 3, 100, out, 4, NULL) == FZN_SYNC_ERR_MALFORMED,
	       "nowhere to put the plan");
	expect(fzn_sync_plan_offer(NULL, theirs, 3, 100, out, 4, &plan) == FZN_SYNC_ERR_MALFORMED,
	       "a null journal to offer from");
	expect(fzn_sync_plan_fetch(&mine, NULL, 0, 100, out, 4, &plan) == FZN_SYNC_OK,
	       "a peer that reported nothing is not malformed");

	printf("sync_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
