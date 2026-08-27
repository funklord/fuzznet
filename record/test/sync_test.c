/* Comparing two hosts' positions, which is the whole of the distribution
 * decision.
 *
 * The cases are chosen for what each would cost. A comparison that requested
 * from an issuer nobody chose lets one peer populate every journal in the
 * network. One that truncated silently leaves a range nobody asks for again.
 * One that ignored `max_per_request` turns "send me everything from 1" into a
 * request a stranger can make of every host at once.
 *
 * THREE OF THE BLOCKS BELOW ARE ABOUT A LYING PEER rather than a wrong one,
 * and they are written so that the honest case is asserted beside the hostile
 * one every time. "The liar was stopped" is satisfied by a planner that plans
 * nothing at all, so every hostile case here is paired with a positive
 * control: an honest peer with more to say than fits must still get a
 * sensible plan and must still see `truncated` reported, and a host that
 * follows an issuer it has received nothing from must still be able to fetch.
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

/* Follow `issuer` on stream 0 from `from`. `from` of zero is the deliberate
 * "I follow this and have received nothing" that `fzn_journal_anchor`
 * reserves sequence zero for, and it is a case in its own right below. */
static void follow(fzn_journal_t *j, const uint8_t *issuer, uint64_t from)
{
	if (fzn_journal_anchor(j, issuer, 0, from) != FZN_JOURNAL_OK)
		printf("  (seed failed)\n");
}

static void position(fzn_sync_position_t *p, const uint8_t *issuer, uint64_t received)
{
	memcpy(p->issuer, issuer, FZN_PUBKEY_LEN);
	p->stream = 0;
	p->received = received;
}

/* Whether any request in the plan names `issuer`. The starvation cases assert
 * PRESENCE with this rather than a count, because a count cannot tell a plan
 * that carried the honest fetch from one that carried two phantoms. */
static int plan_names(const fzn_sync_request_t *out, const fzn_sync_plan_t *plan,
                      const uint8_t *issuer)
{
	for (size_t i = 0; i < plan->request_count; i++)
		if (memcmp(out[i].issuer, issuer, FZN_PUBKEY_LEN) == 0)
			return 1;

	return 0;
}

int main(void)
{
	fzn_journal_t mine;
	fzn_journal_entry_t entries[4];
	fzn_sync_position_t theirs[4], digest[4];
	fzn_sync_request_t out[4];
	fzn_sync_plan_t plan;
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN], c[FZN_PUBKEY_LEN], d[FZN_PUBKEY_LEN];

	identity(a, 0xa1);
	identity(b, 0xb2);
	identity(c, 0xc3);
	identity(d, 0xd4);

	fzn_journal_init(&mine, entries, 4);
	follow(&mine, a, 10);
	follow(&mine, b, 5);

	/* THE DIGEST is what this host tells a peer. */
	{
		size_t dropped = 99;

		expect(fzn_sync_digest(&mine, digest, 4, &dropped) == 2,
		       "the digest should hold both issuers");
		expect(dropped == 0, "nothing was dropped when everything fitted");

		/* THE BOUND MUST BE REPORTED, NOT MERELY RESPECTED. This case
		 * used to assert only the short return, under the name "the
		 * digest must respect its bound" -- which is exactly the
		 * behaviour sync.h forbids, asserted as though it were the
		 * contract. A caller seeing 1 could not tell a host that
		 * follows one issuer from a host that follows a hundred, and
		 * because the scan runs in journal order it was the same
		 * issuers missing from every round. */
		expect(fzn_sync_digest(&mine, digest, 1, &dropped) == 1,
		       "the digest must respect its bound");
		expect(dropped == 1, "the digest did not report what would not fit");

		expect(fzn_sync_digest(NULL, digest, 4, &dropped) == 0,
		       "a null journal yields no digest");
		expect(fzn_sync_digest(&mine, digest, 4, NULL) == 0,
		       "a digest with nowhere to report truncation must refuse");
	}

	/* FETCH: they are ahead on A, level on B, and follow C which we do not. */
	position(&theirs[0], a, 14);
	position(&theirs[1], b, 5);
	position(&theirs[2], c, 99);

	expect(fzn_sync_plan_fetch(&mine, theirs, 3, 100, out, 4, &plan) == FZN_SYNC_OK,
	       "a well-formed fetch plan");
	expect(plan.request_count == 1, "only the issuer they are ahead on should be requested");
	expect(memcmp(out[0].issuer, a, FZN_PUBKEY_LEN) == 0, "the request names the right issuer");
	expect(out[0].from == 11, "the request starts after what is held");
	expect(out[0].count == 4, "the request covers the whole gap");
	expect(plan.unknown_issuers == 1, "an issuer we do not follow should be counted");
	expect(plan.truncated == 0, "nothing should have been truncated");
	expect(plan.positions_ignored == 0, "a three-position digest is not past the ceiling");

	/* AN UNFOLLOWED ISSUER IS NEVER REQUESTED, however far ahead they are.
	 * This is the check that matters most in the file. */
	expect(!plan_names(out, &plan, c), "an issuer nobody chose was requested anyway");

	/* THE WINDOW BOUNDS EACH RANGE. */
	expect(fzn_sync_plan_fetch(&mine, theirs, 3, 2, out, 4, &plan) == FZN_SYNC_OK,
	       "a bounded fetch plan");
	expect(out[0].count == 2, "max_per_request must bound the range");
	expect(out[0].from == 11, "a bounded request still starts after what is held");

	/* TRUNCATION IS COUNTED. One slot, two issuers to fetch.
	 *
	 * THE POSITIVE CONTROL for everything below it: this peer is honest,
	 * it has more for us than the caller left room for, and the plan must
	 * still be sensible and must still say so. A planner that answered the
	 * lying-peer cases by planning nothing would fail here. */
	{
		fzn_journal_t small;
		fzn_journal_entry_t se[2];
		fzn_sync_position_t ahead[2];

		fzn_journal_init(&small, se, 2);
		follow(&small, a, 1);
		follow(&small, b, 1);
		position(&ahead[0], a, 9);
		position(&ahead[1], b, 9);

		expect(fzn_sync_plan_fetch(&small, ahead, 2, 100, out, 1, &plan) == FZN_SYNC_OK,
		       "a fetch plan that cannot fit");
		expect(plan.request_count == 1, "one request fitted");
		expect(plan.truncated == 1, "the range that did not fit must be counted");
		expect(plan.positions_ignored == 0,
		       "an honest overflow is the caller's sizing, not the peer's digest");
		expect(out[0].from == 2 && out[0].count == 8,
		       "the request that did fit must still be the right one");

		/* AND THE SAME PEER, GIVEN ROOM, MUST FILL IT. Otherwise the
		 * assertion above is satisfied by a planner that stops at one. */
		expect(fzn_sync_plan_fetch(&small, ahead, 2, 100, out, 2, &plan) == FZN_SYNC_OK,
		       "the same honest peer with room for both");
		expect(plan.request_count == 2 && plan.truncated == 0,
		       "an honest peer with room gets every range");
	}

	/* A LYING PEER MUST NOT BE ABLE TO AIM THE BOUND.
	 *
	 * Four issuers this host follows; the peer has nothing for three of
	 * them and claims a huge position on each, then names the one it is
	 * genuinely ahead on LAST. Two request slots.
	 *
	 * Measured before the fix, with the plan built in the peer's order:
	 * request_count 2, truncated 2, both slots holding phantoms and the
	 * honest fetch one of the two dropped -- every round, since the peer
	 * sends the same order every round, and the only symptom visible to
	 * the caller was `truncated > 0`.
	 *
	 * The plan is built in THIS host's journal order now, so what is in it
	 * is decided here. The assertion is presence, not count. */
	{
		fzn_journal_t four;
		fzn_journal_entry_t fe[4];
		fzn_sync_position_t liar[4];

		fzn_journal_init(&four, fe, 4);
		follow(&four, a, 6);
		follow(&four, b, 0);
		follow(&four, c, 0);
		follow(&four, d, 0);

		position(&liar[0], d, 1u << 30);
		position(&liar[1], c, 1u << 30);
		position(&liar[2], b, 1u << 30);
		position(&liar[3], a, 10);

		expect(fzn_sync_plan_fetch(&four, liar, 4, 100, out, 2, &plan) == FZN_SYNC_OK,
		       "a fetch plan against a padded digest");
		expect(plan_names(out, &plan, a),
		       "a lying peer starved the one genuine fetch out of the plan");
		expect(memcmp(out[0].issuer, a, FZN_PUBKEY_LEN) == 0,
		       "the plan must open with this host's first journal entry");
		expect(plan.request_count == 2 && plan.truncated == 2,
		       "the bound is still reported, it is just no longer aimed");

		/* AND THE SAME DIGEST CANNOT TRUNCATE AT ALL given a slot per
		 * followed stream. This is the number sync.h promises the
		 * caller, and it is the property that makes `truncated` a fact
		 * about the caller's array rather than about the peer. */
		{
			fzn_sync_request_t room[4];

			expect(fzn_sync_plan_fetch(&four, liar, 4, 100, room, 4, &plan) ==
			               FZN_SYNC_OK,
			       "the padded digest with a slot per followed stream");
			expect(plan.truncated == 0,
			       "out_cap of journal->used must be untruncatable");
			expect(plan.request_count == 4, "all four streams are behind");
		}
	}

	/* ONE FOLLOWED STREAM MAY OCCUPY ONE SLOT, HOWEVER OFTEN IT IS NAMED.
	 *
	 * The other half of the same fault, and the half that needs no
	 * assumption about journal order. Measured before the fix: five copies
	 * of one position produced five requests, took all four slots, and
	 * truncated a second issuer this host was genuinely behind on. */
	{
		fzn_journal_t two;
		fzn_journal_entry_t te[2];
		fzn_sync_position_t repeat[6];

		fzn_journal_init(&two, te, 2);
		follow(&two, a, 1);
		follow(&two, b, 1);

		for (size_t i = 0; i < 5; i++)
			position(&repeat[i], a, 10);
		position(&repeat[5], b, 10);

		expect(fzn_sync_plan_fetch(&two, repeat, 6, 100, out, 4, &plan) == FZN_SYNC_OK,
		       "a fetch plan against a repeated position");
		expect(plan.request_count == 2,
		       "one range per followed stream, whatever the peer repeats");
		expect(plan_names(out, &plan, b),
		       "a repeated position crowded out a genuine second fetch");
		expect(plan.truncated == 0, "nothing needed to be truncated");
	}

	/* DUPLICATES WITH DIFFERENT NUMBERS MUST NOT DEPEND ON THEIR ORDER.
	 *
	 * `theirs_for` used to keep the LAST hit under a comment claiming a
	 * peer could not change the answer by ordering. With two different
	 * numbers the last one is whichever the peer put last. */
	{
		fzn_sync_position_t two_ways[2];
		uint64_t first, second;

		position(&two_ways[0], a, 20);
		position(&two_ways[1], a, 12);
		expect(fzn_sync_plan_fetch(&mine, two_ways, 2, 100, out, 4, &plan) == FZN_SYNC_OK,
		       "a digest that names one stream twice");
		first = out[0].count;

		position(&two_ways[0], a, 12);
		position(&two_ways[1], a, 20);
		expect(fzn_sync_plan_fetch(&mine, two_ways, 2, 100, out, 4, &plan) == FZN_SYNC_OK,
		       "the same digest, the other way round");
		second = out[0].count;

		expect(first == second, "the peer changed the answer by reordering itself");
		expect(first == 10, "the larger of two claims is the one taken");
	}

	/* THE CEILING ON HOW MUCH OF A DIGEST IS EXAMINED, both ways round.
	 *
	 * A check that only showed the honest position being found inside the
	 * ceiling would pass just as loudly with no ceiling at all, so the
	 * same position is placed past it and must NOT produce a request. */
	{
		static fzn_sync_position_t many[FZN_SYNC_MAX_POSITIONS + 2u];
		uint8_t phantom[FZN_PUBKEY_LEN];

		identity(phantom, 0xee);
		for (size_t i = 0; i < FZN_SYNC_MAX_POSITIONS + 2u; i++)
			position(&many[i], phantom, 1);

		position(&many[0], a, 20);
		expect(fzn_sync_plan_fetch(&mine, many, FZN_SYNC_MAX_POSITIONS + 2u, 100, out, 4,
		                           &plan) == FZN_SYNC_OK,
		       "an oversized digest is not malformed");
		expect(plan.request_count == 1, "a position inside the ceiling is acted on");
		expect(plan.positions_ignored == 2, "the excess must be reported, not dropped");
		expect(plan.truncated == 0,
		       "an oversized digest must not be reported as the caller's overflow");
		expect(plan.unknown_issuers == FZN_SYNC_MAX_POSITIONS - 1u,
		       "only the positions examined can be classified");

		position(&many[0], phantom, 1);
		position(&many[FZN_SYNC_MAX_POSITIONS + 1u], a, 20);
		expect(fzn_sync_plan_fetch(&mine, many, FZN_SYNC_MAX_POSITIONS + 2u, 100, out, 4,
		                           &plan) == FZN_SYNC_OK,
		       "an oversized digest hiding the position past the ceiling");
		expect(plan.request_count == 0, "a position past the ceiling was examined anyway");
		expect(plan.positions_ignored == 2, "the excess is reported either way");
	}

	/* AN EMPTY JOURNAL, WHICH MUST STILL BE ABLE TO FETCH.
	 *
	 * Two senses of empty, and the second is the one that matters. A
	 * journal following nothing plans nothing -- that is the file's first
	 * rule, not a bug. A journal that FOLLOWS an issuer and has received
	 * nothing from it is what `fzn_journal_anchor` at sequence zero is
	 * for, and it must fetch from 1. The integration harness found this
	 * once already, by converging on nothing. */
	{
		fzn_journal_t none, fresh;
		fzn_journal_entry_t ne[2], fe[2];

		fzn_journal_init(&none, ne, 2);
		expect(fzn_sync_plan_fetch(&none, theirs, 3, 100, out, 4, &plan) == FZN_SYNC_OK,
		       "a journal following nothing is not malformed");
		expect(plan.request_count == 0 && plan.unknown_issuers == 3,
		       "a journal following nothing requests nothing and counts what it heard");

		fzn_journal_init(&fresh, fe, 2);
		follow(&fresh, a, 0);
		expect(fzn_sync_plan_fetch(&fresh, theirs, 3, 100, out, 4, &plan) == FZN_SYNC_OK,
		       "a followed issuer with nothing received");
		expect(plan.request_count == 1 && out[0].from == 1 && out[0].count == 14,
		       "an issuer followed from the beginning must fetch from 1");
	}

	/* OFFER is the mirror. */
	expect(fzn_sync_plan_offer(&mine, theirs, 3, 100, out, 4, &plan) == FZN_SYNC_OK,
	       "a well-formed offer plan");
	expect(plan.request_count == 0, "we are behind on A and level on B, so nothing to offer");

	/* A ZERO-LENGTH DIGEST ASKS FOR NOTHING.
	 *
	 * Measured before the fix, against a 64-entry journal a million
	 * records deep with `max_per_request` at 512: a digest of NO positions
	 * produced 64 ranges covering 32,768 records. The cheapest message
	 * there is, answered with megabytes.
	 *
	 * Both spellings of "nothing" are asserted, because a caller with an
	 * empty array and a caller with a null pointer are the same request
	 * and only one of them was ever likely to be tested. */
	{
		fzn_sync_position_t empty[1];

		expect(fzn_sync_plan_offer(&mine, NULL, 0, 100, out, 4, &plan) == FZN_SYNC_OK,
		       "a zero-length digest is not malformed");
		expect(plan.request_count == 0,
		       "a zero-length digest was answered with a full-history offer");
		expect(plan.unknown_issuers == 2,
		       "every stream this host holds is unmentioned, and counted");

		position(&empty[0], c, 1);
		expect(fzn_sync_plan_offer(&mine, empty, 0, 100, out, 4, &plan) == FZN_SYNC_OK,
		       "a zero count with a non-null array");
		expect(plan.request_count == 0, "a zero count must be read as zero positions");
	}

	/* AND A PEER THAT ASKS PROPERLY STILL GETS EVERYTHING.
	 *
	 * The positive control for the case above: the ability to receive a
	 * whole history is not removed, it is moved from a silence to a
	 * statement. `fzn_journal_anchor` at sequence zero produces a position
	 * of zero in the peer's digest, and that is offered from 1. */
	{
		fzn_sync_position_t asked[2];

		position(&asked[0], a, 0);
		position(&asked[1], b, 3);

		expect(fzn_sync_plan_offer(&mine, asked, 2, 100, out, 4, &plan) == FZN_SYNC_OK,
		       "an offer to a peer that stated a position of zero");
		expect(plan.request_count == 2, "a stated zero must be offered from the start");
		expect(plan.unknown_issuers == 0, "both streams were mentioned");
		expect(out[0].from == 1 && out[0].count == 10,
		       "a position of zero is offered from 1");
		expect(out[1].from == 4 && out[1].count == 2, "and a real position from after it");
	}

	{
		fzn_sync_position_t behind[1];

		position(&behind[0], a, 3);

		expect(fzn_sync_plan_offer(&mine, behind, 1, 100, out, 4, &plan) == FZN_SYNC_OK,
		       "an offer to a peer that is behind");
		/* B WAS OFFERED HERE ONCE, AND IS NOT NOW. This assertion read
		 * `== 2` under the name "A's gap and B, which they have never
		 * seen", which is the amplifier written down as a contract. */
		expect(plan.request_count == 1, "only the stream they mentioned is offered");
		expect(plan.unknown_issuers == 1, "B is unmentioned, so it is counted");
		expect(!plan_names(out, &plan, b), "an unmentioned stream was offered anyway");

		/* Nothing is offered from before the beginning. */
		for (size_t i = 0; i < plan.request_count; i++)
			expect(out[i].from >= 1, "an offer must start at one or later");
	}

	/* THE PLAN IS CLEARED BEFORE THE ARGUMENTS ARE CHECKED.
	 *
	 * A caller reusing one plan per round is the obvious way to write the
	 * loop, and a refusal used to leave every field holding the previous
	 * round's numbers. Measured: a plan pre-filled with 0x33 came back from
	 * a refused call with `request_count = 3689348814741910323`, which is a
	 * length a caller iterates. `fzn_sync_digest` in the same file already
	 * cleared `*dropped` before validating, and `fzn_link_snapshot` copied
	 * that shape citing it by name; the two planners were the odd ones out.
	 *
	 * 0x33 rather than a small number on purpose: a stale field holding 3
	 * looks like a plausible plan, and a test asserting a small number
	 * cannot tell "cleared" from "left alone" if the previous round wrote
	 * a zero. */
	{
		const uint8_t *fields;
		int all_zero = 1;

		memset(&plan, 0x33, sizeof(plan));
		expect(fzn_sync_plan_fetch(&mine, theirs, 3, 0, out, 4, &plan) ==
		               FZN_SYNC_ERR_MALFORMED,
		       "a refused fetch");
		fields = (const uint8_t *)&plan;
		for (size_t i = 0; i < sizeof(plan); i++)
			if (fields[i] != 0)
				all_zero = 0;
		expect(all_zero, "a refused fetch left the caller's plan holding stale numbers");

		memset(&plan, 0x33, sizeof(plan));
		expect(fzn_sync_plan_offer(&mine, theirs, 3, 0, out, 4, &plan) ==
		               FZN_SYNC_ERR_MALFORMED,
		       "a refused offer");
		all_zero = 1;
		for (size_t i = 0; i < sizeof(plan); i++)
			if (fields[i] != 0)
				all_zero = 0;
		expect(all_zero, "a refused offer left the caller's plan holding stale numbers");
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
	expect(fzn_sync_plan_offer(&mine, theirs, 3, 100, out, 4, NULL) == FZN_SYNC_ERR_MALFORMED,
	       "nowhere to put the offer plan");
	expect(fzn_sync_plan_fetch(&mine, NULL, 0, 100, out, 4, &plan) == FZN_SYNC_OK,
	       "a peer that reported nothing is not malformed");

	printf("sync_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
