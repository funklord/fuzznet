/* Evidence displacing a prior, and the two signals staying apart.
 *
 * The case that matters most is a link that declared itself excellent and is
 * not. Nothing static can express a path that degraded after it was
 * advertised, so a table that trusted the declaration would keep choosing it
 * for ever -- and the failure would be invisible, because the declaration
 * never changes and nothing would contradict it.
 *
 * The second is that a loss must not move the latency estimate. Blending them
 * is exactly the collapsing into one number `sched/` exists to avoid, and it
 * would be undetectable in a single figure of merit.
 */

#include "../link.h"

#include <stdio.h>

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

static void expect_err(fzn_link_err_t got, fzn_link_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		printf("  FAIL: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_link_err_str(got),
		       fzn_link_err_str(want));
	}
}

int main(void)
{
	fzn_link_table_t table;
	fzn_link_entry_t entries[3];
	const fzn_link_entry_t *e;
	fzn_sched_candidate_t snap[4];

	expect_err(fzn_link_table_init(NULL, entries, 3), FZN_LINK_ERR_MALFORMED, "a null table");
	expect_err(fzn_link_table_init(&table, NULL, 3), FZN_LINK_ERR_MALFORMED, "null entries");
	expect_err(fzn_link_table_init(&table, entries, 0), FZN_LINK_ERR_MALFORMED, "no capacity");
	expect_err(fzn_link_table_init(&table, entries, 3), FZN_LINK_OK, "a well-formed table");

	/* THE PRIOR IS THE STARTING ESTIMATE. */
	expect_err(fzn_link_register(&table, 1, 10, 50, 5, 1500), FZN_LINK_OK,
	           "registering a link that declares itself quick");
	e = fzn_link_get(&table, 1);
	expect(e != NULL && e->latency_ms == 50, "the estimate starts at the declaration");
	expect(e != NULL && e->observations == 0, "with no evidence behind it");
	expect(e != NULL && e->usable, "and up until told otherwise");

	expect_err(fzn_link_register(&table, 1, 10, 50, 5, 1500), FZN_LINK_ERR_DUPLICATE,
	           "registering the same id twice");
	expect_err(fzn_link_register(&table, 9, 10, 50, 1001, 1500), FZN_LINK_ERR_MALFORMED,
	           "a loss above one thousand per thousand");

	/* EVIDENCE DISPLACES IT. The link declared 50ms and actually takes 800;
	 * nothing static could have said so, and a table that trusted the
	 * declaration would keep choosing it for ever. */
	for (int i = 0; i < 30; i++)
		expect_err(fzn_link_observe_ack(&table, 1, 800, (uint64_t)(100 + i)), FZN_LINK_OK,
		           "observing a slow round trip");
	e = fzn_link_get(&table, 1);
	expect(e != NULL && e->latency_ms > 700, "the estimate must follow the evidence");
	expect(e != NULL && e->observations == 30, "and count what it saw");
	expect(e != NULL && e->last_seen == 129, "and remember when it last heard anything");

	/* A SUCCESS PULLS LOSS DOWN. Thirty acks from a link that declared 5
	 * per thousand should leave it at or near nothing. */
	expect(e != NULL && e->loss_permille <= 5, "successes must not raise the loss estimate");

	/* A LOSS RAISES LOSS AND LEAVES LATENCY ALONE, which is the separation
	 * the whole design rests on. */
	{
		uint32_t latency_before;
		uint16_t loss_before;

		e = fzn_link_get(&table, 1);
		latency_before = e->latency_ms;
		loss_before = e->loss_permille;

		expect_err(fzn_link_observe_loss(&table, 1, 200), FZN_LINK_OK, "observing a loss");
		e = fzn_link_get(&table, 1);
		expect(e->loss_permille > loss_before, "a loss must raise the loss estimate");
		expect(e->latency_ms == latency_before,
		       "a loss must not move the latency estimate -- there was no round trip");
	}

	/* A LINK THE CONSUMER KNOWS IS DOWN. No measurement can tell this. */
	expect_err(fzn_link_set_usable(&table, 1, 0), FZN_LINK_OK, "marking a link down");
	expect(fzn_link_get(&table, 1)->usable == 0, "and it is down");
	expect_err(fzn_link_set_usable(&table, 1, 1), FZN_LINK_OK, "and up again");

	/* THE SNAPSHOT IS WHAT sched/ CHOOSES FROM. */
	expect_err(fzn_link_register(&table, 2, 20, 30, 2, 1500), FZN_LINK_OK, "a second link");
	{
		size_t dropped = 99;
		size_t n = fzn_link_snapshot(&table, snap, 4, &dropped);
		fzn_class_t any = { 0, 0, 0, 0, 1, 0 };
		size_t chosen = 99;

		expect(n == 2, "both links should appear in the snapshot");
		expect(dropped == 0, "nothing was dropped when everything fitted");
		expect(n == 2 && snap[0].id == 1 && snap[1].id == 2, "with their own ids");
		expect(n == 2 && snap[0].latency_ms > 700,
		       "carrying the measured latency, not the declared one");

		/* And the two modules compose: the measured slow link loses to
		 * the one that has not degraded. */
		expect(fzn_sched_select(snap, n, &any, &chosen) == FZN_SCHED_OK,
		       "selecting from a snapshot");
		expect(chosen == 1, "the link that did not degrade must win on latency");
	}
	/* THE BOUND MUST BE REPORTED, NOT MERELY RESPECTED. This asserted only
	 * the short return, which is satisfied by a snapshot that silently
	 * leaves links out -- and this table never reorders, so the links past
	 * the bound are the same ones on every call. A consumer can be told
	 * "no link satisfies this class" while a healthy link sits one index
	 * past the end, for ever. The old assertion locked that in. */
	{
		size_t dropped = 0;

		expect(fzn_link_snapshot(&table, snap, 1, &dropped) == 1,
		       "a snapshot must respect its bound");
		expect(dropped == 1, "a snapshot did not report the link it left out");
		expect(fzn_link_snapshot(&table, snap, 4, NULL) == 0,
		       "a snapshot with nowhere to report truncation must refuse");
	}

	/* FULL IS REFUSED, NOT EVICTED: forgetting a link discards its
	 * measurements, so the next selection treats a known bad path as
	 * freshly plausible. */
	expect_err(fzn_link_register(&table, 3, 1, 1, 0, 1500), FZN_LINK_OK, "a third link");
	expect_err(fzn_link_register(&table, 4, 1, 1, 0, 1500), FZN_LINK_ERR_FULL, "a fourth");
	expect(fzn_link_get(&table, 1) != NULL, "and the first is still there");

	/* Absent, and arguments. */
	expect_err(fzn_link_observe_ack(&table, 99, 10, 1), FZN_LINK_ERR_ABSENT,
	           "observing an unregistered link");
	expect_err(fzn_link_observe_loss(&table, 99, 1), FZN_LINK_ERR_ABSENT,
	           "losing on an unregistered link");
	expect_err(fzn_link_set_usable(&table, 99, 1), FZN_LINK_ERR_ABSENT,
	           "marking an unregistered link");
	expect(fzn_link_get(&table, 99) == NULL, "asking for one");
	expect(fzn_link_get(NULL, 1) == NULL, "asking a null table");
	{
		size_t dropped = 0;

		expect(fzn_link_snapshot(NULL, snap, 4, &dropped) == 0,
		       "snapshotting a null table");
		expect(fzn_link_snapshot(&table, NULL, 4, &dropped) == 0,
		       "snapshotting into nothing");
	}
	expect_err(fzn_link_observe_ack(NULL, 1, 1, 1), FZN_LINK_ERR_MALFORMED, "a null table");

	/* A large round trip must not wrap the average. */
	{
		fzn_link_table_t big;
		fzn_link_entry_t one[1];

		fzn_link_table_init(&big, one, 1);
		fzn_link_register(&big, 7, 0, 4000000000u, 0, 1500);
		fzn_link_observe_ack(&big, 7, 4000000000u, 1);
		expect(fzn_link_get(&big, 7)->latency_ms > 3000000000u,
		       "a large average must not have wrapped");
	}

	/* THE ESTIMATOR MUST BE ABLE TO REACH ITS EXTREMES.
	 *
	 * The shift discards a remainder, so the average stalls as soon as it
	 * comes within one of the sample -- and the direction it stalls in is
	 * always the flattering one, because lower latency and lower loss both
	 * make a link look better. Measured before the fix: a link on which
	 * 100000 consecutive messages were LOST reported 993 permille, so a
	 * link dropping every single message could not report worse than 99.3%
	 * and any hard constraint above that admitted a dead link.
	 *
	 * A hundred observations is far past where the old code stalled -- it
	 * reached 993 within about sixty and never moved again. */
	{
		fzn_link_table_t ext;
		fzn_link_entry_t one[1];
		int i;

		fzn_link_table_init(&ext, one, 1);
		fzn_link_register(&ext, 11, 0, 500, 0, 1500);

		for (i = 0; i < 100; i++)
			fzn_link_observe_loss(&ext, 11, (uint64_t)i);
		expect(fzn_link_get(&ext, 11)->loss_permille == 1000,
		       "a link losing everything must be able to report total loss");

		/* And back down, which truncation already handled -- asserted so
		 * that a fix biased the other way would be caught too. */
		for (i = 0; i < 100; i++)
			fzn_link_observe_ack(&ext, 11, 500, (uint64_t)i);
		expect(fzn_link_get(&ext, 11)->loss_permille == 0,
		       "a link losing nothing must be able to report no loss");
		expect(fzn_link_get(&ext, 11)->latency_ms == 500,
		       "a steady 500 ms link must estimate 500 ms, not a little under");
	}

	printf("link_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
