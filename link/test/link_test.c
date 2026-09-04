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
#include <string.h>

static int failures;
static int checks;

static void expect(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "  FAIL: %s\n", what);
	}
}

static void expect_err(fzn_link_err_t got, fzn_link_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		fprintf(stderr, "  FAIL: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_link_err_str(got),
		       fzn_link_err_str(want));
	}
}

/*
 * EVERY OPERAND OF EVERY GUARD, not the first one of each.
 *
 * `usable()` is a conjunction and the suite only ever failed its first
 * operand, so `make coverage` reported the rest as never taken both ways
 * while the guard looked tested. sec 88 measured what an unreached operand
 * is worth: the operand after the first is what stands between a partially
 * initialised caller and a null dereference.
 *
 * A struct with `entries` NULL, or with `used` past `capacity`, cannot be
 * built through `_init` -- which refuses both. It is built here by hand,
 * because that is the state a caller has who memcpy'd a struct out of a
 * file, or who zeroed one and filled it in halfway.
 */
static void test_the_operands_the_first_one_hides(void)
{
	fzn_link_table_t t;
	fzn_link_entry_t entries[3];

	memset(entries, 0, sizeof(entries));

	expect(fzn_link_get(NULL, 1u) == NULL, "get accepted a null table");

	t.entries = NULL;
	t.capacity = 3u;
	t.used = 0u;
	expect(fzn_link_get(&t, 1u) == NULL, "get accepted a table whose entries are null");

	t.entries = entries;
	t.used = 4u;
	expect(fzn_link_get(&t, 1u) == NULL,
	       "get accepted a table counting more entries than it has room for");
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
		if (!e) {
			expect(0, "the link this block is about is not in the table");
			return 1;
		}
		latency_before = e->latency_ms;
		loss_before = e->loss_permille;

		expect_err(fzn_link_observe_loss(&table, 1, 200), FZN_LINK_OK, "observing a loss");
		e = fzn_link_get(&table, 1);
		expect(e && e->loss_permille > loss_before, "a loss must raise the loss estimate");
		expect(e && e->latency_ms == latency_before,
		       "a loss must not move the latency estimate -- there was no round trip");
	}

	/* A LINK THE CONSUMER KNOWS IS DOWN. No measurement can tell this. */
	expect_err(fzn_link_set_usable(&table, 1, 0), FZN_LINK_OK, "marking a link down");
	{
		const fzn_link_entry_t *down = fzn_link_get(&table, 1);

		expect(down && down->usable == 0, "and it is down");
	}
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
		const fzn_link_entry_t *huge = fzn_link_get(&big, 7);

		expect(huge && huge->latency_ms > 3000000000u,
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
		expect(fzn_link_get(&ext, 11) && fzn_link_get(&ext, 11)->loss_permille == 1000,
		       "a link losing everything must be able to report total loss");

		/* And back down, which truncation already handled -- asserted so
		 * that a fix biased the other way would be caught too. */
		for (i = 0; i < 100; i++)
			fzn_link_observe_ack(&ext, 11, 500, (uint64_t)i);
		expect(fzn_link_get(&ext, 11) && fzn_link_get(&ext, 11)->loss_permille == 0,
		       "a link losing nothing must be able to report no loss");
		expect(fzn_link_get(&ext, 11) && fzn_link_get(&ext, 11)->latency_ms == 500,
		       "a steady 500 ms link must estimate 500 ms, not a little under");
	}

	/* A CORRUPT TABLE MUST BE REFUSED AT EVERY ENTRY POINT, and none of
	 * them was tested.
	 *
	 * `usable_table` guards six functions on `table->used <= capacity`.
	 * Measured: deleting the guard in `fzn_link_register` left this file
	 * green, and an ASan probe on a two-entry heap table with `used = 3`
	 * then reported `heap-buffer-overflow READ of size 4 ... in find
	 * link/link.c:17`. `find` walks `used` entries, so a table claiming
	 * more than it has reads past the array.
	 *
	 * `chain/revocation.c` refuses the same shape for its store and
	 * `revocation_test` covers it; this module had the guard and not the
	 * assertion. The state is reachable the same way it is there -- a
	 * caller-owned struct whose `used` was written by something other
	 * than this library, which is every consumer restoring one from
	 * disk.
	 *
	 * Every entry point is asserted rather than one, because six
	 * functions sharing a guard is six places a later edit can drop it,
	 * and covering one reads exactly like covering the rule.
	 *
	 * BUT ONLY THREE OF THE SIX FAIL BY NAME, and the difference is
	 * worth knowing before somebody trusts this block further than it
	 * goes. Removing the guard was tried at each site:
	 *
	 *   register, observe_loss, set_usable -- a named assertion here.
	 *   observe_ack, get, snapshot         -- the binary SEGFAULTS.
	 *
	 * For those three the guard is what makes the following code
	 * defined at all, so removing it is undefined behaviour rather than
	 * a wrong answer, and no assertion can be more precise than the
	 * crash. That still fails the suite, which is what stops a
	 * regression; it just names its reason to nobody. `wire/seal.c`'s
	 * sealed gate and `chunk/reassembly.c`'s table-full refusal are the
	 * same shape and were found the same way. Recorded rather than
	 * papered over, because "six entry points asserted" would otherwise
	 * read as six clean discriminating checks and it is three. */
	{
		fzn_link_table_t bad;
		fzn_link_entry_t slots[2];
		fzn_sched_candidate_t out[2];

		expect_err(fzn_link_table_init(&bad, slots, 2), FZN_LINK_OK, "a table to corrupt");
		expect_err(fzn_link_register(&bad, 1, 10, 5, 0, 1500), FZN_LINK_OK,
		           "one genuine link first, so the corruption is the only change");

		bad.used = bad.capacity + 1u;

		expect_err(fzn_link_register(&bad, 2, 10, 5, 0, 1500), FZN_LINK_ERR_MALFORMED,
		           "register accepted a table claiming more entries than it has");
		expect_err(fzn_link_observe_ack(&bad, 1, 5, 0), FZN_LINK_ERR_MALFORMED,
		           "observe_ack accepted a corrupt table");
		expect_err(fzn_link_observe_loss(&bad, 1, 0), FZN_LINK_ERR_MALFORMED,
		           "observe_loss accepted a corrupt table");
		expect_err(fzn_link_set_usable(&bad, 1, 0), FZN_LINK_ERR_MALFORMED,
		           "set_usable accepted a corrupt table");
		expect(fzn_link_get(&bad, 1) == NULL, "get answered from a corrupt table");
		expect(fzn_link_snapshot(&bad, out, 2, 0) == 0,
		       "snapshot read from a corrupt table");

		bad.used = 1u;
		expect(fzn_link_get(&bad, 1) != NULL,
		       "the table stopped working once repaired, so the checks above "
		       "may be refusing for some other reason");
	}

	/* INIT LEAVES THE CALLER'S ENTRY ARRAY IN A KNOWN STATE.
	 *
	 * No lookup in link.c can observe it -- every loop there is bounded by
	 * `used` -- so removing the zeroing fails nothing, which is how
	 * `make sabotage` found it. It is held anyway because what would remove
	 * it is somebody measuring exactly that and concluding it is dead, and a
	 * later lookup that scans `capacity` would need it. project.md sec 39
	 * has the reasoning once; three sibling modules carry the same eight
	 * lines and the same case.
	 *
	 * Determinism is asserted rather than a value: init from dirty memory
	 * must equal init from clean. The header promises nothing about what a
	 * fresh entry contains, and this case is not the place to invent it. */
	{
		fzn_link_table_t from_dirty, from_clean;
		fzn_link_entry_t dirty_entries[3], clean_entries[3];

		memset(dirty_entries, 0xab, sizeof(dirty_entries));
		memset(clean_entries, 0, sizeof(clean_entries));
		expect(memcmp(dirty_entries, clean_entries, sizeof(dirty_entries)) != 0,
		       "the two arrays start equal, so the comparison below cannot fail");

		expect(fzn_link_table_init(&from_dirty, dirty_entries, 3) == FZN_LINK_OK,
		       "init refused a dirty array");
		expect(fzn_link_table_init(&from_clean, clean_entries, 3) == FZN_LINK_OK,
		       "init refused a clean array");
		expect(memcmp(dirty_entries, clean_entries, sizeof(dirty_entries)) == 0,
		       "init left the caller's bytes in the entry array, so what a fresh "
		       "table holds depends on what its memory held");
	}

	test_the_operands_the_first_one_hides();

	printf("link_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
