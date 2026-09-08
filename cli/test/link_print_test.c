/* Tests for cli/link_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is that a declared latency and a measured one
 * render as the same kind of number, and `link.h` says why that matters: it
 * seeds an estimate with the far end's claim so `sched/` has no cliff in it,
 * which leaves REPORTING as the place where a stranger's assertion can be
 * read as evidence. A line that shows "12 ms" for a link nobody has ever sent
 * a packet on has to say so on the number.
 *
 * THE SECOND IS THAT ALL-DOWN IS NOT EMPTY. No links means nobody has
 * configured a path; every link unusable means somebody has and they are
 * switched off. Those send an operator to different halves of the system.
 */

#include "../link_print.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL link_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

int main(void)
{
	fzn_link_entry_t entries[8];
	fzn_link_table_t table;
	char line[FZN_LINK_PRINT_MAX];
	char none_line[FZN_LINK_PRINT_MAX];
	char down_line[FZN_LINK_PRINT_MAX];
	char declared_line[FZN_LINK_PRINT_MAX];
	fzn_link_line_t state = FZN_LINK_LINE_MEASURED;
	size_t unmeasured = 99u;
	size_t len = 0u;

	/* NO TABLE IS THE ZERO VALUE. */
	CHECK(fzn_link_print(NULL, line, sizeof(line), &len, &state, &unmeasured) ==
	              FZN_LINK_OK,
	      "a null table would not render");
	CHECK(state == FZN_LINK_LINE_NONE, "a null table was not reported as no path");
	CHECK(unmeasured == 0u, "a null table reported unmeasured links");
	memcpy(none_line, line, sizeof(line));

	CHECK(fzn_link_table_init(&table, entries, 8u) == FZN_LINK_OK, "init refused");
	CHECK(fzn_link_print(&table, line, sizeof(line), &len, &state, &unmeasured) ==
	              FZN_LINK_OK,
	      "an empty table would not render");
	CHECK(state == FZN_LINK_LINE_NONE, "an empty table was not reported as no path");
	CHECK(strcmp(line, none_line) == 0,
	      "an empty table and an absent one read differently, which claims a "
	      "distinction link.h does not make -- neither holds a link");

	/* EVERY LINK UNUSABLE IS NOT AN EMPTY TABLE. */
	CHECK(fzn_link_register(&table, 1u, 10u, 40u, 0u, 1200u) == FZN_LINK_OK,
	      "register refused");
	CHECK(fzn_link_register(&table, 2u, 20u, 90u, 5u, 1200u) == FZN_LINK_OK,
	      "register refused");
	CHECK(fzn_link_set_usable(&table, 1u, 0) == FZN_LINK_OK, "set_usable refused");
	CHECK(fzn_link_set_usable(&table, 2u, 0) == FZN_LINK_OK, "set_usable refused");
	CHECK(fzn_link_print(&table, line, sizeof(line), &len, &state, &unmeasured) ==
	              FZN_LINK_OK,
	      "an all-down table would not render");
	CHECK(state == FZN_LINK_LINE_ALL_DOWN, "every link unusable was not ALL_DOWN");
	CHECK(strcmp(line, none_line) != 0,
	      "a host with two switched-off paths reads exactly like one with none, "
	      "which sends an operator to configuration instead of to the interfaces");
	CHECK(unmeasured == 0u,
	      "an unusable link was counted as one sched might choose on a stranger's "
	      "word, so switching a bad path off would RAISE the count");
	memcpy(down_line, line, sizeof(line));

	/* THE CASE THIS FILE EXISTS FOR. Usable, and every number is a claim. */
	CHECK(fzn_link_set_usable(&table, 1u, 1) == FZN_LINK_OK, "set_usable refused");
	CHECK(fzn_link_set_usable(&table, 2u, 1) == FZN_LINK_OK, "set_usable refused");
	CHECK(fzn_link_print(&table, line, sizeof(line), &len, &state, &unmeasured) ==
	              FZN_LINK_OK,
	      "an unmeasured table would not render");
	CHECK(state == FZN_LINK_LINE_UNMEASURED,
	      "a table nobody has measured was reported as measured");
	CHECK(unmeasured == 2u, "both usable links should still be on their priors");
	CHECK(strstr(line, "the far end's claim") != NULL,
	      "a latency nobody has ever measured was printed as a plain number, so a "
	      "stranger's assertion is shown in the typeface of evidence");
	CHECK(strstr(line, "still on a declared metric") == NULL,
	      "the unmeasured line says the same thing twice, which reads as two "
	      "findings when every usable link is the one finding");
	CHECK(strcmp(line, down_line) != 0, "usable links read as switched-off ones");
	memcpy(declared_line, line, sizeof(line));

	/* MEASURED, and the line must not read like the declared one. */
	CHECK(fzn_link_observe_ack(&table, 1u, 40u, 1000u) == FZN_LINK_OK,
	      "observe_ack refused");
	CHECK(fzn_link_print(&table, line, sizeof(line), &len, &state, &unmeasured) ==
	              FZN_LINK_OK,
	      "a measured table would not render");
	CHECK(state == FZN_LINK_LINE_MEASURED, "an observed usable link was not MEASURED");
	CHECK(strcmp(line, declared_line) != 0,
	      "one observation changed nothing on the line");
	CHECK(unmeasured == 1u,
	      "the other usable link is still on its declared metric and the state "
	      "cannot say so, which is why the count is a separate out-parameter");
	CHECK(strstr(line, "still on a declared metric") != NULL,
	      "a MEASURED table said nothing about the links sched may still choose "
	      "on a stranger's word");

	/*
	 * THE HAZARD `link.h` NAMES, ARRIVING BY THE DOOR IT LEFT OPEN.
	 *
	 * A link asserted to be fast that nobody has ever used outranks a
	 * measured one on estimate alone -- which is exactly why link.h seeds
	 * the prior rather than answering "what latency does an unmeasured
	 * link have?" with zero. Selection is defended; the LINE is not, and
	 * the number a person reads is the lowest one. So when the lowest
	 * estimate belongs to a link with no observations, the marker has to
	 * be on THAT number, even though the table as a whole is MEASURED.
	 */
	{
		fzn_link_entry_t fresh[4];
		fzn_link_table_t mixed;

		CHECK(fzn_link_table_init(&mixed, fresh, 4u) == FZN_LINK_OK, "init refused");
		CHECK(fzn_link_register(&mixed, 1u, 10u, 200u, 0u, 1200u) == FZN_LINK_OK,
		      "register refused");
		CHECK(fzn_link_observe_ack(&mixed, 1u, 200u, 1000u) == FZN_LINK_OK,
		      "observe_ack refused");
		/* Asserted to be five times faster, and never used. */
		CHECK(fzn_link_register(&mixed, 2u, 10u, 40u, 0u, 1200u) == FZN_LINK_OK,
		      "register refused");

		CHECK(fzn_link_print(&mixed, line, sizeof(line), &len, &state,
		                     &unmeasured) == FZN_LINK_OK,
		      "the mixed table would not render");
		CHECK(state == FZN_LINK_LINE_MEASURED,
		      "a table with one observed usable link was not MEASURED");
		CHECK(unmeasured == 1u, "the asserted link was not counted");
		CHECK(strstr(line, "40 ms DECLARED") != NULL,
		      "the lowest number on the line belongs to a link nobody has ever "
		      "used and is printed as though it were measured, which is the "
		      "hazard link.h seeds the prior to avoid -- defended in selection "
		      "and open in reporting");
	}

	/* EVIDENCE ON A LINK NOTHING CAN CHOOSE IS NOT EVIDENCE. Switching the
	 * only observed link off must drop the state, not leave it MEASURED on
	 * the strength of a path no selection will return. */
	CHECK(fzn_link_set_usable(&table, 1u, 0) == FZN_LINK_OK, "set_usable refused");
	CHECK(fzn_link_print(&table, line, sizeof(line), &len, &state, &unmeasured) ==
	              FZN_LINK_OK,
	      "the table would not render");
	CHECK(state == FZN_LINK_LINE_UNMEASURED,
	      "the only measured link was switched off and the table still claimed "
	      "evidence, so a caller reads MEASURED about a path nothing will choose");
	CHECK(unmeasured == 1u, "the remaining usable link is unmeasured");

	/* THE ORDERING IS LOAD-BEARING, since the header offers it as a test. */
	CHECK(FZN_LINK_LINE_NONE < FZN_LINK_LINE_ALL_DOWN &&
	              FZN_LINK_LINE_ALL_DOWN < FZN_LINK_LINE_UNMEASURED &&
	              FZN_LINK_LINE_UNMEASURED < FZN_LINK_LINE_MEASURED,
	      "the states no longer ascend, so `>= UNMEASURED` has stopped meaning "
	      "there is a path to try");

	/* BOTH OUT-PARAMETERS ARE REQUIRED, and a refusal is conservative. */
	CHECK(fzn_link_print(&table, line, sizeof(line), &len, NULL, &unmeasured) ==
	              FZN_LINK_ERR_MALFORMED,
	      "the state was optional after all");
	CHECK(fzn_link_print(&table, line, sizeof(line), &len, &state, NULL) ==
	              FZN_LINK_ERR_MALFORMED,
	      "the unmeasured count was optional after all");
	{
		char small[8];
		size_t needed = 0u;

		memset(small, '@', sizeof(small));
		state = FZN_LINK_LINE_MEASURED;
		unmeasured = 99u;
		CHECK(fzn_link_print(&table, small, sizeof(small), &needed, &state,
		                     &unmeasured) == FZN_LINK_ERR_MALFORMED,
		      "a buffer too small was written anyway");
		CHECK(needed > sizeof(small), "the size needed was not reported");
		CHECK(small[0] == '@', "a refused render left bytes in the buffer");
		CHECK(state == FZN_LINK_LINE_NONE,
		      "a refused render left a state claiming a path");
		CHECK(unmeasured == 0u, "a refused render left a stale count");
	}

	/* The longest line this can produce must fit what the header promises. */
	{
		fzn_link_entry_t many[16];
		fzn_link_table_t big;
		uint32_t i;

		CHECK(fzn_link_table_init(&big, many, 16u) == FZN_LINK_OK, "init refused");
		for (i = 0u; i < 16u; i++)
			/* THE WIDEST OF EVERY FIELD. 1000 permille is the most
			 * `fzn_link_register` accepts -- it refuses above that,
			 * which is how this fixture found out. */
			CHECK(fzn_link_register(&big, i, 4000000000u, 4000000000u,
			                        1000u, 4000000000u) == FZN_LINK_OK,
			      "register refused");
		CHECK(fzn_link_observe_ack(&big, 0u, 4000000000u, 1u) == FZN_LINK_OK,
		      "observe_ack refused");
		CHECK(fzn_link_print(&big, line, sizeof(line), &len, &state, &unmeasured) ==
		              FZN_LINK_OK,
		      "the widest line does not fit FZN_LINK_PRINT_MAX");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("link_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
