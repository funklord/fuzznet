/* Tests for cli/journal_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is that a caller asks about one stream and
 * needs to be told about the TABLE. sec 186: a full journal refuses every
 * issuer it has not met, the peer being turned away has no row at all, and
 * every row that does exist still looks healthy. So the condition is
 * invisible to anybody who asked the obvious question, and this reports it
 * whether or not they thought to.
 *
 * The second is sec 186's pair: `fzn_journal_next` answers 1 for an issuer
 * never seen AND for a followed stream that has said nothing. The suite
 * asserts the library really does answer 1 for both before checking the
 * printer separates them.
 */

#include "../journal_print.h"

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
	fprintf(stderr, "  FAIL journal_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

#define SLOTS 2u

static fzn_journal_entry_t ROWS[SLOTS];

int main(void)
{
	char line[FZN_JOURNAL_PRINT_MAX];
	char untracked_line[FZN_JOURNAL_PRINT_MAX];
	fzn_journal_t journal;
	fzn_journal_stream_state_t s;
	fzn_journal_table_state_t t;
	uint8_t bob[FZN_PUBKEY_LEN];
	uint8_t carol[FZN_PUBKEY_LEN];
	uint8_t dave[FZN_PUBKEY_LEN];
	size_t len = 0;

	memset(bob, 0xb0, sizeof(bob));
	memset(carol, 0xc0, sizeof(carol));
	memset(dave, 0xd0, sizeof(dave));

	CHECK(fzn_journal_init(&journal, ROWS, SLOTS) == FZN_JOURNAL_OK,
	      "the journal would not init");

	/* NOT FOLLOWED, and the library would answer "wants 1". */
	s = FZN_JOURNAL_STREAM_TRACKING;
	CHECK(fzn_journal_print(&journal, bob, 5u, line, sizeof(line), &len, &s, &t) ==
	              FZN_JOURNAL_OK,
	      "an unfollowed stream would not render");
	CHECK(s == FZN_JOURNAL_STREAM_UNTRACKED, "an unfollowed stream was not untracked");
	CHECK(fzn_journal_next(&journal, bob, 5u) == 1u,
	      "the library does not answer 1 here, so the pair is not being tested");
	memcpy(untracked_line, line, sizeof(line));

	/* FOLLOWED AND SILENT: the same number, the opposite meaning. */
	CHECK(fzn_journal_anchor(&journal, bob, 5u, 0u) == FZN_JOURNAL_OK, "anchor refused");
	CHECK(fzn_journal_print(&journal, bob, 5u, line, sizeof(line), &len, &s, &t) ==
	              FZN_JOURNAL_OK,
	      "a fresh stream would not render");
	CHECK(fzn_journal_next(&journal, bob, 5u) == 1u,
	      "the two cases no longer share a number");
	CHECK(s == FZN_JOURNAL_STREAM_FRESH,
	      "a followed silent stream was not separated from an unfollowed one");
	CHECK(strcmp(line, untracked_line) != 0,
	      "the two print the same line, so a person cannot tell a quiet peer from "
	      "one nobody is listening to");

	/* THE TABLE IS REPORTED WHATEVER WAS ASKED. One slot left. */
	CHECK(t == FZN_JOURNAL_TABLE_ROOM, "a journal with room was called full");

	CHECK(fzn_journal_anchor(&journal, carol, 9u, 0u) == FZN_JOURNAL_OK,
	      "the second anchor refused");

	/* Asked about BOB's stream, told about the TABLE. */
	CHECK(fzn_journal_print(&journal, bob, 5u, line, sizeof(line), &len, &s, &t) ==
	              FZN_JOURNAL_OK,
	      "a full journal would not render");
	CHECK(t == FZN_JOURNAL_TABLE_FULL,
	      "a caller asking about one stream was not told the table is full, and no "
	      "row it could ask about would have said so");
	CHECK(s == FZN_JOURNAL_STREAM_FRESH,
	      "the table's condition changed what the stream's own state says");
	CHECK(strstr(line, "FULL") != NULL, "the table's condition is not on the line");
	CHECK(fzn_journal_anchor(&journal, dave, 1u, 0u) == FZN_JOURNAL_ERR_FULL,
	      "the fixture is not actually refusing peers, so the warning is false");

	/* TRACKING, with the position. */
	CHECK(fzn_journal_admit(&journal, bob, 5u, 1u) == FZN_JOURNAL_OK, "admit refused");
	CHECK(fzn_journal_print(&journal, bob, 5u, line, sizeof(line), &len, &s, &t) ==
	              FZN_JOURNAL_OK,
	      "a tracking stream would not render");
	CHECK(s == FZN_JOURNAL_STREAM_TRACKING, "a stream with a record was not tracking");
	CHECK(strstr(line, "received to 1") != NULL, "the position is not on the line");
	CHECK(strstr(line, "not yet applied") != NULL,
	      "a record received and not applied was not said");

	CHECK(fzn_journal_confirm(&journal, bob, 5u, 1u) == FZN_JOURNAL_OK, "confirm refused");
	CHECK(fzn_journal_print(&journal, bob, 5u, line, sizeof(line), &len, &s, &t) ==
	              FZN_JOURNAL_OK,
	      "a settled stream would not render");
	CHECK(strstr(line, "not yet applied") == NULL,
	      "a settled stream still reported records outstanding");

	/* BOTH OUT-PARAMETERS ARE REQUIRED. */
	CHECK(fzn_journal_print(&journal, bob, 5u, line, sizeof(line), &len, NULL, &t) ==
	              FZN_JOURNAL_ERR_MALFORMED,
	      "the stream state was optional after all");
	CHECK(fzn_journal_print(&journal, bob, 5u, line, sizeof(line), &len, &s, NULL) ==
	              FZN_JOURNAL_ERR_MALFORMED,
	      "the table state was optional -- which for the one a caller did not think "
	      "to ask for is the same as absent");

	/* THE CONSERVATIVE VALUES SURVIVE A REFUSAL. */
	{
		char small[4];
		size_t needed = 0;

		memset(small, '@', sizeof(small));
		s = FZN_JOURNAL_STREAM_TRACKING;
		t = FZN_JOURNAL_TABLE_ROOM;
		CHECK(fzn_journal_print(&journal, bob, 5u, small, sizeof(small), &needed, &s,
		                        &t) == FZN_JOURNAL_ERR_MALFORMED,
		      "a buffer too small was written anyway");
		CHECK(needed > sizeof(small), "the size needed was not reported");
		CHECK(small[0] == '@', "a refused render left bytes in the buffer");
		CHECK(s == FZN_JOURNAL_STREAM_UNTRACKED && t == FZN_JOURNAL_TABLE_FULL,
		      "a refused render left reassuring states behind");
	}

	/* AN UNREADABLE JOURNAL IS ITS OWN ANSWER ON BOTH CHANNELS. */
	journal.used = journal.capacity + 1u;
	CHECK(fzn_journal_print(&journal, bob, 5u, line, sizeof(line), &len, &s, &t) ==
	              FZN_JOURNAL_OK,
	      "an unreadable journal would not render");
	CHECK(s == FZN_JOURNAL_STREAM_UNREADABLE && t == FZN_JOURNAL_TABLE_UNREADABLE,
	      "an unreadable journal reported a position and a capacity");

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("journal_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
