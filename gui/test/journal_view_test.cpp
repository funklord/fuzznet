/* Tests for gui/journal_view.cpp, headless.
 *
 * THE CASE THIS FILE EXISTS FOR is that `fzn_journal_next` answers 1 for an
 * issuer never seen AND for a followed stream that has said nothing. Both
 * want sequence 1; only one is listening. "Why am I getting nothing from Bob"
 * has two opposite answers -- Bob sent nothing, or this host never followed
 * Bob -- and the number answers neither.
 *
 * The second is the full table. journal.h refuses rather than evicts, because
 * "dropping an issuer to make room forgets what was seen from it, and the
 * next record from that issuer is then accepted at any sequence -- which
 * readmits everything it ever sent. A visible refusal a consumer can alarm on
 * is the smaller harm." Visible only if somebody shows it: every row on a full
 * journal still looks healthy.
 */

#include "../journal_view.h"

extern "C" {
#include "../../record/record.h"
}

#include <QApplication>

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
	fprintf(stderr, "  FAIL journal_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

#define SLOTS 2u

static fzn_journal_entry_t ROWS[SLOTS];

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_journal_view view;
	fzn_journal_t journal;
	uint8_t bob[FZN_PUBKEY_LEN];
	uint8_t carol[FZN_PUBKEY_LEN];
	QString untracked;

	memset(bob, 0xb0, sizeof(bob));
	memset(carol, 0xc0, sizeof(carol));

	CHECK(view.shown_state() == fzn_journal_view::NOTHING,
	      "a fresh view is not in the no-journal state");

	CHECK(fzn_journal_init(&journal, ROWS, SLOTS) == FZN_JOURNAL_OK,
	      "the journal would not init");

	/* NOT FOLLOWED. The library would answer "wants 1" here. */
	view.show_stream(&journal, bob, 5u);
	CHECK(view.shown_state() == fzn_journal_view::UNTRACKED,
	      "an unfollowed peer was not shown as unfollowed");
	untracked = view.state_text();
	CHECK(fzn_journal_next(&journal, bob, 5u) == 1u,
	      "the library does not answer 1 for an unfollowed peer, so this case "
	      "proves nothing about the pair");

	/* FOLLOWED AND SILENT. The library answers 1 again -- same number,
	 * opposite meaning. */
	CHECK(fzn_journal_anchor(&journal, bob, 5u, 0u) == FZN_JOURNAL_OK, "anchor refused");
	view.show_stream(&journal, bob, 5u);
	CHECK(view.shown_state() == fzn_journal_view::FRESH,
	      "a followed but silent stream was not distinguished from an unfollowed one");
	CHECK(fzn_journal_next(&journal, bob, 5u) == 1u,
	      "the two cases no longer share a number, so the pair is not being tested");
	CHECK(view.state_text() != untracked,
	      "followed-and-silent and never-followed are shown in the same words, so "
	      "a person cannot tell a quiet peer from one nobody is listening to");

	/* TRACKING, with what was received. */
	CHECK(fzn_journal_admit(&journal, bob, 5u, 1u) == FZN_JOURNAL_OK, "admit refused");
	CHECK(fzn_journal_admit(&journal, bob, 5u, 2u) == FZN_JOURNAL_OK, "admit refused");
	view.show_stream(&journal, bob, 5u);
	CHECK(view.shown_state() == fzn_journal_view::TRACKING,
	      "a stream with records was not shown as tracking");
	CHECK(view.state_text().contains(QStringLiteral("2")),
	      "the received position is not on the screen");

	/* APPLYING BEHIND IS ITS OWN LINE, and settling clears it. */
	CHECK(view.state_text().contains(QStringLiteral("not yet applied")),
	      "records received and not applied were reported as settled");
	CHECK(fzn_journal_confirm(&journal, bob, 5u, 2u) == FZN_JOURNAL_OK, "confirm refused");
	view.show_stream(&journal, bob, 5u);
	CHECK(!view.state_text().contains(QStringLiteral("not yet applied")),
	      "a fully applied stream still reported records outstanding");

	/* THE FULL TABLE. Two slots, both taken, and every row still healthy.
	 * The refusal is real: a third issuer cannot be anchored. */
	CHECK(!view.full(), "a journal with room was reported as full");
	CHECK(fzn_journal_anchor(&journal, carol, 9u, 0u) == FZN_JOURNAL_OK,
	      "the second anchor refused");

	view.show_stream(&journal, bob, 5u);
	CHECK(view.full(),
	      "a journal with no room left was not reported as full, and no single "
	      "row reveals it");
	CHECK(view.state_text().contains(QStringLiteral("FULL")),
	      "the table's own state is not on the screen");
	{
		uint8_t dave[FZN_PUBKEY_LEN];

		memset(dave, 0xd0, sizeof(dave));
		CHECK(fzn_journal_anchor(&journal, dave, 1u, 0u) == FZN_JOURNAL_ERR_FULL,
		      "the fixture is not actually refusing new peers, so the warning "
		      "would be false");
	}
	CHECK(view.shown_state() == fzn_journal_view::TRACKING,
	      "a full table changed what the stream's own row says");

	/* AN EXHAUSTED STREAM IS NOT A VERY LARGE WANT.
	 *
	 * There is no way to reach UINT64_MAX by admitting: `admit` advances
	 * by one and refuses a jump. The row is caller-owned memory, so the
	 * position is set directly -- which is the only way this branch is
	 * reachable at all, and it was written with a guard and no case until
	 * the sabotage harness said so. */
	{
		size_t i;
		int placed = 0;

		for (i = 0; i < journal.used; i++)
			if (ROWS[i].stream == 5u &&
			    memcmp(ROWS[i].issuer, bob, FZN_PUBKEY_LEN) == 0) {
				ROWS[i].received = UINT64_MAX;
				ROWS[i].applied = UINT64_MAX;
				placed = 1;
			}
		CHECK(placed, "the fixture could not find the row to exhaust");
		CHECK(fzn_journal_next(&journal, bob, 5u) == UINT64_MAX,
		      "the library does not report this stream as exhausted, so the case "
		      "proves nothing");

		view.show_stream(&journal, bob, 5u);
		CHECK(view.shown_state() == fzn_journal_view::EXHAUSTED,
		      "a stream that has run out was not shown as exhausted");
		CHECK(!view.state_text().contains(QStringLiteral("18446744073709551615")),
		      "an exhausted stream was drawn as a want for record eighteen "
		      "quintillion");
	}

	/* A JOURNAL THAT CANNOT BE WALKED IS NOT A ROW TO DRAW. */
	journal.used = journal.capacity + 1u;
	view.show_stream(&journal, bob, 5u);
	CHECK(view.shown_state() == fzn_journal_view::UNREADABLE,
	      "a journal counting more streams than it holds was walked anyway");
	CHECK(view.state_text() != untracked,
	      "an unreadable journal reads as a peer nobody follows, which is the "
	      "fail-open answer");

	/* THE ASSERTION THAT KEEPS ONE IMPLEMENTATION. sec 193. */
	{
		char want[FZN_JOURNAL_PRINT_MAX];
		fzn_journal_stream_state_t s2 = FZN_JOURNAL_STREAM_UNTRACKED;
		fzn_journal_table_state_t t2 = FZN_JOURNAL_TABLE_FULL;
		size_t len = 0;
		QString expected;

		journal.used = 2u; /* undo the unreadable case above */
		view.show_stream(&journal, bob, 5u);
		CHECK(fzn_journal_print(&journal, bob, 5u, want, sizeof(want), &len, &s2,
		                        &t2) == FZN_JOURNAL_OK,
		      "the printer would not render what the widget was given");
		expected = QString::fromLatin1(want);
		while (expected.endsWith(QLatin1Char('\n')))
			expected.chop(1);
		CHECK(view.state_text() == expected,
		      "the widget's words are not the printer's, so one screen has two "
		      "wordings again");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("journal_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
