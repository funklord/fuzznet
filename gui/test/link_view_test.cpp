/* Tests for gui/link_view.cpp, headless.
 *
 * THE CASE THIS FILE EXISTS FOR is the one the printer cannot cover. sec 202:
 * `fzn_link_print` can say that N usable links are still on a declared
 * metric, and it names only the lowest, so an operator reading the line knows
 * a claim is in there and not which row it is. This widget's rows say which,
 * and that is the whole of what it adds -- so a row that showed a declared
 * latency the same way it shows a measured one would leave the widget with no
 * reason to exist.
 *
 * NO SCREEN IS NEEDED AND NONE IS OPENED. `QT_QPA_PLATFORM=offscreen` is set
 * before the QApplication is built, the arrangement `qtty` relies on.
 */

extern "C" {
#include "../../link/link.h"
#include "../../cli/link_print.h"
}

#include "../link_view.h"

#include <QApplication>
#include <QString>
#include <QStringList>

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
	fprintf(stderr, "  FAIL link_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* A NODE FOR THE HOSTED VIEW, sec 1121: two legs, one answering at 42 ms
 * and heard 3 s ago, one asked four times and never answered. */
static int legs_silent, legs_unanswered;

static size_t legs_node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (legs_silent)
		return 0;
	if (!strcmp(line, "list leg 0") && legs_unanswered)
		return (size_t)snprintf(reply, cap, "ok 1 1 0 198.51.100.2:4000,-,-,0,-,4,0,4,0\n");
	if (!strcmp(line, "list leg 0"))
		return (size_t)snprintf(reply, cap, "ok 2 1 0 192.0.2.7:4000,42,25,1,3,10,9,9,9 "
		                                    "198.51.100.2:4000,-,-,0,-,4,0,4,0\n");
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	/* Before the QApplication, or it has already chosen a platform. */
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_link_view view;
	fzn_link_entry_t entries[8];
	fzn_link_table_t table;
	QString none_summary, down_summary;

	/* A FRESH WIDGET HAS NO PATH AND DRAWS NO TABLE. A column header with
	 * nothing under it reads as a table that failed to load. */
	CHECK(view.shown_state() == fzn_link_view::NONE, "a fresh widget claimed a path");
	CHECK(view.rows_text().isEmpty(), "a widget with no links drew a header anyway");
	CHECK(!view.summary_text().isEmpty(), "a widget with no links said nothing");
	CHECK(!view.rows_truncated(), "a widget with no links reported truncation");
	none_summary = view.summary_text();

	CHECK(fzn_link_table_init(&table, entries, 8u) == FZN_LINK_OK, "init refused");
	CHECK(fzn_link_register(&table, 1u, 10u, 40u, 0u, 1200u) == FZN_LINK_OK,
	      "register refused");
	CHECK(fzn_link_register(&table, 2u, 20u, 90u, 25u, 1200u) == FZN_LINK_OK,
	      "register refused");

	/* ALL DOWN IS NOT EMPTY, on screen as in the line. */
	CHECK(fzn_link_set_usable(&table, 1u, 0) == FZN_LINK_OK, "set_usable refused");
	CHECK(fzn_link_set_usable(&table, 2u, 0) == FZN_LINK_OK, "set_usable refused");
	view.show_links(&table);
	CHECK(view.shown_state() == fzn_link_view::ALL_DOWN,
	      "two switched-off paths were shown as no paths at all");
	CHECK(view.summary_text() != none_summary,
	      "a host with paths it may not use reads exactly like one with none");
	CHECK(!view.rows_text().isEmpty(),
	      "the rows vanished when the links were switched off, so an operator "
	      "cannot see which path to bring back");
	down_summary = view.summary_text();

	CHECK(fzn_link_set_usable(&table, 1u, 1) == FZN_LINK_OK, "set_usable refused");
	CHECK(fzn_link_set_usable(&table, 2u, 1) == FZN_LINK_OK, "set_usable refused");

	/*
	 * THE CASE THIS FILE EXISTS FOR.
	 *
	 * Link 1 is measured, link 2 has never been observed. The summary can
	 * only say that one usable link is on a declared metric. The rows have
	 * to say it is link 2.
	 */
	CHECK(fzn_link_observe_ack(&table, 1u, 40u, 1000u) == FZN_LINK_OK,
	      "observe_ack refused");
	view.show_links(&table);
	CHECK(view.shown_state() == fzn_link_view::MEASURED, "an observed link was not MEASURED");
	CHECK(view.unmeasured() == 1u, "the declared link was not counted");
	{
		QStringList lines = view.rows_text().split(QLatin1Char('\n'));
		QString measured_row, declared_row;
		int i;

		CHECK(lines.size() == 3, "a header and two links did not produce three lines");
		for (i = 1; i < lines.size(); i++) {
			if (lines.at(i).trimmed().startsWith(QStringLiteral("1 ")))
				measured_row = lines.at(i);
			if (lines.at(i).trimmed().startsWith(QStringLiteral("2 ")))
				declared_row = lines.at(i);
		}

		CHECK(!measured_row.isEmpty() && !declared_row.isEmpty(),
		      "the rows are not one per link");
		CHECK(declared_row.contains(QStringLiteral("declared")),
		      "the row for a link nobody has measured shows its prior as though "
		      "somebody had measured it, which is the one thing this widget adds "
		      "over the printer's line");
		CHECK(!measured_row.contains(QStringLiteral("declared")),
		      "a measured link was marked declared");
		CHECK(measured_row != declared_row,
		      "a measured link and an asserted one render identically");
		CHECK(measured_row.contains(QStringLiteral("0.0%")),
		      "a measured link does not show the loss it measured");
		CHECK(!declared_row.contains(QStringLiteral("2.5%")),
		      "a loss nobody has observed was shown as a rate, so the far end's "
		      "guess is displayed in the column a measurement goes in");

		/* THE COLUMNS ARE IN THE STRING. sec 158's argument: an
		 * alignment a layout owns rearranges with the window, and two
		 * readings of one table that do not line up cannot be
		 * compared. */
		CHECK(measured_row.size() == declared_row.size() &&
		              measured_row.size() == lines.at(0).size(),
		      "the rows are not column-aligned in the text, so the table "
		      "rearranges with the window");
	}

	/*
	 * THE WIDGET AND THE PRINTER MUST AGREE. Both are asked here because
	 * the widget takes its classification from the printer -- so this
	 * pins the wiring, and mutating the printer's classification reddens
	 * this rather than leaving a widget that quietly disagrees.
	 */
	{
		char line[FZN_LINK_PRINT_MAX];
		fzn_link_line_t said = FZN_LINK_LINE_NONE;
		size_t len = 0u;
		size_t unmeasured = 0u;

		CHECK(fzn_link_print(&table, line, sizeof(line), &len, &said, &unmeasured) ==
		              FZN_LINK_OK,
		      "the printer refused a table the widget accepted");
		CHECK(view.summary_text() == QString::fromLatin1(line),
		      "the widget composed its own summary instead of showing the "
		      "printer's, which is sec 168's duplication returning");
		CHECK(view.unmeasured() == unmeasured,
		      "the widget and the printer disagree about how many usable links "
		      "are still running on a stranger's word");
		CHECK(static_cast<int>(view.shown_state()) == static_cast<int>(said),
		      "the widget's state and the printer's have drifted apart");
	}

	/* MORE LINKS THAN ROWS IS SAID, NOT SILENT. */
	{
		fzn_link_entry_t many[FZN_LINK_VIEW_ROWS_MAX + 4u];
		fzn_link_table_t big;
		uint32_t i;

		CHECK(fzn_link_table_init(&big, many, FZN_LINK_VIEW_ROWS_MAX + 4u) ==
		              FZN_LINK_OK,
		      "init refused");
		for (i = 0u; i < FZN_LINK_VIEW_ROWS_MAX + 4u; i++)
			CHECK(fzn_link_register(&big, i, 10u, 40u, 0u, 1200u) == FZN_LINK_OK,
			      "register refused");

		view.show_links(&big);
		CHECK(view.rows_truncated(),
		      "more links than rows were drawn without saying so, and "
		      "fzn_link_snapshot's rule is that the ones past a bound are always "
		      "the same ones");
		CHECK(view.rows_text().contains(QStringLiteral("more not shown")),
		      "the truncation is in an accessor the person reading the rows will "
		      "never call");

		view.show_links(&table);
		CHECK(!view.rows_truncated(),
		      "the truncation flag survived a table that does not truncate");
	}

	/* A NULL TABLE IS THE NO-PATH CASE, not a stale display. */
	view.show_links(nullptr);
	CHECK(view.shown_state() == fzn_link_view::NONE, "a null table left the last state");
	CHECK(view.rows_text().isEmpty(), "a null table left the last rows on screen");
	CHECK(view.summary_text() == none_summary, "a null table did not read as no path");
	CHECK(view.summary_text() != down_summary, "no path reads as paths switched off");
	CHECK(view.unmeasured() == 0u, "a null table left a stale count");

	/* ---- HOSTED, sec 1121: the view asks the node itself. */
	{
		fzn_link_view hosted(legs_node, nullptr);
		QStringList rows;

		CHECK(hosted.refresh(), "the hosted view did not read the legs");
		rows = hosted.rows_text().split(QLatin1Char('\n'));
		CHECK(hosted.shown_state() == fzn_link_view::MEASURED && hosted.unmeasured() == 1u,
		      "one answering leg of two was not MEASURED with one unmeasured");
		CHECK(hosted.summary_text() == "2 link(s), 1 answering", "the hosted summary was wrong");
		CHECK(rows.size() == 3 && rows.value(1).startsWith("192.0.2.7:4000")
		              && rows.value(1).contains("42 ms") && rows.value(1).contains("2.5%")
		              && rows.value(1).contains("9/10")
		              && rows.value(1).contains("3 s ago"),
		      "the answering leg's row lacks its address, round trip, answers or age");
		CHECK(rows.value(2).startsWith("198.51.100.2:4000") && rows.value(2).contains("0/4")
		              && !rows.value(2).contains("%")
		              && rows.value(2).contains("never"),
		      "the silent leg was not said to have never answered");
		legs_unanswered = 1;
		CHECK(hosted.refresh() && hosted.shown_state() == fzn_link_view::UNMEASURED
		              && hosted.summary_text() == "1 link(s), 0 answering",
		      "a leg that never answered read as measured");
		legs_silent = 1;
		CHECK(!hosted.refresh() && hosted.summary_text() == "The node did not answer."
		              && hosted.rows_text().isEmpty(),
		      "a silent node was not said so, or its old rows stayed");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("link_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
