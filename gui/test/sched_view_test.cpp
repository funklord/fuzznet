/* Tests for gui/sched_view.cpp, headless.
 *
 * THE CASE THIS FILE EXISTS FOR is the line that names no fix.
 * `cli/sched_print` says "no single change helps" when links were excluded for
 * different reasons -- deliberately, because naming any one bound would send a
 * reader to change the thing that cannot help. That leaves a reader told there
 * is no single fix and nothing about where the several are, and the rows are
 * the only place that can be said.
 *
 * THE SECOND is that the widget shows the printer's line rather than composing
 * its own, per sec 193. The case below renders the same table through both and
 * requires the summary to be the printer's text, so a second wording cannot
 * drift in.
 *
 * NO SCREEN IS NEEDED AND NONE IS OPENED. `QT_QPA_PLATFORM=offscreen` is set
 * before the QApplication is built, the arrangement `qtty` relies on.
 */

extern "C" {
#include "../../cli/sched_print.h"
#include "../../sched/sched.h"
}

#include "../sched_view.h"

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
	fprintf(stderr, "  FAIL sched_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_sched_candidate_t link_of(uint32_t id, uint32_t latency, uint16_t loss, uint32_t mtu,
                                     int usable)
{
	fzn_sched_candidate_t l;

	memset(&l, 0, sizeof(l));
	l.id = id;
	l.metric = 10u;
	l.latency_ms = latency;
	l.loss_permille = loss;
	l.mtu = mtu;
	l.usable = usable;
	return l;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_sched_view view;
	fzn_sched_candidate_t links[3];
	size_t chosen = 0u;

	static const fzn_class_t VOICE = { 50u, 20u, 1200u, 0u, 1u, 0u };

	/* ---- NOTHING TO SHOW. */
	view.show_choice(nullptr, 0u, &VOICE, FZN_SCHED_ERR_NONE, 0u);
	CHECK(view.shown_state() == fzn_sched_view::NOTHING,
	      "an empty table was given a verdict");
	CHECK(view.rows_text().isEmpty(), "rows were drawn for no links");
	CHECK(view.unusable() == 0u,
	      "a count was reported over a table that was never given");

	/* ---- A LINK CARRIES IT, and the row says WHICH rather than leaving a
	 * reader to compare costs by eye. */
	links[0] = link_of(7u, 10u, 5u, 1500u, 1);
	links[1] = link_of(8u, 20u, 5u, 1500u, 1);
	CHECK(fzn_sched_select(links, 2u, &VOICE, &chosen) == FZN_SCHED_OK, "select refused");
	view.show_choice(links, 2u, &VOICE, FZN_SCHED_OK, chosen);
	CHECK(view.shown_state() == fzn_sched_view::CARRIED,
	      "a carried class was not shown as carried");
	CHECK(view.rows_text().split(QLatin1Char('\n')).size() == 2,
	      "two links did not produce two rows");
	CHECK(view.rows_text().contains(QStringLiteral("CARRYING")),
	      "no row says which link is carrying the traffic");
	CHECK(view.unusable() == 0u, "a link this class admits was counted as unusable");

	/* ---- THE SUMMARY IS THE PRINTER'S LINE, not a second wording. */
	{
		char line[FZN_SCHED_PRINT_MAX];
		size_t len = 0u;
		fzn_sched_line_t said = FZN_SCHED_LINE_NONE;

		CHECK(fzn_sched_print(links, 2u, &VOICE, FZN_SCHED_OK, chosen, line,
		                      sizeof(line), &len, &said) == FZN_SCHED_OK,
		      "the printer refused a table the widget drew");
		CHECK(view.summary_text() == QString::fromLatin1(line).trimmed(),
		      "the widget composed its own summary, so two wordings can drift");
	}

	/* ---- AND THE CASE THIS WIDGET EXISTS FOR. Three links excluded three
	 * ways: the printer names no bound, so the rows must name all three. */
	links[0] = link_of(7u, 500u, 0u, 1500u, 1);  /* slow */
	links[1] = link_of(8u, 10u, 900u, 1500u, 1); /* lossy */
	links[2] = link_of(9u, 10u, 0u, 500u, 1);    /* small */
	view.show_choice(links, 3u, &VOICE, FZN_SCHED_ERR_NONE, 0u);
	CHECK(view.shown_state() == fzn_sched_view::DROPPED,
	      "a dropped class was not shown as dropped");
	CHECK(view.unusable() == 3u, "three excluded links were not all counted");
	CHECK(view.rows_text().contains(QStringLiteral("too slow"))
	              && view.rows_text().contains(QStringLiteral("too lossy"))
	              && view.rows_text().contains(QStringLiteral("MTU too small")),
	      "the rows do not say which link failed which constraint, which is the only "
	      "place that can be said once the line has declined to name a bound");
	CHECK(!view.summary_text().contains(QStringLiteral("max_latency_ms")),
	      "the summary named a bound to change, which the printer refuses to do here");

	/* ---- A DOWN LINK IS DOWN AND NOT SLOW, whatever its latency says: a
	 * link nobody can use has no measurements worth reading. */
	links[0] = link_of(7u, 5000u, 0u, 1500u, 0);
	links[1] = link_of(8u, 10u, 0u, 1500u, 0);
	view.show_choice(links, 2u, &VOICE, FZN_SCHED_ERR_NONE, 0u);
	CHECK(view.rows_text().contains(QStringLiteral("down")),
	      "a link the consumer marked down is not shown as down");
	CHECK(!view.rows_text().contains(QStringLiteral("too slow")),
	      "a down link was described by a measurement nobody can act on");

	/* ---- NOTHING IS TRUNCATED AT THIS SIZE, which is the control for the
	 * flag: a widget that always reported truncation would satisfy every
	 * case above. */
	CHECK(!view.rows_truncated(), "two links were reported as truncated");

	printf("sched_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
