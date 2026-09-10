/* Tests for gui/persist_view.cpp, headless.
 *
 * THE CASE THIS FILE EXISTS FOR is the question a per-slot line cannot
 * answer. `cli/persist_print` says what happened to ONE slot, because that is
 * what a caller asks one call at a time; a person starting a program wants to
 * know whether their identity came back, and that is a fact about the SET.
 *
 * THE SECOND is that a first run must not read as a partial recovery. Nothing
 * stored anywhere is the most common startup there is, and a screen that
 * reported it as four things missing would alarm every new install.
 *
 * NO SCREEN IS NEEDED AND NONE IS OPENED. `QT_QPA_PLATFORM=offscreen` is set
 * before the QApplication is built, the arrangement `qtty` relies on.
 */

extern "C" {
#include "../../cli/persist_print.h"
#include "../../persist/persist.h"
}

#include "../persist_view.h"

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
	fprintf(stderr, "  FAIL persist_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_persist_view_row row_of(fzn_persist_slot_t slot, fzn_persist_err_t err, int had)
{
	fzn_persist_view_row r;

	r.slot = slot;
	r.err = err;
	r.had_stored = had;
	return r;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_persist_view view;
	fzn_persist_view_row rows[5];

	/* ---- NOTHING READ. */
	view.show_slots(nullptr, 0u);
	CHECK(view.shown_state() == fzn_persist_view::NOTHING,
	      "an empty set was given a verdict");
	CHECK(view.rows_text().isEmpty(), "rows were drawn for no slots");
	CHECK(view.missing() == 0u, "a count was reported over a set never given");

	/* ---- EVERYTHING CAME BACK. */
	rows[0] = row_of(FZN_PERSIST_TRUST, FZN_PERSIST_OK, 1);
	rows[1] = row_of(FZN_PERSIST_OWN_PREKEY, FZN_PERSIST_OK, 1);
	rows[2] = row_of(FZN_PERSIST_PEER, FZN_PERSIST_OK, 1);
	view.show_slots(rows, 3u);
	CHECK(view.shown_state() == fzn_persist_view::RECOVERED,
	      "a full recovery was not reported as one");
	CHECK(view.missing() == 0u, "a full recovery reported something missing");
	CHECK(view.rows_text().split(QLatin1Char('\n')).size() == 3,
	      "three slots did not produce three rows");

	/* ---- A FIRST RUN: nothing stored anywhere, and nothing lost. */
	rows[0] = row_of(FZN_PERSIST_TRUST, FZN_PERSIST_ERR_ABSENT, 0);
	rows[1] = row_of(FZN_PERSIST_OWN_PREKEY, FZN_PERSIST_ERR_ABSENT, 0);
	view.show_slots(rows, 2u);
	CHECK(view.shown_state() == fzn_persist_view::FRESH,
	      "a first run was reported as a partial recovery, which would alarm every "
	      "new install");
	CHECK(view.missing() == 0u, "a first run reported slots as missing");
	CHECK(view.summary_text().contains(QStringLiteral("first run")),
	      "the summary does not say this is a first run");

	/* ---- AND THE CASE THIS WIDGET EXISTS FOR. Four recoveries and one
	 * loss: the summary must be about the loss, because a person reads the
	 * first sentence and stops. */
	rows[0] = row_of(FZN_PERSIST_TRUST, FZN_PERSIST_ERR_ABSENT, 1);
	rows[1] = row_of(FZN_PERSIST_OWN_PREKEY, FZN_PERSIST_OK, 1);
	rows[2] = row_of(FZN_PERSIST_PEER, FZN_PERSIST_OK, 1);
	rows[3] = row_of(FZN_PERSIST_SEND_CHAIN, FZN_PERSIST_OK, 1);
	rows[4] = row_of(FZN_PERSIST_RECV_CHAIN, FZN_PERSIST_OK, 1);
	view.show_slots(rows, 5u);
	CHECK(view.shown_state() == fzn_persist_view::INCOMPLETE,
	      "one loss among four recoveries was not reported as incomplete");
	CHECK(view.missing() == 1u, "one loss was not counted");
	CHECK(view.summary_text().contains(QStringLiteral("did not come back")),
	      "the summary is about the recoveries rather than the loss, and a person "
	      "reading the first sentence would stop there");
	CHECK(view.rows_text().contains(QStringLiteral("ATTENTION")),
	      "no row carries the printer's own alarm for the slot that is gone");

	/* ---- THE ROWS ARE IN SLOT ORDER, not sorted by badness, so two
	 * readings of one host line up. */
	{
		QStringList lines = view.rows_text().split(QLatin1Char('\n'));

		CHECK(lines.size() == 5, "five slots did not produce five rows");
		CHECK(lines[0].startsWith(QStringLiteral("trust anchor")),
		      "the first row is not the first slot, so a loss has moved the rows "
		      "under a reader");
		CHECK(lines[4].startsWith(QStringLiteral("receive chain")),
		      "the last row is not the last slot");
	}

	/* ---- A CORRUPT SLOT COUNTS AS MISSING TOO, because it did not come
	 * back either -- and its row still says it is not an attack. */
	rows[0] = row_of(FZN_PERSIST_TRUST, FZN_PERSIST_ERR_SHAPE, 1);
	rows[1] = row_of(FZN_PERSIST_OWN_PREKEY, FZN_PERSIST_OK, 1);
	view.show_slots(rows, 2u);
	CHECK(view.shown_state() == fzn_persist_view::INCOMPLETE,
	      "a corrupt slot was not counted as one that did not come back");
	CHECK(view.missing() == 1u, "a corrupt slot was not counted as missing");
	CHECK(view.rows_text().contains(QStringLiteral("rather than an attack")),
	      "the row does not carry the printer's own words, so the widget has "
	      "composed a second wording that can drift");

	printf("persist_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
