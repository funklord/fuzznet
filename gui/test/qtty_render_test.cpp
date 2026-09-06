/*
 * The widgets, rendered by qtty onto a character cell grid. sec 158.
 *
 * WHY THIS EXISTS SEPARATELY FROM THE OTHER GUI SUITES. Those assert what a
 * widget HOLDS -- the strings a user would read -- and they all passed while
 * the trust view showed a user 63 hex digits of a 64-digit fingerprint at 80
 * columns. The text was whole and the screen was not, and no assertion over
 * the text can see that.
 *
 * So this one asserts the SCREEN, through the same renderer a terminal uses,
 * and it is the only thing here that would have caught that defect.
 *
 * IT IS NOT PART OF `make check`, and that is deliberate rather than
 * reluctant. It needs a qtty checkout, and qtty is pre-alpha with the API
 * movement its README promises -- so a target wired into the default gate
 * would break this tree whenever that one moved, and a gate that breaks for
 * somebody else's reasons is a gate people switch off. `make qtty
 * QTTY_DIR=../qtty` is the same arrangement `make schema SITU_DIR=../situ`
 * uses for the same reason, down to extracting their HEAD read-only rather
 * than building in their tree.
 *
 * THE PROTOCOL IS THEIRS AND GETTING IT WRONG LOOKS LIKE A DEFECT IN US. A
 * widget must have WA_DontShowOnScreen, be resized in CELL units through
 * `GridMetrics::cells`, be shown, and have its events pumped -- read out of
 * qtty's own `test/suite_render.cpp`. The first version of this probe did
 * none of it and reported a truncated label that was entirely the probe's
 * doing.
 */

#include "../trust_view.h"
#include "../log_view.h"

#include <qtty/grid.h>
#include <qtty/testing.h>

#include <QApplication>
#include <QString>

#include <cstdio>
#include <cstring>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL qtty_render_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* Render one widget and hand back what the cells hold, glyphs only. */
static QString rendered(QWidget &w, int cols, int rows)
{
	w.setAttribute(Qt::WA_DontShowOnScreen);
	w.resize(Qtty::GridMetrics::cells(cols, rows));
	w.show();
	QCoreApplication::processEvents();
	return Qtty::test::snapshot_of(w, cols, rows).section(QStringLiteral("--- attrs"), 0, 0);
}

/* Whether every line of the fingerprint is on the screen, character for
 * character.
 *
 * ASKED OF THE SNAPSHOT AND NOT OF THE WIDGET, which is the whole point: the
 * widget's own answer was right throughout the defect this guards.
 *
 * A FIRST VERSION COUNTED ALPHANUMERICS AND SUBTRACTED A RENDER OF THE SAME
 * WIDGET WITH NO ANCHOR, meaning to cancel the source label's own letters. It
 * does not cancel: an anchored view says "configured out of band" where an
 * empty one says "no anchor", so the subtraction was between two different
 * strings and reported a missing character at 41 columns that was not
 * missing. Containment needs no arithmetic and cannot make that mistake. */
static int lines_on_screen(const QString &snapshot, const QString &fingerprint)
{
	const QStringList lines = fingerprint.split(QLatin1Char('\n'));

	for (const QString &line : lines)
		if (!snapshot.contains(line))
			return 0;
	return 1;
}

int main(int argc, char **argv)
{
	fzn_trust_t trust;
	uint8_t root[FZN_PUBKEY_LEN];
	int cols;

	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	memset(root, 0xa7, sizeof(root));
	fzn_trust_init(&trust);
	CHECK(fzn_trust_pin(&trust, root) == FZN_TRUST_OK, "the fixture could not pin");

	/* THE CASE THIS FILE EXISTS FOR. Every width from the floor up must
	 * show every hex digit. 76 to 80 is where they were being lost, and 80
	 * is the width a terminal is by default. */
	{
		int lost = 0;

		for (cols = 41; cols <= 96; cols++) {
			fzn_trust_view view;

			view.show_anchor(&trust);
			if (!lines_on_screen(rendered(view, cols, 12),
			                     view.fingerprint_text())) {
				char msg[128];

				snprintf(msg, sizeof(msg),
				         "a fingerprint line is not on the screen whole at "
				         "%d columns", cols);
				check_at(0, __LINE__, msg);
				lost = 1;
				break;
			}
			checks++;
		}
		/* AND THE SWEEP MUST HAVE RUN. A loop that stopped at the first
		 * width would report one silent pass, which is the vacuous pass
		 * this whole file exists to refuse. */
		CHECK(!lost && cols == 97,
		      "the width sweep did not reach 96 columns, so its passes cover less "
		      "than they appear to");
	}

	/* AND THE FORMAT DOES NOT MOVE. The same fingerprint must occupy the
	 * same number of lines whatever the terminal is, or a user comparing
	 * two screens is comparing two arrangements. */
	{
		fzn_trust_view a;
		fzn_trust_view b;
		QString wide;
		QString narrow;

		a.show_anchor(&trust);
		b.show_anchor(&trust);
		wide = rendered(a, 96, 12);
		narrow = rendered(b, 44, 12);
		CHECK(wide.count(QLatin1Char('\n')) == narrow.count(QLatin1Char('\n')),
		      "the fingerprint occupies different line counts at two widths, so its "
		      "format still moves with the window");
	}

	/* THE LOG VIEW FITS A SMALL TERMINAL. qtty's sec 16 finding is that a
	 * resize below minimumSizeHint is refused and the content overflows
	 * rather than compacting, so a widget whose minimum is large is one a
	 * terminal cannot show at all. */
	{
		fzn_log_view view;
		QSize minimum;
		int wide_cells;
		int tall_cells;

		(void)rendered(view, 60, 10);
		minimum = view.minimumSizeHint();
		wide_cells = (minimum.width() + Qtty::GridMetrics::cw() - 1) /
		             Qtty::GridMetrics::cw();
		tall_cells = (minimum.height() + Qtty::GridMetrics::ch() - 1) /
		             Qtty::GridMetrics::ch();
		CHECK(wide_cells <= 40 && tall_cells <= 12,
		      "the log view's minimum does not fit a 40x12 terminal, so a small "
		      "terminal cannot lay it out at all");
	}

	{
		fzn_trust_view view;
		QSize minimum;

		(void)rendered(view, 60, 10);
		minimum = view.minimumSizeHint();
		CHECK((minimum.width() + Qtty::GridMetrics::cw() - 1) / Qtty::GridMetrics::cw() <=
		              40,
		      "the trust view's minimum does not fit a 40-column terminal");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("qtty_render_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
