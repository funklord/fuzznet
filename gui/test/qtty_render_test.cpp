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
#include "../qr_view.h"

extern "C" {
#include "../../log/log.h"
#include "../../record/journal.h"
#include "../../record/record.h"
}

#include <qtty/grid.h>
#ifdef FZN_HAVE_QUIRC
#include <qtty/application.h>
#include <qtty/cell.h>
#include <qtty/color.h>
#include <QColor>
extern "C" {
#include <quirc.h>
}
#endif
#include <qtty/testing.h>

#include <QApplication>
#include <QString>
#include <QStringList>

#include <cstdio>
#include <cstring>

static uint8_t ISSUER[FZN_PUBKEY_LEN];
static uint8_t SUBJECT[FZN_SUBJECT_LEN];
static uint8_t SLOTS[8][FZN_RECORD_MAX_LEN];

/* The same stub signer log_view_test.cpp uses: this renders records, it does
 * not verify them, and a real signature would only make the fixture slower. */
static void tag(uint8_t out[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	uint64_t h = 1469598103934665603u;
	size_t i;

	for (i = 0; i < msg_len; i++) {
		h ^= msg[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= h << 13;
		h ^= h >> 7;
		h ^= h << 17;
		out[i] = (uint8_t)(h >> 32);
	}
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	tag(sig, msg, msg_len);
	return 1;
}

static int make(fzn_record_t *r, size_t which, uint64_t seq, const uint8_t *body,
                size_t body_len)
{
	fzn_sign_ops_t ops;
	size_t wrote = 0;

	memset(&ops, 0, sizeof(ops));
	ops.sign = stub_sign;
	if (fzn_record_sign(ISSUER, SUBJECT, 5u, 3u, seq, 1u, body, body_len, &ops,
	                    SLOTS[which], FZN_RECORD_MAX_LEN, &wrote) != FZN_RECORD_OK)
		return 0;
	return fzn_record_open(SLOTS[which], wrote, r) == FZN_RECORD_OK;
}

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

#ifdef FZN_HAVE_QUIRC
/* A cell's background as a grey level, which is what carries a QR module: the
 * code is filled rectangles and has no glyphs at all. */
static int cell_grey(const Qtty::Cell &c)
{
	if (c.bg.kind() == Qtty::Color::Rgb) {
		QColor q = QColor::fromRgba(c.bg.value());
		return qGray(q.red(), q.green(), q.blue());
	}
	if (c.bg.kind() == Qtty::Color::Indexed)
		return c.bg.index() == 0 ? 0 : 255;
	/* The terminal's own colour, which for a code drawn on a painted quiet
	 * zone is the light one. */
	return 255;
}

/* Render `view` at `cols` by `rows` cells, rebuild the pixels a terminal
 * would show, and ask quirc what it reads. Returns 1 when the payload comes
 * back whole, 0 for anything else -- no code found, no decode, or a payload
 * that differs. */
static int decodes_off_a_terminal(fzn_qr_view &view, int cols, int rows, const char *want)
{
	const int cw = Qtty::GridMetrics::cw();
	const int ch = Qtty::GridMetrics::ch();
	struct quirc *q;
	struct quirc_code code;
	struct quirc_data data;
	uint8_t *image;
	int w = cols * cw;
	int h = rows * ch;
	int ok = 0;
	int cx;
	int cy;

	view.setAttribute(Qt::WA_DontShowOnScreen);
	view.resize(Qtty::GridMetrics::cells(cols, rows));
	view.show();
	QCoreApplication::processEvents();

	Qtty::CellBuffer buf(cols, rows);
	Qtty::render_once(view, buf);

	q = quirc_new();
	if (!q || quirc_resize(q, w, h) < 0) {
		if (q)
			quirc_destroy(q);
		return 0;
	}
	image = quirc_begin(q, &w, &h);
	for (cy = 0; cy < rows; cy++) {
		for (cx = 0; cx < cols; cx++) {
			int grey = cell_grey(buf.at(cx, cy));
			int py;

			for (py = 0; py < ch; py++) {
				int px;

				for (px = 0; px < cw; px++)
					image[(cy * ch + py) * w + cx * cw + px] =
					        (uint8_t)grey;
			}
		}
	}
	quirc_end(q);

	if (quirc_count(q) == 1) {
		quirc_extract(q, 0, &code);
		if (quirc_decode(&code, &data) == QUIRC_SUCCESS &&
		    data.payload_len == (int)strlen(want) &&
		    memcmp(data.payload, want, strlen(want)) == 0)
			ok = 1;
	}
	quirc_destroy(q);
	return ok;
}
#endif

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

	/*
	 * THE LOG VIEW DRAWS NO BORDER, AND ITS ENTRIES ARE CONSECUTIVE.
	 * sec 159.
	 *
	 * TWO ASSERTIONS AND ONLY ONE OF THEM GUARDS THE FIX, which is worth
	 * saying because the first version of this case had it the other way
	 * round and did not notice.
	 *
	 * The border one is the guard: `setFrameShape(NoFrame)` is what this
	 * widget does about a frame qtty renders as a left edge and nothing
	 * else, and putting the frame back turns exactly this red.
	 *
	 * The consecutive-rows one is NOT a guard for that -- it passes with
	 * the frame and without it. It was written believing the frame
	 * double-spaced the entries; it does, with a PROPORTIONAL font, and
	 * this widget has set a monospace hint since sec 141. It is kept
	 * because consecutive entries are a property worth holding on their
	 * own, and labelled because a reader would otherwise take it for the
	 * frame's guard and be wrong the way its author was.
	 */
	{
		fzn_log_view view;
		fzn_log_entry_t rows[4];
		fzn_journal_entry_t positions[2];
		fzn_log_t log;
		fzn_journal_t journal;
		fzn_record_t rec;
		QStringList screen;
		uint64_t seq;
		int first = -1;
		int seen = 0;
		int consecutive = 1;

		memset(ISSUER, 0x11, sizeof(ISSUER));
		memset(SUBJECT, 0x51, sizeof(SUBJECT));
		CHECK(fzn_log_init(&log, rows, 4) == FZN_LOG_OK, "the log would not init");
		CHECK(fzn_journal_init(&journal, positions, 2) == FZN_JOURNAL_OK,
		      "the journal would not init");
		CHECK(fzn_journal_anchor(&journal, ISSUER, 5u, 0u) == FZN_JOURNAL_OK,
		      "the stream could not be followed");
		for (seq = 1u; seq <= 3u; seq++) {
			const uint8_t body[3] = { 'a', (uint8_t)('0' + seq), 'z' };

			CHECK(make(&rec, (size_t)seq, seq, body, sizeof(body)),
			      "the fixture could not build a record");
			CHECK(fzn_log_append(&log, &rec) == FZN_LOG_OK, "append refused");
			CHECK(fzn_journal_admit(&journal, ISSUER, 5u, seq) == FZN_JOURNAL_OK,
			      "the journal refused the record");
		}
		view.show_stream(&log, &journal, ISSUER, 5u);

		screen = rendered(view, 60, 12).split(QLatin1Char('\n'));
		for (int row = 0; row < screen.size(); row++) {
			if (!screen[row].contains(QLatin1String("a1z")) &&
			    !screen[row].contains(QLatin1String("a2z")) &&
			    !screen[row].contains(QLatin1String("a3z")))
				continue;
			if (first < 0)
				first = row;
			else if (row != first + seen)
				consecutive = 0;
			seen++;
		}
		/* THE GUARD: no box-drawing anywhere in the render. A border
		 * that draws one of its four sides is worse than none, and this
		 * is what putting the frame back breaks. */
		{
			QString flat = screen.join(QLatin1Char(' '));

			CHECK(!flat.contains(QChar(0x250C)) && !flat.contains(QChar(0x2514)) &&
			              !flat.contains(QChar(0x2502)),
			      "the log view drew a box-drawing character, so it is asking "
			      "for a frame qtty renders as a left edge and nothing else");
		}

		CHECK(seen == 3, "not every log entry reached the screen");
		CHECK(consecutive,
		      "the log entries are spread over more rows than they occupy, so a "
		      "reader sees fewer of them than the terminal has room for");
	}

	/*
	 * A QR CODE ON A CHARACTER CELL GRID. sec 161.
	 *
	 * THE CELL IS NOT SQUARE -- 8 by 16 here -- so a module painted one
	 * cell each way arrives at a scanner stretched two to one, and a
	 * stretched code is one a decoder may refuse. `fzn_qr_view` paints
	 * squares in PIXELS, so at two cells per module horizontally and one
	 * vertically the result is square on screen. This is the assertion
	 * that the arithmetic came out.
	 *
	 * READ FROM THE COLOUR LAYER, because the code is drawn as filled
	 * rectangles and carries no glyphs at all: the glyph half of the
	 * snapshot is blank, which is how the first probe here concluded
	 * nothing had rendered.
	 */
	{
		fzn_qr_view view;
		int across;
		int cols;
		int rows;
		QString snap;
		QStringList colours;
		int at;

		view.show_text(QStringLiteral("HELLO WORLD"), FZN_QR_LEVEL_L);
		CHECK(view.modules_across() == 21, "the fixture is not a version-1 code");
		across = view.modules_across() + 2 * (int)FZN_QR_QUIET;
		cols = across * 2;
		rows = across;

		view.setAttribute(Qt::WA_DontShowOnScreen);
		view.resize(Qtty::GridMetrics::cells(cols, rows));
		view.show();
		QCoreApplication::processEvents();
		snap = Qtty::test::snapshot_of(view, cols, rows);

		CHECK(snap.contains(QStringLiteral("--- colours ---")),
		      "the snapshot carries no colour layer, so nothing can be read back");
		colours = snap.section(QStringLiteral("--- colours ---"), 1)
		                  .section(QStringLiteral("--- legend"), 0, 0)
		                  .split(QLatin1Char('\n'));

		/* The top-left finder's first row is seven dark modules, which
		 * at two cells a module is fourteen identical cells -- and the
		 * four quiet modules before it are eight. */
		at = -1;
		for (int i = 0; i < colours.size(); i++) {
			const QString &row = colours[i];

			if (row.contains(QStringLiteral("aaaaaaaaaaaaaa"))) {
				at = i;
				break;
			}
		}
		CHECK(at >= 0,
		      "no row of fourteen identical cells, so a module is not two cells "
		      "wide and the code is not square on screen");
		if (at >= 0) {
			CHECK(colours[at].indexOf(QLatin1Char('a')) == 2 * (int)FZN_QR_QUIET,
			      "the finder does not begin after four quiet modules, so the "
			      "quiet zone is the wrong width");
			/* And the row below it is the finder's second row: dark,
			 * five light, dark -- two cells each. */
			CHECK(at + 1 < colours.size() &&
			              colours[at + 1].contains(QStringLiteral("aa..........aa")),
			      "the finder's second row is not a ring, so the modules are not "
			      "landing on cell boundaries");
		}
	}

#ifdef FZN_HAVE_QUIRC
	/*
	 * THE LOOP CLOSED: widget, terminal, independent decoder. sec 162.
	 *
	 * Everything above asserts SHAPE, and sec 160 is the standing reminder
	 * that a QR code can satisfy every shape assertion and decode as
	 * nothing. This renders the widget onto a character grid, rebuilds the
	 * pixels a terminal would actually show, and hands them to quirc.
	 *
	 * NO ASSUMPTION ABOUT MODULE SIZE. Each CELL becomes its own rectangle
	 * of the reconstructed screen, so nothing here encodes how many cells a
	 * module is meant to be -- if the widget got that wrong, the picture is
	 * wrong and the decode fails, which is the point.
	 *
	 * AND THE STRETCHED CASE IS THE CONTROL. At one cell per module the
	 * code is twice as tall as it is wide, and quirc finds no code at all.
	 * That is what makes the square-module design a measurement rather than
	 * a reasonable-sounding claim, and it is why the pass above means
	 * something.
	 */
	{
		fzn_qr_view view;
		const char *want = "HELLO WORLD";
		int across;
		int wide;
		int narrow;

		view.show_text(QString::fromLatin1(want), FZN_QR_LEVEL_L);
		across = view.modules_across() + 2 * (int)FZN_QR_QUIET;

		wide = decodes_off_a_terminal(view, across * 2, across, want);
		narrow = decodes_off_a_terminal(view, across, across, want);

		CHECK(wide == 1,
		      "a QR code rendered two cells to a module did not decode off the "
		      "terminal, so the widget draws something a scanner cannot read");
		CHECK(narrow == 0,
		      "a QR code rendered ONE cell to a module decoded anyway, so the "
		      "control cannot fail and the square-module design is untested");
	}
#endif

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
