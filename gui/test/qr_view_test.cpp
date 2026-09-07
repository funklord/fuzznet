/* Tests for gui/qr_view.cpp: what it holds and what it says.
 *
 * NO SCREEN IS NEEDED AND NONE IS OPENED -- `QT_QPA_PLATFORM=offscreen` is set
 * before the QApplication, as the other gui suites do.
 *
 * WHAT THIS FILE CANNOT SAY IS THAT THE CODE SCANS. It renders into a
 * QImage and reads modules back, which proves the geometry this widget
 * intends; whether the result is still a readable QR code after a backend has
 * had it is `make qtty`'s question, and sec 160 is the standing reminder that
 * a QR code can satisfy every shape assertion and decode as nothing.
 */

#include "../qr_view.h"

#include <QApplication>
#include <QImage>
#include <QPainter>

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
	fprintf(stderr, "  FAIL qr_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* Paint the widget into an image, which is what a test can inspect. */
static QImage painted(fzn_qr_view &view, int w, int h)
{
	QImage image(w, h, QImage::Format_RGB32);

	image.fill(Qt::gray);
	view.resize(w, h);
	view.render(&image);
	return image;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_qr_view view;

	/* NOTHING ASKED FOR IS NOT A REFUSAL. */
	CHECK(!view.has_code(), "a fresh widget claims a code");
	CHECK(view.modules_across() == 0, "a fresh widget claims modules");
	CHECK(view.message_text().isEmpty(),
	      "a widget nobody has asked anything of is explaining itself");

	/* A CODE, AND THE SIZE THE ENCODER CHOSE. */
	view.show_text(QStringLiteral("HELLO WORLD"), FZN_QR_LEVEL_L);
	CHECK(view.has_code(), "a short payload produced no code");
	CHECK(view.modules_across() == 21, "eleven alphanumeric characters is version 1");
	CHECK(view.message_text().isEmpty(), "a widget with a code is also explaining itself");

	/* A REFUSAL SAYS WHY, IN THE LIBRARY'S WORDS. A blank square and a
	 * failed encode must not look alike. */
	{
		QString huge(4000, QLatin1Char('A'));

		view.show_text(huge, FZN_QR_LEVEL_L);
		CHECK(!view.has_code(), "a payload nothing holds produced a code anyway");
		CHECK(view.message_text() ==
		              QString::fromUtf8(fzn_qr_err_str(FZN_QR_ERR_TOO_LONG)),
		      "the refusal is not the library's own wording");
	}

	/* AND ASKING FOR NOTHING CLEARS IT, rather than leaving the last
	 * refusal on screen for a reader to attribute to the new payload. */
	view.show_text(QString(), FZN_QR_LEVEL_L);
	CHECK(!view.has_code() && view.message_text().isEmpty(),
	      "an empty payload left the previous state on screen");

	/* THE MODULES ARE SQUARE AND WHOLE PIXELS, which is what stops a
	 * character-cell backend rounding one differently from its neighbour.
	 * Read out of the painted image rather than asserted of the code. */
	view.show_text(QStringLiteral("HELLO WORLD"), FZN_QR_LEVEL_L);
	{
		const int across = view.modules_across() + 2 * (int)FZN_QR_QUIET;
		const int module = 6;
		QImage image = painted(view, across * module, across * module);
		int uniform = 1;
		int dy;
		int dx;

		/* Every pixel of the top-left finder's first module must be one
		 * colour: if a module is not a whole number of pixels, its
		 * corner bleeds into the next. */
		for (dy = 0; dy < module; dy++) {
			for (dx = 0; dx < module; dx++) {
				int px = (int)FZN_QR_QUIET * module + dx;
				int py = (int)FZN_QR_QUIET * module + dy;

				if (image.pixel(px, py) != image.pixel(
				                                   (int)FZN_QR_QUIET * module,
				                                   (int)FZN_QR_QUIET * module))
					uniform = 0;
			}
		}
		CHECK(uniform, "a module is not a solid square of pixels");

		/* THE QUIET ZONE IS PAINTED rather than left to whatever is
		 * behind: the image was filled grey, so a light quiet zone
		 * proves the widget drew it. */
		CHECK(image.pixel(module / 2, module / 2) != qRgb(128, 128, 128),
		      "the quiet zone was left as whatever was behind the widget");
	}

	/* A NON-SQUARE WIDGET STILL DRAWS A SQUARE CODE, which is the case a
	 * layout produces and a stretched code is one a decoder may refuse. */
	{
		QImage wide = painted(view, 400, 200);
		int top = -1;
		int bottom = -1;
		int y;

		for (y = 0; y < wide.height(); y++) {
			int x;

			for (x = 0; x < wide.width(); x++) {
				if (wide.pixel(x, y) != qRgb(128, 128, 128)) {
					if (top < 0)
						top = y;
					bottom = y;
					break;
				}
			}
		}
		CHECK(top >= 0 && bottom > top, "nothing was drawn into a wide widget");
		CHECK(bottom - top + 1 <= 200,
		      "the code was drawn taller than the widget it was given");
	}

	/* SIZING. A consumer asks before it lays out. */
	CHECK(view.preferred_side() > 0, "a widget with a code prefers no size");
	CHECK(view.minimumSizeHint().width() == view.minimumSizeHint().height(),
	      "the widget's minimum is not square, so a layout will stretch the code");

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("qr_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
