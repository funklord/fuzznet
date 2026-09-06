/* Tests for gui/trust_view.cpp, headless.
 *
 * THE CASES THIS FILE EXISTS FOR are the two a user's safety turns on: that
 * an anchor with no root does not show an empty fingerprint -- which reads
 * like a fingerprint of something -- and that "adopted on first contact"
 * never appears where "configured out of band" belongs. project.md sec 140.
 *
 * NO SCREEN IS NEEDED AND NONE IS OPENED. `QT_QPA_PLATFORM=offscreen` is set
 * before the QApplication is built, so this runs on a machine with no
 * display, in a container, and under `make check` like every other suite.
 * That is also the arrangement `qtty` relies on -- widgets that never reach a
 * window system -- so a suite that could only run against a real display
 * would be testing the one configuration the terminal backend never uses.
 *
 * IT ASSERTS ON THE TEXT A USER SEES rather than on the widget's internals,
 * because the wording IS the feature here: a fingerprint format nobody can
 * compare, or a source line that says the wrong thing, is the defect.
 */

extern "C" {
#include "../../trust/trust.h"
}

#include "../trust_view.h"

#include <QApplication>
#include <QStringList>
#include <QString>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL trust_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

int main(int argc, char **argv)
{
	/* Before the QApplication, or it has already chosen a platform. */
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_trust_view view;
	fzn_trust_t trust;
	uint8_t key[FZN_PUBKEY_LEN];
	uint8_t nearly[FZN_PUBKEY_LEN];
	char expected[FZN_TRUST_FINGERPRINT_LEN];
	QString adopted_text, pinned_text, self_text;

	memset(key, 0x11, sizeof(key));
	memset(nearly, 0x11, sizeof(nearly));
	nearly[FZN_PUBKEY_LEN - 1u] = 0x12;

	/* A FRESH WIDGET SHOWS NO ANCHOR, and says so. An empty fingerprint
	 * field would read as a fingerprint of something. */
	CHECK(!view.fingerprint_text().isEmpty(),
	      "a widget with no anchor shows an empty fingerprint");
	CHECK(view.fingerprint_text() != QString::fromLatin1("  "),
	      "a widget with no anchor shows blank space where a fingerprint goes");
	CHECK(view.source_text() == QString::fromUtf8(fzn_trust_source_str(FZN_TRUST_NONE)),
	      "a widget with no anchor does not say so");

	/* AND SO DOES ONE GIVEN AN UNANCHORED TRUST, which is the case a
	 * consumer actually hits: it holds a trust that nobody has anchored. */
	fzn_trust_init(&trust);
	view.show_anchor(&trust);
	CHECK(view.source_text() == QString::fromUtf8(fzn_trust_source_str(FZN_TRUST_NONE)),
	      "an unanchored trust was not shown as having no anchor");

	/* THE FINGERPRINT IS THE LIBRARY'S, NOT A SECOND FORMATTING. A widget
	 * that formatted its own would drift from what a CLI prints, and a user
	 * comparing the two would be comparing two spellings of one key. */
	fzn_trust_init(&trust);
	CHECK(fzn_trust_adopt(&trust, key, 99u) == FZN_TRUST_OK, "the fixture could not adopt");
	view.show_anchor(&trust);
	CHECK(fzn_trust_fingerprint(key, expected, sizeof(expected)) == FZN_TRUST_OK,
	      "the fixture could not format");
	/* THE SAME CHARACTERS, ALLOWING THE DISPLAY'S OWN LINE BREAKS. sec 158
	 * puts the breaks in the text so the format cannot move with the
	 * window; what must not move is the KEY's spelling, so the newlines
	 * come out and the rest must match to the character. */
	CHECK(view.fingerprint_text().replace(QLatin1Char('\n'), QLatin1Char(' ')) ==
	              QString::fromLatin1(expected),
	      "the widget shows something other than the library's fingerprint");
	adopted_text = view.source_text();

	/* TWO KEYS DIFFERING IN ONE BYTE MUST NOT DISPLAY ALIKE. */
	fzn_trust_init(&trust);
	CHECK(fzn_trust_adopt(&trust, nearly, 99u) == FZN_TRUST_OK, "the near fixture failed");
	view.show_anchor(&trust);
	CHECK(view.fingerprint_text() != QString::fromLatin1(expected),
	      "two keys differing in one byte display the same fingerprint");

	/* THE THREE PROVENANCES MUST NOT READ ALIKE. TOFU's weakness is the
	 * first contact; a widget that showed an adopted anchor as configured
	 * would tell a user it had been checked when nobody checked it. */
	fzn_trust_init(&trust);
	CHECK(fzn_trust_pin(&trust, key) == FZN_TRUST_OK, "the pin fixture failed");
	view.show_anchor(&trust);
	pinned_text = view.source_text();

	fzn_trust_init(&trust);
	CHECK(fzn_trust_self(&trust, key) == FZN_TRUST_OK, "the self fixture failed");
	view.show_anchor(&trust);
	self_text = view.source_text();

	CHECK(adopted_text != pinned_text, "an adopted anchor reads as a configured one");
	CHECK(self_text != pinned_text, "a self root reads as a configured one");
	CHECK(self_text != adopted_text, "a self root reads as an adopted one");

	/* A NULL IS THE NO-ANCHOR CASE, not a crash and not a stale display. */
	view.show_anchor(nullptr);
	CHECK(view.source_text() == QString::fromUtf8(fzn_trust_source_str(FZN_TRUST_NONE)),
	      "a null anchor left the previous one on screen");

	/*
	 * THE FORMAT MUST NOT MOVE WITH THE WINDOW. sec 158.
	 *
	 * This is the guard for a defect that a screenless test could not see
	 * and did not: rendered through qtty at 76 to 80 columns the label
	 * clipped rather than wrapped, so the widget held 79 characters and
	 * showed 78 -- and every assertion above passed, because they read the
	 * text and a user reads the screen.
	 *
	 * WHAT MAKES IT IMPOSSIBLE RATHER THAN UNLIKELY is that the breaks are
	 * in the text: no line is wider than a small terminal, so no width
	 * decision is left to a layout. That is a property of `wrapped` alone
	 * and needs no screen, no terminal and no qtty to check -- which is
	 * why it is asserted here rather than only in the render target.
	 */
	{
		char formatted[FZN_TRUST_FINGERPRINT_LEN];
		QStringList lines;
		QString flat;
		int widest = 0;

		CHECK(fzn_trust_fingerprint(key, formatted, sizeof(formatted)) == FZN_TRUST_OK,
		      "the fixture could not format");
		lines = fzn_trust_view::wrapped(QString::fromLatin1(formatted))
		                .split(QLatin1Char('\n'));
		for (const QString &line : lines)
			if (line.size() > widest)
				widest = line.size();

		/* 39 CHARACTERS, WHICH RENDERS WHOLE FROM 41 COLUMNS UP. The
		 * floor is 41 rather than 40 because the layout's margin costs
		 * two cells, which was measured rather than reasoned -- see
		 * `wrapped`, whose comment first claimed 40 from the string
		 * length alone. This asserts the string, since that is what
		 * this function decides; the floor it produces is recorded
		 * beside the measurement. */
		CHECK(widest <= 39,
		      "a fingerprint line is wider than 39 characters, so a small "
		      "terminal must wrap it and the format moves with the window again");
		CHECK(lines.size() >= 2,
		      "the fingerprint was not broken at all, so a wide window and a narrow "
		      "one show it differently");

		/* AND NOT ONE HEX DIGIT MAY BE LOST TO THE BREAKING. The whole
		 * point is a fingerprint a user can compare, so the characters
		 * have to survive being arranged. */
		flat = lines.join(QLatin1Char(' '));
		CHECK(flat == QString::fromLatin1(formatted),
		      "breaking the fingerprint into lines changed it");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("trust_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
