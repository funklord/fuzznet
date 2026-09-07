/* Tests for cli/qr_print.c: the spelling, the geometry, the refusals.
 *
 * WHAT THIS FILE CANNOT SAY IS THAT THE TEXT SCANS. It checks the characters
 * and their arrangement; whether a decoder reads them is `make qrcheck`,
 * which draws the text as a terminal would and hands the pixels to quirc.
 * sec 160 is the standing reminder that a QR code can satisfy every shape
 * assertion and decode as nothing.
 */

#include "../qr_print.h"

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
	fprintf(stderr, "  FAIL qr_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static uint8_t modules[FZN_QR_MODULES_MAX];
static char text[FZN_QR_PRINT_MAX];

/* Rows and the widest row in CELLS, counting a UTF-8 lead byte once. */
static void measure(const char *s, int *rows, int *cols)
{
	int c = 0;

	*rows = 0;
	*cols = 0;
	for (; *s; ) {
		if (*s == '\n') {
			(*rows)++;
			if (c > *cols)
				*cols = c;
			c = 0;
			s++;
			continue;
		}
		s += (*s & 0x80) ? 3 : 1;
		c++;
	}
}

int main(void)
{
	size_t size = 0;
	size_t len = 0;
	int rows;
	int cols;
	int across;

	CHECK(fzn_qr_encode("HELLO WORLD", 11u, FZN_QR_LEVEL_L, modules, sizeof(modules),
	                    &size) == FZN_QR_OK,
	      "the fixture would not encode");
	CHECK(size == 21u, "the fixture is not a version-1 code");
	across = (int)size + 2 * (int)FZN_QR_QUIET;

	/* HALF BLOCKS ARE HALF THE ROWS, which is what makes a code fit an
	 * ordinary terminal, and one cell per module -- square on an 8 by 16
	 * cell, which sec 162 measured as the difference between decoding and
	 * not. */
	CHECK(fzn_qr_print(modules, size, FZN_QR_PRINT_HALF, 0, text, sizeof(text), &len) ==
	              FZN_QR_OK,
	      "half blocks would not print");
	measure(text, &rows, &cols);
	CHECK(cols == across, "a half-block row is not one cell per module");
	CHECK(rows == (across + 1) / 2, "half blocks did not halve the rows");

	/* FULL BLOCKS ARE TWO CELLS A MODULE AND EVERY ROW, which is square
	 * the other way. */
	CHECK(fzn_qr_print(modules, size, FZN_QR_PRINT_FULL, 0, text, sizeof(text), &len) ==
	              FZN_QR_OK,
	      "full blocks would not print");
	measure(text, &rows, &cols);
	CHECK(cols == across * 2, "a full-block row is not two cells per module");
	CHECK(rows == across, "full blocks did not use one row per module");

	/* THE FILLED BLOCK IS THE LIGHT MODULE. The quiet zone is light, so
	 * the first row must be entirely filled -- and that is the quickest
	 * way to see the convention has not been flipped. */
	CHECK(fzn_qr_print(modules, size, FZN_QR_PRINT_HALF, 0, text, sizeof(text), &len) ==
	              FZN_QR_OK,
	      "half blocks would not print");
	{
		const char *row = text;
		int filled = 1;
		int i;

		for (i = 0; i < across; i++) {
			if (memcmp(row, "\xe2\x96\x88", 3) != 0)
				filled = 0;
			row += 3;
		}
		CHECK(filled,
		      "the first row is not solid, so the quiet zone is dark and the "
		      "filled block is being used for the dark module");
		CHECK(*row == '\n', "the first row is not the width it measured");
	}

	/* INVERTED IS THE OTHER ONE, for a terminal that is dark on light. */
	CHECK(fzn_qr_print(modules, size, FZN_QR_PRINT_HALF, 1, text, sizeof(text), &len) ==
	              FZN_QR_OK,
	      "the inverted spelling would not print");
	CHECK(text[0] == ' ', "the inverted spelling did not swap light for dark");

	/* ASCII USES NO BYTE ABOVE 127, which is the whole of its reason to
	 * exist -- a terminal with no Unicode gets something. */
	CHECK(fzn_qr_print(modules, size, FZN_QR_PRINT_ASCII, 0, text, sizeof(text), &len) ==
	              FZN_QR_OK,
	      "the ascii spelling would not print");
	{
		int high = 0;
		size_t i;

		for (i = 0; i < len; i++)
			if ((unsigned char)text[i] > 127u)
				high = 1;
		CHECK(!high, "the ascii spelling emitted a byte a plain terminal cannot draw");
	}

	/* SIZING. A short buffer is refused and still says how much was
	 * needed, so a caller can ask once and then allocate. */
	{
		size_t needed = 0;

		CHECK(fzn_qr_print(modules, size, FZN_QR_PRINT_HALF, 0, text, 4u, &needed) ==
		              FZN_QR_ERR_FULL,
		      "a buffer too small was not refused");
		CHECK(needed > 4u, "a refused print did not report what it needed");
		CHECK(fzn_qr_print(modules, size, FZN_QR_PRINT_HALF, 0, NULL, 0u, &needed) ==
		              FZN_QR_ERR_FULL,
		      "a sizing call was not refused, though it wrote nothing");
		CHECK(needed > 0u, "a sizing call reported no size");
	}

	/* Arguments, and a size that is not a QR code's. */
	CHECK(fzn_qr_print(NULL, size, FZN_QR_PRINT_HALF, 0, text, sizeof(text), &len) ==
	              FZN_QR_ERR_MALFORMED,
	      "null modules were accepted");
	CHECK(fzn_qr_print(modules, 22u, FZN_QR_PRINT_HALF, 0, text, sizeof(text), &len) ==
	              FZN_QR_ERR_MALFORMED,
	      "a size no QR version has was accepted");
	CHECK(fzn_qr_print(modules, size, (fzn_qr_print_style_t)9, 0, text, sizeof(text),
	                   &len) == FZN_QR_ERR_MALFORMED,
	      "a style outside the three was accepted");
	CHECK(fzn_qr_print(modules, size, FZN_QR_PRINT_HALF, 0, text, sizeof(text), NULL) ==
	              FZN_QR_ERR_MALFORMED,
	      "nowhere to report the length");

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("qr_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
