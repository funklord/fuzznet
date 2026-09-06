/* Tests for qr/qr.c: the structure, the refusals, and the sizing.
 *
 * WHAT THIS FILE CANNOT DO IS SAY THE CODE IS READABLE, and it is important
 * that a reader knows it. Every assertion here is about shape -- a finder
 * where a finder goes, a size that matches the version, a payload that will
 * not fit being refused -- and a QR code can satisfy all of it and decode as
 * nothing. project.md sec 160: the encoder was wrong in four separate ways
 * that this suite would have passed, and each was caught by `make qrcheck`
 * handing the output to quirc.
 *
 * So this is the half that runs everywhere and catches a regression in the
 * parts that are checkable without a decoder. The half that says it is a QR
 * code at all needs another implementation, and lives in that target.
 */

#include "../qr.h"

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
	fprintf(stderr, "  FAIL qr_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static uint8_t modules[FZN_QR_MODULES_MAX];

/* A finder is a 7x7 ring with a 3x3 core, and it is the same at every
 * version. Reading one back is the cheapest evidence that placement did not
 * move. */
static int finder_at(const uint8_t *m, size_t size, size_t ox, size_t oy)
{
	size_t dx;
	size_t dy;

	for (dy = 0; dy < 7u; dy++) {
		for (dx = 0; dx < 7u; dx++) {
			int want = (dy == 0 || dy == 6 || dx == 0 || dx == 6) ||
			           (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4);

			if ((m[(oy + dy) * size + ox + dx] != 0) != (want != 0))
				return 0;
		}
	}

	return 1;
}

int main(void)
{
	size_t size = 0;
	size_t i;

	/* THE THREE FINDERS, which is what a scanner looks for first. */
	CHECK(fzn_qr_encode("HELLO WORLD", 11u, FZN_QR_LEVEL_L, modules, sizeof(modules),
	                    &size) == FZN_QR_OK,
	      "a short alphanumeric payload would not encode");
	CHECK(size == 21u, "an eleven-character payload is version 1, which is 21 modules");
	CHECK(finder_at(modules, size, 0, 0), "the top-left finder is not a finder");
	CHECK(finder_at(modules, size, size - 7u, 0), "the top-right finder is not a finder");
	CHECK(finder_at(modules, size, 0, size - 7u), "the bottom-left finder is not a finder");

	/* THE TIMING PATTERNS ALTERNATE, and they must not run over the
	 * finders -- doing so is what made the first version of this encoder
	 * unfindable, and it is visible without a decoder. */
	for (i = 8u; i + 8u < size; i++) {
		CHECK((modules[6u * size + i] != 0) == ((i % 2u) == 0u),
		      "the horizontal timing pattern does not alternate");
		CHECK((modules[i * size + 6u] != 0) == ((i % 2u) == 0u),
		      "the vertical timing pattern does not alternate");
	}
	CHECK(modules[1u * size + 6u] != 0,
	      "the top-left finder's right edge is light, so timing has run over it");

	/* THE DARK MODULE is always set, at a place that never moves. */
	CHECK(modules[(size - 8u) * size + 8u] != 0, "the dark module is not dark");

	/* EVERY MODULE IS 0 OR 1, because a caller draws them and a 2 is a
	 * shape nobody has agreed how to paint. */
	{
		int only_bits = 1;

		for (i = 0; i < size * size; i++)
			if (modules[i] > 1u)
				only_bits = 0;
		CHECK(only_bits, "a module is neither light nor dark");
	}

	/* SIZING. A version's size is 17 + 4v, and `fzn_qr_version_for` is what
	 * a caller asks before it allocates. */
	{
		unsigned v = fzn_qr_version_for("HELLO WORLD", 11u, FZN_QR_LEVEL_L);

		CHECK(v == 1u, "eleven alphanumeric characters is not version 1");
		CHECK(size == 17u + 4u * v, "the size does not follow the version");
	}

	/* A LEVEL COSTS CAPACITY, so the same payload needs at least as large a
	 * version at every stronger level. Asserted as a relationship rather
	 * than as four numbers, which is what survives the tables changing. */
	{
		const char *text = "PROVISIONING CARD 1234567890";
		unsigned l = fzn_qr_version_for(text, strlen(text), FZN_QR_LEVEL_L);
		unsigned m = fzn_qr_version_for(text, strlen(text), FZN_QR_LEVEL_M);
		unsigned q = fzn_qr_version_for(text, strlen(text), FZN_QR_LEVEL_Q);
		unsigned h = fzn_qr_version_for(text, strlen(text), FZN_QR_LEVEL_H);

		CHECK(l <= m && m <= q && q <= h,
		      "a stronger level did not need at least as large a version");
		CHECK(l >= 1u && h <= FZN_QR_VERSION_MAX, "a version fell outside the range");
	}

	/* ALPHANUMERIC IS DENSER THAN BYTES, which is why the card fits at all:
	 * the same characters in a payload that forces byte mode need a bigger
	 * code. */
	{
		char upper[200];
		char lower[200];
		unsigned a;
		unsigned b;

		memset(upper, 'A', sizeof(upper) - 1u);
		upper[sizeof(upper) - 1u] = 0;
		memset(lower, 'a', sizeof(lower) - 1u);
		lower[sizeof(lower) - 1u] = 0;
		a = fzn_qr_version_for(upper, strlen(upper), FZN_QR_LEVEL_L);
		b = fzn_qr_version_for(lower, strlen(lower), FZN_QR_LEVEL_L);
		CHECK(a > 0 && b > 0 && a < b,
		      "lowercase did not cost a version, so the mode is not being chosen");
	}

	/* REFUSALS. A payload nothing holds, and a buffer too small, are
	 * different answers and a caller acts on them differently. */
	{
		static char huge[4000];
		size_t sized = 0;

		memset(huge, 'A', sizeof(huge) - 1u);
		huge[sizeof(huge) - 1u] = 0;
		CHECK(fzn_qr_encode(huge, strlen(huge), FZN_QR_LEVEL_L, modules,
		                    sizeof(modules), &sized) == FZN_QR_ERR_TOO_LONG,
		      "a payload past every version was not refused");
		CHECK(fzn_qr_version_for(huge, strlen(huge), FZN_QR_LEVEL_L) == 0,
		      "a payload past every version reported a version anyway");

		/* A SHORT BUFFER STILL LEARNS THE SIZE, which is what lets a
		 * caller ask once and then allocate. */
		sized = 0;
		CHECK(fzn_qr_encode("HELLO", 5u, FZN_QR_LEVEL_L, modules, 4u, &sized) ==
		              FZN_QR_ERR_FULL,
		      "a buffer too small was not refused");
		CHECK(sized == 21u, "a refused encode did not report the size it needed");
	}

	/* Arguments. */
	CHECK(fzn_qr_encode(NULL, 5u, FZN_QR_LEVEL_L, modules, sizeof(modules), &size) ==
	              FZN_QR_ERR_MALFORMED,
	      "a null payload was accepted");
	CHECK(fzn_qr_encode("A", 1u, (fzn_qr_level_t)9, modules, sizeof(modules), &size) ==
	              FZN_QR_ERR_MALFORMED,
	      "a level outside the four was accepted");
	CHECK(fzn_qr_encode("A", 1u, FZN_QR_LEVEL_L, modules, sizeof(modules), NULL) ==
	              FZN_QR_ERR_MALFORMED,
	      "nowhere to report the size");
	CHECK(strcmp(fzn_qr_err_str(FZN_QR_OK), "ok") == 0, "the renderer lost its ok");

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("qr_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
