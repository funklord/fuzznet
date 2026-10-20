/* The local grammar's %XX escape, one copy, sec 668. */

#include "../escape.h"

#include <stdio.h>
#include <string.h>

static int checks;
static int failures;

static void ok_at(int cond, int line, const char *what)
{
	checks++;
	if (!cond) {
		failures++;
		printf("  FAIL escape_test.c:%d: %s\n", line, what);
	}
}

#define ok(c, what) ok_at((c) ? 1 : 0, __LINE__, (what))

int main(void)
{
	static const uint8_t raw[] = { 'a', ' ', '%', ',', 0x7f, 0x00, 'z', 0x21 };
	char out[64];
	uint8_t back[64];
	size_t written = 0, len = 0;

	ok(fzn_escape(raw, sizeof(raw), out, sizeof(out), &written) == sizeof(raw)
	       && written == 18u && memcmp(out, "a%20%25%2c%7f%00z!", 18u) == 0,
	   "a space, %, comma, DEL and NUL were not written %XX in lower case, the rest as is");
	ok(fzn_unescape((const uint8_t *)out, written, back, sizeof(back), &len) && len == sizeof(raw)
	       && memcmp(back, raw, sizeof(raw)) == 0,
	   "an escape did not read back to its bytes");
	ok(fzn_unescape((const uint8_t *)"a%2Cb%2cc", 9u, back, sizeof(back), &len) && len == 5u
	       && memcmp(back, "a,b,c", 5u) == 0,
	   "either case of hex was not read");
	/* CUT SHORT BY THE LENGTH, a hex digit just past it in memory: what a
	 * reader past the input would take. */
	ok(!fzn_unescape((const uint8_t *)"a%21", 3u, back, sizeof(back), &len),
	   "an escape cut short by the length was read, the byte past it taken");
	ok(!fzn_unescape((const uint8_t *)"a%zz", 4u, back, sizeof(back), &len),
	   "an escape that is no hex was read");
	ok(!fzn_unescape((const uint8_t *)"abcd", 4u, back, 3u, &len), "an output past cap was read");
	ok(fzn_unescape((const uint8_t *)"%41", 3u, back, sizeof(back), &len) && len == 1u
	       && back[0] == 'A',
	   "an escape at the very end was refused");
	/* AS FAR AS IT FITS: a byte's whole escape or none of it. */
	ok(fzn_escape(raw, sizeof(raw), out, 5u, &written) == 2u && written == 4u,
	   "an escape cut by the room was not stopped before the byte that did not fit");
	ok(fzn_escape(raw, 0u, out, sizeof(out), &written) == 0u && written == 0u,
	   "nothing was not escaped as nothing");
	if (failures) {
		printf("escape_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("escape_test: all %d checks passed\n", checks);
	return 0;
}
