/* See qr_print.h. */

#include "qr_print.h"

#include <string.h>

/* The four half-block spellings, indexed by (upper << 1) | lower where a set
 * bit is a LIGHT module -- see the header for why the filled glyph is light.
 *
 * UNICODE IN A STRING LITERAL, WHICH IS THE ONE PLACE THE RULE ALLOWS IT.
 * `code-style.md` keeps source and comments ASCII and names user-facing
 * output as the exception; these are the bytes a terminal draws, and there is
 * no ASCII spelling of half a cell. */
static const char *const HALF[4] = {
	" ",      /* both dark  */
	"▄", /* lower light */
	"▀", /* upper light */
	"█", /* both light  */
};

/* Two cells a module, for a terminal whose half blocks render badly. */
static const char *const FULL[2] = { "  ", "██" };
static const char *const ASCII[2] = { "  ", "##" };

/* Whether the module at (x, y) is LIGHT, with the quiet zone -- which is
 * always light -- and `invert` folded in.
 *
 * OUT OF RANGE IS THE QUIET ZONE, which is what lets the callers below walk
 * the padded square without a special case at every edge. */
static int light_at(const uint8_t *modules, size_t size, int x, int y, int invert)
{
	const int quiet = (int)FZN_QR_QUIET;
	int mx = x - quiet;
	int my = y - quiet;
	int dark;

	if (mx < 0 || my < 0 || mx >= (int)size || my >= (int)size)
		dark = 0;
	else
		dark = modules[(size_t)my * size + (size_t)mx] != 0;

	return invert ? dark : !dark;
}

/* Append `s`, or count what it would have taken. `at` advances either way, so
 * one walk both sizes and writes. */
static void put(char *out, size_t cap, size_t *at, const char *s)
{
	size_t n = strlen(s);

	if (out && *at + n < cap)
		memcpy(out + *at, s, n);
	*at += n;
}

fzn_qr_err_t fzn_qr_print(const uint8_t *modules, size_t size,
                          fzn_qr_print_style_t style, int invert, char *out, size_t cap,
                          size_t *len_out)
{
	const int quiet = (int)FZN_QR_QUIET;
	int across;
	size_t at = 0;
	int y;
	int x;

	if (!modules || !len_out)
		return FZN_QR_ERR_MALFORMED;
	if (style != FZN_QR_PRINT_HALF && style != FZN_QR_PRINT_FULL &&
	    style != FZN_QR_PRINT_ASCII)
		return FZN_QR_ERR_MALFORMED;
	/* A QR code is 17 + 4v modules for some version, which is every size
	 * from 21 to 177 in steps of four. A caller handing this something
	 * else has a buffer that is not a code. */
	if (size < 21u || size > FZN_QR_SIZE_MAX || ((size - 21u) % 4u) != 0u)
		return FZN_QR_ERR_MALFORMED;
	if (!out && cap > 0)
		return FZN_QR_ERR_MALFORMED;

	across = (int)size + 2 * quiet;

	if (style == FZN_QR_PRINT_HALF) {
		/* TWO MODULE ROWS TO A TEXT ROW. An odd number of rows leaves
		 * the last one with nothing below it, and that half must be
		 * LIGHT rather than absent: a dark strip along the bottom eats
		 * into the quiet zone, which is the part a scanner needs
		 * most. `light_at` answers light for anything out of range, so
		 * this falls out rather than being special-cased. */
		for (y = 0; y < across; y += 2) {
			for (x = 0; x < across; x++) {
				int upper = light_at(modules, size, x, y, invert);
				int lower = light_at(modules, size, x, y + 1, invert);

				put(out, cap, &at, HALF[(upper << 1) | lower]);
			}
			put(out, cap, &at, "\n");
		}
	} else {
		const char *const *pair = (style == FZN_QR_PRINT_FULL) ? FULL : ASCII;

		for (y = 0; y < across; y++) {
			for (x = 0; x < across; x++)
				put(out, cap, &at, pair[light_at(modules, size, x, y, invert)]);
			put(out, cap, &at, "\n");
		}
	}

	*len_out = at;
	if (!out || at + 1u > cap)
		return FZN_QR_ERR_FULL;
	out[at] = '\0';

	return FZN_QR_OK;
}
