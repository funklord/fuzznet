/* Encode with fuzznet, decode with quirc. Two implementations, one answer. */
#include "qr/qr.h"
#include "cli/qr_print.h"
#include <quirc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SCALE 4
#define QUIET 4

static int roundtrip(const char *text, fzn_qr_level_t level, char *why, size_t why_cap)
{
	static uint8_t modules[FZN_QR_MODULES_MAX];
	struct quirc *q;
	struct quirc_code code;
	struct quirc_data data;
	uint8_t *image;
	size_t size = 0;
	int w, h, n, ok = 0;
	unsigned px, py;

	if (fzn_qr_encode(text, strlen(text), level, modules, sizeof(modules), &size) !=
	    FZN_QR_OK) {
		snprintf(why, why_cap, "encode refused");
		return 0;
	}
	w = h = (int)((size + 2 * QUIET) * SCALE);
	q = quirc_new();
	if (!q || quirc_resize(q, w, h) < 0) { snprintf(why, why_cap, "quirc setup"); return 0; }
	image = quirc_begin(q, &w, &h);
	memset(image, 0xff, (size_t)w * (size_t)h);
	for (py = 0; py < size; py++)
		for (px = 0; px < size; px++)
			if (modules[py * size + px]) {
				unsigned sy, sx;

				for (sy = 0; sy < SCALE; sy++)
					for (sx = 0; sx < SCALE; sx++)
						image[((py + QUIET) * SCALE + sy) *
						              (unsigned)w +
						      (px + QUIET) * SCALE + sx] = 0;
			}
	quirc_end(q);
	n = quirc_count(q);
	if (n != 1) { snprintf(why, why_cap, "quirc found %d codes", n); quirc_destroy(q); return 0; }
	quirc_extract(q, 0, &code);
	if (quirc_decode(&code, &data) != QUIRC_SUCCESS) {
		snprintf(why, why_cap, "quirc could not decode");
		quirc_destroy(q); return 0;
	}
	if (data.payload_len != (int)strlen(text) ||
	    memcmp(data.payload, text, strlen(text)) != 0)
		snprintf(why, why_cap, "payload differs (%d bytes back)", data.payload_len);
	else ok = 1;
	quirc_destroy(q);
	return ok;
}

/* Read printed text back as a terminal would draw it: a glyph is LIGHT on a
 * dark background, so a filled block is a light module. Each cell becomes
 * 8x16 pixels, split top and bottom for the half blocks. */
static void cell_halves(const char *g, size_t n, int *upper, int *lower)
{
	*upper = 0;
	*lower = 0;
	if (n == 1 && g[0] == '#') {
		*upper = 1;
		*lower = 1;
	} else if (n == 3 && memcmp(g, "\xe2\x96\x88", 3) == 0) {
		*upper = 1;
		*lower = 1;
	} else if (n == 3 && memcmp(g, "\xe2\x96\x80", 3) == 0) {
		*upper = 1;
	} else if (n == 3 && memcmp(g, "\xe2\x96\x84", 3) == 0) {
		*lower = 1;
	}
}

static int decode_printed(const char *text, const char *want)
{
	const int cw = 8;
	const int ch = 16;
	int rows = 0;
	int cols = 0;
	int r = 0;
	int c = 0;
	const char *p;
	struct quirc *q;
	struct quirc_code code;
	struct quirc_data data;
	uint8_t *image;
	int w;
	int h;
	int ok = 0;

	for (p = text; *p; ) {
		if (*p == '\n') {
			rows++;
			if (c > cols)
				cols = c;
			c = 0;
			p++;
			continue;
		}
		p += (*p & 0x80) ? 3 : 1;
		c++;
	}
	if (rows == 0 || cols == 0)
		return 0;

	w = cols * cw;
	h = rows * ch;
	q = quirc_new();
	if (!q || quirc_resize(q, w, h) < 0) {
		if (q)
			quirc_destroy(q);
		return 0;
	}
	image = quirc_begin(q, &w, &h);
	memset(image, 0, (size_t)w * (size_t)h);
	r = 0;
	c = 0;
	for (p = text; *p; ) {
		size_t len = (*p & 0x80) ? 3u : 1u;
		int upper;
		int lower;
		int py;

		if (*p == '\n') {
			r++;
			c = 0;
			p++;
			continue;
		}
		cell_halves(p, len, &upper, &lower);
		for (py = 0; py < ch; py++) {
			int px;

			for (px = 0; px < cw; px++)
				image[(r * ch + py) * w + c * cw + px] =
				        (uint8_t)((py < ch / 2 ? upper : lower) ? 255 : 0);
		}
		c++;
		p += len;
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

int main(void)
{
	static const char *NAMES[] = { "L", "M", "Q", "H" };
	char text[900], why[128];
	int level, pass = 0, fail = 0;
	unsigned v;

	for (level = 0; level < 4; level++) {
		for (v = 1; v <= FZN_QR_VERSION_MAX; v++) {
			size_t n;
			/* The longest alphanumeric payload this version holds. */
			for (n = 1; n < sizeof(text) - 1; n++) {
				memset(text, 'A', n); text[n] = 0;
				if (fzn_qr_version_for(text, n, (fzn_qr_level_t)level) > v) break;
			}
			n--; memset(text, 0, sizeof(text));
			memset(text, 'A', n); text[n] = 0;
			if (n == 0 || fzn_qr_version_for(text, n, (fzn_qr_level_t)level) != v)
				continue;
			if (roundtrip(text, (fzn_qr_level_t)level, why, sizeof(why))) pass++;
			else {
				fail++;
				printf("  FAIL qr_quirc_check.c: v%u %s (%zu chars): %s\n",
				       v, NAMES[level], n, why);
			}
		}
	}
	/*
	 * AND THE TEXT SPELLING, sec 163. `cli/qr_print.c` writes the same
	 * modules as terminal characters, so the same question applies: does
	 * what it prints still decode?
	 *
	 * READ BACK AS A TERMINAL DRAWS IT -- a glyph is light on a dark
	 * background, so a filled block is a LIGHT module. That convention is
	 * the thing under test, and the inverted spelling is the control: it
	 * must NOT decode, or the filled-block choice was arbitrary.
	 *
	 * THE ASCII STYLE PASSES HERE AND THAT PROVES LESS THAN IT LOOKS.
	 * This models `#` as a cell filled edge to edge, which no real font
	 * does -- so the pass says the module LAYOUT is right and says nothing
	 * about the contrast a scanner would actually see. The header promises
	 * exactly that much and no more.
	 */
	{
		static uint8_t modules[FZN_QR_MODULES_MAX];
		static char printed[FZN_QR_PRINT_MAX];
		const char *want = "PROVISIONING CARD 1234567890";
		size_t size = 0;
		size_t len = 0;
		int style;

		if (fzn_qr_encode(want, strlen(want), FZN_QR_LEVEL_M, modules,
		                  sizeof(modules), &size) != FZN_QR_OK) {
			printf("  FAIL qr_quirc_check.c: the print fixture would not encode\n");
			fail++;
		} else {
			for (style = 0; style <= 2; style++) {
				static const char *SPELLING[] = { "half", "full", "ascii" };

				if (fzn_qr_print(modules, size, (fzn_qr_print_style_t)style, 0,
				                 printed, sizeof(printed), &len) != FZN_QR_OK) {
					printf("  FAIL qr_quirc_check.c: %s would not print\n",
					       SPELLING[style]);
					fail++;
					continue;
				}
				if (decode_printed(printed, want))
					pass++;
				else {
					printf("  FAIL qr_quirc_check.c: the %s spelling did "
					       "not decode off a terminal\n",
					       SPELLING[style]);
					fail++;
				}
			}
			/* THE CONTROL. */
			if (fzn_qr_print(modules, size, FZN_QR_PRINT_HALF, 1, printed,
			                 sizeof(printed), &len) == FZN_QR_OK) {
				if (decode_printed(printed, want)) {
					printf("  FAIL qr_quirc_check.c: the INVERTED spelling "
					       "decoded on a dark terminal, so the filled-block "
					       "convention is untested\n");
					fail++;
				} else {
					pass++;
				}
			}
		}
	}

	printf("qrcheck: %d of %d checks round-tripped through quirc\n", pass, pass + fail);
	return fail == 0 ? 0 : 1;
}
