/* Encode with fuzznet, decode with quirc. Two implementations, one answer. */
#include "qr/qr.h"
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
	memset(image, 0xff, (size_t)w * h);
	for (py = 0; py < size; py++)
		for (px = 0; px < size; px++)
			if (modules[py * size + px]) {
				int sy, sx;
				for (sy = 0; sy < SCALE; sy++)
					for (sx = 0; sx < SCALE; sx++)
						image[((py + QUIET) * SCALE + sy) * w +
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
			else { fail++; printf("  FAIL v%-2u %s (%zu chars): %s\n", v, NAMES[level], n, why); }
		}
	}
	printf("qrcheck: %d of %d version/level pairs round-tripped through quirc\n",
	       pass, pass + fail);
	return fail == 0 ? 0 : 1;
}
