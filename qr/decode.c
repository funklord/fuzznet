#include "decode.h"

#include <stdlib.h>
#include <string.h>

#include "quirc.h"

/* The only file that knows a recogniser was vendored. Everything above this
 * speaks fzn_qr_scan_* and would not notice a different one underneath. */
struct fzn_qr_scanner {
	struct quirc *q;
	unsigned width, height;
};

fzn_qr_scanner_t *fzn_qr_scanner_new(unsigned width, unsigned height) {
	if (width == 0 || height == 0) return NULL;
	fzn_qr_scanner_t *s = calloc(1, sizeof(*s));
	if (!s) return NULL;
	s->q = quirc_new();
	if (!s->q) {
		free(s);
		return NULL;
	}
	if (quirc_resize(s->q, (int)width, (int)height) < 0) {
		quirc_destroy(s->q);
		free(s);
		return NULL;
	}
	s->width = width;
	s->height = height;
	return s;
}

void fzn_qr_scanner_free(fzn_qr_scanner_t *s) {
	if (!s) return;
	if (s->q) quirc_destroy(s->q);
	free(s);
}

int fzn_qr_scan_frame(fzn_qr_scanner_t *s, const uint8_t *gray, unsigned width, unsigned height,
       uint8_t *out, size_t out_cap) {
	if (!s || !gray || !out) return -1;
	/* The scanner is sized once; a frame of a different shape means the caller
	 * changed capture format without rebuilding it, which would otherwise read
	 * past the end of the working buffer. */
	if (width != s->width || height != s->height) return -1;

	int w = 0, h = 0;
	uint8_t *buf = quirc_begin(s->q, &w, &h);
	if (!buf || w != (int)width || h != (int)height) {
		quirc_end(s->q);
		return -1;
	}
	memcpy(buf, gray, (size_t)width * height);
	quirc_end(s->q);

	/*
	 * A frame can hold several symbols -- a phone showing one next to a
	 * sticker, or a reflection. Take the first that decodes cleanly rather
	 * than the first that is merely found: an undecodable symbol is not a
	 * reason to ignore a good one beside it.
	 */
	int count = quirc_count(s->q);
	for (int i = 0; i < count; i++) {
		struct quirc_code code;
		struct quirc_data data;
		quirc_extract(s->q, i, &code);
		quirc_decode_error_t rc = quirc_decode(&code, &data);
		/* A front camera's picture is mirrored, and reads as a code whose
		 * format is right and whose data is wrong. */
		if (rc == QUIRC_ERROR_DATA_ECC) {
			quirc_flip(&code);
			rc = quirc_decode(&code, &data);
		}
		if (rc != QUIRC_SUCCESS) continue;
		if (data.payload_len <= 0) continue;
		if ((size_t)data.payload_len > out_cap) continue; /* not ours; keep looking */
		memcpy(out, data.payload, (size_t)data.payload_len);
		return data.payload_len;
	}
	return 0;
}
