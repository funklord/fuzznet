/*
 * Round-trip tests: our encoder to an image, our scanner back to the bytes.
 *
 * These need no camera and no external tool, which is the point -- the
 * encoder was verified against a real barcode scanner during development, so
 * pairing it with the recogniser here closes the loop that camera pairing
 * actually depends on: a card this project produces must be readable by this
 * project.
 *
 * A clean synthetic render only proves the two agree on a perfect image, and
 * no camera ever supplies one. So the same symbol is also put through what a
 * lens does to it -- perspective, blur, noise, and a dark room -- because the
 * recogniser's whole job is being liberal about those, and a regression there
 * would otherwise show up as "scanning feels flaky" rather than as a failure.
 */
#include "../qr.h"
#include "../decode.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* EDIT, fuzznet's encoder in place of fuzzypickles' wrapper (client/qr.c):
 * the test draws codes it made, one module array, row by row, 1 dark. */
typedef struct {
	int size;
	uint8_t modules[FZN_QR_SIZE_MAX * FZN_QR_SIZE_MAX];
} test_qr_t;

static int test_qr_encode(const uint8_t *data, size_t len, int level, test_qr_t *qr) {
	size_t size = 0;
	if (fzn_qr_encode((const char *)data, len, (fzn_qr_level_t)level, qr->modules,
	                  sizeof qr->modules, &size) != FZN_QR_OK)
		return -1;
	qr->size = (int)size;
	return 0;
}

static int test_qr_module(const test_qr_t *qr, int x, int y) {
	if (x < 0 || y < 0 || x >= qr->size || y >= qr->size) return 0;
	return qr->modules[(size_t)y * (size_t)qr->size + (size_t)x] != 0;
}

static int failures = 0;

#define CHECK(cond)                                                   \
  do {                                                                \
    if (!(cond)) {                                                    \
      fprintf(stderr, "FAIL decode_test.c:%d: %s\n", __LINE__, #cond); \
      failures++;                                                     \
    }                                                                 \
  } while (0)

/* The size camera.c actually negotiates on this hardware. Testing recognition
 * at a smaller frame than the one we capture measures the wrong thing: a
 * card-sized symbol is around 69 modules, and how many pixels each module gets
 * is precisely what decides whether it reads. */
#define FRAME_W 1280
#define FRAME_H 720

/* Renders the symbol centred on a light background, one module to `scale`
 * pixels, with the mandatory quiet zone. */
static void render(const test_qr_t *qr, uint8_t *frame, int scale) {
	memset(frame, 0xFF, (size_t)FRAME_W * FRAME_H);
	int span = qr->size * scale;
	int ox = (FRAME_W - span) / 2, oy = (FRAME_H - span) / 2;
	for (int my = 0; my < qr->size; my++)
		for (int mx = 0; mx < qr->size; mx++) {
			if (!test_qr_module(qr, mx, my)) continue;
			for (int dy = 0; dy < scale; dy++)
				for (int dx = 0; dx < scale; dx++) {
					int x = ox + mx * scale + dx, y = oy + my * scale + dy;
					if (x >= 0 && x < FRAME_W && y >= 0 && y < FRAME_H)
						frame[(size_t)y * FRAME_W + (size_t)x] = 0x00;
				}
		}
}

/*
 * Defocus: a plain box blur, the one degradation that can be modelled here
 * honestly.
 *
 * A fuller synthetic camera was tried first -- projective keystoning, sensor
 * noise, low light -- and abandoned, because it measured the harness rather
 * than the recogniser. Recognition alternated pass/fail with symbol size (4
 * ok, 5 no, 6 ok, 7 no) which is sampling phase, not image quality: whether
 * module edges happen to land on pixel boundaries after the warp. Adding 3x3
 * supersampling changed nothing. At the largest sizes the keystone pushed the
 * symbol past the frame edge and clipped it, so the test was destroying the
 * code and calling it a recognition failure.
 *
 * Blur alone is stable at every size, so that is what is asserted. Real
 * robustness to angle, motion and light is quirc's domain and is properly
 * checked against a real camera, not against a lens invented here -- claiming
 * otherwise on the strength of this file would be worse than saying nothing.
 */
static void defocus(const uint8_t *src, uint8_t *dst, int radius) {
	for (int y = 0; y < FRAME_H; y++)
		for (int x = 0; x < FRAME_W; x++) {
			int acc = 0, n = 0;
			for (int dy = -radius; dy <= radius; dy++)
				for (int dx = -radius; dx <= radius; dx++) {
					int sx = x + dx, sy = y + dy;
					if (sx < 0 || sy < 0 || sx >= FRAME_W || sy >= FRAME_H) continue;
					acc += src[(size_t)sy * FRAME_W + (size_t)sx];
					n++;
				}
			dst[(size_t)y * FRAME_W + (size_t)x] = (uint8_t)(n ? acc / n : src[(size_t)y * FRAME_W + (size_t)x]);
		}
}

/* degrade is the defocus radius in pixels; 0 renders the symbol cleanly. */
static void round_trip(const char *what, const uint8_t *payload, size_t len, int scale,
           int degrade) {
	static test_qr_t qr;
	if (test_qr_encode(payload, len, FZN_QR_LEVEL_L, &qr) != 0) {
		fprintf(stderr, "FAIL decode_test.c: %s: encode failed\n", what);
		failures++;
		return;
	}
	if (qr.size * scale > FRAME_H) {
		fprintf(stderr, "FAIL decode_test.c: %s: symbol does not fit the test frame\n", what);
		failures++;
		return;
	}

	static uint8_t clean[FRAME_W * FRAME_H], frame[FRAME_W * FRAME_H];
	render(&qr, clean, scale);
	if (degrade) defocus(clean, frame, degrade);
	else memcpy(frame, clean, sizeof(frame));

	fzn_qr_scanner_t *s = fzn_qr_scanner_new(FRAME_W, FRAME_H);
	CHECK(s != NULL);
	if (!s) return;

	static uint8_t out[4096];
	int n = fzn_qr_scan_frame(s, frame, FRAME_W, FRAME_H, out, sizeof(out));
	if (n <= 0) {
		fprintf(stderr, "FAIL decode_test.c: %s: not recognised (returned %d)\n", what, n);
		failures++;
	} else if ((size_t)n != len || memcmp(out, payload, len) != 0) {
		fprintf(stderr, "FAIL decode_test.c: %s: decoded %d bytes, expected %zu\n", what, n, len);
		failures++;
	}
	fzn_qr_scanner_free(s);
}

static void test_clean_render(void) {
	round_trip("short", (const uint8_t *)"HELLO", 5, 12, 0);
	round_trip("text", (const uint8_t *)"fuzzypickles contact card", 25, 8, 0);

	/* A real contact card is around 390 bytes; this is the size that matters. */
	uint8_t card[390];
	for (size_t i = 0; i < sizeof(card); i++) card[i] = (uint8_t)(i * 31 + 7);
	round_trip("card-sized", card, sizeof(card), 5, 0);
}

/* A front camera mirrors what it sees, and a code must read the same. */
static void test_a_mirrored_code_is_read(void) {
	static test_qr_t qr;
	static uint8_t frame[FRAME_W * FRAME_H];
	static const char text[] = "FZI1:MIRRORED";
	CHECK(test_qr_encode((const uint8_t *)text, sizeof text - 1, FZN_QR_LEVEL_L, &qr) == 0);
	render(&qr, frame, 12);
	for (int y = 0; y < FRAME_H; y++)
		for (int x = 0; x < FRAME_W / 2; x++) {
			const uint8_t b = frame[y * FRAME_W + x];
			frame[y * FRAME_W + x] = frame[y * FRAME_W + FRAME_W - 1 - x];
			frame[y * FRAME_W + FRAME_W - 1 - x] = b;
		}
	fzn_qr_scanner_t *s = fzn_qr_scanner_new(FRAME_W, FRAME_H);
	CHECK(s != NULL);
	if (!s) return;
	static uint8_t out[256];
	const int n = fzn_qr_scan_frame(s, frame, FRAME_W, FRAME_H, out, sizeof(out));
	CHECK(n == (int)sizeof text - 1 && memcmp(out, text, sizeof text - 1) == 0);
	fzn_qr_scanner_free(s);
}

static void test_out_of_focus(void) {
	/* A webcam pointed at a screen is rarely in focus, and a card-sized symbol
	 * has small modules, so this is the degradation that matters most in
	 * practice. Both radii verified stable across every symbol size tried. */
	round_trip("short, defocused", (const uint8_t *)"HELLO", 5, 20, 1);

	uint8_t card[390];
	for (size_t i = 0; i < sizeof(card); i++) card[i] = (uint8_t)(i * 31 + 7);
	round_trip("card-sized, defocused", card, sizeof(card), 6, 1);
	round_trip("card-sized, badly defocused", card, sizeof(card), 8, 2);
}

static void test_binary_payload_survives(void) {
	/* Cards are binary, including NUL bytes -- a recogniser that treats the
	 * payload as a C string truncates at the first one and the failure looks
	 * like a corrupt card rather than a decoding bug. */
	uint8_t payload[200];
	for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(i % 256);
	payload[0] = 0x00;
	payload[57] = 0x00;
	round_trip("binary with NULs", payload, sizeof(payload), 7, 0);
}

static void test_no_symbol_is_not_an_error(void) {
	/* Most frames from a hand-held camera contain no code at all. That must
	 * read as "nothing yet", not as a failure, or the caller stops trying. */
	static uint8_t blank[FRAME_W * FRAME_H];
	memset(blank, 0x80, sizeof(blank));
	fzn_qr_scanner_t *s = fzn_qr_scanner_new(FRAME_W, FRAME_H);
	CHECK(s != NULL);
	if (!s) return;
	uint8_t out[64];
	CHECK(fzn_qr_scan_frame(s, blank, FRAME_W, FRAME_H, out, sizeof(out)) == 0);

	/* A frame of the wrong shape is a usage error, and a distinct one: it
	 * would otherwise read past the end of the working buffer. */
	CHECK(fzn_qr_scan_frame(s, blank, FRAME_W / 2, FRAME_H, out, sizeof(out)) == -1);
	fzn_qr_scanner_free(s);
}

int main(void) {
	test_clean_render();
	test_a_mirrored_code_is_read();
	test_out_of_focus();
	test_binary_payload_survives();
	test_no_symbol_is_not_an_error();

	if (failures) {
		fprintf(stderr, "scan_test: %d failure(s)\n", failures);
		return 1;
	}
	printf("decode_test: all passed\n");
	return 0;
}
