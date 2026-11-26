/*
 * fingerprint_test -- which recording a tune is (media/fingerprint.h,
 * project.md sec 1459). AcoustID's answer read: its best result's AcoustID
 * and recording, an error told from an empty answer, and every cut and
 * mangling of an answer read without reading past it, nested ten thousand
 * deep refused. And, where the build has FFmpeg with Chromaprint, a tune
 * made here printed: the same tune with a little noise over it is near its
 * print (snurra's measure, under 0.2), another tune is far, and the base64
 * form AcoustID takes is printable text; nothing is sent without a key.
 */
#include "../analysis.h"
#include "../fingerprint.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static int checks, failures;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			fprintf(stderr, "  FAIL fingerprint_test.c:%d: ", __LINE__); \
			fprintf(stderr, __VA_ARGS__);                          \
			fputc('\n', stderr);                                   \
		}                                                              \
	} while (0)

static const char ANSWER[] =
        "{\"status\": \"ok\", \"results\": ["
        "{\"id\": \"0b1cf1a2-1111-4b4b-8c8c-000000000001\", \"score\": 0.41,"
        " \"recordings\": [{\"id\": \"aaaaaaaa-0000-4000-8000-000000000001\"}]},"
        "{\"score\": 0.97, \"id\": \"0b1cf1a2-2222-4b4b-8c8c-000000000002\","
        " \"recordings\": [{\"id\": \"bbbbbbbb-0000-4000-8000-000000000002\", \"sources\": [1, 2.5e1, true, null]},"
        " {\"id\": \"cccccccc-0000-4000-8000-000000000003\"}], \"extra\": {\"a\": [[], {}], \"b\": \"x\\\"y\"}}]}";

static void reading(void)
{
	fzn_media_identity_t id;
	char *nested;
	size_t i;

	CHECK(fzn_media_acoustid_read(ANSWER, strlen(ANSWER), &id) == FZN_MEDIA_LOOKUP_FOUND
	              && !strcmp(id.acoustid, "0b1cf1a2-2222-4b4b-8c8c-000000000002")
	              && !strcmp(id.recording, "bbbbbbbb-0000-4000-8000-000000000002") && fabs(id.score - 0.97) < 1e-9,
	      "the best result was not read: %s %s %.2f", id.acoustid, id.recording, id.score);
	{
		static const char error[] = "{\"status\": \"error\", \"error\": {\"code\": 4, \"message\": \"invalid API key\"}}";
		static const char empty[] = "{\"status\": \"ok\", \"results\": []}";
		static const char bad_id[] = "{\"status\": \"ok\", \"results\": [{\"id\": \"$(rm -rf ~)\", \"score\": 1}]}";
		static const char no_recording[] =
		        "{\"status\": \"ok\", \"results\": [{\"id\": \"0b1cf1a2-3333-4b4b-8c8c-000000000003\", \"score\": 0.9}]}";

		CHECK(fzn_media_acoustid_read(error, strlen(error), &id) == FZN_MEDIA_LOOKUP_REFUSED && !id.acoustid[0],
		      "an error was not told as one");
		CHECK(fzn_media_acoustid_read(empty, strlen(empty), &id) == FZN_MEDIA_LOOKUP_UNKNOWN,
		      "an answer naming nothing was not told as unknown");
		CHECK(fzn_media_acoustid_read(bad_id, strlen(bad_id), &id) == FZN_MEDIA_LOOKUP_UNKNOWN && !id.acoustid[0],
		      "an id that is no UUID was taken");
		CHECK(fzn_media_acoustid_read(no_recording, strlen(no_recording), &id) == FZN_MEDIA_LOOKUP_FOUND
		              && !id.recording[0],
		      "an AcoustID with no recording was not read");
	}
	/* EVERY CUT of the answer: never found, never past it. */
	for (i = 0; i < strlen(ANSWER); i++) {
		char *cut = malloc(i ? i : 1u);

		memcpy(cut, ANSWER, i);
		if (fzn_media_acoustid_read(cut, i, &id) == FZN_MEDIA_LOOKUP_FOUND) {
			CHECK(0, "an answer cut at %zu was read whole", i);
			free(cut);
			break;
		}
		free(cut);
	}
	/* EVERY BYTE MANGLED, three ways: read or refused, never past the end. */
	for (i = 0; i < strlen(ANSWER); i++) {
		static const char with[3] = { '{', '"', '\0' };
		int k;

		for (k = 0; k < 3; k++) {
			char *m = malloc(strlen(ANSWER));

			memcpy(m, ANSWER, strlen(ANSWER));
			m[i] = with[k];
			(void)fzn_media_acoustid_read(m, strlen(ANSWER), &id);
			free(m);
		}
	}
	nested = malloc(20001u);
	memset(nested, '[', 10000u);
	memset(nested + 10000u, ']', 10000u);
	nested[20000] = '\0';
	memcpy(nested, "{\"x\":", 5u);
	CHECK(fzn_media_acoustid_read(nested, 20000u, &id) == FZN_MEDIA_LOOKUP_NO_ANSWER,
	      "an answer nested ten thousand deep was read");
	free(nested);
	CHECK(fzn_media_acoustid_read(NULL, 0, &id) == FZN_MEDIA_LOOKUP_NO_ANSWER, "no answer was read");
}

static uint64_t seed;
static float white(void)
{
	seed ^= seed << 13;
	seed ^= seed >> 7;
	seed ^= seed << 17;
	return (float)((double)(seed >> 11) / 9007199254740992.0 * 2.0 - 1.0);
}

/* Forty seconds of chords, a progression a tune; `noise` over it. */
static size_t print_of(int tune, float noise, uint32_t *raw, size_t cap)
{
	static const int prog[2][4][3] = { { { 57, 60, 64 }, { 62, 65, 69 }, { 64, 67, 71 }, { 57, 60, 64 } },
		                           { { 66, 70, 73 }, { 71, 75, 78 }, { 61, 65, 68 }, { 66, 70, 73 } } };
	fzn_media_print_t *p = fzn_media_print_open(1);
	const size_t frames = 40u * FZN_MEDIA_ANALYSIS_RATE;
	float block[2 * 1024];
	size_t at = 0, i, n;

	if (!p)
		return 0;
	seed = 9;
	while (at < frames) {
		for (i = 0; i < 1024u; i++) {
			const size_t f = at + i;
			const double t = (double)f / FZN_MEDIA_ANALYSIS_RATE;
			const int *chord = prog[tune][(f / (FZN_MEDIA_ANALYSIS_RATE / 2u)) % 4u];
			double v = 0;
			int c;

			for (c = 0; c < 3; c++)
				v += 0.1 * sin(2 * M_PI * 440 * pow(2.0, (chord[c] - 69) / 12.0) * t);
			v *= 0.5 + 0.5 * sin(2 * M_PI * 2 * t) * sin(2 * M_PI * 2 * t);
			block[2 * i] = block[2 * i + 1] = (float)v + noise * white();
		}
		(void)fzn_media_print_add(p, block, 1024u);
		at += 1024u;
	}
	n = fzn_media_print_finish(p, (uint8_t *)raw, cap * 4u);
	return n / 4u;
}

static void printing(void)
{
	static uint32_t a[4096], b[4096], c[4096];
	size_t an, bn, cn, n, i;
	fzn_media_print_t *p = fzn_media_print_open(0);
	fzn_media_identity_t id;
	uint8_t text[8192];
	double near, far;

	if (!p) {
		printf("fingerprint_test: this build cannot print (no FFmpeg, or no Chromaprint in it); those checks not run\n");
		return;
	}
	fzn_media_print_free(p);
	an = print_of(0, 0.0f, a, 4096u);
	bn = print_of(0, 0.02f, b, 4096u);
	cn = print_of(1, 0.0f, c, 4096u);
	near = fzn_media_print_distance(a, an, b, bn, 80, 40);
	far = fzn_media_print_distance(a, an, c, cn, 80, 40);
	CHECK(an > 100u && bn > 100u && cn > 100u, "forty seconds printed %zu, %zu and %zu sub-fingerprints", an, bn, cn);
	printf("fingerprint_test: one tune under noise %.3f from itself, another %.3f\n", near, far);
	CHECK(near < 0.2 && far > 0.3, "one tune under noise %.3f from itself, another %.3f", near, far);
	/* THE FORM ACOUSTID TAKES: printable, URL-safe base64. */
	p = fzn_media_print_open(0);
	{
		static float silence[2 * 48000];
		static float tone[2 * 48000];

		for (i = 0; i < 48000u; i++)
			tone[2 * i] = tone[2 * i + 1] = (float)(0.3 * sin(2 * M_PI * 440 * (double)i / 48000.0)
			                                         * (0.5 + 0.5 * sin(2 * M_PI * 3 * (double)i / 48000.0)));
		for (i = 0; i < 20u; i++)
			(void)fzn_media_print_add(p, i % 2u ? tone : silence, 48000u);
	}
	n = fzn_media_print_finish(p, text, sizeof(text));
	for (i = 0; i < n && ((text[i] >= 'A' && text[i] <= 'Z') || (text[i] >= 'a' && text[i] <= 'z')
	                      || (text[i] >= '0' && text[i] <= '9') || text[i] == '-' || text[i] == '_');
	     i++)
		;
	CHECK(n > 20u && i == n, "the base64 print was %zu bytes, printable to %zu", n, i);
	CHECK(fzn_media_print_finish(fzn_media_print_open(0), text, sizeof(text)) == 0, "nothing heard printed something");
	/* NOTHING SENT WITHOUT A KEY, or a print. */
	CHECK(fzn_media_acoustid_lookup("http://127.0.0.1:1/", "", "AQAA", 30, &id) == FZN_MEDIA_LOOKUP_NONE
	              && fzn_media_acoustid_lookup("http://127.0.0.1:1/", "key", "", 30, &id) == FZN_MEDIA_LOOKUP_NONE,
	      "a lookup went without a key or a print");
	CHECK(fzn_media_acoustid_lookup("http://127.0.0.1:1/", "key", "AQAA", 30, &id) == FZN_MEDIA_LOOKUP_NO_ANSWER,
	      "a service that is not there answered");
}

int main(void)
{
	reading();
	printing();
	if (failures) {
		fprintf(stderr, "media fingerprint_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("media fingerprint_test: all %d checks passed\n", checks);
	return 0;
}
