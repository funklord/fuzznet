/*
 * analysis_test -- a tune's tempo, key and loudness (media/analysis.h,
 * project.md sec 1457), held to snurra's own measurements of its detector:
 * the same made signals -- a bare kick, a pattern of kick, snare, hats and
 * a held chord, at five tempi and phases, each beat known to the frame --
 * found within 0.02 BPM and every beat within 10 ms of the grid; noise, a
 * steady tone and hits at random times given no beat; a dotted rhythm's
 * beat and not its pulse; chords in four keys found, noise and drums given
 * none; a sine's loudness to a tenth of a LU; keys named on the Camelot
 * wheel. Fed in uneven pieces, as a decoder hands them.
 */
#include "../analysis.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define RATE ((int)FZN_MEDIA_ANALYSIS_RATE)

static int checks, failures;

#define CHECK(cond, ...)                                                    \
	do {                                                                \
		checks++;                                                   \
		if (!(cond)) {                                              \
			failures++;                                         \
			fprintf(stderr, "  FAIL analysis_test.c:%d: ", __LINE__); \
			fprintf(stderr, __VA_ARGS__);                       \
			fputc('\n', stderr);                                \
		}                                                           \
	} while (0)

/* xorshift: the same noise every run. */
static uint64_t seed;
static float white(void)
{
	seed ^= seed << 13;
	seed ^= seed >> 7;
	seed ^= seed << 17;
	return (float)((double)(seed >> 11) / 9007199254740992.0 * 2.0 - 1.0);
}

enum hit { KICK, SNARE, HAT };

/* A drum hit at `at` frames: a decaying 55 Hz thump and a click (kick), or
 * decaying noise (snare, or a short high hat) -- snurra's. */
static void add_hit(float *out, size_t n, double at, enum hit hit)
{
	const int length = hit == HAT ? RATE / 40 : RATE / 4;
	const long start = lround(at);
	float last = 0;
	int i;

	for (i = 0; i < length && start + i < (long)n; ++i) {
		const double t = (double)i / RATE;
		float v = 0;

		if (start + i < 0)
			continue;
		if (hit == KICK)
			v = (float)(0.7 * sin(2 * M_PI * 55 * t) * exp(-t / 0.09) + (i < 96 ? 0.3 * white() : 0));
		if (hit == SNARE)
			v = (float)(0.4 * white() * exp(-t / 0.07));
		if (hit == HAT) {
			const float w = white();
			v = (float)(0.15 * (w - last) * exp(-t / 0.01));
			last = w;
		}
		out[start + i] += v;
	}
}

static double beats[400];
static size_t beat_count;

/* `seconds` of a beat at `bpm`, the first at `first` seconds: a bare kick,
 * or kick, snare, kick, snare with eighth-note hats and a held chord. */
static float *beat(double bpm, double first, int pattern, int seconds, size_t *n)
{
	const double period = 60.0 * RATE / bpm;
	float *mono;
	size_t i;
	int k;

	*n = (size_t)seconds * RATE;
	mono = calloc(*n, sizeof(*mono));
	seed = 7;
	beat_count = 0;
	if (pattern)
		for (i = 0; i < *n; ++i) {
			const double t = (double)i / RATE;
			mono[i] += (float)(0.08 * (sin(2 * M_PI * 220 * t) + sin(2 * M_PI * 277.2 * t) + sin(2 * M_PI * 329.6 * t)));
		}
	for (k = 0;; ++k) {
		const double at = first * RATE + k * period;

		if (at >= (double)*n)
			break;
		if (beat_count < sizeof(beats) / sizeof(beats[0]))
			beats[beat_count++] = at;
		add_hit(mono, *n, at, pattern && k % 2 ? SNARE : KICK);
		if (pattern) {
			add_hit(mono, *n, at, HAT);
			add_hit(mono, *n, at + period / 2, HAT);
		}
	}
	return mono;
}

/* Mono into the analysis as stereo, in pieces of 1 to 4096 frames. */
static int analyse(const float *mono, size_t n, fzn_media_sound_t *out)
{
	fzn_media_analysis_t *a = fzn_media_analysis_open();
	float piece[2 * 4096];
	size_t at = 0, size = 1, i;

	if (!a)
		return 0;
	while (at < n) {
		size_t take = n - at < size ? n - at : size;

		for (i = 0; i < take; i++)
			piece[2 * i] = piece[2 * i + 1] = mono[at + i];
		if (!fzn_media_analysis_add(a, piece, take)) {
			fzn_media_analysis_free(a);
			return 0;
		}
		at += take;
		size = size * 7 % 4093 + 1;
	}
	return fzn_media_analysis_finish(a, out, NULL);
}

static void a_beat_is_found(double bpm, double first, int pattern)
{
	fzn_media_sound_t s;
	size_t n, i;
	float *mono = beat(bpm, first, pattern, 60, &n);
	double worst = 0;

	CHECK(analyse(mono, n, &s) && s.bpm > 0, "%.2f BPM: no beat found (confidence %.1f)", bpm, s.confidence);
	if (s.bpm > 0) {
		const double period = 60.0 * RATE / s.bpm, grid_first = s.first * RATE;

		for (i = 0; i < beat_count; i++) {
			const double k = round((beats[i] - grid_first) / period);
			const double error = fabs(grid_first + k * period - beats[i]) / RATE * 1000;

			if (error > worst)
				worst = error;
		}
		CHECK(fabs(s.bpm - bpm) < 0.02, "%.2f BPM found as %.4f", bpm, s.bpm);
		CHECK(worst < 10, "%.2f BPM: a beat %.2f ms off the grid", bpm, worst);
	}
	free(mono);
}

static void no_beat(int kind)
{
	const size_t n = (size_t)60 * RATE;
	float *mono = calloc(n, sizeof(*mono));
	fzn_media_sound_t s;
	size_t i;

	seed = 11;
	if (kind == 0)
		for (i = 0; i < n; i++)
			mono[i] = 0.3f * white();
	if (kind == 1)
		for (i = 0; i < n; i++)
			mono[i] = (float)(0.3 * sin(2 * M_PI * 440 * (double)i / RATE));
	if (kind == 2) {
		double at = 0;

		while (at < (double)n) {
			double u = (white() + 1.0) / 2.0;

			add_hit(mono, n, at, KICK);
			at += -log(u > 1e-9 ? u : 1e-9) / 2.0 * RATE; /* two a second, at random */
		}
	}
	CHECK(analyse(mono, n, &s) && s.bpm == 0, "kind %d: a beat at %.2f BPM was found (confidence %.2f)", kind,
	      s.bpm, s.confidence);
	free(mono);
}

/* A kick on every beat at 132 and an open hat over a soft chord every beat
 * and a half: the beat is 132, not the hats' 88. */
static void dotted(void)
{
	const size_t n = (size_t)60 * RATE;
	const double period = 60.0 * RATE / 132;
	float *mono = calloc(n, sizeof(*mono));
	fzn_media_sound_t s;
	int k;

	seed = 3;
	for (k = 0;; ++k) {
		const double at = 0.05 * RATE + k * period;

		if (at >= (double)n)
			break;
		add_hit(mono, n, at, KICK);
	}
	for (k = 0;; ++k) {
		const size_t at = (size_t)lround(0.05 * RATE + k * 1.5 * period);
		float last = 0;
		size_t i;

		if (at >= n)
			break;
		for (i = 0; i < (size_t)(RATE / 8) && at + i < n; ++i) {
			const double t = (double)i / RATE;
			const float w = white();
			const double chord = sin(2 * M_PI * 440 * t) + sin(2 * M_PI * 554 * t) + sin(2 * M_PI * 659 * t);

			mono[at + i] += (float)((0.7 * (w - last) + 0.1 * chord) * exp(-t / 0.05));
			last = w;
		}
	}
	CHECK(analyse(mono, n, &s) && fabs(s.bpm - 132) < 0.1, "a dotted rhythm read as %.2f BPM, not 132", s.bpm);
	free(mono);
}

/* Chords, two seconds each round and round for a minute, each note with
 * its harmonics and the root an octave down as a bass. */
static void a_key(const int chords[4][3], int drums, int noise, int want, const char *what)
{
	size_t n = (size_t)60 * RATE, i;
	float *mono = drums ? beat(124, 0.1, 0, 60, &n) : calloc(n, sizeof(float));
	fzn_media_sound_t s;
	char name[16];

	if (noise) {
		seed = 5;
		for (i = 0; i < n; i++)
			mono[i] = 0.3f * white();
	}
	for (i = 0; chords && i < n; ++i) {
		const int *chord = chords[(i / (2u * RATE)) % 4u];
		const double t = (double)i / RATE;
		double v = 0, bass;
		int c, h;

		for (c = 0; c < 3; c++) {
			const double hz = 440 * pow(2.0, (chord[c] - 69) / 12.0);

			for (h = 1; h <= 4; ++h)
				v += 0.05 / h * sin(2 * M_PI * hz * h * t);
		}
		bass = 440 * pow(2.0, (chord[0] - 12 - 69) / 12.0);
		v += 0.08 * sin(2 * M_PI * bass * t);
		mono[i] += (float)v;
	}
	CHECK(analyse(mono, n, &s) && s.key == want, "%s: found key %d (%s), fit %.3f", what, s.key,
	      fzn_media_key_name(s.key, name, sizeof(name)) ? name : "none", s.key_fit);
	free(mono);
}

/* A 997 Hz sine at amplitude 0.1 in both channels: -20 LUFS, the
 * K-weighting's gain there being close to nothing. */
static void loudness(void)
{
	const size_t n = (size_t)10 * RATE;
	float *mono = calloc(n, sizeof(*mono));
	fzn_media_sound_t s;
	size_t i;

	for (i = 0; i < n; i++)
		mono[i] = (float)(0.1 * sin(2 * M_PI * 997 * (double)i / RATE));
	CHECK(analyse(mono, n, &s) && s.loudness_known && fabs(s.loudness + 20.0) < 0.15 && fabs(s.peak - 0.1) < 1e-3,
	      "a -20 dBFS sine read as %.2f LUFS, peak %.4f", s.loudness, s.peak);
	CHECK(fabs(s.seconds - 10.0) < 1e-6, "ten seconds heard as %.3f", s.seconds);
	memset(mono, 0, n * sizeof(*mono));
	CHECK(analyse(mono, n, &s) && !s.loudness_known && s.bpm == 0 && s.key == -1, "silence was given a loudness");
	free(mono);
}

static void names(void)
{
	static const struct {
		int key;
		const char *name;
	} want[] = { { 0, "8B C" },  { 21, "8A Am" }, { 7, "9B G" },   { 5, "7B F" },
		     { 6, "2B Gb" }, { 15, "2A Ebm" }, { 23, "10A Bm" }, { 11, "1B B" } };
	char name[16];
	size_t i;

	for (i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
		CHECK(fzn_media_key_name(want[i].key, name, sizeof(name)) == strlen(want[i].name)
		              && !strcmp(name, want[i].name),
		      "key %d named %s, not %s", want[i].key, name, want[i].name);
		CHECK(fzn_media_key_parse(want[i].name, strlen(want[i].name)) == want[i].key, "%s not read back",
		      want[i].name);
	}
	CHECK(!fzn_media_key_name(-1, name, sizeof(name)) && !fzn_media_key_name(24, name, sizeof(name))
	              && !fzn_media_key_name(23, name, 6u),
	      "no key, or no room, was named");
	CHECK(fzn_media_key_parse("8A", 2) == 21 && fzn_media_key_parse("13A", 3) == -1 && fzn_media_key_parse("8", 1) == -1
	              && fzn_media_key_parse("C", 1) == -1,
	      "a key's name was misread");
	CHECK(fzn_media_key_order(21) < fzn_media_key_order(0) && fzn_media_key_order(0) < fzn_media_key_order(7)
	              && fzn_media_key_order(-1) > fzn_media_key_order(4),
	      "keys did not sort on the wheel");
}

int main(void)
{
	static const int c_major[4][3] = { { 60, 64, 67 }, { 65, 69, 72 }, { 67, 71, 74 }, { 60, 64, 67 } };
	static const int a_minor[4][3] = { { 57, 60, 64 }, { 62, 65, 69 }, { 64, 67, 71 }, { 57, 60, 64 } };
	static const int gb_major[4][3] = { { 66, 70, 73 }, { 71, 75, 78 }, { 73, 77, 80 }, { 66, 70, 73 } };
	static const int eb_minor[4][3] = { { 63, 66, 70 }, { 68, 71, 75 }, { 70, 73, 77 }, { 63, 66, 70 } };
	fzn_media_sound_t s;

	a_beat_is_found(120, 0, 0);
	a_beat_is_found(128, 0.137, 1);
	a_beat_is_found(87.5, 0.5, 1);
	a_beat_is_found(140, 0.31, 1);
	a_beat_is_found(127.3, 0.05, 1);
	no_beat(0);
	no_beat(1);
	no_beat(2);
	dotted();
	a_key(c_major, 0, 0, 0, "C major");
	a_key(a_minor, 0, 0, 21, "A minor");
	a_key(gb_major, 1, 0, 6, "Gb major, with drums");
	a_key(eb_minor, 0, 0, 15, "Eb minor");
	a_key(NULL, 0, 1, -1, "white noise");
	a_key(NULL, 1, 0, -1, "drums alone");
	loudness();
	names();
	CHECK(!fzn_media_analysis_finish(NULL, &s, NULL) && s.key == -1 && !fzn_media_analysis_add(NULL, NULL, 0),
	      "no analysis was taken for one");
	if (failures) {
		fprintf(stderr, "media analysis_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("media analysis_test: all %d checks passed\n", checks);
	return 0;
}
