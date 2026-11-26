/*
 * decode_test -- a file's sound through FFmpeg (media/decode.h, project.md
 * sec 1457): every committed fixture decoded to about its length at 48 kHz
 * stereo; a photograph and a missing file give no sound; a bound on the
 * seconds and a stop are kept. Then, where an ffmpeg program is on the path,
 * snurra's two codec cases: a steady 440 Hz tone through AAC, MP3 and Opus
 * has no beat (a codec's frames ripple a tone at their own period), and a
 * kick at 128 BPM written here and encoded to AAC is found at 128. Run from
 * the tree's root. Without FFmpeg in the build, every call says so.
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "../analysis.h"
#include "../decode.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static int checks, failures;

#define CHECK(cond, ...)                                                  \
	do {                                                              \
		checks++;                                                 \
		if (!(cond)) {                                            \
			failures++;                                       \
			fprintf(stderr, "  FAIL decode_test.c:%d: ", __LINE__); \
			fprintf(stderr, __VA_ARGS__);                     \
			fputc('\n', stderr);                              \
		}                                                         \
	} while (0)

struct heard {
	size_t frames;
	size_t stop_after; /* 0: never */
	fzn_media_analysis_t *a;
};

static int count(void *ctx, const float *stereo, size_t n)
{
	struct heard *h = ctx;

	h->frames += n;
	if (h->a && !fzn_media_analysis_add(h->a, stereo, n))
		return 0;
	return !h->stop_after || h->frames < h->stop_after;
}

static fzn_media_decode_result_t decode(const char *path, double max, struct heard *h)
{
	memset(h, 0, sizeof(*h));
	return fzn_media_decode(path, max, count, h, NULL);
}

/* `path` decoded and analysed. */
static int analyse(const char *path, fzn_media_sound_t *s)
{
	struct heard h;

	memset(&h, 0, sizeof(h));
	h.a = fzn_media_analysis_open();
	if (fzn_media_decode(path, 0, count, &h, NULL) != FZN_MEDIA_DECODE_OK) {
		fzn_media_analysis_free(h.a);
		return 0;
	}
	return fzn_media_analysis_finish(h.a, s, NULL);
}

static int run(char *const argv[])
{
	pid_t pid = fork();
	int status;

	if (pid == 0) {
		int null = open("/dev/null", O_WRONLY);

		if (null >= 0)
			(void)dup2(null, 1);
		execvp(argv[0], argv);
		_exit(127);
	}
	return pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void le16(FILE *f, unsigned v)
{
	fputc((int)(v & 0xff), f);
	fputc((int)(v >> 8), f);
}

static void le32(FILE *f, uint32_t v)
{
	le16(f, v & 0xffffu);
	le16(f, v >> 16);
}

/* Thirty seconds of a bare kick at 128 BPM, mono 16-bit at 48 kHz. */
static int write_kick(const char *path)
{
	const uint32_t n = 30u * 48000u;
	const double period = 60.0 * 48000.0 / 128.0;
	FILE *f = fopen(path, "wb");
	uint32_t i;

	if (!f)
		return 0;
	fwrite("RIFF", 1, 4, f);
	le32(f, 36u + n * 2u);
	fwrite("WAVEfmt ", 1, 8, f);
	le32(f, 16);
	le16(f, 1);
	le16(f, 1);
	le32(f, 48000);
	le32(f, 96000);
	le16(f, 2);
	le16(f, 16);
	fwrite("data", 1, 4, f);
	le32(f, n * 2u);
	for (i = 0; i < n; i++) {
		const double since = fmod((double)i - 0.1 * 48000.0, period);
		const double t = (since < 0 ? since + period : since) / 48000.0;
		double v = t < 0.25 ? 0.7 * sin(2 * M_PI * 55 * t) * exp(-t / 0.09) : 0.0;

		if (t * 48000.0 < 96.0)
			v += 0.3 * sin(t * 48000.0 * 2.3); /* the click */
		le16(f, (unsigned)(uint16_t)(int16_t)lround(v * 32000.0));
	}
	return fclose(f) == 0;
}

static void codecs(void)
{
	static const char *const codec[3][2] = { { "aac", "tone.m4a" }, { "libmp3lame", "tone.mp3" }, { "libopus", "tone.opus" } };
	const char *tmp = getenv("TMPDIR");
	char dir[256], path[300], wav[300], m4a[300];
	fzn_media_sound_t s;
	int i;

	(void)snprintf(dir, sizeof(dir), "%s/fzn-decode-XXXXXX", tmp && *tmp ? tmp : "/tmp");
	if (!mkdtemp(dir)) {
		CHECK(0, "no scratch directory");
		return;
	}
	for (i = 0; i < 3; i++) {
		char *argv[] = { "ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "sine=f=440:d=30", "-c:a",
			         (char *)codec[i][0], path, NULL };

		(void)snprintf(path, sizeof(path), "%s/%s", dir, codec[i][1]);
		if (!run(argv)) {
			fprintf(stderr, "decode_test: ffmpeg has no %s; that case not run\n", codec[i][0]);
			continue;
		}
		CHECK(analyse(path, &s) && s.bpm == 0 && fabs(s.seconds - 30.0) < 0.2,
		      "a steady tone through %s: a beat at %.2f BPM (confidence %.2f), %.2f s", codec[i][0], s.bpm,
		      s.confidence, s.seconds);
		(void)unlink(path);
	}
	(void)snprintf(wav, sizeof(wav), "%s/kick.wav", dir);
	(void)snprintf(m4a, sizeof(m4a), "%s/kick.m4a", dir);
	{
		char *argv[] = { "ffmpeg", "-v", "error", "-y", "-i", wav, "-c:a", "aac", "-b:a", "128k", m4a, NULL };

		CHECK(write_kick(wav) && run(argv) && analyse(m4a, &s) && fabs(s.bpm - 128.0) < 0.05
		              && fabs(remainder(s.first - 0.1, 60.0 / 128.0)) < 0.02,
		      "a kick at 128 through AAC read as %.3f BPM, first beat %.3f s", s.bpm, s.first);
	}
	(void)unlink(wav);
	(void)unlink(m4a);
	CHECK(rmdir(dir) == 0, "the scratch directory was left with something in it");
}

int main(void)
{
	static const struct {
		const char *name;
		double seconds;
	} fixture[] = { { "v24.mp3", 0.25 },    { "v23.mp3", 0.25 },  { "cbr.mp3", 1.045 },       { "song.flac", 0.25 },
		        { "song.ogg", 0.25 },   { "memo.opus", 0.25 }, { "song.m4a", 0.25 },       { "song_fast.m4a", 0.25 } };
	struct heard h;
	char path[128];
	size_t i;

	if (!fzn_media_decode_available()) {
		CHECK(decode("media/test/fixture/song.flac", 0, &h) == FZN_MEDIA_DECODE_NONE && !h.frames,
		      "a build with no decoder decoded");
		printf("media decode_test: no FFmpeg in this build; %d check(s) passed\n", checks - failures);
		return failures ? 1 : 0;
	}
	for (i = 0; i < sizeof(fixture) / sizeof(fixture[0]); i++) {
		double heard;

		(void)snprintf(path, sizeof(path), "media/test/fixture/%s", fixture[i].name);
		CHECK(decode(path, 0, &h) == FZN_MEDIA_DECODE_OK, "%s did not decode", fixture[i].name);
		heard = (double)h.frames / FZN_MEDIA_ANALYSIS_RATE;
		/* The sound made, 0.25 s: FFmpeg drops what LAME's tag says is its
		 * priming and padding, where a container's length counts them. */
		CHECK(fabs(heard - fixture[i].seconds) < 0.06, "%s: %.3f s heard, not %.3f", fixture[i].name, heard,
		      fixture[i].seconds);
	}
	CHECK(decode("media/test/fixture/photo.jpg", 0, &h) == FZN_MEDIA_DECODE_NO_SOUND && !h.frames,
	      "a photograph gave sound");
	CHECK(decode("media/test/fixture/not-there.mp3", 0, &h) == FZN_MEDIA_DECODE_NO_SOUND, "a missing file decoded");
	CHECK(decode("media/test/fixture/cbr.mp3", 0.5, &h) == FZN_MEDIA_DECODE_OK && h.frames == 24000u,
	      "half a second asked for gave %zu frames", h.frames);
	memset(&h, 0, sizeof(h));
	h.stop_after = 1000u;
	CHECK(fzn_media_decode("media/test/fixture/cbr.mp3", 0, count, &h, NULL) == FZN_MEDIA_DECODE_STOPPED
	              && h.frames < 48000u,
	      "a decode told to stop went on");
	{
		const volatile int stop = 1;

		memset(&h, 0, sizeof(h));
		CHECK(fzn_media_decode("media/test/fixture/cbr.mp3", 0, count, &h, &stop) == FZN_MEDIA_DECODE_STOPPED
		              && !h.frames,
		      "a decode stopped before it began went on");
	}
	{
		char *argv[] = { "ffmpeg", "-v", "error", "-version", NULL };

		if (run(argv))
			codecs();
		else
			fprintf(stderr, "decode_test: no ffmpeg program; the codec cases not run\n");
	}
	if (failures) {
		fprintf(stderr, "media decode_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("media decode_test: all %d checks passed\n", checks);
	return 0;
}
