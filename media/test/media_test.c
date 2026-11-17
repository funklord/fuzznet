/*
 * media_test -- a call's codec and jitter buffer, fuzznet sec 1234: mu-law
 * against G.711's known values and back within its step; the buffer holding
 * until three, putting frames back in order, a gap played as lost, a late
 * frame dropped, a stall caught up to the newest three, and the order kept
 * across 2^32.
 */
#include "../ulaw.h"
#include "../jitter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                  \
	do {                                                                               \
		checks++;                                                                  \
		if (!(cond)) {                                                             \
			failures++;                                                        \
			fprintf(stderr, "  FAIL media_test.c:%d: %s\n", __LINE__, what);  \
		}                                                                          \
	} while (0)

/* One frame of one byte, its value its sequence number's low byte. */
static int put(fzn_jitter_t *j, uint32_t seq)
{
	const uint8_t b = (uint8_t)seq;

	return fzn_jitter_take(j, seq, &b, 1u);
}

/* The next pull: -2 buffering, -1 a gap, else the frame's byte. */
static int pulled(fzn_jitter_t *j)
{
	uint8_t f[FZN_JITTER_FRAME_MAX];
	size_t len = 0;

	if (!fzn_jitter_pull(j, f, sizeof(f), &len))
		return -2;
	return len ? f[0] : -1;
}

int main(void)
{
	static fzn_jitter_t j;
	int worst = 0, s;

	/* MU-LAW, G.711's own values: silence is 0xFF, and back again within
	 * the step of the segment a sample falls in. */
	CHECK(fzn_ulaw_encode(0) == 0xffu && fzn_ulaw_decode(0xffu) == 0, "silence was not 0xFF and back");
	CHECK(fzn_ulaw_encode(32767) == 0x80u && fzn_ulaw_encode(-32768) == 0x00u,
	      "the loudest samples were not G.711's 0x80 and 0x00");
	for (s = -32768; s <= 32767; s += 7) {
		const int back = fzn_ulaw_decode(fzn_ulaw_encode((int16_t)s));
		const int err = abs(back - (s > 32635 ? 32635 : s < -32635 ? -32635 : s));
		const int step = abs(s) < 256 ? 16 : abs(s) / 16 + 16;

		if (err > step)
			worst = err > worst ? err : worst;
	}
	CHECK(worst == 0, "a sample came back further than its segment's step");
	{
		int16_t pcm[FZN_ULAW_FRAME_SAMPLES], back[FZN_ULAW_FRAME_SAMPLES];
		uint8_t frame[FZN_ULAW_FRAME_SAMPLES];

		for (s = 0; s < (int)FZN_ULAW_FRAME_SAMPLES; s++)
			pcm[s] = (int16_t)(s * 200 - 16000);
		fzn_ulaw_encode_frame(pcm, FZN_ULAW_FRAME_SAMPLES, frame);
		fzn_ulaw_decode_frame(frame, FZN_ULAW_FRAME_SAMPLES, back);
		CHECK(frame[0] == fzn_ulaw_encode(pcm[0]) && back[159] == fzn_ulaw_decode(frame[159]),
		      "a frame was not each sample encoded and decoded");
	}

	/* HELD UNTIL THREE, then in order, a missing one a gap. */
	fzn_jitter_init(&j);
	CHECK(put(&j, 11) && put(&j, 10) && pulled(&j) == -2, "two frames were played before three were held");
	CHECK(put(&j, 13) && pulled(&j) == 10 && pulled(&j) == 11, "frames were not played back in order");
	CHECK(pulled(&j) == -1 && fzn_jitter_lost(&j) == 1u, "frame 12, never come, was not a gap counted lost");
	CHECK(pulled(&j) == 13, "the frame after a gap was not played");
	/* LATE IS LOST. */
	CHECK(!put(&j, 12) && fzn_jitter_held(&j) == 0u, "a frame played past was taken");
	/* A STALL CAUGHT UP: eleven held, play moves to the newest three. */
	for (s = 14; s <= 24; s++)
		(void)put(&j, (uint32_t)s);
	CHECK(fzn_jitter_held(&j) == 3u && pulled(&j) == 22 && pulled(&j) == 23 && pulled(&j) == 24,
	      "eleven held were not caught up to the newest three");
	CHECK(fzn_jitter_lost(&j) == 1u + 8u, "the frames skipped in catching up were not counted lost");
	/* FAR AHEAD: play moves to it. */
	CHECK(put(&j, 100) && pulled(&j) == 100, "a frame far ahead was not played next");

	/* ACROSS 2^32: frame 0 comes after 0xFFFFFFFF. */
	fzn_jitter_init(&j);
	CHECK(put(&j, 0xfffffffeu) && put(&j, 0u) && put(&j, 0xffffffffu), "frames across 2^32 were not taken");
	CHECK(pulled(&j) == 0xfe && pulled(&j) == 0xff && pulled(&j) == 0x00,
	      "frames across 2^32 were not played in sequence order");

	/* TOO LONG IS REFUSED, not cut. */
	{
		static uint8_t big[FZN_JITTER_FRAME_MAX + 1u];

		CHECK(!fzn_jitter_take(&j, 1u, big, sizeof(big)), "a frame past FZN_JITTER_FRAME_MAX was taken");
	}

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "media_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("media_test: all %d checks passed\n", checks);
	return 0;
}
