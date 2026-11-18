/*
 * call_sound_test -- a call's sound through a scripted node, fuzznet sec
 * 1235: alice's microphone becomes mu-law frames the node keeps, bob reads
 * them into his jitter buffer and plays them back in order, close to what
 * was said; a frame the node said was lost plays as silence; muted sends
 * silence; and the round trip and loss come from the node's report.
 */
#include "../call_sound.h"
#include "../rpc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                       \
	do {                                                                                    \
		checks++;                                                                       \
		if (!(cond)) {                                                                  \
			failures++;                                                             \
			fprintf(stderr, "  FAIL call_sound_test.c:%d: %s\n", __LINE__, what);  \
		}                                                                               \
	} while (0)

#define CALL "0123456789abcdef"

/* THE NODE, ITS REPLIES AS A LINE WITHOUT ITS NEWLINE: every frame added kept, as `list frame` gives them back; the
 * Nth added said lost when `lose_at` is N; a quality report when asked. */
static struct {
	char rows[64][480];
	size_t n;
	int adds, lose_at;
} node_frames;

static int node(void *ctx, const char *verb, const char *arg, size_t arg_len, uint8_t *reply, size_t cap,
                size_t *reply_len)
{
	char line[600];
	int n;

	(void)ctx;
	if (arg_len >= sizeof(line))
		return FZN_RPC_ERR_MALFORMED;
	memcpy(line, arg, arg_len);
	line[arg_len] = '\0';
	if (!strcmp(verb, "add") && !strncmp(line, "frame " CALL " ", 6 + 16 + 1)) {
		unsigned stream, piece, pieces;
		unsigned long seq, at;
		char hex[420];

		node_frames.adds++;
		if (sscanf(line + 6 + 16 + 1, "%u %lu %lu %u %u %419s", &stream, &seq, &at, &piece, &pieces, hex) != 6)
			return FZN_RPC_ERR_MALFORMED;
		if (node_frames.adds == node_frames.lose_at) {
			n = snprintf((char *)reply, cap, "ok lost");
		} else {
			snprintf(node_frames.rows[node_frames.n++ % 64], sizeof(node_frames.rows[0]), "%u,%lu,%lu,%u,%u,%s",
			         stream, seq, at, piece, pieces, hex);
			n = snprintf((char *)reply, cap, "ok sent");
		}
	} else if (!strcmp(verb, "list") && !strncmp(line, "frame " CALL " ", 6 + 16 + 1)) {
		unsigned long long from = strtoull(line + 6 + 16 + 1, NULL, 10);
		size_t i, used;

		/* Three rows a reply, so a reader asks again. */
		n = snprintf((char *)reply, cap, "ok %zu %llu", node_frames.n, from);
		used = (size_t)n;
		for (i = (size_t)from; i < node_frames.n && i < from + 3u; i++)
			used += (size_t)snprintf((char *)reply + used, cap - used, " %s", node_frames.rows[i]);
		n = (int)used;
	} else if (!strcmp(verb, "get") && !strcmp(line, "call " CALL " quality")) {
		/* Bob had 90 and lost 10, the newest at 1000 ms, held 20 ms. */
		n = snprintf((char *)reply, cap, "ok 0,sent,90,10,5,1000,20");
	} else {
		n = snprintf((char *)reply, cap, "error no such thing");
	}
	*reply_len = (size_t)n;
	return FZN_RPC_OK;
}

/* A CODEC FOR THE TEST, sec 1254: 16 kHz, a byte for two samples -- the
 * first's high byte, so a frame is 160 bytes and fits one `add frame` --
 * and 1234 for every sample of a frame that did not come, so concealment
 * shows. */
static int lossy_encode(void *ctx, const int16_t *pcm, size_t n, uint8_t *packet, size_t cap)
{
	size_t i;

	(void)ctx;
	if (n / 2u > cap)
		return -1;
	for (i = 0; i < n / 2u; i++)
		packet[i] = (uint8_t)((uint16_t)pcm[2u * i] >> 8);
	return (int)(n / 2u);
}

static int lossy_decode(void *ctx, const uint8_t *packet, size_t len, int16_t *pcm, size_t cap)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < cap; i++)
		pcm[i] = packet ? (int16_t)(uint16_t)((i / 2u < len ? packet[i / 2u] : 0) << 8) : (int16_t)1234;
	return (int)cap;
}

static const fzn_call_codec_t LOSSY = { NULL, 16000u, 320u, lossy_encode, lossy_decode };

int main(void)
{
	static fzn_call_sound_t alice, bob;
	static int16_t said[FZN_ULAW_FRAME_SAMPLES * 4], heard[FZN_ULAW_FRAME_SAMPLES];
	fzn_rpc_t c;
	size_t i;
	int worst = 0, k;

	fzn_rpc_init(&c);
	c.answer = node;
	CHECK(fzn_call_sound_start(&alice, CALL, 5000) == 0 && fzn_call_sound_start(&bob, CALL, 5000) == 0
	              && fzn_call_sound_start(&bob, "XYZ", 0) == -1,
	      "a call was not started by its id, or one of the wrong shape was");
	fzn_call_sound_start(&bob, CALL, 5000);

	/* A TONE, FOUR FRAMES, given in two uneven captures. */
	for (i = 0; i < sizeof(said) / sizeof(said[0]); i++)
		said[i] = (int16_t)((int)(i % 40) * 800 - 16000);
	CHECK(fzn_call_sound_send(&alice, &c, said, 250, 5020) == 1
	              && fzn_call_sound_send(&alice, &c, said + 250, sizeof(said) / sizeof(said[0]) - 250, 5080) == 3,
	      "four frames' samples were not sent as four frames, whole frames only");
	CHECK(node_frames.n == 4u && !strncmp(node_frames.rows[0], "0,0,20,0,1,", 11)
	              && !strncmp(node_frames.rows[3], "0,3,80,0,1,", 11),
	      "the frames went out unnumbered, off stream 0, or without the time since the call began");

	/* BOB HEARS THEM, in order, close to what was said. */
	CHECK(fzn_call_sound_receive(&bob, &c) == 4 && bob.from == 4u, "bob did not read every frame, asking again");
	for (k = 0; k < 4; k++) {
		size_t s;

		if (fzn_call_sound_play(&bob, heard) != 1) {
			worst = 99999;
			break;
		}
		for (s = 0; s < FZN_ULAW_FRAME_SAMPLES; s++) {
			const int d = abs(heard[s] - said[(size_t)k * FZN_ULAW_FRAME_SAMPLES + s]);

			worst = d > worst ? d : worst;
		}
	}
	CHECK(worst <= 1024, "what bob played was not what alice said, frame for frame");

	/* A FRAME LOST PLAYS AS SILENCE, and the next still plays. */
	node_frames.lose_at = node_frames.adds + 2;
	CHECK(fzn_call_sound_send(&alice, &c, said, FZN_ULAW_FRAME_SAMPLES * 4, 5100) == 4 && alice.seq == 8u,
	      "a frame the node lost was renumbered over");
	CHECK(fzn_call_sound_receive(&bob, &c) == 3, "bob did not read the three that went");
	CHECK(fzn_call_sound_play(&bob, heard) == 1 && heard[3] != 0, "the frame before the lost one was not played");
	{
		int16_t quiet = 0;

		CHECK(fzn_call_sound_play(&bob, heard) == 1, "the lost frame's turn did not play");
		for (i = 0; i < FZN_ULAW_FRAME_SAMPLES; i++)
			quiet |= heard[i];
		CHECK(quiet == 0 && fzn_jitter_lost(&bob.jitter) == 1u, "the lost frame was not silence, counted lost");
	}

	/* MUTED: silence goes out, frames and all. */
	alice.muted = 1;
	CHECK(fzn_call_sound_send(&alice, &c, said, FZN_ULAW_FRAME_SAMPLES, 5200) == 1
	              && strstr(node_frames.rows[(node_frames.n - 1u) % 64], ",ffffffff") != NULL,
	      "a muted end did not send silence");

	/* HOW ALICE IS HEARD: 10 lost of 100, and the round trip on her clock. */
	CHECK(fzn_call_sound_quality(&alice, &c, 5000 + 1500) == 1 && alice.have_quality && alice.loss_pct == 10u
	              && alice.trip_ms == 480,
	      "the other end's report was not read as 10% lost and a 480 ms round trip");

	/* A CODEC, sec 1254: refused where its rate or frame does not fit;
	 * sent on stream 1 at its rate; played through it, a frame that did not
	 * come the codec's to conceal; mu-law that arrives played at its rate,
	 * each sample repeated; and this end's report read for stream 1. */
	{
		static const fzn_call_codec_t ODD = { NULL, 44100u, 882u, lossy_encode, lossy_decode };
		static const fzn_call_codec_t SHORT = { NULL, 16000u, 160u, lossy_encode, lossy_decode };
		static int16_t tone[320 * 5], out[FZN_CALL_SOUND_FRAME_MAX];
		uint8_t mu[FZN_ULAW_FRAME_SAMPLES];
		int taken = 0, ok = 1;

		memset(&node_frames, 0, sizeof(node_frames));
		fzn_call_sound_start(&alice, CALL, 5000);
		fzn_call_sound_start(&bob, CALL, 5000);
		CHECK(fzn_call_sound_codec(&alice, &ODD) == -1 && fzn_call_sound_codec(&alice, &SHORT) == -1
		              && fzn_call_sound_rate(&alice) == 8000u,
		      "a codec whose rate or frame does not fit was taken");
		CHECK(fzn_call_sound_codec(&alice, &LOSSY) == 0 && fzn_call_sound_codec(&bob, &LOSSY) == 0
		              && fzn_call_sound_rate(&bob) == 16000u && fzn_call_sound_frame(&bob) == 320u,
		      "a codec was not taken, its rate and frame the devices'");
		for (i = 0; i < sizeof(tone) / sizeof(tone[0]); i++)
			tone[i] = (int16_t)((int)(i % 64) * 512 - 16384);
		CHECK(fzn_call_sound_send(&alice, &c, tone, 320 * 4, 5020) == 4 && node_frames.n == 4u
		              && !strncmp(node_frames.rows[0], "1,0,20,0,1,", 11),
		      "the codec's frames did not go out on stream 1");
		CHECK(fzn_call_sound_receive(&bob, &c) == 4 && fzn_jitter_held(&bob.coded) == 4u
		              && fzn_jitter_held(&bob.jitter) == 0u,
		      "stream 1 was not read into the codec's buffer");
		for (k = 0; k < 4 && ok; k++) {
			ok = fzn_call_sound_play(&bob, out) == 1;
			for (i = 0; i < 320u && ok; i++)
				ok = (out[i] & ~0xff) == (tone[(size_t)k * 320u + (i & ~1u)] & ~0xff);
		}
		CHECK(ok, "the codec's frames were not played through it, in order");
		node_frames.lose_at = node_frames.adds + 1;
		(void)fzn_call_sound_send(&alice, &c, tone, 320 * 2, 5120);
		(void)fzn_call_sound_receive(&bob, &c);
		CHECK(fzn_call_sound_play(&bob, out) == 1 && out[0] == 1234 && out[319] == 1234,
		      "a coded frame that did not come was not the codec's to conceal");
		CHECK(fzn_call_sound_play(&bob, out) == 1 && (out[1] & ~0xff) == (tone[0] & ~0xff),
		      "the coded frame after a lost one did not play");
		/* MU-LAW FROM AN END WITH NO CODEC, at bob's rate. */
		memset(&bob.coded, 0, sizeof(bob.coded));
		fzn_jitter_init(&bob.coded);
		fzn_ulaw_encode_frame(said, FZN_ULAW_FRAME_SAMPLES, mu);
		for (k = 0; k < 3; k++)
			(void)fzn_rpc_frame_add(&c, CALL, 0, (uint32_t)k, 0, mu, sizeof(mu), &taken);
		(void)fzn_call_sound_receive(&bob, &c);
		CHECK(fzn_call_sound_play(&bob, out) == 1 && out[0] == out[1] && out[2] == out[3]
		              && abs(out[2] - said[1]) <= 1024 && abs(out[318] - said[159]) <= 1024,
		      "mu-law at an end with a codec was not played at its rate, each sample repeated");
		CHECK(fzn_call_sound_quality(&alice, &c, 6000) == 0 && !alice.have_quality,
		      "the report of stream 0 was read as how this end's codec is heard");
	}

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "call_sound_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("call_sound_test: all %d checks passed\n", checks);
	return 0;
}
