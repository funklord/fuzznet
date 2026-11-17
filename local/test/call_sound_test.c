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

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "call_sound_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("call_sound_test: all %d checks passed\n", checks);
	return 0;
}
