/*
 * call_audio_test -- a call's sound between two ends on one scripted node,
 * fuzznet sec 1236, through the test seam in place of the devices: alice's
 * tone reaches bob's speaker after the jitter buffer's three frames, close
 * to what she said; muted, she sends silence and he hears it; the other
 * end's report is said once a second; and a call id of the wrong shape is
 * refused.
 */
#include "../call_audio.h"

#include <QCoreApplication>
#include <QVector>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                     \
	do {                                                                                  \
		checks++;                                                                     \
		if (!(cond)) {                                                                \
			failures++;                                                           \
			fprintf(stderr, "  FAIL call_audio_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                             \
	} while (0)

#define CALL "0123456789abcdef"

/* THE NODE: frames added kept and listed back three a reply, the call's
 * quality reported -- the lines as the typed client sends them. */
static struct {
	char rows[256][480];
	size_t n;
} node_frames;

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (!strncmp(line, "add frame " CALL " ", 10 + 16 + 1)) {
		unsigned stream, piece, pieces;
		unsigned long seq, at;
		char hex[420];

		if (sscanf(line + 10 + 16 + 1, "%u %lu %lu %u %u %419s", &stream, &seq, &at, &piece, &pieces, hex) != 6)
			return (size_t)snprintf(reply, cap, "malformed\n");
		snprintf(node_frames.rows[node_frames.n++ % 256], sizeof(node_frames.rows[0]), "%u,%lu,%lu,%u,%u,%s",
		         stream, seq, at, piece, pieces, hex);
		return (size_t)snprintf(reply, cap, "ok sent\n");
	}
	if (!strncmp(line, "list frame " CALL " ", 11 + 16 + 1)) {
		unsigned long long from = strtoull(line + 11 + 16 + 1, NULL, 10);
		size_t used = (size_t)snprintf(reply, cap, "ok %zu %llu", node_frames.n, from), i;

		for (i = (size_t)from; i < node_frames.n && i < from + 3u; i++)
			used += (size_t)snprintf(reply + used, cap - used, " %s", node_frames.rows[i % 256]);
		return used + (size_t)snprintf(reply + used, cap - used, "\n");
	}
	if (!strcmp(line, "get call " CALL " quality"))
		return (size_t)snprintf(reply, cap, "ok 0,sent,95,5,3,0,0\n");
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	QCoreApplication app(argc, argv);
	fzn_call_audio alice(node, nullptr), bob(node, nullptr);
	QVector<int16_t> heard;
	int k = 0, phase = 0;

	/* ALICE SAYS A TONE, a frame a tick; BOB SAYS NOTHING. */
	alice.set_test_io(
	        [&phase](int16_t *pcm, size_t cap) {
		        size_t i;
		        for (i = 0; i < 160u && i < cap; i++, phase++)
			        pcm[i] = (int16_t)((phase % 40) * 800 - 16000);
		        return i;
	        },
	        [](const int16_t *, size_t) {});
	bob.set_test_io([](int16_t *, size_t) { return (size_t)0; },
	                [&heard](const int16_t *pcm, size_t n) {
		                for (size_t i = 0; i < n; i++)
			                heard.append(pcm[i]);
	                });
	CHECK(!alice.start("XYZ") && !alice.running() && !alice.trouble().isEmpty(),
	      "a call id of the wrong shape was carried");
	CHECK(alice.start(CALL) && bob.start(CALL) && alice.running() && alice.trouble().isEmpty(),
	      "a call was not carried with the test's devices");

	/* TEN TICKS: alice sends ten frames; bob plays from the third. */
	for (k = 0; k < 10; k++) {
		alice.tick(1000 + 20u * (unsigned)k);
		bob.tick(1000 + 20u * (unsigned)k);
	}
	CHECK(alice.frames_sent() == 10u, "alice did not send a frame a tick");
	CHECK(heard.size() >= 160 * 6 && heard.size() % 160 == 0, "bob did not play a frame a tick once three were held");
	{
		int worst = 0;
		for (int i = 0; i < heard.size(); i++) {
			const int d = abs(heard[i] - ((i % 40) * 800 - 16000));
			worst = d > worst ? d : worst;
		}
		CHECK(worst <= 1024, "what bob heard was not alice's tone");
	}

	/* MUTED: silence goes out, and bob hears it. */
	alice.set_muted(true);
	for (k = 0; k < 8; k++) {
		alice.tick(2000 + 20u * (unsigned)k);
		bob.tick(2000 + 20u * (unsigned)k);
	}
	{
		int last = 0;
		for (int i = heard.size() - 160; i < heard.size(); i++)
			last |= heard[i];
		CHECK(alice.muted() && alice.frames_sent() == 18u && last == 0, "a muted alice was heard, or went quiet");
	}

	/* HOW SHE IS HEARD: said once a second, from the node's report. */
	for (k = 0; k < 50; k++)
		alice.tick(3000 + 20u * (unsigned)k);
	CHECK(alice.quality().startsWith("they lose 5%"), "the other end's report was not said");

	alice.stop();
	CHECK(!alice.running(), "a call stopped was still carried");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui call_audio_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui call_audio_test: all %d checks passed\n", checks);
	return 0;
}
