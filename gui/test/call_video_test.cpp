/*
 * call_video_test -- a call's picture on the held media channel, fuzznet
 * sec 1237, over a socketpair standing in for the node: the channel asked
 * for; a picture sent as one JPEG frame on stream 2, at most 320x240;
 * echoed back as the other end's, it arrives a picture again; a frame on
 * the sound's stream is not a picture; a picture that cannot fit is not
 * sent; and the channel's end is said.
 */
#include "../call_video.h"

#include <QApplication>
#include <QColor>

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int checks, failures;

#define CHECK(cond, what)                                                                     \
	do {                                                                                  \
		checks++;                                                                     \
		if (!(cond)) {                                                                \
			failures++;                                                           \
			fprintf(stderr, "  FAIL call_video_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                             \
	} while (0)

#define CALL "0102030405060708"

/* ONE MESSAGE off the node's end: its two bytes of length and the rest. */
static size_t one_message(int fd, uint8_t *out, size_t cap)
{
	size_t len, got = 0;

	if (read(fd, out, 2) != 2)
		return 0;
	len = (size_t)out[0] << 8 | out[1];
	if (len + 2u > cap)
		return 0;
	while (got < len) {
		ssize_t n = read(fd, out + 2 + got, len - got);
		if (n <= 0)
			return 0;
		got += (size_t)n;
	}
	return len + 2u;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	static const uint8_t ok_status[] = { 0, 3, 19, 0, 0 };
	static uint8_t wire[2 + 8192 + 64];
	QImage red(640, 480, QImage::Format_RGB32), seen;
	int sv[2];
	size_t n;

	red.fill(QColor(220, 20, 20));
	/* THE CODEC ALONE: a picture fits a frame, at most 320x240; one that
	 * cannot fit is no frame. */
	{
		const QByteArray f = fzn_video_encode(red, 8160);
		const QImage back = fzn_video_decode(reinterpret_cast<const uint8_t *>(f.constData()), (size_t)f.size());
		CHECK(!f.isEmpty() && (size_t)f.size() <= 8160 && back.width() == 320 && back.height() == 240,
		      "a picture did not become one frame of at most 320x240 and back");
		CHECK(fzn_video_encode(red, 40).isEmpty(), "a picture that cannot fit made a frame");
		CHECK(fzn_video_decode(reinterpret_cast<const uint8_t *>("not a jpeg"), 10).isNull(),
		      "a frame that is no picture was read as one");
	}

	fzn_call_video v(QStringLiteral("/nonexistent"));
	v.on_picture([&seen](const QImage &p) { seen = p; });
	CHECK(!v.send_picture(red), "a picture was sent with no channel open");
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0
	              && write(sv[1], ok_status, sizeof(ok_status)) == (ssize_t)sizeof(ok_status),
	      "fixture: a socketpair, the node's ok waiting");
	CHECK(v.attach(sv[0], CALL) && v.running(), "the call's channel did not open");
	CHECK(one_message(sv[1], wire, sizeof(wire)) == 12u && wire[3] == 128, "the channel was not asked for");

	/* SENT AS ONE FRAME ON STREAM 2. */
	CHECK(v.send_picture(red) && v.frames_sent() == 1u, "a picture was not sent");
	n = one_message(sv[1], wire, sizeof(wire));
	CHECK(n > 23u && wire[3] == 129 && wire[12] == 2 && wire[23] == 0xff && wire[24] == 0xd8,
	      "the picture did not go as one JPEG frame on stream 2");

	/* ECHOED BACK AS THE OTHER END'S: a picture again, red. */
	CHECK(write(sv[1], wire, n) == (ssize_t)n, "fixture: the frame echoed");
	v.poll();
	CHECK(v.frames_received() == 1u && seen.width() == 320 && qRed(seen.pixel(160, 120)) > 180
	              && qGreen(seen.pixel(160, 120)) < 60,
	      "the other end's picture did not arrive as itself");

	/* A FRAME ON THE SOUND'S STREAM is not a picture. */
	wire[12] = 1;
	seen = QImage();
	CHECK(write(sv[1], wire, n) == (ssize_t)n, "fixture: a sound frame");
	v.poll();
	CHECK(v.frames_received() == 1u && seen.isNull(), "a frame on stream 1 was shown as a picture");

	/* THE NODE LETS IT GO: said, and stopped. */
	close(sv[1]);
	v.poll();
	CHECK(!v.running() && !v.trouble().isEmpty(), "a closed channel was not said");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui call_video_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui call_video_test: all %d checks passed\n", checks);
	return 0;
}
