/*
 * devices_view_test -- adding a device on a widget, sec 1122, against a
 * scripted node behind the ask callback: a code made and drawn as a QR, the
 * confirm switch read and set (and put back when the node refuses), the
 * devices waiting listed by key, one let in and one turned away by their
 * full keys, and a node that does not answer. And a code scanned from a
 * picture, sec 1158: one this tree's encoder drew, read and joined with;
 * and the camera's frames thinned and shrunk before they are scanned, sec
 * 1158, without opening a camera, which a test machine may or may not have.
 */

#include "../camera_feed.h"
#include "../devices_view.h"
extern "C" {
#include "../../qr/qr.h"
}

#include <QApplication>
#include <QImage>
#include <QTemporaryDir>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL devices_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                              \
	} while (0)

#define DEV1 "d1d1000000000000000000000000000000000000000000000000000000000001"
#define DEV2 "d2d2000000000000000000000000000000000000000000000000000000000002"

static int silent, confirm_on = 1, refuse_set, joined_after;
static char last[200];

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	if (!strcmp(line, "add invite delegable"))
		return (size_t)snprintf(reply, cap, "ok FZI1:ABCDEFGHIJKLMNOP2345\n");
	if (!strcmp(line, "get setting host invite/confirm"))
		return (size_t)snprintf(reply, cap, "ok invite/confirm %s\n", confirm_on ? "on" : "off");
	/* THIS HOST SERVES AS ITSELF, until the join has been looked at twice. */
	if (!strcmp(line, "get identity"))
		return (size_t)snprintf(reply, cap, "ok %s %s\n", DEV1, joined_after-- > 0 ? DEV1 : DEV2);
	if (!strcmp(line, "list invite"))
		return (size_t)snprintf(reply, cap, "ok 2 %s %s\n", DEV1, DEV2);
	snprintf(last, sizeof last, "%s", line);
	if (refuse_set && !strncmp(line, "set setting host invite/confirm", 31))
		return (size_t)snprintf(reply, cap, "denied only an admin may change that\n");
	return (size_t)snprintf(reply, cap, "ok\n");
}

/* A CODE AS A CAMERA WOULD SEE IT: drawn by this tree's encoder, each
 * module SCALE pixels, with the quiet zone the standard asks. */
static QImage drawn(const char *text, int scale)
{
	static uint8_t modules[177u * 177u];
	size_t size = 0;

	if (fzn_qr_encode(text, strlen(text), FZN_QR_LEVEL_M, modules, sizeof(modules), &size) != FZN_QR_OK)
		return QImage();
	int side = (int)(size + 2u * FZN_QR_QUIET) * scale;
	QImage img(side, side, QImage::Format_RGB32);
	img.fill(Qt::white);
	for (size_t y = 0; y < size; y++)
		for (size_t x = 0; x < size; x++)
			if (modules[y * size + x])
				for (int dy = 0; dy < scale; dy++)
					for (int dx = 0; dx < scale; dx++)
						img.setPixel((int)(x + FZN_QR_QUIET) * scale + dx,
						             (int)(y + FZN_QR_QUIET) * scale + dy, 0xff000000u);
	return img;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_devices_view v(node, nullptr);

	CHECK(v.refresh() && v.confirm()
	              && v.waiting() == QStringList({ "d1d1000000000000", "d2d2000000000000" }),
	      "the switch or the waiting devices were not read");

	/* A CODE, as text and as a QR. */
	CHECK(!v.code_drawn(), "a QR was drawn before any code was made");
	CHECK(v.invite() && v.code() == "FZI1:ABCDEFGHIJKLMNOP2345" && v.code_drawn()
	              && v.status().contains("ten minutes"),
	      "the code was not shown, drawn, or said to expire");

	/* THE SWITCH: set off, and put back when the node refuses. */
	CHECK(v.set_confirm(false) && !strcmp(last, "set setting host invite/confirm off") && !v.confirm(),
	      "confirming was not turned off");
	refuse_set = 1;
	CHECK(!v.set_confirm(true) && !v.confirm() && v.status() == "only an admin may change that",
	      "a refused switch was left showing on, or the node's words were lost");
	refuse_set = 0;

	/* WAITING DEVICES, answered by their full keys. */
	v.select_waiting(1);
	CHECK(v.answer(true) && !strcmp(last, "grant invite " DEV2) && v.status() == "d2d2000000000000 is let in.",
	      "the second device was not let in by its own key");
	v.select_waiting(0);
	CHECK(v.answer(false) && !strcmp(last, "remove invite " DEV1),
	      "the first device was not turned away by its own key");
	v.select_waiting(-1);
	last[0] = '\0';
	CHECK(!v.answer(true) && !last[0], "an answer was sent with no device chosen");

	/* JOINING: the code handed over, not joined at the first look, joined at
	 * the second; a code of the wrong shape asks nothing (sec 1123). */
	joined_after = 2;
	CHECK(v.join("  FZI1:WXYZ  ") && !strcmp(last, "add join FZI1:WXYZ")
	              && v.status().contains("few minutes"),
	      "the code was not handed to the node");
	CHECK(v.poll_join() == 0, "this host was read as joined while serving as before");
	CHECK(v.poll_join() == 1 && v.status() == "This device is one of your hosts now.",
	      "the join was not seen once this host served under the user");
	CHECK(v.poll_join() == 0, "a join already seen was looked at again");
	last[0] = '\0';
	CHECK(!v.join("ABCD") && !last[0] && v.status().contains("not a join code"),
	      "a code of the wrong shape was handed over");

	/* SCANNED, sec 1158: the code read from a picture and joined with; the
	 * frames after it, the same code again, take nothing while the join is
	 * under way; another kind of code is said to be one; a frame of no code
	 * says nothing, as a camera's most frames are. */
#ifdef FZN_QR_DECODE_ON
	CHECK(v.can_scan(), "a build with quirc said it cannot scan");
	joined_after = 2;
	last[0] = '\0';
	CHECK(v.scan_frame(drawn("FZI1:SCANNEDCODE234", 4)) && !strcmp(last, "add join FZI1:SCANNEDCODE234"),
	      "a scanned code was not handed to the node");
	last[0] = '\0';
	CHECK(!v.scan_frame(drawn("FZI1:ANOTHERCODE", 4)) && !last[0],
	      "a second code was taken while a join was under way");
	CHECK(v.poll_join() == 0 && v.poll_join() == 1, "the scanned join was not seen");
	CHECK(!v.scan_frame(drawn("HELLO", 4)) && !last[0] && v.status().contains("not a join code"),
	      "another kind of code was handed over, or not said to be one");
	{
		QImage blank(240, 240, QImage::Format_RGB32);
		QString before = v.status();

		blank.fill(Qt::white);
		CHECK(!v.scan_frame(blank) && !last[0] && v.status() == before,
		      "a frame with no code said something");
	}
	{
		QTemporaryDir dir;
		QString with = dir.filePath("code.png"), without = dir.filePath("room.png");
		QImage room(240, 240, QImage::Format_RGB32);

		room.fill(Qt::gray);
		CHECK(dir.isValid() && drawn("FZI1:FROMAFILE", 3).save(with) && room.save(without),
		      "the pictures were not written");
		joined_after = 2;
		CHECK(v.scan_file(with) && !strcmp(last, "add join FZI1:FROMAFILE"),
		      "the code in a picture file was not joined with");
		CHECK(v.poll_join() == 0 && v.poll_join() == 1, "the file's join was not seen");
		last[0] = '\0';
		CHECK(!v.scan_file(without) && !last[0] && v.status() == "No code was found in that picture.",
		      "a picture with no code was not said to have none");
		CHECK(!v.scan_file(dir.filePath("absent.png")) && v.status().contains("not a picture"),
		      "a missing file was not said to be no picture");
	}
#else
	CHECK(!v.can_scan() && !v.scan_frame(drawn("FZI1:SCANNEDCODE234", 4))
	              && v.status().contains("cannot read a code"),
	      "a build without quirc did not say it cannot scan");
#endif

	/* THE CAMERA'S FRAMES, sec 1158: the first handed on, shrunk to 960
	 * wide; the next, a moment later, left for the scanner to catch up. */
	{
		int handed = 0, width = 0;
		fzn_camera_feed feed(nullptr, [&](const QImage &f) {
			handed++;
			width = f.width();
		});
		QImage wide(1920, 1080, QImage::Format_RGB32);

		wide.fill(Qt::white);
		feed.frame(wide);
		feed.frame(wide);
		CHECK(handed == 1 && width == 960 && !feed.running(),
		      "a camera's frames were not thinned to one, or not shrunk");
	}

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui devices_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui devices_view_test: all %d checks passed\n", checks);
	return 0;
}
