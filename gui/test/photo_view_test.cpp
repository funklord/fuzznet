/*
 * photo_view_test -- the photographs this user's hosts hold, on a widget,
 * sec 1450, answered in binary by the node's own node/library_binary.c over
 * a catalogue the test fills: three photographs over two months and one of
 * no time said, by month newest first, each with its camera, size and
 * place; a song that is no photograph; the one chosen read through the play
 * slices from media/test/fixture/photo.jpg and shown turned as its EXIF
 * orientation says (16 by 12, orientation 6, shown taller than wide); one
 * not here asked for rather than read; found by its camera; a silent node;
 * the view no wider than a 320 px screen; and a phone's video among them
 * (sec 1460), its size and length said, no thumbnail read and nothing
 * decoded, handed to the host's player. Run from the tree's root.
 */

#include "../photo_view.h"

extern "C" {
#include "../../node/library_binary.h"
#include "../../wire/cmd.h"
#include "../../wire/generated/files_local.h"
#include "../../wire/status.h"
}

#include <QApplication>
#include <QFile>
#include <QLocale>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                    \
	do {                                                                                 \
		checks++;                                                                    \
		if (!(cond)) {                                                               \
			failures++;                                                          \
			fprintf(stderr, "  FAIL photo_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                            \
	} while (0)

static fzn_node_catalog_t cat;
static uint8_t me[32], other[32];
static uint64_t seq = 1;
static int silent, ranges_read;
static QByteArray jpeg, thumbed;
static char last[300];

static void say(const uint8_t *issuer, uint8_t fill, const char *name, const char *value)
{
	fzn_catalog_assertion_t a;
	uint8_t root[32], body[1024];
	size_t len = 0;

	memset(root, fill, sizeof(root));
	memset(&a, 0, sizeof(a));
	a.name = (const uint8_t *)name;
	a.name_len = strlen(name);
	a.value = (const uint8_t *)value;
	a.value_len = strlen(value);
	a.attr_class = FZN_CATALOG_LABEL;
	a.scope = FZN_CATALOG_ESTATE;
	a.merge = FZN_CATALOG_DISTINCT;
	a.capability = FZN_CATALOG_CAP_HOLDER;
	if (fzn_catalog_attribute_encode(&a, body, sizeof(body), &len) != FZN_CATALOG_OK
	    || fzn_node_catalog_take(&cat, issuer, root, seq++, FZN_CATALOG_ATTRIBUTE_KIND, body, len)
	               != FZN_NODE_CATALOG_OK)
		fprintf(stderr, "photo_view_test: a claim was not taken\n");
}

/* THE BYTES HERE: the photographs filled 0x21 and 0x26, the fixtures
 * photo.jpg and photo_thumb.jpg. */
static const QByteArray *bytes_of(uint8_t fill)
{
	return fill == 0x21 ? &jpeg : fill == 0x26 ? &thumbed : nullptr;
}

static int file_here(void *ctx, const uint8_t root[32], uint64_t *length, int *whole, uint16_t *arriving)
{
	(void)ctx;
	if (!bytes_of(root[0]))
		return 0;
	*length = (uint64_t)bytes_of(root[0])->size();
	*whole = 1;
	*arriving = 0;
	return 1;
}

static int file_state(void *ctx, const uint8_t root[32], fzn_node_file_here_t *out)
{
	(void)ctx;
	if (!bytes_of(root[0]))
		return 0;
	out->held = out->total = 1;
	out->length = (uint64_t)bytes_of(root[0])->size();
	out->state = 2;
	return 1;
}

struct framing {
	uint8_t *out;
	size_t cap, used;
};

static int frame_one(void *ctx, const uint8_t *msg, size_t len)
{
	struct framing *f = (struct framing *)ctx;

	if (f->used + 2u + len > f->cap)
		return 0;
	f->out[f->used++] = (uint8_t)(len >> 8);
	f->out[f->used++] = (uint8_t)len;
	memcpy(f->out + f->used, msg, len);
	f->used += len;
	return 1;
}

static int node_binary(void *ctx, const uint8_t *msg, size_t len, uint8_t *reply, size_t cap, size_t *reply_len)
{
	struct framing f = { reply, cap, 0 };

	(void)ctx;
	if (silent)
		return -1;
	if (len >= 2u && msg[0] == FZN_CMD_FILES && msg[1] == FZN_FILES_LOCAL_OP_FILE)
		(void)fzn_node_file_binary(file_state, NULL, msg, len, frame_one, &f);
	else if (len >= 2u && msg[0] == FZN_CMD_FILES)
		(void)fzn_node_library_binary(&cat, me, file_here, NULL, msg, len, frame_one, &f);
	else {
		uint8_t s[FZN_STATUS_LEN_MAX];
		(void)frame_one(&f, s, fzn_status_write(s, sizeof(s), FZN_STATUS_MALFORMED, "not here"));
	}
	*reply_len = f.used;
	return 0;
}

/* `get file ROOT OFFSET LENGTH PATH`: the fixture's range written to PATH. */
static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	char hex[65], path[200];
	unsigned long long off, n;

	(void)ctx;
	if (silent)
		return 0;
	if (sscanf(line, "get file %64s %llu %llu %199s", hex, &off, &n, path) == 4
	    && (!strncmp(hex, "2121", 4) || !strncmp(hex, "2626", 4))) {
		const QByteArray &b = hex[1] == '1' ? jpeg : thumbed;
		QFile out(QString::fromUtf8(path));
		if (off > (unsigned long long)b.size() || !out.open(QIODevice::WriteOnly))
			return (size_t)snprintf(reply, cap, "error no\n");
		out.write(b.mid((int)off, (int)n));
		ranges_read++;
		return (size_t)snprintf(reply, cap, "ok whole\n");
	}
	snprintf(last, sizeof last, "%s", line);
	return (size_t)snprintf(reply, cap, "ok\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	QLocale::setDefault(QLocale(QLocale::English, QLocale::UnitedKingdom));
	QFile f(QStringLiteral("media/test/fixture/photo.jpg"));

	if (!f.open(QIODevice::ReadOnly)) {
		fprintf(stderr, "photo_view_test: no media/test/fixture/photo.jpg; run from the tree's root\n");
		return 1;
	}
	jpeg = f.readAll();
	{
		QFile g(QStringLiteral("media/test/fixture/photo_thumb.jpg"));
		if (!g.open(QIODevice::ReadOnly)) {
			fprintf(stderr, "photo_view_test: no media/test/fixture/photo_thumb.jpg\n");
			return 1;
		}
		thumbed = g.readAll();
	}
	memset(me, 0xcc, sizeof(me));
	memset(other, 0xdd, sizeof(other));
	fzn_node_catalog_init(&cat);
	say(me, 0x21, "kind", "image/jpeg");
	say(me, 0x21, "taken", "2023-07-14T21:45:30");
	say(me, 0x21, "camera", "Canon EOS 5D");
	say(me, 0x21, "width", "16");
	say(me, 0x21, "height", "12");
	say(me, 0x21, "place", "67.8560000,20.2250000");
	say(other, 0x22, "kind", "image/jpeg");
	say(other, 0x22, "taken", "2023-07-02T08:00:00");
	say(other, 0x22, "camera", "OnePlus");
	say(other, 0x23, "kind", "image/jpeg");
	say(other, 0x23, "taken", "2025-12-31T23:59:58");
	say(other, 0x23, "place", "-33.8650000,-70.6500000");
	say(other, 0x24, "kind", "image/png");
	say(other, 0x24, "name", "scan.png");
	say(me, 0x26, "kind", "image/jpeg");
	say(me, 0x26, "taken", "2023-07-20T10:00:00");
	say(me, 0x27, "kind", "video/mp4");
	say(me, 0x27, "taken", "2023-07-21T09:00:00");
	say(me, 0x27, "width", "1920");
	say(me, 0x27, "height", "1080");
	say(me, 0x27, "duration", "12000");
	say(me, 0x25, "kind", "audio/mpeg");
	say(me, 0x25, "taken", "2020-01-01T00:00:00");

	fzn_photo_view v(node, nullptr);
	QByteArray played;
	v.answer_binary(node_binary, nullptr);
	v.on_play([&played](const QByteArray &root, const QString &) { played = root; });
	CHECK(v.refresh()
	              && v.rows() == QStringList({ "December 2025 | 1",
	                                           "  2025-12-31 23:59 |  |  | 33.8650° S, 70.6500° W | on 1 host(s)",
	                                           "July 2023 | 4",
	                                           "  2023-07-21 09:00 |  | 1920 × 1080, 0:12 video |  | on 1 host(s)",
	                                           "  2023-07-20 10:00 |  |  |  | here",
	                                           "  2023-07-14 21:45 | Canon EOS 5D | 16 × 12 | 67.8560° N, 20.2250° E | here",
	                                           "  2023-07-02 08:00 | OnePlus |  |  | on 1 host(s)",
	                                           "When unknown | 1", "  scan.png |  |  |  | on 1 host(s)" }),
	      "the photographs were not listed by month newest first, with camera, size and place");
	if (failures)
		for (const QString &r : v.rows())
			fprintf(stderr, "    %s\n", r.toUtf8().constData());
	CHECK(v.status() == "5 photograph(s) and 1 video(s).", "the count was not said");

	/* THUMBNAILS, sec 1455: the two held here read, jhead's showing the
	 * camera's own thumbnail and Pillow's, which has none, showing none. */
	CHECK(v.read_thumbnails(10) == 2 && v.has_thumbnail(4) && !v.has_thumbnail(5) && !v.has_thumbnail(1)
	              && !v.has_thumbnail(3),
	      "a thumbnail was not shown where the camera wrote one, or was where it did not");

	/* SHOWN, turned as its EXIF says: 16 by 12 at orientation 6 is shown
	 * taller than wide. */
	v.select(5);
	const QImage shown = v.shown_picture();
	CHECK(!shown.isNull() && ranges_read > 0 && shown.height() > shown.width(),
	      "the photograph chosen was not read and shown turned as it says");
	/* ONE NOT HERE is asked for, not read. */
	ranges_read = 0;
	v.select(1);
	CHECK(v.shown_picture().isNull() && !ranges_read && v.fetch(), "a photograph not here was read, or not asked for");
	v.select(5);
	CHECK(!v.fetch(), "a photograph here was asked for again");
	CHECK(!v.play() && played.isEmpty(), "a photograph was handed to a video's player");
	/* A VIDEO, chosen: nothing read or decoded, played through the host's
	 * player. */
	ranges_read = 0;
	v.select(3);
	CHECK(v.shown_picture().isNull() && !ranges_read && v.status() == "A video: \"Play\" plays it."
	              && v.play() && played == QByteArray(32, 0x27),
	      "a video was read to be shown, or not handed to the host's player");

	v.set_find("oneplus");
	CHECK(v.rows() == QStringList({ "July 2023 | 4", "  2023-07-02 08:00 | OnePlus |  |  | on 1 host(s)" })
	              && v.status() == "1 of 6 shown.",
	      "a photograph was not found by its camera, in another case");
	v.set_find("");
	CHECK(v.rows().size() == 9, "every photograph did not come back");
	CHECK(v.minimumSizeHint().width() <= 320, "the view was wider than a 320 px screen");

	silent = 1;
	CHECK(!v.refresh() && v.rows().size() == 9, "a node that does not answer cleared the photographs");

	fzn_node_catalog_free(&cat);
	if (failures) {
		fprintf(stderr, "gui photo_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui photo_view_test: all %d checks passed\n", checks);
	return 0;
}
