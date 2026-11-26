/*
 * THE README'S PICTURE, made from the current build (project.md sec 1489):
 * fuzznet's music view, headless, over a demo catalogue answered in binary
 * by the node's own node/library_binary.c, as music_view_test answers it --
 * two albums and a track of none, a tempo and key heard for each, one
 * track with its lyrics and video -- grabbed into a PNG.
 *
 *     screenshot OUT.png
 *
 * `make screenshots` runs it with -platform offscreen. Demo data only:
 * invented artists and albums, no person's library. Exit 0 with the PNG
 * written, 1 otherwise.
 */
#include "../music_view.h"
extern "C" {
#include "../../node/library_binary.h"
#include "../../wire/cmd.h"
#include "../../wire/status.h"
}

#include <QApplication>
#include <QPixmap>

#include <stdio.h>
#include <string.h>

static fzn_node_catalog_t cat;
static uint8_t me[32], other[32];
static uint64_t seq = 1;

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
		fprintf(stderr, "screenshot: a claim was not taken\n");
}

/* THE BYTES HERE: what this host was given filled below 0x20. */
static int file_here(void *ctx, const uint8_t root[32], uint64_t *length, int *whole, uint16_t *arriving)
{
	(void)ctx;
	if (root[0] >= 0x20)
		return 0;
	*length = 6000000u;
	*whole = 1;
	*arriving = 0;
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
	uint8_t s[FZN_STATUS_LEN_MAX];

	(void)ctx;
	if (len >= 2u && msg[0] == FZN_CMD_FILES)
		(void)fzn_node_library_binary(&cat, me, file_here, NULL, msg, len, frame_one, &f);
	else
		(void)frame_one(&f, s, fzn_status_write(s, sizeof(s), FZN_STATUS_MALFORMED, "not here"));
	*reply_len = f.used;
	return 0;
}

/* Text the view asks is answered as a node with nothing to say. */
static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	(void)line;
	return (size_t)snprintf(reply, cap, "ok\n");
}

static void tune(const uint8_t *who, uint8_t fill, const char *title, const char *artist, const char *album,
                 const char *track, const char *ms, const char *bpm, const char *key)
{
	say(who, fill, "kind", "audio/flac");
	say(who, fill, "title", title);
	say(who, fill, "artist", artist);
	if (album)
		say(who, fill, "album", album);
	if (track)
		say(who, fill, "track", track);
	say(who, fill, "duration", ms);
	say(who, fill, "bpm", bpm);
	say(who, fill, "key", key);
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);

	if (argc < 2) {
		fprintf(stderr, "usage: screenshot OUT.png\n");
		return 2;
	}
	memset(me, 0xcc, sizeof(me));
	memset(other, 0xdd, sizeof(other));
	fzn_node_catalog_init(&cat);
	tune(me, 0x11, "Harbour Lights", "The Lanterns", "Night Ferry", "1/9", "214000", "122.00", "8A Am");
	tune(me, 0x12, "Low Tide", "The Lanterns", "Night Ferry", "2/9", "251000", "118.00", "9A Em");
	tune(me, 0x13, "North Wind", "The Lanterns", "Night Ferry", "3/9", "198000", "126.00", "8B C");
	say(me, 0x11, "lyrics", "1919191919191919191919191919191919191919191919191919191919191919");
	say(me, 0x11, "video", "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a");
	tune(other, 0x31, "Blue Hour", "Mara Ode", "Field Recordings", "1/6", "305000", "96.40", "4A Fm");
	tune(other, 0x32, "Slow Rain", "Mara Ode", "Field Recordings", "2/6", "278000", "92.00", "5A Cm");
	tune(me, 0x14, "Demo, take two", "Mara Ode", nullptr, nullptr, "121000", "100.00", "6B F");

	fzn_music_view v(node, nullptr);
	v.answer_binary(node_binary, nullptr);
	/* A PLAYER, so Play reads as it does in a host that has one. */
	v.on_play([](const QByteArray &, const QString &) {});
	v.on_play_all([](const QList<QPair<QByteArray, QString>> &) {});
	v.resize(720, 360);
	if (!v.refresh()) {
		fprintf(stderr, "screenshot: the music did not list\n");
		return 1;
	}
	v.select(2);
	v.show();
	app.processEvents();
	const QPixmap shot = v.grab();
	fzn_node_catalog_free(&cat);
	if (shot.isNull() || !shot.save(QString::fromLocal8Bit(argv[1]), "PNG")) {
		fprintf(stderr, "screenshot: %s was not written\n", argv[1]);
		return 1;
	}
	return 0;
}
