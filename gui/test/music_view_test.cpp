/*
 * music_view_test -- the music this user's hosts hold, on a widget, sec
 * 1449, answered in binary by the node's own node/library_binary.c over a
 * catalogue the test fills: two albums, one by its album artist with a
 * track by a guest, one track of no album, a film that is no music; each
 * album in order with its tracks by disc and track; a track played, an
 * album played in its order, a track not here asked for and one here not;
 * found by a word of its artist, in another case, an album with no track
 * left hidden; a library from before read a page at a time; a node that
 * does not answer; and the view no wider than a 320 px screen.
 */

#include "../music_view.h"

extern "C" {
#include "../../node/library_binary.h"
#include "../../wire/cmd.h"
#include "../../wire/generated/files_local.h"
#include "../../wire/generated/files_local_build.h"
#include "../../wire/status.h"
}

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                    \
	do {                                                                                 \
		checks++;                                                                    \
		if (!(cond)) {                                                               \
			failures++;                                                          \
			fprintf(stderr, "  FAIL music_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                            \
	} while (0)

static fzn_node_catalog_t cat;
static uint8_t me[32], other[32];
static uint64_t seq = 1;
static int hear_pages;
static int silent, pages_asked;
static char last[200];

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
		fprintf(stderr, "music_view_test: a claim was not taken\n");
}

/* THE BYTES HERE: the songs filled 0x11 and 0x12. */
static int file_here(void *ctx, const uint8_t root[32], uint64_t *length, int *whole, uint16_t *arriving)
{
	(void)ctx;
	if (root[0] != 0x11 && root[0] != 0x12)
		return 0;
	*length = 4000000u;
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
	if (silent)
		return -1;
	if (len >= 2u && msg[0] == FZN_CMD_FILES && msg[1] == FZN_FILES_LOCAL_OP_TAGS_PAGE) {
		/* A LIBRARY FROM BEFORE, two pages of it. */
		uint8_t row[12], out[24];
		uint32_t row_len = 0, out_len = 0;
		const uint32_t from = (uint32_t)msg[2] << 24 | (uint32_t)msg[3] << 16 | (uint32_t)msg[4] << 8 | msg[5];

		pages_asked++;
		(void)fzn_files_local_tags_done_build(row, sizeof(row), from ? 40u : 32u, 40u, from ? 3u : 4u, &row_len);
		(void)fzn_files_local_message_build_tags_done(out, sizeof(out), (uint8_t)FZN_CMD_FILES, row, row_len,
		                                             &out_len);
		(void)frame_one(&f, out, out_len);
		(void)frame_one(&f, s, fzn_status_write(s, sizeof(s), FZN_STATUS_OK, NULL));
	} else if (len >= 2u && msg[0] == FZN_CMD_FILES && msg[1] == FZN_FILES_LOCAL_OP_SOUND_PAGE) {
		/* A LIBRARY HEARD, sec 1458: two pages, five tunes queued, six
		 * waiting at the end. */
		uint8_t row[16], out[24];
		uint32_t row_len = 0, out_len = 0;
		const uint32_t from = (uint32_t)msg[2] << 24 | (uint32_t)msg[3] << 16 | (uint32_t)msg[4] << 8 | msg[5];

		hear_pages++;
		(void)fzn_files_local_sound_done_build(row, sizeof(row), from ? 300u : 256u, 300u, from ? 1u : 4u,
		                                       from ? 6u : 5u, &row_len);
		(void)fzn_files_local_message_build_sound_done(out, sizeof(out), (uint8_t)FZN_CMD_FILES, row, row_len,
		                                              &out_len);
		(void)frame_one(&f, out, out_len);
		(void)frame_one(&f, s, fzn_status_write(s, sizeof(s), FZN_STATUS_OK, NULL));
	} else if (len >= 2u && msg[0] == FZN_CMD_FILES) {
		(void)fzn_node_library_binary(&cat, me, file_here, NULL, msg, len, frame_one, &f);
	} else {
		(void)frame_one(&f, s, fzn_status_write(s, sizeof(s), FZN_STATUS_MALFORMED, "not here"));
	}
	*reply_len = f.used;
	return 0;
}

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	snprintf(last, sizeof last, "%s", line);
	return (size_t)snprintf(reply, cap, "ok\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	QList<QPair<QByteArray, QString>> album_played;
	QByteArray played;

	memset(me, 0xcc, sizeof(me));
	memset(other, 0xdd, sizeof(other));
	fzn_node_catalog_init(&cat);
	/* POLAR LIGHTS, by its album artist, track 3 by a guest. */
	say(me, 0x11, "kind", "audio/mpeg");
	say(me, 0x11, "title", "Night Drive");
	say(me, 0x11, "artist", "Svalbard Echo");
	say(me, 0x11, "album", "Polar Lights");
	say(me, 0x11, "track", "2/12");
	say(me, 0x11, "year", "2019");
	say(me, 0x11, "duration", "251000");
	say(me, 0x11, "bpm", "128.00");
	say(me, 0x11, "key", "8A Am");
	say(me, 0x12, "kind", "audio/mpeg");
	say(me, 0x12, "title", "Aurora");
	say(me, 0x12, "artist", "Mira feat. Svalbard Echo");
	say(me, 0x12, "album_artist", "Svalbard Echo");
	say(me, 0x12, "album", "Polar Lights");
	say(me, 0x12, "track", "1/12");
	say(me, 0x12, "bpm", "96.40");
	say(me, 0x12, "key", "9A Em");
	/* SUNDAY AT THE VILLAGE VANGUARD, held elsewhere. */
	say(other, 0x13, "kind", "audio/flac");
	say(other, 0x13, "title", "Waltz for Debby");
	say(other, 0x13, "artist", "Bill Evans");
	say(other, 0x13, "album", "Sunday at the Village Vanguard");
	say(other, 0x13, "year", "1961-06-25");
	say(other, 0x13, "key", "7B F");
	/* a genre holding a key's place in its letters, which finding the
	 * place must pass over (sec 1467) */
	say(other, 0x13, "genre", "Jazz at 8am");
	/* A TRACK OF NO ALBUM, named by its file alone. */
	say(other, 0x14, "kind", "audio/ogg");
	say(other, 0x14, "name", "demo take.ogg");
	say(other, 0x14, "artist", "Svalbard Echo");
	/* A FILM, which is no music. */
	say(me, 0x15, "kind", "video/webm");
	say(me, 0x15, "title", "A film");

	fzn_music_view v(node, nullptr);
	v.answer_binary(node_binary, nullptr);
	v.on_play([&played](const QByteArray &root, const QString &) { played = root; });
	v.on_play_all([&album_played](const QList<QPair<QByteArray, QString>> &t) { album_played = t; });

	CHECK(v.refresh()
	              && v.rows() == QStringList({ "Sunday at the Village Vanguard | Bill Evans | 1961 |  |  | ",
	                                           "  Waltz for Debby |  |  |  | 7B F | on 1 host(s)",
	                                           "No album | Svalbard Echo |  |  |  | ",
	                                           "  demo take.ogg |  |  |  |  | on 1 host(s)",
	                                           "Polar Lights | Svalbard Echo | 2019 |  |  | ",
	                                           "  1. Aurora | Mira feat. Svalbard Echo |  | 96.4 | 9A Em | here",
	                                           "  2. Night Drive |  | 4:11 | 128 | 8A Am | here" }),
	      "the music was not listed by album, its tracks in order, a guest's named, tempo and key shown");
	if (failures)
		for (const QString &r : v.rows())
			fprintf(stderr, "    %s\n", r.toUtf8().constData());
	CHECK(v.status() == "4 piece(s) of music.", "the count was not said");

	/* PLAYING: a track, then an album in its order. */
	v.select(6);
	CHECK(v.play() && played == QByteArray(32, 0x11), "a track was not handed to the host's player");
	v.select(4);
	CHECK(v.play() && album_played.size() == 2 && album_played[0].first == QByteArray(32, 0x12)
	              && album_played[1].first == QByteArray(32, 0x11),
	      "an album was not played in its track order");

	/* GETTING: one held elsewhere asked for; one here is not. */
	last[0] = '\0';
	v.select(6);
	CHECK(!v.fetch() && !last[0], "a track here was asked for again");
	v.select(1);
	CHECK(v.fetch(), "a track held elsewhere was not asked for");

	/* FINDING, by a word of the artist in another case: Bill Evans's album
	 * alone, the others hidden. */
	v.set_find("bill");
	CHECK(v.rows() == QStringList({ "Sunday at the Village Vanguard | Bill Evans | 1961 |  |  | ",
	                                "  Waltz for Debby |  |  |  | 7B F | on 1 host(s)" })
	              && v.status() == "1 of 4 shown.",
	      "music was not found by a word of its artist");
	v.set_find("mira");
	CHECK(v.rows().size() == 2 && v.rows()[1].startsWith("  1. Aurora"), "a guest's track was not found");
	v.set_find("nothing like this");
	CHECK(v.rows().isEmpty() && v.status() == "No music matches.", "finding nothing was not said");
	v.set_find("");
	CHECK(v.rows().size() == 7, "every album did not come back");

	/* BY TEMPO, sec 1458: a group a whole BPM, slowest first, the tunes not
	 * heard last; BY KEY round the wheel, 7B before 8A before 9A; BY
	 * ARTIST, each artist's tracks under them. The track chosen stays
	 * chosen across an order. */
	v.select(6);
	v.set_order(fzn_music_view::BY_TEMPO);
	CHECK(v.rows() == QStringList({ "96 BPM |  |  |  |  | ",
	                                "  Aurora | Mira feat. Svalbard Echo |  | 96.4 | 9A Em | here",
	                                "128 BPM |  |  |  |  | ",
	                                "  Night Drive | Svalbard Echo | 4:11 | 128 | 8A Am | here",
	                                "Tempo not heard |  |  |  |  | ",
	                                "  demo take.ogg | Svalbard Echo |  |  |  | on 1 host(s)",
	                                "  Waltz for Debby | Bill Evans |  |  | 7B F | on 1 host(s)" }),
	      "the music was not ordered by tempo, slowest first, the unheard last");
	CHECK(v.play() && played == QByteArray(32, 0x11), "the track chosen was lost to a new order");
	v.set_order(fzn_music_view::BY_KEY);
	CHECK(v.rows().size() == 8 && v.rows()[0].startsWith("7B F |") && v.rows()[2].startsWith("8A Am |")
	              && v.rows()[4].startsWith("9A Em |") && v.rows()[6].startsWith("Key not heard |"),
	      "the music was not ordered round the Camelot wheel");
	v.set_order(fzn_music_view::BY_ARTIST);
	CHECK(v.rows().size() == 7 && v.rows()[0].startsWith("Bill Evans |")
	              && v.rows()[2].startsWith("Mira feat. Svalbard Echo |") && v.rows()[4].startsWith("Svalbard Echo |")
	              && v.rows()[5].startsWith("  demo take.ogg |  |"),
	      "the music was not ordered by artist");
	v.set_find("8a");
	CHECK(v.rows().size() == 2 && v.rows()[1].startsWith("  Night Drive"),
	      "a track was not found by its key, or one was by a word holding its letters");
	v.set_find("96");
	CHECK(v.rows().size() == 2 && v.rows()[1].startsWith("  Aurora"), "a track was not found by its tempo");
	/* A TEMPO AND A KEY'S PLACE, sec 1467: a span of tempos either way
	 * round, the unit glued or apart, rounded as the column shows it; a
	 * place on the wheel, and not its letters inside a word; every term
	 * held at once. */
	v.set_find("90-130 bpm");
	CHECK(v.rows().size() == 4 && v.rows()[1].startsWith("  Aurora") && v.rows()[3].startsWith("  Night Drive")
	              && v.status() == "2 of 4 shown.",
	      "the tracks within a span of tempos were not found");
	v.set_find("130-120BPM");
	CHECK(v.rows().size() == 2 && v.rows()[1].startsWith("  Night Drive"), "a span written high first was not read");
	v.set_find("96 bpm");
	CHECK(v.rows().size() == 2 && v.rows()[1].startsWith("  Aurora"), "a tempo was not read as the column rounds it");
	v.set_find("200 bpm");
	CHECK(v.rows().isEmpty(), "a tempo nobody is at found a track");
	v.set_find("7b");
	CHECK(v.rows().size() == 2 && v.rows()[1].startsWith("  Waltz for Debby"), "a track was not found by its key's place");
	v.set_find("svalbard 9A");
	CHECK(v.rows().size() == 2 && v.rows()[1].startsWith("  Aurora"), "every term was not held at once");
	v.set_find("svalbard 90-100");
	CHECK(v.rows().isEmpty(), "a span with no unit was read as a tempo");
	v.set_find("");
	v.set_order(fzn_music_view::BY_ALBUM);
	CHECK(v.rows().size() == 7 && v.rows()[0].startsWith("Sunday at"), "the albums did not come back");

	/* A LIBRARY HEARD, a page at a time to the end. */
	CHECK(v.hear() == 6 && hear_pages == 2
	              && v.status() == "6 tune(s) to be heard; their tempo and key show as each is.",
	      "the library was not heard a page at a time, what waits said");

	/* A LIBRARY FROM BEFORE, read a page at a time to the end. */
	CHECK(v.read_tags() == 7 && pages_asked == 2 && v.status() == "Read 40 file(s); 7 name(s) learned.",
	      "the tags were not read a page at a time, what was learned said");

	CHECK(v.minimumSizeHint().width() <= 320, "the view was wider than a 320 px screen");

	silent = 1;
	CHECK(!v.refresh() && v.rows().size() == 7, "a node that does not answer cleared the music");

	fzn_node_catalog_free(&cat);
	if (failures) {
		fprintf(stderr, "gui music_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui music_view_test: all %d checks passed\n", checks);
	return 0;
}
