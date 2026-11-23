/*
 * sticker_picker_view_test -- choosing a sticker and keeping packs, on a
 * widget, sec 1141, against a scripted node behind the ask callback: a kept
 * pack as a tab with two stickers, one drawn from the PNG the node renders
 * and one named by its description, and a Lottie one drawn through the
 * vendored thorvg where it is built in (sec 1151); choosing one hands the host its
 * reference; keeping two pack files, one refused, said as "Kept 1 of 2";
 * and a node that does not answer.
 */

#include "../sticker_picker_view.h"

#include <QAccessible>
#include <QListWidget>
#include "../sticker_render.h"

#include <QApplication>
#include <QDir>
#include <QFile>
#include <QBuffer>
#include <QImage>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                              \
	do {                                                                                           \
		checks++;                                                                              \
		if (!(cond)) {                                                                         \
			failures++;                                                                    \
			fprintf(stderr, "  FAIL sticker_picker_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                                      \
	} while (0)

#define PACK "5757000000000000000000000000000000000000000000000000000000000001"
#define REF "fzn:sticker/" PACK "/0000000000000000000000000000000000000000000000000000000000000002/4096/7"
#define REF8 "fzn:sticker/" PACK "/0000000000000000000000000000000000000000000000000000000000000002/4096/8"

static int silent, let_go, art_asked, sound_asked, silent_asked;

/* A LOTTIE STICKER, the smallest that draws: one red square on a layer. */
static const char LOTTIE[] =
        "{\"v\":\"5.7.4\",\"fr\":30,\"ip\":0,\"op\":30,\"w\":100,\"h\":100,\"nm\":\"t\",\"ddd\":0,"
        "\"assets\":[],\"layers\":[{\"ddd\":0,\"ind\":1,\"ty\":4,\"nm\":\"r\",\"sr\":1,"
        "\"ks\":{\"o\":{\"a\":0,\"k\":100},\"r\":{\"a\":0,\"k\":0},\"p\":{\"a\":0,\"k\":[50,50,0]},"
        "\"a\":{\"a\":0,\"k\":[0,0,0]},\"s\":{\"a\":0,\"k\":[100,100,100]}},\"ao\":0,"
        "\"shapes\":[{\"ty\":\"rc\",\"d\":1,\"s\":{\"a\":0,\"k\":[80,80]},\"p\":{\"a\":0,\"k\":[0,0]},"
        "\"r\":{\"a\":0,\"k\":0},\"nm\":\"rect\"},{\"ty\":\"fl\",\"c\":{\"a\":0,\"k\":[1,0,0,1]},"
        "\"o\":{\"a\":0,\"k\":100},\"r\":1,\"nm\":\"fill\"}],\"ip\":0,\"op\":30,\"st\":0,\"bm\":0}]}";

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	static const char DRAW[] = "get sticker " PACK " 7 thumb ";
	static const char DRAW_LOTTIE[] = "get sticker " PACK " 9 thumb ";
	(void)ctx;
	if (silent)
		return 0;
	if (!strcmp(line, "list sticker 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 " PACK ",4096,waves,1,user\n");
	/* SENT LATELY, sec 1317: thumbs up, then waving, then one of a pack
	 * not kept here. */
	if (!strcmp(line, "list sticker recent"))
		return (size_t)snprintf(reply, cap,
		                        "ok 3 0 " PACK ",8,thumbs%%20up " PACK ",7,waving %064d,3,elsewhere\n", 0);
	if (!strcmp(line, "list sticker " PACK " 0"))
		return (size_t)snprintf(reply, cap, "ok 3 0 7,1,1,waving 8,1,0,thumbs%%20up,12 9,1,4,dancing\n");
	/* STICKER 9 IS A LOTTIE: its JSON written where asked, format 1. */
	if (!strncmp(line, DRAW_LOTTIE, sizeof DRAW_LOTTIE - 1)) {
		FILE *f = fopen(line + sizeof DRAW_LOTTIE - 1, "wbx");
		if (!f || fwrite(LOTTIE, 1, sizeof LOTTIE - 1, f) != sizeof LOTTIE - 1) {
			if (f)
				fclose(f);
			return (size_t)snprintf(reply, cap, "error could not write\n");
		}
		fclose(f);
		return (size_t)snprintf(reply, cap, "ok 1 100 100\n");
	}
	/* STICKER 7 IS DRAWN: a PNG written where asked. 8 HAS NO ART. */
	if (!strncmp(line, DRAW, sizeof DRAW - 1)) {
		QImage one(1, 1, QImage::Format_ARGB32);
		art_asked++;
		one.fill(Qt::red);
		if (!one.save(QString::fromUtf8(line + sizeof DRAW - 1), "PNG"))
			return (size_t)snprintf(reply, cap, "error could not write\n");
		return (size_t)snprintf(reply, cap, "ok 4 1 1\n");
	}
	/* STICKER 7 HAS A SOUND (flag 1): its bytes written where asked. */
	if (!strncmp(line, "get sticker " PACK " 7 sound ", 12 + 64 + 9)) {
		FILE *f = fopen(line + 12 + 64 + 9, "wbx");
		sound_asked++;
		if (!f || fwrite("RIFF", 1, 4, f) != 4) {
			if (f)
				fclose(f);
			return (size_t)snprintf(reply, cap, "error could not write\n");
		}
		fclose(f);
		return (size_t)snprintf(reply, cap, "ok 4\n");
	}
	/* STICKER 8 HAS NO SOUND, and is never asked for one. */
	if (!strncmp(line, "get sticker " PACK " 8 sound ", 12 + 64 + 9)) {
		silent_asked++;
		return (size_t)snprintf(reply, cap, "error no sound\n");
	}
	if (!strncmp(line, "get sticker " PACK " 8 thumb ", 12 + 64 + 9))
		return (size_t)snprintf(reply, cap, "error no art\n");
	if (!strcmp(line, "get sticker " PACK " 7"))
		return (size_t)snprintf(reply, cap, "ok " REF "\n");
	/* STICKER 8 HAS A BOX OF TWELVE: its reference with words, or without
	 * (sec 1296). */
	if (!strcmp(line, "get sticker " PACK " 8 text hi%20there"))
		return (size_t)snprintf(reply, cap, "ok " REF8 ":hi%%20there\n");
	if (!strcmp(line, "get sticker " PACK " 8"))
		return (size_t)snprintf(reply, cap, "ok " REF8 "\n");
	/* KEEPING: a pack file put as a pack and kept, the other refused
	 * (`put sticker PATH`, sec 1278). */
	/* FINDING: "thumbs" fits sticker 8, nothing fits "zebra" (sec 1298). */
	if (!strcmp(line, "list sticker match thumbs"))
		return (size_t)snprintf(reply, cap, "ok 1 0 " PACK ",8,150,thumbs%%20up\n");
	if (!strncmp(line, "list sticker match ", 19))
		return (size_t)snprintf(reply, cap, "ok 0 0\n");
	/* LETTING THE PACK GO, sec 1298. */
	if (!strcmp(line, "remove sticker " PACK)) {
		let_go++;
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	if (!strcmp(line, "put sticker /tmp/fzn-good.fzs"))
		return (size_t)snprintf(reply, cap, "ok " PACK "\n");
	if (!strcmp(line, "put sticker /tmp/fzn-bad.fzs"))
		return (size_t)snprintf(reply, cap, "error not a sticker pack\n");
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

/* THE ORIGINAL TEST SET DRAWS, fuzznet sec 1277: each of its twelve
 * Lottie files, read from the tree, drawn by thorvg at 256 pixels at its
 * start and its middle -- some paint inside the frame, and the two not the
 * same, so the art moves. FZN_TEST_SET_PNG names a directory to save each
 * drawing in, for a person to look at. */
/* AN APNG BY HAND, sec 1322: two 4x4 frames, red then green, the first
 * the default image -- each frame's IDAT taken from a PNG Qt writes, the
 * chunks around them written here, CRCs and all. */
static uint32_t crc_of(const QByteArray &type_and_data)
{
	uint32_t c = 0xffffffffu;
	for (char ch : type_and_data) {
		c ^= (uint8_t)ch;
		for (int b = 0; b < 8; b++)
			c = (c & 1u) ? 0xedb88320u ^ (c >> 1) : c >> 1;
	}
	return c ^ 0xffffffffu;
}

static void be32(QByteArray &out, uint32_t v)
{
	out.append((char)(v >> 24)).append((char)(v >> 16)).append((char)(v >> 8)).append((char)v);
}

static void chunk(QByteArray &out, const char *type, const QByteArray &data)
{
	QByteArray td = QByteArray(type, 4) + data;
	be32(out, (uint32_t)data.size());
	out.append(td);
	be32(out, crc_of(td));
}

/* A PNG's IDAT data and IHDR, of a 4x4 image of one colour. */
static void png_of(Qt::GlobalColor colour, QByteArray *ihdr, QByteArray *idat)
{
	QImage img(4, 4, QImage::Format_ARGB32);
	QByteArray png;
	QBuffer buf(&png);
	int at = 8;

	img.fill(colour);
	buf.open(QIODevice::WriteOnly);
	img.save(&buf, "PNG");
	while (at + 12 <= png.size()) {
		const uint32_t n = (uint32_t)(uint8_t)png[at] << 24 | (uint32_t)(uint8_t)png[at + 1] << 16
		                   | (uint32_t)(uint8_t)png[at + 2] << 8 | (uint8_t)png[at + 3];
		const QByteArray type = png.mid(at + 4, 4), data = png.mid(at + 8, (int)n);
		if (type == "IHDR")
			*ihdr = data;
		else if (type == "IDAT")
			idat->append(data);
		at += 12 + (int)n;
	}
}

static void fctl(QByteArray &out, uint32_t seq)
{
	QByteArray d;
	be32(d, seq);
	be32(d, 4);
	be32(d, 4);
	be32(d, 0);
	be32(d, 0);
	d.append((char)0).append((char)1).append((char)0).append((char)10); /* 1/10 s */
	d.append((char)0).append((char)0);                                   /* dispose none, blend source */
	chunk(out, "fcTL", d);
}

static void test_an_apng_plays(void)
{
	QByteArray ihdr, red, green, apng("\x89PNG\r\n\x1a\n", 8), actl, fdat;
	QByteArray still_ihdr, still_idat, still("\x89PNG\r\n\x1a\n", 8);
	QImage first, last;

	png_of(Qt::red, &ihdr, &red);
	png_of(Qt::green, &ihdr, &green);
	chunk(apng, "IHDR", ihdr);
	be32(actl, 2);
	be32(actl, 0);
	chunk(apng, "acTL", actl);
	fctl(apng, 0);
	chunk(apng, "IDAT", red);
	fctl(apng, 1);
	be32(fdat, 2);
	fdat.append(green);
	chunk(apng, "fdAT", fdat);
	chunk(apng, "IEND", QByteArray());
	CHECK(fzn_sticker_render_frames((const uint8_t *)apng.constData(), (size_t)apng.size(), FZN_STICKER_APNG) == 2,
	      "an APNG of two frames was not counted as two");
	first = fzn_sticker_render_art((const uint8_t *)apng.constData(), (size_t)apng.size(), FZN_STICKER_APNG,
	                               QSize(4, 4), 0.0f)
	                .pixmap.toImage();
	last = fzn_sticker_render_art((const uint8_t *)apng.constData(), (size_t)apng.size(), FZN_STICKER_APNG,
	                              QSize(4, 4), 0.9f)
	               .pixmap.toImage();
	CHECK(!first.isNull() && first.pixelColor(2, 2) == QColor(Qt::red), "an APNG's first frame was not drawn");
	CHECK(!last.isNull() && last.pixelColor(2, 2) == QColor(Qt::green), "an APNG's last frame was not drawn");
	/* A STILL is one frame, drawn the same wherever asked. */
	png_of(Qt::red, &still_ihdr, &still_idat);
	chunk(still, "IHDR", still_ihdr);
	chunk(still, "IDAT", still_idat);
	chunk(still, "IEND", QByteArray());
	CHECK(fzn_sticker_render_frames((const uint8_t *)still.constData(), (size_t)still.size(), FZN_STICKER_APNG) == 1
	              && fzn_sticker_render_art((const uint8_t *)still.constData(), (size_t)still.size(), FZN_STICKER_APNG,
	                                        QSize(4, 4), 0.9f)
	                                 .pixmap.toImage()
	                                 .pixelColor(2, 2)
	                         == QColor(Qt::red),
	      "a still was counted as moving, or drawn differently further in");
}

static void test_the_test_set_draws(void)
{
	const QDir art(QStringLiteral("sticker/fixture/test-set/art"));
	const QStringList files = art.entryList({ QStringLiteral("*.json") }, QDir::Files, QDir::Name);
	const QByteArray save = qgetenv("FZN_TEST_SET_PNG");
	int drawn = 0, moving = 0;

	for (const QString &name : files) {
		QFile f(art.filePath(name));
		if (!f.open(QIODevice::ReadOnly))
			continue;
		const QByteArray json = f.readAll();
		QImage at[2];
		for (int k = 0; k < 2; k++)
			at[k] = fzn_sticker_render_art((const uint8_t *)json.constData(), (size_t)json.size(), 1, QSize(256, 256),
			                               k ? 0.5f : 0.0f)
			                .pixmap.toImage();
		bool painted = false;
		for (int y = 0; !at[0].isNull() && y < at[0].height() && !painted; y += 4)
			for (int x = 0; x < at[0].width() && !painted; x += 4)
				painted = qAlpha(at[0].pixel(x, y)) > 0;
		drawn += painted;
		moving += !at[0].isNull() && at[0] != at[1];
		if (!save.isEmpty() && !at[0].isNull())
			at[0].save(QString::fromLocal8Bit(save) + QLatin1Char('/') + name + QStringLiteral(".png"), "PNG");
	}
	CHECK(files.size() == 12 && drawn == 12, "the test set's twelve stickers did not all draw");
	CHECK(moving == 12, "a sticker of the test set did not move");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_sticker_picker_view v(node, nullptr);
	QString picked;

	test_the_test_set_draws();
	test_an_apng_plays();

	v.on_pick([&picked](const QString &ref) { picked = ref; });
#ifdef FZN_THORVG_ON
	const char *dancing = "  dancing [drawn]";
#else
	const char *dancing = "  dancing";
#endif
	CHECK(v.refresh() && v.shown() == QStringList({ "waves", "  waving [drawn]", "  thumbs up", dancing }),
	      "the pack was not a tab with its stickers, the drawn ones drawn and the other named");
	CHECK(v.pick(0, 0) && picked == REF, "choosing a sticker did not hand over its reference");
	CHECK(!v.pick(0, 5), "a sticker that is not there was chosen");
	/* A SCREEN READER PICKS ONE, sec 1423: TalkBack's double tap is the row's
	 * accessible toggle, which only selects, and is the one gesture it has
	 * -- so the toggle sends, as activation does. */
	{
		QListWidget *pack = nullptr;

		for (QListWidget *l : v.findChildren<QListWidget *>())
			if (l->property("pack").isValid() && l->property("pack").toInt() == 0)
				pack = l;
		QAccessibleInterface *view = pack ? QAccessible::queryAccessibleInterface(pack) : nullptr;
		QAccessibleTableInterface *table = view ? view->tableInterface() : nullptr;
		QAccessibleInterface *cell = table ? table->cellAt(0, 0) : nullptr;
		QAccessibleActionInterface *act = cell ? cell->actionInterface() : nullptr;

		picked.clear();
		if (pack)
			pack->clearSelection();
		if (act)
			act->doAction(QAccessibleActionInterface::toggleAction());
		QCoreApplication::processEvents();
		CHECK(act && picked == REF, "a sticker toggled as a screen reader toggles it was not sent");
	}
	/* THE RECENT TAB, sec 1317: what was sent lately, newest first, each as
	 * its pack's tab shows it; one of a pack not kept here left out; chosen
	 * as its tab's would be; pack numbers not moved by it. */
	CHECK(v.recent() == QStringList({ "thumbs up", "waving" }), "the stickers sent lately were not a Recent tab");
	picked.clear();
	CHECK(v.pick_recent(1) && picked == REF, "a recent sticker was not chosen as its pack's would be");
	/* A STICKER WITH A BOX ASKS FOR ITS WORDS, sec 1296: given, they ride
	 * its reference; called off, nothing is chosen; left empty, it goes as
	 * drawn. */
	{
		QString asked_about, give = QStringLiteral("hi there");
		int asked_limit = 0;
		bool go = true;

		v.on_words([&](const QString &description, int limit, QString *words) {
			asked_about = description;
			asked_limit = limit;
			*words = give;
			return go;
		});
		picked.clear();
		CHECK(v.pick(0, 1) && asked_about == "thumbs up" && asked_limit == 12 && picked == REF8 ":hi%20there",
		      "a sticker with a box did not ask for its words, or did not send them");
		picked.clear();
		CHECK(v.pick(0, 0) && picked == REF && asked_limit == 12, "a sticker with no box asked for words");
		go = false;
		picked.clear();
		CHECK(!v.pick(0, 1) && picked.isEmpty(), "a choice called off at its words was sent");
		go = true;
		give.clear();
		CHECK(v.pick(0, 1) && picked == REF8, "a sticker left without words was not sent as drawn");
	}

	/* A STICKER'S SOUND WHEN TOUCHED, sec 1314: heard where its pack gives
	 * it one, written once across two touches; one without, nothing; no
	 * player, nothing fetched. */
	{
		QStringList played;

		CHECK(!v.touch(0, 0) && !sound_asked, "a sound was fetched with no player to hand it to");
		v.on_sound([&played](const QString &path) { played << path; });
		CHECK(v.touch(0, 0) && v.touch(0, 0) && played.size() == 2 && played[0] == played[1]
		              && QFile(played[0]).size() == 4 && sound_asked == 1,
		      "a sticker with a sound was not played, or was written again");
		CHECK(!v.touch(0, 1) && played.size() == 2 && !silent_asked,
		      "a sticker with no sound was asked for one, or played one");
	}
	/* A TOUCHED STICKER THAT MOVES PLAYS, sec 1322; a still does not. The
	 * sound check's player held a list gone with its block. */
	v.on_sound(nullptr);
	(void)v.touch(0, 0);
	CHECK(!v.playing(), "a still sticker touched played");
#ifdef FZN_THORVG_ON
	(void)v.touch(0, 2);
	CHECK(v.playing(), "a touched Lottie sticker did not play");
	v.refresh();
	CHECK(!v.playing(), "a sticker played on after its tab was built again");
#endif

	CHECK(!v.keep_files({ "/tmp/fzn-good.fzs", "/tmp/fzn-bad.fzs" })
	              && v.status().startsWith("Kept 1 of 2.") && v.status().contains("fzn-bad.fzs: not a sticker pack"),
	      "keeping two packs, one refused, was not said with why");

	/* FINDING A STICKER, sec 1298: found by its words, shown as its tab
	 * shows it, chosen with its box asking for words; none said; cleared,
	 * the tabs again. */
	{
		const int asked_art = art_asked;

		v.set_find(QStringLiteral("thumbs"));
		CHECK(v.found() == QStringList({ "thumbs up" }) && art_asked == asked_art,
		      "a sticker was not found by its words, or its art was asked again");
		v.on_words([](const QString &, int, QString *words) {
			*words = QStringLiteral("hi there");
			return true;
		});
		picked.clear();
		CHECK(v.pick_found(0) && picked == REF8 ":hi%20there", "a sticker found was not chosen as its tab's would be");
		v.set_find(QStringLiteral("zebra"));
		CHECK(v.found().isEmpty() && v.status() == "No sticker kept here fits that.", "finding none was not said");
		v.set_find(QString());
		CHECK(v.found().isEmpty(), "clearing the search left stickers found");
	}
	CHECK(!v.forget(4) && !let_go, "a pack that is not there was let go");
	CHECK(v.forget(0) && let_go == 1 && v.status() == "Let waves go.", "the pack on show was not let go, and said");

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui sticker_picker_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui sticker_picker_view_test: all %d checks passed\n", checks);
	return 0;
}
