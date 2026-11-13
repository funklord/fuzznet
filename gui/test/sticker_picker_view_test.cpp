/*
 * sticker_picker_view_test -- choosing a sticker and keeping packs, on a
 * widget, sec 1141, against a scripted node behind the ask callback: a kept
 * pack as a tab with two stickers, one drawn from the PNG the node renders
 * and one named by its description; choosing one hands the host its
 * reference; keeping two pack files, one refused, said as "Kept 1 of 2";
 * and a node that does not answer.
 */

#include "../sticker_picker_view.h"

#include <QApplication>
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
#define FILE_REF PACK "0000000000000000000000000000000000000000000000000000000000000002" \
	"0000000000001000"

static int silent;

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	static const char DRAW[] = "get sticker " PACK " 7 thumb ";
	(void)ctx;
	if (silent)
		return 0;
	if (!strcmp(line, "list sticker 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 " PACK ",4096,waves,1,user\n");
	if (!strcmp(line, "list sticker " PACK " 0"))
		return (size_t)snprintf(reply, cap, "ok 2 0 7,1,0,waving 8,1,0,thumbs%%20up\n");
	/* STICKER 7 IS DRAWN: a PNG written where asked. 8 HAS NO ART. */
	if (!strncmp(line, DRAW, sizeof DRAW - 1)) {
		QImage one(1, 1, QImage::Format_ARGB32);
		one.fill(Qt::red);
		if (!one.save(QString::fromUtf8(line + sizeof DRAW - 1), "PNG"))
			return (size_t)snprintf(reply, cap, "error could not write\n");
		return (size_t)snprintf(reply, cap, "ok 4 1 1\n");
	}
	if (!strncmp(line, "get sticker " PACK " 8 thumb ", 12 + 64 + 9))
		return (size_t)snprintf(reply, cap, "error no art\n");
	if (!strcmp(line, "get sticker " PACK " 7"))
		return (size_t)snprintf(reply, cap, "ok " REF "\n");
	/* KEEPING: the good pack put and kept, the other refused at put. */
	if (!strcmp(line, "put file /tmp/fzn-good.fzs"))
		return (size_t)snprintf(reply, cap, "ok " FILE_REF " private\n");
	if (!strcmp(line, "put file /tmp/fzn-bad.fzs"))
		return (size_t)snprintf(reply, cap, "error not a sticker pack\n");
	if (!strcmp(line, "add sticker " FILE_REF))
		return (size_t)snprintf(reply, cap, "ok " PACK "\n");
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_sticker_picker_view v(node, nullptr);
	QString picked;

	v.on_pick([&picked](const QString &ref) { picked = ref; });
	CHECK(v.refresh() && v.shown() == QStringList({ "waves", "  waving [drawn]", "  thumbs up" }),
	      "the pack was not a tab with its stickers, the drawn one drawn and the other named");
	CHECK(v.pick(0, 0) && picked == REF, "choosing a sticker did not hand over its reference");
	CHECK(!v.pick(0, 5), "a sticker that is not there was chosen");

	CHECK(!v.keep_files({ "/tmp/fzn-good.fzs", "/tmp/fzn-bad.fzs" })
	              && v.status().startsWith("Kept 1 of 2.") && v.status().contains("fzn-bad.fzs: not a sticker pack"),
	      "keeping two packs, one refused, was not said with why");

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
