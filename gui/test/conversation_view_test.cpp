/*
 * conversation_view_test -- a conversation with one contact on a widget,
 * sec 1126, against a scripted node behind the ask callback: three lines
 * shown oldest first with who wrote each and when, a line holding an escape
 * shown in caret form, the read position set at the newest line that came
 * in, a line sent and the typed text cleared, a refused send keeping it,
 * a sticker line drawn from the art the node renders, asked once, and its
 * pack kept (sec 1145), and a node that does not answer.
 */

#include "../conversation_view.h"
#include "../../local/rpc_types.h"
#include "../notice_line.h"

#include <QApplication>
#include <QFile>
#include <QImage>
#include <QPushButton>
#include <QRect>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int checks, failures;

#define CHECK(cond, what)                                                                           \
	do {                                                                                        \
		checks++;                                                                           \
		if (!(cond)) {                                                                      \
			failures++;                                                                 \
			fprintf(stderr, "  FAIL conversation_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                                   \
	} while (0)

#define BOB "b0b0000000000000000000000000000000000000000000000000000000000001"
#define ID1 "11111111111111111111111111111111"
#define ID2 "22222222222222222222222222222222"
#define ID3 "33333333333333333333333333333333"
#define ID4 "44444444444444444444444444444444"
#define GROUP_ID "f0f0000000000000000000000000000000000000000000000000000000000009"
/* 2023-11-14 23:46:40 UTC. */
#define NOW 1700005600u

static int silent, refuse_send;
static char last_set[200], last_add[200], last_file[600];
static int file_partial;
/* The file dan sent: its root is 64 hex digits of the number 3. */
#define FILE_ROOT "0000000000000000000000000000000000000000000000000000000000000003"
#define FILE_KEY "0000000000000000000000000000000000000000000000000000000000000004"

/* DAN'S STICKER'S PACK, as a node reads it: root, key, length 1000. */
#define DAN_PACK                                                                                         \
	"0000000000000000000000000000000000000000000000000000000000000001"                               \
	"0000000000000000000000000000000000000000000000000000000000000002"                               \
	"00000000000003e8"
static int art_asked, boxes_asked, sounds_written, silent_asked, popups_asked;
static char last_keep[200];

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	/* THE MAIN RENDITION, which the log draws at 128 px (sec 1295). */
	static const char DRAW[] = "get sticker " DAN_PACK " 7 main ";
	(void)ctx;
	if (silent)
		return 0;
	/* THE STICKER'S ART: a PNG written where asked. */
	if (!strncmp(line, DRAW, sizeof DRAW - 1)) {
		QImage one(1, 1, QImage::Format_ARGB32);
		art_asked++;
		one.fill(Qt::red);
		if (!one.save(QString::fromUtf8(line + sizeof DRAW - 1), "PNG"))
			return (size_t)snprintf(reply, cap, "error could not write\n");
		return (size_t)snprintf(reply, cap, "ok 4 1 1\n");
	}
	/* THE PACK'S STICKERS AND THEIR BOXES, read once for a sticker sent
	 * with words (sec 1295): sticker 7, a message sticker with a box. */
	if (!strncmp(line, "list sticker " DAN_PACK, 13 + 144)) {
		boxes_asked++;
		return (size_t)snprintf(reply, cap, "ok 4 0 7,5,0,waving,20,8,8,48,16,FFFFFFC0,000000FF,0,128,128 "
		                                    "9,2,5,dancing,0,0,0,0,0,00000000,00000000,0,128,128 "
		                                    "11,3,0,fireworks,0,0,0,0,0,00000000,00000000,0,128,128 "
		                                    "12,4,0,confetti,0,0,0,0,0,00000000,00000000,0,128,128\n");
	}
	/* STICKER 7 IS NO POP-UP ONE, though a node draws its nearest art for
	 * any role asked: so a log that popped it up would show it (sec 1302). */
	if (!strncmp(line, "get sticker " DAN_PACK " 7 popup ", 12 + 144 + 9)) {
		QImage one(4, 4, QImage::Format_ARGB32);
		one.fill(Qt::red);
		return one.save(QString::fromUtf8(line + 12 + 144 + 9), "PNG") ? (size_t)snprintf(reply, cap, "ok 4 4 4\n")
		                                                             : (size_t)snprintf(reply, cap, "error no\n");
	}
	/* STICKER 11 IS A POP-UP ONE: its pop-up art a PNG (sec 1302). */
	if (!strncmp(line, "get sticker " DAN_PACK " 11 popup ", 12 + 144 + 10)) {
		QImage one(4, 4, QImage::Format_ARGB32);
		one.fill(Qt::green);
		popups_asked++;
		return one.save(QString::fromUtf8(line + 12 + 144 + 10), "PNG") ? (size_t)snprintf(reply, cap, "ok 4 4 4\n")
		                                                              : (size_t)snprintf(reply, cap, "error no\n");
	}
	/* STICKER 12 IS AN EFFECT ONE: its art a blue PNG (sec 1315). */
	if (!strncmp(line, "get sticker " DAN_PACK " 12 popup ", 12 + 144 + 10)) {
		QImage one(4, 4, QImage::Format_ARGB32);
		one.fill(Qt::blue);
		return one.save(QString::fromUtf8(line + 12 + 144 + 10), "PNG") ? (size_t)snprintf(reply, cap, "ok 4 4 4\n")
		                                                              : (size_t)snprintf(reply, cap, "error no\n");
	}
	if (!strcmp(line, "list message jon 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 0 3 0 " BOB ",jon," ID3 ",in,-,1700006000000,1700006000000,1,"
		                        "fzn:sticker/%064d/%064d/1000/12%%20confetti " BOB ",jon," ID2
		                        ",in,-,1700005900000,1700005900000,1,"
		                        "fzn:sticker/%064d/%064d/1000/11%%20fireworks " BOB ",jon," ID1
		                        ",in,-,1700005800000,1700005800000,1,"
		                        "fzn:sticker/%064d/%064d/1000/7%%20waving\n",
		                        1, 2, 1, 2, 1, 2);
	/* STICKER 7 HAS NO SOUND, and is never asked for one (sec 1301). */
	if (!strncmp(line, "get sticker " DAN_PACK " 7 sound ", 12 + 144 + 9)) {
		silent_asked++;
		return (size_t)snprintf(reply, cap, "error that sticker has no sound\n");
	}
	/* STICKER 9'S SOUND, flagged in its row (sec 1301). */
	if (!strncmp(line, "get sticker " DAN_PACK " 9 sound ", 12 + 144 + 9)) {
		FILE *f = fopen(line + 12 + 144 + 9, "wbx");
		sounds_written++;
		if (!f || fwrite("OggS!", 1, 5, f) != 5) {
			if (f)
				fclose(f);
			return (size_t)snprintf(reply, cap, "error could not write\n");
		}
		fclose(f);
		return (size_t)snprintf(reply, cap, "ok 5\n");
	}
	/* KIM SENT DAN'S STICKER 13, AN APNG of two frames, red then green (sec
	 * 1322): its art those bytes, built by hand. */
	if (!strncmp(line, "get sticker " DAN_PACK " 13 main ", 12 + 144 + 9)) {
		static const char APNG[] =
		        "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x00\x01\x00\x00"
		        "\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x08\x61\x63\x54\x4c\x00\x00\x00"
		        "\x02\x00\x00\x00\x00\xf3\x8d\x93\x70\x00\x00\x00\x1a\x66\x63\x54\x4c\x00\x00\x00\x00\x00"
		        "\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x0a\x00\x00\x5a"
		        "\x7f\x30\xd0\x00\x00\x00\x0d\x49\x44\x41\x54\x78\x9c\x63\xf8\xcf\xc0\xf0\x1f\x00\x05\x00"
		        "\x01\xff\x89\x99\x3d\x1d\x00\x00\x00\x1a\x66\x63\x54\x4c\x00\x00\x00\x01\x00\x00\x00\x01"
		        "\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x0a\x00\x00\xc1\x0c\xda\x04"
		        "\x00\x00\x00\x11\x66\x64\x41\x54\x00\x00\x00\x02\x78\x9c\x63\x60\xf8\xcf\xf0\x1f\x00\x04"
		        "\x01\x01\xff\x62\xe7\xe9\x9c\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82";
		FILE *f = fopen(line + 12 + 144 + 9, "wbx");
		if (!f || fwrite(APNG, 1, sizeof APNG - 1, f) != sizeof APNG - 1) {
			if (f)
				fclose(f);
			return (size_t)snprintf(reply, cap, "error could not write\n");
		}
		fclose(f);
		return (size_t)snprintf(reply, cap, "ok 2 1 1\n");
	}
	if (!strcmp(line, "list message kim 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 0 1 0 " BOB ",kim," ID1 ",in,-,1700005800000,1700005800000,1,"
		                        "fzn:sticker/%064d/%064d/1000/13%%20blinking\n",
		                        1, 2);
	/* IKE SENT DAN'S STICKER 9, A LOTTIE ONE, sec 1300: its art the JSON. */
	if (!strncmp(line, "get sticker " DAN_PACK " 9 main ", 12 + 144 + 8)) {
		static const char LOTTIE[] =
		        "{\"v\":\"5.7.4\",\"fr\":30,\"ip\":0,\"op\":30,\"w\":100,\"h\":100,\"nm\":\"t\",\"ddd\":0,"
		        "\"assets\":[],\"layers\":[{\"ddd\":0,\"ind\":1,\"ty\":4,\"nm\":\"r\",\"sr\":1,"
		        "\"ks\":{\"o\":{\"a\":0,\"k\":100},\"r\":{\"a\":0,\"k\":0},\"p\":{\"a\":0,\"k\":[50,50,0]},"
		        "\"a\":{\"a\":0,\"k\":[0,0,0]},\"s\":{\"a\":0,\"k\":[100,100,100]}},\"ao\":0,"
		        "\"shapes\":[{\"ty\":\"rc\",\"d\":1,\"s\":{\"a\":0,\"k\":[80,80]},\"p\":{\"a\":0,\"k\":[0,0]},"
		        "\"r\":{\"a\":0,\"k\":0},\"nm\":\"rect\"},{\"ty\":\"fl\",\"c\":{\"a\":0,\"k\":[1,0,0,1]},"
		        "\"o\":{\"a\":0,\"k\":100},\"r\":1,\"nm\":\"fill\"}],\"ip\":0,\"op\":30,\"st\":0,\"bm\":0}]}";
		FILE *f = fopen(line + 12 + 144 + 8, "wbx");
		if (!f || fwrite(LOTTIE, 1, sizeof LOTTIE - 1, f) != sizeof LOTTIE - 1) {
			if (f)
				fclose(f);
			return (size_t)snprintf(reply, cap, "error could not write\n");
		}
		fclose(f);
		return (size_t)snprintf(reply, cap, "ok 1 100 100\n");
	}
	if (!strcmp(line, "list message ike 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 0 2 0 " BOB ",ike," ID2 ",in,-,1700005900000,1700005900000,1,"
		                        "fzn:sticker/%064d/%064d/1000/9%%20dancing " BOB ",ike," ID1
		                        ",in,-,1700005800000,1700005800000,1,"
		                        "fzn:sticker/%064d/%064d/1000/7%%20waving\n",
		                        1, 2, 1, 2);
	/* GUS SENT DAN'S STICKER WITH WORDS: "hi there" in its box. */
	if (!strcmp(line, "list message gus 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 0 2 0 " BOB ",gus," ID2 ",in,-,1700005900000,1700005900000,1,"
		                        "fzn:sticker/%064d/%064d/1000/7:bye%%2520now%%20waving " BOB ",gus," ID1
		                        ",in,-,1700005800000,1700005800000,1,"
		                        "fzn:sticker/%064d/%064d/1000/7:hi%%2520there%%20waving\n",
		                        1, 2, 1, 2);
	/* A STICKER THAT ANSWERS "where shall we eat", sec 1321: asked with the
	 * line answered as its context, escaped, before a word is typed. */
	if (!strcmp(line, "list sticker answer where%20shall%20we%20eat "))
		return (size_t)snprintf(reply, cap, "ok 1 0 %064d,9,200,eating\n", 1);
	/* A KEPT STICKER FOR "see you", sec 1272; nothing for anything else. */
	if (!strcmp(line, "list sticker match see you"))
		return (size_t)snprintf(reply, cap, "ok 1 0 %064d,7,250,waving\n", 1);
	if (!strncmp(line, "list sticker match ", 19))
		return (size_t)snprintf(reply, cap, "ok 0 0\n");
	{
		char ask_ref[96], ask_draw[96];
		snprintf(ask_ref, sizeof ask_ref, "get sticker %064d 7", 1);
		snprintf(ask_draw, sizeof ask_draw, "get sticker %064d 7 thumb ", 1);
		if (!strcmp(line, ask_ref))
			return (size_t)snprintf(reply, cap, "ok fzn:sticker/%064d/%064d/1000/7 waving\n", 1, 2);
		if (!strncmp(line, ask_draw, strlen(ask_draw))) {
			QImage one(1, 1, QImage::Format_ARGB32);
			one.fill(Qt::blue);
			return one.save(QString::fromUtf8(line + strlen(ask_draw)), "PNG")
			               ? (size_t)snprintf(reply, cap, "ok 4 1 1\n")
			               : (size_t)snprintf(reply, cap, "error could not write\n");
		}
	}
	if (!strcmp(line, "add sticker " DAN_PACK)) {
		snprintf(last_keep, sizeof last_keep, "%s", line);
		return (size_t)snprintf(reply, cap, "ok %064d\n", 5);
	}
	/* NEWEST FIRST, as the node lists them: this user's "ok" at 23:52,
	 * bob's escape at 23:51, this user's line at 23:50, and bob's hello the
	 * day before. */
	if (!strcmp(line, "list message bob 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 0 4 0 " BOB ",bob," ID4 ",out,-,1700005960000,"
		                        "1700005960000,1,ok " BOB ",bob," ID3 ",in,read,1700005900000,1700005900000,1,"
		                        "see%%20you%%1b[2J " BOB ",bob," ID2 ",out,delivered,1700005800000,"
		                        "1700005800000,1,on%%20my%%20way " BOB ",bob," ID1 ",in,read,"
		                        "1699900000000,1699900000000,1,hello\n");
	/* BOB'S CALLS, newest first (sec 1255): this user's video call to him
	 * at 23:53, 4:12 long, and one from him at 23:50 nobody answered. */
	if (!strcmp(line, "list call history bob"))
		return (size_t)snprintf(reply, cap, "ok 2 b1b2b3b4b5b6b7b8,out,3,answered,1700005990,252 "
		                                    "a1a2a3a4a5a6a7a8,in,1,missed,1700005850,0\n");
	/* FAY READ THIS USER'S LINE (sec 1269). */
	if (!strcmp(line, "list message fay 0"))
		return (size_t)snprintf(reply, cap, "ok 0 1 0 " BOB ",fay," ID1 ",out,read,1700005800000,1700005800000,1,"
		                                    "on%%20my%%20way\n");
	/* GIL ASKED, THIS USER REPLIED, AND GIL LIKED THE REPLY (sec 1282). */
	if (!strcmp(line, "list message gil 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 0 3 0 " BOB ",gil," ID3 ",in,-,1700005900000,1700005900000,1,"
		                        "fzn:react/" ID2 "%%20\xf0\x9f\x91\x8d " BOB ",gil," ID2 ",out,delivered,"
		                        "1700005800000,1700005800000,1,fzn:reply/" ID1 "%%20the%%20usual%%20place " BOB
		                        ",gil," ID1 ",in,read,1700005700000,1700005700000,1,where%%20shall%%20we%%20eat\n");
	/* HAL TOOK A LINE BACK, AND THIS USER SENT ONE 100 s AGO (sec 1284),
	 * with unsend on here. */
	if (!strcmp(line, "list message hal 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 0 2 0 " BOB ",hal," ID2 ",out,delivered,1700005500000,1700005500000,1,soon "
		                        BOB ",hal," ID1 ",in,unsent,1700005400000,1700005400000,0,\n");
	if (!strcmp(line, "get schema message/unsend"))
		return (size_t)snprintf(reply, cap, "ok message/unsend,flag,estate+host,0,0,off,,safe-lower,x\n");
	if (!strcmp(line, "get setting here message/unsend"))
		return (size_t)snprintf(reply, cap, "ok host 0 on\n");
	if (!strncmp(line, "remove message hal ", 19)) {
		snprintf(last_add, sizeof last_add, "%s", line);
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	/* EVE AND A QUIET GROUP: nothing said yet (sec 1263). */
	if (!strcmp(line, "list message eve 0") || !strcmp(line, "list message @quiet 0"))
		return (size_t)snprintf(reply, cap, "ok 0 0 0\n");
	/* THE GROUP: carol's line, then this user's, then a member with no
	 * contact here, named by the first bytes of their key. */
	if (!strcmp(line, "list message @family 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 0 3 0 " BOB ",@family:c0c0c0c0c0c0c0c0," ID3 ",in,read,1700005900000,"
		                        "1700005900000,1,who%%20is%%20this " BOB ",@family," ID2 ",out,delivered,"
		                        "1700005800000,1700005800000,1,dinner%%3f " BOB ",@family:carol," ID1
		                        ",in,read,1700005700000,1700005700000,1,hi%%20all\n");
	/* DAN SENT A FILE AND A STICKER, each riding a line's text. */
	if (!strcmp(line, "list message dan 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 0 2 0 " BOB ",dan," ID2 ",in,-,1700005800000,1700005800000,1,"
		                        "fzn:sticker/%064d/%064d/1000/7%%20waving " BOB ",dan," ID1 ",in,-,"
		                        "1700005700000,1700005700000,1,fzn:file/%064d/%064d/2500000%%20holiday.jpg\n",
		                        1, 2, 3, 4);
	/* THE FILE, WHOLE HERE once asked for. */
	if (!strcmp(line, "get file " FILE_ROOT))
		return (size_t)snprintf(reply, cap, file_partial ? "ok 10 4 2500000 partial private 0\n"
		                                                 : "ok 10 10 2500000 whole private 0\n");
	if (!strncmp(line, "fetch file ", 11) || !strncmp(line, "get file ", 9)) {
		snprintf(last_file, sizeof last_file, "%s", line);
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	/* A FILE PUT HERE, PRIVATE, AND SENT AS A LINE, sec 1140. */
	if (!strcmp(line, "put file /tmp/fzn-send-test.jpg")) {
		snprintf(last_file, sizeof last_file, "%s", line);
		return (size_t)snprintf(reply, cap, "ok " FILE_ROOT FILE_KEY "0000000000001000 private\n");
	}
	if (!strcmp(line, "list group 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 family,3," GROUP_ID ",1\n");
	if (!strncmp(line, "set ", 4))
		snprintf(last_set, sizeof last_set, "%s", line);
	if (!strncmp(line, "add ", 4)) {
		snprintf(last_add, sizeof last_add, "%s", line);
		if (refuse_send)
			return (size_t)snprintf(reply, cap, "denied bob is not reachable\n");
	}
	return (size_t)snprintf(reply, cap, "ok\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	/* THE TIMES SHOWN ARE THE READER'S OWN: pinned here to UTC. */
	setenv("TZ", "UTC", 1);
	tzset();
	QApplication app(argc, argv);
	fzn_conversation_view v(node, nullptr);

	v.set_now(NOW);
	CHECK(v.open("bob")
	              && v.lines() == QStringList({ "2023-11-13 18:26 bob: hello", "23:50 You: on my way (delivered)",
	                                            "23:50 Missed call from bob", "23:51 bob: see you^[[2J",
	                                            "23:52 You: ok (sending)", "23:53 You called bob, 4:12 (video)" }),
	      "the lines were not shown oldest first, with who and when, the escape in caret form, and the calls "
	      "among them by when each was rung (sec 1255)");
	v.select_line(2);
	CHECK(v.offered().isEmpty(), "a call among the lines offered something, as a line might");
	v.select_line(-1);
	CHECK(!strcmp(last_set, "set message bob read " ID3),
	      "the read position was not set at the newest line that came in, past this user's own");

	/* BUBBLES ON A PHONE, sec 1241: bob's at the left, this user's at the
	 * right, each within three quarters of the width; a desktop's width the
	 * log again, its lines as they were. */
	v.show();
	v.resize(320, 600);
	app.processEvents();
	{
		const QRect his = v.bubble_rect(0), mine = v.bubble_rect(1);

		CHECK(v.bubbles() && his.isValid() && mine.isValid() && his.left() < 20 && mine.right() > 240
		              && mine.width() <= 320 * 3 / 4 + 1 && his.right() < mine.right(),
		      "on a phone the lines were not bubbles, bob's at the left and this user's at the right");
		/* A FINGER'S TARGETS, AND THE LINE BEING WRITTEN LAST, sec 1253:
		 * Send at least 48 tall, at the bottom, where the keyboard's top
		 * edge will be. */
		QPushButton *send = nullptr;
		for (QPushButton *b : v.findChildren<QPushButton *>())
			if (b->text() == "Send")
				send = b;
		CHECK(send && send->minimumHeight() == FZN_NOTICE_LINE_TOUCH_PX
		              && send->geometry().bottom() >= v.height() - FZN_NOTICE_LINE_TOUCH_PX - 16,
		      "on a phone Send was not a finger's height, or not at the bottom above the keyboard");
	}
	v.resize(800, 600);
	app.processEvents();
	CHECK(!v.bubbles() && !v.bubble_rect(1).isValid() && v.lines().value(4) == "23:52 You: ok (sending)",
	      "a desktop's width did not show the log, its lines as they were");
	v.hide();

	v.set_text("hi there");
	CHECK(v.send() && strstr(last_add, "message bob") && strstr(last_add, "hi") && v.text().isEmpty(),
	      "a line was not sent to bob, or the typed text stayed");

	refuse_send = 1;
	v.set_text("still here");
	CHECK(!v.send() && v.text() == "still here" && v.status() == "bob is not reachable",
	      "a refused line lost what was typed, or the node's words");
	refuse_send = 0;

	v.set_text("   ");
	last_add[0] = '\0';
	CHECK(!v.send() && !last_add[0], "an empty line was sent");

	/* THE STICKER PICKER IN THE CONVERSATION, sec 1243: opened by the
	 * button beside Send, a sticker chosen sent as a line -- what was being
	 * written kept -- and the picker closed. */
	v.show();
	v.set_text("half a thought");
	v.show_stickers(true);
	CHECK(v.stickers_shown(), "the sticker picker did not open in the conversation");
	last_add[0] = '\0';
	CHECK(v.send_sticker("fzn:sticker/1111/2222/1000/7 waving") && strstr(last_add, "message bob")
	              && strstr(last_add, "fzn:sticker/1111") && !v.stickers_shown() && v.text() == "half a thought",
	      "a sticker chosen was not sent as a line, or the words being written were lost");
	v.set_text("");
	/* STICKERS FOR WHAT IS TYPED, sec 1272: "see you" offers the kept
	 * waving sticker, drawn; chosen, it is sent in place of the words;
	 * a line nothing fits shows no row. */
	v.set_text("see you");
	v.suggest_now();
	CHECK(v.suggested() == QStringList({ "waving" }), "the kept sticker was not offered for what was typed");
	last_add[0] = '\0';
	CHECK(v.send_suggested(0) && strstr(last_add, "fzn:sticker/0000") && v.text().isEmpty()
	              && v.suggested().isEmpty(),
	      "the sticker offered was not sent in place of the words");
	v.set_text("the weather");
	v.suggest_now();
	CHECK(v.suggested().isEmpty() && !v.send_suggested(0), "a line nothing fits offered a sticker");
	v.set_text("");
	v.hide();

	/* A FILE AND A STICKER said as what they are, sec 1129. */
	fzn_conversation_view d(node, nullptr);
	d.set_now(NOW);
	CHECK(d.open("dan")
	              && d.lines() == QStringList({ "23:48 dan: a file: holiday.jpg, 2.4 MB",
	                                            "23:50 dan: a sticker: waving" }),
	      "a file or a sticker was shown as its reference");

	/* THE FILE, GOT AND SAVED, sec 1130: asked for by its whole reference,
	 * saved where the person says; a sticker's line offers neither. */
	d.select_line(1);
	last_file[0] = '\0';
	CHECK(!d.fetch() && !last_file[0], "a sticker's line asked for a file");
	d.select_line(0);
	CHECK(d.fetch() && !strcmp(last_file, "fetch file " FILE_ROOT FILE_KEY "00000000002625a0")
	              && d.status().contains("2.4 MB"),
	      "the file was not asked for by its whole reference, or its size not said");
	CHECK(d.save_to("/tmp/holiday.jpg")
	              && !strcmp(last_file, "get file " FILE_ROOT FILE_KEY "00000000002625a0 /tmp/holiday.jpg")
	              && d.status() == "Saved 2.4 MB to /tmp/holiday.jpg.",
	      "the file was not saved where asked");

	/* OPENED WHERE IT IS, sec 1242: not here whole, asked for; whole,
	 * saved; a sticker's line, nothing. */
	file_partial = 1;
	last_file[0] = '\0';
	CHECK(d.open_line(0, "/tmp/holiday.jpg") && !strncmp(last_file, "fetch file " FILE_ROOT, 11 + 64),
	      "a file not here whole was not asked for when its line was opened");
	file_partial = 0;
	CHECK(d.open_line(0, "/tmp/holiday.jpg") && !strncmp(last_file, "get file " FILE_ROOT, 9 + 64)
	              && strstr(last_file, " /tmp/holiday.jpg"),
	      "a file here whole was not saved when its line was opened");
	CHECK(!d.open_line(1, "/tmp/x"), "a sticker's line was opened as a file");

	/* THE STICKER DRAWN, ASKED ONCE, AND ITS PACK KEPT, sec 1145. */
	CHECK(d.drawn(1) && !d.drawn(0), "a sticker line was not drawn, or a file line was");
	CHECK(d.refresh() && d.drawn(1) && art_asked == 1, "a sticker drawn once was asked for again");
	/* THE CHOSEN STICKER PLAYS, sec 1300, where it is a Lottie one: chosen,
	 * it plays; another chosen, it rests; a raster one never plays. */
#ifdef FZN_THORVG_ON
	{
		fzn_conversation_view h(node, nullptr);

		h.open(QStringLiteral("ike"));
		/* OLDEST FIRST: the raster sticker, then the Lottie one. */
		CHECK(h.drawn(1) && !h.playing(), "a Lottie sticker was not drawn, or played unchosen");
		h.select_line(1);
		CHECK(h.playing(), "the chosen Lottie sticker did not play");
		h.select_line(0);
		CHECK(!h.playing(), "a raster sticker chosen played, or the Lottie one did not rest");
	}
#endif
	/* AN APNG OF TWO FRAMES PLAYS when chosen, as a Lottie does (sec 1322);
	 * a still raster one, above, does not. */
	{
		fzn_conversation_view k(node, nullptr);

		k.open(QStringLiteral("kim"));
		CHECK(k.drawn(0) && !k.playing(), "an APNG sticker was not drawn, or played unchosen");
		k.select_line(0);
		CHECK(k.playing(), "the chosen APNG sticker did not play");
	}
	/* ITS SOUND, sec 1301: the sticker flagged with one hands it to the
	 * host's player, written once; one without, nothing. */
	{
		fzn_conversation_view h(node, nullptr);
		QStringList played;

		h.on_sound([&played](const QString &path) { played << path; });
		h.open(QStringLiteral("ike"));
		/* THE LINE A REFRESH CHOOSES PLAYS NOTHING: only a person's choice. */
		h.select_line(0);
		CHECK(played.isEmpty(), "a sound played without a person choosing its sticker");
		h.select_line(1);
		CHECK(played.size() == 1 && QFile::exists(played.value(0)) && sounds_written == 1,
		      "a sticker with a sound chosen did not hand it to the host's player");
		h.select_line(0);
		CHECK(played.size() == 1 && !silent_asked, "a sticker without a sound was asked for one, or played one");
		h.select_line(1);
		CHECK(played.size() == 2 && played.value(1) == played.value(0) && sounds_written == 1,
		      "a sound played again was written again");
	}
	/* A POP-UP STICKER, sec 1302: chosen, its pop-up art across the log,
	 * asked once; another line chosen takes it away. */
	{
		fzn_conversation_view j(node, nullptr);

		/* OLDEST FIRST: the waving sticker, then the fireworks. */
		j.open(QStringLiteral("jon"));
		j.select_line(0);
		CHECK(!j.popped(), "a sticker that is no pop-up one popped up");
		j.select_line(1);
		CHECK(j.popped() && popups_asked == 1, "a pop-up sticker chosen did not pop up");
		j.select_line(0);
		CHECK(!j.popped(), "a pop-up stayed when another line was chosen");
		j.select_line(1);
		CHECK(j.popped() && popups_asked == 1, "a pop-up's art was asked for again");
		/* AN EFFECT STICKER, sec 1315: behind the lines, not over them --
		 * no pop-up, its art painted on the log's background. */
		j.resize(400, 600);
		j.select_line(2);
		CHECK(j.effected() && !j.popped(), "an effect sticker chosen did not play behind the lines");
		const QImage under = j.grab().toImage();
		bool blue = false;
		for (int y = 0; y < under.height() && !blue; y += 2)
			for (int x = 0; x < under.width() && !blue; x += 2)
				blue = under.pixelColor(x, y) == QColor(Qt::blue);
		CHECK(blue, "an effect sticker's art was not painted");
		j.select_line(0);
		CHECK(!j.effected(), "an effect stayed when another line was chosen");
	}
	boxes_asked = 0;
	/* A STICKER WITH WORDS, sec 1295: drawn, its pack's boxes read once. */
	{
		fzn_conversation_view e(node, nullptr);

		e.open(QStringLiteral("gus"));
		CHECK(e.drawn(0) && e.drawn(1) && boxes_asked == 1,
		      "a sticker sent twice with other words was not drawn twice from one reading of its pack");
		CHECK(e.refresh() && e.drawn(0) && e.drawn(1) && boxes_asked == 1, "a pack's boxes were read again");
	}
	d.select_line(0);
	CHECK(!d.keep_pack() && !last_keep[0], "a file's line kept a pack");
	d.select_line(1);
	CHECK(d.keep_pack() && !strcmp(last_keep, "add sticker " DAN_PACK)
	              && d.status() == "Kept the pack with your stickers.",
	      "a sticker that came in did not keep its pack by its whole reference");

	/* ONE NOTICE, ITS ONE ACTION, sec 1253: the file's line offers what fits
	 * it -- got while not here whole, saved once it is -- and the sticker's
	 * its pack kept; taking the offer does it; a refresh keeps the line
	 * chosen, its offer, and the answer to the person's act; and no more
	 * than one button stands for any of it. */
	file_partial = 1;
	d.select_line(-1);
	d.select_line(0);
	CHECK(d.offered() == "Get the file" && d.status().contains("holiday.jpg") && d.status().contains("2.4 MB"),
	      "a file's line not here whole did not offer to get it, named and sized");
	last_file[0] = '\0';
	CHECK(d.take_offer() && !strncmp(last_file, "fetch file " FILE_ROOT, 11 + 64)
	              && d.status().startsWith("Asked for the file") && d.offered().isEmpty(),
	      "taking the offer did not get the file, or the offer stood after it");
	last_file[0] = '\0';
	CHECK(!d.take_offer() && !last_file[0], "the offer could be taken again once its act was done");
	CHECK(d.refresh() && d.status().startsWith("Asked for the file"),
	      "a refresh dropped the answer to the person's act");
	file_partial = 0;
	d.select_line(1);
	CHECK(d.offered() == "Keep this sticker pack", "a sticker that came in did not offer its pack");
	CHECK(d.refresh() && d.offered() == "Keep this sticker pack" && !d.status().startsWith("No messages"),
	      "a refresh dropped the line chosen, and with it its offer");
	d.select_line(0);
	CHECK(d.offered() == "Save the file", "a file's line here whole did not offer to save it");
	{
		int standing = 0;
		for (QPushButton *b : d.findChildren<QPushButton *>())
			if (b->text() == "Get the file" || b->text() == "Save the file" || b->text() == "Keep this sticker pack")
				standing += !b->isHidden() || b->isVisibleTo(&d);
		CHECK(standing <= 1, "more than the one offer's button stood for the chosen line");
	}

	/* OLDER LINES AND A FILE SENT, sec 1140: four lines are not a full page,
	 * so there is nothing older to show; a file put private and attached. */
	CHECK(!d.show_older() || d.lines().size() == 2, "asking for older lines lost the ones shown");
	last_add[0] = '\0';
	CHECK(d.send_file("/tmp/fzn-send-test.jpg") && !strcmp(last_file, "put file /tmp/fzn-send-test.jpg")
	              && !strncmp(last_add, "add message dan out ", 20) && strstr(last_add, "attach " FILE_ROOT)
	              && strstr(last_add, "fzn-send-test.jpg") && d.status().startsWith("Sent fzn-send-test.jpg"),
	      "a file was not put here and sent to dan as a line");

	/* A GROUP, sec 1126: members named, this user's own as You, the read
	 * position kept by the group's id, a line sent to the group. */
	fzn_conversation_view g(node, nullptr);
	g.set_now(NOW);
	last_set[0] = '\0';
	CHECK(g.open("@family")
	              && g.lines() == QStringList({ "23:48 carol: hi all", "23:50 You: dinner? (delivered)",
	                                            "23:51 c0c0c0c0c0c0c0c0: who is this" }),
	      "the group's lines were not shown with each member named");
	CHECK(!strcmp(last_set, "set message @" GROUP_ID " read " ID3),
	      "the group's read position was not kept by its id");
	g.set_text("on my way");
	CHECK(g.send() && strstr(last_add, "message @family"), "a line was not sent to the group");

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	/* NOTHING SAID YET, said kindly, sec 1263 (fuzzypickles' sec 286): a
	 * blank page read as one still loading. */
	{
		fzn_conversation_view e(node, nullptr);

		silent = 0;
		e.set_now(NOW);
		CHECK(e.open("eve") && e.lines().isEmpty() && e.status() == "No messages with eve yet. Say hello!",
		      "an empty conversation was not said as one, with whom");
		CHECK(e.open("@quiet") && e.status() == "No messages in quiet yet.",
		      "an empty group was not said as one, by its name");
		CHECK(e.open("fay") && e.lines().value(0) == "23:50 You: on my way (read)",
		      "a line the contact said they read was not shown read");
		/* A REPLY AND A REACTION, sec 1282: the reply quotes the line it
		 * answers, the reaction is folded under the line it names and is
		 * no line of its own; a line chosen offers a reply, and the next
		 * line sent answers it. */
		CHECK(e.open("gil") && e.lines().size() == 2 && e.lines().value(0).endsWith("gil: where shall we eat")
		              && e.lines().value(1).endsWith("You: (in reply to \"where shall we eat\") the usual place "
		                                             "[\xf0\x9f\x91\x8d 1] (delivered)"),
		      "a reply did not quote its line, or a reaction was not folded under the line it names");
		e.select_line(0);
		CHECK(e.offered() == "Reply", "a line chosen did not offer a reply");
		e.reply_to(QByteArray::fromHex(ID1));
		CHECK(e.suggested() == QStringList({ "eating" }),
		      "a reply did not offer the stickers that answer its line before a word was typed");
		e.set_text("ok then");
		last_add[0] = '\0';
		CHECK(e.send() && strstr(last_add, "message gil") && strstr(last_add, "fzn:reply/" ID1)
		              && strstr(last_add, "ok") && e.replying().isEmpty(),
		      "the line sent in reply did not name the line it answers, or the reply did not end");
		e.set_text("plain");
		last_add[0] = '\0';
		CHECK(e.send() && !strstr(last_add, "fzn:reply/"), "a line after the reply was sent as one too");
		/* A FILE IN REPLY, sec 1510: sent naming the line it answers, and
		 * the reply ended, as a line in reply is. */
		e.reply_to(QByteArray::fromHex(ID1));
		last_add[0] = '\0';
		CHECK(e.send_file("/tmp/fzn-send-test.jpg") && strstr(last_add, "attach " FILE_ROOT)
		              && strstr(last_add, " reply " ID1) && e.replying().isEmpty(),
		      "a file sent while replying did not name the line it answers, or the reply did not end");
		last_add[0] = '\0';
		CHECK(e.react(QByteArray::fromHex(ID1), fzn_conversation_view::reactions().value(0))
		              && strstr(last_add, "message gil") && strstr(last_add, "fzn:react/" ID1 "%20\xf0\x9f\x91\x8d"),
		      "a reaction was not sent naming its line");
		last_add[0] = '\0';
		CHECK(e.react(QByteArray::fromHex(ID1), QString()) && strstr(last_add, "fzn:react/" ID1)
		              && !strstr(last_add, "fzn:react/" ID1 "%20"),
		      "a reaction taken back was not sent as the bare reference");
		CHECK(!e.react(QByteArray("short"), QStringLiteral("x")), "a reaction to no line was sent");
		/* TAKEN BACK, sec 1284: hal's line said so, with nothing after; this
		 * user's own line, under an hour old and unsend on, offers Unsend. */
		CHECK(e.open("hal") && e.lines().value(0) == "23:43 hal: This line was taken back."
		              && e.lines().value(1) == "23:45 You: soon (delivered)",
		      "a line taken back was not said so, or this user's was not shown");
		e.select_line(1);
		CHECK(e.offered() == "Unsend", "this user's line under an hour old did not offer Unsend");
		e.select_line(0);
		CHECK(e.offered() != "Unsend" && e.offered() != "Reply", "a line taken back offered something");
		last_add[0] = '\0';
		CHECK(e.unsend(QByteArray::fromHex(ID2)) && !strcmp(last_add, "remove message hal " ID2),
		      "Unsend did not ask the node to take the line back");
		/* A GROUP'S LINE READ BY THREE, sec 1273; one by one; one that
		 * came in says nothing. */
		CHECK(fzn_conversation_view::state_said(true, FZN_RPC_LINE_READ, 3) == " (read by 3)"
		              && fzn_conversation_view::state_said(true, FZN_RPC_LINE_READ, 1) == " (read by 1)"
		              && fzn_conversation_view::state_said(true, FZN_RPC_LINE_READ, 0) == " (read)"
		              && fzn_conversation_view::state_said(false, FZN_RPC_LINE_READ, 3).isEmpty(),
		      "a group line's readers were not said, or said for a line that came in");
	}

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui conversation_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui conversation_view_test: all %d checks passed\n", checks);
	return 0;
}
