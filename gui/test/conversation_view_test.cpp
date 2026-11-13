/*
 * conversation_view_test -- a conversation with one contact on a widget,
 * sec 1126, against a scripted node behind the ask callback: three lines
 * shown oldest first with who wrote each and when, a line holding an escape
 * shown in caret form, the read position set at the newest line that came
 * in, a line sent and the typed text cleared, a refused send keeping it,
 * and a node that does not answer.
 */

#include "../conversation_view.h"

#include <QApplication>

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
/* The file dan sent: its root is 64 hex digits of the number 3. */
#define FILE_ROOT "0000000000000000000000000000000000000000000000000000000000000003"
#define FILE_KEY "0000000000000000000000000000000000000000000000000000000000000004"

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
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
		return (size_t)snprintf(reply, cap, "ok 10 10 2500000 whole private 0\n");
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
	                                            "23:51 bob: see you^[[2J", "23:52 You: ok" }),
	      "the lines were not shown oldest first, with who and when, the escape in caret form");
	CHECK(!strcmp(last_set, "set message bob read " ID3),
	      "the read position was not set at the newest line that came in, past this user's own");

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

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui conversation_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui conversation_view_test: all %d checks passed\n", checks);
	return 0;
}
