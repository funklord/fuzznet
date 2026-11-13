/*
 * conversations_view_test -- every conversation as a list, on a widget, sec
 * 1138, against a scripted node behind the ask callback: contacts and groups
 * under two headings, newest first, each with its newest line, who wrote it
 * and when, and its unread count; one with nothing said yet; choosing one
 * opens it by name or as @GROUP; each row's menu (sec 1144): a contact's
 * calls and location share, said as shared or not, a group's members and
 * call to everyone it can name; and a node that does not answer.
 */

#include "../conversations_view.h"

#include <QApplication>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int checks, failures;

#define CHECK(cond, what)                                                                            \
	do {                                                                                         \
		checks++;                                                                            \
		if (!(cond)) {                                                                       \
			failures++;                                                                  \
			fprintf(stderr, "  FAIL conversations_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                                    \
	} while (0)

#define BOB "b0b0000000000000000000000000000000000000000000000000000000000001"
#define DAN "da40000000000000000000000000000000000000000000000000000000000003"
#define FAMILY "f0f0000000000000000000000000000000000000000000000000000000000009"
#define SELF "5e1f000000000000000000000000000000000000000000000000000000000000"
/* 2023-11-14 23:46:40 UTC. */
#define NOW 1700005600u

static int silent;
static char asked[512];

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	/* BOB'S LINE AT 23:50, CAROL'S FILE IN THE FAMILY AT 23:48, DAN NOTHING. */
	if (!strcmp(line, "list message newest"))
		return (size_t)snprintf(reply, cap,
		                        "ok 3 0 3 " BOB ",1700005800000,in,-,text,see%%20you%%20at%%208 " FAMILY
		                        ",1700005700000,in,carol,file,photo.jpg " DAN ",0,-,-,none,\n");
	if (!strcmp(line, "list message unread"))
		return (size_t)snprintf(reply, cap, "ok 3 0 3 " BOB ",2,0 " FAMILY ",0,0 " DAN ",0,0\n");
	if (!strcmp(line, "list contact 0"))
		return (size_t)snprintf(reply, cap, "ok 2 0 bob," BOB " dan," DAN "\n");
	if (!strncmp(line, "grant ", 6) || !strncmp(line, "revoke ", 7)) {
		strncat(asked, line, sizeof asked - strlen(asked) - 2);
		strcat(asked, "\n");
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	/* DAN SEES THIS USER'S LOCATION; BOB DOES NOT. */
	if (!strcmp(line, "list stream location granted 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 dan,0\n");
	if (!strcmp(line, "get identity"))
		return (size_t)snprintf(reply, cap, "ok " SELF " " SELF "\n");
	if (!strcmp(line, "get group family member 0"))
		return (size_t)snprintf(reply, cap, "ok 3 0 *" SELF " bob dan\n");
	if (!strcmp(line, "list group 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 family,3," FAMILY ",1\n");
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	setenv("TZ", "UTC", 1);
	tzset();
	QApplication app(argc, argv);
	fzn_conversations_view v(node, nullptr);
	QString opened;

	v.set_now(NOW);
	v.on_open([&opened](const QString &to) { opened = to; });
	CHECK(v.refresh()
	              && v.shown()
	                         == QStringList({ "Contacts", "  bob -- see you at 8 -- 23:50 (2 unread)",
	                                          "  dan -- nothing said yet", "Groups",
	                                          "  family -- carol: a file: photo.jpg -- 23:48" }),
	      "the conversations were not shown under their headings, newest first, with their lines");
	CHECK(v.open(0, 0) && opened == "bob", "a contact's conversation was not opened by its name");
	CHECK(v.open(1, 0) && opened == "@family", "a group's conversation was not opened as @NAME");
	CHECK(!v.open(1, 5), "a row that is not there was opened");

	/* EACH ROW'S MENU. */
	QString what, to;
	v.on_action([&what, &to](const QString &w, const QString &t) {
		what = w;
		to = t;
	});
	CHECK(v.actions(0, 0) == QStringList({ "Send a file...", "Call", "Video call", "Share my location" }),
	      "a contact's menu did not offer its calls and sharing");
	CHECK(v.actions(0, 1).last() == "Stop sharing my location",
	      "a contact who sees this user's location was not offered to stop");
	CHECK(v.act(0, 0, "Video call") && what == "video" && to == "bob", "a video call was not handed over");
	CHECK(v.act(0, 0, "Share my location") && !strcmp(asked, "grant stream location bob 0\n")
	              && v.status() == "bob can see your position now.",
	      "sharing location with a contact was not done and said");
	CHECK(v.act(0, 1, "Stop sharing my location") && strstr(asked, "revoke stream location dan\n")
	              && v.status() == "dan no longer sees your position.",
	      "no longer sharing was not done and said");
	CHECK(v.actions(1, 0) == QStringList({ "Send a file...", "Call everyone", "Members and admins..." }),
	      "a group's menu was not offered");
	CHECK(v.act(1, 0, "Send a file...") && what == "file" && to == "@family",
	      "a file to a group was not handed over as @NAME");
	CHECK(v.act(1, 0, "Members and admins...") && what == "members" && to == "family",
	      "a group's members were not handed over by its name");
	CHECK(v.act(1, 0, "Call everyone") && what == "call" && to == "bob,dan",
	      "calling a group did not ring every member it can name, this user not among them");
	CHECK(!v.act(1, 0, "Video call") && !v.act(0, 9, "Call"), "a choice not offered was carried out");

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui conversations_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui conversations_view_test: all %d checks passed\n", checks);
	return 0;
}
