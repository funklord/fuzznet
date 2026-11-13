/*
 * conversations_view_test -- every conversation as a list, on a widget, sec
 * 1138, against a scripted node behind the ask callback: contacts and groups
 * under two headings, newest first, each with its newest line, who wrote it
 * and when, and its unread count; one with nothing said yet; choosing one
 * opens it by name or as @GROUP; and a node that does not answer.
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
/* 2023-11-14 23:46:40 UTC. */
#define NOW 1700005600u

static int silent;

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
