/*
 * objects_view_test -- the named objects on a widget, sec 1102, against a
 * scripted node behind the ask callback a host hands in: the rows read
 * through the typed client, a value chosen from the words an object allows
 * or typed where it takes any, a held set said so, a refusal in the node's
 * words, and a node that does not answer.
 */

#include "../objects_view.h"

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL objects_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                              \
	} while (0)

#define KEY "aa00000000000000000000000000000000000000000000000000000000000001"

/* THE NODE: what it holds, what it says to a set, and whether it answers. */
static char lamp[16] = "off";
static const char *set_reply = "ok";
static int silent;
static char last_set[128];

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	if (strcmp(line, "list object 0") == 0)
		return (size_t)snprintf(reply, cap, "ok 0 2 0 lamp,%s,1700000000000," KEY
		                                    ",on|off note,-,-,-,*\n",
		                        lamp);
	if (strncmp(line, "set object ", 11) == 0) {
		snprintf(last_set, sizeof last_set, "%s", line + 11);
		if (strcmp(set_reply, "ok") == 0 && strncmp(line + 11, "lamp ", 5) == 0)
			snprintf(lamp, sizeof lamp, "%s", line + 16);
		return (size_t)snprintf(reply, cap, "%s\n", set_reply);
	}
	return (size_t)snprintf(reply, cap, "unsupported\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_objects_view v(node, nullptr);

	CHECK(v.refresh() && v.rows() == QStringList({ "lamp=off", "note=(not set)" }),
	      "the objects were not listed with their values");

	/* A LAMP OFFERS ITS WORDS; a set goes as typed and reads back. */
	v.select(0);
	CHECK(v.offered() == QStringList({ "on", "off" }), "the lamp did not offer on and off");
	v.choose("on");
	CHECK(v.set() && strcmp(last_set, "lamp on") == 0 && v.rows().value(0) == "lamp=on",
	      "the lamp was not set on, or did not read back");

	/* A NOTE TAKES ANY WORD, typed. */
	v.select(1);
	CHECK(v.offered().isEmpty(), "an object taking any word offered a list");
	v.choose("hello");
	CHECK(v.set() && strcmp(last_set, "note hello") == 0, "a typed value was not sent");

	/* HELD: taken, written a moment later, and said so. */
	set_reply = "ok held";
	v.select(0);
	v.choose("off");
	CHECK(v.set() && v.status().contains("being set") && v.rows().value(0) == "lamp=off",
	      "a held set was not said to be on its way");

	/* A REFUSAL IN THE NODE'S WORDS. */
	set_reply = "denied only an estate admin may set that";
	v.select(0);
	v.choose("on");
	CHECK(!v.set() && v.status() == "only an estate admin may set that",
	      "a refusal was not said in the node's words");

	/* NOTHING ANSWERING, which is not "no objects". */
	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.",
	      "a silent node was not said to be silent");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui objects_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui objects_view_test: all %d checks passed\n", checks);
	return 0;
}
