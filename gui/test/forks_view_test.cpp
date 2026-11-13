/*
 * forks_view_test -- what a user's hosts decided apart, on a widget, sec
 * 1127, against a scripted node behind the ask callback: two subjects with
 * two sides each, grouped and dated; a side's value in caret form; the
 * chosen side kept with the value exactly as listed; nothing kept with no
 * side chosen; a refusal; and a node that does not answer.
 */

#include "../forks_view.h"

#include <QApplication>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int checks, failures;

#define CHECK(cond, what)                                                                    \
	do {                                                                                 \
		checks++;                                                                    \
		if (!(cond)) {                                                               \
			failures++;                                                          \
			fprintf(stderr, "  FAIL forks_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                            \
	} while (0)

#define PHONE "0a0a000000000000000000000000000000000000000000000000000000000001"
#define DESK "0b0b000000000000000000000000000000000000000000000000000000000002"

static int silent, refuse;
static char last[200];

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	/* LOG LEVEL: debug on the phone, info on the desk. RELAY: on, and a
	 * value holding an escape. Times are milliseconds. */
	if (!strcmp(line, "list fork 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 0 4 0 log/level," PHONE ",1700000000000,-,debug "
		                        "log/level," DESK ",1700000060000,-,info relay/enabled," PHONE
		                        ",1700000120000,-,on relay/enabled," DESK ",1700000180000,-,"
		                        "o%%1bff\n");
	snprintf(last, sizeof last, "%s", line);
	if (refuse)
		return (size_t)snprintf(reply, cap, "denied only an admin may change that\n");
	return (size_t)snprintf(reply, cap, "ok\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	setenv("TZ", "UTC", 1);
	tzset();
	QApplication app(argc, argv);
	fzn_forks_view v(node, nullptr);

	CHECK(v.refresh()
	              && v.shown()
	                         == QStringList({ "log/level", "  debug -- 0a0a000000000000, 2023-11-14 22:13",
	                                          "  info -- 0b0b000000000000, 2023-11-14 22:14",
	                                          "relay/enabled", "  on -- 0a0a000000000000, 2023-11-14 22:15",
	                                          "  o^[ff -- 0b0b000000000000, 2023-11-14 22:16" }),
	      "the sides were not grouped by subject, dated, and shown in caret form");

	last[0] = '\0';
	CHECK(!v.keep() && !last[0], "a side was kept with none chosen");
	v.select(0, -1);
	CHECK(!v.keep() && !last[0], "a subject's own row was kept as though it were a side");
	v.select(0, 1);
	CHECK(v.keep() && !strcmp(last, "set setting estate log/level info")
	              && v.status() == "Kept for log/level; every host takes it.",
	      "the desk's side was not kept as its value");
	v.select(1, 1);
	CHECK(v.keep() && !strcmp(last, "set setting estate relay/enabled o%1bff"),
	      "a side holding an escape was not kept with exactly its bytes");

	refuse = 1;
	v.select(0, 0);
	CHECK(!v.keep() && v.status() == "only an admin may change that", "a refusal lost the node's words");
	refuse = 0;

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui forks_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui forks_view_test: all %d checks passed\n", checks);
	return 0;
}
