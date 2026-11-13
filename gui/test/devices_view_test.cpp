/*
 * devices_view_test -- adding a device on a widget, sec 1122, against a
 * scripted node behind the ask callback: a code made and drawn as a QR, the
 * confirm switch read and set (and put back when the node refuses), the
 * devices waiting listed by key, one let in and one turned away by their
 * full keys, and a node that does not answer.
 */

#include "../devices_view.h"

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL devices_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                              \
	} while (0)

#define DEV1 "d1d1000000000000000000000000000000000000000000000000000000000001"
#define DEV2 "d2d2000000000000000000000000000000000000000000000000000000000002"

static int silent, confirm_on = 1, refuse_set;
static char last[200];

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	if (!strcmp(line, "add invite delegable"))
		return (size_t)snprintf(reply, cap, "ok FZI1:ABCDEFGHIJKLMNOP2345\n");
	if (!strcmp(line, "get setting host invite/confirm"))
		return (size_t)snprintf(reply, cap, "ok invite/confirm %s\n", confirm_on ? "on" : "off");
	if (!strcmp(line, "list invite"))
		return (size_t)snprintf(reply, cap, "ok 2 %s %s\n", DEV1, DEV2);
	snprintf(last, sizeof last, "%s", line);
	if (refuse_set && !strncmp(line, "set setting host invite/confirm", 31))
		return (size_t)snprintf(reply, cap, "denied only an admin may change that\n");
	return (size_t)snprintf(reply, cap, "ok\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_devices_view v(node, nullptr);

	CHECK(v.refresh() && v.confirm()
	              && v.waiting() == QStringList({ "d1d1000000000000", "d2d2000000000000" }),
	      "the switch or the waiting devices were not read");

	/* A CODE, as text and as a QR. */
	CHECK(!v.code_drawn(), "a QR was drawn before any code was made");
	CHECK(v.invite() && v.code() == "FZI1:ABCDEFGHIJKLMNOP2345" && v.code_drawn()
	              && v.status().contains("ten minutes"),
	      "the code was not shown, drawn, or said to expire");

	/* THE SWITCH: set off, and put back when the node refuses. */
	CHECK(v.set_confirm(false) && !strcmp(last, "set setting host invite/confirm off") && !v.confirm(),
	      "confirming was not turned off");
	refuse_set = 1;
	CHECK(!v.set_confirm(true) && !v.confirm() && v.status() == "only an admin may change that",
	      "a refused switch was left showing on, or the node's words were lost");
	refuse_set = 0;

	/* WAITING DEVICES, answered by their full keys. */
	v.select_waiting(1);
	CHECK(v.answer(true) && !strcmp(last, "grant invite " DEV2) && v.status() == "d2d2000000000000 is let in.",
	      "the second device was not let in by its own key");
	v.select_waiting(0);
	CHECK(v.answer(false) && !strcmp(last, "remove invite " DEV1),
	      "the first device was not turned away by its own key");
	v.select_waiting(-1);
	last[0] = '\0';
	CHECK(!v.answer(true) && !last[0], "an answer was sent with no device chosen");

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui devices_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui devices_view_test: all %d checks passed\n", checks);
	return 0;
}
