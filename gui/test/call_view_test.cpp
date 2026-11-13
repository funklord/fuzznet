/*
 * call_view_test -- calls, on a widget, sec 1142, against a scripted node
 * behind the ask callback: a call ringing in said with who and what kind,
 * answered, then hung up; Answer and Decline only for one ringing here; a
 * call begun to a contact; a call that rang in and went said as missed, one
 * declined said with why; and a node that does not answer.
 */

#include "../call_view.h"

#include <QApplication>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                    \
	do {                                                                                 \
		checks++;                                                                    \
		if (!(cond)) {                                                               \
			failures++;                                                          \
			fprintf(stderr, "  FAIL call_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                            \
	} while (0)

#define BOB "b0b0000000000000000000000000000000000000000000000000000000000001"
#define IN "1111222233334444"
#define OUT "aaaabbbbccccdddd"

/* THE NODE'S CALLS: what `list call` says, and what `get call` says of one
 * that has ended. */
static char live[512];
static char ended_in[32] = "", ended_out[32] = "";
static char said[128];
static int silent;

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	snprintf(said, sizeof said, "%s", line);
	if (!strcmp(line, "list call"))
		return (size_t)snprintf(reply, cap, "ok %s\n", live);
	if (!strcmp(line, "list contact 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 bob," BOB "\n");
	if (!strcmp(line, "get call " IN))
		return (size_t)snprintf(reply, cap, ended_in[0] ? "ok ended %s\n" : "ok live\n", ended_in);
	if (!strcmp(line, "get call " OUT))
		return (size_t)snprintf(reply, cap, ended_out[0] ? "ok ended %s\n" : "ok live\n", ended_out);
	if (!strcmp(line, "set call " IN " answer")) {
		snprintf(live, sizeof live, "1 " IN ",up,3," BOB);
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	if (!strcmp(line, "set call " IN " hangup")) {
		snprintf(live, sizeof live, "0");
		snprintf(ended_in, sizeof ended_in, "ended");
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	if (!strcmp(line, "add call bob audio")) {
		snprintf(live, sizeof live, "1 " OUT ",ringing-out,1," BOB);
		return (size_t)snprintf(reply, cap, "ok " OUT "\n");
	}
	if (!strcmp(line, "add call nobody audio"))
		return (size_t)snprintf(reply, cap, "error no such contact: nobody\n");
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_call_view v(node, nullptr);

	snprintf(live, sizeof live, "0");
	CHECK(v.refresh() && v.calls().isEmpty() && v.status() == "No call.", "no call was not said so");
	CHECK(!v.answer() && !v.hang_up(), "a call that is not there was answered or hung up");

	/* RINGING IN: said with who and what kind; answered, not hung up. */
	snprintf(live, sizeof live, "1 " IN ",ringing-in,3," BOB);
	CHECK(v.refresh() && v.calls() == QStringList({ "bob is calling (audio and video)" }),
	      "a call ringing in was not said with who and what kind");
	CHECK(!v.hang_up() && strncmp(said, "set ", 4), "a call ringing in was hung up rather than declined");
	CHECK(v.answer() && v.calls() == QStringList({ "In a call with bob" }), "answering did not bring the call up");
	CHECK(!v.answer() && !v.decline(), "a call already up was answered or declined again");
	CHECK(v.hang_up() && v.calls().isEmpty() && v.status() == "The call with bob ended: ended.",
	      "hanging up did not end the call, said");

	/* CALLING OUT, then the other end declines. */
	CHECK(v.call("bob", false) && v.calls() == QStringList({ "Calling bob..." }), "a call to bob was not begun");
	CHECK(!v.answer() && strncmp(said, "set ", 4), "a call ringing out was answered");
	snprintf(live, sizeof live, "0");
	snprintf(ended_out, sizeof ended_out, "declined");
	CHECK(v.refresh() && v.status() == "The call with bob ended: declined.", "a declined call was not said so");
	CHECK(!v.call("nobody", false) && v.status() == "no such contact: nobody", "a refused call was not said");

	/* MISSED: rang in here and the caller gave up. */
	snprintf(live, sizeof live, "1 " IN ",ringing-in,1,-");
	ended_in[0] = '\0';
	CHECK(v.refresh() && v.calls() == QStringList({ "someone is calling (audio)" }),
	      "a call from nobody known was not said as someone");
	snprintf(live, sizeof live, "0");
	snprintf(ended_in, sizeof ended_in, "hung-up");
	CHECK(v.refresh() && v.status() == "Missed call from someone.", "a call that rang and went was not missed");

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	if (failures) {
		fprintf(stderr, "gui call_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui call_view_test: all %d checks passed\n", checks);
	return 0;
}
