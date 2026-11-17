/*
 * leg_view_test -- this host's legs on a widget, sec 1210, against a
 * scripted node behind the ask callback: an answering leg and one never
 * answered, each figure where it belongs, the tooltip's sentences, an
 * over-budget leg said, a node from before sec 1210 read, the phone's
 * width, no legs, and a silent node.
 */

#include "../leg_view.h"

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                  \
	do {                                                                               \
		checks++;                                                                  \
		if (!(cond)) {                                                             \
			failures++;                                                        \
			fprintf(stderr, "  FAIL leg_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                          \
	} while (0)

/* A LEG ANSWERING at 42 ms, 25 per mille lost, observed 3 s ago, asked 1.5 s
 * ago and answered 125 s ago, one ask out, in use, costing 43 ms, unlimited; A LEG never
 * answered, four lost in a row, no peer at it, its budget spent. */
static const char *legs = "ok 2 1 0 192.0.2.7:4000,42,25,1,3,10,9,9,9,1500,125000,0,1,1,43,0,1700,86400000 "
                          "198.51.100.2:4000,-,-,0,-,4,0,4,0,2000,-,4,0,0,-,1000000,1000000,86400000\n";
static int silent;

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	if (!strcmp(line, "list leg 0"))
		return (size_t)snprintf(reply, cap, "%s", legs);
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_leg_view v(node, nullptr);

	v.resize(800, 400);
	CHECK(v.refresh() && v.summary() == "2 leg(s), 1 answering", "the summary was not two legs, one answering");
	CHECK(v.rows().value(0) == "192.0.2.7:4000 | udp | 42 ms | 9 of 10 | 43 ms | unlimited",
	      "the answering leg's row was not its address, link, latency, answers, cost and budget");
	CHECK(v.rows().value(1) == "198.51.100.2:4000 | udp | unmeasured | 0 of 4, 4 lost in a row | - | 976.6 KB of 976.6 KB",
	      "the silent leg was not unmeasured, its losses in a row, no cost, its budget spent");
	CHECK(v.detail(0) == "last asked 1 s ago\nlast answered 2 min ago\nan ask is out and unanswered",
	      "the answering leg's tooltip was not its last ask, last answer and the ask out");
	CHECK(v.detail(1).contains("never answered") && v.detail(1).contains("no peer is reached")
	              && v.detail(1).contains("budget is spent"),
	      "the silent leg's tooltip did not say never answered, not in use, budget spent");

	/* A PHONE: the address and what came back, nothing else. */
	v.narrow(true);
	CHECK(v.rows().value(0) == "192.0.2.7:4000 | 9 of 10", "a narrow view kept more than address and answers");
	v.narrow(false);

	/* A NODE FROM BEFORE SEC 1210: nine fields, read, the rest unsaid. */
	legs = "ok 1 0 0 192.0.2.7:4000,42,25,1,3,10,9,9,9\n";
	CHECK(v.refresh() && v.rows().value(0) == "192.0.2.7:4000 | udp | 42 ms | 9 of 10 | - | unlimited",
	      "an older node's leg was not read");
	legs = "ok 0 0 0\n";
	CHECK(v.refresh() && v.rows().isEmpty() && v.summary().startsWith("No legs yet"),
	      "no legs was not said so");
	legs = "ok 1 0 0 192.0.2.7:4000,42,25,1,3,10,9,9,9\n";
	CHECK(v.refresh() && v.rows().size() == 1, "fixture: a leg on screen before the node goes silent");
	silent = 1;
	CHECK(!v.refresh() && v.summary() == "The node did not answer." && v.rows().isEmpty(),
	      "a silent node was not said so, or its rows stayed");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui leg_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui leg_view_test: all %d checks passed\n", checks);
	return 0;
}
