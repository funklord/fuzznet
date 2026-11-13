/*
 * reach_view_test -- how this host is reached, on a widget, sec 1134,
 * against a scripted node behind the ask callback: where two hosts agree
 * this one is seen from outside, one host found on this network with its
 * key, the relay's quota, asking again outside and here, a single report
 * said as unconfirmed, and a node that does not answer.
 */

#include "../reach_view.h"

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                    \
	do {                                                                                 \
		checks++;                                                                    \
		if (!(cond)) {                                                               \
			failures++;                                                          \
			fprintf(stderr, "  FAIL reach_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                            \
	} while (0)

#define DESK "d0d0000000000000000000000000000000000000000000000000000000000001"

static int silent, alone;

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	if (!strcmp(line, "get address"))
		return alone ? (size_t)snprintf(reply, cap, "ok 1 1 0123456789abcdef,203.0.113.5,4000,1700000000\n")
		             : (size_t)snprintf(reply, cap,
		                                "ok 2 2 0123456789abcdef,203.0.113.5,4000,1700000000 "
		                                "fedcba9876543210,203.0.113.5,4000,1700000100\n");
	if (!strcmp(line, "fetch address"))
		return (size_t)snprintf(reply, cap, "ok 3\n");
	if (!strcmp(line, "get lan"))
		return (size_t)snprintf(reply, cap, "ok 1 " DESK ",192.168.1.20,4000,1700000000\n");
	if (!strcmp(line, "fetch lan"))
		return (size_t)snprintf(reply, cap, "ok 2 192.168.1.255\n");
	if (!strcmp(line, "get relay"))
		return (size_t)snprintf(reply, cap, "ok 1 1048576 3600 1 abcdef0123456789,4096,0\n");
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_reach_view v(node, nullptr);

	CHECK(v.refresh() && v.outside() == "Others see this host at 203.0.113.5:4000 (2 of 2 agree).",
	      "where others see this host, and how many agree, was not said");
	CHECK(v.found() == QStringList({ "192.168.1.20:4000 -- d0d0000000000000" }),
	      "the host found on this network was not named by its key");
	CHECK(v.relay() == "This host relays for others: 1048576 bytes per 3600 s each; 1 using it now.",
	      "the relay's quota and users were not said");
	CHECK(v.ask_outside() && v.status().contains("Asked 3 host(s)"), "asking again outside was not said");
	CHECK(v.look_here() && v.status().contains("Asked on this network"), "looking here was not said");

	alone = 1;
	CHECK(v.refresh() && v.outside().contains("nothing confirms it"),
	      "a single report was said as agreed");

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui reach_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui reach_view_test: all %d checks passed\n", checks);
	return 0;
}
