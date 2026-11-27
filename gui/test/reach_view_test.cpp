/*
 * reach_view_test -- how this host is reached, on a widget, sec 1134,
 * against a scripted node behind the ask callback: where two hosts agree
 * this one is seen from outside, one host found on this network with its
 * key, the relay's quota, asking again outside and here, a single report
 * said as unconfirmed, and a node that does not answer. And sec 1196:
 * every report a row with who said it and when, the one picked advertised
 * as `net/address`, a refused one said so, each host found with when it
 * was seen, the relay per peer, and a phone's width hiding what it can
 * do without.
 */

#include "../reach_view.h"

#include <QApplication>
#include <QPushButton>
#include <QTreeWidget>

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

static int silent, alone, behind, refuse_address;
static char last_set[128];

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	if (!strcmp(line, "get address"))
		return alone == 2 ? (size_t)snprintf(reply, cap,
		                                     "ok 2 1 0123456789abcdef,203.0.113.5,4000,1700000000 "
		                                     "fedcba9876543210,198.51.100.7,4100,1700000100\n")
		       : alone ? (size_t)snprintf(reply, cap, "ok 1 1 0123456789abcdef,203.0.113.5,4000,1700000000\n")
		             : (size_t)snprintf(reply, cap,
		                                "ok 2 2 0123456789abcdef,203.0.113.5,4000,1700000000 "
		                                "fedcba9876543210,203.0.113.5,4000,1700000100\n");
	if (!strcmp(line, "fetch address"))
		return (size_t)snprintf(reply, cap, "ok 3\n");
	if (!strcmp(line, "get lan"))
		return (size_t)snprintf(reply, cap, "ok 1 " DESK ",192.168.1.20,4000,1700000000\n");
	if (!strcmp(line, "fetch lan"))
		return (size_t)snprintf(reply, cap, "ok 2 192.168.1.255\n");
	if (!strcmp(line, "get sync-load"))
		return behind ? (size_t)snprintf(reply, cap, "ok 112 growing peers,40,60,30,growing\n")
		              : (size_t)snprintf(reply, cap, "ok 34 ok peers,2,9,3,steady\n");
	if (!strcmp(line, "get schema net/address"))
		return (size_t)snprintf(reply, cap, "ok net/address,address,host,0,253,-,-,advertised,where\n");
	if (!strncmp(line, "set setting ", 12)) {
		snprintf(last_set, sizeof last_set, "%s", line);
		return (size_t)snprintf(reply, cap, refuse_address ? "malformed not an address\n" : "ok\n");
	}
	if (!strcmp(line, "list log 0 I"))
		return (size_t)snprintf(reply, cap, "ok 1 0 1700000000000000,I,relay,0,a%%20peer%%20was%%20turned%%20away\n");
	if (!strcmp(line, "get relay"))
		return (size_t)snprintf(reply, cap, "ok 1 1048576 3600 1 abcdef0123456789,4096,0\n");
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	qputenv("TZ", "UTC"); /* a node's times read the same anywhere */
	QApplication app(argc, argv);
	fzn_reach_view v(node, nullptr);

	CHECK(v.refresh() && v.outside() == "Others see this host at 203.0.113.5:4000 (2 of 2 agree).",
	      "where others see this host, and how many agree, was not said");
	CHECK(v.found() == QStringList({ "192.168.1.20:4000 -- d0d0000000000000 -- 2023-11-14 22:13" }),
	      "the host found on this network was not named by its key, with when it was seen");
	CHECK(v.seen_by()
	              == QStringList({ "203.0.113.5:4000 -- 0123456789abcdef -- 2023-11-14 22:13",
	                               "203.0.113.5:4000 -- fedcba9876543210 -- 2023-11-14 22:15" }),
	      "each report was not a row with who said it and when");
	CHECK(v.relayed() == QStringList({ "abcdef0123456789 -- 4.0 KB of 1.0 MB -- 0" }),
	      "the relay was not said per peer, used against the quota, and refused");
	CHECK(v.activity().size() == 1 && v.activity().value(0).endsWith(" -- a peer was turned away"),
	      "the node's recent activity was not listed, its message without the preamble");
	CHECK(v.advertise(1) && !strcmp(last_set, "set setting host net/address 203.0.113.5 4000")
	              && v.status().startsWith("Advertising 203.0.113.5:4000"),
	      "the report picked was not advertised as this host's net/address");
	refuse_address = 1;
	CHECK(!v.advertise(0) && v.status().contains("was refused"), "a refused address was not said so");
	refuse_address = 0;
	CHECK(!v.advertise(7) && v.status().startsWith("Select an address"), "advertising nothing picked was taken");
	{
		QTreeWidget *seen = v.findChild<QTreeWidget *>(QStringLiteral("reach_seen_by"));

		v.show();
		v.resize(300, 600);
		app.processEvents();
		CHECK(seen && seen->isColumnHidden(1), "a phone's width kept who reported each address");
		v.resize(800, 600);
		app.processEvents();
		CHECK(seen && !seen->isColumnHidden(1), "a desktop's width hid who reported each address");
		v.hide();
	}
	CHECK(v.relay() == "This host relays for others: 1.0 MB per 3600 s each; 1 using it now.",
	      "the relay's quota and users were not said");
	CHECK(v.keeping_up() == "Keeping up: syncing takes 34% of each round.",
	      "keeping up was not said with its share of a round");
	behind = 1;
	CHECK(v.refresh() && v.keeping_up().startsWith("Not keeping up (112% of each round): more is waiting")
	              && v.keeping_up().endsWith(" Growing: peers 40 (mean 30)."),
	      "falling behind was not said with fuzznet's advice and the queue that grows");
	behind = 0;
	CHECK(v.ask_outside() && v.status().contains("Asked 3 host(s)"), "asking again outside was not said");
	CHECK(v.look_here() && v.status().contains("Asked on this network"), "looking here was not said");

	alone = 1;
	CHECK(v.refresh() && v.outside().contains("nothing confirms it") && !v.outside().contains("disagree"),
	      "a single report was said as agreed, or as a disagreement");
	/* PEERS DISAGREEING, sec 1228: said, with what helps. */
	alone = 2;
	CHECK(v.refresh() && v.outside().contains("Peers disagree") && v.outside().contains("relay helps"),
	      "two peers seeing this host at two addresses were not said to disagree");
	alone = 1;

	/* A REFRESH KEEPS THE PERSON'S PLACE, sec 1225: the answer to Look on
	 * this network stays through a refresh; the report chosen stays chosen,
	 * found by address and reporter, and Advertise stays pressable. */
	CHECK(v.refresh() && v.status().contains("Asked on this network"),
	      "a refresh wiped the answer to the person's own press");
	alone = 0;
	{
		auto *seen = v.findChild<QTreeWidget *>(QStringLiteral("reach_seen_by"));
		auto *advertise = v.findChild<QPushButton *>(QStringLiteral("reach_advertise"));

		CHECK(v.refresh() && seen->topLevelItemCount() == 2, "fixture: two reports");
		seen->setCurrentItem(seen->topLevelItem(1));
		CHECK(v.refresh() && seen->currentItem() == seen->topLevelItem(1) && seen->currentItem()->isSelected()
		              && seen->currentItem()->text(1).contains("fedcba98") && advertise && advertise->isEnabled(),
		      "a refresh dropped the report chosen, and Advertise with it");
	}

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");
	/* AND A FAILED REFRESH'S WORDS GO WHEN ONE SUCCEEDS. */
	silent = 0;
	CHECK(v.refresh() && v.status().isEmpty(), "a refresh that worked left the last one's failure said");

	/* NO WIDER THAN A 320 px SCREEN, sec 1503: a phone's cover screen. */
	CHECK(v.minimumSizeHint().width() <= 320, "the view is wider than a 320 px cover screen");
	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui reach_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui reach_view_test: all %d checks passed\n", checks);
	return 0;
}
