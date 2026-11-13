/*
 * contacts_view_test -- contacts and pairing requests on a widget, sec 1107,
 * against a scripted node behind the ask callback: both lists (a contact in
 * a state shown with it, one in a state unknown here left out, sec 1118), a request's
 * proposed name shown beside its key and offered as the local name, approve
 * and reject, rename by key, remove by name, a name already held refused in
 * the client's words (not as a silent node), and a node that does not answer.
 */

#include "../contacts_view.h"

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                       \
	do {                                                                                    \
		checks++;                                                                       \
		if (!(cond)) {                                                                  \
			failures++;                                                             \
			fprintf(stderr, "  FAIL contacts_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                               \
	} while (0)

#define BOB "b0b0000000000000000000000000000000000000000000000000000000000001"
#define EVE "e7e0000000000000000000000000000000000000000000000000000000000002"
#define DAN "da40000000000000000000000000000000000000000000000000000000000003"
#define CAL "ca10000000000000000000000000000000000000000000000000000000000004"
#define ZED "2ed0000000000000000000000000000000000000000000000000000000000005"
#define DEE "dee0000000000000000000000000000000000000000000000000000000000006"

static int silent;
static char last[160];
static const char *write_reply = "ok";

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	if (!strcmp(line, "list contact 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 5 0 bob,%s alice,%s carol,%s,suspended zed,%s,later dee,%s,retired\n",
		                        BOB, DAN, CAL, ZED, DEE);
	if (!strcmp(line, "list request 0"))
		return (size_t)snprintf(reply, cap, "ok 1 %s,eve,1700000000,10.0.0.9:48080\n", EVE);
	snprintf(last, sizeof last, "%s", line);
	return (size_t)snprintf(reply, cap, "%s\n", write_reply);
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_contacts_view v(node, nullptr);

	CHECK(v.refresh() && v.contacts() == QStringList({ "bob b0b0000000000000", "alice da40000000000000",
	                                                   "carol ca10000000000000 (Removed on another of your hosts)",
	                                                   "dee dee0000000000000 (Removed for good)" })
	              && v.requests() == QStringList({ "eve e7e0000000000000" }),
	      "the contacts and the request were not listed with their keys and states");

	/* A REQUEST: its proposed name offered, approved under the person's. */
	v.select_request(0);
	CHECK(v.name() == "eve", "the proposed name was not offered as the local name");
	v.set_name("eve_from_work");
	CHECK(v.approve() && !strcmp(last, "grant request " EVE " eve_from_work"),
	      "a request was not approved under the name chosen");

	/* A NAME ALREADY HELD: the client refuses before asking, in its words. */
	v.select_request(0);
	v.set_name("bob");
	last[0] = '\0';
	CHECK(!v.approve() && !last[0] && v.status().contains("already have a contact of that name"),
	      "a name already held was asked of the node, or read as a silent node");

	/* NO NAME: nothing asked, and said why. */
	v.select_request(0);
	v.set_name("");
	last[0] = '\0';
	CHECK(!v.approve() && !last[0] && v.status().contains("name first"),
	      "a request was approved under no name");

	v.select_request(0);
	CHECK(v.reject() && !strcmp(last, "remove request " EVE), "a request was not rejected by its key");

	/* A CONTACT: renamed by key, removed by name. */
	v.select_contact(0);
	CHECK(v.name() == "bob", "a contact chosen did not offer its name");
	v.set_name("robert");
	CHECK(v.rename() && !strcmp(last, "add contact robert " BOB), "a rename was not asked by key");
	v.select_contact(1);
	CHECK(v.remove() && !strcmp(last, "remove contact alice"), "a contact was not removed by name");

	/* A CONTACT IN A STATE, sec 1118: removed on another host, added back
	 * by its key under its name; removed for good, nothing asked. */
	v.select_contact(2);
	CHECK(v.name() == "carol" && v.rename() && !strcmp(last, "add contact carol " CAL)
	              && v.status() == "carol is a contact again.",
	      "a suspended contact was not added back by its key");
	v.select_contact(3);
	last[0] = '\0';
	CHECK(!v.rename() && !last[0] && v.status().contains("for good"),
	      "a contact removed for good was asked to be added back");

	/* A REFUSAL IN THE NODE'S WORDS. */
	write_reply = "denied only the user's own hosts may change contacts";
	v.select_contact(0);
	CHECK(!v.remove() && v.status() == "only the user's own hosts may change contacts",
	      "a refusal was not said in the node's words");

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui contacts_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui contacts_view_test: all %d checks passed\n", checks);
	return 0;
}
