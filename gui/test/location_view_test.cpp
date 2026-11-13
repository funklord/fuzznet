/*
 * location_view_test -- positions shared with this user on a widget, sec
 * 1109, against a scripted node behind the ask callback: this host's
 * sampling and own fix, each contact's newest fix with its accuracy, age and
 * the distance and direction from here, a coarse fix said so, asking a
 * contact where they are, granting and taking back this user's own, and a
 * node that does not answer.
 */

#include "../location_view.h"

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                       \
	do {                                                                                    \
		checks++;                                                                       \
		if (!(cond)) {                                                                  \
			failures++;                                                             \
			fprintf(stderr, "  FAIL location_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                               \
	} while (0)

#define ME "aaaa000000000000000000000000000000000000000000000000000000000001"
#define ROOT "bbbb000000000000000000000000000000000000000000000000000000000002"
#define NOW 1700003600u

static int silent;
static char last[160];

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	if (!strcmp(line, "get location"))
		return (size_t)snprintf(reply, cap, "ok 1 off 30 10 5 0 1700003500 platform\n");
	if (!strcmp(line, "get identity"))
		return (size_t)snprintf(reply, cap, "ok %s %s\n", ME, ROOT);
	/* THIS HOST AT 59.33 N 18.06 E; BOB ABOUT 1.1 KM NORTH, A MINUTE OLD;
	 * EVE COARSE, TWO HOURS OLD. */
	if (!strcmp(line, "list location 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 3 0 aaaa000000000000,9,0,59.3300000,18.0600000,1700003590,-,-,5,5,-,0,- "
		                        "c0c0000000000000,4,0,59.3400000,18.0600000,1700003540,-,-,10,10,-,0,bob "
		                        "e0e0000000000000,2,0,59.3000000,18.1000000,1699996400,-,-,1000,1000,-,1,eve\n");
	snprintf(last, sizeof last, "%s", line);
	return (size_t)snprintf(reply, cap, "ok\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_location_view v(node, nullptr);

	v.set_now(NOW);
	CHECK(v.refresh(), "the positions were not read");
	CHECK(v.own().contains("every 30 s from platform") && v.own().contains("59.33000, 18.06000"),
	      "this host's sampling or its own fix was not said");
	QStringList rows = v.rows();
	CHECK(rows.size() == 2, "not one row a contact");
	CHECK(rows.value(0).startsWith("bob | 59.34000, 18.06000 | within 10 m | 1 min ago")
	              && rows.value(0).contains("km") && rows.value(0).endsWith("N"),
	      "bob's fix, its age, its distance or its direction north was not said");
	CHECK(rows.value(1).contains("coarse") && rows.value(1).contains("2 h ago"),
	      "a coarse fix was not said so, or its age was wrong");

	v.select(0);
	CHECK(v.fetch() && !strcmp(last, "fetch stream location bob"), "bob was not asked where he is");
	CHECK(v.share(true) && !strcmp(last, "grant stream location bob 0"),
	      "this user's position was not granted to bob");
	CHECK(v.share(false) && !strcmp(last, "revoke stream location bob"),
	      "this user's position was not taken back from bob");

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui location_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui location_view_test: all %d checks passed\n", checks);
	return 0;
}
