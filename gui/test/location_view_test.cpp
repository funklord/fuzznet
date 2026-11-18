/*
 * location_view_test -- positions shared with this user on a widget, sec
 * 1109, against a scripted node behind the ask callback: this host's
 * sampling and own fix, each contact's newest fix with its accuracy, age and
 * the distance and direction from here, a coarse fix said so, asking a
 * contact where they are, granting and taking back this user's own, and a
 * node that does not answer.
 */

#include "../phone_layout.h"

#include <QLabel>
#include "../location_view.h"
#include "../compass_rose.h"

#include <QApplication>
#include <QHeaderView>
#include <QTableWidget>

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

static int silent, no_self;
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
	if (!strcmp(line, "list location 0") && no_self)
		return (size_t)snprintf(reply, cap,
		                        "ok 1 0 c0c0000000000000,4,0,59.3400000,18.0600000,1700003540,-,-,10,10,-,0,bob\n");
	if (!strcmp(line, "list location 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 3 0 aaaa000000000000,9,0,59.3300000,18.0600000,1700003590,-,-,5,5,-,0,- "
		                        "c0c0000000000000,4,0,59.3400000,18.0600000,1700003540,-,-,10,10,-,0,bob "
		                        "e0e0000000000000,2,0,59.3000000,18.1000000,1699996400,-,-,1000,1000,-,1,eve\n");
	/* BOB IS GRANTED THIS HOST'S POSITION TO ABOUT 1 KM; EVE NOTHING. */
	if (!strcmp(line, "list contact 0"))
		return (size_t)snprintf(reply, cap, "ok 4 0 bob,%064d eve,%064d dan,%064d gone,%064d,suspended\n",
		                        0, 0, 0, 0);
	if (!strcmp(line, "list stream location granted 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 bob,1\n");
	snprintf(last, sizeof last, "%s", line);
	return (size_t)snprintf(reply, cap, "ok\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_location_view v(node, nullptr);

	v.set_now(NOW);
	QStringList told;
	v.on_chosen([&told](const QString &name) { told << name; });
	CHECK(v.refresh(), "the positions were not read");
	CHECK(v.own().contains("every 30 s from platform") && v.own().contains("Your newest position was taken ")
	              && v.own().contains(" ago") && !v.own().contains("59.33000")
	              && v.own().startsWith("Your position is taken") && !v.own().contains("host"),
	      "this user's sampling or their own fix was not said, in their words");
	{
		/* THE COORDINATES THE TOOLTIP, sec 1271, not the line. */
		bool tipped = false;
		for (QLabel *l : v.findChildren<QLabel *>())
			tipped = tipped || (l->text() == v.own() && l->toolTip() == "59.33000, 18.06000");
		CHECK(tipped, "this user's coordinates were not the own line's tooltip");
	}
	/* THE FIRST CONTACT CHOSEN, AND TOLD ONCE, sec 1233. */
	CHECK(v.chosen() == "bob" && told == QStringList({ "bob" }),
	      "the first contact was not chosen when nobody was, or the host was not told");
	CHECK(v.refresh() && told == QStringList({ "bob" }), "a refresh keeping bob told the host again");
	QStringList rows = v.rows();
	/* DAN SHARES NOTHING BACK and still has a row to be granted from,
	 * sec 1119; a suspended contact has none. */
	CHECK(rows.size() == 3 && rows.value(2).startsWith("dan | not shared with you"),
	      "not one row a contact, or dan, who shares nothing, had none");
	CHECK(rows.value(0).startsWith("bob | 59.34000, 18.06000 | within 10 m | 1 min ago")
	              && rows.value(0).contains("km") && rows.value(0).endsWith(QString::fromUtf8("N 0\xc2\xb0")),
	      "bob's fix, its age, its distance or its direction north, in degrees too, was not said");
	/* THE BADGES, sec 1197: bob fresh, an arrow north and a distance; eve two
	 * hours old, her age and stale; dan, who shares nothing, none. */
	CHECK(v.badge_for("bob").startsWith(QString::fromUtf8("\xe2\x86\x91 ")) && v.badge_for("bob").contains("km")
	              && !v.badge_is_stale("bob"),
	      "bob's fresh badge was not an arrow north and a distance");
	CHECK(v.badge_for("eve") == "2 h ago" && v.badge_is_stale("eve"), "eve's old fix was not her age, stale");
	CHECK(v.badge_for("dan").isEmpty() && !v.badge_is_stale("dan"), "dan, who shares nothing, had a badge");
	CHECK(v.map_url("bob").toString()
	              == "https://www.openstreetmap.org/?mlat=59.3400000&mlon=18.0600000#map=15/59.3400000/18.0600000",
	      "bob's place was not a map link");
	CHECK(rows.value(1).contains("coarse") && rows.value(1).contains("2 h ago"),
	      "a coarse fix was not said so, or its age was wrong");

	/* WHAT IS GRANTED, read back (sec 1119): bob to about 1 km, eve none. */
	v.select(1);
	CHECK(v.status().contains("do not share") && v.status().contains("eve"),
	      "eve was not said to be granted nothing");
	v.select(0);
	CHECK(v.precision() == 1 && v.status().contains("about 1 km"),
	      "bob's grant to about 1 km was not read back");
	/* THE ROSE, sec 1211: bob is due north. With no heading it is north-up
	 * and says so; facing east he is to the left, and his badge's arrow
	 * points left; facing south he is behind; facing 10 degrees, ahead.
	 * His fix gone stale, there is nothing to point at. */
	CHECK(v.rose()->needle_deg() == 0.0
	              && v.rose()->said().startsWith("bob is at 0 degrees from north; this device's heading is not known"),
	      "with no heading, the rose was not north-up and said so");
	v.set_heading(90.0);
	CHECK(v.rose()->needle_deg() == 270.0 && v.rose()->said() == "bob is 90 degrees to your left."
	              && v.badge_for("bob").startsWith(QString::fromUtf8("\xe2\x86\x90 ")),
	      "facing east, bob due north was not to the left, needle and badge");
	v.set_heading(180.0);
	CHECK(v.rose()->said() == "bob is behind you.", "facing south, bob due north was not behind");
	v.set_heading(10.0);
	CHECK(v.rose()->said() == "bob is straight ahead.", "within 15 degrees was not straight ahead");
	v.set_now(NOW + FZN_LOCATION_VIEW_FRESH_S + 120u);
	v.select(1);
	v.select(0);
	CHECK(v.rose()->needle_deg() < 0.0 && v.rose()->said() == "No one to point at.",
	      "bob's fix, gone stale, was pointed at");
	v.set_now(NOW);
	v.clear_heading();
	v.select(0);
	CHECK(v.badge_for("bob").startsWith(QString::fromUtf8("\xe2\x86\x91 ")) && v.rose()->needle_deg() == 0.0,
	      "with the heading cleared, the badge and the rose were not north-up again");
	CHECK(v.fetch() && !strcmp(last, "fetch stream location bob"), "bob was not asked where he is");
	last[0] = '\0';
	CHECK(!v.fetch() && !last[0] && v.status().startsWith("bob was asked 0 s ago"),
	      "asking bob again at once was sent, or not said with when he was asked");
	v.set_now(NOW + FZN_LOCATION_VIEW_ASK_GAP_S);
	CHECK(v.fetch() && !strcmp(last, "fetch stream location bob"), "bob could not be asked again after the gap");
	/* A REFRESH KEEPS THE PERSON'S PLACE, sec 1225: bob still chosen, by
	 * name, the rose still at him, and the answer to asking him still said;
	 * then a choice's own words are the view's to say again. */
	{
		QTableWidget *t = v.findChild<QTableWidget *>();

		CHECK(v.refresh() && t && t->currentRow() >= 0 && t->item(t->currentRow(), 0)
		              && t->item(t->currentRow(), 0)->text() == "bob" && v.rose()->said().contains("bob")
		              && v.status() == "Asked bob where they are.",
		      "a refresh dropped bob, the rose's target, or the answer to asking him");
		v.select(1);
		CHECK(v.refresh() && t->item(t->currentRow(), 0)->text() == "eve" && v.status().contains("do not share"),
		      "a refresh after choosing eve did not keep her, with her grant said");
		v.select(0);
	}
	v.set_now(NOW);
	v.set_precision(0);
	CHECK(v.share(true) && !strcmp(last, "grant stream location bob 0"),
	      "this user's position was not granted to bob exactly");
	v.set_precision(2);
	CHECK(v.share(true) && !strcmp(last, "grant stream location bob 2") && v.status().contains("10 km"),
	      "the precision chosen was not the one granted");
	CHECK(v.share(false) && !strcmp(last, "revoke stream location bob"),
	      "this user's position was not taken back from bob");

	/* THE BEARING AND HOW FAR AS NUMBERS, and the map through the opener
	 * given, sec 1233. */
	{
		double deg = -1.0, metres = -1.0;
		QUrl opened;

		v.select(0);
		CHECK(v.bearing_to("bob", &deg, &metres) && deg >= 0.0 && deg < 360.0 && metres > 0.0,
		      "bob's bearing and distance were not given as numbers");
		v.set_map_opener([&opened](const QUrl &url) {
			opened = url;
			return true;
		});
		CHECK(v.show_on_map() && opened == v.map_url("bob") && !opened.isEmpty(),
		      "Show on a map did not go through the opener given");
		CHECK(told.last() == "bob", "fixture: bob chosen");
	}

	v.select(2);
	v.set_precision(1);
	CHECK(v.share(true) && !strcmp(last, "grant stream location dan 1"),
	      "dan, who shares nothing back, was not granted this host's position");

	{
		QTableWidget *t = v.findChild<QTableWidget *>();

		v.show();
		v.resize(300, 600);
		app.processEvents();
		/* ONE COLUMN ON A PHONE, sec 1233: who, with how far and how long
		 * ago under it; no row numbers, no header. */
		CHECK(t && t->isColumnHidden(0) && t->isColumnHidden(1) && t->isColumnHidden(4) && !t->isColumnHidden(5)
		              && t->item(0, 5)->text().startsWith("bob\n") && t->item(0, 5)->text().contains(" ago")
		              && !t->verticalHeader()->isVisible() && !t->horizontalHeader()->isVisible(),
		      "a phone's width did not show one column of who, how far and how long ago");
		/* A PIXEL'S 411 dp IS A PHONE, sec 1271: below 600. */
		v.resize(411, 600);
		app.processEvents();
		CHECK(t && t->isColumnHidden(0) && !t->isColumnHidden(5), "a Pixel's width was not a phone's");
		v.resize(800, 600);
		app.processEvents();
		CHECK(t && !t->isColumnHidden(0) && !t->isColumnHidden(1) && t->isColumnHidden(5)
		              && t->horizontalHeader()->isVisible(),
		      "a desktop's width did not show the five columns");
		/* AND A HOST THAT KNOWS IT IS A PHONE SAYS SO, at any width. */
		fzn_phone_layout_pin(1);
		v.resize(801, 600);
		app.processEvents();
		CHECK(t && t->isColumnHidden(0) && !t->isColumnHidden(5), "a host's pinned phone layout was not taken");
		fzn_phone_layout_pin(-1);
		v.resize(800, 600);
		app.processEvents();
		CHECK(t && !t->isColumnHidden(0), "unpinned, the width did not decide again");
		v.hide();
	}
	/* NO FIX OF ITS OWN, sec 1197: said why no distance shows, and bob's
	 * badge his age, there being nothing to measure from. */
	no_self = 1;
	CHECK(v.refresh() && v.own().contains("turn Location on") && v.own().contains("Show on a map")
	              && v.badge_for("bob") == "1 min ago",
	      "a host with no fix of its own did not say why, or measured from nothing");
	no_self = 0;

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
