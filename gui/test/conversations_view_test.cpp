/*
 * conversations_view_test -- every conversation as a list, on a widget, sec
 * 1138, against a scripted node behind the ask callback: contacts and groups
 * under two headings, newest first, each with its newest line, who wrote it
 * and when, and its unread count; one with nothing said yet; choosing one
 * opens it by name or as @GROUP; each row's menu (sec 1144): a contact's
 * calls and location share, said as shared or not, a group's members and
 * call to everyone it can name; and a node that does not answer.
 */

#include "../conversations_view.h"

#include <QAccessible>
#include <QApplication>
#include <QElapsedTimer>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTreeWidget>

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int about_line; /* bob's newest: 1 a reaction, 2 a reply, 3 one taken back */
static int checks, failures;

#define CHECK(cond, what)                                                                            \
	do {                                                                                         \
		checks++;                                                                            \
		if (!(cond)) {                                                                       \
			failures++;                                                                  \
			fprintf(stderr, "  FAIL conversations_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                                    \
	} while (0)

#define BOB "b0b0000000000000000000000000000000000000000000000000000000000001"
#define BOB_24 "b0b000000000000000000000000000000000000000000000"
#define DAN "da40000000000000000000000000000000000000000000000000000000000003"
#define FAMILY "f0f0000000000000000000000000000000000000000000000000000000000009"
#define SELF "5e1f000000000000000000000000000000000000000000000000000000000000"
/* 2023-11-14 23:46:40 UTC. */
#define NOW 1700005600u

static int silent, members_mode, called;
static char read_choice[8]; /* bob's own read-marks choice, "" none (sec 1274) */
static char asked[512];

/* TWENTY THOUSAND CONTACTS, each with a conversation, sec 1496: every
 * listing paged a hundred at a time, as fuzznetd pages them. */
static int big;
/* A CONTACT AND A GROUP CALLED family, listed oldest first, sec 1496. */
static int twin;
#define BIG_N 20000u
#define BIG_PAGE 100u

static size_t big_page(const char *line, char *reply, size_t cap)
{
	size_t from = 0, at, n;
	const int newest = !strncmp(line, "list message newest", 19);
	const int unread = !strncmp(line, "list message unread", 19);
	const int contact = !strncmp(line, "list contact ", 13);

	if (!newest && !unread && !contact)
		return 0;
	if (sscanf(line + (contact ? 13 : 19), "%zu", &from) != 1)
		from = 0;
	at = contact ? (size_t)snprintf(reply, cap, "ok %u %zu", BIG_N, from)
	             : (size_t)snprintf(reply, cap, "ok %u %zu %u", BIG_N, from,
	                                from + BIG_PAGE > BIG_N ? BIG_N - (unsigned)from : BIG_PAGE);
	for (n = from; n < from + BIG_PAGE && n < BIG_N && at < cap; n++)
		at += contact ? (size_t)snprintf(reply + at, cap - at, " c%zu,%064zx", n, n + 1)
		      : newest ? (size_t)snprintf(reply + at, cap - at, " %064zx,%llu,in,-,text,hello", n + 1,
		                                  1700000000000ull + n * 1000ull)
		               : (size_t)snprintf(reply + at, cap - at, " %064zx,%u,0", n + 1, n % 7 ? 0u : 1u);
	at += (size_t)snprintf(reply + at, cap - at, "\n");
	return at;
}

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	if (twin && !strcmp(line, "list message newest"))
		return (size_t)snprintf(reply, cap,
		                        "ok 3 0 3 " DAN ",1700004600000,in,-,text,old " FAMILY
		                        ",1700005700000,in,carol,text,hi " BOB ",1700005800000,in,-,text,new\n");
	if (twin && !strcmp(line, "list message unread"))
		return (size_t)snprintf(reply, cap, "ok 3 0 3 " BOB ",2,0 " FAMILY ",3,0 " DAN ",1,0\n");
	if (twin && !strcmp(line, "list contact 0"))
		return (size_t)snprintf(reply, cap, "ok 2 0 bob," BOB " family," DAN "\n");
	if (big) {
		const size_t said = big_page(line, reply, cap);
		if (said)
			return said;
		if (!strcmp(line, "list group 0"))
			return (size_t)snprintf(reply, cap, "ok 0 0\n");
	}
	/* BOB'S LINE AT 23:50, CAROL'S FILE IN THE FAMILY AT 23:48, DAN NOTHING. */
	/* READ MARKS, sec 1274: the choice everywhere off, and bob's own as
	 * the menu set it -- "" when it follows. */
	if (!strcmp(line, "get schema message/read-marks"))
		return (size_t)snprintf(reply, cap, "ok message/read-marks,flag,estate+host,0,0,off,,safe-lower,x\n");
	if (!strncmp(line, "get schema message/read/", 24))
		return (size_t)snprintf(reply, cap, "ok message/read/,flag,estate+host,0,0,,,safe-lower,x\n");
	if (!strcmp(line, "get setting here message/read-marks"))
		return (size_t)snprintf(reply, cap, "ok absent\n");
	if (!strncmp(line, "get setting here message/read/" BOB_24, 30 + 48))
		return read_choice[0] ? (size_t)snprintf(reply, cap, "ok host 0 %s\n", read_choice)
		                      : (size_t)snprintf(reply, cap, "ok absent\n");
	if (!strncmp(line, "set setting host message/read/" BOB_24 " ", 30 + 48 + 1)) {
		snprintf(read_choice, sizeof read_choice, "%s", line + 30 + 48 + 1);
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	if (!strcmp(line, "remove setting host message/read/" BOB_24)) {
		read_choice[0] = '\0';
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	/* BOB'S NEWEST A REACTION, OR A REPLY (sec 1282). */
	if (!strcmp(line, "list message newest") && about_line)
		return (size_t)snprintf(reply, cap,
		                        "ok 3 0 3 " BOB ",1700005800000,in,-,%s,%s " FAMILY
		                        ",1700005700000,in,carol,file,photo.jpg " DAN ",0,-,-,none,\n",
		                        about_line == 4 ? "unsent" : "text",
		                        about_line == 4 ? ""
		                        : about_line == 1 ? "fzn:react/00112233445566778899aabbccddeeff%20\xf0\x9f\x91\x8d"
		                        : about_line == 2 ? "fzn:reply/00112233445566778899aabbccddeeff%20on%20my%20way"
		                                          : "fzn:react/00112233445566778899aabbccddeeff");
	/* DAN'S MISSED CALL AT 23:30, his newest (sec 1270). */
	if (!strcmp(line, "list message newest") && called)
		return (size_t)snprintf(reply, cap,
		                        "ok 3 0 3 " BOB ",1700005800000,in,-,text,see%%20you%%20at%%208 " FAMILY
		                        ",1700005700000,in,carol,file,photo.jpg " DAN ",1700004600000,in,-,call,2:1:0\n");
	if (!strcmp(line, "list message newest"))
		return (size_t)snprintf(reply, cap,
		                        "ok 3 0 3 " BOB ",1700005800000,in,-,text,see%%20you%%20at%%208 " FAMILY
		                        ",1700005700000,in,carol,file,photo.jpg " DAN ",0,-,-,none,\n");
	if (!strcmp(line, "list message unread"))
		return (size_t)snprintf(reply, cap, "ok 3 0 3 " BOB ",2,0 " FAMILY ",0,0 " DAN ",0,0\n");
	if (!strcmp(line, "list contact 0"))
		return (size_t)snprintf(reply, cap, "ok 2 0 bob," BOB " dan," DAN "\n");
	if (!strncmp(line, "grant ", 6) || !strncmp(line, "revoke ", 7)) {
		strncat(asked, line, sizeof asked - strlen(asked) - 2);
		strcat(asked, "\n");
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	/* DAN SEES THIS USER'S LOCATION; BOB DOES NOT. */
	if (!strcmp(line, "list stream location granted 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 dan,0\n");
	if (!strcmp(line, "get identity"))
		return (size_t)snprintf(reply, cap, "ok " SELF " " SELF "\n");
	if (!strcmp(line, "get group family member 0")) {
		/* ONE MEMBER BUT THIS USER, or seventeen besides, sec 1232. */
		if (members_mode == 1)
			return (size_t)snprintf(reply, cap, "ok 1 0 *" SELF "\n");
		/* THIS USER NO ADMIN, bob one (sec 1246). */
		if (members_mode == 3)
			return (size_t)snprintf(reply, cap, "ok 3 0 " SELF " *bob dan\n");
		if (members_mode == 2) {
			size_t n = (size_t)snprintf(reply, cap, "ok 18 0 *" SELF);
			for (int k = 0; k < 17; k++)
				n += (size_t)snprintf(reply + n, cap - n, " m%d", k);
			return n + (size_t)snprintf(reply + n, cap - n, "\n");
		}
		return (size_t)snprintf(reply, cap, "ok 3 0 *" SELF " bob dan\n");
	}
	/* A GROUP'S MEMBERS CHANGED FROM THE MENU, sec 1246: bob's admin
	 * waiting on one more admin, dan removed, the group deleted here. */
	if (!strcmp(line, "add admin family bob") || !strcmp(line, "remove member family dan")
	    || !strcmp(line, "remove group family")) {
		strncat(asked, line, sizeof asked - strlen(asked) - 2);
		strcat(asked, "\n");
		return (size_t)snprintf(reply, cap, !strcmp(line, "add admin family bob") ? "ok proposed 1 2\n" : "ok\n");
	}
	/* A GROUP MADE, sec 1483: its new id. */
	if (!strcmp(line, "add group gardeners")) {
		strncat(asked, line, sizeof asked - strlen(asked) - 2);
		strcat(asked, "\n");
		return (size_t)snprintf(reply, cap, "ok 6767676767676767676767676767676767676767676767676767676767676767\n");
	}
	if (!strcmp(line, "list group 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 family,3," FAMILY ",1\n");
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

/* A ROW TOGGLED AS ANDROID TOGGLES IT for a screen reader's double tap, sec
 * 1423: through the row's accessible cell. 1 when there was such a cell. */
static bool toggle_row(QAbstractItemView *view, int row)
{
	QAccessibleInterface *iface = QAccessible::queryAccessibleInterface(view);
	QAccessibleTableInterface *table = iface ? iface->tableInterface() : nullptr;
	QAccessibleInterface *cell = table && row < table->rowCount() ? table->cellAt(row, 0) : nullptr;
	QAccessibleActionInterface *act = cell ? cell->actionInterface() : nullptr;

	if (!act || !act->actionNames().contains(QAccessibleActionInterface::toggleAction()))
		return false;
	act->doAction(QAccessibleActionInterface::toggleAction());
	QCoreApplication::processEvents();
	return true;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	setenv("TZ", "UTC", 1);
	tzset();
	QApplication app(argc, argv);
	fzn_conversations_view v(node, nullptr);
	QString opened;

	v.set_now(NOW);
	v.on_open([&opened](const QString &to) { opened = to; });
	CHECK(v.refresh()
	              && v.shown()
	                         == QStringList({ "Contacts", "  bob -- see you at 8 -- 23:50 (2 unread)",
	                                          "  dan -- nothing said yet", "Groups",
	                                          "  family -- carol: a file: photo.jpg -- 23:48" }),
	      "the conversations were not shown under their headings, newest first, with their lines");
	called = 1;
	CHECK(v.refresh() && v.shown().value(2) == "  dan -- Missed call -- 23:30",
	      "a missed call, a conversation's newest, was not shown as one, by when it rang");
	called = 0;
	CHECK(v.refresh(), "the list did not come back without the call");
	about_line = 1;
	CHECK(v.refresh() && v.shown().value(1) == "  bob -- reacted \xf0\x9f\x91\x8d -- 23:50 (2 unread)",
	      "a reaction, a conversation's newest, was shown as its reference");
	about_line = 2;
	CHECK(v.refresh() && v.shown().value(1) == "  bob -- on my way -- 23:50 (2 unread)",
	      "a reply, a conversation's newest, was not shown by its own words");
	about_line = 3;
	CHECK(v.refresh() && v.shown().value(1) == "  bob -- took back a reaction -- 23:50 (2 unread)",
	      "a reaction taken back was shown as its reference");
	about_line = 4;
	CHECK(v.refresh() && v.shown().value(1) == "  bob -- a line taken back -- 23:50 (2 unread)",
	      "a line taken back, a conversation's newest, was not said so (sec 1284)");
	about_line = 0;
	CHECK(v.open(0, 0) && opened == "bob", "a contact's conversation was not opened by its name");
	/* AND BY A SCREEN READER, sec 1423: its double tap only selects, and
	 * opens the conversation as activation does. */
	{
		QTreeWidget *tree = v.findChild<QTreeWidget *>();

		opened.clear();
		for (int r = 0; tree && opened.isEmpty() && r < 8; r++)
			if (!toggle_row(tree, r))
				break;
		CHECK(opened == "bob", "a conversation toggled as a screen reader toggles it was not opened");
	}
	/* READ MARKS FOR ONE CONVERSATION, sec 1274: three ways, the one
	 * standing marked; chosen, set or cleared for bob's key alone. */
	CHECK(v.actions(0, 0).contains("Read marks: As everywhere (off) *")
	              && v.actions(0, 0).contains("Read marks: Tell them when I read"),
	      "bob's row did not offer read marks three ways, following marked");
	CHECK(v.act(0, 0, "Read marks: Don't tell them") && !strcmp(read_choice, "off")
	              && v.actions(0, 0).contains("Read marks: Don't tell them *")
	              && v.status() == "bob is not told when you read.",
	      "bob's own choice was not set, marked and said");
	CHECK(v.act(0, 0, "Read marks: As everywhere (off) *") && !read_choice[0]
	              && v.actions(0, 0).contains("Read marks: As everywhere (off) *"),
	      "bob's choice was not cleared to follow the choice everywhere");
	CHECK(v.open(1, 0) && opened == "@family", "a group's conversation was not opened as @NAME");
	CHECK(!v.open(1, 5), "a row that is not there was opened");
	/* A REFRESH KEEPS THE ROW CHOSEN, sec 1225: family's, under Groups. */
	{
		auto *tree = v.findChild<QTreeWidget *>();

		/* ON A DESKTOP THE OPEN ONE STAYS CHOSEN, sec 1496 (sec 1232's
		 * clearing is a phone's, which leaves the list). */
		CHECK(tree && tree->currentItem() && tree->currentItem()->text(0).startsWith("family")
		              && v.chosen() == "@family",
		      "a conversation opened on a desktop was not left chosen");
		tree->setCurrentItem(tree->topLevelItem(1)->child(0));
		opened.clear();
		CHECK(v.refresh() && tree && tree->currentItem() && tree->currentItem()->text(0).startsWith("family")
		              && tree->currentItem()->isSelected() && opened.isEmpty(),
		      "a refresh dropped the conversation chosen, or opened it");
	}

	/* EACH ROW'S MENU. */
	QString what, to;
	v.on_action([&what, &to](const QString &w, const QString &t) {
		what = w;
		to = t;
	});
	CHECK(v.actions(0, 0).mid(0, 4) == QStringList({ "Send a file...", "Call", "Video call", "Share my location" }),
	      "a contact's menu did not offer its calls and sharing");
	CHECK(v.actions(0, 1).value(3) == "Stop sharing my location",
	      "a contact who sees this user's location was not offered to stop");
	CHECK(v.act(0, 0, "Video call") && what == "video" && to == "bob", "a video call was not handed over");
	CHECK(v.act(0, 0, "Share my location") && !strcmp(asked, "grant stream location bob 0\n")
	              && v.status() == "bob can see your position now.",
	      "sharing location with a contact was not done and said");
	CHECK(v.act(0, 1, "Stop sharing my location") && strstr(asked, "revoke stream location dan\n")
	              && v.status() == "dan no longer sees your position.",
	      "no longer sharing was not done and said");
	CHECK(v.actions(1, 0).mid(0, 3) == QStringList({ "Send a file...", "Call everyone", "Members and admins..." }),
	      "a group's menu was not offered");
	CHECK(v.act(1, 0, "Send a file...") && what == "file" && to == "@family",
	      "a file to a group was not handed over as @NAME");
	CHECK(v.act(1, 0, "Members and admins...") && what == "members" && to == "family",
	      "a group's members were not handed over by its name");
	CHECK(v.act(1, 0, "Call everyone") && what == "call" && to == "bob,dan",
	      "calling a group did not ring every member it can name, this user not among them");
	CHECK(!v.act(1, 0, "Video call") && !v.act(0, 9, "Call"), "a choice not offered was carried out");

	/* A GROUP'S MEMBERS FROM ITS ROW'S MENU, sec 1246: an admin offered each
	 * member made an admin or removed, and this device's copy deleted; the
	 * change waiting on other admins said so; the deletion asked once and
	 * done the second time; and one who is not an admin refused, saying
	 * why. */
	{
		const QStringList offered = v.actions(1, 0);

		CHECK(offered.contains("Make an admin: bob") && offered.contains("Remove: dan")
		              && offered.contains("Delete this device's copy") && !offered.contains("Remove: you"),
		      "an admin was not offered each member to make an admin or remove");
		asked[0] = '\0';
		CHECK(v.act(1, 0, "Make an admin: bob") && strstr(asked, "add admin family bob")
		              && v.status() == "Asked. It takes effect when 1 more admin(s) ask.",
		      "making an admin, waiting on another admin, was not said so");
		CHECK(v.act(1, 0, "Remove: dan") && strstr(asked, "remove member family dan")
		              && v.status() == "dan is no longer in family.",
		      "a member removed was not removed, said");
		CHECK(v.act(1, 0, "Delete this device's copy") && !strstr(asked, "remove group family")
		              && v.status().startsWith("Choose \"Delete this device's copy\" again"),
		      "deleting this device's copy was done at once, not asked");
		CHECK(v.act(1, 0, "Delete this device's copy") && strstr(asked, "remove group family")
		              && v.status() == "Deleted family from this device.",
		      "deleting this device's copy, chosen again, was not done");
		v.refresh();
		members_mode = 3;
		const QStringList barred = v.actions(1, 0);
		CHECK(barred.contains("Add a member") && v.refused("Add a member") == "only the group's admins change who is in it"
		              && !v.act(1, 0, "Add a member") && v.status() == "only the group's admins change who is in it",
		      "one who is not an admin was offered the members' changes, or not told why");
		members_mode = 0;
		/* A NEW GROUP, sec 1483: made by its name and said; a blank name not
		 * asked. */
		asked[0] = '\0';
		CHECK(!v.create_group("   ") && !asked[0] && v.status() == "Name the group.",
		      "a group of no name was asked for");
		CHECK(v.create_group("gardeners") && strstr(asked, "add group gardeners")
		              && v.status() == "Made the group gardeners; add its members from its menu.",
		      "a new group was not made by its name, or not said");
	}

	/* CALL EVERYONE OFFERED DISABLED, SAYING WHY, sec 1232. */
	(void)v.actions(1, 0);
	CHECK(v.refused("Call everyone").isEmpty(), "calling a group of two was refused");
	members_mode = 1;
	(void)v.actions(1, 0);
	CHECK(v.refused("Call everyone") == "nobody else to call yet",
	      "a group of this user alone offered a call without saying there is nobody");
	members_mode = 2;
	(void)v.actions(1, 0);
	CHECK(v.refused("Call everyone").startsWith("too many to ring at once")
	              && !v.act(1, 0, "Call everyone") && v.status().startsWith("Too many in family"),
	      "a group past what is rung at once was offered a call, or rung");
	members_mode = 0;

	/* THE ROW AS A MESSENGER LAYS IT OUT, sec 1232: the unread count its own
	 * bold mark; the host's badge beside a contact, dimmed when stale. */
	v.set_badge([](const QString &name, bool *stale) {
		if (name == "dan")
			*stale = true;
		return name == "bob" ? QStringLiteral("near") : name == "dan" ? QStringLiteral("2 h ago") : QString();
	});
	{
		auto *tree = v.findChild<QTreeWidget *>();
		QTreeWidgetItem *bob = tree && v.refresh() ? tree->topLevelItem(0)->child(0) : nullptr;
		QTreeWidgetItem *dan = bob ? tree->topLevelItem(0)->child(1) : nullptr;

		CHECK(bob && bob->text(3) == "2" && bob->font(3).bold() && bob->text(0).startsWith("bob -- ")
		              && !bob->text(0).contains("unread"),
		      "bob's two unread were not a mark of their own");
		CHECK(bob && dan && bob->text(1) == "near" && dan->text(1) == "2 h ago"
		              && dan->foreground(1) != bob->foreground(1)
		              && v.shown().at(1) == "  bob -- see you at 8 [near] -- 23:50 (2 unread)",
		      "the host's badge was not beside each contact, the stale one dimmed");
	}

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	/* ONE LIST ON A PHONE, sec 1245: no headings, newest first, contacts
	 * and groups together, the group marked; a group and a contact still
	 * opened by their place among their kind; a desktop's two headings
	 * back at its width. */
	silent = 0;
	v.show();
	v.resize(320, 600);
	app.processEvents();
	{
		const QStringList rows = v.shown();

		CHECK(v.flat() && rows.size() == 3 && rows.value(0).startsWith("  bob -- ")
		              && rows.value(1).startsWith("  family -- ") && rows.value(1).contains("(group)")
		              && rows.value(2).startsWith("  dan -- ") && !rows.contains("Contacts"),
		      "on a phone the conversations were not one list, newest first, the group marked");
		auto *tree = v.findChild<QTreeWidget *>();
		CHECK(tree && tree->topLevelItemCount() == 3 && !tree->topLevelItem(1)->icon(0).isNull()
		              && tree->topLevelItem(1)->data(0, Qt::AccessibleDescriptionRole).toString() == "a group"
		              && tree->topLevelItem(0)->data(0, Qt::AccessibleDescriptionRole).toString().isEmpty(),
		      "flat, the group was not marked as one, or a contact was");
		/* A CONTACT'S PICTURE, its initial (sec 1264). */
		CHECK(!tree->topLevelItem(0)->icon(0).isNull() && !tree->topLevelItem(2)->icon(0).isNull(),
		      "flat, a contact had no picture");
		opened.clear();
		CHECK(v.open(1, 0) && opened == "@family" && v.open(0, 0) && opened == "bob",
		      "flat, a group or a contact was not opened by its place among its kind");
	}
	v.resize(800, 600);
	app.processEvents();
	CHECK(!v.flat() && v.shown().value(0) == "Contacts", "a desktop's width did not bring the headings back");
	/* AND WHAT THE REFRESH SAID STAYS through a change of width. */
	silent = 1;
	CHECK(!v.refresh(), "fixture: a silent node");
	v.resize(320, 600);
	app.processEvents();
	CHECK(v.flat() && v.status() == "The node did not answer.", "a change of width wiped what the refresh said");
	silent = 0;
	v.hide();

	/* THE INITIAL'S COLOUR, sec 1264: one name one colour, in any case;
	 * two names apart; white on it 4.5:1 or better for every name tried. */
	{
		int legible = 0;

		for (int i = 0; i < 300; i++) {
			const QColor c = fzn_conversations_view::initial_colour(QStringLiteral("name%1").arg(i));
			auto lin = [](double v) { return v <= 0.03928 ? v / 12.92 : pow((v + 0.055) / 1.055, 2.4); };
			const double l = 0.2126 * lin(c.redF()) + 0.7152 * lin(c.greenF()) + 0.0722 * lin(c.blueF());

			legible += 1.05 / (l + 0.05) >= 4.5;
		}
		CHECK(fzn_conversations_view::initial_colour("bob") == fzn_conversations_view::initial_colour("Bob")
		              && fzn_conversations_view::initial_colour("bob") != fzn_conversations_view::initial_colour("dan")
		              && legible == 300,
		      "an initial's colour was not the name's alone, or white on it was not 4.5:1");
	}

	/* WHAT A HOST HOSTING THE LIST WANTS OF IT, sec 1496 (fuzzypickles,
	 * inbox 20261126T2240Z). */
	{
		fzn_conversations_view w(node, nullptr);
		QStringList told;
		QString opened_here;
		int opens = 0;
		auto *tree = w.findChild<QTreeWidget *>();

		silent = 0;
		twin = 1;
		w.resize(800, 600);
		w.on_open([&opened_here, &opens](const QString &to) {
			opened_here = to;
			opens++;
		});
		w.on_chosen([&told](const QString &to, bool person) { told << to + (person ? " by a person" : " by a refresh"); });
		CHECK(w.refresh(), "fixture: the twins listed");
		/* NEWEST FIRST BY THE VIEW, whatever order the node gave. */
		CHECK(w.shown().value(1).startsWith("  bob") && w.shown().value(2).startsWith("  family"),
		      "the contacts were not shown newest first by the view's own order");
		/* A CONTACT AND A GROUP SHARING A NAME, kept apart. */
		CHECK(w.select("family", false) && tree->currentItem()->text(0).startsWith("family -- old")
		              && w.select("family", true) && tree->currentItem()->text(0).startsWith("family -- carol"),
		      "a contact and a group called family were not told apart");
		/* COUNTS, and changed at once by the host marking one read. */
		CHECK(w.contacts_count() == 2 && w.groups_count() == 1 && w.unread_total() == 6,
		      "the counts for a host were not contacts, groups and every unread line");
		w.mark_read("@family");
		CHECK(w.unread_total() == 3, "marking a conversation read did not change the count at once");
		/* ONE CLICK OPENS, and on a desktop it stays chosen, told as a
		 * person's choice; a refresh that loses it told as the refresh's. */
		QTreeWidgetItem *bob_row = tree->topLevelItem(0)->child(0);
		tree->itemClicked(bob_row, 0);
		tree->itemActivated(bob_row, 0);
		CHECK(opened_here == "bob" && opens == 1 && w.chosen() == "bob" && told == QStringList({ "bob by a person" }),
		      "one click did not open bob once, keep it chosen and tell the host");
		CHECK(w.refresh() && tree->currentItem() && tree->currentItem()->text(0).startsWith("bob"),
		      "a refresh did not keep the open conversation chosen");
		twin = 0;
		w.refresh();
		CHECK(told.size() == 1 && w.chosen() == "bob", "fixture: bob still listed");
		/* THE CHOSEN ONE'S MENU, for a phone's More. */
		CHECK(w.chosen_actions().contains("Send a file..."), "the chosen conversation's menu was not offered");
		/* A NEW GROUP NAMED INLINE, no dialog. */
		w.ask_group_name();
		auto *name = w.findChild<QLineEdit *>();
		QPushButton *make = nullptr;
		for (QPushButton *b : w.findChildren<QPushButton *>())
			if (b->text() == "Make the group")
				make = b;
		CHECK(name && make && name->isVisibleTo(&w), "New group did not ask the name inline");
		if (name && make) {
			name->setText("gardeners");
			make->click();
		}
		CHECK(name && !name->isVisibleTo(&w) && w.status().startsWith("Made the group gardeners"),
		      "the group named inline was not made");
		/* THE HOST'S OWN CONTROLS: ours hidden. */
		w.set_controls_shown(false);
		CHECK(!make->isVisibleTo(&w) && !w.findChild<QLabel *>()->isVisibleTo(&w),
		      "the host could not hide the view's own controls");
		/* ON A PHONE, opened, the list is left with nothing highlighted. */
		w.set_layout(1);
		tree->itemClicked(tree->topLevelItem(0), 0);
		CHECK(w.flat() && opens == 2 && !tree->currentItem() && tree->selectedItems().isEmpty(),
		      "a conversation opened on a phone was left highlighted");
		/* COLOURS BY KEY: two contacts with one name differ. */
		CHECK(fzn_conversations_view::key_colour(QByteArray(32, '\x10'))
		              != fzn_conversations_view::key_colour(QByteArray(32, '\x90')),
		      "two keys gave one colour");
	}
	/* TWENTY THOUSAND, sec 1496 (fuzzypickles' list holds them, with their
	 * badges, in under a second): every one listed, none hidden past a
	 * cap, the newest first, and a refresh in a bounded time. */
	{
		fzn_conversations_view many(node, nullptr);
		QElapsedTimer took;
		int badges = 0;

		silent = 0;
		big = 1;
		many.set_badge([&badges](const QString &, bool *) {
			badges++;
			return QString();
		});
		took.start();
		const bool done = many.refresh();
		const qint64 ms = took.elapsed();
		const QStringList rows = many.shown();
		fprintf(stderr, "conversations_view_test: 20000 contacts refreshed in %lld ms\n", (long long)ms);
		CHECK(done && rows.size() >= (int)BIG_N && rows.join("\n").contains("c19999") && many.status().isEmpty()
		              && badges >= (int)BIG_N,
		      "twenty thousand conversations were not all listed, with their badges");
		CHECK(ms < 5000, "twenty thousand conversations took five seconds or more to refresh");
		big = 0;
	}
	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui conversations_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui conversations_view_test: all %d checks passed\n", checks);
	return 0;
}
