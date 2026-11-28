/*
 * group_view_test -- one group's members, on a widget, sec 1143, against a
 * scripted node behind the ask callback: the members with this user as
 * "you" and the admins marked; the active contacts not in it offered, a
 * suspended one not; an admin adds, removes, proposes an admin and is told
 * how many have asked, and sets the earlier-lines setting; a member who is
 * no admin changes nothing and asks nothing; leaving; and silence.
 */

#include "../group_view.h"

#include <QApplication>
#include <QCheckBox>
#include <QPushButton>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                     \
	do {                                                                                  \
		checks++;                                                                     \
		if (!(cond)) {                                                                \
			failures++;                                                           \
			fprintf(stderr, "  FAIL group_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                             \
	} while (0)

#define SELF "5e1f000000000000000000000000000000000000000000000000000000000000"
#define BOB "b0b0000000000000000000000000000000000000000000000000000000000001"
#define CAROL "ca40000000000000000000000000000000000000000000000000000000000002"
#define DAN "da40000000000000000000000000000000000000000000000000000000000003"
#define EVE "e7e0000000000000000000000000000000000000000000000000000000000004"
#define STRANGER "0570000000000000000000000000000000000000000000000000000000000005"
#define FAMILY "f0f0000000000000000000000000000000000000000000000000000000000009"

/* THE GROUP AS THE NODE HOLDS IT: its member rows, whether this user is an
 * admin, its earlier-lines setting, and every set the view asked. */
static char members[512];
static int earlier = 1;
static char asked[1024];
static int silent;
/* WHAT BOB AND CAROL HOLD OF THIS HOST'S LINES, sec 1510. */
static int watered;
/* THE EARLIER-LINES SETTING UNREADABLE (sec 1540). */
static int earlier_away;

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	if (!strncmp(line, "add ", 4) || !strncmp(line, "remove ", 7) || !strncmp(line, "set ", 4)) {
		strncat(asked, line, sizeof asked - strlen(asked) - 2);
		strcat(asked, "\n");
	}
	if (!strcmp(line, "get identity"))
		return (size_t)snprintf(reply, cap, "ok " SELF " " SELF "\n");
	/* COUNTS (node/groups.c): this host wrote 5 lines; bob holds 5, dan 3. */
	if (watered && !strcmp(line, "get group family water 0"))
		return (size_t)snprintf(reply, cap, watered == 1 ? "ok 2 0 5 " BOB ",x,5,y " CAROL ",x,-,y\n"
		                                                 : "ok 2 0 5 " BOB ",x,5,y " DAN ",x,3,y\n");
	if (!strcmp(line, "get group family member 0"))
		return (size_t)snprintf(reply, cap, "ok %s\n", members);
	if (!strcmp(line, "list group 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 family,3," FAMILY ",1\n");
	if (!strcmp(line, "list contact 0"))
		return (size_t)snprintf(reply, cap, "ok 4 0 bob," BOB " carol," CAROL " dan," DAN " eve," EVE
		                                    ",suspended\n");
	if (earlier_away && !strcmp(line, "get group family backfill"))
		return (size_t)snprintf(reply, cap, "error the store refused\n");
	if (!strcmp(line, "get group family backfill"))
		return (size_t)snprintf(reply, cap, "ok %d\n", earlier);
	if (!strcmp(line, "add member family dan")) {
		snprintf(members, sizeof members, "4 0 *" SELF " *bob carol dan");
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	if (!strcmp(line, "remove member family carol")) {
		snprintf(members, sizeof members, "3 0 *" SELF " *bob dan");
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	if (!strcmp(line, "add admin family dan"))
		return (size_t)snprintf(reply, cap, "ok proposed 1 2\n");
	if (!strcmp(line, "set group family backfill 0")) {
		earlier = 0;
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	if (!strcmp(line, "remove group family"))
		return (size_t)snprintf(reply, cap, "ok\n");
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_group_view v(node, nullptr);

	CHECK(!v.refresh() && v.status() == "No group chosen.", "a view with no group asked for one");
	v.set_group("family");

	/* A MEMBER WHO IS NO ADMIN: shown, and changes nothing. */
	snprintf(members, sizeof members, "4 0 " SELF " *bob carol " STRANGER);
	CHECK(v.refresh() && v.members() == QStringList({ "you", "bob (admin)", "carol", "(not a contact)" }),
	      "the members were not shown with this user as you and the admins marked");
	CHECK(!v.may_change() && v.status() == "Only the group's admins change who is in it.",
	      "a member who is no admin was not told who changes the group");
	CHECK(!v.add_member("dan") && !v.remove_member(2) && !v.set_earlier(false) && !asked[0],
	      "a member who is no admin asked the node to change the group");

	/* WHAT CHANGED, TOLD THE HOST (sec 1545). */
	QStringList told;
	v.on_members_changed([&told](const QString &g) { told << "members " + g; });
	v.on_left([&told](const QString &g) { told << "left " + g; });
	/* AN ADMIN. */
	snprintf(members, sizeof members, "3 0 *" SELF " *bob carol");
	CHECK(v.refresh() && v.may_change() && v.members() == QStringList({ "you (admin)", "bob (admin)", "carol" }),
	      "an admin was not told it may change the group");
	CHECK(v.addable() == QStringList({ "dan" }),
	      "the contacts offered were not the active ones outside the group");
	CHECK(v.earlier(), "the earlier-lines setting was not read");
	CHECK(v.add_member("dan") && v.members().contains("dan") && v.status() == "Added dan.",
	      "a contact was not added");
	CHECK(!v.remove_member(0) && !v.remove_member(9), "this user or a row not there was removed");
	CHECK(v.remove_member(2) && !v.members().contains("carol") && v.status() == "Removed carol.",
	      "a member was not removed");
	CHECK(!v.set_admin(1, true), "an admin was made an admin again");
	CHECK(v.set_admin(2, true) && v.status() == "Asked: 1 of the 2 admins needed have asked so far.",
	      "a proposed admin was not said with how many have asked");
	CHECK(v.set_earlier(false) && !v.earlier() && earlier == 0, "the earlier-lines setting was not set");

	/* LEAVE ASKED BY PRESSING AGAIN (sec 1515): the first press leaves
	 * nothing. */
	{
		QPushButton *leave_button = nullptr;
		for (QPushButton *b : v.findChildren<QPushButton *>())
			if (b->text() == "Leave group")
				leave_button = b;
		if (leave_button)
			leave_button->click();
		CHECK(leave_button && !v.members().isEmpty() && v.status().startsWith("Press Leave group again"),
		      "Leave acted on the first press, or did not say to press again");
	}
	CHECK(v.leave() && v.members().isEmpty() && v.status() == "You left family; it is forgotten here.",
	      "leaving was not said");
	CHECK(strstr(asked, "remove group family\n") != nullptr, "leaving did not ask the node");
	CHECK(told == QStringList({ "members family", "members family", "members family", "left family" }),
	      "the host was not told of the members changed and the group left, once each");

	v.set_group("family");
	/* THE ROSTER SAYS WHAT EACH HOLDS of this host's lines (sec 1510). */
	watered = 1;
	CHECK(v.refresh() && v.members().filter("bob").value(0).endsWith(" -- has all your lines")
	              && v.members().filter("dan").value(0).endsWith(" -- has said nothing yet"),
	      "the roster did not say what each member holds of this host's lines");
	watered = 2;
	CHECK(v.refresh() && v.members().filter("dan").value(0).endsWith(" -- has 3 of your 5 lines"),
	      "a member holding some of this host's lines was not said as a count of them");
	watered = 0;
	/* AN UNREADABLE EARLIER-LINES SETTING (sec 1540): the roster shown,
	 * the setting unoffered and said. */
	earlier_away = 1;
	{
		QCheckBox *box = v.findChild<QCheckBox *>();
		CHECK(v.refresh() && !v.members().isEmpty() && box && !box->isEnabled()
		              && v.status().startsWith("Whether members added later get the earlier lines could not be read"),
		      "an unreadable earlier-lines setting failed the roster, or was not said");
	}
	earlier_away = 0;
	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	/* NO WIDER THAN A 320 px SCREEN, sec 1503: a phone's cover screen. */
	CHECK(v.minimumSizeHint().width() <= 320, "the view is wider than a 320 px cover screen");
	if (failures) {
		fprintf(stderr, "gui group_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui group_view_test: all %d checks passed\n", checks);
	return 0;
}
