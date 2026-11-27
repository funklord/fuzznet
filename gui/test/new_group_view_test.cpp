/*
 * new_group_view_test -- a new group with its members, sec 1508, against a
 * scripted node: nothing made without a name; made by its name, and its
 * contacts offered -- bob and carol tickable, eve (added from a prekey)
 * shown and refused, dan (suspended) not offered; bob and carol ticked and
 * added, carol refused by the node, both said; ready, opened as @NAME; and
 * skipping members; every line told the host; no wider than 320 px.
 */
#include "../new_group_view.h"

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL new_group_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                              \
	} while (0)

#define BOB "b0b0000000000000000000000000000000000000000000000000000000000001"
#define CAROL "ca20000000000000000000000000000000000000000000000000000000000002"
#define DAN "da40000000000000000000000000000000000000000000000000000000000003"

static char asked[1024];

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (!strncmp(line, "add group ", 10) || !strncmp(line, "add member ", 11)) {
		strncat(asked, line, sizeof asked - strlen(asked) - 2);
		strcat(asked, "\n");
		if (!strcmp(line, "add member gardeners carol"))
			return (size_t)snprintf(reply, cap, "error carol's host is not reachable\n");
		/* A GROUP MADE IS ANSWERED BY ITS ID. */
		if (!strncmp(line, "add group ", 10))
			return (size_t)snprintf(reply, cap, "ok %064d\n", 67);
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	if (!strcmp(line, "list contact 0"))
		return (size_t)snprintf(reply, cap, "ok 4 0 bob," BOB " carol," CAROL " eve,%064d dan," DAN ",suspended\n",
		                        0);
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	QStringList told;
	QString opened;

	{
		fzn_new_group_view v(node, nullptr);
		v.on_notice([&told](const QString &line) { told << line; });
		v.on_open([&opened](const QString &to) { opened = to; });
		CHECK(v.step() == 1 && v.title() == "New group", "a new form did not start at the name");
		CHECK(!v.create("  ") && !asked[0] && v.status() == "Name the group.", "a group of no name was asked for");
		CHECK(v.create("gardeners") && strstr(asked, "add group gardeners") && v.step() == 2
		              && v.title() == "gardeners",
		      "the group was not made by its name, or the members not offered next");
		/* WHO IS OFFERED: active contacts; a prekey one shown, not tickable. */
		CHECK(v.contacts() == QStringList({ "bob", "carol", "eve" }) && v.tickable("bob") && !v.tickable("eve"),
		      "the contacts offered were not the active ones, a prekey contact untickable");
		CHECK(!v.tick("eve", true) && v.status().startsWith("eve cannot be added: added from a prekey"),
		      "a prekey contact was ticked, or not said why not");
		CHECK(v.tick("bob", true) && v.tick("carol", true), "fixture: bob and carol ticked");
		/* ADDED IN ONE GO, a refusal said with its reason. */
		CHECK(!v.add_ticked() && strstr(asked, "add member gardeners bob") && strstr(asked, "add member gardeners carol")
		              && v.step() == 3 && v.summary().startsWith("gardeners is made, with you, bob.")
		              && v.summary().contains("Not added: carol -- carol's host is not reachable."),
		      "the members ticked were not added, or who was not and why not said");
		CHECK(v.open() && opened == "@gardeners", "the group made was not opened as @NAME");
		CHECK(told.contains("Made the group gardeners.") && told.last() == v.summary(),
		      "the lines said were not told the host");
		CHECK(v.minimumSizeHint().width() <= 320, "the view is wider than a 320 px cover screen");
	}
	/* MEMBERS SKIPPED: made, with this user alone in it. */
	{
		fzn_new_group_view v(node, nullptr);
		asked[0] = '\0';
		CHECK(v.create("solo"), "fixture: solo made");
		v.skip();
		CHECK(v.step() == 3 && v.summary() == "solo is made, with you alone in it for now."
		              && !strstr(asked, "add member"),
		      "skipping the members did not make the group with this user alone");
	}

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui new_group_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui new_group_view_test: all %d checks passed\n", checks);
	return 0;
}
