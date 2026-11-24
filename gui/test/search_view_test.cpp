/*
 * search_view_test -- the one search on a widget, sec 1293, against a
 * scripted node behind the ask callback: a search asked of two hosts, the
 * page read as they answer and said partial until both have; the next
 * page asked after the last hit; a search with a contact asked by name; a
 * hit opened; and a node that does not answer.
 */

#include "../search_view.h"
#include "../combo.h"

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                     \
	do {                                                                                  \
		checks++;                                                                     \
		if (!(cond)) {                                                                \
			failures++;                                                           \
			fprintf(stderr, "  FAIL search_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                             \
	} while (0)

#define NOTE "5050000000000000000000000000000000000000000000000000000000000001"
#define LINE "7070000000000000000000000000000000000000000000000000000000000002" \
             "0000000000000000000000000000000a"

static int silent, answered, stopped_short;
static char last[400];

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	/* BOB IS A CONTACT, so a search with him names one (sec 1318: the
	 * client finds the contact before asking). */
	if (!strcmp(line, "list contact 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 1 0 bob,b0b0000000000000000000000000000000000000000000000000000000000001\n");
	if (!strncmp(line, "fetch search", 12)) {
		snprintf(last, sizeof last, "%s", line);
		answered = 0;
		return (size_t)snprintf(reply, cap, "ok 2\n");
	}
	/* ONE HOST ANSWERED, then both, the line's host adding its hit. */
	if (!strcmp(line, "get search")) {
		/* A HOST THAT STOPPED SHORT, sec 1328: MORE 2. */
		if (stopped_short)
			return (size_t)snprintf(reply, cap, "ok 1 2 2 2 0 notes," NOTE ",160,1000,a%%20heron\n");
		if (answered++ == 0)
			return (size_t)snprintf(reply, cap, "ok 1 0 2 1 0 notes," NOTE ",160,1000,a%%20heron\n");
		return (size_t)snprintf(reply, cap,
		                        "ok 2 1 2 2 0 notes," NOTE ",160,1000,a%%20heron lines," LINE
		                        ",100,2000,heron%%2c%%20flying\n");
	}
	return (size_t)snprintf(reply, cap, "error not scripted\n");
}

int main(int argc, char **argv)
{
	/* OFFSCREEN, as every other view's test: run from `make test` on a
	 * desk it opened its window on the desktop, and under the sanitizers
	 * Qt's X11 platform left allocations LeakSanitizer reported. */
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_search_view view(node, nullptr);
	QString opened_store;
	QByteArray opened_key;

	view.on_open([&](const QString &store, const QByteArray &key) {
		opened_store = store;
		opened_key = key;
	});
	CHECK(!view.search(QStringLiteral("   ")), "an empty search was asked");
	CHECK(view.search(QStringLiteral("heron")) && !strcmp(last, "fetch search heron"),
	      "a search was not asked as fetch search");
	CHECK(view.rows().size() == 1 && view.rows()[0].startsWith(QStringLiteral("a heron | a note"))
	              && !view.settled() && view.status().contains(QStringLiteral("1 of 2")),
	      "the first host's hit was not shown, or the page was said whole");
	CHECK(view.poll() && view.settled() && view.rows().size() == 2
	              && view.rows()[1].startsWith(QStringLiteral("heron, flying | a conversation")),
	      "the second host's hit did not join the page");
	CHECK(!view.status().contains(QStringLiteral("answered")), "a page every host answered was said partial");
	CHECK(!view.status().contains(QStringLiteral("newest")), "a page searched whole was said to be the newest only");
	CHECK(view.more() && !strcmp(last, "fetch search after lines," LINE ",100,2000 heron"),
	      "the next page was not asked after the last hit");
	CHECK(view.search(QStringLiteral("heron"), QStringLiteral("bob")) && !strcmp(last, "fetch search with bob heron"),
	      "a search with a contact did not name the contact");
	CHECK(!view.search(QStringLiteral("heron"), QStringLiteral("nobody")) && view.status().contains(QStringLiteral("no such contact")),
	      "a search with no such contact was asked, or not said");
	stopped_short = 1;
	CHECK(view.search(QStringLiteral("heron")) && view.status().contains(QStringLiteral("only the newest")),
	      "a page from a host that stopped short was not said to be the newest only");
	stopped_short = 0;
	/* SELECT THEN OPEN, as the header has it, sec 1356: the row selected is
	 * the row opened. */
	CHECK(view.search(QStringLiteral("heron")) && view.poll() && view.rows().size() == 2,
	      "fixture: two hits listed");
	view.select(1);
	CHECK(view.open() && opened_store == QStringLiteral("lines"),
	      "select(1) then open() did not open the second hit");
	view.select(0);
	CHECK(view.open() && opened_store == QStringLiteral("notes"),
	      "select(0) then open() did not open the first hit");
	/* A HOST'S OWN CHOOSER, sec 1357: the view's combos are the hooked kind,
	 * and opening one goes to the host's hook -- TalkBack opens a combo by
	 * calling showPopup, and a second window aborts a Widgets app under it. */
	{
		int hooked = 0, combos = 0;

		fzn_combo_box::set_popup([&hooked](QComboBox *) {
			hooked++;
			return true;
		});
		for (QComboBox *c : view.findChildren<QComboBox *>()) {
			combos++;
			CHECK(dynamic_cast<fzn_combo_box *>(c) != nullptr, "a combo of the view is not the hooked kind");
			c->showPopup();
		}
		fzn_combo_box::set_popup({});
		CHECK(combos > 0 && hooked == combos, "opening a combo did not go to the host's hook");
	}
	silent = 1;
	CHECK(!view.search(QStringLiteral("heron")) && view.status() == QStringLiteral("The node did not answer."),
	      "a node that did not answer was not said");
	if (failures) {
		fprintf(stderr, "search_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("search_view_test: all %d checks passed\n", checks);
	return 0;
}
