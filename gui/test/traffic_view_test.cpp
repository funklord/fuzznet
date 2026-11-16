/* gui traffic_view_test -- what this node has moved, sec 1182: a parent per
 * family and per host from the daemon's own sums, its rows beneath, a file
 * by the library's name and a peer by its address, what was open kept open
 * across a refresh, and a node that did not answer said so. */
#include "../traffic_view.h"

#include <QApplication>
#include <QTreeWidget>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                       \
	do {                                                                                    \
		checks++;                                                                       \
		if (!(cond)) {                                                                  \
			failures++;                                                             \
			fprintf(stderr, "  FAIL traffic_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                               \
	} while (0)

#define ROOT "abababababababababababababababababababababababababababababababab"
#define HOST "aa00000000000000000000000000000000000000000000000000000000000001"
#define USER "bb00000000000000000000000000000000000000000000000000000000000002"

static int silent;

/* A NODE THAT SPEAKS TEXT, as a view's test node does: two families, three
 * rows over two hosts, and one file the library names. */
static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	unsigned from = 0;

	(void)ctx;
	if (silent)
		return 0;
	if (!strcmp(line, "get transfer"))
		return (size_t)snprintf(reply, cap, "ok files,4096,1048576 reconcile,10,20\n");
	if (sscanf(line, "list transfer %u", &from) == 1)
		return from ? (size_t)snprintf(reply, cap, "ok 3 %u\n", from)
		            : (size_t)snprintf(reply, cap,
		                               "ok 3 0 files,10.0.0.2:7000," ROOT ",100,200,3,4,1700000000,1700000060 "
		                               "files,10.0.0.3:7000,,5,6,0,0,5,5 "
		                               "reconcile,10.0.0.2:7000,,10,20,0,0,1,1\n");
	if (sscanf(line, "list catalog %u", &from) == 1)
		return from ? (size_t)snprintf(reply, cap, "ok 1 %u\n", from)
		            : (size_t)snprintf(reply, cap, "ok 1 0 " ROOT ",name,holiday,aa00000000000000\n");
	if (!strcmp(line, "get identity"))
		return (size_t)snprintf(reply, cap, "ok " HOST " " USER "\n");
	if (sscanf(line, "list file %u", &from) == 1)
		return (size_t)snprintf(reply, cap, "ok 0 %u\n", from);
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

static QTreeWidgetItem *top(QTreeWidget *t, const char *key)
{
	for (int i = 0; i < t->topLevelItemCount(); i++)
		if (t->topLevelItem(i)->text(0) == QString::fromLatin1(key))
			return t->topLevelItem(i);
	return nullptr;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_traffic_view view(node, nullptr);
	QTreeWidgetItem *files, *reconcile, *near_host;

	{
		int before = failures;

		CHECK(0, "deliberate");
		CHECK(failures == before + 1, "a failure counts");
		failures = before;
		checks -= 1;
	}
	CHECK(view.summary() == QStringLiteral("nothing moving"), "a fresh view said something moved");
	CHECK(view.refresh(), "the node's traffic was not read");
	CHECK(view.summary().startsWith(QStringLiteral("3 row(s) across 2 host(s)")),
	      "the summary did not count the daemon's rows and hosts");
	files = top(view.by_family(), "files");
	reconcile = top(view.by_family(), "reconcile");
	CHECK(view.by_family()->topLevelItemCount() == 2 && files && reconcile,
	      "the families were not a parent each");
	CHECK(files && files->text(1) == QStringLiteral("2") && files->childCount() == 2
	              && files->text(2) == QStringLiteral("1.0 MB"),
	      "a family's parent was not the daemon's sum over its two rows");
	CHECK(files && files->childCount() == 2 && files->child(0)->text(0) == QStringLiteral("holiday")
	              && files->child(1)->text(0) == QStringLiteral("10.0.0.3:7000"),
	      "a file was not named from the library, or a chat row not by its peer");
	near_host = top(view.by_host(), "10.0.0.2:7000");
	CHECK(view.by_host()->topLevelItemCount() == 2 && near_host && near_host->childCount() == 2
	              && near_host->child(0)->text(0) == QStringLiteral("files: holiday"),
	      "a host's parent did not hold its rows, each by its family");
	/* WHAT WAS OPEN STAYS OPEN, by key, across a refresh. */
	if (files)
		files->setExpanded(true);
	CHECK(view.refresh() && top(view.by_family(), "files") && top(view.by_family(), "files")->isExpanded()
	              && !top(view.by_family(), "reconcile")->isExpanded(),
	      "an open family was folded by a refresh, or a folded one opened");
	silent = 1;
	CHECK(!view.refresh() && view.summary().startsWith(QStringLiteral("Traffic could not be read"))
	              && view.by_family()->topLevelItemCount() == 2,
	      "a silent node was not said so, or the trees were cleared");
	if (failures) {
		fprintf(stderr, "gui traffic_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui traffic_view_test: all %d checks passed\n", checks);
	return 0;
}
