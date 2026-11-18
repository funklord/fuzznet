/*
 * share_view_test -- what another program shares, sent to a conversation,
 * fuzznet sec 1257, against a scripted node: this user's contacts and
 * groups listed and narrowed by the filter; a path that is no file
 * refused; a file stored here and sent to the contact chosen, the host
 * told where; a text sent to a group; a refusal said, the words kept.
 */
#include "../share_view.h"

#include <QApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryFile>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                       \
	do {                                                                                    \
		checks++;                                                                       \
		if (!(cond)) {                                                                  \
			failures++;                                                             \
			fprintf(stderr, "  FAIL share_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                               \
	} while (0)

#define BOB "b0b0000000000000000000000000000000000000000000000000000000000001"
#define DAN "da40000000000000000000000000000000000000000000000000000000000003"
#define FAMILY "f0f0000000000000000000000000000000000000000000000000000000000009"
#define ROOT "5555555555555555555555555555555555555555555555555555555555555555"
#define KEY "6666666666666666666666666666666666666666666666666666666666666666"

static char last_put[512], last_add[1024];
static int refuse_send;

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (!strcmp(line, "list contact 0"))
		return (size_t)snprintf(reply, cap, "ok 2 0 bob," BOB " dan," DAN "\n");
	if (!strcmp(line, "list group 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 family,3," FAMILY ",1\n");
	if (!strncmp(line, "put file ", 9)) {
		snprintf(last_put, sizeof last_put, "%s", line);
		return (size_t)snprintf(reply, cap, "ok " ROOT KEY "0000000000000005 private\n");
	}
	if (!strncmp(line, "add ", 4)) {
		snprintf(last_add, sizeof last_add, "%s", line);
		if (refuse_send)
			return (size_t)snprintf(reply, cap, "denied bob is not reachable\n");
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_share_view v(node, nullptr);
	QString told;
	QTemporaryFile f(QStringLiteral("%1/fzn-share-test-XXXXXX.txt").arg(QDir::tempPath()));

	v.on_sent([&told](const QString &to) { told = to; });
	CHECK(v.refresh() && v.listed() == QStringList({ "bob", "dan", "@family" }),
	      "this user's contacts and groups were not listed, groups as @NAME");
	v.set_filter("FAM");
	CHECK(v.listed() == QStringList({ "@family" }), "the filter did not narrow the list, whatever its case");
	v.set_filter("");
	CHECK(v.listed().size() == 3, "an empty filter did not list them all again");

	/* NOT A FILE: refused, and nothing to send. */
	CHECK(!v.set_file("/nonexistent/fzn-share") && v.status().contains("not a file") && !v.send(),
	      "a path that is no file was taken");

	/* A FILE, to bob: stored here, private, and sent as a line. */
	CHECK(f.open() && f.write("hello") == 5, "fixture: a file to share");
	f.close();
	CHECK(v.set_file(f.fileName()) && v.shared().contains(QFileInfo(f.fileName()).fileName())
	              && v.shared().contains("5 bytes"),
	      "the file shared was not said by its name and size");
	CHECK(!v.send(), "something was sent with no conversation chosen");
	v.choose(0);
	CHECK(v.chosen() == "bob" && v.send() && !strncmp(last_put, "put file ", 9)
	              && strstr(last_put, QFile::encodeName(f.fileName()).constData())
	              && !strncmp(last_add, "add message bob out ", 20) && strstr(last_add, "attach " ROOT)
	              && told == "bob" && v.status().startsWith("Sent "),
	      "the file was not stored here and sent to bob as a line, the host told where");

	/* WORDS, to the group. */
	told.clear();
	last_add[0] = '\0';
	CHECK(v.set_text("see you at eight") && v.shared() == "see you at eight", "the words shared were not shown");
	v.choose(2);
	CHECK(v.chosen() == "@family" && v.send() && strstr(last_add, "family") && strstr(last_add, "see")
	              && told == "@family",
	      "the words were not sent to the group chosen, the host told where");

	/* REFUSED: said, and the words kept. */
	refuse_send = 1;
	told.clear();
	v.choose(0);
	CHECK(!v.send() && v.status() == "bob is not reachable" && v.shared() == "see you at eight" && told.isEmpty(),
	      "a refusal was not said, or the words were lost, or the host told it went");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui share_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui share_view_test: all %d checks passed\n", checks);
	return 0;
}
