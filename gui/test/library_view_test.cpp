/*
 * library_view_test -- the files the catalogue names, on a widget, sec
 * 1131, against a scripted node behind the ask callback: a file held here
 * and catalogued by another host, a file held only elsewhere, each with
 * where it is; the one not here asked for; the one here not asked for
 * again; and a node that does not answer.
 */

#include "../library_view.h"

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL library_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                              \
	} while (0)

#define SONG "5050000000000000000000000000000000000000000000000000000000000001"
#define TALK "7070000000000000000000000000000000000000000000000000000000000002"
#define ME "cccc000000000000000000000000000000000000000000000000000000000003"

static int silent;
static char last[200];

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	/* A SONG another host catalogued, held here too; A TALK held only by
	 * the host that catalogued it. */
	if (!strcmp(line, "list catalog 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 5 0 " SONG ",name,song.ogg,aaaa000000000000 " SONG
		                        ",kind,audio/ogg,aaaa000000000000 " SONG
		                        ",duration,185000,aaaa000000000000 " TALK
		                        ",name,talk.webm,bbbb000000000000 " TALK
		                        ",kind,video/webm,bbbb000000000000\n");
	if (!strcmp(line, "get identity"))
		return (size_t)snprintf(reply, cap, "ok %s %s\n", ME, ME);
	if (!strcmp(line, "list file 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 " SONG ",4194304\n");
	snprintf(last, sizeof last, "%s", line);
	return (size_t)snprintf(reply, cap, "ok\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_library_view v(node, nullptr);

	CHECK(v.refresh()
	              && v.rows() == QStringList({ "song.ogg | audio/ogg | 4.0 MB | 3:05 | here, and on 1 other host(s)",
	                                           "talk.webm | video/webm |  |  | on 1 host(s)" }),
	      "the files were not listed with their kind, size, length and where they are");

	v.select(0);
	last[0] = '\0';
	CHECK(!v.fetch() && !last[0], "a file already here was asked for again");
	v.select(1);
	CHECK(v.fetch() && !strcmp(last, "fetch file " TALK) && v.status().contains("talk.webm"),
	      "the file held elsewhere was not asked for by its root");

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui library_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui library_view_test: all %d checks passed\n", checks);
	return 0;
}
