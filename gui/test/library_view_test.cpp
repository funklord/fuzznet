/*
 * library_view_test -- the files the catalogue names, on a widget, sec
 * 1131, against a scripted node behind the ask callback: a file held here
 * and catalogued by another host, a file held only elsewhere, each with
 * where it is; the one not here asked for; the one here not asked for
 * again; what a person does on a file here (sec 1156) -- played through the
 * host's player, shared with every contact, a contact and a group and
 * taken back, saved, verified with a broken piece said, removed; and a node
 * that does not answer.
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
#define MOVIE "3030000000000000000000000000000000000000000000000000000000000004"

static int silent, broken;
static char last[200];
static char shares[200] = "ok 0 0";
#define FAMILY "f0f0000000000000000000000000000000000000000000000000000000000009"
#define BOB "b0b0000000000000000000000000000000000000000000000000000000000001"

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	/* A SONG another host catalogued, held here too; A TALK held only by
	 * the host that catalogued it. */
	if (!strcmp(line, "list catalog 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 6 0 " MOVIE ",name,movie.mkv,bbbb000000000000 " SONG ",name,song.ogg,aaaa000000000000 " SONG
		                        ",kind,audio/ogg,aaaa000000000000 " SONG
		                        ",duration,185000,aaaa000000000000 " TALK
		                        ",name,talk.webm,bbbb000000000000 " TALK
		                        ",kind,video/webm,bbbb000000000000\n");
	if (!strcmp(line, "get identity"))
		return (size_t)snprintf(reply, cap, "ok %s %s\n", ME, ME);
	if (!strcmp(line, "list file 0"))
		return (size_t)snprintf(reply, cap, "ok 2 0 " SONG ",4194304 " MOVIE
		                                    ",734003200,fetching=400/1000\n");
	/* WHOM THE SONG IS SHARED WITH, as each act leaves it. */
	if (!strcmp(line, "get file " SONG " shares 0"))
		return (size_t)snprintf(reply, cap, "%s\n", shares);
	if (!strcmp(line, "set file " SONG " public"))
		snprintf(shares, sizeof shares, "ok 1 0 everyone");
	if (!strcmp(line, "grant file " SONG " bob"))
		snprintf(shares, sizeof shares, "ok 2 0 everyone contact," BOB ",bob");
	if (!strcmp(line, "grant file " SONG " @family"))
		snprintf(shares, sizeof shares, "ok 3 0 everyone contact," BOB ",bob group," FAMILY ",family");
	if (!strcmp(line, "revoke file " SONG " bob"))
		snprintf(shares, sizeof shares, "ok 2 0 everyone group," FAMILY ",family");
	if (!strcmp(line, "get reference " SONG))
		return (size_t)snprintf(reply, cap, "ok " SONG "%064d0000000000400000\n", 7);
	if (!strcmp(line, "get file " SONG))
		return (size_t)snprintf(reply, cap, "ok 4096 4096 4194304 whole private 0\n");
	if (!strcmp(line, "get file " SONG " check"))
		return (size_t)snprintf(reply, cap, broken ? "ok dropped 2\n" : "ok intact\n");
	snprintf(last, sizeof last, "%s", line);
	return (size_t)snprintf(reply, cap, "ok\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_library_view v(node, nullptr);

	CHECK(v.refresh()
	              && v.rows() == QStringList({ "movie.mkv |  | 700.0 MB |  | arriving, 40%, from 1 host(s)",
	                                           "song.ogg | audio/ogg | 4.0 MB | 3:05 | here, and on 1 other host(s)",
	                                           "talk.webm | video/webm |  |  | on 1 host(s)" }),
	      "the files were not listed with their kind, size, length and where they are");

	v.select(1);
	last[0] = '\0';
	CHECK(!v.fetch() && !last[0], "a file already here was asked for again");
	v.select(2);
	CHECK(v.fetch() && !strcmp(last, "fetch file " TALK) && v.status().contains("talk.webm"),
	      "the file held elsewhere was not asked for by its root");

	v.select(0);
	last[0] = '\0';
	CHECK(!v.fetch() && !last[0], "a file on its way was asked for again");

	/* WHAT A PERSON DOES ON A FILE HERE, sec 1156. */
	QByteArray played;
	QString played_name;
	v.on_play([&played, &played_name](const QByteArray &root, const QString &name) {
		played = root;
		played_name = name;
	});
	v.select(2);
	CHECK(!v.play() && played.isEmpty() && !v.share("") && !v.remove(),
	      "a file held only elsewhere was played, shared or removed");
	v.select(1);
	CHECK(v.play() && played.size() == 32 && (uint8_t)played[0] == 0x50 && played_name == "song.ogg",
	      "a file here was not handed to the host's player by its root and name");
	CHECK(v.share("") && v.shares() == QStringList({ "every contact" }) && v.status().contains("every contact"),
	      "sharing with every contact was not done and said");
	CHECK(v.share("bob") && v.share("@family") && v.shares() == QStringList({ "every contact", "bob", "@family" }),
	      "sharing with a contact and a group was not read back");
	CHECK(v.unshare("bob") && v.shares() == QStringList({ "every contact", "@family" })
	              && v.status() == "song.ogg is no longer shared with bob.",
	      "taking a share back was not done and said");
	last[0] = '\0';
	CHECK(v.save_to("/tmp/fzn-song.ogg") && strstr(last, "get file " SONG) && strstr(last, "/tmp/fzn-song.ogg")
	              && v.status() == "Saved 4.0 MB to /tmp/fzn-song.ogg.",
	      "a file was not saved by its reference where asked");
	CHECK(v.verify() && v.status() == "4096 pieces checked, every one whole.", "a whole file's check was not said");
	broken = 1;
	CHECK(v.verify() && v.status().contains("2 broken, dropped to be fetched again"),
	      "broken pieces were not said as dropped to be fetched again");
	last[0] = '\0';
	CHECK(v.remove() && !strcmp(last, "remove file " SONG) && v.status() == "song.ogg is removed from this device.",
	      "removing this device's copy was not done and said");

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
