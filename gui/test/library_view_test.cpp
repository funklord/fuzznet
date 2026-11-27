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
#include "../rpc_ask.h"

#include <QAccessible>
#include <QApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTableWidget>
#include <QTemporaryDir>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
static int removed, puts_asked;
/* THE MOVIE ARRIVING, sec 1493: three slices of it reached. */
#define MOVIE_REACHED (3u * FZN_RPC_LIBRARY_PLAY_MAX_SLICE)
static char shares[200] = "ok 0 0";
#define FAMILY "f0f0000000000000000000000000000000000000000000000000000000000009"
#define BOB "b0b0000000000000000000000000000000000000000000000000000000000001"

/* WHAT A FILE ADDED ASKED, sec 1485: its catalogue lines. */
static QStringList catalogued;
#define ADDED "add0000000000000000000000000000000000000000000000000000000000001"

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	/* `get file ROOT OFFSET LENGTH PATH`: the song whole, the movie as far
	 * as it has arrived, written to PATH as fuzznetd writes a range. */
	{
		char hex[65], path[200];
		unsigned long long off, n;
		if (sscanf(line, "get file %64s %llu %llu %199s", hex, &off, &n, path) == 4) {
			const bool movie = !strcmp(hex, MOVIE);
			if (movie && off + n > MOVIE_REACHED)
				return (size_t)snprintf(reply, cap, "error the fetch has not reached that range yet\n");
			QFile out(QString::fromUtf8(path));
			if (!out.open(QIODevice::WriteOnly))
				return (size_t)snprintf(reply, cap, "error no\n");
			out.write(QByteArray((int)n, movie ? 'm' : 's'));
			return (size_t)snprintf(reply, cap, movie ? "ok partial\n" : "ok whole\n");
		}
	}
	/* WHO CLAIMS EACH, sec 1497: the song this host and the laptop, a
	 * sibling; the talk a host this one does not know. */
	if (!strcmp(line, "get catalog " SONG))
		return (size_t)snprintf(reply, cap, "ok 2 cccc000000000000 aaaa000000000000\n");
	if (!strcmp(line, "get catalog " TALK))
		return (size_t)snprintf(reply, cap, "ok 1 bbbb000000000000\n");
	/* A CLAIMANT THAT IS NOT HEX: no answer to read. */
	if (!strcmp(line, "get catalog " MOVIE))
		return (size_t)snprintf(reply, cap, "ok 1 zzzz000000000000\n");
	if (!strcmp(line, "list sibling 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 aaaa%060d,-,1,0,laptop\n", 0);
	if (!strcmp(line, "get file " MOVIE))
		return (size_t)snprintf(reply, cap, "ok 400 1000 734003200 partial private 0\n");
	if (!strcmp(line, "remove file " SONG))
		removed++;
	if (!strncmp(line, "put file ", 9))
		puts_asked++;
	if (!strncmp(line, "put file ", 9)) {
		if (strstr(line, "bad.bin"))
			return (size_t)snprintf(reply, cap, "error the store is full\n");
		return (size_t)snprintf(reply, cap, "ok " ADDED "%064d%016x private\n", 0, 5u);
	}
	if (!strncmp(line, "add catalog " ADDED " ", 12 + 64 + 1)) {
		catalogued << QString::fromUtf8(line + 12 + 64 + 1);
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	/* A SONG another host catalogued, held here too; A TALK held only by
	 * the host that catalogued it. */
	if (!strcmp(line, "list catalog 0"))
		return (size_t)snprintf(reply, cap,
		                        "ok 7 0 " MOVIE ",name,movie.mkv,bbbb000000000000 " SONG ",name,song.ogg,aaaa000000000000 " SONG
		                        ",kind,audio/ogg,aaaa000000000000 " SONG
		                        ",duration,185000,aaaa000000000000 " TALK
		                        ",name,talk.webm,bbbb000000000000 " TALK
		                        ",kind,video/webm,bbbb000000000000 " TALK
		                        ",duration,5223000,bbbb000000000000\n");
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
	                                           "talk.webm | video/webm |  | 1:27:03 | on 1 host(s)" }),
	      "the files were not listed with their kind, size, length and where they are");

	/* FINDING A FILE, sec 1207: by a word of its name or kind, any case, and
	 * by kind; kept across a refresh; a file hidden is not acted on. */
	CHECK(v.kinds() == QStringList({ "Every audio kind", "Every video kind", "audio/ogg", "video/webm" }),
	      "the kinds offered were not the files' own, after every kind of each family");
	/* EVERY AUDIO KIND, sec 1493: the family's prefix, not one kind. */
	v.set_kind("audio/*");
	CHECK(v.rows().size() == 1 && v.rows()[0].startsWith("song.ogg"), "every audio kind did not show the audio");
	v.set_kind("");
	v.set_find("SONG");
	CHECK(v.rows().size() == 1 && v.rows()[0].startsWith("song.ogg") && v.status() == "1 of 3 files shown.",
	      "a file was not found by a word of its name, in another case");
	v.set_find("video");
	CHECK(v.rows().size() == 1 && v.rows()[0].startsWith("talk.webm"), "a file was not found by its kind");
	v.set_find("");
	v.set_kind("video/webm");
	CHECK(v.rows().size() == 1 && v.rows()[0].startsWith("talk.webm"), "one kind was not shown alone");
	v.select(1);
	last[0] = '\0';
	CHECK(!v.play() && !v.remove() && !last[0], "a file hidden by the kind chosen was acted on");
	v.set_find("song");
	CHECK(v.rows().isEmpty() && v.status() == "No file matches.", "finding nothing was not said");
	v.set_find("");
	CHECK(v.refresh() && v.rows().size() == 1 && v.rows()[0].startsWith("talk.webm")
	              && v.status() == "1 of 3 files shown.",
	      "the kind chosen was lost on a refresh");
	v.set_find("");
	v.set_kind("");
	CHECK(v.rows().size() == 3 && v.status().isEmpty(), "every file did not come back, the count unsaid");
	CHECK(v.minimumSizeHint().width() <= 320, "the finding row made the view wider than a 320 px screen");

	/* FILES ADDED FROM THIS MACHINE, sec 1485: stored, then catalogued by
	 * name and by the kind the system names; one refused, said so. */
	{
		QTemporaryDir dir;
		const QString tune = dir.filePath(QStringLiteral("tune.mp3")), bad = dir.filePath(QStringLiteral("bad.bin"));
		QFile f(tune), g(bad);
		CHECK(dir.isValid() && f.open(QIODevice::WriteOnly) && f.write("ID3\x04", 4) == 4 && g.open(QIODevice::WriteOnly),
		      "fixture: two files");
		f.close();
		g.close();
		CHECK(v.add_files({ tune }) == 1 && catalogued.contains(QStringLiteral("name tune.mp3"))
		              && catalogued.contains(QStringLiteral("kind audio/mpeg"))
		              && v.status() == "Added 1 file(s) to the library.",
		      "a file was not stored and catalogued by its name and kind, or not said");
		CHECK(v.add_files({ bad }) == 0 && v.status() == "bad.bin was not added: the store is full",
		      "a file the store refused was not said so");
	}

	v.select(1);
	last[0] = '\0';
	CHECK(!v.fetch() && !last[0], "a file already here was asked for again");
	v.select(2);
	CHECK(v.fetch() && !strcmp(last, "fetch file " TALK) && v.status().contains("talk.webm"),
	      "the file held elsewhere was not asked for by its root");
	/* AND CHOSEN BY A SCREEN READER, sec 1423: its double tap only selects;
	 * the row is made current, so "Get the file" asks for that one. */
	{
		QTableWidget *table = v.findChild<QTableWidget *>();
		QAccessibleInterface *iface = table ? QAccessible::queryAccessibleInterface(table) : nullptr;
		QAccessibleTableInterface *t = iface ? iface->tableInterface() : nullptr;
		QAccessibleInterface *cell = t ? t->cellAt(2, 0) : nullptr;
		QAccessibleActionInterface *act = cell ? cell->actionInterface() : nullptr;

		v.select(0);
		if (act)
			act->doAction(QAccessibleActionInterface::toggleAction());
		QCoreApplication::processEvents();
		last[0] = '\0';
		CHECK(act && v.fetch() && !strcmp(last, "fetch file " TALK),
		      "a file toggled as a screen reader toggles it was not the one asked for");
	}

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
	/* A FILE CHOSEN BY ITS ROOT, sec 1500, as a host opens a search hit
	 * -- a find hiding it cleared first; a root not listed, refused. */
	{
		const QByteArray talk = QByteArray::fromHex(TALK);
		v.set_find("song");
		CHECK(v.select_root(talk) && v.chosen_root() == talk && v.rows().size() == 3,
		      "a file was not chosen by its root, with the find hiding it cleared");
		CHECK(!v.select_root(QByteArray(32, '\x01')) && v.chosen_root() == talk,
		      "a root not listed was chosen, or moved the choice");
	}
	/* HELD ONLY ELSEWHERE: shared and removed never; played, it is asked
	 * for and handed on at once (sec 1493). */
	v.select(2);
	CHECK(!v.share("") && !v.remove(), "a file held only elsewhere was shared or removed");
	CHECK(v.detail() == "Held by a host bbbb0000.", "a host this one does not know was not named by its key");
	CHECK(v.play() && played.size() == 32 && (uint8_t)played[0] == 0x70 && v.status().startsWith("Asked for talk.webm"),
	      "a file held only elsewhere was not asked for and handed to the host's player");
	played.clear();
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
	/* THE CHOSEN FILE'S DETAIL: who holds it, and how much plays here. */
	CHECK(v.detail() == "Held by this host, laptop. Whole here, 4.0 MB.",
	      "the chosen file's holders by name, and how much plays here, were not said");
	/* REMOVE ASKED INLINE FIRST, sec 1493: nothing done until confirmed. */
	QStringList notices;
	v.on_notice([&notices](const QString &line) { notices << line; });
	v.ask_remove();
	CHECK(v.offered().startsWith("Remove this device's copy of song.ogg?") && !removed,
	      "remove did not ask inline before acting");
	CHECK(v.confirm() && removed == 1 && v.status() == "song.ogg is removed from this device."
	              && notices.contains("song.ogg is removed from this device."),
	      "removing this device's copy was not done on confirming, said, and told the host");

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	/* THE PLAYABLE PART OF A FILE ARRIVING, saved private (sec 1493). */
	silent = 0;
	{
		const QString to = QDir::tempPath() + QStringLiteral("/fzn-library-test-%1.part").arg(getpid());
		int movie = -1;
		for (int r = 0; r < v.rows().size(); r++)
			if (v.rows()[r].startsWith("movie.mkv"))
				movie = r;
		v.select(movie);
		CHECK(!v.detail().contains("Held by"), "a claimant that is not hex was read as a host");
		CHECK(movie >= 0 && v.save_to(to) && QFileInfo(to).size() == (qint64)MOVIE_REACHED
		              && QFileInfo(to).permissions() == (QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ReadUser | QFileDevice::WriteUser)
		              && v.status().contains("that has arrived"),
		      "the playable part of a file arriving was not saved, private, as far as it had come");
		QFile::remove(to);
	}
	/* A NAME TOO LONG FOR THE LIBRARY, refused before its bytes are stored. */
	{
		const int asked = puts_asked;
		CHECK(v.add_files({ QStringLiteral("/nonexistent/") + QString(300, QLatin1Char('n')) + QStringLiteral(".ogg") }) == 0
		              && v.status().contains("longer than the library keeps") && puts_asked == asked,
		      "a name too long was cut short or stored, not refused");
	}
	/* NARROW ON A PHONE: Kind, Size and Length dropped. */
	v.set_narrow(true);
	CHECK(v.narrow() && v.findChild<QTableWidget *>()->isColumnHidden(1) && v.findChild<QTableWidget *>()->isColumnHidden(3)
	              && !v.findChild<QTableWidget *>()->isColumnHidden(4),
	      "narrow did not drop Kind, Size and Length");
	v.set_narrow(false);
	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui library_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui library_view_test: all %d checks passed\n", checks);
	return 0;
}
