/*
 * entries_view_test -- a host's log on a widget, read from a log directory
 * through the same gather queries a remote host answers. sec 468.
 *
 * In a scratch directory of its own that it leaves empty.
 */

extern "C" {
#include "../../log/entry.h"
#include "../../log/gather.h"
}

#include "../entries_view.h"

#include <QApplication>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL entries_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                              \
	} while (0)

static char top[64];

/* netcfgd.log: a header, then entries 0..4 of one instance and 0..1 of
 * another, at times a second apart starting now. */
static int write_log(void)
{
	static char line[FZN_ENTRY_LINE_MAX];
	char path[128];
	uint64_t now_us = (uint64_t)time(nullptr) * 1000000u;
	FILE *f;
	int k, ok;

	snprintf(path, sizeof(path), "%s/netcfgd.log", top);
	f = fopen(path, "w");
	if (!f)
		return 0;
	ok = fputs("#fuzznet-log 1 machine=00000000000000000000000000000000 host=nabbe\n", f) >= 0;
	for (k = 0; k < 7 && ok; k++) {
		fzn_entry_t e;
		size_t len = 0;

		memset(&e, 0, sizeof(e));
		strcpy(e.name.user, "root");
		strcpy(e.name.program, "netcfgd");
		e.name.pid = k < 5 ? 812u : 900u;
		e.name.start_ms = 1u;
		e.name.position = (uint64_t)(k < 5 ? k : k - 5);
		e.time_us = now_us - 60000000u + ((uint64_t)k * 1000000u);
		e.level = FZN_ENTRY_INFO;
		strcpy(e.subsystem, "apply/exec");
		e.text = (const uint8_t *)"ip link set eth0 up";
		e.text_len = strlen((const char *)e.text);
		ok = fzn_entry_classic(&e, "nabbe", line, sizeof(line), &len) == FZN_ENTRY_OK
		     && fwrite(line, 1u, len, f) == len;
	}
	return (fclose(f) == 0) && ok;
}

static int silent(void *, const uint8_t *, size_t, uint8_t *, size_t, size_t *)
{
	return 0;
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);
	char path[128];

	snprintf(top, sizeof(top), "/tmp/fzn-entries-view-test-XXXXXX");
	if (!mkdtemp(top) || !write_log()) {
		fprintf(stderr, "  FAIL entries_view_test.cpp: no scratch log\n");
		return 1;
	}
	{
		fzn_entries_view w(fzn_entries_view_dir_ask, top);

		w.set_program(QStringLiteral("netcfgd"));
		w.set_short(false);
		CHECK(w.refresh() && w.lines().size() == 7
		              && w.status() == QStringLiteral("7 line(s)."),
		      "the program's seven lines are read from its directory");
		CHECK(w.text().count(QLatin1Char('\n')) == 7
		              && w.text().startsWith(w.lines().value(0) + QLatin1Char('\n')),
		      "shown whole, they are the lines as the file holds them");
		w.set_short(true);
		CHECK(w.text().startsWith(QStringLiteral("-- "))
		              && w.text().contains(QStringLiteral(" #1 I ip link set eth0 up\n"))
		              && w.text().contains(QStringLiteral(" 900@1 #0 I apply/exec ")),
		      "shortened, the date heads them, a repeat shows its position and level, and a "
		      "new instance shows from the instance down");
		CHECK(w.lines().size() == 7, "and the lines themselves are kept whole");

		w.set_match(QStringLiteral("812@1#3"));
		CHECK(w.refresh() && w.lines().size() == 1
		              && w.lines().value(0).contains(QStringLiteral("812@1#3 ")),
		      "a match on an instance field gives that entry");
		w.set_match(QString());
		w.set_since(10u);
		CHECK(w.refresh() && w.lines().isEmpty() && w.status() == QStringLiteral("No lines."),
		      "the last ten seconds hold none of them, and it says so");
		w.set_since(0u);
		w.set_program(QStringLiteral("nothing"));
		CHECK(w.refresh() && w.status() == QStringLiteral("No lines."),
		      "a program with no log has no lines");
		w.set_program(QString());
		CHECK(!w.refresh(), "an empty program is refused");
	}
	{
		fzn_entries_view w(silent, nullptr);

		CHECK(!w.refresh() && w.status() == QStringLiteral("The host did not answer."),
		      "a host that does not answer says so, rather than showing no lines");
	}

	snprintf(path, sizeof(path), "%s/netcfgd.log", top);
	(void)remove(path);
	CHECK(rmdir(top) == 0, "the scratch directory is empty, and goes");

	if (failures) {
		fprintf(stderr, "entries_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("entries_view_test: all %d checks passed\n", checks);
	return 0;
}
