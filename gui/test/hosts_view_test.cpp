/*
 * hosts_view_test -- this user's other hosts on a widget, sec 1124, against
 * a scripted node behind the ask callback: two hosts listed, one with no
 * address said so, an address set on the chosen host by its key, a malformed
 * address refused unasked, and a node that does not answer.
 */

#include "../hosts_view.h"

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                    \
	do {                                                                                 \
		checks++;                                                                    \
		if (!(cond)) {                                                               \
			failures++;                                                          \
			fprintf(stderr, "  FAIL hosts_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                            \
	} while (0)

#define PHONE "0a0a000000000000000000000000000000000000000000000000000000000001"
#define DESK "0b0b000000000000000000000000000000000000000000000000000000000002"

static int silent;
static char last[200];

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	if (!strcmp(line, "list sibling 0"))
		return (size_t)snprintf(reply, cap, "ok 2 0 %s,192.0.2.4:4000,paired,9,phone %s,-,unpaired,-,desk\n",
		                        PHONE, DESK);
	snprintf(last, sizeof last, "%s", line);
	/* A BACKUP: three files, or a directory that is not empty refused. */
	if (!strcmp(line, "put backup /tmp/fzn-hosts-backup-test"))
		return (size_t)snprintf(reply, cap, "ok 3\n");
	if (!strncmp(line, "put backup ", 11))
		return (size_t)snprintf(reply, cap, "denied the directory is not empty\n");
	return (size_t)snprintf(reply, cap, "ok\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_hosts_view v(node, nullptr);

	CHECK(v.refresh()
	              && v.rows() == QStringList({ "phone | 0a0a000000000000 | 192.0.2.4:4000 | yes",
	                                           "desk | 0b0b000000000000 | not known | no" }),
	      "the hosts were not listed with their keys, addresses and pairing");

	v.select(1);
	CHECK(v.address_text().isEmpty(), "a host with no address offered one");
	v.set_address_text("198.51.100.7:4000");
	CHECK(v.set_address() && !strcmp(last, "set setting host=" DESK " net/address 198.51.100.7 4000")
	              && v.status() == "desk is reached at 198.51.100.7:4000 now.",
	      "the address was not set on the chosen host by its key");
	v.select(0);
	CHECK(v.address_text() == "192.0.2.4:4000", "the chosen host's address was not offered");
	v.set_address_text("nowhere");
	last[0] = '\0';
	CHECK(!v.set_address() && !last[0] && v.status().contains("HOST:PORT"),
	      "an address of the wrong shape was asked");

	/* A BACKUP, sec 1133: where said, how much said; a refusal in the node's
	 * words; no directory, nothing asked. */
	CHECK(v.back_up("/tmp/fzn-hosts-backup-test") && !strcmp(last, "put backup /tmp/fzn-hosts-backup-test")
	              && v.status().startsWith("Backed up: 3 file(s)"),
	      "the backup was not asked into the directory given, or not said");
	CHECK(!v.back_up("/tmp") && v.status() == "the directory is not empty",
	      "a refused backup lost the node's words");
	last[0] = '\0';
	CHECK(!v.back_up("  ") && !last[0] && v.status().startsWith("Say which empty directory"),
	      "a backup with no directory was asked, or not said why");

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui hosts_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui hosts_view_test: all %d checks passed\n", checks);
	return 0;
}
