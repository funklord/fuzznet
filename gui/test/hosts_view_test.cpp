/*
 * hosts_view_test -- this user's other hosts on a widget, sec 1124, against
 * a scripted node behind the ask callback: two hosts listed, one with no
 * address said so, an address set on the chosen host by its key, a malformed
 * address refused unasked, a host made an admin with its chain shown and
 * whom this host granted named (sec 1157), a chain applied and a bad one
 * refused, and a node that does not answer.
 */

#include "../hosts_view.h"

#include <QApplication>
#include <QLabel>
#include <QPushButton>

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

#define ROOT "0c0c000000000000000000000000000000000000000000000000000000000003"

static int silent, resets;
static char last[200];
static int granted;

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (silent)
		return 0;
	/* ADMIN, sec 1157: the phone granted, the grants listed, a chain kept. */
	if (!strcmp(line, "grant admin " PHONE)) {
		granted = 1;
		return (size_t)snprintf(reply, cap, "ok h1 aaaa bbbb cccc\n");
	}
	/* A SHARE GRANT THAT LAPSED, and a read that fails (sec 1542). */
	if (!strcmp(line, "list grant 0") && granted == 2)
		return (size_t)snprintf(reply, cap, "ok 1 0 " PHONE ",share,1700000000,1\n");
	if (!strcmp(line, "list grant 0") && granted == 3)
		return (size_t)snprintf(reply, cap, "error the store refused\n");
	if (!strcmp(line, "list grant 0"))
		return granted ? (size_t)snprintf(reply, cap, "ok 2 0 " PHONE ",admin,0,1 %064d,admin,0,0\n", 5)
		               : (size_t)snprintf(reply, cap, "ok 0 0\n");
	if (!strcmp(line, "set admin h1 dddd eeee"))
		return (size_t)snprintf(reply, cap, "ok\n");
	if (!strncmp(line, "set admin ", 10))
		return (size_t)snprintf(reply, cap, "malformed that chain does not verify\n");
	if (!strcmp(line, "list sibling 0"))
		return (size_t)snprintf(reply, cap, "ok 2 0 %s,192.0.2.4:4000,paired,9,phone %s,-,unpaired,-,desk\n",
		                        PHONE, DESK);
	/* WHO THIS HOST IS, for its reset (sec 1215): desk, of the user ROOT. */
	if (!strcmp(line, "get identity"))
		return (size_t)snprintf(reply, cap, "ok %s %s\n", DESK, ROOT);
	if (!strcmp(line, "get setting host host/name"))
		return (size_t)snprintf(reply, cap, "ok host desk\n");
	/* WHAT THIS HOST HOLDS, sec 1505: member usable, admin not verifying,
	 * to lapse on 2030-01-01. */
	if (!strcmp(line, "list capability"))
		return (size_t)snprintf(reply, cap, "ok 2 member,1,1,0 admin,0,2,1893456000\n");
	if (!strcmp(line, "get message owed"))
		return (size_t)snprintf(reply, cap, "ok 0 0 0\n");
	if (!strcmp(line, "get node"))
		return (size_t)snprintf(reply, cap, "ok udp 4000 started 1\n");
	if (!strcmp(line, "remove identity " DESK)) {
		resets++;
		return (size_t)snprintf(reply, cap, "ok 12\n");
	}
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

	/* WHAT THIS HOST HOLDS, sec 1505, read with the host itself. */
	CHECK(v.refresh() && v.held() == "This host holds: member (usable), admin (does not verify) until 2030-01-01.",
	      "what this host holds, and whether each is usable, was not said");

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
	/* WHAT IS BEING TYPED SURVIVES A POLL (sec 1515). */
	v.set_address_text("10.0.0.");
	CHECK(v.refresh() && v.address_text() == "10.0.0.", "a refresh wiped the address being typed");
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

	/* ADMIN, sec 1157: the phone made an admin and its chain shown; whom this
	 * host granted, named as its hosts, one no longer a host by its key and
	 * revoked; a chain given to this host applied, and a bad one refused. */
	CHECK(v.refresh() && v.granted().isEmpty(), "a host that granted nothing listed a grant");
	v.select(0);
	CHECK(v.make_admin() && v.granted_chain() == "h1 aaaa bbbb cccc" && v.status().contains("phone is granted admin")
	              && v.granted() == QStringList({ "admin to phone, never lapsing",
	                                              "admin to 0000000000000000, never lapsing, revoked as far as this "
	                                              "host has heard" }),
	      "a host made an admin did not show its chain, or the grants were not named");
	/* EVERY AUTHORITY ISSUED (sec 1542): a share grant, lapsed, said with
	 * its date; a read that fails said so, not as none. */
	granted = 2;
	CHECK(v.refresh() && v.granted().size() == 1 && v.granted().value(0).startsWith("share to phone, lapsed 20"),
	      "a grant of another capability, lapsed, was not listed with its date");
	granted = 3;
	CHECK(v.refresh() && v.granted().isEmpty(), "fixture: the grants unread");
	{
		bool said = false;
		for (QLabel *l : v.findChildren<QLabel *>())
			said = said || l->text().startsWith("What this host has granted could not be read");
		CHECK(said, "a failed read of the grants was shown as none");
	}
	granted = 1;
	v.set_chain_text("h1 dddd eeee");
	CHECK(v.apply_chain() && v.status().startsWith("Applied"), "a chain given to this host was not applied");
	v.set_chain_text("h1 ffff");
	CHECK(!v.apply_chain() && v.status() == "that chain does not verify", "a bad chain was not refused in the node's words");
	v.set_chain_text("");
	CHECK(!v.apply_chain(), "an empty chain was applied");

	/* RESET, sec 1215: not until the host's name is typed in full; then
	 * its keys wiped and its node stopped, said. */
	{
		QPushButton *reset = nullptr;

		for (QPushButton *b : v.findChildren<QPushButton *>())
			if (b->text() == "Reset this host")
				reset = b;
		CHECK(v.refresh() && v.reset_phrase() == "desk" && reset && !reset->isEnabled(),
		      "the reset was offered before anything was typed, or its phrase was not the host's name");
		v.set_reset_text("des");
		CHECK(!reset->isEnabled() && !v.reset_host() && !resets && v.status().contains("Type this host's name"),
		      "a reset went ahead on part of the host's name");
		v.set_reset_text("Desk");
		CHECK(!reset->isEnabled() && !v.reset_host() && !resets, "a reset went ahead on the name in another case");
		v.set_reset_text("desk");
		CHECK(reset->isEnabled() && v.reset_host() && resets == 1
		              && v.status() == "This host was reset: 12 file(s) wiped, and its node has stopped.",
		      "the reset, its name typed in full, was not done and said");
	}

	silent = 1;
	CHECK(!v.refresh() && v.status() == "The node did not answer.", "a silent node was not said so");

	/* NO WIDER THAN A 320 px SCREEN, sec 1503: a phone's cover screen. */
	CHECK(v.minimumSizeHint().width() <= 320, "the view is wider than a 320 px cover screen");
	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui hosts_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui hosts_view_test: all %d checks passed\n", checks);
	return 0;
}
