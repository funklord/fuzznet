#!/usr/bin/env python3
"""A group reached through a member's second host: `make livecheck`, secs
641 to 643.

Four stores over loopback. A is a contact of B and of C, as live_groups.py
has them; B2 is a second device of B's user, joined to B's estate by verbs
(sec 638). C is not B's contact.

    a  A makes the group family of A, B and C; B, B2 and C learn it --
       B2 from B, so B names itself in the group's log before B2 does --
       and C's share pass comes to ask all three member hosts, A's, B's and
       B2's
    b  B is stopped. B2 writes a note and shares it with the group; C,
       which learns B2's place in the log through A and lists B first for
       B's user, pulls the note from B2 into B's user's tree
    c  A is stopped too. B2, a host of B's user, whom A made an admin,
       sets the group's backfill off; C takes the act from B2 itself
    d  B2 writes a line to the group; C files it, as B's user's, from B2

Against a daemon that syncs a group's log only with contacts' hosts and
the estate's, phase c never takes B2's act: nobody else is up to carry it;
against one that asks a group's lines the same way, phase d never files
B2's line.
Against a daemon that asks one host per member -- the first its group
lists, as sec 630 did -- C asks two hosts and phase a fails; and were it
let through, phase b would never pull B2's note: B is the one asked, and B
is gone.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import re
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
from live_groups import KEPT_RE, PREKEY_HOST, groups, members  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 800.0

ROUNDS = 6
TAKEN_RE = re.compile(r"group pass: (\d+) act\(s\) taken")
ASKED_RE = re.compile(r"group share pass: (\d+) member host\(s\) asked")
TITLE = "b2-note"


def main(argv):
	if len(argv) != 2:
		print("usage: live_group_hosts.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 32000 + (os.getpid() % 150) * 4
	port = {"a": str(base), "b": str(base + 1), "c": str(base + 2), "b2": str(base + 3)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}

		def up(who, tag):
			started[who] = daemon(run, tag, dirs[who], socks[who],
			                      extra=["--udp-port=" + port[who]])
			return started[who]

		def turn(who, tag):
			if who in started:
				started.pop(who).stop()
			d = up(who, tag)
			d.wait_for(ROUND_DONE_RE, "%s's round" % who.upper(), within=60.0)
			return d

		try:
			keys = {}
			for who in ("a", "b", "c"):
				os.mkdir(dirs[who])
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
				keys[who] = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"],
				                    None)[PREKEY_HOST]
			os.mkdir(dirs["b2"])
			for who in port:
				up(who, who + "0")
				expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who],
				       "ok")

			# B2 JOINS B's estate by verbs, as live_join.py has it.
			got = ask(socks["b2"], "get prekey").split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("setup: B2's get prekey answered %r" % got)
			card = ask(socks["b"], "add peer %s delegable" % got[1]).split()
			if len(card) != 2 or card[0] != "ok":
				raise failed("setup: B's add peer answered %r" % card)
			card_path = os.path.join(scratch, "card")
			with open(card_path, "w") as f:
				f.write(card[1] + "\n")
			joined = ask(socks["b2"], "add join %s 127.0.0.1 %s" % (card_path, port["b"]))
			if not joined.startswith("ok "):
				raise failed("setup: B2's add join answered %r" % joined)
			deadline = time.monotonic() + 20.0
			while time.monotonic() < deadline:
				try:
					if ask(socks["b2"], "status").startswith("ok "):
						break
				except OSError:
					pass
				time.sleep(0.2)
			else:
				raise failed("setup: B2's socket did not come back after the join")

			# A asks B and C by their cards; each approves.
			for who, name in (("b", "bob"), ("c", "carol")):
				card = ask(socks[who], "get card " + name)
				if not card.startswith("ok FZC1:"):
					raise failed("setup: get card at %s answered %r" % (who.upper(), card))
				got = ask(socks["a"], "add contact %s %s" % (name, card.split(" ", 1)[1].strip()))
				if got.strip() != "ok " + keys[who]:
					raise failed("setup: A's add contact %s answered %r" % (name, got))
				started[who].wait_for(KEPT_RE, "%s keeping A's request" % who.upper())
				expect(socks[who], who, "grant request %s alice" % keys["a"], "ok")
			print("livecheck: setup: B2 joined B's estate, and A is B's and C's contact")

			# a: the group, learned at B, B2 and C, every host named in its log
			# -- B before B2, so B is the host a one-host pass asks.
			expect(socks["a"], "a", "add group family", "ok")
			expect(socks["a"], "a", "add member family bob", "ok")
			expect(socks["a"], "a", "add member family carol", "ok")
			# B AN ADMIN, a majority of one, so B2 can act for B's user in c.
			expect(socks["a"], "a", "add admin family bob", "ok")
			name = None
			order = ("a", "b", "c", "b2")
			for rnd in range(ROUNDS):
				for who in order:
					turn(who, "%s-a%d" % (who, rnd))
				held = {who: groups(socks[who], who) for who in ("b", "b2", "c")}
				if all(h and h[0][1] == 3 for h in held.values()):
					name = held["c"][0][0]
					break
			if not name:
				raise failed("a: the group was learned at %r"
				             % ({w: groups(socks[w], w) for w in ("b", "b2", "c")},))
			got = members(socks["c"], "c", name)
			if len(got) != 3:
				raise failed("a: C's members of the group are %r" % got)
			# a2: C KNOWS B2 among the group's hosts -- its share pass asks A's,
			# B's and B2's. Waited for while B still runs: with B gone, nothing
			# carries B2's place in the log to C (A knows B's devices from B),
			# and a fork can make B2 name itself again late.
			asked = 0
			for rnd in range(ROUNDS):
				for who in ("a", "b", "b2", "c"):
					turn(who, "%s-k%d" % (who, rnd))
				got = ASKED_RE.findall(started["c"].log())
				asked = int(got[-1]) if got else 0
				if asked >= 3:
					break
			if asked < 3:
				raise failed("a2: C's share pass asks %d member host(s), not A's, B's and "
				             "B2's%s" % (asked, tail(started["c"], ("group",))))
			print("livecheck: a: B, B2 and C learned the group, and C asks all three "
			      "member hosts")

			# b: B gone; B2 shares a note with the group; C pulls it from B2.
			started.pop("b").stop()
			b2_name = groups(socks["b2"], "b2")[0][0]
			note = ask(socks["b2"], "add note top " + TITLE)
			if not note.startswith("ok "):
				raise failed("b: B2's add note answered %r" % note)
			expect(socks["b2"], "b2", "add share %s @%s" % (note.split()[1], b2_name), "ok")
			found = False
			for rnd in range(ROUNDS):
				# A TOO: B2's act naming it reaches C only through A, C's
				# one contact -- group acts go to a contact's hosts and the
				# estate's, never to a member's host (sec 626).
				for who in ("b2", "a", "c"):
					turn(who, "%s-b%d" % (who, rnd))
				if pulled(socks["c"], TITLE):
					found = True
					break
			if not found:
				raise failed("b: C never holds B2's note; C's sharers %r%s"
				             % (ask(socks["c"], "list sharer").strip(),
				                tail(started["c"], ("group", "received", "refused", "node/peer"))))
			print("livecheck: b: with B gone, C pulled B2's note from B2")

			# c: A gone too; B2, for B's user an admin, sets the group's
			# backfill off, and C takes the act -- from B2, the only host of
			# the group still up, which is neither C's contact nor its
			# estate's (sec 642).
			started.pop("a").stop()
			expect(socks["b2"], "b2", "set group %s backfill 0" % b2_name, "ok")
			taken = None
			for rnd in range(ROUNDS):
				for who in ("b2", "c"):
					turn(who, "%s-c%d" % (who, rnd))
				taken = TAKEN_RE.search(started["c"].log())
				if taken:
					break
			if not taken:
				raise failed("c: with A and B gone, C took no act of B2's%s"
				             % tail(started["c"], ("group",)))
			print("livecheck: c: with A and B gone, C took B2's act from B2 itself")

			# d: still with A and B gone, B2 writes a line to the group and C
			# files it as B's user's -- asked of B2 itself (sec 643).
			def has_line(text):
				reply = ask(socks["c"], "list message @" + name)
				return any(item.split(",")[1] == "@%s:%s" % (name, keys["b"][:16])
				           and item.endswith("," + text)
				           for item in reply.split()[4:] if item.count(",") >= 8)

			expect(socks["b2"], "b2", "add message @%s out %s from_b2" % (b2_name, "d2" * 16),
			       "ok")
			filed = False
			for rnd in range(ROUNDS):
				for who in ("b2", "c"):
					turn(who, "%s-d%d" % (who, rnd))
				if has_line("from_b2"):
					filed = True
					break
			if not filed:
				raise failed("d: C never files B2's line; C lists %r; B2's epoch %r%s"
				             % (ask(socks["c"], "list message @" + name).strip(),
				                ask(socks["b2"], "get epoch " + b2_name).strip(),
				                tail(started["c"], ("group", "lines", "refused", "denied"))))
			print("livecheck: d: with A and B gone, C filed B2's line, as B's user's")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started.values():
				d.stop()
			for pid in run.started:
				if os.path.exists("/proc/%d" % pid):
					try:
						with open("/proc/%d/cmdline" % pid, "rb") as f:
							alive = run.fuzznetd.encode() in f.read()
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: a group was reached through a member's second host")
	return 0


def pulled(sock, title):
	"""Whether `title` is in some sharer's tree held at `sock`."""
	words = ask(sock, "list sharer").split()
	for row in words[3:]:
		key = row.split(",")[0]
		if title in ask(sock, "list shared %s top" % key):
			return True
	return False


def tail(d, words):
	told = [l[-200:] for l in d.log().splitlines() if any(w in l for w in words)]
	return "".join("\n  " + l for l in told[-12:])


if __name__ == "__main__":
	sys.exit(main(sys.argv))
