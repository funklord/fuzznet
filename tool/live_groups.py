#!/usr/bin/env python3
"""A group made, learned, administered and left: `make livecheck`, sec 626.

Three stores over loopback, each a user of one machine with an address. A
is a contact of B and of C, by card as live_pairing.py has it; B and C do
not know each other.

    a  A makes the group family and adds B and C; each learns the group from
       A at its next round -- named by its id here, its three members, A
       its admin
    b  A makes B an admin, a majority of one; B's next round says so
    a2 each host names itself in the log, and the epoch's secret is sealed
       to all three, which each come to hold it (sec 627)
    c  C leaves, by an act of its own; A learns it from C at A's next round,
       and the group there has two members
    c2 A and B hold the secret of the epoch C's leave began

Against a daemon that answers no group sync, phase a never learns the
group; against one whose log takes an act made by a member who is not an
admin, nothing here notices -- group_log_test does.

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
from live_rejoin import command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 480.0

KEPT_RE = re.compile(r"a contact request from ([0-9a-f]{16}), waiting")
ROUND_END_RE = re.compile(r"history pass: ")
PREKEY_HOST = slice(4, 68)
ROUNDS = 4


def groups(sock, who):
	"""`who`'s groups, as [(name, count)]."""
	reply = ask(sock, "list group")
	words = reply.split()
	if len(words) < 3 or words[0] != "ok":
		raise failed("%s: list group answered %r" % (who, reply))
	return [(w.split(",")[0], int(w.split(",")[1])) for w in words[3:]]


def members(sock, who, name):
	"""`who`'s members of group `name`, as words."""
	reply = ask(sock, "get group " + name)
	words = reply.split()
	if len(words) < 2 or words[0] != "ok":
		raise failed("%s: get group %s answered %r" % (who, name, reply))
	return words[2:]


def epoch(sock, who, name):
	"""`who`'s current epoch of group `name`, and whether it holds its secret."""
	reply = ask(sock, "get epoch " + name)
	words = reply.split()
	if len(words) != 3 or words[0] != "ok" or not words[1].isdigit():
		raise failed("%s: get epoch %s answered %r" % (who, name, reply))
	return int(words[1]), words[2] == "held"


def main(argv):
	if len(argv) != 2:
		print("usage: live_groups.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 1100 + (os.getpid() % 200) * 4
	port = {"a": str(base), "b": str(base + 1), "c": str(base + 2)}
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
			d.wait_for(ROUND_END_RE, "%s's round" % who.upper())
			return d

		try:
			keys = {}
			for who in port:
				os.mkdir(dirs[who])
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
				keys[who] = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"],
				                    None)[PREKEY_HOST]
			for who in port:
				up(who, who + "0")
				expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who],
				       "ok")

			# A asks B and C by their cards; each approves.
			for who, name in (("b", "bob"), ("c", "carol")):
				card = ask(socks[who], "get card " + name)
				if not card.startswith("ok FZC1:"):
					raise failed("get card at %s answered %r" % (who.upper(), card))
				got = ask(socks["a"], "add contact %s %s" % (name, card.split(" ", 1)[1].strip()))
				if got.strip() != "ok " + keys[who]:
					raise failed("A's add contact %s answered %r" % (name, got))
				started[who].wait_for(KEPT_RE, "%s keeping A's request" % who.upper())
				expect(socks[who], who, "grant request %s alice" % keys["a"], "ok")

			# a: the group, made at A and learned at B and C.
			expect(socks["a"], "a", "add group family", "ok")
			expect(socks["a"], "a", "add member family bob", "ok")
			expect(socks["a"], "a", "add member family carol", "ok")
			if groups(socks["a"], "a") != [("family", 3)]:
				raise failed("a: A's groups are %r" % (groups(socks["a"], "a"),))
			learned = {}
			for rnd in range(ROUNDS):
				for who in ("a", "b", "c"):
					turn(who, "%s-a%d" % (who, rnd))
				for who in ("b", "c"):
					held = groups(socks[who], who)
					if held and held[0][1] == 3:
						learned[who] = held[0][0]
				if len(learned) == 2:
					break
			if len(learned) != 2:
				raise failed("a: after %d rounds the group was learned at %r" % (ROUNDS, learned))
			if learned["b"] != learned["c"] or len(learned["b"]) != 16:
				raise failed("a: B and C named the group %r, not by one id" % (learned,))
			name = learned["b"]
			got = members(socks["b"], "b", name)
			if "*alice" not in got or len(got) != 3:
				raise failed("a: B's members of the group are %r, not three with A admin" % got)
			print("livecheck: a: A made the group, and B and C learned it from A, A its admin")

			# a2: each host named in the log, and the epoch's secret sealed to
			# all three (sec 627).
			names = {"a": "family", "b": name, "c": name}
			for rnd in range(ROUNDS):
				got = {who: epoch(socks[who], who, names[who]) for who in port}
				if all(h for _, h in got.values()) and len({e for e, _ in got.values()}) == 1:
					break
				for who in ("a", "b", "c"):
					turn(who, "%s-k%d" % (who, rnd))
			got = {who: epoch(socks[who], who, names[who]) for who in port}
			if not all(h for _, h in got.values()) or len({e for e, _ in got.values()}) != 1:
				raise failed("a2: the epochs held are %r, not one epoch held by all" % (got,))
			first_epoch = got["a"][0]
			print("livecheck: a2: A, B and C each hold epoch %d's secret" % first_epoch)

			# b: B made an admin, a majority of one.
			expect(socks["a"], "a", "add admin family bob", "ok")
			for rnd in range(ROUNDS):
				turn("a", "a-b%d" % rnd)
				turn("b", "b-b%d" % rnd)
				got = members(socks["b"], "b", name)
				if "*" + keys["b"] in got:
					break
			if "*" + keys["b"] not in got:
				raise failed("b: B's members are %r, B not marked admin" % got)
			print("livecheck: b: A made B an admin, and B's round says so")

			# c: C leaves; A learns it from C.
			expect(socks["c"], "c", "remove group " + name, "ok")
			if groups(socks["c"], "c"):
				raise failed("c: C still holds %r" % (groups(socks["c"], "c"),))
			# C'S LEAVE MAY LOSE A FORK to A's admin act, which C never
			# had: C's round meets it at A and makes its leave again.
			for rnd in range(ROUNDS):
				turn("a", "a-c%d" % rnd)
				if groups(socks["a"], "a") == [("family", 2)]:
					break
				turn("c", "c-c%d" % rnd)
				if groups(socks["c"], "c"):
					raise failed("c: C holds %r again after a round"
					             % (groups(socks["c"], "c"),))
				turn("a", "a-c%db" % rnd)
				if groups(socks["a"], "a") == [("family", 2)]:
					break
			if groups(socks["a"], "a") != [("family", 2)]:
				told = [l[-170:] for l in started["a"].log().splitlines()
				        if any(w in l for w in ("group", "refused", "node/peer", "contact"))]
				raise failed("c: A's groups are %r, C's leave not learned%s"
				             % (groups(socks["a"], "a"), "".join("\n  " + l for l in told[-12:])))
			redone = any("lost a fork" in d.log() for d in started.values())
			print("livecheck: c: C left, and A learned it from C%s"
			      % (" -- the leave lost a fork to A's admin act and was made again"
			         if redone else ""))

			# c2: A and B hold the epoch C's leave began; C was never given it.
			for rnd in range(ROUNDS):
				got = {who: epoch(socks[who], who, names[who]) for who in ("a", "b")}
				if all(h for _, h in got.values()) and got["a"][0] == got["b"][0] > first_epoch:
					break
				turn("a", "a-k2%d" % rnd)
				turn("b", "b-k2%d" % rnd)
			got = {who: epoch(socks[who], who, names[who]) for who in ("a", "b")}
			if not (all(h for _, h in got.values()) and got["a"][0] == got["b"][0] > first_epoch):
				raise failed("c2: after C left the epochs held are %r" % (got,))
			print("livecheck: c2: A and B hold epoch %d's secret, begun by C's leave"
			      % got["a"][0])
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
	print("livecheck: a group was made, learned by its members, administered and left")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
