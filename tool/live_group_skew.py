#!/usr/bin/env python3
"""A later member's floor where the adder's clock is wrong: sec 719 stage 4.

Run against `make fuzznetd-faults`' daemon, whose rounds FZN_TUNE_PULL_EVERY
makes short. Four stores over loopback: A, which shares and adds, its clock
900 s behind by faketime; B and X, devices of A's estate on time, so that A
measures its own clock wrong against two; and C, a contact, another user's.

    a  A and C are contacts, B and X join A's estate, and A says its own
       clock is wrong against two devices
    b  A shares folder S0 with the group `backfill 0`; B writes a note into
       S0, which A then holds
    c  A adds C to the group, and then writes a second note into S0. C
       holds A's second note, and not B's, written before C joined
    d  C sends two lines. B, on time, marks the first read; then A marks
       the second. Both read the conversation as read through: the later
       mark wins although its device's clock is behind

A later member's floor is the time of the act that added it, stamped by the
adder's clock, and each note's time is its writer's. With A's acts on A's own
clock, the floor sat 900 s early, B's earlier note passed it, and C read what
was written before it joined -- a privacy fault, not a timing one. On estate
time the adder's clock is corrected, and the note is withheld.

The user's read marks are its devices' too, and the newest stamp wins. A
mark made later on A, stamped by a clock 900 s behind, lost to B's earlier
one, and the conversation stayed unread where it had been read.

BOUNDED FROM INSIDE as live_estate.py is: one deadline, each daemon in its own
process group, and every daemon checked gone.

Exit 0 on a pass, 1 on a failure, 0 with SKIPPED when faketime is absent.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
from live_groups import KEPT_RE, PREKEY_HOST  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 600.0

# ROUNDS OF TWO SECONDS, the fault build's knob (sec 693).
ROUND_S = "2"
SKEW = "-900s"
WHO = ("a", "b", "x", "c")
SETTLE = 120.0


def main(argv):
	if len(argv) != 2:
		print("usage: live_group_skew.py PATH_TO_FAULTS_FUZZNETD", file=sys.stderr)
		return 2
	if not shutil.which("faketime"):
		print("livecheck: group skew SKIPPED -- needs faketime on PATH")
		return 0

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 41000 + (os.getpid() % 500) * 8
	port = {k: str(base + i) for i, k in enumerate(WHO)}
	os.environ["FZN_TUNE_PULL_EVERY"] = ROUND_S
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in WHO}
		socks = {k: os.path.join(sock_dir, k) for k in WHO}
		started = {}

		def up(who):
			started[who] = daemon(run, who, dirs[who], socks[who],
			                      fake=SKEW if who == "a" else None,
			                      extra=["--udp-port=" + port[who]])
			return started[who]

		def said(who, line):
			return ask(socks[who], line).strip()

		def polled(who, line, test, what):
			until = time.monotonic() + SETTLE
			while True:
				got = said(who, line)
				if test(got):
					return got
				if time.monotonic() > until:
					raise failed("%s: %s answered %r, %s" % (who, line, got, what))
				time.sleep(0.5)

		def made(who, line):
			got = said(who, line).split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("%s: %s answered %r" % (who, line, got))
			return got[1]

		def back_in_place(who, pid):
			until = time.monotonic() + 30.0
			while time.monotonic() < until:
				try:
					if said(who, "status").startswith("ok "):
						break
				except OSError:
					pass
				time.sleep(0.2)
			else:
				raise failed("%s: the socket did not come back after the join" % who)
			if started[who].proc.poll() is not None or started[who].proc.pid != pid:
				raise failed("%s: did not start again in place after the join" % who)

		def join(who):
			"""`who`, a fresh daemon, joins A's estate by a card A answers."""
			os.mkdir(dirs[who])
			up(who)
			got = said(who, "get prekey").split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("%s: get prekey answered %r" % (who, got))
			card = said("a", "add peer %s delegable" % got[1]).split()
			if len(card) != 2 or card[0] != "ok":
				raise failed("a: add peer for %s answered %r" % (who, card))
			path = os.path.join(scratch, "card-" + who)
			with open(path, "w") as f:
				f.write(card[1] + "\n")
			pid = started[who].proc.pid
			joined = said(who, "add join " + path).split()
			if len(joined) != 2 or joined[0] != "ok":
				raise failed("%s: add join answered %r" % (who, joined))
			back_in_place(who, pid)
			polled(who, "list capability", lambda g: "member,1,1,0" in g.split()[2:],
			       "not member held by one hop")
			expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who], "ok")

		try:
			# a: the contacts, the estate, and A's clock said to be wrong.
			for who in ("a", "c"):
				os.mkdir(dirs[who])
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"],
				        SKEW if who == "a" else None)
			keys = {"c": command(run, ["--fuzznet-dir=" + dirs["c"], "--prekey"],
			                     None)[PREKEY_HOST]}
			for who in ("a", "c"):
				up(who).wait_for(ROUND_DONE_RE, "%s's first round" % who.upper())
				expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who],
				       "ok")
			keys["a"] = said("a", "get prekey").split()[1][PREKEY_HOST]
			card = said("c", "get card carol")
			if not card.startswith("ok FZC1:"):
				raise failed("a: C's get card answered %r" % card)
			got = said("a", "add contact carol " + card.split(" ", 1)[1])
			if got != "ok " + keys["c"]:
				raise failed("a: A's add contact answered %r" % got)
			started["c"].wait_for(KEPT_RE, "C keeping A's request")
			expect(socks["c"], "c", "grant request %s alice" % keys["a"], "ok")
			for who in ("b", "x"):
				join(who)
			made("a", "add group family")
			polled("a", "get clock", lambda g: g.split()[2:] == ["2", "wrong"],
			       "not wrong against two devices")
			print("livecheck: a: A and C are contacts, B and X joined A's estate, and A's "
			      "clock is wrong against two")

			# b: a share not catching up, and B's note in it.
			s0 = made("a", "add folder top s0-folder")
			expect(socks["a"], "a", "add share %s @family backfill 0" % s0, "ok")
			polled("b", "list note top", lambda g: "s0-folder" in g, "without S0")
			made("b", "add note %s b-before" % s0)
			polled("a", "list note " + s0, lambda g: "b-before" in g, "without B's note")
			print("livecheck: b: A shared S0 not catching up, and holds B's note in it")

			# c: C added after, then A writes; C reads A's later note alone.
			time.sleep(2.0)
			expect(socks["a"], "a", "add member family carol", "ok")
			time.sleep(2.0)
			made("a", "add note %s a-after" % s0)
			got = polled("c", "list shared alice " + s0, lambda g: "a-after" in g,
			             "without A's note written after C joined")
			if "b-before" in got:
				raise failed("c: C, a later member, holds B's note written before it "
				             "joined: %r" % got)
			print("livecheck: c: C holds A's note written after it joined, and not B's "
			      "from before")

			# d: read marks across the user's devices, the later one A's.
			# ONE AT A TIME: a conversation's order is the order its lines
			# are filed in, and two sent 13 ms apart were filed either way,
			# so the second goes once both devices hold the first.
			lines = ("d1" * 16, "d2" * 16)
			for i, line in enumerate(lines):
				expect(socks["c"], "c", "add message alice out %s line%d" % (line, i), "ok")
				for who in ("a", "b"):
					polled(who, "get message carol unread",
					       lambda g, n=str(i + 1): g.split()[1:2] == [n],
					       "not C's line%d unread" % i)
			expect(socks["b"], "b", "set message carol read " + lines[0], "ok")
			for who in ("a", "b"):
				try:
					polled(who, "get message carol unread",
					       lambda g: g.split()[1:2] == ["1"], "not B's mark of the first line")
				except failed as e:
					raise failed("%s; A lists %r, B lists %r"
					             % (e, said("a", "list message carol"),
					                said("b", "list message carol")))
			time.sleep(2.0)
			expect(socks["a"], "a", "set message carol read " + lines[1], "ok")
			for who in ("a", "b"):
				polled(who, "get message carol unread", lambda g: g.split()[1:2] == ["0"],
				       "not A's later mark of the second: an earlier one by an on-time "
				       "clock still wins")
			print("livecheck: d: A's mark, made after B's, won on both, its clock 900 s behind")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			for name in sorted(os.listdir(scratch)):
				if name.endswith(".err"):
					with open(os.path.join(scratch, name), errors="replace") as f:
						tail = f.read().splitlines()[-8:]
					print("livecheck: --- %s" % name)
					for line in tail:
						print("livecheck:     %s" % line)
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
	print("livecheck: a later member's floor held, the adder's clock 900 s behind")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
