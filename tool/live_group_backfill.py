#!/usr/bin/env python3
"""A group share that does not catch up a later member: `make livecheck`,
sec 655.

Two stores over loopback, A and C, contacts by card as live_groups.py has
them. A makes the group family alone.

    a  A shares folder S0 with the group `backfill 0`, and folder S1
       `backfill 1`, each holding a note; `list share` says which is which
    b  A adds C, a second after the shares were made, and then writes a
       second note into S0. C, a later member, holds S1 and its note, and
       S0's second note -- and neither S0 nor the note it held before C
       joined

Against a daemon that reads a group share's reach at the request alone, as
sec 471 did, phase b finds S0 and its first note at C.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
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

live_trim.DEADLINE = time.monotonic() + 420.0

ROUNDS = 6


def main(argv):
	if len(argv) != 2:
		print("usage: live_group_backfill.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 32620 + (os.getpid() % 30) * 2
	port = {"a": str(base), "c": str(base + 1)}
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

		def made(who, line):
			got = ask(socks[who], line).split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("%s: %s answered %r" % (who.upper(), line, got))
			return got[1]

		def titles(parent):
			"""C's listing of A's tree under `parent`, as text."""
			return ask(socks["c"], "list shared alice " + parent)

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
			card = ask(socks["c"], "get card carol")
			if not card.startswith("ok FZC1:"):
				raise failed("setup: get card answered %r" % card)
			got = ask(socks["a"], "add contact carol " + card.split(" ", 1)[1].strip())
			if got.strip() != "ok " + keys["c"]:
				raise failed("setup: add contact answered %r" % got)
			started["c"].wait_for(KEPT_RE, "C keeping A's request")
			expect(socks["c"], "c", "grant request %s alice" % keys["a"], "ok")
			made("a", "add group family")
			print("livecheck: setup: A and C are contacts, and A made the group alone")

			# a: two shares with the group, one catching up and one not.
			s0 = made("a", "add folder top s0-folder")
			made("a", "add note %s s0-before" % s0)
			s1 = made("a", "add folder top s1-folder")
			made("a", "add note %s s1-before" % s1)
			expect(socks["a"], "a", "add share %s @family backfill 0" % s0, "ok")
			expect(socks["a"], "a", "add share %s @family backfill 1" % s1, "ok")
			rows = ask(socks["a"], "list share").split()
			if rows[:3] != ["ok", "2", "0"] or set(rows[3:]) != {s0 + ",@family,0",
			                                                     s1 + ",@family,1"}:
				raise failed("a: A's list share answered %r" % rows)
			print("livecheck: a: A shared S0 not catching up and S1 catching up")

			# b: C joins a second later; A writes into S0 after.
			time.sleep(1.5)
			expect(socks["a"], "a", "add member family carol", "ok")
			time.sleep(1.5)
			made("a", "add note %s s0-after" % s0)
			ok = False
			for rnd in range(ROUNDS):
				for who in ("a", "c"):
					turn(who, "%s-b%d" % (who, rnd))
				top = titles("top")
				if "s0-after" in top and "s1-folder" in top and "s1-before" in titles(s1):
					ok = True
					break
			top = titles("top")
			if not ok:
				raise failed("b: C's top of A's tree is %r, and S1 holds %r"
				             % (top.strip(), titles(s1).strip()))
			if "s0-folder" in top or "s0-before" in top or "s0-before" in titles(s0):
				raise failed("b: C, a later member, holds what S0 held before it joined: %r"
				             % top.strip())
			print("livecheck: b: C, joining later, got S1 whole and S0 only from its joining")
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
	print("livecheck: a group share kept from a later member what came before it")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
