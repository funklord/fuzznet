#!/usr/bin/env python3
"""An estate joined by verbs on running daemons: `make livecheck`, sec 638.

Two stores over loopback: A the root of its estate, B a fresh device. Both
run as daemons throughout, and the join is made by local verbs alone, as a
client drives it -- no one-shot command, no daemon stopped by its client.

    a  B answers `get prekey` with its prekey record; A, given it with
       `add peer RECORD delegable`, answers a card
    b  B, given `add join PATH HOST PORT` -- the card in a file --, answers A's key and starts
       again in place -- the same process, its socket back -- and its
       first round reads a setting A made before B joined
    c  B started again with no `--root-at` still pulls from A, where the
       join kept it, and reads a second setting A makes

Against a daemon whose `add join` did not start it again, phase b's round
never reads A's setting; against one that kept no address, phase c's.

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
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 300.0

# A KEY ON THE STATUS LINE: what `add join` answers, the root's.
KEY_LEN = 64


def main(argv):
	if len(argv) != 2:
		print("usage: live_join.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 1024 + (os.getpid() % 19) * 4
	port = {"a": str(base), "b": str(base + 1)}
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

		def round_done(who, what, within=60.0):
			"""The first round's end of `who`'s current run."""
			return started[who].wait_for(ROUND_DONE_RE, what, within=within)

		def setting(who, key):
			reply = ask(socks[who], "get setting estate " + key).strip()
			return reply

		def reads(who, key, within=90.0):
			"""Whether `who` comes to read `key` as A set it, within `within`.
			Polled rather than waited on a round's end: a run started again in
			place keeps its pid, so the round ends logged before it still match."""
			until = time.monotonic() + within
			while time.monotonic() < until:
				if setting(who, key) == "ok root 1":
					return True
				time.sleep(0.5)
			return False

		try:
			for who in port:
				os.mkdir(dirs[who])
			command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
			up("a", "a1")
			round_done("a", "A's first round")
			expect(socks["a"], "a", "set setting estate x/before 1", "ok")
			up("b", "b1")

			# a: B's prekey, and A's card for it.
			got = ask(socks["b"], "get prekey").split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("a: get prekey answered %r" % got)
			card = ask(socks["a"], "add peer %s delegable" % got[1]).split()
			if len(card) != 2 or card[0] != "ok":
				raise failed("a: add peer ... delegable answered %r" % card)
			print("livecheck: a: B said its prekey, and A answered a card for it")

			# b: B joins, by a verb, and starts again in place.
			pid = started["b"].proc.pid
			# THE CARD IN A FILE: it is longer than a request line.
			card_path = os.path.join(scratch, "card")
			with open(card_path, "w") as f:
				f.write(card[1] + "\n")
			joined = ask(socks["b"], "add join %s 127.0.0.1 %s" % (card_path, port["a"])).split()
			if len(joined) != 2 or joined[0] != "ok" or len(joined[1]) != KEY_LEN:
				raise failed("b: add join answered %r" % joined)
			deadline = time.monotonic() + 20.0
			while time.monotonic() < deadline:
				try:
					if ask(socks["b"], "status").startswith("ok "):
						break
				except OSError:
					pass
				time.sleep(0.2)
			else:
				raise failed("b: B's socket did not come back after the join")
			if started["b"].proc.poll() is not None or started["b"].proc.pid != pid:
				raise failed("b: B did not start again in place")
			if not reads("b", "x/before"):
				raise failed("b: after joining, B reads %r of A's setting"
				             % setting("b", "x/before"))
			print("livecheck: b: B joined by a verb, started again in place, and read A's "
			      "setting")

			# c: started again plainly, B pulls from where the join kept A.
			started.pop("b").stop()
			expect(socks["a"], "a", "set setting estate x/after 1", "ok")
			up("b", "b2")
			round_done("b", "B's first round from the kept address")
			if not reads("b", "x/after"):
				raise failed("c: started again with no --root-at, B reads %r"
				             % setting("b", "x/after"))
			print("livecheck: c: B, started with no --root-at, pulled from where the join "
			      "kept its root")
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
	print("livecheck: an estate was joined by verbs on running daemons")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
