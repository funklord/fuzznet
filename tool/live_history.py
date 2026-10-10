#!/usr/bin/env python3
"""A note's history, kept and trimmed by the rules: `make livecheck`, sec 581.

One store. A note is written and edited three times:

    a  with no history rule, the node keeps every earlier version -- three
       listed by `list history`, kept by default as the holder decided
    b  restarted with `--log-rule=prune history count 1`, the round's
       history pass lets two versions go -- "history pass: 1 of 1 rule(s),
       2 version(s) let go" -- and one is listed, the newest

Against a daemon that does not trim the history, phase b fails at the pass
line; against one that keeps none, phase a does.

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

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402

PASS_RE = re.compile(r"history pass: (\d+) of (\d+) rule\(s\), (\d+) version\(s\) let go")


def versions(sock, tag, note):
	"""`list history` for `note` at `sock`: its total, and its reply."""
	reply = ask(sock, "list history " + note)
	if not reply.startswith("ok "):
		raise failed("%s: list history answered %r" % (tag, reply))
	return int(reply.split()[1]), reply


def main(argv):
	if len(argv) != 2:
		print("usage: live_history.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		store = os.path.join(scratch, "n")
		sock = os.path.join(sock_dir, "n")
		os.mkdir(store)
		try:
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)

			# a: three edits, three versions kept.
			d = daemon(run, "n1", store, sock)
			try:
				reply = ask(sock, "add note top v0")
				if not reply.startswith("ok "):
					raise failed("a: add note answered %r" % reply)
				note = reply.split()[1]
				for i in (1, 2, 3):
					reply = ask(sock, "set note %s title v%d" % (note, i))
					if reply != "ok":
						raise failed("a: set note answered %r" % reply)
				kept, _ = versions(sock, "a", note)
				if kept != 3:
					raise failed("a: %d earlier version(s) kept, not 3" % kept)
			finally:
				d.stop()
			print("livecheck: a: three edits kept three earlier versions")

			# b: one version, by the rule.
			d = daemon(run, "n2", store, sock,
			           extra=["--log-rule=prune history count 1"])
			try:
				got = d.wait_for(PASS_RE, "history pass")
				if got.group(1) != "1" or got.group(3) != "2":
					raise failed("b: the pass weighed %s rule(s) and let %s version(s) go"
					             % (got.group(1), got.group(3)))
				kept, reply = versions(sock, "b", note)
				if kept != 1 or ",here,v2" not in reply:
					raise failed("b: list history answered %r, not the newest alone" % reply)
			finally:
				d.stop()
			print("livecheck: b: prune history count 1 let two go and kept the newest")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for pid in run.started:
				if os.path.exists("/proc/%d" % pid):
					try:
						with open("/proc/%d/cmdline" % pid, "rb") as f:
							alive = f.read() != b""
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: a note's history was kept and trimmed by the rules")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
