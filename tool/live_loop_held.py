#!/usr/bin/env python3
"""What held the loop, said: sec 993.

One root, against `make fuzznetd-faults`' daemon, whose FZN_TUNE_LOOP_HELD_MS
sets the threshold the loop is held to.

    a  at the default, a quiet root asked `status` a few times says nothing
       of its loop being held
    b  at 1 ms, the same root's own work between answers is said, naming the
       longest step; and a Takeout of 40 notes imported is said as answering
       that held the loop

Against a daemon that times nothing, b never says either.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import json
import os
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 120.0

OWN = "the loop's own work held it"
ANSWERING = "answering what came in held the loop"


def main(argv):
	if len(argv) != 2:
		print("usage: live_loop_held.py PATH_TO_FAULTS_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		r_dir = os.path.join(scratch, "r")
		take = os.path.join(scratch, "takeout")
		os.mkdir(r_dir)
		os.mkdir(take)
		for i in range(40):
			with open(os.path.join(take, "n%02d.json" % i), "w") as f:
				json.dump({"title": "n%d" % i, "textContent": "x" * 40,
				           "createdTimestampUsec": 1600000000000000 + i * 1000000}, f)
		sock = os.path.join(sock_dir, "r")
		r = None
		try:
			command(run, ["--fuzznet-dir=" + r_dir, "--new-root"], None)

			# a: THE DEFAULT, quiet.
			os.environ.pop("FZN_TUNE_LOOP_HELD_MS", None)
			r = daemon(run, "r0", r_dir, sock)
			for _ in range(5):
				ask(sock, "status")
				time.sleep(0.5)
			if OWN in r.log() or ANSWERING in r.log():
				raise failed("a: a quiet root said its loop was held at the default")
			r.stop()
			r = None
			print("livecheck: a: at the default a quiet root says nothing of its loop")

			# b: AT 1 MS, both said.
			os.environ["FZN_TUNE_LOOP_HELD_MS"] = "1"
			r = daemon(run, "r1", r_dir, sock)
			reply = ask(sock, "add import top " + take)
			if not reply.startswith("ok 40 "):
				raise failed("b: the import answered %r" % reply[:60])
			until = time.monotonic() + 30.0
			while not (OWN in r.log() and ANSWERING in r.log()):
				if time.monotonic() > until:
					raise failed("b: own work said %s, answering said %s"
					             % (OWN in r.log(), ANSWERING in r.log()))
				ask(sock, "status")
				time.sleep(0.5)
			line = [l for l in r.log().splitlines() if OWN in l][0]
			if "the longest" not in line or "nothing timed" in line:
				raise failed("b: the held loop did not name its longest step: %r" % line)
			print("livecheck: b: at 1 ms the loop's own work and an import's answering are said")
		except failed as e:
			print("livecheck: FAILED: %s" % e, file=sys.stderr)
			return 1
		finally:
			os.environ.pop("FZN_TUNE_LOOP_HELD_MS", None)
			if r:
				r.stop()
	print("livecheck: what held the loop is said")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
