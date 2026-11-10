#!/usr/bin/env python3
"""A host answers through what it owes every group: `make livecheck`, sec 941.

    a  3000 groups added: the last hundred took about what the first did, not the
       two reads of every group's name an add once cost
    b  through the rounds that tend them all, a client is answered within a second.
       One step of a round, each drawing, sealing and signing, held the loop 14 s
    c  and they were tended, each one's act made

Against a daemon tending in one step, b waits many seconds. Against one reading each
name from its file, a counts thousands of reads a hundred.

BOUNDED FROM INSIDE as live_rejoin.py is: one deadline, the daemon in its own process
group, and checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import re
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_many_contacts import reads  # noqa: E402
from live_rejoin import command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 180.0

GROUPS = 3000
SAMPLE = 100
# Reads a hundred adds may grow by. A name read from its file is 200000 at the end.
SLACK = 2000
# The longest a client may wait through a round. A slice is 50 ms, so this is the
# machine's load and not the work.
ANSWERED_S = 1.0
# A round comes within this of the start, and its tending takes some seconds.
ROUND_S = 100.0
TENDED = re.compile(r"(\d+) group act\(s\) made tending")


def adding(sock, pid, first, last):
	before = reads(pid)
	for i in range(first, last):
		reply = ask(sock, "add group g%d" % i)
		if not reply.startswith("ok"):
			raise failed("group %d answered %r" % (i, reply))
	return reads(pid) - before


def main(argv):
	if len(argv) != 2:
		print("usage: live_many_groups.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		store = os.path.join(scratch, "s")
		sock = os.path.join(sock_dir, "s")
		os.mkdir(store)
		d = None
		try:
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)
			d = daemon(run, "s0", store, sock)
			pid = d.proc.pid
			began = time.monotonic()

			adding(sock, pid, 0, SAMPLE)
			early = adding(sock, pid, SAMPLE, 2 * SAMPLE)
			adding(sock, pid, 2 * SAMPLE, GROUPS - SAMPLE)
			late = adding(sock, pid, GROUPS - SAMPLE, GROUPS)
			if late > 2 * early + SLACK:
				raise failed("a: %d reads for an early hundred, %d for the last" % (early, late))
			print("livecheck: a: %d groups, %d reads for an early hundred and %d for the last"
			      % (GROUPS, early, late))

			# b: asked all through the rounds, until what they tended covers every
			# group. MORE THAN ONE PASS since sec 1004: an act made starts a round
			# soon, so one may begin while the groups are still being added, and
			# tend those held by then.
			worst = 0.0
			done = 0
			while done < GROUPS and time.monotonic() - began < ROUND_S:
				t = time.monotonic()
				if not ask(sock, "status").startswith("ok "):
					raise failed("b: status did not answer")
				worst = max(worst, time.monotonic() - t)
				done = sum(int(m.group(1)) for m in TENDED.finditer(d.log()))
				time.sleep(0.05)
			if not done:
				raise failed("c: no group was tended in %.0f s" % ROUND_S)
			if worst > ANSWERED_S:
				raise failed("b: a client waited %.1f s through a round" % worst)
			print("livecheck: b: answered within %.2f s through the round" % worst)
			if done < GROUPS:
				raise failed("c: %d acts for %d groups in %.0f s" % (done, GROUPS, ROUND_S))
			print("livecheck: c: %d acts made tending" % done)
		except (failed, TimeoutError) as e:
			print("livecheck: FAILED -- %s" % e, file=sys.stderr)
			return 1
		finally:
			if d:
				d.stop()
	print("livecheck: a host answered through what it owes every group")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
