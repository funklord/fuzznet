#!/usr/bin/env python3
"""The typed client against a running node: `make livecheck`, sec 1098.

    a  a fresh host's fuzznetd answers every fzn_rpc_ call rpc_probe makes, and
       each answer parses: the client's grammar is the daemon's

rpc_test checks the client against the grammar it believes, over a scripted
node; this checks the belief. A verb renamed or a field moved on the daemon's
side fails here by the call's name.

BOUNDED FROM INSIDE as live_rejoin.py is: one deadline, the daemon in its own
process group, and checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon  # noqa: E402
from live_trim import failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 90.0


def main(argv):
	if len(argv) != 3:
		print("usage: live_rpc.py PATH_TO_FUZZNETD PATH_TO_RPC_PROBE", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	probe = os.path.abspath(argv[2])
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
			r = subprocess.run([probe, sock], capture_output=True, text=True, timeout=60)
			if r.returncode != 0:
				raise failed("a: rpc_probe answered %d:\n%s" % (r.returncode, r.stderr.rstrip()))
			print("livecheck: a: %s" % r.stdout.strip())
		except (failed, TimeoutError, subprocess.TimeoutExpired) as e:
			print("livecheck: FAILED -- %s" % e, file=sys.stderr)
			return 1
		finally:
			if d:
				d.stop()
	print("livecheck: the typed client reads what a running node says")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
