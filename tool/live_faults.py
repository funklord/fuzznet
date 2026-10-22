#!/usr/bin/env python3
"""The fault build's faults fire: `make livecheck-faults`, sec 689 step 0b.

Run against `make fuzznetd-faults`' daemon. Each fault is shown taken, so
the scenarios built on them test something:

    a  loss: B, a device joined to A, at FZN_FAULT_LOSS=100 sends nothing
       -- A counts no reconcile bytes from it while B's round runs -- and
       at 0 A counts them
    b  a crash: a daemon with FZN_FAULT_CRASH=persist.synced dies by
       SIGKILL at its first save -- at start, or at the setting asked --
       saying where; started again without it, it serves from the same
       store
    c  a full disk: with FZN_FAULT_WRITE_BUDGET=1 a daemon says the disk
       is full, and a setting it cannot save is refused rather than
       answered `ok`

Against a daemon built without faults, phase a's B is counted at 100 per
cent loss, phase b's daemon does not die, and phase c's says nothing.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this
reuses: one deadline, each daemon in its own process group, and every
daemon checked gone.

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
from live_rejoin import RECONCILE_RE, ROUND_DONE_RE, command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402

FAULTS = ("FZN_FAULT_LOSS", "FZN_FAULT_CRASH", "FZN_FAULT_WRITE_BUDGET", "FZN_FAULT_SEED")


def faulted(env):
	"""Set the fault variables for the next daemon started, the rest cleared."""
	for k in FAULTS:
		os.environ.pop(k, None)
	os.environ.update(env)


def reconcile_from(sock, tag):
	"""The reconcile bytes A counted from any peer, both ways."""
	reply = ask(sock, "get transfer")
	for w in reply.split()[1:]:
		name, up, down = w.split(",")
		if name == "reconcile":
			return int(up), int(down)
	if not reply.startswith("ok"):
		raise failed("%s: get transfer answered %r" % (tag, reply))
	return 0, 0


def main(argv):
	if len(argv) != 2:
		print("usage: live_faults.py PATH_TO_FUZZNETD_WITH_FAULTS", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port = str(14000 + os.getpid() % 2000)
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		a_dir, b_dir, c_dir = (os.path.join(scratch, k) for k in "abc")
		a_sock, b_sock, c_sock = (os.path.join(sock_dir, k) for k in "abc")
		for d in (a_dir, b_dir, c_dir):
			os.mkdir(d)
		try:
			faulted({})
			command(run, ["--fuzznet-dir=" + a_dir, "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + b_dir, "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + a_dir, "--pair=" + prekey, "--delegable"],
			               None)
			command(run, ["--fuzznet-dir=" + b_dir, "--accept=" + card, "--join"], None)

			# a: B at total loss reaches A with nothing; at none it does.
			a = daemon(run, "a1", a_dir, a_sock, extra=["--udp-port=" + port])
			try:
				faulted({"FZN_FAULT_LOSS": "100"})
				b = daemon(run, "b1", b_dir, b_sock, extra=["--root-at", "127.0.0.1", port])
				faulted({})
				try:
					b.wait_for(ROUND_DONE_RE, "B's first round under total loss", within=60.0)
					if reconcile_from(a_sock, "a") != (0, 0):
						raise failed("a: A counted reconcile bytes from a B losing everything")
				finally:
					b.stop()
				b = daemon(run, "b2", b_dir, b_sock, extra=["--root-at", "127.0.0.1", port])
				try:
					b.settled(b.wait_for(RECONCILE_RE, "B's reconcile pass"))
					up, down = reconcile_from(a_sock, "a")
					if not up or not down:
						raise failed("a: A counted %d up and %d down from B at no loss"
						             % (up, down))
				finally:
					b.stop()
			finally:
				a.stop()
			print("livecheck: a: at total loss B reached A with nothing; at none, %d bytes "
			      "each way" % min(up, down))

			# b: dying at the first save, then serving again from the store.
			command(run, ["--fuzznet-dir=" + c_dir, "--new-root"], None)
			faulted({"FZN_FAULT_CRASH": "persist.synced"})
			c = daemon(run, "c1", c_dir, c_sock)
			faulted({})
			# ITS FIRST SAVE MAY BE AT START, before it answers anything.
			try:
				ask(c_sock, "set setting host x/crash 1")
			except (failed, OSError):
				pass
			until = time.monotonic() + 30.0
			while c.proc.poll() is None and time.monotonic() < until:
				time.sleep(0.2)
			status = c.proc.poll()
			said = c.stderr()
			c.stop()
			if status != -9 or "fault: dying at persist.synced" not in said:
				raise failed("b: the daemon did not die at persist.synced: %r, %r"
				             % (status, said[-300:]))
			c = daemon(run, "c2", c_dir, c_sock)
			try:
				if not ask(c_sock, "status").startswith("ok "):
					raise failed("b: the store did not serve again after the crash")
			finally:
				c.stop()
			print("livecheck: b: the daemon died by SIGKILL at persist.synced and served "
			      "again from its store")

			# c: a disk full from the first byte.
			faulted({"FZN_FAULT_WRITE_BUDGET": "1"})
			c = daemon(run, "c3", c_dir, c_sock)
			faulted({})
			try:
				reply = ask(c_sock, "set setting host x/full 1")
				said = c.stderr()
				if "fault: the disk is full" not in said or reply == "ok":
					raise failed("c: a full disk answered %r and said %r" % (reply, said[-300:]))
			finally:
				c.stop()
			print("livecheck: c: the disk was full, said so, and the setting was refused: %r"
			      % reply)
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			faulted({})
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
	print("livecheck: the fault build lost, crashed and filled its disk on demand")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
