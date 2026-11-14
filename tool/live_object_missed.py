#!/usr/bin/env python3
"""A change's round that misses a live sibling asks again soon, sec 1149.

    a  R makes `lamp` and A, a member, reads it; a set on R reaches A at once,
       so R has heard A lately
    b  R is cut off (FZN_FAULT_MUTE_FILE), sets `lamp on`, and stays cut off
       until its change's round has missed A; once R can be heard again, A
       reads `on` well inside a round of 60 s, not at R's next timed round

Before sec 1149 the change's round passed A over and nothing asked again
until the timed round, up to a minute later: fuzzypickles' "no such object"
on the other host of the estate for 60 s under load (inbox 1736Z).

Needs the faults build: `make fuzznetd-faults`, then this with
faults/fuzznetd. BOUNDED FROM INSIDE as live_objects.py is: one deadline,
each daemon in its own process group, and every daemon checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import re
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon, expect, free_slot  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402
from live_objects import heard  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 280.0

# CUT OFF THIS LONG after the set: the change's round starts within 2 s and
# its journal pull waits out 3 s of resends (sec 737).
MUTED_S = 20.0
# HEARD WITHIN THIS once R can be heard again: a follow-up comes a gap after
# the round's end (sec 1004), where the timed round is 60 s.
SOON_S = 20.0


def main(argv):
	if len(argv) != 2:
		print("usage: live_object_missed.py PATH_TO_FAULTS_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = free_slot(43600, 4, 500, 2)
	port = {"r": str(base), "a": str(base + 1)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		mute = os.path.join(scratch, "mute")
		started = {}

		def up(who, muted=False):
			# R ALONE IS CUT OFF: the environment is read when it starts.
			if muted:
				os.environ["FZN_FAULT_MUTE_FILE"] = mute
			try:
				started[who] = daemon(run, who, dirs[who], socks[who],
				                      extra=["--udp-port=" + port[who]])
			finally:
				os.environ.pop("FZN_FAULT_MUTE_FILE", None)
			return started[who]

		def said(who, line):
			return ask(socks[who], line).strip()

		def polled(who, line, test, what, wait):
			until = time.monotonic() + wait
			while True:
				got = said(who, line)
				if test(got):
					return got
				if time.monotonic() > until:
					raise failed("%s: %s answered %r, %s" % (who, line, got, what))
				time.sleep(0.2)

		try:
			os.mkdir(dirs["r"])
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			up("r", muted=True)
			polled("r", "status", lambda g: g.startswith("ok "), "not answering", 30.0)
			expect(socks["r"], "r", "set setting host net/address 127.0.0.1 " + port["r"], "ok")
			os.mkdir(dirs["a"])
			up("a")
			got = said("a", "get prekey").split()
			card = said("r", "add peer %s delegable" % got[1]).split()
			if len(card) != 2 or card[0] != "ok":
				raise failed("r: add peer answered %r" % card)
			path = os.path.join(scratch, "card")
			with open(path, "w") as f:
				f.write(card[1] + "\n")
			pid = started["a"].proc.pid
			if not said("a", "add join " + path).startswith("ok"):
				raise failed("a: add join did not take")
			until = time.monotonic() + 30.0
			while time.monotonic() < until:
				try:
					if said("a", "status").startswith("ok "):
						break
				except OSError:
					pass
				time.sleep(0.2)
			if started["a"].proc.pid != pid:
				raise failed("a: did not start again in place")
			polled("a", "list capability", lambda g: "member,1,1,0" in g.split()[2:],
			       "not a member", 60.0)
			expect(socks["a"], "a", "set setting host net/address 127.0.0.1 " + port["a"], "ok")

			# a: made on R, read on A; then a set heard on A at once, so R's
			# own round has heard A lately.
			expect(socks["r"], "r", "add object lamp on off", "ok")
			polled("a", "get object lamp", lambda g: g == "ok - 0 - on|off",
			       "without R's object", 70.0)
			t = heard(socks["a"], "a2", lambda: expect(socks["r"], "r", "set object lamp off", "ok"))
			polled("a", "get object lamp", lambda g: g.startswith("ok off "), "not off", 15.0)
			print("livecheck: a: R made an object, A reads it, and R's set reached A in %.1f s" % t)

			# b: R cut off for its change's round, then heard again.
			with open(mute, "w"):
				pass
			expect(socks["r"], "r", "set object lamp on", "ok")
			time.sleep(MUTED_S)
			if said("a", "get object lamp").startswith("ok on "):
				raise failed("b: A read `on` while R was cut off -- the fault took nothing")
			os.unlink(mute)
			back = time.monotonic()
			polled("a", "get object lamp", lambda g: g.startswith("ok on "),
			       "not within %.0f s of R being heard again" % SOON_S, SOON_S)
			print("livecheck: b: R's change, missed by A while R was cut off, read on A "
			      "%.1f s after R was heard again" % (time.monotonic() - back))
			started["r"].wait_for(re.compile(r"missed this round's change; asking again soon"),
			                      "its change's round missing A", within=5.0)
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			for name in sorted(os.listdir(scratch)):
				if name.endswith(".err"):
					with open(os.path.join(scratch, name), errors="replace") as f:
						tail = f.read().splitlines()[-30:]
					print("livecheck: --- %s" % name)
					for line in tail:
						print("livecheck:     %s" % line)
			return 1
		finally:
			if os.path.exists(mute):
				os.unlink(mute)
			for d in started.values():
				d.stop()
	print("livecheck: a change's round that missed a live sibling asked again soon")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
