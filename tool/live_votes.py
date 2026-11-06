#!/usr/bin/env python3
"""A value changed by the estate's k, or a root alone: `make livecheck`, sec 909.

R the root, A and B its admins, T a member run as a vault, whose `relay/enabled`
its profile gives to a vote. k is 2, fuzznetd's default.

    a  T's user is refused the value, and so is A's own word
    b  one admin's vote changes nothing, and neither does a plain member's
    c  a second admin's vote carries, on T, by T's own count
    d  a root alone sets it, and the votes already carried do not change it back

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses: one
deadline, each daemon in its own process group, and every daemon checked gone.

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

DEADLINE_S = 640.0
SETTLE_S = 200.0
QUIET_S = 130.0
KEY = "relay/enabled"


def main(argv):
	if len(argv) != 2:
		print("usage: live_votes.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	live_trim.DEADLINE = time.monotonic() + DEADLINE_S
	base = 27900 + (os.getpid() % 300) * 4
	port = {k: str(base + i) for i, k in enumerate(("r", "a", "b", "t"))}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}

		def on_t():
			return ask(socks["t"], "get setting host " + KEY)

		def comes_to(want, what):
			until = time.monotonic() + SETTLE_S
			while on_t() != want:
				if time.monotonic() > until:
					raise failed("%s: T holds %r" % (what, on_t()))
				time.sleep(1.0)

		def stays(want, what):
			until = time.monotonic() + QUIET_S
			while time.monotonic() < until:
				if on_t() != want:
					raise failed("%s: T came to hold %r" % (what, on_t()))
				time.sleep(1.0)

		try:
			for d in dirs.values():
				os.mkdir(d)
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			keys = {}
			for who in ("a", "b", "t"):
				prekey = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"], None)
				keys[who] = prekey[4:68]
				card = command(run, ["--fuzznet-dir=" + dirs["r"], "--pair=" + prekey,
				                     "--delegable"], None)
				command(run, ["--fuzznet-dir=" + dirs[who], "--accept=" + card, "--join"], None)
			started["r"] = daemon(run, "r", dirs["r"], socks["r"],
			                      extra=["--udp-port=" + port["r"]])
			for who in ("a", "b", "t"):
				extra = ["--udp-port=" + port[who], "--root-at", "127.0.0.1", port["r"]]
				if who == "t":
					extra.append("--preset=vault")
				started[who] = daemon(run, who, dirs[who], socks[who], extra=extra)
				started[who].wait_for(ROUND_DONE_RE, "%s's first round" % who.upper(), within=60.0)
			for who in ("a", "b"):
				granted = ask(socks["r"], "grant admin " + keys[who]).split()
				if len(granted) < 2 or granted[0] != "ok":
					raise failed("setup: grant admin answered %r" % granted[:2])
				path = os.path.join(scratch, "admin-" + who)
				with open(path, "w") as f:
					f.write(" ".join(granted[1:]) + "\n")
				expect(socks[who], who, "set admin " + path, "ok %d" % (len(granted) - 1))
				until = time.monotonic() + 40.0
				while True:
					try:
						if any(e.startswith("admin,1,")
						       for e in ask(socks[who], "list capability").split()):
							break
					except OSError:
						pass
					if time.monotonic() > until:
						raise failed("setup: %s never held admin" % who.upper())
					time.sleep(0.5)
			comes_to("ok host on", "setup")

			# a: NOT BY A WORD.
			got = ask(socks["t"], "set setting host %s off" % KEY)
			if not got.startswith("denied"):
				raise failed("a: T's user was answered %r" % got)
			print("livecheck: a: T's user was refused a value the profile gives to a vote")

			# b: ONE IS NOT k, and a member is nobody's vote.
			got = ask(socks["t"], "add vote setting self %s off" % KEY)
			if not got.startswith("denied"):
				raise failed("b: a member's vote was answered %r" % got)
			expect(socks["a"], "a", "add vote setting %s %s off" % (keys["t"], KEY), "ok")
			stays("ok host on", "b")
			print("livecheck: b: one admin's vote of k 2 changed nothing")

			# c: k.
			expect(socks["b"], "b", "add vote setting %s %s off" % (keys["t"], KEY), "ok")
			comes_to("ok host off", "c")
			print("livecheck: c: a second admin's vote carried on T, by T's own count")

			# d: A ROOT ALONE, and what was carried stays spent.
			expect(socks["r"], "r", "set setting host=%s %s on" % (keys["t"], KEY), "ok")
			comes_to("ok root on", "d")
			stays("ok root on", "d")
			print("livecheck: d: a root set it alone, and the old votes did not change it back")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started.values():
				d.stop()
	print("livecheck: a value took the estate's k, or a root alone")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
