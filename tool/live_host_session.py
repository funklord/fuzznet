#!/usr/bin/env python3
"""Two hosts in a session, saying words both ways: sec 1018, sec 1017's first step.

Two stores over loopback, each running the extension daemon, whose `add said HOST
WORD` says a word to a host and whose `get heard` tells the last word heard: R a
root, M joined to it and pulling from it (`--root-at`).

    a  M says a word to R. It holds no session with R, so it asks one (`ok asked`),
       and a word said again once R has granted it goes (`ok said`); R hears it,
       from M
    b  R says a word to M in the same session, unasked, and M hears it, from R
    c  a word R echoes: M says it, R says it back, and M hears it

Against a daemon that asks no session of a host, a never goes; against one whose
asked session is checked against a key no peer row holds, b is never heard.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses: one
deadline, each daemon in its own process group, and every daemon checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_files_many import answering  # noqa: E402
from live_groups import PREKEY_HOST  # noqa: E402
from live_rejoin import command, daemon, expect, free_slot  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 200.0

WAIT = 30.0


def until(what, test, wait=WAIT):
	began = time.monotonic()
	while True:
		got = test()
		if got:
			return got
		if time.monotonic() - began > wait:
			raise failed("%s, after %.0f s" % (what, wait))
		time.sleep(0.25)


def main(argv):
	if len(argv) != 2:
		print("usage: live_host_session.py PATH_TO_EXT_DAEMON", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = free_slot(48000, 4, 300, 2)
	port = {"r": base, "m": base + 1}
	started = {}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		try:
			for d in dirs.values():
				os.mkdir(d)
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			key = {"r": command(run, ["--fuzznet-dir=" + dirs["r"], "--prekey"], None)[PREKEY_HOST]}
			prekey = command(run, ["--fuzznet-dir=" + dirs["m"], "--prekey"], None)
			key["m"] = prekey[PREKEY_HOST]
			card = command(run, ["--fuzznet-dir=" + dirs["r"], "--pair=" + prekey, "--delegable"],
			               None)
			command(run, ["--fuzznet-dir=" + dirs["m"], "--accept=" + card, "--join"], None)
			started["r"] = daemon(run, "r", dirs["r"], socks["r"],
			                      extra=["--udp-port=%d" % port["r"]])
			answering(socks["r"], "r")
			started["m"] = daemon(run, "m", dirs["m"], socks["m"],
			                      extra=["--udp-port=%d" % port["m"],
			                             "--root-at", "127.0.0.1", str(port["r"])])
			answering(socks["m"], "m")

			# a: M SAYS TO R, asking a session first.
			first = ask(socks["m"], "add said %s noecho:m-to-r" % key["r"])
			if first not in ("ok asked", "ok said"):
				raise failed("a: add said answered %r" % first)
			began = time.monotonic()
			until("a: M's word never went",
			      lambda: ask(socks["m"], "add said %s noecho:m-to-r" % key["r"]) == "ok said")
			heard = until("a: R never heard M",
			              lambda: (lambda w: w if len(w) == 4 and w[3] == "noecho:m-to-r" else None)(
			                      ask(socks["r"], "get heard").split()))
			if heard[2] != key["m"]:
				raise failed("a: R heard it from %s, not M" % heard[2][:16])
			print("livecheck: a: M asked R for a session (first answer %r) and said a word in it, "
			      "%.1f s; R heard it, from M" % (first, time.monotonic() - began))

			# b: R SAYS TO M, unasked, in the same session.
			expect(socks["r"], "r", "add said %s noecho:r-to-m" % key["m"], "ok said")
			heard = until("b: M never heard R",
			              lambda: (lambda w: w if len(w) == 4 and w[3] == "noecho:r-to-m" else None)(
			                      ask(socks["m"], "get heard").split()))
			if heard[2] != key["r"]:
				raise failed("b: M heard it from %s, not R" % heard[2][:16])
			print("livecheck: b: R said a word back in M's session, and M heard it, from R")

			# c: A WORD R ECHOES.
			before = int(ask(socks["m"], "get heard").split()[1])
			expect(socks["m"], "m", "add said %s ping" % key["r"], "ok said")
			until("c: M never heard its word echoed",
			      lambda: (lambda w: len(w) == 4 and int(w[1]) > before and w[3] == "ping")(
			              ask(socks["m"], "get heard").split()))
			print("livecheck: c: M said a word, and R said it back")
		except failed as e:
			print("livecheck: FAILED -- %s" % e, file=sys.stderr)
			return 1
		finally:
			for who in ("m", "r"):
				if who in started:
					started[who].stop()
	print("livecheck: two hosts held a session and said words both ways")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
