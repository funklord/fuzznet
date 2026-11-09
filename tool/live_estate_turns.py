#!/usr/bin/env python3
"""An estate past a round's siblings, asked in turns: sec 964.

Twelve stores over loopback: R a root and eleven members joined to it with
grants they can pass on, each pulling from R (`--root-at`) and setting its
address, so each has ten siblings where a round asks
FZND_SIBLING_TARGETS_MAX, 8. Run against `make fuzznetd-faults`' daemon,
whose rounds FZN_TUNE_PULL_EVERY makes a few seconds.

    a  the members pair one another through R, and every member's rounds
       come to ask each of its ten siblings, in turns of eight
    b  R and eight members are stopped. The three left each set a cell of
       their own, and each comes to read the other two's -- which only they
       hold, so it took them from one another

Against a daemon whose round asks the first eight siblings it lists every
time, phase a fails: no member asks more than eight. Phase b may pass even
so, when the three left happen to be among one another's first eight.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

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

live_trim.DEADLINE = time.monotonic() + 600.0

MEMBERS = 11
ROUND_S = "3"
ASKED_RE = re.compile(r"a sibling in this round's turn: 127\.0\.0\.1 port (\d+)")
LEFT = 3


def main(argv):
	if len(argv) != 2:
		print("usage: live_estate_turns.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	os.environ["FZN_TUNE_PULL_EVERY"] = ROUND_S
	who = ["r"] + ["m%02d" % i for i in range(MEMBERS)]
	members = who[1:]
	base = free_slot(36000, 16, 120, len(who))
	port = {k: base + i for i, k in enumerate(who)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in who}
		socks = {k: os.path.join(sock_dir, k) for k in who}
		started = {}
		keys = {}

		def up(k):
			extra = ["--udp-port=%d" % port[k]]
			if k != "r":
				extra += ["--root-at", "127.0.0.1", str(port["r"])]
			started[k] = daemon(run, k, dirs[k], socks[k], extra=extra)

		def asked(k):
			return {int(p) for p in ASKED_RE.findall(started[k].log())}

		try:
			for d in dirs.values():
				os.mkdir(d)
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			for k in members:
				prekey = command(run, ["--fuzznet-dir=" + dirs[k], "--prekey"], None)
				keys[k] = prekey[4:68]
				card = command(run, ["--fuzznet-dir=" + dirs["r"], "--pair=" + prekey,
				                     "--delegable"], None)
				command(run, ["--fuzznet-dir=" + dirs[k], "--accept=" + card, "--join"], None)
			for k in who:
				up(k)
			for k in who:
				until = time.monotonic() + 30.0
				while not ask(socks[k], "status").startswith("ok "):
					if time.monotonic() > until:
						raise failed("%s: not answering" % k)
					time.sleep(0.2)
				expect(socks[k], k, "set setting host net/address 127.0.0.1 %d" % port[k], "ok")

			# a: each member's turns come round its ten siblings.
			began = time.monotonic()
			until = began + 300.0
			while True:
				short = {k: sorted({port[m] for m in members if m != k} - asked(k))
				         for k in members}
				short = {k: v for k, v in short.items() if v}
				if not short:
					break
				if time.monotonic() > until:
					raise failed("a: after %.0f s, members not yet asking all ten siblings: %s"
					             % (time.monotonic() - began,
					                ", ".join("%s asked %d, never %s" % (k, len(asked(k)), v)
					                          for k, v in sorted(short.items()))))
				time.sleep(1.0)
			print("livecheck: a: each of %d members asked all %d siblings in turns, in %.0f s"
			      % (MEMBERS, MEMBERS - 1, time.monotonic() - began))

			# b: three left, among themselves.
			left = members[-LEFT:]
			for k in ["r"] + members[:-LEFT]:
				started[k].stop()
			for k in left:
				expect(socks[k], k, "set setting host x/turns %s" % k, "ok")
			began = time.monotonic()
			until = began + 120.0
			for k in left:
				for other in left:
					if other == k:
						continue
					line = "get setting host=%s x/turns" % keys[other]
					while ask(socks[k], line).strip() != "ok host " + other:
						if time.monotonic() > until:
							raise failed("b: %s never read %s's cell: %r"
							             % (k, other, ask(socks[k], line)))
						time.sleep(0.5)
			print("livecheck: b: with R and eight members away, the three left read one "
			      "another's cells in %.0f s" % (time.monotonic() - began))
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			for name in sorted(os.listdir(scratch)):
				if name.endswith(".err"):
					with open(os.path.join(scratch, name), errors="replace") as f:
						tail = f.read().splitlines()[-8:]
					print("livecheck: --- %s" % name)
					for line in tail:
						print("livecheck:     %s" % line)
			return 1
		finally:
			for d in started.values():
				d.stop()
	print("livecheck: an estate of %d members asked its siblings in turns" % MEMBERS)
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
