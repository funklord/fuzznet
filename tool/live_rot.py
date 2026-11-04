#!/usr/bin/env python3
"""A file that rots, found unasked, and a trash emptied: `make livecheck`, sec 884.

Two stores over loopback, A a root and B joined to it. B fetches a file of
A's, and then a byte under B's store is flipped behind the daemon's back, as
a bad sector would. Nobody asks anything of B after that but whether it is
done.

    a  B fetches A's file whole, and it checks intact
    b  one byte of the spool is flipped; within a few scrub periods B says
       the file failed its check at rest, by itself (sec 492)
    c  B fetches again what it dropped, from A, and the file checks intact
       and exports as what A put
    d  a note reaches B; B is stopped; A trashes it and empties the trash.
       It leaves A's listing at once, and is not erased while B, which
       would push it straight back, is away (sec 427)
    e  B back, it signs off: the note is gone from both, and stays gone

Against a daemon with no scrub, phase b never hears of it: the corruption
sits until a reader meets it.

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
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

DEADLINE_S = 560.0
PAYLOAD_LEN = 300000
ROT_RE = re.compile(r"failed its check at rest; (\d+) leaf")


def main(argv):
	if len(argv) != 2:
		print("usage: live_rot.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	live_trim.DEADLINE = time.monotonic() + DEADLINE_S
	base = 26300 + (os.getpid() % 300) * 2
	port = {"a": str(base), "b": str(base + 1)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}
		try:
			for d in dirs.values():
				os.mkdir(d)
			command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + dirs["b"], "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + dirs["a"], "--pair=" + prekey, "--delegable"],
			               None)
			command(run, ["--fuzznet-dir=" + dirs["b"], "--accept=" + card, "--join"], None)
			started["a"] = daemon(run, "a", dirs["a"], socks["a"],
			                      extra=["--udp-port=" + port["a"]])
			started["b"] = daemon(run, "b", dirs["b"], socks["b"],
			                      extra=["--udp-port=" + port["b"], "--root-at", "127.0.0.1",
			                             port["a"]])
			started["b"].wait_for(ROUND_DONE_RE, "B's first round")
			payload = os.path.join(scratch, "payload")
			with open(payload, "wb") as f:
				f.write(os.urandom(PAYLOAD_LEN))
			put = ask(socks["a"], "put file " + payload)
			if not put.startswith("ok "):
				raise failed("a: put file answered %r" % put)
			ref = put.split()[1]
			root = ref[:64]
			expect(socks["b"], "b", "fetch file " + ref, "ok")

			def intact(within, what):
				until = time.monotonic() + within
				while ask(socks["b"], "get file %s check" % root).strip() != "ok intact":
					if time.monotonic() > until:
						raise failed("%s: B's file is %r" % (what, ask(socks["b"], "get file " + root)))
					time.sleep(1.0)

			intact(90.0, "a")
			print("livecheck: a: B fetched A's file whole")

			# b: THE ROT, in the largest file of B's store: the spool, at least
			# as long as the sealed file, and in nothing else here.
			found = []
			for at, _, files in os.walk(dirs["b"]):
				found += [os.path.join(at, f) for f in files]
			spool = max(found, key=os.path.getsize)
			if os.path.getsize(spool) < PAYLOAD_LEN:
				raise failed("b: nothing in B's store is as long as the file: %s" % spool)
			with open(spool, "r+b") as f:
				f.seek(PAYLOAD_LEN // 2)
				was = f.read(1)
				f.seek(PAYLOAD_LEN // 2)
				f.write(bytes([was[0] ^ 0x40]))
			got = started["b"].wait_for(ROT_RE, "B finding the rot", within=120.0)
			print("livecheck: b: a byte flipped under B's store, and B said so unasked, dropping "
			      "%s leaf(s)" % got.group(1))

			# c: REPAIRED FROM A, nobody asking.
			intact(120.0, "c")
			out = os.path.join(scratch, "out")
			expect(socks["b"], "b", "get file %s %s" % (ref, out), "ok")
			with open(payload, "rb") as f, open(out, "rb") as g:
				if f.read() != g.read():
					raise failed("c: what B exported is not what A put")
			print("livecheck: c: B fetched the leaf again from A, and the file is whole")

			# d: EMPTIED WITH A DEVICE AWAY.
			note = ask(socks["a"], "add note top to-be-emptied").split()
			if len(note) != 2 or note[0] != "ok":
				raise failed("d: add note answered %r" % note)
			note = note[1]
			until = time.monotonic() + 120.0
			while note not in ask(socks["b"], "list note top"):
				if time.monotonic() > until:
					raise failed("d: the note never reached B")
				time.sleep(1.0)
			started.pop("b").stop()
			expect(socks["a"], "a", "set note %s trash" % note, "ok")
			got = ask(socks["a"], "remove note trash")
			if not got.startswith("ok"):
				raise failed("d: remove note trash answered %r" % got)
			if note in ask(socks["a"], "list note top"):
				raise failed("d: the note stayed in A's listing")
			held = ask(socks["a"], "get note " + note)
			if not held.startswith("ok "):
				raise failed("d: with B away A erased the note: get note answered %r" % held)
			print("livecheck: d: emptied with B away, the note left A's listing and was not erased")

			# e: B BACK, AND IT SIGNS OFF.
			started["b"] = daemon(run, "b2", dirs["b"], socks["b"],
			                      extra=["--udp-port=" + port["b"], "--root-at", "127.0.0.1",
			                             port["a"]])
			until = time.monotonic() + 150.0
			while True:
				at_a = ask(socks["a"], "get note " + note)
				at_b = ask(socks["b"], "get note " + note)
				if not at_a.startswith("ok ") and not at_b.startswith("ok "):
					break
				if time.monotonic() > until:
					raise failed("e: with B back, A answers %r and B %r" % (at_a, at_b))
				time.sleep(1.0)
			time.sleep(6.0)
			if note in ask(socks["a"], "list note top") or note in ask(socks["b"], "list note top"):
				raise failed("e: the note came back")
			print("livecheck: e: B back, the note is gone from both, and stayed gone")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started.values():
				d.stop()
	print("livecheck: a file that rotted was found unasked and mended, and a trash emptied")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
