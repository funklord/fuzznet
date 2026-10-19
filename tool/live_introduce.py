#!/usr/bin/env python3
"""A sibling reached through an introduction: `make livecheck`, sec 623.

Three stores over loopback, as live_siblings.py has them: A a root, B and C
joined with grants they can pass on, pulling from A. C advertises a port
nobody listens on -- as a host behind a NAT would -- and says hello to A
from the socket it serves on.

    a  B and C pair each other through the estate
    b  C puts a file and B asks for it: B's round cannot reach C at the
       address C advertised; its next round asks A to introduce C, A tells
       B where C said hello from (and tells C where B asked from), and B
       fetches the file whole from C, A holding none of it

On loopback no NAT stands between them, so this shows the introduced
address used and the request through it answered; whether a NAT lets it
through is the hellos', and is not what loopback can show.

Against a daemon that introduces nobody, phase b never fetches the file.

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
from live_rejoin import ROUND_DONE_RE, RECONCILE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 420.0

TAKEN_RE = re.compile(r"(\d+) sibling\(s\) paired, (\d+) pairing\(s\) taken")
WHOLE_RE = re.compile(r"file [0-9a-f]{8}, (\d+) bytes, whole from (\d+) peer\(s\)")
INTRODUCED_RE = re.compile(r"a sibling introduced at 127\.0\.0\.1 (\d+)")
ROUNDS = 6
PAYLOAD_LEN = 50000


def took(d):
	return any(int(m.group(2)) > 0 for m in TAKEN_RE.finditer(d.log()))


def main(argv):
	if len(argv) != 2:
		print("usage: live_introduce.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 4000 + (os.getpid() % 500) * 4
	port = {"a": str(base), "b": str(base + 1), "c": str(base + 2), "nobody": str(base + 3)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in ("a", "b", "c")}
		socks = {k: os.path.join(sock_dir, k) for k in ("a", "b", "c")}
		for d in dirs.values():
			os.mkdir(d)
		payload = os.path.join(scratch, "payload")
		with open(payload, "wb") as f:
			f.write(os.urandom(PAYLOAD_LEN))
		args = {"b": ["--udp-port=" + port["b"], "--root-at", "127.0.0.1", port["a"]],
		        "c": ["--udp-port=" + port["c"], "--root-at", "127.0.0.1", port["a"]]}
		started = {}
		try:
			command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
			for who in ("b", "c"):
				prekey = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"], None)
				card = command(run, ["--fuzznet-dir=" + dirs["a"], "--pair=" + prekey,
				                     "--delegable"], None)
				command(run, ["--fuzznet-dir=" + dirs[who], "--accept=" + card, "--join"], None)
			started["a"] = daemon(run, "a1", dirs["a"], socks["a"],
			                      extra=["--udp-port=" + port["a"]])

			# a: the pairings, both ways.
			ref = None
			taken = {"b": False, "c": False}
			for rnd in range(ROUNDS):
				for who in ("c", "b"):
					d = daemon(run, "%s%d" % (who, rnd), dirs[who], socks[who], extra=args[who])
					try:
						if ref is None and who == "c":
							# A MEMBER'S SETTING once its first round is over: it is allowed by the
							# grant that round brings, and a round answers mid-way (sec 637).
							d.wait_for(ROUND_DONE_RE, "C's first round")
							expect(socks["c"], "c", "set setting host net/address 127.0.0.1 "
							       + port["nobody"], "ok")
							reply = ask(socks["c"], "put file " + payload)
							if not reply.startswith("ok "):
								raise failed("a: put file answered %r" % reply)
							ref = reply.split()[1]
						d.wait_for(RECONCILE_RE, "reconcile pass")
						taken[who] = taken[who] or took(d)
					finally:
						d.stop()
				if all(taken.values()):
					break
			if not all(taken.values()):
				raise failed("a: after %d rounds each, a pairing taken at B %s, at C %s"
				             % (ROUNDS, taken["b"], taken["c"]))
			print("livecheck: a: B and C paired each other through the estate")

			# b: C up and saying hello to A; B asks for C's file.
			started["c"] = daemon(run, "c-b", dirs["c"], socks["c"], extra=args["c"])
			started["c"].wait_for(RECONCILE_RE, "C's reconcile pass")
			started["b"] = daemon(run, "b-b", dirs["b"], socks["b"], extra=args["b"])
			started["b"].wait_for(RECONCILE_RE, "B's reconcile pass")
			expect(socks["b"], "b", "fetch file " + ref, "ok")
			# A LATER ROUND introduces C: waited for here rather than by
			# wait_for, whose limit is half a round. Up to three rounds: A,
			# the root, also asks C at its dead address, and a round of A's
			# spent waiting on it may leave B's introduction unanswered,
			# which stays due for B's next round.
			deadline = time.monotonic() + 200.0
			while time.monotonic() < deadline and not INTRODUCED_RE.search(started["b"].log()):
				time.sleep(0.5)
			got = INTRODUCED_RE.search(started["b"].log())
			if not got or got.group(1) != port["c"]:
				told = [l[-170:] for l in started["b"].log().splitlines()
				        if any(w in l for w in ("sibling", "journal", "refused", "node/peer"))]
				raise failed("b: B was introduced to C at %r, not C's serving port %s%s"
				             % (got.group(1) if got else None, port["c"],
				                "".join("\n  " + l for l in told[-10:])
				                + "".join("\n  A: " + l[-170:]
				                          for l in started["a"].log().splitlines()[-8:])
				                + "\n  A stderr: " + started["a"].stderr()[-600:]))
			whole = started["b"].wait_for(WHOLE_RE, "the file whole")
			if whole.groups() != (str(PAYLOAD_LEN), "1"):
				raise failed("b: B's file was %s bytes from %s peer(s)" % whole.groups())
			reply = ask(socks["a"], "get file " + ref[:64])
			if reply.startswith("ok ") and len(reply.split()) >= 5 and reply.split()[4] != "none":
				raise failed("b: A holds the file, so the peer may have been A: %r" % reply)
			print("livecheck: b: introduced through A, B fetched C's file whole from C")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started.values():
				d.stop()
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
	print("livecheck: a sibling unreached at its address was reached through an introduction")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
