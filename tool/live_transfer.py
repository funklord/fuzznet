#!/usr/bin/env python3
"""What crossed the remote hop, by family: `make livecheck`, sec 685.

Two stores: A a root, B a device joined to it, pulling from A.

    a  once B's reconcile round has ended, B's `get transfer` names the
       reconcile family with bytes both ways -- asked and answered -- and
       `list transfer` has a reconcile row for A's address
    b  A, which answered, counts the same family both ways too, by the
       address B asked from
    c  `list transfer FROM` at the total answers no rows, and a FROM that
       is not a number is refused
    d  `get node` at A answers the port it serves on and when it started
       (sec 687); B, given no `--udp-port`, serves on none and answers `-`

Against a daemon with no meter, phase a is `unsupported`; against one whose
callers or whose answering side count nothing, phase a or b finds no
reconcile bytes.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import RECONCILE_RE, command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402


def families(sock, tag):
	"""`get transfer` at `sock`: {family: (up, down)}."""
	reply = ask(sock, "get transfer")
	words = reply.split()
	if not words or words[0] != "ok":
		raise failed("%s: get transfer answered %r" % (tag, reply))
	out = {}
	for w in words[1:]:
		name, up, down = w.split(",")
		out[name] = (int(up), int(down))
	return out


def rows(sock, tag):
	"""Every `list transfer` row at `sock`, read a page at a time."""
	got, start = [], 0
	while True:
		words = ask(sock, "list transfer %d" % start).split()
		if words[:1] != ["ok"] or len(words) < 3 or words[2] != str(start):
			raise failed("%s: list transfer %d answered %r" % (tag, start, words[:6]))
		page = [r.split(",") for r in words[3:]]
		if not page:
			return int(words[1]), got
		got += page
		start += len(page)


def main(argv):
	if len(argv) != 2:
		print("usage: live_transfer.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port = str(16000 + os.getpid() % 2000)
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		a_dir = os.path.join(scratch, "a")
		b_dir = os.path.join(scratch, "b")
		a_sock = os.path.join(sock_dir, "a")
		b_sock = os.path.join(sock_dir, "b")
		os.mkdir(a_dir)
		os.mkdir(b_dir)
		try:
			command(run, ["--fuzznet-dir=" + a_dir, "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + b_dir, "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + a_dir, "--pair=" + prekey, "--delegable"],
			               None)
			command(run, ["--fuzznet-dir=" + b_dir, "--accept=" + card, "--join"], None)

			a = daemon(run, "a", a_dir, a_sock, extra=["--udp-port=" + port])
			try:
				b = daemon(run, "b", b_dir, b_sock, extra=["--root-at", "127.0.0.1", port])
				try:
					b.settled(b.wait_for(RECONCILE_RE, "reconcile pass"))

					# a: B, which asked.
					got = families(b_sock, "a")
					up, down = got.get("reconcile", (0, 0))
					if not up or not down:
						raise failed("a: B counted reconcile %d up and %d down: %r"
						             % (up, down, got))
					total, listed = rows(b_sock, "a")
					peer = "127.0.0.1:" + port
					if total != len(listed) or not any(r[0] == "reconcile" and r[1] == peer
					                                   for r in listed):
						raise failed("a: B listed %d of %d row(s), none reconcile with %s: %r"
						             % (len(listed), total, peer, listed[:4]))
					print("livecheck: a: B counted reconcile %d bytes asked and %d answered, "
					      "in %d row(s)" % (up, down, total))

					# b: A, which answered.
					got = families(a_sock, "b")
					up, down = got.get("reconcile", (0, 0))
					if not up or not down:
						raise failed("b: A counted reconcile %d up and %d down: %r"
						             % (up, down, got))
					total, listed = rows(a_sock, "b")
					if not any(r[0] == "reconcile" and r[1].startswith("127.0.0.1:")
					           and r[1] != peer for r in listed):
						raise failed("b: A has no reconcile row for where B asked from: %r"
						             % listed[:4])
					print("livecheck: b: A counted reconcile %d bytes answered and %d asked"
					      % (up, down))

					# c: past the end, and a FROM that is no number.
					reply = ask(b_sock, "list transfer 1000000")
					if not reply.startswith("ok ") or len(reply.split()) != 3:
						raise failed("c: a FROM past the rows answered %r" % reply)
					reply = ask(b_sock, "list transfer x")
					if not reply.startswith("malformed"):
						raise failed("c: list transfer x answered %r" % reply)
					print("livecheck: c: past the rows answered none, and a bad FROM refused")

					# d: `get node`, sec 687: the port A was told to serve on, read
					# back from its socket, and a start time within this run.
					words = ask(a_sock, "get node").split()
					if len(words) != 5 or words[:3] != ["ok", "udp", port] \
					   or words[3] != "started" or abs(int(words[4]) - time.time()) > 600:
						raise failed("d: get node at A answered %r" % words)
					words = ask(b_sock, "get node").split()
					if len(words) != 5 or words[:3] != ["ok", "udp", "-"] or words[3] != "started":
						raise failed("d: get node at B answered %r" % words)
					print("livecheck: d: get node gave A's port %s, B's %s, and when each "
					      "started" % (port, words[2]))
				finally:
					b.stop()
			finally:
				a.stop()
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for pid in run.started:
				if os.path.exists("/proc/%d" % pid):
					try:
						with open("/proc/%d/cmdline" % pid, "rb") as f:
							alive = run.fuzznetd.encode() in f.read()
						# STILL OUR CHILD, sec 741: a reaped daemon's pid, handed to
						# another run's daemon of the same binary, is not this run's.
						with open("/proc/%d/stat" % pid) as f:
							alive = alive and int(f.read().rsplit(")", 1)[1].split()[1]) == os.getpid()
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: what crossed was counted by family on both sides")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
