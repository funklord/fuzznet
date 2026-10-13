#!/usr/bin/env python3
"""Local subscribers told what changed: `make livecheck`, sec 609.

One daemon over one store, and clients of its local socket:

    a  two clients ask `get events` and are answered `ok events`; a third
       sets a setting and adds a note, and each subscriber reads `event
       setting -` and `event note -`, in that order
    b  one subscriber hangs up; the next change still reaches the other,
       and the daemon answers a request as before
    c  FZN_NODE_EVENTS_MAX subscribers are taken and the next is not: its
       `get events` is answered as any request, and the connection closed

Against a daemon that keeps no subscribers, phase a waits for nothing to
come; against one that blocks on a subscriber, phase b does.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, every daemon checked
gone, and every socket read under a timeout.

Exit 0 on a pass, 1 on a failure.
"""

import os
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon, expect  # noqa: E402
from live_trim import ask, failed, left  # noqa: E402

EVENTS_MAX = 8


class subscriber:
	"""A local client that asked `get events`."""

	def __init__(self, sock_path, tag):
		self.tag = tag
		self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.s.settimeout(min(5.0, left()))
		self.s.connect(sock_path)
		self.s.sendall(b"get events\n")
		self.buf = b""
		self.first = self.line()

	def line(self):
		"""The next line, or None at end of stream."""
		until = time.monotonic() + 5.0
		while b"\n" not in self.buf:
			if time.monotonic() > until or left() < 0.1:
				raise failed("%s: no line within 5 s (held %r)" % (self.tag, self.buf))
			try:
				chunk = self.s.recv(4096)
			except socket.timeout:
				continue
			if not chunk:
				return None
			self.buf += chunk
		line, self.buf = self.buf.split(b"\n", 1)
		return line.decode()

	def close(self):
		self.s.close()


def main(argv):
	if len(argv) != 2:
		print("usage: live_events.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	subs = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		store = os.path.join(scratch, "n")
		sock = os.path.join(sock_dir, "n")
		os.mkdir(store)
		try:
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)
			d = daemon(run, "n", store, sock)
			try:
				# a: two subscribers, told of two changes.
				for i in range(2):
					subs.append(subscriber(sock, "s%d" % i))
					if subs[-1].first != "ok events":
						raise failed("a: `get events` answered %r" % subs[-1].first)
				expect(sock, "a", "set setting host x/seen 1", "ok")
				reply = ask(sock, "add note top a-note")
				if not reply.startswith("ok "):
					raise failed("a: add note answered %r" % reply)
				for sub in subs:
					got = [sub.line(), sub.line()]
					if got != ["event setting -", "event note -"]:
						raise failed("a: %s read %r" % (sub.tag, got))
				print("livecheck: a: two subscribers each read the setting's and the note's "
				      "events, in order")

				# b: one hangs up; the other is still told, and the daemon
				# still answers.
				subs.pop(0).close()
				expect(sock, "b", "set setting host x/seen 2", "ok")
				got = subs[0].line()
				if got != "event setting -":
					raise failed("b: the remaining subscriber read %r" % got)
				reply = ask(sock, "get setting host x/seen")
				if not (reply.startswith("ok ") and reply.endswith(" 2")):
					raise failed("b: the daemon answered %r after a subscriber left" % reply)
				print("livecheck: b: one subscriber gone, the other still told and the "
				      "daemon still answering")

				# c: the bound. One is held; seven more fill it, and the
				# next is answered as any request is, then closed.
				for i in range(EVENTS_MAX - 1):
					subs.append(subscriber(sock, "c%d" % i))
					if subs[-1].first != "ok events":
						raise failed("c: subscriber %d answered %r" % (i, subs[-1].first))
				extra = subscriber(sock, "c-extra")
				after = extra.line()
				extra.close()
				if extra.first == "ok events" or after is not None:
					raise failed("c: a subscriber past %d was answered %r, then %r"
					             % (EVENTS_MAX, extra.first, after))
				expect(sock, "c", "set setting host x/seen 3", "ok")
				if any(sub.line() != "event setting -" for sub in subs):
					raise failed("c: a subscriber within the bound was not told")
				print("livecheck: c: %d subscribers taken, the next answered as a request "
				      "(%r) and closed" % (EVENTS_MAX, extra.first))
			finally:
				for sub in subs:
					sub.close()
				d.stop()
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except (subprocess.TimeoutExpired, OSError) as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		finally:
			for pid in run.started:
				if os.path.exists("/proc/%d" % pid):
					try:
						with open("/proc/%d/cmdline" % pid, "rb") as f:
							alive = f.read() != b""
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: local subscribers were told what changed")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
