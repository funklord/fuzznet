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
    d  one line added to a conversation raises `event message` once, not
       again when the node absorbs its own record (sec 876); and one
       catalogue assertion raises `event catalog` once

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

	def lines_within(self, seconds):
		"""Every line that arrives within `seconds`."""
		got = []
		until = time.monotonic() + seconds
		while time.monotonic() < until and left() > 0.1:
			while b"\n" in self.buf:
				line, self.buf = self.buf.split(b"\n", 1)
				got.append(line.decode())
			self.s.settimeout(max(0.05, min(0.5, until - time.monotonic())))
			try:
				chunk = self.s.recv(4096)
			except socket.timeout:
				continue
			if not chunk:
				break
			self.buf += chunk
		while b"\n" in self.buf:
			line, self.buf = self.buf.split(b"\n", 1)
			got.append(line.decode())
		return got

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

				# d: ONE LINE, ONE EVENT, sec 876 -- fuzzypickles saw two, the
				# second when the node absorbed its own record.
				expect(sock, "d", "add contact alice " + "5a" * 32, "ok")
				for sub in subs:
					sub.lines_within(0.5)
				reply = ask(sock, "add message alice in %032x hello" % 1)
				if reply != "ok":
					raise failed("d: add message answered %r" % reply)
				got = [l for l in subs[0].lines_within(3.0) if l.startswith("event message")]
				if got != ["event message -"]:
					raise failed("d: one line raised %r" % got)
				# AND THE CATALOGUE, the same shape: the verb indexes its own
				# record as it answers.
				src = os.path.join(scratch, "song")
				with open(src, "wb") as f:
					f.write(b"la" * 600)
				put = ask(sock, "put file " + src).split()
				if len(put) != 3 or put[0] != "ok":
					raise failed("d: put file answered %r" % put)
				for sub in subs:
					sub.lines_within(0.5)
				reply = ask(sock, "add catalog %s name song" % put[1][:64])
				if reply != "ok":
					raise failed("d: add catalog answered %r" % reply)
				got = [l for l in subs[0].lines_within(3.0) if l.startswith("event catalog")]
				if len(got) != 1:
					raise failed("d: one catalogue assertion raised %r" % got)
				print("livecheck: d: one line added raised `event message` once, and one "
				      "catalogue assertion `event catalog` once")
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
	print("livecheck: local subscribers were told what changed")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
