#!/usr/bin/env python3
"""The daemon's message trim, run end to end: `make livecheck`, sec 534.

A line's month is the writing clock's, so a line old enough to trim can
only be written by a daemon whose clock says so: phase a runs fuzznetd
under `faketime` some sixty days back and writes one line in each of two
conversations, x's and y's. The phases after it restart the same node on
the real clock:

    b  no rule                                -> both read
    c  a message rule for another host, and
       a log rule                             -> both read
    d  `prune messages contact=X age 1d`      -> x's month trimmed, y's reads
    e  the same rule, for every contact, SET AS THIS HOST'S SETTING by the
       admin verb (sec 540), after the pass   -> y's still reads
    f  no command-line rule                   -> the setting trims y's month
    g  again                                  -> both stay trimmed

b, c and e are the controls, and a control means nothing unless the trim
ran: every phase waits for the daemon's own debug line saying a trim pass
finished, and reads that pass's rule count, before it looks at the lines.

BOUNDED FROM INSIDE: one deadline over the whole run, each daemon in its
own process group, stopped with TERM and then KILL, and checked gone.
Scratch is two TemporaryDirectory trees, the socket's under /tmp because
`fzn_socket_path_ok` wants a short absolute path.

Exit 0 on a pass, 1 on a failure, 0 with SKIPPED when faketime is absent
-- said, not silent.
"""

import datetime
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

DEADLINE = time.monotonic() + 240.0
CONTACT = "5a" * 32
OTHER_CONTACT = "6b" * 32
OTHER_HOST = "77" * 32
LINE_ID = "01" + "00" * 15
CAPABILITY = ["--fuzznet-service=1", "--fuzznet-product=1"]
PASS_RE = re.compile(r"trim pass: (\d+) of (\d+) rule\(s\) over conversations here, "
                     r"(\d+) month\(s\) trimmed")


class failed(Exception):
	pass


def left():
	remaining = DEADLINE - time.monotonic()
	if remaining <= 0:
		raise failed("the run passed its 240 s deadline")
	return remaining


def ask(sock_path, line):
	s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	s.settimeout(min(5.0, left()))
	try:
		s.connect(sock_path)
		s.sendall(line.encode() + b"\n")
		buf = b""
		while b"\n" not in buf and len(buf) < 65536:
			chunk = s.recv(4096)
			if not chunk:
				break
			buf += chunk
	finally:
		s.close()
	return buf.decode(errors="replace").rstrip("\n")


class daemon:
	"""One fuzznetd over the node, stopped and reaped on every path out."""

	def __init__(self, run, tag, fake=None, extra=()):
		self.run = run
		self.tag = tag
		self.log_dir = os.path.join(run.scratch, "log-" + tag)
		os.mkdir(self.log_dir)
		if os.path.exists(run.sock):
			os.unlink(run.sock)
		argv = [run.fuzznetd, "--socket=" + run.sock, "--fuzznet-dir=" + run.node,
		        "--log-dir=" + self.log_dir, "--log-level=debug"] + CAPABILITY + list(extra)
		env = dict(os.environ)
		if fake:
			argv = ["faketime", "-f", fake] + argv
			env["FAKETIME_DONT_FAKE_MONOTONIC"] = "1"
		self.err_path = os.path.join(run.scratch, tag + ".err")
		self.err = open(self.err_path, "wb")
		self.proc = subprocess.Popen(argv, stdout=self.err, stderr=subprocess.STDOUT,
		                             env=env, start_new_session=True)
		run.started.append(self.proc.pid)
		while not os.path.exists(run.sock):
			if self.proc.poll() is not None:
				raise failed("%s: the daemon exited before listening:\n%s"
				             % (tag, self.stderr()))
			if left() < 0.1:
				break
			time.sleep(0.1)

	def stderr(self):
		self.err.flush()
		with open(self.err_path, "rb") as f:
			return f.read(4096).decode(errors="replace")

	def trim_pass(self):
		"""Wait for the first trim pass's line; (selected, gathered, months).

		A pass runs in the round the daemon starts with, so 30 s is ample;
		a daemon that never trims fails here rather than at the deadline."""
		until = time.monotonic() + 30.0
		while True:
			for name in sorted(os.listdir(self.log_dir)):
				with open(os.path.join(self.log_dir, name), "rb") as f:
					m = PASS_RE.search(f.read(1 << 20).decode(errors="replace"))
				if m:
					return tuple(int(g) for g in m.groups())
			if self.proc.poll() is not None:
				raise failed("%s: the daemon exited before a trim pass:\n%s"
				             % (self.tag, self.stderr()))
			if left() < 0.1 or time.monotonic() > until:
				raise failed("%s: no trim pass was logged within 30 s" % self.tag)
			time.sleep(0.2)

	def stop(self):
		if self.proc.poll() is None:
			os.killpg(self.proc.pid, signal.SIGTERM)
			try:
				self.proc.wait(timeout=10)
			except subprocess.TimeoutExpired:
				os.killpg(self.proc.pid, signal.SIGKILL)
				self.proc.wait(timeout=10)
		self.err.close()


def row(run, tag, contact=CONTACT):
	"""A conversation's one line: (written_at_ms, readable, text)."""
	reply = ask(run.sock, "list message " + contact)
	fields = reply.split(" ", 4)
	if len(fields) < 5 or fields[0] != "ok" or fields[2] != "1":
		raise failed("%s: list message answered %r" % (tag, reply))
	parts = fields[4].split(",")
	return int(parts[6]), int(parts[7]), parts[8]


def phase(run, tag, want_pass, want_readable, extra=(), then=None):
	"""One daemon: its first trim pass's counts, then each conversation's
	line readable or not, as `want_readable` (x's, y's); `then`, given,
	is asked of the daemon after both are checked."""
	d = daemon(run, tag, extra=extra)
	try:
		got = d.trim_pass()
		if got != want_pass:
			raise failed("%s: the trim pass said %d of %d rule(s), %d month(s); "
			             "expected %d of %d, %d" % ((tag,) + got + want_pass))
		readable = (row(run, tag, CONTACT)[1], row(run, tag, OTHER_CONTACT)[1])
		if readable != want_readable:
			raise failed("%s: the lines read %d and %d after the pass, expected %d and %d"
			             % ((tag,) + readable + want_readable))
		if then:
			then(run, tag)
	finally:
		d.stop()
	print("livecheck: %s: %d of %d rule(s) applied, %d month(s) trimmed, lines readable %d %d"
	      % ((tag,) + want_pass + want_readable))


def set_the_rule(run, tag):
	"""This host's retention rule, as a setting, by the admin verb."""
	reply = ask(run.sock, "set setting host retention/1 prune messages age 1d")
	if reply != "ok":
		raise failed("%s: set setting answered %r" % (tag, reply))
	reply = ask(run.sock, "get setting host retention/1")
	if reply != "ok root prune%20messages%20age%201d":
		raise failed("%s: get setting answered %r" % (tag, reply))


def main(argv):
	if len(argv) != 2:
		print("usage: live_trim.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2
	if not shutil.which("faketime"):
		print("livecheck: no faketime on PATH, so it was SKIPPED")
		return 0

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		run.node = os.path.join(scratch, "node")
		run.sock = os.path.join(sock_dir, "s")
		os.mkdir(run.node)
		try:
			# a: sixty-odd days back, so the line's month ended more than a
			# day ago whatever today is, and is never the current month.
			then = datetime.datetime.now() - datetime.timedelta(days=62)
			fake = "@" + then.strftime("%Y-%m-%d") + " 12:00:00"
			d = daemon(run, "a", fake=fake)
			try:
				for contact in (CONTACT, OTHER_CONTACT):
					reply = ask(run.sock,
					            "add message %s out %s an old line" % (contact, LINE_ID))
					if reply != "ok":
						raise failed("a: add message answered %r" % reply)
				written, readable, text = row(run, "a")
			finally:
				d.stop()
			# THE CLOCK HAS TO HAVE BEEN FAKED, or every phase below tests a
			# line of the current month: the capability, not faketime's name.
			if written > (time.time() - 31 * 86400) * 1000 or readable != 1:
				raise failed("a: the line was written at %d ms, readable %d: faketime did "
				             "not take, so nothing below would be old enough" % (written, readable))
			print("livecheck: a: a line in each of two conversations written under %s" % fake)
			phase(run, "b", (0, 0, 0), (1, 1))
			phase(run, "c", (0, 2, 0), (1, 1),
			      ["--log-rule=prune messages host=%s age 1d" % OTHER_HOST,
			       "--log-rule=prune * age 1d"])
			phase(run, "d", (1, 1, 1), (0, 1),
			      ["--log-rule=prune messages contact=%s age 1d" % CONTACT])
			phase(run, "e", (0, 0, 0), (0, 1), then=set_the_rule)
			phase(run, "f", (1, 1, 1), (0, 0))
			phase(run, "g", (1, 1, 0), (0, 0))
		except failed as e:
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
	print("livecheck: the daemon's message trim ran end to end")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
