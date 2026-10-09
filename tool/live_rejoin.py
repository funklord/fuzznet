#!/usr/bin/env python3
"""A member away past the journal's window, rejoining: `make livecheck`, sec 554.

Two stores over loopback. A makes a root and pairs B with a grant B can pass
on; B joins A's estate. Everything below phase b runs on the real clock, and
setup and phase a under `faketime` sixty-two days back, so what they write is
older than the 60-day window when A next cuts:

    a  A sets x/old; B, serving with --root-at A, takes it by the journal and
       is stopped; A then sets x/away, writes a note and a message line,
       none of which B pulls
    b  A, on the real clock, sets x/now and cuts what is older than the
       window -- x/old's, x/away's and the note's records among it. B
       starts: its pull finds both of A's streams cut below what it lacks,
       moves each up to A's base (sec 552), and reconciliation brings x/away
       and the note's claim (secs 551, 555), which no journal holds any
       more; the note lists, its wrap key given by the wraps exchange; and
       the line comes by its conversation's bucket (sec 564), its key
       asked of A, and reads
    c  B restarts: its journal follows from the new bases, the pull misses
       nothing, and the settings and the note read
    d  C, a device paired to A with a plain --accept and so of an estate of
       its own, pulls from A: its reconcile pass counts A as another
       estate's and fetches nothing (sec 556)

The waits are on the daemons' own lines -- A's cut pass, B's reconcile
pass, B's "moved up" -- and each is checked before the settings are.

BOUNDED FROM INSIDE: one deadline over the whole run, each daemon in its own
process group, stopped with TERM and then KILL, and checked gone. Scratch is
two TemporaryDirectory trees, the sockets under /tmp because
`fzn_socket_path_ok` wants a short absolute path.

Exit 0 on a pass, 1 on a failure, 0 with SKIPPED when faketime is absent --
said, not silent.
"""

import datetime
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_trim import ask, failed, left, stop_process  # noqa: E402

CAPABILITY = ["--fuzznet-service=1", "--fuzznet-product=1"]
CUT_RE = re.compile(r"cut pass: a window of (\d+) day\(s\), (\d+) record\(s\) cut")
RECONCILE_RE = re.compile(r"reconcile pass: (\d+) peer\(s\), (\d+) of another estate passed "
                          r"over, (\d+) lacked, (\d+) applied, (\d+) waiting, (\d+) refused")
MOVED_RE = re.compile(r"(\d+) stream\(s\) moved up to 127\.0\.0\.1's base")
WITNESS_RE = re.compile(r"an estate stream moved up to 127\.0\.0\.1's base, its bridge "
                        r"confirmed by (\d+) other peer\(s\) of (\d+) asked")
MISSING_RE = re.compile(r"claims no longer hold what this node lacks|would not move")


def command(run, args, fake):
	"""One fuzznetd command that exits; its stdout's last line."""
	argv = [run.fuzznetd] + args + CAPABILITY
	if fake:
		argv = ["faketime", "-f", fake] + argv
	env = dict(os.environ)
	env["FAKETIME_DONT_FAKE_MONOTONIC"] = "1"
	r = subprocess.run(argv, capture_output=True, timeout=min(20.0, left()), env=env)
	if r.returncode != 0:
		raise failed("%s answered %d: %s" % (args[1], r.returncode,
		                                     r.stderr.decode(errors="replace")[:400]))
	return r.stdout.decode().strip().splitlines()[-1]


class daemon:
	"""One fuzznetd over a store, stopped and reaped on every path out."""

	def __init__(self, run, tag, store, sock, fake=None, extra=()):
		self.tag = tag
		self.log_dir = os.path.join(run.scratch, "log-" + tag)
		os.mkdir(self.log_dir)
		if os.path.exists(sock):
			os.unlink(sock)
		argv = [run.fuzznetd, "--socket=" + sock, "--fuzznet-dir=" + store,
		        "--log-dir=" + self.log_dir, "--log-level=debug"] + CAPABILITY + list(extra)
		env = dict(os.environ)
		self.wrapped = bool(fake)
		if fake:
			argv = ["faketime", "-f", fake] + argv
			env["FAKETIME_DONT_FAKE_MONOTONIC"] = "1"
		self.err_path = os.path.join(run.scratch, tag + ".err")
		self.err = open(self.err_path, "wb")
		self.proc = subprocess.Popen(argv, stdout=self.err, stderr=subprocess.STDOUT,
		                             env=env, start_new_session=True)
		run.started.append(self.proc.pid)
		while not os.path.exists(sock):
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

	def log(self):
		text = ""
		for name in sorted(os.listdir(self.log_dir)):
			with open(os.path.join(self.log_dir, name), "rb") as f:
				text += f.read(1 << 20).decode(errors="replace")
		return text

	def wait_for(self, pattern, what):
		"""The first match of `pattern` in this daemon's log, within 30 s."""
		until = time.monotonic() + 30.0
		while True:
			m = pattern.search(self.log())
			if m:
				return m
			if self.proc.poll() is not None:
				raise failed("%s: the daemon exited before %s:\n%s"
				             % (self.tag, what, self.stderr()))
			if left() < 0.1 or time.monotonic() > until:
				raise failed("%s: no %s was logged within 30 s" % (self.tag, what))
			time.sleep(0.2)

	def stop(self):
		stop_process(self.proc, self.wrapped)
		self.err.close()


def expect(sock, tag, line, want):
	reply = ask(sock, line)
	if reply != want:
		raise failed("%s: %s answered %r, expected %r" % (tag, line, reply, want))


def listed(sock, tag):
	"""The note A wrote while B was away, listed at B."""
	reply = ask(sock, "list note top")
	if not reply.startswith("ok ") or ",away-note," not in reply:
		raise failed("%s: list note top answered %r, without away-note" % (tag, reply))


CONTACT = "5a" * 32
LINE_ID = "02" + "00" * 15


def line_reads(sock, tag):
	"""The line A wrote while B was away, readable at B, within 30 s: its
	key is asked for in the round that filed it, or the next."""
	until = time.monotonic() + 30.0
	while True:
		reply = ask(sock, "list message " + CONTACT)
		fields = reply.split(" ", 4)
		if len(fields) == 5 and fields[0] == "ok" and fields[2] == "1":
			parts = fields[4].split(",")
			if len(parts) >= 9 and parts[7] == "1" and parts[8] == "away-line":
				return
		if time.monotonic() > until or left() < 0.1:
			raise failed("%s: list message answered %r, without away-line readable"
			             % (tag, reply))
		time.sleep(0.5)


def main(argv):
	if len(argv) != 2:
		print("usage: live_rejoin.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2
	if not shutil.which("faketime"):
		print("livecheck: no faketime on PATH, so the rejoin was SKIPPED")
		return 0

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port = str(42000 + os.getpid() % 2000)
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		a_dir = os.path.join(scratch, "a")
		b_dir = os.path.join(scratch, "b")
		a_sock = os.path.join(sock_dir, "a")
		b_sock = os.path.join(sock_dir, "b")
		os.mkdir(a_dir)
		os.mkdir(b_dir)
		then = datetime.datetime.now() - datetime.timedelta(days=62)
		fake = "@" + then.strftime("%Y-%m-%d") + " 12:00:00"
		try:
			# SETUP, under the old clock, so the grants are not from the
			# future when phase a judges them.
			command(run, ["--fuzznet-dir=" + a_dir, "--new-root"], fake)
			prekey = command(run, ["--fuzznet-dir=" + b_dir, "--prekey"], fake)
			card = command(run, ["--fuzznet-dir=" + a_dir, "--pair=" + prekey, "--delegable"],
			               fake)
			command(run, ["--fuzznet-dir=" + b_dir, "--accept=" + card, "--join"], fake)

			# a: B takes x/old by the journal, then A sets x/away unseen.
			a = daemon(run, "a1", a_dir, a_sock, fake=fake, extra=["--udp-port=" + port])
			try:
				expect(a_sock, "a", "set setting estate x/old 1", "ok")
				b = daemon(run, "b1", b_dir, b_sock, fake=fake,
				           extra=["--root-at", "127.0.0.1", port])
				try:
					b.wait_for(RECONCILE_RE, "reconcile pass")
					expect(b_sock, "a", "get setting estate x/old", "ok root 1")
				finally:
					b.stop()
				expect(a_sock, "a", "set setting estate x/away 1", "ok")
				reply = ask(a_sock, "add note top away-note")
				if not reply.startswith("ok"):
					raise failed("a: add note answered %r" % reply)
				reply = ask(a_sock, "add message %s out %s away-line" % (CONTACT, LINE_ID))
				if not reply.startswith("ok"):
					raise failed("a: add message answered %r" % reply)
			finally:
				a.stop()
			print("livecheck: a: B took x/old by the journal and left; A set x/away under %s"
			      % fake)

			# b: A cuts, B rejoins past the window.
			a = daemon(run, "a2", a_dir, a_sock, extra=["--udp-port=" + port])
			try:
				cut = a.wait_for(CUT_RE, "cut pass")
				if int(cut.group(2)) < 2:
					raise failed("b: A's cut pass cut %s record(s); x/old's and x/away's "
					             "were older than the window" % cut.group(2))
				expect(a_sock, "b", "set setting estate x/now 1", "ok")
				b = daemon(run, "b2", b_dir, b_sock, extra=["--root-at", "127.0.0.1", port])
				try:
					moved = b.wait_for(MOVED_RE, "move up to A's base")
					rec = b.wait_for(RECONCILE_RE, "reconcile pass")
					if int(rec.group(2)) != 0 or int(rec.group(4)) < 1 or int(rec.group(6)) != 0:
						raise failed("b: B's reconcile pass passed %s peer(s) over, applied %s "
						             "and refused %s; x/away is in no journal"
						             % (rec.group(2), rec.group(4), rec.group(6)))
					for key in ("x/old", "x/away", "x/now"):
						expect(b_sock, "b", "get setting estate " + key, "ok root 1")
					witnessed = b.wait_for(WITNESS_RE, "the estate bridge's witness count")
					if witnessed.groups() != ("0", "0"):
						raise failed("b: B's estate bridge was confirmed by %s of %s; it pulls "
						             "from A alone" % witnessed.groups())
					if moved.group(1) != "3":
						raise failed("b: B moved %s stream(s) up; A's estate, notes and "
						             "conversations streams were cut below it" % moved.group(1))
					listed(b_sock, "b")
					line_reads(b_sock, "b")
				finally:
					b.stop()
				print("livecheck: b: A cut %s record(s); B moved %s stream(s) up to A's base "
				      "and reconciled %s object(s); x/old, x/away and x/now read"
				      % (cut.group(2), moved.group(1), rec.group(4)))

				# c: B restarts, from the new base, missing nothing.
				b = daemon(run, "b3", b_dir, b_sock, extra=["--root-at", "127.0.0.1", port])
				try:
					rec = b.wait_for(RECONCILE_RE, "reconcile pass")
					if MISSING_RE.search(b.log()):
						raise failed("c: B's pull after the move still missed a stream")
					for key in ("x/old", "x/away", "x/now"):
						expect(b_sock, "c", "get setting estate " + key, "ok root 1")
					listed(b_sock, "c")
					line_reads(b_sock, "c")
				finally:
					b.stop()
			finally:
				a.stop()
			print("livecheck: c: B restarted from the new base, missing nothing, "
			      "the three settings read")

			# d: a device paired to A, not joined, is of an estate of its
			# own: it pulls from A and reconciles nothing with it. sec 556.
			c_dir = os.path.join(scratch, "c")
			c_sock = os.path.join(sock_dir, "c")
			os.mkdir(c_dir)
			prekey = command(run, ["--fuzznet-dir=" + c_dir, "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + a_dir, "--pair=" + prekey], None)
			a_node = command(run, ["--fuzznet-dir=" + c_dir, "--accept=" + card], None)
			a = daemon(run, "a3", a_dir, a_sock, extra=["--udp-port=" + port])
			try:
				c = daemon(run, "c1", c_dir, c_sock,
				           extra=["--pull-from", a_node, "127.0.0.1", port])
				try:
					rec = c.wait_for(RECONCILE_RE, "reconcile pass")
					if rec.group(1) != "1" or rec.group(2) != "1" or rec.group(3) != "0":
						raise failed("d: the paired device's reconcile pass said %s peer(s), "
						             "%s of another estate, %s lacked; A is of another estate"
						             % (rec.group(1), rec.group(2), rec.group(3)))
				finally:
					c.stop()
			finally:
				a.stop()
			print("livecheck: d: a device paired to A, not joined, passed A over and "
			      "fetched nothing of its estate")
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
							alive = f.read() != b""
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: a member away past the window rejoined end to end")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
