#!/usr/bin/env python3
"""The journal's window, cut by the daemon end to end: `make livecheck`, sec 548.

A record old enough to cut can only be signed by a daemon whose clock says
so: phase a runs fuzznetd under `faketime` sixty-two days back, writes a
line in a conversation, sets the estate's `journal/window` to 100 days, and
sets and clears the estate's `c/x`. The phases after it restart the same
node on the real clock:

    b  a window of 100 days              -> nothing cut, no clear forgotten;
                                            then the window is set to 30, a
                                            record of today
    c  a window of 30                    -> the old records cut and c/x's
                                            clear forgotten (sec 549), the
                                            line and the setting still read
    d  again                             -> nothing more cut or forgotten, and
                                            the streams cut in c are read
                                            from their base

b is the control, and it means nothing unless the cut ran: every phase waits
for the daemon's own debug line saying a cut pass finished, and reads its
window and count, before it looks at anything else. d is the restart a cut
has to survive: a daemon that read a cut stream from 1 finds it empty, and
its next pass logs that the stream would not cut, which fails the phase --
seen to, against a build with the start-up scan's base taken away. The
line and the setting read either way, since each is kept in the store.

BOUNDED FROM INSIDE, as live_trim.py is, whose daemon handling this reuses:
one deadline over the whole run, each daemon in its own process group,
stopped with TERM and then KILL, and checked gone.

Exit 0 on a pass, 1 on a failure, 0 with SKIPPED when faketime is absent
-- said, not silent.
"""

import datetime
import os
import re
import shutil
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_trim  # noqa: E402
from live_trim import ask, failed, left, row  # noqa: E402

CUT_RE = re.compile(r"cut pass: a window of (\d+) day\(s\), (\d+) record\(s\) cut, "
                    r"(\d+) clear\(s\) forgotten")
REFUSED_RE = re.compile(r"a stream would not cut")


class daemon(live_trim.daemon):
	def log(self):
		text = ""
		for name in sorted(os.listdir(self.log_dir)):
			with open(os.path.join(self.log_dir, name), "rb") as f:
				text += f.read(1 << 20).decode(errors="replace")
		return text

	def cut_pass(self):
		"""Wait for the first cut pass's line; (window days, records cut,
		clears forgotten)."""
		until = time.monotonic() + 30.0
		while True:
			text = self.log()
			if REFUSED_RE.search(text):
				raise failed("%s: the daemon logged a stream that would not cut" % self.tag)
			m = CUT_RE.search(text)
			if m:
				return tuple(int(g) for g in m.groups())
			if self.proc.poll() is not None:
				raise failed("%s: the daemon exited before a cut pass:\n%s"
				             % (self.tag, self.stderr()))
			if left() < 0.1 or time.monotonic() > until:
				raise failed("%s: no cut pass was logged within 30 s" % self.tag)
			time.sleep(0.2)


def setting(run, tag, want):
	reply = ask(run.sock, "get setting estate journal/window")
	if reply != "ok root " + want:
		raise failed("%s: get setting answered %r, expected the window %s" % (tag, reply, want))


def set_window(run, tag, days):
	reply = ask(run.sock, "set setting estate journal/window %d" % days)
	if reply != "ok":
		raise failed("%s: set setting answered %r" % (tag, reply))


def phase(run, tag, window, cut, forgot, then=None):
	"""One daemon: its first cut pass's window, count -- `cut` exactly, or at
	least its negation when negative -- and clears forgotten, then the line
	and the window."""
	d = daemon(run, tag)
	try:
		got_window, got_cut, got_forgot = d.cut_pass()
		if got_window != window or (got_cut != cut if cut >= 0 else got_cut < -cut) \
		   or got_forgot != forgot:
			raise failed("%s: the cut pass said a window of %d, %d cut, %d forgotten; "
			             "expected %d, %s, %d"
			             % (tag, got_window, got_cut, got_forgot, window,
			                cut if cut >= 0 else "at least %d" % -cut, forgot))
		reply = ask(run.sock, "get setting estate c/x")
		if reply != "ok absent":
			raise failed("%s: c/x, cleared, answered %r" % (tag, reply))
		written, readable, text = row(run, tag)
		if readable != 1 or text != "an%20old%20line":
			raise failed("%s: the line reads %d, %r after the pass" % (tag, readable, text))
		setting(run, tag, str(window))
		if then:
			then(run, tag)
	finally:
		d.stop()
	print("livecheck: %s: a window of %d day(s), %d record(s) cut, %d clear(s) forgotten, "
	      "the line and the window read" % (tag, got_window, got_cut, got_forgot))


def main(argv):
	if len(argv) != 2:
		print("usage: live_cut.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2
	if not shutil.which("faketime"):
		print("livecheck: no faketime on PATH, so the cut was SKIPPED")
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
			then = datetime.datetime.now() - datetime.timedelta(days=62)
			fake = "@" + then.strftime("%Y-%m-%d") + " 12:00:00"
			d = daemon(run, "a", fake=fake)
			try:
				reply = ask(run.sock, "add message %s out %s an old line"
				            % (live_trim.CONTACT, live_trim.LINE_ID))
				if reply != "ok":
					raise failed("a: add message answered %r" % reply)
				set_window(run, "a", 100)
				for line in ("set setting estate c/x on", "remove setting estate c/x"):
					reply = ask(run.sock, line)
					if reply != "ok":
						raise failed("a: %s answered %r" % (line, reply))
				written, readable, text = row(run, "a")
			finally:
				d.stop()
			# THE CLOCK HAS TO HAVE BEEN FAKED, or nothing below is old.
			if written > (time.time() - 61 * 86400) * 1000:
				raise failed("a: the line was written at %d ms: faketime did not take, "
				             "so nothing below would be old enough to cut" % written)
			print("livecheck: a: a line, a window of 100 days and a cleared c/x written "
			      "under %s" % fake)
			phase(run, "b", 100, 0, 0, then=lambda r, t: set_window(r, t, 30))
			phase(run, "c", 30, -4, 1)
			phase(run, "d", 30, 0, 0)
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
	print("livecheck: the journal's window was cut end to end")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
