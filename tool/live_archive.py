#!/usr/bin/env python3
"""Log segments archived to the fossil class, and verified there alone:
`make livecheck`, sec 588.

One store, its log directory kept across runs, its segments small:

    a  short runs until the log holds two packed segments
    b  a run with `--log-rule=archive * count 0`: every packed segment
       moves to LOGDIR/archive -- "segment(s) of fuzznetd archived to" --
       and leaves the log directory
    c  `fuzznetd --log-dir=LOGDIR/archive --check-log` walks the archive
       alone, no store and no journal: its chain holds, signed by the node
    d  a run with `prune * archived count 0` and `keep * archived count 1`:
       the archive's own rules (sec 589) prune all but its newest fossil,
       which still verifies alone

Against a daemon that does not archive, phase b fails at its line; against
one whose archive breaks the chain, phase c does.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure, 0 with SKIPPED for a build that does
not pack -- said, not silent.
"""

import os
import re
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import CAPABILITY, PACKED_RE, command, daemon  # noqa: E402
from live_trim import failed, left  # noqa: E402

ROUND_END_RE = re.compile(r"history pass: ")
ARCHIVED_RE = re.compile(r"(\d+) segment\(s\) of fuzznetd archived to ")
PRUNED_RE = re.compile(r"(\d+) archived segment\(s\) of fuzznetd pruned")
CHECKED_RE = re.compile(r"fuzznetd's log: (\d+) packed segment\(s\), the chain holds")
RUNS = 12


def closed_in(directory):
	"""The closed, unpacked segments of fuzznetd in `directory`."""
	if not os.path.isdir(directory):
		return []
	return [n for n in os.listdir(directory)
	        if n.startswith("fuzznetd.") and n.endswith(".log") and n.count(".") >= 3]


def packed_in(directory):
	"""The packed segments of fuzznetd in `directory`, by name."""
	if not os.path.isdir(directory):
		return []
	return sorted(n for n in os.listdir(directory)
	              if n.startswith("fuzznetd.") and n.endswith(".log.zst"))


def main(argv):
	if len(argv) != 2:
		print("usage: live_archive.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		store = os.path.join(scratch, "n")
		logs = os.path.join(scratch, "log-n")
		archive = os.path.join(logs, "archive")
		sock = os.path.join(sock_dir, "n")
		os.mkdir(store)
		small = ["--log-segment=4096"]
		try:
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)

			# a: two packed segments. A RUN LOGS ABOUT 1.4 KiB, so a 4 KiB
			# segment closes in a few; a closed one is packed once it has
			# settled ten seconds (FZN_LOG_PACK_SETTLE_DEFAULT).
			runs = 0
			while len(closed_in(logs)) < 2:
				if runs >= RUNS:
					raise failed("a: %d runs closed %d segment(s)" % (runs, len(closed_in(logs))))
				runs += 1
				d = daemon(run, "n%d" % runs, store, sock, extra=small, log_dir=logs)
				try:
					d.wait_for(ROUND_END_RE, "a round")
				finally:
					d.stop()
			time.sleep(11)
			d = daemon(run, "np", store, sock, extra=small, log_dir=logs)
			try:
				d.wait_for(PACKED_RE, "the log pass packing")
			finally:
				d.stop()
			held = packed_in(logs)
			if len(held) < 2:
				raise failed("a: %d packed segment(s) after %d runs" % (len(held), RUNS))
			print("livecheck: a: %d packed segments in the log" % len(held))

			# b: all but the newest archived.
			d = daemon(run, "nb", store, sock,
			           extra=small + ["--log-rule=archive * count 0"], log_dir=logs)
			try:
				got = d.wait_for(ARCHIVED_RE, "segments archived")
			finally:
				d.stop()
			fossils = packed_in(archive)
			if int(got.group(1)) < 1 or not fossils or set(fossils) & set(packed_in(logs)):
				raise failed("b: %s archived, the archive holds %r and the log %r"
				             % (got.group(1), fossils, packed_in(logs)))
			print("livecheck: b: %d segment(s) moved to the archive" % len(fossils))

			# c: the archive verified alone.
			r = subprocess.run([run.fuzznetd, "--log-dir=" + archive, "--check-log"]
			                   + CAPABILITY, capture_output=True, timeout=min(20.0, left()))
			out = r.stdout.decode(errors="replace")
			m = CHECKED_RE.search(out)
			if r.returncode != 0 or not m or int(m.group(1)) != len(fossils):
				raise failed("c: --check-log on the archive answered %d: %r %r"
				             % (r.returncode, out, r.stderr.decode(errors="replace")[:300]))
			print("livecheck: c: the archive's %s segment(s) verified alone" % m.group(1))

			# d: the archive's own rules.
			if len(fossils) < 2:
				raise failed("d: %d fossil(s); the phase needs two" % len(fossils))
			d = daemon(run, "nd", store, sock,
			           extra=small + ["--log-rule=prune * archived count 0",
			                          "--log-rule=keep * archived count 1"], log_dir=logs)
			try:
				got = d.wait_for(PRUNED_RE, "the archive pruned")
			finally:
				d.stop()
			left_over = packed_in(archive)
			if int(got.group(1)) != len(fossils) - 1 or left_over != fossils[-1:]:
				raise failed("d: %s pruned; the archive holds %r of %r"
				             % (got.group(1), left_over, fossils))
			r = subprocess.run([run.fuzznetd, "--log-dir=" + archive, "--check-log"]
			                   + CAPABILITY, capture_output=True, timeout=min(20.0, left()))
			m = CHECKED_RE.search(r.stdout.decode(errors="replace"))
			if r.returncode != 0 or not m or m.group(1) != "1":
				raise failed("d: --check-log on the pruned archive answered %d" % r.returncode)
			print("livecheck: d: the archive's rules kept its newest fossil, which verifies")
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
	print("livecheck: log segments archived, and the archive verified alone")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
