#!/usr/bin/env python3
"""Run live scripts again and again, keeping what failed: sec 689 step 0a.

    live_repeat.py --out DIR [--runs N] [--keep K] [--fuzznetd PATH]
                   [--timeout S] [--args 'OPTIONS'] SCRIPT...

SCRIPT is a live script's name as `make livecheck` runs it -- `deliver`
for `tool/live_deliver.py` -- run against PATH (./fuzznetd by default), N
times each in turn (3 by default), one at a time.

WHY: a flake is found by repetition and diagnosed from what the failing
run left behind, and `make livecheck` gives neither. It runs each script
once, and every script's scratch -- the daemons' logs and stores -- is a
TemporaryDirectory gone the moment the script exits. Sec 675's failures
stayed unexplained for exactly those two reasons.

WHAT IS KEPT: each run gets a TMPDIR of its own under DIR, and runs with
`tempfile.TemporaryDirectory` wrapped so a directory under that TMPDIR is
not removed when it is let go. A socket directory, made under /tmp by
name for the length of a socket path, is removed as before. A run that
passes has its TMPDIR removed by this runner; one that fails keeps it,
with the script's output beside it, until K are kept (5 by default) --
past that a failure is tallied and its directory removed, so a script
that always fails cannot fill a disk.

BOUNDED FROM INSIDE:
- each run has the timeout `make livecheck` gives its script, read from
  the Makefile, or 600 s for one it does not run, or S for all;
- a run past its timeout is sent SIGINT, which the scripts take as
  KeyboardInterrupt, so their `finally` blocks stop their daemons; 20 s
  later SIGKILL to its process group;
- after every run, any process still running whose command line names
  that run's TMPDIR -- a daemon a killed script could not stop -- is
  sent SIGKILL, its command line read again just before, so a pid reused
  by another process is left alone;
- the whole is N times the scripts named, one at a time, nothing more.

Exit 0 when every run passed, 1 when any failed, 2 on a usage error.
"""

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import time

TOOL = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOL)
DEFAULT_TIMEOUT = 600
GRACE_S = 20

# THE WRAPPER a run is started through: the script run as __main__, with a
# TemporaryDirectory under this run's TMPDIR kept rather than removed.
BOOT = r"""
import os, runpy, sys, tempfile
keep_under = os.path.realpath(os.environ["FZN_LIVE_KEEP_UNDER"]) + os.sep
class Kept(tempfile.TemporaryDirectory):
	def cleanup(self):
		if os.path.realpath(self.name).startswith(keep_under):
			self._finalizer.detach()
			return
		super().cleanup()
	def __exit__(self, *exc):
		self.cleanup()
tempfile.TemporaryDirectory = Kept
script = sys.argv[1]
sys.argv = sys.argv[1:]
sys.path.insert(0, os.path.dirname(script))
runpy.run_path(script, run_name="__main__")
"""


def timeouts():
	"""Each script's timeout as `make livecheck` gives it."""
	found = {}
	try:
		with open(os.path.join(ROOT, "Makefile")) as f:
			for line in f:
				m = re.search(r"timeout (\d+) python3 tool/live_(\w+)\.py", line)
				if m:
					found[m.group(2)] = int(m.group(1))
	except OSError:
		pass
	return found


def holds(pid, needle):
	"""Whether `pid` is still a process whose command line names `needle`."""
	try:
		with open("/proc/%d/cmdline" % pid, "rb") as f:
			return needle.encode() in f.read()
	except OSError:
		return False


def sweep(run_dir):
	"""Kill what a run left running under its TMPDIR; how many."""
	killed = 0
	for name in os.listdir("/proc"):
		if not name.isdigit() or int(name) == os.getpid():
			continue
		pid = int(name)
		if holds(pid, run_dir):
			# READ AGAIN RIGHT BEFORE THE SIGNAL: a pid is a moment.
			if holds(pid, run_dir):
				try:
					os.kill(pid, signal.SIGKILL)
					killed += 1
				except OSError:
					pass
	return killed


def run_once(script, fuzznetd, run_dir, limit, extra=()):
	"""One run: its exit status (None when it was stopped) and output;
	`extra` after the daemon's path, as a script's own options."""
	env = dict(os.environ)
	env["TMPDIR"] = run_dir
	env["FZN_LIVE_KEEP_UNDER"] = run_dir
	out_path = os.path.join(run_dir, "output.txt")
	with open(out_path, "wb") as out:
		proc = subprocess.Popen([sys.executable, "-c", BOOT, script, fuzznetd] + list(extra),
		                        cwd=ROOT,
								env=env, stdout=out, stderr=subprocess.STDOUT,
								start_new_session=True)
		try:
			status = proc.wait(timeout=limit)
		except subprocess.TimeoutExpired:
			status = None
			try:
				os.killpg(proc.pid, signal.SIGINT)
				proc.wait(timeout=GRACE_S)
			except (OSError, subprocess.TimeoutExpired):
				try:
					os.killpg(proc.pid, signal.SIGKILL)
				except OSError:
					pass
				proc.wait()
	with open(out_path, "rb") as f:
		return status, f.read().decode(errors="replace")


def main(argv):
	p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	p.add_argument("--out", required=True)
	p.add_argument("--runs", type=int, default=3)
	p.add_argument("--keep", type=int, default=5)
	p.add_argument("--fuzznetd", default=os.path.join(ROOT, "fuzznetd"))
	p.add_argument("--timeout", type=int, default=0)
	p.add_argument("--args", default="",
	               help="options handed to every script after the daemon, e.g. '--skew 900'")
	p.add_argument("scripts", nargs="+")
	a = p.parse_args(argv[1:])
	if a.runs < 1 or a.keep < 0:
		print("live_repeat: --runs is at least 1, --keep at least 0", file=sys.stderr)
		return 2
	limits = timeouts()
	paths = {}
	for s in a.scripts:
		path = os.path.join(TOOL, "live_%s.py" % s)
		if not os.path.isfile(path):
			print("live_repeat: no tool/live_%s.py" % s, file=sys.stderr)
			return 2
		paths[s] = path
	out = os.path.abspath(a.out)
	os.makedirs(out, exist_ok=True)
	fuzznetd = os.path.abspath(a.fuzznetd)
	tally = {s: [0, 0, 0] for s in a.scripts}   # passed, failed, stopped
	kept = 0
	for n in range(1, a.runs + 1):
		for s in a.scripts:
			run_dir = os.path.join(out, "%s.%d" % (s, n))
			if os.path.exists(run_dir):
				shutil.rmtree(run_dir)
			os.mkdir(run_dir)
			started = time.monotonic()
			limit = a.timeout or limits.get(s, DEFAULT_TIMEOUT)
			status, text = run_once(paths[s], fuzznetd, run_dir, limit, a.args.split())
			took = time.monotonic() - started
			left = sweep(run_dir)
			ok = status == 0 and left == 0
			tally[s][0 if ok else (2 if status is None else 1)] += 1
			said = [l for l in text.splitlines() if "FAILED" in l][:1]
			print("live_repeat: %s run %d: %s in %.1f s%s%s" % (
				s, n, "passed" if ok else ("stopped at its timeout" if status is None
										   else "FAILED (%s)" % status), took,
				", %d process(es) left running and killed" % left if left else "",
				"\n  " + said[0] if said and not ok else ""), flush=True)
			if ok or kept >= a.keep:
				shutil.rmtree(run_dir, ignore_errors=True)
			else:
				kept += 1
				print("live_repeat:   kept %s" % run_dir, flush=True)
	bad = 0
	for s in a.scripts:
		passed, failed, stopped = tally[s]
		bad += failed + stopped
		print("live_repeat: %s: %d passed, %d failed, %d stopped, of %d" % (
			s, passed, failed, stopped, a.runs))
	return 1 if bad else 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
