#!/usr/bin/env python3
"""The file transfer's throughput by its knobs: sec 692's bench.

    bench_transfer.py FUZZNETD_FAULTS [--sizes 1,16] [--loss 0,5]
                      [--tune NAME=V1,V2 ...] [--repeat N] [--deadline S]

Run against `make fuzznetd-faults`' daemon, whose knobs FZN_TUNE_NAME sets
(`fault/fault.h`): FETCH_WINDOW, LEAVES_A_ROUND, PULL_EVERY and
SPAN_DEADLINE_MS. An estate of two: A, the root, puts a file of SIZE MiB
of random bytes; B, joined to it, is handed the file's reference and
fetches it from A. Every point of sizes x loss x each --tune grid is run
on freshly started daemons, since a knob is read once at start, and
--repeat times.

FOR EACH POINT:
- the seconds from `fetch file` to B answering `get file ROOT check` with
  `ok intact`, and the MiB/s that makes;
- each daemon's CPU seconds a MiB, from /proc, over the fetch;
- the meter's file bytes (sec 685) each way at both, against the file's
  length;
- the longest B's local socket kept a `get file` waiting during the
  fetch: a fetch runs in the daemon's loop.

MEASURES, AND TUNES NOTHING: files stay outside sec 689's subset, the
holder's "to get them right later". A point that does not finish within
--deadline seconds is reported as such, not dropped.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this
reuses: each point's deadline, each daemon in its own process group and
stopped, and every daemon checked gone.
"""

import argparse
import itertools
import os
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import RECONCILE_RE, command, daemon  # noqa: E402
import live_trim  # noqa: E402
from live_trim import failed  # noqa: E402

KNOBS = ("FETCH_WINDOW", "LEAVES_A_ROUND", "PULL_EVERY", "SPAN_DEADLINE_MS")
TICK = os.sysconf("SC_CLK_TCK")


def timed_ask(sock_path, line, within=600.0):
	"""`line` asked at `sock_path`: its answer, and the seconds it took. A
	daemon busy fetching may keep its local socket waiting, which is one of
	the things measured here, so the wait is long and timed rather than
	failed at live_trim's five seconds."""
	started = time.monotonic()
	s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	s.settimeout(within)
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
	return buf.decode(errors="replace").rstrip("\n"), time.monotonic() - started


def load():
	"""The machine's one-minute load: a point measured on a loaded machine is
	not the same measurement, and this machine is shared."""
	with open("/proc/loadavg") as f:
		return float(f.read().split()[0])


def cpu_s(pid):
	"""User and system seconds `pid` has spent."""
	with open("/proc/%d/stat" % pid) as f:
		fields = f.read().rsplit(")", 1)[1].split()
	return (int(fields[11]) + int(fields[12])) / TICK


def files_bytes(sock):
	"""The meter's file family, up and down."""
	for w in timed_ask(sock, "get transfer")[0].split()[1:]:
		name, up, down = w.split(",")
		if name == "files":
			return int(up), int(down)
	return 0, 0


def environment(loss, tune):
	for k in list(os.environ):
		if k.startswith("FZN_FAULT_") or k.startswith("FZN_TUNE_"):
			del os.environ[k]
	if loss:
		os.environ["FZN_FAULT_LOSS"] = str(loss)
	for k, v in tune.items():
		os.environ["FZN_TUNE_" + k] = str(v)


def point(run, dirs, socks, port, size_mib, loss, tune, deadline, n):
	"""One measurement: a dict, or one saying it did not finish."""
	environment(loss, tune)
	a = daemon(run, "a%d" % n, dirs["a"], socks["a"], extra=["--udp-port=" + port])
	try:
		b = daemon(run, "b%d" % n, dirs["b"], socks["b"],
		           extra=["--root-at", "127.0.0.1", port])
		try:
			b.wait_for(RECONCILE_RE, "B's first reconcile pass", within=120.0)
			path = os.path.join(run.scratch, "payload.%d" % n)
			with open(path, "wb") as f:
				for _ in range(size_mib):
					f.write(os.urandom(1 << 20))
			put = timed_ask(socks["a"], "put file " + path)[0].split()
			if len(put) < 2 or put[0] != "ok":
				raise failed("put file answered %r" % put)
			ref = put[1]
			root = ref[:64]
			a_cpu, b_cpu = cpu_s(a.proc.pid), cpu_s(b.proc.pid)
			a_up0, a_down0 = files_bytes(socks["a"])
			b_up0, b_down0 = files_bytes(socks["b"])
			load_before = load()
			started = time.monotonic()
			got = timed_ask(socks["b"], "fetch file " + ref)[0]
			if not got.startswith("ok"):
				raise failed("fetch file answered %r" % got)
			done, stall = None, 0.0
			while time.monotonic() - started < deadline:
				try:
					said, took = timed_ask(socks["b"], "get file %s check" % root,
					                       within=max(1.0, deadline
					                                  - (time.monotonic() - started)))
				except socket.timeout:
					# STILL WAITING AT THE DEADLINE: not finished, and the
					# wait is the stall.
					stall = max(stall, time.monotonic() - started)
					break
				stall = max(stall, took)
				if said.strip() == "ok intact":
					done = time.monotonic() - started
					break
				time.sleep(0.1)
			a_up, a_down = files_bytes(socks["a"])
			b_up, b_down = files_bytes(socks["b"])
			out = {
				"size": size_mib, "loss": loss, "tune": tune, "seconds": done,
				"a_cpu": cpu_s(a.proc.pid) - a_cpu, "b_cpu": cpu_s(b.proc.pid) - b_cpu,
				"a_up": a_up - a_up0, "b_down": b_down - b_down0,
				"a_down": a_down - a_down0, "b_up": b_up - b_up0, "stall": stall,
				"load": max(load_before, load()),
			}
			os.remove(path)
			return out
		finally:
			b.stop()
	finally:
		a.stop()


def show(p):
	tune = ",".join("%s=%s" % kv for kv in sorted(p["tune"].items())) or "defaults"
	if p["seconds"] is None:
		return "%4d MiB  loss %2d%%  %-40s  did not finish, load %.0f" % (
			p["size"], p["loss"], tune, p["load"])
	mib = p["size"]
	return ("%4d MiB  loss %2d%%  %-40s  %7.1f s  %6.2f MiB/s  cpu/MiB A %.3f s B %.3f s  "
	        "files A up %.2fx B down %.2fx  B's socket waited %.1f s  load %.0f" % (
	            mib, p["loss"], tune, p["seconds"], mib / p["seconds"] if p["seconds"] else 0,
	            p["a_cpu"] / mib, p["b_cpu"] / mib, p["a_up"] / (mib << 20),
	            p["b_down"] / (mib << 20), p["stall"], p["load"]))


def main(argv):
	ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	ap.add_argument("fuzznetd")
	ap.add_argument("--sizes", default="1,16")
	ap.add_argument("--loss", default="0")
	ap.add_argument("--tune", action="append", default=[])
	ap.add_argument("--repeat", type=int, default=1)
	ap.add_argument("--deadline", type=float, default=600.0)
	a = ap.parse_args(argv[1:])
	grids = {}
	for t in a.tune:
		k, _, vs = t.partition("=")
		if k not in KNOBS or not vs:
			print("bench_transfer: --tune NAME=V1,V2, NAME one of %s" % ", ".join(KNOBS),
			      file=sys.stderr)
			return 2
		grids[k] = [int(v) for v in vs.split(",")]
	sizes = [int(s) for s in a.sizes.split(",")]
	losses = [int(x) for x in a.loss.split(",")]
	combos = [dict(zip(grids, vals)) for vals in itertools.product(*grids.values())] or [{}]
	# THE HELPERS' DEADLINE, live_trim's 240 s for a live script, made the
	# bench's: every point's own and a start-up's more.
	points = len(sizes) * len(losses) * len(combos) * a.repeat
	live_trim.DEADLINE = time.monotonic() + points * (a.deadline + 180.0) + 120.0

	class run:
		pass

	run.fuzznetd = os.path.abspath(a.fuzznetd)
	run.started = []
	port = str(12000 + os.getpid() % 2000)
	results = []
	with tempfile.TemporaryDirectory(prefix="fzn-bench.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in "ab"}
		socks = {k: os.path.join(sock_dir, k) for k in "ab"}
		try:
			for d in dirs.values():
				os.mkdir(d)
			environment(0, {})
			command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + dirs["b"], "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + dirs["a"], "--pair=" + prekey,
			                     "--delegable"], None)
			command(run, ["--fuzznet-dir=" + dirs["b"], "--accept=" + card, "--join"], None)
			n = 0
			for size, loss, tune, _ in itertools.product(sizes, losses, combos,
			                                              range(a.repeat)):
				n += 1
				p = point(run, dirs, socks, port, size, loss, tune, a.deadline, n)
				results.append(p)
				print("bench_transfer: " + show(p), flush=True)
		except failed as e:
			print("bench_transfer: FAILED -- %s" % e)
			return 1
		finally:
			environment(0, {})
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
						print("bench_transfer: FAILED -- daemon %d outlived its point" % pid)
						return 1
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
