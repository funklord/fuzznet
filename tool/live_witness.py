#!/usr/bin/env python3
"""A rejoining member's bridge witnessed by a third node: `make livecheck`, secs 558-559.

Three stores over loopback. A makes a root; B and W join A's estate with
grants they can pass on, and W pairs B as well, so B pulls from both A
(`--root-at`) and W (`--pull-from`). Setup and phase a run under `faketime`
sixty-two days back:

    a  A sets x/old; B takes it and is stopped. A sets x/away, and W,
       started after it, takes all of A's stream
    b  on the real clock A and W each cut what is older than the 60-day
       window, W keeping its spine. B starts: its pull finds A's estate
       stream cut below what it lacks, and the bridge A serves is asked of
       W too and must agree -- "confirmed by 1 other peer(s) of 1 asked"
       (sec 557) -- before B moves up to A's base and reconciles x/away
    c  W is stopped and one subject byte of every entry of its spine is
       changed on disk -- a witness whose store tells the stream otherwise,
       staged without a test hook in the daemon. C, a member like B that
       took x/old and left, starts: the bridge A serves and the one W
       serves disagree, C's estate stream does not move ("a second peer
       tells the stream otherwise"), and reconciliation still brings
       x/away, since the state is signed objects and needs no bridge

Against a daemon that passes no witnesses, phase b fails at that count;
against one that does not compare what they give, phase c moves C.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, a faked one stopped
through its wrapper's child so the wrapper cleans /dev/shm, and every
daemon checked gone.

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

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import RECONCILE_RE, command, daemon, expect  # noqa: E402
from live_trim import failed  # noqa: E402

WITNESS_RE = re.compile(r"an estate stream moved up to 127\.0\.0\.1's base, its bridge "
                        r"confirmed by (\d+) other peer\(s\) of (\d+) asked")
CUT_RE = re.compile(r"cut pass: a window of (\d+) day\(s\), (\d+) record\(s\) cut")
CONFLICT_RE = re.compile(r"a stream behind 127\.0\.0\.1's base would not move: a second peer "
                         r"tells the stream otherwise")
ESTATE_MOVED_RE = re.compile(r"an estate stream moved up to")
SPINE_ENTRY = 96
SPINE_SUBJECT = 64


def falsify_spine(store):
	"""One subject byte of every kept entry of every spine row under
	`store` changed, the rows found by their file names (slot 40). How
	many entries were changed."""
	changed = 0
	for root, _dirs, files in os.walk(store):
		for name in files:
			if not name.startswith("40-"):
				continue
			path = os.path.join(root, name)
			with open(path, "rb") as f:
				row = bytearray(f.read())
			for at in range(0, len(row) - SPINE_ENTRY + 1, SPINE_ENTRY):
				if any(row[at:at + 32]):
					row[at + SPINE_SUBJECT] ^= 1
					changed += 1
			with open(path, "wb") as f:
				f.write(row)
	return changed


def main(argv):
	if len(argv) != 2:
		print("usage: live_witness.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2
	if not shutil.which("faketime"):
		print("livecheck: no faketime on PATH, so the witness was SKIPPED")
		return 0

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port_a = str(44000 + os.getpid() % 2000)
	port_w = str(46000 + os.getpid() % 2000)
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in ("a", "b", "c", "w")}
		socks = {k: os.path.join(sock_dir, k) for k in ("a", "b", "c", "w")}
		for d in dirs.values():
			os.mkdir(d)
		then = datetime.datetime.now() - datetime.timedelta(days=62)
		fake = "@" + then.strftime("%Y-%m-%d") + " 12:00:00"
		try:
			# SETUP: B and W join A's estate; W pairs B too.
			command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], fake)
			prekeys = {k: command(run, ["--fuzznet-dir=" + dirs[k], "--prekey"], fake)
			           for k in ("b", "c", "w")}
			for who in ("b", "c", "w"):
				card = command(run, ["--fuzznet-dir=" + dirs["a"], "--pair=" + prekeys[who],
				                     "--delegable"], fake)
				command(run, ["--fuzznet-dir=" + dirs[who], "--accept=" + card, "--join"], fake)
			for who in ("b", "c"):
				card = command(run, ["--fuzznet-dir=" + dirs["w"], "--pair=" + prekeys[who]],
				               fake)
				w_node = command(run, ["--fuzznet-dir=" + dirs[who], "--accept=" + card], fake)
			b_args = ["--root-at", "127.0.0.1", port_a, "--pull-from", w_node, "127.0.0.1",
			          port_w]
			w_args = ["--udp-port=" + port_w, "--root-at", "127.0.0.1", port_a]

			# a: B takes x/old and leaves; W, started after x/away, takes all.
			a = daemon(run, "a1", dirs["a"], socks["a"], fake=fake,
			           extra=["--udp-port=" + port_a])
			try:
				expect(socks["a"], "a", "set setting estate x/old 1", "ok")
				for who in ("b", "c"):
					m = daemon(run, who + "1", dirs[who], socks[who], fake=fake,
					           extra=["--root-at", "127.0.0.1", port_a])
					try:
						m.wait_for(RECONCILE_RE, "reconcile pass")
						expect(socks[who], "a", "get setting estate x/old", "ok root 1")
					finally:
						m.stop()
				expect(socks["a"], "a", "set setting estate x/away 1", "ok")
				w = daemon(run, "w1", dirs["w"], socks["w"], fake=fake, extra=w_args)
				try:
					w.wait_for(RECONCILE_RE, "reconcile pass")
					expect(socks["w"], "a", "get setting estate x/away", "ok root 1")
				finally:
					w.stop()
			finally:
				a.stop()
			print("livecheck: a: B and C took x/old and left; W took x/away under %s" % fake)

			# b: A and W cut; B rejoins with W as the witness of A's bridge.
			a = daemon(run, "a2", dirs["a"], socks["a"], extra=["--udp-port=" + port_a])
			try:
				cut = a.wait_for(CUT_RE, "A's cut pass")
				w = daemon(run, "w2", dirs["w"], socks["w"], extra=w_args)
				try:
					w_cut = w.wait_for(CUT_RE, "W's cut pass")
					if int(cut.group(2)) < 2 or int(w_cut.group(2)) < 2:
						raise failed("b: A cut %s and W %s record(s); both held records older "
						             "than the window" % (cut.group(2), w_cut.group(2)))
					b = daemon(run, "b2", dirs["b"], socks["b"], extra=b_args)
					try:
						witnessed = b.wait_for(WITNESS_RE, "the estate bridge's witness count")
						if witnessed.groups() != ("1", "1"):
							raise failed("b: B's estate bridge was confirmed by %s of %s; W "
							             "is a peer of the estate holding the same stream"
							             % witnessed.groups())
						b.wait_for(RECONCILE_RE, "reconcile pass")
						expect(socks["b"], "b", "get setting estate x/away", "ok root 1")
					finally:
						b.stop()
				finally:
					w.stop()
			finally:
				a.stop()
			print("livecheck: b: A cut %s and W %s record(s); B's bridge from A was confirmed "
			      "by W, and x/away reads" % (cut.group(2), w_cut.group(2)))

			# c: W's spine tells the stream otherwise; C does not move.
			changed = falsify_spine(dirs["w"])
			if changed < 1:
				raise failed("c: W's store held no spine entry to change")
			a = daemon(run, "a3", dirs["a"], socks["a"], extra=["--udp-port=" + port_a])
			try:
				w = daemon(run, "w3", dirs["w"], socks["w"], extra=w_args)
				try:
					w.wait_for(RECONCILE_RE, "W's reconcile pass")
					c = daemon(run, "c2", dirs["c"], socks["c"], extra=b_args)
					try:
						c.wait_for(CONFLICT_RE, "conflict between A's bridge and W's")
						c.wait_for(RECONCILE_RE, "reconcile pass")
						if ESTATE_MOVED_RE.search(c.log()):
							raise failed("c: C's estate stream moved up on a bridge W tells "
							             "otherwise")
						expect(socks["c"], "c", "get setting estate x/away", "ok root 1")
					finally:
						c.stop()
				finally:
					w.stop()
			finally:
				a.stop()
			print("livecheck: c: %d of W's spine entries changed; C's bridge from A met W's "
			      "disagreement and did not move, and x/away reads by reconciliation"
			      % changed)
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
	print("livecheck: a rejoining member's bridge was witnessed by a third node")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
