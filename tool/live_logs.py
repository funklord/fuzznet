#!/usr/bin/env python3
"""A host's log configured by verb, and gathered by a member: sec 735.

Run against `make fuzznetd-faults`' daemon, whose rounds FZN_TUNE_PULL_EVERY
makes short. Two stores over loopback: A, a root, and B, a device joined to
A's estate.

    a  A's `set setting host log/level info` stops the debug lines its
       `--log-level=debug` wrote, and `remove setting host log/level` brings
       the flag's level back
    b  B, stopped, gathers A's log by its estate pairing (`--gather` with
       `--root-at`): refused while A's log is host-private, the default
    c  A's `set setting host log/scope estate`: B's gather takes A's lines
    d  A's `set setting host log/segment 4096`: A's log rotates into closed
       segments as it writes

Each was a flag alone before (`--log-level`, `--log-scope`,
`--log-segment`), so a client could not configure a running host's log.

BOUNDED FROM INSIDE as live_estate.py is: one deadline, each daemon in its own
process group, and every daemon checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 400.0

# ROUNDS OF TWO SECONDS, the fault build's knob (sec 693).
ROUND_S = "2"
SETTLE = 60.0


def main(argv):
	if len(argv) != 2:
		print("usage: live_logs.py PATH_TO_FAULTS_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 42000 + (os.getpid() % 500) * 4
	port = {"a": str(base), "b": str(base + 1)}
	os.environ["FZN_TUNE_PULL_EVERY"] = ROUND_S
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}

		def up(who):
			started[who] = daemon(run, who, dirs[who], socks[who],
			                      extra=["--udp-port=" + port[who]])
			return started[who]

		def said(who, line):
			return ask(socks[who], line).strip()

		def polled(test, what):
			until = time.monotonic() + SETTLE
			while not test():
				if time.monotonic() > until:
					raise failed(what)
				time.sleep(0.5)

		def lines_at(level):
			"""A's log file's lines at `level`, a letter, in the file now."""
			path = os.path.join(started["a"].log_dir, "fuzznetd.log")
			try:
				with open(path, errors="replace") as f:
					return sum(1 for line in f if (" %s " % level) in line)
			except OSError:
				return 0

		def gather():
			"""B's gather of A's log, B stopped: (exit status, stdout, stderr)."""
			p = subprocess.run([run.fuzznetd, "--fuzznet-dir=" + dirs["b"],
			                    "--gather=fuzznetd", "--since=600",
			                    "--root-at", "127.0.0.1", port["a"]],
			                   capture_output=True, text=True, timeout=60)
			return p.returncode, p.stdout, p.stderr

		try:
			os.mkdir(dirs["a"])
			command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
			up("a").wait_for(ROUND_DONE_RE, "A's first round")
			expect(socks["a"], "a", "set setting host net/address 127.0.0.1 " + port["a"], "ok")

			# B joins A's estate by a card A answers, as live_group_skew's.
			os.mkdir(dirs["b"])
			up("b")
			got = said("b", "get prekey").split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("b: get prekey answered %r" % got)
			card = said("a", "add peer %s delegable" % got[1]).split()
			if len(card) != 2 or card[0] != "ok":
				raise failed("a: add peer answered %r" % card)
			path = os.path.join(scratch, "card-b")
			with open(path, "w") as f:
				f.write(card[1] + "\n")
			joined = said("b", "add join " + path).split()
			if len(joined) != 2 or joined[0] != "ok":
				raise failed("b: add join answered %r" % joined)
			until = time.monotonic() + 30.0
			while time.monotonic() < until:
				try:
					if said("b", "status").startswith("ok "):
						break
				except OSError:
					pass
				time.sleep(0.2)
			polled(lambda: "member,1,1,0" in said("b", "list capability").split()[2:],
			       "b: not member held by one hop")
			expect(socks["b"], "b", "set setting host net/address 127.0.0.1 " + port["b"], "ok")

			# a: the level by verb over the flag's, and back. The test's daemons
			# start with `--log-level=debug`.
			expect(socks["a"], "a", "set setting host log/level info", "ok")
			time.sleep(2.0)
			settled = lines_at("D")
			time.sleep(3 * int(ROUND_S))
			if lines_at("D") != settled:
				raise failed("a: debug lines still written at log/level info: %d, then %d"
				             % (settled, lines_at("D")))
			expect(socks["a"], "a", "remove setting host log/level", "ok")
			polled(lambda: lines_at("D") > settled + 3,
			       "a: no debug lines once log/level was removed, --log-level=debug's again")
			print("livecheck: a: A's log kept no debug lines at log/level info, and took them "
			      "again from --log-level once it was removed")

			# b: a member's gather, refused while A's log is host-private.
			started.pop("b").stop()
			rc, out, err = gather()
			if rc == 0 or out.strip():
				raise failed("b: gathered A's host-private log: rc %d, %r, %r"
				             % (rc, out[:200], err[-200:]))
			print("livecheck: b: B's gather of A's host-private log was refused")

			# c: the estate's to gather, by verb.
			expect(socks["a"], "a", "set setting host log/scope estate", "ok")
			time.sleep(2.0)
			rc, out, err = gather()
			if rc != 0 or "fuzznetd" not in out:
				raise failed("b: no lines gathered after log/scope estate: rc %d, %r, %r"
				             % (rc, out[:200], err[-300:]))
			print("livecheck: c: after log/scope estate, B gathered %d of A's lines"
			      % len(out.splitlines()))

			# d: a segment size by verb, and the log rotating at it.
			def closed():
				return [n for n in os.listdir(started["a"].log_dir)
				        if n.startswith("fuzznetd.") and n != "fuzznetd.log"
				        and (n.endswith(".log") or n.endswith(".log.zst"))]
			had = len(closed())
			expect(socks["a"], "a", "set setting host log/segment 4096", "ok")
			polled(lambda: len(closed()) >= had + 2,
			       "a: no closed segments after log/segment 4096 (%d before)" % had)
			print("livecheck: d: A's log rotated at 4096 bytes by log/segment")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			for name in sorted(os.listdir(scratch)):
				if name.endswith(".err"):
					with open(os.path.join(scratch, name), errors="replace") as f:
						tail = f.read().splitlines()[-8:]
					print("livecheck: --- %s" % name)
					for line in tail:
						print("livecheck:     %s" % line)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started.values():
				d.stop()
			for pid in run.started:
				if os.path.exists("/proc/%d" % pid):
					try:
						with open("/proc/%d/cmdline" % pid, "rb") as f:
							alive = run.fuzznetd.encode() in f.read()
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: a host's log configured by verb, and gathered by a member as its "
	      "scope allows")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
