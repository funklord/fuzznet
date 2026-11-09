#!/usr/bin/env python3
"""Sync-load, what waits to cross and whether it drains: sec 966.

Three stores over loopback: R a root, M a member joined to it and pulling
from it (`--root-at`), and X a root of its own estate, which neither knows.
Run against `make fuzznetd-faults`' daemon, whose rounds
FZN_TUNE_PULL_EVERY makes two seconds.

    a  quiet: after a window of M's rounds, `get sync-load` says `ok`, every
       queue steady
    b  X puts files and stops. M asks for one of them each round, which no
       host it reaches holds: its `files` queue grows a file a round, and
       `get sync-load` comes to say `growing` with the queue growing, and M
       warns, naming the queue and the rules to write

Against a daemon that samples nothing, phase b never says `growing`.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon, expect, free_slot  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 300.0

ROUND_S = 2
WINDOW = 16
FILES = 30


def answering(sock, who):
	until = time.monotonic() + 60.0
	while True:
		try:
			if ask(sock, "status").startswith("ok "):
				return
		except OSError:
			pass
		if time.monotonic() > until:
			raise failed("%s: not answering" % who)
		time.sleep(0.2)


def queues(reply):
	"""`get sync-load`'s queues by name: (now, peak, mean, trend)."""
	out = {}
	for item in reply.split()[3:]:
		name, now, peak, mean, trend = item.split(",")
		out[name] = (int(now), int(peak), int(mean), trend)
	return out


def main(argv):
	if len(argv) != 2:
		print("usage: live_sync_load.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	os.environ["FZN_TUNE_PULL_EVERY"] = str(ROUND_S)
	base = free_slot(38000, 4, 400, 3)
	port = {"r": base, "m": base + 1, "x": base + 2}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}
		try:
			for d in dirs.values():
				os.mkdir(d)
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			command(run, ["--fuzznet-dir=" + dirs["x"], "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + dirs["m"], "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + dirs["r"], "--pair=" + prekey,
			                     "--delegable"], None)
			command(run, ["--fuzznet-dir=" + dirs["m"], "--accept=" + card, "--join"], None)

			# X's files, which nobody M reaches holds.
			started["x"] = daemon(run, "x", dirs["x"], socks["x"],
			                      extra=["--udp-port=%d" % port["x"]])
			answering(socks["x"], "x")
			refs = []
			for i in range(FILES):
				path = os.path.join(scratch, "x%03d" % i)
				with open(path, "wb") as f:
					f.write(os.urandom(1000 + i))
				reply = ask(socks["x"], "put file " + path)
				if not reply.startswith("ok "):
					raise failed("x: put file answered %r" % reply)
				refs.append(reply.split()[1])
			started["x"].stop()

			started["r"] = daemon(run, "r", dirs["r"], socks["r"],
			                      extra=["--udp-port=%d" % port["r"]])
			answering(socks["r"], "r")
			started["m"] = daemon(run, "m", dirs["m"], socks["m"],
			                      extra=["--udp-port=%d" % port["m"],
			                             "--root-at", "127.0.0.1", str(port["r"])])
			answering(socks["m"], "m")

			# a: quiet, after a window of rounds.
			time.sleep(ROUND_S * (WINDOW + 4))
			got = ask(socks["m"], "get sync-load").strip()
			words = got.split()
			if len(words) < 3 or words[0] != "ok" or words[2] != "ok" \
			   or any(q[3] != "steady" for q in queues(got).values()):
				raise failed("a: a quiet M said %r" % got)
			print("livecheck: a: quiet, M says %s" % got)

			# b: a file more each round that nobody holds.
			began = time.monotonic()
			for i, ref in enumerate(refs):
				expect(socks["m"], "m", "fetch file " + ref, "ok")
				time.sleep(ROUND_S)
				got = ask(socks["m"], "get sync-load").strip()
				if got.split()[2:3] == ["growing"]:
					break
			files = queues(got).get("files")
			if got.split()[2:3] != ["growing"] or not files or files[3] != "growing":
				raise failed("b: after %d files asked, M said %r" % (i + 1, got))
			until = time.monotonic() + 3 * ROUND_S
			while "sync-load: files grew" not in started["m"].log():
				if time.monotonic() > until:
					raise failed("b: M said growing and warned of nothing")
				time.sleep(0.5)
			print("livecheck: b: %d files asked a round apart, M says growing in %.0f s: %s"
			      % (i + 1, time.monotonic() - began, got))
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			for name in sorted(os.listdir(scratch)):
				if name.endswith(".err"):
					with open(os.path.join(scratch, name), errors="replace") as f:
						tail = f.read().splitlines()[-10:]
					print("livecheck: --- %s" % name)
					for line in tail:
						print("livecheck:     %s" % line)
			return 1
		finally:
			for d in started.values():
				d.stop()
	print("livecheck: sync-load said a queue the rounds do not drain")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
