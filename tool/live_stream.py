#!/usr/bin/env python3
"""A file played from its middle while it arrives: sec 998, sec 29's streaming.

Two stores over loopback: R a root, M a member pulling from it (`--root-at`).
R puts an 8 MiB file. Against `make fuzznetd-faults`' daemon, M's fetch window
held at one (FZN_TUNE_FETCH_WINDOW): over loopback a wide window takes the
whole file in half a second, too fast to see in which order.

    a  M fetches it with its playhead three quarters in (`fetch file REF at
       OFFSET`), and reads the playhead's range before the file's start has
       come, which the plan reaches only as it wraps -- 1024 leaves a turn
       (FZN_TUNE_LEAVES_A_ROUND), so the order is seen
    b  M seeks back to the start, and the whole file comes, exported the
       same bytes as R put

Against a daemon that fetches every file from its first leaf, the start
is here first, and a fails.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import filecmp
import os
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_files_many import answering  # noqa: E402
from live_rejoin import command, daemon, expect, free_slot  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 300.0

SIZE = 8 * 1024 * 1024
WHOLE_S = 180.0


def main(argv):
	if len(argv) != 2:
		print("usage: live_stream.py PATH_TO_FAULTS_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = free_slot(38600, 4, 300, 2)
	port = {"r": base, "m": base + 1}
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
			prekey = command(run, ["--fuzznet-dir=" + dirs["m"], "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + dirs["r"], "--pair=" + prekey,
			                     "--delegable"], None)
			command(run, ["--fuzznet-dir=" + dirs["m"], "--accept=" + card, "--join"], None)
			started["r"] = daemon(run, "r", dirs["r"], socks["r"],
			                      extra=["--udp-port=%d" % port["r"]])
			answering(socks["r"], "r")
			src = os.path.join(scratch, "film")
			with open(src, "wb") as f:
				f.write(os.urandom(SIZE))
			reply = ask(socks["r"], "put file " + src)
			if not reply.startswith("ok "):
				raise failed("r: put file answered %r" % reply)
			ref = reply.split()[1]
			os.environ["FZN_TUNE_FETCH_WINDOW"] = "1"
			os.environ["FZN_TUNE_LEAVES_A_ROUND"] = "1024"
			started["m"] = daemon(run, "m", dirs["m"], socks["m"],
			                      extra=["--udp-port=%d" % port["m"],
			                             "--root-at", "127.0.0.1", str(port["r"])])
			answering(socks["m"], "m")

			# a: PLAYED FROM THREE QUARTERS IN.
			head = SIZE * 3 // 4
			expect(socks["m"], "m", "fetch file %s at %d" % (ref, head), "ok")
			part = os.path.join(scratch, "part")
			began = time.monotonic()
			while not ask(socks["m"], "get file %s %d 65536 %s" % (ref, head, part)).startswith("ok"):
				if os.path.exists(part):
					os.remove(part)
				if time.monotonic() - began > WHOLE_S:
					raise failed("a: the playhead's range not read in %.0f s" % WHOLE_S)
				time.sleep(0.02)
			at_head = time.monotonic() - began
			os.remove(part)
			# THE START NOT YET HERE when it came: a fetch takes 1024 leaves a
			# turn, so the first turn from the playhead holds the file's last
			# quarter, and the start comes at the next.
			start = ask(socks["m"], "get file %s 0 65536 %s" % (ref, part))
			if os.path.exists(part):
				os.remove(part)
			words = ask(socks["m"], "get file " + ref[:64]).split()
			if start.startswith("ok"):
				raise failed("a: the file's start was here when the playhead's range came, %s of "
				             "%s leaves held: not fetched from the playhead" % (words[1], words[2]))
			print("livecheck: a: the playhead's range read in %.2f s, %s of %s leaves held, the "
			      "start not yet" % (at_head, words[1], words[2]))

			# b: A SEEK TO THE START, and the whole file -- M started again
			# without the tunes, its want kept on disk and its playhead not.
			started["m"].stop()
			os.environ.pop("FZN_TUNE_FETCH_WINDOW", None)
			os.environ.pop("FZN_TUNE_LEAVES_A_ROUND", None)
			started["m"] = daemon(run, "m2", dirs["m"], socks["m"],
			                      extra=["--udp-port=%d" % port["m"],
			                             "--root-at", "127.0.0.1", str(port["r"])])
			answering(socks["m"], "m")
			began = time.monotonic()
			expect(socks["m"], "m", "fetch file %s at 0" % ref, "ok")
			while ask(socks["m"], "get file " + ref[:64]).split()[4:5] != ["whole"]:
				if time.monotonic() - began > WHOLE_S:
					raise failed("b: the file not whole in %.0f s" % WHOLE_S)
				time.sleep(0.5)
			out = os.path.join(scratch, "out")
			expect(socks["m"], "m", "get file %s %s" % (ref, out), "ok")
			if not filecmp.cmp(src, out, shallow=False):
				raise failed("b: the file M exported is not the one R put")
			print("livecheck: b: whole in %.1f s, and the same bytes" % (time.monotonic() - began))
		except failed as e:
			print("livecheck: FAILED: %s" % e, file=sys.stderr)
			return 1
		finally:
			os.environ.pop("FZN_TUNE_FETCH_WINDOW", None)
			os.environ.pop("FZN_TUNE_LEAVES_A_ROUND", None)
			for who in ("m", "r"):
				if who in started:
					started[who].stop()
	print("livecheck: a file is played from its middle while it arrives")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
