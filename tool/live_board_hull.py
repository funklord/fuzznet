#!/usr/bin/env python3
"""The smallest host on a board hull runs asks a real host: `make
livecheck-board-hull`, sec 1509 -- live_board.py's two phases with the board
a hull machine (sec 1100 step 2) rather than qemu started by hand.

R is an estate's root, D a store the device's keys are made in and paired by
hand, as live_board.py does. The board is `device/board/mps2.c` as hull's pc
class runs it, `(tuning (pc (machine mps2-an385)))`: its UART0 held by
`hull exec ID -- console` on pipes, 8-bit clean (hull project.md sec 5.0),
which `fuzznet-bridge` takes as its stdin and stdout; its UART1, where the
board says its answer, read as `console 2`.

    a  over 51-byte units the board, given its image and a seed on its line,
       asks R's `events` and is answered
    b  the same board given an image of another estate is answered nothing

Needs hull (`--hull=PATH`, else `hull` on PATH) with qemu-system-arm, and
the board's ELF (`make device-board`). Exits 77, saying why, without hull.

BOUNDED FROM INSIDE: one deadline; each `hull run` under a timeout and
stopped by `hull stop`, its run waited for; every console and bridge killed
and waited for; the daemon in its own process group.

Exit 0 on a pass, 1 on a failure, 77 skipped.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon  # noqa: E402
from live_trim import failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 300.0


def console(hull, name, *port):
	"""A console of the machine on pipes, as a program holds one."""
	p = subprocess.Popen([hull, "exec", name, "--", "console", *port], stdin=subprocess.PIPE,
	                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
	os.set_blocking(p.stdout.fileno(), False)
	return p


def read_until(p, said, test, within):
	"""What `p` says added to `said` until `test` holds or `within` passes."""
	end = time.monotonic() + within
	while not test(said) and time.monotonic() < end:
		try:
			chunk = os.read(p.stdout.fileno(), 4096)
		except BlockingIOError:
			time.sleep(0.05)
			continue
		if not chunk:
			break
		said += chunk.decode(errors="replace")
	return said


def stop(p):
	if p and p.poll() is None:
		p.kill()
		p.wait(timeout=10)


def on_the_board(run, image, unit, name, args, port, within=60.0):
	"""The board run by hull, its line typed on UART0, the bridge on UART0:
	what it said on UART1 once it answered or `within` seconds passed."""
	machine = "fz%d" % len(run.boards)
	conf = os.path.join(run.scratch, machine + ".conf")
	shutil.copyfile(run.elf, os.path.join(run.scratch, machine + ".elf"))
	with open(conf, "w") as f:
		f.write('(machine (source "image:%s.elf") (backend pc) (hostname "%s") '
		        '(tuning (pc (machine mps2-an385))))\n' % (machine, machine))
	out = os.path.join(run.scratch, machine + ".out")
	runner = subprocess.Popen(["timeout", "-k", "2", "120", run.hull, "run", "-f", conf],
	                          stdout=open(out, "w"), stderr=subprocess.STDOUT, cwd=run.scratch,
	                          start_new_session=True)
	run.boards.append(runner)
	uart1 = first = bridge = held = None
	try:
		# UP WHEN THE BOARD SAYS SO on UART1: hull says nothing of a board's
		# readiness, and `console 2` is refused until the machine is there.
		start, said = time.monotonic(), ""
		while "device: ready" not in said:
			if runner.poll() is not None or time.monotonic() - start > 40.0:
				raise failed("the board did not say it was ready on UART1: %r; hull: %r"
				             % (said, open(out).read()[-300:]))
			stop(uart1)
			uart1 = console(run.hull, machine, "2")
			said = read_until(uart1, said, lambda s: "device: ready" in s, 3.0)
		# THE LINE TYPED, then the console let go: one at a time per port.
		first = console(run.hull, machine)
		first.stdin.write(("%s %d %s %s %s\n" % (os.urandom(32).hex(), unit, name, args or "-", image)).encode())
		first.stdin.flush()
		time.sleep(0.5)
		stop(first)
		# THE BRIDGE ON UART0, its stdin and stdout the console's.
		held = subprocess.Popen([run.hull, "exec", machine, "--", "console"], stdin=subprocess.PIPE,
		                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
		bridge = subprocess.Popen([run.bridge, "--unit=%d" % unit, "--udp=127.0.0.1:%s" % port],
		                          stdin=held.stdout, stdout=held.stdin, stderr=subprocess.DEVNULL,
		                          start_new_session=True)
		return read_until(uart1, said, lambda s: "device: status" in s or s.count("device: ") > 1,
		                  within)
	finally:
		for p in (bridge, held, first, uart1):
			stop(p)
		subprocess.run([run.hull, "stop", machine], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
		               timeout=40)
		try:
			runner.wait(timeout=30)
		except subprocess.TimeoutExpired:
			os.killpg(runner.pid, 9)
			runner.wait(timeout=10)


def main(argv):
	hull = shutil.which("hull")
	args = [a for a in argv[1:] if not a.startswith("--hull=")]
	for a in argv[1:]:
		if a.startswith("--hull="):
			hull = a[len("--hull="):]
	if len(args) != 3:
		print("usage: live_board_hull.py [--hull=PATH] PATH_TO_FUZZNETD PATH_TO_BRIDGE PATH_TO_BOARD_ELF",
		      file=sys.stderr)
		return 2
	if not hull or not os.access(hull, os.X_OK):
		print("livecheck: SKIPPED -- no hull: give --hull=PATH (make HULL=PATH) or put hull on PATH")
		return 77

	class run:
		pass

	run.hull = os.path.abspath(hull)
	run.fuzznetd = os.path.abspath(args[0])
	run.bridge = os.path.abspath(args[1])
	run.elf = os.path.abspath(args[2])
	run.started = []
	run.boards = []
	port = str(41800 + (os.getpid() % 90))
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in ("r", "d", "o", "p")}
		for k in ("r", "d", "o"):
			os.mkdir(dirs[k])
		r = None
		try:
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + dirs["d"], "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + dirs["r"], "--pair=" + prekey], None)
			gateway = command(run, ["--fuzznet-dir=" + dirs["d"], "--accept=" + card], None)
			image = command(run, ["--fuzznet-dir=" + dirs["d"], "--device-image=" + gateway], None)
			command(run, ["--fuzznet-dir=" + dirs["o"], "--new-root"], None)
			prekey_p = command(run, ["--fuzznet-dir=" + dirs["p"], "--prekey"], None)
			card_p = command(run, ["--fuzznet-dir=" + dirs["o"], "--pair=" + prekey_p], None)
			other = command(run, ["--fuzznet-dir=" + dirs["p"], "--accept=" + card_p], None)
			image_p = command(run, ["--fuzznet-dir=" + dirs["p"], "--device-image=" + other], None)
			r = daemon(run, "r0", dirs["r"], os.path.join(sock_dir, "r"), extra=["--udp-port=" + port])

			# a: answered.
			said = on_the_board(run, image, 51, "events", "0", port)
			if not re.search(r"device: status 0, \d+ byte\(s\)", said):
				raise failed("a: the board said %r" % said)
			print("livecheck: a: the board, run by hull, asked over 51-byte units and was answered: %s"
			      % said.strip().splitlines()[-1][:80])

			# b: another estate's image, answered nothing.
			said = on_the_board(run, image_p, 51, "events", "0", port, within=30.0)
			if "device: status" in said:
				raise failed("b: a board of another estate was answered: %r" % said)
			print("livecheck: b: a board of another estate asked and was answered nothing")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		finally:
			if r:
				r.stop()
			for q in run.boards:
				if q.poll() is None:
					os.killpg(q.pid, 9)
					q.wait(timeout=10)
	print("livecheck: the smallest host ran on a board hull runs, and was answered")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
