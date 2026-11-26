#!/usr/bin/env python3
"""The smallest host on an emulated Cortex-M3 asks a real host: `make
livecheck-board`, sec 1481.

R is an estate's root, D a store the device's keys are made in and paired by
hand, as live_device.py does. The device is `device/board/mps2.c` on qemu's
MPS2 AN385: its UART0 a terminal `fuzznet-bridge` holds, as it would hold a
real board's serial line, its UART1 a file the board says its answer to.

    a  over 51-byte units the board, given its image and a seed on its line,
       asks R's `events` and is answered -- the device core's crypto, framing
       and session on a 32-bit target with no operating system
    b  the same board given an image of another estate is answered nothing

Needs qemu-system-arm and the board's ELF (`make device-board`).

BOUNDED FROM INSIDE: one deadline; qemu and the bridge each bounded by a
wait, killed and checked gone; the daemon in its own process group.

Exit 0 on a pass, 1 on a failure.
"""

import os
import re
import select
import subprocess
import sys
import tempfile
import termios
import time
import tty

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon  # noqa: E402
from live_trim import failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 240.0
PTY_RE = re.compile(r"char device redirected to (/dev/pts/\d+) \(label serial0\)")


def on_the_board(run, scratch, image, unit, name, args, port, within=60.0):
	"""The board booted, its line typed, the bridge on its UART0: what it said
	on UART1 once it answered or `within` seconds passed."""
	said = os.path.join(scratch, "uart1-%d.txt" % len(run.boards))
	qemu = subprocess.Popen(["qemu-system-arm", "-machine", "mps2-an385", "-nographic", "-monitor", "none",
	                         "-kernel", run.elf, "-serial", "pty", "-serial", "file:" + said],
	                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
	run.boards.append(qemu)
	bridge = None
	try:
		path, err = None, b""
		start = time.monotonic()
		# ON STDOUT, qemu's word for where UART0 went; read with a bound,
		# never a read that waits for ever.
		while path is None and time.monotonic() - start < 10.0:
			if select.select([qemu.stdout], [], [], 0.5)[0]:
				chunk = os.read(qemu.stdout.fileno(), 4096)
				if not chunk:
					break
				err += chunk
			m = PTY_RE.search(err.decode(errors="replace"))
			path = m.group(1) if m else None
		if path is None:
			raise failed("qemu named no terminal for UART0: %r" % err[-300:])
		while "device: ready" not in (open(said).read() if os.path.exists(said) else ""):
			if time.monotonic() - start > 20.0:
				raise failed("the board did not say it was ready")
			time.sleep(0.1)
		fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
		tty.setraw(fd)
		os.write(fd, ("%s %d %s %s %s\n" % (os.urandom(32).hex(), unit, name, args or "-", image)).encode())
		termios.tcdrain(fd)
		os.close(fd)
		bridge = subprocess.Popen([run.bridge, "--unit=%d" % unit, "--udp=127.0.0.1:%s" % port,
		                           "--serial=" + path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
		                          start_new_session=True)
		while time.monotonic() - start < within:
			text = open(said).read()
			if "device: status" in text or text.count("device: ") > 1:
				return text
			time.sleep(0.2)
		return open(said).read()
	finally:
		for p in (bridge, qemu):
			if p and p.poll() is None:
				p.kill()
				p.wait(timeout=10)


def main(argv):
	if len(argv) != 4:
		print("usage: live_board.py PATH_TO_FUZZNETD PATH_TO_BRIDGE PATH_TO_BOARD_ELF", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.bridge = os.path.abspath(argv[2])
	run.elf = os.path.abspath(argv[3])
	run.started = []
	run.boards = []
	port = str(41900 + (os.getpid() % 90))
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
			said = on_the_board(run, scratch, image, 51, "events", "0", port)
			if not re.search(r"device: status 0, \d+ byte\(s\)", said):
				raise failed("a: the board said %r" % said)
			print("livecheck: a: the board, a Cortex-M3 with no operating system, asked over 51-byte "
			      "units and was answered: %s" % said.strip().splitlines()[-1][:80])

			# b: another estate's image, answered nothing.
			said = on_the_board(run, scratch, image_p, 51, "events", "0", port, within=30.0)
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
					q.kill()
					q.wait(timeout=10)
	print("livecheck: the smallest host ran on a board and was answered")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
