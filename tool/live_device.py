#!/usr/bin/env python3
"""A device with no IP asks a real host over a simulated radio: `make livecheck`,
sec 912.

R is an estate's root. D is a store the device's keys are made in, paired by
hand: its prekey carried to R, R's card carried back, and its image read off.
Nothing but that text reaches the device, which is `device_sim`.

Between the device and `fuzznet-bridge` runs this script as the radio. Each unit
that passes is held to the link's size, and may be lost.

    a  over 51-byte units, the longest-range LoRa figure sec 48 records: the
       device, which has no clock, learns R's and is answered by `events`
    b  over 51-byte units with 10 per cent of units lost, each way, so that a
       frame of several pieces is often lost whole: asked again and again, it
       still is, every time, and units were seen to be lost
    b2 the bridge on a terminal rather than a pipe, as it would hold a UART
    c  a device of another estate holds a session R never made, and is answered
       nothing
    c2 a rule at R says who may call `events` (sec 921): none, root and a rule for
       every procedure keep D out, and `host:D` and `member` let it in
    d  R revokes D: the same image is answered no more

Against a bridge that passes a frame in pieces past the unit, every phase fails
on the radio's own check. Against a daemon that takes an image's capability
after its revocation, d is answered.

BOUNDED FROM INSIDE as live_rejoin.py is: one deadline, each daemon in its own
process group, each radio pass bounded by the device's own tries, and every
process checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import pty
import random
import select
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402
from live_groups import PREKEY_HOST  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 200.0

LOSSY_ASKS = 6
# A TIME ASK AND A SHORT CALL ARE EACH FOUR PIECES AT 51 BYTES (phase a).
UNITS_A_FRAME = 4

END = 0xC0
ESC = 0xDB


class wire:
	"""One direction of the radio: SLIP packets read off one stream, each held to
	the link's unit and passed on, or lost."""

	def __init__(self, source, sink, unit, loss, rng):
		self.source, self.sink, self.unit, self.loss, self.rng = source, sink, unit, loss, rng
		self.packet = bytearray()
		self.passed = self.lost = 0
		self.largest = 0

	def feed(self, data):
		for byte in data:
			if byte != END:
				self.packet.append(byte)
				continue
			if self.packet:
				self.one(bytes(self.packet))
				self.packet = bytearray()

	def one(self, coded):
		length = len(coded) - coded.count(ESC)
		if length > self.unit:
			raise failed("a unit of %d bytes on a link of %d" % (length, self.unit))
		self.largest = max(self.largest, length)
		if self.rng.random() < self.loss:
			self.lost += 1
			return
		self.passed += 1
		os.write(self.sink, bytes([END]) + coded + bytes([END]))


def on_the_air(run, image, unit, loss, name, args, port, tty=False):
	"""The device asks `name` through a bridge at `port`: its exit and what it said,
	and the units that went each way. With `tty` the bridge reads a terminal, as it
	would a UART, and this script holds the far end of it."""
	rng = random.Random()
	argv = [run.bridge, "--unit=%d" % unit, "--udp=127.0.0.1:%s" % port]
	master = slave = -1
	if tty:
		master, slave = pty.openpty()
		bridge = subprocess.Popen(argv + ["--serial=" + os.ttyname(slave)],
		                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
	else:
		bridge = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	sim = subprocess.Popen([run.sim, image, str(unit), name] + ([args] if args else []),
	                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
	                       stderr=subprocess.PIPE)
	up = wire(sim.stdout.fileno(), master if tty else bridge.stdin.fileno(), unit, loss, rng)
	down = wire(master if tty else bridge.stdout.fileno(), sim.stdin.fileno(), unit, loss, rng)
	try:
		until = time.monotonic() + 40.0
		while sim.poll() is None and time.monotonic() < until:
			ready, _, _ = select.select([up.source, down.source], [], [], 0.2)
			for w in (up, down):
				if w.source in ready:
					data = os.read(w.source, 4096)
					if data:
						w.feed(data)
		if sim.poll() is None:
			raise failed("the device was still asking at the radio's bound")
		said = sim.stderr.read().decode(errors="replace").strip()
		return sim.returncode, said, up, down
	finally:
		for p in (sim, bridge):
			if p.poll() is None:
				p.terminate()
			try:
				p.wait(timeout=5.0)
			except subprocess.TimeoutExpired:
				p.kill()
				p.wait()
		for fd in (master, slave):
			if fd >= 0:
				os.close(fd)


def main(argv):
	if len(argv) != 4:
		print("usage: live_device.py PATH_TO_FUZZNETD PATH_TO_BRIDGE PATH_TO_DEVICE_SIM",
		      file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.bridge = os.path.abspath(argv[2])
	run.sim = os.path.abspath(argv[3])
	run.started = []
	port = str(27900 + (os.getpid() % 300))
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in ("r", "d", "o", "p")}
		sock = os.path.join(sock_dir, "r")
		for d in dirs.values():
			os.mkdir(d)
		r = None
		try:
			# THE MANUAL KEY EXCHANGE: two pieces of text, carried by hand.
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + dirs["d"], "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + dirs["r"], "--pair=" + prekey], None)
			gateway = command(run, ["--fuzznet-dir=" + dirs["d"], "--accept=" + card], None)
			image = command(run, ["--fuzznet-dir=" + dirs["d"], "--device-image=" + gateway], None)
			if not image.startswith("FZD1:"):
				raise failed("--device-image wrote %r" % image[:40])
			print("livecheck: the image is %d characters of text" % len(image))

			# ANOTHER ESTATE'S DEVICE, paired to its own root O.
			command(run, ["--fuzznet-dir=" + dirs["o"], "--new-root"], None)
			prekey_p = command(run, ["--fuzznet-dir=" + dirs["p"], "--prekey"], None)
			card_p = command(run, ["--fuzznet-dir=" + dirs["o"], "--pair=" + prekey_p], None)
			other = command(run, ["--fuzznet-dir=" + dirs["p"], "--accept=" + card_p], None)
			image_p = command(run, ["--fuzznet-dir=" + dirs["p"], "--device-image=" + other], None)

			r = daemon(run, "r0", dirs["r"], sock, extra=["--udp-port=" + port])

			# a: the longest-range unit.
			code, said, up, down = on_the_air(run, image, 51, 0.0, "events", "0", port)
			if code != 0:
				raise failed("a: over 51-byte units the device said %r (%d)" % (said, code))
			print("livecheck: a: answered over 51-byte units, %d up and %d down: %s"
			      % (up.passed, down.passed, said[:60]))

			# b: a lossy link. A POSITIVE CONTROL: units must be seen lost.
			lost = heard = sent = 0
			for _ in range(LOSSY_ASKS):
				code, said, up, down = on_the_air(run, image, 51, 0.10, "events", "0", port)
				if code != 0:
					raise failed("b: at 10 per cent loss the device said %r (%d)" % (said, code))
				lost += up.lost + down.lost
				sent += (up.lost + up.passed) // UNITS_A_FRAME
				heard += up.lost + down.lost + up.passed + down.passed
			if not lost:
				raise failed("b: no unit was lost in %d, so nothing was tested" % heard)
			print("livecheck: b: answered %d times of %d over 51-byte units, %d of %d units "
			      "lost, %d frames sent for %d exchanges"
			      % (LOSSY_ASKS, LOSSY_ASKS, lost, heard, sent, 2 * LOSSY_ASKS))

			# b2: through a terminal, where a line discipline would eat bytes.
			code, said, _, _ = on_the_air(run, image, 51, 0.0, "events", "0", port, tty=True)
			if code != 0:
				raise failed("b2: over a terminal the device said %r (%d)" % (said, code))
			print("livecheck: b2: answered through a terminal, as a UART would carry it")

			# c: another estate's.
			code, said, _, _ = on_the_air(run, image_p, 222, 0.0, "events", "0", port)
			if code == 0:
				raise failed("c: a device of another estate was answered: %r" % said)
			print("livecheck: c: a device of another estate was answered nothing: %s" % said[:60])

			# c2: each call by a rule. A device is a member, and holds no more than a
			# rule leaves it.
			device_host = prekey[PREKEY_HOST]
			for key, rule, answered in (("remote/permit/events", "none", False),
			                            ("remote/permit/events", "root", False),
			                            ("remote/permit/events", "host:" + device_host, True),
			                            ("remote/permit", "none", True),
			                            ("remote/permit/events", "member", True)):
				reply = ask(sock, "set setting host %s %s" % (key, rule))
				if not reply.startswith("ok"):
					raise failed("c2: %s %s answered %r" % (key, rule[:12], reply))
				code, said, _, _ = on_the_air(run, image, 222, 0.0, "events", "0", port)
				if (code == 0) != answered:
					raise failed("c2: under %s %s the device said %r (%d)"
					             % (key, rule[:12], said, code))
			print("livecheck: c2: each rule let the device in or kept it out: %s" % said[:60])

			# d: revoked.
			reply = ask(sock, "revoke peer " + prekey[PREKEY_HOST])
			if not reply.startswith("ok"):
				raise failed("d: revoke peer answered %r" % reply)
			code, said, _, _ = on_the_air(run, image, 222, 0.0, "events", "0", port)
			if code == 0:
				raise failed("d: a revoked device was answered: %r" % said)
			print("livecheck: d: revoked, the same image is answered no more: %s" % said[:60])
		except failed as e:
			print("livecheck: FAILED: %s" % e, file=sys.stderr)
			return 1
		finally:
			if r:
				r.stop()
	print("livecheck: a device with no IP reached a host through a keyless bridge")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
