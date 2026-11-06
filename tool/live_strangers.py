#!/usr/bin/env python3
"""What a stranger gets, and what a copied hello moves: `make livecheck`, sec 884.

Two stores over loopback, A a root and B joined to it, B reaching A through
a proxy this script runs, so it holds B's own frames. A third socket, the
stranger's, holds no key.

    a  THE STRANGER HEARS NOTHING. Random datagrams, every first byte, a box
       that opens to nothing, a frame cut short, and a LAN probe naming a key
       A has never met: not one byte comes back, so A reflects nothing to
       a spoofed source. And a probe naming B, from the same socket, IS
       answered, no larger than it was: A was listening, and the socket
       would have heard (sec 624)
    b  A COPIED HELLO MOVES NOTHING. A frame of B's, delivered and then sent
       again from the stranger's socket, is dropped: `get lan` never shows
       that socket and nothing comes back
    b2 NOR A COPY MADE AT ONCE, inside the seconds a request's reply is kept for
       its caller's resend: it goes only where the request came from (sec 900)
    c  THE COPY WAS REAL. The proxy holds B's frames back and the stranger
       sends the first copy instead: `get lan` shows the stranger where B
       said hello. So phase b's silence was the replay window's, and not a
       frame that could never have moved anything. It is also the limit,
       stated in sec 884: whoever can stop a frame can redirect it, and
       reads nothing by it

Against a daemon that answers a stranger, phase a's count is not 0; against
one that admits a hello again, phase b sees the stranger's socket.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone. The proxy's thread is a daemon thread, ended with the run.

Exit 0 on a pass, 1 on a failure.
"""

import os
import select
import socket
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

DEADLINE_S = 500.0
PROBE_LEN = 144
PROBE_MARK = 0xFC
BOX_MARK = 0xFB
LISTEN_S = 3.0


class proxy(threading.Thread):
	"""B's datagrams to A, passed on and kept; `hold` keeps them unsent."""

	def __init__(self, port, to):
		super().__init__(daemon=True)
		self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.front.bind(("127.0.0.1", port))
		self.back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.back.bind(("127.0.0.1", 0))
		self.to = to
		self.client = None
		self.hold = False
		self.passed = []
		self.held = []
		self.done = False

	def run(self):
		while not self.done:
			ready, _, _ = select.select([self.front, self.back], [], [], 0.2)
			for s in ready:
				data, who = s.recvfrom(65536)
				if s is self.back:
					if self.client:
						self.front.sendto(data, self.client)
				else:
					self.client = who
					if self.hold:
						self.held.append(data)
					else:
						self.passed.append(data)
						self.back.sendto(data, self.to)


def heard(s, within):
	"""Every datagram `s` hears within `within` seconds."""
	got = []
	until = time.monotonic() + within
	while True:
		left = until - time.monotonic()
		if left <= 0:
			return got
		s.settimeout(left)
		try:
			got.append(s.recvfrom(65536)[0])
		except socket.timeout:
			return got


def probe(key):
	p = bytearray(PROBE_LEN)
	p[0] = PROBE_MARK
	p[1] = 1
	p[2:34] = key
	p[34:42] = os.urandom(8)
	return bytes(p)


def main(argv):
	if len(argv) != 2:
		print("usage: live_strangers.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	live_trim.DEADLINE = time.monotonic() + DEADLINE_S
	base = 21000 + (os.getpid() % 500) * 4
	port = {"a": base, "b": base + 1, "proxy": base + 2}
	started = {}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in ("a", "b")}
		socks = {k: os.path.join(sock_dir, k) for k in ("a", "b")}
		for d in dirs.values():
			os.mkdir(d)
		via = proxy(port["proxy"], ("127.0.0.1", port["a"]))
		via.start()
		stranger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		stranger.bind(("127.0.0.1", 0))
		a_at = ("127.0.0.1", port["a"])
		try:
			command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + dirs["b"], "--prekey"], None)
			b_key = bytes.fromhex(prekey[4:68])
			card = command(run, ["--fuzznet-dir=" + dirs["a"], "--pair=" + prekey, "--delegable"],
			               None)
			command(run, ["--fuzznet-dir=" + dirs["b"], "--accept=" + card, "--join"], None)
			started["a"] = daemon(run, "a", dirs["a"], socks["a"],
			                      extra=["--udp-port=%d" % port["a"]])
			started["b"] = daemon(run, "b", dirs["b"], socks["b"],
			                      extra=["--udp-port=%d" % port["b"], "--root-at", "127.0.0.1",
			                             str(port["proxy"])])
			started["b"].wait_for(ROUND_DONE_RE, "B's first round")
			until = time.monotonic() + 60.0
			while "member,1" not in ask(socks["b"], "list capability"):
				if time.monotonic() > until:
					raise failed("B never held the member capability")
				time.sleep(0.5)

			# B'S CHAIN AT A, which a probe naming B is judged by: with B's
			# stream, so it is here once B's own setting is.
			expect(socks["b"], "b", "set setting host net/address 127.0.0.1 %d" % port["b"], "ok")
			expect(socks["a"], "a", "set setting host net/discovery 127.0.0.1", "ok")
			expect(socks["b"], "b", "set setting host x/here 1", "ok")
			# TWO ROUNDS, 120 s and a little: a bound of 120 failed now and then.
			until = time.monotonic() + 200.0
			while ask(socks["a"], "get setting host=%s x/here" % b_key.hex()) != "ok host 1":
				if time.monotonic() > until:
					raise failed("A never held B's setting")
				time.sleep(0.5)

			# a: THE STRANGER HEARS NOTHING.
			sent = 0
			for first in range(256):
				for size in (1, 2, 40, PROBE_LEN, 1200):
					stranger.sendto(bytes([first]) + os.urandom(size - 1), a_at)
					sent += 1
			for _ in range(200):
				stranger.sendto(os.urandom(1 + (os.urandom(1)[0] * 5)), a_at)
				sent += 1
			for size in (1, 64, 400):
				stranger.sendto(bytes([BOX_MARK]) + os.urandom(size), a_at)
				sent += 1
			for _ in range(8):
				stranger.sendto(probe(os.urandom(32)), a_at)
				sent += 1
			if via.passed:
				stranger.sendto(via.passed[0][:len(via.passed[0]) // 2], a_at)
				sent += 1
			back = heard(stranger, LISTEN_S)
			if back:
				raise failed("a: A answered a stranger: %d datagram(s), %d byte(s), the first "
				             "%r" % (len(back), sum(map(len, back)), back[0][:16]))
			# ALIVE, AND THE SOCKET WOULD HEAR: a probe naming B is answered.
			answer = []
			for _ in range(5):
				stranger.sendto(probe(b_key), a_at)
				answer = heard(stranger, 2.0)
				if answer:
					break
			if not answer:
				raise failed("a: A never answered a probe naming B: its silence proves nothing")
			if max(map(len, answer)) > PROBE_LEN:
				raise failed("a: a probe of %d bytes drew %d" % (PROBE_LEN, max(map(len, answer))))
			if not ask(socks["a"], "status").startswith("ok "):
				raise failed("a: A stopped serving after a stranger's %d datagrams" % sent)
			print("livecheck: a: %d datagrams from a stranger drew nothing, and a probe naming B "
			      "drew %d byte(s) on the same socket" % (sent, len(answer[0])))

			# b: A COPIED HELLO MOVES NOTHING.
			here = "127.0.0.1,%d," % stranger.getsockname()[1]

			# `get lan` SHOWS WHAT WAS HEARD SINCE A PROBE WENT, so a probe goes
			# first, and a second later what follows is past it.
			def mark():
				said = ask(socks["a"], "fetch lan").split()
				if len(said) < 2 or said[1] == "0":
					raise failed("A sent no probe, so `get lan` shows nothing: %r" % said)
				time.sleep(1.1)

			def stranger_shown():
				time.sleep(0.5)
				return here in ask(socks["a"], "get lan")

			count = len(via.passed)
			until = time.monotonic() + 45.0
			while len(via.passed) <= count:
				if time.monotonic() > until:
					raise failed("b: B sent A nothing to copy")
				time.sleep(0.2)
			copies = list(via.passed[-12:])
			mark()
			for frame in copies:
				stranger.sendto(frame, a_at)
			back = heard(stranger, LISTEN_S)
			if back:
				raise failed("b: A answered %d copied frame(s) of B's" % len(back))
			if stranger_shown():
				raise failed("b: a copied frame of B's moved B to the stranger's socket")
			print("livecheck: b: %d frames of B's, copied after delivery, moved nothing and "
			      "drew nothing" % len(copies))

			# b2: NOR A COPY INSIDE THE WINDOW A RESEND IS ANSWERED IN, sec 900: a
			# request's reply is kept 6 s for its caller, and goes to no one else.
			at = len(via.passed)
			tried = 0
			until = time.monotonic() + 100.0
			while time.monotonic() < until and tried < 30:
				if len(via.passed) == at:
					time.sleep(0.02)
					continue
				fresh, at = via.passed[at:], len(via.passed)
				time.sleep(0.15)
				for frame in fresh:
					stranger.sendto(frame, a_at)
					tried += 1
				back = heard(stranger, 0.3)
				if back:
					raise failed("b2: A answered a copy at once, after %d: %d datagram(s) of %d "
					             "byte(s)" % (tried, len(back), len(back[0])))
			if not tried:
				raise failed("b2: B sent A nothing to copy")
			print("livecheck: b2: %d frames of B's, copied within a resend's window, drew nothing"
			      % tried)

			# c: THE COPY WAS REAL.
			via.held.clear()
			via.hold = True
			tried = 0
			until = time.monotonic() + 45.0
			moved = False
			while not moved:
				if time.monotonic() > until:
					raise failed("c: none of %d held frames of B's moved it: phase b tested a "
					             "frame that could not have" % tried)
				time.sleep(1.0)
				frames, via.held = list(via.held), []
				if frames:
					tried += len(frames)
					mark()
					for frame in frames:
						stranger.sendto(frame, a_at)
					moved = stranger_shown()
			via.hold = False
			print("livecheck: c: a frame of B's held from A and sent first by the stranger moved "
			      "B to its socket, so phase b's refusal was the replay window's")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		finally:
			via.done = True
			for d in started.values():
				d.stop()
			stranger.close()
	print("livecheck: a stranger heard nothing, and a copied frame moved nothing")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
