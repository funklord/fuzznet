#!/usr/bin/env python3
"""Two daemons of one identity, one the face: `make livecheck`, sec 666
stage 1.

One store, two fuzznetd processes on it, each with a socket of its own.

    a  A, started first, takes the claim and is the face: it writes where it
       serves into the store's `face`
    b  B, started second, cannot take it and follows: `status` asked on B's
       socket is answered by A, and a setting written through B is A's
    b2 `get events` asked on B's socket streams A's events, and B answers
       another client while it holds the stream (sec 669)
    b3 thirty clients that close before their answers leave B serving
    c  A stopped, B takes the claim within seconds and starts again as the
       face, serving its own socket

Against a daemon that takes no claim, B boots a second writer on A's store
and phase b's `status` comes from B itself, not A. Against sec 667's
follower, which refused events, phase b2 fails; against one writing to its
clients with write(2), SIGPIPE ends B in phase b3.

BOUNDED FROM INSIDE: one deadline; each daemon in its own process group,
stopped by SIGTERM then SIGKILL, and checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import signal
import socket
import subprocess
import sys
import tempfile
import time

DEADLINE_S = 120.0


class failed(Exception):
	pass


def ask(sock, line, within=10.0):
	until = time.monotonic() + within
	while True:
		try:
			c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			c.settimeout(10.0)
			c.connect(sock)
			c.sendall(line.encode() + b"\n")
			reply = b""
			while not reply.endswith(b"\n"):
				got = c.recv(4096)
				if not got:
					break
				reply += got
			c.close()
			return reply.decode(errors="replace").strip()
		except OSError:
			if time.monotonic() > until:
				raise failed("%s never answered %r" % (sock, line))
			time.sleep(0.2)


def face_of(store):
	"""Where the store's face says it serves, or None."""
	try:
		with open(os.path.join(store, "face")) as f:
			return f.read().strip()
	except OSError:
		return None


def main(argv):
	if len(argv) != 2:
		print("usage: live_face.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2
	fuzznetd = os.path.abspath(argv[1])
	deadline = time.monotonic() + DEADLINE_S
	procs = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzf.", dir="/tmp") as sock_dir:
		store = os.path.join(scratch, "store")
		os.mkdir(store)
		socks = {k: os.path.join(sock_dir, k) for k in ("a", "b")}

		def start(who):
			log = open(os.path.join(scratch, who + ".err"), "w")
			# A LOG DIRECTORY EACH: told none, a daemon logs into the
			# user's own `~/.local/state/fuzznet/log`.
			p = subprocess.Popen([fuzznetd, "--socket=" + socks[who], "--fuzznet-dir=" + store,
			                      "--log-dir=" + os.path.join(scratch, "log-" + who),
			                      "--fuzznet-service=1", "--fuzznet-product=1"],
			                     stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
			procs.append(p)
			return p

		def said(who):
			with open(os.path.join(scratch, who + ".err")) as f:
				return f.read()

		def stop(p):
			if p.poll() is None:
				os.killpg(p.pid, signal.SIGTERM)
				try:
					p.wait(timeout=10)
				except subprocess.TimeoutExpired:
					os.killpg(p.pid, signal.SIGKILL)
					p.wait(timeout=10)

		try:
			# A STORE THAT IS NOT THERE is refused, not made: the claim needs
			# its directory, and a mistyped path must not start an empty store.
			absent = os.path.join(scratch, "absent")
			r = subprocess.run([fuzznetd, "--socket=" + socks["a"], "--fuzznet-dir=" + absent,
			                    "--log-dir=" + os.path.join(scratch, "log-absent"),
			                    "--fuzznet-service=1", "--fuzznet-product=1"],
			                   capture_output=True, timeout=20)
			if r.returncode == 0 or os.path.exists(absent):
				raise failed("0: a store that is not there was started, or made")
			a = start("a")
			if not ask(socks["a"], "status").startswith("ok "):
				raise failed("a: A's status did not answer ok")
			if face_of(store) != socks["a"]:
				raise failed("a: the store's face names %r, not A's socket" % face_of(store))
			print("livecheck: a: A took the claim and is the face, its socket in the store")

			b = start("b")
			until = time.monotonic() + 20.0
			while "following the face" not in said("b"):
				if b.poll() is not None or time.monotonic() > until:
					raise failed("b: B did not follow; it said %r" % said("b")[-300:])
				time.sleep(0.2)
			a_status = ask(socks["a"], "status")
			b_status = ask(socks["b"], "status")
			if a_status.split()[:3] != b_status.split()[:3]:
				raise failed("b: B's status %r is not A's %r" % (b_status[:60], a_status[:60]))
			if ask(socks["b"], "set setting host x/through 1") != "ok":
				raise failed("b: a setting written through B was refused")
			if ask(socks["a"], "get setting host x/through").split()[:1] != ["ok"]:
				raise failed("b: A does not hold the setting written through B")
			print("livecheck: b: B followed, its status and a setting written through it A's")

			# EVENTS THROUGH B, with a request beside them: the follower holds
			# the subscriber's connection open to the face and passes each
			# event as it comes, while it answers another client.
			sub = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			sub.settimeout(10.0)
			sub.connect(socks["b"])
			sub.sendall(b"get events\n")
			held = b""

			def sub_line():
				nonlocal held
				until = time.monotonic() + 10.0
				while b"\n" not in held:
					if time.monotonic() > until:
						raise failed("b2: no line on B's events within 10 s (held %r)" % held)
					got = sub.recv(4096)
					if not got:
						raise failed("b2: B's events closed (held %r)" % held)
					held += got
				line, held = held.split(b"\n", 1)
				return line.decode(errors="replace")

			first = sub_line()
			if first != "ok events":
				raise failed("b2: `get events` through B answered %r" % first)
			if not ask(socks["b"], "status").startswith("ok "):
				raise failed("b2: B did not answer status while holding events open")
			if ask(socks["a"], "set setting host x/evented 1") != "ok":
				raise failed("b2: a setting written through A was refused")
			ev = sub_line()
			if ev != "event setting -":
				raise failed("b2: B passed %r, not the setting's event" % ev)
			sub.close()
			print("livecheck: b2: events streamed through B, and B answered beside them")

			# CLIENTS THAT LEAVE BEFORE THEIR ANSWER: the follower's write to
			# each is to a closed socket, which must not stop it.
			for _ in range(30):
				c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
				try:
					c.connect(socks["b"])
					c.sendall(b"status\n")
				except OSError as e:
					raise failed("b3: B stopped taking clients (%s); it exited %r"
					             % (e, b.poll()))
				finally:
					c.close()
			time.sleep(1.0)
			if b.poll() is not None:
				raise failed("b3: B exited %r after clients left early" % b.returncode)
			if not ask(socks["b"], "status").startswith("ok "):
				raise failed("b3: B did not answer after clients left early")
			print("livecheck: b3: thirty clients left before their answers, and B served on")

			pid_b = b.pid
			stop(a)
			until = time.monotonic() + 30.0
			while "starting again as the face" not in said("b"):
				if b.poll() is not None or time.monotonic() > until:
					raise failed("c: B did not take the face; it said %r" % said("b")[-300:])
				time.sleep(0.2)
			if not ask(socks["b"], "status", within=30.0).startswith("ok "):
				raise failed("c: B, now the face, did not answer")
			if face_of(store) != socks["b"]:
				raise failed("c: the store's face names %r, not B's socket" % face_of(store))
			if b.pid != pid_b or b.poll() is not None:
				raise failed("c: B did not start again in place")
			print("livecheck: c: A gone, B took the claim and serves as the face")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		finally:
			for p in procs:
				stop(p)
		if time.monotonic() > deadline:
			print("livecheck: FAILED -- past the deadline")
			return 1
	print("livecheck: two daemons of one identity, one the face, and a follower took over")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
