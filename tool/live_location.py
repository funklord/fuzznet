#!/usr/bin/env python3
"""A node sampling gpsd: `make livecheck`, sec 678.

One store, one daemon, and a stand-in gpsd: a TCP listener on loopback
that waits for the node's WATCH and then sends TPV reports, a good fix and
a poor one in turn.

    a  sampling is off until it is set: `get location` says `ok 0 off`
    b  `location/gpsd` aimed at the stand-in, `location/every` 1 and
       `location/enabled` on (sec 686's spelling): the node connects and sends WATCH, its link
       reads `watching`, the good fixes are kept and the 500 m ones
       dropped, and `list location` holds the good fix as gpsd gave it
    b2 the daemon killed by SIGKILL while sampling and started again: the
       fixes kept before are still listed, and it watches gpsd again and
       keeps the next (sec 766)
    c  `location/enabled` off: the link reads `off`, and no fix is kept after
    d  twenty fixes held, past what one reply holds: bare `list location`
       says so and names the page, and `list location FROM` pages the
       newest sixteen, each once, in order (sec 770)

Against a daemon that does not sample, phase b's link never reads
watching; against one with no accuracy gate, nothing is dropped.

BOUNDED FROM INSIDE: one deadline; the daemon in its own process group,
stopped by SIGTERM then SIGKILL; the stand-in's thread a daemon thread on
sockets with timeouts, told to stop.

Exit 0 on a pass, 1 on a failure.
"""

import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

DEADLINE_S = 120.0

GOOD = ('{"class":"TPV","mode":3,"time":"2026-10-21T12:00:05.000Z","lat":59.329323456,'
        '"lon":18.068581549,"altHAE":31.6,"epx":4.2,"epy":8.6,"epv":19.4}\n')
POOR = '{"class":"TPV","mode":2,"lat":10.0,"lon":10.0,"eph":500}\n'


class failed(Exception):
	pass


def ask(sock, line, within=20.0):
	until = time.monotonic() + within
	while True:
		try:
			c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			c.settimeout(10.0)
			c.connect(sock)
			c.sendall(line.encode() + b"\n")
			reply = b""
			while not reply.endswith(b"\n"):
				got = c.recv(65536)
				if not got:
					break
				reply += got
			c.close()
			return reply.decode(errors="replace").strip()
		except OSError:
			if time.monotonic() > until:
				raise failed("%s never answered %r" % (sock, line))
			time.sleep(0.2)


class stand_in(threading.Thread):
	"""gpsd enough for the node: a WATCH heard, then reports."""

	def __init__(self):
		super().__init__(daemon=True)
		self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.listener.bind(("127.0.0.1", 0))
		self.listener.listen(2)
		self.listener.settimeout(0.5)
		self.port = self.listener.getsockname()[1]
		self.stop = threading.Event()
		self.watched = False

	def run(self):
		while not self.stop.is_set():
			try:
				conn, _ = self.listener.accept()
			except socket.timeout:
				continue
			conn.settimeout(0.5)
			heard = b""
			try:
				while b"\n" not in heard and not self.stop.is_set():
					try:
						heard += conn.recv(1024)
					except socket.timeout:
						pass
				if heard.startswith(b"?WATCH="):
					self.watched = True
				n = 0
				while not self.stop.is_set():
					conn.sendall((GOOD if n % 2 == 0 else POOR).encode())
					n += 1
					time.sleep(0.3)
			except OSError:
				pass
			finally:
				conn.close()
		self.listener.close()


def status(sock):
	reply = ask(sock, "get location").split()
	if len(reply) != 8 or reply[0] != "ok":
		raise failed("get location answered %r" % reply)
	return reply


def main(argv):
	if len(argv) != 2:
		print("usage: live_location.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2
	fuzznetd = os.path.abspath(argv[1])
	deadline = time.monotonic() + DEADLINE_S
	proc = None
	gpsd = stand_in()
	gpsd.start()
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzg.", dir="/tmp") as sock_dir:
		store = os.path.join(scratch, "store")
		os.mkdir(store)
		sock = os.path.join(sock_dir, "s")
		log = open(os.path.join(scratch, "daemon.err"), "w")
		try:
			# A LOG DIRECTORY OF ITS OWN: told none, the daemon logs into the
			# user's own `~/.local/state/fuzznet/log`.
			argv_daemon = [fuzznetd, "--socket=" + sock, "--fuzznet-dir=" + store,
			               "--log-dir=" + os.path.join(scratch, "log"),
			               "--fuzznet-service=1", "--fuzznet-product=1"]
			proc = subprocess.Popen(argv_daemon, stdout=log, stderr=subprocess.STDOUT,
			                        start_new_session=True)
			got = status(sock)
			if got[1:3] != ["0", "off"] or got[5] != "0":
				raise failed("a: before it was set, get location said %r" % got)
			print("livecheck: a: sampling was off until it was set")

			for key, value in (("location/gpsd", "127.0.0.1 %d" % gpsd.port),
			                   ("location/every", "1"), ("location/enabled", "on")):
				if ask(sock, "set setting host %s %s" % (key, value)) != "ok":
					raise failed("b: set setting host %s answered otherwise" % key)
			until = time.monotonic() + 40.0
			while True:
				got = status(sock)
				if got[2] == "watching" and int(got[5]) >= 2 and int(got[6]) >= 1:
					break
				if time.monotonic() > until:
					raise failed("b: the node did not come to sample gpsd: %r, watch %s"
					             % (got, gpsd.watched))
				time.sleep(0.5)
			if not gpsd.watched:
				raise failed("b: the node read reports without sending WATCH")
			rows = [r.split(",") for r in ask(sock, "list location").split()[1:]]
			if not rows or any(r[3:12] != ["59.3293235", "18.0685815", "1792584005", "32", "-",
			                               "4", "9", "19", "0"] for r in rows):
				raise failed("b: list location holds %r, not the good fix alone" % rows)
			print("livecheck: b: the node watched gpsd, kept %s good fixes and dropped %s "
			      "poor ones" % (got[5], got[6]))

			# b2: KILLED WHILE SAMPLING, started again (sec 766, sec 689's
			# journey 5): the fixes kept before are still listed, and the node
			# watches gpsd again and keeps the next.
			before = len(rows)
			os.killpg(proc.pid, signal.SIGKILL)
			proc.wait(timeout=10)
			proc = subprocess.Popen(argv_daemon, stdout=log, stderr=subprocess.STDOUT,
			                        start_new_session=True)
			until = time.monotonic() + 40.0
			while True:
				got = status(sock)
				if got[2] == "watching" and int(got[5]) >= 1:
					break
				if time.monotonic() > until:
					raise failed("b2: started again, the node did not sample gpsd again: %r"
					             % got)
				time.sleep(0.5)
			rows = [r.split(",") for r in ask(sock, "list location").split()[1:]]
			if len(rows) < before or any(r[3:5] != ["59.3293235", "18.0685815"] for r in rows):
				raise failed("b2: started again, list location holds %r, not the %d fix(es) "
				             "kept before and the good fix alone" % (rows, before))
			print("livecheck: b2: killed while sampling and started again, the node kept its "
			      "%d fix(es) and watched gpsd again" % before)

			if ask(sock, "set setting host location/enabled off") != "ok":
				raise failed("c: turning sampling off was refused")
			time.sleep(2.0)
			got = status(sock)
			kept = got[5]
			time.sleep(3.0)
			later = status(sock)
			if later[1:3] != ["0", "off"] or later[5] != kept:
				raise failed("c: after it was turned off, get location said %r then %r"
				             % (got, later))
			print("livecheck: c: turned off, the node let gpsd go and kept nothing more")

			# d: PAST ONE REPLY (sec 770): the 13th fix of one host's no
			# longer fitted `list location`, and the list answered an error.
			last = 0
			while last < 20:
				got = ask(sock, "add location 59.3293230 18.0685810 alt 31 bearing 90 acc 5 9 "
				                "vacc 20 at %d" % (1792600000 + last))
				if not got.startswith("ok "):
					raise failed("d: add location answered %r" % got)
				last = int(got.split()[1])
			bare = ask(sock, "list location")
			if bare != "error the list does not fit a reply: list location 0 pages it":
				raise failed("d: a list past one reply answered %r" % bare[:120])
			rows, pages = [], 0
			while True:
				page = ask(sock, "list location %d" % len(rows)).split()
				if page[:1] != ["ok"] or int(page[2]) != len(rows) or int(page[1]) != 16:
					raise failed("d: list location %d answered %r" % (len(rows), page[:3]))
				pages += 1
				rows += page[3:]
				if not page[3:] or len(rows) >= 16:
					break
			seqs = [int(r.split(",")[1]) for r in rows]
			if seqs != list(range(last - 15, last + 1)) or pages < 2:
				raise failed("d: the pages listed %r in %d page(s), not the newest sixteen of "
				             "%d" % (seqs, pages, last))
			if not ask(sock, "list location x").startswith("malformed "):
				raise failed("d: list location x was not refused")
			print("livecheck: d: %d fixes held: the bare list said it does not fit, and %d "
			      "pages listed the newest sixteen once each" % (last, pages))
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		finally:
			gpsd.stop.set()
			if proc is not None and proc.poll() is None:
				os.killpg(proc.pid, signal.SIGTERM)
				try:
					proc.wait(timeout=10)
				except subprocess.TimeoutExpired:
					os.killpg(proc.pid, signal.SIGKILL)
					proc.wait(timeout=10)
			log.close()
		if time.monotonic() > deadline:
			print("livecheck: FAILED -- past the deadline")
			return 1
	print("livecheck: a node sampled gpsd, gated by accuracy, under its settings")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
