#!/usr/bin/env python3
"""Named objects between two hosts, sec 948, on real daemons at the default round.

    a  R makes `lamp`, on or off, and A, a member, reads it
    b  a value set on R reaches a client held on A as an event, well inside a
       round, and A reads it with when and who; the same from A to R
    c  A goes away, R sets, and A come back reads the last value
    d  R's older values go at its next start's trim, each host's newest staying
    e  fifty sets at once on R: the first written, the rest held to the window,
       and the newest written once it passes, read on R and at A (sec 1034)

The default round is 60 s, so `FAST_S` says a change did not wait for one.

BOUNDED FROM INSIDE as live_estate.py is: one deadline, each daemon in its own
process group, and every daemon checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import select
import socket
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon, expect, free_slot  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 280.0

FAST_S = 15.0
LAMP = "lamp".encode().hex()


def heard(sock_path, what, trigger):
	"""`trigger` run with a client held on `sock_path`: how long until it hears
	`event object lamp`."""
	s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	s.settimeout(5.0)
	s.connect(sock_path)
	try:
		s.sendall(b"get events\n")
		buf = b""
		while b"\n" not in buf:
			buf += s.recv(4096)
		if not buf.startswith(b"ok events"):
			raise failed("%s: get events answered %r" % (what, buf))
		buf = buf.split(b"\n", 1)[1]
		began = time.monotonic()
		trigger()
		while time.monotonic() - began < FAST_S:
			if ("event object %s\n" % LAMP).encode() in buf:
				return time.monotonic() - began
			if select.select([s], [], [], 0.2)[0]:
				got = s.recv(4096)
				if not got:
					raise failed("%s: the node hung up on its client" % what)
				buf += got
		raise failed("%s: no event in %.0f s, of a round of 60: %r" % (what, FAST_S, buf[-120:]))
	finally:
		s.close()


def main(argv):
	if len(argv) != 2:
		print("usage: live_objects.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = free_slot(43000, 4, 500, 2)
	port = {"r": str(base), "a": str(base + 1)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}

		def up(who, name=None):
			started[who] = daemon(run, name or who, dirs[who], socks[who],
			                      extra=["--udp-port=" + port[who]])
			return started[who]

		def said(who, line):
			return ask(socks[who], line).strip()

		def polled(who, line, test, what, wait=FAST_S):
			until = time.monotonic() + wait
			while True:
				got = said(who, line)
				if test(got):
					return got
				if time.monotonic() > until:
					raise failed("%s: %s answered %r, %s" % (who, line, got, what))
				time.sleep(0.2)

		try:
			os.mkdir(dirs["r"])
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			up("r")
			# ANSWERING, not a round logged: an embedded host says less.
			polled("r", "status", lambda g: g.startswith("ok "), "not answering", 30.0)
			expect(socks["r"], "r", "set setting host net/address 127.0.0.1 " + port["r"], "ok")
			os.mkdir(dirs["a"])
			up("a")
			got = said("a", "get prekey").split()
			card = said("r", "add peer %s delegable" % got[1]).split()
			if len(card) != 2 or card[0] != "ok":
				raise failed("r: add peer answered %r" % card)
			path = os.path.join(scratch, "card")
			with open(path, "w") as f:
				f.write(card[1] + "\n")
			pid = started["a"].proc.pid
			if not said("a", "add join " + path).startswith("ok"):
				raise failed("a: add join did not take")
			until = time.monotonic() + 30.0
			while time.monotonic() < until:
				try:
					if said("a", "status").startswith("ok "):
						break
				except OSError:
					pass
				time.sleep(0.2)
			if started["a"].proc.pid != pid:
				raise failed("a: did not start again in place")
			polled("a", "list capability", lambda g: "member,1,1,0" in g.split()[2:],
			       "not a member", 60.0)
			expect(socks["a"], "a", "set setting host net/address 127.0.0.1 " + port["a"], "ok")

			# a: made on one host, read on the other.
			expect(socks["r"], "r", "add object lamp on off", "ok")
			polled("a", "get object lamp", lambda g: g == "ok - 0 - on|off",
			       "without R's object", 70.0)
			print("livecheck: a: R made an object and A reads it")

			# b: each way, as an event, inside a round.
			t = heard(socks["a"], "b", lambda: expect(socks["r"], "r", "set object lamp on", "ok"))
			got = polled("a", "get object lamp", lambda g: g.startswith("ok on "), "not on")
			by = got.split()[3]
			print("livecheck: b: R's set heard on A in %.1f s" % t)
			t = heard(socks["r"], "b2", lambda: expect(socks["a"], "a", "set object lamp off", "ok"))
			got = polled("r", "get object lamp", lambda g: g.startswith("ok off "), "not off")
			if got.split()[3] == by:
				raise failed("b2: A's value says R set it: %r" % got)
			print("livecheck: b2: A's set heard on R in %.1f s, and says who set it" % t)
			got = said("r", "call object get lamp")
			if got != "ok off":
				raise failed("b3: a local call answered %r" % got)
			expect(socks["r"], "r", "set setting host local/permit/object local:#1=r", "ok")

			# c: away, and back to the last value.
			started["a"].stop()
			expect(socks["r"], "r", "set object lamp on", "ok")
			up("a", "a2")
			polled("a", "get object lamp", lambda g: g.startswith("ok on "),
			       "not the value set while it was away", 70.0)
			print("livecheck: c: A, away for a set, reads the last value")

			# d: older values go by default, sec 963. R sets four times more
			# and starts again, whose first trim pass runs at start: each
			# host's newest value alone stays, and the value reads the same.
			# A WINDOW APART, sec 1034: sets inside one are held, not each recorded.
			for v in ("off", "on", "off", "on"):
				time.sleep(1.1)
				expect(socks["r"], "r", "set object lamp " + v, "ok")
			under = "list record under list/object-value/lamp"
			rows = said("r", under).split()[4:]
			if len(rows) < 6:
				raise failed("d: R held %d values before its trim: %r" % (len(rows), rows))
			value = said("r", "get object lamp")
			started["r"].stop()
			up("r", "r2")
			polled("r", "status", lambda g: g.startswith("ok "), "not answering", 30.0)
			got = polled("r", under, lambda g: len(g.split()[4:]) == 2,
			             "not each host's newest value alone", 30.0)
			if said("r", "get object lamp") != value:
				raise failed("d: the trim changed the value: %r" % said("r", "get object lamp"))
			print("livecheck: d: %d values trimmed to each host's newest, %r" % (len(rows), got))

			# e: A FLOOD, sec 1034: fifty sets at once on R are taken, most held to
			# the window, and the newest is written once it passes and reaches A.
			time.sleep(1.1)
			answers = [said("r", "set object lamp " + ("on" if k % 2 else "off"))
			           for k in range(50)]
			if answers[0] != "ok" or answers[1:].count("ok held") < 45:
				raise failed("e: a flood was answered %r" % sorted(set(answers)))
			polled("r", "get object lamp", lambda g: g.startswith("ok on "),
			       "not the flood's newest, on", 10.0)
			polled("a", "get object lamp", lambda g: g.startswith("ok on "),
			       "not the flood's newest at A", 70.0)
			print("livecheck: e: fifty sets at once, %d held, the newest written and at A"
			      % answers.count("ok held"))
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			for name in sorted(os.listdir(scratch)):
				if name.endswith(".err"):
					with open(os.path.join(scratch, name), errors="replace") as f:
						tail = f.read().splitlines()[-30:]
					print("livecheck: --- %s" % name)
					for line in tail:
						print("livecheck:     %s" % line)
			return 1
		finally:
			for d in started.values():
				d.stop()
	print("livecheck: named objects went between two hosts")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
