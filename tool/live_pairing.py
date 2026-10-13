#!/usr/bin/env python3
"""Two strangers become contacts by a card: `make livecheck`, sec 619.

Three stores over loopback, each a user of one machine with an address:
A asks, B is asked, C asks and is turned away.

    a  B shows its card (`get card bob`); A adds B by it (`add contact bob
       FZC1:...`), which sends B a request in a sealed box; B lists one
       request, from A's root, with A's card's name
    b  B approves it (`grant request ROOT alice`); B's round pairs A's host
       and offers B's, which is A's answer; A writes a line to B and it is
       delivered, and B files it under A's root
    c  C asks too; B rejects it (`remove request ROOT`) and lists none

Against a daemon that drops every box, phase a lists no request; against
one whose approval does not hand over to the contact round, phase b
delivers nothing.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import re
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402

KEPT_RE = re.compile(r"a contact request from ([0-9a-f]{16}), waiting")
OFFERED_RE = re.compile(r"line\(s\) offered to 127\.0\.0\.1: 1 delivered")
ROUND_END_RE = re.compile(r"history pass: ")
LINE = "51" * 16
PREKEY_HOST = slice(4, 68)


def requests(sock, who):
	"""`who`'s waiting requests, as [(root, name)]."""
	reply = ask(sock, "list request")
	words = reply.split()
	if len(words) < 2 or words[0] != "ok":
		raise failed("%s: list request answered %r" % (who, reply))
	return [tuple(w.split(",")[:2]) for w in words[2:]]


def main(argv):
	if len(argv) != 2:
		print("usage: live_pairing.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 8000 + (os.getpid() % 500) * 4
	port = {"a": str(base), "b": str(base + 1), "c": str(base + 2)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}

		def up(who, tag):
			started[who] = daemon(run, tag, dirs[who], socks[who],
			                      extra=["--udp-port=" + port[who]])
			return started[who]

		def down(who):
			started.pop(who).stop()

		try:
			keys = {}
			for who in port:
				os.mkdir(dirs[who])
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
				keys[who] = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"],
				                    None)[PREKEY_HOST]
			for who in port:
				up(who, who + "1")
				expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who],
				       "ok")

			# a: A asks B by B's card.
			card = ask(socks["b"], "get card bob")
			if not card.startswith("ok FZC1:"):
				raise failed("a: get card answered %r" % card)
			card = card.split(" ", 1)[1].strip()
			got = ask(socks["a"], "add contact bob " + card)
			if got.strip() != "ok " + keys["b"]:
				raise failed("a: add contact by card answered %r" % got)
			started["b"].wait_for(KEPT_RE, "B keeping A's request")
			held = requests(socks["b"], "b")
			if held != [(keys["a"], "-")]:
				raise failed("a: B's requests are %r, not A's alone" % (held,))
			print("livecheck: a: A asked B by B's card, and B holds A's request")

			# b: B approves; the round pairs them; a line goes.
			expect(socks["b"], "b", "grant request %s alice" % keys["a"], "ok")
			if requests(socks["b"], "b"):
				raise failed("b: B's request was still listed once approved")
			for who in ("b", "a"):
				down(who)
				d = up(who, who + "2")
				d.wait_for(ROUND_END_RE, "%s's round" % who.upper())
			expect(socks["a"], "a", "add message bob out %s hello%%20bob" % LINE, "ok")
			try:
				started["a"].wait_for(OFFERED_RE, "A's delivery to B")
			except failed:
				# A ROUND MORE at each, the pairing taking one to settle.
				for who in ("b", "a"):
					down(who)
					d = up(who, who + "3")
					d.wait_for(ROUND_END_RE, "%s's round" % who.upper())
				started["a"].wait_for(OFFERED_RE, "A's delivery to B")
			reply = ask(socks["b"], "list message " + keys["a"])
			if LINE not in reply or "hello%20bob" not in reply:
				raise failed("b: B holds %r under A's root" % reply)
			print("livecheck: b: approved, the two paired by the round, and A's line "
			      "delivered to B under A's root")

			# c: C asks; B turns it away.
			got = ask(socks["c"], "add contact bob " + card)
			if not got.startswith("ok "):
				raise failed("c: C's add contact answered %r" % got)
			deadline = time.monotonic() + 20.0
			while time.monotonic() < deadline:
				held = requests(socks["b"], "b")
				if held:
					break
				time.sleep(0.2)
			if held != [(keys["c"], "-")]:
				raise failed("c: B's requests are %r, not C's alone" % (held,))
			expect(socks["b"], "b", "remove request " + keys["c"], "ok")
			if requests(socks["b"], "b"):
				raise failed("c: a rejected request was still listed")
			print("livecheck: c: C asked too, and B turned it away")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
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
							alive = f.read() != b""
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: two strangers became contacts by a card, and a third was turned away")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
