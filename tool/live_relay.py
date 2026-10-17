#!/usr/bin/env python3
"""A line relayed to a host nobody else reaches: `make livecheck`, sec 622.

Three stores over loopback. A is one user's one machine. B1 and B2 are
another's: B1, the root, is reached at its address, keeps no messages and
relays; B2, joined to B1, advertises an address nobody listens on -- as a
host behind a NAT would -- and says hello to B1 from its serving socket.

    a  A asks B for contact by B1's card, and B1 approves; the rounds pair
       A with B1 and B2, and A holds both hosts to deliver to
    b  A writes a line to B: B1 refuses it, keeping none; B2 does not
       answer at the address it advertised; A asks B1 to relay it to B2,
       and B2 holds the line under A's root
    c  A writes a second line while B's hosts are away, so the delivery a
       fresh write makes at once reaches nobody -- answering A's own client
       while it waits for them; once they are back, A's own
       round relays it -- the round's delivery, a conversation of its own
       (sec 637), and not the one between rounds

Against a daemon that relays nothing, phase b never delivers; against one
whose relay sends the answer nowhere, it waits out each offer.

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
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 420.0

PASS_RE = re.compile(r"contact pass: (\d+) contact\(s\) asked, (\d+) kept from members, "
                     r"(\d+) paired, (\d+) host\(s\) to deliver to")
KEPT_RE = re.compile(r"a contact request from ([0-9a-f]{16}), waiting")
RELAYED_RE = re.compile(r"line\(s\) offered to 127\.0\.0\.1 through 127\.0\.0\.1: 1 delivered")
# A ROUND'S OWN END, after its fetches and log pass: "history pass" comes
# before them (sec 637).
ROUND_END_RE = ROUND_DONE_RE
LINE = "61" * 16
LATER = "62" * 16
NOBODY_RE = re.compile(r"line\(s\) offered to 127\.0\.0\.1: 0 delivered, 0 settled, 0 refused, "
                       r"1 unanswered")
PREKEY_HOST = slice(4, 68)


def main(argv):
	if len(argv) != 2:
		print("usage: live_relay.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 6000 + (os.getpid() % 500) * 4
	port = {"a": str(base), "b1": str(base + 1), "b2": str(base + 2), "nobody": str(base + 3)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		names = ("a", "b1", "b2")
		dirs = {k: os.path.join(scratch, k) for k in names}
		socks = {k: os.path.join(sock_dir, k) for k in names}
		args = {
			"a": ["--udp-port=" + port["a"]],
			"b1": ["--udp-port=" + port["b1"], "--log-rule=policy messages drop"],
			"b2": ["--udp-port=" + port["b2"], "--root-at", "127.0.0.1", port["b1"]],
		}
		started = {}

		def up(who, tag):
			started[who] = daemon(run, tag, dirs[who], socks[who], extra=args[who])
			return started[who]

		def down(who):
			started.pop(who).stop()

		def turn(who, tag):
			if who in started:
				down(who)
			d = up(who, tag)
			d.wait_for(ROUND_END_RE, "%s's round" % who.upper())
			return d

		try:
			keys = {}
			for who in names:
				os.mkdir(dirs[who])
			for who in ("a", "b1"):
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
				keys[who] = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"],
				                    None)[PREKEY_HOST]
			prekey = command(run, ["--fuzznet-dir=" + dirs["b2"], "--prekey"], None)
			keys["b2"] = prekey[PREKEY_HOST]
			card = command(run, ["--fuzznet-dir=" + dirs["b1"], "--pair=" + prekey,
			                     "--delegable"], None)
			command(run, ["--fuzznet-dir=" + dirs["b2"], "--accept=" + card, "--join"], None)

			# B's estate: B1 reached and relaying; B2 advertising nowhere.
			up("b1", "b1a")
			expect(socks["b1"], "b1", "set setting host net/address 127.0.0.1 " + port["b1"], "ok")
			expect(socks["b1"], "b1", "set setting host relay/enabled 1", "ok")
			expect(socks["b1"], "b1", "set setting estate routing/advertise 1", "ok")
			up("b2", "b2a")
			expect(socks["b2"], "b2", "set setting host net/address 127.0.0.1 " + port["nobody"],
			       "ok")
			turn("b2", "b2b")
			turn("b1", "b1b")
			up("a", "a1")
			expect(socks["a"], "a", "set setting host net/address 127.0.0.1 " + port["a"], "ok")

			# a: A asks B by B1's card; B1 approves; the rounds pair them.
			got = ask(socks["b1"], "get card bee")
			if not got.startswith("ok FZC1:"):
				raise failed("a: get card answered %r" % got)
			got = ask(socks["a"], "add contact bee " + got.split(" ", 1)[1].strip())
			if got.strip() != "ok " + keys["b1"]:
				raise failed("a: add contact by card answered %r" % got)
			started["b1"].wait_for(KEPT_RE, "B1 keeping A's request")
			expect(socks["b1"], "b1", "grant request %s aye" % keys["a"], "ok")
			hosts = 0
			for rnd in range(4):
				turn("b1", "b1-r%d" % rnd)
				turn("b2", "b2-r%d" % rnd)
				d = turn("a", "a-r%d" % rnd)
				got = [int(m.group(4)) for m in PASS_RE.finditer(d.log())]
				hosts = got[-1] if got else 0
				if hosts == 2:
					break
			if hosts != 2:
				raise failed("a: after %d rounds A holds %d host(s) of B to deliver to"
				             % (rnd + 1, hosts))
			print("livecheck: a: A and B paired by B1's card, A holding B1 and B2")

			# b: the line, relayed through B1 to B2.
			turn("b2", "b2-c")
			expect(socks["a"], "a", "add message %s out %s relayed" % (keys["b1"], LINE), "ok")
			try:
				started["a"].wait_for(RELAYED_RE, "A's line relayed through B1")
			except failed:
				turn("b2", "b2-d")
				d = turn("a", "a-d")
				d.wait_for(RELAYED_RE, "A's line relayed through B1")
			reply = ask(socks["b2"], "list message " + keys["a"])
			if LINE not in reply:
				raise failed("b: B2 holds %r under A's root" % reply)
			print("livecheck: b: B1 refused the line and relayed it to B2, which holds it")

			# c: a line written while B's hosts are away, relayed by A's round.
			down("b1")
			down("b2")
			before = len(NOBODY_RE.findall(started["a"].log()))
			expect(socks["a"], "a", "add message %s out %s later" % (keys["b1"], LATER), "ok")
			# ANSWERED WHILE THAT DELIVERY WAITS, sec 637: it waits out B's two
			# hosts, 3 s each, and the loop answers meanwhile. One that answered
			# only after would have logged the delivery's end first -- counted
			# past phase b's own, logged by the same daemon.
			try:
				reply = ask(socks["a"], "list message " + keys["b1"])
			except OSError as e:
				raise failed("c: A did not answer while its delivery waited: %s" % e)
			if not reply.startswith("ok ") \
			   or len(NOBODY_RE.findall(started["a"].log())) > before:
				raise failed("c: A answered %r only once its delivery to nobody was over"
				             % reply[:40])
			until = time.monotonic() + 30.0
			while len(NOBODY_RE.findall(started["a"].log())) == before:
				if time.monotonic() > until:
					raise failed("c: A's delivery to nobody was not logged within 30 s")
				time.sleep(0.2)
			turn("b1", "b1e")
			turn("b2", "b2e")
			d = turn("a", "a-e")
			d.wait_for(RELAYED_RE, "A's round relaying the second line through B1")
			reply = ask(socks["b2"], "list message " + keys["a"])
			if LATER not in reply:
				raise failed("c: B2 holds %r under A's root" % reply)
			print("livecheck: c: A's own round relayed a line written while B was away")
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
							alive = run.fuzznetd.encode() in f.read()
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: a line was relayed to a host nobody else reaches")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
