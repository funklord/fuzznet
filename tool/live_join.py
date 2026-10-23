#!/usr/bin/env python3
"""An estate joined by verbs on running daemons: `make livecheck`, sec 638.

Two stores over loopback: A the root of its estate, B a fresh device. Both
run as daemons throughout, and the join is made by local verbs alone, as a
client drives it -- no one-shot command, no daemon stopped by its client.

    a  B answers `get prekey` with its prekey record; A, given it with
       `add peer RECORD delegable`, answers a card and lists the grant at
       once (sec 712). A card made before A
       has a `net/address` says nowhere, and B's `add join PATH` with it
       is refused, joining nothing; A sets its address and the next card
       says where A is (sec 671)
    b  B, given `add join PATH` -- the card in a file, no HOST PORT --,
       answers A's key and starts again in place -- the same process, its
       socket back -- and its first round reads a setting A made before B
       joined
    c  B started again with no `--root-at` still pulls from A, where the
       join kept it, and reads a second setting A makes
    d  A's `list sibling` names B, paired
    e  B's `list capability` holds member by one hop; A's `list grant` names
       the grant it made B, standing
    f  A grants B admin; B keeps the chain with `set admin PATH` and starts
       again in place, holding admin by one hop
    g  A's `list log` reads what A logged, newest first: at its default
       level no debug entry, and at D more, debug among them (sec 711)

Against a daemon whose `add join` did not start it again, phase b's round
never reads A's setting; against one that kept no address, phase c's;
against one whose card says nowhere, phase b's join is refused.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 300.0

# A KEY ON THE STATUS LINE: what `add join` answers, the root's.
KEY_LEN = 64
# A PREKEY RECORD'S HOST KEY, in hex.
PREKEY_HOST = slice(4, 68)


def main(argv):
	if len(argv) != 2:
		print("usage: live_join.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 1024 + (os.getpid() % 19) * 4
	port = {"a": str(base), "b": str(base + 1)}
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

		def round_done(who, what, within=60.0):
			"""The first round's end of `who`'s current run."""
			return started[who].wait_for(ROUND_DONE_RE, what, within=within)

		def setting(who, key):
			reply = ask(socks[who], "get setting estate " + key).strip()
			return reply

		def reads(who, key, within=90.0):
			"""Whether `who` comes to read `key` as A set it, within `within`.
			Polled rather than waited on a round's end: a run started again in
			place keeps its pid, so the round ends logged before it still match."""
			until = time.monotonic() + within
			while time.monotonic() < until:
				if setting(who, key) == "ok root 1":
					return True
				time.sleep(0.5)
			return False

		try:
			for who in port:
				os.mkdir(dirs[who])
			command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
			up("a", "a1")
			round_done("a", "A's first round")
			expect(socks["a"], "a", "set setting estate x/before 1", "ok")
			up("b", "b1")

			# a: B's prekey, and A's card for it.
			got = ask(socks["b"], "get prekey").split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("a: get prekey answered %r" % got)
			key_b = got[1][PREKEY_HOST]
			# A CARD THAT SAYS NOWHERE, made before A has an address: B's
			# join with it and no HOST PORT is refused, and joins nothing.
			card = ask(socks["a"], "add peer %s delegable" % got[1]).split()
			if len(card) != 2 or card[0] != "ok":
				raise failed("a: add peer ... delegable answered %r" % card)
			nowhere_path = os.path.join(scratch, "card-nowhere")
			with open(nowhere_path, "w") as f:
				f.write(card[1] + "\n")
			refused = ask(socks["b"], "add join %s" % nowhere_path)
			if not refused.startswith("malformed the card says nowhere"):
				raise failed("a: a card that says nowhere was answered %r" % refused)
			expect(socks["a"], "a", "set setting host net/address 127.0.0.1 " + port["a"], "ok")
			card = ask(socks["a"], "add peer %s delegable" % got[1]).split()
			if len(card) != 2 or card[0] != "ok":
				raise failed("a: add peer ... delegable answered %r" % card)
			# AT ONCE, sec 712: the grant A just minted is in A's own listing,
			# where it waited for A's next round to apply A's own stream.
			granted = ask(socks["a"], "list grant").split()
			if not any(e.startswith(key_b + ",member,") and e.endswith(",1") for e in granted[3:]):
				raise failed("a: straight after add peer, A's list grant answered %r" % granted)
			print("livecheck: a: B said its prekey, A answered a card for it, and a card "
			      "made before A had an address joined nothing")

			# b: B joins, by a verb, and starts again in place.
			pid = started["b"].proc.pid
			# THE CARD IN A FILE: it is longer than a request line.
			card_path = os.path.join(scratch, "card")
			with open(card_path, "w") as f:
				f.write(card[1] + "\n")
			# NO HOST PORT: the card says where A is.
			joined = ask(socks["b"], "add join %s" % card_path).split()
			if len(joined) != 2 or joined[0] != "ok" or len(joined[1]) != KEY_LEN:
				raise failed("b: add join answered %r" % joined)
			deadline = time.monotonic() + 20.0
			while time.monotonic() < deadline:
				try:
					if ask(socks["b"], "status").startswith("ok "):
						break
				except OSError:
					pass
				time.sleep(0.2)
			else:
				raise failed("b: B's socket did not come back after the join")
			if started["b"].proc.poll() is not None or started["b"].proc.pid != pid:
				raise failed("b: B did not start again in place")
			if not reads("b", "x/before"):
				raise failed("b: after joining, B reads %r of A's setting"
				             % setting("b", "x/before"))
			print("livecheck: b: B joined by a verb, started again in place, and read A's "
			      "setting")

			# c: started again plainly, B pulls from where the join kept A.
			started.pop("b").stop()
			expect(socks["a"], "a", "set setting estate x/after 1", "ok")
			up("b", "b2")
			round_done("b", "B's first round from the kept address")
			if not reads("b", "x/after"):
				raise failed("c: started again with no --root-at, B reads %r"
				             % setting("b", "x/after"))
			print("livecheck: c: B, started with no --root-at, pulled from where the join "
			      "kept its root")

			# d: A lists B among its siblings, paired (sec 638) -- once a round of
			# A's own has applied the prekey B's estate stream carries.
			until = time.monotonic() + 90.0
			while True:
				listed = ask(socks["a"], "list sibling").split()
				if len(listed) >= 3 and listed[0] == "ok" \
				   and any(e.startswith(key_b + ",") and ",paired," in e for e in listed[3:]):
					break
				if time.monotonic() > until:
					raise failed("d: A's list sibling answered %r, not B paired" % listed)
				time.sleep(1.0)
			print("livecheck: d: A lists B among its siblings, paired")

			# e: B holds the member capability by A's grant, one hop; A lists
			# the grant it made B, standing (sec 638).
			def polled(who, line, test, what):
				until = time.monotonic() + 90.0
				while True:
					got = ask(socks[who], line).split()
					if got and got[0] == "ok" and test(got):
						return got
					if time.monotonic() > until:
						raise failed("e: %s answered %r, %s" % (line, got, what))
					time.sleep(1.0)

			polled("b", "list capability", lambda g: "member,1,1,0" in g[2:],
			       "not member held by one hop")
			polled("a", "list grant",
			       lambda g: any(e.startswith(key_b + ",member,") and e.endswith(",1")
			                     for e in g[3:]),
			       "not B's member grant, standing")
			print("livecheck: e: B holds the member capability by A's grant, and A lists it")

			# f: A grants B admin; B keeps the chain by a verb and starts again
			# in place, holding admin by one hop (sec 658) -- what took
			# `fuzznetd --set-admin`, the daemon stopped.
			if any(e.startswith("admin,1,") for e in ask(socks["b"], "list capability").split()[2:]):
				raise failed("f: B holds admin before any grant")
			granted = ask(socks["a"], "grant admin " + key_b).split()
			if len(granted) < 2 or granted[0] != "ok" or not granted[1].startswith("h"):
				raise failed("f: A's grant admin answered %r" % granted[:2])
			chain_path = os.path.join(scratch, "admin-chain")
			with open(chain_path, "w") as f:
				f.write(" ".join(granted[1:]) + "\n")
			pid = started["b"].proc.pid
			expect(socks["b"], "b", "set admin " + chain_path, "ok %d" % (len(granted) - 1))
			deadline = time.monotonic() + 20.0
			while time.monotonic() < deadline:
				try:
					if ask(socks["b"], "status").startswith("ok "):
						break
				except OSError:
					pass
				time.sleep(0.2)
			if started["b"].proc.poll() is not None or started["b"].proc.pid != pid:
				raise failed("f: B did not start again in place")
			polled("b", "list capability", lambda g: any(e.startswith("admin,1,1,") for e in g[2:]),
			       "not admin held by one hop")
			print("livecheck: f: A granted B admin, and B kept it by a verb, started again in place")

			# g: A's own log, read by a verb (sec 711).
			got = ask(socks["a"], "list log").split()
			if len(got) < 4 or got[0] != "ok" or int(got[1]) < 1 or got[2] != "0":
				raise failed("g: A's list log answered %r" % got[:4])
			if any(e.split(",")[1] in ("D", "T") for e in got[3:]):
				raise failed("g: list log at its default level holds debug: %r" % got[3:6])
			times = [int(e.split(",")[0]) for e in got[3:]]
			if times != sorted(times, reverse=True):
				raise failed("g: A's log entries are not newest first: %r" % times[:6])
			at_info = int(got[1])
			got = ask(socks["a"], "list log 0 D").split()
			if len(got) < 4 or int(got[1]) <= at_info \
			   or not any(e.split(",")[1] == "D" for e in got[3:]):
				raise failed("g: at D, A's log holds no more than at I, or no debug: %r"
				             % got[:6])
			print("livecheck: g: A's list log reads its own entries newest first, debug at D "
			      "alone")
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
	print("livecheck: an estate was joined by verbs on running daemons")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
