#!/usr/bin/env python3
"""One name given to two people on two hosts: `make livecheck`, sec 893.

Two hosts of a user's, A and B, admins of R's estate, apart while each adds
a different person as bob. Two admins, since a root's word outranks an
admin's: a clash is between equals. A contact here is a name for a key, so two
made-up keys serve.

    a  A names key K1 bob, and B names K2 bob, each before hearing the other
    b  both hosts call both people bob, and neither was renamed behind its
       user. `bob` is refused on each, for what it might reach, and a key
       reaches the one meant
    c  a name given where it is already held is kept, and said to clash
    d  renaming one reaches the same person on both, and `bob` then means
       the other on every host
    e  one person renames one contact two ways, on A and on B, before either
       hears: one stands, and `list fork` shows both on both hosts (sec 895)
    f  making the change again on one host, having seen both, closes it on both
    g  renames one after the other on two hosts make no fork, however late
       the first host's record comes
    h  two jobs decide one subject apart from different grounds; each decides
       again from both, reaches one value, and the fork closes with no person
    i  an estate setting a person writes is tracked the same way

Against a daemon that settles a clash by key, as sec 888 did, the higher key
goes by bob_2 and phase b never agrees; against one that leaves it for a later
round, as sec 699 did, each host keeps its own bob.

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

DEADLINE_S = 1500.0
SETTLE_S = 180.0
LOW = "11" * 32
HIGH = "ee" * 32
THIRD = "77" * 32


def main(argv):
	if len(argv) != 2:
		print("usage: live_names.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	live_trim.DEADLINE = time.monotonic() + DEADLINE_S
	base = 25100 + (os.getpid() % 300) * 3
	port = {"r": str(base), "a": str(base + 1), "b": str(base + 2)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}

		def names(who):
			"""`who`'s contacts as {key: name}."""
			rows = ask(socks[who], "list contact").split()[3:]
			return {r.split(",")[1]: r.split(",")[0] for r in rows if "," in r}

		def agreed(want, what):
			until = time.monotonic() + SETTLE_S
			while True:
				held = {who: names(who) for who in ("a", "b")}
				if all(all(held[who].get(k) == v for k, v in want.items()) for who in held):
					return
				if time.monotonic() > until:
					raise failed("%s: the hosts hold %r" % (what, held))
				time.sleep(1.0)

		try:
			for d in dirs.values():
				os.mkdir(d)
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			keys = {}
			for who in ("a", "b"):
				prekey = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"], None)
				keys[who] = prekey[4:68]
				card = command(run, ["--fuzznet-dir=" + dirs["r"], "--pair=" + prekey,
				                     "--delegable"], None)
				command(run, ["--fuzznet-dir=" + dirs[who], "--accept=" + card, "--join"], None)
			started["r"] = daemon(run, "r", dirs["r"], socks["r"],
			                      extra=["--udp-port=" + port["r"]])
			for who in ("a", "b"):
				started[who] = daemon(run, who, dirs[who], socks[who],
				                      extra=["--udp-port=" + port[who], "--root-at", "127.0.0.1",
				                             port["r"]])
				started[who].wait_for(ROUND_DONE_RE, "%s's first round" % who.upper(), within=60.0)
			for who in ("a", "b"):
				granted = ask(socks["r"], "grant admin " + keys[who]).split()
				if len(granted) < 2 or granted[0] != "ok":
					raise failed("setup: grant admin answered %r" % granted[:2])
				path = os.path.join(scratch, "admin-" + who)
				with open(path, "w") as f:
					f.write(" ".join(granted[1:]) + "\n")
				expect(socks[who], who, "set admin " + path, "ok %d" % (len(granted) - 1))
				until = time.monotonic() + 40.0
				while True:
					try:
						if any(e.startswith("admin,1,")
						       for e in ask(socks[who], "list capability").split()):
							break
					except OSError:
						pass
					if time.monotonic() > until:
						raise failed("setup: %s never held admin" % who.upper())
					time.sleep(0.5)

			# a: EACH HOST HOLDS BOTH PEOPLE, then BOB, TWICE, each host's word
			# made before it hears the other's.
			def retried(who, line, want):
				until = time.monotonic() + 30.0
				while True:
					got = ask(socks[who], line)
					if got == want:
						return
					if time.monotonic() > until:
						raise failed("a: %s answered %r" % (line, got))
					time.sleep(0.5)

			retried("a", "add contact first " + LOW, "ok")
			retried("a", "add contact second " + HIGH, "ok")
			retried("b", "add contact uno " + LOW, "ok")
			retried("b", "add contact dos " + HIGH, "ok")
			time.sleep(1.1)
			retried("a", "add contact bob " + LOW, "ok")
			retried("b", "add contact bob " + HIGH, "ok")
			print("livecheck: a: A named one key bob, and B another")

			# b: BOTH ARE BOB, and bob is no answer to who.
			agreed({LOW: "bob", HIGH: "bob"}, "b")
			for who in ("a", "b"):
				expect(socks[who], who, "list message bob",
				       "error two contacts have that name: give the key")
				expect(socks[who], who, "list device bob",
				       "error two contacts have that name: give the key")
				expect(socks[who], who, "remove contact bob",
				       "error two contacts have that name: give the key")
				got = ask(socks[who], "list message " + HIGH)
				if not got.startswith("ok"):
					raise failed("b: by key %s answered %r" % (who.upper(), got))
			print("livecheck: b: both hosts hold two bobs, refuse the name, and take a key")

			# c: SAID TO CLASH, and kept.
			expect(socks["a"], "a", "add contact third " + THIRD, "ok")
			got = ask(socks["a"], "add contact bob " + THIRD).split()
			if got[:2] != ["ok", "clash"] or sorted(got[2:]) != sorted([LOW, HIGH]):
				raise failed("c: a third bob answered %r" % got)
			if names("a").get(THIRD) != "bob":
				raise failed("c: A does not hold the third as bob: %r" % names("a"))
			expect(socks["a"], "a", "remove contact " + THIRD, "ok")
			print("livecheck: c: a third bob was kept and said to clash with both")

			# d: A RENAME reaches the same person, and bob comes to mean one.
			expect(socks["a"], "a", "add contact robert " + HIGH, "ok")
			agreed({LOW: "bob", HIGH: "robert"}, "d")
			for who in ("a", "b"):
				got = ask(socks[who], "list message bob")
				if not got.startswith("ok"):
					raise failed("d: `list message bob` on %s answered %r" % (who.upper(), got))
			print("livecheck: d: renamed on A, the higher key is robert on both, and bob is one")

			# e: ONE PERSON RENAMED APART, sec 895: the same contact named two ways,
			# neither host having heard. One stands, and both are shown on each.
			def fork_on(who):
				rows = ask(socks[who], "list fork").split()[4:]
				return sorted(r.split(",")[4] for r in rows if "," in r)

			def forks_settle(want, what):
				until = time.monotonic() + SETTLE_S
				while True:
					held = {who: fork_on(who) for who in ("a", "b")}
					if all(v == want for v in held.values()):
						return
					if time.monotonic() > until:
						raise failed("%s: the hosts hold forks %r" % (what, held))
					time.sleep(1.0)

			retried("a", "add contact dave " + LOW, "ok")
			retried("b", "add contact david " + LOW, "ok")
			forks_settle(["dave", "david"], "e")
			print("livecheck: e: one contact named two ways apart is shown as a fork on both")

			# f: CHOSEN, on either host, by making the change again.
			expect(socks["b"], "b", "add contact dave " + LOW, "ok")
			forks_settle([], "f")
			agreed({LOW: "dave"}, "f")
			print("livecheck: f: named again on B having seen both, the fork closed on both")

			# g: NO FORK WITHOUT A SPLIT: B renames as soon as the setting shows
			# A's, whatever has become of A's record.
			expect(socks["a"], "a", "add contact daniel " + LOW, "ok")
			agreed({LOW: "daniel"}, "g")
			expect(socks["b"], "b", "add contact dan " + LOW, "ok")
			agreed({LOW: "dan"}, "g")
			time.sleep(2.0)
			forks_settle([], "g")
			print("livecheck: g: renames one after the other, on two hosts, never forked")

			# h: TWO JOBS DECIDE APART, then each again from both grounds.
			retried("a", "add decided tune/x grounds=g1 5", "ok")
			retried("b", "add decided tune/x grounds=g2 7", "ok")
			forks_settle(["5", "7"], "h")
			retried("a", "add decided tune/x grounds=g1+g2 7", "ok")
			retried("b", "add decided tune/x grounds=g1+g2 7", "ok")
			forks_settle([], "h")
			got = ask(socks["a"], "get decided tune/x").split()
			if got[0] != "ok" or not all(r.endswith(",g1+g2,7") or r.endswith(",g1%2bg2,7")
			                             for r in got[2:]):
				raise failed("h: A's heads are %r" % got)
			print("livecheck: h: two deciders forked, and each deciding from both grounds "
			      "settled it with no person")

			# i: AN ESTATE SETTING WRITTEN TWO WAYS APART, by the verb a person uses.
			retried("a", "set setting estate room/temp 19", "ok")
			retried("b", "set setting estate room/temp 21", "ok")
			forks_settle(["19", "21"], "i")
			expect(socks["a"], "a", "set setting estate room/temp 20", "ok")
			forks_settle([], "i")
			print("livecheck: i: an estate setting written two ways apart was shown, and "
			      "settled by writing it again")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started.values():
				d.stop()
	print("livecheck: two people sharing a name stayed two, and no host guessed between them")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
