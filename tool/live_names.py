#!/usr/bin/env python3
"""One name given to two people on two hosts: `make livecheck`, sec 887.

Two hosts of a user's, A and B, admins of R's estate, apart while each adds
a different person as bob. Two admins, since a root's word outranks an
admin's: a clash is between equals. A contact here is a name for a key, so two
made-up keys serve.

    a  A names key K1 bob, and B names K2 bob, each before hearing the other
    b  both hosts hold both, and agree: the lower key is bob and the higher
       bob_2 on each, so `bob` is one person on every device
    c  renaming the higher reaches the same person on both, and frees
       nothing else: bob stays the lower key's

Against a daemon that leaves a clash for a later round, as sec 699 did, each
host keeps its own bob and phase b never agrees.

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

DEADLINE_S = 300.0
SETTLE_S = 120.0
LOW = "11" * 32
HIGH = "ee" * 32


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

			# b: ONE ANSWER ON EVERY HOST.
			agreed({LOW: "bob", HIGH: "bob_2"}, "b")
			print("livecheck: b: both hosts call the lower key bob and the higher bob_2")

			# c: A RENAME reaches the same person.
			expect(socks["a"], "a", "add contact robert " + HIGH, "ok")
			agreed({LOW: "bob", HIGH: "robert"}, "c")
			print("livecheck: c: renamed on A, the higher key is robert on both, bob unmoved")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started.values():
				d.stop()
	print("livecheck: one name given to two people came to mean one person on every host")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
