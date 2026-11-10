#!/usr/bin/env python3
"""News between two running hosts in seconds, not rounds: sec 1004.

Two stores over loopback, each running throughout -- no restart to make a
round come, as the other group scripts make one. A asks for B by B's card and
B approves, and both are let finish the rounds that brings.

    a  A, holding B's host to deliver to, writes to B alone, and B reads it
       within CONTACT_S: the delivery a write makes at once (sec 637). First,
       before any group's news, whose rounds would carry it as well
    b  B makes a group and adds A; A holds it within JOIN_S, well inside one
       timed round (FZND_PULL_EVERY, 60 s): B's act starts a round at B,
       whose sync names a group A lacks, so A asks back
    c  B says a line, and A reads it within LINE_S: sealed as it was written
       and asked for at once, A's round started by B's lines asking it
    d  A says one back, and B reads it as soon

Fuzzypickles' scenarios, given two minutes, failed where a joining took
three rounds and a line two (inbox 2026-11-10). Against a daemon that starts
no round for a group's news, a takes up to a round and fails JOIN_S.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import re
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_groups import PREKEY_HOST  # noqa: E402
from live_rejoin import command, daemon, expect, free_slot  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 420.0

# A TIMED ROUND IS 60 s: each wait is well inside one, so a pass shows a
# follow-up round did the work.
JOIN_S = 40.0
LINE_S = 30.0
# A CONTACT'S LINE, tighter: one waiting out a timed round waits some 40 s.
CONTACT_S = 12.0
# HOW LONG A IS GIVEN TO HOLD B'S HOST, its contact passes' work.
HOSTS_S = 200.0
HOSTS_RE = re.compile(r"contact pass: \d+ contact\(s\) asked, \d+ kept from members, \d+ "
                      r"paired, ([1-9]\d*) host\(s\) to deliver to")


def until(what, test, wait):
	began = time.monotonic()
	while not test():
		if time.monotonic() - began > wait:
			raise failed("%s within %.0f s" % (what, wait))
		time.sleep(0.25)
	return time.monotonic() - began


def main(argv):
	if len(argv) != 2:
		print("usage: live_soon.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = free_slot(46000, 4, 500, 2)
	port = {"a": str(base), "b": str(base + 1)}
	started = {}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		try:
			keys = {}
			for who in port:
				os.mkdir(dirs[who])
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
				keys[who] = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"],
				                    None)[PREKEY_HOST]
			for who in port:
				started[who] = daemon(run, who, dirs[who], socks[who],
				                      extra=["--udp-port=" + port[who]])
				expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who],
				       "ok")
			card = ask(socks["b"], "get card bea")
			if not card.startswith("ok FZC1:"):
				raise failed("b: get card answered %r" % card)
			got = ask(socks["a"], "add contact bea " + card.split(" ", 1)[1].strip())
			if got.strip() != "ok " + keys["b"]:
				raise failed("a: add contact answered %r" % got)
			until("b never kept A's request",
			      lambda: ask(socks["b"], "grant request %s ada" % keys["a"]) == "ok", 30.0)

			# A HOLDING B'S HOST, as a contact of a while does: before it, a line
			# waits for the contact pass that learns it.
			started["a"].wait_for(HOSTS_RE, "A holding B's host", within=HOSTS_S)

			# a: A WRITES TO B ALONE.
			expect(socks["a"], "a", "add message %s out %s to_b_alone" % (keys["b"], "d1" * 16),
			       "ok")
			took = until("a: B never read A's line to it",
			             lambda: "to_b_alone" in ask(socks["b"], "list message " + keys["a"]),
			             CONTACT_S)
			print("livecheck: a: B read the line A wrote to it in %.1f s" % took)

			# b: B MAKES THE GROUP AND ADDS A.
			made = ask(socks["b"], "add group soon").split()
			if len(made) != 2 or made[0] != "ok":
				raise failed("b: add group answered %r" % made)
			expect(socks["b"], "b", "add member soon ada", "ok")
			took = until("b: A never held the group",
			             lambda: "soon," in ask(socks["a"], "list group"), JOIN_S)
			print("livecheck: b: A held the group %.1f s after B added it" % took)

			# c: B SAYS A LINE.
			expect(socks["b"], "b", "add message @soon out %s from_b" % ("b1" * 16), "ok")
			took = until("c: A never read B's line",
			             lambda: "from_b" in ask(socks["a"], "list message @soon"), LINE_S)
			print("livecheck: c: A read B's line in %.1f s" % took)

			# d: A SAYS ONE BACK.
			expect(socks["a"], "a", "add message @soon out %s from_a" % ("a1" * 16), "ok")
			took = until("d: B never read A's line",
			             lambda: "from_a" in ask(socks["b"], "list message @soon"), LINE_S)
			print("livecheck: d: B read A's line in %.1f s" % took)
		except failed as e:
			print("livecheck: FAILED: %s" % e, file=sys.stderr)
			return 1
		finally:
			for d in started.values():
				d.stop()
	print("livecheck: a group's joining and its lines, and a contact's line, come in seconds")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
