#!/usr/bin/env python3
"""A contact that moved address: `make livecheck`, sec 884.

Two users of one machine each, contacts by card as live_group_backfill.py has
them. B moves as the holder's desk did on 2026-11-01: it comes back on
another port and tells nobody. Its device record still names the old one.

    a  A's line reaches B at the address B advertised
    b  B moves. A's next line reaches B at its new port, with no verb said
       at either end (sec 812)
    c  B's line, written after the move, reaches A
    d  A restarted, so what it heard is gone from memory: its next line
       still reaches B, by B's next hello

Sec 812's other limit, both ends moving at once, is not here: neither hears
the other, and that is stated there rather than claimed to work.

Against a daemon that sends only to the address a device record gives,
phase b's line never arrives.

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
from live_rejoin import command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
from live_groups import KEPT_RE, PREKEY_HOST  # noqa: E402
import live_trim  # noqa: E402

DEADLINE_S = 420.0
REACH_S = 120.0


def main(argv):
	if len(argv) != 2:
		print("usage: live_moved.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	live_trim.DEADLINE = time.monotonic() + DEADLINE_S
	base = 23100 + (os.getpid() % 300) * 4
	port = {"a": str(base), "b": str(base + 1)}
	moved_to = str(base + 2)
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}

		def up(who, tag, at=None):
			started[who] = daemon(run, tag, dirs[who], socks[who],
			                      extra=["--udp-port=" + (at or port[who])])
			return started[who]

		def reaches(who, of, text, what):
			"""`who` lists a line of `of`'s holding `text`, within REACH_S."""
			until = time.monotonic() + REACH_S
			while text not in ask(socks[who], "list message " + keys[of]):
				if time.monotonic() > until:
					raise failed("%s: %s lists %r" % (what, who.upper(),
					             ask(socks[who], "list message " + keys[of])[:300]))
				time.sleep(1.0)

		try:
			keys = {}
			for who in port:
				os.mkdir(dirs[who])
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
				keys[who] = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"],
				                    None)[PREKEY_HOST]
			for who in port:
				up(who, who + "0")
				expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who],
				       "ok")
			card = ask(socks["b"], "get card bob")
			if not card.startswith("ok FZC1:"):
				raise failed("setup: get card answered %r" % card)
			got = ask(socks["a"], "add contact bob " + card.split(" ", 1)[1].strip())
			if got.strip() != "ok " + keys["b"]:
				raise failed("setup: add contact answered %r" % got)
			started["b"].wait_for(KEPT_RE, "B keeping A's request")
			expect(socks["b"], "b", "grant request %s alice" % keys["a"], "ok")

			# a: at the address B advertised.
			expect(socks["a"], "a", "add message %s out %s before_the_move" % (keys["b"], "a1" * 16),
			       "ok")
			reaches("b", "a", "before_the_move", "a")
			print("livecheck: a: A's line reached B where B said it was")

			# b: B moves, and says so to nobody.
			started.pop("b").stop()
			up("b", "b-moved", moved_to)
			expect(socks["a"], "a", "add message %s out %s after_the_move" % (keys["b"], "b1" * 16),
			       "ok")
			reaches("b", "a", "after_the_move", "b")
			print("livecheck: b: B moved and told nobody, and A's next line reached it")

			# c: the other way.
			expect(socks["b"], "b", "add message %s out %s from_the_new_place" % (keys["a"], "c1" * 16),
			       "ok")
			reaches("a", "b", "from_the_new_place", "c")
			print("livecheck: c: B's line from its new port reached A")

			# d: A forgets where it heard B.
			started.pop("a").stop()
			up("a", "a-again")
			expect(socks["a"], "a", "add message %s out %s after_a_restart" % (keys["b"], "d1" * 16),
			       "ok")
			reaches("b", "a", "after_a_restart", "d")
			print("livecheck: d: A, started again, reached B by its next hello")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started.values():
				d.stop()
	print("livecheck: a contact that moved was followed with nothing said")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
