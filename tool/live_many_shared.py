#!/usr/bin/env python3
"""A folder of thousands reaches who it was shared with: `make livecheck`, sec 942.

S shares a folder of 2200 notes with R, a contact, past what one index page holds.

    a  R holds them all. A full page is 69132 bytes in 68 pieces, which a slot of 69132
       refused as too large, so a share past about 2000 notes never arrived, and the
       only sign was "the peer did not answer" each round
    b  each page of the tree read back, each note once, in CPU ticks that are not
       the view loaded again a page

Against a daemon whose reply slot is not in whole pieces, a holds nothing.

BOUNDED FROM INSIDE as live_rejoin.py is: one deadline, each daemon in its own process
group, and every daemon checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_many_contacts import cpu_ticks  # noqa: E402
from live_rejoin import command, daemon  # noqa: E402
from live_shares import PREKEY_HOST  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 230.0

NOTES = 2200
WAIT_S = 150.0
# CPU ticks a listing may take, rounds landing in it included. The view loaded a page
# is thousands.
LISTING_TICKS = 150


def retried(sock, line):
	"""`line` answered, through what a first large pull holds the loop for."""
	for _ in range(6):
		try:
			return ask(sock, line)
		except TimeoutError:
			continue
	raise failed("%r went unanswered" % line)


def listed(sock, parent):
	seen, at, total = [], 0, None
	while total is None or at < total:
		words = retried(sock, "list shared sam %s %d" % (parent, at)).split()
		if len(words) < 3 or words[0] != "ok":
			raise failed("b: a page at %d answered %r" % (at, words[:3]))
		total = int(words[1])
		seen += [w.split(",")[0] for w in words[3:]]
		at += len(words) - 3
	return seen


def main(argv):
	if len(argv) != 2:
		print("usage: live_many_shared.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port = str(26000 + os.getpid() % 2000)
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in "sr"}
		socks = {k: os.path.join(sock_dir, k) for k in "sr"}
		for d in dirs.values():
			os.mkdir(d)
		s = r = None
		try:
			for who in "sr":
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
			s_key = command(run, ["--fuzznet-dir=" + dirs["s"], "--prekey"], None)[PREKEY_HOST]
			r_prekey = command(run, ["--fuzznet-dir=" + dirs["r"], "--prekey"], None)
			s = daemon(run, "s1", dirs["s"], socks["s"], extra=["--udp-port=" + port])
			ask(socks["s"], "add contact rory " + r_prekey[PREKEY_HOST])
			folder = ask(socks["s"], "add folder top big").split()[1]
			for i in range(NOTES):
				reply = ask(socks["s"], "add note %s n%d" % (folder, i))
				if not reply.startswith("ok"):
					raise failed("note %d answered %r" % (i, reply))
			ask(socks["s"], "add share %s rory" % folder)
			card = ask(socks["s"], "grant share rory " + r_prekey)
			if not card.startswith("ok "):
				raise failed("grant share answered %r" % card)
			card_path = os.path.join(scratch, "card")
			with open(card_path, "w") as f:
				f.write(card.split(" ", 1)[1])

			r = daemon(run, "r1", dirs["r"], socks["r"])
			ask(socks["r"], "add contact sam " + s_key)
			reply = ask(socks["r"], "add received sam 127.0.0.1 %s %s" % (port, card_path))
			if not reply.startswith("ok"):
				raise failed("add received answered %r" % reply)
			began = time.monotonic()
			held = 0
			while time.monotonic() - began < WAIT_S and held < NOTES:
				words = retried(socks["r"], "list shared sam %s" % folder).split()
				held = int(words[1]) if words[0] == "ok" and words[1].isdigit() else 0
				time.sleep(1.0)
			if held < NOTES:
				raise failed("a: R holds %d of %d after %.0f s" % (held, NOTES, WAIT_S))
			print("livecheck: a: R took a share of %d notes in %.0f s"
			      % (NOTES, time.monotonic() - began))

			# b: the round over, so what is counted is the pages.
			before = cpu_ticks(r.proc.pid)
			seen = listed(socks["r"], folder)
			ticks = cpu_ticks(r.proc.pid) - before
			if len(seen) != NOTES or len(set(seen)) != NOTES:
				raise failed("b: %d rows, %d notes, of %d" % (len(seen), len(set(seen)), NOTES))
			if ticks > LISTING_TICKS:
				raise failed("b: a listing of %d took %d CPU ticks" % (NOTES, ticks))
			print("livecheck: b: every page of %d read back in %d CPU ticks" % (NOTES, ticks))
		except failed as e:
			print("livecheck: FAILED -- %s" % e, file=sys.stderr)
			return 1
		finally:
			for d in (r, s):
				if d:
					d.stop()
	print("livecheck: a folder of thousands reached who it was shared with")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
