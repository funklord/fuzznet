#!/usr/bin/env python3
"""More notes than a host could once hold, kept and carried: `make livecheck`,
sec 914.

A is an estate's root and B a member of it, joined by a card.

    a  A takes 1000 notes, past the 256 it refused beyond, and lists them all
    b  B, started after, holds all 1000 within its rounds

Against a daemon bound at 256 claims, a stops at the 257th.

BOUNDED FROM INSIDE as live_rejoin.py is: one deadline, each daemon in its own
process group, and every daemon checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 500.0

NOTES = 1000


def held(sock):
	"""How many notes `sock`'s host lists at the top."""
	words = ask(sock, "list note top").split()
	if len(words) < 2 or words[0] != "ok" or not words[1].isdigit():
		raise failed("list note top answered %r" % words[:3])
	return int(words[1])


def main(argv):
	if len(argv) != 2:
		print("usage: live_many_notes.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port = str(28300 + (os.getpid() % 300))
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		a_dir, b_dir = os.path.join(scratch, "a"), os.path.join(scratch, "b")
		a_sock, b_sock = os.path.join(sock_dir, "a"), os.path.join(sock_dir, "b")
		os.mkdir(a_dir)
		os.mkdir(b_dir)
		a = b = None
		try:
			command(run, ["--fuzznet-dir=" + a_dir, "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + b_dir, "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + a_dir, "--pair=" + prekey, "--delegable"], None)
			command(run, ["--fuzznet-dir=" + b_dir, "--accept=" + card, "--join"], None)

			a = daemon(run, "a0", a_dir, a_sock, extra=["--udp-port=" + port])
			began = time.monotonic()
			for i in range(NOTES):
				reply = ask(a_sock, "add note top n%d" % i)
				if not reply.startswith("ok"):
					raise failed("a: note %d answered %r" % (i, reply))
			if held(a_sock) != NOTES:
				raise failed("a: A lists %d of %d" % (held(a_sock), NOTES))
			print("livecheck: a: A took %d notes in %.0f s" % (NOTES, time.monotonic() - began))

			b = daemon(run, "b0", b_dir, b_sock, extra=["--root-at", "127.0.0.1", port])
			began = time.monotonic()
			until = began + 300.0
			count = 0
			while time.monotonic() < until:
				count = held(b_sock)
				if count == NOTES:
					break
				time.sleep(2.0)
			if count != NOTES:
				raise failed("b: B holds %d of %d after 300 s" % (count, NOTES))
			print("livecheck: b: B held all %d in %.0f s" % (NOTES, time.monotonic() - began))
		except failed as e:
			print("livecheck: FAILED: %s" % e, file=sys.stderr)
			return 1
		finally:
			for d in (b, a):
				if d:
					d.stop()
	print("livecheck: a host keeps and carries more notes than it once could")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
