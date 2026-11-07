#!/usr/bin/env python3
"""Fill a running host with contacts, to measure what thousands cost: sec 933.

    seed_contacts.py SOCKET COUNT [PREFIX]

COUNT contacts named PREFIXN, each a random key, over the host's own socket. A
measuring tool, and nothing here is a real person's.

Says the longest wait and where it fell, as seeding is also a measurement of a
burst: on this machine 15600 contacts in 150 s, none waiting past 1.7 s.

BOUNDED: COUNT requests, each with its own wait and a fixed number of tries, and
it stops at the first that goes unanswered that many times.

Exit 0 when all were added, 1 otherwise.
"""

import os
import socket
import sys
import time

WAIT_S = 30.0
TRIES = 3


def ask(path, line):
	"""One request and its line, or None when none came within WAIT_S."""
	s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	s.settimeout(WAIT_S)
	try:
		s.connect(path)
		s.sendall(line.encode() + b"\n")
		got = b""
		while b"\n" not in got:
			chunk = s.recv(4096)
			if not chunk:
				return None
			got += chunk
		return got.decode(errors="replace").strip()
	except OSError:
		return None
	finally:
		s.close()


def main(argv):
	if len(argv) not in (3, 4):
		print(__doc__.split("\n\n")[1].strip(), file=sys.stderr)
		return 2
	path, count = argv[1], int(argv[2])
	prefix = argv[3] if len(argv) == 4 else "seed"
	began = time.monotonic()
	worst = worst_at = 0
	for i in range(count):
		line = "add contact %s%d %s" % (prefix, i, os.urandom(32).hex())
		for _ in range(TRIES):
			t = time.monotonic()
			reply = ask(path, line)
			took = time.monotonic() - t
			if took > worst:
				worst, worst_at = took, i
			if reply is not None:
				break
		if reply is None or not reply.startswith("ok"):
			print("seed: contact %d answered %r" % (i, reply), file=sys.stderr)
			return 1
	print("seed: %d contacts in %.1f s, the longest wait %.3f s at %d"
	      % (count, time.monotonic() - began, worst, worst_at))
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
