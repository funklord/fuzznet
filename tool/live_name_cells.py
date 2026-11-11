#!/usr/bin/env python3
"""Contacts whose keys share a name cell keep their own names: sec 1010.

One store, running throughout. Each contact's estate name is a setting under
`contact/name/` and the first 16 bytes of its key, and a round renames a
contact to the name its cell holds. Three contacts are added whose keys share
those 16 bytes, as keys made up for a test do, and a fourth whose key is its
own; a group is made, so a round comes soon (sec 1004), and two more.

    a  every contact still has the name it was added with, and each is found
       by it -- where the three had all taken the last one's name, and one was
       found twice and the others not at all (fuzzypickles 20261111T0024Z)

Against a daemon that takes a shared cell's name for every contact in it, a
fails.

BOUNDED: one deadline; the daemon in its own process group, stopped on every
path out.

Exit 0 on a pass, 1 on a failure.
"""

import os
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 200.0

SHARED = "11" * 16
KEYS = {"ann": SHARED + "a1" * 16, "ben": SHARED + "b2" * 16, "cy": SHARED + "c3" * 16,
        "dot": "d4" * 32}
ROUNDS = 3


def main(argv):
	if len(argv) != 2:
		print("usage: live_name_cells.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	d = None
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		store = os.path.join(scratch, "s")
		sock = os.path.join(sock_dir, "s")
		try:
			os.mkdir(store)
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)
			d = daemon(run, "s", store, sock)
			for name, key in KEYS.items():
				expect(sock, "s", "add contact %s %s" % (name, key), "ok")
			# ROUNDS, each started by a group made (sec 1004).
			for k in range(ROUNDS):
				before = len(ROUND_DONE_RE.findall(d.log()))
				ask(sock, "add group cells%d" % k)
				limit = time.monotonic() + 40.0
				while len(ROUND_DONE_RE.findall(d.log())) <= before:
					if time.monotonic() > limit:
						raise failed("a: no round came after a group was made")
					time.sleep(0.25)
			listed = {}
			frm = 0
			while True:
				w = ask(sock, "list contact %d" % frm).split()
				rows = w[3:]
				for row in rows:
					f = row.split(",")
					listed[f[1]] = f[0]
				frm += len(rows)
				if not rows or frm >= int(w[1]):
					break
			for name, key in KEYS.items():
				if listed.get(key) != name:
					raise failed("a: %s... is listed as %r, not %s" % (key[:40], listed.get(key),
					                                                    name))
				got = ask(sock, "add member cells0 " + name)
				if not got.startswith("ok"):
					raise failed("a: %s was not found by its name: %r" % (name, got))
			print("livecheck: a: through %d rounds, three contacts of one name cell and one of "
			      "its own kept their names, each found by it" % ROUNDS)
		except failed as e:
			print("livecheck: FAILED -- %s" % e, file=sys.stderr)
			return 1
		finally:
			if d:
				d.stop()
	print("livecheck: contacts sharing a name cell keep their own names")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
