#!/usr/bin/env python3
"""A share carries what the sharer's other host wrote: `make livecheck`, sec 884.

Three stores over loopback. S a root and S2 joined to it are one user's two
hosts; R is a contact of S's, in no estate of theirs.

    a  S shares a folder with R, and R lists what S put in it
    b  S2 writes a note into that folder: R comes to list it, a note S's
       user wrote on the other device, and S2 is nobody R has paired
    c  S2 writes another after the share is in use: it follows too

Against a daemon that serves a share of the sharing host's own writes alone,
phase b never lists the note.

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
from live_groups import PREKEY_HOST  # noqa: E402
import live_trim  # noqa: E402

DEADLINE_S = 420.0
REACH_S = 150.0


def main(argv):
	if len(argv) != 2:
		print("usage: live_share_sibling.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	live_trim.DEADLINE = time.monotonic() + DEADLINE_S
	base = 27100 + (os.getpid() % 300) * 3
	port = {"s": str(base), "s2": str(base + 1), "r": str(base + 2)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}

		def shared(folder):
			return ask(socks["r"], "list shared sam " + folder)

		def lists(folder, title, what):
			until = time.monotonic() + REACH_S
			while title not in shared(folder):
				if time.monotonic() > until:
					raise failed("%s: R lists %r" % (what, shared(folder)[:300]))
				time.sleep(1.0)

		try:
			for d in dirs.values():
				os.mkdir(d)
			for who in ("s", "r"):
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + dirs["s2"], "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + dirs["s"], "--pair=" + prekey, "--delegable"],
			               None)
			command(run, ["--fuzznet-dir=" + dirs["s2"], "--accept=" + card, "--join"], None)
			s_key = command(run, ["--fuzznet-dir=" + dirs["s"], "--prekey"], None)[PREKEY_HOST]
			r_prekey = command(run, ["--fuzznet-dir=" + dirs["r"], "--prekey"], None)
			r_key = r_prekey[PREKEY_HOST]
			started["s"] = daemon(run, "s", dirs["s"], socks["s"],
			                      extra=["--udp-port=" + port["s"]])
			started["s2"] = daemon(run, "s2", dirs["s2"], socks["s2"],
			                       extra=["--udp-port=" + port["s2"], "--root-at", "127.0.0.1",
			                              port["s"]])
			started["s2"].wait_for(ROUND_DONE_RE, "S2's first round", within=60.0)

			# a: THE SHARE.
			expect(socks["s"], "s", "add contact rory " + r_key, "ok")
			got = ask(socks["s"], "add folder top shared").split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("a: add folder answered %r" % got)
			folder = got[1]
			if not ask(socks["s"], "add note %s from-s" % folder).startswith("ok "):
				raise failed("a: add note refused")
			expect(socks["s"], "s", "add share %s rory" % folder, "ok")
			card = ask(socks["s"], "grant share rory " + r_prekey)
			if not card.startswith("ok "):
				raise failed("a: grant share answered %r" % card)
			card_path = os.path.join(scratch, "card")
			with open(card_path, "w") as f:
				f.write(card.split(" ", 1)[1])
			started["r"] = daemon(run, "r", dirs["r"], socks["r"],
			                      extra=["--udp-port=" + port["r"]])
			expect(socks["r"], "r", "add contact sam " + s_key, "ok")
			expect(socks["r"], "r", "add received sam 127.0.0.1 %s %s" % (port["s"], card_path),
			       "ok")
			lists(folder, "from-s", "a")
			print("livecheck: a: R lists what S put in the folder it shared")

			# b: FROM THE OTHER HOST.
			until = time.monotonic() + 90.0
			while folder not in ask(socks["s2"], "list note top"):
				if time.monotonic() > until:
					raise failed("b: the folder never reached S2")
				time.sleep(1.0)
			if not ask(socks["s2"], "add note %s from-s2" % folder).startswith("ok "):
				raise failed("b: S2's add note was refused")
			lists(folder, "from-s2", "b")
			print("livecheck: b: R lists a note S2 wrote into the folder S shared")

			# c: AND IT GOES ON.
			if not ask(socks["s2"], "add note %s later-from-s2" % folder).startswith("ok "):
				raise failed("c: S2's second add note was refused")
			lists(folder, "later-from-s2", "c")
			print("livecheck: c: and the next one S2 wrote followed it")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started.values():
				d.stop()
	print("livecheck: a share carried what the sharer's other host wrote")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
