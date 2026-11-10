#!/usr/bin/env python3
"""A friend's shared folder of files, browsed and fetched: sec 1000.

Two stores over loopback, S sharing and R a contact, neither in the other's
estate. S puts a file and an attachment naming it in a folder, `films`, and
shares the folder with R.

    a  R browses: `list shared sam top` names the folder, the folder lists the
       attachment by its title, and `get shared ... ref` answers the file's
       reference
    b  R fetches the file by that reference -- from S, which serves it because
       the share reaches its attachment -- and exports the same bytes
    c  S takes the share back: R, the file removed, fetches it again and is
       given nothing

Against a daemon that serves a file only by its own share rows (sec 493), b
never brings the file; against one that keeps serving after the folder is
unshared, c brings it again.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import filecmp
import os
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_groups import PREKEY_HOST  # noqa: E402
from live_rejoin import command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 400.0

WAIT = 120.0
GONE_S = 30.0
SIZE = 600 * 1024


def until(what, test, wait=WAIT):
	limit = time.monotonic() + wait
	while True:
		got = test()
		if got:
			return got
		if time.monotonic() > limit:
			raise failed("%s, after %.0f s" % (what, wait))
		time.sleep(0.5)


def main(argv):
	if len(argv) != 2:
		print("usage: live_browse.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port_s = str(26500 + os.getpid() % 1500)
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in ("s", "r")}
		socks = {k: os.path.join(sock_dir, k) for k in ("s", "r")}
		for d in dirs.values():
			os.mkdir(d)
		s = r = None
		try:
			for who in ("s", "r"):
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
			s_key = command(run, ["--fuzznet-dir=" + dirs["s"], "--prekey"], None)[PREKEY_HOST]
			r_prekey = command(run, ["--fuzznet-dir=" + dirs["r"], "--prekey"], None)
			r_key = r_prekey[PREKEY_HOST]

			# S: A FILE, IN A FOLDER, SHARED WITH R.
			s = daemon(run, "s", dirs["s"], socks["s"], extra=["--udp-port=" + port_s])
			src = os.path.join(scratch, "film.mkv")
			with open(src, "wb") as f:
				f.write(os.urandom(SIZE))
			put = ask(socks["s"], "put file " + src).split()
			if len(put) < 2 or put[0] != "ok":
				raise failed("s: put file answered %r" % put)
			ref = put[1]
			folder = ask(socks["s"], "add folder top films").split()
			if len(folder) != 2 or folder[0] != "ok":
				raise failed("s: add folder answered %r" % folder)
			attached = ask(socks["s"], "add attachment %s %s film.mkv" % (folder[1], ref)).split()
			if len(attached) != 2 or attached[0] != "ok":
				raise failed("s: add attachment answered %r" % attached)
			expect(socks["s"], "s", "add contact rory " + r_key, "ok")
			expect(socks["s"], "s", "add share %s rory" % folder[1], "ok")
			card = ask(socks["s"], "grant share rory " + r_prekey)
			if not card.startswith("ok "):
				raise failed("s: grant share answered %r" % card)
			card_path = os.path.join(scratch, "card")
			with open(card_path, "w") as f:
				f.write(card.split(" ", 1)[1])

			# a: R BROWSES S'S FOLDER.
			r = daemon(run, "r", dirs["r"], socks["r"])
			expect(socks["r"], "r", "add contact sam " + s_key, "ok")
			expect(socks["r"], "r", "add received sam 127.0.0.1 %s %s" % (port_s, card_path), "ok")
			until("a: R never listed S's folder",
			      lambda: folder[1] in ask(socks["r"], "list shared sam top"))
			row = until("a: R's listing of the folder never named the film",
			            lambda: [w for w in ask(socks["r"], "list shared sam " + folder[1]).split()
			                     if w.startswith(attached[1]) and "film.mkv" in w])
			print("livecheck: a: R lists S's folder and the film in it: %s" % row[0][:90])
			got = until("a: R never read the film's reference",
			            lambda: (lambda g: g if g.startswith("ok ") else None)(
			                    ask(socks["r"], "get shared sam %s ref" % attached[1])))
			if got.split()[1] != ref:
				raise failed("a: R read the reference %r, not S's" % got[:40])
			print("livecheck: a: and reads its reference")

			# b: R FETCHES IT FROM S, served by the share reaching the attachment.
			expect(socks["r"], "r", "fetch file " + ref, "ok")
			began = time.monotonic()
			until("b: R never held the film whole",
			      lambda: ask(socks["r"], "get file " + ref[:64]).split()[4:5] == ["whole"])
			out = os.path.join(scratch, "out.mkv")
			expect(socks["r"], "r", "get file %s %s" % (ref, out), "ok")
			if not filecmp.cmp(src, out, shallow=False):
				raise failed("b: the film R exported is not the one S put")
			print("livecheck: b: R fetched the film from S in %.1f s, the same bytes"
			      % (time.monotonic() - began))

			# c: UNSHARED, and the file given no more.
			expect(socks["s"], "s", "remove share %s rory" % folder[1], "ok")
			expect(socks["r"], "r", "remove file " + ref[:64], "ok")
			expect(socks["r"], "r", "fetch file " + ref, "ok")
			limit = time.monotonic() + GONE_S
			while time.monotonic() < limit:
				words = ask(socks["r"], "get file " + ref[:64]).split()
				if words[4:5] == ["whole"] or (len(words) > 1 and words[1] != "0"):
					raise failed("c: unshared, R was given the film again: %r" % words)
				time.sleep(1.0)
			print("livecheck: c: the folder unshared, R was given nothing of the film in %.0f s"
			      % GONE_S)
		except failed as e:
			print("livecheck: FAILED: %s" % e, file=sys.stderr)
			return 1
		finally:
			for d in (r, s):
				if d:
					d.stop()
	print("livecheck: a friend's shared folder of files is browsed and fetched")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
