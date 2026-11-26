#!/usr/bin/env python3
"""What a host keeps a copy of: `make livecheck`, sec 1473.

Two stores over loopback, one user's two machines: A its root, holding a
tune, its lyrics beside it, its music video and a photograph; B joined,
pulling from A.

    a  B set to keep music fetches the tune and its lyrics by itself, and
       neither the video nor the photograph -- a video does not follow the
       music unless the host says so
    b  set to keep music and video, B fetches the video too, and still not
       the photograph
    c  a setting naming no class, or one twice, is refused
    d  the photograph, which B does not keep, streamed from its playhead
       (sec 1474): fetched whole for the player, then, nothing reading it,
       let go -- and A's copy untouched
    e  streamed again and then asked for plainly, it is kept: a plain fetch
       is a host asking to keep a copy
    f  the tune, of a class B keeps, removed by hand is not fetched back
       (sec 1476), across rounds and restarts; asked for plainly, it is
    g  a second tune and its lyrics A never linked (sec 1478): B keeping
       music fetches both -- the lyrics by their name -- and links them on
       their arrival

Needs the faults build, `make fuzznetd-faults`: phase d shortens the idle
time a streamed copy is kept to two seconds (FZN_TEST_STREAM_IDLE_S).

BOUNDED FROM INSIDE as live_catalog.py is, whose daemon handling this
reuses: one deadline, the daemons in their own process groups, checked
gone.

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

live_trim.DEADLINE = time.monotonic() + 480.0
os.environ["FZN_TEST_STREAM_IDLE_S"] = "2"
PREKEY_HOST = slice(4, 68)
ROUNDS = 6


def main(argv):
	if len(argv) != 2:
		print("usage: live_keep.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 41000 + (os.getpid() % 400) * 2
	port = {"a": str(base), "b": str(base + 1)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		args = {"a": ["--udp-port=" + port["a"]],
		        "b": ["--udp-port=" + port["b"], "--root-at", "127.0.0.1", port["a"]]}
		started = {}

		def turn(who, tag):
			if who in started:
				started.pop(who).stop()
			started[who] = daemon(run, tag, dirs[who], socks[who], extra=args[who])
			started[who].wait_for(ROUND_DONE_RE, "%s's round" % who.upper())

		def until(check, what):
			for rnd in range(ROUNDS):
				if check():
					return
				for who in ("a", "b"):
					turn(who, "%s-%s%d" % (who, what, rnd))
			if not check():
				raise failed("%s: not after %d rounds" % (what, ROUNDS))

		def put(name, kind, data):
			path = os.path.join(scratch, name)
			with open(path, "wb") as fh:
				fh.write(data)
			reply = ask(socks["a"], "put file " + path)
			if not reply.startswith("ok "):
				raise failed("put file %s answered %r" % (name, reply))
			root = reply.split()[1][:64]
			expect(socks["a"], "put", "add catalog %s name %s" % (root, name), "ok")
			if kind:
				expect(socks["a"], "put", "add catalog %s kind %s" % (root, kind), "ok")
			return root

		def whole(who, root):
			return ask(socks[who], "get file %s check" % root).strip() == "ok intact"

		try:
			for who in port:
				os.mkdir(dirs[who])
			command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + dirs["b"], "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + dirs["a"], "--pair=" + prekey, "--delegable"],
			               None)
			command(run, ["--fuzznet-dir=" + dirs["b"], "--accept=" + card, "--join"], None)
			for who in ("a", "b"):
				turn(who, who + "0")
				expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who],
				       "ok")

			tune = put("tune.mp3", "audio/mpeg", os.urandom(6000))
			# g's: put and never read at A, so A never links them.
			song2 = put("other.ogg", "audio/ogg", os.urandom(5000))
			words2 = put("other.lrc", None, b"[00:02.00]another line\n")
			lyrics = put("tune.lrc", None, b"[00:01.00]a line to sing\n")
			film = put("tune.webm", "video/webm", os.urandom(9000))
			photo = put("photo.jpg", "image/jpeg", os.urandom(3000))
			reply = ask(socks["a"], "add tags " + tune)
			if not reply.startswith("ok "):
				raise failed("add tags answered %r" % reply)
			got = ask(socks["a"], "list catalog " + tune)
			if lyrics not in got or film not in got:
				raise failed("A did not link the tune's lyrics and video: %r" % got)

			# a: music kept, and only music.
			expect(socks["b"], "a", "set setting host library/keep music", "ok")
			until(lambda: whole("b", tune) and whole("b", lyrics), "a")
			if whole("b", film) or whole("b", photo):
				raise failed("a: B, keeping music, fetched the video or the photograph")
			print("livecheck: a: B keeping music fetched the tune and its lyrics, "
			      "and not the video nor the photograph")

			# b: video kept too.
			expect(socks["b"], "b", "set setting host library/keep music video", "ok")
			until(lambda: whole("b", film), "b")
			if whole("b", photo):
				raise failed("b: B, keeping music and video, fetched the photograph")
			print("livecheck: b: B keeping music and video fetched the video, and not the photograph")

			# c: what is no class refused.
			for bad in ("music bogus", "music music", "music  video", "music "):
				reply = ask(socks["b"], "set setting host library/keep " + bad)
				if reply.startswith("ok"):
					raise failed("c: library/keep %r was taken" % bad)
			print("livecheck: c: a setting naming no class, or one twice, refused")

			# d: streamed, not kept.
			expect(socks["b"], "d", "fetch file %s at 1000" % photo, "ok")
			until(lambda: whole("b", photo), "d-whole")
			time.sleep(3)
			until(lambda: not ask(socks["b"], "get file " + photo).startswith("ok "), "d-gone")
			if not whole("a", photo):
				raise failed("d: A's copy went with B's streamed one")
			print("livecheck: d: the photograph streamed to B, which does not keep it, "
			      "and let go once idle")

			# e: streamed, then asked for: kept.
			expect(socks["b"], "e", "fetch file %s at 0" % photo, "ok")
			expect(socks["b"], "e", "fetch file " + photo, "ok")
			until(lambda: whole("b", photo), "e-whole")
			time.sleep(3)
			for who in ("a", "b"):
				turn(who, who + "-e-idle")
			time.sleep(3)
			turn("b", "b-e-idle2")
			if not whole("b", photo):
				raise failed("e: a copy asked for after its stream was let go")
			print("livecheck: e: streamed and then asked for plainly, the photograph is kept")

			# f: let go by hand, not fetched back until asked for.
			expect(socks["b"], "f", "remove file " + tune, "ok")
			for rnd in range(2):
				for who in ("a", "b"):
					turn(who, "%s-f%d" % (who, rnd))
				time.sleep(6)
			if ask(socks["b"], "get file " + tune).startswith("ok "):
				raise failed("f: a tune let go by hand was fetched back")
			expect(socks["b"], "f", "fetch file " + tune, "ok")
			until(lambda: whole("b", tune), "f-again")
			print("livecheck: f: a kept tune let go by hand stayed gone, and came back when asked for")

			# g: linked where both arrived.
			until(lambda: whole("b", song2) and whole("b", words2)
			      and words2 in ask(socks["b"], "list catalog " + song2), "g")
			print("livecheck: g: a tune and its lyrics put apart were fetched by B and linked on arrival")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started.values():
				d.stop()
			for pid in run.started:
				if os.path.exists("/proc/%d" % pid):
					try:
						with open("/proc/%d/cmdline" % pid, "rb") as fh:
							alive = run.fuzznetd.encode() in fh.read()
						with open("/proc/%d/stat" % pid) as fh:
							alive = alive and int(fh.read().rsplit(")", 1)[1].split()[1]) == os.getpid()
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: each host kept what library/keep says, and nothing else")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
