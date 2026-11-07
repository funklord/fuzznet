#!/usr/bin/env python3
"""A session both ends speak in: `make livecheck`, sec 935.

R is a daemon with an extension, a store D paired to it by hand, and `device_sim`
holding D's image, straight on R's UDP port as a client on a host would, or through
a bridge over 51-byte units as a radio.

    a  D says something, no call: R's extension says it back, in the session
    b  R speaks first: `ring` says a word before it answers
    c  a rule says who may speak: `remote/permit/said none` keeps D out, and a rule
       of `member` lets it back
    d  over 51-byte units, through a bridge: R's word finds D on the radio
    e  R revokes D: what D says is heard no more

Against a host that takes a frame with no message for a call, a is answered
wrongly; against one that forgets where a peer was, b is `mute`.

BOUNDED FROM INSIDE as live_rejoin.py is: one deadline, each daemon in its own
process group, each device bounded by its own tries, and every process checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_device import on_the_air  # noqa: E402
from live_rejoin import command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402
from live_groups import PREKEY_HOST  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 150.0


def direct(run, image, port, name, args, presses=1):
	"""The device on R's port: its exit and what it said."""
	done = subprocess.run([run.sim, image, "udp:127.0.0.1:%s" % port, name, args, str(presses)],
	                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
	                      stderr=subprocess.PIPE, timeout=40.0)
	return done.returncode, done.stderr.decode(errors="replace")


def main(argv):
	if len(argv) != 4:
		print("usage: live_session.py PATH_TO_EXT_DAEMON PATH_TO_BRIDGE PATH_TO_DEVICE_SIM",
		      file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.bridge = os.path.abspath(argv[2])
	run.sim = os.path.abspath(argv[3])
	run.started = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {t: os.path.join(scratch, t) for t in "rd"}
		for path in dirs.values():
			os.mkdir(path)
		sock = os.path.join(sock_dir, "r")
		port = str(28300 + (os.getpid() % 300))
		r = None
		try:
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + dirs["d"], "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + dirs["r"], "--pair=" + prekey], None)
			gateway = command(run, ["--fuzznet-dir=" + dirs["d"], "--accept=" + card], None)
			image = command(run, ["--fuzznet-dir=" + dirs["d"], "--device-image=" + gateway], None)
			r = daemon(run, "r0", dirs["r"], sock, extra=["--udp-port=" + port])

			# a: said, and said back.
			code, said = direct(run, image, port, "-", "hello", presses=3)
			if code != 0 or said.count("heard 5 byte(s): hello") != 3:
				raise failed("a: said three times, the device said %r (%d)" % (said, code))
			print("livecheck: a: said three times over UDP, and said back each time")

			# b: R first.
			code, said = direct(run, image, port, "ring", "")
			if code != 0 or "heard 4 byte(s): ring" not in said or "rung" not in said:
				raise failed("b: asked to ring, the device said %r (%d)" % (said, code))
			print("livecheck: b: R spoke first, and then answered")

			# c: a rule.
			if not ask(sock, "set setting host remote/permit/said none").startswith("ok"):
				raise failed("c: remote/permit/said was refused")
			code, said = direct(run, image, port, "-", "hello")
			if code != 4 or "heard" in said:
				raise failed("c: kept out, the device said %r (%d)" % (said, code))
			if not ask(sock, "set setting host remote/permit/said member").startswith("ok"):
				raise failed("c: remote/permit/said was refused")
			code, said = direct(run, image, port, "-", "hello")
			if code != 0:
				raise failed("c: let in, the device said %r (%d)" % (said, code))
			print("livecheck: c: a rule kept D's word out, and let it back")

			# d: over the radio.
			code, said, _, _ = on_the_air(run, image, 51, 0.0, "ring", "", port)
			if code != 0 or "heard 4 byte(s): ring" not in said:
				raise failed("d: over a radio the device said %r (%d)" % (said, code))
			print("livecheck: d: R's word found D through a bridge, over 51-byte units")

			# e: revoked.
			reply = ask(sock, "revoke peer " + prekey[PREKEY_HOST])
			if not reply.startswith("ok"):
				raise failed("e: revoke peer answered %r" % reply)
			code, said = direct(run, image, port, "-", "hello")
			if code == 0 or "heard" in said:
				raise failed("e: revoked, the device said %r (%d)" % (said, code))
			print("livecheck: e: revoked, D is heard no more: %s" % said.strip()[:60])
		except failed as e:
			print("livecheck: FAILED: %s" % e, file=sys.stderr)
			return 1
		finally:
			if r:
				r.stop()
	print("livecheck: a session is spoken in from both ends")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
