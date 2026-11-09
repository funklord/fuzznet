#!/usr/bin/env python3
"""More files wanted than a turn once held: sec 965.

Two stores over loopback: R a root, and M a member joined to it, pulling
from R (`--root-at`). R puts FILES small files; M asks to fetch every one
by its reference, and comes to hold each whole.

Against a daemon whose fetch held the wanted files in room for 64, the
turn read roots and lengths past it once more than 64 were wanted:
undefined behaviour that a sanitized daemon (`make SANITIZE=1`) reports,
and an ordinary one may survive, its garbage asks refused.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon, expect, free_slot  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 400.0

FILES = 70
WHOLE_S = 240.0


def answering(sock, who):
	"""Until `who` answers `status`, a sanitized daemon being slow to start."""
	until = time.monotonic() + 60.0
	while True:
		try:
			if ask(sock, "status").startswith("ok "):
				return
		except OSError:
			pass
		if time.monotonic() > until:
			raise failed("%s: not answering" % who)
		time.sleep(0.2)


def main(argv):
	if len(argv) != 2:
		print("usage: live_files_many.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = free_slot(38000, 4, 400, 2)
	port = {"r": base, "m": base + 1}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}
		try:
			for d in dirs.values():
				os.mkdir(d)
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + dirs["m"], "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + dirs["r"], "--pair=" + prekey,
			                     "--delegable"], None)
			command(run, ["--fuzznet-dir=" + dirs["m"], "--accept=" + card, "--join"], None)
			started["r"] = daemon(run, "r", dirs["r"], socks["r"],
			                      extra=["--udp-port=%d" % port["r"]])
			answering(socks["r"], "r")
			refs = []
			for i in range(FILES):
				path = os.path.join(scratch, "f%03d" % i)
				with open(path, "wb") as f:
					f.write(os.urandom(2000 + i))
				reply = ask(socks["r"], "put file " + path)
				if not reply.startswith("ok "):
					raise failed("r: put file answered %r" % reply)
				refs.append(reply.split()[1])
			started["m"] = daemon(run, "m", dirs["m"], socks["m"],
			                      extra=["--udp-port=%d" % port["m"],
			                             "--root-at", "127.0.0.1", str(port["r"])])
			answering(socks["m"], "m")
			for ref in refs:
				expect(socks["m"], "m", "fetch file " + ref, "ok")
			began = time.monotonic()
			left = [r[:64] for r in refs]
			while left:
				left = [r for r in left
				        if ask(socks["m"], "get file " + r).split()[4:5] != ["whole"]]
				if not started["m"].proc.poll() is None:
					raise failed("m: the daemon exited, %d file(s) not whole" % len(left))
				if left and time.monotonic() - began > WHOLE_S:
					raise failed("m: %d of %d file(s) not whole after %.0f s"
					             % (len(left), FILES, WHOLE_S))
				time.sleep(1.0)
			print("livecheck: M took all %d files whole in %.0f s"
			      % (FILES, time.monotonic() - began))

			# A STICKER PACK OF HUNDREDS, sec 978: 500 stickers, each its own
			# art, a spec past 64 KiB, which `put sticker` once refused.
			pack = os.path.join(scratch, "pack")
			os.makedirs(os.path.join(pack, "art"))
			with open(os.path.join(pack, "big.spec"), "w") as spec:
				spec.write("name big\n")
				for i in range(1, 501):
					with open(os.path.join(pack, "art", "a%d.png" % i), "wb") as f:
						f.write(os.urandom(64))
					spec.write("sticker %d static\ndescription a sticker of a pack of "
					           "hundreds, number %d, described as a person would\n"
					           "inline png 128 128 art/a%d.png\n" % (i, i, i))
			spec_len = os.path.getsize(os.path.join(pack, "big.spec"))
			got = ask(socks["r"], "put sticker " + os.path.join(pack, "big.spec"))
			if spec_len <= 64 * 1024 or not got.startswith("ok "):
				raise failed("a spec of 500 stickers, %d bytes, answered %r" % (spec_len, got))
			print("livecheck: a pack of 500 stickers, its spec %d bytes, was put" % spec_len)
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			for name in sorted(os.listdir(scratch)):
				if name.endswith(".err"):
					with open(os.path.join(scratch, name), errors="replace") as f:
						tail = f.read().splitlines()[-25:]
					print("livecheck: --- %s" % name)
					for line in tail:
						print("livecheck:     %s" % line)
			return 1
		finally:
			for d in started.values():
				d.stop()
	print("livecheck: more than 64 files wanted were all fetched")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
