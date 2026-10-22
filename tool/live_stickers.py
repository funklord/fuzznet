#!/usr/bin/env python3
"""A user's stickers on a node: `make livecheck`, sec 681.

One store, one daemon, a spec and its art in scratch.

    a  `put sticker SPEC` builds the pack from the spec and the files
       beside it, puts it, and saves it: `list sticker` names it, held, in
       the estate's settings
    b  `list sticker ROOT` lists its stickers; `get sticker ROOT ID` answers
       the reference a message carries, `fzn:sticker/...`; `get sticker ROOT
       ID ROLE PATH` writes the rendition asked for, or the nearest, and its
       bytes are the art's
    c  a spec naming a file above it, and one repeating a description, are
       refused, and nothing is saved by either
    d  `remove sticker ROOT` forgets the pack and keeps its bytes: listed no
       more, and still answered through its whole reference
    e  a pack of thirty stickers, past one reply, read a page at a time
       (`list sticker PACK FROM`, sec 684), gives each sticker once

Against a daemon with no sticker verbs, phase a is `unsupported`.

BOUNDED FROM INSIDE: one deadline; the daemon in its own process group,
stopped by SIGTERM then SIGKILL.

Exit 0 on a pass, 1 on a failure.
"""

import os
import signal
import socket
import subprocess
import sys
import tempfile
import time

DEADLINE_S = 120.0


class failed(Exception):
	pass


def ask(sock, line, within=20.0):
	until = time.monotonic() + within
	while True:
		try:
			c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			c.settimeout(20.0)
			c.connect(sock)
			c.sendall(line.encode() + b"\n")
			reply = b""
			while not reply.endswith(b"\n"):
				got = c.recv(65536)
				if not got:
					break
				reply += got
			c.close()
			return reply.decode(errors="replace").strip()
		except OSError:
			if time.monotonic() > until:
				raise failed("%s never answered %r" % (sock, line))
			time.sleep(0.2)


SPEC = """# two cats
name cats and their moods
sticker 1 static
description a ginger cat waving hello
keyword wave
inline png 128 128 art/wave.png
thumb png 64 64 art/wave-thumb.png
sticker 2 animated sound
description the same cat spinning very fast
main lottie 320 320 art/spin.json
sound art/spin.ogg
"""


def main(argv):
	if len(argv) != 2:
		print("usage: live_stickers.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2
	fuzznetd = os.path.abspath(argv[1])
	deadline = time.monotonic() + DEADLINE_S
	proc = None
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzk.", dir="/tmp") as sock_dir:
		store = os.path.join(scratch, "store")
		os.mkdir(store)
		packdir = os.path.join(scratch, "pack")
		os.makedirs(os.path.join(packdir, "art"))
		art = {"art/wave.png": os.urandom(700), "art/wave-thumb.png": os.urandom(90),
		       "art/spin.json": b'{"v":"5.7.0","layers":[]}', "art/spin.ogg": os.urandom(300)}
		for name, data in art.items():
			with open(os.path.join(packdir, name), "wb") as f:
				f.write(data)
		spec = os.path.join(packdir, "cats.spec")
		with open(spec, "w") as f:
			f.write(SPEC)
		sock = os.path.join(sock_dir, "s")
		log = open(os.path.join(scratch, "daemon.err"), "w")
		try:
			# A LOG DIRECTORY OF ITS OWN: told none, the daemon logs into the
			# user's own `~/.local/state/fuzznet/log`.
			proc = subprocess.Popen([fuzznetd, "--socket=" + sock, "--fuzznet-dir=" + store,
			                         "--log-dir=" + os.path.join(scratch, "log"),
			                         "--fuzznet-service=1", "--fuzznet-product=1"],
			                        stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
			got = ask(sock, "put sticker " + spec).split()
			if len(got) != 2 or got[0] != "ok" or len(got[1]) != 64:
				raise failed("a: put sticker answered %r" % got)
			root = got[1]
			listed = ask(sock, "list sticker").split()
			rows = [r.split(",") for r in listed[3:]]
			if listed[:3] != ["ok", "1", "0"] or len(rows) != 1 or rows[0][0] != root \
			   or rows[0][2] != "cats%20and%20their%20moods" or rows[0][3:] != ["1", "estate"]:
				raise failed("a: list sticker answered %r" % listed)
			print("livecheck: a: the pack was built from its spec, put, and saved to the "
			      "estate")

			got = ask(sock, "list sticker " + root).split()
			if got[:3] != ["ok", "2", "0"] or got[3] != "1,1,0,a%20ginger%20cat%20waving%20hello" \
			   or got[4] != "2,2,1,the%20same%20cat%20spinning%20very%20fast":
				raise failed("b: list sticker ROOT answered %r" % got)
			ref = ask(sock, "get sticker %s 1" % root)
			if not ref.startswith("ok fzn:sticker/" + root + "/") \
			   or not ref.endswith("/1 a ginger cat waving hello"):
				raise failed("b: get sticker ROOT 1 answered %r" % ref)
			out = os.path.join(scratch, "thumb.out")
			got = ask(sock, "get sticker %s 1 thumb %s" % (root, out))
			if got != "ok 4 64 64":
				raise failed("b: the thumb was answered %r" % got)
			with open(out, "rb") as f:
				if f.read() != art["art/wave-thumb.png"]:
					raise failed("b: the thumb written is not the thumb's art")
			out2 = os.path.join(scratch, "popup.out")
			got = ask(sock, "get sticker %s 2 popup %s" % (root, out2))
			with open(out2, "rb") as f:
				if got != "ok 1 320 320" or f.read() != art["art/spin.json"]:
					raise failed("b: a role the sticker lacks did not give the nearest: %r"
					             % got)
			print("livecheck: b: its stickers listed, a reference answered, and each "
			      "rendition written as its art")

			bad = os.path.join(packdir, "bad.spec")
			with open(bad, "w") as f:
				f.write("name x\nsticker 1 static\ndescription y\nmain png 1 1 ../escape.png\n")
			got = ask(sock, "put sticker " + bad)
			if not got.startswith("malformed the spec: line 4"):
				raise failed("c: a path above the spec was answered %r" % got)
			with open(bad, "w") as f:
				f.write("name x\nsticker 1 static\ndescription same\nmain png 1 1 art/wave.png\n"
				        "sticker 2 static\ndescription same\nmain png 1 1 art/wave.png\n")
			got = ask(sock, "put sticker " + bad)
			if not got.startswith("malformed the pack would not build"):
				raise failed("c: a repeated description was answered %r" % got)
			if ask(sock, "list sticker").split()[:3] != ["ok", "1", "0"]:
				raise failed("c: a refused spec saved something")
			print("livecheck: c: a path above the spec and a repeated description were "
			      "refused, nothing saved")

			whole = ref.split("/")
			pack_ref = whole[1] + whole[2] + "%016x" % int(whole[3])
			if ask(sock, "remove sticker " + root) != "ok":
				raise failed("d: remove sticker was refused")
			if ask(sock, "list sticker") != "ok 0 0":
				raise failed("d: a forgotten pack is still listed")
			got = ask(sock, "list sticker " + pack_ref).split()
			if got[:3] != ["ok", "2", "0"]:
				raise failed("d: a forgotten pack's bytes are gone: %r" % got)
			print("livecheck: d: the pack forgotten, and its bytes kept")

			# e: A PACK PAST ONE REPLY, sec 684: thirty stickers with long
			# descriptions, read a page at a time, each sticker once.
			big = os.path.join(packdir, "big.spec")
			with open(big, "w") as f:
				f.write("name thirty cats\n")
				for i in range(1, 31):
					f.write("sticker %d static\ndescription cat number %d, with a "
					        "description long enough to fill a row\n"
					        "inline png 8 8 art/wave.png\n" % (i, i))
			got = ask(sock, "put sticker " + big).split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("e: the thirty-sticker pack answered %r" % got)
			seen, start, pages = [], 0, 0
			while True:
				page = ask(sock, "list sticker %s %d" % (got[1], start))
				words = page.split()
				if words[:3] != ["ok", "30", str(start)] or len(page) > 1024:
					raise failed("e: a page from %d answered %r" % (start, page[:120]))
				rows = words[3:]
				if not rows:
					break
				seen += [int(r.split(",")[0]) for r in rows]
				start += len(rows)
				pages += 1
			if seen != list(range(1, 31)) or pages < 2:
				raise failed("e: the pages gave %r over %d page(s)" % (seen, pages))
			print("livecheck: e: a pack past one reply was read in %d pages, each sticker once"
			      % pages)
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		finally:
			if proc is not None and proc.poll() is None:
				os.killpg(proc.pid, signal.SIGTERM)
				try:
					proc.wait(timeout=10)
				except subprocess.TimeoutExpired:
					os.killpg(proc.pid, signal.SIGKILL)
					proc.wait(timeout=10)
			log.close()
		if time.monotonic() > deadline:
			print("livecheck: FAILED -- past the deadline")
			return 1
	print("livecheck: a user's stickers were built, saved, listed, drawn and forgotten")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
