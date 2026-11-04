#!/usr/bin/env python3
"""A user's stickers on a node: `make livecheck`, sec 681.

One store, one daemon, a spec and its art in scratch.

    a  `put sticker SPEC` builds the pack from the spec and the files
       beside it, puts it, and saves it: `list sticker` names it, held, in
       the estate's settings
    b  `list sticker ROOT` lists its stickers; `get sticker ROOT ID` answers
       the reference a message carries, `fzn:sticker/...`, and `get sticker
       ROOT ID text WORDS` one carrying a message sticker's words, refused
       for a sticker with no text box (sec 830); `get sticker ROOT ID ROLE
       PATH` writes the rendition asked for, or the nearest, and its bytes
       are the art's
    c  a spec naming a file above it, and one whose two stickers take one id
       from one art, are refused, and nothing is saved by either
    d  `remove sticker ROOT` forgets the pack and keeps its bytes: listed no
       more, and still answered through its whole reference
    e  a pack of seventy stickers, past one reply and past version 1's cap
       of 64, read a page at a time (`list sticker PACK FROM`, secs 684,
       702), gives each sticker once
    f  a sticker given no id takes the first 8 bytes of BLAKE2b-256 over its
       renditions and then its sound, as fuzzypickles derives it (sec 702),
       checked against Python's hashlib; one with no description has a
       reference ending at its id, and a pack with no name is saved

Against a daemon with no sticker verbs, phase a is `unsupported`.

BOUNDED FROM INSIDE: one deadline; the daemon in its own process group,
stopped by SIGTERM then SIGKILL.

Exit 0 on a pass, 1 on a failure.
"""

import hashlib
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
sticker 3 message
description a sign the sender writes on
text 20 8 8 112 40 FFFFFFC0 000000FF 5
inline png 128 128 art/wave.png
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
			# A SPEC NAMING ART THAT IS NOT THERE is refused in words, and the
			# node goes on: it answered from memory it had just freed, which a
			# sanitized build dies on (fuzzypickles, inbox 2026-11-04).
			missing = os.path.join(packdir, "missing.spec")
			with open(spec) as f, open(missing, "w") as g:
				g.write(f.read().replace("art/wave.png", "art/gone.png"))
			refused = ask(sock, "put sticker " + missing)
			if not refused.startswith("error ") or "would not read beside the spec" not in refused:
				raise failed("a: a spec naming no art answered %r" % refused)
			if not ask(sock, "status").startswith("ok "):
				raise failed("a: the node did not answer after a refused spec")
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
			# EACH ROW GIVES ITS BOX'S LIMIT, sec 841 -- sticker 3's is 20 --
			# THEN THE BOX, sec 864: X Y W H, fill, ink, turn, and the main
			# rendition's size (the nearest, where a sticker has no main).
			if got[:3] != ["ok", "3", "0"] \
			   or got[3] != "1,1,0,a%20ginger%20cat%20waving%20hello,0,0,0,0,0,00000000," \
			                "00000000,0,128,128" \
			   or got[4] != "2,2,1,the%20same%20cat%20spinning%20very%20fast,0,0,0,0,0," \
			                "00000000,00000000,0,320,320" \
			   or not got[5].startswith("3,5,0,") \
			   or not got[5].endswith(",20,8,8,112,40,FFFFFFC0,000000FF,5,128,128"):
				raise failed("b: list sticker ROOT answered %r" % got)
			ref = ask(sock, "get sticker %s 1" % root)
			if not ref.startswith("ok fzn:sticker/" + root + "/") \
			   or not ref.endswith("/1 a ginger cat waving hello"):
				raise failed("b: get sticker ROOT 1 answered %r" % ref)
			out = os.path.join(scratch, "thumb.out")
			# THE SENDER'S WORDS, sec 830: carried in the reference, escaped as
			# fuzzypickles escapes them; refused for a sticker with no text box.
			ref3 = ask(sock, "get sticker %s 3 text Hej%%20d%%C3%%A5" % root)
			if not ref3.startswith("ok fzn:sticker/" + root + "/") \
			   or not ref3.rstrip("\n").endswith("/3:Hej%20d%C3%A5 a sign the sender writes on"):
				raise failed("b: get sticker ROOT 3 text WORDS answered %r" % ref3)
			refused = ask(sock, "get sticker %s 1 text hi" % root)
			if not refused.startswith("error that sticker takes no words"):
				raise failed("b: words for a sticker with no text box were answered %r" % refused)
			# NO MORE THAN THE BOX HOLDS, in characters (sec 841): twenty
			# taken, twenty-one refused, each a two-byte character.
			if not ask(sock, "get sticker %s 3 text %s" % (root, "%C3%A5" * 20)).startswith("ok "):
				raise failed("b: twenty characters for a box of twenty were refused")
			refused = ask(sock, "get sticker %s 3 text %s" % (root, "%C3%A5" * 21))
			if refused != "malformed more than the sticker holds: 20 characters at most":
				raise failed("b: twenty-one characters for a box of twenty were answered %r"
				             % refused)
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
			# TWO STICKERS OF ONE ART, given no ids, take one id from it
			# (sec 702), and two of one id are no pack.
			with open(bad, "w") as f:
				f.write("name x\nsticker static\nmain png 1 1 art/wave.png\n"
				        "sticker static\nmain png 1 1 art/wave.png\n")
			got = ask(sock, "put sticker " + bad)
			if not got.startswith("malformed the pack would not build"):
				raise failed("c: two stickers of one art were answered %r" % got)
			if ask(sock, "list sticker").split()[:3] != ["ok", "1", "0"]:
				raise failed("c: a refused spec saved something")
			print("livecheck: c: a path above the spec and two stickers of one id were "
			      "refused, nothing saved")

			whole = ref.split("/")
			pack_ref = whole[1] + whole[2] + "%016x" % int(whole[3])
			if ask(sock, "remove sticker " + root) != "ok":
				raise failed("d: remove sticker was refused")
			if ask(sock, "list sticker") != "ok 0 0":
				raise failed("d: a forgotten pack is still listed")
			got = ask(sock, "list sticker " + pack_ref).split()
			if got[:3] != ["ok", "3", "0"]:
				raise failed("d: a forgotten pack's bytes are gone: %r" % got)
			print("livecheck: d: the pack forgotten, and its bytes kept")

			# e: A PACK PAST ONE REPLY, sec 684, and past version 1's cap of
			# 64 (sec 702): seventy stickers with long descriptions, read a
			# page at a time, each sticker once.
			big = os.path.join(packdir, "big.spec")
			with open(big, "w") as f:
				f.write("name seventy cats\n")
				for i in range(1, 71):
					f.write("sticker %d static\ndescription cat number %d, with a "
					        "description long enough to fill a row\n"
					        "inline png 8 8 art/wave.png\n" % (i, i))
			got = ask(sock, "put sticker " + big).split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("e: the seventy-sticker pack answered %r" % got)
			seen, start, pages = [], 0, 0
			while True:
				page = ask(sock, "list sticker %s %d" % (got[1], start))
				words = page.split()
				if words[:3] != ["ok", "70", str(start)] or len(page) > 1024:
					raise failed("e: a page from %d answered %r" % (start, page[:120]))
				rows = words[3:]
				if not rows:
					break
				seen += [int(r.split(",")[0]) for r in rows]
				start += len(rows)
				pages += 1
			if seen != list(range(1, 71)) or pages < 2:
				raise failed("e: the pages gave %r over %d page(s)" % (seen, pages))
			print("livecheck: e: a pack of seventy, past one reply, was read in %d pages, each "
			      "sticker once" % pages)

			# f: AN ID FROM THE ART, sec 702, against hashlib's BLAKE2b.
			derived = os.path.join(packdir, "derived.spec")
			with open(derived, "w") as f:
				f.write("sticker animated sound\nmain lottie 320 320 art/spin.json\n"
				        "inline png 128 128 art/wave.png\nsound art/spin.ogg\n")
			got = ask(sock, "put sticker " + derived).split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("f: a spec with no name and no id answered %r" % got)
			digest = hashlib.blake2b(art["art/spin.json"] + art["art/wave.png"]
			                         + art["art/spin.ogg"], digest_size=32).digest()
			want = int.from_bytes(digest[:8], "big") or 1
			rows = ask(sock, "list sticker " + got[1]).split()
			if rows[:3] != ["ok", "1", "0"] \
			   or rows[3] != "%d,2,1,,0,0,0,0,0,00000000,00000000,0,320,320" % want:
				raise failed("f: the derived id was listed %r, not %d" % (rows, want))
			ref = ask(sock, "get sticker %s %d" % (got[1], want))
			if not ref.startswith("ok fzn:sticker/") or not ref.endswith("/%d" % want):
				raise failed("f: a sticker with no description was referenced %r" % ref)
			# THE PACK'S OWN ID, sec 859: the stickers' digests summed as
			# 256-bit little-endian numbers, BLAKE2b over the sum -- here one
			# sticker, so the sum is its digest.
			total = int.from_bytes(digest, "little") % (1 << 256)
			pack_digest = hashlib.blake2b(total.to_bytes(32, "little"), digest_size=32).digest()
			pack_want = int.from_bytes(pack_digest[:8], "big") or 1
			got_id = ask(sock, "get sticker " + got[1])
			if got_id != "ok %d" % pack_want:
				raise failed("f: the pack's own id was %r, not %d" % (got_id, pack_want))
			# AND OF THE THREE CATS, a sum of three with carries: each
			# sticker's renditions in its order, then its sound.
			parts = [art["art/wave.png"] + art["art/wave-thumb.png"],
			         art["art/spin.json"] + art["art/spin.ogg"], art["art/wave.png"]]
			total = sum(int.from_bytes(hashlib.blake2b(p, digest_size=32).digest(), "little")
			            for p in parts) % (1 << 256)
			pack_digest = hashlib.blake2b(total.to_bytes(32, "little"), digest_size=32).digest()
			pack_want = int.from_bytes(pack_digest[:8], "big") or 1
			# PUT AGAIN, the pack having been forgotten above.
			again = ask(sock, "put sticker " + spec).split()
			if len(again) != 2 or again[0] != "ok":
				raise failed("f: the cats' pack put again answered %r" % again)
			got_id = ask(sock, "get sticker " + again[1])
			if got_id != "ok %d" % pack_want:
				raise failed("f: the cats' pack's own id was %r, not %d" % (got_id, pack_want))
			print("livecheck: f: a sticker given no id took its art's BLAKE2b, as hashlib "
			      "says, with no description its reference ends at the id, and a pack's "
			      "own id is the BLAKE2b of its stickers' digests summed")
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
