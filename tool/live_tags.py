#!/usr/bin/env python3
"""What a stored file says of itself, catalogued: `make livecheck`, sec 1447.

One store, a root serving. The fixtures media/test/fixture/ holds, put into
its files as a library does it:

    a  `add tags ROOT` for the ID3v2.3 song reads its tag where the bytes are
       and asserts it as this host's: `list catalog ROOT` names its title in
       UTF-16 past Latin-1, its artist, album, track, year and duration
    b  asked again, nothing new is asserted -- the catalogue is not made to
       grow by asking twice
    c  `add tags from N` reads the held files a page at a time: the photo's
       `taken`, `camera` and `place`, and the FLAC file's title and
       duration, are listed after the pages are walked to the end, and no
       copy of a file's head is left in the store
    d  a root this store does not hold is refused, and so is a FROM past the
       last file
    e  a file of no format read asserts nothing and is no failure
    f  the same asked in binary, as the typed client does: one file's
       reading answered by a tags_done naming what it asserted, and a page
       from the start, every file read already, asserting nothing
    g  the music and photo catalogues listed: the two songs by their titles,
       the two photographs with EXIF, and not the JPEG that says nothing
    h  an M4A with its movie box after the media, read by its boxes' sizes

Against a daemon without the verb, phase a reads `malformed`; against one
that asserts what it read again each time, phase b counts it.

BOUNDED FROM INSIDE as live_catalog.py is, whose daemon handling this
reuses: one deadline, the daemon in its own process group, checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import subprocess
import sys
import tempfile
import time
import urllib.parse

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
from live_rpc import binary  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 120.0
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "media", "test", "fixture")


def main(argv):
	if len(argv) != 2:
		print("usage: live_tags.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port = str(40000 + (os.getpid() % 500) * 2)
	started = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		store = os.path.join(scratch, "a")
		sock = os.path.join(sock_dir, "a")

		def put(name):
			reply = ask(sock, "put file " + os.path.join(FIXTURE, name))
			if not reply.startswith("ok "):
				raise failed("put file %s answered %r" % (name, reply))
			root = reply.split()[1][:64]
			expect(sock, "put", "add catalog %s name %s" % (root, name), "ok")
			return root

		def listed(root):
			"""`root`'s catalogue as {name: value}, values unescaped."""
			reply = ask(sock, "list catalog " + root).split()
			if not reply or reply[0] != "ok":
				raise failed("list catalog answered %r" % reply)
			out = {}
			for row in reply[3:]:
				_, name, value, _ = row.split(",")
				out[name] = urllib.parse.unquote(value)
			return out

		def tags(word):
			reply = ask(sock, "add tags " + word)
			if not reply.startswith("ok "):
				raise failed("add tags %s answered %r" % (word, reply))
			return [int(w) for w in reply.split()[1:]]

		try:
			os.mkdir(store)
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)
			started.append(daemon(run, "a", store, sock, extra=["--udp-port=" + port]))
			started[0].wait_for(ROUND_DONE_RE, "A's round")

			# a: one file, read and asserted.
			song = put("v23.mp3")
			n = tags(song)[0]
			got = listed(song)
			want = {"title": "Förlåt — 夜", "artist": "Björk", "track": "7", "year": "1997",
			        "duration": "250", "name": "v23.mp3"}
			if n < 6 or any(got.get(k) != v for k, v in want.items()) \
			   or not got.get("album", "").startswith("Homogenic"):
				raise failed("a: %d asserted, and the song lists %r" % (n, got))
			print("livecheck: a: the song's ID3v2.3 tag read where its bytes are, %d names" % n)

			# b: again, nothing new.
			if tags(song) != [0]:
				raise failed("b: asking again asserted more")
			print("livecheck: b: asked again, nothing new asserted")

			# c: the rest a page at a time.
			photo, flac, plain = put("photo.jpg"), put("song.flac"), put("plain.jpg")
			at, total, pages = 0, None, 0
			while True:
				at, total, _ = tags("from %d" % at)
				pages += 1
				if at >= total or pages > 10:
					break
			p, f, q = listed(photo), listed(flac), listed(plain)
			if p.get("taken") != "2023-07-14T21:45:30" or p.get("camera") != "Canon EOS 5D Mark IV" \
			   or p.get("place") != "67.8560000,20.2250000" or f.get("title") != "Waltz for Debby" \
			   or f.get("duration") != "250" or q.get("width") != "17" or total != 4:
				raise failed("c: after %d page(s) of %r: photo %r, flac %r, plain %r"
				             % (pages, total, p, f, q))
			# THE PLAINTEXT OPENED TO READ IT IS GONE: no scratch copy of a
			# file's head is left in the store.
			left = [os.path.join(d, n) for d, _, ns in os.walk(store) for n in ns if n.startswith(".tags-")]
			if left:
				raise failed("c: the heads read were left behind: %r" % left)
			print("livecheck: c: %d held files read a page at a time: a photo's time, camera "
			      "and place, a FLAC's title and length" % total)

			# d: refusals.
			reply = ask(sock, "add tags " + "ab" * 32)
			if not reply.startswith("error"):
				raise failed("d: a root not held answered %r" % reply)
			reply = ask(sock, "add tags from 99")
			if not reply.startswith("malformed"):
				raise failed("d: a FROM past the last file answered %r" % reply)
			print("livecheck: d: a root not held, and a FROM past the end, refused")

			# e: nothing to read.
			other = os.path.join(scratch, "notes.txt")
			with open(other, "w") as fh:
				fh.write("plain words, no tags\n")
			reply = ask(sock, "put file " + other)
			if not reply.startswith("ok ") or tags(reply.split()[1][:64]) != [0]:
				raise failed("e: a text file answered %r" % reply)
			print("livecheck: e: a file of no format read asserted nothing")

			# f: the same in binary, as the typed client asks it (FZN_CMD_FILES 1,
			# `tags` 138 and `tags_page` 139): a tags_done (140), then a STATUS
			# ok -- one file's asserting four names, and a page from the start.
			photo_le = put("photo_le.jpg")
			got = binary(sock, bytes([1, 138]) + bytes.fromhex(photo_le))
			if len(got) != 2 or got[0][:2] != bytes([1, 140]) or got[1][:2] != bytes([0x13, 0]) \
			   or int.from_bytes(got[0][10:14], "big") < 4:
				raise failed("f: tags in binary answered %r" % got)
			got = binary(sock, bytes([1, 139, 0, 0, 0, 0]))
			if len(got) != 2 or got[0][:2] != bytes([1, 140]) \
			   or int.from_bytes(got[0][2:6], "big") != int.from_bytes(got[0][6:10], "big") \
			   or int.from_bytes(got[0][10:14], "big") != 0:
				raise failed("f: a page in binary answered %r" % got)
			if listed(photo_le).get("place") != "-33.8650000,-70.6500000":
				raise failed("f: the photo read in binary lists %r" % listed(photo_le))
			print("livecheck: f: the same asked in binary, a file and a page")

			# g: the catalogues (`music` 141, `photos` 143): a row each (142, 144),
			# then a STATUS ok. The two songs are music by what they say; the
			# photographs with EXIF are photographs by theirs; the JPEG with
			# none, catalogued with no kind, is neither.
			got = binary(sock, bytes([1, 141]))
			titles = sorted(m[2 + 32 + 8 + 2 + 1 + 10 + 1:2 + 32 + 8 + 2 + 1 + 10 + 1 + m[2 + 32 + 8 + 2 + 1 + 10]]
			                .decode() for m in got[:-1] if m[:2] == bytes([1, 142]))
			if got[-1][:2] != bytes([0x13, 0]) or titles != ["Förlåt — 夜", "Waltz for Debby"]:
				raise failed("g: the music listed %r" % titles)
			got = binary(sock, bytes([1, 143]))
			roots = sorted(m[2:34].hex() for m in got[:-1] if m[:2] == bytes([1, 144]))
			if got[-1][:2] != bytes([0x13, 0]) or roots != sorted([photo, photo_le]):
				raise failed("g: the photographs listed %r" % roots)
			print("livecheck: g: two pieces of music and two photographs listed, by what they say")

			# h: an M4A whose movie box stands after its media, read box by box
			# where the sizes put them (sec 1452).
			m4a = put("song.m4a")
			if tags(m4a)[0] < 8 or listed(m4a).get("title") != "Midnight Sun" \
			   or listed(m4a).get("track") != "2/9" or listed(m4a).get("duration") != "250":
				raise failed("h: the M4A lists %r" % listed(m4a))
			print("livecheck: h: an M4A's items read past its media, as the node holds it")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started:
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
	print("livecheck: what stored files say of themselves was catalogued")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
