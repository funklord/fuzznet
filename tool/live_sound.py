#!/usr/bin/env python3
"""What a held tune sounds like, catalogued: `make livecheck`, sec 1457.

One store, a root serving, built with a decoder (FZN_MEDIA_DECODE). A tune
made here -- thirty seconds of a kick at 128 BPM, the first at 0.1 s, over an
A minor chord, written as a WAV -- is put into its files as a library does:

    a  `add sound ROOT` queues it, `ok 1 1`, and the host hears it in a
       process of its own: `list catalog ROOT` comes to name its `bpm`
       128.00, its first `beat` at 0.100 s, its `key` 8A Am, its `loudness`
       and `peak`, and `heard` 1 -- while the host goes on answering
    b  asked again, nothing is queued: a tune is heard once
    c  `add sound from 0` walks the held files: a photograph is no tune and
       is not queued; a file the catalogue calls `audio/` that holds no
       sound is heard, found to say nothing, and marked heard; and no copy of
       any file is left in the store
    d  a root this store does not hold is refused, and so is a FROM past the
       last file
    e  the same asked in binary, as the typed client does (FZN_CMD_FILES 1,
       `sound` 145, `sound_page` 146): a sound_done (147) naming nothing
       queued, every tune heard already, then a STATUS ok
    f  the music listed in binary (`music` 141), as a player reads its grid
       and level (sec 1462): the tune's row carries the tempo, first beat,
       key, loudness and peak its host heard

Against a daemon without the verb, phase a reads `malformed`; against one that
hears in its own loop rather than a child, the `get` asked while it hears
waits for it, which phase a times.

BOUNDED FROM INSIDE as live_tags.py is, whose daemon handling this reuses:
one deadline, the daemon in its own process group, checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import math
import os
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import wave

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
from live_rpc import binary  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 150.0
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "media", "test", "fixture")
RATE = 48000


def write_tune(path):
	"""Thirty seconds of a kick at 128 BPM from 0.1 s, over A minor's i iv v i,
	two seconds a chord, each note with its harmonics and a bass. The chords'
	eight seconds and one kick are made once and laid end to end, which keeps
	the making to a few seconds of Python."""
	period = 60.0 * RATE / 128
	chords = [(57, 60, 64), (62, 65, 69), (64, 67, 71), (57, 60, 64)]
	cycle = []
	for i in range(8 * RATE):
		t = i / RATE
		chord = chords[i // (2 * RATE)]
		v = 0.06 * math.sin(2 * math.pi * 440 * 2 ** ((chord[0] - 12 - 69) / 12) * t)
		for note in chord:
			hz = 440 * 2 ** ((note - 69) / 12)
			for h in (1, 2, 3, 4):
				v += 0.04 / h * math.sin(2 * math.pi * hz * h * t)
		cycle.append(v)
	kick = []
	for i in range(RATE // 4):
		s = i / RATE
		kick.append(0.6 * math.sin(2 * math.pi * 55 * s) * math.exp(-s / 0.09)
		            + (0.25 * math.sin(i * 2.3) if i < 96 else 0.0))
	sound = [cycle[i % len(cycle)] for i in range(30 * RATE)]
	at = 0.1 * RATE
	while at < len(sound):
		start = int(round(at))
		for i, v in enumerate(kick[:len(sound) - start]):
			sound[start + i] += v
		at += period
	frames = struct.pack("<%dh" % len(sound), *(max(-32767, min(32767, int(v * 32000))) for v in sound))
	with wave.open(path, "wb") as w:
		w.setnchannels(1)
		w.setsampwidth(2)
		w.setframerate(RATE)
		w.writeframes(frames)


def main(argv):
	if len(argv) != 2:
		print("usage: live_sound.py PATH_TO_FUZZNETD", file=sys.stderr)
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

		def put(path, kind):
			reply = ask(sock, "put file " + path)
			if not reply.startswith("ok "):
				raise failed("put file %s answered %r" % (path, reply))
			root = reply.split()[1][:64]
			expect(sock, "put", "add catalog %s kind %s" % (root, kind), "ok")
			return root

		def listed(root):
			"""`root`'s catalogue as {name: value}, values unescaped: `ok LIVE
			FROM ROWS...`, as many rows as a reply holds, so asked again from
			where it ended."""
			out, rows = {}, 0
			while True:
				reply = ask(sock, "list catalog %s %d" % (root, rows)).split()
				if len(reply) < 3 or reply[0] != "ok":
					raise failed("list catalog answered %r" % reply)
				for row in reply[3:]:
					_, name, value, _ = row.split(",")
					out[name] = urllib.parse.unquote(value)
				rows += len(reply) - 3
				if rows >= int(reply[1]) or len(reply) == 3:
					return out

		def heard(root, what):
			while time.monotonic() < live_trim.DEADLINE:
				got = listed(root)
				if got.get("heard") == "1":
					return got
				time.sleep(0.2)
			raise failed("%s: the tune was never heard; it lists %r" % (what, listed(root)))

		try:
			os.mkdir(store)
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)
			started.append(daemon(run, "a", store, sock, extra=["--udp-port=" + port]))
			started[0].wait_for(ROUND_DONE_RE, "A's round")

			# a: a tune heard, while the host answers.
			tune_path = os.path.join(scratch, "tune.wav")
			write_tune(tune_path)
			tune = put(tune_path, "audio/wav")
			reply = ask(sock, "add sound " + tune)
			if reply.startswith("error this host was built with no decoder"):
				print("livecheck: SKIP -- this fuzznetd was built with no decoder (FZN_MEDIA_DECODE=0)")
				return 0
			if reply.split() != ["ok", "1", "1"]:
				raise failed("a: add sound answered %r" % reply)
			began = time.monotonic()
			ask(sock, "get file " + tune)
			answered = time.monotonic() - began
			got = heard(tune, "a")
			if abs(float(got.get("bpm", "0")) - 128.0) > 0.05 or abs(float(got.get("beat", "9")) - 0.1) > 0.02 \
			   or got.get("key") != "8A Am" or not -30 < float(got.get("loudness", "0")) < -5 \
			   or not 0.5 < float(got.get("peak", "0")) <= 1.0:
				raise failed("a: the tune lists %r" % got)
			if answered > 0.5:
				raise failed("a: the host took %.2f s to answer while it heard" % answered)
			print("livecheck: a: a tune heard where its bytes are: %s BPM from %s s, %s, %s LUFS, "
			      "the host answering in %.0f ms meanwhile"
			      % (got["bpm"], got["beat"], got["key"], got["loudness"], answered * 1000))

			# b: once.
			reply = ask(sock, "add sound " + tune)
			if reply.split() != ["ok", "0", "0"]:
				raise failed("b: asking again answered %r" % reply)
			print("livecheck: b: asked again, nothing queued")

			# c: the held files walked.
			photo = put(os.path.join(FIXTURE, "photo.jpg"), "image/jpeg")
			noise_path = os.path.join(scratch, "not-a-song.mp3")
			with open(noise_path, "wb") as fh:
				fh.write(b"plain words, and no sound in them\n" * 40)
			mute = put(noise_path, "audio/mpeg")
			reply = ask(sock, "add sound from 0").split()
			if reply[:1] != ["ok"] or reply[1:4] != ["3", "3", "1"]:
				raise failed("c: from 0 answered %r" % reply)
			got = heard(mute, "c")
			if set(got) & {"bpm", "key", "loudness"} or "heard" in listed(photo):
				raise failed("c: the mute file lists %r, the photo %r" % (got, listed(photo)))
			left = [os.path.join(d, n) for d, _, ns in os.walk(store) for n in ns if n.startswith(".sound-")]
			if left:
				raise failed("c: the files heard were left behind: %r" % left)
			print("livecheck: c: three held files walked: the photo passed over, a mute file "
			      "heard to say nothing, nothing left behind")

			# d: refusals.
			reply = ask(sock, "add sound " + "ab" * 32)
			if not reply.startswith("error"):
				raise failed("d: a root not held answered %r" % reply)
			reply = ask(sock, "add sound from 99")
			if not reply.startswith("malformed"):
				raise failed("d: a FROM past the last file answered %r" % reply)
			print("livecheck: d: a root not held, and a FROM past the end, refused")

			# e: binary.
			got = binary(sock, bytes([1, 145]) + bytes.fromhex(tune))
			if len(got) != 2 or got[0][:2] != bytes([1, 147]) or got[1][:2] != bytes([0x13, 0]) \
			   or got[0][2:18] != bytes(16):
				raise failed("e: sound in binary answered %r" % got)
			got = binary(sock, bytes([1, 146, 0, 0, 0, 0]))
			if len(got) != 2 or got[0][:2] != bytes([1, 147]) \
			   or int.from_bytes(got[0][2:6], "big") != 3 or int.from_bytes(got[0][6:10], "big") != 3 \
			   or got[0][10:18] != bytes(8):
				raise failed("e: a page in binary answered %r" % got)
			print("livecheck: e: the same asked in binary, a tune and a page")

			# f: the music row, `music_row` 142, its words as asserted.
			got = listed(tune)
			rows = [m for m in binary(sock, bytes([1, 141]))[:-1]
			        if m[:2] == bytes([1, 142]) and m[2:34].hex() == tune]
			want = [got[k].encode() for k in ("bpm", "beat", "key", "loudness", "peak")]
			if len(rows) != 1 or not all(w in rows[0] for w in want):
				raise failed("f: the tune's music row %r lacks one of %r" % (rows, want))
			print("livecheck: f: the music row carries %s" % ", ".join(w.decode() for w in want))
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
	print("livecheck: what held tunes sound like was catalogued")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
