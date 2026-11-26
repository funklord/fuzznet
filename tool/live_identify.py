#!/usr/bin/env python3
"""Which recording a held tune is, catalogued: `make livecheck`, sec 1459.

One store, a root serving, built with faults on (so it asks AcoustID where
FZN_TEST_ACOUSTID_URL says) and with a decoder and Chromaprint. A server here
stands in for AcoustID, answering one recording; live_sound.py's tune is put
into the store as a library does:

    a  with no `media/acoustid` set, the tune is heard -- its tempo and key --
       and nothing is sent: the server is asked nothing
    b  the key set, `add sound` asks again of the tune heard before: the
       server is POSTed the key, the tune's length in whole seconds and a
       fingerprint, and nothing else; `list catalog ROOT` comes to name the
       `acoustid` and `musicbrainz_recording` it answered, and `identified`
    c  asked again, nothing is queued and the server is asked nothing more
    d  a server answering an error (a bad key) leaves the tune unidentified,
       to be asked again: no `identified`, no `acoustid`
    e  the untagged tune of b is named by the recording, its `title` and
       `artist` (sec 1463); a tune that names itself keeps its own title and
       is given no second one
    f  with the key set, a `video/` is heard and AcoustID is not asked of it
       -- a person's own recording, which a key for their music did not ask
       to have fingerprinted (sec 1464) -- and asking again queues nothing

Against a daemon that sends with no key, phase a counts a request; against one
that never asks again once heard, phase b times out.

BOUNDED FROM INSIDE as live_sound.py is: one deadline, the daemon in its own
process group, the server a thread of this process, checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import http.server
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
from live_sound import write_tune  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 150.0
ACOUSTID = "0b1cf1a2-2222-4b4b-8c8c-000000000002"
RECORDING = "bbbbbbbb-0000-4000-8000-000000000002"


class acoustid(http.server.BaseHTTPRequestHandler):
	asked = []
	refuse = False

	def do_POST(self):
		body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
		acoustid.asked.append((self.path, self.headers.get("Content-Type"), urllib.parse.parse_qs(body)))
		if acoustid.refuse:
			out = b'{"status": "error", "error": {"code": 4, "message": "invalid API key"}}'
		else:
			out = ('{"status": "ok", "results": [{"id": "%s", "score": 0.93, "recordings": [{"id": "%s", '
			       '"title": "Night Drive \\u2014 Live", "artists": [{"name": "Svalbard Echo"}, {"name": "Mira"}]}]}]}'
			       % (ACOUSTID, RECORDING)).encode()
		self.send_response(200)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Length", str(len(out)))
		self.end_headers()
		self.wfile.write(out)

	def log_message(self, *args):
		pass


def main(argv):
	if len(argv) != 2:
		print("usage: live_identify.py PATH_TO_FAULTS_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port = str(40000 + (os.getpid() % 500) * 2)
	started = []
	server = http.server.HTTPServer(("127.0.0.1", 0), acoustid)
	serving = threading.Thread(target=server.serve_forever, daemon=True)
	serving.start()
	os.environ["FZN_TEST_ACOUSTID_URL"] = "http://127.0.0.1:%d/v2/lookup" % server.server_port
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		store = os.path.join(scratch, "a")
		sock = os.path.join(sock_dir, "a")

		def listed(root):
			"""`root`'s catalogue as {name: value}: `ok LIVE FROM ROWS...`, as
			many rows as a reply holds, so asked again from where it ended."""
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

		def until(root, what, done):
			while time.monotonic() < live_trim.DEADLINE:
				got = listed(root)
				if done(got):
					return got
				time.sleep(0.2)
			raise failed("%s: never came; the tune lists %r" % (what, listed(root)))

		try:
			os.mkdir(store)
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)
			started.append(daemon(run, "a", store, sock, extra=["--udp-port=" + port]))
			started[0].wait_for(ROUND_DONE_RE, "A's round")
			tune_path = os.path.join(scratch, "tune.wav")
			write_tune(tune_path)
			reply = ask(sock, "put file " + tune_path)
			if not reply.startswith("ok "):
				raise failed("put file answered %r" % reply)
			tune = reply.split()[1][:64]
			expect(sock, "a", "add catalog %s kind audio/wav" % tune, "ok")

			# a: no key, nothing sent.
			reply = ask(sock, "add sound " + tune)
			if reply.startswith("error this host was built with no decoder"):
				print("livecheck: SKIP -- this fuzznetd was built with no decoder")
				return 0
			got = until(tune, "a: the hearing", lambda g: g.get("heard") == "1")
			if acoustid.asked or "acoustid" in got or "identified" in got:
				raise failed("a: with no key, AcoustID was asked %r; the tune lists %r" % (acoustid.asked, got))
			print("livecheck: a: heard at %s BPM with no key set, and nothing sent" % got.get("bpm"))

			# b: the key set, asked again.
			expect(sock, "a", "set setting estate media/acoustid test-key", "ok")
			reply = ask(sock, "add sound " + tune)
			if reply.split()[:2] != ["ok", "1"]:
				raise failed("b: add sound with a key set answered %r" % reply)
			got = until(tune, "b: the identity", lambda g: g.get("identified") == "1")
			if len(acoustid.asked) != 1:
				raise failed("b: AcoustID was asked %d time(s)" % len(acoustid.asked))
			path, kind, form = acoustid.asked[0]
			if path != "/v2/lookup" or kind != "application/x-www-form-urlencoded" \
			   or form.get("client") != ["test-key"] or form.get("duration") != ["30"] \
			   or len(form.get("fingerprint", [""])[0]) < 100 \
			   or set(form) != {"client", "duration", "fingerprint", "format", "meta"}:
				raise failed("b: AcoustID was asked %r %r %r" % (path, kind, {k: v[0][:40] for k, v in form.items()}))
			if got.get("acoustid") != ACOUSTID or got.get("musicbrainz_recording") != RECORDING:
				raise failed("b: the tune lists %r" % got)
			print("livecheck: b: the key set, asked once -- key, 30 s and a %d-byte print, nothing else -- "
			      "and the recording named" % len(form["fingerprint"][0]))

			# c: once.
			reply = ask(sock, "add sound " + tune)
			if reply.split() != ["ok", "0", "0"] or len(acoustid.asked) != 1:
				raise failed("c: asking again answered %r, AcoustID asked %d time(s)" % (reply, len(acoustid.asked)))
			print("livecheck: c: asked again, nothing queued or sent")

			# d: a refusal leaves it to be asked again.
			acoustid.refuse = True
			other_path = os.path.join(scratch, "other.wav")
			with open(tune_path, "rb") as src, open(other_path, "wb") as dst:
				dst.write(src.read() + b"\0" * 16)
			reply = ask(sock, "put file " + other_path)
			other = reply.split()[1][:64]
			expect(sock, "a", "add catalog %s kind audio/wav" % other, "ok")
			reply = ask(sock, "add sound " + other)
			got = until(other, "d: the hearing", lambda g: g.get("heard") == "1")
			if len(acoustid.asked) != 2 or "identified" in got or "acoustid" in got:
				raise failed("d: a refusal left %r, AcoustID asked %d time(s)" % (got, len(acoustid.asked)))
			if ask(sock, "add sound " + other).split()[:2] != ["ok", "1"]:
				raise failed("d: a tune refused was not queued again")
			print("livecheck: d: an error from AcoustID left the tune to be asked again")

			# e: named where nothing names it; a title of its own stands.
			got = listed(tune)
			if got.get("title") != "Night Drive \u2014 Live" or got.get("artist") != "Svalbard Echo, Mira":
				raise failed("e: the untagged tune lists %r" % got)
			acoustid.refuse = False
			own_path = os.path.join(scratch, "own.wav")
			with open(tune_path, "rb") as src, open(own_path, "wb") as dst:
				dst.write(src.read() + b"\0" * 32)
			reply = ask(sock, "put file " + own_path)
			own = reply.split()[1][:64]
			expect(sock, "e", "add catalog %s kind audio/wav" % own, "ok")
			expect(sock, "e", "add catalog %s title Mine" % own, "ok")
			ask(sock, "add sound " + own)
			got = until(own, "e: the identity", lambda g: g.get("identified") == "1")
			rows = ask(sock, "list catalog %s 0" % own).split()[3:]
			titles = [r.split(",")[2] for r in rows if r.split(",")[1] == "title"]
			if titles != ["Mine"] or got.get("acoustid") != ACOUSTID:
				raise failed("e: a tune naming itself has titles %r and lists %r" % (titles, got))
			print("livecheck: e: an untagged tune named by its recording, one naming itself left its own")

			# f: a video heard, not asked after.
			video_path = os.path.join(scratch, "video.wav")
			with open(tune_path, "rb") as src, open(video_path, "wb") as dst:
				dst.write(src.read() + b"\0" * 48)
			reply = ask(sock, "put file " + video_path)
			video = reply.split()[1][:64]
			expect(sock, "f", "add catalog %s kind video/mp4" % video, "ok")
			before = len(acoustid.asked)
			ask(sock, "add sound " + video)
			got = until(video, "f: the hearing", lambda g: g.get("heard") == "1")
			again = ask(sock, "add sound " + video).split()
			if len(acoustid.asked) != before or "identified" in got or got.get("bpm") != "128.00" \
			   or again != ["ok", "0", "0"]:
				raise failed("f: a video lists %r, AcoustID asked %d more time(s), asked again: %r"
				             % (got, len(acoustid.asked) - before, again))
			print("livecheck: f: a video heard at %s BPM, AcoustID not asked of it, nothing queued again"
			      % got["bpm"])
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started:
				d.stop()
			server.shutdown()
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
	print("livecheck: which recording a held tune is was catalogued")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
