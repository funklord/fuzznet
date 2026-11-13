#!/usr/bin/env python3
"""A call on a sibling's session: another host of the user's -- a paired phone --
rings, answers, carries and places calls through this host: sec 1025.

Two stores over loopback, A and B, users who are contacts, as in live_call.py; and
D, a phone paired to B's estate -- a sibling of B's host -- reaching it straight over
UDP (`device_sim ... live`, which says words in hex and prints in hex
each word it hears).

    a  A rings B: D, listening, hears the RING
    b  D answers: A holds the call up, and D hears A's frame
    c  D sends a frame: A reads it as from its one participant, 1
    d  D hangs up: neither host holds the call
    e  D places a call to A: A holds it ringing in, answers, and D hears the
       answer; A hangs up and D hears that too

Against a daemon that rings no sibling, a never hears the RING; against one that
takes no sibling's word, b never holds the call up.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses: one
deadline, each daemon in its own process group, and every device run bounded by
its own listening time and a timeout here.

Exit 0 on a pass, 1 on a failure.
"""

import os
import re
import secrets
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_groups import PREKEY_HOST  # noqa: E402
from live_rejoin import command, daemon, expect, free_slot  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 460.0

WAIT = 20.0
HOSTS_S = 200.0
HOSTS_RE = re.compile(r"contact pass: \d+ contact\(s\) asked, \d+ kept from members, \d+ "
                      r"paired, ([1-9]\d*) host\(s\) to deliver to")

# A CALL'S WORDS, node/live.h: version 2, type 61, kind, call 8.
RING, ANSWER, DECLINE, HANGUP, FRAME = 1, 2, 3, 4, 5


def word(kind, call, rest=b""):
	return bytes([18, kind]) + call + rest  # FZN_CMD_CALL, sec 1087


def frame(call, seq, media):
	# STREAM 1 | FROM 2 | SEQ 4 | AT 4 | PIECE 2 | PIECES 2 | MEDIA
	return word(FRAME, call, bytes([1, 0, 0]) + seq.to_bytes(4, "big") + (500).to_bytes(4, "big")
	            + (0).to_bytes(2, "big") + (1).to_bytes(2, "big") + media)


def until(what, test, wait=WAIT):
	began = time.monotonic()
	while True:
		got = test()
		if got:
			return got
		if time.monotonic() - began > wait:
			raise failed("%s within %.0f s" % (what, wait))
		time.sleep(0.2)


def calls(sock):
	got = ask(sock, "list call").split()
	return {r.split(",")[0]: r.split(",")[1] for r in got[2:]} if got[:1] == ["ok"] else {}


def frames(sock, call):
	got = ask(sock, "list frame %s" % call).split()
	return got[3:] if got[:1] == ["ok"] else []


class device:
	"""One run of device_sim in live mode: WORDS said, then SECONDS listened."""

	def __init__(self, run, words, seconds):
		self.out = open(os.path.join(run.scratch, "device-%d.log" % time.monotonic_ns()), "w+")
		self.proc = subprocess.Popen(
		        [run.sim, run.image, "udp:127.0.0.1:%s" % run.port_b, "live",
		         ",".join(w.hex() for w in words), str(seconds)],
		        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=self.out,
		        start_new_session=True)
		self.seconds = seconds

	def heard(self):
		self.out.flush()
		self.out.seek(0)
		# WHOLE LINES ONLY: the last, unended, may still be being written.
		lines = self.out.read().split("\n")[:-1]
		return [bytes.fromhex(line[len("device: heard hex "):]) for line in lines
		        if line.startswith("device: heard hex ")]

	def finish(self):
		try:
			code = self.proc.wait(timeout=self.seconds + 30)
		except subprocess.TimeoutExpired:
			os.killpg(self.proc.pid, 9)
			self.proc.wait()
			raise failed("device_sim outlived its listening")
		if code != 0:
			self.out.seek(0)
			raise failed("device_sim exited %d: %s" % (code, self.out.read()[-300:]))
		return self.heard()


def main(argv):
	if len(argv) != 3:
		print("usage: live_sibling_call.py PATH_TO_FUZZNETD PATH_TO_DEVICE_SIM", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.sim = os.path.abspath(argv[2])
	run.started = []
	base = free_slot(49600, 4, 200, 2)
	port = {"a": str(base), "b": str(base + 1)}
	run.port_b = port["b"]
	started = {}
	running = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in ("a", "b", "d")}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		try:
			keys = {}
			for d in dirs.values():
				os.mkdir(d)
			for who in port:
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
				keys[who] = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"],
				                    None)[PREKEY_HOST]
			# D, B'S DEVICE: its prekey to B, B's card back, and its image.
			prekey = command(run, ["--fuzznet-dir=" + dirs["d"], "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + dirs["b"], "--pair=" + prekey], None)
			gateway = command(run, ["--fuzznet-dir=" + dirs["d"], "--accept=" + card], None)
			run.image = command(run, ["--fuzznet-dir=" + dirs["d"], "--device-image=" + gateway],
			                    None)
			if not run.image.startswith("FZD1:"):
				raise failed("--device-image wrote %r" % run.image[:40])
			for who in port:
				started[who] = daemon(run, who, dirs[who], socks[who],
				                      extra=["--udp-port=" + port[who]])
				expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who],
				       "ok")
			got = ask(socks["b"], "get card bea")
			if not got.startswith("ok FZC1:"):
				raise failed("b: get card answered %r" % got)
			got = ask(socks["a"], "add contact bea " + got.split(" ", 1)[1].strip())
			if got.strip() != "ok " + keys["b"]:
				raise failed("a: add contact answered %r" % got)
			until("b never kept A's request",
			      lambda: ask(socks["b"], "grant request %s ada" % keys["a"]) == "ok", 30.0)
			for who in ("a", "b"):
				started[who].wait_for(HOSTS_RE, "%s holding the other's host" % who.upper(),
				                      within=HOSTS_S)

			# a: A RINGS B; D, LISTENING, HEARS IT.
			listening = device(run, [], 12)
			running.append(listening)
			time.sleep(2.0)
			rung = ask(socks["a"], "add call bea audio").split()
			if len(rung) != 2 or rung[0] != "ok":
				raise failed("a: add call answered %r" % rung)
			call = bytes.fromhex(rung[1])
			until("a: D never heard the RING",
			      lambda: any(h[:len(word(RING, call))] == word(RING, call) for h in listening.heard()))
			listening.finish()
			running.remove(listening)
			print("livecheck: a: A rang B, and D, B's device, heard the ring")

			# b: D ANSWERS; A's FRAME REACHES IT.
			answering = device(run, [word(ANSWER, call)], 10)
			running.append(answering)
			until("b: A never held the call up", lambda: calls(socks["a"]).get(rung[1]) == "up")
			if calls(socks["b"]).get(rung[1]) != "up":
				raise failed("b: B does not hold the call up")
			said = ask(socks["a"], "add frame %s 1 7 500 0 1 c0ffee" % rung[1])
			if said not in ("ok sent", "ok lost"):
				raise failed("b: add frame answered %r" % said)
			until("b: D never heard A's frame",
			      lambda: any(h[:len(word(FRAME, call))] == word(FRAME, call) and h.endswith(b"\xc0\xff\xee")
			                  for h in answering.heard()))
			answering.finish()
			running.remove(answering)
			print("livecheck: b: D answered, A holds the call up, and D heard A's frame")

			# c: D SENDS A FRAME; A READS IT AS FROM ITS ONE MEMBER.
			sending = device(run, [frame(call, 9, b"\x0b\x0e")], 3)
			running.append(sending)
			until("c: A never read D's frame",
			      lambda: "1,9,500,0,1,0b0e,1" in frames(socks["a"], rung[1]))
			sending.finish()
			running.remove(sending)
			print("livecheck: c: D sent a frame, and A read it, from its one participant")

			# d: D HANGS UP.
			hanging = device(run, [word(HANGUP, call)], 2)
			running.append(hanging)
			until("d: A still held the call", lambda: rung[1] not in calls(socks["a"]))
			until("d: B still held the call", lambda: rung[1] not in calls(socks["b"]))
			hanging.finish()
			running.remove(hanging)
			print("livecheck: d: D hung up, and neither host holds the call")

			# e: D PLACES A CALL TO A.
			mine = secrets.token_bytes(8)
			placing = device(run, [word(RING, mine, bytes([1]) + bytes.fromhex(keys["a"]))], 14)
			running.append(placing)
			until("e: A never held D's call ringing in",
			      lambda: calls(socks["a"]).get(mine.hex()) == "ringing-in")
			expect(socks["a"], "a", "set call %s answer" % mine.hex(), "ok")
			until("e: D never heard A answer",
			      lambda: any(h == word(ANSWER, mine) for h in placing.heard()))
			expect(socks["a"], "a", "set call %s hangup" % mine.hex(), "ok")
			until("e: D never heard A hang up",
			      lambda: any(h == word(HANGUP, mine) for h in placing.heard()))
			placing.finish()
			running.remove(placing)
			print("livecheck: e: D placed a call to A, heard it answered, and heard it hung up")
		except failed as e:
			print("livecheck: FAILED -- %s" % e, file=sys.stderr)
			return 1
		finally:
			for dev in running:
				if dev.proc.poll() is None:
					os.killpg(dev.proc.pid, 9)
					dev.proc.wait()
			for who in ("a", "b"):
				if who in started:
					started[who].stop()
	print("livecheck: a call was carried on a sibling's session, both ways")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
