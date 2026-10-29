#!/usr/bin/env python3
"""A sibling found on the LAN by a probe: `make livecheck`, sec 624.

Three stores over loopback, as live_introduce.py has them: A a root, B and
C joined with grants they can pass on. C advertises an address on another
network, 192.0.2.1, at the port it really serves on -- as a host whose
recorded address is somewhere else while it sits on the same LAN.

    a  B and C pair each other through the estate
    b  A is gone, so nobody can introduce C. C puts a file and B asks for
       it; B probes the LAN, its discovery address set to 127.0.0.1, at
       the port C advertises; C answers B, a sibling, with a hello from its
       serving socket; B's next round finds C where that hello came from
       and fetches the file whole from C. `fetch lan` answers how many
       probes it sent, and where
    c  B's discovery switched off, `fetch lan` sends none and says why

Against a daemon that answers no probe, phase b never finds C; against one
whose `net/discovery off` still broadcasts, phase c's answer is a count.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, RECONCILE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402


TAKEN_RE = re.compile(r"(\d+) sibling\(s\) paired, (\d+) pairing\(s\) taken")
WHOLE_RE = re.compile(r"file [0-9a-f]{8}, (\d+) bytes, whole from (\d+) peer\(s\)")
FOUND_RE = re.compile(r"a sibling found where it said hello, 127\.0\.0\.1 (\d+)")
PROBED_RE = re.compile(r"(\d+) LAN probe\(s\) sent to 127\.0\.0\.1")
# ROUNDS EACH, more under loss, as live_introduce.py's (sec 756).
LOSS = int(os.environ.get("FZN_FAULT_LOSS", "0") or 0)
ROUNDS = 6 + LOSS // 2
live_trim.DEADLINE = time.monotonic() + 420.0 + 30.0 * LOSS
PAYLOAD_LEN = 50000


def took(d):
	return any(int(m.group(2)) > 0 for m in TAKEN_RE.finditer(d.log()))


def main(argv):
	# `--skew S`, sec 757: B S seconds ahead and C S behind, by faketime;
	# A, the root, on the real clock.
	skew = 0
	if len(argv) == 4 and argv[2] == "--skew" and argv[3].isdigit():
		skew = int(argv[3])
	elif len(argv) != 2:
		print("usage: live_lan.py PATH_TO_FUZZNETD [--skew S]", file=sys.stderr)
		return 2
	skews = {}
	if skew:
		if not shutil.which("faketime"):
			print("livecheck: lan SKIPPED -- --skew needs faketime on PATH")
			return 0
		skews = {"b": "+%ds" % skew, "c": "-%ds" % skew}

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 2000 + (os.getpid() % 500) * 4
	port = {"a": str(base), "b": str(base + 1), "c": str(base + 2)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in ("a", "b", "c")}
		socks = {k: os.path.join(sock_dir, k) for k in ("a", "b", "c")}
		for d in dirs.values():
			os.mkdir(d)
		payload = os.path.join(scratch, "payload")
		with open(payload, "wb") as f:
			f.write(os.urandom(PAYLOAD_LEN))
		args = {"b": ["--udp-port=" + port["b"], "--root-at", "127.0.0.1", port["a"]],
		        "c": ["--udp-port=" + port["c"], "--root-at", "127.0.0.1", port["a"]]}
		started = {}
		try:
			command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
			host_key = {}
			for who in ("b", "c"):
				prekey = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"], skews.get(who))
				host_key[who] = prekey[4:68]
				card = command(run, ["--fuzznet-dir=" + dirs["a"], "--pair=" + prekey,
				                     "--delegable"], None)
				command(run, ["--fuzznet-dir=" + dirs[who], "--accept=" + card, "--join"],
				        skews.get(who))
			started["a"] = daemon(run, "a1", dirs["a"], socks["a"],
			                      extra=["--udp-port=" + port["a"]])

			# a: the pairings, both ways.
			ref = None
			taken = {"b": False, "c": False}
			for rnd in range(ROUNDS):
				for who in ("c", "b"):
					d = daemon(run, "%s%d" % (who, rnd), dirs[who], socks[who], fake=skews.get(who),
					           extra=args[who])
					try:
						if ref is None and who == "c":
							# A MEMBER'S SETTING once its first round is over: it is allowed by the
							# grant that round brings, and a round answers mid-way (sec 637).
							d.wait_for(ROUND_DONE_RE, "C's first round")
							expect(socks["c"], "c", "set setting host net/address 192.0.2.1 "
							       + port["c"], "ok")
							reply = ask(socks["c"], "put file " + payload)
							if not reply.startswith("ok "):
								raise failed("a: put file answered %r" % reply)
							ref = reply.split()[1]
						if rnd == 0 and who == "b":
							expect(socks["b"], "b", "set setting host net/discovery 127.0.0.1",
							       "ok")
						d.wait_for(RECONCILE_RE, "reconcile pass")
						taken[who] = taken[who] or took(d)
					finally:
						d.stop()
				if all(taken.values()):
					break
			if not all(taken.values()):
				raise failed("a: after %d rounds each, a pairing taken at B %s, at C %s"
				             % (ROUNDS, taken["b"], taken["c"]))
			print("livecheck: a: B and C paired each other through the estate")

			# b: A gone; B probes the LAN and finds C.
			started.pop("a").stop()
			started["c"] = daemon(run, "c-b", dirs["c"], socks["c"], fake=skews.get("c"),
			                      extra=args["c"])
			started["c"].wait_for(RECONCILE_RE, "C's reconcile pass")
			started["b"] = daemon(run, "b-b", dirs["b"], socks["b"], fake=skews.get("b"),
			                      extra=args["b"])
			started["b"].wait_for(RECONCILE_RE, "B's reconcile pass")
			expect(socks["b"], "b", "fetch file " + ref, "ok")
			# NOTHING HEARD BEFORE A PROBE, sec 659.
			expect(socks["b"], "b", "get lan", "ok 0")
			# THE ANSWER SAYS WHAT WAS SENT, sec 639: the probes are sent
			# before it.
			said = ask(socks["b"], "fetch lan").split()
			if len(said) != 3 or said[0] != "ok" or said[2] != "127.0.0.1" \
			   or not said[1].isdigit() or said[1] == "0":
				raise failed("b: fetch lan answered %r, not probes sent to 127.0.0.1" % said)
			probed = started["b"].wait_for(PROBED_RE, "B's LAN probes")
			if probed.group(1) != said[1]:
				raise failed("b: fetch lan said %s probe(s), the log %s"
				             % (said[1], probed.group(1)))
			# WHO ANSWERED, sec 659: C's hello, from its serving port on this
			# network, its time in seconds.
			# PROBED AGAIN when nothing is heard within 10 s, three probes at
			# most: under loss a probe or its hello is lost, and a user asks
			# again.
			heard = []
			deadline = time.monotonic() + 30.0
			again = time.monotonic() + 10.0
			probes = 1
			while time.monotonic() < deadline:
				heard = ask(socks["b"], "get lan").split()
				if any(r.startswith(host_key["c"] + ",127.0.0.1," + port["c"] + ",")
				       for r in heard[2:]):
					break
				if time.monotonic() > again and probes < 3:
					ask(socks["b"], "fetch lan")
					probes += 1
					again = time.monotonic() + 10.0
				time.sleep(0.5)
			else:
				raise failed("b: B's get lan answered %r, not C at 127.0.0.1 %s"
				             % (heard, port["c"]))
			row = [r for r in heard[2:] if r.startswith(host_key["c"] + ",")][0]
			if abs(int(row.rsplit(",", 1)[1]) - time.time()) > 120:
				raise failed("b: C's row %r has no time in seconds" % row)
			# B'S NEXT ROUND finds C: waited for here rather than by wait_for,
			# whose limit is half a round.
			deadline = time.monotonic() + 200.0 + 10.0 * LOSS
			while time.monotonic() < deadline and not FOUND_RE.search(started["b"].log()):
				time.sleep(0.5)
			got = FOUND_RE.search(started["b"].log())
			if not got or got.group(1) != port["c"]:
				told = [l[-170:] for l in started["b"].log().splitlines()
				        if any(w in l for w in ("sibling", "net/lan", "refused", "node/peer"))]
				raise failed("b: B found C at %r, not C's serving port %s%s"
				             % (got.group(1) if got else None, port["c"],
				                "".join("\n  " + l for l in told[-10:])
				                + "\n  C stderr: " + started["c"].stderr()[-600:]))
			# THE FILE WHOLE, waited for past half a round under loss: its
			# pieces are fetched over the found address, a step at a time.
			deadline = time.monotonic() + 30.0 + 6.0 * LOSS
			while time.monotonic() < deadline and not WHOLE_RE.search(started["b"].log()):
				time.sleep(0.5)
			whole = started["b"].wait_for(WHOLE_RE, "the file whole")
			if whole.groups() != (str(PAYLOAD_LEN), "1"):
				raise failed("b: B's file was %s bytes from %s peer(s)" % whole.groups())
			print("livecheck: b: B probed the LAN, found C, and fetched its file whole")

			# c: switched off, B sends nothing and says why (sec 639).
			expect(socks["b"], "c", "set setting host net/discovery off", "ok")
			said = ask(socks["b"], "fetch lan").strip()
			if not said.startswith("ok 0 - ") or "off" not in said:
				raise failed("c: switched off, fetch lan answered %r" % said)
			print("livecheck: c: B's discovery switched off, it sent no probe and said why")
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
						with open("/proc/%d/cmdline" % pid, "rb") as f:
							alive = run.fuzznetd.encode() in f.read()
						# STILL OUR CHILD, sec 741: a reaped daemon's pid, handed to
						# another run's daemon of the same binary, is not this run's.
						with open("/proc/%d/stat" % pid) as f:
							alive = alive and int(f.read().rsplit(")", 1)[1].split()[1]) == os.getpid()
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: a sibling advertised elsewhere was found on the LAN")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
