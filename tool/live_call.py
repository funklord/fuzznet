#!/usr/bin/env python3
"""A call between two contacts' hosts, rung, answered, framed and hung up: sec 1020.

Two stores over loopback, two users who are contacts, each host running throughout.
Each waits until it holds the other's host -- A to ring B, B to take A's words as a
contact's. Each host's own client is a caller on its socket.

    a  A rings B (`add call bea audio`, `ok ID`), and B lists the call ringing in,
       and was told so (`event call ID ring`)
    b  B answers; A lists the call up
    c  A sends a frame; B reads it back, the same bytes, stream, number and time
    d  B sends one back; A reads it
    e  A sends video frames 1, 2, 4 and 5: B measures four received and one lost,
       and reports it, and A reads it (`get call ID quality`, sec 1021)
    e2 a frame stamped with A's client's clock comes back in B's report, its AT and
       how long B held it, and the client reads the round trip (sec 1026)
    f  A hangs up; B holds the call no more
    g  B rings A at once, then A B, three times each way: each rung end holds the
       call ringing in, and names the other end's user as the fourth field of
       `list call` (sec 1040), as the ringing end names the user it rang; the
       caller hangs up and the callee holds it no more. A ring said once and lost
       was a call never rung (sec 1039): fuzzypickles saw one in three missed

Against a daemon that takes no call's word from a session, a never rings; against
one whose asked session is dropped when the other host's frame comes, b is never
heard at A.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses: one
deadline, each daemon in its own process group, and every daemon checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import re
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_groups import PREKEY_HOST  # noqa: E402
from live_rejoin import command, daemon, expect, free_slot  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 500.0

WAIT = 20.0
HOSTS_S = 200.0
HOSTS_RE = re.compile(r"contact pass: \d+ contact\(s\) asked, \d+ kept from members, \d+ "
                      r"paired, ([1-9]\d*) host\(s\) to deliver to")


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


def rows(sock):
	"""`list call` as ID -> its fields."""
	got = ask(sock, "list call").split()
	return {r.split(",")[0]: r.split(",") for r in got[2:]} if got[:1] == ["ok"] else {}


def frames(sock, call):
	got = ask(sock, "list frame %s" % call).split()
	return got[3:] if got[:1] == ["ok"] else []


def main(argv):
	if len(argv) != 2:
		print("usage: live_call.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = free_slot(48600, 4, 300, 2)
	port = {"a": str(base), "b": str(base + 1)}
	started = {}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		try:
			keys = {}
			for who in port:
				os.mkdir(dirs[who])
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
				keys[who] = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"],
				                    None)[PREKEY_HOST]
			for who in port:
				started[who] = daemon(run, who, dirs[who], socks[who],
				                      extra=["--udp-port=" + port[who]])
				expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who],
				       "ok")
			card = ask(socks["b"], "get card bea")
			if not card.startswith("ok FZC1:"):
				raise failed("b: get card answered %r" % card)
			got = ask(socks["a"], "add contact bea " + card.split(" ", 1)[1].strip())
			if got.strip() != "ok " + keys["b"]:
				raise failed("a: add contact answered %r" % got)
			until("b never kept A's request",
			      lambda: ask(socks["b"], "grant request %s ada" % keys["a"]) == "ok", 30.0)
			for who in ("a", "b"):
				started[who].wait_for(HOSTS_RE, "%s holding the other's host" % who.upper(),
				                      within=HOSTS_S)

			# a: A RINGS B.
			rung = ask(socks["a"], "add call bea audio").split()
			if len(rung) != 2 or rung[0] != "ok":
				raise failed("a: add call answered %r" % rung)
			call = rung[1]
			began = time.monotonic()
			until("a: B never held the call ringing in",
			      lambda: calls(socks["b"]).get(call) == "ringing-in")
			print("livecheck: a: A rang B, and B holds the call ringing in after %.1f s"
			      % (time.monotonic() - began))

			# b: B ANSWERS.
			expect(socks["b"], "b", "set call %s answer" % call, "ok")
			until("b: A never held the call up", lambda: calls(socks["a"]).get(call) == "up")
			print("livecheck: b: B answered, and A holds the call up")

			# c: A SENDS A FRAME, d: B ONE BACK.
			# FROM, sec 1024: the caller 0, the callee its one participant, 1.
			for frm, to, media, seq, number in (("a", "b", "c0ffee", 7, 0),
			                                   ("b", "a", "0b0e", 9, 1)):
				said = ask(socks[frm], "add frame %s 1 %d 1234 0 1 %s" % (call, seq, media))
				if said not in ("ok sent", "ok lost"):
					raise failed("%s: add frame answered %r" % (frm, said))
				want = "1,%d,1234,0,1,%s,%d" % (seq, media, number)
				until("%s: never read %s's frame" % (to.upper(), frm.upper()),
				      lambda: want in frames(socks[to], call))
				print("livecheck: %s: %s sent a frame, and %s read it back the same"
				      % ("c" if frm == "a" else "d", frm.upper(), to.upper()))

			# e: QUALITY, sec 1021: A sends video frames 1, 2, 4 and 5; B measures four
			# received and one lost, and reports it, which A reads as what it sent.
			for seq in (1, 2, 4, 5):
				said = ask(socks["a"], "add frame %s 2 %d %d 0 1 ab" % (call, seq, 2000 + 40 * seq))
				if said not in ("ok sent", "ok lost"):
					raise failed("e: add frame answered %r" % said)
			until("e: B never measured four received and one lost",
			      lambda: any(r.startswith("2,received,4,1,")
			                  for r in ask(socks["b"], "get call %s quality" % call).split()[1:]))
			until("e: A never read B's report of its video",
			      lambda: any(r.startswith("2,sent,4,1,")
			                  for r in ask(socks["a"], "get call %s quality" % call).split()[1:]))
			print("livecheck: e: B measured A's video, 4 received and 1 lost, and A reads it")

			# e2: THE ROUND TRIP, sec 1026: a frame stamped with this client's own
			# clock; B's report of it carries its AT back and how long B held it, and
			# this clock's now less both is the round trip -- no clock of B's in it.
			def ms():
				return int(time.monotonic() * 1000) & 0xffffffff
			stamp = ms()
			said = ask(socks["a"], "add frame %s 2 6 %d 0 1 ab" % (call, stamp))
			if said not in ("ok sent", "ok lost"):
				raise failed("e2: add frame answered %r" % said)
			row = until("e2: A never read B's report of the stamped frame",
			            lambda: next((r for r in ask(socks["a"], "get call %s quality" % call)
			                          .split()[1:]
			                          if r.startswith("2,sent,") and r.split(",")[5] == str(stamp)),
			                         None))
			# ASKED AGAIN 1.5 s on: HELD has grown by the wait, so the trip is the same,
			# where a HELD not carried, or not grown here, would read 1.5 s and more.
			time.sleep(1.5)
			row = next(r for r in ask(socks["a"], "get call %s quality" % call).split()[1:]
			           if r.startswith("2,sent,"))
			trip = ms() - int(row.split(",")[5]) - int(row.split(",")[6])
			if row.split(",")[5] != str(stamp) or not 0 <= trip < 1000:
				raise failed("e2: a round trip of %d ms, from %r" % (trip, row))
			print("livecheck: e2: A's client reads the round trip off B's report: %d ms" % trip)

			# f: A HANGS UP.
			expect(socks["a"], "a", "set call %s hangup" % call, "ok")
			until("f: B still held the call", lambda: call not in calls(socks["b"]))
			if call in calls(socks["a"]):
				raise failed("f: A still holds the call it hung up")
			print("livecheck: f: A hung up, and neither holds the call")

			# g: RUNG BOTH WAYS, each right after the last is gone.
			for frm, to, name in (("b", "a", "ada"), ("a", "b", "bea")) * 3:
				rung = ask(socks[frm], "add call %s audio" % name).split()
				if len(rung) != 2 or rung[0] != "ok":
					raise failed("g: %s's add call answered %r" % (frm.upper(), rung))
				began = time.monotonic()
				row = until("g: %s never held %s's ring" % (to.upper(), frm.upper()),
				            lambda: rows(socks[to]).get(rung[1], [None, None])[1] == "ringing-in"
				            and rows(socks[to])[rung[1]])
				if len(row) != 4 or row[3] != keys[frm]:
					raise failed("g: %s's row for %s's ring names %r, not %s" % (
					             to.upper(), frm.upper(), row, keys[frm]))
				mine = rows(socks[frm]).get(rung[1])
				if not mine or len(mine) != 4 or mine[3] != keys[to]:
					raise failed("g: %s's row for its ring names %r, not %s" % (
					             frm.upper(), mine, keys[to]))
				expect(socks[frm], frm, "set call %s hangup" % rung[1], "ok")
				until("g: %s still held the call %s hung up" % (to.upper(), frm.upper()),
				      lambda: rung[1] not in calls(socks[to]))
				print("livecheck: g: %s rang %s, heard after %.1f s, named either end, hung up"
				      % (frm.upper(), to.upper(), time.monotonic() - began))
		except failed as e:
			print("livecheck: FAILED -- %s" % e, file=sys.stderr)
			return 1
		finally:
			for who in ("a", "b"):
				if who in started:
					started[who].stop()
	print("livecheck: a call was rung, answered, carried both ways and hung up")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
