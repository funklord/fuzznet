#!/usr/bin/env python3
"""A call between two contacts' hosts, rung, answered, framed and hung up: sec 1020.

Two stores over loopback, two users who are contacts, each host running throughout.
Each waits until it holds the other's host -- A to ring B, B to take A's words as a
contact's. Each host's own client is a caller on its socket.

    a  A rings B (`add call bea audio`, `ok ID`), and B lists the call ringing in,
       and a client subscribed to B's events was told so (`event call ID`)
    b  B answers; A lists the call up
    c  A sends a frame; B reads it back, the same bytes, stream, number and time
    d  B sends one back; A reads it
    e  A sends video frames 1, 2, 4 and 5: B measures four received and one lost,
       and reports it, and A reads it (`get call ID quality`, sec 1021)
    e2 a frame stamped with A's client's clock comes back in B's report, its AT and
       how long B held it, and the client reads the round trip (sec 1026)
    f  A hangs up; B holds the call no more, and B's subscriber was told so
    g  B rings A at once, then A B, three times each way: each rung end holds the
       call ringing in, and names the other end's user as the fourth field of
       `list call` (sec 1040), as the ringing end names the user it rang; the
       caller hangs up and the callee holds it no more. A ring said once and lost
       was a call never rung (sec 1039): fuzzypickles saw one in three missed
    i  B rings A and is stopped while ringing: A drops the call within seconds, not
       45; A rings B, gone, and drops it as unreachable (sec 1062)
    j  B started again and rung, so A holds a session with it; B restarted, and A
       rings it at once: B holds the ring within 12 s. A restarted host keeps none
       of its sessions, and rings said on one it forgot were lost (sec 1072)
    k  B sets its ring time to 5 s; A rings it and nobody answers: B ends the call
       no-answer at 5 s and tells A, which ends it no-answer -- not 45 s, nor
       gone for RINGING stopping (sec 1073); `get call ID` then answers `ok ended
       no-answer` at both ends, and phase l's `ok ended busy` (sec 1082)
    l  B lets a user ring twice, one more a day; A rings twice, held, then a third
       time: A's call ends busy within 4 s, before B's ring time, and B never holds
       it (sec 1074)

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
from live_events import subscriber  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 600.0

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

			# a: A RINGS B, and a client of B's subscribed to its events hears it.
			heard_b = subscriber(socks["b"], "b's events")
			if heard_b.first != "ok events":
				raise failed("a: B's `get events` answered %r" % heard_b.first)
			rung = ask(socks["a"], "add call bea audio").split()
			if len(rung) != 2 or rung[0] != "ok":
				raise failed("a: add call answered %r" % rung)
			call = rung[1]
			began = time.monotonic()
			until("a: B never held the call ringing in",
			      lambda: calls(socks["b"]).get(call) == "ringing-in")
			print("livecheck: a: A rang B, and B holds the call ringing in after %.1f s"
			      % (time.monotonic() - began))
			# `event call ID`, sec 1043: the id alone -- once with a word after it,
			# which an event's name may not carry, and refused unsent.
			if "event call %s" % call not in heard_b.lines_within(3.0):
				raise failed("a: B's subscriber never heard `event call %s`" % call)
			print("livecheck: a: and B's subscriber heard `event call ID`")

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
			# -1 IS ROUNDING: the client's clock and the daemon's HELD are each
			# whole ms, truncated apart, so a trip under one reads -1 now and then
			# (sec 1064: one gate run in several).
			if row.split(",")[5] != str(stamp) or not -1 <= trip < 1000:
				raise failed("e2: a round trip of %d ms, from %r" % (trip, row))
			print("livecheck: e2: A's client reads the round trip off B's report: %d ms" % trip)

			# f: A HANGS UP. What B's subscriber heard before -- B's own answer among
			# it -- read and set aside first, so only the end can pass.
			heard_b.lines_within(1.0)
			expect(socks["a"], "a", "set call %s hangup" % call, "ok")
			until("f: B still held the call", lambda: call not in calls(socks["b"]))
			if "event call %s" % call not in heard_b.lines_within(3.0):
				raise failed("f: B's subscriber never heard the call end")
			heard_b.close()
			if call in calls(socks["a"]):
				raise failed("f: A still holds the call it hung up")
			print("livecheck: f: A hung up, and neither holds the call")

			# h: A'S LEGS LOGGED, sec 1053 and 1075: `metric/log/leg` set, each leg A
			# measured is said under metric/leg -- B's among them, from the call.
			expect(socks["a"], "a", "set setting host metric/log/leg 10", "ok")
			started["a"].wait_for(re.compile(r"metric/leg .*127\.0\.0\.1:%s," % port["b"]),
			                      "A logging its leg to B under metric/leg", within=30.0)
			print("livecheck: h: A logs its leg to B under metric/leg")
			# AND ITS METER, sec 1054: the families that carried anything, each
			# FAMILY,UP,DOWN,RATE_UP,RATE_DOWN,PEERS.
			expect(socks["a"], "a", "set setting host metric/log/meter 10", "ok")
			started["a"].wait_for(re.compile(r"metric/meter .*[a-z-]+,\d+,\d+,\d+,\d+,\d+"),
			                      "A logging its meter under metric/meter", within=30.0)
			print("livecheck: h: and its meter under metric/meter")

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

			# i: RINGING IS A STATE BOTH ENDS CHECK, sec 1062. B rings A and is stopped
			# while it rings: A, ringing in, drops the call within a few seconds of
			# B's rings stopping, where it rang on for 45. Then A rings B, gone: no
			# RINGING ever comes, and A drops it as unreachable.
			rung = ask(socks["b"], "add call ada audio").split()
			if len(rung) != 2 or rung[0] != "ok":
				raise failed("i: B's add call answered %r" % rung)
			until("i: A never held B's ring", lambda: calls(socks["a"]).get(rung[1]) == "ringing-in")
			started.pop("b").stop()
			began = time.monotonic()
			until("i: A still rang 8 s after B was stopped",
			      lambda: rung[1] not in calls(socks["a"]), 8.0)
			print("livecheck: i: B stopped while ringing, A dropped the call after %.1f s"
			      % (time.monotonic() - began))
			rung = ask(socks["a"], "add call bea audio").split()
			if len(rung) != 2 or rung[0] != "ok":
				raise failed("i: A's add call answered %r" % rung)
			began = time.monotonic()
			until("i: A still rang B, gone, after 50 s",
			      lambda: rung[1] not in calls(socks["a"]), 50.0)
			print("livecheck: i: A rang B, gone, and dropped it as unreachable after %.1f s"
			      % (time.monotonic() - began))

			# j: A RING TO A HOST RESTARTED, sec 1072. B back, rung once so A holds a
			# session with it; B restarted, and A's next ring said at once.
			def ring_reaches(phase, within):
				rung = ask(socks["a"], "add call bea audio").split()
				if len(rung) != 2 or rung[0] != "ok":
					raise failed("%s: A's add call answered %r" % (phase, rung))
				began = time.monotonic()
				until("%s: B never held A's ring" % phase,
				      lambda: calls(socks["b"]).get(rung[1]) == "ringing-in", within)
				took = time.monotonic() - began
				expect(socks["a"], "a", "set call %s hangup" % rung[1], "ok")
				until("%s: B still held the call A hung up" % phase,
				      lambda: rung[1] not in calls(socks["b"]))
				return took

			started["b"] = daemon(run, "b", dirs["b"], socks["b"],
			                      extra=["--udp-port=" + port["b"]])
			took = ring_reaches("j", 40.0)
			print("livecheck: j: B started again, A's ring held after %.1f s" % took)
			started.pop("b").stop()
			started["b"] = daemon(run, "b", dirs["b"], socks["b"],
			                      extra=["--udp-port=" + port["b"]])
			took = ring_reaches("j", 12.0)
			print("livecheck: j: B restarted, A's next ring held after %.1f s" % took)

			# k: THE RECEIVER'S RING TIME, sec 1073.
			expect(socks["b"], "b", "set setting host call/ring 5s", "ok")
			rung = ask(socks["a"], "add call bea audio").split()
			if len(rung) != 2 or rung[0] != "ok":
				raise failed("k: A's add call answered %r" % rung)
			until("k: B never held A's ring",
			      lambda: calls(socks["b"]).get(rung[1]) == "ringing-in")
			began = time.monotonic()
			until("k: A still rang B 12 s on, B ringing for 5",
			      lambda: rung[1] not in calls(socks["a"]), 12.0)
			took = time.monotonic() - began
			if took < 3.0:
				raise failed("k: A's call ended after %.1f s, before B's 5 s" % took)
			for who in ("a", "b"):
				started[who].wait_for(re.compile(r"call %s: no-answer" % rung[1]),
				                      "%s ending the call no-answer" % who.upper(), within=5.0)
			# AND A CLIENT ASKING WHY, sec 1082: both ends say it.
			for who in ("a", "b"):
				got = ask(socks[who], "get call %s" % rung[1]).strip()
				if got != "ok ended no-answer":
					raise failed("k: %s's get call answered %r, not why it ended" % (who.upper(), got))
			print("livecheck: k: B rang 5 s; both ended the call no-answer, A after %.1f s" % took)

			# l: RINGS GUARDED, sec 1074.
			expect(socks["b"], "b", "set setting host call/ring-burst 2", "ok")
			expect(socks["b"], "b", "set setting host call/ring-refill 1d", "ok")
			for _ in range(2):
				ring_reaches("l", 20.0)
			rung = ask(socks["a"], "add call bea audio").split()
			if len(rung) != 2 or rung[0] != "ok":
				raise failed("l: A's add call answered %r" % rung)
			began = time.monotonic()
			# BUSY IS SAID AT ONCE: within 4 s, before B's 5 s ring time (phase k) could
			# end the call as no-answer instead.
			until("l: A still rang B 4 s on, past B's two rings",
			      lambda: rung[1] not in calls(socks["a"]), 4.0)
			took = time.monotonic() - began
			if rung[1] in calls(socks["b"]):
				raise failed("l: B held a ring past its two")
			started["a"].wait_for(re.compile(r"call %s: busy" % rung[1]),
			                      "A ending the call busy", within=5.0)
			started["b"].wait_for(re.compile(r"refused busy: past its rings"),
			                      "B saying it refused A's rings", within=5.0)
			got = ask(socks["a"], "get call %s" % rung[1]).strip()
			if got != "ok ended busy":
				raise failed("l: A's get call answered %r, not busy" % got)
			print("livecheck: l: B let A ring twice; the third ended busy after %.1f s" % took)
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
