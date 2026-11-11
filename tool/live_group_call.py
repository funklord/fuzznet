"""A call of three, A the hub between B and C: sec 1022.

Three stores over loopback, A a contact of B and of C, each host running throughout.

    a  A rings B and C at once (`add call bea,cy audio`); both hold it ringing in
    b  both answer; A holds it up
    c  A sends a frame; B and C each read it
    d  B sends a frame; A reads it, and C reads it too, A's host passing it on
    e  B hangs up; A still holds the call, and C's frame reaches A
    f  C hangs up; A holds the call no more

Against a daemon whose hub passes no member's frame on to the others, d fails at C
(run by hand, sec 1022).

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

live_trim.DEADLINE = time.monotonic() + 560.0

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


def frames(sock, call):
	got = ask(sock, "list frame %s" % call).split()
	return got[3:] if got[:1] == ["ok"] else []


def main(argv):
	if len(argv) != 2:
		print("usage: live_group_call.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = free_slot(49200, 4, 200, 3)
	port = {"a": str(base), "b": str(base + 1), "c": str(base + 2)}
	names = {"b": "bea", "c": "cy"}
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
			for who in ("b", "c"):
				card = ask(socks[who], "get card " + names[who])
				if not card.startswith("ok FZC1:"):
					raise failed("%s: get card answered %r" % (who, card))
				got = ask(socks["a"], "add contact %s %s" % (names[who], card.split(" ", 1)[1].strip()))
				if got.strip() != "ok " + keys[who]:
					raise failed("a: add contact %s answered %r" % (names[who], got))
				until("%s never kept A's request" % who.upper(),
				      lambda: ask(socks[who], "grant request %s ada" % keys["a"]) == "ok", 30.0)
			two = re.compile(HOSTS_RE.pattern.replace("([1-9]\\d*)", "([2-9]|[1-9]\\d+)"))
			started["a"].wait_for(two, "A holding both hosts", within=HOSTS_S)
			for who in ("b", "c"):
				started[who].wait_for(HOSTS_RE, "%s holding A's host" % who.upper(), within=HOSTS_S)

			# a: A RINGS B AND C.
			rung = ask(socks["a"], "add call bea,cy audio").split()
			if len(rung) != 2 or rung[0] != "ok":
				raise failed("a: add call answered %r" % rung)
			call = rung[1]
			for who in ("b", "c"):
				until("a: %s never held the call ringing in" % who.upper(),
				      lambda: calls(socks[who]).get(call) == "ringing-in")
			print("livecheck: a: A rang B and C at once, and both hold it ringing in")

			# b: BOTH ANSWER.
			for who in ("b", "c"):
				expect(socks[who], who, "set call %s answer" % call, "ok")
			until("b: A never held the call up", lambda: calls(socks["a"]).get(call) == "up")
			print("livecheck: b: B and C answered, and A holds the call up")

			def sends(frm, seq, to):
				said = ask(socks[frm], "add frame %s 1 %d 500 0 1 %02x" % (call, seq, seq))
				if said not in ("ok sent", "ok lost"):
					raise failed("%s: add frame answered %r" % (frm, said))
				want = "1,%d,500,0,1,%02x" % (seq, seq)
				for t in to:
					until("%s never read %s's frame %d" % (t.upper(), frm.upper(), seq),
					      lambda: want in frames(socks[t], call))

			# c: A'S FRAME TO BOTH; d: B'S TO A AND, THROUGH A, TO C.
			sends("a", 1, ("b", "c"))
			print("livecheck: c: A sent a frame, and B and C each read it")
			sends("b", 2, ("a", "c"))
			print("livecheck: d: B sent a frame, and A read it, and C, A's host passing it on")

			# e: B HANGS UP; THE CALL GOES ON.
			expect(socks["b"], "b", "set call %s hangup" % call, "ok")
			until("e: B still held the call", lambda: call not in calls(socks["b"]))
			if calls(socks["a"]).get(call) != "up":
				raise failed("e: A did not keep the call up with C still in it")
			sends("c", 3, ("a",))
			print("livecheck: e: B hung up, and A and C went on, C's frame reaching A")

			# f: C HANGS UP; THE CALL ENDS.
			expect(socks["c"], "c", "set call %s hangup" % call, "ok")
			until("f: A still held the call", lambda: call not in calls(socks["a"]))
			print("livecheck: f: C hung up too, and A holds the call no more")
		except failed as e:
			print("livecheck: FAILED -- %s" % e, file=sys.stderr)
			return 1
		finally:
			for who in ("a", "b", "c"):
				if who in started:
					started[who].stop()
	print("livecheck: a call of three was carried through its hub")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
