#!/usr/bin/env python3
"""A line relayed to a host nobody else reaches: `make livecheck`, sec 622.

Three stores over loopback. A is one user's one machine. B1 and B2 are
another's: B1, the root, is reached at its address, keeps no messages and
relays; B2, joined to B1, advertises an address nobody listens on -- as a
host behind a NAT would -- and says hello to B1 from its serving socket.

    a  A asks B for contact by B1's card, and B1 approves; the rounds pair
       A with B1 and B2, and A holds both hosts to deliver to
    b  A writes a line to B: B1 refuses it, keeping none; B2 does not
       answer at the address it advertised; A asks B1 to relay it to B2,
       and B2 holds the line under A's root
    c  A writes a second line while B's hosts are away, so the delivery a
       fresh write makes at once reaches nobody -- answering A's own client
       while it waits for them; once they are back, A's own
       round relays it -- the round's delivery, a conversation of its own
       (sec 637), and not the one between rounds
    d  A writes a third line: B2, reached only through B1 a moment ago,
       is passed over rather than offered it at the address that went
       unanswered, and the line is relayed at once (sec 699)
    e  B1's relay quota set to what A has had relayed: A's fourth line is
       refused, and A hears why from B1 at once rather than waiting out
       B2's answer (sec 754); B1's window set to a second, it rolls over
       and A's round relays the line
    f  B1 killed by SIGKILL as A's fifth line goes through it; started
       again, B2's next hello tells it where B2 is, and A's rounds relay the
       line, which B2 lists once (secs 757, 759)

`--skew S` runs B1 S seconds ahead and B2 S behind, by faketime (sec 757).

Against a daemon that relays nothing, phase b never delivers; against one
whose relay sends the answer nowhere, it waits out each offer.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

LOSS = int(os.environ.get("FZN_FAULT_LOSS", "0") or 0)
live_trim.DEADLINE = time.monotonic() + 420.0 + 20.0 * LOSS

PASS_RE = re.compile(r"contact pass: (\d+) contact\(s\) asked, (\d+) kept from members, "
                     r"(\d+) paired, (\d+) host\(s\) to deliver to")
KEPT_RE = re.compile(r"a contact request from ([0-9a-f]{16}), waiting")
RELAYED_RE = re.compile(r"line\(s\) offered to 127\.0\.0\.1 through 127\.0\.0\.1: 1 delivered")
# A ROUND'S OWN END, after its fetches and log pass: "history pass" comes
# before them (sec 637).
ROUND_END_RE = ROUND_DONE_RE
LINE = "61" * 16
LATER = "62" * 16
FINAL = "63" * 16
FOURTH = "64" * 16
FIFTH = "65" * 16
QUOTA_RE = re.compile(r"the relay to 127\.0\.0\.1 refused: over this host's relay quota")
PASSED_RE = re.compile(r"127\.0\.0\.1 passed over: reached only through a relay lately")
NOBODY_RE = re.compile(r"line\(s\) offered to 127\.0\.0\.1: 0 delivered, 0 settled, 0 refused, "
                       r"1 unanswered")
PREKEY_HOST = slice(4, 68)


def free(port):
	"""Whether UDP `port` can be bound now, on every address as the daemon
	binds it: live_chat.py's check (sec 743)."""
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		s.bind(("", port))
		return True
	except OSError:
		return False
	finally:
		s.close()


def main(argv):
	# `--skew S`, sec 757: B1, the relay, S seconds ahead and B2, the host it
	# relays to, S behind, by faketime -- every clock of the three apart.
	skew = 0
	if len(argv) == 4 and argv[2] == "--skew" and argv[3].isdigit():
		skew = int(argv[3])
	elif len(argv) != 2:
		print("usage: live_relay.py PATH_TO_FUZZNETD [--skew S]", file=sys.stderr)
		return 2
	skews = {}
	if skew:
		if not shutil.which("faketime"):
			print("livecheck: relay SKIPPED -- --skew needs faketime on PATH")
			return 0
		skews = {"b1": "+%ds" % skew, "b2": "-%ds" % skew}

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	# A SLOT ALL FREE, from the pid's on, as live_chat.py takes its own (sec
	# 743): one run in three at 20 per cent loss, sec 756, met B1's port held
	# and its daemon could not bind.
	base = None
	for t in range(500):
		at = 6000 + ((os.getpid() + t) % 500) * 4
		if all(free(at + i) for i in range(4)):
			base = at
			break
	if base is None:
		raise SystemExit("livecheck: FAILED -- no slot of four free ports in 6000-7999")
	port = {"a": str(base), "b1": str(base + 1), "b2": str(base + 2), "nobody": str(base + 3)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		names = ("a", "b1", "b2")
		dirs = {k: os.path.join(scratch, k) for k in names}
		socks = {k: os.path.join(sock_dir, k) for k in names}
		args = {
			"a": ["--udp-port=" + port["a"]],
			"b1": ["--udp-port=" + port["b1"], "--log-rule=policy messages drop"],
			"b2": ["--udp-port=" + port["b2"], "--root-at", "127.0.0.1", port["b1"]],
		}
		started = {}

		def up(who, tag):
			started[who] = daemon(run, tag, dirs[who], socks[who], fake=skews.get(who),
			                      extra=args[who])
			return started[who]

		def down(who):
			started.pop(who).stop()

		def killed(who):
			"""`who` killed by SIGKILL, no cleanup, as a power cut would."""
			d = started.pop(who)
			try:
				os.killpg(d.proc.pid, signal.SIGKILL)
			except ProcessLookupError:
				pass
			d.proc.wait(timeout=10)

		def turn(who, tag):
			if who in started:
				down(who)
			d = up(who, tag)
			d.wait_for(ROUND_END_RE, "%s's round" % who.upper())
			return d

		try:
			keys = {}
			for who in names:
				os.mkdir(dirs[who])
			for who in ("a", "b1"):
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], skews.get(who))
				keys[who] = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"],
				                    skews.get(who))[PREKEY_HOST]
			prekey = command(run, ["--fuzznet-dir=" + dirs["b2"], "--prekey"], skews.get("b2"))
			keys["b2"] = prekey[PREKEY_HOST]
			card = command(run, ["--fuzznet-dir=" + dirs["b1"], "--pair=" + prekey,
			                     "--delegable"], skews.get("b1"))
			command(run, ["--fuzznet-dir=" + dirs["b2"], "--accept=" + card, "--join"],
			        skews.get("b2"))

			# B's estate: B1 reached and relaying; B2 advertising nowhere.
			up("b1", "b1a")
			expect(socks["b1"], "b1", "set setting host net/address 127.0.0.1 " + port["b1"], "ok")
			expect(socks["b1"], "b1", "set setting host relay/enabled 1", "ok")
			expect(socks["b1"], "b1", "set setting estate routing/advertise 1", "ok")
			# A MEMBER'S SETTING once its first round is over: it is allowed by the
			# grant that round brings, and a round answers mid-way (sec 637).
			up("b2", "b2a").wait_for(ROUND_END_RE, "B2's first round")
			expect(socks["b2"], "b2", "set setting host net/address 127.0.0.1 " + port["nobody"],
			       "ok")
			turn("b2", "b2b")
			turn("b1", "b1b")
			up("a", "a1")
			expect(socks["a"], "a", "set setting host net/address 127.0.0.1 " + port["a"], "ok")

			# a: A asks B by B1's card; B1 approves; the rounds pair them.
			got = ask(socks["b1"], "get card bee")
			if not got.startswith("ok FZC1:"):
				raise failed("a: get card answered %r" % got)
			got = ask(socks["a"], "add contact bee " + got.split(" ", 1)[1].strip())
			if got.strip() != "ok " + keys["b1"]:
				raise failed("a: add contact by card answered %r" % got)
			started["b1"].wait_for(KEPT_RE, "B1 keeping A's request")
			expect(socks["b1"], "b1", "grant request %s aye" % keys["a"], "ok")
			hosts = 0
			for rnd in range(4):
				turn("b1", "b1-r%d" % rnd)
				turn("b2", "b2-r%d" % rnd)
				d = turn("a", "a-r%d" % rnd)
				got = [int(m.group(4)) for m in PASS_RE.finditer(d.log())]
				hosts = got[-1] if got else 0
				if hosts == 2:
					break
			if hosts != 2:
				raise failed("a: after %d rounds A holds %d host(s) of B to deliver to"
				             % (rnd + 1, hosts))
			print("livecheck: a: A and B paired by B1's card, A holding B1 and B2")

			# b: the line, relayed through B1 to B2.
			turn("b2", "b2-c")
			expect(socks["a"], "a", "add message %s out %s relayed" % (keys["b1"], LINE), "ok")
			try:
				started["a"].wait_for(RELAYED_RE, "A's line relayed through B1")
			except failed:
				turn("b2", "b2-d")
				d = turn("a", "a-d")
				d.wait_for(RELAYED_RE, "A's line relayed through B1")
			reply = ask(socks["b2"], "list message " + keys["a"])
			if LINE not in reply:
				raise failed("b: B2 holds %r under A's root" % reply)
			print("livecheck: b: B1 refused the line and relayed it to B2, which holds it")
			# AND B1 SAYS SO (sec 638): relaying, and A's frames counted.
			got = ask(socks["b1"], "get relay").split()
			if len(got) < 5 or got[0] != "ok" or got[1] != "1" \
			   or not any(e.startswith(keys["a"] + ",") and int(e.split(",")[1]) > 0
			              for e in got[5:]):
				raise failed("b: B1's get relay answered %r, not A's frames relayed" % got)

			# c: a line written while B's hosts are away, relayed by A's round.
			down("b1")
			down("b2")
			before = len(NOBODY_RE.findall(started["a"].log()))
			expect(socks["a"], "a", "add message %s out %s later" % (keys["b1"], LATER), "ok")
			# ANSWERED WHILE THAT DELIVERY WAITS, sec 637: it waits out B's two
			# hosts, 3 s each, and the loop answers meanwhile. One that answered
			# only after would have logged the delivery's end first -- counted
			# past phase b's own, logged by the same daemon.
			try:
				reply = ask(socks["a"], "list message " + keys["b1"])
			except OSError as e:
				raise failed("c: A did not answer while its delivery waited: %s" % e)
			if not reply.startswith("ok ") \
			   or len(NOBODY_RE.findall(started["a"].log())) > before:
				raise failed("c: A answered %r only once its delivery to nobody was over"
				             % reply[:40])
			until = time.monotonic() + 30.0
			while len(NOBODY_RE.findall(started["a"].log())) == before:
				if time.monotonic() > until:
					raise failed("c: A's delivery to nobody was not logged within 30 s")
				time.sleep(0.2)
			turn("b1", "b1e")
			turn("b2", "b2e")
			# AS MANY AS FOUR OF A'S ROUNDS, and half the loss more (sec 756): started
			# again, B2 says hello to B1 once and then every 20 s, and a hello
			# lost leaves B1 refusing -- "that host has not said where it is",
			# answered to A now (sec 754) -- until the next.
			for rnd in range(4 + LOSS // 2):
				d = turn("a", "a-e%d" % rnd)
				try:
					d.wait_for(RELAYED_RE, "A's round relaying the second line through B1")
					break
				except failed:
					if rnd == 3 + LOSS // 2:
						raise
					turn("b2", "b2e%d" % rnd)
			reply = ask(socks["b2"], "list message " + keys["a"])
			if LATER not in reply:
				raise failed("c: B2 holds %r under A's root" % reply)
			print("livecheck: c: A's own round relayed a line written while B was away")

			# d: the relay first, B2's own address not asked again.
			log = d.log()
			nobody, relayed = len(NOBODY_RE.findall(log)), len(RELAYED_RE.findall(log))
			expect(socks["a"], "a", "add message %s out %s final" % (keys["b1"], FINAL), "ok")
			# UNDER LOSS, A'S OWN ROUNDS AFTER (sec 756): the fresh delivery's
			# relayed attempt and its resends can all be lost at 20 per cent,
			# and A's next round, the same daemon, relays what it left. What
			# phase d holds is that B2's own address is not asked again,
			# whichever relays it.
			until = time.monotonic() + 30.0 + 4.0 * LOSS
			while len(RELAYED_RE.findall(d.log())) == relayed:
				if time.monotonic() > until:
					raise failed("d: A's third line was not relayed within %d s"
					             % (30 + 4 * LOSS))
				time.sleep(0.2)
			log = d.log()
			if not PASSED_RE.search(log) or len(NOBODY_RE.findall(log)) != nobody:
				raise failed("d: A offered B2 the line at its own address again: %d offer(s) "
				             "to nobody, passed over %s"
				             % (len(NOBODY_RE.findall(log)) - nobody, bool(PASSED_RE.search(log))))
			if FINAL not in ask(socks["b2"], "list message " + keys["a"]):
				raise failed("d: B2 does not hold the third line")
			print("livecheck: d: A relayed its third line to B2 at once, not asking B2's own "
			      "address again")

			# e: B1's quota spent, its refusal answered to A, and its window
			# rolled over (sec 754, sec 689's journey 4). The quota set to
			# what A has had relayed, so A's next frame is past it.
			got = ask(socks["b1"], "get relay").split()
			used = [int(e.split(",")[1]) for e in got[5:] if e.startswith(keys["a"] + ",")]
			if not used or used[0] <= 0:
				raise failed("e: B1's get relay answered %r, no bytes for A" % got)
			expect(socks["b1"], "b1", "set setting host relay/quota %d" % used[0], "ok")
			refused = len(QUOTA_RE.findall(started["a"].log()))
			expect(socks["a"], "a", "add message %s out %s spent" % (keys["b1"], FOURTH), "ok")
			until = time.monotonic() + 30.0
			while len(QUOTA_RE.findall(started["a"].log())) == refused:
				if time.monotonic() > until:
					raise failed("e: A did not hear B1's refusal over its quota within 30 s")
				time.sleep(0.2)
			if FOURTH in ask(socks["b2"], "list message " + keys["a"]):
				raise failed("e: B2 holds the fourth line though B1's quota was spent")
			got = ask(socks["b1"], "get relay").split()
			if not any(e.startswith(keys["a"] + ",") and int(e.split(",")[2]) > 0
			           for e in got[5:]):
				raise failed("e: B1's get relay answered %r, no refusal counted for A" % got)
			print("livecheck: e: B1 refused A over its quota, and A heard why")
			relayed = len(RELAYED_RE.findall(started["a"].log()))
			expect(socks["b1"], "b1", "set setting host relay/window 1", "ok")
			time.sleep(1.5)
			for rnd in range(4):
				turn("b2", "b2-f%d" % rnd)
				d = turn("a", "a-f%d" % rnd)
				if len(RELAYED_RE.findall(d.log())) > relayed:
					break
			if FOURTH not in ask(socks["b2"], "list message " + keys["a"]):
				raise failed("e: B2 does not hold the fourth line after B1's window rolled over")
			print("livecheck: e: B1's window rolled over and the fourth line was relayed")

			# f: the relay killed with a line on its way through it (sec 757,
			# tags of its own, sec 759: phase e's `a-f%d` reused, a round's end
			# was read from e's lines in the same log and A stopped at once),
			# sec 689's restart inside an operation): A writes its fifth line
			# and B1 dies by SIGKILL at once, its tables of where B2 was seen
			# gone with it. Started again, B2's next hello tells it, and A's
			# rounds relay the line, which B2 then holds once.
			expect(socks["b1"], "b1", "set setting host relay/quota 0", "ok")
			expect(socks["a"], "a", "add message %s out %s killed" % (keys["b1"], FIFTH), "ok")
			killed("b1")
			up("b1", "b1g").wait_for(ROUND_END_RE, "B1's round after its kill")
			got_it = False
			for rnd in range(4 + LOSS // 2):
				turn("b2", "b2-g%d" % rnd)
				turn("a", "a-g%d" % rnd)
				listed = ask(socks["b2"], "list message " + keys["a"])
				if FIFTH in listed:
					got_it = True
					break
			if not got_it:
				raise failed("f: B2 does not hold the fifth line after B1 was killed and started "
				             "again\n  B2 lists %r\n  A lists %r"
				             % (listed[:400], ask(socks["a"], "list message " + keys["b1"])[:400]))
			if listed.count("," + FIFTH + ",") != 1:
				raise failed("f: B2 lists the fifth line %d times: %r"
				             % (listed.count("," + FIFTH + ","), listed[:300]))
			print("livecheck: f: B1 killed with A's fifth line on its way; started again, the "
			      "line reached B2 once")
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
	print("livecheck: a line was relayed to a host nobody else reaches")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
