#!/usr/bin/env python3
"""Any device of a user delivers to any host of a contact: `make livecheck`,
sec 614.

Four stores over loopback, two users of two machines each: S, a root, with
S2 joined to it; R, a root, with R2 joined to it. S grants R the contact
capability and R accepts the card -- the one pairing a contact relation
starts with. S and S2 each set `net/address`, S at metric 10 and S2 at 20,
and S's estate advertises.

    a  R's round offers R and R2 to S and takes S's hosts; S2, restarted,
       takes R's devices from S and pairs them; R2, which was never paired
       with anybody of S's, takes S's hosts from R. R2 writes a line to S:
       it is delivered, and S files it IN under R's root -- the user, not
       the device that sent it
    b  S restarted under `policy messages drop`, R2 restarted with S's
       manifest now held: its next line is refused by S, the host of lower
       metric, and held by S2, which files it under R's root too
    c  S keeps messages again: each of S and S2 settles the line it filed
       once the other holds it, and R2, offering both again, is answered
       settled and marks them so (sec 615)
    d  R2, given an address so R hears it, writes a line while S's estate
       is down, then falls silent past R's `archive/gone`: R takes the line
       over and delivers it once S is back (sec 616)

Against a daemon that carries no contact devices, R2 has no host to offer
to and phase a waits in vain; against one that files under the sending
device, phase a's listing under R's root is empty.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import re
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

# FOUR DAEMONS RESTARTED IN TURN, phases c and d most of all, take longer
# than the 240 s the other checks are held to; still one deadline.
live_trim.DEADLINE = time.monotonic() + 420.0

OFFERED_RE = re.compile(r"(\d+) line\(s\) offered to 127\.0\.0\.1: (\d+) delivered, "
                        r"(\d+) settled, (\d+) refused, (\d+) unanswered")
# A ROUND'S OWN END, after its fetches and log pass: "history pass" comes
# before them (sec 637).
ROUND_END_RE = ROUND_DONE_RE
PASS_RE = re.compile(r"contact pass: (\d+) contact\(s\) asked, (\d+) kept from members, "
                     r"(\d+) paired, (\d+) host\(s\) to deliver to")
LINE_1 = "41" * 16
LINE_2 = "42" * 16
LINE_3 = "43" * 16
PREKEY_HOST = slice(4, 68)


def lines(sock, who, key):
	"""`who`'s lines with `key`, as {id: (direction, state, text)}."""
	reply = ask(sock, "list message " + key)
	head = reply.split("\n", 1)[0].split(" ")
	if len(head) < 4 or head[0] != "ok":
		raise failed("%s: list message answered %r" % (who, reply))
	out = {}
	for row in reply.split(" ", 4)[4:] if head[2] != "0" else []:
		for line in row.split(" "):
			f = line.split(",", 8)
			if len(f) == 9:
				out[f[2]] = (f[3], f[4], f[8])
	return out


def said(*ds):
	"""What each daemon said about contacts, routing and delivery, last lines."""
	out = []
	for d in ds:
		lines_ = [l for l in d.log().splitlines()
		          if any(w in l for w in ("messages/deliver", "contact", "routing", "node/peer",
		                                  "refused"))]
		out += ["\n  %s: %s" % (d.tag, l[-200:]) for l in lines_[-8:]]
	return "".join(out)


def passes(d):
	return [tuple(int(g) for g in m.groups()) for m in PASS_RE.finditer(d.log())]


def offers(d):
	return [tuple(int(g) for g in m.groups()) for m in OFFERED_RE.finditer(d.log())]


def main(argv):
	if len(argv) != 2:
		print("usage: live_contacts.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 10000 + (os.getpid() % 500) * 4
	port = {"s": str(base), "s2": str(base + 1), "r": str(base + 2), "r2": str(base + 3)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		names = ("s", "s2", "r", "r2")
		dirs = {k: os.path.join(scratch, k) for k in names}
		socks = {k: os.path.join(sock_dir, k) for k in names}
		for d in dirs.values():
			os.mkdir(d)
		args = {
			"s": ["--udp-port=" + port["s"]],
			"s2": ["--udp-port=" + port["s2"], "--root-at", "127.0.0.1", port["s"]],
			"r": ["--udp-port=" + port["r"]],
			"r2": ["--udp-port=" + port["r2"], "--root-at", "127.0.0.1", port["r"]],
		}
		started = {}

		def up(who, tag, extra=()):
			started[who] = daemon(run, tag, dirs[who], socks[who], extra=args[who] + list(extra))
			return started[who]

		def down(who):
			started.pop(who).stop()

		try:
			keys = {}
			for root, member in (("s", "s2"), ("r", "r2")):
				command(run, ["--fuzznet-dir=" + dirs[root], "--new-root"], None)
				keys[root] = command(run, ["--fuzznet-dir=" + dirs[root], "--prekey"],
				                     None)[PREKEY_HOST]
				prekey = command(run, ["--fuzznet-dir=" + dirs[member], "--prekey"], None)
				keys[member] = prekey[PREKEY_HOST]
				card = command(run, ["--fuzznet-dir=" + dirs[root], "--pair=" + prekey,
				                     "--delegable"], None)
				command(run, ["--fuzznet-dir=" + dirs[member], "--accept=" + card, "--join"],
				        None)
			r_prekey = command(run, ["--fuzznet-dir=" + dirs["r"], "--prekey"], None)

			# S's estate: addresses, metrics, advertised; the contact and its card.
			s = up("s", "s1")
			s2 = up("s2", "s2a")
			# A MEMBER'S SETTING once its first round is over: it is allowed by the
			# grant that round brings, and a round answers mid-way (sec 637).
			s2.wait_for(ROUND_END_RE, "S2's first round")
			expect(socks["s2"], "s2", "set setting host net/address 127.0.0.1 " + port["s2"],
			       "ok")
			expect(socks["s2"], "s2", "set setting host net/metric 20", "ok")
			down("s2")
			expect(socks["s"], "s", "set setting host net/address 127.0.0.1 " + port["s"], "ok")
			expect(socks["s"], "s", "set setting host net/metric 10", "ok")
			expect(socks["s"], "s", "set setting estate routing/advertise 1", "ok")
			expect(socks["s"], "s", "add contact rory " + keys["r"], "ok")
			card = ask(socks["s"], "grant share rory " + r_prekey)
			if not card.startswith("ok "):
				raise failed("grant share answered %r" % card)
			card_path = os.path.join(scratch, "card")
			with open(card_path, "w") as f:
				f.write(card.split(" ", 1)[1])
			s2 = up("s2", "s2b")
			s2.wait_for(PASS_RE, "S2's round")
			down("s")
			s = up("s", "s2nd")
			s.wait_for(PASS_RE, "S's round")

			# a: R offers its devices; S2 and R2 learn from their members.
			r = up("r", "r1")
			expect(socks["r"], "r", "add contact sam " + keys["s"], "ok")
			# FOR PHASE d: a device of R's silent 3 s is gone. R hears R2 only
			# once R2 has an address, which is phase d's.
			expect(socks["r"], "r", "set setting estate archive/gone 3s", "ok")
			expect(socks["r"], "r", "add received sam 127.0.0.1 %s %s" % (port["s"], card_path),
			       "ok")
			# R2 once, so its prekey reaches R in R2's estate stream.
			r2 = up("r2", "r2pre")
			r2.wait_for(PASS_RE, "R2's first round")
			down("r2")
			down("r")
			r = up("r", "r2nd")
			r.wait_for(PASS_RE, "R's contact pass")
			if passes(r)[0][0] != 1:
				raise failed("a: R's pass asked %d contact(s), not S%s"
				             % (passes(r)[0][0], said(r, s)))
			down("s2")
			s2 = up("s2", "s2c")
			s2.wait_for(PASS_RE, "S2's contact pass")
			got = passes(s2)[0]
			if got[1] < 2 or got[2] < 2:
				raise failed("a: S2 kept %d of R's devices from S and paired %d" % got[1:3])
			# LISTED AS KEPT, sec 645: R's two hosts under R, its user -- by
			# name at S, and by R's key at S2, which names nobody R.
			for who, line in (("s", "list device rory"), ("s2", "list device " + keys["r"])):
				listed = ask(socks[who], line).split()
				if len(listed) < 3 or listed[:3] != ["ok", "2", "0"] \
				   or {row.split(",")[0] for row in listed[3:]} != {keys["r"], keys["r2"]}:
					raise failed("a: %s's %s answered %r, not R's and R2's hosts"
					             % (who.upper(), line, listed))
			r2 = up("r2", "r2a")
			got = r2.wait_for(PASS_RE, "R2's contact pass")
			if int(got.group(4)) != 2:
				raise failed("a: R2 holds %s host(s) of S to deliver to, not S and S2"
				             % got.group(4))
			expect(socks["r2"], "r2", "add message %s out %s from%%20r2" % (keys["s"], LINE_1),
			       "ok")
			# WHICHEVER HOST FIRST: R2 holds no manifest of S's yet, so the
			# order is the store's. Every offer is answered and one holds.
			r2.wait_for(re.compile(r"line\(s\) offered to 127\.0\.0\.1: 1 delivered"),
			            "R2's delivery")
			if any(o[4] for o in offers(r2)):
				raise failed("a: an offer of R2's went unanswered: %r%s"
				             % (offers(r2), said(r2, s, s2)))
			filed = {}
			for who in ("s", "s2"):
				filed.update(lines(socks[who], who, keys["r"]))
				if lines(socks[who], who, keys["r2"]):
					raise failed("a: %s filed R2's line under R2, a device, not its user"
					             % who.upper())
			if filed.get(LINE_1) != ("in", "-", "from%20r2"):
				raise failed("a: S and S2 hold %r under R's root" % (filed,))
			print("livecheck: a: R2, paired by nobody of S's, delivered a line to S's "
			      "estate, filed under R's root")

			# b: S keeps none; S2, of higher metric, takes it.
			down("s")
			s = up("s", "s3", ["--log-rule=policy messages drop"])
			down("r2")
			r2 = up("r2", "r2b")
			r2.wait_for(PASS_RE, "R2's contact pass")
			expect(socks["r2"], "r2", "add message %s out %s again" % (keys["s"], LINE_2), "ok")
			r2.wait_for(re.compile(r"line\(s\) offered to 127\.0\.0\.1: 1 delivered"),
			            "R2's delivery to S2")
			# REFUSED BY S FIRST, whatever else R2 offered: its restart also
			# offers the first line again for settlement (sec 615).
			if not any(o[3] for o in offers(r2)):
				raise failed("b: R2's offers were %r, none refused by S%s"
				             % (offers(r2), said(r2, s, s2)))
			filed = lines(socks["s2"], "s2", keys["r"])
			if filed.get(LINE_2) != ("in", "-", "again"):
				raise failed("b: S2 holds %r under R's root" % (filed,))
			print("livecheck: b: S, keeping none, refused; S2, next by metric, held the line")

			# c: settlement. Each host settles the line it filed once the
			# other holds it; R2's next round, offering both again, is
			# answered settled. Hosts restarted in turn, so each round pulls
			# what the other took; a few turns at most.
			down("s")
			s = up("s", "s4")
			states = {}
			for turn in range(4):
				for who in ("s2", "s"):
					down(who)
					d = up(who, "%s-c%d" % (who, turn))
					d.wait_for(ROUND_END_RE, "%s's round" % who.upper())
				down("r2")
				r2 = up("r2", "r2-c%d" % turn)
				r2.wait_for(ROUND_END_RE, "R2's round")
				held = lines(socks["r2"], "r2", keys["s"])
				states = {k: held.get(k, ("", "", ""))[1] for k in (LINE_1, LINE_2)}
				if set(states.values()) == {"settled"}:
					break
			if set(states.values()) != {"settled"}:
				raise failed("c: after %d turns R2's lines are %r%s"
				             % (turn + 1, states, said(r2, started["s"], started["s2"])))
			print("livecheck: c: both lines settled at S's estate, and R2 was told so in "
			      "%d turn(s)" % (turn + 1))

			# d: a writer gone (sec 616). R2, given an address so R hears
			# it, writes a line while S's estate is down; R2 then falls
			# silent past R's `archive/gone`, and R takes the line over and
			# delivers it once S is back.
			down("s")
			down("s2")
			expect(socks["r2"], "r2", "set setting host net/address 127.0.0.1 " + port["r2"],
			       "ok")
			expect(socks["r2"], "r2", "add message %s out %s orphaned" % (keys["s"], LINE_3),
			       "ok")
			r2.wait_for(re.compile(r"line\(s\) offered to 127\.0\.0\.1: 0 delivered, 0 settled, "
			                       r"0 refused, 1 unanswered"), "R2's offer to nobody")
			down("r2")
			r2 = up("r2", "r2-d")
			r2.wait_for(ROUND_END_RE, "R2's round, pushing the line to R")
			down("r")
			r = up("r", "r-d1")
			# 60 S, NOT 30: with S's estate down R's round spends a deadline on
			# each of S's hosts, then on the relays it may try, its own among
			# them since sec 697 -- measured at 28 s and climbing.
			r.wait_for(ROUND_END_RE, "R's round, hearing R2", within=60.0)
			down("r")
			down("r2")
			time.sleep(4.0)
			for who in ("s", "s2"):
				d = up(who, "%s-d" % who)
				d.wait_for(ROUND_END_RE, "%s's round" % who.upper())
			r = up("r", "r-d2")
			got = r.wait_for(re.compile(r"line\(s\) offered to 127\.0\.0\.1: 1 delivered"),
			                 "R's delivery of R2's line")
			filed = {}
			for who in ("s", "s2"):
				filed.update(lines(socks[who], who, keys["r"]))
			if filed.get(LINE_3, ("", "", ""))[2] != "orphaned":
				raise failed("d: S's estate holds %r%s" % (filed, said(r)))
			print("livecheck: d: R took over the line R2 wrote and fell silent on, and "
			      "delivered it")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			if os.environ.get("LIVE_DEBUG"):
				import shutil
				dst = os.environ["LIVE_DEBUG"]
				for name in os.listdir(scratch):
					if name.startswith("log-"):
						shutil.copytree(os.path.join(scratch, name), os.path.join(dst, name),
						                dirs_exist_ok=True)
					elif name.endswith(".err"):
						shutil.copy(os.path.join(scratch, name), dst)
			if os.environ.get("LIVE_DEBUG") and "s2" in started:
				print("S2 list peer: %r" % ask(socks["s2"], "list peer")[:900])
				print("keys: %r" % {k: v[:16] for k, v in keys.items()})
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
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: a member delivered to a contact's hosts it learned through its estate, "
	      "in metric order")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
