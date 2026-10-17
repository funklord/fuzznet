#!/usr/bin/env python3
"""A line delivered to a contact: `make livecheck`, sec 613.

Two stores over loopback, S and R, neither in the other's estate. S grants
R the contact capability and R accepts the card, so R holds the pairing it
delivers under:

    a  R writes a line to S: it goes at once, S answers held and files it
       IN under R's key, and R marks it delivered
    b  S restarted under `policy messages drop`: R's next line is refused,
       stays being sent, and S files nothing
    c  S, having no other device, settled the first line at its first pass
       after filing it; restarted with no rule, and R restarted, R offers the
       waiting line again and the first for settlement: one is held, the
       other answered settled (sec 615)

Against a daemon whose contact branch never reaches the messages, phase a
is refused in words and nothing is delivered; against one that files
regardless of the rules, phase b files.

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

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402

OFFERED_RE = re.compile(r"(\d+) line\(s\) offered to 127\.0\.0\.1: (\d+) delivered, "
                        r"(\d+) settled, (\d+) refused, (\d+) unanswered")
# A ROUND'S OWN END, after its fetches and log pass: "history pass" comes
# before them (sec 637).
ROUND_RE = ROUND_DONE_RE
LINE_1 = "31" * 16
LINE_2 = "32" * 16
# A prekey's text: version and object, a byte each, then the host's key.
PREKEY_HOST = slice(4, 68)


def offers(d):
	"""Every delivery `d` has logged, as (offered, delivered, refused, unanswered)."""
	return [tuple(int(g) for g in m.groups()) for m in OFFERED_RE.finditer(d.log())]


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


def main(argv):
	if len(argv) != 2:
		print("usage: live_deliver.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port_s = str(18000 + os.getpid() % 2000)
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in ("s", "r")}
		socks = {k: os.path.join(sock_dir, k) for k in ("s", "r")}
		for d in dirs.values():
			os.mkdir(d)
		try:
			for who in ("s", "r"):
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
			s_key = command(run, ["--fuzznet-dir=" + dirs["s"], "--prekey"], None)[PREKEY_HOST]
			r_prekey = command(run, ["--fuzznet-dir=" + dirs["r"], "--prekey"], None)
			r_key = r_prekey[PREKEY_HOST]
			s_args = ["--udp-port=" + port_s]

			# a: R delivers a line, and S files it.
			s = daemon(run, "s1", dirs["s"], socks["s"], extra=s_args)
			try:
				expect(socks["s"], "s", "add contact rory " + r_key, "ok")
				card = ask(socks["s"], "grant share rory " + r_prekey)
				if not card.startswith("ok "):
					raise failed("a: grant share answered %r" % card)
				card_path = os.path.join(scratch, "card")
				with open(card_path, "w") as f:
					f.write(card.split(" ", 1)[1])
				r = daemon(run, "r1", dirs["r"], socks["r"])
				try:
					expect(socks["r"], "r", "add contact sam " + s_key, "ok")
					expect(socks["r"], "r", "add received sam 127.0.0.1 %s %s"
					       % (port_s, card_path), "ok")
					expect(socks["r"], "r", "add message sam out %s hello%%20sam" % LINE_1, "ok")
					got = r.wait_for(OFFERED_RE, "R's delivery")
					if tuple(int(g) for g in got.groups()) != (1, 1, 0, 0, 0):
						raise failed("a: R's delivery was %r, not one line delivered"
						             % (got.groups(),))
					held = lines(socks["r"], "r", s_key)
					if held.get(LINE_1, ("", "", ""))[:2] != ("out", "delivered"):
						raise failed("a: R's line is %r" % (held,))
					filed = lines(socks["s"], "s", r_key)
					if filed != {LINE_1: ("in", "-", "hello%20sam")}:
						raise failed("a: S holds %r" % (filed,))
				finally:
					r.stop()
			finally:
				s.stop()
			print("livecheck: a: R's line was delivered, and S filed it IN under R")

			# b: S keeps no messages: refused, nothing filed.
			s = daemon(run, "s2", dirs["s"], socks["s"],
			           extra=s_args + ["--log-rule=policy messages drop"])
			try:
				r = daemon(run, "r2", dirs["r"], socks["r"])
				try:
					expect(socks["r"], "r", "add message sam out %s again" % LINE_2, "ok")
					got = r.wait_for(OFFERED_RE, "R's offer to S")
					if tuple(int(g) for g in got.groups()) != (1, 0, 0, 1, 0):
						raise failed("b: R's offer was %r, not one line refused"
						             % (got.groups(),))
					held = lines(socks["r"], "r", s_key)
					if held.get(LINE_2, ("", "", ""))[:2] != ("out", "-"):
						raise failed("b: R's refused line is %r" % (held,))
					filed = lines(socks["s"], "s", r_key)
					if LINE_2 in filed:
						raise failed("b: S, keeping no messages, filed %r" % (filed,))
				finally:
					r.stop()
			finally:
				s.stop()
			print("livecheck: b: S keeping no messages refused the line, and filed nothing")

			# c: S keeps them again: the waiting line goes, and the first,
			# settled at S -- which has no other device -- is answered so.
			s = daemon(run, "s3", dirs["s"], socks["s"], extra=s_args)
			try:
				s.wait_for(ROUND_RE, "S's round")
				r = daemon(run, "r3", dirs["r"], socks["r"])
				try:
					got = r.wait_for(OFFERED_RE, "R's re-offer")
					if tuple(int(g) for g in got.groups()) != (2, 1, 1, 0, 0):
						raise failed("c: R's re-offer was %r, not the waiting line "
						             "delivered and the first settled" % (got.groups(),))
					held = lines(socks["r"], "r", s_key)
					if held.get(LINE_1, ("", "", ""))[:2] != ("out", "settled"):
						raise failed("c: R's first line is %r" % (held,))
					filed = lines(socks["s"], "s", r_key)
					if sorted(filed) != sorted([LINE_1, LINE_2]):
						raise failed("c: S holds %r" % (filed,))
				finally:
					r.stop()
			finally:
				s.stop()
			print("livecheck: c: the waiting line was offered again and S holds both; the "
			      "first settled")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
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
	print("livecheck: a line was delivered to a contact, refused by a host keeping none, "
	      "and offered again")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
