#!/usr/bin/env python3
"""A removed contact's shares are pulled no further: `make livecheck`, sec 576.

Two stores over loopback, S sharing and R receiving, neither in the
other's estate:

    a  S adds R as a contact, shares a note with it and grants the share
       to R's prekey; R adds S and accepts the card. R's received pass
       pulls the note from S. R removes S, and S edits the note
    b  R is restarted: its pass holds the share and passes it over -- "1 of
       removed contacts passed over" -- and the edit is not pulled. What
       was received is kept
    c  R adds S back and is restarted: the pass passes nothing over, and
       the edit is pulled
    d  R writes a line to S and marks it handed over: restarted with S
       standing, it stays handed over; S removed and R restarted, the round
       marks it not delivered -- "1 line(s) handed over for a contact that
       no longer stands" -- which the device that handed it off reads
       (sec 607)

Against a daemon that does not ask whether a sharer still stands, phase b
pulls; against one that never asks again, phase c does not.

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

PASS_RE = re.compile(r"received pass: (\d+) share\(s\), (\d+) of removed contacts passed over")
PULLED_RE = re.compile(r"(\d+) shared note record\(s\) from 127\.0\.0\.1")
# A ROUND'S OWN END, after its fetches and log pass: "history pass" comes
# before them (sec 637).
ROUND_END_RE = ROUND_DONE_RE
GIVEN_UP_RE = re.compile(r"(\d+) line\(s\) handed over or still being sent for a contact "
                         r"that no longer stands")
LINE_ID = "02" + "00" * 15
# A prekey's text: version and object, a byte each, then the host's key.
PREKEY_HOST = slice(4, 68)


def passes(d):
	"""Every received pass `d` has logged, as (shares, passed over)."""
	return [(int(m.group(1)), int(m.group(2))) for m in PASS_RE.finditer(d.log())]


def main(argv):
	if len(argv) != 2:
		print("usage: live_shares.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port_s = str(26000 + os.getpid() % 2000)
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

			s = daemon(run, "s1", dirs["s"], socks["s"], extra=["--udp-port=" + port_s])
			try:
				# a: S shares a note with R, and R pulls it.
				expect(socks["s"], "s", "add contact rory " + r_key, "ok")
				note = ask(socks["s"], "add note top shared-note")
				if not note.startswith("ok "):
					raise failed("a: add note answered %r" % note)
				expect(socks["s"], "s", "add share %s rory" % note.split()[1], "ok")
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
					r.wait_for(PULLED_RE, "pull from S")
					expect(socks["r"], "r", "remove contact sam", "ok")
				finally:
					r.stop()
				expect(socks["s"], "s", "set note %s text edited-away" % note.split()[1], "ok")
				print("livecheck: a: R pulled the note S shares and removed S; S edited it")

				# b: S removed: the share is held and passed over.
				r = daemon(run, "r2", dirs["r"], socks["r"])
				try:
					r.wait_for(PASS_RE, "received pass")
					if passes(r)[0] != (1, 1):
						raise failed("b: R's first pass was %d share(s), %d passed over; "
						             "the one share's sharer is removed" % passes(r)[0])
					if PULLED_RE.search(r.log()):
						raise failed("b: R pulled S's edit, S being a removed contact")
					expect(socks["r"], "r", "add contact sam " + s_key, "ok")
				finally:
					r.stop()
				print("livecheck: b: removed, S's share was held and passed over, "
				      "nothing pulled")

				# c: S back: the share is pulled again.
				r = daemon(run, "r3", dirs["r"], socks["r"])
				try:
					r.wait_for(PULLED_RE, "pull of S's edit")
					if passes(r)[0] != (1, 0):
						raise failed("c: R's first pass was %d share(s), %d passed over; "
						             "S stands again" % passes(r)[0])
				finally:
					r.stop()
				print("livecheck: c: added back, S's edit was pulled")

				# d: a hand-off given up on, sec 607.
				def state():
					"""The state of R's one line to S, by S's key."""
					reply = ask(socks["r"], "list message " + s_key)
					fields = reply.split(" ", 4)
					if len(fields) < 5 or fields[0] != "ok" or fields[2] != "1":
						raise failed("d: list message answered %r" % reply)
					return fields[4].split(",")[4]

				r = daemon(run, "r4", dirs["r"], socks["r"])
				try:
					r.wait_for(ROUND_END_RE, "R's round")
					expect(socks["r"], "r", "add message sam out %s hello" % LINE_ID, "ok")
					expect(socks["r"], "r", "set message sam out %s handed-over" % LINE_ID, "ok")
				finally:
					r.stop()
				r = daemon(run, "r5", dirs["r"], socks["r"])
				try:
					r.wait_for(ROUND_END_RE, "R's round")
					if GIVEN_UP_RE.search(r.log()) or state() != "handed-over":
						raise failed("d: with S standing, the line handed over is %s"
						             % state())
					expect(socks["r"], "r", "remove contact sam", "ok")
				finally:
					r.stop()
				r = daemon(run, "r6", dirs["r"], socks["r"])
				try:
					got = r.wait_for(GIVEN_UP_RE, "the hand-off given up on")
					if got.group(1) != "1" or state() != "not-delivered":
						raise failed("d: S removed, %s line(s) given up on and the line is %s"
						             % (got.group(1), state()))
				finally:
					r.stop()
				print("livecheck: d: a line handed over for S, removed, was marked not "
				      "delivered")
			finally:
				s.stop()
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
						# STILL OUR CHILD, sec 741: a reaped daemon's pid, handed to
						# another run's daemon of the same binary, is not this run's.
						with open("/proc/%d/stat" % pid) as f:
							alive = alive and int(f.read().rsplit(")", 1)[1].split()[1]) == os.getpid()
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: a removed contact's shares were pulled no further")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
