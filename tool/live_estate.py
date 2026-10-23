#!/usr/bin/env python3
"""The estate's journey, end to end over daemons: sec 689 journey 1, sec 707.

Run against `make fuzznetd-faults`' daemon, whose rounds FZN_TUNE_PULL_EVERY
makes short. Six stores over loopback, every one a daemon driven by verbs:
R the estate's root, A1 and A2 its admins, D a device, then N (A1's
successor) and E (a device paired by the second root).

    a  A1, A2 and D join R's estate by `add join`, each holding the member
       capability by R's grant
    b  settings at each rank: R's estate setting read as root's on every
       device; A1, made admin, sets one read as admin's at R; D sets its own
       host cell, read as host's at R, and is denied the estate's
    c  k of n while D writes: R sets k to 2. D sets h/before, which every
       node reads; A1 votes D revoked, its cut at D's head as A1 holds it;
       D sets h/mid, which R takes -- one vote is not k; A2 votes. At R,
       D's grant stands no more, h/before still reads and h/mid does not
       (sec 706): kept before the second vote came, it was past A1's cut.
       D, writing throughout, sets h/after, which never reads at R
    d  a succession: R re-keys A1 as N, N joins by the card R answers, and
       R lists A1 succeeded by N, counting, and N holding the member
       capability
    e  a vote through a crash: R grants N admin, as a re-keyed admin needs
       (sec 499), and D2 joins. A2, started at total loss so it can send
       nothing, votes D2 revoked and is killed by SIGKILL; N votes. Started
       again, A2 pushes the vote it cast before it died, and at R D2's
       grant stands no more -- k of 2 reached by a vote that crossed a
       crash
    f  recovery: R adds A2 as a root and is stopped for good; A2 removes R
       from the roots, pairs E, and E joins and reads what A2 sets as root

`--skew S` runs A1's clock S seconds ahead and D's S behind, by faketime.
`--loss P` runs every daemon at FZN_FAULT_LOSS=P with one seed per run;
`--keep DIR` copies a failed run's daemon output and logs into DIR, which
must not exist. The stores are left out.

Against a daemon that keeps a setting past its setter's cut, phase c's
h/mid still reads at R.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

# A PREKEY RECORD'S HOST KEY, in hex.
PREKEY_HOST = slice(4, 68)
KEY_LEN = 64
# ROUNDS OF TWO SECONDS, the fault build's knob (sec 693).
ROUND_S = "2"
WHO = ("r", "a1", "a2", "d", "n", "d2", "e")


def main(argv):
	parser = argparse.ArgumentParser(description="the estate's journey over daemons")
	parser.add_argument("fuzznetd", help="a daemon built by make fuzznetd-faults")
	parser.add_argument("--loss", type=int, default=0, help="per cent of datagrams lost")
	parser.add_argument("--within", type=float, default=900.0, help="the whole run's deadline")
	parser.add_argument("--keep", help="on a failure, copy the run's logs into this new directory")
	parser.add_argument("--skew", type=int, default=0,
	                    help="seconds A1's clock runs ahead and D's behind, by faketime")
	args = parser.parse_args(argv[1:])
	live_trim.DEADLINE = time.monotonic() + args.within
	# A CLOCK EACH WAY: A1 ahead and D behind, the pair that vote against
	# each other in phase c, R and the rest on the real clock.
	skews = {}
	if args.skew:
		if not shutil.which("faketime"):
			print("livecheck: estate SKIPPED -- --skew needs faketime on PATH")
			return 0
		skews = {"a1": "+%ds" % args.skew, "d": "-%ds" % args.skew}
	# A WAIT, at 20 per cent loss, may cost many rounds.
	settle = 60.0 + 6.0 * args.loss

	class run:
		pass

	run.fuzznetd = os.path.abspath(args.fuzznetd)
	run.started = []
	base = 1024 + (os.getpid() % 19) * 8
	port = {k: str(base + i) for i, k in enumerate(WHO)}
	os.environ["FZN_TUNE_PULL_EVERY"] = ROUND_S
	if args.loss:
		os.environ["FZN_FAULT_LOSS"] = str(args.loss)
		os.environ["FZN_FAULT_SEED"] = str(os.getpid())
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in WHO}
		socks = {k: os.path.join(sock_dir, k) for k in WHO}
		started = {}
		keys = {}
		runs = {k: 0 for k in WHO}

		def up(who, loss=None):
			"""`who` started, at `loss` per cent rather than the run's when
			given."""
			runs[who] += 1
			was = os.environ.get("FZN_FAULT_LOSS")
			if loss is not None:
				os.environ["FZN_FAULT_LOSS"] = str(loss)
			try:
				started[who] = daemon(run, "%s%d" % (who, runs[who]), dirs[who], socks[who],
				                      fake=skews.get(who), extra=["--udp-port=" + port[who]])
			finally:
				if loss is not None:
					if was is None:
						os.environ.pop("FZN_FAULT_LOSS", None)
					else:
						os.environ["FZN_FAULT_LOSS"] = was
			return started[who]

		def killed(who):
			"""`who` killed by SIGKILL, no cleanup, as a power cut would."""
			d = started.pop(who)
			try:
				os.killpg(d.proc.pid, signal.SIGKILL)
			except ProcessLookupError:
				pass
			d.proc.wait(timeout=10)

		def said(who, line):
			return ask(socks[who], line).strip()

		def polled(who, line, test, what, within=None):
			"""`who`'s answer to `line` once `test` takes it, polled: a round's
			end may already be logged by a run started again in place."""
			until = time.monotonic() + (within or settle)
			while True:
				got = said(who, line)
				if test(got):
					return got
				if time.monotonic() > until:
					raise failed("%s: %s answered %r, %s" % (who, line, got, what))
				time.sleep(0.5)

		def back_in_place(who, pid, what):
			"""`who`'s socket back after a start again in the same process."""
			until = time.monotonic() + 30.0
			while time.monotonic() < until:
				try:
					if said(who, "status").startswith("ok "):
						break
				except OSError:
					pass
				time.sleep(0.2)
			else:
				raise failed("%s: the socket did not come back after %s" % (who, what))
			if started[who].proc.poll() is not None or started[who].proc.pid != pid:
				raise failed("%s: did not start again in place after %s" % (who, what))

		def join(who, by, delegable=True):
			"""`who`, a fresh daemon, joins by a card `by` answers for its
			prekey; its key kept."""
			os.mkdir(dirs[who])
			up(who)
			got = said(who, "get prekey").split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("%s: get prekey answered %r" % (who, got))
			keys[who] = got[1][PREKEY_HOST]
			card = said(by, "add peer %s%s" % (got[1], " delegable" if delegable else "")).split()
			if len(card) != 2 or card[0] != "ok":
				raise failed("%s: add peer for %s answered %r" % (by, who, card))
			return card_join(who, card[1])

		def card_join(who, card):
			path = os.path.join(scratch, "card-" + who)
			with open(path, "w") as f:
				f.write(card + "\n")
			pid = started[who].proc.pid
			joined = said(who, "add join " + path).split()
			if len(joined) != 2 or joined[0] != "ok" or len(joined[1]) != KEY_LEN:
				raise failed("%s: add join answered %r" % (who, joined))
			back_in_place(who, pid, "the join")
			return joined[1]

		def member(who):
			polled(who, "list capability", lambda g: "member,1,1,0" in g.split()[2:],
			       "not member held by one hop")

		def grant_stands(who, key):
			"""Whether `who` lists a grant it made `key` as standing, by the
			`list grant` STANDS field; None when it lists none."""
			for e in said(who, "list grant").split()[3:]:
				if e.startswith(key + ","):
					return e.endswith(",1")
			return None

		def admin(who):
			granted = said("r", "grant admin " + keys[who]).split()
			if len(granted) < 2 or granted[0] != "ok" or not granted[1].startswith("h"):
				raise failed("%s: R's grant admin answered %r" % (who, granted[:2]))
			path = os.path.join(scratch, "admin-" + who)
			with open(path, "w") as f:
				f.write(" ".join(granted[1:]) + "\n")
			pid = started[who].proc.pid
			expect(socks[who], who, "set admin " + path, "ok %d" % (len(granted) - 1))
			back_in_place(who, pid, "set admin")
			polled(who, "list capability",
			       lambda g: any(e.startswith("admin,1,1,") for e in g.split()[2:]),
			       "not admin held by one hop")

		writing = {"go": False, "n": 0, "error": None, "denied": False}

		def writer():
			"""D WRITING THROUGHOUT phase c, a value a third of a second."""
			while writing["go"]:
				try:
					got = said("d", "set setting host h/n %d" % writing["n"])
					# REFUSED ONCE D HAS LEARNED ITS OWN REVOCATION: its own
					# write is judged as any setter's is.
					if got.startswith("denied"):
						writing["denied"] = True
						return
					if got != "ok":
						writing["error"] = got
						return
					writing["n"] += 1
				except OSError as e:
					writing["error"] = str(e)
					return
				time.sleep(0.3)

		try:
			os.mkdir(dirs["r"])
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			up("r")
			started["r"].wait_for(ROUND_DONE_RE, "R's first round")
			expect(socks["r"], "r", "set setting host net/address 127.0.0.1 " + port["r"], "ok")
			# A ROOT'S RECORD FIRST: k is a root's to set once it has one.
			expect(socks["r"], "r", "set setting estate x/start 1", "ok")

			# a: three devices join.
			root = None
			for who in ("a1", "a2", "d"):
				root = join(who, "r")
				member(who)
			print("livecheck: a: A1, A2 and D joined R's estate by verbs")

			# b: settings at each rank.
			expect(socks["r"], "r", "set setting estate b/root 1", "ok")
			for who in ("a1", "a2", "d"):
				polled(who, "get setting estate b/root", lambda g: g == "ok root 1",
				       "not R's setting at the root's rank")
			admin("a1")
			admin("a2")
			expect(socks["a1"], "a1", "set setting estate b/admin 1", "ok")
			polled("r", "get setting estate b/admin", lambda g: g == "ok admin 1",
			       "not A1's setting at the admin's rank")
			expect(socks["d"], "d", "set setting host b/host 1", "ok")
			polled("r", "get setting host=%s b/host" % keys["d"], lambda g: g == "ok host 1",
			       "not D's own host cell at the host's rank")
			denied = said("d", "set setting estate b/d 1")
			if not denied.startswith("denied"):
				raise failed("b: D's estate setting was answered %r" % denied)
			print("livecheck: b: R set as root, A1 as admin, D its own host cell; D was "
			      "denied the estate's")

			# c: k of n while D writes.
			expect(socks["r"], "r", "set quorum 2", "ok 2")
			for who in ("a1", "a2", "d"):
				polled(who, "get setting estate revocation/k", lambda g: g == "ok root 2",
				       "not k of 2 set by the root")
			expect(socks["d"], "d", "set setting host h/before 1", "ok")
			for who in ("r", "a1", "a2"):
				polled(who, "get setting host=%s h/before" % keys["d"],
				       lambda g: g == "ok host 1", "not D's h/before")
			writing["go"] = True
			pen = threading.Thread(target=writer, daemon=True)
			pen.start()
			vote = said("a1", "revoke peer " + keys["d"]).split()
			if len(vote) != 4 or vote[:3] != ["ok", keys["d"], "keeping"] or vote[3] == "nothing":
				raise failed("c: A1's vote answered %r, not a cut at D's head" % vote)
			# ONE VOTE IS NOT K: D's next setting is still taken at R.
			expect(socks["d"], "d", "set setting host h/mid 1", "ok")
			polled("r", "get setting host=%s h/mid" % keys["d"], lambda g: g == "ok host 1",
			       "not D's h/mid, one vote short of k")
			if grant_stands("r", keys["d"]) is not True:
				raise failed("c: R's grant to D stands no more after one vote of two")
			vote = said("a2", "revoke peer " + keys["d"]).split()
			if len(vote) != 4 or vote[:3] != ["ok", keys["d"], "keeping"]:
				raise failed("c: A2's vote answered %r" % vote)
			polled("r", "list grant", lambda g: grant_stands("r", keys["d"]) is False,
			       "with D's grant still standing after two votes")
			writing["go"] = False
			pen.join(10.0)
			if writing["error"]:
				raise failed("c: D's own writes were answered %r" % writing["error"])
			got = said("r", "get setting host=%s h/before" % keys["d"])
			if got != "ok host 1":
				raise failed("c: D's h/before, before every cut, reads %r at R" % got)
			polled("r", "get setting host=%s h/mid" % keys["d"], lambda g: g == "ok absent",
			       "though h/mid was past A1's cut")
			after = said("d", "set setting host h/after 1")
			if after != "ok" and not after.startswith("denied"):
				raise failed("c: D's h/after was answered %r" % after)
			time.sleep(6.0 * float(ROUND_S))
			got = said("r", "get setting host=%s h/after" % keys["d"])
			if got != "ok absent":
				raise failed("c: D's h/after, written once revoked, reads %r at R" % got)
			print("livecheck: c: A1 and A2 revoked D, k of 2, while it wrote %d values%s; "
			      "h/before stands at R, h/mid and h/after (%s at D) do not"
			      % (writing["n"], ", then was refused its own" if writing["denied"] else "",
			         after.split()[0]))

			# d: R re-keys A1 as N.
			os.mkdir(dirs["n"])
			up("n")
			got = said("n", "get prekey").split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("d: N's get prekey answered %r" % got)
			keys["n"] = got[1][PREKEY_HOST]
			card = said("r", "add succession %s %s" % (keys["a1"], got[1])).split()
			if len(card) != 2 or card[0] != "ok":
				raise failed("d: R's add succession answered %r" % card)
			card_join("n", card[1])
			member("n")
			polled("r", "list succession",
			       lambda g: "%s>%s,counting" % (keys["a1"], keys["n"]) in g.split()[3:],
			       "not A1 succeeded by N, counting")
			if grant_stands("r", keys["a1"]) is not False:
				raise failed("d: R's grant to A1 still stands once A1 is succeeded")
			print("livecheck: d: R re-keyed A1 as N, which joined, and A1's grant stands "
			      "no more")

			# e: a vote cast, then a crash before it could be sent.
			admin("n")
			join("d2", "r")
			member("d2")
			started.pop("a2").stop()
			up("a2", loss=100)
			vote = said("a2", "revoke peer " + keys["d2"]).split()
			if len(vote) != 4 or vote[:3] != ["ok", keys["d2"], "keeping"]:
				raise failed("e: A2's vote at total loss answered %r" % vote)
			killed("a2")
			vote = said("n", "revoke peer " + keys["d2"]).split()
			if len(vote) != 4 or vote[:3] != ["ok", keys["d2"], "keeping"]:
				raise failed("e: N's vote answered %r" % vote)
			if grant_stands("r", keys["d2"]) is not True:
				raise failed("e: R's grant to D2 fell with N's vote alone, one of two")
			up("a2")
			polled("r", "list grant", lambda g: grant_stands("r", keys["d2"]) is False,
			       "with D2's grant standing: A2's vote, cast before it was killed, never "
			       "arrived")
			print("livecheck: e: A2 voted at total loss and was killed; started again, its vote "
			      "reached R and, with N's, revoked D2")

			# f: recovery through a second root.
			expect(socks["r"], "r", "add root " + keys["a2"], "ok " + keys["a2"])
			expect(socks["a2"], "a2", "set setting host net/address 127.0.0.1 " + port["a2"],
			       "ok")
			polled("a2", "set setting estate e/as-root 1", lambda g: g == "ok",
			       "as A2 acting")
			polled("a2", "set quorum 2", lambda g: g == "ok 2", "not as a root")
			started.pop("r").stop()
			expect(socks["a2"], "a2", "remove root " + root, "ok " + root)
			join("e", "a2")
			member("e")
			expect(socks["a2"], "a2", "set setting estate e/after 1", "ok")
			polled("e", "get setting estate e/after", lambda g: g == "ok root 1",
			       "not A2's setting at the root's rank")
			print("livecheck: f: R added A2 as a root and was stopped; A2 removed R, paired "
			      "E, and E reads A2 as its root")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			# EACH DAEMON'S LAST WORDS, since the scratch goes with the run.
			for name in sorted(os.listdir(scratch)):
				if name.endswith(".err"):
					with open(os.path.join(scratch, name), errors="replace") as f:
						tail = f.read().splitlines()[-12:]
					print("livecheck: --- %s" % name)
					for line in tail:
						print("livecheck:     %s" % line)
			if args.keep:
				shutil.copytree(scratch, args.keep, ignore=shutil.ignore_patterns("[a-z]", "[a-z][0-9]"),
				                symlinks=True)
				print("livecheck: the run's logs kept in %s" % args.keep)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			writing["go"] = False
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
	print("livecheck: the estate's journey, at %d per cent loss" % args.loss)
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
