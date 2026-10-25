#!/usr/bin/env python3
"""1:1 chat, end to end over daemons: sec 689 journey 2.

Run against `make fuzznetd-faults`' daemon, whose rounds FZN_TUNE_PULL_EVERY
makes short. Four stores over loopback, two users of two hosts each: A1, a
root, with A2 joined to it; B1, a root, with B2 joined to it.

    a  A2 and B2 join their users' estates; A1 adds B by B1's card and B1
       grants the request, so every host of each holds the other as a
       contact
    b  lines both ways, from every host: A1 and A2 each write to B, B1 and
       B2 each to A. Every host of each user holds all four, and each
       writer's lines end delivered or settled
    c  read state across the user's hosts: B1 marks B's conversation read
       through the last line, and B2 reads it read too; A2 does the same
       for A1
    d  nothing owed: every host's `get message owed` comes to `ok 0 0 0`,
       no line held undelivered and none delivered unsettled
    d2 a host killed while a line is in flight: A2 is killed by SIGKILL, as
       a power cut would, B1 writes a line to A, and A2 started again
       holds it; B1 owes nothing once A has it
    e  a contact removed: A1 removes B, and A2 lists B suspended, the
       roster being the user's (sec 489); B2 then writes a line, and no
       host of A's holds it after six rounds. B, never told it was
       removed, keeps the line, owed

`--skew S` runs A2's clock S seconds behind and B1's S ahead, by faketime.
`--loss P` runs every daemon at FZN_FAULT_LOSS=P with one seed per run.

BOUNDED FROM INSIDE as live_estate.py is: one deadline, each daemon in its
own process group, and every daemon checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
from live_groups import KEPT_RE, PREKEY_HOST  # noqa: E402
import live_trim  # noqa: E402

# ROUNDS OF TWO SECONDS, the fault build's knob (sec 693).
ROUND_S = "2"
SETTLE_S = "4"
WHO = ("a1", "a2", "b1", "b2")
NAME = {"a": "alice", "b": "bob"}
# A LINE EACH HOST WRITES, its id 32 hex digits naming the writer.
LINE = {"a1": "a1" * 16, "a2": "a2" * 16, "b1": "b1" * 16, "b2": "b2" * 16}


def main(argv):
	parser = argparse.ArgumentParser(description="1:1 chat over daemons")
	parser.add_argument("fuzznetd", help="a daemon built by make fuzznetd-faults")
	parser.add_argument("--loss", type=int, default=0, help="per cent of datagrams lost")
	parser.add_argument("--skew", type=int, default=0,
	                    help="seconds A2's clock runs behind and B1's ahead, by faketime")
	parser.add_argument("--keep", help="a directory, not yet there, to keep a failed run's logs in")
	args = parser.parse_args(argv[1:])
	skews = {}
	if args.skew:
		if not shutil.which("faketime"):
			print("livecheck: chat SKIPPED -- --skew needs faketime on PATH")
			return 0
		skews = {"a2": "-%ds" % args.skew, "b1": "+%ds" % args.skew}
	settle = 90.0 + 6.0 * args.loss
	live_trim.DEADLINE = time.monotonic() + 600.0 + 20.0 * args.loss

	class run:
		pass

	run.fuzznetd = os.path.abspath(args.fuzznetd)
	run.started = []
	base = 42000 + (os.getpid() % 500) * 8
	port = {k: str(base + i) for i, k in enumerate(WHO)}
	os.environ["FZN_TUNE_PULL_EVERY"] = ROUND_S
	# A DELIVERED LINE OFFERED AGAIN FOR SETTLEMENT every few seconds rather
	# than hourly, so phase d measures settlement rather than the hour.
	os.environ["FZN_TUNE_SETTLE_EVERY"] = SETTLE_S
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

		def up(who):
			started[who] = daemon(run, who, dirs[who], socks[who], fake=skews.get(who),
			                      extra=["--udp-port=" + port[who]])
			return started[who]

		def said(who, line):
			return ask(socks[who], line).strip()

		def polled(who, line, test, what):
			until = time.monotonic() + settle
			while True:
				got = said(who, line)
				if test(got):
					return got
				if time.monotonic() > until:
					raise failed("%s: %s answered %r, %s" % (who, line, got, what))
				time.sleep(0.5)

		def back_in_place(who, pid):
			until = time.monotonic() + 30.0
			while time.monotonic() < until:
				try:
					if said(who, "status").startswith("ok "):
						break
				except OSError:
					pass
				time.sleep(0.2)
			else:
				raise failed("%s: the socket did not come back after the join" % who)
			if started[who].proc.poll() is not None or started[who].proc.pid != pid:
				raise failed("%s: did not start again in place after the join" % who)

		def join(who, root):
			"""`who`, a fresh daemon, joins `root`'s estate by a card it answers."""
			os.mkdir(dirs[who])
			up(who)
			got = said(who, "get prekey").split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("%s: get prekey answered %r" % (who, got))
			card = said(root, "add peer %s delegable" % got[1]).split()
			if len(card) != 2 or card[0] != "ok":
				raise failed("%s: add peer for %s answered %r" % (root, who, card))
			path = os.path.join(scratch, "card-" + who)
			with open(path, "w") as f:
				f.write(card[1] + "\n")
			pid = started[who].proc.pid
			joined = said(who, "add join " + path).split()
			if len(joined) != 2 or joined[0] != "ok":
				raise failed("%s: add join answered %r" % (who, joined))
			back_in_place(who, pid)
			polled(who, "list capability", lambda g: "member,1,1,0" in g.split()[2:],
			       "not member held by one hop")
			expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who], "ok")

		def killed(who):
			"""`who` killed by SIGKILL, no cleanup; under faketime the daemon
			itself, so the wrapper reaps it and clears its files."""
			d = started.pop(who)
			kids = []
			if d.wrapped:
				try:
					with open("/proc/%d/task/%d/children" % (d.proc.pid, d.proc.pid)) as f:
						kids = [int(k) for k in f.read().split()]
				except OSError:
					kids = []
			for pid in kids or [d.proc.pid]:
				try:
					os.kill(pid, signal.SIGKILL)
				except ProcessLookupError:
					pass
			d.proc.wait(timeout=10)

		def other(who):
			return "b" if who[0] == "a" else "a"

		def held(who):
			"""The ids `who` lists in its conversation with the other user."""
			got = said(who, "list message " + keys[other(who)]).split()
			if not got or got[0] != "ok":
				raise failed("%s: list message answered %r" % (who, got))
			return {f.split(",")[2]: f.split(",")[3:5] for f in got[4:] if f.count(",") >= 8}

		try:
			# a: two estates, and the users contacts.
			for who in ("a1", "b1"):
				os.mkdir(dirs[who])
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], skews.get(who))
				up(who).wait_for(ROUND_DONE_RE, "%s's first round" % who.upper())
				expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who],
				       "ok")
				keys[who[0]] = said(who, "get prekey").split()[1][PREKEY_HOST]
			join("a2", "a1")
			join("b2", "b1")
			card = said("b1", "get card " + NAME["b"])
			if not card.startswith("ok FZC1:"):
				raise failed("a: B1's get card answered %r" % card)
			got = said("a1", "add contact %s %s" % (NAME["b"], card.split(" ", 1)[1]))
			if got != "ok " + keys["b"]:
				raise failed("a: A1's add contact answered %r" % got)
			started["b1"].wait_for(KEPT_RE, "B1 keeping A's request", within=settle)
			expect(socks["b1"], "b1", "grant request %s %s" % (keys["a"], NAME["a"]), "ok")
			for who in WHO:
				polled(who, "list contact", lambda g, who=who: keys[other(who)] in g,
				       "without the other user as a contact")
			print("livecheck: a: A2 and B2 joined their users' estates, and A and B are "
			      "contacts on all four hosts")

			# b: lines both ways, from every host.
			for who in WHO:
				expect(socks[who], who, "add message %s out %s from%%20%s"
				       % (keys[other(who)], LINE[who], who), "ok")
			for who in WHO:
				try:
					polled(who, "list message " + keys[other(who)],
					       lambda g: all(LINE[w] in g for w in WHO), "without all four lines")
				except failed as e:
					seen = {w: (said(w, "list offset"), said(w, "list clock")) for w in WHO}
					raise failed("%s; offsets and clocks: %r" % (e, seen))
			for who in WHO:
				got = held(who)
				state = got.get(LINE[who])
				if not state or state[0] != "out":
					raise failed("b: %s holds its own line as %r" % (who, state))
				polled(who, "list message " + keys[other(who)],
				       lambda g, who=who: held(who).get(LINE[who], ["", ""])[1]
				       in ("delivered", "settled"),
				       "its own line neither delivered nor settled")
			print("livecheck: b: four lines, one from each host, held on all four and each "
			      "delivered")

			# c: read state across the user's hosts.
			for reader, peer in (("b1", "b2"), ("a2", "a1")):
				last = said(reader, "list message " + keys[other(reader)]).split()[4].split(",")[2]
				expect(socks[reader], reader, "set message %s read %s"
				       % (keys[other(reader)], last), "ok")
				for who in (reader, peer):
					try:
						polled(who, "get message %s unread" % keys[other(who)],
						       lambda g: g.split()[1:2] == ["0"],
						       "not read through, after %s read it" % reader)
					except failed as e:
						order = {w: [f.split(",")[2][:4] for f in
						             said(w, "list message " + keys[other(w)]).split()[4:]]
						         for w in (reader, peer)}
						raise failed("%s; %s read through %s; newest first, %r"
						             % (e, reader, last[:4], order))
			print("livecheck: c: B1's read and A2's reached the other host of each user")

			# d: nothing owed anywhere.
			for who in WHO:
				polled(who, "get message owed", lambda g: g.split()[1:3] == ["0", "0"],
				       "still owing lines")
			print("livecheck: d: no host owes a line, held or unsettled")

			# d2: A2 killed with a line on its way; started again, it has it.
			killed("a2")
			late = "d2" * 16
			expect(socks["b1"], "b1", "add message %s out %s while%%20a2%%20down"
			       % (keys["a"], late), "ok")
			time.sleep(2 * int(ROUND_S))
			up("a2")
			for who in ("a1", "a2"):
				polled(who, "list message " + keys["b"], lambda g: late in g,
				       "without B1's line written while A2 was down")
			polled("b1", "get message owed", lambda g: g.split()[1:3] == ["0", "0"],
			       "still owing the line once A has it")
			print("livecheck: d2: A2 killed while B1's line was on its way; started again, "
			      "both of A's hosts hold it, and B1 owes nothing")

			# e: B removed by A; nothing of B's after reaches A.
			expect(socks["a1"], "a1", "remove contact " + NAME["b"], "ok")
			# NOT ACTIVE at A2: B marked suspended or retired, or gone from the
			# listing with the name A1 forgot.
			def b_inactive(g):
				rows = [r for r in g.split()[3:] if keys["b"] in r]
				return not rows or all(r.endswith((",suspended", ",retired", ",absent"))
				                       for r in rows)
			polled("a2", "list contact", b_inactive, "with B still active")
			after = "e1" * 16
			expect(socks["b2"], "b2", "add message %s out %s after%%20removal"
			       % (keys["a"], after), "ok")
			time.sleep(6 * int(ROUND_S) + 2.0)
			for who in ("a1", "a2"):
				got = said(who, "list message " + keys["b"])
				if after in got:
					raise failed("e: %s holds B2's line written after A removed B: %r"
					             % (who, got))
			owed = said("b2", "get message owed").split()
			if owed[1:2] != ["1"]:
				raise failed("e: B2's line to A, removed, is not held as owed: %r" % owed)
			print("livecheck: e: A removed B, A2 lists B suspended, and B2's later line "
			      "reached no host of A's; B2 holds it owed")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			if args.keep:
				shutil.copytree(scratch, args.keep, symlinks=True,
				                ignore=shutil.ignore_patterns("a1", "a2", "b1", "b2"))
				print("livecheck: the run's logs kept in %s" % args.keep)
			for name in sorted(os.listdir(scratch)):
				if name.endswith(".err"):
					with open(os.path.join(scratch, name), errors="replace") as f:
						tail = f.read().splitlines()[-8:]
					print("livecheck: --- %s" % name)
					for line in tail:
						print("livecheck:     %s" % line)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		except Exception:
			print("livecheck: FAILED -- %s" % traceback.format_exc().strip().replace("\n", " | "))
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
	print("livecheck: 1:1 chat across two users of two hosts, at %d per cent loss" % args.loss)
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
