#!/usr/bin/env python3
"""fuzzypickles' client over fuzznetd, under loss: sec 710.

fuzzypickles' `fzp` command, run with `--node-socket`, maps its commands
onto fuzznetd's verbs (its sec 284). Its own scenarios drive that mapping
against one machine's daemons, and none of them sends a datagram between
nodes -- they pass at 100 per cent loss. This one does, run against
`make fuzznetd-faults`' daemon on rounds of 2 s:

    a  bob shows his card; alice asks for him by it; bob lists the request
       and approves it; each lists the other as a peer
    b  alice sends bob five lines and bob five back; each reads all five
       in, and every line alice's `delivery` still lists says delivered
    c  bob stopped, alice sends three lines; bob started again reads all
       three, sent again by alice's rounds
    d  alice shares her location with bob at coarse precision; a fix is
       added at alice, and bob, fetching, shows it on the 0.01 degree grid,
       marked coarse -- never alice's exact position
    e  carol, a fresh node, asks to join alice's estate by fzp's
       host-join-request; alice approves it and carol installs the approval.
       carol's root is then alice's, as fuzznetd's `get identity` says, and
       carol reads a setting alice makes for the estate; fzp's cap-show at
       carol says member valid and cap-granted at alice lists carol's
       member grant, and the approval warns of nothing

`--loss P` runs every daemon at FZN_FAULT_LOSS=P with one seed a run, and
`--keep DIR` copies a failed run's daemon output into DIR. FZP names the
client, ../fuzzypickles/cli/fzp by default; without one this is SKIPPED,
saying so. Ports are 40000 + pid % 10000 and up, clear of fuzzypickles'
own (29800 to 31000), and each is checked free before it is used.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this
reuses: one deadline, each daemon in its own process group, every daemon
checked gone; every fzp run has a timeout.

Exit 0 on a pass or a skip, 1 on a failure.
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WHO = ("alice", "bob", "carol")


def free(port):
	"""Whether UDP `port` on loopback can be bound now."""
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		s.bind(("127.0.0.1", port))
		return True
	except OSError:
		return False
	finally:
		s.close()


def main(argv):
	parser = argparse.ArgumentParser(description="fuzzypickles' client over fuzznetd")
	parser.add_argument("fuzznetd", help="a daemon built by make fuzznetd-faults")
	parser.add_argument("--loss", type=int, default=0, help="per cent of datagrams lost")
	parser.add_argument("--within", type=float, default=600.0, help="the whole run's deadline")
	parser.add_argument("--keep", help="on a failure, copy the run's daemon output here")
	args = parser.parse_args(argv[1:])
	fzp_path = os.path.abspath(os.environ.get(
		"FZP", os.path.join(HERE, "..", "..", "fuzzypickles", "cli", "fzp")))
	if not os.access(fzp_path, os.X_OK):
		print("livecheck: fzp SKIPPED -- no fuzzypickles client at %s (set FZP)" % fzp_path)
		return 0
	live_trim.DEADLINE = time.monotonic() + args.within
	settle = 60.0 + 6.0 * args.loss

	class run:
		pass

	run.fuzznetd = os.path.abspath(args.fuzznetd)
	run.started = []
	base = 40000 + os.getpid() % 10000
	port = {}
	for k in WHO:
		while not free(base):
			base += 1
		port[k] = base
		base += 1
	os.environ["FZN_TUNE_PULL_EVERY"] = "2"
	if args.loss:
		os.environ["FZN_FAULT_LOSS"] = str(args.loss)
		os.environ["FZN_FAULT_SEED"] = str(os.getpid())
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		# fzp's own state and staging in the scratch, not the user's.
		os.environ["FUZZYPICKLES_CONFIG"] = os.path.join(scratch, "fzp.ini")
		open(os.environ["FUZZYPICKLES_CONFIG"], "w").close()
		os.environ["XDG_CONFIG_HOME"] = os.path.join(scratch, "config")
		os.environ["XDG_CACHE_HOME"] = os.path.join(scratch, "cache")
		os.environ["TMPDIR"] = scratch
		socks = {k: os.path.join(sock_dir, k) for k in WHO}
		dirs = {k: os.path.join(scratch, k) for k in WHO}
		started = {}
		runs = {k: 0 for k in WHO}

		def up(who):
			runs[who] += 1
			started[who] = daemon(run, "%s%d" % (who, runs[who]), dirs[who], socks[who],
			                      extra=["--udp-port=%d" % port[who]])
			return started[who]

		def fzp(who, *words, err=None, busy_ok=False):
			"""`fzp WORDS --node-socket` at `who`'s daemon: its output, or a
			failure naming the command when it exits non-zero; its stderr
			into the list `err` when one is given."""
			# NOT RUNNABLE is said, not raised: the client is a sibling tree's
			# build, and one being rebuilt is briefly not there to run.
			try:
				p = subprocess.run([fzp_path] + list(words) + ["--node-socket", socks[who]],
				                   capture_output=True, text=True, cwd=scratch,
				                   timeout=min(30.0, live_trim.left()))
			except OSError as e:
				raise failed("%s: fzp %s would not run (%s) -- is %s being rebuilt?"
				             % (who, words[0], e, fzp_path))
			# A NODE STILL BUSY WITH EARLIER ASKS refuses another, by its own
			# bound (sec 704's fetch slots): for a poll, that is "wait".
			if p.returncode != 0 and busy_ok and "too many fetches waiting" in p.stdout + p.stderr:
				return ""
			if p.returncode != 0:
				raise failed("%s: fzp %s exited %d: %s" % (who, words[0], p.returncode,
				                                           (p.stdout + p.stderr).strip()[-300:]))
			if err is not None:
				err.append(p.stderr)
			return p.stdout

		def until(who, words, test, what):
			"""`who`'s `fzp WORDS` once `test` takes its output, polled."""
			give_up = time.monotonic() + settle
			while True:
				out = fzp(who, *words)
				if test(out):
					return out
				if time.monotonic() > give_up:
					raise failed("%s: fzp %s printed %r, %s" % (who, " ".join(words), out[-300:],
					                                            what))
				time.sleep(0.5)

		try:
			for who in ("alice", "bob"):
				os.mkdir(dirs[who])
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
				up(who).wait_for(ROUND_DONE_RE, who + "'s first round")
				if ask(socks[who], "set setting host net/address 127.0.0.1 %d" % port[who]) != "ok":
					raise failed("%s would not take its address" % who)

			# a: contacts by a card, through fzp.
			out = fzp("bob", "contact-card-show", "--address", "127.0.0.1:%d" % port["bob"],
			          "--name", "bob").splitlines()
			cards = [out[i + 1].strip() for i, line in enumerate(out[:-1])
			         if line.startswith("contact card (hex)")]
			if not cards:
				raise failed("a: bob's contact-card-show printed no hex card: %r" % out)
			fzp("alice", "peer-request", "--card", cards[0], "--name", "bob", "--my-address",
			    "127.0.0.1:%d" % port["alice"])
			listed = until("bob", ["peer-request-list"],
			               lambda o: any(len(w) == 64 for w in o.split()),
			               "with no request from alice")
			asker = [w for w in listed.split() if len(w) == 64][0]
			fzp("bob", "peer-request-approve", "--host", asker, "--name", "alice")
			until("alice", ["peer-list"], lambda o: o.startswith("bob "), "not bob")
			until("bob", ["peer-list"], lambda o: o.startswith("alice "), "not alice")
			print("livecheck: a: alice asked for bob by his card, bob approved, and each lists "
			      "the other")

			# b: lines both ways.
			for n in range(5):
				fzp("alice", "message-send", "--to", "bob", "--text", "from alice %d" % n)
				fzp("bob", "message-send", "--to", "alice", "--text", "from bob %d" % n)
			until("bob", ["inbox", "--peer", "alice"],
			      lambda o: all("<- alice: from alice %d" % n in o for n in range(5)),
			      "not all five of alice's lines in")
			until("alice", ["inbox", "--peer", "bob"],
			      lambda o: all("<- bob: from bob %d" % n in o for n in range(5)),
			      "not all five of bob's lines in")
			until("alice", ["delivery"],
			      lambda o: all("delivered" in line for line in o.splitlines() if line.strip()
			                    and not line.startswith("(")),
			      "with a line not yet delivered")
			print("livecheck: b: five lines each way read in, and alice's delivery says each "
			      "delivered")

			# c: bob away while alice writes.
			started.pop("bob").stop()
			for n in range(3):
				fzp("alice", "message-send", "--to", "bob", "--text", "while away %d" % n)
			up("bob")
			until("bob", ["inbox", "--peer", "alice"],
			      lambda o: all("<- alice: while away %d" % n in o for n in range(3)),
			      "not all three lines sent while it was away")
			print("livecheck: c: three lines sent while bob was away read in once he was back")

			# d: location, coarse.
			fzp("alice", "location-share", "--name", "bob", "--enable", "--precision", "coarse")
			if not ask(socks["alice"], "add location 59.3293230 18.0685810 alt 31 bearing 90 "
			                           "acc 5 9 vacc 20 at 1792600000").startswith("ok"):
				raise failed("d: alice would not take a fix")

			def fetched(out):
				if "+59.3300000 +18.0700000" in out:
					return True
				fzp("bob", "location-fetch", "--name", "alice", busy_ok=True)
				return False

			shown = until("bob", ["location-show", "--origin", "alice"], fetched,
			              "not alice's fix on the coarse grid")
			if "[coarse]" not in shown or "59.3293230" in shown:
				raise failed("d: bob shows %r of alice's fix, not it coarse alone" % shown)
			print("livecheck: d: alice's fix, shared coarse, reads at bob on the 0.01 degree "
			      "grid")

			# e: a device joins alice's estate through fzp.
			os.mkdir(dirs["carol"])
			command(run, ["--fuzznet-dir=" + dirs["carol"], "--new-root"], None)
			up("carol").wait_for(ROUND_DONE_RE, "carol's first round")
			alice_root = ask(socks["alice"], "get identity").split()[2]

			def blob(out, heading):
				lines = out.splitlines()
				found = [lines[i + 1].strip() for i, line in enumerate(lines[:-1])
				         if line.startswith(heading)]
				if not found:
					raise failed("e: no %r in %r" % (heading, out[-300:]))
				return found[0]

			request = blob(fzp("carol", "host-join-request", "--name", "carol", "--address",
			                   "127.0.0.1:%d" % port["carol"]), "join request blob (hex)")
			warned = []
			approval = blob(fzp("alice", "host-join-approve", "--request-blob", request,
			                    "--address", "127.0.0.1:%d" % port["alice"], err=warned),
			                "join approval blob (hex)")
			if "warning" in "".join(warned):
				raise failed("e: alice's host-join-approve warned: %r" % "".join(warned)[-300:])
			fzp("carol", "host-join-install", "--approval-blob", approval)
			give_up = time.monotonic() + 30.0
			while True:
				try:
					said = ask(socks["carol"], "get identity").split()
					if len(said) == 3 and said[2] == alice_root:
						break
				except OSError:
					said = []
				if time.monotonic() > give_up:
					raise failed("e: after the install carol says %r, not alice's root %s"
					             % (said, alice_root))
				time.sleep(0.5)
			if ask(socks["alice"], "set setting estate fzp/joined 1") != "ok":
				raise failed("e: alice would not set the estate's fzp/joined")
			give_up = time.monotonic() + settle
			while ask(socks["carol"], "get setting estate fzp/joined") != "ok root 1":
				if time.monotonic() > give_up:
					raise failed("e: carol never read alice's estate setting")
				time.sleep(0.5)
			# AND fzp SAYS SO, fuzzypickles' 0441ca0: carol holds member, and
			# alice lists the grant she made carol.
			carol_host = ask(socks["carol"], "get identity").split()[1]
			until("carol", ["cap-show"],
			      lambda o: any(line.split()[:2] == ["member", "valid"] for line in o.splitlines()
			                    if line.strip()),
			      "not member valid")
			until("alice", ["cap-granted"], lambda o: carol_host in o and "member" in o,
			      "not the member grant alice made carol")
			print("livecheck: e: carol joined alice's estate through fzp's host-join, reads what "
			      "alice sets for it, and fzp shows the member grant on both sides")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			for name in sorted(os.listdir(scratch)):
				if name.endswith(".err"):
					with open(os.path.join(scratch, name), errors="replace") as f:
						tail = f.read().splitlines()[-10:]
					print("livecheck: --- %s" % name)
					for line in tail:
						print("livecheck:     %s" % line)
			if args.keep:
				shutil.copytree(scratch, args.keep, symlinks=True,
				                ignore=shutil.ignore_patterns(*WHO))
				print("livecheck: the run's output kept in %s" % args.keep)
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
	print("livecheck: fuzzypickles' client over fuzznetd, at %d per cent loss" % args.loss)
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
