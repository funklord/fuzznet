#!/usr/bin/env python3
"""Erasure coding at 4 + 2 over six hosts, the rebuild fetching from keepers:
`make livecheck`, sec 606.

Six stores over loopback. A makes a root; B to F join A's estate with grants
they can pass on, each listening on its own port with its address set, so
every member reaches every other (sec 579).

    a  every host runs in turn until each member has taken a pairing to
       each of the other four from their grants
    b  B logs into small segments until it has closed some, and archives
       its own; with the estate's `archive/erasure` at 4+2, B's round cuts
       each fossil into six pieces over the six hosts, one to a host
    c  a round counts them: each host holds its piece of each fossil, and B,
       which let its copies of the others' go, holds its own alone
    d  C loses the files of the pieces it keeps, its rows kept. B, holding
       one piece of each where a rebuild takes four, fetches three from the
       other keepers by id (sec 600), rebuilds each fossil, cuts it again
       and puts C's back -- the fetch half of a rebuild that the two-host
       checks, at 1 + 1, never reach

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline -- 480 s here, six hosts going round in turn -- each daemon in
its own process group, and every daemon checked gone.

`--loss P` runs every daemon at FZN_FAULT_LOSS=P, against the fault build's
daemon (sec 736). `--keep DIR` copies a failed run's stores and logs there,
and `--keep-passed` a passing run's as well, so a phase's rounds can be read
when it passes slowly.

Exit 0 on a pass, 1 on a failure.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_trim  # noqa: E402
from live_rejoin import ROUND_DONE_RE, COUNTED_RE, OWN_ARCHIVED_RE, command, daemon, expect  # noqa: E402
from live_trim import failed  # noqa: E402

# SIX HOSTS GOING ROUND IN TURN take longer than the 240 s the other checks
# are held to; the bound is still one deadline over the whole run.
live_trim.DEADLINE = time.monotonic() + 480.0

# A ROUND'S OWN END, after its fetches and log pass: "history pass" comes
# before them (sec 637).
ROUND_END_RE = ROUND_DONE_RE
CUT_RE = re.compile(r"(\d+) archived segment\(s\) cut into 4 \+ 2 pieces over 6 host\(s\)")
HOSTS = ("a", "b", "c", "d", "e", "f")
MEMBERS = HOSTS[1:]
CYCLES = 6


def main(argv):
	# `--loss P`, sec 736: every daemon at FZN_FAULT_LOSS=P, one seed per
	# run, so PATH must be `make fuzznetd-faults`' daemon.
	# `--keep DIR`: a failed run's stores and logs copied there.
	loss, keep, keep_passed = 0, None, False
	rest = argv[2:]
	argv = argv[:2]
	while rest and rest[0] in ("--loss", "--keep", "--keep-passed"):
		if rest[0] == "--keep-passed":
			keep_passed = True
			rest = rest[1:]
			continue
		if len(rest) < 2:
			break
		if rest[0] == "--loss" and rest[1].isdigit():
			loss = int(rest[1])
		elif rest[0] == "--keep":
			keep = rest[1]
		else:
			break
		rest = rest[2:]
	if len(argv) != 2 or rest or (keep_passed and not keep):
		print("usage: live_erasure.py PATH_TO_FUZZNETD [--loss PER_CENT] [--keep DIR "
		      "[--keep-passed]]", file=sys.stderr)
		return 2
	if loss:
		os.environ["FZN_FAULT_LOSS"] = str(loss)
		os.environ["FZN_FAULT_SEED"] = str(os.getpid())
		live_trim.DEADLINE += 30.0 * loss
	# A ROUND'S LENGTH GROWS WITH LOSS once each lost exchange costs a
	# resend's slice rather than the round (sec 737): 15 to 22 s at 20%
	# against 3 at none, measured. So the waits on one grow with it.
	patience = 3.0 * loss

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	# BELOW THE EPHEMERAL RANGE (32768 up), where a daemon's own client
	# sockets take their ports and could take one of these between runs.
	base = 12000 + (os.getpid() % 1000) * 6
	ports = {h: str(base + i) for i, h in enumerate(HOSTS)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {h: os.path.join(scratch, h) for h in HOSTS}
		socks = {h: os.path.join(sock_dir, h) for h in HOSTS}
		logs = {h: os.path.join(scratch, "log-" + h) for h in HOSTS}
		for h in HOSTS:
			os.mkdir(dirs[h])
			os.mkdir(logs[h])
		small = ["--log-segment=4096"]
		args = {h: ["--udp-port=" + ports[h]] + small
		           + ([] if h == "a" else ["--root-at", "127.0.0.1", ports["a"]])
		        for h in HOSTS}
		addressed = set()

		def pairings(h):
			"""How many nodes `h` holds a pairing to: its store's rows in
			FZN_PERSIST_PAIRED_NODE, slot 8, one file per node. Asked of the
			store rather than counted from log lines, which a small segment
			packs away before they are read."""
			return sum(1 for n in os.listdir(dirs[h]) if n.startswith("8-"))

		def up(h, tag, rules=()):
			# A SEED A START, sec 736: one seed for the whole run made every
			# restart lose the same datagrams, so the one host whose first
			# request was lost lost it every cycle and never paired.
			if loss:
				os.environ["FZN_FAULT_SEED"] = str(os.getpid() * 1000 + len(run.started))
			return daemon(run, tag + h, dirs[h], socks[h],
			              extra=args[h] + ["--log-rule=" + r for r in rules], log_dir=logs[h])

		def round_all(tag, wait=ROUND_END_RE, rules=(), alone=False):
			"""Every host up, each through its first round, B last; the match
			of `wait` in B's log. With `alone`, B by itself."""
			ds = []
			try:
				# THE OTHERS TOGETHER, then their rounds waited on: one at a
				# time, each first round would wait out every sibling not yet
				# started. B last, so its round meets every host up.
				others = () if alone else ("a", "c", "d", "e", "f")
				for h in others:
					ds.append(up(h, tag))
				# SIXTY SECONDS A FIRST ROUND, not thirty: five hosts started
				# together each ask siblings still in their own rounds, and a
				# single-threaded round waits on them (sec 424; 635). Measured
				# 2026-10-15 from their common start, phase a3's first rounds
				# ended 15.6 s in for A and 28 to 41 s in for the rest, so a
				# wait begun after A's could pass 30 (sec 631).
				for h, d in zip(others, ds):
					d.wait_for(ROUND_END_RE, h.upper() + "'s round", within=60.0 + patience)
					note(h, d)
				b = up("b", tag, rules)
				try:
					got = b.wait_for(wait, tag, within=30.0 + patience)
					if not alone:
						b.wait_for(ROUND_END_RE, "B's round", within=30.0 + patience)
					note("b", b)
					return got
				finally:
					b.stop()
			finally:
				for d in ds:
					d.stop()

		def note(h, d):
			"""A member's address, set once while it is up."""
			if h == "a":
				return
			if h not in addressed:
				expect(socks[h], "a", "set setting host net/address 127.0.0.1 " + ports[h], "ok")
				addressed.add(h)

		def pieces(h):
			d = os.path.join(logs[h], "archive", "pieces")
			return sorted(n for n in (os.listdir(d) if os.path.isdir(d) else [])
			              if n.endswith(".piece"))

		def packed(d):
			return [n for n in (os.listdir(d) if os.path.isdir(d) else [])
			        if n.endswith(".log.zst")]

		def closed(d):
			return [n for n in (os.listdir(d) if os.path.isdir(d) else [])
			        if n.endswith(".log") and n.count(".") >= 3]

		try:
			command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
			for h in MEMBERS:
				prekey = command(run, ["--fuzznet-dir=" + dirs[h], "--prekey"], None)
				card = command(run, ["--fuzznet-dir=" + dirs["a"], "--pair=" + prekey,
				                     "--delegable"], None)
				command(run, ["--fuzznet-dir=" + dirs[h], "--accept=" + card, "--join"], None)

			# a: every member paired to every other: four pairings more than
			# its own to the root, which joining gave it.
			joined = {h: pairings(h) for h in MEMBERS}
			# UNDER LOSS, AS MANY AS IT TAKES up to 30, and said: one lost
			# datagram passes a peer over for the round, so the cycles
			# needed are the measure of that cost (sec 736).
			cycles = CYCLES if not loss else 30
			for cycle in range(cycles):
				round_all("a%d" % cycle)
				have = {h: pairings(h) - joined[h] for h in MEMBERS}
				if all(n >= len(MEMBERS) - 1 for n in have.values()):
					break
			if not all(n >= len(MEMBERS) - 1 for n in have.values()):
				raise failed("a: after %d cycles the members held %r pairing(s) to siblings, "
				             "each wanting %d" % (cycles, have, len(MEMBERS) - 1))
			print("livecheck: a: five members paired with one another in %d cycle(s)"
			      % (cycle + 1))

			# b: B's fossils, cut 4 + 2 over the six.
			runs = 0
			while not closed(logs["b"]) and not packed(logs["b"]):
				runs += 1
				if runs > 8:
					raise failed("b: eight runs and B closed no segment")
				round_all("bl%d" % runs, alone=True)
			time.sleep(11)
			round_all("b-pack", OWN_ARCHIVED_RE, ["archive * count 0"], alone=True)
			archive = os.path.join(logs["b"], "archive")
			fossils = packed(archive)
			if not fossils:
				raise failed("b: B archived none of its segments")
			a = up("a", "b-set")
			try:
				a.wait_for(ROUND_END_RE, "A's round")
				expect(socks["a"], "b", "set setting estate archive/erasure 4+2", "ok")
			finally:
				a.stop()
			# A CUT NEEDS EVERY PEER ANSWERING ITS ROUND, and under loss one
			# ask failed past its resends passes a peer over for that round
			# (sec 737): so a later round cuts, and under loss several are
			# given, as phase a's cycles are.
			for attempt in range(1 if not loss else 8):
				try:
					got = round_all("b-cut%d" % attempt, CUT_RE)
					break
				except failed:
					if not loss or attempt == 7:
						raise
			if loss:
				print("livecheck: b: the cut came in B's round %d" % (attempt + 1))
			if got.group(1) != str(len(fossils)):
				raise failed("b: B cut %s of its %d fossil(s)" % (got.group(1), len(fossils)))
			print("livecheck: b: B cut its %d fossil(s) into 4 + 2 pieces over six hosts"
			      % len(fossils))

			# c: counted, a piece of each on each host.
			# UNDER LOSS, ROUNDS UNTIL PLACED: a piece pushed to a peer passed
			# over that round waits for a later one (sec 737).
			for attempt in range(1 if not loss else 8):
				got = round_all("c%d" % attempt, COUNTED_RE)
				held = {h: len(pieces(h)) for h in HOSTS}
				if got.group(2) == "0" and all(n == len(fossils) for n in held.values()):
					break
			if got.group(2) != "0" or any(n != len(fossils) for n in held.values()):
				raise failed("c: B counted %s short, and the hosts hold %r piece(s) of %d "
				             "fossil(s)" % (got.group(2), held, len(fossils)))
			print("livecheck: c: each of the six holds one piece of each fossil")

			# d: C's pieces lost; B fetches three of each from the others.
			lost = pieces("c")
			for n in lost:
				os.remove(os.path.join(logs["c"], "archive", "pieces", n))
			got = round_all("d", COUNTED_RE)
			# UNDER LOSS, ROUNDS UNTIL C HOLDS ITS PIECES AGAIN, and then what
			# a later round put back is not this round's count (sec 737).
			for attempt in range(0 if not loss else 7):
				if pieces("c") == lost:
					break
				got = round_all("d%d" % attempt, COUNTED_RE)
			# C's PIECES BACK IS THE PROOF: no other host held them, so only
			# B's rebuild could put them there. B holding them too is a
			# round's state, which a later count lets go.
			if loss and pieces("c") == lost:
				print("livecheck: d: C lost its %d piece(s); B fetched from the other keepers, "
				      "rebuilt each fossil and put them back, under loss" % len(lost))
				lost = None
			# REBUILT, NOT PUSHED FROM A COPY: B let its copies of C's pieces
			# go in phase c, so it holds them again only because it rebuilt
			# each fossil and cut it again. The same round's count lets the
			# four other keepers' copies go, leaving B its own and C's.
			b_has = pieces("b")
			if lost is None:
				pass
			elif got.group(4) != str(len(lost)) or pieces("c") != lost \
			   or not set(lost) <= set(b_has) or len(b_has) != 2 * len(fossils):
				raise failed("d: C lost %d piece(s); B put back %s, C holds %d, and B holds "
				             "%d, %d of them C's"
				             % (len(lost), got.group(4), len(pieces("c")), len(b_has),
				                len(set(lost) & set(b_has))))
			if lost is not None:
				print("livecheck: d: C lost its %d piece(s); B fetched from the other "
				      "keepers, rebuilt each fossil and put them back" % len(lost))
			if keep and keep_passed:
				shutil.copytree(scratch, keep, symlinks=True)
				print("livecheck: the run's stores and logs kept in %s" % keep)
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			if keep:
				shutil.copytree(scratch, keep, symlinks=True)
				print("livecheck: the run's stores and logs kept in %s" % keep)
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
	print("livecheck: erasure at 4 + 2 rebuilt from pieces fetched off five keepers")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
