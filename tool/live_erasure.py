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
import live_trim  # noqa: E402
from live_rejoin import COUNTED_RE, OWN_ARCHIVED_RE, command, daemon, expect  # noqa: E402
from live_trim import failed  # noqa: E402

# SIX HOSTS GOING ROUND IN TURN take longer than the 240 s the other checks
# are held to; the bound is still one deadline over the whole run.
live_trim.DEADLINE = time.monotonic() + 480.0

ROUND_END_RE = re.compile(r"history pass: ")
CUT_RE = re.compile(r"(\d+) archived segment\(s\) cut into 4 \+ 2 pieces over 6 host\(s\)")
HOSTS = ("a", "b", "c", "d", "e", "f")
MEMBERS = HOSTS[1:]
CYCLES = 6


def main(argv):
	if len(argv) != 2:
		print("usage: live_erasure.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

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
				for h, d in zip(others, ds):
					d.wait_for(ROUND_END_RE, h.upper() + "'s round")
					note(h, d)
				b = up("b", tag, rules)
				try:
					got = b.wait_for(wait, tag)
					if not alone:
						b.wait_for(ROUND_END_RE, "B's round")
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
			for cycle in range(CYCLES):
				round_all("a%d" % cycle)
				have = {h: pairings(h) - joined[h] for h in MEMBERS}
				if all(n >= len(MEMBERS) - 1 for n in have.values()):
					break
			if not all(n >= len(MEMBERS) - 1 for n in have.values()):
				raise failed("a: after %d cycles the members held %r pairing(s) to siblings, "
				             "each wanting %d" % (CYCLES, have, len(MEMBERS) - 1))
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
			got = round_all("b-cut", CUT_RE)
			if got.group(1) != str(len(fossils)):
				raise failed("b: B cut %s of its %d fossil(s)" % (got.group(1), len(fossils)))
			print("livecheck: b: B cut its %d fossil(s) into 4 + 2 pieces over six hosts"
			      % len(fossils))

			# c: counted, a piece of each on each host.
			got = round_all("c", COUNTED_RE)
			held = {h: len(pieces(h)) for h in HOSTS}
			if got.group(2) != "0" or any(n != len(fossils) for n in held.values()):
				raise failed("c: B counted %s short, and the hosts hold %r piece(s) of %d "
				             "fossil(s)" % (got.group(2), held, len(fossils)))
			print("livecheck: c: each of the six holds one piece of each fossil")

			# d: C's pieces lost; B fetches three of each from the others.
			lost = pieces("c")
			for n in lost:
				os.remove(os.path.join(logs["c"], "archive", "pieces", n))
			got = round_all("d", COUNTED_RE)
			# REBUILT, NOT PUSHED FROM A COPY: B let its copies of C's pieces
			# go in phase c, so it holds them again only because it rebuilt
			# each fossil and cut it again. The same round's count lets the
			# four other keepers' copies go, leaving B its own and C's.
			b_has = pieces("b")
			if got.group(4) != str(len(lost)) or pieces("c") != lost \
			   or not set(lost) <= set(b_has) or len(b_has) != 2 * len(fossils):
				raise failed("d: C lost %d piece(s); B put back %s, C holds %d, and B holds "
				             "%d, %d of them C's"
				             % (len(lost), got.group(4), len(pieces("c")), len(b_has),
				                len(set(lost) & set(b_has))))
			print("livecheck: d: C lost its %d piece(s); B fetched from the other keepers, "
			      "rebuilt each fossil and put them back" % len(lost))
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
	print("livecheck: erasure at 4 + 2 rebuilt from pieces fetched off five keepers")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
