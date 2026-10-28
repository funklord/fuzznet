#!/usr/bin/env python3
"""Siblings reach one another, by pairing and address: `make livecheck`, sec 579.

Three stores over loopback. A makes a root; B and C join A's estate with
grants they can pass on, and pull from A (`--root-at`). Neither is paired
with the other, and A, which has no pull peers, fetches from neither.

    a  C puts a file. B and C start in turns: each carries its prekey in
       its estate stream, pairs the other once the other's prekey arrives
       through A, and logs the grant; each then takes its pairing to the
       other from that grant -- "1 pairing(s) taken" at both
    b  C is up with no address set. B asks for the file: its round passes,
       and the file is still not whole -- a pairing without an address
       reaches nobody, and A holds none of it
    c  C sets `net/address` to where it listens and is restarted, so its
       round carries the setting to A. B, restarted, fetches the file whole
       from one peer, and exports the same bytes C put; A
       still holds none of it, so the peer was C

    e  A is stopped. C sets one of its own host cells and restarts; B,
       whose --root-at reaches nobody, reads C's value, which it can only
       have taken from C, as a round's pull peer (sec 586)

    f  pieces placed on a host that went away, moved (sec 601): each host
       logs into small segments, B archives its own, and with the estate's
       `archive/erasure` at 1+1 cuts each over the three hosts; a keeper
       other than B is stopped, `archive/gone` set to 3s, and once it has
       been silent that long B rebuilds each of its pieces and places it on
       the one host keeping none, which then holds it
    g  the gone keeper comes back: B's round pushes it the signed release
       of each piece moved off it, and it lets those pieces go (sec 602)
    h  the estate's routing manifest (sec 611): A, the root, signs one
       listing C's address at the default metric; C sets its `net/metric`
       to 7, A signs the next generation, and B -- a member, not a signer
       -- takes it from a peer and holds C at metric 7

Against a daemon that carries no prekeys, or pairs no siblings, phase a
fails waiting for the pairings; against one that never asks a sibling,
phase c does; against one that asks siblings for files alone, phase e.

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
from live_rejoin import (ROUND_DONE_RE, COUNTED_RE, OWN_ARCHIVED_RE, RECONCILE_RE,  # noqa: E402
                         command, daemon, expect)
from live_trim import ask, failed  # noqa: E402

TAKEN_RE = re.compile(r"(\d+) sibling\(s\) paired, (\d+) pairing\(s\) taken")
WHOLE_RE = re.compile(r"file [0-9a-f]{8}, (\d+) bytes, whole from (\d+) peer\(s\)")
# A ROUND'S OWN END, after its fetches and log pass: "history pass" comes
# before them (sec 637).
ROUND_END_RE = ROUND_DONE_RE
ROUNDS = 6
PAYLOAD_LEN = 200000


def took(d):
	"""Whether `d` has logged a pairing taken from a sibling's grant."""
	return any(int(m.group(2)) > 0 for m in TAKEN_RE.finditer(d.log()))


def held(sock, tag, root):
	"""The `get file ROOT` answer's state word at `sock`, or "none"."""
	reply = ask(sock, "get file " + root)
	if not reply.startswith("ok "):
		return "none"
	words = reply.split()
	if len(words) < 5:
		raise failed("%s: get file answered %r" % (tag, reply))
	return words[4]


def main(argv):
	if len(argv) != 2:
		print("usage: live_siblings.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port_a = str(28000 + os.getpid() % 2000)
	port_c = str(30000 + os.getpid() % 2000)
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in ("a", "b", "c")}
		socks = {k: os.path.join(sock_dir, k) for k in ("a", "b", "c")}
		for d in dirs.values():
			os.mkdir(d)
		payload = os.path.join(scratch, "payload")
		with open(payload, "wb") as f:
			f.write(os.urandom(PAYLOAD_LEN))
		out = os.path.join(scratch, "out")
		b_args = ["--root-at", "127.0.0.1", port_a]
		c_args = ["--udp-port=" + port_c, "--root-at", "127.0.0.1", port_a]
		try:
			command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
			keys = {}
			for who in ("b", "c"):
				prekey = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"], None)
				keys[who] = prekey[4:68]
				card = command(run, ["--fuzznet-dir=" + dirs["a"], "--pair=" + prekey,
				                     "--delegable"], None)
				command(run, ["--fuzznet-dir=" + dirs[who], "--accept=" + card, "--join"], None)

			a = daemon(run, "a1", dirs["a"], socks["a"], extra=["--udp-port=" + port_a])
			try:
				# a: the pairings, both ways.
				ref = None
				taken = {"b": False, "c": False}
				for rnd in range(ROUNDS):
					for who, args in (("c", c_args), ("b", b_args)):
						d = daemon(run, "%s%d" % (who, rnd), dirs[who], socks[who], extra=args)
						try:
							if ref is None and who == "c":
								reply = ask(socks["c"], "put file " + payload)
								if not reply.startswith("ok "):
									raise failed("a: put file answered %r" % reply)
								ref = reply.split()[1]
							d.wait_for(RECONCILE_RE, "reconcile pass")
							taken[who] = taken[who] or took(d)
						finally:
							d.stop()
					if all(taken.values()):
						break
				if not all(taken.values()):
					raise failed("a: after %d rounds each, a pairing taken at B %s, at C %s"
					             % (ROUNDS, taken["b"], taken["c"]))
				root = ref[:64]
				print("livecheck: a: B and C paired each other through the estate in %d "
				      "round(s)" % (rnd + 1))

				# b: no address, no reach.
				c = daemon(run, "cb", dirs["c"], socks["c"], extra=c_args)
				try:
					c.wait_for(RECONCILE_RE, "C's reconcile pass")
					b = daemon(run, "bb", dirs["b"], socks["b"], extra=b_args)
					try:
						rec = b.wait_for(RECONCILE_RE, "B's reconcile pass")
						expect(socks["b"], "b", "fetch file " + ref, "ok")
						# ITS ROUND OVER FIRST, whose last step fetches what
						# was asked meanwhile (sec 637): what B holds is then
						# what an attempt with no address for C could get.
						b.settled(rec)
						d_round = b.log().count("reconcile pass")
						state = held(socks["b"], "b", root)
						if state == "whole" or WHOLE_RE.search(b.log()):
							raise failed("b: B fetched the file with no address for C (%s, "
							             "%d pass(es))" % (state, d_round))
					finally:
						b.stop()
					if held(socks["a"], "a", root) != "none":
						raise failed("b: A holds the file, so a fetch from A would prove "
						             "nothing about C")

					# c: the address, and the file. Written into C's stream; C
					# restarted, so its first round pushes it to A, before B.
					expect(socks["c"], "c", "set setting host net/address 127.0.0.1 " + port_c,
					       "ok")
				finally:
					c.stop()
				c = daemon(run, "cc", dirs["c"], socks["c"], extra=c_args)
				try:
					c.wait_for(RECONCILE_RE, "C's reconcile pass")
					b = daemon(run, "bc", dirs["b"], socks["b"], extra=b_args)
					try:
						got = b.wait_for(WHOLE_RE, "the file whole")
						if got.groups() != (str(PAYLOAD_LEN), "1"):
							raise failed("c: B's file was %s bytes from %s peer(s)"
							             % got.groups())
						expect(socks["b"], "b", "get file %s %s" % (ref, out), "ok")
					finally:
						b.stop()
				finally:
					c.stop()
				with open(payload, "rb") as f1, open(out, "rb") as f2:
					if f1.read() != f2.read():
						raise failed("c: the file B exported is not the one C put")
				if held(socks["a"], "a", root) != "none":
					raise failed("c: A came to hold the file, so the peer may have been A")
			finally:
				a.stop()
			print("livecheck: b: with no address for C, B's fetch did not complete")
			print("livecheck: c: with C's address set, B fetched the file whole from C alone")

			# e: the root away. C sets one of its host cells and restarts; B,
			# whose --root-at reaches nobody, takes it from C (sec 586).
			c = daemon(run, "ce", dirs["c"], socks["c"], extra=c_args)
			try:
				# THE ROUND FIRST: it waits on the root, which is away, and
				# the node answers nothing until it has gone round -- the
				# history pass is the last of it that waits on a peer.
				c.wait_for(ROUND_END_RE, "C's round")
				expect(socks["c"], "c", "set setting host x/away 1", "ok")
			finally:
				c.stop()
			c = daemon(run, "ce2", dirs["c"], socks["c"], extra=c_args)
			try:
				c.wait_for(ROUND_END_RE, "C's round")
				b = daemon(run, "be", dirs["b"], socks["b"], extra=b_args)
				try:
					b.wait_for(ROUND_END_RE, "B's round")
					expect(socks["b"], "b", "get setting host=%s x/away" % keys["c"],
					       "ok host 1")
				finally:
					b.stop()
			finally:
				c.stop()
			print("livecheck: e: with the root away, B took C's setting from C")

			# f: pieces moved off a gone keeper, sec 601.
			logs = {k: os.path.join(scratch, "log-" + k) for k in ("a", "b", "c")}
			small = ["--log-segment=4096"]
			a_args = ["--udp-port=" + port_a]

			def up(who, tag, rules=()):
				args = {"a": a_args, "b": b_args, "c": c_args}[who]
				return daemon(run, tag, dirs[who], socks[who],
				              extra=args + small + ["--log-rule=" + r for r in rules],
				              log_dir=logs[who])

			def b_round(tag, others, rules=(), wait=ROUND_END_RE):
				"""B's first round with `others` up, each through its own round
				first; the match of `wait` in B's log."""
				ds = []
				try:
					for who in others:
						ds.append(up(who, tag + who))
						ds[-1].wait_for(ROUND_END_RE, who.upper() + "'s round")
					b = up("b", tag + "b", rules)
					try:
						return b.wait_for(wait, tag)
					finally:
						b.stop()
				finally:
					for d in ds:
						d.stop()

			def packed(d):
				return [n for n in (os.listdir(d) if os.path.isdir(d) else [])
				        if n.endswith(".log.zst")]

			def closed(d):
				return [n for n in (os.listdir(d) if os.path.isdir(d) else [])
				        if n.endswith(".log") and n.count(".") >= 3]

			a = up("a", "af-set")
			try:
				a.wait_for(ROUND_END_RE, "A's round")
				expect(socks["a"], "f", "set setting estate archive/erasure 1+1", "ok")
			finally:
				a.stop()
			f_runs = 0
			while not closed(logs["b"]) and not packed(logs["b"]):
				f_runs += 1
				if f_runs > 8:
					raise failed("f: eight runs and B closed no segment")
				b_round("f%d" % f_runs, ("a", "c"))
			time.sleep(11)
			b_round("f-pack", ("a", "c"), ["archive * count 0"], OWN_ARCHIVED_RE)
			archive = os.path.join(logs["b"], "archive")
			fossils = packed(archive)
			if not fossils:
				raise failed("f: B archived none of its segments")
			# CUT, PLACED AND COUNTED: a round to cut and push, one to count.
			b_round("f-cut", ("a", "c"))
			b_round("f-count", ("a", "c"), wait=COUNTED_RE)

			def placements():
				"""Each of B's cut records, as (id hex, [keeper hex, ...])."""
				d = os.path.join(archive, "pieces")
				out = []
				for n in sorted(os.listdir(d)):
					if n.endswith(".cut"):
						with open(os.path.join(d, n), "rb") as f:
							rec = f.read()
						k, m = rec[33], rec[34]
						out.append((n[:64], [rec[35 + 32 * i:67 + 32 * i].hex()
						                     for i in range(k + m)]))
				return out

			def who(key):
				return "b" if key == keys["b"] else "c" if key == keys["c"] else "a"

			before = placements()
			if len(before) != len(fossils):
				raise failed("f: %d fossil(s) and %d cut record(s)" % (len(fossils), len(before)))
			# THE GONE ONE: a keeper other than B, C where it keeps any.
			kept_by = {w for _, ks in before for w in map(who, ks)} - {"b"}
			gone = "c" if "c" in kept_by else "a"
			others = tuple(w for w in ("a", "c") if w != gone)
			a = up("a", "af-gone")
			try:
				a.wait_for(ROUND_END_RE, "A's round")
				expect(socks["a"], "f", "set setting estate archive/gone 3s", "ok")
			finally:
				a.stop()
			# B HEARS THE SETTING with every host up, then the keeper goes.
			b_round("f-hear", ("a", "c"))
			time.sleep(4)
			got = b_round("f-move", others, wait=COUNTED_RE)
			after = placements()
			moved = [(i, n) for (i, ks0), (_, ks1) in zip(before, after)
			         for n, (k0, k1) in enumerate(zip(ks0, ks1)) if k0 != k1]
			want = sum(1 for _, ks in before for k in ks if who(k) == gone)
			if int(got.group(5)) != want or len(moved) != want or any(
			        who(k) == gone for _, ks in after for k in ks):
				raise failed("f: %s keeps %d piece(s); B moved %s, its records moved %d, and "
				             "%s still keeps %d" % (gone.upper(), want, got.group(5),
				                                    len(moved), gone.upper(),
				                                    sum(1 for _, ks in after for k in ks
				                                        if who(k) == gone)))
			# AND THE NEW KEEPER HOLDS EACH, under its name.
			for fid, n in moved:
				keeper = who(dict(after)[fid][n])
				path = os.path.join(logs[keeper], "archive", "pieces", "%s.%d.piece" % (fid, n))
				if not os.path.isfile(path):
					raise failed("f: piece %d of %.8s moved to %s, which does not hold it"
					             % (n, fid, keeper.upper()))
			print("livecheck: f: %s gone, B moved its %d piece(s) to the host keeping none"
			      % (gone.upper(), want))

			# g: the gone keeper back, its moved pieces released, sec 602.
			stale = [os.path.join(logs[gone], "archive", "pieces", "%s.%d.piece" % (fid, n))
			         for fid, n in moved]
			if not all(os.path.isfile(p) for p in stale):
				raise failed("g: %s does not hold the pieces moved off it to begin with"
				             % gone.upper())
			b_round("g", ("a", "c"))
			if any(os.path.isfile(p) for p in stale):
				raise failed("g: back, %s still holds %d of the %d piece(s) moved off it"
				             % (gone.upper(), sum(map(os.path.isfile, stale)), len(stale)))
			print("livecheck: g: %s back, it let go of the %d piece(s) B released"
			      % (gone.upper(), len(stale)))

			# h: the routing manifest, signed by the root and taken by a
			# member, sec 611.
			def routing(who):
				reply = ask(socks[who], "get routing")
				return reply.split() if reply.startswith("ok ") else [reply]

			entry_c = "127.0.0.1:%s:" % port_c
			a = up("a", "ah1")
			try:
				a.wait_for(ROUND_END_RE, "A's round")
				got = routing("a")
				if len(got) < 5 or not got[1].isdigit() or entry_c + "100" not in got[4:]:
					raise failed("h: A's routing manifest is %r, without C at metric 100"
					             % (got,))
				first = int(got[1])
			finally:
				a.stop()
			c = up("c", "ch")
			try:
				c.wait_for(ROUND_END_RE, "C's round")
				expect(socks["c"], "h", "set setting host net/metric 7", "ok")
			finally:
				c.stop()
			# C AGAIN, so its round carries the setting to A; then A signs.
			b_round("h2", ("a", "c"))
			# A FIRST: its round applies C's setting and signs; then B's asks.
			a = up("a", "ah3")
			b = None
			try:
				a.wait_for(ROUND_END_RE, "A's round")
				b = up("b", "bh3")
				b.wait_for(ROUND_END_RE, "B's round")
				got = routing("b")
				if len(got) < 5 or not got[1].isdigit() or int(got[1]) <= first \
				   or entry_c + "7" not in got[4:]:
					raise failed("h: B holds %r, not a generation past %d with C at metric 7"
					             % (got, first))
			finally:
				if b:
					b.stop()
				a.stop()
			print("livecheck: h: A signed the routing manifest at generation %d, and B took "
			      "generation %s with C's metric from a peer" % (first, got[1]))
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
	print("livecheck: siblings reached one another by pairing and address")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
