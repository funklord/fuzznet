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

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import RECONCILE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402

TAKEN_RE = re.compile(r"(\d+) sibling\(s\) paired, (\d+) pairing\(s\) taken")
WHOLE_RE = re.compile(r"file [0-9a-f]{8}, (\d+) bytes, whole from (\d+) peer\(s\)")
ROUND_END_RE = re.compile(r"history pass: ")
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
	port_a = str(50000 + os.getpid() % 2000)
	port_c = str(52000 + os.getpid() % 2000)
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
						b.wait_for(RECONCILE_RE, "B's reconcile pass")
						expect(socks["b"], "b", "fetch file " + ref, "ok")
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
							alive = f.read() != b""
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: siblings reached one another by pairing and address")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
