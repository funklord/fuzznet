#!/usr/bin/env python3
"""The fault build's faults fire: `make livecheck-faults`, sec 689 step 0b.

Run against `make fuzznetd-faults`' daemon. Each fault is shown taken, so
the scenarios built on them test something:

    a  loss: B, a device joined to A, at FZN_FAULT_LOSS=100 sends nothing
       -- A counts no reconcile bytes from it while B's round runs -- and
       at 0 A counts them
    b  a crash: a daemon with FZN_FAULT_CRASH=persist.synced dies by
       SIGKILL at its first save -- at start, or at the setting asked --
       saying where; started again without it, it serves from the same
       store
    c  a full disk: with FZN_FAULT_WRITE_BUDGET=1 a daemon says the disk
       is full, and a setting it cannot save is refused rather than
       answered `ok`
    d  rounds at FZN_TUNE_PULL_EVERY=2, one of the build's knobs (sec
       693): R's contact S does not advertise, and over six of R's
       contact passes refuses R its manifest once, saying why (sec 699)
       -- where it was asked and refused every round
    e  a root makes 80 changes to its estate's roots, more than the 64 a
       node's own tables hold, every one answered `ok`; started again, it
       loads them all and makes another (sec 703) -- where the 65th was
       refused for good, and a store holding more would not start
    f  a root pairs 300 devices, more than the 64 peers its own room once
       held and the 256 grants its index held, and starts with all of
       them; started again, it loads all 300 grants (sec 704) -- where a
       store of more than 64 peers kept the daemon from starting, and the
       257th grant was lost
    g  a root adds 300 contacts, more than the 128 its roster's own tables
       hold, every one answered `ok` and listed; started again, it loads
       all 300 onto its roster, lists them and takes another (sec 704) -- where the 129th was
       answered an error and a store holding more started without them
    h  a root revokes 300 keys, more than the 256 its revocations' tables
       held, every one answered `ok`; started again, it loads all 300 and
       revokes another (sec 704) -- where the 257th was refused and a store
       holding more would not start

Against a daemon built without faults, phase a's B is counted at 100 per
cent loss, phase b's daemon does not die, and phase c's says nothing.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this
reuses: one deadline, each daemon in its own process group, and every
daemon checked gone.

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
from live_rejoin import RECONCILE_RE, ROUND_DONE_RE, command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402

# A CONTACT PASS that asked S: phase d's.
PASS_RE = re.compile(r"contact pass: [1-9]\d* contact\(s\) asked")
FAULTS = ("FZN_FAULT_LOSS", "FZN_FAULT_CRASH", "FZN_FAULT_WRITE_BUDGET", "FZN_FAULT_SEED")


def faulted(env):
	"""Set the fault variables for the next daemon started, the rest cleared."""
	for k in FAULTS:
		os.environ.pop(k, None)
	os.environ.update(env)


def reconcile_from(sock, tag):
	"""The reconcile bytes A counted from any peer, both ways."""
	reply = ask(sock, "get transfer")
	for w in reply.split()[1:]:
		name, up, down = w.split(",")
		if name == "reconcile":
			return int(up), int(down)
	if not reply.startswith("ok"):
		raise failed("%s: get transfer answered %r" % (tag, reply))
	return 0, 0


def main(argv):
	if len(argv) != 2:
		print("usage: live_faults.py PATH_TO_FUZZNETD_WITH_FAULTS", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port = str(14000 + os.getpid() % 2000)
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		a_dir, b_dir, c_dir = (os.path.join(scratch, k) for k in "abc")
		a_sock, b_sock, c_sock = (os.path.join(sock_dir, k) for k in "abc")
		for d in (a_dir, b_dir, c_dir):
			os.mkdir(d)
		try:
			faulted({})
			command(run, ["--fuzznet-dir=" + a_dir, "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + b_dir, "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + a_dir, "--pair=" + prekey, "--delegable"],
			               None)
			command(run, ["--fuzznet-dir=" + b_dir, "--accept=" + card, "--join"], None)

			# a: B at total loss reaches A with nothing; at none it does.
			a = daemon(run, "a1", a_dir, a_sock, extra=["--udp-port=" + port])
			try:
				faulted({"FZN_FAULT_LOSS": "100"})
				b = daemon(run, "b1", b_dir, b_sock, extra=["--root-at", "127.0.0.1", port])
				faulted({})
				try:
					b.wait_for(ROUND_DONE_RE, "B's first round under total loss", within=60.0)
					if reconcile_from(a_sock, "a") != (0, 0):
						raise failed("a: A counted reconcile bytes from a B losing everything")
				finally:
					b.stop()
				b = daemon(run, "b2", b_dir, b_sock, extra=["--root-at", "127.0.0.1", port])
				try:
					b.settled(b.wait_for(RECONCILE_RE, "B's reconcile pass"))
					up, down = reconcile_from(a_sock, "a")
					if not up or not down:
						raise failed("a: A counted %d up and %d down from B at no loss"
						             % (up, down))
				finally:
					b.stop()
			finally:
				a.stop()
			print("livecheck: a: at total loss B reached A with nothing; at none, %d bytes "
			      "each way" % min(up, down))

			# b: dying at the first save, then serving again from the store.
			command(run, ["--fuzznet-dir=" + c_dir, "--new-root"], None)
			faulted({"FZN_FAULT_CRASH": "persist.synced"})
			c = daemon(run, "c1", c_dir, c_sock)
			faulted({})
			# ITS FIRST SAVE MAY BE AT START, before it answers anything.
			try:
				ask(c_sock, "set setting host x/crash 1")
			except (failed, OSError):
				pass
			until = time.monotonic() + 30.0
			while c.proc.poll() is None and time.monotonic() < until:
				time.sleep(0.2)
			status = c.proc.poll()
			said = c.stderr()
			c.stop()
			if status != -9 or "fault: dying at persist.synced" not in said:
				raise failed("b: the daemon did not die at persist.synced: %r, %r"
				             % (status, said[-300:]))
			c = daemon(run, "c2", c_dir, c_sock)
			try:
				if not ask(c_sock, "status").startswith("ok "):
					raise failed("b: the store did not serve again after the crash")
			finally:
				c.stop()
			print("livecheck: b: the daemon died by SIGKILL at persist.synced and served "
			      "again from its store")

			# c: a disk full from the first byte.
			faulted({"FZN_FAULT_WRITE_BUDGET": "1"})
			c = daemon(run, "c3", c_dir, c_sock)
			faulted({})
			try:
				reply = ask(c_sock, "set setting host x/full 1")
				said = c.stderr()
				if "fault: the disk is full" not in said or reply == "ok":
					raise failed("c: a full disk answered %r and said %r" % (reply, said[-300:]))
			finally:
				c.stop()
			print("livecheck: c: the disk was full, said so, and the setting was refused: %r"
			      % reply)

			# d: a contact that does not advertise, asked its manifest once.
			s_dir, r_dir = (os.path.join(scratch, k) for k in ("s", "r"))
			s_sock, r_sock = (os.path.join(sock_dir, k) for k in ("s", "r"))
			s_port, r_port = str(int(port) + 1), str(int(port) + 2)
			keys = {}
			for k, d in (("s", s_dir), ("r", r_dir)):
				os.mkdir(d)
				command(run, ["--fuzznet-dir=" + d, "--new-root"], None)
				keys[k] = command(run, ["--fuzznet-dir=" + d, "--prekey"], None)[4:68]
			r_prekey = command(run, ["--fuzznet-dir=" + r_dir, "--prekey"], None)
			s = daemon(run, "s1", s_dir, s_sock, extra=["--udp-port=" + s_port])
			try:
				for line in ("set setting host net/address 127.0.0.1 " + s_port,
				             "add contact rory " + keys["r"]):
					if ask(s_sock, line) != "ok":
						raise failed("d: S's %r refused" % line)
				share = ask(s_sock, "grant share rory " + r_prekey)
				if not share.startswith("ok "):
					raise failed("d: grant share answered %r" % share)
				card_path = os.path.join(scratch, "card")
				with open(card_path, "w") as f:
					f.write(share.split(" ", 1)[1])
				r = daemon(run, "r1", r_dir, r_sock, extra=["--udp-port=" + r_port])
				try:
					for line in ("add contact sam " + keys["s"],
					             "add received sam 127.0.0.1 %s %s" % (s_port, card_path)):
						if ask(r_sock, line) != "ok":
							raise failed("d: R's %r refused" % line)
				finally:
					r.stop()
				os.environ["FZN_TUNE_PULL_EVERY"] = "2"
				try:
					r = daemon(run, "r2", r_dir, r_sock, extra=["--udp-port=" + r_port])
				finally:
					del os.environ["FZN_TUNE_PULL_EVERY"]
				try:
					until = time.monotonic() + 90.0
					while len(PASS_RE.findall(r.log())) < 6 and time.monotonic() < until:
						time.sleep(0.5)
					said = r.log()
				finally:
					r.stop()
			finally:
				s.stop()
			passes = len(PASS_RE.findall(said))
			plainly = said.count("does not advertise where it is reached")
			otherwise = said.count("may only fetch what is shared")
			if passes < 6 or plainly != 1 or otherwise:
				raise failed("d: over %d of R's contact passes S refused its manifest %d time(s) "
				             "saying it does not advertise and %d otherwise"
				             % (passes, plainly, otherwise))
			print("livecheck: d: over %d contact passes S, not advertising, refused R its "
			      "manifest once" % passes)

			# e: more root changes than a node's own tables hold.
			e_dir = os.path.join(scratch, "e")
			e_sock = os.path.join(sock_dir, "e")
			os.mkdir(e_dir)
			command(run, ["--fuzznet-dir=" + e_dir, "--new-root"], None)
			e = daemon(run, "e1", e_dir, e_sock)
			try:
				for i in range(40):
					root = "%064x" % (0x5e00 + i)
					for verb in ("add", "remove"):
						reply = ask(e_sock, "%s root %s" % (verb, root))
						if not reply.startswith("ok"):
							raise failed("e: change %d, %s root, answered %r"
							             % (2 * i + (verb == "remove") + 1, verb, reply))
			finally:
				e.stop()
			e = daemon(run, "e2", e_dir, e_sock)
			try:
				reply = ask(e_sock, "add root %064x" % 0x5f00)
				if not reply.startswith("ok"):
					raise failed("e: after a restart over 80 root changes, the 81st answered %r"
					             % reply)
			finally:
				e.stop()
			print("livecheck: e: 80 root changes taken, loaded again after a restart, and an "
			      "81st")

			# f: more peers than a node's first room.
			f_dir = os.path.join(scratch, "f")
			f_sock = os.path.join(sock_dir, "f")
			os.mkdir(f_dir)
			command(run, ["--fuzznet-dir=" + f_dir, "--new-root"], None)
			for i in range(300):
				d = os.path.join(scratch, "f%d" % i)
				os.mkdir(d)
				prekey = command(run, ["--fuzznet-dir=" + d, "--prekey"], None)
				command(run, ["--fuzznet-dir=" + f_dir, "--pair=" + prekey], None)
			f = daemon(run, "f1", f_dir, f_sock)
			try:
				listed = ask(f_sock, "list peer").split()
				if len(listed) < 2 or listed[0] != "ok" or listed[1] != "300":
					raise failed("f: a root that paired 300 devices listed %r" % listed[:3])
			finally:
				f.stop()
			f = daemon(run, "f2", f_dir, f_sock)
			try:
				# ASKED FIRST: the socket is there before the grants load,
				# and an answer comes only once the start is done.
				ask(f_sock, "list peer")
				if not re.search(r"\b300 grant\(s\) from", f.stderr()):
					raise failed("f: started again, it did not load all 300 grants:\n%s"
					             % f.stderr()[-600:])
			finally:
				f.stop()
			print("livecheck: f: 300 devices paired, the daemon started with all of them, and "
			      "loaded all 300 grants again")

			# g: more contacts than the roster's own tables hold.
			g_dir = os.path.join(scratch, "g")
			g_sock = os.path.join(sock_dir, "g")
			os.mkdir(g_dir)
			command(run, ["--fuzznet-dir=" + g_dir, "--new-root"], None)
			g = daemon(run, "g1", g_dir, g_sock)
			try:
				for i in range(300):
					reply = ask(g_sock, "add contact g%d %064x" % (i, 0x6a0000 + i))
					if not reply.startswith("ok"):
						raise failed("g: contact %d answered %r" % (i + 1, reply))
				listed = ask(g_sock, "list contact").split()
				if len(listed) < 2 or listed[0] != "ok" or listed[1] != "300":
					raise failed("g: a root that added 300 contacts listed %r" % listed[:3])
			finally:
				g.stop()
			g = daemon(run, "g2", g_dir, g_sock)
			try:
				listed = ask(g_sock, "list contact").split()
				if len(listed) < 2 or listed[0] != "ok" or listed[1] != "300":
					raise failed("g: started again over 300 contacts, it listed %r" % listed[:3])
				# THE ROSTER, not only the names: a node that could not load
				# it starts with the roster off and lists the names anyway.
				if not re.search(r"\b300 roster record\(s\)", g.stderr()) \
				   or any(w.endswith(",absent") for w in listed):
					raise failed("g: started again, it did not hold all 300 on its roster:\n%s"
					             % g.stderr()[-600:])
				reply = ask(g_sock, "add contact g300 %064x" % (0x6a0000 + 300))
				if not reply.startswith("ok"):
					raise failed("g: after a restart over 300 contacts, the 301st answered %r"
					             % reply)
			finally:
				g.stop()
			print("livecheck: g: 300 contacts added and listed, listed again after a restart, "
			      "and a 301st")

			# h: more revocations than the old tables held.
			h_dir = os.path.join(scratch, "h")
			h_sock = os.path.join(sock_dir, "h")
			os.mkdir(h_dir)
			command(run, ["--fuzznet-dir=" + h_dir, "--new-root"], None)
			h = daemon(run, "h1", h_dir, h_sock)
			try:
				for i in range(300):
					reply = ask(h_sock, "revoke peer %064x" % (0x7b0000 + i))
					if not reply.startswith("ok"):
						raise failed("h: revocation %d answered %r" % (i + 1, reply))
			finally:
				h.stop()
			h = daemon(run, "h2", h_dir, h_sock)
			try:
				if not re.search(r"\b300 revocation\(s\) from", h.stderr()):
					raise failed("h: started again, it did not load all 300 revocations:\n%s"
					             % h.stderr()[-600:])
				reply = ask(h_sock, "revoke peer %064x" % (0x7b0000 + 300))
				if not reply.startswith("ok"):
					raise failed("h: after a restart over 300 revocations, the 301st answered %r"
					             % reply)
			finally:
				h.stop()
			print("livecheck: h: 300 revocations cast, all loaded again after a restart, and "
			      "a 301st")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			faulted({})
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
	print("livecheck: the fault build lost, crashed and filled its disk on demand, and its "
	      "rounds ran short")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
