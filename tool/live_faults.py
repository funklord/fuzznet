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
    i  a root re-keys 100 devices, more than the 64 successions its own
       table held, every one answered `ok` and listed; started again, it
       loads and lists all 100 (sec 704) -- where the 65th was refused
    j  a root adds 60 contacts by their cards, each a host with an
       address, more than the 32 contact hosts it once reached and the 48
       its first room holds; its round grows the room and delivers to all
       60 (sec 704) -- where the 33rd host was never reached
    k  a member joined by its card, at 100 per cent loss so it can pull
       nothing, lists member held at once, and admin straight after `set
       admin` (sec 709) -- where both waited for a pull from the root to
       bring back grants the member already kept
    l  a member whose clock runs 900 s behind the root, then an hour ahead:
       its requests are dropped either way, and the root's log says why,
       read by `list log` (sec 714), and `list clock` names the member and
       the way its clock is off (sec 717), and the member measures the
       root's clock by a time ask to within 5 s (sec 719) -- where both ends
       saw only silence
    m  a crash at every reach of each crash point inside a setting, a
       pairing and a vote: each daemon, started again without the fault,
       serves, and the acts made again stand (sec 718)
    n  a full disk at every depth of the same acts, by a write budget in
       steps of 250 bytes: each act refused or kept, and none answered ok
       that a restart with room does not find (sec 718)
    o  a crash at every reach of each crash point inside a conversation's
       acts: a contact added by card, a line out of two parts, a line in
       as a delivery files it, and a read mark. Started again, the acts
       made again are answered, and every line is listed once, whole, and
       read (sec 733) -- where a cut between a line's index entry and its
       count stopped its conversation taking lines for good
    p  a full disk at every depth of the same acts: each refused or kept,
       none answered ok that a restart does not find, no line twice
    q  a crash at every reach of each crash point inside a trim pass,
       journey 3's: a store with a line in each of two conversations
       written sixty-odd days back, under faketime, and a rule pruning
       one contact's. Started again with the rule, the pass trims that
       month, the other's line still reads, and each is listed once
       (sec 746)
    r  a full disk at every depth of the same pass: with room again, the
       same

Against a daemon built without faults, phase a's B is counted at 100 per
cent loss, phase b's daemon does not die, and phase c's says nothing.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this
reuses: one deadline, each daemon in its own process group, and every
daemon checked gone.

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
from live_rejoin import RECONCILE_RE, ROUND_DONE_RE, command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

# ONE DEADLINE FOR THE WHOLE RUN, its own: phases o and p (sec 733) doubled
# the run to about two minutes at a load of 250, past half live_trim's 240 s.
live_trim.DEADLINE = time.monotonic() + 600.0
from live_events import subscriber  # noqa: E402

# A CONTACT PASS that asked S: phase d's.
PASS_RE = re.compile(r"contact pass: [1-9]\d* contact\(s\) asked")
FAULTS = ("FZN_FAULT_LOSS", "FZN_FAULT_CRASH", "FZN_FAULT_WRITE_BUDGET", "FZN_FAULT_SEED")


def faulted(env):
	"""Set the fault variables for the next daemon started, the rest cleared."""
	for k in FAULTS:
		os.environ.pop(k, None)
	os.environ.update(env)


def trim_faults(run, scratch, sock_dir):
	"""Phases q and r: journey 3's trim pass, at every crash point and at
	every depth of a full disk. One store is written old, under faketime,
	and copied for each try, so every try trims the same month."""
	if not shutil.which("faketime"):
		print("livecheck: q, r: no faketime on PATH, so they were SKIPPED")
		return

	class q:
		pass

	q.fuzznetd = run.fuzznetd
	q.started = run.started
	q.scratch = scratch
	q.sock = os.path.join(sock_dir, "q")
	template = os.path.join(scratch, "q-old")
	q.node = template
	os.mkdir(template)
	live_trim.write_old(q, "q-old")
	rule = ["--log-rule=prune messages contact=%s age 1d" % live_trim.CONTACT]

	def stands(where, tag):
		"""The rule's month trimmed, the other's line read, each listed once."""
		pass_said = None
		node = live_trim.daemon(q, tag + "-again", extra=rule)
		try:
			pass_said = node.trim_pass()
			trimmed = live_trim.row(q, where, live_trim.CONTACT)[1]
			kept = live_trim.row(q, where, live_trim.OTHER_CONTACT)[1]
		finally:
			node.stop()
		if pass_said[:2] != (1, 1) or (trimmed, kept) != (0, 1):
			raise failed("%s: started again, the pass said %r and the lines read %d and %d; "
			             "expected the rule applied, 0 and 1" % ((where, pass_said, trimmed, kept)))

	def fresh(name):
		q.node = os.path.join(scratch, name)
		shutil.copytree(template, q.node)

	swept = {}
	for point in ("persist.synced", "persist.renamed", "record.body"):
		inside = 0
		for n in range(1, 400):
			tag = "q-%s-%d" % (point, n)
			fresh(tag)
			faulted({"FZN_FAULT_CRASH": "%s:%d" % (point, n)})
			try:
				node = live_trim.daemon(q, tag, extra=rule)
			except failed as e:
				if "fault: dying at" not in str(e):
					raise
				continue  # at start, before the pass: N too small
			finally:
				faulted({})
			try:
				node.trim_pass()
				crashed = node.proc.poll() is not None
			except failed as e:
				if "exited before a trim pass" not in str(e):
					raise
				crashed = True
			finally:
				node.stop()
			if not crashed:
				break
			inside += 1
			stands("q: after a crash at %s:%d" % (point, n), tag)
		else:
			raise failed("q: %s was still reached after 400 writes" % point)
		swept[point] = inside
	if not any(swept.values()):
		raise failed("q: no crash point fell inside a trim pass: %r" % swept)
	print("livecheck: q: a crash at every write of a trim pass (%s), each started again: "
	      "the month trimmed, the other line read, each listed once"
	      % ", ".join("%s %d" % kv for kv in swept.items()))

	short = 0
	for budget in range(0, 400000, 250):
		tag = "r-%d" % budget
		fresh(tag)
		faulted({"FZN_FAULT_WRITE_BUDGET": str(budget)})
		try:
			node = live_trim.daemon(q, tag, extra=rule)
		except failed:
			continue  # full before it could serve
		finally:
			faulted({})
		try:
			try:
				node.trim_pass()
				done = live_trim.row(q, tag, live_trim.CONTACT)[1] == 0
			except failed:
				done = False
			if node.proc.poll() is not None or not ask(q.sock, "status").startswith("ok "):
				raise failed("r: at a budget of %d the daemon stopped serving" % budget)
		finally:
			node.stop()
		if done:
			break
		short += 1
		stands("r: at a budget of %d, with room again," % budget, tag)
	else:
		raise failed("r: the pass was still short of room at the largest budget")
	if not short:
		raise failed("r: no budget fell inside a trim pass")
	print("livecheck: r: a full disk at %d depths of a trim pass: with room again, the month "
	      "trimmed, the other line read, each listed once" % short)


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
					# `none` SAID, sec 721: these keys never act, so no head of
					# theirs is held, and a removal with no cut is refused.
					for verb, cut in (("add", ""), ("remove", " none")):
						reply = ask(e_sock, "%s root %s%s" % (verb, root, cut))
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
				# AND EVERY STREAM FOLLOWED: past 256 the journal had no room
				# for 300 devices' notes and conversations.
				if not re.search(r"\b300 grant\(s\) from", f.stderr()) \
				   or "no room to follow" in f.stderr():
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
				# ASKED FIRST, as in f: the socket is there before the start
				# is done.
				ask(h_sock, "list peer")
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

			# i: more re-keys than the successions' own table held.
			i_dir = os.path.join(scratch, "i")
			i_sock = os.path.join(sock_dir, "i")
			os.mkdir(i_dir)
			command(run, ["--fuzznet-dir=" + i_dir, "--new-root"], None)
			prekeys = []
			for n in range(100):
				d = os.path.join(scratch, "i%d" % n)
				os.mkdir(d)
				prekeys.append(command(run, ["--fuzznet-dir=" + d, "--prekey"], None))
			node = daemon(run, "i1", i_dir, i_sock)
			try:
				for n, prekey in enumerate(prekeys):
					reply = ask(i_sock, "add succession %064x %s" % (0x8c0000 + n, prekey))
					if not reply.startswith("ok"):
						raise failed("i: re-key %d answered %r" % (n + 1, reply))
				listed = ask(i_sock, "list succession").split()
				if len(listed) < 2 or listed[0] != "ok" or listed[1] != "100":
					raise failed("i: a root that re-keyed 100 devices listed %r" % listed[:3])
			finally:
				node.stop()
			node = daemon(run, "i2", i_dir, i_sock)
			try:
				listed = ask(i_sock, "list succession").split()
				if len(listed) < 2 or listed[0] != "ok" or listed[1] != "100" \
				   or not re.search(r"\b100 succession\(s\) from", node.stderr()):
					raise failed("i: started again, it listed %r:\n%s"
					             % (listed[:3], node.stderr()[-600:]))
			finally:
				node.stop()
			print("livecheck: i: 100 devices re-keyed and listed, and all 100 loaded again "
			      "after a restart")

			# j: more contact hosts than the round once reached.
			cards = []
			for n in range(60):
				d = os.path.join(scratch, "j%d" % n)
				sock = os.path.join(sock_dir, "j%d" % n)
				os.mkdir(d)
				command(run, ["--fuzznet-dir=" + d, "--new-root"], None)
				udp = str(int(port) + 10 + n)
				host = daemon(run, "j%d" % n, d, sock, extra=["--udp-port=" + udp])
				try:
					if ask(sock, "set setting host net/address 127.0.0.1 " + udp) != "ok":
						raise failed("j: host %d would not take its address" % n)
					card = ask(sock, "get card j%d" % n)
					if not card.startswith("ok FZC1:"):
						raise failed("j: get card at host %d answered %r" % (n, card))
					cards.append(card.split(" ", 1)[1].strip())
				finally:
					host.stop()
			j_dir = os.path.join(scratch, "j")
			j_sock = os.path.join(sock_dir, "j")
			os.mkdir(j_dir)
			command(run, ["--fuzznet-dir=" + j_dir, "--new-root"], None)
			os.environ["FZN_TUNE_PULL_EVERY"] = "2"
			try:
				j = daemon(run, "jr", j_dir, j_sock, extra=["--udp-port=" + str(int(port) + 60)])
			finally:
				del os.environ["FZN_TUNE_PULL_EVERY"]
			try:
				if ask(j_sock, "set setting host net/address 127.0.0.1 %d" % (int(port) + 60)) != "ok":
					raise failed("j: the root would not take its address")
				for n, card in enumerate(cards):
					reply = ask(j_sock, "add contact j%d %s" % (n, card))
					if not reply.startswith("ok"):
						raise failed("j: contact %d answered %r" % (n + 1, reply))
				until = time.monotonic() + 60.0
				said = ""
				while time.monotonic() < until:
					said = j.log()
					if re.search(r"\b60 host\(s\) to deliver to", said):
						break
					time.sleep(0.5)
				if not re.search(r"\b60 host\(s\) to deliver to", said) \
				   or not re.search(r"room for \d+ contact hosts", said):
					raise failed("j: 60 contact hosts kept, and the round did not grow to deliver "
					             "to all of them:\n%s" % said[-600:])
			finally:
				j.stop()
			print("livecheck: j: 60 contact hosts added, and the round grew its room and "
			      "delivered to all of them")

			# k: a member that can pull nothing holds what it keeps (sec 709).
			k_dir, k_root = (os.path.join(scratch, w) for w in ("k", "kr"))
			k_sock, kr_sock = (os.path.join(sock_dir, w) for w in ("k", "kr"))
			for d in (k_dir, k_root):
				os.mkdir(d)
			command(run, ["--fuzznet-dir=" + k_root, "--new-root"], None)
			k_prekey = command(run, ["--fuzznet-dir=" + k_dir, "--prekey"], None)
			k_card = command(run, ["--fuzznet-dir=" + k_root, "--pair=" + k_prekey, "--delegable"],
			                 None)
			command(run, ["--fuzznet-dir=" + k_dir, "--accept=" + k_card, "--join"], None)
			kr_port = str(int(port) + 70)
			root = daemon(run, "kr", k_root, kr_sock, extra=["--udp-port=" + kr_port])
			try:
				faulted({"FZN_FAULT_LOSS": "100"})
				try:
					member = daemon(run, "k", k_dir, k_sock, extra=["--root-at", "127.0.0.1", kr_port])
				finally:
					faulted({})
				try:
					held = ask(k_sock, "list capability").split()
					if "member,1,1,0" not in held[2:]:
						raise failed("k: a member at total loss lists %r, not member held by "
						             "the chain it joined with" % held)
					granted = ask(kr_sock, "grant admin " + k_prekey[4:68]).split()
					if len(granted) < 2 or granted[0] != "ok":
						raise failed("k: the root's grant admin answered %r" % granted[:2])
					chain = os.path.join(scratch, "k-admin")
					with open(chain, "w") as f:
						f.write(" ".join(granted[1:]) + "\n")
					kept = ask(k_sock, "set admin " + chain)
					if kept != "ok %d" % (len(granted) - 1):
						raise failed("k: set admin answered %r" % kept)
					until = time.monotonic() + 20.0
					while True:
						try:
							if ask(k_sock, "status").startswith("ok "):
								break
						except OSError:
							pass
						if time.monotonic() > until:
							raise failed("k: the member did not serve again after set admin")
						time.sleep(0.2)
					held = ask(k_sock, "list capability").split()
					if not any(e.startswith("admin,1,1,") for e in held[2:]):
						raise failed("k: at total loss, straight after set admin, the member "
						             "lists %r, not admin held by the chain it kept" % held)
				finally:
					member.stop()
			finally:
				root.stop()
			print("livecheck: k: a member that can pull nothing holds member and admin by the "
			      "chains it keeps")

			# l: a member's clock out of the window, said by the root (sec 714).
			if shutil.which("faketime"):
				l_dir, l_root = (os.path.join(scratch, w) for w in ("l", "lr"))
				l_sock, lr_sock = (os.path.join(sock_dir, w) for w in ("l", "lr"))
				for d in (l_dir, l_root):
					os.mkdir(d)
				command(run, ["--fuzznet-dir=" + l_root, "--new-root"], None)
				l_prekey = command(run, ["--fuzznet-dir=" + l_dir, "--prekey"], None)
				l_card = command(run, ["--fuzznet-dir=" + l_root, "--pair=" + l_prekey,
				                       "--delegable"], None)
				command(run, ["--fuzznet-dir=" + l_dir, "--accept=" + l_card, "--join"], None)
				lr_port = str(int(port) + 80)
				root = daemon(run, "lr", l_root, lr_sock, extra=["--udp-port=" + lr_port])
				told = subscriber(lr_sock, "l events")
				try:
					for skew, said, way, root_off in (("-900s", "expired", "behind", 900000),
					                                  ("+3600s", "past this node's horizon",
					                                   "ahead", -3600000)):
						os.environ["FZN_TUNE_PULL_EVERY"] = "2"
						try:
							member = daemon(run, "l" + skew, l_dir, l_sock, fake=skew,
							                extra=["--root-at", "127.0.0.1", lr_port])
						finally:
							del os.environ["FZN_TUNE_PULL_EVERY"]
						try:
							until = time.monotonic() + 30.0
							warned = []
							while time.monotonic() < until:
								warned = [e for e in ask(lr_sock, "list log 0 W").split()[3:]
								          if e.split(",")[2] == "node/clock"
								          and said.replace(" ", "%20")
								          in e]
								if warned:
									break
								time.sleep(0.5)
							if not warned:
								raise failed("l: with the member's clock %s, the root said "
								             "nothing of it in its log" % skew)
							# AND A ROW A CLIENT READS, sec 717: the member by its
							# full key, the way its clock is off.
							rows = ask(lr_sock, "list clock").split()
							if not any(r.startswith(l_prekey[4:68] + "," + way + ",")
							           for r in rows[3:]):
								raise failed("l: with the member's clock %s, list clock "
								             "answered %r" % (skew, rows))
							# AND TOLD AS IT HAPPENED: a new row, or a row turned,
							# is a `clock` event naming the member.
							heard = []
							until = time.monotonic() + 20.0
							while time.monotonic() < until:
								try:
									line = told.line()
								except failed:
									continue
								if line is None:
									break
								heard.append(line)
								if line == "event clock " + l_prekey[4:68]:
									break
							else:
								line = None
							if line != "event clock " + l_prekey[4:68]:
								raise failed("l: with the member's clock %s, no clock event "
								             "came: %r" % (skew, heard[-4:]))
							# AND THE MEMBER MEASURES THE ROOT'S CLOCK (sec 719): its
							# time ask is answered though nothing else of its is.
							until = time.monotonic() + 30.0
							measured = None
							while time.monotonic() < until and measured is None:
								for r in ask(l_sock, "list offset").split()[3:]:
									f = r.split(",")
									if len(f) == 4:
										measured = int(f[1])
								if measured is None:
									time.sleep(0.5)
							if measured is None or abs(measured - root_off) > 5000:
								raise failed("l: with the member's clock %s, it measured the "
								             "root's offset as %r, not about %d ms"
								             % (skew, measured, root_off))
						finally:
							member.stop()
				finally:
					told.close()
					root.stop()
				print("livecheck: l: a member's clock 900 s behind and an hour ahead, each "
				      "said in the root's log, listed by list clock, told as an event, and "
				      "measured by the member's own time ask")
			else:
				print("livecheck: l SKIPPED -- no faketime on PATH")

			# m: a crash at every write of the estate's acts (sec 718).
			m_dev = os.path.join(scratch, "m-dev")
			os.mkdir(m_dev)
			m_prekey = command(run, ["--fuzznet-dir=" + m_dev, "--prekey"], None)
			m_victim = "%064x" % 0x9d0000

			def m_acts(sock):
				"""The acts, each answered: a setting, a pairing, a vote."""
				said = [ask(sock, "set setting estate m/x 1"),
				        ask(sock, "add peer %s delegable" % m_prekey),
				        ask(sock, "revoke peer " + m_victim)]
				return said

			swept = {}
			for point in ("persist.synced", "persist.renamed", "record.body"):
				inside = 0
				for n in range(1, 200):
					d = os.path.join(scratch, "m-%s-%d" % (point, n))
					sock = os.path.join(sock_dir, "m%d" % n)
					os.mkdir(d)
					command(run, ["--fuzznet-dir=" + d, "--new-root"], None)
					faulted({"FZN_FAULT_CRASH": "%s:%d" % (point, n)})
					try:
						node = daemon(run, "m%s%d" % (point[0], n), d, sock)
					except failed as e:
						if "fault: dying at" not in str(e):
							raise
						continue  # at start, before any act: N too small
					finally:
						faulted({})
					try:
						m_acts(sock)
						crashed = False
					except OSError:
						crashed = True
					if not crashed:
						# AFTER EVERY ACT, ANSWERED: no write of the acts reaches
						# this point an Nth time, so the sweep is done.
						node.stop()
						break
					inside += 1
					node.stop()
					if os.path.exists(sock):
						os.unlink(sock)
					# STARTED AGAIN, NO FAULT: it serves, and every act made
					# again stands -- whatever the crash left half written.
					try:
						node = daemon(run, "m%s%dr" % (point[0], n), d, sock)
					except failed as e:
						raise failed("m: after a crash at %s:%d the daemon would not start "
						             "again:\n%s" % (point, n, str(e)[-400:]))
					try:
						again = m_acts(sock)
						if again[0] != "ok" or not again[1].startswith("ok ") \
						   or not again[2].startswith("ok " + m_victim):
							raise failed("m: after a crash at %s:%d the acts made again "
							             "answered %r" % (point, n, again))
						if ask(sock, "get setting estate m/x") != "ok root 1":
							raise failed("m: after a crash at %s:%d the setting does not "
							             "read" % (point, n))
						if not any(e.startswith(m_prekey[4:68] + ",member,")
						           for e in ask(sock, "list grant").split()[3:]):
							raise failed("m: after a crash at %s:%d the pairing's grant is "
							             "not listed" % (point, n))
					finally:
						node.stop()
				else:
					raise failed("m: %s was still reached after 200 writes" % point)
				swept[point] = inside
			if not any(swept.values()):
				raise failed("m: no crash point fell inside the acts: %r" % swept)
			print("livecheck: m: a crash at every write of a setting, a pairing and a vote "
			      "(%s), each started again and the acts made again standing"
			      % ", ".join("%s %d" % kv for kv in swept.items()))

			# n: a full disk at every depth of the same acts (sec 718): what
			# was answered ok is kept.
			refused_any = 0
			for budget in range(0, 400000, 250):
				d = os.path.join(scratch, "n-%d" % budget)
				sock = os.path.join(sock_dir, "n%d" % (budget // 250))
				os.mkdir(d)
				command(run, ["--fuzznet-dir=" + d, "--new-root"], None)
				faulted({"FZN_FAULT_WRITE_BUDGET": str(budget)})
				try:
					node = daemon(run, "n%d" % budget, d, sock)
				except failed:
					continue  # full before it could serve: a smaller disk than any act
				finally:
					faulted({})
				try:
					said = m_acts(sock)
					if not ask(sock, "status").startswith("ok "):
						raise failed("n: at a budget of %d the daemon stopped serving" % budget)
				finally:
					node.stop()
				kept = [w.startswith("ok") for w in said]
				if all(kept):
					break  # past the acts: the disk was large enough
				refused_any += 1
				if os.path.exists(sock):
					os.unlink(sock)
				# STARTED AGAIN WITH ROOM: an act answered ok is there before
				# anything is made again.
				node = daemon(run, "n%dr" % budget, d, sock)
				try:
					if kept[0] and ask(sock, "get setting estate m/x") != "ok root 1":
						raise failed("n: at a budget of %d the setting was answered ok and "
						             "is not kept" % budget)
					if kept[1] and not any(e.startswith(m_prekey[4:68] + ",member,")
					                       for e in ask(sock, "list grant").split()[3:]):
						raise failed("n: at a budget of %d the pairing was answered ok and "
						             "its grant is not kept" % budget)
					if kept[2] and "already" not in ask(sock, "revoke peer " + m_victim):
						raise failed("n: at a budget of %d the vote was answered ok and is "
						             "not kept" % budget)
					again = m_acts(sock)
					if not all(w.startswith("ok") for w in again):
						raise failed("n: at a budget of %d, with room again, the acts "
						             "answered %r" % (budget, again))
				finally:
					node.stop()
			else:
				raise failed("n: the acts were still refused at the largest budget")
			if not refused_any:
				raise failed("n: no budget fell inside the acts")
			print("livecheck: n: a full disk at %d depths of the same acts: each refused or "
			      "kept, never answered ok and lost" % refused_any)

			# o: a crash at every write of a conversation's acts (sec 733): a
			# contact added by card, a line out of two parts, a line in as a
			# delivery files it, and a read mark. Made again after the
			# crash, as a client that heard no answer would, each line is
			# listed once, whole, and read.
			o_port = 44000 + (os.getpid() % 500) * 8
			o_c = os.path.join(scratch, "o-c")
			os.mkdir(o_c)
			command(run, ["--fuzznet-dir=" + o_c, "--new-root"], None)
			o_c_sock = os.path.join(sock_dir, "oc")
			carol = daemon(run, "oc", o_c, o_c_sock, extra=["--udp-port=%d" % o_port])
			try:
				if ask(o_c_sock, "set setting host net/address 127.0.0.1 %d" % o_port) != "ok":
					raise failed("o: C's address was not set")
				card = ask(o_c_sock, "get card carol")
				if not card.startswith("ok FZC1:"):
					raise failed("o: C's get card answered %r" % card)
				card = card.split(" ", 1)[1]
				o_out, o_in = "%032x" % 0x0a1, "%032x" % 0x0a2
				# THE LONGEST TEXT, by file: a request line holds 512 bytes in
				# all, so a text of 512 cannot be written in one.
				o_long = "x" * 512
				o_long_path = os.path.join(scratch, "o-long")
				with open(o_long_path, "w") as f:
					f.write(o_long)

				def o_acts(sock):
					"""The acts, each answered. The host's address is set first,
					so the contact added can be sent this host's request."""
					return [ask(sock, "set setting host net/address 127.0.0.1 %d" % (o_port + 1)),
					        ask(sock, "add contact carol " + card),
					        ask(sock, "add message carol out %s file %s" % (o_out, o_long_path)),
					        ask(sock, "add message carol in %s at 12345 hi" % o_in),
					        ask(sock, "set message carol read " + o_in)]

				def o_answered(said):
					"""Every act answered as made with room: the contact by its key."""
					return said[0] == "ok" and said[1].startswith("ok ") and said[2:] == ["ok"] * 3

				def o_stands(sock, where):
					"""Each line listed once, whole, and the conversation read."""
					listed = ask(sock, "list message carol")
					for line_id, text in ((o_out, o_long), (o_in, "hi")):
						if listed.count("," + line_id + ",") != 1:
							raise failed("o: %s line %s listed %d times: %r"
							             % (where, line_id, listed.count("," + line_id + ","),
							                listed[:300]))
						if ",%s," % line_id not in listed or not any(
						        e.split(",")[-1] == text for e in listed.split()[4:]
						        if "," + line_id + "," in e):
							raise failed("o: %s line %s is not whole" % (where, line_id))
					unread = ask(sock, "get message carol unread")
					if unread.split()[1:2] != ["0"]:
						raise failed("o: %s the read mark does not stand: %r" % (where, unread))

				o_swept = {}
				for point in ("persist.synced", "persist.renamed", "record.body"):
					inside = 0
					for n in range(1, 400):
						d = os.path.join(scratch, "o-%s-%d" % (point, n))
						sock = os.path.join(sock_dir, "o%d" % n)
						os.mkdir(d)
						command(run, ["--fuzznet-dir=" + d, "--new-root"], None)
						faulted({"FZN_FAULT_CRASH": "%s:%d" % (point, n)})
						try:
							node = daemon(run, "o%s%d" % (point[0], n), d, sock,
							              extra=["--udp-port=%d" % (o_port + 1)])
						except failed as e:
							if "fault: dying at" not in str(e):
								raise
							continue  # at start, before any act: N too small
						finally:
							faulted({})
						try:
							o_acts(sock)
							crashed = False
						except OSError:
							crashed = True
						if not crashed:
							node.stop()
							break
						inside += 1
						node.stop()
						try:
							node = daemon(run, "o%s%dr" % (point[0], n), d, sock,
							              extra=["--udp-port=%d" % (o_port + 1)])
						except failed as e:
							raise failed("o: after a crash at %s:%d the daemon would not start "
							             "again:\n%s" % (point, n, str(e)[-400:]))
						try:
							again = o_acts(sock)
							if not o_answered(again):
								raise failed("o: after a crash at %s:%d the acts made again "
								             "answered %r" % (point, n, again))
							o_stands(sock, "after a crash at %s:%d," % (point, n))
						finally:
							node.stop()
					else:
						raise failed("o: %s was still reached after 400 writes" % point)
					o_swept[point] = inside
				if not any(o_swept.values()):
					raise failed("o: no crash point fell inside the acts: %r" % o_swept)
				print("livecheck: o: a crash at every write of a contact added, two lines and a "
				      "read mark (%s), each started again, the acts made again, every line "
				      "listed once" % ", ".join("%s %d" % kv for kv in o_swept.items()))

				# p: a full disk at every depth of the same acts (sec 733): what
				# was answered ok is kept, and nothing is filed twice.
				o_refused = 0
				for budget in range(0, 400000, 250):
					d = os.path.join(scratch, "p-%d" % budget)
					sock = os.path.join(sock_dir, "p%d" % (budget // 250))
					os.mkdir(d)
					command(run, ["--fuzznet-dir=" + d, "--new-root"], None)
					faulted({"FZN_FAULT_WRITE_BUDGET": str(budget)})
					try:
						node = daemon(run, "p%d" % budget, d, sock,
						              extra=["--udp-port=%d" % (o_port + 1)])
					except failed:
						continue  # full before it could serve
					finally:
						faulted({})
					try:
						said = o_acts(sock)
						if not ask(sock, "status").startswith("ok "):
							raise failed("p: at a budget of %d the daemon stopped serving"
							             % budget)
					finally:
						node.stop()
					kept = [w.startswith("ok") for w in said]
					if o_answered(said):
						break
					o_refused += 1
					node = daemon(run, "p%dr" % budget, d, sock,
					              extra=["--udp-port=%d" % (o_port + 1)])
					try:
						listed = ask(sock, "list message carol")
						if kept[2] and listed.count("," + o_out + ",") != 1:
							raise failed("p: at a budget of %d the line out was answered ok "
							             "and is listed %d times"
							             % (budget, listed.count("," + o_out + ",")))
						if kept[3] and listed.count("," + o_in + ",") != 1:
							raise failed("p: at a budget of %d the line in was answered ok "
							             "and is listed %d times"
							             % (budget, listed.count("," + o_in + ",")))
						if kept[4] and ask(sock, "get message carol unread").split()[1:2] != ["0"]:
							raise failed("p: at a budget of %d the read mark was answered ok "
							             "and is not kept" % budget)
						again = o_acts(sock)
						if not o_answered(again):
							raise failed("p: at a budget of %d, with room again, the acts "
							             "answered %r" % (budget, again))
						o_stands(sock, "at a budget of %d, with room again," % budget)
					finally:
						node.stop()
				else:
					raise failed("p: the acts were still refused at the largest budget")
				if not o_refused:
					raise failed("p: no budget fell inside the acts")
				print("livecheck: p: a full disk at %d depths of a conversation's acts: each "
				      "refused or kept, never answered ok and lost, no line filed twice"
				      % o_refused)
			finally:
				carol.stop()

			# q and r: a trim pass crashed, and then short of disk (sec 746).
			trim_faults(run, scratch, sock_dir)
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
						# STILL OUR CHILD, sec 741: a reaped daemon's pid, handed to
						# another run's daemon of the same binary, is not this run's.
						with open("/proc/%d/stat" % pid) as f:
							alive = alive and int(f.read().rsplit(")", 1)[1].split()[1]) == os.getpid()
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
