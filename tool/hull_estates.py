#!/usr/bin/env python3
"""Two estates behind NATs, end to end, on hull: sec 692's topology.

    hull_estates.py [FUZZNETD_FAULTS]

Eight qemu machines on four segments named for the run, each running
`tool/hull_node.py` -- a gateway's NAT, or a node's plan of steps:

    public  203.0.113.0/24  A's root at .10 (a server: reachable), and the
                            outsides of three gateways, .1 .2 .3
    homea   192.168.1.0/24  A's home machine at .10, behind gateway A
    phone   10.0.0.0/24     A's phone at .10, behind a NAT of its own
    homeb   192.168.2.0/24  B's root at .10 and B's member at .11, behind
                            gateway B: nobody outside can reach either

THE JOURNEYS, each a labelled step whose outcome and time are recorded:
- within A: the home machine and the phone join A's root and take its
  estate setting;
- within B: the member joins B's root over their LAN, and takes B's;
- between them: B's root asks A by A's card, A's root approves, and B
  writes A a line, which A's root and A's phone come to hold; A's phone
  writes B a line back, which B's root comes to hold -- a machine nothing
  can reach, reached.

A step that fails is recorded and the rest go on (each machine's later
steps are soft), so one run maps every journey: the point is finding what
breaks, and the table is the finding.

The faults build is used for its knobs (sec 692): `PULL_EVERY` is 5 s, so a
journey takes seconds, not minutes. Nothing else of it is turned on.

hull is `$HULL`, else `hull` on the PATH; /dev/kvm and /dev/vhost-vsock
open to the user.

BOUNDED FROM INSIDE: every machine's plan has its own deadline; each `hull
run` is in its own process group under a timeout; the host's deadline stops
them all; and nothing named for this run is left running.

Exit 0 when every step passed, 1 when any failed, 2 without hull.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

TOOL = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOL)
ROLE_S = 600
DEADLINE_S = 720.0
TUNE = {"FZN_TUNE_PULL_EVERY": "5"}
# A'S ROOT RELAYING, or -- HULL_ESTATES_RELAY=0 -- not: then A's phone's
# line can reach B only by an introduction through A's root (sec 698).
RELAY = "off" if os.environ.get("HULL_ESTATES_RELAY") == "0" else "on"
LINE_B = "62" * 16
LINE_A = "61" * 16

GATEWAYS = {
	"gw_a": ("homea", "192.168.1.1/24", "203.0.113.1/24"),
	"gw_b": ("homeb", "192.168.2.1/24", "203.0.113.2/24"),
	"gw_p": ("phone", "10.0.0.1/24", "203.0.113.3/24"),
}


def joiner(name, root_at):
	"""A device's plan up to its estate's setting: prekey, card, join, pull."""
	return [
		{"cli": ["--prekey"], "put": "prekey.%s" % name},
		{"wait": "card.%s" % name, "var": "card"},
		{"cli": ["--accept={card}", "--join"]},
		{"daemon": ["--root-at"] + root_at.split(":"), "env": TUNE},
	]


def plans():
	"""Every node's: NAME -> (segment, ADDR, GATEWAY or None, gateway ready file, steps)."""
	a_root = [
		{"cli": ["--new-root"]},
		{"wait": "prekey.a_home", "var": "pk"},
		{"cli": ["--pair={pk}", "--delegable"], "put": "card.a_home"},
		{"wait": "prekey.a_phone", "var": "pk"},
		{"cli": ["--pair={pk}", "--delegable"], "put": "card.a_phone"},
		{"daemon": ["--udp-port=7000"], "env": TUNE},
		{"ask": "set setting host net/address 203.0.113.10 7000", "expect": "ok"},
		{"ask": "set setting estate e2e/a 1", "expect": "ok"},
		# A SERVER RELAYING, its owner's choice and off by default (sec 622):
		# for this estate and its contacts, to a host that said hello.
		{"ask": "set setting host relay/enabled %s" % RELAY, "expect": "ok"},
		# AND ADVERTISING ITS HOSTS to contacts, its owner's choice too (sec
		# 611): a contact that does not know A's phone cannot open its line.
		{"ask": "set setting estate routing/advertise on", "expect": "ok"},
		{"ask": "get card alice", "expect": "ok FZC1:", "word": 1, "put": "card.alice"},
		{"wait": "root.b", "var": "broot"},
		{"until": "list request", "contains": "{broot}", "within": 180,
		 "label": "A's root holds B's request", "soft": True},
		{"ask": "grant request {broot} bob", "expect": "ok",
		 "label": "A's root approves B", "soft": True},
		{"until": "list message {broot}", "contains": "hello%20from%20b", "within": 240,
		 "label": "B's line at A's root", "soft": True},
		{"ask": "list device {broot}", "label": "B's devices at A's root", "keep": True,
		 "soft": True},
		# WHAT A'S ROOT RELAYED, once A's phone has had time to ask it.
		{"wait": "root.b"},
		{"until": "get relay", "contains": "ok %d " % (RELAY == "on"), "within": 5,
		 "label": "A's root relays" if RELAY == "on" else "A's root does not relay",
		 "keep": True, "soft": True},
	]
	a_home = joiner("a_home", "203.0.113.10:7000") + [
		{"until": "get setting estate e2e/a", "endswith": " 1", "within": 180,
		 "label": "A's home machine takes A's setting", "soft": True},
	]
	a_phone = joiner("a_phone", "203.0.113.10:7000") + [
		{"until": "get setting estate e2e/a", "endswith": " 1", "within": 180,
		 "label": "A's phone takes A's setting", "soft": True},
		{"wait": "root.b", "var": "broot"},
		{"until": "list message {broot}", "contains": "hello%20from%20b", "within": 300,
		 "label": "B's line at A's phone", "soft": True},
		# B BY ITS ROOT KEY: the name A's root gave B, `bob`, is that host's
		# own -- found 2026-10-22, the phone's `add message bob` refused.
		{"ask": "list contact", "label": "A's phone's contacts", "keep": True, "soft": True},
		{"ask": "add message {broot} out %s hello%%20from%%20a%%20phone" % LINE_A, "expect": "ok",
		 "label": "A's phone writes B", "soft": True},
	]
	b_root = [
		{"cli": ["--new-root"]},
		{"wait": "prekey.b_home", "var": "pk"},
		{"cli": ["--pair={pk}", "--delegable"], "put": "card.b_home"},
		{"wait": "ready.gw_b"},
		{"daemon": ["--udp-port=7000"], "env": TUNE},
		{"ask": "set setting host net/address 192.168.2.10 7000", "expect": "ok"},
		{"ask": "set setting estate e2e/b 1", "expect": "ok"},
		{"ask": "get identity", "word": 2, "put": "root.b"},
		{"wait": "card.alice", "var": "acard"},
		{"ask": "add contact alice {acard}", "expect": "ok", "word": 1, "var": "aroot",
		 "label": "B's root asks A by card", "soft": True},
		{"until": "list contact", "contains": "alice", "within": 60, "soft": True},
		{"ask": "add message alice out %s hello%%20from%%20b" % LINE_B, "expect": "ok",
		 "label": "B's root writes A", "soft": True},
		{"until": "list message {aroot}", "contains": "hello%20from%20a%20phone", "within": 300,
		 "label": "A's phone's line at B's root", "soft": True},
		# WHICH OF A'S DEVICES B KNOWS: a line relayed from one B holds no
		# pairing for would be dropped unread at B.
		{"ask": "list device {aroot}", "label": "A's devices at B's root", "keep": True,
		 "soft": True},
	]
	b_home = joiner("b_home", "192.168.2.10:7000") + [
		{"until": "get setting estate e2e/b", "endswith": " 1", "within": 180,
		 "label": "B's member takes B's setting over the LAN", "soft": True},
	]
	return {
		"a_root": ("public", "203.0.113.10/24", None, None, a_root),
		"a_home": ("homea", "192.168.1.10/24", "192.168.1.1", "ready.gw_a", a_home),
		"a_phone": ("phone", "10.0.0.10/24", "10.0.0.1", "ready.gw_p", a_phone),
		"b_root": ("homeb", "192.168.2.10/24", "192.168.2.1", None, b_root),
		"b_home": ("homeb", "192.168.2.11/24", "192.168.2.1", None, b_home),
	}


def conf(path, name, run_id, volume, segments, argv):
	segs = " ".join('"%s-%s"' % (s, run_id) for s in segments)
	cmd = " ".join('"%s"' % a for a in ["/usr/bin/python3", os.path.join(TOOL, "hull_node.py")]
	               + argv)
	with open(path, "w") as f:
		f.write('(machine (source "dir:/") (backend vm) (mutable overlay) (hostname "%s")\n'
		        '\t(cpus 1) (memory "512M")\n'
		        '\t(segments %s)\n'
		        '\t(volumes (volume (host "%s") (guest "/vol")))\n'
		        '\t(command %s))\n' % (name.replace("_", "-"), segs, volume, cmd))


def main(argv):
	hull = os.environ.get("HULL") or shutil.which("hull")
	if not hull or not os.access(hull, os.X_OK):
		print("hull_estates: no hull ($HULL, or hull on the PATH), so this was SKIPPED")
		return 2
	fuzznetd = os.path.abspath(argv[1] if len(argv) > 1
	                           else os.path.join(ROOT, "faults", "fuzznetd"))
	run_id = "fze%d" % os.getpid()
	until = time.monotonic() + DEADLINE_S
	procs, names = [], []
	with tempfile.TemporaryDirectory(prefix="fzn-hull.") as scratch:
		volume = os.path.join(scratch, "vol")
		os.mkdir(volume)
		machines = []
		for name, (home, inside, outside) in GATEWAYS.items():
			machines.append((name, [home, "public"],
			                 ["gateway", "/vol", fuzznetd, "NAME=" + name, "READY=ready." + name,
			                  "HOME_ADDR=" + inside, "PUBLIC_ADDR=" + outside,
			                  "DEADLINE=%d" % ROLE_S]))
		for name, (seg, addr, gw, ready, steps) in plans().items():
			if ready:
				steps = [steps[0], steps[1], {"wait": ready}] + steps[2:]
			with open(os.path.join(volume, "plan.%s.json" % name), "w") as f:
				json.dump(steps, f)
			opts = ["NAME=" + name, "ADDR=" + addr, "DEADLINE=%d" % ROLE_S]
			if gw:
				opts.append("GATEWAY=" + gw)
			machines.append((name, [seg], ["node", "/vol", fuzznetd] + opts))
		try:
			for name, segs, args in machines:
				path = os.path.join(scratch, name + ".conf")
				conf(path, name, run_id, volume, segs, args)
				out = open(os.path.join(scratch, name + ".out"), "w")
				env = dict(os.environ)
				env["HULL_CORE_IDLE"] = "1"
				procs.append((name, out, subprocess.Popen(
					["timeout", str(int(DEADLINE_S)), hull, "run", "-f", path], cwd=scratch,
					stdout=out, stderr=subprocess.STDOUT, env=env, start_new_session=True)))
				names.append(name)
			seen, gone = {}, set()
			while len(seen) + len(gone) < len(names) and time.monotonic() < until:
				for (name, _, p) in procs:
					path = os.path.join(volume, name + ".json")
					if name not in seen and os.path.exists(path):
						with open(path) as f:
							seen[name] = json.load(f)
					elif name not in seen and p.poll() is not None:
						# A MACHINE ENDED WITHOUT ITS RESULT -- refused by hull,
						# or dead: every plan waiting on it would wait out its
						# deadline, so all are told to stop now.
						gone.add(name)
						open(os.path.join(volume, "stop"), "w").close()
				time.sleep(1.0)
			open(os.path.join(volume, "stop"), "w").close()
			for _, _, p in procs:
				try:
					p.wait(timeout=60)
				except subprocess.TimeoutExpired:
					pass
		finally:
			for _, out, p in procs:
				if p.poll() is None:
					os.killpg(p.pid, signal.SIGTERM)
					try:
						p.wait(timeout=20)
					except subprocess.TimeoutExpired:
						os.killpg(p.pid, signal.SIGKILL)
						p.wait()
				out.close()
		said = {n: open(os.path.join(scratch, n + ".out")).read()[-800:] for n in names}
		# THE LOGS, kept where the host can read them after: a run's finding
		# is as good as what explains it.
		keep = os.environ.get("HULL_ESTATES_KEEP")
		if keep:
			os.makedirs(keep, exist_ok=True)
			for n in os.listdir(volume):
				if n.endswith((".log", ".json", ".conntrack")):
					shutil.copy(os.path.join(volume, n), keep)
	bad = 0
	for name in names:
		s = seen.get(name)
		if not s:
			print("hull_estates: %-8s wrote nothing; it said: %s" % (name, said[name][-300:]))
			bad += 1
			continue
		if not s.get("ok"):
			print("hull_estates: %-8s FAILED: %s" % (name, s.get("why")))
			bad += 1
		for st in s.get("steps", []):
			print("hull_estates: %-8s %-44s %s at %5.1f s%s" % (
				name, st["label"], "ok    " if st["ok"] else "FAILED", st["at"],
				"" if st["ok"] else "  (%s)" % st.get("why", "")[:160]))
			if st.get("said"):
				print("hull_estates: %-8s   said: %s" % (name, st["said"][:300]))
			bad += 0 if st["ok"] else 1
	left = [l for l in subprocess.run(["ps", "-eo", "args="], capture_output=True,
	                                  text=True).stdout.splitlines() if run_id in l]
	if left:
		print("hull_estates: FAILED -- left running: %r" % left)
		bad += 1
	print("hull_estates: %s" % ("every journey passed" if not bad else "%d step(s) failed" % bad))
	return 0 if not bad else 1


if __name__ == "__main__":
	sys.exit(main(sys.argv))
