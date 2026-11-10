#!/usr/bin/env python3
"""A member behind a NAT joins its root, on hull: sec 692's first step.

    hull_nat.py [FUZZNETD]

Three hull machines (qemu vms, the host's own root as their overlaid
source), on two segments named for this run:

    public  203.0.113.0/24   the root R at .10, serving on 7000; the
                             gateway's outside at .1
    home    192.168.1.0/24   the member M at .10; the gateway's inside at .1

The gateway masquerades home out of public with nftables, a home router. M
is given R's card through the shared volume, joins, and pulls from R's
public address. Each machine runs `tool/hull_node.py` in its role and
writes what it saw to the volume.

PASSES WHEN:
- R's estate setting reaches M, and M's own host setting reaches R -- the
  journal both ways through the NAT;
- R's meter counted M from the gateway's public address and never from M's
  home one, which is what shows the traffic crossed a NAT at all.

hull is `$HULL`, else `hull` on the PATH. `/dev/kvm` and `/dev/vhost-vsock`
must be open to the user (hull's own requirement).

BOUNDED FROM INSIDE: every machine's role has its own deadline; each `hull
run` is in its own process group under a timeout; the host's own deadline
stops them all, by SIGTERM and then SIGKILL; and nothing named for this run
is left running when it ends.

Exit 0 on a pass, 1 on a failure, 2 when hull is not there to run it.
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
DEADLINE_S = 360.0
ROLE_S = 300


def machine(conf, name, run_id, volume, segments, role, fuzznetd, opts):
	segs = " ".join('"%s-%s"' % (s, run_id) for s in segments)
	args = " ".join('"%s"' % a for a in [os.path.join(TOOL, "hull_node.py"), role, "/vol",
	                                     fuzznetd, "DEADLINE=%d" % ROLE_S] + opts)
	with open(conf, "w") as f:
		f.write('(machine (source "dir:/") (backend vm) (mutable overlay) (hostname "%s")\n'
		        '\t(segments %s)\n'
		        '\t(volumes (volume (host "%s") (guest "/vol")))\n'
		        '\t(command "/usr/bin/python3" %s))\n' % (name, segs, volume, args))



def stop_stragglers(scratch):
	"""Whatever still runs in `scratch`, stopped: its descriptions.

	A `hull core` a run started is a daemon of its own, reparented to init,
	its command line naming nothing of the run -- only its working directory
	does. One was found running with a machine of hull_estates' still up
	after the script had passed, sec 1002. Given 15 s to go by itself; then
	each is re-read just before it is signalled, so a pid reused meanwhile is
	left alone; SIGTERM, then SIGKILL after 20 s."""
	def found():
		out = []
		for pid in os.listdir("/proc"):
			if not pid.isdigit() or int(pid) == os.getpid():
				continue
			try:
				cwd = os.readlink("/proc/%s/cwd" % pid)
				args = open("/proc/%s/cmdline" % pid, "rb").read().replace(b"\0", b" ")
			except OSError:
				continue
			if cwd == scratch or cwd.startswith(scratch + "/"):
				out.append((int(pid), args.decode(errors="replace").strip()))
		return out

	# A GRACE FIRST: what is on its way out by itself is not left running.
	limit = time.monotonic() + 15.0
	while found() and time.monotonic() < limit:
		time.sleep(0.5)
	strays = found()
	for sig, wait in ((signal.SIGTERM, 20.0), (signal.SIGKILL, 5.0)):
		for pid, args in found():
			try:
				if open("/proc/%d/cmdline" % pid, "rb").read().replace(b"\0", b" ").decode(
				        errors="replace").strip() == args:
					os.kill(pid, sig)
			except OSError:
				pass
		limit = time.monotonic() + wait
		while found() and time.monotonic() < limit:
			time.sleep(0.5)
		if not found():
			break
	return ["%d %s" % (pid, args) for pid, args in strays]

def main(argv):
	hull = os.environ.get("HULL") or shutil.which("hull")
	if not hull or not os.access(hull, os.X_OK):
		print("hull_nat: no hull ($HULL, or hull on the PATH), so this was SKIPPED")
		return 2
	fuzznetd = os.path.abspath(argv[1] if len(argv) > 1 else os.path.join(ROOT, "fuzznetd"))
	run_id = "fzn%d" % os.getpid()
	until = time.monotonic() + DEADLINE_S
	procs = []
	strays = []
	with tempfile.TemporaryDirectory(prefix="fzn-hull.") as scratch:
		volume = os.path.join(scratch, "vol")
		os.mkdir(volume)
		plan = [
			("gateway", ["home", "public"], ["HOME_ADDR=192.168.1.1/24",
			                                 "PUBLIC_ADDR=203.0.113.1/24"]),
			("root", ["public"], ["ADDR=203.0.113.10/24", "PORT=7000"]),
			("member", ["home"], ["ADDR=192.168.1.10/24", "GATEWAY=192.168.1.1",
			                      "ROOT_ADDR=203.0.113.10:7000"]),
		]
		try:
			for role, segs, opts in plan:
				conf = os.path.join(scratch, role + ".conf")
				machine(conf, "%s-%s" % (role, run_id), run_id, volume, segs, role, fuzznetd,
				        opts)
				out = open(os.path.join(scratch, role + ".out"), "w")
				env = dict(os.environ)
				env["HULL_CORE_IDLE"] = "1"
				procs.append((role, out, subprocess.Popen(
					["timeout", str(int(DEADLINE_S)), hull, "run", "-f", conf], cwd=scratch,
					stdout=out, stderr=subprocess.STDOUT, env=env, start_new_session=True)))
			seen = {}
			while len(seen) < len(plan) and time.monotonic() < until:
				for role, _, _ in plan:
					path = os.path.join(volume, role + ".json")
					if role not in seen and os.path.exists(path):
						with open(path) as f:
							seen[role] = json.load(f)
				time.sleep(0.5)
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
			# WHAT STILL RUNS IN THE SCRATCH, sec 1002: a `hull core`
			# names nothing of the run but its directory.
			strays = stop_stragglers(scratch)
		said = {role: open(os.path.join(scratch, role + ".out")).read()[-1500:]
		        for role, _, _ in plan}
	bad = []
	for role, _, _ in plan:
		s = seen.get(role)
		if not s:
			bad.append("%s wrote nothing; it said:\n%s" % (role, said[role]))
		elif not s.get("ok"):
			bad.append("%s failed: %s" % (role, s.get("why")))
	if "root" in seen:
		for row in seen["root"].get("rows", []):
			print("hull_nat: the root's meter: " + row)
		print("hull_nat: the member's net/address at the root: %r"
		      % seen["root"].get("net/address@member"))
	if not bad:
		peers = seen["root"].get("peers", [])
		if peers != ["203.0.113.1"]:
			bad.append("the root saw the member from %r, not the gateway's public address "
			           "alone: the traffic did not cross the NAT" % peers)
	left = [l for l in subprocess.run(["ps", "-eo", "args="], capture_output=True,
	                                  text=True).stdout.splitlines() if run_id in l]
	if left:
		bad.append("left running: %r" % left)
	if strays:
		bad.append("left running in its scratch, now stopped: %r" % strays)
	if bad:
		for b in bad:
			print("hull_nat: FAILED -- " + b)
		return 1
	print("hull_nat: a member behind a NAT joined its root and the journal crossed both ways; "
	      "the root saw it only as the gateway's public address")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
