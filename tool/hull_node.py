#!/usr/bin/env python3
"""One machine's part in a NAT test on hull: sec 692's end-to-end test.

    hull_node.py ROLE VOLUME FUZZNETD [NAME=VALUE ...]

Run INSIDE a hull guest, as its command, by `tool/hull_nat.py`. The guest is
root of its own kernel, so it sets its own addresses and NAT. VOLUME is a
directory shared with the host and every other machine of the test: the
machines hand each other their prekeys and cards as files in it, and each
writes what it saw to VOLUME/ROLE.json for the host to judge.

ROLES:
- gateway: eth1 on its home segment as HOME_ADDR, eth2 on the public one as
  PUBLIC_ADDR, forwarding, and nftables masquerading the home side out of
  the public one -- a home router.
- root: eth1 on the public segment at ADDR, an estate's root serving on
  PORT. It pairs the member whose prekey appears, sets an estate setting,
  and waits for the member's own host setting to reach it, through the NAT,
  by the member's push.
- member: eth1 on its home segment at ADDR, routed through GATEWAY. It
  writes its prekey, joins with the card it is given, pulls from the root
  at ROOT_ADDR, and waits for the root's setting to reach it.

BOUNDED FROM INSIDE: every wait has DEADLINE seconds in all, 300 by
default; fuzznetd is stopped before the role ends; and the role ends when
VOLUME/stop appears or the deadline passes, whichever is first.
"""

import json
import os
import socket
import subprocess
import sys
import time

CAPABILITY = ["--fuzznet-service=1", "--fuzznet-product=1"]


class failed(Exception):
	pass


def run(*argv):
	r = subprocess.run(list(argv), capture_output=True, timeout=30)
	if r.returncode != 0:
		raise failed("%s answered %d: %s" % (" ".join(argv), r.returncode,
		                                      r.stderr.decode(errors="replace")[:300]))
	return r.stdout.decode(errors="replace").strip()


def ask(sock, line):
	s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	s.settimeout(20.0)
	try:
		s.connect(sock)
		s.sendall(line.encode() + b"\n")
		buf = b""
		while b"\n" not in buf:
			chunk = s.recv(4096)
			if not chunk:
				break
			buf += chunk
	finally:
		s.close()
	return buf.decode(errors="replace").strip()


class role:
	def __init__(self, name, volume, fuzznetd, opts):
		self.name = name
		self.volume = volume
		self.fuzznetd = fuzznetd
		self.opts = opts
		self.until = time.monotonic() + float(opts.get("DEADLINE", "300"))
		self.seen = {"role": name}
		self.proc = None

	def left(self):
		return self.until - time.monotonic()

	def wait_file(self, name):
		path = os.path.join(self.volume, name)
		while not os.path.exists(path):
			if self.left() <= 0:
				raise failed("%s never appeared" % name)
			if os.path.exists(os.path.join(self.volume, "stop")):
				raise failed("stopped waiting for %s" % name)
			time.sleep(0.2)
		with open(path) as f:
			return f.read().strip()

	def put_file(self, name, text):
		tmp = os.path.join(self.volume, "." + name + ".tmp")
		with open(tmp, "w") as f:
			f.write(text + "\n")
		os.rename(tmp, os.path.join(self.volume, name))

	def wait_reply(self, sock, line, good, what):
		reply = ""
		while self.left() > 0:
			try:
				reply = ask(sock, line)
			except OSError:
				reply = ""
			if good(reply):
				return reply
			time.sleep(0.5)
		raise failed("%s: %r last answered %r" % (what, line, reply))

	def daemon(self, store, sock, extra):
		log = open("/tmp/fuzznetd.%s.err" % self.name, "w")
		self.log_dir = "/tmp/log-" + self.name
		self.proc = subprocess.Popen(
			[self.fuzznetd, "--socket=" + sock, "--fuzznet-dir=" + store,
			 "--log-dir=/tmp/log-" + self.name, "--log-level=debug"] + CAPABILITY + extra,
			stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
		self.wait_reply(sock, "status", lambda r: r.startswith("ok "), "the daemon's start")

	def address(self, nic, addr, gateway=None):
		run("ip", "link", "set", nic, "up")
		run("ip", "addr", "add", addr, "dev", nic)
		if gateway:
			# REPLACING passt's default through eth0, so the home machine reaches
			# out only through its gateway.
			run("ip", "route", "replace", "default", "via", gateway, "dev", nic)

	def finish(self, ok, why=""):
		self.seen["ok"] = ok
		if why:
			self.seen["why"] = why
		self.put_file(self.opts.get("NAME", self.name) + ".json",
		              json.dumps(self.seen, sort_keys=True))
		# HELD UP until the host says stop, so every machine is up while any
		# still waits on it.
		while self.left() > 0 and not os.path.exists(os.path.join(self.volume, "stop")):
			time.sleep(0.5)
		if self.proc and self.proc.poll() is None:
			self.proc.terminate()
			try:
				self.proc.wait(timeout=10)
			except subprocess.TimeoutExpired:
				self.proc.kill()
		# THE DAEMON'S LOG KEPT, at most a MiB of its end, for the host to
		# read why a step failed: the guest's /tmp goes with the machine.
		log = os.path.join(getattr(self, "log_dir", "/nonexistent"), "fuzznetd.log")
		if os.path.exists(log):
			with open(log, "rb") as f:
				f.seek(max(0, os.path.getsize(log) - (1 << 20)))
				tail = f.read()
			with open(os.path.join(self.volume, self.opts.get("NAME", self.name) + ".log"),
			          "wb") as f:
				f.write(tail)


def gateway(r):
	r.address("eth1", r.opts["HOME_ADDR"])
	r.address("eth2", r.opts["PUBLIC_ADDR"])
	# THE NAT BEFORE THE FORWARDING: forwarding first let a datagram that
	# came in the gap through unmasqueraded, and the root saw the member's
	# home address -- one run in three, until this order.
	rules = ("table ip nat {\n"
	         " chain post { type nat hook postrouting priority 100; oifname \"eth2\" masquerade; }\n"
	         "}\n")
	with open("/tmp/nat.nft", "w") as f:
		f.write(rules)
	run("/usr/sbin/nft", "-f", "/tmp/nat.nft")
	r.seen["nat"] = run("/usr/sbin/nft", "list", "ruleset").count("masquerade")
	with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
		f.write("1\n")
	r.put_file(r.opts.get("READY", "gateway.ready"), "1")


def root(r):
	r.address("eth1", r.opts["ADDR"])
	store, sock, port = "/tmp/store", "/tmp/fzn.sock", r.opts["PORT"]
	os.mkdir(store)
	run(r.fuzznetd, "--fuzznet-dir=" + store, "--new-root", *CAPABILITY)
	prekey = r.wait_file("prekey.member")
	card = run(r.fuzznetd, "--fuzznet-dir=" + store, "--pair=" + prekey, "--delegable",
	           *CAPABILITY).splitlines()[-1]
	r.put_file("card.member", card)
	r.daemon(store, sock, ["--udp-port=" + port])
	host = r.opts["ADDR"].split("/")[0]
	if ask(sock, "set setting host net/address %s %s" % (host, port)) != "ok" \
	   or ask(sock, "set setting estate nat/from-root 1") != "ok":
		raise failed("the root's settings were refused")
	member = r.wait_file("key.member")
	r.wait_reply(sock, "get setting host=%s nat/from-member" % member,
	             lambda x: x.endswith(" 1"), "the member's setting at the root")
	# WHERE THE MEMBER CAME FROM, as the root's meter counted it: the
	# gateway's public address, if it crossed a NAT.
	rows = ask(sock, "list transfer").split()[3:]
	r.seen["peers"] = sorted({row.split(",")[1].rsplit(":", 1)[0] for row in rows})
	# EACH ROW, family, peer and bytes each way: a peer counted only going
	# out is one asked that never answered.
	r.seen["rows"] = [",".join(row.split(",")[i] for i in (0, 1, 3, 4)) for row in rows]
	for k in ("net/address", "routing/advertise"):
		r.seen[k + "@member"] = ask(sock, "get setting host=%s %s" % (member, k))


def member(r):
	r.address("eth1", r.opts["ADDR"], r.opts["GATEWAY"])
	store, sock = "/tmp/store", "/tmp/fzn.sock"
	os.mkdir(store)
	prekey = run(r.fuzznetd, "--fuzznet-dir=" + store, "--prekey", *CAPABILITY).splitlines()[-1]
	r.put_file("prekey.member", prekey)
	card = r.wait_file("card.member")
	# NOTHING SENT before the gateway masquerades.
	r.wait_file("gateway.ready")
	run(r.fuzznetd, "--fuzznet-dir=" + store, "--accept=" + card, "--join", *CAPABILITY)
	root_host, root_port = r.opts["ROOT_ADDR"].split(":")
	r.daemon(store, sock, ["--root-at", root_host, root_port])
	key = ask(sock, "get identity").split()
	if len(key) < 2 or key[0] != "ok":
		raise failed("get identity answered %r" % key)
	r.put_file("key.member", key[1])
	r.wait_reply(sock, "get setting estate nat/from-root", lambda x: x.endswith(" 1"),
	             "the root's setting at the member")
	if ask(sock, "set setting host nat/from-member 1") != "ok":
		raise failed("the member's own setting was refused")
	r.seen["took_root_setting"] = True


def node(r):
	"""A PLAN'S STEPS, from VOLUME/plan.NAME.json, NAME this machine's: what
	`tool/hull_estates.py` asks of each machine of a topology. Each step
	is a dict:

	    {"cli": [ARG...], "put": FILE, "var": V}   fuzznetd ARG... on the
	                                                store, its last line kept
	    {"wait": FILE, "var": V}                     a file another machine
	                                                writes, read into V
	    {"daemon": [ARG...], "env": {K: V}}          fuzznetd started, serving
	    {"ask": LINE, "expect": PREFIX, "word": N,   a verb; its reply's word N
	     "put": FILE, "var": V}                      kept
	    {"until": LINE, "contains": S | "endswith": S, "within": SECONDS}
	                                                asked again until it says so

	`{V}` in a string is a variable. Every step may carry a "label", under
	which its outcome and the seconds since the plan began are recorded; a
	step with "soft": true records a failure and the plan goes on, so one
	run maps every journey rather than stopping at the first that fails."""
	r.address("eth1", r.opts["ADDR"], r.opts.get("GATEWAY"))
	store, sock = "/tmp/store", "/tmp/fzn.sock"
	os.mkdir(store)
	with open(os.path.join(r.volume, "plan.%s.json" % r.opts["NAME"])) as f:
		plan = json.load(f)
	var = {}
	began = time.monotonic()
	r.seen["steps"] = []

	def sub(x):
		return x.format(**var) if isinstance(x, str) else [sub(y) for y in x]

	for step in plan:
		label = step.get("label")
		t0 = time.monotonic()
		out = ""
		try:
			if "cli" in step:
				out = run(r.fuzznetd, "--fuzznet-dir=" + store, *(sub(step["cli"]) + CAPABILITY))
				out = out.splitlines()[-1] if out else ""
			elif "wait" in step:
				out = r.wait_file(sub(step["wait"]))
			elif "daemon" in step:
				os.environ.update(step.get("env", {}))
				r.daemon(store, sock, sub(step["daemon"]))
			elif "ask" in step:
				out = ask(sock, sub(step["ask"]))
				if "expect" in step and not out.startswith(sub(step["expect"])):
					raise failed("%r answered %r" % (sub(step["ask"]), out))
			elif "until" in step:
				until = time.monotonic() + float(step.get("within", r.left()))
				while True:
					try:
						out = ask(sock, sub(step["until"]))
					except OSError:
						out = ""
					if ("contains" in step and sub(step["contains"]) in out) \
					   or ("endswith" in step and out.endswith(sub(step["endswith"]))):
						break
					if time.monotonic() > until or r.left() <= 0:
						raise failed("%r last answered %r" % (sub(step["until"]), out))
					time.sleep(1.0)
			if "word" in step:
				out = out.split()[step["word"]]
			if "var" in step:
				var[step["var"]] = out
			if "put" in step:
				r.put_file(sub(step["put"]), out)
			if label:
				r.seen["steps"].append({"label": label, "ok": True,
				                        "at": round(time.monotonic() - began, 1),
				                        "took": round(time.monotonic() - t0, 1)})
				# AN ANSWER KEPT WHOLE, where what was said is the finding.
				if step.get("keep"):
					r.seen["steps"][-1]["said"] = out[:400]
		except (failed, OSError, subprocess.TimeoutExpired, IndexError, KeyError) as e:
			r.seen["steps"].append({"label": label or str(step)[:60], "ok": False,
			                        "at": round(time.monotonic() - began, 1), "why": str(e)[:300]})
			if not step.get("soft"):
				raise failed("step %s: %s" % (label or step, e))


ROLES = {"gateway": gateway, "root": root, "member": member, "node": node}


def main(argv):
	if len(argv) < 4 or argv[1] not in ROLES:
		print("usage: hull_node.py gateway|root|member|node VOLUME FUZZNETD [NAME=VALUE ...]",
		      file=sys.stderr)
		return 2
	opts = dict(a.split("=", 1) for a in argv[4:])
	r = role(argv[1], argv[2], argv[3], opts)
	try:
		ROLES[argv[1]](r)
		r.finish(True)
	except (failed, OSError, subprocess.TimeoutExpired) as e:
		r.finish(False, str(e))
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
