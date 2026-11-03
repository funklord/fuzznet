#!/usr/bin/env python3
"""livecheck-lean: fuzznetd built with the consumer services left out, sec 856.

The holder's of 2026-11-03: build-time flags for the consumer services, "kept
separate from the ability to relay and store those subsystems". So a lean
build is held to two things at once:

    gone     each service left out answers its verbs `unsupported`, as a
             node that never had it would
    kept     what the node carries and keeps for the estate still works:
             status, records and lists, and the files a sticker pack is

One daemon, one store, a few requests; it stops the daemon on every path
out.

    estate  given the full fuzznetd too: a lean root A, and full B and C
            joined to it, each pulling from A alone. C writes a record and
            a note; A, which has no notes verbs, lists C's record, and B,
            whose one pull peer is A, comes to hold both -- the lean node
            keeping and handing on what its own build cannot use

Usage: live_lean.py PATH_TO_LEAN_FUZZNETD [PATH_TO_FULL_FUZZNETD]
"""

import os
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_trim  # noqa: E402
from live_rejoin import command, daemon  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 560.0
failed = live_trim.failed


def ask(sock, line, within=20.0):
	until = time.monotonic() + within
	while True:
		try:
			c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			c.settimeout(10.0)
			c.connect(sock)
			c.sendall(line.encode() + b"\n")
			reply = b""
			while not reply.endswith(b"\n"):
				got = c.recv(4096)
				if not got:
					break
				reply += got
			c.close()
			return reply.decode(errors="replace").strip()
		except OSError:
			if time.monotonic() > until:
				raise failed("%s never answered %r" % (sock, line))
			time.sleep(0.2)


# EACH SERVICE LEFT OUT, and requests of its that a build with it answers
# and this one must not.
GONE = {
	"stickers": ["list sticker", "get sticker 00 1", "remove sticker 00"],
	"catalogue": ["list catalog", "get catalog " + "00" * 32],
	"notes": ["list note top", "add note top hello", "list history " + "00" * 16,
	          "list shared"],
	"groups": ["list group", "add group friends", "get group " + "00" * 32],
}


class run_of:
	"""What live_rejoin's daemon wants of a run: a binary and a scratch."""

	def __init__(self, fuzznetd, scratch):
		self.fuzznetd = fuzznetd
		self.scratch = scratch
		self.started = []


def joined(sock, within=30.0):
	"""The node at `sock` back after a join's restart."""
	until = time.monotonic() + within
	while True:
		try:
			if ask(sock, "status", within=2.0).startswith("ok "):
				return
		except failed:
			pass
		if time.monotonic() > until:
			raise failed("%s did not come back after the join" % sock)
		time.sleep(0.3)


def estate(lean_path, full_path, scratch, sock_dir):
	"""A lean root carrying a full sibling's record and note to another."""
	lean, full = run_of(lean_path, scratch), run_of(full_path, scratch)
	# BELOW THE EPHEMERAL RANGE, which starts at 32768 here.
	port = 31700 + (os.getpid() % 16) * 3
	dirs = {k: os.path.join(scratch, "e-" + k) for k in "abc"}
	socks = {k: os.path.join(sock_dir, "e" + k) for k in "abc"}
	started = {}
	try:
		for d in dirs.values():
			os.mkdir(d)
		command(lean, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
		started["a"] = daemon(lean, "ea", dirs["a"], socks["a"], extra=["--udp-port=%d" % port])
		for who in "bc":
			started[who] = daemon(full, "e" + who, dirs[who], socks[who],
			                      extra=["--udp-port=%d" % (port + (1 if who == "b" else 2))])
			got = ask(socks[who], "get prekey").split()
			card = ask(socks["a"], "add peer %s delegable" % got[1]).split()
			if len(card) != 2 or card[0] != "ok":
				raise failed("estate: the lean root's add peer answered %r" % card)
			path = os.path.join(scratch, "card-" + who)
			with open(path, "w") as f:
				f.write(card[1] + "\n")
			got = ask(socks[who], "add join %s 127.0.0.1 %d" % (path, port)).split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("estate: %s's add join answered %r" % (who.upper(), got))
			joined(socks[who])
		c_host = ask(socks["c"], "get prekey").split()[1][4:68]
		if ask(socks["c"], "add record seen/wlan0/aa-bb lean") != "ok":
			raise failed("estate: C's add record was refused")
		made = ask(socks["c"], "add note top through-the-lean-root")
		if not made.startswith("ok "):
			raise failed("estate: C's add note answered %r" % made)
		until = time.monotonic() + 400.0
		a_has = b_record = b_note = False
		while not (a_has and b_record and b_note):
			if time.monotonic() > until:
				raise failed("estate: within 400 s the lean root %s C's record, and B %s it "
				             "and %s the note" % ("held" if a_has else "did not hold",
				                                  "held" if b_record else "did not hold",
				                                  "held" if b_note else "did not hold"))
			a_has = a_has or ",seen/wlan0/aa-bb," in ask(socks["a"], "list record " + c_host)
			b_record = b_record or ",seen/wlan0/aa-bb," in ask(socks["b"],
			                                                   "list record " + c_host)
			b_note = b_note or "through-the-lean-root" in ask(socks["b"], "list note top")
			time.sleep(2.0)
		if not ask(socks["a"], "list note top").startswith("unsupported"):
			raise failed("estate: the lean root answered a notes verb")
		print("livecheck-lean: estate: the lean root kept C's record and handed it and C's "
		      "note on to B, with no notes verb of its own")
	finally:
		for d in started.values():
			d.stop()


def main(argv):
	if len(argv) not in (2, 3):
		print("usage: live_lean.py PATH_TO_LEAN_FUZZNETD [PATH_TO_FULL_FUZZNETD]",
		      file=sys.stderr)
		return 2
	daemon_path = os.path.abspath(argv[1])
	with tempfile.TemporaryDirectory(prefix="fzn-lean.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzl.", dir="/tmp") as sock_dir:
		store = os.path.join(scratch, "store")
		os.mkdir(store)
		sock = os.path.join(sock_dir, "s")
		base = [daemon_path, "--fuzznet-dir=" + store, "--log-dir=" + os.path.join(scratch, "log"),
		        "--fuzznet-service=1", "--fuzznet-product=1"]
		proc = None
		try:
			r = subprocess.run(base + ["--new-root"], capture_output=True, timeout=60)
			if r.returncode != 0:
				raise failed("--new-root failed: %r" % r.stderr.decode(errors="replace")[-300:])
			proc = subprocess.Popen(base + ["--socket=" + sock], stdout=subprocess.DEVNULL,
			                        stderr=subprocess.DEVNULL, start_new_session=True)
			if not ask(sock, "status").startswith("ok "):
				raise failed("the lean daemon did not answer status")
			for service, lines in GONE.items():
				for line in lines:
					got = ask(sock, line)
					if not got.startswith("unsupported"):
						raise failed("%s left out, %r answered %r" % (service, line, got))
			print("livecheck-lean: gone: %s answer unsupported" % ", ".join(sorted(GONE)))
			if ask(sock, "add record seen/wlan0/aa-bb 1") != "ok" \
			   or not ask(sock, "list record self").startswith("ok 0 1 0 "):
				raise failed("records were not kept by the lean build")
			if ask(sock, "add listed allow aa-bb") != "ok" \
			   or ask(sock, "get listed allow aa-bb") != "ok in":
				raise failed("lists were not kept by the lean build")
			src = os.path.join(scratch, "pack")
			with open(src, "wb") as f:
				f.write(os.urandom(5000))
			got = ask(sock, "put file " + src)
			if not got.startswith("ok "):
				raise failed("a file was not kept by the lean build: %r" % got)
			root = got.split()[1][:64]
			listed = ask(sock, "list file")
			if not listed.startswith("ok ") or root not in listed:
				raise failed("the lean build did not list the file put, %s: %r" % (root, listed))
			# NO HUGE PAGE, sec 862, where the kernel hands them out always:
			# fuzznetd runs itself again when one was faulted before main.
			with open("/sys/kernel/mm/transparent_hugepage/enabled") as f:
				always = "[always]" in f.read()
			huge = 0
			with open("/proc/%d/smaps_rollup" % proc.pid) as f:
				for line in f:
					if line.startswith("AnonHugePages:"):
						huge = int(line.split()[1])
			if always and huge:
				raise failed("the lean daemon holds %d kB of huge pages" % huge)
			print("livecheck-lean: kept: status, records, lists and files%s"
			      % (", and no huge page" if always else ""))
			if len(argv) == 3:
				estate(daemon_path, os.path.abspath(argv[2]), scratch, sock_dir)
		except failed as e:
			print("livecheck-lean: FAILED -- %s" % e)
			return 1
		finally:
			if proc is not None:
				try:
					os.killpg(proc.pid, signal.SIGTERM)
					proc.wait(timeout=10)
				except (ProcessLookupError, subprocess.TimeoutExpired):
					os.killpg(proc.pid, signal.SIGKILL)
					proc.wait(timeout=10)
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
