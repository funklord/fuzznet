#!/usr/bin/env python3
"""A node's identity backed up, reset and restored: `make livecheck`, sec 620.

One store, a root, with a contact added:

    a  `put backup DIR` refuses a directory of mode 0755 and takes an empty
       one of 0700, every file of the state in it
    b  `remove identity KEY` refuses a key that is not this node's; with
       its own key, the state is wiped, the answer comes, and the node stops,
       leaving no regular file in its store
    c  the backup copied back, the node starts with the same identity and
       knows the same contact

Against a daemon that does not stop on a reset, phase b times out; against
one whose backup skips a file, phase c finds another identity or no contact.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402

PREKEY_HOST = slice(4, 68)
CONTACT = "ab" * 32


def regular_files(top):
	"""Every regular file under `top`, not following links."""
	found = []
	for root, dirs, names in os.walk(top):
		for n in names:
			p = os.path.join(root, n)
			if os.path.isfile(p) and not os.path.islink(p):
				found.append(p)
	return found


def main(argv):
	if len(argv) != 2:
		print("usage: live_identity.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		store = os.path.join(scratch, "node")
		sock = os.path.join(sock_dir, "n")
		backup = os.path.join(scratch, "backup")
		loose = os.path.join(scratch, "loose")
		os.mkdir(store)
		try:
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)
			key = command(run, ["--fuzznet-dir=" + store, "--prekey"], None)[PREKEY_HOST]
			d = daemon(run, "n1", store, sock)
			try:
				expect(sock, "n", "add contact carol " + CONTACT, "ok")

				# a: the backup.
				os.mkdir(loose, 0o755)
				got = ask(sock, "put backup " + loose)
				if not got.startswith("error "):
					raise failed("a: a 0755 directory took a backup: %r" % got)
				os.mkdir(backup, 0o700)
				got = ask(sock, "put backup " + backup).split()
				if len(got) != 2 or got[0] != "ok" or int(got[1]) < 1:
					raise failed("a: put backup answered %r" % got)
				if len(regular_files(backup)) != int(got[1]):
					raise failed("a: the backup holds %d file(s), not the %s answered"
					             % (len(regular_files(backup)), got[1]))
				print("livecheck: a: a 0755 directory refused; %s file(s) backed up" % got[1])

				# b: the reset.
				got = ask(sock, "remove identity " + "cd" * 32)
				if not got.startswith("denied "):
					raise failed("b: a reset naming another key answered %r" % got)
				got = ask(sock, "remove identity " + key)
				if not got.startswith("ok "):
					raise failed("b: the reset answered %r" % got)
				until = time.monotonic() + 20.0
				while d.proc.poll() is None and time.monotonic() < until:
					time.sleep(0.2)
				if d.proc.poll() is None:
					raise failed("b: the node did not stop after its reset")
			finally:
				d.stop()
			left = regular_files(store)
			if left:
				raise failed("b: the reset left %d file(s): %r" % (len(left), left[:3]))
			print("livecheck: b: another key refused; the node wiped its state and stopped")

			# c: restored by copying back.
			shutil.rmtree(store)
			shutil.copytree(backup, store)
			again = command(run, ["--fuzznet-dir=" + store, "--prekey"], None)[PREKEY_HOST]
			if again != key:
				raise failed("c: the restored node is %s, not %s" % (again[:16], key[:16]))
			d = daemon(run, "n2", store, sock)
			try:
				got = ask(sock, "list contact")
				if CONTACT not in got:
					raise failed("c: the restored node lists %r" % got)
			finally:
				d.stop()
			print("livecheck: c: restored by copying back, the same identity and contact")
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
	print("livecheck: a node's identity was backed up, reset and restored")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
