#!/usr/bin/env python3
"""A host goes on when its disk will not: `make livecheck`, sec 917.

Runs itself again in a user and mount namespace, so that a store can be made
read-only or full with no privilege. Where that cannot be done it says SKIPPED.

    a  READ-ONLY, from the start: the host opens, says `store ram`, and takes a
       setting, a record, a note and its text, a peer added and that peer
       revoked, each read back, and a note the disk held still reads
    b  the disk writes again: all of it flushes unasked, `store disk`, and after a
       restart every one is there
    c  FULL, while running, on a tmpfs of its own: `add record` is kept, reads
       back, and flushes when room comes
    d  a rule moves a kind of work, and none reaches what must work
    e  A KEY THAT WILL NOT READ: it says so on its socket, `identity waiting`, serves
       nothing else, makes no key of its own, and starts the moment the key reads

Against a daemon with no delta, a does not open or c says the record was not
kept.

BOUNDED FROM INSIDE as live_rejoin.py is: one deadline, each daemon in its own
process group, every daemon checked gone. Its mounts go with its namespace.

Exit 0 on a pass or a skip, 1 on a failure.
"""

import os
import re
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402
from live_groups import PREKEY_HOST  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 200.0
KEY_FILE = "7-h"  # FZN_PERSIST_OWN_IDENTITY, in the store's own names


def mount(*args):
	r = subprocess.run(["mount"] + list(args), capture_output=True, timeout=10.0)
	if r.returncode != 0:
		raise failed("mount %s: %s" % (" ".join(args), r.stderr.decode(errors="replace")))


def node_says(sock):
	"""`get node`, as word pairs."""
	words = ask(sock, "get node").split()
	if not words or words[0] != "ok":
		raise failed("get node answered %r" % words)
	return dict(zip(words[1::2], words[2::2]))


def key_said(d):
	"""The identity a daemon said it loaded."""
	found = re.search(r"identity ([0-9a-f]{64}) (?:created in|loaded from)", d.stderr())
	if not found:
		raise failed("no identity said: %r" % d.stderr()[-200:])
	return found.group(1)


def node_says_any(sock):
	"""`get node` across a socket being handed over, {} while it is."""
	try:
		return node_says(sock)
	except (OSError, failed):
		return {}


def until_store(sock, want, what):
	until = time.monotonic() + 15.0
	said = {}
	while time.monotonic() < until:
		said = node_says(sock)
		if said.get("store") == want:
			return said
		time.sleep(0.25)
	raise failed("%s: get node said %r, not store %s" % (what, said, want))


def want_ok(sock, line, what):
	reply = ask(sock, line)
	if not reply.startswith("ok"):
		raise failed("%s: %s answered %r" % (what, line[:50], reply))
	return reply


def note_with_text(sock, title, letter, what):
	"""A note whose text is `letter` three hundred times, its id."""
	made = want_ok(sock, "add note top " + title, what).split()
	want_ok(sock, "set note %s text %s" % (made[1], letter * 300), what)
	return made[1]


def text_reads(sock, note, letter, what):
	got = ask(sock, "get note %s text" % note)
	if letter * 300 not in got.replace("\n", ""):
		raise failed("%s did not read: %r" % (what, got[:120]))


def inside(fuzznetd):
	class run:
		pass

	run.fuzznetd = os.path.abspath(fuzznetd)
	run.started = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		store = os.path.join(scratch, "s")
		other = os.path.join(scratch, "o")
		full = os.path.join(scratch, "f")
		sock = os.path.join(sock_dir, "s")
		for d in (store, other, full):
			os.mkdir(d)
		d = None
		try:
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + other, "--prekey"], None)
			# ONCE SERVED, so what a working host leaves on disk is what goes read-only.
			d = daemon(run, "s0", store, sock)
			want_ok(sock, "set setting host x/before 1", "setup")
			old_note = note_with_text(sock, "before", "b", "setup")
			d.stop()
			d = None

			# a: read-only.
			mount("--bind", store, store)
			mount("-o", "remount,bind,ro", store)
			d = daemon(run, "s1", store, sock)
			want_ok(sock, "set setting host x/ram 7", "a")
			if ask(sock, "get setting host x/ram").split()[-1] != "7":
				raise failed("a: the setting did not read back")
			if ask(sock, "get setting host x/before").split()[-1] != "1":
				raise failed("a: what the disk held did not read")
			want_ok(sock, "add record seen/ram b", "a")
			if not ask(sock, "get record seen/ram").endswith(",b"):
				raise failed("a: the record did not read back")
			text_reads(sock, old_note, "b", "a: on a read-only disk, a note it held")
			ram_note = note_with_text(sock, "ram", "r", "a")
			text_reads(sock, ram_note, "r", "a: a note written to RAM")
			want_ok(sock, "add peer " + prekey, "a")
			want_ok(sock, "revoke peer " + prekey[PREKEY_HOST], "a")
			until_store(sock, "ram", "a")
			print("livecheck: a: read-only, it opened and took a setting, a record, a note, "
			      "a peer and that peer's revocation")

			# b: the disk back.
			mount("-o", "remount,bind,rw", store)
			said = until_store(sock, "disk", "b")
			d.stop()
			d = daemon(run, "s2", store, sock)
			if ask(sock, "get setting host x/ram").split()[-1] != "7":
				raise failed("b: the setting did not reach the disk")
			if not ask(sock, "get record seen/ram").endswith(",b"):
				raise failed("b: the record did not reach the disk")
			text_reads(sock, ram_note, "r", "b: after a restart, the note from RAM")
			print("livecheck: b: the disk back, it all flushed and stood a restart: %s"
			      % said.get("pressure"))
			d.stop()
			d = None

			# c: full, while running.
			mount("-t", "tmpfs", "-o", "size=4m", "tmpfs", full)
			command(run, ["--fuzznet-dir=" + full, "--new-root"], None)
			d = daemon(run, "f0", full, sock)
			want_ok(sock, "set setting host x/room 1", "c")
			filler = os.path.join(full, "filler")
			with open(filler, "wb") as f:
				try:
					while True:
						f.write(b"\0" * 4096)
						f.flush()
				except OSError:
					pass
			want_ok(sock, "set setting host x/full 2", "c")
			want_ok(sock, "add record seen/full c", "c")
			full_note = note_with_text(sock, "full", "f", "c")
			text_reads(sock, full_note, "f", "c: a note on a full disk")
			if not ask(sock, "get record seen/full").endswith(",c"):
				raise failed("c: the record did not read back on a full disk")
			until_store(sock, "ram", "c")
			os.unlink(filler)
			until_store(sock, "disk", "c")
			d.stop()
			d = daemon(run, "f1", full, sock)
			text_reads(sock, full_note, "f", "c: after a restart, the note from a full disk")
			print("livecheck: c: full, it kept what it was told, and flushed when room came")

			# d: rules.
			want_ok(sock, "set setting host pressure/rank/group-lines user", "d")
			reply = ask(sock, "set setting host pressure/rank/files control")
			if reply.startswith("ok"):
				raise failed("d: a rule reached the top of the ladder: %r" % reply)
			print("livecheck: d: a rule moved a kind of work, and none reached what must work")
			d.stop()
			d = None

			# e: a key that will not read: a directory where its file was.
			keyed = os.path.join(scratch, "k")
			os.mkdir(keyed)
			command(run, ["--fuzznet-dir=" + keyed, "--new-root"], None)
			d = daemon(run, "k0", keyed, sock)
			was = key_said(d)
			d.stop()
			d = None
			key = os.path.join(keyed, KEY_FILE)
			os.rename(key, key + ".aside")
			os.mkdir(key)
			d = daemon(run, "k1", keyed, sock)
			said = node_says(sock)
			if said.get("identity") != "waiting":
				raise failed("e: a host with no key said %r" % said)
			reply = ask(sock, "status")
			if not reply.startswith("error"):
				raise failed("e: a host with no key answered status: %r" % reply)
			os.rmdir(key)
			os.rename(key + ".aside", key)
			until = time.monotonic() + 15.0
			while node_says_any(sock).get("identity") != "held":
				if time.monotonic() > until:
					raise failed("e: the key read again and the host did not start")
				time.sleep(0.2)
			if key_said(d) != was:
				raise failed("e: the host came back as another")
			print("livecheck: e: it waited for its key, said so, and started as itself")
		except failed as e:
			print("livecheck: FAILED: %s" % e, file=sys.stderr)
			return 1
		finally:
			if d:
				d.stop()
			# GONE BEFORE THE DIRECTORIES ARE: a mount point will not be removed.
			for point in (store, full):
				subprocess.run(["umount", "-l", point], capture_output=True, timeout=10.0)
	print("livecheck: a host went on with a disk read-only and a disk full")
	return 0


def main(argv):
	if len(argv) == 3 and argv[2] == "--inside":
		return inside(argv[1])
	if len(argv) != 2:
		print("usage: live_store_trouble.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2
	probe = subprocess.run(["unshare", "-Urm", "true"], capture_output=True, timeout=10.0)
	if probe.returncode != 0:
		print("livecheck: store trouble SKIPPED -- no user namespace here")
		return 0
	return subprocess.run(["unshare", "-Urm", sys.executable, os.path.abspath(__file__), argv[1],
	                       "--inside"], timeout=220.0).returncode


if __name__ == "__main__":
	sys.exit(main(sys.argv))
