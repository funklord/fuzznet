#!/usr/bin/env python3
"""The typed client against a running node: `make livecheck`, sec 1098.

    a  a fresh host's fuzznetd answers every fzn_rpc_ call rpc_probe makes, and
       each answer parses: the client's grammar is the daemon's
    b  named objects asked in binary (sec 1152), in bytes written here rather
       than by the client: `get` answers the row the text verb reads, and
       `list` a row each then a STATUS ok -- so the probe's object calls are
       known to have a binary node to speak to, not only a text one
    c  every conversation's newest line and count asked in binary (sec 1155),
       in bytes written here: as many rows as the text verbs' totals, then ok
    d  the lines asked in binary (sec 1159): a line written to the probe's
       group, everyone's lines the text listing's by id and in order, then
       ok, and the group's own asked by its key, marked a group's

rpc_test checks the client against the grammar it believes, over a scripted
node; this checks the belief. A verb renamed or a field moved on the daemon's
side fails here by the call's name.

BOUNDED FROM INSIDE as live_rejoin.py is: one deadline, the daemon in its own
process group, and checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 90.0

OBJECTS = 0x15  # FZN_CMD_OBJECTS, wire/cmd.h
MESSAGES = 0x0A  # FZN_CMD_MESSAGES
STATUS = 0x13   # FZN_CMD_STATUS


def binary(sock_path, msg):
	"""MSG framed and sent on its own connection; every framed answer, until the
	node closes."""
	s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	s.settimeout(10.0)
	s.connect(sock_path)
	try:
		s.sendall(len(msg).to_bytes(2, "big") + msg)
		s.shutdown(socket.SHUT_WR)
		buf = b""
		while True:
			got = s.recv(65536)
			if not got:
				break
			buf += got
	finally:
		s.close()
	out = []
	while buf:
		n = int.from_bytes(buf[:2], "big")
		if n == 0 or len(buf) < 2 + n:
			raise failed("b: an answer cut short: %r" % buf[:40])
		out.append(buf[2:2 + n])
		buf = buf[2 + n:]
	return out


def row(m):
	"""A row message's name, value and allowed words."""
	if len(m) < 3 or m[0] != OBJECTS or m[1] != 0x85:
		raise failed("b: not a row: %r" % m[:16])
	at = 2
	n = m[at]
	name = m[at + 1:at + 1 + n]
	at += 1 + n
	n = m[at]
	value = m[at + 1:at + 1 + n]
	at += 1 + n + 8 + 32
	n = m[at]
	return name.decode(), value.decode(), m[at + 1:at + 1 + n].decode()


def main(argv):
	if len(argv) != 3:
		print("usage: live_rpc.py PATH_TO_FUZZNETD PATH_TO_RPC_PROBE", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	probe = os.path.abspath(argv[2])
	run.started = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		store = os.path.join(scratch, "s")
		sock = os.path.join(sock_dir, "s")
		os.mkdir(store)
		d = None
		try:
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)
			d = daemon(run, "s0", store, sock)
			r = subprocess.run([probe, sock], capture_output=True, text=True, timeout=60)
			if r.returncode != 0:
				raise failed("a: rpc_probe answered %d:\n%s" % (r.returncode, r.stderr.rstrip()))
			print("livecheck: a: %s" % r.stdout.strip())

			# b: the same object, asked in bytes.
			text = ask(sock, "get object probe_lamp").split()
			got = binary(sock, bytes([OBJECTS, 0x82, 10]) + b"probe_lamp")
			if len(got) != 1 or row(got[0])[:2] != ("probe_lamp", text[1]):
				raise failed("b: a binary get answered %r where the text verb said %r" % (got, text))
			got = binary(sock, bytes([OBJECTS, 0x83]))
			names = [row(m)[0] for m in got[:-1]]
			if not got or got[-1][:2] != bytes([STATUS, 0]) or "probe_lamp" not in names:
				raise failed("b: a binary list answered %r" % got)
			got = binary(sock, bytes([OBJECTS, 0x82, 6]) + b"nobody")
			if got != [bytes([STATUS, 0, 0])]:
				raise failed("b: a binary get of nothing answered %r" % got)
			print("livecheck: b: in binary, probe_lamp read %s as the text verb does, and a"
			      " list of %d ended with ok" % (text[1], len(names)))

			# c: the conversation list's two listings, in bytes.
			for op, verb, row_op in ((0x80, "newest", 0x82), (0x81, "unread", 0x83)):
				total = int(ask(sock, "list message " + verb).split()[1])
				got = binary(sock, bytes([MESSAGES, op]))
				rows = [m for m in got[:-1] if m[:2] == bytes([MESSAGES, row_op])]
				if not got or got[-1][:2] != bytes([STATUS, 0]) or len(rows) != len(got) - 1 \
				   or len(rows) != total or (verb == "newest" and total < 1):
					raise failed("c: %s in binary answered %d message(s) where the text verb"
					             " counts %d: %r" % (verb, len(got), total, got[:3]))
			print("livecheck: c: newest and unread in binary, as many rows as the text verbs count"
			      " (the probe's group among them)")

			# d: the lines, in bytes, against the text listing's.
			said = ask(sock, "add message @probe_crew out " + "d1" * 16 + " hello")
			if not said.startswith("ok"):
				raise failed("d: a line to the probe's group was not written: %r" % said)
			text = ask(sock, "list message").split()
			shown = int(text[2])
			ids = [item.split(",")[2] for item in text[4:4 + shown]]
			got = binary(sock, bytes([MESSAGES, 0x84, 0]) + bytes(32) + bytes(4) + (20).to_bytes(2, "big"))
			rows = [m for m in got[:-1] if m[:2] == bytes([MESSAGES, 0x85])]
			if shown < 1 or not got or got[-1][:2] != bytes([STATUS, 0]) or len(rows) != len(got) - 1 \
			   or [m[34:50].hex() for m in rows] != ids:
				raise failed("d: everyone's lines in binary were %r where the text listing has %r"
				             % ([m[34:50].hex() for m in rows], ids))
			mine = binary(sock, bytes([MESSAGES, 0x84, 1]) + rows[0][2:34] + bytes(4)
			              + (20).to_bytes(2, "big"))
			if len(mine) != 2 or mine[0][34:50].hex() != ids[0] or mine[0][50] != 1:
				raise failed("d: the group's lines asked by its key answered %r" % mine)
			print("livecheck: d: %d line(s) in binary, the text listing's by id and in order, and"
			      " the group's own asked by its key" % shown)
		except (failed, TimeoutError, subprocess.TimeoutExpired) as e:
			print("livecheck: FAILED -- %s" % e, file=sys.stderr)
			return 1
		finally:
			if d:
				d.stop()
	print("livecheck: the typed client reads what a running node says")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
