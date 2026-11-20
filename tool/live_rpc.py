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
    e  a line sent in binary (sec 1161) to that group by its key, taken with
       a STATUS ok and then listed by the text verb by its text, under the
       members' id (sec 1285)
    f  this user's contacts in binary (sec 1162): a contact added, and as many
       rows as `list contact` counts, the contact among them by name and key
    g  a contact added, renamed and removed in binary (sec 1167), each
       answered ok and seen by `list contact`
    h  the contact requests in binary (sec 1169): as many rows as `list
       request` counts, then ok; a grant and a refusal of a key no request
       came from each refused in the node's words
    i  this user's groups in binary (sec 1170): as many rows as `list group`
       counts, the probe's group among them by name, then ok
    j  a file's acts in binary (sec 1303): a file put is shared with every
       contact (ok), its shares one row saying so, then ok; a share with a
       name that is no contact refused in the node's words, never as
       malformed; the file removed (ok), and the text verb no longer has it
    k  a governance act in binary (sec 1305): `set quorum 1` on the estate's
       one root answered ok, and `add root` with a key that is no key
       refused in the verb's words, never as malformed

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
CONTACTS = 0x0B  # FZN_CMD_CONTACTS
GROUPS = 0x0D    # FZN_CMD_GROUPS
STATUS = 0x13   # FZN_CMD_STATUS
FILES = 0x01    # FZN_CMD_FILES
MEMBERS = 0x09  # FZN_CMD_MEMBERS


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

			# e: a line sent in bytes, read back by the verb.
			got = binary(sock, bytes([MESSAGES, 0x86]) + rows[0][2:34] + bytes([0xe1] * 16) + bytes(33)
			             + (5).to_bytes(2, "big") + b"howdy")
			listed = ask(sock, "list message")
			# LISTED UNDER THE MEMBERS' ID, sec 1285, not the id it was written
			# under: a group's own line is listed as every member files it.
			if got != [bytes([STATUS, 0, 0])] or "howdy" not in listed:
				raise failed("e: a line sent in binary answered %r and listed %r" % (got, listed[:200]))
			print("livecheck: e: a line sent in binary to the group by its key, and listed by the verb")

			# f: the contacts, in bytes, against the text listing's.
			pal = "5a" * 32
			said = ask(sock, "add contact probe_pal " + pal)
			if not said.startswith("ok"):
				raise failed("f: a contact was not added: %r" % said)
			total = int(ask(sock, "list contact").split()[1])
			got = binary(sock, bytes([CONTACTS, 0x80]))
			rows = [m for m in got[:-1] if m[:2] == bytes([CONTACTS, 0x81])]
			named = [(m[36:36 + m[35]].decode(), m[2:34].hex()) for m in rows]
			if not got or got[-1][:2] != bytes([STATUS, 0]) or len(rows) != len(got) - 1 \
			   or len(rows) != total or ("probe_pal", pal) not in named:
				raise failed("f: contacts in binary were %r where the text verb counts %d" % (named, total))
			print("livecheck: f: %d contact(s) in binary, as many as the text verb counts, probe_pal"
			      " by name and key" % total)

			# g: a contact added, renamed and removed, in bytes.
			two = bytes([0x6b] * 32)
			for msg, want, what in (
			        (bytes([CONTACTS, 0x82]) + two + bytes([9]) + b"probe_two", "probe_two,", "added"),
			        (bytes([CONTACTS, 0x82]) + two + bytes([9]) + b"probe_new", "probe_new,", "renamed"),
			        (bytes([CONTACTS, 0x83]) + two, None, "removed")):
				got = binary(sock, msg)
				listed = ask(sock, "list contact")
				shown = want in listed if want else ("6b" * 32) not in listed
				if not got or got[-1][:2] != bytes([STATUS, 0]) or not shown:
					raise failed("g: a contact %s in binary answered %r and listed %r"
					             % (what, got, listed[:200]))
			print("livecheck: g: a contact added, renamed and removed in binary, each seen by the"
			      " text verb")

			# h: the requests, in bytes.
			total = int(ask(sock, "list request").split()[1])
			got = binary(sock, bytes([CONTACTS, 0x85]))
			rows = [m for m in got[:-1] if m[:2] == bytes([CONTACTS, 0x86])]
			if not got or got[-1][:2] != bytes([STATUS, 0]) or len(rows) != total:
				raise failed("h: the requests in binary were %r where the text verb counts %d"
				             % (got, total))
			nobody = bytes([0x7a] * 32)
			for msg, what in ((bytes([CONTACTS, 0x87]) + nobody + bytes([3]) + b"zed", "let in"),
			                  (bytes([CONTACTS, 0x88]) + nobody, "turned away")):
				got = binary(sock, msg)
				if len(got) != 1 or got[0][:2] != bytes([STATUS, 3]) or b"no request" not in got[0]:
					raise failed("h: a key no request came from %s answered %r" % (what, got))
			print("livecheck: h: %d request(s) in binary as the text verb counts, and a key with"
			      " none refused both ways" % total)

			# i: the groups, in bytes.
			total = int(ask(sock, "list group").split()[1])
			got = binary(sock, bytes([GROUPS, 0x80]))
			rows = [m for m in got[:-1] if m[:2] == bytes([GROUPS, 0x81])]
			names = [m[48:48 + m[47]].decode() for m in rows]
			if not got or got[-1][:2] != bytes([STATUS, 0]) or len(rows) != total or total < 1 \
			   or "probe_crew" not in names:
				raise failed("i: the groups in binary were %r where the text verb counts %d"
				             % (names, total))
			print("livecheck: i: %d group(s) in binary as the text verb counts, probe_crew among"
			      " them" % total)

			# j: a file's acts, in bytes (sec 1303).
			path = os.path.join(scratch, "probe.bin")
			with open(path, "wb") as f:
				f.write(os.urandom(3000))
			put = ask(sock, "put file %s" % path).split()
			if len(put) < 2 or put[0] != "ok":
				raise failed("j: put file answered %r" % put)
			root = bytes.fromhex(put[1][:64])
			got = binary(sock, bytes([FILES, 0x86]) + root + bytes([1, 0]))
			if len(got) != 1 or got[0][:2] != bytes([STATUS, 0]):
				raise failed("j: a share with every contact in binary answered %r" % got)
			got = binary(sock, bytes([FILES, 0x87]) + root)
			if len(got) != 2 or got[0][:3] != bytes([FILES, 0x88, 0]) or got[1][:2] != bytes([STATUS, 0]):
				raise failed("j: the shares in binary were %r" % got)
			got = binary(sock, bytes([FILES, 0x86]) + root + bytes([1, 6]) + b"nobody")
			if len(got) != 1 or got[0][0] != STATUS or got[0][1] in (0, 2):
				raise failed("j: a share with no contact in binary answered %r" % got)
			got = binary(sock, bytes([FILES, 0x85]) + root)
			if len(got) != 1 or got[0][:2] != bytes([STATUS, 0]):
				raise failed("j: a file removed in binary answered %r" % got)
			still = ask(sock, "get file %s" % root.hex())
			if still.startswith("ok"):
				raise failed("j: the file removed in binary is still answered %r" % still)
			print("livecheck: j: a file shared, its shares listed, a stranger refused and the file"
			      " removed, in binary")

			# k: a governance act, in bytes (sec 1305).
			got = binary(sock, bytes([MEMBERS, 0x98, 2, 0, 1]) + b"1")
			if len(got) != 1 or got[0][:2] != bytes([STATUS, 0]):
				raise failed("k: set quorum 1 in binary answered %r" % got)
			got = binary(sock, bytes([MEMBERS, 0x98, 0, 0, 2]) + b"zz")
			if len(got) != 1 or got[0][0] != STATUS or got[0][1] in (0, 2):
				raise failed("k: add root with no key in binary answered %r" % got)
			print("livecheck: k: a quorum set in binary, and a root that is no key refused in the"
			      " verb's words")
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
