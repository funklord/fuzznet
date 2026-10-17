#!/usr/bin/env python3
"""A user's library across its own hosts: `make livecheck`, sec 633.

Two stores over loopback, one user's two machines: A its root, B joined
with a grant it can pass on, pulling from A.

    a  A puts a file and names it in the catalogue; B, at its next round,
       lists A's name for it and A as the one host holding it
    a2 B holds the file's reference, carried from A (sec 634)
    b  B fetches the file by its root alone, exports it whole and equal to
       what A put, and names it too: both hosts list the two names, each by
       its own host, and two holders
    c  A takes its name back: B lists B's alone, and one holder
    g  A makes a group; B, holding none, learns it from its sibling at its
       next round, with the same members (sec 626)

Against a daemon that does not follow its siblings' catalogue stream, B
never lists A's name; against one that does not sync its siblings' groups,
B never lists A's group.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

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
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 420.0

# A ROUND'S OWN END, after its fetches and log pass: "history pass" comes
# before them (sec 637).
ROUND_END_RE = ROUND_DONE_RE
WHOLE_RE = re.compile(r"file [0-9a-f]{8}, (\d+) bytes, whole from (\d+) peer\(s\)")
PREKEY_HOST = slice(4, 68)
PAYLOAD_LEN = 20000
ROUNDS = 4


def main(argv):
	if len(argv) != 2:
		print("usage: live_catalog.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 1900 + (os.getpid() % 25) * 4
	port = {"a": str(base), "b": str(base + 1)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		args = {"a": ["--udp-port=" + port["a"]],
		        "b": ["--udp-port=" + port["b"], "--root-at", "127.0.0.1", port["a"]]}
		started = {}

		def turn(who, tag):
			if who in started:
				started.pop(who).stop()
			started[who] = daemon(run, tag, dirs[who], socks[who], extra=args[who])
			started[who].wait_for(ROUND_END_RE, "%s's round" % who.upper())

		def listed(who, root):
			reply = ask(socks[who], "list catalog " + root).split()
			if not reply or reply[0] != "ok":
				raise failed("%s: list catalog answered %r" % (who, reply))
			return sorted((e.split(",")[2], e.split(",")[3]) for e in reply[2:])

		def holders(who, root):
			reply = ask(socks[who], "get catalog " + root).split()
			if not reply or reply[0] != "ok":
				raise failed("%s: get catalog answered %r" % (who, reply))
			return sorted(reply[2:])

		def groups(who):
			"""`who`'s groups, each as what follows its name -- B names a
			group it learned by its id."""
			reply = ask(socks[who], "list group").split()
			if len(reply) < 3 or reply[0] != "ok":
				raise failed("%s: list group answered %r" % (who, reply))
			return sorted(w.split(",")[1:] for w in reply[3:])

		def until(check, what):
			for rnd in range(ROUNDS):
				if check():
					return
				for who in ("a", "b"):
					turn(who, "%s-%s%d" % (who, what, rnd))
			if not check():
				raise failed("%s: not after %d rounds" % (what, ROUNDS))

		try:
			for who in port:
				os.mkdir(dirs[who])
			command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
			key_a = command(run, ["--fuzznet-dir=" + dirs["a"], "--prekey"], None)[PREKEY_HOST]
			prekey = command(run, ["--fuzznet-dir=" + dirs["b"], "--prekey"], None)
			key_b = prekey[PREKEY_HOST]
			card = command(run, ["--fuzznet-dir=" + dirs["a"], "--pair=" + prekey, "--delegable"],
			               None)
			command(run, ["--fuzznet-dir=" + dirs["b"], "--accept=" + card, "--join"], None)
			for who in ("a", "b"):
				turn(who, who + "0")
				expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who],
				       "ok")

			# a: A names a file; B learns it.
			payload = os.path.join(scratch, "song")
			with open(payload, "wb") as f:
				f.write(os.urandom(PAYLOAD_LEN))
			put = ask(socks["a"], "put file " + payload)
			if not put.startswith("ok "):
				raise failed("a: put file answered %r" % put)
			ref = put.split()[1]
			root = ref[:64]
			expect(socks["a"], "a", "add catalog %s name song" % root, "ok")
			until(lambda: listed("b", root) == [("song", key_a[:16])], "a")
			if holders("b", root) != [key_a[:16]]:
				raise failed("a: B's holders are %r, not A alone" % holders("b", root))
			print("livecheck: a: A named a file, and B lists A's name and A holding it")

			# a2: B comes to hold the file's reference from A, sec 634, and so
			# fetches by the root alone and opens what it fetched.
			until(lambda: ask(socks["b"], "get reference " + root).strip() == "ok " + ref,
			      "a2")
			print("livecheck: a2: B holds the file's reference, carried from A")

			# b: B fetches it by its root, opens it, and names it too.
			expect(socks["b"], "b", "fetch file " + root, "ok")
			until(lambda: WHOLE_RE.search(started["b"].log()) is not None, "b-fetch")
			out = os.path.join(scratch, "song-at-b")
			expect(socks["b"], "b", "get file %s %s" % (root, out), "ok")
			with open(payload, "rb") as f, open(out, "rb") as g:
				if f.read() != g.read():
					raise failed("b: the file B exported is not the file A put")
			expect(socks["b"], "b", "add catalog %s name tune" % root, "ok")
			both = sorted([("song", key_a[:16]), ("tune", key_b[:16])])
			until(lambda: listed("a", root) == both and listed("b", root) == both, "b")
			if holders("a", root) != sorted([key_a[:16], key_b[:16]]):
				raise failed("b: A's holders are %r" % holders("a", root))
			print("livecheck: b: B fetched it by its root, opened it whole, and named it; both list "
			      "both names, two holders")

			# c: A takes its name back.
			expect(socks["a"], "a", "remove catalog %s name" % root, "ok")
			until(lambda: listed("b", root) == [("tune", key_b[:16])], "c")
			if holders("b", root) != [key_b[:16]]:
				raise failed("c: B's holders are %r, not B alone" % holders("b", root))
			print("livecheck: c: A took its name back; B lists its own alone, one holder")

			# g: a group made at A, learned by its sibling B (sec 626).
			expect(socks["a"], "a", "add group family", "ok")
			until(lambda: len(groups("b")) == 1 and groups("b") == groups("a"), "g")
			print("livecheck: g: A made a group, and its sibling B learned it")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started.values():
				d.stop()
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
	print("livecheck: a user's library was carried across its own hosts")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
