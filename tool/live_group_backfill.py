#!/usr/bin/env python3
"""A group share that does not catch up a later member: `make livecheck`,
sec 655.

Two stores over loopback, A and C, contacts by card as live_groups.py has
them. A makes the group family alone.

    a  A shares folder S0 with the group `backfill 0`, and folder S1
       `backfill 1`, each holding a note; `list share` says which is which
    b  A adds C, a second after the shares were made, and then writes a
       second note into S0. C, a later member, holds S1 and its note, and
       S0's second note -- and neither S0 nor the note it held before C
       joined

    c  a file granted to the group before C joined: C fetches it whole by
       its reference, and exports the same bytes; and while it arrives C reads
       its opening range, which is the file's (secs 495, 884)
    d  C under `policy messages drop`, keeping nothing and relaying nothing,
       takes none of A's lines, sealed or not (sec 894); relaying it carries
       them and lets a past month go; and started with no rule it files them
       (sec 886)
    d3 a group with backfill off: a line written and a file granted before C
       joined stay from it, and what follows reaches it (sec 905)

Against a daemon that reads a group share's reach at the request alone, as
sec 471 did, phase b finds S0 and its first note at C.

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
from live_groups import KEPT_RE, PREKEY_HOST  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 1100.0

ROUNDS = 6
DROP_LINES = 30
LINES_TAKEN_RE = re.compile(r"lines pass: \d+ sealed, (\d+) taken")
SEALED_GONE_RE = re.compile(r"(\d+) sealed group line\(s\) trimmed")
# PAST ONE ROUND'S LEAVES, 4096 of 1024 bytes, so it is seen arriving.
PLAYED_LEN = 6 * 1024 * 1024


def main(argv):
	if len(argv) != 2:
		print("usage: live_group_backfill.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 32620 + (os.getpid() % 30) * 2
	port = {"a": str(base), "c": str(base + 1)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}

		def up(who, tag, extra=()):
			started[who] = daemon(run, tag, dirs[who], socks[who],
			                      extra=["--udp-port=" + port[who]] + list(extra))
			return started[who]

		def turn(who, tag):
			if who in started:
				started.pop(who).stop()
			d = up(who, tag)
			d.wait_for(ROUND_DONE_RE, "%s's round" % who.upper(), within=60.0)
			return d

		def made(who, line):
			got = ask(socks[who], line).split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("%s: %s answered %r" % (who.upper(), line, got))
			return got[1]

		def titles(parent):
			"""C's listing of A's tree under `parent`, as text."""
			return ask(socks["c"], "list shared alice " + parent)

		try:
			keys = {}
			for who in port:
				os.mkdir(dirs[who])
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], None)
				keys[who] = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"],
				                    None)[PREKEY_HOST]
			for who in port:
				up(who, who + "0")
				expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who],
				       "ok")
			card = ask(socks["c"], "get card carol")
			if not card.startswith("ok FZC1:"):
				raise failed("setup: get card answered %r" % card)
			got = ask(socks["a"], "add contact carol " + card.split(" ", 1)[1].strip())
			if got.strip() != "ok " + keys["c"]:
				raise failed("setup: add contact answered %r" % got)
			started["c"].wait_for(KEPT_RE, "C keeping A's request")
			expect(socks["c"], "c", "grant request %s alice" % keys["a"], "ok")
			made("a", "add group family")
			print("livecheck: setup: A and C are contacts, and A made the group alone")

			# a: two shares with the group, one catching up and one not.
			s0 = made("a", "add folder top s0-folder")
			made("a", "add note %s s0-before" % s0)
			s1 = made("a", "add folder top s1-folder")
			made("a", "add note %s s1-before" % s1)
			expect(socks["a"], "a", "add share %s @family backfill 0" % s0, "ok")
			expect(socks["a"], "a", "add share %s @family backfill 1" % s1, "ok")
			rows = ask(socks["a"], "list share").split()
			if rows[:3] != ["ok", "2", "0"] or set(rows[3:]) != {s0 + ",@family,0",
			                                                     s1 + ",@family,1"}:
				raise failed("a: A's list share answered %r" % rows)
			print("livecheck: a: A shared S0 not catching up and S1 catching up")
			# AND A FILE GRANTED TO THE GROUP before C is in it, for phase c.
			payload = os.path.join(scratch, "granted-before")
			with open(payload, "wb") as f:
				f.write(os.urandom(PLAYED_LEN))
			put = ask(socks["a"], "put file " + payload)
			if not put.startswith("ok "):
				raise failed("a: put file answered %r" % put)
			ref = put.split()[1]
			expect(socks["a"], "a", "grant file %s @family" % ref[:64], "ok")

			# b: C joins a second later; A writes into S0 after.
			time.sleep(1.5)
			expect(socks["a"], "a", "add member family carol", "ok")
			time.sleep(1.5)
			made("a", "add note %s s0-after" % s0)
			ok = False
			for rnd in range(ROUNDS):
				for who in ("a", "c"):
					turn(who, "%s-b%d" % (who, rnd))
				top = titles("top")
				if "s0-after" in top and "s1-folder" in top and "s1-before" in titles(s1):
					ok = True
					break
			top = titles("top")
			if not ok:
				raise failed("b: C's top of A's tree is %r, and S1 holds %r"
				             % (top.strip(), titles(s1).strip()))
			if "s0-folder" in top or "s0-before" in top or "s0-before" in titles(s0):
				raise failed("b: C, a later member, holds what S0 held before it joined: %r"
				             % top.strip())
			print("livecheck: b: C, joining later, got S1 whole and S0 only from its joining")

			# c: THE GRANT REACHES WHO IS A MEMBER WHEN ASKED, secs 626 and 630: C,
			# added after it, fetches the file whole by its reference, and what
			# it exports is the file. fuzzypickles' fzpd pinned a file to the
			# epoch of its sharing, and refused this; a node's reach is the
			# group's, as it is for lines and a share catching up.
			expect(socks["c"], "c", "fetch file " + ref, "ok")
			whole = False
			tries = partial = 0
			for rnd in range(ROUNDS):
				turn("c", "c-c%d" % rnd)
				until = time.monotonic() + 20.0
				while time.monotonic() < until and not whole:
					# PLAYED AS IT ARRIVES, sec 495: the opening range, read while
					# the rest is on its way, is the file's own bytes.
					part = os.path.join(scratch, "part-%d" % tries)
					tries += 1
					said = ask(socks["c"], "get file %s 0 4096 %s" % (ref, part)).strip()
					if said == "ok partial":
						with open(payload, "rb") as f, open(part, "rb") as g:
							if f.read(4096) != g.read():
								raise failed("c: the range read while arriving is not the file's")
						partial += 1
					if os.path.exists(part):
						os.unlink(part)
					whole = ask(socks["c"], "get file %s check" % ref[:64]).strip() == "ok intact"
					time.sleep(0.2)
				if whole:
					break
			if not whole:
				raise failed("c: C, a later member, never held the file granted before it joined: "
				             "%r" % ask(socks["c"], "get file " + ref[:64]))
			out = os.path.join(scratch, "granted-out")
			expect(socks["c"], "c", "get file %s %s" % (ref, out), "ok")
			with open(payload, "rb") as f, open(out, "rb") as g:
				if f.read() != g.read():
					raise failed("c: what C exported is not the file")
			if not partial:
				raise failed("c: no read of the file saw it partial in %d tries: the range read "
				             "was never tried on a file arriving" % tries)
			print("livecheck: c: C, added after a file was granted to the group, fetched it "
			      "whole, reading its opening %d time(s) as it arrived" % partial)

			# d: A HOST THAT KEEPS NO MESSAGES OPENS NO GROUP LINE, sec 886. C
			# under `policy messages drop`: A's line comes, and nothing in C's
			# store holds its text. Started with no rule, C files it, so the
			# line was there to be filed.
			text = "a-line-to-a-host-that-keeps-none"
			started.pop("c").stop()
			up("c", "c-drop", ["--log-rule=policy messages drop"])
			started["c"].wait_for(ROUND_DONE_RE, "C's round under drop", within=60.0)
			# FIRST, as a line of a past month is: a trim goes from the oldest.
			expect(socks["a"], "a", "add message @family out %s at %d old-month-line"
			       % ("d6" * 16, int((time.time() - 45 * 86400) * 1000)), "ok")
			expect(socks["a"], "a", "add message @family out %s %s" % ("d4" * 16, text), "ok")
			for i in range(DROP_LINES):
				expect(socks["a"], "a", "add message @family out %032x %s" % (0xd5 << 120 | i,
				       "traffic-" + "x" * 400), "ok")

			def stored(store):
				return sum(os.path.getsize(os.path.join(at, f))
				           for at, _, files in os.walk(store) for f in files)

			before = stored(dirs["c"])
			taken = 0
			for rnd in range(3):
				turn("a", "a-d%d" % rnd)
				taken += sum(int(n) for n in LINES_TAKEN_RE.findall(started["c"].log()))
				started.pop("c").stop()
				up("c", "c-drop%d" % rnd, ["--log-rule=policy messages drop"])
				started["c"].wait_for(ROUND_DONE_RE, "C's round under drop", within=60.0)
			taken += sum(int(n) for n in LINES_TAKEN_RE.findall(started["c"].log()))
			print("livecheck: d: C under drop took %d sealed line(s) of %d; its store went from %d "
			      "to %d bytes" % (taken, DROP_LINES + 2, before, stored(dirs["c"])))
			if taken:
				raise failed("d: C, with no retention and no relay, carries %d sealed line(s)" % taken)

			# d2: A RELAY CARRIES THE MONTH AND NO MORE, sec 894: under drop C
			# takes lines again once it relays, and lets go a month gone by.
			expect(socks["c"], "c", "set setting host relay/enabled 1", "ok")
			expect(socks["a"], "a", "add message @family out %s this-month-line" % ("d7" * 16), "ok")
			turn("a", "a-d2")
			started.pop("c").stop()
			up("c", "c-relay", ["--log-rule=policy messages drop"])
			started["c"].wait_for(ROUND_DONE_RE, "C's round relaying", within=60.0)
			turn("a", "a-d3")
			until = time.monotonic() + 120.0
			relayed = []
			while time.monotonic() < until and not sum(int(n) for n in relayed):
				relayed = LINES_TAKEN_RE.findall(started["c"].log())
				time.sleep(1.0)
			if not sum(int(n) for n in relayed):
				raise failed("d: C, relaying, took no line")
			# THE TRIM RUNS AT A START AND HOURLY.
			started.pop("c").stop()
			up("c", "c-relay2", ["--log-rule=policy messages drop"])
			went = started["c"].wait_for(SEALED_GONE_RE, "the past month's line let go", within=60.0)
			print("livecheck: d: C, relaying, took %d line(s) and let %s of a past month go"
			      % (sum(int(n) for n in relayed), went.group(1)))
			expect(socks["c"], "c", "set setting host relay/enabled 0", "ok")

			def clear(store):
				for at, _, files in os.walk(store):
					for f in files:
						try:
							with open(os.path.join(at, f), "rb") as data:
								if text.encode() in data.read():
									return os.path.join(at, f)
						except OSError:
							pass
				return None

			if clear(dirs["c"]):
				raise failed("d: C, keeping no messages, holds the line in %s" % clear(dirs["c"]))
			filed = False
			started.pop("c").stop()
			up("c", "c-keep")
			until = time.monotonic() + 90.0
			while time.monotonic() < until and not filed:
				at, more = 0, 1
				while more and not filed:
					page = ask(socks["c"], "list message @family %d" % at)
					words = page.split()
					if len(words) < 4 or words[0] != "ok":
						break
					filed = text in page
					at, more = at + int(words[2]), int(words[3])
				time.sleep(1.0)
			if not filed:
				raise failed("d: C, under no rule, never filed the line: phase d's silence proves "
				             "nothing: %r" % ask(socks["c"], "list message @family")[:300])
			print("livecheck: d: C under drop held A's group line sealed and opened none; with "
			      "no rule it filed it")

			# d3: A GROUP THAT DOES NOT BACKFILL, sec 905: a line written and a file
			# granted before C joined stay out of its reach, and what follows
			# reaches it. Written just before the add, so the line is sealed after
			# it: sealed at the epoch of that moment, it reached C.
			made("a", "add group shut")
			expect(socks["a"], "a", "set group shut backfill 0", "ok")
			expect(socks["a"], "a", "get group shut backfill", "ok 0")
			turn("a", "a-shut0")
			expect(socks["a"], "a", "add message @shut out %s before-joining" % ("e1" * 16), "ok")
			def small_file(name):
				path = os.path.join(scratch, name)
				with open(path, "wb") as f:
					f.write(name.encode() * 400)
				got = ask(socks["a"], "put file " + path)
				if not got.startswith("ok "):
					raise failed("d3: put file answered %r" % got)
				return got.split()[1]

			kept_from = small_file("before-file")
			expect(socks["a"], "a", "grant file %s @shut" % kept_from[:64], "ok")
			expect(socks["a"], "a", "add member shut carol", "ok")
			time.sleep(1.1)
			expect(socks["a"], "a", "add message @shut out %s after-joining" % ("e2" * 16), "ok")
			given = small_file("after-file")
			expect(socks["a"], "a", "grant file %s @shut" % given[:64], "ok")
			until = time.monotonic() + 200.0
			seen = ""
			# LEFT RUNNING: a host restarted each round never reaches its lines pass
			# with its contact's host answered.
			while time.monotonic() < until and "after-joining" not in seen:
				seen = ask(socks["c"], "list message @shut")
				time.sleep(2.0)
			if "after-joining" not in seen:
				raise failed("d3: C never read what followed its joining: %r" % seen[:300])
			if "before-joining" in seen:
				raise failed("d3: C, with backfill off, read what came before it joined")
			expect(socks["c"], "c", "fetch file " + kept_from, "ok")
			expect(socks["c"], "c", "fetch file " + given, "ok")
			had = False
			until = time.monotonic() + 200.0
			while time.monotonic() < until and not had:
				had = ask(socks["c"], "get file %s check" % given[:64]).strip() == "ok intact"
				time.sleep(1.0)
			if not had:
				raise failed("d3: C never fetched a file granted after it joined")
			if ask(socks["c"], "get file %s check" % kept_from[:64]).strip() == "ok intact":
				raise failed("d3: C, with backfill off, fetched a file granted before it joined")
			print("livecheck: d3: with backfill off C read what followed its joining, and not "
			      "what came before")
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
						# STILL OUR CHILD, sec 741: a reaped daemon's pid, handed to
						# another run's daemon of the same binary, is not this run's.
						with open("/proc/%d/stat" % pid) as f:
							alive = alive and int(f.read().rsplit(")", 1)[1].split()[1]) == os.getpid()
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: a group share kept from a later member what came before it")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
