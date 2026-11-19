#!/usr/bin/env python3
"""A device joins by one code read off a host's screen: `make livecheck`, sec 896.

R, the root of its estate, shows a code. D, E, G and F are fresh devices that
hold nothing but what they read, and nothing is carried back by a person.

    a  `add invite` is refused with no `net/address`, and given one answers a
       code; `get invite` counts it
    b  D, told `add join CODE` alone, joins: R pairs it, its subscriber hears
       `event member` naming D, and D starts again in place and reads R's
       setting
    c  ONE USE: E, told the same code, joins nothing and R pairs nothing
    d  LAPSED: a code of a second's life, read past it, joins nobody
    e  ENDED: `remove invite` ends a code that was open
    f  THE WRONG HOST: G reads a code changed to name another host, as a person
       who photographed one might show. R answers it, and G refuses a card its
       named host did not sign, and stays unjoined
    g  E, refused in c, joins by a code of its own: what stopped it was the
       one use, not the device
    h  CONFIRMED: a code that needs a word from R's user. F waits, named by
       `list invite` and `event invite`, and is not paired; a second device
       cannot ask past it; `remove invite KEY` turns one away; `grant invite
       KEY` lets F in. And `invite/confirm` makes that the host's default,
       which `open` overrides -- that second round in binary (sec 1250):
       the code, F waiting as a row, an unknown key refused in words, F
       let in
    i  JOIN BY REQUEST (sec 1288): R opens an offer; H, knowing nothing of R,
       probes the network, lists R by name and key, joins by the code heard,
       waits, and is let in; R ends the offer
    j  THE SEARCH OF THIS USER'S HOSTS (sec 1287): H's search is asked of
       R, and R's contact is on H's page with R's answer

Against a daemon that takes a used code again, phase c pairs E; against one
that believes any card, phase f joins G.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import base64
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402
from live_rpc import binary  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 400.0

PREKEY_HOST = slice(4, 68)
QUIET_S = 12.0
NOT_ITS_HOST_RE = re.compile(r"not its host.s")
SETTLE_S = 40.0


def renamed_host(code):
	"""`code` with its host's key changed, and all else as it was."""
	body = code[5:]
	raw = bytearray(base64.b32decode(body + "=" * (-len(body) % 8)))
	raw[0] ^= 0xff
	return code[:5] + base64.b32encode(bytes(raw)).decode().rstrip("=")


def main(argv):
	if len(argv) != 2:
		print("usage: live_invite.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 26000 + (os.getpid() % 300) * 6
	port = {k: str(base + i) for i, k in enumerate(("r", "d", "e", "f", "g", "h"))}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}

		def key_of(who):
			got = ask(socks[who], "get prekey").split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("get prekey on %s answered %r" % (who, got))
			return got[1][PREKEY_HOST]

		def paired(key):
			at = 0
			while True:
				got = ask(socks["r"], "list peer %d" % at).split()
				if got[0] != "ok":
					raise failed("list peer answered %r" % got)
				rows = got[3:]
				if key in rows:
					return True
				at += len(rows)
				if not rows or at >= int(got[1]):
					return False

		def code(line="add invite delegable"):
			got = ask(socks["r"], line).split()
			if len(got) != 2 or got[0] != "ok" or not got[1].startswith("FZI1:"):
				raise failed("%s answered %r" % (line, got))
			return got[1]

		def joined(who, key, what):
			"""`who` paired at R, and started again in place reading R's setting."""
			until = time.monotonic() + SETTLE_S
			while True:
				try:
					if paired(key) and ask(socks[who], "get setting estate x/before") == "ok root 1":
						return
				except OSError:
					pass
				if time.monotonic() > until:
					raise failed("%s: %s is not joined: paired %r" % (what, who, paired(key)))
				time.sleep(0.5)

		def stays_out(who, key, what):
			until = time.monotonic() + QUIET_S
			while time.monotonic() < until:
				if paired(key):
					raise failed("%s: R paired %s" % (what, who))
				time.sleep(0.5)
			got = ask(socks[who], "get setting estate x/before")
			if got.startswith("ok root"):
				raise failed("%s: %s reads R's setting: %r" % (what, who, got))

		try:
			for d in dirs.values():
				os.mkdir(d)
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			for who in port:
				started[who] = daemon(run, who, dirs[who], socks[who],
				                      extra=["--udp-port=" + port[who]])
			started["r"].wait_for(ROUND_DONE_RE, "R's first round", within=60.0)
			expect(socks["r"], "r", "set setting estate x/before 1", "ok")

			# a: A CODE.
			expect(socks["r"], "r", "add invite", "error this host has no net/address to invite to")
			expect(socks["r"], "r", "set setting host net/address 127.0.0.1 " + port["r"], "ok")
			first = code()
			expect(socks["r"], "r", "get invite", "ok 1")
			print("livecheck: a: R showed a code of %d characters" % len(first))

			# b: D JOINS BY IT, and R's subscriber hears.
			key_d = key_of("d")
			with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sub:
				sub.settimeout(SETTLE_S)
				sub.connect(socks["r"])
				sub.sendall(b"get events\n")
				heard = b""
				while b"\n" not in heard:
					heard += sub.recv(4096)
				if not heard.startswith(b"ok events"):
					raise failed("b: get events answered %r" % heard)
				pid = started["d"].proc.pid
				expect(socks["d"], "d", "add join " + first, "ok asking")
				want = b"event member " + key_d.encode()
				while want not in heard:
					more = sub.recv(4096)
					if not more:
						raise failed("b: R's subscriber heard %r" % heard[-200:])
					heard += more
			joined("d", key_d, "b")
			if started["d"].proc.poll() is not None or started["d"].proc.pid != pid:
				raise failed("b: D did not start again in place")
			expect(socks["r"], "r", "get invite", "ok 0")
			print("livecheck: b: D joined by the code alone, and R's subscriber heard its key")

			# c: ONE USE.
			key_e = key_of("e")
			expect(socks["e"], "e", "add join " + first, "ok asking")
			stays_out("e", key_e, "c")
			expect(socks["e"], "e", "get join", "ok asking")
			print("livecheck: c: E, told the used code, joined nothing")

			# d: LAPSED.
			key_f = key_of("f")
			lapsed = code("add invite delegable 1")
			time.sleep(1.5)
			expect(socks["f"], "f", "add join " + lapsed, "ok asking")
			stays_out("f", key_f, "d")
			print("livecheck: d: F, told a lapsed code, joined nothing")

			# e: ENDED.
			ended = code()
			expect(socks["r"], "r", "remove invite", "ok 1")
			expect(socks["f"], "f", "add join " + ended, "ok asking")
			stays_out("f", key_f, "e")
			print("livecheck: e: F, told a code ended, joined nothing")

			# f: THE WRONG HOST. R pairs it, and the card is no use to G.
			key_g = key_of("g")
			expect(socks["g"], "g", "add join " + renamed_host(code()), "ok asking")
			until = time.monotonic() + SETTLE_S
			while not paired(key_g):
				if time.monotonic() > until:
					raise failed("f: R never answered, so G refused nothing")
				time.sleep(0.5)
			started["g"].wait_for(NOT_ITS_HOST_RE, "G refusing the card", within=SETTLE_S)
			got = ask(socks["g"], "get setting estate x/before")
			if got.startswith("ok root"):
				raise failed("f: G joined on a card its code's host did not sign: %r" % got)
			print("livecheck: f: G refused a card from a host its code did not name")

			# g: E, BY A CODE OF ITS OWN.
			expect(socks["e"], "e", "add join " + code(), "ok asking")
			joined("e", key_e, "g")
			print("livecheck: g: E joined by its own code: the one use was what stopped it")

			# h: CONFIRMED. F first turned away, then let in.
			def waiting(key):
				until = time.monotonic() + SETTLE_S
				while key not in ask(socks["r"], "list invite").split():
					if time.monotonic() > until:
						raise failed("h: %s never waited: %r" % (key, ask(socks["r"], "list invite")))
					time.sleep(0.5)

			refused = code("add invite delegable confirm")
			expect(socks["f"], "f", "add join " + refused, "ok asking")
			waiting(key_f)
			if paired(key_f):
				raise failed("h: R paired F with nobody's word")
			expect(socks["r"], "r", "remove invite " + key_f, "ok")
			stays_out("f", key_f, "h")
			expect(socks["r"], "r", "set setting host invite/confirm 1", "ok")
			# THE SECOND ROUND IN BINARY, sec 1250: the code, F waiting as a
			# row, a key nobody waits by refused in words, and F let in.
			got = binary(socks["r"], bytes([0x09, 0x86, 1, 0, 0, 0, 0, 0]))
			if len(got) != 2 or got[0][:2] != bytes([0x09, 0x87]) or got[1][:2] != bytes([0x13, 0]) \
			   or not got[0][3:3 + got[0][2]].startswith(b"FZI1:"):
				raise failed("h: an invite in binary answered %r" % got)
			second = got[0][3:3 + got[0][2]].decode()
			expect(socks["f"], "f", "add join " + second, "ok asking")
			waiting(key_f)
			got = binary(socks["r"], bytes([0x09, 0x88]))
			if len(got) != 2 or got[0] != bytes([0x09, 0x89]) + bytes.fromhex(key_f) \
			   or got[1][:2] != bytes([0x13, 0]):
				raise failed("h: the devices waiting in binary answered %r" % got)
			got = binary(socks["r"], bytes([0x09, 0x8A]) + bytes(32) + bytes([1]))
			if len(got) != 1 or got[0][:2] != bytes([0x13, 3]) or b"no device waits by that key" not in got[0]:
				raise failed("h: letting in a key nobody waits by, in binary, answered %r" % got)
			stays_out("f", key_f, "h")
			got = binary(socks["r"], bytes([0x09, 0x8A]) + bytes.fromhex(key_f) + bytes([1]))
			if got != [bytes([0x13, 0, 0])]:
				raise failed("h: letting F in, in binary, answered %r" % got)
			joined("f", key_f, "h")
			expect(socks["r"], "r", "list invite", "ok 0")
			if binary(socks["r"], bytes([0x09, 0x88])) != [bytes([0x13, 0, 0])]:
				raise failed("h: a device still waits in binary once F is in")
			print("livecheck: h: a confirmed code held F until R's user said, and turned it away "
			      "when told; invite/confirm made that the default")

			# i: JOIN BY REQUEST, sec 1288. R's user opens an offer; H, which
			# knows nothing of R, probes the network (loopback here), lists R by
			# its name and key, joins by the code it heard, waits for R's user,
			# and is let in. The offer then ends.
			key_h = key_of("h")
			expect(socks["r"], "r", "set setting host host/name the%20root", "ok")
			got = ask(socks["r"], "add offer 60")
			if got != "ok 6290 60":
				raise failed("i: add offer answered %r" % got)
			if not ask(socks["r"], "get offer").startswith("ok open "):
				raise failed("i: get offer said %r while open" % ask(socks["r"], "get offer"))
			expect(socks["h"], "h", "set setting host net/discovery 127.0.0.1", "ok")
			got = ask(socks["h"], "fetch offer")
			if got != "ok 127.0.0.1 6290":
				raise failed("i: fetch offer answered %r" % got)
			until = time.monotonic() + 15.0
			while True:
				listed = ask(socks["h"], "list offer").split()
				if listed[:2] == ["ok", "1"]:
					break
				if time.monotonic() > until:
					raise failed("i: H heard no offer: %r" % listed)
				time.sleep(0.3)
			name, fingerprint, heard = listed[2].split(",", 2)
			if name != "the%20root" or fingerprint != key_of("r")[:16] or not heard.startswith("FZI1:"):
				raise failed("i: H listed %r, not R by its name and key with a code" % listed[2])
			expect(socks["h"], "h", "add join " + heard, "ok asking")
			waiting(key_h)
			if paired(key_h):
				raise failed("i: R paired H, found on the network, with nobody's word")
			expect(socks["r"], "r", "grant invite " + key_h, "ok")
			joined("h", key_h, "i")
			expect(socks["r"], "r", "remove offer", "ok")
			expect(socks["r"], "r", "get offer", "ok closed")
			print("livecheck: i: H found R on the network by its offer, joined by the code it "
			      "heard, waited for R's user, and was let in")

			# j: THE SEARCH OF THIS USER'S HOSTS, sec 1287 steps 2 and 3. H,
			# now of R's estate, searches: it asks the estate's hosts its round
			# reaches -- R, whose code it joined by; a host learns no address of
			# a device that joined it, so not the other way -- and R's answer
			# puts R's contact on H's page. Asked again until a round has R.
			expect(socks["r"], "r", "add contact zelda " + "5a" * 32, "ok")
			until = time.monotonic() + SETTLE_S
			while True:
				got = ask(socks["h"], "fetch search in contacts zelda").split()
				if got[0] != "ok":
					raise failed("j: fetch search answered %r" % got)
				time.sleep(3.5)
				page = ask(socks["h"], "get search").split()
				if page[0] != "ok":
					raise failed("j: get search answered %r" % page)
				if int(page[3]) >= 1 and int(page[4]) >= 1 and any(r.startswith("contacts,") and r.endswith(",zelda")
				                                                   for r in page[6:]):
					break
				if time.monotonic() > until:
					raise failed("j: H's search never heard from R: %r; H: %s"
					             % (page, " | ".join(l for l in started["h"].log().splitlines()
					                                 if "search" in l)[-600:]))
			print("livecheck: j: H's search was asked of R, of its estate, and R's contact was on "
			      "H's page: %s asked, %s answered" % (page[3], page[4]))
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except (subprocess.TimeoutExpired, socket.timeout) as e:
			print("livecheck: FAILED -- a wait passed its deadline: %s" % e)
			for who in started:
				print("  %s: %s" % (who, " | ".join(l for l in started[who].log().splitlines()
				                                    if "invite" in l)[-400:]))
			return 1
		finally:
			for d in started.values():
				d.stop()
	print("livecheck: a device joined by one code, once, from the host the code named")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
