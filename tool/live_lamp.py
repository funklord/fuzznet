#!/usr/bin/env python3
"""The smallest host's first use, end to end: a lamp switched from another node.

The holder, 2026-11-10: the smallest host "is just setting up an object that
can be switched on/off to get started and is used for other nodes too". Secs
912 (the device), 948 (named objects) and 921 (who may call) each had their
own test; this one is the whole of it.

R is an estate's root holding the object `lamp`, on or off. A is a member,
a phone, say. D is the smallest host: a device paired to R by hand, asking R
over a simulated radio of 51-byte units through `fuzznet-bridge`.

    a  A switches the lamp on, and D's light, asking R, reads it on
    b  D's button switches it off, and A reads it off, set by D
    c  a value the lamp may not take is refused on the device, as on A

Against a daemon that does not carry an object between its hosts, a or b
times out; against one that takes a call from a device no rule lets in, the
first set in c2 of live_device would pass, and here the rule is what lets D in.

BOUNDED FROM INSIDE as live_rejoin.py is: one deadline, each daemon in its own
process group, each radio pass bounded by the device's own tries, and every
process checked gone.

Usage: live_lamp.py PATH_TO_FUZZNETD PATH_TO_BRIDGE PATH_TO_DEVICE_SIM
Exit 0 on a pass, 1 on a failure.
"""

import os
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_device import on_the_air  # noqa: E402
from live_groups import PREKEY_HOST  # noqa: E402
from live_rejoin import command, daemon, expect, free_slot  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 240.0

# A ROUND IS 60 s: an object crosses between hosts well inside one (sec 948).
FAST_S = 20.0
UNIT = 51


def main(argv):
	if len(argv) != 4:
		print(__doc__.strip().splitlines()[-2], file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.bridge = os.path.abspath(argv[2])
	run.sim = os.path.abspath(argv[3])
	run.started = []
	base = free_slot(44000, 4, 500, 2)
	port = {"r": str(base), "a": str(base + 1)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in ("r", "a", "d")}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		for d in dirs.values():
			os.mkdir(d)
		started = {}

		def said(who, line):
			return ask(socks[who], line).strip()

		def polled(who, line, test, what, wait=FAST_S):
			until = time.monotonic() + wait
			while True:
				got = said(who, line)
				if test(got):
					return got
				if time.monotonic() > until:
					raise failed("%s: %s answered %r, %s" % (who, line, got, what))
				time.sleep(0.2)

		def device(args):
			"""What the device said for `object ARGS`, and its exit."""
			code, out, _, _ = on_the_air(run, image, UNIT, 0.0, "object", args, port["r"])
			return code, out

		try:
			# R, AND THE DEVICE'S MANUAL KEY EXCHANGE, before R serves.
			command(run, ["--fuzznet-dir=" + dirs["r"], "--new-root"], None)
			prekey = command(run, ["--fuzznet-dir=" + dirs["d"], "--prekey"], None)
			card = command(run, ["--fuzznet-dir=" + dirs["r"], "--pair=" + prekey], None)
			gateway = command(run, ["--fuzznet-dir=" + dirs["d"], "--accept=" + card], None)
			image = command(run, ["--fuzznet-dir=" + dirs["d"], "--device-image=" + gateway], None)
			if not image.startswith("FZD1:"):
				raise failed("--device-image wrote %r" % image[:40])
			device_host = prekey[PREKEY_HOST]

			started["r"] = daemon(run, "r", dirs["r"], socks["r"],
			                      extra=["--udp-port=" + port["r"]])
			polled("r", "status", lambda g: g.startswith("ok "), "not answering", 30.0)
			expect(socks["r"], "r", "set setting host net/address 127.0.0.1 " + port["r"], "ok")

			# A JOINS R, as live_objects' member does.
			started["a"] = daemon(run, "a", dirs["a"], socks["a"],
			                      extra=["--udp-port=" + port["a"]])
			got = said("a", "get prekey").split()
			member = said("r", "add peer %s delegable" % got[1]).split()
			if len(member) != 2 or member[0] != "ok":
				raise failed("r: add peer answered %r" % member)
			path = os.path.join(scratch, "card")
			with open(path, "w") as f:
				f.write(member[1] + "\n")
			if not said("a", "add join " + path).startswith("ok"):
				raise failed("a: add join did not take")
			# A STARTS AGAIN IN PLACE, joined: its socket is gone a moment.
			until = time.monotonic() + 30.0
			while time.monotonic() < until:
				try:
					if said("a", "status").startswith("ok "):
						break
				except OSError:
					pass
				time.sleep(0.2)
			polled("a", "list capability", lambda g: "member,1,1,0" in g.split()[2:],
			       "not a member", 60.0)
			expect(socks["a"], "a", "set setting host net/address 127.0.0.1 " + port["a"], "ok")

			# THE LAMP, and the rule that lets the device at it.
			expect(socks["r"], "r", "add object lamp on off", "ok")
			expect(socks["r"], "r", "set setting host remote/permit/object host:" + device_host,
			       "ok")
			polled("a", "get object lamp", lambda g: g.startswith("ok - "),
			       "without R's lamp", 70.0)

			# a: A switches it on; D's light reads it.
			expect(socks["a"], "a", "set object lamp on", "ok")
			began = time.monotonic()
			while True:
				code, out = device("get lamp")
				if code == 0 and "on" in out.split():
					break
				if time.monotonic() - began > FAST_S:
					raise failed("a: the device read %r (%d), not on" % (out, code))
				time.sleep(0.5)
			print("livecheck: a: A switched the lamp on, and the device read it on in %.1f s"
			      % (time.monotonic() - began))

			# b: D's button switches it off; A reads it off, set by D.
			code, out = device("set lamp off")
			if code != 0 or "off" not in out.split():
				raise failed("b: the button said %r (%d)" % (out, code))
			got = polled("a", "get object lamp", lambda g: g.startswith("ok off "),
			             "not the device's off")
			if device_host not in got:
				raise failed("b: A reads %r, not set by the device %s" % (got, device_host[:16]))
			print("livecheck: b: the device switched it off, and A read it off, set by the device")

			# c: a value the lamp may not take, on the device and on A.
			code, out = device("set lamp dim")
			if code == 0:
				raise failed("c: the device set the lamp dim: %r" % out)
			if said("a", "set object lamp dim").startswith("ok"):
				raise failed("c: A set the lamp dim")
			print("livecheck: c: neither the device nor A can set a value the lamp does not have")
		except failed as e:
			print("livecheck: FAILED: %s" % e, file=sys.stderr)
			return 1
		finally:
			for who in ("a", "r"):
				if who in started:
					started[who].stop()
	print("livecheck: a lamp is switched from a member and from the smallest host")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
