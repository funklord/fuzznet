#!/usr/bin/env python3
"""A host's profile: `make livecheck`, sec 908.

One store, a root, started with `--preset=`.

    a  `--preset=vault` applied at the first start: each value in force, and
       `list preset` says who may change it
    b  a root's own host may change what a root may, and is refused the
       profile's own, whatever its rank
    c  started again, nothing is applied: a value changed stays
    d  an update, by another profile: what somebody chose stays, the new
       profile's own is put back, and `preset/applied` says so
    d2 `set preset` switches among a build's user presets, refusing one no user
       may choose and another build's, and the choice outlives a restart;
       `list preset choices` names those it takes and no other (sec 1023)
    e  a name no profile has ends the start
    f  on a fresh host, what one preset wrote and nobody chose follows a switch to
       another (sec 973)

The rank below root needs a second host: `presets_test` holds that.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses.

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

live_trim.DEADLINE = time.monotonic() + 240.0
APPLIED_RE = re.compile(r"the profile \S+ \S+ applied: (\d+) value")


def main(argv):
	if len(argv) != 2:
		print("usage: live_preset.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	port = str(27000 + os.getpid() % 900)
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		store = os.path.join(scratch, "r")
		sock = os.path.join(sock_dir, "r")
		d = None

		def up(tag, preset):
			return daemon(run, tag, store, sock, extra=["--udp-port=" + port, "--preset=" + preset])

		def value(key):
			return ask(sock, "get setting host " + key)

		def applied(within=20.0):
			until = time.monotonic() + within
			while time.monotonic() < until:
				got = APPLIED_RE.search(d.log())
				if got:
					return int(got.group(1))
				time.sleep(0.2)
			raise failed("the profile was never applied: %r" % ask(sock, "get preset"))

		try:
			os.mkdir(store)
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)

			# a: APPLIED.
			d = up("r1", "vault")
			d.wait_for(ROUND_DONE_RE, "the first round", within=60.0)
			wrote = applied()
			if wrote != 4:
				raise failed("a: %d values written" % wrote)
			expect(sock, "a", "get preset", "ok vault")
			if value("relay/enabled") != "ok root on":
				raise failed("a: relay/enabled is %r" % value("relay/enabled"))
			rows = ask(sock, "list preset").split()
			if rows[:2] != ["ok", "4"] or "relay/enabled,vote,on" not in rows \
			   or "location/enabled,nobody,off" not in rows:
				raise failed("a: list preset answered %r" % rows)
			print("livecheck: a: the vault profile applied its 4 values and said who may change each")

			# b: BY RANK. A root may change a root's; nobody the profile's own.
			expect(sock, "b", "set setting host relay/enabled off", "ok")
			expect(sock, "b", "set setting host invite/confirm off", "ok")
			got = ask(sock, "set setting host location/enabled on")
			if not got.startswith("denied"):
				raise failed("b: the profile's own value answered %r" % got)
			got = ask(sock, "remove setting host location/enabled")
			if not got.startswith("denied"):
				raise failed("b: its removal answered %r" % got)
			got = ask(sock, "set setting host preset/applied x")
			if not got.startswith("denied"):
				raise failed("b: preset/applied answered %r" % got)
			expect(sock, "b", "set setting host net/metric 50", "ok")
			print("livecheck: b: a root changed a root's value, and nobody the profile's own")

			# c: STARTED AGAIN.
			d.stop()
			d = up("r2", "vault")
			d.wait_for(ROUND_DONE_RE, "the second start's round", within=60.0)
			if APPLIED_RE.search(d.log()):
				raise failed("c: the same profile was applied again")
			if value("relay/enabled") != "ok root off":
				raise failed("c: a chosen value went: %r" % value("relay/enabled"))
			print("livecheck: c: started again, nothing was applied and the value stayed")

			# d: AN UPDATE, to another profile.
			d.stop()
			d = up("r3", "rootd")
			d.wait_for(ROUND_DONE_RE, "the update's round", within=60.0)
			applied()
			if value("relay/enabled") != "ok root off" or value("invite/confirm") != "ok root off":
				raise failed("d: chosen values went: %r %r"
				             % (value("relay/enabled"), value("invite/confirm")))
			if value("location/enabled") != "ok root off":
				raise failed("d: location/enabled is %r" % value("location/enabled"))
			if not value("preset/applied").endswith("rootd%201.0"):
				raise failed("d: preset/applied is %r" % value("preset/applied"))
			print("livecheck: d: an update kept what was chosen, and said what was applied")
			# d2: A USER'S SWITCH, with no rebuild, kept over a restart.
			d.stop()
			d = up("r4", "userd")
			d.wait_for(ROUND_DONE_RE, "the switch's round", within=60.0)
			# THE CHOICES, sec 1023: the user's presets this build takes, and no other.
			choices = ask(sock, "list preset choices").split()
			if (choices[:1] != ["ok"] or int(choices[1]) != len(choices) - 2
			        or "relay" not in choices or "userd" not in choices
			        or "rootd" in choices or "embedded-device" in choices):
				raise failed("d2: list preset choices answered %r" % choices)
			expect(sock, "d2", "set preset relay", "ok")
			got = ask(sock, "set preset rootd")
			if not got.startswith("denied"):
				raise failed("d2: a preset no user may switch to answered %r" % got)
			got = ask(sock, "set preset embedded-device")
			if not got.startswith("denied"):
				raise failed("d2: another build's preset answered %r" % got)
			until = time.monotonic() + 20.0
			while not value("preset/applied").endswith("relay%201.0"):
				if time.monotonic() > until:
					raise failed("d2: preset/applied is %r" % value("preset/applied"))
				time.sleep(0.3)
			d.stop()
			d = up("r5", "userd")
			d.wait_for(ROUND_DONE_RE, "the restart's round", within=60.0)
			until = time.monotonic() + 15.0
			while ask(sock, "get preset") != "ok relay":
				if time.monotonic() > until:
					raise failed("d2: after a restart: %r" % ask(sock, "get preset"))
				time.sleep(0.3)
			print("livecheck: d2: a user switched to relay with no rebuild, and it held")
			d.stop()
			d = None

			# e: NO SUCH PROFILE.
			done = subprocess.run([run.fuzznetd, "--socket=" + sock, "--fuzznet-dir=" + store,
			                       "--preset=nothing", "--fuzznet-service=1", "--fuzznet-product=1"],
			                      capture_output=True, timeout=20)
			if done.returncode == 0:
				raise failed("e: a profile nobody has started a daemon")
			print("livecheck: e: a name no profile has ended the start")

			# f: WHAT A PRESET WROTE FOLLOWS ANOTHER, sec 973: a fresh host under
			# userd holds its relay/enabled off, chosen by nobody; switched to
			# relay, it takes relay's on.
			store = os.path.join(scratch, "f")
			os.mkdir(store)
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)
			d = up("f1", "userd")
			d.wait_for(ROUND_DONE_RE, "f's first round", within=60.0)
			if not value("relay/enabled").endswith(" off"):
				raise failed("f: under userd relay/enabled is %r" % value("relay/enabled"))
			expect(sock, "f", "set preset relay", "ok")
			until = time.monotonic() + 20.0
			while not value("relay/enabled").endswith(" on"):
				if time.monotonic() > until:
					raise failed("f: switched to relay, relay/enabled is %r"
					             % value("relay/enabled"))
				time.sleep(0.3)
			print("livecheck: f: what userd wrote and nobody chose followed the switch to relay")
			d.stop()
			d = None
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			if d:
				d.stop()
	print("livecheck: a profile set what a host starts with, and kept what was chosen")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
