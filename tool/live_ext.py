#!/usr/bin/env python3
"""A daemon with an extension: `make livecheck`, sec 673.

`node/test/ext_daemon` is fuzznetd's node called with options and verbs of
its own (`node/daemon.h`), as fzpd will call it. One store, one daemon.

    a  its own option refused ends the start in its words; an option
       neither fuzznet nor it takes is refused with the usage, which lists
       its own options
    b  started with `--greeting=howdy --quiet`, it answers `get greeting`
       with `ok howdy`; `status` and `list contact` are fuzznet's, never the
       extension's, so a verb fuzznet answers stays fuzznet's; an
       extension's answer outside
       the reply vocabulary is answered `error`; a verb neither answers is
       `unsupported`

Against a daemon that hands nothing to the extension, phase a's option is
refused as unknown and phase b's `get greeting` is `unsupported`; against
one that asks the extension first, phase b's `list contact` is the
extension's.

BOUNDED FROM INSIDE: one deadline; the daemon in its own process group,
stopped by SIGTERM then SIGKILL, and checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import signal
import socket
import subprocess
import sys
import tempfile
import time

DEADLINE_S = 90.0


class failed(Exception):
	pass


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


def main(argv):
	if len(argv) != 2:
		print("usage: live_ext.py PATH_TO_EXT_DAEMON", file=sys.stderr)
		return 2
	daemon = os.path.abspath(argv[1])
	deadline = time.monotonic() + DEADLINE_S
	proc = None
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fze.", dir="/tmp") as sock_dir:
		store = os.path.join(scratch, "store")
		os.mkdir(store)
		sock = os.path.join(sock_dir, "s")
		base = [daemon, "--socket=" + sock, "--fuzznet-dir=" + store,
		        "--fuzznet-service=1", "--fuzznet-product=1"]
		try:
			# a: its own option refused, and one nobody takes.
			r = subprocess.run(base + ["--greeting=no"], capture_output=True, timeout=30)
			said = r.stderr.decode(errors="replace")
			if r.returncode == 0 or "will not say no" not in said:
				raise failed("a: --greeting=no was not refused in the extension's words: "
				             "%r" % said[-300:])
			r = subprocess.run(base + ["--nonsense"], capture_output=True, timeout=30)
			said = r.stderr.decode(errors="replace")
			if r.returncode == 0 or "--greeting=VALUE" not in said:
				raise failed("a: --nonsense was not refused with a usage naming the "
				             "extension's options: %r" % said[-300:])
			print("livecheck: a: the extension refused its own option in its words, and an "
			      "unknown one was refused with a usage naming its options")

			# b: its verbs, beside fuzznet's.
			log = open(os.path.join(scratch, "daemon.err"), "w")
			proc = subprocess.Popen(base + ["--greeting=howdy", "--quiet"], stdout=log,
			                        stderr=subprocess.STDOUT, start_new_session=True)
			got = ask(sock, "get greeting")
			if got != "ok howdy":
				raise failed("b: get greeting answered %r" % got)
			got = ask(sock, "status")
			if not got.startswith("ok ") or "extension" in got:
				raise failed("b: status was not fuzznet's: %r" % got)
			got = ask(sock, "list contact")
			if not got.startswith("ok") or "extension" in got:
				raise failed("b: list contact was not fuzznet's: %r" % got)
			got = ask(sock, "get garbled")
			if got != "error the extension's answer is not a reply":
				raise failed("b: an answer outside the vocabulary was passed on as %r" % got)
			got = ask(sock, "get nothing")
			if not got.startswith("unsupported"):
				raise failed("b: a verb nobody answers was answered %r" % got)
			print("livecheck: b: the extension answered its verb with its option's value; "
			      "status and list contact stayed fuzznet's; a garbled answer became error; "
			      "the rest unsupported")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		finally:
			if proc is not None and proc.poll() is None:
				os.killpg(proc.pid, signal.SIGTERM)
				try:
					proc.wait(timeout=10)
				except subprocess.TimeoutExpired:
					os.killpg(proc.pid, signal.SIGKILL)
					proc.wait(timeout=10)
		if time.monotonic() > deadline:
			print("livecheck: FAILED -- past the deadline")
			return 1
	print("livecheck: a daemon with an extension took its options and answered its verbs "
	      "after fuzznet's")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
