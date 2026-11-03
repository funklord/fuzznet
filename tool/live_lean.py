#!/usr/bin/env python3
"""livecheck-lean: fuzznetd built with the consumer services left out, sec 856.

The holder's of 2026-11-03: build-time flags for the consumer services, "kept
separate from the ability to relay and store those subsystems". So a lean
build is held to two things at once:

    gone     each service left out answers its verbs `unsupported`, as a
             node that never had it would
    kept     what the node carries and keeps for the estate still works:
             status, records and lists, and the files a sticker pack is

One daemon, one store, a few requests; it stops the daemon on every path
out. Usage: live_lean.py PATH_TO_LEAN_FUZZNETD
"""

import os
import signal
import socket
import subprocess
import sys
import tempfile
import time


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


# EACH SERVICE LEFT OUT, and requests of its that a build with it answers
# and this one must not.
GONE = {
	"stickers": ["list sticker", "get sticker 00 1", "remove sticker 00"],
	"catalogue": ["list catalog", "get catalog " + "00" * 32],
}


def main(argv):
	if len(argv) != 2:
		print("usage: live_lean.py PATH_TO_LEAN_FUZZNETD", file=sys.stderr)
		return 2
	daemon = os.path.abspath(argv[1])
	with tempfile.TemporaryDirectory(prefix="fzn-lean.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzl.", dir="/tmp") as sock_dir:
		store = os.path.join(scratch, "store")
		os.mkdir(store)
		sock = os.path.join(sock_dir, "s")
		base = [daemon, "--fuzznet-dir=" + store, "--log-dir=" + os.path.join(scratch, "log"),
		        "--fuzznet-service=1", "--fuzznet-product=1"]
		proc = None
		try:
			r = subprocess.run(base + ["--new-root"], capture_output=True, timeout=60)
			if r.returncode != 0:
				raise failed("--new-root failed: %r" % r.stderr.decode(errors="replace")[-300:])
			proc = subprocess.Popen(base + ["--socket=" + sock], stdout=subprocess.DEVNULL,
			                        stderr=subprocess.DEVNULL, start_new_session=True)
			if not ask(sock, "status").startswith("ok "):
				raise failed("the lean daemon did not answer status")
			for service, lines in GONE.items():
				for line in lines:
					got = ask(sock, line)
					if not got.startswith("unsupported"):
						raise failed("%s left out, %r answered %r" % (service, line, got))
			print("livecheck-lean: gone: %s answer unsupported" % ", ".join(sorted(GONE)))
			if ask(sock, "add record seen/wlan0/aa-bb 1") != "ok" \
			   or not ask(sock, "list record self").startswith("ok 0 1 0 "):
				raise failed("records were not kept by the lean build")
			if ask(sock, "add listed allow aa-bb") != "ok" \
			   or ask(sock, "get listed allow aa-bb") != "ok in":
				raise failed("lists were not kept by the lean build")
			src = os.path.join(scratch, "pack")
			with open(src, "wb") as f:
				f.write(os.urandom(5000))
			got = ask(sock, "put file " + src)
			if not got.startswith("ok "):
				raise failed("a file was not kept by the lean build: %r" % got)
			root = got.split()[1][:64]
			listed = ask(sock, "list file")
			if not listed.startswith("ok ") or root not in listed:
				raise failed("the lean build did not list the file put, %s: %r" % (root, listed))
			print("livecheck-lean: kept: status, records, lists and files")
		except failed as e:
			print("livecheck-lean: FAILED -- %s" % e)
			return 1
		finally:
			if proc is not None:
				try:
					os.killpg(proc.pid, signal.SIGTERM)
					proc.wait(timeout=10)
				except (ProcessLookupError, subprocess.TimeoutExpired):
					os.killpg(proc.pid, signal.SIGKILL)
					proc.wait(timeout=10)
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
