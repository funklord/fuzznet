#!/usr/bin/env python3
"""A daemon told no socket serves on the default one: `make livecheck`, sec
663.

One store. fuzznetd is started with XDG_RUNTIME_DIR set to a scratch
directory and no `--socket`; it serves on XDG_RUNTIME_DIR/fuzznet/
fuzznetd.sock, its directory mode 0700, and answers `status` there. Against
a daemon with no default, it serves no local socket and the wait for it
fails.

BOUNDED FROM INSIDE: one deadline; the daemon in its own process group,
stopped by SIGTERM and then SIGKILL, and checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

DEADLINE_S = 60.0


def main(argv):
	if len(argv) != 2:
		print("usage: live_socket.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2
	fuzznetd = os.path.abspath(argv[1])
	deadline = time.monotonic() + DEADLINE_S
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzx.", dir="/tmp") as run_dir:
		store = os.path.join(scratch, "store")
		os.mkdir(store)
		os.chmod(run_dir, 0o700)
		env = dict(os.environ, XDG_RUNTIME_DIR=run_dir)
		sock = os.path.join(run_dir, "fuzznet", "fuzznetd.sock")
		log = open(os.path.join(scratch, "fuzznetd.err"), "w")
		proc = subprocess.Popen([fuzznetd, "--fuzznet-dir=" + store], env=env, stdout=log,
		                        stderr=subprocess.STDOUT, start_new_session=True)
		try:
			while time.monotonic() < deadline and not os.path.exists(sock):
				if proc.poll() is not None:
					break
				time.sleep(0.2)
			if not os.path.exists(sock):
				log.flush()
				with open(log.name) as f:
					said = f.read()[-400:]
				print("livecheck: FAILED -- no socket at %s; fuzznetd said %r" % (sock, said))
				return 1
			mode = stat.S_IMODE(os.stat(os.path.dirname(sock)).st_mode)
			if mode != 0o700:
				print("livecheck: FAILED -- the socket's directory is mode %o, not 700" % mode)
				return 1
			reply = b""
			while time.monotonic() < deadline:
				try:
					c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
					c.settimeout(5.0)
					c.connect(sock)
					c.sendall(b"status\n")
					while not reply.endswith(b"\n"):
						got = c.recv(4096)
						if not got:
							break
						reply += got
					c.close()
					break
				except OSError:
					time.sleep(0.3)
			if not reply.startswith(b"ok "):
				print("livecheck: FAILED -- status at the default socket answered %r" % reply[:80])
				return 1
			print("livecheck: a daemon told no socket served on the default one, its "
			      "directory 0700")
			return 0
		finally:
			if proc.poll() is None:
				os.killpg(proc.pid, signal.SIGTERM)
				try:
					proc.wait(timeout=10)
				except subprocess.TimeoutExpired:
					os.killpg(proc.pid, signal.SIGKILL)
					proc.wait(timeout=10)
			log.close()


if __name__ == "__main__":
	sys.exit(main(sys.argv))
