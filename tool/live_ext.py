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
    c  two of them, A the root of an estate and B joined to it by verbs:
       `add mark hello` at A writes a journal record of the extension's
       kind into A's stream, and B's extension applies it -- `get marks`
       at B comes to say `ok 1 hello` -- so a kind fuzznet itself does not
       process is carried and handed over (sec 675)

Against a daemon that hands nothing to the extension, phase a's option is
refused as unknown and phase b's `get greeting` is `unsupported`; against
one that asks the extension first, phase b's `list contact` is the
extension's; against one that carries no record of an unknown kind, or
hands none to the extension, phase c's `get marks` at B stays `ok 0`.

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

DEADLINE_S = 240.0

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_trim  # noqa: E402
from live_rejoin import ROUND_DONE_RE, command, daemon  # noqa: E402

live_trim.DEADLINE = time.monotonic() + DEADLINE_S


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


def c_marks(daemon_path, scratch, sock_dir):
	"""Phase c: a mark written at A, applied by B's extension."""

	class run:
		pass

	run.fuzznetd = daemon_path
	run.started = []
	run.scratch = scratch
	base = 32700 + (os.getpid() % 16) * 2
	port = {"a": str(base), "b": str(base + 1)}
	dirs = {k: os.path.join(scratch, "c-" + k) for k in port}
	socks = {k: os.path.join(sock_dir, "c" + k) for k in port}
	started = {}
	try:
		for who in port:
			os.mkdir(dirs[who])
		command(run, ["--fuzznet-dir=" + dirs["a"], "--new-root"], None)
		for who in ("a", "b"):
			started[who] = daemon(run, "c" + who, dirs[who], socks[who],
			                      extra=["--udp-port=" + port[who]])
		started["a"].wait_for(ROUND_DONE_RE, "A's first round", within=60.0)
		got = ask(socks["b"], "get prekey").split()
		if len(got) != 2 or got[0] != "ok":
			raise failed("c: get prekey answered %r" % got)
		card = ask(socks["a"], "add peer %s delegable" % got[1]).split()
		if len(card) != 2 or card[0] != "ok":
			raise failed("c: add peer ... delegable answered %r" % card)
		card_path = os.path.join(scratch, "c-card")
		with open(card_path, "w") as f:
			f.write(card[1] + "\n")
		joined = ask(socks["b"], "add join %s 127.0.0.1 %s" % (card_path, port["a"])).split()
		if len(joined) != 2 or joined[0] != "ok":
			raise failed("c: add join answered %r" % joined)
		until = time.monotonic() + 30.0
		while True:
			try:
				if ask(socks["b"], "status", within=2.0).startswith("ok "):
					break
			except failed:
				pass
			if time.monotonic() > until:
				raise failed("c: B's socket did not come back after the join")
			time.sleep(0.3)
		if ask(socks["b"], "get marks") != "ok 0":
			raise failed("c: B held a mark before A wrote one")
		got = ask(socks["a"], "add mark hello")
		if got != "ok":
			raise failed("c: add mark at A answered %r" % got)
		until = time.monotonic() + 120.0
		while ask(socks["b"], "get marks") != "ok 1 hello":
			if time.monotonic() > until:
				raise failed("c: B's extension never applied A's mark: %r"
				             % ask(socks["b"], "get marks"))
			time.sleep(1.0)
		print("livecheck: c: a record of the extension's kind written at A was carried to B "
		      "and applied by B's extension")
	finally:
		for d in started.values():
			d.stop()


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
		# A LOG DIRECTORY OF ITS OWN: told none, the daemon logs into the
		# user's own `~/.local/state/fuzznet/log`.
		base = [daemon, "--socket=" + sock, "--fuzznet-dir=" + store,
		        "--log-dir=" + os.path.join(scratch, "log"),
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
			os.killpg(proc.pid, signal.SIGTERM)
			proc.wait(timeout=10)
			c_marks(daemon_path=daemon, scratch=scratch, sock_dir=sock_dir)
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
