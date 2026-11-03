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
    b2 its own FIFO, named by `--poke`, read when the node's loop says it is
       readable, and its tick called by the loop (sec 831); and, where the
       kernel's transparent huge pages are "always", the daemon holds no
       huge page, having asked for none and run itself again (secs 842, 862)
    b3 a local request asked in-process from its tick is answered by
       fuzznet's handlers, and refused from inside another; a change of its
       own, published from its tick, reaches a `get events` subscriber
       (sec 843); asked by its
       FIFO to stop, the node returns 0 with its socket and `face` file
       removed (sec 835)
    b4 started beside a face on the same store, it follows; its FIFO is
       still read and its tick still runs, a request it asks in-process is
       answered by the face, and asked to stop it returns 0 with its own
       socket removed, the face serving on (sec 838)
    b5 started on the face's own socket path, as two daemons told no
       `--socket` both are, it follows with no socket of its own, still
       ticks, and stops leaving the face's socket and the face serving
       (sec 841)
    c  two of them, A the root of an estate and B joined to it by verbs:
       `add mark hello` at A writes a journal record of the extension's
       kind into A's stream, and B's extension applies it -- `get marks`
       at B comes to say `ok 1 hello` -- so a kind fuzznet itself does not
       process is carried and handed over (sec 675). B was started with
       `--own-word=kept`, the extension's own option that fuzznet never
       sees, and still says it after the join's restart (sec 835)
    d  at A, the extension's declared setting is listed by `list schema`
       and `get schema`, and `set setting` refuses a value past its
       declaration and takes one inside it (sec 686); in phase a, an
       extension declaring a key of fuzznet's ends the start

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
			                      extra=["--udp-port=" + port[who]]
			                      + (["--own-word=kept"] if who == "b" else []))
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
		got = ask(socks["b"], "get own")
		if got != "ok kept":
			raise failed("c: B's own option was lost over the join's restart: %r" % got)
		if ask(socks["b"], "get marks") != "ok 0":
			raise failed("c: B held a mark before A wrote one")
		# A CALL ACROSS THE ESTATE, sec 853: B calls A's procedure by A's
		# host key, and A answers it as a remote caller's.
		a_host = ask(socks["a"], "get prekey").split()[1][4:68]
		until = time.monotonic() + 60.0
		while True:
			got = ask(socks["b"], "call echo at %s hi there" % a_host)
			if got == "ok remote%20hi%20there":
				break
			if time.monotonic() > until:
				raise failed("c: B's call of A's echo answered %r" % got)
			time.sleep(1.0)
		print("livecheck: c: B called A's procedure by name, and A answered it as a remote "
		      "caller's")
		# c2: A FOLLOWER'S PROCEDURE CALLED FROM ANOTHER HOST, sec 853 step 3:
		# A's face has no `fecho`, its follower offers it, and B's call is
		# forwarded there with B as the caller.
		follower = daemon(run, "cf", dirs["a"], os.path.join(sock_dir, "cf"),
		                  extra=["--echo-as=fecho"])
		started["af"] = follower
		until = time.monotonic() + 20.0
		while "offering 2 procedure" not in follower.stderr():
			if time.monotonic() > until or follower.proc.poll() is not None:
				raise failed("c2: A's follower offered nothing: %r" % follower.stderr()[-300:])
			time.sleep(0.2)
		got = ask(socks["b"], "call fecho at %s from b" % a_host)
		if got != "ok remote%20from%20b":
			raise failed("c2: B's call of A's follower's fecho answered %r" % got)
		follower.stop()
		del started["af"]
		print("livecheck: c2: B called a procedure A's follower offered, and A's face "
		      "forwarded it as a remote caller's")
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
		# c3: A'S EVENTS FROM B, sec 866: B asks what A published since 0,
		# and is told A's `add mark` among them, with a cursor to ask on.
		got = ask(socks["b"], "call events at %s 0" % a_host)
		words = got.split()
		if len(words) < 2 or words[0] != "ok" or "%20mark%20" not in words[1]:
			raise failed("c3: B's call events at A answered %r" % got[:200])
		print("livecheck: c3: B read A's events since its cursor, A's mark among them")

		# d: ITS SETTING DECLARED, sec 686: listed after fuzznet's, and a
		# value its declaration refuses refused.
		got = ask(socks["a"], "get schema ext/greeting")
		if not got.startswith("ok ext/greeting,text,host,1,16,hello,"):
			raise failed("d: get schema ext/greeting answered %r" % got)
		got = ask(socks["a"], "list schema ext/")
		if not got.startswith("ok 1 0 ext/greeting,"):
			raise failed("d: list schema ext/ answered %r" % got)
		got = ask(socks["a"], "set setting host ext/greeting " + "x" * 17)
		if got != "malformed ext/greeting: text of the wrong length":
			raise failed("d: a greeting past 16 bytes was answered %r" % got)
		if ask(socks["a"], "set setting host ext/greeting hi") != "ok" \
		   or ask(socks["a"], "get setting host ext/greeting") != "ok root hi":
			raise failed("d: a greeting its declaration takes was not set")
		print("livecheck: d: the extension's setting was listed after fuzznet's, a value "
		      "past its declaration refused, and one inside it set")
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
			# A KEY FUZZNET DECLARES, claimed by the extension, sec 686.
			env = dict(os.environ)
			env["FZN_EXT_CLASH"] = "1"
			r = subprocess.run(base, capture_output=True, timeout=30, env=env)
			said = r.stderr.decode(errors="replace")
			if r.returncode != 2 or "setting location/enabled is fuzznet's" not in said:
				raise failed("a: an extension claiming location/enabled started, or said "
				             "%r" % said[-300:])
			print("livecheck: a: the extension refused its own option in its words, an "
			      "unknown one was refused with a usage naming its options, and a "
			      "setting of fuzznet's it claimed ended the start")

			# b: its verbs, beside fuzznet's.
			log = open(os.path.join(scratch, "daemon.err"), "w")
			fifo = os.path.join(scratch, "poke")
			os.mkfifo(fifo)
			proc = subprocess.Popen(base + ["--greeting=howdy", "--quiet", "--poke=" + fifo],
			                        stdout=log, stderr=subprocess.STDOUT,
			                        start_new_session=True)
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
			# A LOCAL PERMISSION, sec 852: well-formed grants taken, and a
			# malformed one refused when written, as its reader would.
			if ask(sock, "set setting host local/permit/status group:root=r user:#0=rw") != "ok":
				raise failed("b: a well-formed local permit was refused")
			got = ask(sock, "set setting host local/permit/status group:root=w")
			if not got.startswith("malformed"):
				raise failed("b: a malformed local permit was answered %r" % got)
			# A PROCEDURE CALLED BY NAME, sec 853: here, its answer escaped.
			# THE BOUND STATED, sec 863: an answer whose escaped form is
			# FZN_DAEMON_CALL_ESCAPED_MAX (1020) bytes reaches the caller,
			# and one byte more is refused naming it -- plain bytes, and
			# spaces, which escape to three.
			for line, want in (("call fill 1020", "ok " + "a" * 1020),
			                   ("call fill 340 s", "ok " + "%20" * 340)):
				got = ask(sock, line)
				if got != want:
					raise failed("b: %s answered %r" % (line, got[:80]))
			for line in ("call fill 1021", "call fill 341 s"):
				got = ask(sock, line)
				if not got.startswith("error ") or "FZN_DAEMON_CALL_ESCAPED_MAX" not in got:
					raise failed("b: %s answered %r" % (line, got[:120]))
			# FUZZNET'S OWN PROCEDURE, sec 866: `events` from 0 -- NEXT, FIRST,
			# and what this node published since it started.
			got = ask(sock, "call events 0")
			if not got.startswith("ok ") or not got[3:].split("%20")[0].isdigit():
				raise failed("b: call events 0 answered %r" % got[:200])
			got = ask(sock, "call echo hello world")
			if got != "ok local%20hello%20world":
				raise failed("b: call echo answered %r" % got)
			got = ask(sock, "call nosuch")
			if not got.startswith("error no procedure nosuch here"):
				raise failed("b: a call of no procedure answered %r" % got)
			# THE CALLER'S CREDENTIALS, handed to the extension (sec 849).
			got = ask(sock, "get caller")
			if got != "ok %d" % os.getuid():
				raise failed("b: the extension was handed the caller %r, not uid %d"
				             % (got, os.getuid()))
			print("livecheck: b: the extension answered its verb with its option's value; "
			      "status and list contact stayed fuzznet's; a garbled answer became error; "
			      "the rest unsupported")

			# b2: ITS OWN DESCRIPTOR AND TIMER, sec 831: three bytes written to
			# the FIFO it watches are read when the node's loop says so, and
			# the loop ticks it.
			wfd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
			try:
				os.write(wfd, b"abc")
			finally:
				os.close(wfd)
			until = time.monotonic() + 10.0
			while ask(sock, "get pokes") != "ok 3":
				if time.monotonic() > until:
					raise failed("b2: the extension's own descriptor was read %r"
					             % ask(sock, "get pokes"))
				time.sleep(0.2)
			first = int(ask(sock, "get ticks").split()[1])
			time.sleep(2.5)
			later = int(ask(sock, "get ticks").split()[1])
			if first < 1 or later <= first:
				raise failed("b2: the extension was ticked %d, then %d times" % (first, later))
			# NO HUGE PAGES ASKED FOR, sec 842: measured, 14,336 kB of them
			# on an empty store before, one page of 2,048 kB faulted before
			# the call after. Only where the kernel would give them.
			try:
				with open("/sys/kernel/mm/transparent_hugepage/enabled") as f:
					always = "[always]" in f.read()
			except OSError:
				always = False
			if always:
				huge = 0
				with open("/proc/%d/smaps_rollup" % proc.pid) as f:
					for line in f:
						if line.startswith("AnonHugePages:"):
							huge = int(line.split()[1])
				# NONE SINCE sec 862: the daemon runs itself again, once,
				# when a huge page was faulted before its main.
				if huge > 0:
					raise failed("b2: the daemon holds %d kB of huge pages" % huge)
			print("livecheck: b2: the extension's own descriptor was read when ready, and the "
			      "node's loop ticked it%s" % (", with no huge page" if always
			                                   else ""))

			# b3: IN-PROCESS, AND A CLEAN STOP, sec 835.
			got = ask(sock, "get nested")
			if got != "ok 0":
				raise failed("b3: a request in-process from inside one was answered: %r" % got)

			def poke(data):
				wfd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
				try:
					os.write(wfd, data)
				finally:
					os.close(wfd)

			poke(b"L")
			until = time.monotonic() + 10.0
			while True:
				got = ask(sock, "get inproc")
				if got != "ok none":
					break
				if time.monotonic() > until:
					raise failed("b3: the tick never asked its request in-process")
				time.sleep(0.2)
			if not got.startswith("ok ") or got == "ok refused" or "extension" in got:
				raise failed("b3: status asked in-process was answered %r" % got)
			# A CHANGE OF ITS OWN, told to the node's subscribers (sec 843).
			sub = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			sub.settimeout(10.0)
			try:
				sub.connect(sock)
				sub.sendall(b"get events\n")
				heard = b""
				while not heard.endswith(b"\n"):
					heard += sub.recv(256)
				if heard.strip() != b"ok events":
					raise failed("b3: get events answered %r" % heard)
				poke(b"E")
				heard = b""
				while not heard.endswith(b"\n"):
					got = sub.recv(256)
					if not got:
						break
					heard += got
				if heard.strip() != b"event ext-poke -":
					raise failed("b3: the subscriber heard %r of the extension's change" % heard)
			except socket.timeout:
				raise failed("b3: the subscriber heard nothing of the extension's change")
			finally:
				sub.close()
			face = os.path.join(store, "face")
			if not os.path.exists(face):
				raise failed("b3: the face file was never written")
			poke(b"S")
			try:
				code = proc.wait(timeout=10)
			except subprocess.TimeoutExpired:
				raise failed("b3: asked to stop, the node went on serving")
			if code != 0 or os.path.exists(sock) or os.path.exists(face):
				raise failed("b3: stopped with %d, socket left %s, face left %s"
				             % (code, os.path.exists(sock), os.path.exists(face)))
			print("livecheck: b3: a request asked in-process was fuzznet's, refused inside "
			      "another, and a stop asked removed the socket and the face file")

			# b4: A FOLLOWER IS STILL THE DAEMON, sec 838.
			face_proc = subprocess.Popen(base, stdout=log, stderr=subprocess.STDOUT,
			                             start_new_session=True)
			try:
				if not ask(sock, "status").startswith("ok "):
					raise failed("b4: the face did not answer")
				fsock = os.path.join(sock_dir, "f")
				ferr_path = os.path.join(scratch, "follower.err")
				ferr = open(ferr_path, "w")
				fargs = [a for a in base if not a.startswith("--socket=")]
				follower = subprocess.Popen(fargs + ["--socket=" + fsock, "--poke=" + fifo,
				                                     "--echo-as=fecho"],
				                            stdout=ferr, stderr=subprocess.STDOUT,
				                            start_new_session=True)
				try:
					until = time.monotonic() + 10.0
					while "following the face" not in open(ferr_path).read():
						if time.monotonic() > until or follower.poll() is not None:
							raise failed("b4: the second daemon did not follow: %r"
							             % open(ferr_path).read()[-300:])
						time.sleep(0.2)
					# A PROCEDURE THE FOLLOWER ALONE HAS, sec 853 step 3: the face
					# forwards it, unread, and answers what the follower said.
					until = time.monotonic() + 10.0
					while "offering 2 procedure" not in open(ferr_path).read():
						if time.monotonic() > until:
							raise failed("b4: the follower offered no procedure: %r"
							             % open(ferr_path).read()[-300:])
						time.sleep(0.2)
					got = ask(sock, "call fecho via the face")
					if got != "ok local%20via%20the%20face":
						raise failed("b4: the face's forward of fecho answered %r" % got)
					got = ask(sock, "call nosuch")
					if got != "error no procedure nosuch here":
						raise failed("b4: an unoffered name answered %r" % got)
					poke(b"L")
					until = time.monotonic() + 10.0
					while "ext_daemon: inproc" not in open(ferr_path).read():
						if time.monotonic() > until:
							raise failed("b4: the follower's tick asked nothing in-process")
						time.sleep(0.2)
					said = [l for l in open(ferr_path).read().splitlines()
					        if l.startswith("ext_daemon: inproc")][-1]
					if not said.startswith("ext_daemon: inproc ok ") or "refused" in said:
						raise failed("b4: the follower's request in-process was %r" % said)
					poke(b"S")
					try:
						code = follower.wait(timeout=10)
					except subprocess.TimeoutExpired:
						raise failed("b4: asked to stop, the follower went on")
					if code != 0 or os.path.exists(fsock):
						raise failed("b4: the follower stopped with %d, socket left %s"
						             % (code, os.path.exists(fsock)))
					if not ask(sock, "status").startswith("ok "):
						raise failed("b4: the face stopped serving with its follower")
					got = ask(sock, "call fecho again")
					if got != "error no procedure fecho here":
						raise failed("b4: the stopped follower's fecho answered %r" % got)
				finally:
					if follower.poll() is None:
						os.killpg(follower.pid, signal.SIGKILL)
						follower.wait(timeout=10)
					ferr.close()
				print("livecheck: b4: following a face, the extension's FIFO was read and its "
				      "tick ran, its request in-process was the face's, the face forwarded "
				      "its procedure, and a stop removed its socket and its offer")

				# b5: ON THE FACE'S OWN SOCKET PATH, sec 841.
				s_err_path = os.path.join(scratch, "shared.err")
				s_err = open(s_err_path, "w")
				shared = subprocess.Popen(base + ["--poke=" + fifo], stdout=s_err,
				                          stderr=subprocess.STDOUT, start_new_session=True)
				try:
					until = time.monotonic() + 10.0
					while "its clients the face's" not in open(s_err_path).read():
						if time.monotonic() > until or shared.poll() is not None:
							raise failed("b5: a daemon on the face's socket did not follow: %r"
							             % open(s_err_path).read()[-300:])
						time.sleep(0.2)
					poke(b"L")
					until = time.monotonic() + 10.0
					while "ext_daemon: inproc ok " not in open(s_err_path).read():
						if time.monotonic() > until:
							raise failed("b5: the follower on the face's socket did not tick")
						time.sleep(0.2)
					poke(b"S")
					try:
						code = shared.wait(timeout=10)
					except subprocess.TimeoutExpired:
						raise failed("b5: asked to stop, the follower went on")
					if code != 0 or not os.path.exists(sock) \
					   or not ask(sock, "status").startswith("ok "):
						raise failed("b5: stopped with %d, and the face's socket %s"
						             % (code, "there" if os.path.exists(sock) else "gone"))
				finally:
					if shared.poll() is None:
						os.killpg(shared.pid, signal.SIGKILL)
						shared.wait(timeout=10)
					s_err.close()
			finally:
				os.killpg(face_proc.pid, signal.SIGTERM)
				try:
					face_proc.wait(timeout=10)
				except subprocess.TimeoutExpired:
					os.killpg(face_proc.pid, signal.SIGKILL)
					face_proc.wait(timeout=10)
			print("livecheck: b5: on the face's own socket path it followed with none of its "
			      "own, ticked, and stopped leaving the face's socket serving")

			# b6: NO CAPABILITY, sec 857: started with no --fuzznet-service and
			# --fuzznet-product, its own verbs and procedures still answer,
			# status stays fuzznet's, and the rest is unsupported.
			bare = [a for a in base if not a.startswith("--fuzznet-")]
			alone = subprocess.Popen(bare, stdout=log, stderr=subprocess.STDOUT,
			                         start_new_session=True)
			try:
				if not ask(sock, "status").startswith("ok "):
					raise failed("b6: with no capability, status did not answer")
				got = ask(sock, "get greeting")
				if got != "ok hello":
					raise failed("b6: with no capability, get greeting answered %r" % got)
				got = ask(sock, "get caller")
				if got != "ok %d" % os.getuid():
					raise failed("b6: with no capability, local_from was not asked: %r" % got)
				got = ask(sock, "call echo alone")
				if got != "ok local%20alone":
					raise failed("b6: with no capability, call echo answered %r" % got)
				got = ask(sock, "get garbled")
				if not got.startswith("error "):
					raise failed("b6: a garbled answer with no capability was %r" % got)
				got = ask(sock, "list nothing")
				if not got.startswith("unsupported"):
					raise failed("b6: with no capability, list nothing answered %r" % got)
			finally:
				os.killpg(alone.pid, signal.SIGTERM)
				try:
					alone.wait(timeout=10)
				except subprocess.TimeoutExpired:
					os.killpg(alone.pid, signal.SIGKILL)
					alone.wait(timeout=10)
			print("livecheck: b6: with no capability its verbs, its caller's credentials and "
			      "its procedure answered, status stayed fuzznet's, the rest unsupported")
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
