#!/usr/bin/env python3
"""fuzznetd's and fuzznet-bridge's --help and --version for a manual page:
`make livecheck`, sec 1443.

`--help` and `-h` print the usage on stdout, nothing on stderr, and exit 0;
`--version` prints the program's name, fuzznet's version and the copyright
on stdout and exits 0 -- what help2man reads. A mistaken option keeps the
usage on stderr and status 2, so a script that typed it wrong still sees a
failure. Against either program before the change, --help fell through to
the mistaken case and fails every check here. And fuzznetd refuses, status
2, a `--group` that names no group and a port that is not 1 to 65535 in
full (sec 1444).

BOUNDED FROM INSIDE: every run has a timeout of its own; nothing is served,
so no process outlives its run.

Exit 0 on a pass, 1 on a failure.
"""

import os
import subprocess
import sys
import tempfile

RUN_TIMEOUT_S = 10.0


SCRATCH = tempfile.TemporaryDirectory(prefix="fzn-live.")


def run(fuzznetd, *args):
	"""In a scratch XDG home: a program that wrongly accepts a value goes on
	to make a store and a socket, and must make them nowhere that matters."""
	env = dict(os.environ)
	for v in ("XDG_DATA_HOME", "XDG_RUNTIME_DIR", "XDG_STATE_HOME", "HOME"):
		env[v] = SCRATCH.name
	try:
		return subprocess.run([fuzznetd] + list(args), capture_output=True, text=True,
		                      timeout=RUN_TIMEOUT_S, stdin=subprocess.DEVNULL, env=env)
	except subprocess.TimeoutExpired:
		return subprocess.CompletedProcess(args, -1, "", "(still running at the timeout)")


# VALUES fuzznetd REFUSES, sec 1444: strtol once read each as 0 or a prefix.
REFUSED = (
	("--group", "fzn-no-such-group-here"),
	("--group", "100x"),
	("--to", "127.0.0.1", "80x"),
	("--root-at", "127.0.0.1", "0"),
	("--pull-from", "00" * 32, "127.0.0.1", "65536"),
)

# AND THE BRIDGE'S, the same section: a unit or a port with a tail.
BRIDGE_REFUSED = (
	("--unit=64x", "--udp=127.0.0.1:9"),
	("--unit=64", "--udp=127.0.0.1:9x"),
	("--unit=64", "--udp=127.0.0.1:"),
)


def check(program, name, version):
	failed = []
	for flag in ("--help", "-h"):
		r = run(program, flag)
		if r.returncode != 0 or r.stderr or not r.stdout.startswith("usage: "):
			failed.append("%s %s: status %d, %d bytes on stderr, stdout opens %r"
			              % (name, flag, r.returncode, len(r.stderr), r.stdout[:20]))
	r = run(program, "--version")
	first = r.stdout.split("\n", 1)[0]
	if r.returncode != 0 or r.stderr or first != name + " (fuzznet) " + version \
	   or "Copyright" not in r.stdout:
		failed.append("%s --version: status %d, stdout %r" % (name, r.returncode, r.stdout[:80]))
	r = run(program, "--no-such-option")
	if r.returncode != 2 or r.stdout or "usage: " not in r.stderr:
		failed.append("%s, a mistaken option: status %d, %d bytes on stdout"
		              % (name, r.returncode, len(r.stdout)))
	return failed


def main(argv):
	if len(argv) not in (2, 3):
		print("usage: live_help.py PATH_TO_FUZZNETD [PATH_TO_FUZZNET_BRIDGE]", file=sys.stderr)
		return 2
	version = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
	                            "VERSION")).read().strip()
	failed = check(os.path.abspath(argv[1]), "fuzznetd", version)
	for args in REFUSED:
		r = run(os.path.abspath(argv[1]), *args)
		if r.returncode != 2 or ("fuzznetd: %s: " % args[0]) not in r.stderr \
		   or not ("is not a port" in r.stderr or "is no group" in r.stderr):
			failed.append("fuzznetd %s: status %d, said %r" % (" ".join(args), r.returncode,
			                                                    r.stderr[-120:]))
	if len(argv) == 3:
		failed += check(os.path.abspath(argv[2]), "fuzznet-bridge", version)
		for args in BRIDGE_REFUSED:
			r = run(os.path.abspath(argv[2]), *args)
			if r.returncode != 2 or not r.stderr.startswith("usage: "):
				failed.append("fuzznet-bridge %s: status %d" % (" ".join(args), r.returncode))
	for f in failed:
		print("livecheck: help FAILED -- " + f)
	if not failed:
		print("livecheck: help passed -- %d program(s): --help, -h and --version on stdout "
		      "with 0, a mistake on stderr with 2; %d bad value(s) refused"
		      % (len(argv) - 1, len(REFUSED) + (len(BRIDGE_REFUSED) if len(argv) == 3 else 0)))
	return 1 if failed else 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
