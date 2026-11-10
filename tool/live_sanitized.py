#!/usr/bin/env python3
"""The live scripts over a sanitized fuzznetd: `make livecheck-san`, sec 889.

`make sancheck` runs the suite under ASan and UBSan and no live script, so
what only a running node reaches was not reached: fuzzypickles found a read
of freed memory and a table of uninitialised rows that way. Here each script
runs over a sanitized daemon.

Reports go to files, one per process, so a daemon that died and a script that
passed anyway are both seen: ANY report fails the run, whatever the script
said. That covers leaks: SIGTERM stops a serving daemon cleanly (sec 897), so
LeakSanitizer runs at its exit. A daemon a script KILLs, as a crash test does,
says nothing of them.

A run with no script run has tested nothing, so a list that reaches none
fails too.

BOUNDED FROM INSIDE: each script has its own deadline and this one's bound
over it, and each stops its daemons as it does under `make livecheck`.

Exit 0 on a pass, 1 on a failure.
"""

import glob
import os
import subprocess
import sys
import tempfile

# THE FILES AND OBJECTS, the last four, since sec 1002: transfers, a folder of
# files a friend browses, and named objects had run over no sanitized daemon.
SCRIPTS = ("live_events", "live_stickers", "live_location", "live_socket", "live_face",
           "live_strangers", "live_rot", "live_moved", "live_names", "live_share_sibling", "live_groups",
           "live_group_backfill", "live_group_hosts", "live_contacts", "live_pairing",
           "live_relay", "live_siblings", "live_shares", "live_catalog", "live_join", "live_preset", "live_votes",
           "live_invite",
           "live_files_many", "live_browse", "live_objects", "live_transfer")
SCRIPT_S = 2400


def main(argv):
	if len(argv) != 2:
		print("usage: live_sanitized.py PATH_TO_SANITIZED_FUZZNETD", file=sys.stderr)
		return 2
	here = os.path.dirname(os.path.abspath(__file__))
	daemon = os.path.abspath(argv[1])
	failed = []
	ran = 0
	with tempfile.TemporaryDirectory(prefix="fzn-san.") as logs:
		env = dict(os.environ)
		env["ASAN_OPTIONS"] = "detect_leaks=1:log_path=" + os.path.join(logs, "asan")
		env["UBSAN_OPTIONS"] = "print_stacktrace=1:log_path=" + os.path.join(logs, "ubsan")
		for name in SCRIPTS:
			path = os.path.join(here, name + ".py")
			if not os.path.exists(path):
				continue
			ran += 1
			try:
				done = subprocess.run([sys.executable, path, daemon], env=env, timeout=SCRIPT_S,
				                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
				if done.returncode != 0:
					failed.append(name)
					print(done.stdout.decode(errors="replace")[-800:])
			except subprocess.TimeoutExpired:
				failed.append(name + " (past its bound)")
			print("livecheck: sanitized: %s %s" % (name, "FAILED" if name in failed else "passed"),
			      flush=True)
		reports = sorted(glob.glob(os.path.join(logs, "asan.*"))
		                 + glob.glob(os.path.join(logs, "ubsan.*")))
		for report in reports[:6]:
			with open(report, errors="replace") as f:
				print("livecheck: --- %s\n%s" % (os.path.basename(report), f.read()[:2000]))
	if not ran:
		print("livecheck: FAILED -- no script was found to run")
		return 1
	if reports or failed:
		print("livecheck: FAILED -- %d report(s), and failed: %s" % (len(reports), failed))
		return 1
	print("livecheck: %d live scripts over a sanitized daemon, and no report" % ran)
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
