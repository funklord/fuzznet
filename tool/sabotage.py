#!/usr/bin/env python3
"""Break one guard at a time and see whether anything goes red.

A guard nothing holds to account is a guard that is correct today and
load-bearing tomorrow, and reading the code finds none of them: both halves
look identical on the page. The only observation that separates "defended"
from "defended-looking" is removing the line and watching the suite.

WHAT THIS IS FOR, and it is not carefulness. evidence.md: the argument for a
sabotage harness is that it removes the moment where being careful is a
choice. project.md sec 11 records two guards found this way -- a body bound
in `fzn_record_is_open` whose removal left all 47 binaries green, and a
clearing in reassembly's `admit_first` that `release` already did -- and sec
36 records two more, both in `chain/manifest.c`, whose identical siblings in
`chain/chain.c` were defended all along.

THE POLARITY IS INVERTED HERE AND THAT IS THE WHOLE DESIGN PROBLEM.
Everywhere else in this tree a passing check is the thing to distrust. In a
sabotage sweep the SURVIVOR is the result, so a harness that quietly mutated
nothing reports every entry as a finding and is wrong about all of them.
Hence CONTROLS below, which must be caught, and whose failure suppresses the
report rather than annotating it.

HOW IT STOPS: a fixed list, one `make test` per entry, a timeout on each,
no recursion and nothing backgrounded. The worst case is
len(SABOTAGES) * TIMEOUT, and `--only` narrows it to one.

WHAT IT REFUSES TO DO: run in a tree with uncommitted changes to the files
it edits. It rewrites tracked files in place and restores them from memory,
so if it is killed hard the recovery is `git checkout -- <file>` -- and
CLAUDE.md is emphatic that a discard is unrecoverable in a way a bad commit
is not. Requiring those files to be clean first is what makes the recovery
safe to recommend.
"""

import argparse
import hashlib
import io
import os
import signal
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIMEOUT = 1800

# id, file, exact text to remove, what replaces it, why it is a candidate.
#
# THE OLD TEXT IS MATCHED EXACTLY AND MUST OCCUR ONCE. project.md sec 4
# records a sweep whose pattern for `peer.c` matched nothing while the run
# reported a clean result, which is the same vacuous pass this tree keeps
# meeting: a mutation that did not apply and a check that cannot fail are
# indistinguishable from the output.
SABOTAGES = [
	(
		"CONTROL-wipe",
		"session/commitment.c",
		"\tfzn_wipe(derived, sizeof(derived));\n",
		"\t/* control: wipe removed */\n",
		"codegen_gate pins the wipe count -- MUST be caught",
	),
	(
		"CONTROL-delegable",
		"chain/chain.c",
		"\tout[FZN_HOP_OFF_DELEGABLE] = delegable ? 1u : 0u;\n",
		"\tout[FZN_HOP_OFF_DELEGABLE] = delegable ? 0u : 1u;\n",
		"inverts delegable -- MUST be caught by the suite",
	),
	(
		"hop-sig-zero",
		"chain/chain.c",
		"\tmemset(out + FZN_HOP_OFF_SIGNATURE, 0, FZN_SIG_LEN);\n",
		"\t/* sabotage */\n",
		"the encoder zeroes the signature field before signing",
	),
	(
		"hop-refused-clear",
		"chain/chain.c",
		"\t\tmemset(out, 0, FZN_HOP_LEN);\n",
		"\t\t/* sabotage */\n",
		"a refused signing must leave no openable hop",
	),
	(
		"manifest-sig-zero-sign",
		"chain/manifest.c",
		"\tfzn_put_be16(out + FZN_MANIFEST_OFF_COUNT, (uint16_t)count);\n"
		"\tmemset(out + FZN_MANIFEST_BODY_LEN(count), 0, FZN_SIG_LEN);\n",
		"\tfzn_put_be16(out + FZN_MANIFEST_OFF_COUNT, (uint16_t)count);\n"
		"\t/* sabotage */\n",
		"KNOWN SURVIVOR, and not a defect -- see project.md sec 36",
	),
	(
		"manifest-refused-clear",
		"chain/manifest.c",
		"\t\tmemset(out, 0, FZN_MANIFEST_LEN(count));\n",
		"\t\t/* sabotage */\n",
		"a refused issue must leave no openable manifest",
	),
	(
		"prekey-peer-zero",
		"prekey/prekey.c",
		"\tmemset(peer, 0, sizeof(*peer));\n",
		"\t/* sabotage */\n",
		"peer init must not depend on what the memory held",
	),
]

# Entries known to survive for a reason rather than through a gap. Listed so
# that a clean run reads as clean: an expected survivor reported as a finding
# every time is how a report stops being read. Removing an id from here is
# how you ask the question again.
EXPECTED_SURVIVORS = {"manifest-sig-zero-sign"}


def make_env():
	"""The environment for the inner `make`, with the outer one's removed.

	Run from a `make sabotage` recipe this is a nested make, and MAKEFLAGS
	carries the parent's jobserver file descriptors. A sub-make that inherits
	them without having been started by make itself reports "jobserver
	unavailable" and drops to serial, which is noise in the one place the
	output has to be read carefully. MAKELEVEL goes for the same reason.
	"""
	env = dict(os.environ)
	for name in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL"):
		env.pop(name, None)
	return env


def digest_of(path):
	return hashlib.sha256(io.open(path, "rb").read()).hexdigest()


def refuse(*lines):
	for line in lines:
		sys.stderr.write("sabotage: " + line + "\n")
	raise SystemExit(2)


def dirty_files(paths):
	"""Which of `paths` git reports as modified, staged or untracked."""
	out = subprocess.run(
		["git", "-C", ROOT, "status", "--porcelain", "--"] + list(paths),
		capture_output=True, text=True, check=False)
	if out.returncode != 0:
		# A git that will not answer is a broken instrument, not a clean
		# tree, and the two arrive here identically as empty output. The
		# same reasoning as style_gate.py's discovery step.
		refuse("git will not report the status of the files to be edited.",
		       *out.stderr.strip().splitlines(),
		       "refusing rather than editing a tree whose state is unknown.")
	return [line[3:] for line in out.stdout.splitlines() if line.strip()]


def main(argv):
	ap = argparse.ArgumentParser(
		description="break one guard at a time and rebuild through make test")
	ap.add_argument("--list", action="store_true",
	                help="print the entries and exit, running nothing")
	ap.add_argument("--only", metavar="ID", action="append",
	                help="run only this entry; repeatable. Controls are "
	                     "always added, since a run without them proves "
	                     "nothing")
	ap.add_argument("--timeout", type=int, default=TIMEOUT, metavar="SECONDS",
	                help="ceiling on one `make test` (default %d)" % TIMEOUT)
	args = ap.parse_args(argv)

	if args.list:
		for sid, rel, _, _, why in SABOTAGES:
			mark = " (expected survivor)" if sid in EXPECTED_SURVIVORS else ""
			print("%-24s %-22s %s%s" % (sid, rel, why, mark))
		return 0

	chosen = SABOTAGES
	if args.only:
		wanted = set(args.only) | {s[0] for s in SABOTAGES
		                           if s[0].startswith("CONTROL")}
		unknown = set(args.only) - {s[0] for s in SABOTAGES}
		if unknown:
			refuse("no such entry: " + ", ".join(sorted(unknown)))
		chosen = [s for s in SABOTAGES if s[0] in wanted]

	touched = sorted({rel for _, rel, _, _, _ in chosen})

	# The tree has to be clean in the files about to be rewritten. More than
	# one session works in these trees, and a file that is dirty is somebody
	# else's work in progress until proven otherwise.
	dirty = dirty_files(touched)
	if dirty:
		refuse("these files have uncommitted changes:", *["  " + d for d in dirty],
		       "this rewrites them in place and restores from memory, so a",
		       "hard kill leaves `git checkout` as the recovery -- which would",
		       "discard whatever is uncommitted. Commit or stash first.")

	pristine = {rel: io.open(os.path.join(ROOT, rel), encoding="utf-8").read()
	            for rel in touched}
	digests = {rel: digest_of(os.path.join(ROOT, rel)) for rel in touched}

	def restore_all():
		for rel, text in pristine.items():
			io.open(os.path.join(ROOT, rel), "w", encoding="utf-8").write(text)

	def on_signal(signum, frame):
		# A restore that only runs on the happy path is not a restore. The
		# suite is the long part of every iteration, so an interrupt almost
		# always arrives with a file mutated.
		del frame
		restore_all()
		sys.stderr.write("\nsabotage: signal %d -- files restored\n" % signum)
		raise SystemExit(130)

	signal.signal(signal.SIGINT, on_signal)
	signal.signal(signal.SIGTERM, on_signal)

	results = []
	try:
		for sid, rel, old, new, why in chosen:
			path = os.path.join(ROOT, rel)
			text = pristine[rel]
			seen = text.count(old)
			if seen != 1:
				print("%-24s PATTERN-MISS (%d matches), not run" % (sid, seen),
				      flush=True)
				results.append((sid, "PATTERN", why))
				continue
			io.open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
			if digest_of(path) == digests[rel]:
				restore_all()
				refuse("%s: the file did not change on disk." % sid,
				       "a mutation that did not apply looks exactly like a",
				       "guard nothing catches, so this stops instead.")
			run = subprocess.run(["make", "test"], cwd=ROOT, env=make_env(),
			                     capture_output=True, text=True,
			                     timeout=args.timeout)
			io.open(path, "w", encoding="utf-8").write(text)
			if digest_of(path) != digests[rel]:
				refuse("%s: restore did not reproduce the original." % rel)
			verdict = "CAUGHT" if run.returncode != 0 else "SURVIVED"
			detail = ""
			if run.returncode != 0:
				named = [ln for ln in (run.stdout + run.stderr).splitlines()
				         if "FAIL" in ln and "deliberate" not in ln]
				detail = named[-1].strip()[:70] if named else ""
			results.append((sid, verdict, detail or why))
			print("%-24s %-9s %s" % (sid, verdict, detail), flush=True)
	finally:
		restore_all()
		for rel in touched:
			if digest_of(os.path.join(ROOT, rel)) != digests[rel]:
				sys.stderr.write("sabotage: %s NOT RESTORED\n" % rel)
				return 2

	controls = [r for r in results if r[0].startswith("CONTROL")]
	if not controls or any(v != "CAUGHT" for _, v, _ in controls):
		refuse("a control was not caught, so nothing above means anything.",
		       "the suite or the build is not running what it appears to be.")

	missed = [r for r in results if r[1] == "PATTERN"]
	if missed:
		refuse("%d pattern(s) matched nothing, so the sweep is incomplete."
		       % len(missed),
		       "a stale pattern reports a guard as defended without testing it.")

	surprises = [(sid, why) for sid, verdict, why in results
	             if verdict == "SURVIVED" and sid not in EXPECTED_SURVIVORS]
	unexpected_catch = [sid for sid, verdict, _ in results
	                    if verdict == "CAUGHT" and sid in EXPECTED_SURVIVORS]
	for sid in unexpected_catch:
		print("\nsabotage: %s is listed as an expected survivor and was "
		      "CAUGHT." % sid)
		print("sabotage: something now tests it -- take it off the list.")
	if not surprises:
		print("\nsabotage: every guard is held to account by something.")
		return 0
	print("\nsabotage: %d guard(s) nothing noticed:" % len(surprises))
	for sid, why in surprises:
		print("   %s: %s" % (sid, why))
	return 1


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
