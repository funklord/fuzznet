#!/usr/bin/env python3
"""Every subsystem this library logs under is asserted by some test.

THE HAZARD IS THAT A SUBSYSTEM IS PRINTED AND NEVER COMPARED. A misspelled
one produces a log line that looks perfectly normal and files itself under a
name nobody greps for, and no suite can fail on it -- the emit succeeded, the
text is right, and only the filing is wrong. Reported by fuzzypickles on
2026-09-08, who found their own subsystems had drifted into three spellings
with nothing watching; this is the same guard against the same hazard, aimed
at this tree's convention rather than theirs.

WHAT IT CHECKS is not spelling but COVERAGE: each subsystem literal an emit
site uses must also appear in a test, which is the only thing that pins it.
A typo then fails, because the test asserts the old string -- and an emit site
added with no test at all fails too, which is the case a spelling check cannot
see.

IT DERIVES ITS POPULATION FROM THE SOURCE rather than from a list, so a new
emit site is covered by existing it rather than by somebody remembering to
add it. And it REFUSES AN EMPTY SWEEP: finding no emit sites means the
detector has stopped matching, not that the tree is clean, and those look
identical in the output.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Vendored trees and the consumer-facing halves, which are not the library.
SKIP = ("qtty", "quirc", "monocypher", "flog", "gui", "cli", "sim", "tool", ".git")

# `X_LOG(ctx, "sub/sys", SEVERITY, ...)` -- the subsystem is always the second
# argument, which is why the macros were made one shape.
EMIT = re.compile(r'\b[A-Z][A-Z_]*_LOG\s*\(\s*[^,]+,\s*"([^"]+)"')

# AND THE SEVERITY, BECAUSE THE SUBSYSTEM ALONE IS A NAME AND NOT A LINE.
#
# The check used to be "some test mentions this subsystem", and the summary
# said "each asserted by a test" -- which is a claim about SITES made by a
# check over NAMES. `chunk/reasm` has three sites under one name; one
# assertion satisfied all three, and a site added at a severity nothing
# asserts was invisible.
#
# A severity is what a test actually compares (`seen.type == FLOG_WARN`), so
# requiring one test FILE to name the subsystem and that severity together is
# the strongest thing available without matching message text. Concatenating
# every test first would be vacuous: FLOG_WARN appears somewhere in the suite
# whatever any one module asserts.
#
# WHAT IT STILL DOES NOT CATCH, pinned here so nobody quotes it for more:
# two sites at the SAME subsystem and severity, one asserted and one not.
# Catching that needs message text, and a test asserts fragments rather than
# the whole line, so there is nothing mechanical to compare.
PAIR = re.compile(r'\b[A-Z][A-Z_]*_LOG\s*\(\s*[^,]+,\s*"([^"]+)"\s*,\s*(FLOG_[A-Z_]+)')

# AND THE PATTERN ABOVE ENCODES A NAMING CONVENTION, WHICH IS A HOLE UNLESS
# SOMETHING CHECKS IT. sec 217: a wrapper named `LOG_DIAG` rather than
# `STREAM_LOG` was invisible to EMIT, so its emit site was never checked --
# and the empty-sweep guard could not fire either, because sixteen other sites
# still matched. **The gate reported success while missing one.**
#
# So every macro that wraps `flog_printf` must be named the way EMIT scans
# for. This finds the definitions and checks their names, which is the only
# way a mis-named one becomes loud rather than absent.
WRAPPER = re.compile(r'#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^\n]*\\?\n(?:[^\n]*\\\n)*[^\n]*flog_printf')


def sources(test):
	for dirpath, dirnames, filenames in os.walk(ROOT):
		dirnames[:] = [d for d in dirnames if d not in SKIP]
		for name in filenames:
			if not name.endswith(".c"):
				continue
			is_test = os.sep + "test" + os.sep in dirpath + os.sep
			if is_test == test:
				yield os.path.join(dirpath, name)


def main():
	emitted = {}
	pairs = {}
	unreadable = 0
	for path in sources(test=False):
		with open(path, encoding="utf-8") as f:
			text = f.read()
		rel = os.path.relpath(path, ROOT)
		subs = EMIT.findall(text)
		for sub in subs:
			emitted.setdefault(sub, []).append(rel)
		found = PAIR.findall(text)
		for sub, sev in found:
			pairs.setdefault((sub, sev), set()).add(rel)
		# A SITE WHOSE SEVERITY THIS CANNOT READ TAKES ITS PAIR WITH IT,
		# and would be counted as covered by the subsystem check above.
		# Same reasoning as the wrapper-name check below: a hole in a
		# pattern is silent unless something compares two counts.
		if len(found) != len(subs):
			print("log-gate: %s has %d emit site(s) and %d readable "
			      "severities" % (rel, len(subs), len(found)))
			unreadable += 1
	if unreadable:
		print("log-gate: a site whose severity is not a plain FLOG_ constant is")
		print("log-gate: invisible to the per-severity check, and nothing else")
		print("log-gate: would have said so.")
		return 2

	# THE WRAPPERS' NAMES, BEFORE ANY VERDICT ABOUT SUBSYSTEMS. A wrapper
	# EMIT cannot see contributes no subsystem, and its absence is silent.
	misnamed = 0
	for path in sources(test=False):
		with open(path, encoding="utf-8") as f:
			for name in WRAPPER.findall(f.read()):
				if not re.fullmatch(r"[A-Z][A-Z_]*_LOG", name):
					print("log-gate: %s wraps flog_printf and is named %s, which "
					      "this gate cannot see" % (os.path.relpath(path, ROOT), name))
					misnamed += 1
	if misnamed:
		print("log-gate: a wrapper the emit pattern misses takes its subsystems")
		print("log-gate: with it, and nothing here would have said so.")
		return 2

	if not emitted:
		print("log-gate: no emit sites found at all, so this checked nothing.")
		print("log-gate: the pattern has stopped matching, or the macros were renamed.")
		return 2

	# PER FILE, NOT CONCATENATED. See PAIR above: a severity looked for in
	# every test at once is found in all of them.
	tests = []
	for path in sources(test=True):
		with open(path, encoding="utf-8") as f:
			tests.append(f.read())
	asserted = "".join(tests)

	bad = 0
	for sub in sorted(emitted):
		if '"%s"' % sub not in asserted:
			print("log-gate: nothing asserts the subsystem %s" % sub)
			print("log-gate:   emitted from %s" % ", ".join(sorted(set(emitted[sub]))))
			bad += 1

	for sub, sev in sorted(pairs):
		if not any('"%s"' % sub in t and sev in t for t in tests):
			print("log-gate: no test names %s and %s together" % (sub, sev))
			print("log-gate:   emitted from %s"
			      % ", ".join(sorted(pairs[(sub, sev)])))
			bad += 1

	if bad:
		# BOTH FAILURES ARRIVE HERE AND THEY ARE NOT THE SAME FAULT, so
		# the trailer names both rather than explaining whichever one it
		# was written for first.
		print("log-gate: a subsystem printed and never compared lets a typo file a")
		print("log-gate: normal-looking line where nobody greps for it; a severity")
		print("log-gate: nothing asserts lets a line arrive at a level that filters")
		print("log-gate: it out, which is the same silence by another route.")
		return 1

	# THE SUMMARY NAMES WHAT WAS CHECKED. It used to say every site was
	# asserted, over a check that only ever looked at names.
	print("log-gate: %d subsystem(s) over %d emit site(s); each subsystem, and "
	      "each severity it emits at, is named by a test"
	      % (len(emitted), sum(len(v) for v in emitted.values())))
	return 0


if __name__ == "__main__":
	sys.exit(main())
