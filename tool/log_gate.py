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
	for path in sources(test=False):
		with open(path, encoding="utf-8") as f:
			for sub in EMIT.findall(f.read()):
				emitted.setdefault(sub, []).append(os.path.relpath(path, ROOT))

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

	asserted = ""
	for path in sources(test=True):
		with open(path, encoding="utf-8") as f:
			asserted += f.read()

	bad = 0
	for sub in sorted(emitted):
		if '"%s"' % sub not in asserted:
			print("log-gate: nothing asserts the subsystem %s" % sub)
			print("log-gate:   emitted from %s" % ", ".join(sorted(set(emitted[sub]))))
			bad += 1

	if bad:
		print("log-gate: a subsystem is printed and never compared, so a typo")
		print("log-gate: files a normal-looking line where nobody greps for it.")
		return 1

	print("log-gate: %d subsystem(s) over %d emit site(s), each asserted by a test"
	      % (len(emitted), sum(len(v) for v in emitted.values())))
	return 0


if __name__ == "__main__":
	sys.exit(main())
