#!/usr/bin/env python3
"""Refuse a library source that throws away a status it was handed.

WHY THIS EXISTS. project.md sec 75 found a seam whose failure CANNOT be
reported -- `fzn_aead_ops.seal` returns void, and over an in-place AEAD that
turns a backend failure into plaintext on the wire. This is the same class one
step out: a failure that IS reported and then discarded.

`evidence.md` states it as a rule -- *a guard's failure has to become the
caller's failure, or its absence is a pass* -- and gives the incident: a
cleanup trap that ran `waitgone.sh "$R"; rm -rf "$R"`, status never read, so
every scenario printed "No such file or directory" and then reported all cases
passed.

Measured 2026-09-04 across 131 status-returning functions: **no library source
discards one.** That is the property this keeps, because a property nobody
checks is one that stops being true without anybody noticing.

WHAT IT IS, HONESTLY: a heuristic on line shape, not a parser. It finds a call
that begins a line, to a function a header declares as returning a status,
where the previous non-blank line ended a statement. That is the shape a
discarded return actually takes in this tree.

WHAT IT CANNOT SEE, pinned here so nobody quotes it for a guarantee it does
not make:

  - a discarded call that is not first on its line -- `x = 1; fzn_foo();`
  - a status assigned to a variable that is then never read
  - a call made through a function pointer or generated from a macro
  - anything in the generated or vendored sources, which it skips

Tests and tools are counted and NOT refused. 82 of them discard a status, and
almost all are `fzn_*_init` in a fixture with literal arguments and stack
buffers, which cannot fail: those inits refuse only a null pointer or a zero
capacity, and a literal cannot be either. The real hazard there -- a fixture
that silently did not build, then asserted over it -- is what `REQUIRE`
already exists for in the unit suites, and sweeping 82 call sites to restate
it would be a large mechanical edit for a risk the suites already handle by
going red.

ITS CONTROL IS INSIDE IT AND RUNS FIRST, for `enum_gate.py`'s reason: a probe
whose failure mode is silence has to demonstrate on every run that it can
speak.
"""

import re
import sys
import glob

SKIP_DIRS = ("monocypher/",)


def blank_comments(text):
	"""Strip comments and string bodies, KEEPING every newline.

	The newlines are the point. A first version stripped comments outright
	and then reported line numbers computed from the stripped text, so every
	number it printed pointed at the wrong line -- and two of them were read
	as findings before the mismatch showed up. An instrument that reports a
	true fault at a false address costs the reader the same as a false one.
	"""
	out = []
	i = 0
	n = len(text)
	while i < n:
		if text.startswith("/*", i):
			j = text.find("*/", i + 2)
			j = n if j < 0 else j + 2
			out.append(re.sub(r"[^\n]", " ", text[i:j]))
			i = j
		elif text.startswith("//", i):
			j = text.find("\n", i)
			j = n if j < 0 else j
			out.append(" " * (j - i))
			i = j
		elif text[i] in "\"'":
			quote = text[i]
			j = i + 1
			while j < n and text[j] != quote:
				j += 2 if text[j] == "\\" else 1
			out.append(text[i:j + 1])
			i = j + 1
		else:
			out.append(text[i])
			i += 1
	return "".join(out)


def wanted(path):
	if any(path.startswith(d) for d in SKIP_DIRS):
		return False
	return "generated" not in path


def returns_status():
	"""Every fzn_ function a header declares as returning a status."""
	found = {}
	for header in glob.glob("**/*.h", recursive=True):
		if not wanted(header):
			continue
		with open(header, errors="replace") as handle:
			text = blank_comments(handle.read())
		for m in re.finditer(
		        r"^\s*((?:fzn_\w+_(?:err|verdict)_t)|int)\s+(fzn_\w+)\s*\(",
		        text, re.M):
			found[m.group(2)] = m.group(1)
	return found


def discards(text, status):
	"""Lines where a status-returning call stands alone as a statement."""
	lines = blank_comments(text).split("\n")
	hits = []
	for i, line in enumerate(lines):
		m = re.match(r"^[ \t]+(fzn_\w+)\s*\(", line)
		if not m or m.group(1) not in status:
			continue
		j = i - 1
		while j >= 0 and not lines[j].strip():
			j -= 1
		prev = lines[j].rstrip() if j >= 0 else "{"
		if not prev.endswith((";", "{", "}", ":")):
			continue
		hits.append((i + 1, m.group(1), status[m.group(1)], line.strip()))
	return hits


CONTROL_STATUS = {"fzn_control_call": "fzn_control_err_t"}
CONTROL_CLEAN = "\n".join([
        "void caller(void)",
        "{",
        "\tif (fzn_control_call(x) != FZN_CONTROL_OK)",
        "\t\treturn;",
        "\terr = fzn_control_call(y);",
        "}",
])
CONTROL_DISCARD = "\n".join([
        "void caller(void)",
        "{",
        "\tsetup();",
        "\tfzn_control_call(x);",
        "}",
])


def control():
	hits = discards(CONTROL_CLEAN, CONTROL_STATUS)
	if hits:
		return "a checked call was reported as discarded: %r" % (hits,)
	hits = discards(CONTROL_DISCARD, CONTROL_STATUS)
	if len(hits) != 1:
		return "the discarded control was NOT found: %r" % (hits,)
	if hits[0][0] != 4:
		return "the discarded control was found at line %d, wanted 4" % hits[0][0]
	return None


def main():
	failed = control()
	if failed:
		print("status-gate: THE CONTROL FAILED -- %s" % failed)
		print("status-gate: nothing below would have meant anything, so nothing ran.")
		return 1

	status = returns_status()
	library = []
	elsewhere = 0

	for source in sorted(glob.glob("**/*.c", recursive=True)):
		if not wanted(source):
			continue
		with open(source, errors="replace") as handle:
			hits = discards(handle.read(), status)
		if not hits:
			continue
		if "/test/" in source or source.startswith("tool/"):
			elsewhere += len(hits)
			continue
		for line, name, kind, text in hits:
			library.append((source, line, kind, text))

	for source, line, kind, text in library:
		print("status-gate: %s:%d discards %s -- %s" % (source, line, kind, text))

	if library:
		print("status-gate: a status that is handed back and dropped is a failure")
		print("status-gate: the caller reports as success. project.md sec 76.")
		return 1

	print("status-gate: %d status-returning functions, no library source discards "
	      "one (%d in tests and tools, not refused; control passed)"
	      % (len(status), elsewhere))
	return 0


if __name__ == "__main__":
	sys.exit(main())
