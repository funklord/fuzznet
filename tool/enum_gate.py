#!/usr/bin/env python3
"""Refuse two enumerators that share a value.

WHY THIS EXISTS. Reported by fuzzypickles 2026-09-04: they gave a notes frame
`sub_type` a number an asset-key ack already had, in a set declared across two
hundred lines so that no two members are visible at once. Every ack routed
into the wrong handler and was refused, and the sharer's owed-key ledger would
have re-sent for ever. Their unit gates all passed, because A VALUE CLASH IS
NOT A TYPE ERROR, and one end-to-end scenario out of 74 caught it.

`wire/bytes.h` answers that for the object tags with a `_Static_assert` chain
and a compiler-computed marker -- see project.md sec 73. This answers it for
every OTHER enum in the tree, which is 37 more, and for the ones nobody has
written yet.

WHAT IT REFUSES, and the second is the point:

  1. two enumerators of one enum sharing a value, unless waived by name;
  2. an enum this tool could not evaluate.

The second is what keeps the first honest. A parser that skips what it cannot
read reports a clean tree in exactly the words a clean tree uses, and the
enums it cannot read are the interesting ones -- computed initialisers,
unusual spellings, whatever somebody adds next. Anything unevaluated is a
refusal with the reason printed, never a silent omission.

ITS CONTROL IS INSIDE IT AND RUNS FIRST. The tool parses two fixtures before
it touches the tree: one clean, one with a deliberate clash. If the clash is
not found, or the clean one is flagged, it exits non-zero saying so and
reports nothing about the tree -- because a probe whose failure mode is
silence has to demonstrate on every run that it can speak.
"""

import re
import sys
import glob

# The one place two enumerators legitimately share a value, pinned by every
# name involved so that it cannot quietly absorb a different clash. Two
# array-size constants in one test that happen to be the same size are not a
# tag space; if either name or the value changes, this stops matching and the
# gate fires, which is the property a bare file-level exclusion would lose.
WAIVED = {
    ("sim/test/provision_test.c", "<anonymous>", 4, ("POSITIONS", "REQUESTS")),
}

ENUM = re.compile(r"\benum\b\s*(\w+)?\s*\{(.*?)\}\s*(\w*)\s*;", re.S)
ENTRY = re.compile(r"(\w+)\s*(?:=\s*([^,}]+))?\s*(?:,|$)")
NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def strip_comments(text):
	text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
	return re.sub(r"//.*", "", text)


def enums_in(text):
	"""Yield (name, {value: [enumerator, ...]}, reason_unevaluated)."""
	for m in ENUM.finditer(strip_comments(text)):
		tag, body, alias = m.group(1) or "", m.group(2), m.group(3) or ""
		name = alias or tag or "<anonymous>"
		values = {}
		nxt = 0
		why = None

		for entry in ENTRY.finditer(body):
			ident, given = entry.group(1), entry.group(2)
			if not NAME.match(ident):
				continue
			if given:
				literal = given.strip().rstrip("uU")
				try:
					value = int(literal, 0)
				except ValueError:
					why = "non-literal initialiser: %s = %s" % (
					        ident, given.strip()[:40])
					break
				nxt = value + 1
			else:
				value = nxt
				nxt += 1
			values.setdefault(value, []).append(ident)

		if why is None and not values:
			why = "no enumerators matched"
		yield name, values, why


def clashes_in(text):
	"""(clashes, unevaluated) for one file's text."""
	found, blind = [], []
	for name, values, why in enums_in(text):
		if why:
			blind.append((name, why))
			continue
		for value, names in values.items():
			if len(names) > 1:
				found.append((name, value, tuple(names)))
	return found, blind


CONTROL_CLEAN = """
typedef enum fzn_control_err { FZN_A = 0, FZN_B = 1, FZN_C } fzn_control_err_t;
"""
CONTROL_CLASH = """
typedef enum fzn_control_err { FZN_A = 0, FZN_B = 1, FZN_C = 1 } fzn_control_err_t;
"""


def control():
	"""Prove the parser can speak, before it is believed about anything."""
	found, blind = clashes_in(CONTROL_CLEAN)
	if found or blind:
		return "the clean control was flagged: %r %r" % (found, blind)
	found, blind = clashes_in(CONTROL_CLASH)
	if blind:
		return "the clashing control could not be evaluated: %r" % (blind,)
	if len(found) != 1 or found[0][1] != 1:
		return "the clashing control was NOT found: %r" % (found,)
	return None


def sources():
	out = []
	for pattern in ("**/*.h", "**/*.c"):
		for path in glob.glob(pattern, recursive=True):
			if path.startswith("monocypher/") or "generated" in path:
				continue
			out.append(path)
	return sorted(set(out))


def main():
	failed = control()
	if failed:
		print("enum-gate: THE CONTROL FAILED -- %s" % failed)
		print("enum-gate: nothing below would have meant anything, so nothing ran.")
		return 1

	total = 0
	problems = []
	unevaluated = []

	for path in sources():
		with open(path, errors="replace") as handle:
			text = handle.read()
		found, blind = clashes_in(text)
		total += len(list(enums_in(text)))
		for name, value, names in found:
			if (path, name, value, names) in WAIVED:
				continue
			problems.append((path, name, value, names))
		for name, why in blind:
			unevaluated.append((path, name, why))

	for path, name, why in unevaluated:
		print("enum-gate: could not evaluate %s in %s -- %s" % (name, path, why))
	for path, name, value, names in problems:
		print("enum-gate: %s in %s: %s share the value %d"
		      % (name, path, " and ".join(names), value))

	if problems or unevaluated:
		print("enum-gate: a value clash is not a type error, so nothing else")
		print("enum-gate: in this tree would have caught it. project.md sec 74.")
		return 1

	print("enum-gate: %d enums, no two enumerators share a value "
	      "(%d waived, control passed)" % (total, len(WAIVED)))
	return 0


if __name__ == "__main__":
	sys.exit(main())
