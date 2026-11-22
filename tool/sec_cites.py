#!/usr/bin/env python3
"""Every `sec N` this tree cites names a section that exists.

project.md is cited by section number from code, tests, tools and from
itself, thousands of times, and nothing held a citation to a heading. The
holder's rule of 2026-11-20 moves what was true once to doc/journal.md;
a section moved there keeps its number, so a citation resolves when a
heading of that number is in either file. This is the checker sec 0 asked
for before anything cited may move (project.md sec 1403).

Reads `git ls-files`, so only tracked text is held to it. A citation of
another project's section -- `situ's sec 7a`, `their sec 191`,
`fuzzypickles sec 196` -- names no heading here and is passed over: the
words just before `sec` say whose it is. Only the section's integer is
checked: `sec 4.4a` resolves where a heading 4 exists.

Exit 0 when every citation resolves; 1 with each one that does not, by
file and line; 2 when the headings could not be read at all, which is
never a pass.
"""

import os
import re
import subprocess
import sys

DOCS = ("project.md", "doc/journal.md")
HEADING = re.compile(r"^#{2,4} ([0-9]+)[0-9a-z.]*[. ]")
# `sec N`, `secs N, M and K`, `secs N to M`, `secs N-M`, `section N` -- a
# date after the comma (`sec 298, 2026-09-17`) not read as one.
CITE = re.compile(r"\bsec(?:s|tions?)?\.? ((?:[0-9]+[0-9a-z.]*(?:, (?:and )?| and | to | ?- ?|-)(?![0-9]{4}-[0-9]{2}))*[0-9]+)")
NUMBER = re.compile(r"[0-9]+")
# WHOSE SECTION: a project or another document named just before.
OTHERS = re.compile(r"(situ|netcfgd|fuzzypickles|raidcfgd|hembygd|beerssh|hydra|qtty|ossacli|hull|fmake|"
                    r"their|its own|the guidelines|guidelines'|decision|RFC|kernel|harmonization|"
                    r"working-practice|code-style|build-and-commit|running-code)[^.;\n]{0,24}$", re.I)
TEXT = (".c", ".h", ".cpp", ".py", ".md", ".situ", ".sh", ".mk", ".pro", ".pri", ".txt", ".vectors")


def headings(root):
	found = set()
	read = 0
	for doc in DOCS:
		path = os.path.join(root, doc)
		if not os.path.exists(path):
			continue
		with open(path, encoding="utf-8", errors="replace") as f:
			for line in f:
				m = HEADING.match(line)
				if m:
					found.add(int(m.group(1)))
		read += 1
	return found if read else None


def tracked(root):
	out = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True)
	names = [n for n in out.stdout.decode("utf-8", "replace").split("\0") if n]
	return [n for n in names if n.endswith(TEXT) or os.path.basename(n) == "Makefile"]


def dangling(root, known):
	bad = []
	for name in tracked(root):
		path = os.path.join(root, name)
		if not os.path.isfile(path) or name.startswith("wire/generated/"):
			continue
		with open(path, encoding="utf-8", errors="replace") as f:
			for number, line in enumerate(f, 1):
				for m in CITE.finditer(line):
					if OTHERS.search(line[:m.start()]):
						continue
					for n in NUMBER.findall(re.sub(r"[0-9]+[.][0-9]+", lambda x: x.group(0).split(".")[0],
					                               m.group(1))):
						if int(n) not in known:
							bad.append((name, number, int(n), line.strip()[:100]))
	return bad


def main():
	root = sys.argv[1] if len(sys.argv) > 1 else "."
	known = headings(root)
	if not known:
		print("sec_cites: no section headings read from %s" % ", ".join(DOCS))
		return 2
	bad = dangling(root, known)
	for name, number, n, text in bad:
		print("%s:%d: sec %d names no section: %s" % (name, number, n, text))
	print("sec_cites: %d citation(s) of %d sections' numbers name nothing" % (len(bad), len(known)))
	return 1 if bad else 0


if __name__ == "__main__":
	sys.exit(main())
