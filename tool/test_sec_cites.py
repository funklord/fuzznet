#!/usr/bin/env python3
"""tool/sec_cites.py held to what it is for: a citation naming no section
fails, one naming a section in project.md or doc/journal.md passes, and
another project's section, a date after a comma, and an empty tree are
read as they should be. Each case is a git tree of its own in a temporary
directory, removed with it."""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FAILED = 0


def case(files, want, what):
	global FAILED
	with tempfile.TemporaryDirectory() as root:
		subprocess.run(["git", "init", "-q", root], check=True)
		for name, text in files.items():
			path = os.path.join(root, name)
			os.makedirs(os.path.dirname(path), exist_ok=True)
			with open(path, "w") as f:
				f.write(text)
		subprocess.run(["git", "-C", root, "add", "--"] + list(files), check=True)
		got = subprocess.run([sys.executable, os.path.join(HERE, "sec_cites.py"), root],
		                     capture_output=True).returncode
	if got != want:
		FAILED += 1
		print("FAIL %s: exit %d, wanted %d" % (what, got, want))


DOC = "## 1. One\n\ntext\n\n## 2. Two, 2026-11-22\n"
case({"project.md": DOC, "a.c": "/* sec 1, secs 1-2 */\n"}, 0, "citations of sections that exist")
case({"project.md": DOC, "a.c": "/* sec 7 */\n"}, 1, "a citation naming no section")
case({"project.md": DOC, "a.c": "/* secs 1, 2 and 9 */\n"}, 1, "the last of a list naming no section")
case({"project.md": DOC, "doc/journal.md": "## 7. Moved\n", "a.c": "/* sec 7 */\n"}, 0,
     "a section moved to the journal")
case({"project.md": DOC, "a.c": "/* situ's sec 77, fuzzypickles sec 196 */\n"}, 0, "another project's section")
case({"project.md": DOC, "a.c": "/* sec 2, 2026-11-22 */\n"}, 0, "a date after the comma")
case({"a.c": "/* sec 1 */\n"}, 2, "no headings read is never a pass")
print("test_sec_cites: %s" % ("FAILED %d" % FAILED if FAILED else "all passed"))
sys.exit(1 if FAILED else 0)
