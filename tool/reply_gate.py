#!/usr/bin/env python3
"""Refuse a reply that opens with a word the reply vocabulary does not have.

WHY THIS EXISTS. A client reads the first word of a reply through
`fzn_reply_of` and its kin in `local/vocabulary.h`, and a word that table does
not list reads as FZN_REPLY_NONE -- a line no reader understands. fuzznetd
answered `absent` in three places (`get routing` with no manifest held, and
`grant request` and `remove request` for a root with no request), and
fuzzypickles' typed calls found it by refusing the line (project.md sec 646).
Nothing here had looked.

WHAT IT READS: the spellings from `local/vocabulary.c`'s REPLIES table, so a
word added there is a word allowed here; and every `snprintf` into a buffer
named `reply` in `node/*.c` whose format is a literal, by the format's first
word. Exit 1 naming each site whose word is not a reply word, and 1 too when
it finds no sites at all or no spellings: a gate over nothing is no gate.

WHAT IT CANNOT SEE: a reply built another way -- `say()`, `answer()` and
their kin take the token as an enum and cannot spell it wrong, which is why
they are not read -- a format held in a variable, or a word written by
`memcpy`. The peer replies of `node/shelf.c` and `node/files.c` ("absent",
by `memcpy`) answer a binary request, not the local socket, and are out of
this vocabulary's reach on purpose.
"""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPELLING = re.compile(r'\[FZN_REPLY_[A-Z]+\]\s*=\s*\{\s*"([a-z]+)"')
SITE = re.compile(r'snprintf\(\s*(?:\(char \*\))?reply(?:\s*\+\s*\w+)?\s*,[^;"]*?"([a-z]+)[ \\]',
                  re.S)


def main():
	with open(os.path.join(ROOT, "local", "vocabulary.c")) as f:
		words = set(SPELLING.findall(f.read()))
	if not words:
		print("reply-gate: no spellings read from local/vocabulary.c")
		return 1
	sites = 0
	bad = []
	for path in sorted(glob.glob(os.path.join(ROOT, "node", "*.c"))):
		with open(path) as f:
			text = f.read()
		for m in SITE.finditer(text):
			sites += 1
			if m.group(1) not in words:
				bad.append("%s:%d: a reply opening %r" % (os.path.relpath(path, ROOT),
				                                         text.count("\n", 0, m.start()) + 1,
				                                         m.group(1)))
	if not sites:
		print("reply-gate: no reply sites found in node/*.c")
		return 1
	for b in bad:
		print("reply-gate: %s, not one of %s" % (b, ", ".join(sorted(words))))
	if bad:
		return 1
	print("reply-gate: %d literal reply(ies) in node/*.c, each opening with one of %d words"
	      % (sites, len(words)))
	return 0


if __name__ == "__main__":
	sys.exit(main())
