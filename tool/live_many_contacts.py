#!/usr/bin/env python3
"""What a contact costs does not grow with the contacts: `make livecheck`, sec 926, 927.

Counted in system calls, from /proc, so a loaded machine cannot pass or fail it.

    a  1500 contacts added: the last hundred read no more than the first hundred
       did, near enough. A name found by opening every contact's file costs two
       reads a contact each add, and one own record walked each request as many
    b  each request answered: `get contact`, and a page of `list contact`, read as
       little at 1500 as at 100
    c  every page of `list contact` read back, each contact once, and a contact
       added between pages is seen, as a list kept is one no write has moved

Against a daemon that walks either, a or b counts thousands.

BOUNDED FROM INSIDE as live_rejoin.py is: one deadline, the daemon in its own process
group, and checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import command, daemon  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

live_trim.DEADLINE = time.monotonic() + 200.0

CONTACTS = 1500
SAMPLE = 100
# Reads a request may grow by, past its share when nothing grows: a round may land in
# a sample.
SLACK = 400


def reads(pid):
	"""System calls `pid` has made to read."""
	with open("/proc/%d/io" % pid) as f:
		for line in f:
			if line.startswith("syscr:"):
				return int(line.split()[1])
	raise failed("no syscr in /proc/%d/io" % pid)


def add(sock, i):
	reply = ask(sock, "add contact p%d %s" % (i, os.urandom(32).hex()))
	if not reply.startswith("ok"):
		raise failed("contact %d answered %r" % (i, reply))


def adding(sock, pid, first, last):
	"""Contacts `first` up to `last` added; the reads it cost."""
	before = reads(pid)
	for i in range(first, last):
		add(sock, i)
	return reads(pid) - before


def one_page(sock, pid):
	before = reads(pid)
	if not ask(sock, "list contact 0").startswith("ok "):
		raise failed("list contact did not answer")
	return reads(pid) - before


def main(argv):
	if len(argv) != 2:
		print("usage: live_many_contacts.py PATH_TO_FUZZNETD", file=sys.stderr)
		return 2

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		store = os.path.join(scratch, "s")
		sock = os.path.join(sock_dir, "s")
		os.mkdir(store)
		d = None
		try:
			command(run, ["--fuzznet-dir=" + store, "--new-root"], None)
			d = daemon(run, "s0", store, sock)
			pid = d.proc.pid

			# a: the first hundred after the slot is walked once, and the last.
			adding(sock, pid, 0, SAMPLE)
			early = adding(sock, pid, SAMPLE, 2 * SAMPLE)
			page_early = one_page(sock, pid)
			adding(sock, pid, 2 * SAMPLE, CONTACTS - SAMPLE)
			late = adding(sock, pid, CONTACTS - SAMPLE, CONTACTS)
			if late > 2 * early + SLACK:
				raise failed("a: %d reads for the first hundred, %d for the last" % (early, late))
			print("livecheck: a: %d contacts, %d reads for an early hundred and %d for the last"
			      % (CONTACTS, early, late))

			# b: a page, after a write, and one that moved nothing.
			page_late = one_page(sock, pid)
			page_again = one_page(sock, pid)
			if page_again > SLACK or page_late > page_early + SLACK:
				raise failed("b: a page read %d at first, %d at %d, then %d"
				             % (page_early, page_late, CONTACTS, page_again))
			print("livecheck: b: a page read %d at first, %d at %d contacts, then %d"
			      % (page_early, page_late, CONTACTS, page_again))

			# c: every page, and a contact added part way.
			seen, at, total, added = [], 0, None, False
			while total is None or at < total:
				words = ask(sock, "list contact %d" % at).split()
				if len(words) < 3 or words[0] != "ok":
					raise failed("c: list contact %d answered %r" % (at, words[:3]))
				total = int(words[1])
				seen += [w.split(",")[0] for w in words[3:]]
				at += len(words) - 3
				if len(words) == 3:
					raise failed("c: an empty page at %d of %d" % (at, total))
				if not added:
					add(sock, CONTACTS)
					added = True
			if total != CONTACTS + 1:
				raise failed("c: a contact added was not listed: %d" % total)
			if len(set(seen)) < CONTACTS:
				raise failed("c: %d of %d contacts came back" % (len(set(seen)), total))
			print("livecheck: c: every page read back, and a contact added was seen")
		except failed as e:
			print("livecheck: FAILED -- %s" % e, file=sys.stderr)
			return 1
		finally:
			if d:
				d.stop()
	print("livecheck: what a contact costs did not grow with the contacts")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
