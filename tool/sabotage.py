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
# Roughly ten times a healthy `make test` on this tree. The old 1800 was
# headroom nothing needed, and it bought a single hang half an hour.
TIMEOUT = 600

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
	# BATCH TWO, aimed by where batch one landed. Both gaps it found were in
	# chain/manifest.c -- a module with no fuzz or guided harness of its own,
	# and 30 of the 39 library sources are in that set. So these are the same
	# two shapes, chosen from modules nothing sweeps: a clear on a refusal
	# path, and an init that zeroes a struct before filling part of it.
	(
		"trust-init-zero",
		"trust/trust.c",
		"\tmemset(trust, 0, sizeof(*trust));\n",
		"\t/* sabotage */\n",
		"fzn_trust_init's totality is what prekey_test's init case assumes",
	),
	(
		"ratchet-init-zero",
		"ratchet/ratchet.c",
		"\tmemset(chain, 0, sizeof(*chain));\n",
		"\t/* sabotage */\n",
		"the key is copied only if non-NULL, so this is the NULL path's zero",
	),
	(
		"seal-open-clears-out",
		"wire/seal.c",
		"\tmemset(out, 0, sizeof(*out));\n",
		"\t/* sabotage */\n",
		"clears the caller's output before any refusal below it",
	),
	# INVERTED, BECAUSE THE GUARD TURNED OUT TO BE THE FAULT. This entry
	# used to delete a `memset(out, 0, ...)` from fzn_persist_secret_open and
	# report SURVIVED. It was not an unheld guard: the clearing destroyed the
	# caller's secret before an install that promises not to, and it is gone.
	# So the sabotage is now to PUT IT BACK, and persist_test must notice.
	# See project.md sec 37.
	(
		"persist-open-must-not-clear",
		"persist/persist.c",
		"\tif (fzn_agree_secret_install(out, agree, bytes + OFF_BODY) != FZN_AGREE_OK)\n",
		"\tmemset(out, 0, sizeof(*out));\n"
		"\tif (fzn_agree_secret_install(out, agree, bytes + OFF_BODY) != FZN_AGREE_OK)\n",
		"a refused restore must leave the caller's secret in place",
	),
	(
		"sync-clear-plan",
		"record/sync.c",
		"\tmemset(plan, 0, sizeof(*plan));\n",
		"\t/* sabotage */\n",
		"clear_plan is the plan's only zeroing",
	),
	# BATCH THREE, from an audit rather than a shape. Of the 32 public
	# functions that can refuse and take an output, 13 write that output and
	# 3 can still refuse afterwards -- measured with comments and string
	# literals excluded, because the first pass matched the word `memset` in
	# a comment explaining a `memset` that had been removed. All three turn
	# out to be correct, so the tree's convention holds everywhere: a refused
	# call leaves no plausible bytes in the caller's output. These two ask
	# whether the correct ones are HELD.
	(
		"blob-leaf-auth-wipe",
		"blob/blob.c",
		"\t\tfzn_wipe(out, plain_len);\n",
		"\t\t/* sabotage */\n",
		"a refused AEAD leaves ciphertext in the caller's plaintext buffer",
	),
	(
		"reasm-accept-clears-out",
		"chunk/reassembly.c",
		"\t*out = NULL;\n",
		"\t/* sabotage */\n",
		"*out points at a slot only on completion, and this is what makes that true",
	),
	# BATCH FOUR: the four table `_init`s, in modules the sweep had never
	# touched. Same shape as prekey and ratchet -- zero a caller-supplied
	# array, then set the fields that say how much of it is in use. Whether
	# the zeroing is load-bearing depends on whether anything scans capacity
	# rather than `used`, which is a question to answer by breaking it rather
	# than by reading four lookup loops.
	(
		"state-init-zeroes-entries",
		"state/state.c",
		"\tmemset(entries, 0, capacity * sizeof(*entries));\n",
		"\t/* sabotage */\n",
		"init sets used=0; whether the array zeroing is also load-bearing",
	),
	(
		"log-init-zeroes-entries",
		"log/log.c",
		"\tmemset(entries, 0, capacity * sizeof(*entries));\n",
		"\t/* sabotage */\n",
		"init sets used=0; whether the array zeroing is also load-bearing",
	),
	(
		"link-init-zeroes-entries",
		"link/link.c",
		"\tmemset(entries, 0, capacity * sizeof(*entries));\n",
		"\t/* sabotage */\n",
		"init sets used=0; whether the array zeroing is also load-bearing",
	),
	(
		"journal-init-zeroes-entries",
		"record/journal.c",
		"\tmemset(entries, 0, capacity * sizeof(*entries));\n",
		"\t/* sabotage */\n",
		"init sets used=0; whether the array zeroing is also load-bearing",
	),
	(
		"spool-want-ceiling",
		"spool/plan.c",
		"\tif (want_count > FZN_SPOOL_MAX_WANT)\n\t\twant_count = FZN_SPOOL_MAX_WANT;\n",
		"\t/* sabotage */\n",
		"the ceiling on how many wants a peer can make this walk",
	),
	# THE PROPERTY manifest_fuzz WAS BUILT FOR. Per-issuer state written to
	# the wrong issuer: manifest_test PASSES this and the harness catches it,
	# measured across four mutations of the same class. Kept so that the
	# harness's reason for existing is itself held -- if manifest_fuzz ever
	# stops modelling two followed issuers, this goes quiet and says so.
	(
		"manifest-overflow-wrong-issuer",
		"chain/manifest.c",
		"\t\t\tentry->overflowed = 1;\n",
		"\t\t\tstate->issuers[0].overflowed = 1;\n",
		"the overflow flag is per issuer, and only the fuzz harness says so",
	),
	# BATCH FIVE: "a rule that is per-something is only tested by a fixture
	# holding two of that something", which is what manifest_fuzz measured
	# (sec 41) and what revocation_fuzz recorded before it. Each of these
	# makes a table's KEY TERM always true, so the first entry answers for
	# every key. If nothing goes red, that term is decided by nothing.
	(
		"state-lookup-ignores-subject",
		"state/state.c",
		"\t\t    fzn_ct_memeq(state->entries[i].subject, subject, FZN_SUBJECT_LEN))\n",
		"\t\t    1)\n",
		"the subject term in the state lookup",
	),
	(
		"log-lookup-ignores-issuer",
		"log/log.c",
		"\t\t    fzn_ct_memeq(log->entries[i].issuer, issuer, FZN_PUBKEY_LEN))\n\t\t\thit = &log->entries[i];\n",
		"\t\t    1)\n\t\t\thit = &log->entries[i];\n",
		"the issuer term in the log lookup",
	),
	(
		"journal-lookup-ignores-issuer",
		"record/journal.c",
		"\t\t    fzn_ct_memeq(journal->entries[i].issuer, issuer, FZN_PUBKEY_LEN))\n",
		"\t\t    1)\n",
		"the issuer term in the journal lookup",
	),
	# RECORD KEY CONFUSION, which sec 14 recorded the integration harness as
	# unable to see. It can: fzn_record_verify is called from network_test
	# and the near-miss pair decides the key. Kept so it stays that way.
	(
		"record-verify-wrong-key",
		"record/record.c",
		"\tif (!sign->verify(sign->ctx, fzn_record_issuer(record), at, len,\n",
		"\tif (!sign->verify(sign->ctx, at, at, len,\n",
		"a record must verify under its own issuer and no other",
	),

	# THE LENGTH, not the term. Batch five asks whether a key comparison
	# happens at all; this asks whether it reads the whole key. They are
	# different questions and a fixture can answer one and not the other --
	# two identities differing at byte 0 decide the term and say nothing
	# about the length. project.md sec 14 recorded the integration harness
	# as unable to see this; `sim_near_identity` closed it and this entry is
	# what keeps it closed.
	(
		"reasm-sender-compare-length",
		"chunk/reassembly.c",
		"\t\t    memcmp(slot->sender, sender, FZN_SENDER_LEN) == 0)\n\t\t\treturn slot;\n",
		"\t\t    memcmp(slot->sender, sender, 1u) == 0)\n\t\t\treturn slot;\n",
		"the sender comparison must read the whole key, not its first byte",
	),
	(
		"reasm-lookup-ignores-sender",
		"chunk/reassembly.c",
		"\t\t    memcmp(slot->sender, sender, FZN_SENDER_LEN) == 0)\n\t\t\treturn slot;\n",
		"\t\t    1)\n\t\t\treturn slot;\n",
		"the sender term in the reassembly slot lookup",
	),
	(
		"link-lookup-ignores-id",
		"link/link.c",
		"\t\tif (table->entries[i].id == id)\n",
		"\t\tif (1)\n",
		"the id term in the link lookup",
	),
	# BATCH SIX: wipes that clear a CALLER-VISIBLE buffer on a refusal.
	#
	# Most of this library's 32 fzn_wipe calls scrub locals, and their
	# absence is unobservable through the API by construction -- agree.c says
	# so itself, recording its own as "unreachable-by-test today". Sweeping
	# those would produce survivors that mean nothing. These four are the
	# subset a caller CAN see, so a missing one is a real leak into somebody
	# else's buffer and a test can say so.
	(
		"session-hash-fail-wipes-out",
		"session/session.c",
		"\t\tfzn_wipe(out, FZN_CHAIN_KEY_LEN);\n\t\terr = FZN_SESSION_ERR_HASH;\n",
		"\t\terr = FZN_SESSION_ERR_HASH;\n",
		"a failed derivation must not leave a partial chain key with the caller",
	),
	(
		"session-half-pair-wipes-send",
		"session/session.c",
		"\t\tfzn_wipe(send_chain_out, FZN_CHAIN_KEY_LEN);\n\t\treturn err;\n",
		"\t\treturn err;\n",
		"one chain without the other is unusable and must not be handed back",
	),
	(
		"agree-degenerate-wipes-shared",
		"session/agree.c",
		"\t\tfzn_wipe(shared_out, FZN_AGREE_SHARED_LEN);\n\t\treturn FZN_AGREE_ERR_DEGENERATE;\n",
		"\t\treturn FZN_AGREE_ERR_DEGENERATE;\n",
		"a degenerate agreement must not leave a shared secret with the caller",
	),
	(
		"seal-refused-build-wipes-frame",
		"wire/seal.c",
		"\t\t\tfzn_wipe(frame, total);\n\t\t\treturn err;\n",
		"\t\t\treturn err;\n",
		"a refused build must not leave frame material with the caller",
	),
	(
		"prekey-peer-zero",
		"prekey/prekey.c",
		"\tmemset(peer, 0, sizeof(*peer));\n",
		"\t/* sabotage */\n",
		"peer init must not depend on what the memory held",
	),
	# THE TWO DOMAIN LABELS, WHICH ARE PROTOCOL RATHER THAN GUARDS -- the
	# only entries here that break no check and refuse nothing. They earn
	# their place because both SURVIVED before session_kat_test existed:
	# every session test derives both sides with the same code, so a label
	# change moved both halves together and 64 binaries stayed green.
	#
	# What they hold to account is the vector itself. Delete it, or let it
	# stop reaching these bytes, and the protocol is silently unpinned
	# again -- which is the state this library was in until 2026-09-01 and
	# could not see. See project.md sec 45.
	(
		"session-label-is-protocol",
		"session/session.c",
		'static const char FZN_SESSION_LABEL[16] = "fuzznet-sess-v1\\0";',
		'static const char FZN_SESSION_LABEL[16] = "fuzznet-sess-v2\\0";',
		"the session domain label is pinned against silent change",
	),
	(
		"hop-layout-is-protocol",
		"chain/chain.h",
		"#define FZN_HOP_OFF_GRANTOR 2u\n#define FZN_HOP_OFF_GRANTEE 34u",
		"#define FZN_HOP_OFF_GRANTOR 34u\n#define FZN_HOP_OFF_GRANTEE 2u",
		"the hop's field offsets are pinned against silent change",
	),
	(
		"ratchet-label-is-protocol",
		"ratchet/ratchet.c",
		'static const char FZN_RATCHET_LABEL[16] = "fuzznet-ratchet1";',
		'static const char FZN_RATCHET_LABEL[16] = "fuzznet-ratchet9";',
		"the ratchet label is pinned against silent change",
	),
	(
		"blob-key-label-is-protocol",
		"blob/blob.c",
		'static const char FZN_BLOB_KEY_LABEL[16] = "fuzznet-blob-v1\\0";',
		'static const char FZN_BLOB_KEY_LABEL[16] = "fuzznet-blob-v9\\0";',
		"the blob content-key label is pinned against silent change",
	),
	(
		"dir-label-is-protocol",
		"session/session.c",
		'static const char FZN_SESSION_DIR_LABEL[16] = "fuzznet-dir-v1\\0\\0";',
		'static const char FZN_SESSION_DIR_LABEL[16] = "fuzznet-dir-v9\\0\\0";',
		"the directed chain label is pinned against silent change",
	),
	(
		"transcript-v2-version-is-protocol",
		"session/session.h",
		"#define FZN_SESSION_TRANSCRIPT_V2 2u",
		"#define FZN_SESSION_TRANSCRIPT_V2 9u",
		"the v2 transcript version byte is pinned against silent change",
	),
	(
		"root-label-is-protocol",
		"session/commitment.c",
		'static const char FZN_ROOT_LABEL[16] = "fuzznet-kdf-v2\\0\\0";',
		'static const char FZN_ROOT_LABEL[16] = "fuzznet-kdf-v3\\0\\0";',
		"the root derivation label is pinned against silent change",
	),
]

# Entries known to survive for a reason rather than through a gap. Listed so
# that a clean run reads as clean: an expected survivor reported as a finding
# every time is how a report stops being read. Removing an id from here is
# how you ask the question again.
EXPECTED_SURVIVORS = {
	"manifest-sig-zero-sign",
	# PROSPECTIVE BY THE CODE'S OWN MEASUREMENT, not for want of a test.
	# wire/seal.c's comment re-measured this on 2026-08-28: every shape
	# refusal now returns BEFORE the capability is copied in, so the wipe's
	# own reproduction cases no longer reach it. It is kept because the
	# hazard returns the moment any refusal surfaces after the copy, and the
	# comment says so in order that "the next reader who mutates it and sees
	# nothing fail deletes it knowing what they are removing" -- which is
	# this entry's reader exactly.
	"seal-refused-build-wipes-frame",
}


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
			# A SABOTAGE THAT HANGS IS A THIRD ANSWER, not a crash. Removing
			# record/sync.c's clear_plan made `make test` run past half an
			# hour: the suite consumed a plan full of the caller's bytes and
			# looped on a count that was never zeroed. Letting TimeoutExpired
			# propagate lost every entry after it and printed a traceback
			# where a result belonged -- so it is caught, reported as HUNG,
			# and the sweep carries on.
			#
			# It is deliberately NOT folded into CAUGHT. A hang does stop a
			# green suite, but as a detection it is the worst kind: it names
			# nothing, it costs the whole timeout, and in CI it looks like
			# infrastructure rather than a fault. A guard whose absence hangs
			# the suite wants a test that fails fast, and calling that CAUGHT
			# would retire the question.
			#
			# AND THE TIMEOUT KILLS THE PROCESS GROUP, not the `make` it
			# started. subprocess's own timeout signals the direct child
			# only, so the recipe's `for t in ...; do $t; done` shell and
			# whichever test binary is looping are reparented to init and go
			# on running. Measured: one hang left a shell loop alive for 34
			# minutes, found by `ps --ppid 1` afterwards and not by anything
			# in the run. running-code.md is about exactly this -- a bound
			# that stops the supervisor while the work continues is worse
			# than no bound, because it converts a runaway into an invisible
			# one. start_new_session puts make in its own group; killpg takes
			# the whole tree.
			run = None
			proc = subprocess.Popen(["make", "test"], cwd=ROOT,
			                        env=make_env(), stdout=subprocess.PIPE,
			                        stderr=subprocess.STDOUT, text=True,
			                        start_new_session=True)
			try:
				out, _ = proc.communicate(timeout=args.timeout)
				run = subprocess.CompletedProcess(proc.args, proc.returncode,
			                                          out, "")
			except subprocess.TimeoutExpired:
				try:
					os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
				except (ProcessLookupError, PermissionError):
					proc.kill()
				proc.wait()
			io.open(path, "w", encoding="utf-8").write(text)
			if digest_of(path) != digests[rel]:
				refuse("%s: restore did not reproduce the original." % rel)
			if run is None:
				results.append((sid, "HUNG", why))
				print("%-24s %-9s make test did not finish in %ds"
				      % (sid, "HUNG", args.timeout), flush=True)
				continue
			verdict = "CAUGHT" if run.returncode != 0 else "SURVIVED"
			detail = ""
			if run.returncode != 0:
				named = [ln for ln in (run.stdout or "").splitlines()
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

	hung = [(sid, why) for sid, verdict, why in results if verdict == "HUNG"]
	for sid, why in hung:
		print("\nsabotage: %s HUNG the suite rather than failing it." % sid)
		print("sabotage: the guard is load-bearing and its absence is not")
		print("sabotage: diagnosable -- it wants a test that fails fast. %s" % why)
	surprises = [(sid, why) for sid, verdict, why in results
	             if verdict == "SURVIVED" and sid not in EXPECTED_SURVIVORS]
	unexpected_catch = [sid for sid, verdict, _ in results
	                    if verdict == "CAUGHT" and sid in EXPECTED_SURVIVORS]
	for sid in unexpected_catch:
		print("\nsabotage: %s is listed as an expected survivor and was "
		      "CAUGHT." % sid)
		print("sabotage: something now tests it -- take it off the list.")
	if not surprises and not hung:
		print("\nsabotage: every guard is held to account by something.")
		return 0
	if not surprises:
		return 1
	print("\nsabotage: %d guard(s) nothing noticed:" % len(surprises))
	for sid, why in surprises:
		print("   %s: %s" % (sid, why))
	return 1


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
