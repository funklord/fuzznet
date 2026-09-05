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
	# BOTH SEAL ENTRIES CARRY CONTEXT, and the reason is a finding rather
	# than a style choice. This was one entry matching a bare
	# `memset(out, 0, sizeof(*out));`, which was unique in wire/seal.c until
	# 3131bc0 (2026-09-01) gave `fzn_seal_peek` the same clear. From then
	# until the 2026-09-03 sweep the entry reported PATTERN-MISS and tested
	# nothing, and nothing else would have said so -- see project.md sec 52.
	#
	# So a pattern here is spelled with enough of its neighbours to name ONE
	# call site, even where the bare line happens to be unique today. A
	# second caller of the same idiom is a normal thing for a module to
	# grow, and it must not silently retire an entry.
	(
		"seal-open-clears-out",
		"wire/seal.c",
		"\tmemset(out, 0, sizeof(*out));\n"
		"\n"
		"\tif (!views(frame, frame_len, &msg, &fv, &hv))\n",
		"\t/* sabotage */\n"
		"\n"
		"\tif (!views(frame, frame_len, &msg, &fv, &hv))\n",
		"fzn_seal_open clears the caller's output before any refusal below it",
	),
	(
		"seal-peek-clears-out",
		"wire/seal.c",
		"\tif (!frame || !out)\n"
		"\t\treturn FZN_SEAL_ERR_MALFORMED;\n"
		"\tmemset(out, 0, sizeof(*out));\n",
		"\tif (!frame || !out)\n"
		"\t\treturn FZN_SEAL_ERR_MALFORMED;\n"
		"\t/* sabotage */\n",
		"fzn_seal_peek promises the same clear in seal.h and was never swept",
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
		"persist-version-is-protocol",
		"persist/persist.h",
		"#define FZN_PERSIST_VERSION 1u",
		"#define FZN_PERSIST_VERSION 2u",
		"the on-disk version byte is pinned against silent change",
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
	# BATCH FOUR: GUARDS A LATER CHECK IN THE SAME FUNCTION MAY BE HIDING.
	#
	# `fzn_manifest_issue`, `fzn_revocation_issue` and `hop_sign` all open
	# their own output before signing it, which is a deliberate and good
	# thing -- it is where an encoder and its accessors would be caught
	# disagreeing. It also means every guard ABOVE that re-open is judged a
	# second time by a parser that refuses more than the guard did, so
	# deleting one can leave the return code unchanged and the sweep with
	# nothing to see.
	#
	# The three below are `issue`'s bounds on the ISSUER'S OWN STORE, as
	# distinct from the bounds `fzn_manifest_open` keeps on what a peer
	# sent. They were added the day their suite was written, because the
	# first version of that suite passed with the ceiling cut out: at an
	# `out_cap` larger than FZN_MANIFEST_MAX_LEN the re-open refuses the
	# oversized count and the guard is invisible. It is the buffer size
	# that makes the difference observable, so an entry here is only worth
	# as much as the case that feeds it -- which is the argument for
	# listing them rather than trusting the case to stay pointed.
	#
	# Checked at the other two re-open sites when this batch was written:
	# `fzn_revocation_issue` has no guard above its re-open beyond the
	# argument check its encoder repeats, and `hop_sign`'s expiry guard is
	# caught by chain_test. So this shape is one module's, not a pattern.
	(
		"manifest-issue-ceiling",
		"chain/manifest.c",
		"\t\tif (count >= FZN_MANIFEST_MAX_PAIRS)\n"
		"\t\t\treturn FZN_MANIFEST_ERR_SHAPE;\n",
		"\t\t/* sabotage */\n",
		"the ceiling on how large a manifest an issuer's own store may make",
	),
	(
		"manifest-issue-out-cap",
		"chain/manifest.c",
		"\t\tif (out_cap < FZN_MANIFEST_LEN(count + 1u))\n"
		"\t\t\treturn FZN_MANIFEST_ERR_MALFORMED;\n",
		"\t\t/* sabotage */\n",
		"the per-pair bound that stops the insertion sort leaving the buffer",
	),
	(
		"manifest-issue-dedup-skip",
		"chain/manifest.c",
		"\t\tif (duplicate)\n\t\t\tcontinue;\n",
		"\t\t/* sabotage */\n",
		"the duplicate skip, which the store's own dedup should make unreachable",
	),
	# BATCH FIVE, 2026-09-03: THE FIFTEEN SOURCES THIS TABLE HAD NEVER
	# TOUCHED.
	#
	# Batches one to four grew by shape. This one grew by ABSENCE: nineteen
	# library sources had an entry and fifteen had none, which is a list a
	# reader can compute and nobody had. Seven guards in that set turned out
	# to be unheld, each confirmed with `--probe` before a line of test was
	# written -- and three of the seven were unheld behind a test that names
	# them, which is this tree's recurring shape rather than a coincidence:
	#
	#   revocation_test.c drove the hop ceiling against a store whose `used`
	#   was zero, so the loop the ceiling guards never ran;
	#   split_test.c's two disagreeing plans were both refused by an EARLIER
	#   guard, returning the same error either way;
	#   spool_test.c asked `has` for index 6 against a one-byte bitmap, so
	#   the out-of-range read landed in the same byte.
	#
	# Each now has a case that discriminates, and each case was checked by
	# deleting the guard and watching it fail. project.md sec 53.
	(
		"rev-covers-hop-ceiling",
		"chain/revocation.c",
		" || hop_count > (size_t)FZN_CHAIN_MAX_HOPS",
		"",
		"the only bound on a consumer walking a chain it parsed itself",
	),
	(
		"rev-first-break",
		"chain/revocation.c",
		"\t\t\t\tfirst = j;\n\t\t\t\tbreak;\n",
		"\t\t\t\tfirst = j;\n",
		"entitlement starts at a key's FIRST grant; the break is what makes it",
	),
	(
		"split-count-agreement",
		"chunk/split.c",
		"\tif ((size_t)plan->chunks != (plan->total - 1u) / plan->chunk_size + 1u)\n"
		"\t\treturn FZN_SPLIT_ERR_MALFORMED;\n",
		"\t/* sabotage */\n",
		"the one plan check the three around it do not imply",
	),
	(
		"spool-read-cap",
		"spool/spool.c",
		"\twant = cap < FZN_BLOB_SEALED_MAX ? cap : FZN_BLOB_SEALED_MAX;\n",
		"\twant = FZN_BLOB_SEALED_MAX;\n",
		"the caller's buffer size is what bounds the write into it",
	),
	(
		"spool-has-index",
		"spool/spool.c",
		"\tif (!spool || index >= spool->leaves)\n\t\treturn 0;\n",
		"\tif (!spool)\n\t\treturn 0;\n",
		"the bound keeping bit_get inside the bitmap the caller lent",
	),
	(
		"ct-null-operand",
		"constant_time/constant_time.c",
		"\tif (!pa || !pb)\n\t\treturn len == 0;\n",
		"\t/* sabotage */\n",
		"a missing operand answers not-equal rather than crashing (caught by the crash)",
	),
	(
		"tree-reachable-examined",
		"tree/tree.c",
		"\tif (mark_cap < count)\n\t\treturn FZN_TREE_ERR_CAPACITY;\n\n"
		"\twalk->emitted = 0u;\n\twalk->examined = 0u;\n",
		"\tif (mark_cap < count)\n\t\treturn FZN_TREE_ERR_CAPACITY;\n\n"
		"\twalk->emitted = 0u;\n",
		"a reused walk must not report the previous call's count added to its own",
	),
	# BATCH SIX, 2026-09-03: frame/ and wire/relay.c, the two sources batch
	# five left over. Same census, same method, and one of the three unheld
	# guards here is the amplification clamp's neighbour rather than the
	# clamp itself -- which is why the clamp is listed beside them as a
	# caught control rather than left out for being obviously covered.
	(
		"relay-len-truncation",
		"wire/relay.c",
		"\tif (!frame || frame_len > UINT32_MAX)\n\t\treturn 0;\n",
		"\tif (!frame)\n\t\treturn 0;\n",
		"a size_t length above UINT32_MAX must not be truncated into the message",
	),
	(
		"relay-budget-clamp",
		"wire/relay.c",
		"\t*out = claimed < allowed ? claimed : allowed;\n",
		"\t*out = claimed;\n",
		"the clamp on a stranger's hop count, which is the amplifier if believed",
	),
	(
		"relay-hop-header-min",
		"wire/relay.c",
		"\tif (frame_len < SITU_FZN_HOP_SIZE_MAX)\n\t\treturn 0;\n",
		"",
		"KNOWN SURVIVOR: situ's generated accessor bounds-checks first (expected)",
	),
	(
		"freshness-sweep-entries",
		"frame/freshness.c",
		"\tif (!window || !window->entries)\n\t\treturn 0;\n",
		"\tif (!window)\n\t\treturn 0;\n",
		"a window claiming entries behind a null pointer (caught by the crash)",
	),
	(
		"freshness-horizon-sat",
		"frame/freshness.c",
		"\treturn max_ahead > UINT64_MAX - now ? UINT64_MAX : now + max_ahead;\n",
		"\treturn now + max_ahead;\n",
		"the horizon saturates rather than wrapping, held by one assertion",
	),
	(
		"freshness-admit-corrupt",
		"frame/freshness.c",
		"\tif (window->used > window->capacity)\n\t\treturn FZN_FRESH_ERR_MALFORMED;\n",
		"",
		"a window whose fields disagree is refused rather than scanned and appended to",
	),
	# BATCH SEVEN, 2026-09-03: the trim, and the honest half of it. sec 55
	# fixed a truncated /proc read and shipped with no test, because the
	# path needs a status file past 8192 bytes and this process's own is
	# not. Extracting the logic made the LOGIC testable; the WIRING still
	# is not, and both entries below say which is which rather than one
	# entry implying the whole fix is held.
	(
		"peer-whole-lines",
		"local/peer.c",
		"\twhile (len > 0 && text[len - 1] != '\\n')\n\t\tlen--;\n",
		"",
		"the trim that makes peer.h's whole-lines precondition satisfiable",
	),
	(
		"peer-linux-trim-call",
		"local/peer_linux.c",
		"\telse if (got == sizeof(status))\n\t\tgot = fzn_peer_whole_lines(status, got);\n",
		"",
		"KNOWN SURVIVOR: no test can make this process's own /proc read fill 8192 bytes",
	),
	# BATCH EIGHT, 2026-09-03: the last sources with no entry, which closes
	# the census sec 53 opened. Four of the five were caught first time and
	# are here so the table's coverage is a fact rather than an impression.
	# The fifth was not, and it was the one whose header is written around
	# it -- see the note on authz-unspelled-denies.
	(
		"sched-usable-veto",
		"sched/sched.c",
		"\tif (!link->usable)\n\t\treturn 0;\n",
		"",
		"a link the host has marked down is not a candidate, whatever its metrics",
	),
	(
		"authz-unspelled-denies",
		"chain/authz.c",
		"\tif (!policy.spelled)\n\t\treturn FZN_AUTHZ_DENIED;\n",
		"",
		"an unspelled policy denies -- the line authz.h opens with, unheld until 2026-09-03",
	),
	(
		"authz-origin-gate",
		"chain/authz.c",
		"\tif (!fzn_authz_origin_permitted(policy, origin))\n\t\treturn FZN_AUTHZ_DENIED;\n",
		"",
		"which origins may reach a kind at all, before any question of capability",
	),
	(
		"vocab-exact-length",
		"local/vocabulary.c",
		"\t\tif (rules[i].verb_len != verb_len)\n\t\t\tcontinue;\n",
		"",
		"a rule matches a whole verb, not a prefix of one",
	),
	(
		"random-linux-null-out",
		"session/random_linux.c",
		"\tif (!out)\n\t\treturn 0;\n",
		"",
		"the system source refuses a null buffer (caught by the crash, inherently)",
	),
	(
		"random-failure-clears-nonce",
		"session/random.c",
		"\t\tmemset(out, 0, FZN_AEAD_NONCE_LEN);\n",
		"\t\t/* sabotage */\n",
		"a failed source leaves zeroes, not most of a nonce",
	),
	# THE CANONICAL TIMING MUTATION, and the only entry in this table that
	# no assertion catches. Replacing the accumulator with an early exit
	# preserves every RESULT and destroys the property the module exists
	# for, so `secret_flow_test` passes with 10 of 10 -- measured. What
	# fails is `codegencheck`, inside `make test`, on the object code.
	#
	# It is here to hold that gate to account rather than the function: a
	# SURVIVED on some future machine would mean codegen_gate.py had
	# skipped, which it does silently for a non-x86-64, sanitized or -O0
	# object.
	(
		"ct-memeq-accumulator",
		"constant_time/constant_time.c",
		"\tfor (size_t i = 0; i < len; i++)\n\t\tdiff |= (uint8_t)(pa[i] ^ pb[i]);\n",
		"\tfor (size_t i = 0; i < len; i++)\n\t\tif (pa[i] != pb[i])\n\t\t\treturn 0;\n",
		"result-preserving, timing-destroying; caught by codegencheck alone",
	),
	# BATCH NINE, 2026-09-03: the withdrawal path. Seven guards, and three
	# of them SURVIVED when first written -- the chain walk's action check,
	# the manifest's omission of a withdrawn pair, and the deficit's
	# replication predicate. Each had a test written for it afterwards.
	# Adding a mechanism and not holding it is the shape this table exists
	# for, and it arrived in the same day's work that spent itself finding
	# it elsewhere. project.md sec 56.
	(
		"rev-covers-reads-action",
		"chain/revocation.c",
		"\t\treturn at < store->used && !store->entries[at].withdrawn;\n",
		"\t\treturn at < store->used;\n",
		"presence is not the answer once a withdrawal can replace in place",
	),
	(
		"rev-walk-reads-action",
		"chain/revocation.c",
		"\t\tif (entry->withdrawn)\n\t\t\tcontinue;\n",
		"",
		"the chain walk is a second reader and must read the action too",
	),
	(
		"rev-stale-copy-ignored",
		"chain/revocation.c",
		"\t\t\tif (fzn_ct_memeq(id, entry->id, FZN_REVOCATION_ID_LEN)) {\n",
		"\t\t\tif (0) {\n",
		"a re-relayed copy of a withdrawn revocation must not re-revoke",
	),
	(
		"rev-reissue-must-chain",
		"chain/revocation.c",
		"\t\t\tif (!fzn_ct_memeq(fzn_revocation_supersedes(record), entry->id,\n"
		"\t\t\t                  FZN_REVOCATION_ID_LEN)) {\n",
		"\t\t\tif (0) {\n",
		"where the chaining rule is a mechanism rather than a sentence",
	),
	(
		"rev-withdrawal-names-what-we-hold",
		"chain/revocation.c",
		"\t\tif (!fzn_ct_memeq(store->entries[at].id, fzn_revocation_supersedes(record),\n"
		"\t\t                  FZN_REVOCATION_ID_LEN))\n"
		"\t\t\treturn FZN_CHAIN_ERR_UNKNOWN_TARGET;\n",
		"",
		"a withdrawal of an old revocation must not undo the one that superseded it",
	),
	# `manifest-omits-withdrawn` STOOD HERE AND THE GUARD IT NAMED IS GONE,
	# deliberately: sec 57 reversed it. While an entry carried no state,
	# publishing a withdrawn pair told every receiver to revoke a pair the
	# issuer had restored; now an entry SAYS which state it is in, and
	# omitting it is what leaves every other host revoked for ever. Three
	# entries take its place, over the three things that make the state
	# safe to carry.
	#
	# `--verify` is what caught the removal, in `make style`, within a
	# minute of the guard going. That is the read-only half of this file
	# earning its place: a stale entry cannot sit in the table pretending
	# to test something.
	(
		"manifest-entry-carries-state",
		"chain/manifest.c",
		"\t\tcandidate[FZN_MANIFEST_OFF_ENTRY_STATE] =\n"
		"\t\t        e->withdrawn ? (uint8_t)FZN_MANIFEST_WITHDRAWN\n"
		"\t\t                     : (uint8_t)FZN_MANIFEST_REVOKED;\n",
		"\t\tcandidate[FZN_MANIFEST_OFF_ENTRY_STATE] = (uint8_t)FZN_MANIFEST_REVOKED;\n",
		"a withdrawn pair published as revoked undoes the withdrawal everywhere",
	),
	(
		"manifest-state-byte-validated",
		"chain/manifest.c",
		"\t\tif (state != (uint8_t)FZN_MANIFEST_REVOKED &&\n"
		"\t\t    state != (uint8_t)FZN_MANIFEST_WITHDRAWN)\n"
		"\t\t\treturn FZN_MANIFEST_ERR_SHAPE;\n",
		"",
		"a third state value is refused, which is what the accessor's complement rests on",
	),
	(
		"manifest-orders-on-the-key",
		"chain/manifest.c",
		"\treturn memcmp(a, b, FZN_MANIFEST_KEY_LEN);\n",
		"\treturn memcmp(a, b, FZN_MANIFEST_PAIR_LEN);\n",
		"one issuer has one opinion per pair; comparing the entry admits two",
	),
	(
		"manifest-deficit-is-replication",
		"chain/manifest.c",
		"\t\t\telse\n"
		"\t\t\t\tahead = !(fzn_manifest_is_withdrawn(record, i) &&\n"
		"\t\t\t\t          !mine_withdrawn);\n",
		"\t\t\telse\n\t\t\t\tahead = 1;\n",
		"same record and they cleared means this host is behind, not agreed",
	),
	(
		"chain-stage-two-gate",
		"chain/chain.c",
		"\t\t\tif (fzn_manifest_pending(manifest, fzn_hop_grantor(hops[i])) > 0)\n"
		"\t\t\t\treturn FZN_CHAIN_ERR_INCOMPLETE;\n",
		"",
		"a host that knows it is behind must not answer as though it were current",
	),
	(
		"blob-tree-leaf-bound",
		"blob/blob.c",
		"\tif (tree->leaves >= FZN_BLOB_MAX_LEAVES)\n"
		"\t\treturn FZN_BLOB_ERR_FULL;\n",
		"",
		"the streaming tree refuses a leaf past its bound rather than counting on",
	),
	(
		"blob-tree-depth-bound",
		"blob/blob.c",
		"\tif (tree->depth >= FZN_BLOB_MAX_DEPTH)\n"
		"\t\treturn FZN_BLOB_ERR_FULL;\n",
		"",
		"a push onto a full stack would write past the end of the array",
	),
	# ---- the provisioning legs, sim/test/provision_test.c ----------------
	#
	# Every one of these was run by hand while the leg it belongs to was
	# written, and every one was caught. They are here because a mutation
	# run once and restored is not a guard anybody re-runs: project.md sec
	# 68 records that two of those legs existed only because an ad-hoc
	# sabotage found the first version green, which is precisely the
	# argument for keeping them.
	(
		"chain-root-is-the-pin",
		"chain/chain.c",
		"\tif (!fzn_ct_memeq(fzn_hop_grantor(hops[0]), root, FZN_PUBKEY_LEN))\n",
		"\tif (0)\n",
		"a grant minted under a root this host never scanned must be refused, or anybody with a printer can provision a device",
	),
	(
		"trust-zero-root-refused",
		"trust/trust.c",
		"\t\tif (any == 0)\n\t\t\treturn FZN_TRUST_ERR_MALFORMED;\n",
		"",
		"an all-zero root anchors permanently to a key nobody holds, which is what a truncated or half-parsed payload carries",
	),
	(
		"trust-pin-is-not-adopt",
		"trust/trust.c",
		"\ttrust->source = source;\n",
		"\ttrust->source = FZN_TRUST_ADOPTED;\n",
		"an anchor configured out of band must not report itself adopted, or the user is told it was authenticated by nothing",
	),
	(
		"ratchet-advance-in-place",
		"ratchet/ratchet.c",
		"\tif (to == from)\n\t\treturn FZN_RATCHET_ERR_IN_PLACE;\n",
		"",
		"the unsafe caller must have no spelling: committing before verifying lets one forged datagram end a sender's delivery for ever",
	),
	(
		"relay-budget-exhausted",
		"wire/relay.c",
		"\tif (budget == 0)\n\t\treturn FZN_RELAY_ERR_EXHAUSTED;\n",
		"",
		"a frame with no budget left must not be forwarded, or a loop does not die -- which is the one thing the byte is for",
	),
	(
		"seal-hops-within-bound",
		"wire/seal.c",
		"\tif (what->hops > FZN_RELAY_MAX_HOPS)\n\t\treturn FZN_SEAL_ERR_MALFORMED;\n",
		"",
		"the hop count must stay inside 0..8, which is half of fuzzypickles' frame-format discriminator at offset 1",
	),
	(
		"spool-place-verifies",
		"spool/spool.c",
		"\tif (fzn_blob_proof_verify(hash, leaf_hash, index, spool->leaves, proof, proof_len,\n\t                          spool->root) != FZN_BLOB_OK)\n\t\treturn FZN_SPOOL_ERR_UNVERIFIED;\n",
		"",
		"a store that writes whatever it is handed is a store an attacker fills",
	),
	(
		"persist-pinned-anchor-refused",
		"persist/persist.c",
		"\t\tif (fzn_trust_pin(out, bytes + OFF_BODY) != FZN_TRUST_OK)\n\t\t\treturn FZN_PERSIST_ERR_SHAPE;\n",
		"\t\t(void)fzn_trust_pin(out, bytes + OFF_BODY);\n",
		"a stored anchor whose root is unusable must not restore, or a host back from a tampered file is anchored to a key nobody holds",
	),
	(
		"sync-offer-unmentioned",
		"record/sync.c",
		"\t\t\tplan->unknown_issuers++;\n\t\t\tcontinue;\n\t\t}\n\n\t\tadd_range(journal->entries[i].issuer, journal->entries[i].stream, t->received,\n",
		"\t\t\tplan->unknown_issuers++;\n\t\t\tadd_range(journal->entries[i].issuer,\n\t\t\t          journal->entries[i].stream, 0u,\n\t\t\t          journal->entries[i].received, max_per_request, out,\n\t\t\t          out_cap, plan);\n\t\t\tcontinue;\n\t\t}\n\n\t\tadd_range(journal->entries[i].issuer, journal->entries[i].stream, t->received,\n",
		"a stream the peer did not mention must be counted and never offered: offering from zero makes the cheapest message the amplifier",
	),
	(
		"disclose-leaf-covers-the-salt",
		"disclose/disclose.c",
		"\tif (fzn_blob_leaf_hash(hash, committed, committed_len, out) != FZN_BLOB_OK)\n",
		"\tif (fzn_blob_leaf_hash(hash, committed + FZN_DISCLOSE_SALT_LEN,\n"
		"\t                       committed_len - FZN_DISCLOSE_SALT_LEN, out) != FZN_BLOB_OK)\n",
		"a leaf that hashes the field without its salt is searchable from the root, so the construction reveals exactly what it withholds and still verifies",
	),
	(
		"disclose-verify-before-handing-back",
		"disclose/disclose.c",
		"\tif (fzn_blob_proof_verify(hash, leaf, index, field_count, siblings, sibling_count,\n"
		"\t                          root) != FZN_BLOB_OK)\n"
		"\t\treturn FZN_DISCLOSE_ERR_PROOF;\n\n"
		"\treturn fzn_disclose_field(committed, committed_len, field_out, field_len_out);\n",
		"\t(void)fzn_disclose_field(committed, committed_len, field_out, field_len_out);\n"
		"\tif (fzn_blob_proof_verify(hash, leaf, index, field_count, siblings, sibling_count,\n"
		"\t                          root) != FZN_BLOB_OK)\n"
		"\t\treturn FZN_DISCLOSE_ERR_PROOF;\n\n"
		"\treturn FZN_DISCLOSE_OK;\n",
		"a caller that reads the field without reading the status must not be handed one the proof never covered",
	),
	(
		"seal-aead-refusal-read",
		"wire/seal.c",
		"\t\tif (!aead->seal(aead->ctx, key, situ_fzn_head_nonce_ptr(hv),\n"
		"\t\t                frame + covered_at, head_len,\n"
		"\t\t                frame + covered_at + head_len, covered_len - head_len,\n"
		"\t\t                tag))\n"
		"\t\t\treturn FZN_SEAL_ERR_AEAD;\n",
		"\t\t(void)aead->seal(aead->ctx, key, situ_fzn_head_nonce_ptr(hv),\n"
		"\t\t                 frame + covered_at, head_len,\n"
		"\t\t                 frame + covered_at + head_len, covered_len - head_len,\n"
		"\t\t                 tag);\n",
		"the seal is in place, so a backend that refuses and is not heard leaves the payload and the capability on the wire in the clear under a finalised tag",
	),
	(
		"blob-seal-refusal-wipes",
		"blob/blob.c",
		"\t\tfzn_wipe(out, plain_len + FZN_BLOB_LEAF_OVERHEAD);\n",
		"",
		"a refused leaf seal must not leave the plaintext in the caller's buffer, because a sealed leaf is what a seeder hands to strangers",
	),
	(
		"provision-envelope-verified",
		"provision/provision.c",
		"\tif (!verifier->verify(verifier->ctx, card.root, card.base, FZN_PROVISION_BODY_LEN,\n"
		"\t                      card.base + FZN_PROVISION_OFF_SIGNATURE))\n"
		"\t\treturn FZN_PROVISION_ERR_SIGNATURE;\n",
		"\t(void)verifier;\n",
		"the three objects in a card are each public, so without the envelope anybody assembles a genuine hop with their own prekey record and the device sessions with them",
	),
	(
		"provision-tag-is-not-a-hop",
		"provision/provision.c",
		"\tif (bytes[FZN_PROVISION_OFF_OBJECT] != (uint8_t)FZN_OBJECT_PROVISION)\n"
		"\t\treturn FZN_PROVISION_ERR_SHAPE;\n",
		"",
		"a card's body opens with a hop's leading fields, so without the tag one signature could be read as either object",
	),
	(
		"provision-text-is-canonical",
		"provision/provision.c",
		"\tif (bits > 0 && (acc & ((1u << bits) - 1u)) != 0u)\n\t\treturn FZN_PROVISION_ERR_SHAPE;\n",
		"\t(void)bits;\n",
		"677 characters carry one bit more than the card, so an unchecked padding bit gives two strings for one card and \"the code I scanned\" stops naming one thing",
	),
	(
		"tree-cmp-breaks-ties",
		"tree/tree.c",
		"\treturn memcmp(a->id, b->id, (size_t)FZN_TREE_ID_LEN);\n",
		"\treturn 0;\n",
		"two nodes at one order must sort the same way on every host, or a replicated outline has no order at all",
	),
	(
		"rev-drain-stale-copy",
		"chain/revocation.c",
		"\t\t\t\tfzn_manifest_satisfy(manifest,\n"
		"\t\t\t\t                     fzn_revocation_issuer(record),\n"
		"\t\t\t\t                     fzn_revocation_capability(record),\n"
		"\t\t\t\t                     fzn_revocation_grantee(record));\n"
		"\t\t\t\treturn FZN_CHAIN_OK;\n",
		"\t\t\t\treturn FZN_CHAIN_OK;\n",
		"a stale copy of a withdrawn revocation must settle the deficit that "
		"asked for it, or the fetch repeats for ever and the gate never opens",
	),
	(
		"rev-drain-unchained",
		"chain/revocation.c",
		"\t\t\t\tfzn_manifest_satisfy(manifest,\n"
		"\t\t\t\t                     fzn_revocation_issuer(record),\n"
		"\t\t\t\t                     fzn_revocation_capability(record),\n"
		"\t\t\t\t                     fzn_revocation_grantee(record));\n"
		"\t\t\t\treturn FZN_CHAIN_ERR_UNKNOWN_TARGET;\n",
		"\t\t\t\treturn FZN_CHAIN_ERR_UNKNOWN_TARGET;\n",
		"a record refused for not chaining to a held withdrawal is one this host "
		"is ahead of, so the deficit must drain even though nothing was stored",
	),
	(
		"rev-drain-chained-reissue",
		"chain/revocation.c",
		"\t\t\tmemcpy(entry->id, id, FZN_REVOCATION_ID_LEN);\n"
		"\t\t\tfzn_manifest_satisfy(manifest, fzn_revocation_issuer(record),\n"
		"\t\t\t                     fzn_revocation_capability(record),\n"
		"\t\t\t                     fzn_revocation_grantee(record));\n",
		"\t\t\tmemcpy(entry->id, id, FZN_REVOCATION_ID_LEN);\n",
		"a reissue that lifts a withdrawal stores what the deficit named, so the "
		"deficit must drain with it",
	),
	(
		"chain-gate-unscoped",
		"chain/chain.c",
		"\t\tfor (size_t i = 0; i < hop_count; i++) {\n"
		"\t\t\tif (fzn_manifest_pending(manifest, fzn_hop_grantor(hops[i])) > 0)\n"
		"\t\t\t\treturn FZN_CHAIN_ERR_INCOMPLETE;\n"
		"\t\t}\n",
		"\t\tfor (size_t i = 0; i < manifest->issuer_used; i++) {\n"
		"\t\t\tif (fzn_manifest_pending(manifest, manifest->issuers[i].issuer) > 0)\n"
		"\t\t\t\treturn FZN_CHAIN_ERR_INCOMPLETE;\n"
		"\t\t}\n",
		"the gate is scoped to this chain's grantors -- unscoped it is sec 13d's "
		"returning device that refuses everything, one line away",
	),
	(
		"authz-drops-manifest",
		"chain/authz.c",
		"\t                     manifest, &proven) != FZN_CHAIN_OK)\n",
		"\t                     NULL, &proven) != FZN_CHAIN_OK)\n",
		"the decision layer must hand the verifier what it was given, or the "
		"gate is absent from the call a consumer actually makes",
	),
	(
		"rev-reissue-advances-id",
		"chain/revocation.c",
		"\t\tif (!fzn_ct_memeq(id, entry->id, FZN_REVOCATION_ID_LEN) &&\n"
		"\t\t    fzn_ct_memeq(fzn_revocation_supersedes(record), entry->id,\n"
		"\t\t                 FZN_REVOCATION_ID_LEN))\n"
		"\t\t\tmemcpy(entry->id, id, FZN_REVOCATION_ID_LEN);\n",
		"",
		"a store that does not advance to the current revocation applies a "
		"withdrawal of the superseded one, which un-revokes a revoked pair",
	),
	(
		"rev-withdrawal-tombstone",
		"chain/revocation.c",
		"\t\t\tstore->entries[store->used].withdrawn = 1;\n\t\t\tstore->used++;\n"
		"\t\t\treturn FZN_CHAIN_OK;\n",
		"\t\t\treturn FZN_CHAIN_ERR_UNKNOWN_TARGET;\n",
		"a withdrawal that overtakes its revocation is kept, not dropped",
	),
	# BATCH ELEVEN, 2026-09-05: chain/chain_store.c, added with the module so
	# it is never a source with no entries. All three were run against the
	# suite before being written down -- the expiry and the replacement fail
	# two assertions each, and the verify-first one takes the binary down
	# with a SIGSEGV rather than a message, which still fails the run but is
	# a weaker catch than the others and is recorded as such.
	(
		"chain-store-expiry",
		"chain/chain_store.c",
		"\tif (e->chain.expires_at != FZN_NO_EXPIRY && e->chain.expires_at <= now)\n"
		"\t\treturn 0;\n",
		"\t(void)now;\n",
		"an expired chain must not be handed back, since a caller that forgot "
		"to check would authorise on a dead grant",
	),
	(
		"chain-store-verify-first",
		"chain/chain_store.c",
		"\terr = fzn_chain_verify(hops, hop_count, root, capability, now, sign, revocations,\n"
		"\t                       manifest, &verified);\n"
		"\tif (err != FZN_CHAIN_OK)\n"
		"\t\treturn err;\n",
		"\tmemset(&verified, 0, sizeof(verified));\n",
		"a chain is verified before it is stored, or the store is fillable with "
		"junk by anyone who can send bytes",
	),
	(
		"chain-store-offer-ceiling",
		"chain/chain_store.c",
		"\tplan->examined = want_count < holds_cap ? want_count : holds_cap;\n",
		"\tplan->examined = want_count;\n",
		"a peer picks want_count, so the answer is clipped to what fits rather "
		"than written past the caller's array",
	),
	(
		"chain-store-offer-truncated",
		"chain/chain_store.c",
		"\tplan->truncated = want_count > holds_cap;\n",
		"\tplan->truncated = 0;\n",
		"a clipped request must say so, or the unexamined tail reads as "
		"not-held and a peer acts on it",
	),
	(
		"chain-store-offer-zero-cap",
		"chain/chain_store.c",
		"\tif (!holds || holds_cap == 0u)\n",
		"\tif (!holds)\n",
		"a zero capacity is refused rather than read as unlimited, which is "
		"record/sync.h's rule inherited",
	),
	(
		"chain-store-offer-unsound",
		"chain/chain_store.c",
		"\tif (want_count > 0u && !wants)\n\t\treturn FZN_CHAIN_ERR_MALFORMED;\n"
		"\tif (!store || corrupt(store))\n",
		"\tif (want_count > 0u && !wants)\n\t\treturn FZN_CHAIN_ERR_MALFORMED;\n"
		"\tif (!store)\n",
		"a store that cannot be scanned must not promise to serve every triple "
		"a peer named",
	),
	(
		"chain-store-replaces",
		"chain/chain_store.c",
		"\tat = find_entry(store, verified.root, &verified.capability, verified.grantee);\n",
		"\tat = store->used;\n",
		"a second chain for one triple replaces the first, or lookup has to "
		"answer which one and no caller asked that",
	),
	# BATCH TEN, 2026-09-04: the guard-operand sweep's one source change.
	# `fzn_tree_order_between` carried `*out == lo && hi - lo <= 1u`, whose
	# second operand was dead -- `lo > hi` is refused above, so the midpoint
	# equals `lo` exactly when the gap is 0 or 1, and no input separates the
	# two. The operand is gone; this holds what is left to account, because
	# a guard that has just been simplified is exactly the one to prove is
	# still load-bearing.
	(
		"tree-order-exhaustion",
		"tree/tree.c",
		"\tif (*out == lo)\n\t\treturn FZN_TREE_ORDER_EXHAUSTED;\n",
		"\t/* sabotage */\n",
		"neighbours with no gap must report exhaustion rather than a midpoint "
		"that is one of them",
	),
]

# Entries known to survive for a reason rather than through a gap. Listed so
# that a clean run reads as clean: an expected survivor reported as a finding
# every time is how a report stops being read. Removing an id from here is
# how you ask the question again.
EXPECTED_SURVIVORS = {
	"manifest-sig-zero-sign",
	# `seal-refused-build-wipes-frame` WAS HERE AND IS NOT ANY MORE, removed
	# 2026-09-05 because the harness reported it CAUGHT. Kept as a comment
	# rather than deleted, because the exemption predicted its own end and
	# getting that right is worth more than the line it saved.
	#
	# It read: prospective by the code's own measurement, not for want of a
	# test -- every SHAPE refusal returns before the capability is copied
	# in, so the wipe's reproduction cases no longer reached it -- and it
	# was kept because "the hazard returns the moment any refusal surfaces
	# after the copy".
	#
	# That is exactly what happened. `f05d977` made the AEAD seam return a
	# value, and an AEAD refusal happens AFTER the copy, so the wipe went
	# live again in the same commit that gave it something to be live for.
	# The case that catches it is that commit's own refusing-aead test.
	#
	# The lesson is the exemption's shape rather than this instance: it
	# named the condition under which it would stop being true, so the day
	# it stopped, the harness said so and nobody had to remember.
	# REDUNDANT WITH ANOTHER PROJECT'S GENERATED CODE, which is why it is
	# kept rather than deleted. `situ_view_at` bounds-checks before any
	# accessor reads, so a frame too short for the hop header is refused
	# there and this returns the same 0 either way -- measured 2026-09-03.
	# Two redundant checks inside one file have been deleted here twice, on
	# the argument that a reader should not have to work out which is
	# load-bearing; this one guards against a change in a schema compiler
	# that lives in a different repository and is not covered by this
	# tree's gates, which is a different risk and not one to trade away
	# without the holder.
	"relay-hop-header-min",
	# THE WIRING OF A FIX WHOSE LOGIC IS HELD. `fzn_peer_whole_lines` is
	# caught by peer_test; the call to it is reached only when a
	# /proc/<pid>/status read fills 8192 bytes, which no test can arrange
	# -- this process's own status file is about a tenth of that and
	# nothing here can grow it. Listed rather than omitted so the gap is a
	# recorded one: sec 55's fix is verified in its logic and unverified in
	# its placement, and those should not look the same from the table.
	"peer-linux-trim-call",
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


# Library sources with nothing to sabotage, named with the reason. A source
# is either covered by an entry or listed here; one that is neither fails the
# gate, which is what stops the census from decaying the next time a module
# is added.
#
# The bar for this list is "no branch, no bound, no clear, no comparison" --
# not "well tested" and not "small". A module whose guards are all held
# elsewhere still gets an entry, because the table is where that fact is
# recorded.
NO_GUARDS = {
	"version/version.c": "three accessors returning macros; nothing to remove",
}


def source_list():
	"""The library's own source list, from `make manifest`.

	That target is pure `echo` with no prerequisites, so this builds
	nothing and cannot recurse. `make_env` strips the parent's MAKEFLAGS
	for the reason it always does.
	"""
	try:
		out = subprocess.run(["make", "-s", "manifest"], cwd=ROOT, env=make_env(),
		                     capture_output=True, text=True, check=False)
	except OSError:
		return None
	if out.returncode != 0:
		return None
	return [l.split(None, 1)[1] for l in out.stdout.splitlines()
	        if l.startswith("source ")]


# EVERY ENTRY STILL NAMES EXACTLY ONE SITE.
#
# An entry whose `old` text has stopped matching is not a milder version of a
# finding -- it is an entry that reports nothing while sitting in a table that
# reads as coverage. The sweep already says so when it runs, and the whole
# problem is that it runs rarely, because it rewrites tracked files and cannot
# be part of a routine gate.
#
# Nothing here opens a compiler or writes a byte, so it can be. The check that
# would have caught 3131bc0 the same afternoon is a substring count.
#
# IT ALSO CHECKS THE SURVIVOR LIST, for the same reason in the other
# direction. An id in EXPECTED_SURVIVORS that no longer names an entry is a
# silenced verdict with nothing behind it: rename an entry and its exemption
# stays, ready to suppress a real survivor that happens to reuse the name.
def verify():
	bad = 0
	files = {rel for _, rel, _, _, _ in SABOTAGES}
	for sid, rel, old, new, _ in SABOTAGES:
		path = os.path.join(ROOT, rel)
		if not os.path.exists(path):
			print("sabotage: %s names %s, which does not exist" % (sid, rel))
			bad += 1
			continue
		seen = io.open(path, encoding="utf-8").read().count(old)
		if seen == 0:
			print("sabotage: %s matches nothing in %s" % (sid, rel))
			bad += 1
		elif seen > 1:
			print("sabotage: %s matches %d sites in %s, wanted 1 -- spell it "
			      "with enough context to name one" % (sid, seen, rel))
			bad += 1
		if old == new:
			print("sabotage: %s replaces its text with itself" % sid)
			bad += 1
	ids = {sid for sid, _, _, _, _ in SABOTAGES}
	for sid in sorted(EXPECTED_SURVIVORS):
		if sid not in ids:
			print("sabotage: %s is exempted as an expected survivor and is "
			      "not in the table" % sid)
			bad += 1
	# AND EVERY LIBRARY SOURCE IS EITHER COVERED OR EXCLUDED ON PURPOSE.
	#
	# The table grew by shape for its first four batches and a census found
	# seven unheld guards in the fifteen sources it had never touched
	# (project.md sec 53). Nothing stopped that gap reopening: a module
	# added tomorrow joins the build, the suite and the style gate, and
	# this table would not notice. Now it does.
	#
	# A FAILURE TO READ THE SOURCE LIST IS A FAILURE, not a skip. A
	# coverage check that quietly checks nothing reports success exactly as
	# loudly as a real pass, which is the shape this tree keeps meeting.
	srcs = source_list()
	if srcs is None:
		print("sabotage: `make manifest` could not be read, so coverage was "
		      "NOT checked -- this is a failure rather than a skip, because a "
		      "coverage check over an empty list passes")
		bad += 1
	else:
		for src in srcs:
			if src not in files and src not in NO_GUARDS:
				print("sabotage: %s has no entry and is not listed as "
				      "guard-free" % src)
				bad += 1
		for src in sorted(NO_GUARDS):
			if src not in srcs:
				print("sabotage: %s is listed as guard-free and is not a "
				      "library source" % src)
				bad += 1

	if bad:
		print("sabotage: %d problem(s). A stale entry reports a guard as "
		      "defended without testing it; an uncovered source reports a "
		      "module as swept when nothing swept it." % bad)
		return 2
	print("sabotage: %d entries over %d of %d library sources, each naming "
	      "exactly one site (nothing was built or changed)"
	      % (len(SABOTAGES), len(srcs) - len(NO_GUARDS), len(srcs)))
	return 0


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
	# READ-ONLY, BUILDS NOTHING, AND THAT IS WHY `make style` CAN CALL IT.
	# The full sweep rewrites tracked files, so it is deliberately outside
	# `make check` and gets run when somebody remembers. That left a stale
	# pattern undetected for two days -- see project.md sec 52. Everything
	# needed to notice it was a substring count.
	ap.add_argument("--verify", action="store_true",
	                help="check every entry still names exactly one site, "
	                     "without mutating or building anything")
	# ONE-OFF MUTATIONS BELONG HERE TOO, and this argument exists because
	# they were repeatedly written by hand instead. Exploring "is this
	# constant pinned by anything?" is the same operation as an entry in
	# the table -- clean tree, mutation asserted to land, process group
	# killed on a timeout, restore verified, the verdict distinguishing a
	# failed build from a failed test -- and every one of those disciplines
	# was got wrong at least once in the hand-written version. Three probes
	# reported catches they had not earned. See project.md sec 45.
	ap.add_argument("--probe", nargs=3, metavar=("FILE", "OLD", "NEW"),
	                help="run ONE mutation not in the table and report it, "
	                     "then restore. For asking whether something is "
	                     "pinned before deciding to pin it")
	args = ap.parse_args(argv)

	if args.list:
		for sid, rel, _, _, why in SABOTAGES:
			mark = " (expected survivor)" if sid in EXPECTED_SURVIVORS else ""
			print("%-24s %-22s %s%s" % (sid, rel, why, mark))
		return 0

	if args.verify:
		return verify()

	chosen = SABOTAGES
	if args.probe:
		if args.only:
			refuse("--probe runs one mutation of its own; --only selects "
			       "from the table. Use one or the other.")
		rel, old_text, new_text = args.probe
		if old_text == new_text:
			refuse("--probe was given the same text twice, so the mutation "
			       "cannot land and the run would prove nothing.")
		# NO CONTROL IS AVAILABLE for a one-off, and that is a real
		# limitation rather than an oversight: the table's controls prove
		# the suite can fail at all, and a probe borrows no such proof. So
		# a SURVIVED here is weaker evidence than a SURVIVED below, and
		# saying so is cheaper than someone assuming otherwise.
		chosen = [("PROBE", rel, old_text, new_text, "one-off probe")]
	elif args.only:
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
			# WHICH KIND OF CAUGHT, because they are not the same
			# evidence and a non-zero exit does not distinguish them.
			#
			# A FAILED BUILD EXITS NON-ZERO EXACTLY AS A FAILING TEST
			# DOES. This cost a wrong result: `fzn_put_be64` was swapped
			# for `fzn_put_le64` to check that blob's index encoding was
			# pinned, the run came back non-zero, and it was recorded as
			# CAUGHT. `fzn_put_le64` does not exist in this library. The
			# mutation was a compile error and the probe had tested
			# nothing -- see project.md sec 45.
			#
			# A STATIC ASSERTION IS THE OPPOSITE CASE and also does not
			# build. Since the layout entries are held by
			# `_Static_assert`, refusing to compile IS the guard working,
			# and it is the loudest, cheapest form available. So the two
			# must be told apart rather than both called "did not build":
			# an assertion firing is a catch, any other compile error
			# means the entry stopped being evidence and needs fixing.
			out = run.stdout or ""
			asserts = [ln for ln in out.splitlines()
			           if "static assertion failed" in ln]
			errors = [ln for ln in out.splitlines()
			          if "error:" in ln and "static assertion" not in ln]
			named = [ln for ln in out.splitlines()
			         if "FAIL" in ln and "deliberate" not in ln]
			if run.returncode == 0:
				verdict, detail = "SURVIVED", ""
			elif asserts:
				verdict = "CAUGHT"
				detail = asserts[0].split("failed:", 1)[-1].strip()[:70]
			elif errors:
				verdict = "NOT-BUILT"
				detail = errors[0].strip()[-70:]
			else:
				verdict = "CAUGHT"
				detail = named[-1].strip()[:70] if named else ""
			results.append((sid, verdict, detail or why))
			print("%-24s %-9s %s" % (sid, verdict, detail), flush=True)
	finally:
		restore_all()
		for rel in touched:
			if digest_of(os.path.join(ROOT, rel)) != digests[rel]:
				sys.stderr.write("sabotage: %s NOT RESTORED\n" % rel)
				return 2

	if args.probe:
		verdict = results[0][1] if results else "PATTERN"
		print("\nsabotage: probe %s." % verdict)
		if verdict == "SURVIVED":
			print("sabotage: nothing in the suite noticed. NOTE that a probe")
			print("sabotage: runs no control, so this says the suite did not")
			print("sabotage: fail -- not that it could have.")
		return 0 if verdict in ("CAUGHT", "SURVIVED") else 2

	controls = [r for r in results if r[0].startswith("CONTROL")]
	if not controls or any(v != "CAUGHT" for _, v, _ in controls):
		refuse("a control was not caught, so nothing above means anything.",
		       "the suite or the build is not running what it appears to be.")

	missed = [r for r in results if r[1] == "PATTERN"]
	if missed:
		refuse("%d pattern(s) matched nothing, so the sweep is incomplete."
		       % len(missed),
		       "a stale pattern reports a guard as defended without testing it.")

	# A MUTATION THAT DID NOT COMPILE TESTED NOTHING, and it is the same
	# failure as a stale pattern one step later: the entry looks like a
	# result and is not one. Refused rather than reported, because a sweep
	# that prints CAUGHT beside an entry it never ran is worse than a sweep
	# that stops -- see `evidence.md` on a gate that inspected nothing.
	broken = [(sid, why) for sid, verdict, why in results
	          if verdict == "NOT-BUILT"]
	if broken:
		refuse("%d entr(y/ies) failed to COMPILE rather than to test:"
		       % len(broken),
		       *["  %s: %s" % (sid, why) for sid, why in broken],
		       "a build that fails exits non-zero exactly as a failing test",
		       "does, so this would otherwise have been reported as CAUGHT.",
		       "fix the mutation so it compiles, or the entry proves nothing.")

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
