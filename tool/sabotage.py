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
		"facet-both-sides-refuses",
		"facet/facet.c",
		"\t\t\t\treturn FZN_FACET_ERR_BOTH_SIDES;\n",
		"\t\t\t\treturn FZN_FACET_OK;\n",
		"F27: a term in both P and N always denotes the empty set, so validate must refuse it; returning OK admits an expression a tri-state editor cannot produce. facet_test's both-sides check catches it.",
	),
	(
		"facet-alt-spans-dimensions",
		"facet/facet.c",
		"\t\t\treturn FZN_FACET_ERR_ALT_DIMENSION;\n",
		"\t\t\treturn FZN_FACET_OK;\n",
		"F8: an alternation whose members span dimensions is cross-facet union smuggled inside one term; accepting it reintroduces the commutativity failure the (P, N) form settles. facet_test's cross-dimension check catches it.",
	),
	(
		"facet-collation-pads-digit-runs",
		"facet/facet.c",
		"\t\t\tpad = (run < digit_width) ? (digit_width - run) : 0;\n",
		"\t\t\tpad = 0;\n",
		"F20: the collation key zero-pads each digit run so 9 sorts before 10 and 720p before 1080p; with no padding a range term silently drops values. facet_test's collation checks catch it.",
	),
	(
		"facet-eval-intersects-positives",
		"facet/facet.c",
		"\t\t\tif (entity_in(&out[j], scratch, sn))\n",
		"\t\t\tif (!entity_in(&out[j], scratch, sn))\n",
		"F11-F13: a positive term intersects -- an entity stays only if every P term's postings hold it. Inverting keeps the ones they do NOT, which is not the algebra. facet_test's house-and-y1994 case catches it.",
	),
	(
		"facet-eval-refuses-incomplete-negative",
		"facet/facet.c",
		"\t\t\treturn FZN_FACET_ERR_INCOMPLETE;\n",
		"\t\t\treturn FZN_FACET_OK;\n",
		"F24: a negative term incomplete on this host makes the subtraction over-include, which could drive a deletion, so evaluate refuses. Returning OK proceeds with a wrong set. facet_test's incomplete-N case catches it.",
	),
	(
		"catalogue-refuses-a-mixed-attribute-set",
		"catalog/catalog.c",
		"\t\t\treturn FZN_CATALOG_ERR_NOT_ONE_ATTRIBUTE;\n",
		"\t\t\treturn FZN_CATALOG_OK;\n",
		"C28: a resolution set must be one attribute; accepting a mixed set resolves values that were never about the same thing. catalog_test's differing name/merge/entity cases catch it.",
	),
	(
		"catalogue-refuses-an-unknown-enum",
		"catalog/catalog.c",
		"\t\t\treturn FZN_CATALOG_ERR_KIND;\n",
		"\t\t\treturn FZN_CATALOG_OK;\n",
		"C28/F26: an unknown class/scope/merge/capability is refused, never skipped. catalog_test's unknown-class case catches it.",
	),
	(
		"catalogue-marks-the-authority",
		"catalog/catalog.c",
		"\t\t\te = emit(out, &n, out_cap, &set[i], 1);\n",
		"\t\t\te = emit(out, &n, out_cap, &set[i], 0);\n",
		"C5b AUTHORITATIVE names whose value is the authority's; without the mark a view cannot tell a preference from a consensus. catalog_test's authoritative case catches it.",
	),
	(
		"catalogue-attribute-value-is-exactly-the-remaining-bytes",
		"catalog/catalog.c",
		"\tif (value_len != body_len - off)\n",
		"\tif (value_len > body_len - off)\n",
		"One canonical encoding (C8): the value must be EXACTLY the bytes left, so a trailing byte is refused rather than ignored. `>` admits a shorter value_len than the bytes present, a second spelling of one assertion the signature differs over. catalog_test's trailing-byte case catches it.",
	),
	(
		"catalogue-attribute-body-must-fit-a-record",
		"catalog/catalog.c",
		"\tif (total > cap || total > (size_t)FZN_RECORD_BODY_MAX)\n",
		"\tif (total > cap)\n",
		"A body no record can carry is not an encoding at all (catalog/'s FZN_CATALOG_INLINE_MAX): the value bound accounts for the head, not FZN_RECORD_BODY_MAX. Dropping the record-body check admits a body that fits the caller's buffer but no record. catalog_test's overflow case catches it.",
	),
	(
		"catalogue-attribute-decode-refuses-an-oversize-body",
		"catalog/catalog.c",
		"\tif (body_len > (size_t)FZN_RECORD_BODY_MAX)\n\t\treturn FZN_CATALOG_ERR_RANGE;\n",
		"\tif (body_len > (size_t)FZN_RECORD_BODY_MAX && 0)\n\t\treturn FZN_CATALOG_ERR_RANGE;\n",
		"Decode's body-size bound is symmetric with encode's, so a body that decodes always re-encodes. Without it an internally-consistent body larger than a record body decodes yet cannot re-encode, breaking the canonical invariant. catalog_test's oversize case and attribute_fuzz's canonical check catch it.",
	),
	(
		"catalogue-referenced-counts-only-live",
		"catalog/catalog.c",
		"if (set[i].live && set[i].capability != FZN_CATALOG_CAP_HOLDER",
		"if (1 && set[i].capability != FZN_CATALOG_CAP_HOLDER",
		"Reachability (sec 317) counts only LIVE assertions: a retracted link does not keep an entity referenced. Counting non-live assertions would keep a withdrawn entity alive, defeating any later GC. catalog_test's non-live case catches it.",
	),
	(
		"catalogue-sources-counts-a-dropped-issuer-once",
		"catalog/catalog.c",
		"\t\t\tint earlier = 0;\n\t\t\tfor (j = 0; j < i; j++)\n\t\t\t\tif (bytes_eq(set[j].issuer, set[j].issuer_len,\n\t\t\t\t             a->issuer, a->issuer_len)) {\n\t\t\t\t\tearlier = 1;\n\t\t\t\t\tbreak;\n\t\t\t\t}\n\t\t\tif (!earlier)\n\t\t\t\td++;\n",
		"\t\t\tint earlier = 0;\n\t\t\tfor (j = 0; j < i; j++)\n\t\t\t\tif (bytes_eq(set[j].issuer, set[j].issuer_len,\n\t\t\t\t             a->issuer, a->issuer_len)) {\n\t\t\t\t\tearlier = 1;\n\t\t\t\t\tbreak;\n\t\t\t\t}\n\t\t\tif (!earlier || 1)\n\t\t\t\td++;\n",
		"An overflowing issuer is dropped once, not per assertion (reach.c's rule), so `dropped` is a count of distinct issuers a reader must still account for. Counting per row inflates it and a caller sizing a catch-up buffer over-allocates. catalog_test's repeated-dropped-issuer case catches it.",
	),
	(
		"purge-agreement-must-come-from-a-pinned-host",
		"catalog/purge.c",
		"\t/* NOT IN THE PINNED SET. A host that began holding the entity after the\n\t * purge was queued is not part of the consensus, and counting it would\n\t * let the queue close while a PINNED host had still not answered. */\n\treturn FZN_CATALOG_ERR_ABSENT;",
		"\treturn FZN_CATALOG_OK;",
		"C19a pins the consensus set when the purge is queued. Accepting an "
		"agreement from a host outside it means a host that began holding the "
		"entity AFTER the queue can close it -- while a pinned host that still "
		"has the bytes has not answered, and will re-send them. purge_test has "
		"a third host start holding after the queue. sec 335",
	),
	(
		"purge-eliminates-no-earlier-than-consensus",
		"catalog/purge.c",
		"if (!fzn_catalog_purge_closed(purges, entity, entity_len))",
		"if (0)",
		"\"No earlier, because a host that has not yet agreed still holds a copy "
		"and will re-send it\" -- so eliminating an open entry does not lose "
		"bookkeeping, it UNDOES THE DELETION at that host's next sync. The "
		"queue entry is the thing being paid for and it goes when consensus "
		"closes, not before. purge_test eliminates at zero and at half "
		"agreement. sec 335",
	),
	(
		"purge-an-empty-set-is-not-consensus",
		"catalog/purge.c",
		"if (written == 0)",
		"if (0)",
		"a purge whose pinned set is empty closes instantly, so the bytes go "
		"while some host nobody asked still holds them. Nothing holding an "
		"entity here means there is no consensus to attain -- which is not the "
		"same as a purge already done. purge_test queues over a set that only "
		"CURATES the entity. sec 335",
	),
	(
		"purge-refuses-to-requeue-and-discard-agreement",
		"catalog/purge.c",
		"\tif (find(purges, entity))\n\t\treturn FZN_CATALOG_ERR_KIND;",
		"\tif (0)\n\t\treturn FZN_CATALOG_ERR_KIND;",
		"re-queueing re-pins against the set as it stands NOW and silently "
		"discards the agreement already collected, which is the recomputed-set "
		"failure arriving by another route: hosts that agreed are asked again "
		"and hosts that have since left are dropped. purge_test agrees once, "
		"re-queues, and requires the agreement to survive. sec 335",
	),
	(
		"filing-a-retracted-link-is-not-a-place",
		"catalog/filing.c",
		"\t\tif (!a->live)\n\t\t\tcontinue;\n",
		"\t\tif (0)\n\t\t\tcontinue;\n",
		"C5c: a link that has been retracted is not a place an entity "
		"belongs, so it cannot back a filing. Admitting one lets a host keep "
		"writing files to a path the records stopped asserting -- and since "
		"filed_under re-checks with this same function, a stale filing would "
		"go on answering for ever. filing_test files on a retracted link and "
		"drives the read-side re-check. sec 323",
	),
	(
		"filing-a-holder-assertion-is-not-a-link",
		"catalog/filing.c",
		"if (a->capability == FZN_CATALOG_CAP_HOLDER)",
		"if (0)",
		"C9 and sec 321 again, one layer up: a HOLDER assertion says where "
		"bytes ARE, not where they BELONG. Letting one back a filing means "
		"the fact that a host holds something decides where that host files "
		"it, which is the same fixpoint sec 321 found in reachability. "
		"filing_test offers a HOLDER assertion for the exact (entity, "
		"dimension, path) a curated control then accepts. sec 323",
	),
	(
		"filing-is-a-subset-of-the-records",
		"catalog/filing.c",
		"if (!link_asserted(set, count, entity, entity_len, name, name_len, path, path_len))",
		"if (0)",
		"the old module marked an EXISTING membership edge, so a filing the "
		"records did not assert was not expressible; here it is, and must be "
		"refused. Without this a host files entities at paths nothing curates "
		"and the filing and the records drift apart silently. filing_test "
		"drives an unasserted path, an unasserted dimension and another "
		"entity's link, each against a control. sec 323",
	),
	(
		"filing-is-rechecked-when-it-is-read",
		"catalog/filing.c",
		"if (!row_backed(row, set, count))",
		"if (0)",
		"the old module cleared a filing when its edge was unlinked, because "
		"it owned the edge table; this model owns no assertions, so there is "
		"no unlink to hook and the check moves to the read. Skipping it lets "
		"a host compute a path from a membership nobody asserts any more -- "
		"the exact failure the old clear-on-unlink rule existed to prevent. "
		"filing_test retracts a link with nothing calling in to say so. "
		"sec 323",
	),
	(
		"filing-replaces-rather-than-adds",
		"catalog/filing.c",
		"\trow = find(filings, entity);\n\tif (!row) {\n\t\tif (filings->used >= filings->capacity)",
		"\trow = NULL;\n\tif (!row) {\n\t\tif (filings->used >= filings->capacity)",
		"exactly-once per entity is STRUCTURAL: setting a filing overwrites "
		"whatever was there, so a second place is not expressible rather than "
		"being detected afterwards. Always adding a row files one entity in "
		"two places at once, and the path a consumer gets depends on which "
		"row it finds first. filing_test re-files an entity and requires the "
		"count to stay at one. sec 323",
	),
	(
		"filing-refile-sorts-so-a-restart-resumes",
		"catalog/filing.c",
		"while (at > 0 && memcmp(moves[at - 1].entity, move->entity,\n\t                        FZN_CATALOG_ENTITY_LEN) > 0) {",
		"while (at > 0 && memcmp(moves[at - 1].entity, move->entity,\n\t                        FZN_CATALOG_ENTITY_LEN) < 0) {",
		"the cursor is a count, and the old module leaned on a catalogue lock "
		"to make resuming from one sound. This model has no lock, so the sort "
		"is what is left: the table's order is whatever filing produced, and "
		"a restart that rebuilt it would resume at a different entity and "
		"move the wrong file. filing_test walks a captured job across a "
		"simulated restart. sec 323",
	),
	(
		"copy-want-needs-retention",
		"catalog/copy.c",
		"if (retained_only &&\n\t\t    !fzn_catalog_keeps(holds, a->entity, a->entity_len, now)) {",
		"if (0) {",
		"want is retained AND referenced AND not-held, and the retention term "
		"is load-bearing: without it a host fetches everything the ESTATE "
		"curates, filling its disk with bytes it had already decided not to "
		"keep. sec 317 records this as a correction to its own first cut. "
		"copy_plan_test drives the wide bit off and requires nothing wanted. "
		"sec 322",
	),
	(
		"copy-want-needs-something-curating-it",
		"catalog/copy.c",
		"if (retained_only &&\n\t\t    !fzn_catalog_referenced(set, count, a->entity, a->entity_len)) {",
		"if (0) {",
		"C9: a curated link is what says an entity is wanted; a holder "
		"assertion says only where it is. Without this a host fetches bytes "
		"nothing links to -- every entity any peer merely HOLDS becomes a "
		"fetch. copy_plan_test drives a retained, unheld, uncurated entity "
		"and requires not_referenced. sec 322",
	),
	(
		"copy-holdings-announces-a-fact-not-a-policy",
		"catalog/copy.c",
		"return walk(set, count, NULL, 0, self, self_len, 0, 0, out, out_cap, plan);",
		"return walk(set, count, NULL, 1, self, self_len, 0, 0, out, out_cap, plan);",
		"holdings announces what this host CAN SERVE; whether it means to go "
		"on keeping it is its own business and not a peer's to read. Turning "
		"the retention filter on under-announces what is servable AND leaks "
		"the policy -- and with a NULL holds table it announces nothing at "
		"all. The two walks share a walk, so this collapse is the cheapest "
		"defect here: copy_plan_test drops an entity and still requires it "
		"announced. sec 322",
	),
	(
		"copy-offer-checks-its-scope",
		"catalog/copy.c",
		"if (!known_here(set, count, wants[i].b, FZN_CATALOG_ENTITY_LEN)) {",
		"if (0) {",
		"without the scope check a want list is a request for any bytes whose "
		"hash a peer can name, so a peer that learns a hash from anywhere can "
		"pull those bytes out of a host that never agreed to serve them. "
		"copy_plan_test names an entity outside this host's view and requires "
		"`unknown`. sec 322",
	),
	(
		"sweep-retention-is-the-first-guard",
		"catalog/sweep.c",
		"if (fzn_catalog_keeps(holds, a->entity, a->entity_len, now)) {",
		"if (0) {",
		"an entity this host KEEPS is not a candidate at all, so retention "
		"opens the chain. Skipping it plans a removal for bytes the host "
		"said to keep -- the one outcome a planner must never reach -- and "
		"also mis-attributes the outcome, since a consumer reading last_copy "
		"goes looking for replicas of something it wanted kept. "
		"sweep_plan_test drives a KEEP row and a deadline. sec 321",
	),
	(
		"sweep-refuses-to-guess-a-missing-holder",
		"catalog/sweep.c",
		"if (!mine && dropped > 0)",
		"if (0)",
		"sec 316's asymmetry: on partial data, never delete. A holder list "
		"that did not fit hides whether THIS host is among them, and 'did "
		"not fit' is indistinguishable from 'is not a holder' -- opposite "
		"outcomes. Guessing reports absent for an entity this host may hold, "
		"so the sweep silently skips bytes it should have planned. "
		"sweep_plan_test puts self past the scratch, with self-first as the "
		"control. sec 321",
	),
	(
		"sweep-last-copy-counts-others-not-self",
		"catalog/sweep.c",
		"*others = written + dropped - (mine ? 1u : 0u);",
		"*others = written + dropped;",
		"the last-copy guard asks how many OTHER hosts hold the bytes, so "
		"this host's own holder assertion must come out of the count. "
		"Leaving it in makes a sole holder look like one other holder, and "
		"min_others of 1 then plans the removal of the only copy in "
		"existence. sweep_plan_test holds an entity here and nowhere else. "
		"sec 321",
	),
	(
		"sweep-sorts-so-the-cursor-resumes",
		"catalog/sweep.c",
		"while (at > 0 && memcmp(rows[at - 1].entity, row->entity,\n\t                        FZN_CATALOG_ENTITY_LEN) > 0) {",
		"while (at > 0 && memcmp(rows[at - 1].entity, row->entity,\n\t                        FZN_CATALOG_ENTITY_LEN) < 0) {",
		"the job's rows are sorted so `done` means the same thing on every "
		"machine: a count into an arrival-ordered list resumes at a "
		"different row once the set is rebuilt from a store that returns "
		"records in another order, so a consumer that crashed mid-sweep "
		"removes the wrong bytes on restart. Reversing the compare sorts "
		"descending; sweep_plan_test feeds three entities in descending "
		"order and requires ascending rows. sec 321",
	),
	(
		"catalogue-compares-the-whole-identifier",
		"catalog/catalog.c",
		"\treturn memcmp(a, b, a_len) == 0;",
		"\treturn a_len == 1u || memcmp(a, b, a_len - 1u) == 0;",
		"every entity and issuer comparison in this module runs through here, "
		"so a compare that stops short folds two identifiers into one on BOTH "
		"axes: an entity differing in its last byte reads as referenced by "
		"another entity's assertion, and two hosts differing in one byte "
		"count as one holder -- which makes a last copy look replicated and "
		"lets the sweep remove it. The old reach_test guarded this with "
		"reads_the_whole_id and reads_the_whole_issuer; catalog_test drives "
		"both with last-byte pairs. sec 324",
	),
	(
		"retention-finds-on-the-whole-entity",
		"catalog/retention.c",
		"if (memcmp(holds->rows[i].entity, entity, FZN_CATALOG_ENTITY_LEN) == 0)",
		"if (memcmp(holds->rows[i].entity, entity, FZN_CATALOG_ENTITY_LEN - 1u) == 0)",
		"a row is keyed on the whole subject; a short compare makes two "
		"entities sharing a prefix share a row, so a host keeps or drops a "
		"file because of a decision taken about a DIFFERENT file and nothing "
		"in the output says so. retention_test holds a last-byte pair with "
		"opposite verdicts. sec 324",
	),
	(
		"filing-finds-on-the-whole-entity",
		"catalog/filing.c",
		"if (memcmp(filings->rows[i].entity, entity, FZN_CATALOG_ENTITY_LEN) == 0)",
		"if (memcmp(filings->rows[i].entity, entity, FZN_CATALOG_ENTITY_LEN - 1u) == 0)",
		"same key, worse consequence: two entities sharing a filing row means "
		"filed_under answers for whichever it finds first, so a consumer "
		"writes one file over another. filing_test files a last-byte pair at "
		"two different paths. sec 324",
	),
	(
		"catalogue-a-holder-assertion-is-not-a-reference",
		"catalog/catalog.c",
		"if (set[i].live && set[i].capability != FZN_CATALOG_CAP_HOLDER",
		"if (set[i].live",
		"C9: a curated link is a reference, the host observation (C7/C8) is "
		"not. 'I hold these bytes' says where they are, not that anything "
		"wants them kept -- so counting it makes every entity a host holds "
		"referenced BY THE FACT OF HOLDING IT, a fixpoint sec 321's sweep "
		"planner can never escape: it would keep everything and plan nothing "
		"for ever. catalog_test asserts the same assertion is invisible to "
		"`referenced` and decisive for `holders`, with a curated control so "
		"the skip cannot widen. sec 321",
	),
	(
		"catalogue-holders-are-only-holder-capability-assertions",
		"catalog/catalog.c",
		"\t\tif (!a->live || a->capability != FZN_CATALOG_CAP_HOLDER\n",
		"\t\tif (!a->live || 0\n",
		"C8/C8a derive the holder set from the capability axis: only a HOLDER-capability assertion (C5e) proves the issuer holds the bytes. Counting NONE or GRANTED assertions as holdings invents holders a file does not have -- a last-copy guard would then delete the final real copy believing others held it. catalog_test's NONE-claim case catches it.",
	),
	(
		"retention-deadline-fires-at-the-deadline",
		"catalog/retention.c",
		"if (row->until != 0 && now >= row->until)",
		"if (row->until != 0 && now > row->until)",
		"a row says `mode` UNTIL `until` and `then` from `until` onwards, so "
		"the word changes AT T. `>` leaves it saying the old word for the one "
		"instant T, which is exactly the instant a consumer that drew a due "
		"list at T asks about -- `fzn_catalog_due` uses >= and the two would "
		"disagree on the rows it just listed. retention_test drives 99, 100 "
		"and 101 against a keep-until-100-then-drop row. sec 320",
	),
	(
		"retention-default-gives-the-row-back",
		"catalog/retention.c",
		"if (mode == FZN_CATALOG_RETAIN_DEFAULT) {",
		"if (0) {",
		"DEFAULT is the absence of a word, not a third opinion, so storing it "
		"fills a caller-owned table with entities that say 'whatever the "
		"catalogue says' and a consumer changing its mind can never get a slot "
		"back. keeps() reads the same either way, which is why the count is "
		"what asserts it: retention_test requires hold_count to fall. sec 320",
	),
	(
		"retention-keeps-nothing-until-told",
		"catalog/retention.c",
		"return holds && holds->keep_all;",
		"return holds != NULL;",
		"a table that has said nothing keeps NOTHING: defaulting to keep would "
		"make a host that adopted a stranger's catalogue start filling its "
		"disk, and a default nobody chose is the kind discovered when the disk "
		"is full. This returns keep for every entity with no row of its own, "
		"whatever the wide bit says. retention_test asserts both settings. "
		"sec 320",
	),
	(
		"retention-entity-is-a-whole-subject",
		"catalog/retention.c",
		"if (entity_len != FZN_CATALOG_ENTITY_LEN)",
		"if (entity_len > FZN_CATALOG_ENTITY_LEN)",
		"a row outlives the call that wrote it and carries the entity bytes, "
		"so the key is a full record subject (C1) rather than the borrowed "
		"view catalog.h's queries take. Admitting a short one keys the row "
		"on whatever follows it in the caller's memory and compares 32 bytes "
		"against a shorter buffer. retention_test passes LEN-1 and LEN+1 with "
		"a full-length control. sec 320",
	),
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
		"manifest-issue-reads-the-whole-issuer",
		"chain/manifest.c",
		"\t\tif (!fzn_ct_memeq(e->issuer, issuer, FZN_PUBKEY_LEN))\n\t\t\tcontinue;",
		"\t\tif (!fzn_ct_memeq(e->issuer, issuer, 1u))\n\t\t\tcontinue;",
		"issue builds a manifest by filtering the store to one issuer's revocations; a prefix compare includes an issuer one byte off, so a host advertises pairs another key signed as its own. The existing exclusion test uses an issuer that differs in the FIRST byte, which a truncated compare excludes anyway. sec 315",
	),
	(
		"manifest-pending-reads-the-whole-issuer",
		"chain/manifest.c",
		"\tfor (size_t i = 0; i < state->deficit_used; i++) {\n\t\tif (fzn_ct_memeq(state->deficit[i].issuer, issuer, FZN_PUBKEY_LEN))\n\t\t\tn++;",
		"\tfor (size_t i = 0; i < state->deficit_used; i++) {\n\t\tif (fzn_ct_memeq(state->deficit[i].issuer, issuer, 1u))\n\t\t\tn++;",
		"pending counts the deficits owed to one issuer; a prefix compare counts an issuer one byte off, attributing one key's missing pairs to another. The pair inside a deficit was near-miss-tested and the issuer keying it was not. sec 315",
	),
	(
		"manifest-satisfy-reads-the-whole-issuer",
		"chain/manifest.c",
		"\t\tif (fzn_ct_memeq(d->issuer, issuer, FZN_PUBKEY_LEN) &&\n\t\t    fzn_ct_memeq(d->capability.b, capability->b, FZN_CAP_ID_LEN) &&\n\t\t    fzn_ct_memeq(d->grantee, grantee, FZN_PUBKEY_LEN)) {",
		"\t\tif (fzn_ct_memeq(d->issuer, issuer, 1u) &&\n\t\t    fzn_ct_memeq(d->capability.b, capability->b, FZN_CAP_ID_LEN) &&\n\t\t    fzn_ct_memeq(d->grantee, grantee, FZN_PUBKEY_LEN)) {",
		"satisfy clears a deficit when a revocation is admitted; a prefix compare on the issuer lets a key one byte off clear a deficit that is not its, so a pair stays owed to nobody and is never fetched. sec 315",
	),
	(
		"manifest-deficit-report-reads-the-whole-issuer",
		"chain/manifest.c",
		"\tfor (size_t i = 0; i < state->deficit_used; i++)\n\t\tif (fzn_ct_memeq(state->deficit[i].issuer, issuer, FZN_PUBKEY_LEN))\n\t\t\ttotal++;",
		"\tfor (size_t i = 0; i < state->deficit_used; i++)\n\t\tif (fzn_ct_memeq(state->deficit[i].issuer, issuer, 1u))\n\t\t\ttotal++;",
		"the deficit report counts an issuer's owed pairs before walking them; a prefix compare in the count reports pairs dropped for want of room they did not need, since the walk that follows still filters on the whole key. The paired walk is masked by this count and takes no entry. sec 315",
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
		"log-position-usable-is-inclusive",
		"log/log.c",
		"\treturn journal && journal->entries && journal->used <= journal->capacity;",
		"\treturn journal && journal->entries && journal->used < journal->capacity;",
		"fzn_log_get judges GONE against ABSENT using the caller's journal, and position_usable refuses one whose used is PAST capacity. used == capacity is a busy host's ordinary state, not corruption, and must still be read; the corrupt case is tested but the endpoint was not, so <= could tighten to < and turn every query a full host makes into MALFORMED. sec 321",
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
		"reasm-plan-want-reads-the-whole-sender",
		"chunk/reassembly.c",
		"\t\t    && memcmp(candidate->sender, sender, FZN_SENDER_LEN) == 0) {",
		"\t\t    && memcmp(candidate->sender, sender, 1u) == 0) {",
		"fzn_reasm_plan_want repeats find's sender match with its own memcmp; a prefix read lets a sender one byte off the slot's owner be told which chunks it lacks, the leak the sender-in-the-match prevents. find and held_by are near-miss-tested and this third compare was not: the absent-message test uses alice and bob, who differ at byte 0. sec 316",
	),
	(
		"revocation-covers-a-full-chain",
		"chain/revocation.c",
		"\tif (hop_count == 0 || hop_count > (size_t)FZN_CHAIN_MAX_HOPS)\n\t\treturn;",
		"\tif (hop_count == 0 || hop_count >= (size_t)FZN_CHAIN_MAX_HOPS)\n\t\treturn;",
		"a chain of exactly FZN_CHAIN_MAX_HOPS is in bounds for the revoked[] array and must be covered; >= skips coverage for a full chain, so a revoked hop in it goes unmarked and chain_verify grants a revoked chain. Every other revocation test uses a shorter chain, where > and >= agree. sec 297",
	),
	(
		"qr-version-fit-is-inclusive",
		"qr/qr.c",
		"payload_bits(text_len, version, alnum) <=",
		"payload_bits(text_len, version, alnum) <",
		"a payload of exactly a version's capacity fits it; < bumps every exact fit to the next version, larger than needed and, at FZN_QR_VERSION_MAX, a refusal to encode a message that fits. 47 alphanumeric chars fill version 2 to the bit -- 13 (length, level) pairs reach the edge, and the round-trip check that would hold it needs quirc, absent here. sec 296",
	),
	(
		"vocabulary-verb-max-is-inclusive",
		"local/vocabulary.c",
		"\tif (!rule->verb || rule->verb_len == 0 || rule->verb_len > FZN_VERB_MAX)",
		"\tif (!rule->verb || rule->verb_len == 0 || rule->verb_len >= FZN_VERB_MAX)",
		"a verb of exactly FZN_VERB_MAX is the longest a rule and a query both accept, so it must match; >= rejects the endpoint. The suite paired a MAX verb with short rules (no match either way) and tested MAX+1 (refused either way) -- only a MAX verb meeting a MAX rule holds it. The query-side bounds in names and admit are the same edge, held by the same test. sec 295",
	),
	(
		"vocabulary-match-reads-the-whole-verb",
		"local/vocabulary.c",
		"\treturn fzn_ct_memeq(rule->verb, verb, verb_len) ? 1 : 0;",
		"\treturn fzn_ct_memeq(rule->verb, verb, verb_len - 1u) ? 1 : 0;",
		"the verb match must read the WHOLE verb, or a query one byte off a named verb matches its rule and a peer is granted a verb no rule names -- authorisation by near miss. rule_names is shared by admit and names, so one near-miss test pins both; every other verb differs from the rest in an earlier byte. sec 307",
	),
	(
		"store-file-read-fits-the-buffer",
		"record/store_file.c",
		"\tif (len > FZN_RECORD_MAX_LEN || len > cap)",
		"\tif (len > FZN_RECORD_MAX_LEN || (len > cap \x26\x26 0))",
		"the backend reads a length off the disk and preads that many bytes into the caller's buffer; without len > cap a record longer than the buffer is read into it -- an out-of-bounds write a corrupt store file controls. Every other read offers a full-size buffer, so only a deliberately small cap holds it. sec 293",
	),
	(
		"disclose-field-max-is-inclusive",
		"disclose/disclose.c",
		"\tif (field_len > FZN_DISCLOSE_MAX_FIELD)",
		"\tif (field_len >= FZN_DISCLOSE_MAX_FIELD)",
		"a field of exactly FZN_DISCLOSE_MAX_FIELD is legal and one more is not; >= refuses the maximum disclosure at commit. Every other case commits a short field, so only a maximum field holds the edge. sec 292",
	),
	(
		"disclose-committed-max-is-inclusive",
		"disclose/disclose.c",
		"\treturn committed_len <= FZN_DISCLOSE_MAX_LEN;",
		"\treturn committed_len < FZN_DISCLOSE_MAX_LEN;",
		"a committed blob of exactly FZN_DISCLOSE_MAX_LEN (salt plus the maximum field) is well-shaped; < rejects it as misshapen and refuses to hash a maximum disclosure's leaf. sec 292",
	),
	(
		"message-have-ceiling-is-inclusive",
		"spool/message.c",
		"\tif (range_count > FZN_MSG_MAX_RANGES)\n\t\treturn FZN_MSG_ERR_TOO_LARGE;\n\tif (len != FZN_MSG_HAVE_LEN(range_count))",
		"\tif (range_count >= FZN_MSG_MAX_RANGES)\n\t\treturn FZN_MSG_ERR_TOO_LARGE;\n\tif (len != FZN_MSG_HAVE_LEN(range_count))",
		"the HAVE decoder must accept exactly FZN_MSG_MAX_RANGES: the ceiling is > MAX, so a full have-set is legal and one more is not. Every other decode carries a handful of ranges, so > could tighten to >= and refuse a peer's full set unseen. sec 290",
	),
	(
		"message-have-leaf-count-is-inclusive",
		"spool/message.c",
		"\tleaf_count = fzn_get_be64(bytes + FZN_MSG_HAVE_OFF_LEAF_COUNT);\n\tif (leaf_count == 0u || leaf_count > FZN_SPOOL_MAX_LEAVES)",
		"\tleaf_count = fzn_get_be64(bytes + FZN_MSG_HAVE_OFF_LEAF_COUNT);\n\tif (leaf_count == 0u || leaf_count >= FZN_SPOOL_MAX_LEAVES)",
		"a HAVE for a blob of exactly FZN_SPOOL_MAX_LEAVES leaves is the largest one this host can hold and must parse. The null-argument test drove one past the ceiling; the endpoint was unbuilt, so > could tighten to >= and drop a peer's advertisement of the maximal blob unseen. sec 309",
	),
	(
		"message-data-span-end-is-inclusive",
		"spool/message.c",
		"\tfirst = fzn_get_be64(bytes + FZN_MSG_DATA_OFF_FIRST);\n\tif (first > FZN_SPOOL_MAX_LEAVES || count > FZN_SPOOL_MAX_LEAVES - first)",
		"\tfirst = fzn_get_be64(bytes + FZN_MSG_DATA_OFF_FIRST);\n\tif (first > FZN_SPOOL_MAX_LEAVES || count >= FZN_SPOOL_MAX_LEAVES - first)",
		"a DATA span ending exactly at FZN_SPOOL_MAX_LEAVES -- the tail of the largest legal blob -- is bounded by count > MAX - first, which admits first + count == MAX. Every DATA fixture sat near the bottom of the address space, so >= would refuse the ceiling span and drop those leaves. sec 309",
	),
	(
		"link-loss-permille-tops-at-1000",
		"link/link.c",
		"\tif (loss_permille > 1000u)",
		"\tif (loss_permille >= 1000u)",
		"1000 per-mille is 100% loss, a real measurement that must register; the bound refuses only values a per-mille cannot mean. link_test's other case uses 1001, which > and >= both refuse -- only a link at exactly 1000 holds this edge. sec 289",
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
	# Two from the session harness (sec 279). The first is held by the
	# harness alone: session_test sorts identities that differ in their
	# first byte, so a canonical order that reads a prefix and breaks the
	# tie by which side is asking never meets a tie there. The second was
	# held by nothing until the v2 KAT vector was re-aimed so that role
	# order and canonical order disagree.
	(
		"session-order-reads-the-whole-identity",
		"session/session.c",
		"\tif (order < 0) {\n",
		"\tif (memcmp(self_identity, peer_identity, 16u) <= 0) {\n",
		"a canonical order that reads only a prefix of the identity ties on identities agreeing that far and resolves the tie by which host is asking, so the two sides derive two roots for one pair and cannot talk; only the harness's shared-prefix identities reach the tie",
	),
	(
		"session-v2-is-role-ordered",
		"session/session.c",
		"\tmemcpy(out + at, initiator_id, FZN_SESSION_IDENTITY_LEN);\n\tat += FZN_SESSION_IDENTITY_LEN;\n\tmemcpy(out + at, initiator_prekey, FZN_AGREE_PUBLIC_LEN);\n\tat += FZN_AGREE_PUBLIC_LEN;\n\tmemcpy(out + at, responder_id, FZN_SESSION_IDENTITY_LEN);\n\tat += FZN_SESSION_IDENTITY_LEN;\n\tmemcpy(out + at, responder_prekey, FZN_AGREE_PUBLIC_LEN);\n\tat += FZN_AGREE_PUBLIC_LEN;\n",
		"\t{ int lt = memcmp(initiator_id, responder_id, FZN_SESSION_IDENTITY_LEN) < 0;\n\tmemcpy(out + at, lt ? initiator_id : responder_id, FZN_SESSION_IDENTITY_LEN);\n\tat += FZN_SESSION_IDENTITY_LEN;\n\tmemcpy(out + at, lt ? initiator_prekey : responder_prekey, FZN_AGREE_PUBLIC_LEN);\n\tat += FZN_AGREE_PUBLIC_LEN;\n\tmemcpy(out + at, lt ? responder_id : initiator_id, FZN_SESSION_IDENTITY_LEN);\n\tat += FZN_SESSION_IDENTITY_LEN;\n\tmemcpy(out + at, lt ? responder_prekey : initiator_prekey, FZN_AGREE_PUBLIC_LEN);\n\tat += FZN_AGREE_PUBLIC_LEN; }\n",
		"the v2 transcript is role-ordered on purpose, and a v2 that sorted instead agreed with the KAT for as long as the vector's initiator happened to sort first; the vector's roles are the other way round now, and only a layout check can see this at all",
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
		"spool-has-ceiling-is-exclusive",
		"spool/spool.c",
		"\tif (!spool || index >= spool->leaves)\n\t\treturn 0;\n",
		"\tif (!spool || index > spool->leaves)\n\t\treturn 0;\n",
		"leaf indices run 0..leaves-1, so has(index == leaves) must answer 0. spool-has-index catches deleting the bound via has(8), which > still refuses; only the endpoint index == leaves slips through >, and the has(TEST_LEAVES) check read a zero bit there until a bit past the leaves was set. sec 312",
	),
	(
		"spool-open-ceiling-is-inclusive",
		"spool/spool.c",
		"\tif (leaves > (uint64_t)FZN_SPOOL_MAX_LEAVES)",
		"\tif (leaves >= (uint64_t)FZN_SPOOL_MAX_LEAVES)",
		"a blob of exactly FZN_SPOOL_MAX_LEAVES is at the ceiling, not over it, and open admits it; >= refuses the largest blob this store will assemble. The test drives one past the ceiling, which > and >= reject alike, so only the ceiling itself holds this edge. sec 305",
	),
	(
		"spool-span-count-is-inclusive",
		"spool/spool.c",
		"\tif (count == 0u || count > SPAN_MAX_LEAVES)",
		"\tif (count == 0u || count >= SPAN_MAX_LEAVES)",
		"SPAN_MAX_LEAVES is 64, fuzzypickles' batch; a span of exactly that count is admitted and only more is refused, so >= would reject the full-size batch. Every other span placed carries four leaves, well short of the cap, so only a span of exactly SPAN_MAX_LEAVES holds this edge. sec 305",
	),
	(
		"spool-forget-reaches-the-end",
		"spool/spool.c",
		"\tif (first >= spool->leaves || count > spool->leaves - first)\n\t\treturn 0u;",
		"\tif (first >= spool->leaves || count >= spool->leaves - first)\n\t\treturn 0u;",
		"count == leaves - first is the largest valid range, forgetting to the last leaf; >= refuses it and drops nothing. place_span draws the identical bound and its end-reaching span is held, but forget's was not. sec 305",
	),
	(
		"ct-null-operand",
		"constant_time/constant_time.c",
		"\tif (!pa || !pb)\n\t\treturn len == 0;\n",
		"\t/* sabotage */\n",
		"a missing operand answers not-equal rather than crashing (caught by the crash)",
	),
	(
		"tree-cmp-reads-the-whole-id",
		"tree/tree.c",
		"\treturn memcmp(a->id, b->id, (size_t)FZN_TREE_ID_LEN);",
		"\treturn memcmp(a->id, b->id, 1u);",
		"fzn_tree_cmp orders siblings by id when their order ties; a prefix read calls two ids differing only in their last byte equal and leaves them in arrival order, so a tree renders its equal-order siblings in a machine-dependent order rather than a canonical one. The sibling-order test distinguishes ids by their first byte. sec 320",
	),
	(
		"tree-children-reads-the-whole-parent",
		"tree/tree.c",
		"\tif (memcmp(nodes[i].parent, parent,\n\t\t           (size_t)FZN_TREE_ID_LEN) != 0)",
		"\tif (memcmp(nodes[i].parent, parent, 1u) != 0)",
		"fzn_tree_children matches a node's parent against the queried one; a prefix read returns a node whose parent is one byte off the query as a child, so a node appears under a parent that did not claim it. sec 320",
	),
	(
		"tree-reachable-reads-the-whole-parent",
		"tree/tree.c",
		"\t\t\t\tif (memcmp(nodes[j].id, nodes[i].parent,\n\t\t\t\t           (size_t)FZN_TREE_ID_LEN) == 0) {",
		"\t\t\t\tif (memcmp(nodes[j].id, nodes[i].parent, 1u) == 0) {",
		"fzn_tree_reachable follows a node's parent to its id; a prefix read reaches a node whose parent is one byte off a real id, so an orphan is walked as though it were rooted. sec 320",
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
		"\tif (!window || !window->entries)\n\t\treturn 0;\n\n\t/* The worst of the three, because this loop WRITES",
		"\tif (!window)\n\t\treturn 0;\n\n\t/* The worst of the three, because this loop WRITES",
		"a window claiming entries behind a null pointer (caught by the crash). RE-POINTED sec 229: `fzn_replay_expirable` opens with the same two lines, so the anchor stopped naming one site without anybody touching this entry -- an anchor's uniqueness is a property of the file at the moment of the edit, not of the string",
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
		"peer-gid-max-is-inclusive",
		"local/peer.c",
		"\t\t\tif (value > 0xffffffffu)",
		"\t\t\tif (value >= 0xffffffffu)",
		"4294967295 is the largest gid a uint32 holds -- (gid_t)-1, a real value a process carries -- and the bound admits it, refusing only a run of digits too long to be a 32-bit gid. The test refuses one past it, which > and >= reject alike; only a gid of exactly the maximum holds this edge, and >= refuses it as an overflow. sec 303",
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
		"\tif (!link->usable)\n\t\treturn FZN_SCHED_EXCLUDED_UNUSABLE;\n",
		"",
		"a link the host has marked down is not a candidate, whatever its metrics -- the site moved into fzn_sched_excluded_by when that accessor took over the one definition of a hard constraint, and this entry stopped matching, which the verify gate said before any of it was committed -- sec 247",
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
		"\tif (rule->verb_len != verb_len)\n\t\treturn 0;\n",
		"",
		"a rule matches a whole verb, not a prefix of one -- and the check moved into `rule_names` when sec 204 gave `fzn_vocabulary_names` the same question to ask, so ONE deletion now breaks both functions, which is the point of their sharing it",
	),
	(
		"vocab-names-honours-the-same-rules",
		"local/vocabulary.c",
		"\t\tif (rule_names(&rules[i], verb, verb_len))\n\t\t\treturn 1;\n",
		"\t\tif (rules[i].verb_len == verb_len)\n\t\t\treturn 1;\n",
		"`fzn_vocabulary_names` must count exactly the rules `fzn_vocabulary_admit` obeys, or the pair contradict each other: a table of rules the module ignores would report that the policy covers a verb and is denying you -- sec 204",
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
		"manifest-version-compare-reads-the-whole-id",
		"chain/manifest.c",
		"\t\t\telse if (memcmp(mine, fzn_manifest_id(record, i),\n\t\t\t                FZN_REVOCATION_ID_LEN) != 0)",
		"\t\t\telse if (memcmp(mine, fzn_manifest_id(record, i),\n\t\t\t                1u) != 0)",
		"for a pair this host already holds a revocation for, this decides whether the manifest names the same revocation or a different one; a prefix read takes a different id for the held one, reports admit's ask row as agreed, and drops a genuine gap. manifest-orders-on-the-key pins the pair key one field over; this pins the version compare beside it. sec 301",
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
		"\t\tif (any == 0) {\n",
		"\t\tif (0) {\n",
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
		"sync-digest-capacity-is-inclusive",
		"record/sync.c",
		"!out || journal->used > journal->capacity)",
		"!out || journal->used >= journal->capacity)",
		"a journal filled to exactly capacity is the ordinary state of a busy host and must still digest every position it holds. used == capacity is the endpoint the digest tests never reached (they follow two issuers into a four-entry journal), so > could tighten to >= and leave a full host silent -- never advertising a position, so never learning it is behind and never syncing. sec 313",
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
		"service-namespace-mandatory",
		"chain/service.c",
		"\tfzn_put_be32(input + at, service);\n",
		"\tfzn_put_be32(input + at, 0u);\n",
		"the service must be inside the derivation or a capability minted for one subsystem authorises every other, which is the whole of what sec 129 made mandatory",
	),
	(
		"service-product-filters",
		"chain/service.c",
		"\tfzn_put_be32(input + at, product);\n",
		"\tfzn_put_be32(input + at, 0u);\n",
		"drop the product and every product-scoped capability equals the see-everything one, so the optional filter silently admits every project's records",
	),
	(
		"service-name-separates",
		"chain/service.c",
		"\tat += name_len;\n",
		"\tat += 0u;\n",
		"the consumer's own name is where a verb lives, so dropping it collapses read and write into one capability",
	),
	(
		"service-wildcard-not-a-subject",
		"chain/service.c",
		"\tif (product == FZN_PRODUCT_ANY)\n\t\treturn FZN_CHAIN_ERR_MALFORMED;\n",
		"\tif (0)\n\t\treturn FZN_CHAIN_ERR_MALFORMED;\n",
		"a check whose subject is every-product asks whether a holder may see all of them, and answering it rather than refusing is how a scoped grant reads as a wildcard",
	),
	(
		"stream-carries-product",
		"chain/service.c",
		"\t*out = (product << FZN_STREAM_PRODUCT_SHIFT) | index;\n",
		"\t*out = index;\n",
		"a stream must carry its product or two products share one, which is authorised correctly and syncs into the permanent journal wedge sec 129 describes",
	),
	(
		"stream-product-recovered",
		"chain/service.c",
		"\treturn stream >> FZN_STREAM_PRODUCT_SHIFT;\n",
		"\treturn FZN_PRODUCT_NONE;\n",
		"recovering the product from the stream is what ties the capability check to a signed field, so a receiver that cannot read it back is trusting something a sender chose",
	),
	(
		"stream-refuses-none",
		"chain/service.c",
		"\tif (product == FZN_PRODUCT_NONE || product > FZN_PRODUCT_MAX)\n",
		"\tif (product > FZN_PRODUCT_MAX)\n",
		"nobody's records have no stream, and an unspelled product reaching the derivation would put them in fuzznet's own space",
	),
	(
		"stream-refuses-wildcard",
		"chain/service.c",
		"\tif (product == FZN_PRODUCT_NONE || product > FZN_PRODUCT_MAX)\n",
		"\tif (product == FZN_PRODUCT_NONE)\n",
		"everybody's records are not a place bytes go, so the wildcard must not derive a stream that a real product could later be assigned",
	),
	(
		"cap-product-bounded",
		"chain/service.c",
		"\tif (product > FZN_PRODUCT_MAX && product != FZN_PRODUCT_ANY)\n\t\treturn FZN_CHAIN_ERR_MALFORMED;\n",
		"\tif (0)\n\t\treturn FZN_CHAIN_ERR_MALFORMED;\n",
		"a capability for a product no stream can carry corresponds to no record anybody can send, which is a bug rather than a narrower grant",
	),
	# Two the fuzz harness earned (sec 278): `service_test` derives "read",
	# "write" and "" -- names that differ in their first byte -- so neither
	# a padded input nor a name hashed in part is visible to it.
	(
		"service-length-hashed",
		"chain/service.c",
		"\tif (!hash->hash(hash->ctx, derived, sizeof(derived), input, at))\n",
		"\tmemset(input + at, 0, sizeof(input) - at);\n\tif (!hash->hash(hash->ctx, derived, sizeof(derived), input, sizeof(input)))\n",
		"a derivation that pads its input and hashes the padding makes a name and the same name plus a zero byte one capability; only the fuzz harness's names carry zeros",
	),
	(
		"service-name-hashed-whole",
		"chain/service.c",
		"\t\tmemcpy(input + at, name, name_len);\n\tat += name_len;\n",
		"\t\tmemcpy(input + at, name, name_len > 4u ? 4u : name_len);\n\tat += name_len > 4u ? 4u : name_len;\n",
		"a name hashed in part makes every name sharing that prefix one capability; the fixed names in `service_test` differ before the cut",
	),
	(
		"claim-broken-backend-is-not-contention",
		"claim/claim.c",
		"\treturn held ? FZN_CLAIM_ERR_HELD : FZN_CLAIM_ERR_BACKEND;\n",
		"\treturn FZN_CLAIM_ERR_HELD;\n",
		"a store that cannot arbitrate ownership at all must not look like a busy one, or a caller waits for ever for an owner that does not exist",
	),
	(
		"claim-failed-release-gives-up",
		"claim/claim.c",
		"\tclaim->held = 0;\n\tif (!claim->ops->release(",
		"\tif (!claim->ops->release(",
		"a process that believes it still owns state the kernel may have handed on is the one way this design desynchronises a ratchet, so a failed release must still give up ownership",
	),
	(
		"claim-held-is-total",
		"claim/claim.c",
		"\tif (!claim || !claim->ops)\n\t\treturn 0;\n\treturn claim->held;\n",
		"\treturn claim->held;\n",
		"a process that does not know whether it is the owner is not the owner, and sec 132's self-submit deadlock is prevented by this answer being right",
	),
	(
		"store-placement-checked",
		"record/store.c",
		"\tif (memcmp(fzn_record_issuer(record), issuer, FZN_PUBKEY_LEN) != 0\n\t    || fzn_record_stream(record) != stream || fzn_record_seq(record) != seq) {\n",
		"\tif (0) {\n",
		"a store several processes share is safe only because a reader checks what it got, and a misplaced record may be perfectly well signed -- so no signature check further up would catch it",
	),
	(
		"store-placement-issuer-half",
		"record/store.c",
		"\tif (memcmp(fzn_record_issuer(record), issuer, FZN_PUBKEY_LEN) != 0\n\t    || fzn_record_stream(record) != stream || fzn_record_seq(record) != seq) {\n",
		"\tif (fzn_record_stream(record) != stream || fzn_record_seq(record) != seq) {\n",
		"the issuer is a third of the address, and dropping it hands one issuer's record back as another's at the same stream and sequence",
	),
	(
		"store-placement-reads-the-whole-issuer",
		"record/store.c",
		"\tif (memcmp(fzn_record_issuer(record), issuer, FZN_PUBKEY_LEN) != 0",
		"\tif (memcmp(fzn_record_issuer(record), issuer, 1u) != 0",
		"the placement check must read the WHOLE issuer, not a prefix: a record from an issuer agreeing on every byte but the last, at the right stream and sequence, is otherwise handed back as this issuer's. store-placement-issuer-half deletes the term and a first-byte-different issuer catches that; only a last-byte near miss holds the whole read. sec 302",
	),
	(
		"store-absent-is-not-backend",
		"record/store.c",
		"\t\treturn found ? FZN_RECORD_STORE_ERR_BACKEND : FZN_RECORD_STORE_ERR_ABSENT;\n",
		"\t\treturn FZN_RECORD_STORE_ERR_ABSENT;\n",
		"a broken store reported as an empty one makes a reader refetch the world rather than report that its store is unusable",
	),
	(
		"store-file-crash-order",
		"record/store_file.c",
		"\tif (pwrite(fd, bytes, len, at + 2) != (ssize_t)len)\n\t\treturn 0;\n\tfzn_put_be16(prefix, (uint16_t)len);\n\tif (pwrite(fd, prefix, sizeof(prefix), at) != (ssize_t)sizeof(prefix))\n\t\treturn 0;\n",
		"\tfzn_put_be16(prefix, (uint16_t)len);\n\tif (pwrite(fd, prefix, sizeof(prefix), at) != (ssize_t)sizeof(prefix))\n\t\treturn 0;\n\tif (pwrite(fd, bytes, len, at + 2) != (ssize_t)len)\n\t\treturn 0;\n",
		"the length is written after the record so a process that dies between them leaves the slot absent; the other order leaves a length promising bytes that were never stored",
	),
	(
		"store-file-seq-bound-get",
		"record/store_file.c",
		"\tif (seq == 0u || seq > MAX_SEQ)\n\t\treturn 0;\n\n\tfd = stream_fd(file, issuer, stream);\n\tif (fd < 0) {\n",
		"\tif (seq == 0u)\n\t\treturn 0;\n\n\tfd = stream_fd(file, issuer, stream);\n\tif (fd < 0) {\n",
		"a slot offset is (seq-1)*670 in unsigned arithmetic and 670 is even, so a sequence of 2^63+1 wraps to offset zero and would be answered from slot one",
	),
	(
		"store-file-seq-bound-put",
		"record/store_file.c",
		"\tif (seq == 0u || seq > MAX_SEQ)\n\t\treturn 0;\n\n\tfd = stream_fd(file, issuer, stream);\n\tif (fd < 0)\n\t\treturn 0;\n",
		"\tif (seq == 0u)\n\t\treturn 0;\n\n\tfd = stream_fd(file, issuer, stream);\n\tif (fd < 0)\n\t\treturn 0;\n",
		"the writing side of the same wrap is the worse half: a wrapping get reads the wrong record and a wrapping put destroys the right one",
	),
	(
		"store-file-cache-identity",
		"record/store_file.c",
		"\tif (file->cached && file->stream == stream\n\t    && memcmp(file->issuer, issuer, FZN_PUBKEY_LEN) == 0)\n\t\treturn file->fd;\n",
		"\tif (file->cached)\n\t\treturn file->fd;\n",
		"one stream's descriptor is cached so a replay does not reopen per record, and a cache that does not check whose file it holds answers one issuer's request from another's",
	),
	(
		"store-file-cache-reads-the-whole-issuer",
		"record/store_file.c",
		"\t    && memcmp(file->issuer, issuer, FZN_PUBKEY_LEN) == 0)",
		"\t    && memcmp(file->issuer, issuer, 1u) == 0)",
		"the cache must match the WHOLE issuer: a prefix compare hands back one issuer's descriptor for a near twin, so one issuer's records are read from and written to another's file. store-file-cache-identity drops the check and a first-byte-different issuer catches that; only a last-byte near miss holds the whole read. sec 302",
	),
	(
		"store-file-dir-bound",
		"record/store_file.c",
		"\tif (len + FZN_RECORD_STORE_FILE_NAME_LEN > sizeof(file->dir))\n\t\treturn NULL;\n",
		"\tif (0)\n\t\treturn NULL;\n",
		"a truncated path is not a shorter path: a directory long enough to cut the issuer off puts several issuers' records in one file, each overwriting the last",
	),
	(
		"peer-print-two-denials-differ",
		"cli/peer_print.c",
		"\tput_str(s, named ? \"denied -- the policy reserves this verb to a group this peer \"\n\t                   \"does not hold\"\n\t                 : \"denied -- no rule names this verb, so the policy does not \"\n\t                   \"cover it\");\n",
		"\tput_str(s, \"denied\");\n",
		"a verb the policy does not cover and a verb it reserves to another group are a configuration finding and an access decision, and reporting both as `denied` sends an operator to the wrong half of the system -- sec 204",
	),
	(
		"peer-print-escapes-a-hostile-verb",
		"cli/peer_print.c",
		"\t\tif (c >= 0x20u && c < 0x7fu && c != '\"' && c != '\\\\') {\n",
		"\t\tif (1) {\n",
		"a verb is bytes a stranger chose, so a newline in one reaches the log unescaped and lets a peer that cannot run a command forge the record saying somebody did -- sec 204",
	),
	(
		"peer-view-unreadable-is-not-empty",
		"gui/peer_view.cpp",
		"\tif (!peer->groups_known) {\n",
		"\tif (0) {\n",
		"an unreadable group list and a genuinely empty one both draw as an empty widget, which is peer.h's whole subject arriving at the last inch -- sec 204",
	),
	(
		"peer-view-unknown-is-not-a-denial",
		"gui/peer_view.cpp",
		"\treturn QStringLiteral(\"cannot tell\");\n",
		"\treturn QStringLiteral(\"denied\");\n",
		"the tri-state exists so `could not tell` cannot be read as `no`; rendering them as one word undoes a whole module at the point a person reads it -- sec 204",
	),
	(
		"log-eviction-names-the-record",
		"log/log.c",
		"\"log/stream\", FLOG_INFO,\n",
		"\"log/stream\", FLOG_WARN,\n",
		"eviction is this log's NORMAL condition rather than a failure -- a log that refused once full would stop recording exactly when something interesting started happening -- so reporting it as a problem is wrong about the design rather than merely noisy, and the count `dropped` already exists for the health number -- sec 217",
	),
	(
		"ledger-unreadable-is-said-at-all",
		"record/ledger.c",
		"\t\treturn 0;\n\n\t/*\n\t * SAID HERE RATHER THAN AT THE THREE CALLERS",
		"\t\treturn 0;\n\treturn 1;\n\n\t/*\n\t * SAID HERE RATHER THAN AT THE THREE CALLERS",
		"the readers have NO error channel -- `fzn_ledger_confirmed` returns a version and `fzn_ledger_count` a count, so an unscannable table answers zero, which is what an honest `never heard of this peer` answers; the line is the only way the condition is expressible at all -- sec 218",
	),
	(
		"ledger-unreadable-is-an-error",
		"record/ledger.c",
		"FLOG_ERR,\n\t           \"ledger cannot be scanned",
		"FLOG_INFO,\n\t           \"ledger cannot be scanned",
		"a broken invariant in caller-owned memory is not informational: every read now answers as if nothing were confirmed, and nothing recovers without the caller fixing the struct -- sec 218",
	),
	(
		"ledger-stale-says-how-far",
		"record/ledger.c",
		"(unsigned long long)(ledger->entries[at].version - version),\n",
		"(unsigned long long)version,\n",
		"one reordered datagram and a peer whose view has fallen a long way behind return the SAME value, so the distance is the whole content the line adds to FZN_LEDGER_ERR_STALE -- sec 218",
	),
	# BATCH TWENTY-THREE, 2026-09-09: the clamp on the one field outside the
	# authenticated region. project.md sec 233.
	(
		"manifest-state-is-read-back",
		"chain/manifest.h",
		"\treturn rec.base[FZN_MANIFEST_OFF_PAIRS + FZN_MANIFEST_PAIR_LEN * i +\n\t                FZN_MANIFEST_OFF_ENTRY_STATE] == (uint8_t)FZN_MANIFEST_WITHDRAWN;\n",
		"\t(void)i;\n\treturn 0;\n",
		"a field the decoder drops is invisible to a model that reaches the module through the same accessors, so the byte comparison is what sees it WITHOUT somebody having written a case for that field -- manifest_test happens to cover this one and runs first, and mutation cannot ask the question at all because the state byte is inside the signed range -- sec 234",
	),
	(
		"revocation-supersedes-is-read-back",
		"chain/revocation.h",
		"\treturn rec.base + FZN_REV_OFF_SUPERSEDES;\n",
		"\treturn rec.base + FZN_REV_OFF_ISSUER;\n",
		"an accessor wired to the wrong field hands the model a record whose bytes it never sees, so re-encoding what the decoder returned is what asks whether the two agree -- revocation_test has carried that property on one fixture since 75865bc and catches this first, and what the harness adds is the population it holds over rather than the property itself -- sec 234",
	),
	(
		"record-kind-is-its-own-field",
		"record/record.h",
		"\treturn fzn_get_be32(r.base + FZN_RECORD_OFF_KIND);\n",
		"\treturn fzn_get_be32(r.base + FZN_RECORD_OFF_STREAM);\n",
		"record.h warns that `stream` and `kind` are both uint32 and swap at a call site with nothing to say so, and record_fuzz's PROPERTY 2 says a wrong offset shows in the bytes -- nothing in this file had ever been sabotaged, so that property had never been seen to fail, which sec 52 says is the same as not having it -- sec 234",
	),
	(
		"authz-requires-is-guarded",
		"chain/authz.h",
		"\tpolicy.guarded = 1;\n",
		"\tpolicy.guarded = 0;\n",
		"a policy built by fzn_authz_requires that reports itself UNGUARDED is the failure this header is written against -- its own comment calls an unguarded default the one that never fails and silently retires the check, and the whole point of the constructor is that unguarded has to be asked for by name -- sec 234",
	),
	(
		"get-be16-is-big-endian",
		"wire/bytes.h",
		"\treturn (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);\n",
		"\treturn (uint16_t)(((uint16_t)p[1] << 8) | (uint16_t)p[0]);\n",
		"every length and every counter on this wire is big-endian and this is where six of them are read, so an accessor that agrees with its own writer and with nobody else's is a format nobody can interoperate with -- the header holding it had no entry until the census learned to read headers -- sec 234",
	),
	# BATCH TWENTY-FIVE, 2026-09-09: the bound that binds before the capacity
	# does. project.md sec 235.
	(
		"held-by-counts-handed-slots",
		"chunk/reassembly.c",
		"\t\tif (slot->live && memcmp(slot->sender, sender, FZN_SENDER_LEN) == 0)\n",
		"\t\tif (slot->live && !slot->handed\n\t\t    && memcmp(slot->sender, sender, FZN_SENDER_LEN) == 0)\n",
		"a handed slot is live until released, so a count that skips it is SMALLER than the one the quota enforces -- which is the natural reading of the walk and the whole reason fzn_reasm_held_by exists rather than being three lines in a consumer -- sec 235",
	),
	(
		"reasm-quota-is-asked",
		"cli/reasm_print.c",
		"\t\t\tsaid = c.capped ? FZN_REASM_LINE_QUOTA : FZN_REASM_LINE_HOLDING;\n",
		"\t\t\tsaid = FZN_REASM_LINE_HOLDING;\n",
		"a table with room reports HOLDING while a sender at per_sender_max has its chunks dropped, and HOLDING is true -- the sender being refused is simply not in the sentence, which is the same shape as a full replay window that does not look like an emergency -- sec 235",
	),
	(
		"reasm-quota-counts-senders-once",
		"cli/reasm_print.c",
		"\t\tif (earlier->live\n\t\t    && memcmp(earlier->sender, table->partials[at].sender, FZN_SENDER_LEN) == 0)\n\t\t\treturn 0;\n",
		"\t\tif (earlier->live\n\t\t    && memcmp(earlier->sender, table->partials[at].sender, FZN_SENDER_LEN) == 0)\n\t\t\treturn 1;\n",
		"one sender holding three slots is one peer being refused and not three, so a census counting slots inflates the number of peers this bound is turning away -- the printer's fixture needed a third slot before the question could be asked at all -- sec 235",
	),
	# Two expiry boundaries from reassembly_test's deadline case (sec 283).
	# A slot is dead AT its deadline, not a tick after; every other expiry
	# case sweeps well past it, and reassembly_fuzz fixes `now`.
	(
		"reassembly-reap-at-the-deadline",
		"chunk/reassembly.c",
		"slot->live && !slot->handed && slot->expires_at <= now",
		"slot->live && !slot->handed && slot->expires_at < now",
		"a slot is reclaimed AT its deadline, not a tick after; weakened to < it outlives its deadline by one tick, held only by a sweep that lands exactly on it",
	),
	(
		"reassembly-accept-at-the-deadline",
		"chunk/reassembly.c",
		"\tif (expires_at != 0 && expires_at <= now)\n\t\treturn FZN_REASM_ERR_EXPIRED;",
		"\tif (expires_at != 0 && expires_at < now)\n\t\treturn FZN_REASM_ERR_EXPIRED;",
		"a chunk whose expiry equals the clock is already dead and must not cost a slot; the same boundary as the reap, at accept",
	),
	(
		"reasm-existing-slot-index-in-range",
		"chunk/reassembly.c",
		"\t\tif (index >= slot->chunks)\n\t\t\treturn FZN_REASM_ERR_MISMATCH;",
		"\t\tif (index > slot->chunks)\n\t\t\treturn FZN_REASM_ERR_MISMATCH;",
		"a chunk sent to an already-admitted slot whose index equals the chunk count is one past the last and must be refused; the admit-path index check is held by agreement_test but this one, on a subsequent chunk, was tested only with an index far past the total (9 against 3) which > rejects too -- at index == chunks with a slack buffer > writes the chunk into the slack and counts it, completing a message with a real chunk still missing. sec 299",
	),
	(
		"expire-separates-loss-from-abandonment",
		"chunk/reassembly.c",
		"\t\t\tif (slot->arrived > 1u)\n",
		"\t\t\tif (slot->arrived > 0u)\n",
		"a sender that spoke once and stopped is ordinary loss and a transfer this host gave up on mid-flight is the symptom of a max_hold below the arrival time -- reported at one severity they are indistinguishable to anybody filtering, which is the only thing a log level is for -- sec 236",
	),
	(
		"scrub-says-which-cell-rotted",
		"spool/scrub.c",
		"\t\t\t\t          (unsigned long long)cell, (unsigned long long)len,\n",
		"\t\t\t\t          (unsigned long long)first, (unsigned long long)len,\n",
		"out_dropped already says how many and may be NULL; the index is the only thing that says WHICH, and clustered failures are a region of a disk going while scattered ones are something else -- a line without it is the count again in words -- sec 238",
	),
	(
		"scrub-progress-reads-the-bitmap",
		"spool/scrub.c",
		"\t\tif (bit_get(scrub->sealed, cell))\n\t\t\tn++;\n",
		"\t\tif (cell < scrub->cells)\n\t\t\tn++;\n",
		"an answer that counts cells rather than reading their seals is the running total a consumer already had, and it is right until a cell is repaired -- which is to say right until the module does the thing it exists for and wrong from then on -- sec 239",
	),
	(
		"scrub-open-cells-is-inclusive",
		"spool/scrub.c",
		"\tif (cells < need || sealed_len < FZN_SCRUB_SEALED_LEN(need))",
		"\tif (cells <= need || sealed_len < FZN_SCRUB_SEALED_LEN(need))",
		"a roots array of exactly fzn_scrub_cells(leaves) is the frugal, correct size and must open. The guard sweep drives one cell short; the exact fit was unbuilt, every fixture over-provisioning with FZN_SCRUB_MAX_CELLS, so < could tighten to <= and refuse a buffer sized to precisely its need. sec 311",
	),
	(
		"scrub-open-sealed-is-inclusive",
		"spool/scrub.c",
		"\tif (cells < need || sealed_len < FZN_SCRUB_SEALED_LEN(need))",
		"\tif (cells < need || sealed_len <= FZN_SCRUB_SEALED_LEN(need))",
		"a seal bitmap of exactly FZN_SCRUB_SEALED_LEN(need) bytes holds one bit per cell and must open. The sweep drives a zero-length bitmap; the exact fit was unbuilt, so < could tighten to <= and refuse a bitmap sized to precisely its grid. sec 311",
	),
	# BATCH TWENTY-SIX, 2026-09-09: the detector's own two halves.
	# project.md sec 242.
	(
		"scrub-detects-a-changed-cell",
		"spool/scrub.c",
		"\t\t\tif (memcmp(root, scrub->roots + cell * FZN_BLOB_HASH_LEN,\n\t\t\t           FZN_BLOB_HASH_LEN) != 0) {\n",
		"\t\t\tif (memcmp(root, scrub->roots + cell * FZN_BLOB_HASH_LEN,\n\t\t\t           FZN_BLOB_HASH_LEN) == 0) {\n",
		"the comparison IS the module: inverted, a host keeps every cell whose bytes changed and re-fetches every cell that was fine, and the only outward sign is a want-list that never empties -- scrub_fuzz asks it of arbitrary corruptions rather than of one flipped bit -- sec 242",
	),
	(
		"scrub-returns-the-leaves-it-drops",
		"spool/scrub.c",
		"\t\t\t\t(void)fzn_spool_forget(scrub->spool, first, len);\n",
		"\t\t\t\t(void)first;\n",
		"clearing the seal without returning the leaves leaves the spool claiming bytes the reference no longer matches, and scrub.h calls the forget the whole of repair -- detection without it is a scrub that notices and does nothing -- sec 242",
	),
	# BATCH TWENTY-SEVEN, 2026-09-10: the ratchet's bookkeeping, and the one
	# refusal that lands after the work starts. project.md sec 245.
	(
		"ratchet-jump-counts-every-step",
		"ratchet/ratchet.c",
		"\tfor (i = 0; i < jump; i++) {\n",
		"\tfor (i = 0; i + 1u < jump; i++) {\n",
		"a chain one derivation short of where it should be hands every later message a key nobody can open, and the two sides agree with themselves throughout -- only stepping one at a time as an oracle sees it -- sec 245",
	),
	(
		"ratchet-dropped-is-counted",
		"ratchet/ratchet.c",
		"\t\t\t} else {\n\t\t\t\tlost++;\n\t\t\t}\n",
		"\t\t\t} else {\n\t\t\t\t(void)0;\n\t\t\t}\n",
		"a caller that asked for fewer skipped keys than there were must be told rather than left to infer it from a count that stopped short, which is the shape ratchet.h takes from fzn_manifest_deficit -- silently, the keys for those sequences are gone and nothing said so -- sec 245",
	),
	(
		"ratchet-writes-the-destination-last",
		"ratchet/ratchet.c",
		"\twork = *from;\n",
		"\twork = *from;\n\t*to = work;\n",
		"a refusal part-way through must not leave a caller holding a position that is neither the old one nor a usable new one -- and this SURVIVED 2000 cases of ratchet_fuzz until that harness learned to fail a hash mid-jump, because a behind target and a jump past the bound both return before the module touches anything -- sec 245",
	),
	(
		"sched-cost-saturates",
		"sched/sched.c",
		"\treturn a > UINT64_MAX - b ? UINT64_MAX : a + b;\n",
		"\treturn a + b;\n",
		"this module's one recorded defect: a wrapped sum made a link declaring metric and latency both at 4294967295 cost ZERO under a heavy weight, so the worst link available was chosen consistently and looked deliberate -- widening the multiplies was not enough because the sum was a bare plus -- sec 246",
	),
	(
		"sched-ties-go-to-the-lowest-index",
		"sched/sched.c",
		"\t\tif (!found || cost < best_cost) {\n",
		"\t\tif (!found || cost <= best_cost) {\n",
		"a scheduler whose choice wandered between identical candidates would make a network's behaviour unreproducible for no gain, which is sched.h's own reason for the rule -- and every fixture in sched_test.c selects over a PAIR, where a three-way tie cannot be expressed -- sec 246",
	),
	(
		"sched-filter-is-not-a-penalty",
		"sched/sched.c",
		"\t\tif (!fzn_sched_admits(&links[i], wanted))\n\t\t\tcontinue;\n",
		"\t\tif (0 && !fzn_sched_admits(&links[i], wanted))\n\t\t\tcontinue;\n",
		"scoring a link that fails a hard constraint rather than skipping it lets a large enough weight elsewhere bring it back, which is the wrong kind of helpful this module refuses -- a voice class would be handed a link it had ruled out -- sec 246",
	),
	(
		"sched-print-has-no-fix-to-name",
		"cli/sched_print.c",
		"\tif (kinds > 1u)\n\t\treturn FZN_SCHED_LINE_NO_SINGLE_FIX;\n",
		"\tif (kinds > 2u)\n\t\treturn FZN_SCHED_LINE_NO_SINGLE_FIX;\n",
		"links excluded for DIFFERENT reasons have no single fix, and a line naming any one bound sends a reader to change the thing that cannot help -- every other state here points at a field and this one exists to say that pointing would be wrong -- sec 247",
	),
	(
		"sched-print-blames-the-links-not-the-class",
		"cli/sched_print.c",
		"\tif (kinds == 0u)\n\t\treturn FZN_SCHED_LINE_NOTHING_UP;\n",
		"\tif (kinds == 0u && c->down == 0u)\n\t\treturn FZN_SCHED_LINE_NOTHING_UP;\n",
		"a table of dead links excludes every class there is, so telling somebody to raise a latency bound sends them to change the one thing that cannot help -- the state has to outrank the constraints or a down table reads as a class problem -- sec 247",
	),
	(
		"sched-print-does-not-vouch-for-a-choice",
		"cli/sched_print.c",
		"\t\tif (err == FZN_SCHED_OK && chosen < link_count\n\t\t    && fzn_sched_admits(&links[chosen], wanted)) {\n",
		"\t\tif (err == FZN_SCHED_OK && chosen < link_count) {\n",
		"an OK naming a link the class excludes is either a caller pairing an answer with the wrong table or a selection this module would not have made, and describing it as a choice puts the printer's name behind it -- sec 247",
	),
	(
		"sched-view-names-the-carrier",
		"gui/sched_view.cpp",
		"\t\tif (state_ == CARRIED && i == chosen)\n\t\t\treason = QStringLiteral(\"CARRYING\");\n\t\telse\n\t\t\treason = reason_for(links[i], *wanted);\n",
		"\t\treason = reason_for(links[i], *wanted);\n",
		"on a table where three links qualify, a reader has to see which one is carrying the traffic without comparing costs by eye -- rows that all say `qualifies` leave the choice to be inferred from the summary and the arithmetic -- sec 248",
	),
	(
		"sched-view-shows-the-printers-line",
		"gui/sched_view.cpp",
		"\tsummary_->setText(QString::fromLatin1(line).trimmed());\n",
		"\tsummary_->setText(QStringLiteral(\"a link was considered\"));\n",
		"sec 193: the verdict is the printer's to state and a widget composing its own is a second wording to keep in step -- the two drift and the screen is the copy nobody re-reads -- sec 248",
	),
	# BATCH TWENTY-EIGHT, 2026-09-10: the anchoring table, walked whole.
	# project.md sec 250.
	(
		"trust-only-a-pin-replaces-a-self-root",
		"trust/trust.c",
		"\t\tif (!(trust->source == FZN_TRUST_SELF && source == FZN_TRUST_PINNED)) {\n",
		"\t\tif (!(trust->source == FZN_TRUST_SELF)) {\n",
		"widening the join to any source is what re-opens the window a self-root closes: a node trusting itself for want of anybody else could be taken by whoever answers first, which trust.h calls the whole point of the asymmetry -- caught at [self(1) adopt(0)] -- sec 250",
	),
	(
		"trust-the-same-key-is-an-echo",
		"trust/trust.c",
		"\t\tif (fzn_ct_memeq(trust->root, root, FZN_PUBKEY_LEN))\n\t\t\treturn FZN_TRUST_ERR_UNCHANGED;\n",
		"",
		"a join repeated or a bundle delivered twice is an echo and not a fault, and a consumer telling a user its trust was attacked when the same root arrived again is the alarm nobody will read the second time -- caught at [pin(0) pin(0)] -- sec 250",
	),
	(
		"claim-print-does-not-alarm-on-the-normal-case",
		"cli/claim_print.c",
		"\t\tput_str(s, \"another process of this identity owns its mutable state, which \"\n",
		"\t\tput_str(s, \"PROBLEM -- the identity is locked by another process, which \"\n",
		"claim.h calls FZN_CLAIM_ERR_HELD an answer rather than a fault and the expected result for every process but one, so a line that alarms on it alarms a person about a host that is fine -- and it is the line most consumers will show most often -- sec 251",
	),
	(
		"claim-print-separates-broken-from-busy",
		"cli/claim_print.c",
		"\t\tcase FZN_CLAIM_ERR_BACKEND:\n\t\t\tsaid = FZN_CLAIM_LINE_UNARBITRATED;\n",
		"\t\tcase FZN_CLAIM_ERR_BACKEND:\n\t\t\tsaid = FZN_CLAIM_LINE_ELSEWHERE;\n",
		"a host that cannot arbitrate ownership at all is a broken store and a host whose claim is held is a working one, which claim.h keeps apart because they want different responses -- collapsed, the unusable store reads as the ordinary case and nobody is sent to look -- sec 251",
	),
	(
		"prekey-print-announces-a-rollback",
		"cli/prekey_print.c",
		"\t\tput_str(s, \"ATTENTION -- an older prekey for this peer was replayed and \"\n",
		"\t\tput_str(s, \"refused -- an older prekey for this peer was replayed and \"\n",
		"prekey.h says of this code that it exists because it is the one an operator has to see: a real, correctly signed, older record replayed, and if that key has since leaked, accepting it is the whole attack -- a line that does not announce it is the surface failing at the one thing it was built for -- sec 252",
	),
	(
		"prekey-print-does-not-blame-the-peer",
		"cli/prekey_print.c",
		"\t\tcase FZN_PREKEY_ERR_SIGNER:\n\t\tcase FZN_PREKEY_ERR_MALFORMED:\n\t\t\tsaid = FZN_PREKEY_LINE_LOCAL;\n",
		"\t\tcase FZN_PREKEY_ERR_SIGNER:\n\t\t\tsaid = FZN_PREKEY_LINE_UNVERIFIED;\n\t\t\tbreak;\n\t\tcase FZN_PREKEY_ERR_MALFORMED:\n\t\t\tsaid = FZN_PREKEY_LINE_LOCAL;\n",
		"a host with no verifier configured and a forged record both stop a peer being pinned, and only one of them is about the peer -- rendering the first as `could not be verified` accuses somebody of something this host did -- sec 252",
	),
	(
		"prekey-print-tells-a-redelivery-from-a-rotation",
		"cli/prekey_print.c",
		"\t\t\telse if (prekey_moved(before, after))\n\t\t\t\tsaid = FZN_PREKEY_LINE_ROTATED;\n\t\t\telse\n\t\t\t\tsaid = FZN_PREKEY_LINE_UNCHANGED;\n",
		"\t\t\telse\n\t\t\t\tsaid = FZN_PREKEY_LINE_ROTATED;\n",
		"a first pin, a rotation and a re-delivery all answer FZN_PREKEY_OK, and prekey.h calls the last of them ordinary and not an event -- a consumer showing a key change every time a record is redelivered teaches a person to ignore the one that is real -- sec 252",
	),
	(
		"persist-print-tells-a-loss-from-a-first-run",
		"cli/persist_print.c",
		"\t\t\tsaid = had_stored ? FZN_PERSIST_LINE_LOST : FZN_PERSIST_LINE_FRESH;\n",
		"\t\t\tsaid = FZN_PERSIST_LINE_FRESH;\n",
		"the store answers identically whether this is a first run or somebody removed a host's identity, so nothing but the caller's own context tells them apart -- collapsed, the day a person's stored state disappears is reported as an ordinary startup and nobody is told anything -- sec 253",
	),
	(
		"persist-print-rules-out-an-attack",
		"cli/persist_print.c",
		"\t\tput_str(s, \" is stored in a shape this version does not read: a corrupt or \"\n\t\t           \"foreign file rather than an attack, left alone rather than \"\n\t\t           \"repaired\\n\");\n",
		"\t\tput_str(s, \" is stored in a shape this version does not read\\n\");\n",
		"persist.h says a peer cannot reach these bytes so this is a corrupt or foreign file rather than an attack, and a person told their identity is corrupt assumes the worst thing it could mean unless the line rules it out -- and the file is left alone, which they need to know they still have -- sec 253",
	),
	(
		"persist-view-does-not-alarm-a-first-run",
		"gui/persist_view.cpp",
		"\t\telse if (said == FZN_PERSIST_LINE_FRESH)\n\t\t\tfresh++;\n",
		"\t\telse if (said == FZN_PERSIST_LINE_FRESH)\n\t\t\tmissing_++;\n",
		"nothing stored anywhere is the most common startup there is, and counting it as state that did not come back would alarm every new install about a loss that never happened -- the first run and the partial recovery are not degrees of one thing -- sec 254",
	),
	(
		"persist-view-summary-follows-the-worst-row",
		"gui/persist_view.cpp",
		"\tif (missing_ > 0u) {\n\t\tstate_ = INCOMPLETE;\n",
		"\tif (0) {\n\t\tstate_ = INCOMPLETE;\n",
		"a person scanning five lines reads the first sentence and stops, so one loss among four recoveries has to be what that sentence is about -- a summary counting the recoveries is true and is the half nobody needed -- sec 254",
	),
	(
		"relay-print-separates-a-decision-from-an-ending",
		"cli/relay_print.c",
		"\tcase FZN_RELAY_ERR_REFUSED:\n\t\tsaid = FZN_RELAY_LINE_REFUSED;\n",
		"\tcase FZN_RELAY_ERR_REFUSED:\n\t\tsaid = FZN_RELAY_LINE_ENDED;\n",
		"relay.h argues at length that collapsing these makes a misconfigured policy indistinguishable from normal traffic reaching the end of its budget -- an operator watching frames stop would have no way to ask whether the host is doing it -- sec 256",
	),
	(
		"relay-print-says-whether-there-is-a-row",
		"cli/relay_print.c",
		"\t\tif (row)\n\t\t\tput_str(s, \", whose ceiling for it is zero\");\n\t\telse\n\t\t\tput_str(s, \", which has no row of its own and takes the fallback\");\n",
		"\t\t(void)row;\n\t\tput_str(s, \", whose ceiling for it is zero\");\n",
		"a ceiling somebody wrote down and a subsystem with no entry at all are different edits, and sending an operator to find a policy row that does not exist is worse than not naming one -- sec 256",
	),
	(
		"store-print-separates-empty-from-broken",
		"cli/store_print.c",
		"\tcase FZN_RECORD_STORE_ERR_BACKEND:\n\t\tsaid = FZN_RECORD_STORE_LINE_UNREADABLE;\n",
		"\tcase FZN_RECORD_STORE_ERR_BACKEND:\n\t\tsaid = FZN_RECORD_STORE_LINE_NOT_HELD;\n",
		"store.h states the harm outright: a caller that treated a broken store as an empty one would refetch the world, and not-held is most of what a busy reader asks for so the collapse hides inside ordinary traffic -- sec 258",
	),
	(
		"store-print-tells-a-wrong-find-from-a-bad-one",
		"cli/store_print.c",
		"\tcase FZN_RECORD_STORE_ERR_MISPLACED:\n\t\tsaid = FZN_RECORD_STORE_LINE_MISPLACED;\n",
		"\tcase FZN_RECORD_STORE_ERR_MISPLACED:\n\t\tsaid = FZN_RECORD_STORE_LINE_DAMAGED;\n",
		"a store that answers with the WRONG record has not failed to find something, it has found the wrong thing and said nothing -- described as corruption it sends somebody to inspect a file when the fault is the index -- sec 258",
	),
	(
		"link-snapshot-does-not-rotate",
		"link/link.c",
		"\tfor (size_t i = 0; i < table->used; i++) {\n\t\tconst fzn_link_entry_t *e = &table->entries[i];\n",
		"\tfor (size_t i = 0; i < table->used; i++) {\n\t\tconst fzn_link_entry_t *e =\n\t\t        &table->entries[(i + (size_t)table->entries[0].id) % table->used];\n",
		"link.h says table order IS registration order, permanently, and sched's cursor relies on it -- rotating to be fair to starved links would make which link a consumer sees depend on when it asked, which is the fix this behaviour is pinned against rather than an improvement -- sec 259",
	),
	(
		"link-snapshot-counts-past-the-bound",
		"link/link.c",
		"\t\tif (n >= out_cap) {\n\t\t\t(*dropped)++;\n\t\t\tcontinue;\n\t\t}\n",
		"\t\tif (n >= out_cap)\n\t\t\tbreak;\n",
		"a snapshot that stops at the bound reports nothing dropped, and link.h calls a snapshot that quietly does not fit worse than a short list -- a consumer is then told the network is down with no number saying how much it was not shown -- sec 259",
	),
	(
		"claim-a-failed-release-still-lets-go",
		"claim/claim.c",
		"\tclaim->held = 0;\n\tif (!claim->ops->release(claim->ops->ctx)) {\n",
		"\tif (!claim->ops->release(claim->ops->ctx)) {\n",
		"clearing held only on success is the fix a reader makes on meeting this, and it puts the process back in the state claim.c rules out: believing it owns state the kernel may have handed on -- of the two wrong answers, refusing to act is the one that cannot desynchronise a ratchet -- caught at [take=got release=fails] -- sec 260",
	),
	(
		"claim-taking-twice-is-a-lost-track",
		"claim/claim.c",
		"\tif (claim->held)\n\t\treturn FZN_CLAIM_ERR_STATE;\n",
		"\tif (claim->held)\n\t\treturn FZN_CLAIM_OK;\n",
		"a backend whose lock is per open-file-description reports success for a second take and leaves the caller believing two takes need two releases, which claim.c names as the reason this is refused rather than absorbed -- caught at [take=got take=got] -- sec 260",
	),
	(
		"log-body-escapes-what-a-terminal-obeys",
		"log/log.c",
		"\t\tif (body[i] >= 0x20u && body[i] <= 0x7eu) {\n",
		"\t\tif (body[i] >= 0x0au && body[i] <= 0x7eu) {\n",
		"a viewer showing one entry per line, handed a body with a newline and a plausible sequence number, displays a SECOND entry no issuer ever signed -- and the same argument covers a terminal escape sequence, which is what an unescaped control byte delivers -- sec 233",
	),
	(
		"log-body-max-is-inclusive",
		"log/log.c",
		"\tif (body_len > FZN_RECORD_BODY_MAX)",
		"\tif (body_len >= FZN_RECORD_BODY_MAX)",
		"a body of exactly FZN_RECORD_BODY_MAX is the largest a record can carry and must render; >= refuses the maximum-size body as malformed. Every other body_text case renders a handful of bytes, and the bound test uses MAX+1 which > and >= both refuse -- only a body of exactly MAX holds this edge. sec 300",
	),
	(
		"relay-budget-clamps",
		"wire/relay.c",
		"\t*out = claimed < allowed ? claimed : allowed;\n",
		"\t*out = claimed;\n",
		"the budget is mutable in flight by anyone and a stranger can write 255 into a frame it did not create -- trusting that number turns one datagram into as many forwards as the network has paths, which relay.h calls an amplifier built out of a helpful default -- sec 233",
	),
	# BATCH TWENTY-TWO, 2026-09-09: one encoding per stored anchor.
	# project.md sec 232.
	(
		"persist-one-encoding-per-anchor",
		"persist/persist.c",
		"\tif (source != (uint8_t)FZN_TRUST_ADOPTED && adopted_at != 0u)\n\t\treturn FZN_PERSIST_ERR_SHAPE;\n",
		"\tif (0)\n\t\treturn FZN_PERSIST_ERR_SHAPE;\n",
		"`fzn_trust_pin` and `fzn_trust_self` take no timestamp, so without this the eight bytes `pack` writes for them are read by nobody -- a stored anchor could carry anything there and still open to the same struct and re-pack to the original bytes, which is the second encoding `head_check` refuses a trailing byte for -- sec 232",
	),
	# BATCH TWENTY-ONE, 2026-09-09: a full reassembly table, and which of
	# its THREE fixes it needs. project.md sec 230.
	(
		"reasm-print-handed-is-not-sweepable",
		"cli/reasm_print.c",
		"\t\tif (slot->handed) {\n\t\t\tc->handed++;\n\t\t\tcontinue;\n\t\t}\n",
		"\t\tif (slot->handed)\n\t\t\tc->handed++;\n",
		"`fzn_reasm_expire` skips handed slots so the caller can still read the bytes it was promised, so counting an expired handed slot as sweepable offers back a slot no sweep will return -- sec 230",
	),
	(
		"reasm-print-leak-outranks-a-sweep",
		"cli/reasm_print.c",
		"\t\telse if (c.handed)\n\t\t\tsaid = FZN_REASM_LINE_FULL_HANDED;\n",
		"\t\telse if (0)\n\t\t\tsaid = FZN_REASM_LINE_FULL_HANDED;\n",
		"a caller that never releases exhausts the table and never recovers, which reassembly.h chose as the honest symptom of that bug -- reporting it as a missed sweep sends somebody to call expire, which will free nothing -- sec 230",
	),
	(
		"reasm-print-rules-out-what-will-not-help",
		"cli/reasm_print.c",
		"\t\tput_str(s, \" slots all live and unexpired, so waiting and releasing will not \"\n\t\t           \"help and the bounds are too small\\n\");\n",
		"\t\tput_str(s, \" slots all live and unexpired\\n\");\n",
		"reassembly.h says a consumer reading a full table concludes that time alone fixes it, so the line that means otherwise has to rule both other fixes out rather than report a number -- sec 230",
	),
	# BATCH TWENTY, 2026-09-09: a full replay window, and which of its two
	# fixes it needs. project.md sec 229.
	# NO ENTRY FOR "expirable does not expire", AND THAT IS THE FINDING.
	# The first one written here mutated `due++` into `window->used--` and
	# the harness reported NOT-BUILT: `fzn_replay_expirable` takes a
	# `const fzn_replay_window_t *`, so no mutation of that function can
	# reclaim anything. The property is enforced by the SIGNATURE, and
	# trying to sabotage a compiler-enforced guarantee is a category error
	# rather than a badly written entry. sec 229.
	(
		"replay-expirable-draws-the-same-boundary",
		"frame/freshness.c",
		"\t\tif (window->entries[i].expires_at <= now)\n",
		"\t\tif (window->entries[i].expires_at < now)\n",
		"`> now` KEEPS in the compaction, so an entry expiring exactly at `now` is dropped -- a counter drawing a different boundary answers about a window the operation it describes would not produce -- sec 229",
	),
	(
		"replay-print-names-which-fix",
		"cli/replay_print.c",
		"\t\telse if (due)\n\t\t\tsaid = FZN_REPLAY_LINE_FULL_UNPRUNED;\n",
		"\t\telse if (0)\n\t\t\tsaid = FZN_REPLAY_LINE_FULL_UNPRUNED;\n",
		"frame/freshness.h says a full window means either that nobody is expiring or that the capacity is too small, and that `those want different fixes and the value says neither` -- collapsing them here puts a reader back where the return value left them -- sec 229",
	),
	(
		"replay-print-full-is-an-emergency",
		"cli/replay_print.c",
		"\t\tput_str(s, \"REFUSING FRESH FRAMES -- full at \");\n\t\tput_size(s, capacity);\n\t\tput_str(s, \" with \");\n",
		"\t\tput_str(s, \"full at \");\n\t\tput_size(s, capacity);\n\t\tput_str(s, \" with \");\n",
		"the window refuses rather than evicting -- deliberately, since evicting would let an attacker flush it and replay what they recorded -- so a full one is a host turning away FRESH traffic, which `full` alone does not say",
	),
	# BATCH NINETEEN, 2026-09-09: the delivery list, where one unreadable
	# table voids a screen of green rows. project.md sec 228.
	(
		"ledger-view-asks-the-table-not-the-rows",
		"gui/ledger_view.cpp",
		"\tif (!fzn_ledger_sound(ledger)) {\n",
		"\tif (0) {\n",
		"unreadability belongs to the TABLE rather than to a peer, so without this every row prints `cannot say` while the summary counts none of them outstanding and reports delivery -- and the first two entries written here SURVIVED because they varied a distinction the code cannot express -- sec 228",
	),
	(
		"ledger-view-counts-what-it-was-asked",
		"gui/ledger_view.cpp",
		"\t\t\trows_truncated_ = true;\n\t\t\tcontinue;\n",
		"\t\t\trows_truncated_ = true;\n\t\t\tbreak;\n",
		"the summary describes the peers ASKED ABOUT and the rows describe what fitted; stopping the walk at the row limit makes the summary describe what fitted too, so a peer past the limit that has not confirmed disappears from both -- sec 228",
	),
	# BATCH EIGHTEEN, 2026-09-09: what a peer has confirmed, and the
	# predicate that separates two zeroes. project.md sec 227.
	(
		"ledger-sound-is-silent",
		"record/ledger.c",
		"\treturn !unscannable(ledger);\n",
		"\treturn !corrupt(ledger);\n",
		"`fzn_ledger_sound` IS an error channel -- it returns the answer -- so a line from it contradicts the argument the ERR inside `corrupt` rests on, and a consumer refreshing a screen would emit the same error every frame -- sec 227",
	),
	(
		"ledger-print-asks-sound-first",
		"cli/ledger_print.c",
		"\t\tif (!fzn_ledger_sound(ledger)) {\n",
		"\t\tif (0) {\n",
		"every other accessor answers an unreadable ledger in the voice of a readable one: `confirmed` returns 0, which reads as `never acknowledged`, and `behind` returns non-zero, which reads as a measured comparison -- sec 227",
	),
	(
		"ledger-print-unreadable-is-not-unknown",
		"cli/ledger_print.c",
		"\t\tput_str(s, \"cannot say -- this ledger cannot be scanned, so every peer reads \"\n\t\t           \"as behind\\n\");\n",
		"\t\tput_str(s, \"nothing confirmed -- this peer has never acknowledged this \"\n\t\t           \"subject\\n\");\n",
		"one peer out of date and a table nobody can walk are opposite findings: the first is somebody to resend to, the second is a screen where nothing is evidence -- sec 227",
	),
	(
		"ledger-print-ahead-is-not-behind",
		"cli/ledger_print.c",
		"\t\t\telse if (confirmed < current)\n",
		"\t\t\telse if (confirmed != current)\n",
		"a peer that confirmed a version this host has not reached is not behind, and the ledger refuses to move backwards precisely so that state persists -- reporting it as behind would resend for ever -- sec 227",
	),
	# BATCH SEVENTEEN, 2026-09-09: the issuer list, and the two things it
	# adds that no single call to the printer can. project.md sec 226.
	(
		"manifest-view-worst-row-decides",
		"gui/manifest_view.cpp",
		"\tif (understated) {\n\t\tstate_ = UNDERSTATED;\n",
		"\tif (understated > asked / 2u) {\n\t\tstate_ = UNDERSTATED;\n",
		"a dropped pair is the one refusal here that fails OPEN, so four sound issuers and one understated is not `mostly fine` -- the understated row is the only one that can be hiding an authority this host still honours, and a majority rule would hide exactly it -- sec 226",
	),
	(
		"manifest-view-counts-what-it-was-asked",
		"gui/manifest_view.cpp",
		"\t\t\trows_truncated_ = true;\n\t\t\tcontinue;\n",
		"\t\t\trows_truncated_ = true;\n\t\t\tbreak;\n",
		"the summary describes the issuers ASKED ABOUT and the rows describe what fitted; stopping the walk at the row limit makes the summary describe what fitted too, so an understated issuer past the limit disappears from both -- sec 226",
	),
	(
		"manifest-view-no-state-is-not-current",
		"gui/manifest_view.cpp",
		"\t\tsummary_->setText(QStringLiteral(\"nothing is being tracked\"));\n\t\trows_->setText(QString());\n\t\treturn;\n\t}\n\n\tfor (i = 0u; i < count; i++) {\n",
		"\t\tsummary_->setText(QStringLiteral(\"all issuers are up to date\"));\n\t\trows_->setText(QString());\n\t\treturn;\n\t}\n\n\tfor (i = 0u; i < count; i++) {\n",
		"a host with no manifest state is tracking nothing, and reporting that as current is the same fail-open cli/manifest_print refuses for the same reason: a zero where there is nothing to measure reads as a measurement -- sec 226",
	),
	# BATCH SIXTEEN, 2026-09-09: the two widgets the census could not see.
	#
	# `gui/qr_view.cpp` and `gui/trust_view.cpp` are the FIRST pair, written
	# before this table covered widgets at all, and they were the only two of
	# fifteen with no entry. Nothing said so: `make manifest` named the front
	# ends as one literal and one directory, so the coverage check had no
	# population to compare them against. Both are fixed in sec 225.
	(
		"qr-view-uses-the-library-s-words",
		"gui/qr_view.cpp",
		"\t\tmessage_ = QString::fromUtf8(fzn_qr_err_str(err));\n",
		"\t\tmessage_ = QStringLiteral(\"no code\");\n",
		"a widget that words its own refusal gives a consumer a second vocabulary for one fact, and a user comparing a dialog against a log would be comparing two spellings rather than the fault",
	),
	(
		"trust-view-absent-is-not-empty",
		"gui/trust_view.cpp",
		"\t\tfingerprint_->setText(QStringLiteral(\"(none)\"));\n",
		"\t\tfingerprint_->setText(QStringLiteral(\"\"));\n",
		"an empty field where a fingerprint belongs reads as a fingerprint OF SOMETHING, and somebody comparing it out of band would conclude the peer is wrong when the truth is this host has no anchor at all",
	),
	# BATCH FIFTEEN, 2026-09-09: the deficit on a screen, and the accessor
	# it needed. project.md sec 224.
	(
		"manifest-follows-refuses-an-unreadable-state",
		"chain/manifest.c",
		"\tif (!state_sound(state) || !state->issuers || !issuer)\n\t\treturn 0;\n\n\treturn find_issuer(state, issuer) < state->issuer_used;\n",
		"\tif (!state_sound(state) || !state->issuers || !issuer)\n\t\treturn 1;\n\n\treturn find_issuer(state, issuer) < state->issuer_used;\n",
		"this answers the OPPOSITE conservative direction from fzn_manifest_overflowed on purpose: claiming to follow a key whose entry cannot be read hides the same gap from the other side, and both refuse to flatter the host -- sec 224",
	),
	(
		"manifest-print-asks-follows-first",
		"cli/manifest_print.c",
		"\t\tif (!fzn_manifest_follows(state, issuer)) {\n",
		"\t\tif (0) {\n",
		"`pending` answers 0 for an unfollowed issuer and calls that the absence of a question, and `overflowed` answers 1 for it -- so without asking `follows` an issuer nothing is tracked from renders as one whose count is a floor, which is the opposite sentence -- sec 224",
	),
	(
		"manifest-print-floor-is-not-a-count",
		"cli/manifest_print.c",
		"\t\tput_str(s, \"AT LEAST \");\n",
		"\t\tput_str(s, \"\");\n",
		"a floor printed as a count is the fail-open this file exists to make visible: the host looks MORE complete than it is, and a person reading a number has no way to know it can only go up -- sec 224",
	),
	(
		"manifest-print-no-state-is-not-zero",
		"cli/manifest_print.c",
		"\t\tput_str(s, \"cannot say -- there is no manifest state to read\\n\");\n",
		"\t\tput_str(s, \"0 revocations outstanding\\n\");\n",
		"a zero where there is nothing to measure reads as a measurement of a real thing, which is exactly the direction manifest.h refuses everywhere else -- sec 224",
	),
	# BATCH FOURTEEN, 2026-09-09: chain/manifest, the one refusal in this
	# library that fails OPEN. project.md sec 223.
	(
		"manifest-drop-says-how-many",
		"chain/manifest.c",
		"\t\t             \"dropped %d of %zu pairs with the deficit table full at %zu, so \"\n",
		"\t\t             \"dropped pairs with the deficit table full at %zu, so \"\n",
		"the enumerator's own comment is that a dropped pair makes this host report a SMALLER deficit than it has -- one pair short and forty are the same code and the same one-bit flag, and until sec 223 the count existed nowhere at all",
	),
	(
		"manifest-replay-is-not-an-update",
		"chain/manifest.c",
		"\t} else {\n\t\t/* A MANIFEST SMALLER THAN ONE ALREADY SEEN.",
		"\t} else if (0) {\n\t\t/* A MANIFEST SMALLER THAN ONE ALREADY SEEN.",
		"a manifest naming fewer pairs than one already seen is exactly the rollback case -- revocations only accumulate -- and a replay aimed at clearing an overflow flag is somebody trying to make this host look complete",
	),
	(
		"manifest-full-is-permanent",
		"chain/manifest.c",
		"\t\tMANIFEST_LOG(state, \"chain/manifest\", FLOG_CRIT,\n",
		"\t\tMANIFEST_LOG(state, \"chain/manifest\", FLOG_WARN,\n",
		"nothing in the issuer table is ever evicted, so a full one means this host can never follow anybody again and will not see what they revoke -- this module cites record/journal.h, which takes CRIT for the same structure",
	),
	(
		"manifest-stranger-is-silent",
		"chain/manifest.c",
		"\t\treturn FZN_MANIFEST_ERR_UNKNOWN_ISSUER;\n",
		"\t{ MANIFEST_LOG(state, \"chain/manifest\", FLOG_WARN, \"unknown issuer\");\n"
		"\t  return FZN_MANIFEST_ERR_UNKNOWN_ISSUER; }\n",
		"declining to follow a stranger is the design working and arrives at whatever rate a stranger chooses; this header says a receiver that logged a stranger's bytes as its own defect would be looking in the wrong place -- braced, per batch thirteen",
	),
	# BATCH THIRTEEN, 2026-09-09: the two modules where a diagnostic IS the
	# security surface, and the three lines deliberately NOT written. A
	# decline nobody asserts the absence of is one somebody adds back for
	# symmetry. project.md sec 222.
	#
	# THE TWO SILENCE ENTRIES CARRY BRACES, AND THE FIRST VERSIONS DID NOT.
	# Both returns sit inside a BRACELESS `if`, so inserting a statement
	# before one makes the return unconditional -- and both were then
	# reported CAUGHT by a case about something else entirely: a re-delivery
	# refused, a different root reported unchanged. A sabotage that changes
	# control flow instead of adding a line tests nothing it claims to, and
	# the CAUGHT verdict is what hides it. Reading WHICH check failed is the
	# whole of the fix, and `evidence.md` says so in as many words.
	(
		"trust-refusal-names-the-transition",
		"trust/trust.c",
		"\t\t\tTRUST_LOG(trust, \"trust/anchor\", FLOG_WARN,\n\t\t\t          \"refusing to re-anchor",
		"\t\t\tTRUST_LOG(trust, \"trust/anchor\", FLOG_NOTE,\n\t\t\t          \"refusing to re-anchor",
		"`trust.h` says an attempt to re-anchor is the one error a consumer should treat as HOSTILE rather than as a condition, so reporting it as merely notable is wrong about the event -- sec 222",
	),
	(
		"trust-fingerprint-goes-last",
		"trust/trust.c",
		"\t\t          \"anchored: %s%s%s, fingerprint %s\", fzn_trust_source_str(source),\n",
		"\t\t          \"fingerprint %s: anchored %s%s%s\", print, fzn_trust_source_str(source),\n",
		"sec 207: a terminal clips from the RIGHT, so 79 characters of hex in front of the verdict lose the verdict -- and this is the line a person reads when comparing an anchor out of band",
	),
	(
		"trust-echo-is-silent",
		"trust/trust.c",
		"\t\t\treturn FZN_TRUST_ERR_UNCHANGED;\n",
		"\t\t{ TRUST_LOG(trust, \"trust/anchor\", FLOG_WARN, \"echo\");\n"
		"\t\t  return FZN_TRUST_ERR_UNCHANGED; }\n",
		"a join repeated or a bundle delivered twice is not a fault and the return value already says so; a line per branch is symmetry rather than merit -- sec 201, asserted here so the decline cannot be undone quietly",
	),
	(
		"prekey-rotation-is-not-ordinary",
		"prekey/prekey.c",
		"\tPREKEY_LOG(peer, \"prekey/pin\", FLOG_NOTE,\n",
		"\tPREKEY_LOG(peer, \"prekey/pin\", FLOG_INFO,\n",
		"a rotation replaces this peer's key material and returns the SAME FZN_PREKEY_OK as a re-delivery that moved nothing, so the line is the only way to tell them apart and its severity is what says which mattered -- sec 222",
	),
	(
		"prekey-rollback-says-how-far",
		"prekey/prekey.c",
		"\t\t           (unsigned long long)(peer->created_at - record.created_at));\n",
		"\t\t           (unsigned long long)peer->created_at);\n",
		"a record one second older than the one held and one a year older are the same FZN_PREKEY_ERR_ROLLBACK and are not the same event -- the second says somebody kept a copy -- sec 222",
	),
	# Two from prekey_fuzz's near-miss block (sec 282). The host and prekey
	# compares must read the whole key; the fuzz loop keys identity on byte 0,
	# so only the near-miss block reaches a shared prefix.
	(
		"prekey-host-whole",
		"prekey/prekey.c",
		"fzn_ct_memeq(anchor, record.host, FZN_PUBKEY_LEN)",
		"fzn_ct_memeq(anchor, record.host, 1u)",
		"the host match must read the WHOLE key, or a record from a host agreeing on a prefix is taken as a rotation and a prekey is pinned for a peer nobody signed; held by prekey_fuzz's near-miss block",
	),
	(
		"prekey-prekey-whole",
		"prekey/prekey.c",
		"fzn_ct_memeq(peer->prekey, record.prekey, FZN_PREKEY_LEN)",
		"fzn_ct_memeq(peer->prekey, record.prekey, 1u)",
		"the re-delivery check must read the WHOLE prekey, or a different prekey sharing a prefix at the held timestamp is taken as a re-delivery rather than the rollback it is",
	),
	(
		"prekey-wrong-host-is-silent",
		"prekey/prekey.c",
		"\t\treturn FZN_PREKEY_ERR_WRONG_HOST;\n",
		"\t{ PREKEY_LOG(peer, \"prekey/pin\", FLOG_WARN, \"wrong host\");\n"
		"\t  return FZN_PREKEY_ERR_WRONG_HOST; }\n",
		"the caller chose both the peer and the record, so it already holds everything a line could name; asserted so the decline is a decision rather than an omission -- sec 222",
	),
	# BATCH TWELVE, 2026-09-09: THE EIGHT SOURCES THE CENSUS COULD NOT SEE.
	#
	# The coverage check below reads `make manifest` and required an entry
	# for every `source ` line. The four crypto BINDINGS and the four file
	# BACKENDS are named `binding ` and `backend `, so seven of them had
	# never been sabotaged and nothing said so -- the census that exists to
	# stop a module joining the tree unswept had a narrower population than
	# the tree. `record/store_file.c` had entries anyway, which is what says
	# the exclusion was accidental rather than deliberate. project.md sec
	# 221.
	(
		"sign-verify-checks-the-signature",
		"chain/sign_monocypher.c",
		"\treturn crypto_eddsa_check(sig, pubkey, msg, msg_len) == 0;\n",
		"\treturn 1;\n",
		"the whole of this binding is the polarity inversion in its comment, and a verifier that accepts everything is the one defect in this tree that nothing above it can catch",
	),
	(
		"aead-open-checks-the-tag",
		"session/aead_monocypher.c",
		"\treturn crypto_aead_unlock(text, tag, key, nonce, aad, aad_len, text, text_len) == 0;\n",
		"\treturn 1;\n",
		"an open that ignores the tag turns an authenticated channel into an obfuscated one, and the plaintext it hands back is whatever an attacker chose",
	),
	(
		"hash-covers-the-whole-input",
		"session/hash_monocypher.c",
		"\tcrypto_blake2b(out, out_len, in, in_len);\n",
		"\tcrypto_blake2b(out, out_len, in, 0);\n",
		"a digest over none of its input is stable, well-formed and identical for every message, which is what a commitment must never be",
	),
	(
		"agree-refuses-an-all-zero-shared-secret",
		"session/agree_monocypher.c",
		"\treturn any != 0;\n",
		"\treturn 1;\n",
		"an all-zero X25519 output is what a low-order peer public key produces, and accepting it agrees a key an attacker knows -- the check is contributory behaviour and nothing above this binding repeats it",
	),
	(
		"persist-secret-mode-0600",
		"persist/persist_file.c",
		"\tfd = open(temp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);\n",
		"\tfd = open(temp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);\n",
		"the mode is set AT CREATION rather than chmod'ed afterwards precisely so a prekey secret is never briefly world-readable, and the window would be exactly as long as the write",
	),
	(
		"persist-absent-is-not-a-fault",
		"persist/persist_file.c",
		"\t\t\tPERSIST_LOG(store, \"persist/file\", FLOG_INFO,\n",
		"\t\t\tPERSIST_LOG(store, \"persist/file\", FLOG_WARN,\n",
		"a slot nothing has written yet is a host's first run, and reporting it as a problem would alarm on every start-up -- while sharing its return value with every real fault, which is why the severity is the whole distinction -- sec 220",
	),
	(
		"persist-foreign-file-is-named",
		"persist/persist_file.c",
		"\t\tPERSIST_LOG(store, \"persist/file\", FLOG_WARN,\n",
		"\t\tPERSIST_LOG(store, \"persist/file\", FLOG_INFO,\n",
		"a file too large for the caller's buffer, at this store's own name, is one this library did not write -- the opposite of the absent case it shares a return value with -- sec 220",
	),
	(
		"persist-save-names-the-step",
		"persist/persist_file.c",
		"\t\tsay_failed(store, \"create at mode 0600\", temp, errno);\n",
		"\t\tsay_failed(store, \"save\", temp, errno);\n",
		"the four steps of an atomic save fail for reasons a person acts on differently, and the `int` names none of them, so the verb is the content -- sec 220",
	),
	(
		"claim-file-contention-is-its-own-answer",
		"claim/claim_file.c",
		"\tif (held_out && (errno == EWOULDBLOCK || errno == EINTR))\n",
		"\tif (0 && held_out)\n",
		"EWOULDBLOCK is the only contention answer and everything else is a broken store rather than a busy one; a caller that read EACCES as `somebody else owns it` would wait for ever for an owner that does not exist",
	),
	(
		"spool-file-sidecar-belongs-to-this-blob",
		"spool/spool_file.c",
		"\tif (head[0] != BITS_VERSION || memcmp(head + BITS_OFF_ROOT, root, FZN_BLOB_HASH_LEN) != 0\n",
		"\tif (head[0] != BITS_VERSION\n",
		"a sidecar from another blob at a reused path would be read as this blob's progress, so leaves nobody has would be reported present and never re-requested",
	),
	(
		"record-store-names-what-came-back",
		"record/store.c",
		"\"record/store\", FLOG_ERR,\n",
		"\"record/store\", FLOG_INFO,\n",
		"a record handed back under the wrong key may be perfectly well signed, so a signature check further up cannot catch it and this is the only layer that can see the backend is confusing sequences or issuers -- sec 216",
	),
	(
		"claim-refused-release-is-said",
		"claim/claim.c",
		"\"claim/hold\", FLOG_ERR,\n",
		"\"claim/hold\", FLOG_INFO,\n",
		"`held` is already cleared when the backend refuses, so this object believes the claim is gone while the world may disagree, nothing later retries it, and the return reaches a caller unwinding a failure path that is unlikely to look -- sec 216",
	),
	(
		"replay-refusal-is-said",
		"frame/freshness.c",
		"\"frame/replay\", FLOG_WARN,\n",
		"\"frame/replay\", FLOG_DEBUG,\n",
		"a replay is the security event this module exists to refuse, and FZN_FRESH_ERR_REPLAY reaches a caller that may do nothing with it -- one replay is a retransmission and a stream of them is somebody trying, which only a log accumulates -- sec 215",
	),
	(
		"replay-window-full-names-what-prunes",
		"frame/freshness.c",
		"\"frame/replay\", FLOG_CRIT,\n",
		"\"frame/replay\", FLOG_WARN,\n",
		"a full window refuses every FRESH frame, and nothing here prunes on its own -- fzn_replay_expire is the consumer's to call -- so this is either nobody expiring or a capacity below the arrival rate the horizon implies -- sec 215",
	),
	(
		"reasm-saturation-is-said",
		"chunk/reassembly.c",
		"\"chunk/reasm\", FLOG_WARN,\n\t\t          \"reassembly table saturated:",
		"\"chunk/reasm\", FLOG_DEBUG,\n\t\t          \"reassembly table saturated:",
		"one refused chunk and a table full for a minute look identical to a caller, and this module's own header argues that a table refusing when full is one a single sender can fill -- at debug the saturation is filtered out by default -- sec 214",
	),
	(
		"spool-backend-refusal-is-said",
		"spool/spool.c",
		"\"spool/store\", FLOG_ERR,\n",
		"\"spool/store\", FLOG_INFO,\n",
		"the leaf VERIFIED and then did not land, so the spool's bookkeeping and the storage disagree from now on and it will be asked for again for ever -- the consumer's own storage failing is not an informational event -- sec 214",
	),
	(
		"journal-anchor-refuses-a-standstill",
		"record/journal.c",
		"\tif (seq <= e->received)\n\t\treturn FZN_JOURNAL_ERR_DUPLICATE;\n\n\te->received = seq;",
		"\tif (seq < e->received)\n\t\treturn FZN_JOURNAL_ERR_DUPLICATE;\n\n\te->received = seq;",
		"a re-anchor at the exact sequence already received must be DUPLICATE, not OK: reporting a new anchor where nothing moved. The backwards case is strictly less, which < refuses too, and the seq-zero re-anchor is caught by the explicit zero check rather than this comparison -- so only the equal edge holds it. sec 286",
	),
	(
		"journal-gap-says-how-many",
		"record/journal.c",
		"\"record/journal\", FLOG_WARN,\n",
		"\"record/journal\", FLOG_DEBUG,\n",
		"one missed record and an hour of unreachability are the same FZN_JOURNAL_ERR_GAP, and they want different responses -- at debug the difference is filtered out by default and the caller is back to the return value -- sec 212",
	),
	(
		"journal-full-is-permanent",
		"record/journal.c",
		"\"record/journal\", FLOG_CRIT,\n",
		"\"record/journal\", FLOG_WARN,\n",
		"a full journal cannot track a NEW issuer at all and refuses rather than evicting, because forgetting an issuer readmits everything it ever sent -- it does not recover on its own, which is what separates it from every other refusal here -- sec 212",
	),
	(
		"state-conflict-names-the-other-issuer",
		"state/state.c",
		"\"state/cell\", FLOG_WARN,\n",
		"\"state/cell\", FLOG_DEBUG,\n",
		"two issuers competing for one cell is a fact about the deployment rather than about this call, and FZN_STATE_ERR_CONFLICT says only that the write was refused -- sec 212",
	),
	(
		"state-full-is-permanent",
		"state/state.c",
		"\"state/cell\", FLOG_CRIT,\n",
		"\"state/cell\", FLOG_WARN,\n",
		"a full state refuses rather than evicting because dropping a setting reverts it to a default nobody can trace, so the condition stands until somebody enlarges it -- sec 212",
	),
	(
		"chain-store-full-of-live-is-not-full-of-stale",
		"chain/chain_store.c",
		"\"chain/store\", FLOG_WARN,\n",
		"\"chain/store\", FLOG_NOTE,\n",
		"a store full of LIVE grants wants a bigger store and one full of stale entries wants a sweep; the return value is FZN_CHAIN_ERR_STORE_FULL either way, so the severity is the only thing separating a condition that resolves itself from one that does not -- sec 211",
	),
	(
		"chain-store-says-what-it-reclaimed",
		"chain/chain_store.c",
		"\"reclaimed an entry expired at",
		"\"NOT REACHED expired at",
		"admitting a chain can make an unrelated expired grant stop existing, and the caller asked for the first and never hears about the second -- sec 211",
	),
	(
		"revocation-full-is-permanent",
		"chain/revocation.c",
		"\"chain/revocation\", FLOG_CRIT,\n",
		"\"chain/revocation\", FLOG_WARN,\n",
		"this store never evicts because a revocation does not expire, so a full one refuses every withdrawal from then on -- the host has stopped being able to learn about revocations at all, which is the one condition here that does not recover on its own -- sec 211",
	),
	(
		"revocation-tombstone-full-is-inclusive",
		"chain/revocation.c",
		"\t\t\tif (store->used >= store->capacity)\n\t\t\t\treturn FZN_CHAIN_ERR_STORE_FULL;",
		"\t\t\tif (store->used > store->capacity)\n\t\t\t\treturn FZN_CHAIN_ERR_STORE_FULL;",
		"a withdrawal for a triple the store never held is appended as a tombstone, and that add has its own full check. The revocation-add path's full check is tested by admitting a fifth revocation; nothing drove a withdrawal for an unknown pair into a FULL store, so >= could weaken to > and, at used == capacity, append the tombstone at entries[capacity] -- one past the caller's array. sec 314",
	),
	(
		"link-snapshot-says-what-it-dropped",
		"link/link.c",
		"\tif (*dropped)\n\t\tLINK_LOG(table, \"link/snapshot\", FLOG_WARN,\n",
		"\tif (0)\n\t\tLINK_LOG(table, \"link/snapshot\", FLOG_WARN,\n",
		"a caller reading `dropped` learns a number; what no return value carries is that the dropped links are the SAME ones every call, so they are never selected, never sent on and never measured -- sec 209, and the first thing this library was ever able to say out loud",
	),
	(
		"link-init-clears-the-log",
		"link/link.c",
		"\ttable->log = NULL;\n",
		"\t;\n",
		"a table declared on a caller's stack would otherwise carry whatever was there, so whether this library talks would be decided by uninitialised memory -- sec 209",
	),
	(
		"link-print-unmeasured-is-not-measured",
		"cli/link_print.c",
		"\tif (t->unmeasured == t->usable)\n\t\treturn FZN_LINK_LINE_UNMEASURED;\n",
		"\tif (0)\n\t\treturn FZN_LINK_LINE_UNMEASURED;\n",
		"a table whose every usable link is still on the far end's declared metric would report MEASURED, so a caller testing `== FZN_LINK_LINE_MEASURED` acts on evidence that does not exist -- sec 202",
	),
	(
		"link-print-unusable-links-are-not-counted",
		"cli/link_print.c",
		"\t\tif (!e->usable)\n\t\t\tcontinue;\n",
		"\t\tif (0)\n\t\t\tcontinue;\n",
		"the unmeasured count exists to say how many links sched may still choose on a stranger's word, so counting unusable ones makes the number RISE when an operator switches a bad path off -- sec 202",
	),
	(
		"link-print-a-declared-lowest-is-marked",
		"cli/link_print.c",
		"\tif (!t->best->observations) {\n",
		"\tif (0) {\n",
		"a link asserted to be fast that nobody has used holds the lowest estimate and is the number a person reads, so printing it unmarked shows a stranger's claim in the typeface of evidence -- link.h seeds the prior to defend SELECTION, and this is the same hazard arriving through reporting",
	),
	(
		"link-view-a-declared-row-says-so",
		"gui/link_view.cpp",
		"\tif (!e->observations) {\n",
		"\tif (0) {\n",
		"the printer can say how MANY usable links are on a declared metric and names only the lowest; the row saying WHICH is the whole of what this widget adds, and without it an operator cannot tell which path to take out of service -- sec 202",
	),
	(
		"link-view-truncation-is-not-silent",
		"gui/link_view.cpp",
		"\t\t\trows_truncated_ = true;\n",
		"\t\t\trows_truncated_ = false;\n",
		"a table longer than the rows drawn hides the same links every time, since link/ never reorders -- fzn_link_snapshot's own finding, and a silent cut reproduces it on screen",
	),
	(
		"trust-print-self-is-not-an-absence",
		"cli/trust_print.c",
		"\t\tcase FZN_TRUST_SELF:\n\t\t\tsaid = FZN_TRUST_LINE_SELF;\n",
		"\t\tcase FZN_TRUST_SELF:\n\t\t\tsaid = FZN_TRUST_LINE_NONE;\n",
		"a self-anchored node is a working state and an unanchored one adopts whoever reaches it first, so reporting the first as the second invites an operator to fix a correct node into the dangerous one -- sec 201, and it is the mistake an earlier `default:` actually made",
	),
	(
		"trust-self-refuses-adopt",
		"trust/trust.c",
		"\t\tif (!(trust->source == FZN_TRUST_SELF && source == FZN_TRUST_PINNED)) {\n",
		"\t\tif (!(trust->source == FZN_TRUST_SELF)) {\n",
		"a self-rooted node must not be takeable by trust on first use, which is the whole reason sec 136 ships a node self-rooted rather than blank",
	),
	(
		"trust-self-permits-pin",
		"trust/trust.c",
		"\t\tif (!(trust->source == FZN_TRUST_SELF && source == FZN_TRUST_PINNED)) {\n",
		"\t\tif (1) {\n",
		"an operator pinning a real root over a self-root is the join, and refusing it would leave a self-rooted node unable to enter an estate at all",
	),
	(
		"trust-self-records-its-source",
		"trust/trust.c",
		"\treturn anchor(trust, own, FZN_TRUST_SELF, 0);\n",
		"\treturn anchor(trust, own, FZN_TRUST_PINNED, 0);\n",
		"a self-root recorded as pinned is indistinguishable from an estate an operator joined, which is the one distinction the source field exists to draw",
	),
	(
		"cli-prefix-needs-equals",
		"cli/cli.c",
		"\tif (arg[len] != '=')\n\t\treturn 0;\n",
		"\tif (0)\n\t\treturn 0;\n",
		"the matcher compares a prefix, so without this an option whose name merely starts with a known one is claimed and its value silently misread",
	),
	(
		"cli-product-bound-is-shared",
		"cli/cli.c",
		"\t\tif (!parse_u32(value, &number) || number == FZN_PRODUCT_NONE\n\t\t    || number > FZN_PRODUCT_MAX)\n",
		"\t\tif (!parse_u32(value, &number) || number == FZN_PRODUCT_NONE)\n",
		"the bound belongs to chain/service.h and a value this accepted that the module refuses fails much later and somewhere else -- the wildcard would let a node claim to be every product",
	),
	(
		"cli-overflow-bounded",
		"cli/cli.c",
		"\t\tif (value > 0xffffffffu)\n\t\t\treturn 0;\n",
		"\t\tif (0)\n\t\t\treturn 0;\n",
		"a long run of digits must be refused rather than wrapped, since a wrapped service or product is a valid-looking number nobody typed",
	),
	(
		"cli-duplicate-refused",
		"cli/cli.c",
		"\t\tif (cli->dir)\n\t\t\treturn FZN_CLI_ERR_DUPLICATE;\n",
		"\t\tif (0)\n\t\t\treturn FZN_CLI_ERR_DUPLICATE;\n",
		"two values for one setting is an ambiguous invocation, and silently keeping either is how a configuration bug survives somebody reading the command line",
	),
	(
		"fingerprint-never-truncated",
		"trust/trust.c",
		"\tif (cap < FZN_TRUST_FINGERPRINT_LEN)\n\t\treturn FZN_TRUST_ERR_MALFORMED;\n",
		"\tif (cap < 8u)\n\t\treturn FZN_TRUST_ERR_MALFORMED;\n",
		"a truncated fingerprint is indistinguishable from a whole one at a glance, and comparing a prefix is the security decision sec 140 refuses to take on a caller's behalf",
	),
	(
		"fingerprint-carries-every-byte",
		"trust/trust.c",
		"\tfor (i = 0; i < FZN_PUBKEY_LEN; i++) {\n",
		"\tfor (i = 0; i < FZN_PUBKEY_LEN - 1u; i++) {\n",
		"a fingerprint that drops a byte makes two keys differing only in it compare alike, which is the whole of what a user is asked to check",
	),
	(
		"trust-sources-do-not-read-alike",
		"trust/trust.c",
		"\tcase FZN_TRUST_ADOPTED:\n\t\treturn \"adopted on first contact\";\n",
		"\tcase FZN_TRUST_ADOPTED:\n\t\treturn \"configured out of band\";\n",
		"TOFU's weakness is the first contact, so an adopted anchor shown as configured tells a user it was checked when nobody checked it",
	),
	(
		"body-escapes-non-printable",
		"log/log.c",
		"\t\tif (body[i] >= 0x20u && body[i] <= 0x7eu) {\n",
		"\t\tif (body[i] != 0x00u) {\n",
		"a body carrying a newline and a plausible sequence would otherwise draw a second entry in a viewer that no issuer ever signed, and an escape byte would drive the terminal it is drawn on",
	),
	(
		"body-measured-before-written",
		"log/log.c",
		"\tif (cap < needed)\n\t\treturn FZN_LOG_ERR_MALFORMED;\n",
		"\tif (cap < 1u)\n\t\treturn FZN_LOG_ERR_MALFORMED;\n",
		"the rendering is measured before anything is written so a short buffer leaves the caller's as it found it rather than holding a line that stops mid-escape",
	),
	(
		"log-print-names-what-was-evicted",
		"cli/log_print.c",
		"\tif (first > 1u) {\n",
		"\tif (0) {\n",
		"a log evicts by design, so a viewer that lists what it holds and stops presents a shorter history as a complete one -- sec 141; it moved here from gui/log_view.cpp with the wording in sec 168, and now guards both screens at once",
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
	(
		"spool-span-proof-checked",
		"spool/spool.c",
		"\tif (fzn_blob_span_proof_verify(hash, span_root, first, count, spool->leaves, "
		"proof,\n\t                               proof_len, spool->root) != FZN_BLOB_OK)"
		"\n\t\treturn FZN_SPOOL_ERR_UNVERIFIED;\n",
		"\t(void)proof; (void)proof_len;\n",
		"a span is placed only when it proves against the root, or a stranger "
		"fills the store with bytes that assemble into nothing",
	),
	(
		"spool-span-bit-after-write",
		"spool/spool.c",
		"\t\tif (!spool->ops->write_at(spool->ops->ctx, offset_of(index), sealed[i],\n"
		"\t\t                          sealed_len[i]))\n"
		"\t\t\treturn FZN_SPOOL_ERR_BACKEND;\n",
		"\t\tbit_set(spool->present, index);\n"
		"\t\tif (!spool->ops->write_at(spool->ops->ctx, offset_of(index), sealed[i],\n"
		"\t\t                          sealed_len[i]))\n"
		"\t\t\treturn FZN_SPOOL_ERR_BACKEND;\n",
		"a bit set over a failed write is a hole next_missing skips and nothing "
		"re-requests -- a transfer that reports complete over a corrupt blob",
	),
	(
		"blob-geometry-exact-multiple",
		"blob/blob.c",
		"\tif (tail != 0u)\n\t\tleaves++;\n\telse\n\t\ttail = FZN_BLOB_LEAF_SIZE;\n",
		"\tleaves++;\n\tif (tail == 0u)\n\t\ttail = FZN_BLOB_LEAF_SIZE;\n",
		"a content length that is an exact multiple of the leaf size claiming one "
		"leaf too many -- the off-by-one every hand-written version of this makes "
		"once, and the reason the arithmetic is in the library rather than in each "
		"consumer",
	),
	(
		"blob-geometry-content-ceiling-is-inclusive",
		"blob/blob.c",
		"\tif (content_len > BLOB_MAX_CONTENT)\n\t\treturn FZN_BLOB_ERR_SHAPE;\n\n\tleaves = content_len / FZN_BLOB_LEAF_SIZE;",
		"\tif (content_len >= BLOB_MAX_CONTENT)\n\t\treturn FZN_BLOB_ERR_SHAPE;\n\n\tleaves = content_len / FZN_BLOB_LEAF_SIZE;",
		"content of exactly FZN_BLOB_MAX_LEAVES * FZN_BLOB_LEAF_SIZE is the largest this library addresses and geometry must answer it; >= refuses the largest legal blob. The test drove one byte past the ceiling, which > and >= reject alike. sec 308",
	),
	(
		"blob-extent-content-ceiling-is-inclusive",
		"blob/blob.c",
		"\tif (content_len > BLOB_MAX_CONTENT)\n\t\treturn FZN_BLOB_ERR_SHAPE;\n\tif (len == 0u)",
		"\tif (content_len >= BLOB_MAX_CONTENT)\n\t\treturn FZN_BLOB_ERR_SHAPE;\n\tif (len == 0u)",
		"the same content ceiling in extent_of, and the same endpoint: exactly the ceiling must be addressable, >= refuses it. sec 308",
	),
	(
		"blob-leaf-open-reads-the-whole-commitment",
		"blob/blob.c",
		"\tif (!fzn_ct_memeq(sealed, commitment, FZN_COMMITMENT_LEN)) {",
		"\tif (!fzn_ct_memeq(sealed, commitment, 1u)) {",
		"leaf_open checks the sealed leaf's embedded commitment against the derived one BEFORE the AEAD, because a plain AEAD is non-committing -- a ciphertext can be crafted to open under two keys. A prefix read lets a commitment matching on all but the last byte through, and the search for a colliding leaf shrinks to one byte. The commitment test bends byte 0, which a one-byte read catches; a last-byte near miss holds it. sec 317",
	),
	(
		"blob-proof-verify-reads-the-whole-root",
		"blob/blob.c",
		"\treturn fzn_ct_memeq(acc, root, FZN_BLOB_HASH_LEN) ? FZN_BLOB_OK : FZN_BLOB_ERR_PROOF;\n}\n\n/* See blob.h.",
		"\treturn fzn_ct_memeq(acc, root, 1u) ? FZN_BLOB_OK : FZN_BLOB_ERR_PROOF;\n}\n\n/* See blob.h.",
		"the verifier's final check must compare the WHOLE root, or a proof climbing to the real root verifies against a root one byte off it -- content pinned to a near-miss id. blob_fuzz catches a low-byte truncation but never flips only the last byte of root; a valid proof against a last-byte-flipped root holds it. sec 308",
	),
	(
		"blob-span-verify-reads-the-whole-root",
		"blob/blob.c",
		"\terr = finalise_root(hash, acc, leaf_count, acc);\n\tif (err != FZN_BLOB_OK)\n\t\treturn err;\n\n\treturn fzn_ct_memeq(acc, root, FZN_BLOB_HASH_LEN) ? FZN_BLOB_OK : FZN_BLOB_ERR_PROOF;\n}",
		"\terr = finalise_root(hash, acc, leaf_count, acc);\n\tif (err != FZN_BLOB_OK)\n\t\treturn err;\n\n\treturn fzn_ct_memeq(acc, root, 1u) ? FZN_BLOB_OK : FZN_BLOB_ERR_PROOF;\n}",
		"the span verifier's final check, same edge as proof_verify's one function over. sec 308",
	),
	(
		"blob-extent-refuses-not-clamps",
		"blob/blob.c",
		"\tif (offset >= content_len || len > content_len - offset)\n"
		"\t\treturn FZN_BLOB_ERR_MALFORMED;\n",
		"\tif (offset >= content_len)\n\t\treturn FZN_BLOB_ERR_MALFORMED;\n"
		"\tif (len > content_len - offset)\n\t\tlen = content_len - offset;\n",
		"a range running past the content CLAMPED rather than refused, which turns a "
		"caller's arithmetic bug into a short read it never hears about",
	),
	(
		"msg-have-range-bounded",
		"spool/message.c",
		"\t\tif (first > leaf_count || count > leaf_count - first)\n"
		"\t\t\treturn FZN_MSG_ERR_MALFORMED;\n\t\tout_ranges[at].first = first;\n",
		"\t\tout_ranges[at].first = first;\n",
		"a have-set naming leaves outside the blob, handed to a caller that will plan "
		"fetches from it -- caught by the unit case and independently by message_fuzz "
		"at case 2, which is two witnesses rather than one",
	),
	(
		"scrub-notices-rot",
		"spool/scrub.c",
		"\t\t\tif (memcmp(root, scrub->roots + cell * FZN_BLOB_HASH_LEN,\n"
		"\t\t\t           FZN_BLOB_HASH_LEN) != 0) {\n",
		"\t\t\tif (0 && memcmp(root, scrub->roots + cell * FZN_BLOB_HASH_LEN,\n"
		"\t\t\t           FZN_BLOB_HASH_LEN) != 0) {\n",
		"a scrub that reads every byte and compares nothing, which is what every "
		"clean-blob assertion in the suite would still pass against",
	),
	(
		"scrub-drops-only-its-own-cell",
		"spool/scrub.c",
		"\t\t\t\t(void)fzn_spool_forget(scrub->spool, first, len);\n",
		"\t\t\t\t(void)fzn_spool_forget(scrub->spool, 0u, scrub->spool->leaves);\n",
		"one rotted byte costing the whole blob instead of one cell -- a blast "
		"radius no test that only asks 'did it notice' can see",
	),
	(
		"scrub-unseals-what-it-drops",
		"spool/scrub.c",
		"\t\t\t\tbit_clear(scrub->sealed, cell);\n\t\t\t\tdropped++;\n",
		"\t\t\t\tdropped++;\n",
		"a dropped cell keeping its stale reference is one that can never be "
		"resealed, so the repair fetches good bytes and the scrub drops them again",
	),
	(
		"scrub-seals-only-whole-cells",
		"spool/scrub.c",
		"\t\tif (!bit_get(scrub->sealed, cell) && cell_is_whole(scrub->spool, first, len)) {\n",
		"\t\tif (!bit_get(scrub->sealed, cell)) {\n",
		"sealing a cell whose leaves have not all arrived, which records a reference "
		"over holes and fails a partial transfer that was never wrong",
	),
	(
		"spool-forget-corrects-have",
		"spool/spool.c",
		"\t\tbit_clear(spool->present, first + i);\n\t\tspool->have--;\n",
		"\t\tbit_clear(spool->present, first + i);\n",
		"a bitmap and a count that disagree, so fzn_spool_complete answers yes over "
		"a blob with holes -- the one lie that struct must never tell",
	),
	(
		"transfer-records-before-asking",
		"spool/transfer.c",
		"\t\tif (slot->live && overlaps(first, count, slot->first, slot->count))\n"
		"\t\t\treturn 1;\n",
		"\t\tif (0 && slot->live && overlaps(first, count, slot->first, slot->count))\n"
		"\t\t\treturn 1;\n",
		"two peers handed the same range, which every test with ONE peer passes -- "
		"fuzzypickles measured exactly this gap in their own suite",
	),
	(
		"transfer-delivery-verified",
		"spool/transfer.c",
		"\t\tif (!fzn_spool_has(transfer->spool, first + i))\n"
		"\t\t\treturn FZN_TRANSFER_ERR_UNKNOWN;\n",
		"\t\tif (0 && !fzn_spool_has(transfer->spool, first + i))\n"
		"\t\t\treturn FZN_TRANSFER_ERR_UNKNOWN;\n",
		"congestion control opening on work that never happened, because a claim of "
		"delivery was taken from a caller rather than asked of the store",
	),
	(
		"transfer-window-floor",
		"spool/transfer.c",
		"\tif (transfer->window == 0u)\n\t\ttransfer->window = 1u;\n",
		"\tif (0 && transfer->window == 0u)\n\t\ttransfer->window = 1u;\n",
		"a window at zero can ask for nothing and can therefore never learn the path "
		"recovered -- link/ demotes rather than deletes for the same reason",
	),
	(
		"transfer-not-slow-start",
		"spool/transfer.c",
		"\tif (transfer->successes < transfer->window)\n\t\treturn;\n",
		"\tif (transfer->successes < 1u)\n\t\treturn;\n",
		"one increase per SUCCESS rather than per window of successes doubles the "
		"window every window, which is slow start and is deliberately not done",
	),
	(
		"transfer-one-halving-per-event",
		"spool/transfer.c",
		"\t\tslot->live = 0u;\n\t\ttransfer->in_flight--;\n\t\tdropped++;\n",
		"\t\tslot->live = 0u;\n\t\ttransfer->in_flight--;\n\t\tdropped++;\n"
		"\t\ton_loss(transfer);\n",
		"one stalled peer holding four batches charged as four losses puts the window "
		"on its floor for a single event, which is what AIMD exists to avoid",
	),
	(
		"transfer-open-capacity-is-inclusive",
		"spool/transfer.c",
		"\tif (cap == 0u || cap > FZN_TRANSFER_MAX_ASSIGNS)\n\t\treturn FZN_TRANSFER_ERR_MALFORMED;",
		"\tif (cap == 0u || cap >= FZN_TRANSFER_MAX_ASSIGNS)\n\t\treturn FZN_TRANSFER_ERR_MALFORMED;",
		"a transfer opened with exactly FZN_TRANSFER_MAX_ASSIGNS slots is the widest window the protocol allows and must open. The guard sweep drives one past the ceiling; the endpoint was unbuilt (SLOTS is 8), so > could tighten to >= and make the maximal window impossible to open. sec 310",
	),
	(
		"transfer-touching-is-not-overlap",
		"spool/transfer.c",
		"\treturn a_first < b_first + b_count && b_first < a_first + a_count;",
		"\treturn a_first <= b_first + b_count && b_first < a_first + a_count;",
		"half-open ranges that touch share no leaf and must not count as overlapping. is_pending compares a new candidate against the lower-positioned pending ranges, so a < widened to <= treats the span beginning exactly where a pending one ends as already asked and skips it. The two-peer test only requires its ranges disjoint, which a farther pick satisfies. The mirror < is the unreachable half, a candidate never being lower than a pending range. sec 310",
	),
	(
		"seal-commitment-refuses-a-stranger",
		"wire/seal.c",
		"\tif (fzn_commitment_check(derived, situ_fzn_head_commitment_ptr(hv)) "
		"!= FZN_COMMITMENT_OK)\n\t\treturn FZN_SEAL_ERR_COMMITMENT;\n",
		"\tif (0 && fzn_commitment_check(derived, situ_fzn_head_commitment_ptr(hv)) "
		"!= FZN_COMMITMENT_OK)\n\t\treturn FZN_SEAL_ERR_COMMITMENT;\n",
		"the stranger filter's REFUSE arm, which fuzzypickles found covered on its "
		"accept arm and never once shown a frame it should reject -- an entry here "
		"because a filter called on every valid frame reads as thoroughly tested",
	),
	(
		"msg-have-refused-not-truncated",
		"spool/message.c",
		"\tif (range_count > cap)\n\t\treturn FZN_MSG_ERR_TOO_LARGE;\n",
		"\tif (range_count > cap)\n\t\trange_count = cap;\n",
		"a have-set truncated rather than refused reports a peer as holding less "
		"than it does, and the transfer re-fetches leaves that were there all along",
	),
	(
		"msg-type-separates-the-parsers",
		"spool/message.c",
		"\tif (bytes[FZN_MSG_OFF_TYPE] != (uint8_t)want)\n\t\treturn FZN_MSG_ERR_MALFORMED;\n",
		"\t(void)want;\n",
		"a seal proves who wrote the bytes and not which question they answer, so "
		"without the type byte a have and a want of compatible length are one "
		"message with two readings",
	),
	(
		"msg-data-length-exact",
		"spool/message.c",
		"\tif (len != need + body)\n\t\treturn FZN_MSG_ERR_MALFORMED;\n",
		"\tif (len < need + body)\n\t\treturn FZN_MSG_ERR_MALFORMED;\n",
		"bytes past the last leaf are a second encoding of one message, which is "
		"how a receiver that de-duplicates by bytes sees two spans where a peer sent one",
	),
	(
		"spool-plan-cuts-canonical",
		"spool/plan.c",
		"\t\tuint64_t take = fzn_blob_span_largest_at(spool->leaves, first, bound);\n",
		"\t\tuint64_t take = bound;\n",
		"a planned range must be a node of the tree, or a peer answering it has "
		"no single proof and the request costs 62% overhead instead of 0.68%",
	),
	# BATCH THIRTEEN, 2026-09-05: blob/'s span proofs, added with them.
	#
	# A FOURTH MUTATION WAS TRIED AND IS NOT HERE, because it was a no-op
	# rather than an uncaught defect: making the straddle branch descend
	# left instead of refusing changes nothing, since the walk still
	# cannot reach a straddling span and refuses one level later. It read
	# as "not caught" and was "not a mutation". Landing in the source is
	# not the same as changing the behaviour, which is one step past what
	# evidence.md's confirm-the-sabotage rule asks for.
	(
		"blob-span-exit-needs-count",
		"blob/blob.c",
		"\twhile (!(lo == first && n == count)) {\n",
		"\twhile (!(lo == first)) {\n",
		"a span is a node of the tree, so the walk stops when the subtree IS "
		"the span -- matching only its start would prove a different set",
	),
	(
		"blob-span-binds-leaf-count",
		"blob/blob.c",
		"\terr = finalise_root(hash, acc, leaf_count, acc);\n"
		"\tif (err != FZN_BLOB_OK)\n\t\treturn err;\n\n"
		"\treturn fzn_ct_memeq(acc, root, FZN_BLOB_HASH_LEN) ? FZN_BLOB_OK "
		": FZN_BLOB_ERR_PROOF;\n}\n",
		"\treturn fzn_ct_memeq(acc, root, FZN_BLOB_HASH_LEN) ? FZN_BLOB_OK "
		": FZN_BLOB_ERR_PROOF;\n}\n",
		"a span proof binds the leaf count like a leaf proof does, or a span "
		"from a differently-sized blob verifies",
	),
	(
		"blob-span-proof-length",
		"blob/blob.c",
		"\tif (sibling_count != depth)\n\t\treturn FZN_BLOB_ERR_SHAPE;\n",
		"\t(void)0;\n",
		"the depth is a function of the claim, so a proof of another length "
		"describes another tree and must be refused rather than truncated",
	),
	# BATCH TWELVE, 2026-09-05: record/ledger.c, added with the module.
	#
	# ALL SEVEN WERE RUN, AND THE FIRST RUN WAS A LIE. Two reported as not
	# caught, and the cause was in the test rather than the code: that
	# file's REQUIRE evaluated its condition twice, so
	# `REQUIRE(fzn_ledger_confirm(...) == OK)` re-confirmed the same
	# version on the second evaluation, the monotonic rule correctly called
	# it STALE, and the case returned there with 25 assertions never
	# running. The check count was identical either way. Nine other suites
	# already spelled REQUIRE safely; that one was typed from memory.
	(
		"ledger-monotonic",
		"record/ledger.c",
		"\t\tif (version <= ledger->entries[at].version) {\n",
		"\t\tif (0) {\n",
		"a late acknowledgement is reordering rather than retraction, so a "
		"confirmation must never move backwards",
	),
	(
		"ledger-lookup-reads-the-whole-peer",
		"record/ledger.c",
		"\t\tif (e->kind == kind && fzn_ct_memeq(e->peer, peer, FZN_PUBKEY_LEN)",
		"\t\tif (e->kind == kind && fzn_ct_memeq(e->peer, peer, 1u)",
		"the row lookup must read the WHOLE peer, or two peers agreeing on a prefix land in one row and a confirmation for one reads back as the other's -- a record withheld from a peer that never received it; the other cases separate their peers in the first byte, so only a last-byte near miss holds this. sec 302",
	),
	(
		"ledger-lookup-reads-the-whole-subject",
		"record/ledger.c",
		"\t\t    && fzn_ct_memeq(e->subject, subject, FZN_SUBJECT_LEN))",
		"\t\t    && fzn_ct_memeq(e->subject, subject, 1u))",
		"the row lookup must read the WHOLE subject, or two subjects agreeing on a prefix share one row and a confirmation for one is read back for the other. sec 302",
	),
	(
		"ledger-stale-reported",
		"record/ledger.c",
		"\t\t\treturn FZN_LEDGER_ERR_STALE;\n",
		"\t\t\treturn FZN_LEDGER_OK;\n",
		"a confirmation that went backwards is reported, not absorbed -- out "
		"of order acks are a fact about the network a caller may want",
	),
	(
		"ledger-unknown-is-behind",
		"record/ledger.c",
		"\treturn fzn_ledger_confirmed(ledger, peer, subject, kind) < current;\n",
		"\treturn ledger && fzn_ledger_confirmed(ledger, peer, subject, kind) < current;\n",
		"a peer never heard from is behind, because under-claiming costs a "
		"retransmission and over-claiming skips a delivery",
	),
	(
		"ledger-corrupt-answers-zero",
		"record/ledger.c",
		"\tif (corrupt(ledger) || !ledger->entries)\n\t\treturn 0u;\n\n"
		"\tat = find_row(ledger, peer, subject, kind);\n",
		"\tat = find_row(ledger, peer, subject, kind);\n",
		"a ledger that cannot be scanned must not report a peer current on the "
		"strength of rows nobody can read",
	),
	(
		"ledger-confirm-null-entries",
		"record/ledger.c",
		"\tif (corrupt(ledger) || !ledger->entries)\n"
		"\t\treturn FZN_LEDGER_ERR_MALFORMED;\n",
		"\tif (corrupt(ledger))\n\t\treturn FZN_LEDGER_ERR_MALFORMED;\n",
		"corrupt() reports `used == 0 && !entries` sound, so the operand beside "
		"it is all that stops a write through a null array "
		"(caught by the crash, which is a weaker catch than a message)",
	),
	(
		"ledger-version-zero",
		"record/ledger.c",
		"\tif (version == 0u)\n\t\treturn FZN_LEDGER_ERR_MALFORMED;\n",
		"\t(void)0;\n",
		"zero is what an absent row answers, so storing it would make "
		"'confirmed nothing' and 'never heard of' one state",
	),
	(
		"ledger-init-zeroes-entries",
		"record/ledger.c",
		"\tmemset(entries, 0, capacity * sizeof(*entries));\n",
		"\t(void)0;\n",
		"sec 39's convention: a fresh table must not hold what the caller's "
		"memory held",
	),
	(
		"ledger-full-refuses",
		"record/ledger.c",
		"\tif (ledger->used >= ledger->capacity) {\n",
		"\tif (0) {\n",
		"nothing here expires, so a full ledger refuses rather than "
		"overwriting somebody's confirmation",
	),
	# BATCH ELEVEN, 2026-09-05: chain/chain_store.c, added with the module so
	# it is never a source with no entries, and extended the same day after
	# an independent review found four more properties nothing held.
	#
	# EVERY ONE OF THE NINE WAS RUN AGAINST THE SUITE BEFORE BEING WRITTEN
	# DOWN. The first version of this comment said "all three" and three
	# entries followed it; four `chain-store-offer-*` entries were added in
	# a later commit and the sentence was not, so a reader could not tell
	# whether those had been run or written from the code. They had been
	# run. Two reviewers reported the discrepancy independently, which is
	# the argument for the sentence naming a COUNT rather than a list.
	#
	# `chain-store-verify-first` takes the binary down with a SIGSEGV rather
	# than a message. It still fails the run, and it is a weaker catch than
	# the others, and it is recorded as such rather than counted level.
	(
		"chain-store-init-zeroes-entries",
		"chain/chain_store.c",
		"\tmemset(entries, 0, capacity * sizeof(*entries));\n",
		"\t(void)0;\n",
		"a fresh store must not hold what the caller's memory held -- sec 39's "
		"convention, and an entry here is a 1434-byte buffer lookup points into",
	),
	(
		"chain-store-evicts-only-the-dead",
		"chain/chain_store.c",
		"\t\tif (fzn_chain_expired_at(c, now))\n"
		"\t\t\treturn at;\n",
		"\t\t(void)now;\n\t\treturn at;\n",
		"eviction spends a dead entry and never a live one, or which chain a "
		"host holds depends on the order they arrived in",
	),
	(
		"chain-store-evicts-at-all",
		"chain/chain_store.c",
		"\t\t\tat = find_expired(store, now);\n",
		"\t\t\tat = store->used;\n",
		"a store holding nothing but expired chains must take a live one rather "
		"than refusing for ever",
	),
	(
		"chain-store-lookup-len-bound",
		"chain/chain_store.c",
		"\tif (e->len > FZN_CHAIN_MAX_LEN)\n\t\treturn 0;\n",
		"\t(void)0;\n",
		"a length past the entry's own buffer must not reach a caller who may "
		"write() it to a peer; corrupt() reaches store shape and not this",
	),
	(
		"chain-store-lookup-len-is-inclusive",
		"chain/chain_store.c",
		"\tif (e->len > FZN_CHAIN_MAX_LEN)\n\t\treturn 0;\n",
		"\tif (e->len >= FZN_CHAIN_MAX_LEN)\n\t\treturn 0;\n",
		"a chain of FZN_CHAIN_MAX_HOPS hops packs to exactly FZN_CHAIN_MAX_LEN, so the bound admits a maximal chain and refuses only a length past the buffer; >= refuses the largest chain the store can hold, and the host re-fetches one it has. Every other case admits a one- or two-hop chain, well short of the bound. sec 304",
	),
	(
		"chain-store-expiry",
		"chain/chain_store.c",
		"\tif (fzn_chain_expired_at(&e->chain, now))\n"
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
	# Three from chain_store_fuzz's near-miss block (sec 281). find_entry
	# matches the lookup key on (root, capability, grantee) with three
	# whole-field compares; a prefix read would return a cached chain for a
	# triple it was not verified for. The fuzz loop's keys differ in byte 0,
	# so only the near-miss block -- four chains differing in one last byte --
	# reaches each.
	(
		"chain-store-root-whole",
		"chain/chain_store.c",
		"fzn_ct_memeq(e->chain.root, root, FZN_PUBKEY_LEN)",
		"fzn_ct_memeq(e->chain.root, root, 1u)",
		"the cached-chain lookup must compare the WHOLE root, or two roots agreeing on a prefix share a cached authorisation; held by chain_store_fuzz's near-miss block, whose fuzz-loop roots differ in byte 0",
	),
	(
		"chain-store-capability-whole",
		"chain/chain_store.c",
		"fzn_ct_memeq(e->chain.capability.b, capability->b, FZN_CAP_ID_LEN)",
		"fzn_ct_memeq(e->chain.capability.b, capability->b, 1u)",
		"the cached-chain lookup must compare the WHOLE capability id, or a chain cached for one capability answers a lookup for another sharing a prefix",
	),
	(
		"chain-store-grantee-whole",
		"chain/chain_store.c",
		"fzn_ct_memeq(e->chain.grantee, subject, FZN_PUBKEY_LEN)",
		"fzn_ct_memeq(e->chain.grantee, subject, 1u)",
		"the cached-chain lookup must compare the WHOLE grantee, or a chain cached for one subject answers a lookup for another sharing a prefix",
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
	# BATCH ELEVEN, 2026-09-06: the subsystem hint, sec 153. A relay reads a
	# claim it cannot check, so what needs holding to account is not the
	# reading but the three things that keep an unverifiable field safe --
	# the ceiling actually clamps, a refusal is told apart from an
	# exhaustion, and a service too large to fit is refused rather than
	# quietly aliased onto another one.
	(
		"relay-policy-first-match",
		"wire/relay.c",
		"		if (policy[i].service == hinted) {\n\t\t\t*out = policy[i].allowed;\n\t\t\tbreak;\n\t\t}\n",
		"		if (policy[i].service == hinted)\n\t\t\t*out = policy[i].allowed;\n",
		"a shadowed duplicate must not win over the entry a caller put first",
	),
	(
		"relay-policy-refused",
		"wire/relay.c",
		"	if (*out == 0)\n\t\treturn FZN_RELAY_ERR_REFUSED;\n",
		"	/* sabotage */\n",
		"a subsystem this host declines must be distinguishable from a frame "
		"whose budget ran out on its own",
	),
	(
		"relay-hint-not-truncated",
		"wire/seal.c",
		"	if (what->service_hint > FZN_RELAY_SERVICE_MAX)\n\t\treturn FZN_SEAL_ERR_MALFORMED;\n",
		"	/* sabotage */\n",
		"a service too large to hint must be refused, not truncated onto "
		"another service no host downstream could tell it from",
	),
	# BATCH TWELVE, 2026-09-06: the cross-host copy, sec 154. The first is
	# the security property -- an offer that leaves the catalogue turns a
	# want list into a request for any blob whose hash a peer can name --
	# and the second is the correction sec 152 needed, since a holdings
	# announcement that reads the retention table publishes an intention as
	# though it were a fact.
	# BATCH THIRTEEN, 2026-09-06: planned deletion, sec 155. Every entry
	# here guards a way of losing data rather than a way of being untidy,
	# which is why the module exists at all: deleting one file at a time as
	# a mark is set gets each of these wrong, and none of them announces
	# itself afterwards.
	# BATCH FOURTEEN, 2026-09-06: reachability, sec 156. The module proposes
	# deletions, so every guard here is a way of proposing to delete
	# something live -- and the two that matter most are the frontier check,
	# which is the whole discriminator between "nobody links this" and "I
	# have not caught up", and the scratch refusal, whose absence turns
	# reachable nodes into candidates.
	# BATCH FIFTEEN, 2026-09-06: the deletion schedule, sec 157. A deadline
	# that fires early deletes something somebody was still keeping, and one
	# that never fires is a feature that silently does nothing -- so both
	# directions are held, and so is the field that stops a promise to
	# delete turning into a promise to keep.
	# BATCH SIXTEEN, 2026-09-07: the QR encoder, sec 160. Only the guards a
	# SHAPE test can hold are here -- the timing pattern that must not run
	# over a finder, and the dark module. What makes the encoder produce a
	# READABLE code is held by `make qrcheck` against quirc, which this
	# harness cannot run because it needs a sibling checkout.
	(
		"qr-timing-spares-the-finder",
		"qr/qr.c",
		"\tfor (i = 8u; i + 8u < size; i++) {\n",
		"\tfor (i = 0u; i < size; i++) {\n",
		"the timing pattern must not run over the finders, or the code stops "
		"being findable at all",
	),
	(
		"qr-dark-module",
		"qr/qr.c",
		"\tset_fixed(m, size, 8u, size - 8u, 1u);\n",
		"\t/* sabotage */\n",
		"the dark module is always set, and a format reservation one cell too "
		"long is what clears it",
	),
	# BATCH SEVENTEEN, 2026-09-07: the terminal spelling, sec 163. The
	# filled block is the LIGHT module, because a glyph is drawn light on a
	# dark background and the inverse is the photographic negative of the
	# code -- which sec 163 measured a decoder refusing outright.
	(
		"qr-print-filled-is-light",
		"cli/qr_print.c",
		"\treturn invert ? dark : !dark;\n",
		"\treturn invert ? !dark : dark;\n",
		"the filled block is the light module, or a terminal draws the "
		"negative of the code and no scanner reads it",
	),
	(
		"qr-print-odd-row-is-light",
		"cli/qr_print.c",
		"\tif (mx < 0 || my < 0 || mx >= (int)size || my >= (int)size)\n\t\tdark = 0;\n",
		"\tif (mx < 0 || my < 0 || mx >= (int)size || my >= (int)size)\n\t\tdark = 1;\n",
		"everything outside the code is quiet zone and must be light, which is "
		"also what fills the half row an odd height leaves over",
	),
	# BATCH EIGHTEEN, 2026-09-07: the configuration form, sec 164. The
	# guard is that a refusal leaves NOTHING applied -- a caller handed half
	# a configuration has one that was never asked for, and every field
	# before the bad one would be in it.
	(
		"config-refusal-applies-nothing",
		"gui/config_view.cpp",
		"\t\t\tfzn_cli_init(cli);\n\t\t\treturn err;\n\t\t}\n\t}\n\n\t{\n\t\tconst QByteArray arg =",
		"\t\t\treturn err;\n\t\t}\n\t}\n\n\t{\n\t\tconst QByteArray arg =",
		"a refused apply must leave nothing applied, or a caller acts on half "
		"a configuration nobody asked for",
	),
	# BATCH NINETEEN, 2026-09-07: the permissions view, sec 165. Both guards
	# are about a screen that would look right while saying something the
	# library does not: an origin row the widget decided for itself, and an
	# unspelled policy rendered as though somebody had written it.
	# Two zero-lifetime boundaries (sec 284). A grant expiring the instant it
	# was issued never had a valid moment; the existing test uses a gap
	# (5000 vs 4000), so <= could weaken to < and still refuse it -- only
	# issued == expires tells them apart. Held on both sides now.
	(
		"chain-verify-zero-lifetime",
		"chain/chain.c",
		"if (expires_at <= fzn_hop_issued_at(hop))",
		"if (expires_at < fzn_hop_issued_at(hop))",
		"the verifier must refuse a hop expiring the instant it was issued; weakened to < it accepts a zero-lifetime grant, held only by a fixture whose expires equals its issued and whose clock is below both",
	),
	(
		"chain-mint-zero-lifetime",
		"chain/chain.c",
		"if (expires_at != FZN_NO_EXPIRY && expires_at <= issued_at)",
		"if (expires_at != FZN_NO_EXPIRY && expires_at < issued_at)",
		"the minter refuses a zero-lifetime grant at the same boundary, so the mistake is caught where it is made rather than at the far end of a network",
	),
	(
		"chain-expired-at-compares-the-sentinel",
		"chain/chain.c",
		"\treturn chain->expires_at != FZN_NO_EXPIRY && chain->expires_at <= now;\n",
		"\treturn chain->expires_at <= now;\n",
		"FZN_NO_EXPIRY is 0, so dropping the comparison against it does not "
		"weaken the test but inverts it for every chain that never expires",
	),
	(
		"log-print-escapes-the-body",
		"cli/log_print.c",
		"\t\t} else {\n\t\t\tput_str(s, text);\n\t\t}\n",
		"\t\t} else {\n\t\t\tput(s, (const char *)window[i]->body,"
		" window[i]->body_len);\n\t\t}\n",
		"a body must reach a terminal escaped, or a newline in it draws an "
		"entry nobody signed and an escape byte drives the terminal",
	),
	(
		"log-print-unrenderable-is-said",
		"cli/log_print.c",
		"\t\t\tput_str(s, \"(unrenderable body)\");\n",
		"\t\t\t;\n",
		"a body that will not render costs a note and not a line, since a row "
		"missing from a list reads as a record that was never appended",
	),
	(
		"log-print-window-is-the-tail",
		"cli/log_print.c",
		"\t\tuint64_t since = last > (uint64_t)rows ? last - (uint64_t)rows : 0u;\n",
		"\t\tuint64_t since = 0u;\n",
		"a window must show the newest entries, or the summary calls the oldest "
		"ones the newest",
	),
	(
		"log-print-window-is-declared",
		"cli/log_print.c",
		"\tif (more_held && got > 0) {\n",
		"\tif (0) {\n",
		"a window shorter than the log must say so, or a tail is presented as "
		"the whole of what is held",
	),
	(
		"log-print-empty-is-the-logs-range",
		"cli/log_print.c",
		"\tif (last == 0u) {\n",
		"\tif (got == 0u) {\n",
		"whether a log holds nothing is the log's range and not what the caller "
		"asked for, or a summary-only call reports a full log as empty",
	),
	(
		"log-print-names-what-only-the-journal-knows",
		"cli/log_print.c",
		"\t\tif (next > 1u) {\n",
		"\t\tif (0) {\n",
		"an entirely evicted stream must report what was received, or it reads "
		"exactly like a stream this host never followed",
	),
	(
		"log-print-refuses-a-buffer-too-small",
		"cli/log_print.c",
		"\t\t*len_out = measure.used + 1u;\n\t\treturn FZN_LOG_ERR_MALFORMED;\n",
		"\t\t*len_out = measure.used + 1u;\n\t\treturn FZN_LOG_OK;\n",
		"a buffer that cannot hold the result is refused rather than reported "
		"as a success over bytes nobody wrote",
	),
	(
		"log-print-says-the-size-it-needed",
		"cli/log_print.c",
		"\t\t*len_out = measure.used + 1u;\n",
		"\t\t*len_out = 0u;\n",
		"a refusal must say how much room it wanted, or a caller has no way to "
		"size and retry",
	),
	(
		"log-view-shows-the-librarys-words",
		"gui/log_view.cpp",
		"\tsummary_->setText(trimmed(text));\n",
		"\tsummary_->setText(QStringLiteral(\"%1 rows\").arg((qulonglong)rows));\n",
		"the widget must SHOW cli/log_print's summary rather than have its own, "
		"or one screen has two wordings again with nothing comparing them",
	),
	(
		"log-view-declares-the-window-it-settled-on",
		"gui/log_view.cpp",
		"\tif (fzn_log_summary(log, journal, issuer, stream, rows, text, sizeof(text),"
		" &len) !=\n",
		"\tif (fzn_log_summary(log, journal, issuer, stream, FZN_LOG_VIEW_ROWS, text,"
		" sizeof(text), &len) !=\n",
		"a summary must describe the window that fit rather than the one that was "
		"wanted, or a shortened view declares rows that are not on the screen",
	),
	(
		"qr-codewords-bound-is-checked-not-trusted",
		"qr/qr.c",
		"#define QR_CODEWORDS_MAX 655u\n",
		"#define QR_CODEWORDS_MAX 654u\n",
		"the constant sizing the codeword buffers must be compared against the "
		"table rather than trusted to match it, since nothing else can catch a "
		"typed value that has to equal a table entry",
	),
	(
		"provision-view-code-level-is-forced",
		"gui/provision_view.cpp",
		"\treturn FZN_QR_LEVEL_L;\n",
		"\treturn FZN_QR_LEVEL_M;\n",
		"a card fits a QR code at level L and at no other, so the level is a "
		"measured constraint rather than a preference",
	),
	(
		"chain-store-sound-is-the-guards-rule",
		"chain/chain_store.c",
		"\tif (store->used > store->capacity)\n\t\treturn 0;\n",
		"\tif (0)\n\t\treturn 0;\n",
		"the public predicate must be the same rule the internal guards use, or "
		"a consumer bounding a walk by it reads off the end of the array",
	),
	(
		"chain-store-sound-answers-for-null",
		"chain/chain_store.c",
		"int fzn_chain_store_sound(const fzn_chain_store_t *store)\n{\n\tif (!store)\n\t\treturn 1;\n",
		"int fzn_chain_store_sound(const fzn_chain_store_t *store)\n{\n\tif (!store)\n\t\treturn 0;\n",
		"a null store holds nothing, which is an answer -- calling it unreadable "
		"collapses an absent store into a corrupt one, which is chain/manifest.c's "
		"long-standing contract",
	),
	(
		"revocation-store-sound-is-the-guards-rule",
		"chain/revocation.c",
		"\tif (store->used > store->capacity)\n\t\treturn 0;\n",
		"\tif (0)\n\t\treturn 0;\n",
		"the public predicate must be the same rule covers and known fail closed "
		"on, or the answer a consumer bounds its walk by disagrees with the "
		"answer the library acts on",
	),
	(
		"state-sound-is-the-guards-rule",
		"state/state.c",
		"\treturn state && state->entries && state->used <= state->capacity;\n",
		"\treturn state != NULL;\n",
		"the public predicate must be the rule the mutating paths already use, or "
		"a consumer bounding a walk by it disagrees with what the library accepts",
	),
	(
		"sync-print-unmeasured-is-the-default",
		"cli/sync_print.c",
		"\tif (state_out)\n\t\t*state_out = FZN_SYNC_UNMEASURED;\n",
		"\tif (state_out)\n\t\t*state_out = FZN_SYNC_UP_TO_DATE;\n",
		"a caller that ignores the state must see the conservative answer, or a "
		"refused render leaves a health check reading green",
	),
	(
		"sync-print-asks-whether-it-can-say",
		"cli/sync_print.c",
		"\tif (!fzn_manifest_overflowed(state, issuer)) {\n",
		"\tif (1) {\n",
		"up to date and cannot say both have a deficit of zero, and a health "
		"check told the number would call an unmeasurable host green",
	),
	(
		"sync-print-state-is-required",
		"cli/sync_print.c",
		"\tif (!issuer || !out || !len_out || !state_out)\n",
		"\tif (!issuer || !out || !len_out)\n",
		"an optional out-parameter is one every caller ignores, and this is the "
		"one a health check must not",
	),
	(
		"journal-print-reports-the-table",
		"cli/journal_print.c",
		"\t\ttable = used >= capacity ? FZN_JOURNAL_TABLE_FULL : FZN_JOURNAL_TABLE_ROOM;\n",
		"\t\ttable = FZN_JOURNAL_TABLE_ROOM;\n",
		"a caller asks about one stream and no row it could ask about says the "
		"table is full, so the condition is invisible unless reported unasked",
	),
	(
		"journal-print-untracked-is-not-fresh",
		"cli/journal_print.c",
		"\t\tif (!row) {\n",
		"\t\tif (0) {\n",
		"fzn_journal_next answers 1 for a peer never seen AND for a followed "
		"stream that has said nothing, and only one of them is listening",
	),
	(
		"journal-print-states-are-required",
		"cli/journal_print.c",
		"\tif (!journal || !issuer || !out || !len_out || !stream_out || !table_out)\n",
		"\tif (!journal || !issuer || !out || !len_out || !stream_out)\n",
		"the table's state is the one a caller did not think to ask for, so making "
		"it optional is making it absent",
	),
	(
		"sync-view-shows-the-printers-words",
		"gui/sync_view.cpp",
		"\t\tstate_label_->setText(text);\n",
		"\t\tstate_label_->setText(QStringLiteral(\"synced\"));\n",
		"the widget must SHOW cli/sync_print's line rather than have a wording of "
		"its own, or one screen has two implementations again -- sec 168's "
		"duplication, re-created by writing a CLI counterpart for an existing "
		"widget and removed in sec 193",
	),
	(
		"journal-view-shows-the-printers-words",
		"gui/journal_view.cpp",
		"\t\tstate_label_->setText(text);\n",
		"\t\tstate_label_->setText(QStringLiteral(\"ok\"));\n",
		"the widget must SHOW cli/journal_print's line, including the table "
		"condition a caller did not ask about, rather than composing its own",
	),
	(
		"sweep-print-held-back-is-not-empty",
		"cli/sweep_print.c",
		"\t\t\tsaid = (plan->retained > 0u || plan->last_copy > 0u ||\n"
		"\t\t\t        plan->incomplete > 0u)\n",
		"\t\t\tsaid = (0)\n",
		"sweep.h keeps its counters apart because a sweep held back by a guard "
		"and a catalogue with nothing in it want opposite responses, and in an "
		"alerting rule only one of them needs anybody to act",
	),
	(
		"sweep-print-does-not-advance",
		"cli/sweep_print.c",
		"\t\tif (job && fzn_catalog_sweep_progress(job, &done, &total) == FZN_CATALOG_OK)\n",
		"\t\tif (job && (fzn_catalog_sweep_advance((fzn_catalog_sweep_t *)job), 1) &&\n"
		"\t\t    fzn_catalog_sweep_progress(job, &done, &total) == FZN_CATALOG_OK)\n",
		"reporting a sweep must not advance its cursor: _advance is called AFTER "
		"the bytes are gone, so a reporter that called it records a removal that "
		"never happened",
	),
	(
		"sweep-print-names-each-reason",
		"cli/sweep_print.c",
		"\tif (plan->last_copy > 0u) {\n",
		"\tif (0) {\n",
		"each reason calls for a different action, so they are named rather than "
		"summed -- last_copy means more replicas, not more sweeping",
	),
	(
		"sweep-print-truncation-is-independent",
		"cli/sweep_print.c",
		"\t\ttruncated = plan->truncated > 0u;\n",
		"\t\ttruncated = 0;\n",
		"a plan can be ready AND short at once, and short means every count "
		"beside it understates",
	),
	(
		"sweep-view-shows-the-printers-words",
		"gui/sweep_view.cpp",
		"\t\tstate_label_->setText(text);\n",
		"\t\tstate_label_->setText(QStringLiteral(\"idle\"));\n",
		"the widget must SHOW cli/sweep_print's line rather than have a wording "
		"of its own -- sec 193's rule, applied in the same commit this time",
	),
	(
		"transfer-print-does-not-reclaim",
		"cli/transfer_print.c",
		"\t\t\tin_flight = fzn_transfer_in_flight(transfer);\n",
		"\t\t\tin_flight = fzn_transfer_in_flight(transfer);\n"
		"\t\t\t(void)fzn_transfer_expire((fzn_transfer_t *)transfer, now);\n",
		"asking a host for status must not change it: fzn_transfer_expire "
		"reclaims a peer's outstanding ranges, so a reporter that called it makes "
		"the transfer depend on whether anybody ran a health check",
	),
	(
		"transfer-print-idle-is-not-stalled",
		"cli/transfer_print.c",
		"\t\telse if (held == 0u)\n",
		"\t\telse if (0)\n",
		"not started, stalled and complete all read in_flight == 0, and an "
		"alerting rule told only the count pages about a finished download and "
		"ignores a stuck one",
	),
	(
		"transfer-print-complete-is-the-librarys-answer",
		"cli/transfer_print.c",
		"\t\tif (fzn_spool_complete(spool))\n",
		"\t\tif (0)\n",
		"a finished transfer must not report as a stalled one, which is what it "
		"becomes when completion is not detected",
	),
	(
		"transfer-view-shows-the-printers-words",
		"gui/transfer_view.cpp",
		"\t\tstate_label_->setText(text);\n",
		"\t\tstate_label_->setText(QStringLiteral(\"busy\"));\n",
		"the widget must SHOW cli/transfer_print's line rather than have a wording "
		"of its own -- sec 193's rule, applied in the same commit",
	),
	(
		"capability-print-revoked-asks-covers",
		"cli/capability_print.c",
		"\t\tif (fzn_revocation_covers(revocations, chain->root, &chain->capability,\n",
		"\t\tif (fzn_revocation_known(revocations, chain->root, &chain->capability,\n",
		"revoked is the authorization question and `known` is the replication "
		"one; asking the wrong one reports a RESTORED capability as cut off",
	),
	(
		"capability-print-expiry-asks-the-library",
		"cli/capability_print.c",
		"\t\telse if (fzn_chain_expired_at(chain, now))\n",
		"\t\telse if (chain->expires_at <= now)\n",
		"FZN_NO_EXPIRY is 0, so the obvious comparison reports every chain that "
		"never expires as the most expired thing a host holds",
	),
	(
		"capability-print-revocation-wins-over-expiry",
		"cli/capability_print.c",
		"\t\tif (fzn_revocation_covers(revocations, chain->root, &chain->capability,\n"
		"\t\t                          chain->grantee))\n",
		"\t\tif (!fzn_chain_expired_at(chain, now) &&\n"
		"\t\t    fzn_revocation_covers(revocations, chain->root, &chain->capability,\n"
		"\t\t                          chain->grantee))\n",
		"a chain both expired and revoked must report the revocation: expiry wants "
		"renewing and a revocation is a decision, so renewing it would be exactly "
		"the wrong response",
	),
	(
		"capability-view-shows-the-printers-words",
		"gui/capability_view.cpp",
		"\t\tstate_label_->setText(text);\n",
		"\t\tstate_label_->setText(QStringLiteral(\"held\"));\n",
		"the widget must SHOW cli/capability_print's line rather than have a "
		"wording of its own -- sec 193's rule",
	),
	(
		"state-print-cleared-is-not-never-set",
		"cli/state_print.c",
		"\t\t\tsaid = row ? FZN_STATE_CELL_CLEARED : FZN_STATE_CELL_NEVER_SET;\n",
		"\t\t\tsaid = FZN_STATE_CELL_NEVER_SET;\n",
		"fzn_state_get answers NULL for a tombstone and for a subject nobody set, "
		"deliberately, and a report must separate what a decision must not",
	),
	(
		"state-print-refuses-an-unreadable-state",
		"cli/state_print.c",
		"\tif (fzn_state_sound(st)) {\n",
		"\tif (1) {\n",
		"an unreadable state reported as unset invites writing over something "
		"nobody has looked at, which is the fail-open answer",
	),
	(
		"state-view-shows-the-printers-words",
		"gui/state_view.cpp",
		"\t\tstate_label_->setText(text);\n",
		"\t\tstate_label_->setText(QStringLiteral(\"unset\"));\n",
		"the widget must SHOW cli/state_print's line rather than have a wording of "
		"its own -- sec 193's rule",
	),
	(
		"revocation-print-withdrawn-is-not-in-force",
		"cli/revocation_print.c",
		"\t\t\t\tif (store->entries[i].withdrawn)\n",
		"\t\t\t\tif (0)\n",
		"a withdrawal replaces a revocation at its key rather than removing it, "
		"so counting rows reports every RESTORED capability as still cut off",
	),
	(
		"revocation-print-refuses-an-unreadable-store",
		"cli/revocation_print.c",
		"\tif (fzn_revocation_store_sound(store)) {\n",
		"\tif (1) {\n",
		"a store that cannot be walked reported as nothing-revoked is the "
		"fail-open answer: it claims every capability is fine when this host "
		"cannot say",
	),
	(
		"revocation-print-says-when-something-was-restored",
		"cli/revocation_print.c",
		"\t\tif (withdrawn > 0u) {\n",
		"\t\tif (0) {\n",
		"a capability that was cut off and is not any more is what somebody is "
		"looking for, and it is invisible in a total",
	),
	(
		"revocation-view-shows-the-printers-words",
		"gui/revocation_view.cpp",
		"\t\tstate_label_->setText(text);\n",
		"\t\tstate_label_->setText(QStringLiteral(\"clear\"));\n",
		"the widget must SHOW cli/revocation_print's line rather than have a "
		"wording of its own -- sec 193's rule",
	),
	(
		"authz-print-unspelled-is-its-own-state",
		"cli/authz_print.c",
		"\tif (policy && policy->spelled)\n",
		"\tif (policy)\n",
		"a policy nobody spelled and one written to refuse everything both deny, "
		"and only one of them is a configuration fault somebody has to find",
	),
	(
		"authz-print-asks-the-library",
		"cli/authz_print.c",
		"\t\tif (!fzn_authz_origin_permitted(*policy, ORIGINS[i].origin))\n",
		"\t\tif (!(policy->origins & FZN_ORIGIN_BIT(ORIGINS[i].origin)))\n",
		"the line must ASK which origins reach a kind rather than deciding, or "
		"there are two implementations of the rule that gates requests",
	),
	(
		"authz-print-guarded-is-not-unguarded",
		"cli/authz_print.c",
		"\tif (state == FZN_AUTHZ_LINE_UNGUARDED)\n",
		"\tif (0)\n",
		"a policy that has drifted to unguarded is a thing somebody has to be "
		"able to find, and it cannot be found if the line says the same for both",
	),
	(
		"authz-view-shows-the-printers-words",
		"gui/authz_view.cpp",
		"\t\tstate_label_->setText(text);\n",
		"\t\tstate_label_->setText(QStringLiteral(\"policy\"));\n",
		"the widget must SHOW cli/authz_print's line rather than have a wording of "
		"its own -- sec 193's rule",
	),
	(
		"provision-print-withholds-the-fingerprint",
		"cli/provision_print.c",
		"\tif (state >= FZN_PROVISION_LINE_UNDATED) {\n",
		"\tif (1) {\n",
		"a card that did not verify must put no root in a log: the recombined "
		"card gets that field RIGHT, and a logged fingerprint is read later by "
		"somebody who was not there",
	),
	(
		"provision-print-unchecked-is-its-own-state",
		"cli/provision_print.c",
		"\t\t\tif (!verifier) {\n",
		"\t\t\tif (0) {\n",
		"a card nobody was asked to check is not the same as one that failed a "
		"check, and only the second says anything about the card",
	),
	(
		"provision-print-undated-is-not-usable",
		"cli/provision_print.c",
		"\t\t\t\t\tsaid = now ? FZN_PROVISION_LINE_USABLE\n",
		"\t\t\t\t\tsaid = FZN_PROVISION_LINE_USABLE ? FZN_PROVISION_LINE_USABLE\n",
		"a card verified with no clock has not had its expiry looked at, so "
		"calling it in date reports a check that was never made",
	),
	(
		"provision-view-shows-the-printers-words",
		"gui/provision_view.cpp",
		"\t\tstate_label_->setText(whole);\n",
		"\t\tstate_label_->setText(QStringLiteral(\"card\"));\n",
		"the widget must SHOW cli/provision_print's line rather than have a "
		"wording of its own -- sec 193's rule",
	),
	(
		"provision-view-code-needs-a-card",
		"gui/provision_view.cpp",
		"\t\tif (!bytes || len == 0u ||\n\t\t    fzn_provision_open(bytes, len, &parsed) != FZN_PROVISION_OK)\n",
		"\t\tif (!bytes || len == 0u)\n",
		"fzn_provision_text will base32 any bytes of the right length, so rubbish "
		"would be drawn as a scannable code",
	),
	# BATCH TWENTY, 2026-09-10: constant_time's reach, sec 261. Added after
	# an audit that set out to write a fuzz harness for `fzn_ct_memeq` and
	# concluded it was not warranted -- the suite already answers. What the
	# audit found is that the answer rests on ONE test: 30.5 million calls
	# at ten lengths, and only record_test's tamper cases compare 64 bytes.
	# The two entries above hold the null operand and the accumulator's
	# SHAPE; nothing held its reach, which is the half a length-dependent
	# shortcut would break.
	(
		"ct-memeq-reaches-past-a-key",
		"constant_time/constant_time.c",
		"\tfor (size_t i = 0; i < len; i++)\n\t\tdiff |= (uint8_t)(pa[i] ^ pb[i]);\n",
		"\tif (len > 32u)\n\t\treturn 1;\n\n"
		"\tfor (size_t i = 0; i < len; i++)\n\t\tdiff |= (uint8_t)(pa[i] ^ pb[i]);\n",
		"a comparison that answers equal above the key length is invisible to "
		"every 16- and 32-byte caller; record_test's 64-byte signature is the "
		"only thing in the suite that can see it",
	),
	# BATCH TWENTY-ONE, 2026-09-10: which reason, sec 262. A sweep of the
	# 435 public functions for ones no test names left four, and this was
	# the one that was a gap rather than an accessor covered through its
	# caller.
	(
		"sched-a-missing-operand-blames-the-link",
		"sched/sched.c",
		"\t\treturn FZN_SCHED_EXCLUDED_MALFORMED;\n",
		"\t\treturn FZN_SCHED_EXCLUDED_UNUSABLE;\n",
		"both answers are non-ADMITTED, so fzn_sched_admits cannot tell them "
		"apart and neither can any printer state; it SURVIVED the whole suite "
		"until sched_test asked which reason",
	),
	# BATCH TWENTY-TWO, 2026-09-10: states nobody had ever seen, sec 263.
	# Both came from sweeping the 411 enumerators for ones no test names,
	# which is sec 262's question asked of states rather than functions.
	(
		"journal-print-exhausted-has-no-line",
		"cli/journal_print.c",
		"\tcase FZN_JOURNAL_STREAM_EXHAUSTED:\n"
		"\t\tput_str(s, \"exhausted, no next sequence\");\n"
		"\t\tbreak;\n",
		"",
		"an exhausted stream falls to the default and is drawn as a position it "
		"has not got; gui/journal_view_test.cpp covers the widget's own enum and "
		"only where Qt is present, so a GUI-less build saw nothing",
	),
	(
		"cli-asking-to-be-owner-becomes-auto",
		"cli/cli.c",
		"\t\t\twant = FZN_CLI_OWNER_YES;\n",
		"\t\t\twant = FZN_CLI_OWNER_AUTO;\n",
		"--fuzznet-owner=yes silently becomes the default; cli_test read back "
		"auto and no and never the third value",
	),
	# BATCH TWENTY-THREE, 2026-09-11: the catalogue's merge rule, sec 269.
	# catalog/ was the last module with no fuzz harness and now has one.
	# Both of these were SURVIVED by catalog_fuzz's first draft, whose
	# properties were edge-set convergence and link-only membership --
	# nearly vacuous, because a set of links makes every asserted edge
	# linked under almost any resolver. The single-issuer oracle is what
	# catches them, and sec 269 records the two that still survive it.
	# BATCH TWENTY-FOUR, 2026-09-11: the reachability walk, sec 270. Held
	# by catalog/test/reach_fuzz.c, which is a DIFFERENTIAL harness rather
	# than a property one -- a breadth-first search written from reach.h
	# against the walk in reach.c. sec 269 records why that distinction
	# decided what each harness could catch.
	# BATCH TWENTY-FIVE, 2026-09-11: the sweep protocol, sec 271. A third
	# kind of harness after sec 269's properties and sec 270's oracle: this
	# subject is a six-call protocol over a path that deletes bytes, and
	# what a random call sequence finds is an ordering fault.
	# BATCH TWENTY-SIX, 2026-09-11: the want walk, sec 272. Held by
	# catalog/test/copy_fuzz.c, a METAMORPHIC harness -- it checks things
	# the answer must not depend on rather than the answer, because a want
	# list's oracle would be a model of retention, holdings and inline
	# content, which is copy.c rewritten in the test.
	# BATCH TWENTY-SEVEN, 2026-09-11: batch assignment, sec 273. Held by
	# spool/test/transfer_fuzz.c, whose first draft could not hold this
	# property at all: it stubbed the store, so no delivery succeeded, so
	# the window stayed at its floor of one, so at most ONE assignment was
	# ever live and "no two overlap" compared each range against nothing.
	(
		"transfer-a-live-assignment-blocks-an-overlap",
		"spool/transfer.c",
		"\t\tif (slot->live && overlaps(first, count, slot->first, slot->count))\n",
		"\t\tif (0 && overlaps(first, count, slot->first, slot->count))\n",
		"the pending record is the ONLY mechanism producing disjoint ranges "
		"since the internal cursor was removed -- transfer.h says a property "
		"with two mechanisms is one no test can hold",
	),
	(
		"transfer-the-window-never-reaches-zero",
		"spool/transfer.c",
		"\ttransfer->window /= 2u;\n\tif (transfer->window == 0u)\n"
		"\t\ttransfer->window = 1u;\n",
		"\ttransfer->window /= 2u;\n",
		"a transfer whose window reaches zero can never ask for anything "
		"again, so it can never learn the path recovered",
	),
	# BATCH TWENTY-EIGHT, 2026-09-12: the store's shape check, sec 274. Four
	# entries already held placement and absent-versus-backend; none held
	# the check BEFORE placement, that what came back opens as a record at
	# all. record/test/store_fuzz.c found it by having its backend truncate
	# at random, and it is the one entry that harness earns.
	(
		"record-store-what-came-back-must-open",
		"record/store.c",
		"\tif (fzn_record_open(out, len, &record) != FZN_RECORD_OK)\n"
		"\t\treturn FZN_RECORD_STORE_ERR_SHAPE;\n",
		"\tif (fzn_record_open(out, len, &record) != FZN_RECORD_OK)\n"
		"\t\trecord.base = out, record.len = len;\n",
		"a backend that truncates hands back bytes that are not a record, and "
		"the placement check reads fields off a view that was never opened",
	),
	# BATCH TWENTY-NINE, 2026-09-12: the authorization decision, sec 277.
	# Held by chain/test/authz_fuzz.c, a decision table written from the
	# header that mints its own chains so it never asks the library whether
	# one verifies. Three entries already held unspelled, the origin gate
	# and the manifest; these two were not held.
	(
		"authz-no-chain-is-not-no-capability-required",
		"chain/authz.c",
		"\tif (!hops || hop_count == 0)\n\t\treturn FZN_AUTHZ_DENIED;\n",
		"\tif (!hops || hop_count == 0)\n\t\treturn FZN_AUTHZ_GRANTED_UNGUARDED;\n",
		"authz.h names this as exactly the case that must not be confusable: "
		"holding no chain for an issuer is an ordinary state, and a guarded kind "
		"met with no chain is a denial, not a kind that needed none",
	),
	(
		"authz-reads-what-verify-answered",
		"chain/authz.c",
		"\t                     manifest, &proven) != FZN_CHAIN_OK)\n"
		"\t\treturn FZN_AUTHZ_DENIED;\n",
		"\t                     manifest, &proven) != FZN_CHAIN_OK && 0)\n"
		"\t\treturn FZN_AUTHZ_DENIED;\n",
		"a chain for the wrong capability, an expired one, or one that does not "
		"verify at all would grant -- every refusal fzn_chain_verify can give "
		"passes through this one comparison",
	),
	(
		"relay-hop-floor-is-inclusive",
		"wire/relay.c",
		"frame_len < SITU_FZN_HOP_SIZE_MAX",
		"frame_len <= SITU_FZN_HOP_SIZE_MAX",
		"hop_view's floor is the five-byte hop header a relay reads without a "
		"key: SITU_FZN_HOP_SIZE_MAX is the smallest legal input, not a whole "
		"frame. Every relay_test case above passes a whole "
		"SITU_FZN_FRAME_SIZE_MIN datagram, so <= would refuse a bare hop header "
		"-- the one input hop_view exists to accept -- and the too-short case "
		"tested sits three bytes below the boundary, not one. sec 323",
	),
	(
		"peer-groups-cap-admits-the-maximum",
		"local/peer.c",
		"if (count == FZN_PEER_MAX_GROUPS)",
		"if (count == FZN_PEER_MAX_GROUPS - 1u)",
		"a Groups: line naming exactly FZN_PEER_MAX_GROUPS is a complete, "
		"KNOWN membership; the cap fires on the NEXT group, so - 1 marks a "
		"peer that names exactly the maximum unknown and denies it. The "
		"overflow test drives MAX+5 and every other parse case carries "
		"sixteen, so the accepted endpoint of the bound was untested. sec 325",
	),
	(
		"revocation-rerevoke-supersedes-reads-the-whole-id",
		"chain/revocation.c",
		"\t\t\tif (!fzn_ct_memeq(fzn_revocation_supersedes(record), entry->id,\n"
		"\t\t\t                  FZN_REVOCATION_ID_LEN)) {",
		"\t\t\tif (!fzn_ct_memeq(fzn_revocation_supersedes(record), entry->id,\n"
		"\t\t\t                  FZN_REVOCATION_ID_LEN - 1u)) {",
		"a genuinely new revocation over a withdrawal must chain to it -- its "
		"supersedes must equal the held id. supersedes is caller-set and "
		"signed, entry->id a computed hash, so a near miss is constructible; a "
		"prefix compare re-revokes a withdrawn pair on an id it does not name. "
		"The reissue cases drive only the exact id and a wholly different one. "
		"sec 326",
	),
	(
		"line-a-full-line-is-not-overlong",
		"local/line.c",
		"if (len > reader->cap - reader->used) {",
		"if (len >= reader->cap - reader->used) {",
		"the framing bound accepts a line exactly cap long -- the newline is "
		"not kept, so it needs no room of its own -- and refuses one byte more "
		"as OVERLONG. >= would refuse the full line, the frugal legal case. "
		"line_test drives exactly cap and cap+1. The local socket and line "
		"framer returned to fuzznet under sec 2's 2026-09-06 supersession.",
	),
	(
		"socket-path-must-be-absolute",
		"local/socket.c",
		"if (path[0] != '/')",
		"if (path[0] == '/')",
		"a local socket path must be absolute: a relative one names a socket "
		"in whatever directory the process happens to be in, which an attacker "
		"may reach. Inverting the test refuses every absolute path and admits "
		"relative ones; socket_test's live listener and its relative-path "
		"refusal catch it. Returned to fuzznet under sec 2's 2026-09-06 "
		"supersession.",
	),
	(
		"socket-path-check-reserves-the-temp-name",
		"local/socket.c",
		"if (len + TMP_SUFFIX_MAX >= SUN_PATH_LEN)",
		"if (len >= SUN_PATH_LEN)",
		"the longest bindable path is shorter than sun_path by the temporary "
		"name listen binds and renames over, and that headroom is invisible to "
		"a caller -- raidcfgd's --check approved a 107-byte path their daemon "
		"then refused. Dropping the reserve admits paths whose temporary name "
		"cannot fit, so the predicate and the bind disagree. socket_test finds "
		"the longest path the predicate accepts and requires listen to take "
		"it. sec 319",
	),
	(
		"socket-listen-asks-the-path-rule",
		"local/socket.c",
		"verdict = fzn_socket_path_ok(path);",
		"verdict = FZN_SOCKET_OK;",
		"listen asks the predicate rather than restating the rule, which is "
		"what makes a caller's dry run agree with the start it predicts. "
		"Assuming OK leaves only fill_addr's raw length guard, so a relative "
		"path is bound in whatever directory the process is in and a path past "
		"the reserve binds or not depending on this pid's width. socket_test "
		"requires ERR_PATH for both. sec 319",
	),
	(
		"udp-send-refuses-only-past-the-max",
		"net/udp.c",
		"len > FZN_UDP_DATAGRAM_MAX",
		"len >= FZN_UDP_DATAGRAM_MAX",
		"one frame per datagram: a sealed frame is exactly "
		"FZN_UDP_DATAGRAM_MAX (1168) at its largest, sized to fit the IPv6 "
		"minimum-MTU UDP payload, so the full frame must send. >= refuses it "
		"and forces the fragment the bound exists to avoid. udp_test rounds a "
		"1168-byte frame through and refuses 1169.",
	),
	(
		"udp-recv-needs-msg-trunc-to-see-truncation",
		"net/udp.c",
		"recvfrom(fd, buf, cap, MSG_TRUNC,",
		"recvfrom(fd, buf, cap, 0,",
		"MSG_TRUNC is what makes an oversize datagram report its true length "
		"rather than the copied prefix; without it a truncated frame is "
		"handed back as a short one, a different frame an attacker can craft. "
		"udp_test sends a full datagram into a 16-byte buffer and requires "
		"FZN_UDP_ERR_TRUNCATED.",
	),
	(
		"udp-resolve-refuses-a-name",
		"net/udp.c",
		"inet_pton(AF_INET, host, &v4.sin_addr) != 1",
		"inet_pton(AF_INET, host, &v4.sin_addr) < 0",
		"the remote hop resolves numeric addresses only -- no DNS, no "
		"discovery. inet_pton returns 0 for a name and 1 for a numeric "
		"address, so != 1 refuses a hostname while < 0 lets it through and "
		"builds a zero address. udp_test requires a hostname to be refused.",
	),
	(
		"node-same-user-needs-a-uid-match",
		"node/node.c",
		"peer->uid == config->uid",
		"peer->uid != config->uid",
		"the SAME_USER access method is the caller's uid matching the "
		"node's own. Inverting it calls a stranger the node's own user and "
		"the node's user a stranger. node_test drives a matching and a "
		"non-matching uid.",
	),
	(
		"node-local-needs-group-membership",
		"node/node.c",
		"== FZN_PEER_MEMBER",
		"!= FZN_PEER_MEMBER",
		"the LOCAL access method is membership of the service group. "
		"Inverting the verdict admits every non-member as LOCAL and denies "
		"every member. node_test drives a member and a non-member of the "
		"service group.",
	),
	(
		"node-serves-only-the-configured-local-origins",
		"node/node.c",
		"fzn_authz_unguarded(config->local_origins)",
		"fzn_authz_unguarded(FZN_ORIGIN_ANY)",
		"a local origin is granted only if the node serves it: "
		"authentication by the kernel is not authorisation. Widening the "
		"mask to ANY grants a kernel-authenticated origin the node was "
		"configured not to serve. node_test denies a LOCAL caller of a "
		"node that serves only SAME_USER.",
	),
	(
		"node-local-serve-answers-the-real-verdict",
		"node/local.c",
		"if (verdict == FZN_AUTHZ_DENIED)",
		"if (verdict != FZN_AUTHZ_DENIED)",
		"the status line the node writes must reflect the verdict it "
		"reached: a denied caller is told denied and a served one served. "
		"Inverting it tells a stranger they were served and the node's own "
		"user they were denied. local_test reads the reply over a real "
		"socketpair for each origin.",
	),
	(
		"node-local-serve-refuses-an-overlong-request",
		"node/local.c",
		"fzn_line_push(&reader, chunk, (size_t)n) != FZN_LINE_OK",
		"fzn_line_push(&reader, chunk, (size_t)n) == FZN_LINE_OK",
		"a request line is bounded: the framer returns OVERLONG at the cap "
		"and the node refuses rather than reading without bound. Inverting "
		"the test refuses every well-formed request as if it were overlong. "
		"local_test's served cases catch it.",
	),
	(
		"node-remote-frame-must-match-its-session",
		"node/remote.c",
		"memcmp(sender, peer->sender, FZN_PUBKEY_LEN) != 0",
		"memcmp(sender, peer->sender, FZN_PUBKEY_LEN) == 0",
		"the frame's clear sender must be the peer the daemon routed it to, "
		"or a session's key would be tried against another sender's frame. "
		"Inverting it drops the legitimate frame and admits the mismatched "
		"one. remote_test drives a matching and a wrong sender.",
	),
	(
		"node-remote-authenticates-by-opening-the-seal",
		"node/remote.c",
		"hash, aead, opened) != FZN_SEAL_OK",
		"hash, aead, opened) == FZN_SEAL_OK",
		"the remote hop authenticates cryptographically: a frame is this "
		"peer's only if it opens under the agreed session key. Inverting the "
		"test drops every frame that opens and admits every one that does "
		"not. remote_test grants a real frame and drops a tampered one.",
	),
	(
		"node-remote-authorises-as-remote",
		"node/remote.c",
		"FZN_ORIGIN_REMOTE, hops,\n",
		"FZN_ORIGIN_SAME_USER, hops,\n",
		"a network caller is authorised as FZN_ORIGIN_REMOTE, so the "
		"capability is checked against the wire origin rather than a local "
		"one. Deciding as SAME_USER runs the kernel-authenticated path for a "
		"caller the kernel never saw. remote_test grants a remote request.",
	),
	(
		"node-find-peer-matches-the-sender",
		"node/serve.c",
		"memcmp(peers[i].sender, sender, FZN_PUBKEY_LEN) == 0",
		"memcmp(peers[i].sender, sender, FZN_PUBKEY_LEN) != 0",
		"the daemon routes a datagram to the session whose sender matches "
		"the frame's. Inverting the match returns the wrong peer's session "
		"for a sender and none for the right one. serve_test looks up a "
		"present and an absent sender.",
	),
	(
		"node-provision-verifies-the-device-prekey",
		"node/provision.c",
		"device_prekey, id->sign, FZN_TRUST_PINNED, now)\n\t    != FZN_PREKEY_OK",
		"device_prekey, id->sign, FZN_TRUST_PINNED, now)\n\t    == FZN_PREKEY_OK",
		"a device is provisioned only if its prekey verifies -- the pin "
		"proves the device signed its own X25519 key. Flipping the test "
		"rejects a real device and would admit a forged prekey. "
		"provision_test provisions a genuine device end to end.",
	),
	(
		"node-accept-card-verifies-the-envelope",
		"node/provision.c",
		"fzn_provision_verify(card, device->sign, now) != FZN_PROVISION_OK",
		"fzn_provision_verify(card, device->sign, now) == FZN_PROVISION_OK",
		"a device provisions itself from a card only if the card's envelope "
		"verifies under the root it names, so a forged card is refused. "
		"Flipping the test refuses a genuine card and would accept a forged "
		"one. provision_test accepts a real card.",
	),
	(
		"node-reply-is-sealed-as-from-the-node",
		"node/remote.c",
		"what.sender = node_pubkey;",
		"what.sender = peer->sender;",
		"a reply is sealed as from the node, whose identity the caller "
		"established the session with. Sealing it as from the caller makes "
		"the reply claim the caller's identity, and a caller checking who "
		"answered would see itself. remote_test and provision_test both "
		"require the reply's sender to be the node.",
	),
	(
		"node-remote-admits-through-the-replay-window",
		"node/remote.c",
		"FZN_EXPIRY_REQUIRED, now) != FZN_FRESH_OK",
		"FZN_EXPIRY_REQUIRED, now) == FZN_FRESH_OK",
		"the authenticated frame's nonce is admitted into the replay window, "
		"and a nonce already seen -- or a stale or no-expiry command -- is "
		"dropped. Flipping the test drops every fresh frame and admits every "
		"replay. remote_test replays a captured frame; provision_test replays "
		"a datagram over UDP.",
	),
]

# Entries known to survive for a reason rather than through a gap. Listed so
# that a clean run reads as clean: an expected survivor reported as a finding
# every time is how a report stops being read. Removing an id from here is
# how you ask the question again.
EXPECTED_SURVIVORS = {
	"manifest-sig-zero-sign",
	"authz-print-asks-the-library",
	# CANNOT BE CAUGHT BY BEHAVIOUR, and that is a fact about the two
	# expressions rather than a gap in the suite. sec 165, and it MOVED
	# with the logic in sec 199 rather than being retired.
	#
	# `fzn_authz_origin_permitted` is `origin != FZN_ORIGIN_NONE &&
	# (origins & FZN_ORIGIN_BIT(origin))`, and only the three real origins
	# are ever asked about -- so the call and the open-coded bitmask agree
	# on every input either the printer or the widget can produce. A test
	# comparing the output against the library compares a copy of the rule
	# against the rule.
	#
	# THAT IT SURVIVED THE MOVE IS THE POINT. sec 199 consolidated the
	# widget onto the printer, and the mutation is no more catchable in one
	# place than it was in the other: the uncatchability was never about
	# WHERE the code lived, it was about the two expressions being equal
	# over the reachable inputs. Consolidation fixes duplication and does
	# not turn a structural guard into a behavioural one.
	#
	# THE GUARD IS STILL REAL AND IS STRUCTURAL: there must be ONE
	# implementation of reachability, because the day the library's answer
	# grows a condition -- as it already has one for FZN_ORIGIN_NONE -- a
	# copy stops agreeing and nothing says so.
	#
	# It would become catchable if anything ever reported FZN_ORIGIN_NONE,
	# which neither deliberately does.
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
	# EVERY KIND OF SOURCE, NOT ONLY THE ONES SPELLED `source`. The manifest
	# names the crypto bindings `binding ` and the file backends `backend `,
	# each with the macro that gates it -- so a census reading only `source `
	# excluded eight files, seven of which had never been sabotaged while
	# this printed a coverage figure. `record/store_file.c` had entries
	# anyway, which is what shows the exclusion was an artifact of the word
	# rather than a decision. project.md sec 221.
	#
	# A `backend ` line carries a second field (the macro), so the path is
	# the SECOND word and not the rest of the line.
	# AND THE FRONT ENDS, which were the last kind the census could not see.
	# sec 221 widened this to `binding` and `backend`; `subsystem` was still
	# outside it, and until sec 225 those lines named one file where the tree
	# has sixteen, so widening to them would have been widening to a wrong
	# list. Both are fixed together for that reason.
	#
	# A `subsystem` line carries the gating macro as its third field, exactly
	# as `backend` does, so the path is still the SECOND word.
	want = ("source ", "binding ", "backend ", "subsystem ")
	return [l.split()[1] for l in out.stdout.splitlines() if l.startswith(want)]


def code_header_list():
	"""The installed headers that carry executable code, from the same target.

	SOME HEADERS ARE CODE, and this census could not see them. A `static
	inline` body is compiled into every consumer's translation unit, so it
	is more exposed than a `.c` rather than less -- and `record/record.h`
	holds eleven of them, every accessor of the richest format here, with
	no entry against it while a figure over "92 of 93 sources" was
	printed. project.md sec 234.

	Which headers those are is decided by READING them rather than by a
	naming convention, for sec 217's reason: a population derived from a
	convention is an enumeration wearing a derivation's clothes. The
	manifest supplies the list of headers; their contents supply which of
	them hold code.

	Returns None on the same failures `source_list` does, and for the same
	reason -- a census that cannot read its population has not passed.
	"""
	try:
		out = subprocess.run(["make", "-s", "manifest"], cwd=ROOT, env=make_env(),
		                     capture_output=True, text=True, check=False)
	except OSError:
		return None
	if out.returncode != 0:
		return None
	found = []
	for line in out.stdout.splitlines():
		if not line.startswith("header "):
			continue
		rel = line.split()[1]
		path = os.path.join(ROOT, rel)
		if not os.path.exists(path):
			return None
		text = io.open(path, encoding="utf-8").read()
		if "\nstatic inline" in text or text.startswith("static inline"):
			found.append(rel)
	return found


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
	# AND THE HEADERS THAT ARE CODE, on the same terms.
	hdrs = code_header_list()
	if hdrs is None:
		print("sabotage: the header list could not be read, so header "
		      "coverage was NOT checked -- a failure rather than a skip, for "
		      "the reason above")
		bad += 1
		hdrs = []
	else:
		for hdr in hdrs:
			if hdr not in files and hdr not in NO_GUARDS:
				print("sabotage: %s carries inline bodies, has no entry and "
				      "is not listed as guard-free" % hdr)
				bad += 1

	if srcs is not None:
		for src in sorted(NO_GUARDS):
			if src not in srcs and src not in hdrs:
				print("sabotage: %s is listed as guard-free and is not a "
				      "library source or a header carrying code" % src)
				bad += 1

	if bad:
		print("sabotage: %d problem(s). A stale entry reports a guard as "
		      "defended without testing it; an uncovered source reports a "
		      "module as swept when nothing swept it." % bad)
		return 2
	# THE REPORT NAMES THE WHOLE POPULATION, because a figure that describes
	# a narrower one is how the headers went unnoticed: this line said "92 of
	# 93 sources" while `record/record.h` had never been touched. A count
	# that does not name its denominator is the same shape as a gate over an
	# empty list.
	print("sabotage: %d entries over %d of %d library, binding, backend and "
	      "front-end sources and %d of %d headers carrying inline bodies, "
	      "each naming exactly one site (nothing was built or changed)"
	      % (len(SABOTAGES), len(srcs) - len(NO_GUARDS), len(srcs),
	         len([h for h in hdrs if h not in NO_GUARDS]), len(hdrs)))
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
				# PREFER A FAILURE FROM THE SABOTAGED MODULE'S OWN
				# SUITE, because which line is shown was otherwise a
				# fact about RUN ORDER rather than about coverage.
				#
				# `named[-1]` is the last suite to fail, and the last
				# suite to run is arbitrary with respect to the file
				# that was broken. Measured 2026-09-06: breaking
				# `trust/trust.c` reported a failure from
				# `persist_test.c`, which reads as though trust's own
				# suite did not hold its own guard -- and it does, and
				# is the first to say so. The report sent a reader to
				# the wrong file.
				#
				# So it shows a line from a suite under the same
				# top-level directory as the sabotaged source when
				# there is one. When there is NOT, the line shown is
				# still another module's, and that is informative
				# rather than misleading: it says no test in this
				# module's own suite caught it, which is a gap worth
				# seeing.
				#
				# THREE RUNGS, BECAUSE THE PARAGRAPH ABOVE DESCRIBED
				# A DIRECTORY AND THE CODE MATCHED A STEM. That gap
				# cost a real report on 2026-09-06: breaking a guard
				# in `catalog/catalog.c` is caught by
				# `catalog/test/sweep_test.c`, whose stem is not
				# `catalog_test.c`, so the same-stem rung missed and
				# the fallback showed the LAST failure anywhere --
				# three lines below the assertion written for the
				# guard. The comment had said "same directory" all
				# along; only the code disagreed.
				#
				#   1. the suite named for the file, by this tree's
				#      convention that `<dir>/<stem>.c` is covered by
				#      `<dir>/test/<stem>_test.c`
				#   2. any suite under the same `<dir>/test/`, which
				#      is what the paragraph above always meant
				#   3. the FIRST failure anywhere, not the last: a
				#      run's first refusal is nearer the cause than
				#      its last, and both are arbitrary with respect
				#      to the broken file
				stem = os.path.basename(rel)[:-2] + "_test.c"
				mine = [ln for ln in named if stem in ln]
				if not mine:
					here = os.path.join(os.path.dirname(rel), "test")
					siblings = [f for f in os.listdir(here)
					            if f.endswith("_test.c")] \
						if os.path.isdir(here) else []
					mine = [ln for ln in named
					        if any(sib in ln for sib in siblings)]
				detail = (mine[0] if mine else named[0]).strip()[:70] if named else ""
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
