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
		"materialise-a-value-cannot-make-directories",
		"catalog/materialise.c",
		"if (value[i] == '/' || value[i] == '\\\\')",
		"if (0)",
		"the pattern is the OPERATOR's and a value is another host's "
		"assertion, so the pattern's own separators make directories and a "
		"value's must not. Admitting one lets anybody who can assert an "
		"attribute about an entity create directories the pattern never asked "
		"for, inside the one place C14 says an organiser may write. "
		"materialise_test drives a value of evil/name against a control of an "
		"unusual but safe name. sec 338",
	),
	(
		"materialise-refuses-a-climbing-value",
		"catalog/materialise.c",
		"\tif (len == 2u && value[0] == '.' && value[1] == '.')\n\t\treturn 0;",
		"\tif (0)\n\t\treturn 0;",
		"a value of `..` climbs OUT of the managed source, which is a write "
		"outside the one place C14 permits one -- and it arrives as an "
		"ordinary signed assertion from any host in the estate. "
		"materialise_test substitutes `..` and requires the refusal, with a "
		"safe control beside it. sec 338",
	),
	(
		"materialise-never-picks-a-winner",
		"catalog/materialise.c",
		"\t\tif (found)\n\t\t\treturn FZN_CATALOG_ERR_KIND;",
		"\t\tif (0)\n\t\t\treturn FZN_CATALOG_ERR_KIND;",
		"C5b one layer out: two DIFFERENT live values for an attribute is a "
		"disagreement between hosts, and choosing one to build a filename "
		"from resolves it in the one place nobody would look for a "
		"resolution. The pair asserting the SAME value is the control -- that "
		"is agreement, not disagreement, and refusing it would make a "
		"filename depend on how many hosts happened to say so. sec 338",
	),
	(
		"materialise-a-missing-attribute-is-refused",
		"catalog/materialise.c",
		"return found ? FZN_CATALOG_OK : FZN_CATALOG_ERR_ABSENT;",
		"return FZN_CATALOG_OK;",
		"`{artist} - {title}` with no artist gives ' - title', a name a person "
		"did not ask for and would have to notice. Refusing is recoverable, "
		"because C22 stores the result and a consumer may supply a path "
		"itself; a malformed name is not. materialise_test drives a missing "
		"attribute and a retracted one. sec 338",
	),
	(
		"source-a-policy-cannot-be-flipped",
		"catalog/source.c",
		"\t\treturn found->policy == policy ? FZN_CATALOG_OK\n\t\t                               : FZN_CATALOG_ERR_KIND;",
		"\t\treturn FZN_CATALOG_OK;",
		"re-declaring a source with a different policy is the ONE call that "
		"would make an entire referenced collection writable at once, and a "
		"typo in an enum argument is how it would happen. C15 as settled "
		"makes promotion per entry precisely so no single call has that "
		"reach. source_test replays the same policy as its control -- that "
		"must stay OK, or a caller re-reading its own config is punished. "
		"sec 340",
	),
	(
		"source-a-promotion-is-one-place",
		"catalog/source.c",
		"\treturn bytes_eq(row->path, row->path_len, path, path_len);",
		"\treturn 1;",
		"a promotion binds to the entity AND the place. Without the place "
		"the permission follows the entity around the disk, so an organiser "
		"may write wherever it thinks the entity is -- including the "
		"directory above it, which is the subtree C15 exists to protect. "
		"source_test asks about the containing directory, a prefix of the "
		"promoted path and a path the owner has moved it to, against the "
		"promoted path itself as the control. sec 340",
	),
	(
		"source-a-promotion-is-one-source",
		"catalog/source.c",
		"\tif (!bytes_eq(row->source, row->source_len, source, source_len))\n\t\treturn 0;",
		"\tif (0)\n\t\treturn 0;",
		"two collections can easily share a relative path, so a promotion "
		"that does not compare the source name reaches into a second "
		"referenced collection at the same relative path. source_test "
		"declares a second referenced source rather than using an undeclared "
		"name, because an undeclared name is caught by the lookup and proves "
		"nothing about this comparison. sec 340",
	),
	(
		"source-the-predicate-asks-the-path-rule",
		"catalog/source.c",
		"\tif (!fzn_catalog_relative_path_ok(path, path_len))\n\t\treturn 0;\n\n\tsrc = fzn_catalog_source_find",
		"\tif (0)\n\t\treturn 0;\n\n\tsrc = fzn_catalog_source_find",
		"a path `fzn_catalog_promote` would refuse must not be one "
		"`fzn_catalog_writable` approves, or the refusal is only as strong "
		"as the caller's habit of going through promote -- and the managed "
		"source is where it bites, since everything there is writable "
		"without a row. source_test asks the predicate about every bad path "
		"it asks promote about. sec 340",
	),
	(
		"source-managed-needs-no-promotion",
		"catalog/source.c",
		"\tif (src->policy == FZN_CATALOG_POLICY_MANAGED)\n\t\treturn FZN_CATALOG_ERR_KIND;",
		"\tif (0)\n\t\treturn FZN_CATALOG_ERR_KIND;",
		"promoting inside a managed source is refused rather than accepted "
		"as a no-op, because a caller who believes the promotion granted the "
		"write also believes demoting would take it away -- and it would "
		"not. source_test requires the refusal and that no row is left "
		"behind. sec 340",
	),
	(
		"index-refuses-a-trailing-byte",
		"catalog/index.c",
		"\tif (at != body_len)\n\t\treturn FZN_CATALOG_ERR_MALFORMED;",
		"\tif (0)\n\t\treturn FZN_CATALOG_ERR_MALFORMED;",
		"the signature is over these bytes, so two spellings of one index "
		"would let a peer re-sign a different one -- the attribute and purge "
		"codecs refuse a trailing byte for the same reason. index_test "
		"decodes the same head at its own length as the control and one byte "
		"longer as the case. sec 341",
	),
	(
		"index-guards-the-multiplication",
		"catalog/index.c",
		"\tif (shards > (size_t)-1 / FZN_CATALOG_INDEX_ENTRY_LEN)\n\t\treturn FZN_CATALOG_ERR_RANGE;",
		"\tif (0)\n\t\treturn FZN_CATALOG_ERR_RANGE;",
		"the shard count arrives over the wire, and on a 32-bit host a peer "
		"naming 2^26 shards wraps the body length to something small and "
		"plausible. A wrapped product is a legal size_t and cannot be "
		"checked afterwards, which is why the guard is BEFORE the multiply. "
		"index_test drives the boundary and the value one below it as the "
		"control. sec 341",
	),
	(
		"index-refuses-overlapping-ranges",
		"catalog/index.c",
		"\t\tif (!key_before(plan[i - 1u].first.b, plan[i].first.b))\n\t\t\treturn FZN_CATALOG_ERR_MALFORMED;",
		"\t\tif (0)\n\t\t\treturn FZN_CATALOG_ERR_MALFORMED;",
		"an index whose ranges overlap cannot say which blob holds a key, and "
		"nothing downstream notices -- the lookup returns a confident wrong "
		"shard. shard_plan refuses an unsorted key list for the same reason. "
		"index_test swaps two entries and also gives two shards one start, "
		"since EQUAL is overlapping too. sec 341",
	),
	(
		"index-body-ok-checks-order",
		"catalog/index.c",
		"\t\tif (!key_before(&body[(i - 1u) * FZN_CATALOG_INDEX_ENTRY_LEN],\n\t\t                &body[i * FZN_CATALOG_INDEX_ENTRY_LEN]))\n\t\t\treturn 0;",
		"\t\tif (0)\n\t\t\treturn 0;",
		"the encoder refuses an out-of-order plan, and a blob arrives from "
		"somewhere that may not have used the encoder. This is the one pass "
		"that makes the binary search sound, so a consumer runs it when the "
		"blob lands; a search cannot notice that what it searches is out of "
		"order. index_test swaps two entries in the ENCODED body. sec 341",
	),
	(
		"index-lookup-finds-the-shard-a-key-is-in",
		"catalog/index.c",
		"\t*index_out = lo == 0 ? 0 : lo - 1u;",
		"\t*index_out = lo;",
		"the search wants the LAST entry whose first key is at or below the "
		"key, and the loop leaves `lo` one past it. Off by one, every key "
		"routes to the next shard along and a fetch reveals interest in the "
		"wrong range. Caught by an INDEPENDENT LINEAR MODEL in index_test "
		"rather than by cases the author of the search chose -- that is what "
		"makes the agreement evidence. sec 341",
	),
	(
		"facet-codec-refuses-a-trailing-byte",
		"facet/codec.c",
		"\tif (at != body_len) {",
		"\tif (0) {",
		"facet.h section 4 encodes an expression so that equal expressions "
		"are byte-equal and can be hashed for identity. A trailing byte "
		"ignored is a second spelling of one expression, which is a second "
		"IDENTITY -- two cache keys, two dedup entries, for one thing. "
		"codec_test decodes the same expression at its own length as the "
		"control and one byte longer as the case. sec 342",
	),
	(
		"facet-codec-refuses-terms-out-of-order",
		"facet/codec.c",
		"\t\t\tif (i > 0 && enc_cmp(&body[prev_at], prev_len,\n\t\t\t                     &body[here], at - here) >= 0) {",
		"\t\t\tif (0) {",
		"F16 gives an expression exactly one encoding, and F27 requires "
		"refusing an encoding that violates F16 to F19. Bytes arrive from "
		"somewhere that may not have used this encoder, so a decoder that "
		"trusts the order accepts several encodings of one expression and "
		"the identity hash stops being an identity. codec_test swaps two "
		"equal-length terms where they lie on the wire. sec 342",
	),
	(
		"facet-codec-refuses-members-out-of-order",
		"facet/codec.c",
		"\t\t\tif (i > 0 && enc_cmp(&body[prev_at], prev_len,\n\t\t\t                     &body[here], *at - here) >= 0) {",
		"\t\t\tif (0) {",
		"F18 applies F16's order recursively to an alternation's members, so "
		"the same argument as the terms above applies one level down and is "
		"a separate check that can be lost separately. codec_test swaps two "
		"members' identifier bytes on the wire. sec 342",
	),
	(
		"facet-codec-refuses-an-unknown-kind",
		"facet/codec.c",
		"\tif (kind != (uint8_t)FZN_FACET_PREFIX && kind != (uint8_t)FZN_FACET_RANGE\n\t    && kind != (uint8_t)FZN_FACET_ALT)\n\t\treturn FZN_FACET_ERR_KIND;",
		"\tif (0)\n\t\treturn FZN_FACET_ERR_KIND;",
		"F26: an implementation MUST refuse a term kind it does not know and "
		"MUST NOT SKIP it, because skipping evaluates a DIFFERENT expression "
		"while reporting success -- and an expression drives a placement or "
		"a delete. codec_test refuses one on the way out; the way in is this "
		"site. sec 342",
	),
	(
		"facet-codec-hoists-the-alternation-dimension",
		"facet/codec.c",
		"\t\t\tif (enc_cmp(t->members[i].dim, t->members[i].dim_len,\n\t\t\t            t->node.dim, t->node.dim_len) != 0)\n\t\t\t\treturn FZN_FACET_ERR_ALT_DIMENSION;",
		"\t\t\tif (0)\n\t\t\t\treturn FZN_FACET_ERR_ALT_DIMENSION;",
		"F8 binds an alternation to ONE dimension, and admitting a spanning "
		"one would be expression-level union, which F13 forbids. The "
		"encoding hoists the dimension so a spanning alternation cannot be "
		"SPELLED -- this check is what keeps the encoder from writing bytes "
		"that say something other than what the caller handed it. "
		"codec_test puts a member in a second dimension, with the "
		"one-dimension alternation beside it as the control. sec 342",
	),
	(
		"facet-reports-an-unpadded-run",
		"facet/facet.c",
		"\t\t\tif (pad == 0 && run >= digit_width && unpadded)\n\t\t\t\t*unpadded = 1;",
		"\t\t\tif (0)\n\t\t\t\t*unpadded = 1;",
		"a digit run at or above the dimension's width is left unpadded, and "
		"the key MISORDERS from there: unpadded 9999 sorts after unpadded "
		"10000. No width removes that, it only moves where it starts, so the "
		"report is what makes a per-dimension width safe -- a caller doing "
		"F7 must treat it as a refusal, because a RANGE on a misordering key "
		"selects the wrong files and F25 forbids that. facet_test checks the "
		"flag AND that the misordering it warns about is real. sec 343",
	),
	(
		"facet-refuses-a-natural-width-of-zero",
		"facet/facet.c",
		"\tif (dim->digit_width == 0)\n\t\treturn FZN_FACET_ERR_MALFORMED;",
		"\tif (0)\n\t\treturn FZN_FACET_ERR_MALFORMED;",
		"a NATURAL declaration of width zero pads nothing, which is RAW said "
		"a second way -- one spelling per thing, F19's instinct applied to a "
		"declaration rather than to a term. Accepting it lets a dimension be "
		"raw while claiming to be natural, and the next reader of the "
		"declaration believes the claim. facet_test drives it with the "
		"restored width beside it as the control. sec 343",
	),
	(
		"facet-sort-orders-the-terms",
		"facet/codec.c",
		"\t\t\tif (c <= 0)\n\t\t\t\tbreak;",
		"\t\t\tbreak;",
		"F16 gives an expression exactly ONE encoding so that equal "
		"expressions are byte-equal and can be hashed for identity, and "
		"nothing else in the library produces that order -- expr_encode "
		"REFUSES an unsorted array rather than sorting it. A sort that does "
		"not sort therefore leaves every consumer's expression unencodable, "
		"or worse, encodable in whatever order it happened to build them. "
		"codec_test drives an out-of-order fixture that must be refused "
		"BEFORE the sort and accepted after. sec 346",
	),
	(
		"facet-sort-dedups-the-terms",
		"facet/codec.c",
		"\t\tif (c != 0)\n\t\t\tarr[w++] = arr[i];",
		"\t\tarr[w++] = arr[i];",
		"F19 removes duplicate terms within P and within N, and "
		"expr_encode requires STRICTLY ascending -- so a sort that orders "
		"without deduplicating produces an array that still will not "
		"encode, which is the one outcome worse than not sorting, because "
		"the caller now believes it has canonicalised. codec_test puts the "
		"same PREFIX term in P twice. sec 346",
	),
	(
		"facet-sort-dedups-the-members",
		"facet/codec.c",
		"\t\tif (member_cmp(&m[w - 1u], &m[i]) != 0)\n\t\t\tm[w++] = m[i];",
		"\t\tm[w++] = m[i];",
		"F18 sorts AND deduplicates an alternation's members. A repeated "
		"member is the commonest thing a tri-state editor produces (F32/F33 "
		"-- two marks on one node in one dimension), so this is not an edge "
		"case, and two spellings of one alternation are two identities for "
		"one expression. facet.h claimed fzn_facet_normalize did this and it "
		"never did; sec 346 records that. codec_test repeats a member. "
		"sec 346",
	),
	(
		"facet-sort-collapses-a-dedup-to-a-prefix",
		"facet/codec.c",
		"\t\tif (arr[i].member_count == 1u) {\n\t\t\tarr[i].kind = FZN_FACET_PREFIX;",
		"\t\tif (0) {\n\t\t\tarr[i].kind = FZN_FACET_PREFIX;",
		"F19: one member is not an alternation, and the codec refuses an "
		"alternation of fewer than two members outright -- so an "
		"alternation the member dedup reduced to one is unencodable unless "
		"it is collapsed. This is why the collapse sits BETWEEN the member "
		"dedup and the term sort: earlier there is nothing to collapse, "
		"later the term has already sorted under the wrong encoding. "
		"codec_test gives an alternation three copies of one member. "
		"sec 346",
	),
	(
		"admit-an-expired-frame-never-reaches-replay",
		"admit/admit.c",
		"\tif (fr != FZN_FRESH_OK) {\n\t\trefuse(out, FZN_ADMIT_FRESHNESS, FZN_ADMIT_VOCAB_FRESH, (int)fr);\n\t\treturn;\n\t}",
		"\tif (fr != FZN_FRESH_OK)\n\t\trefuse(out, FZN_ADMIT_FRESHNESS, FZN_ADMIT_VOCAB_FRESH, (int)fr);",
		"sec 4.7's rule that is not an ordering: a refusal at any step must "
		"not have cost a slot at a LATER one. Replay is the first mutation, "
		"so a freshness refusal that falls through takes a window entry for "
		"a frame it just rejected -- and the genuine frame carrying that "
		"nonce is then refused as a replay. An off-path attacker with no key "
		"fills the window with expired frames. sequence_test runs the genuine "
		"frame after every refusal above replay and requires it admitted. "
		"sec 350",
	),
	(
		"admit-an-unknown-sender-is-a-drop",
		"admit/admit.c",
		"\tif (n == 0 || n > candidate_cap) {",
		"\tif (n > candidate_cap) {",
		"sec 4.7 step 2 calls this the constraint a consumer is likeliest to "
		"get wrong: an unknown sender must produce a DROP, not an object. "
		"Falling through hands the later steps a key set that does not "
		"exist, and every natural repair for it -- a pending-peer entry, a "
		"negative cache -- is an unauthenticated write. sequence_test requires "
		"the refusal to name KEY SELECT rather than a step further down, "
		"because where it stops is what says nothing was built. sec 350",
	),
	(
		"admit-fails-closed-without-a-chain",
		"admit/admit.c",
		"\tif (!fzn_chain_store_lookup(env->chains, root, &cap, out->opened.sender,\n\t                            now, &chain_bytes, &chain_len)) {",
		"\tif (0) {",
		"a capability this host cannot prove is one it does not act on. The "
		"chain is not in the frame (sec 13), so the store answering nothing "
		"is the whole of what this host knows -- proceeding would verify "
		"whatever bytes happened to be in hand. sequence_test drives a frame "
		"whose capability no chain covers and requires the NO_CHAIN "
		"vocabulary, which is what says the chain module was never reached. "
		"sec 350",
	),
	(
		"admit-an-absence-is-not-a-chain-error",
		"admit/admit.c",
		"\t\trefuse(out, FZN_ADMIT_CHAIN, FZN_ADMIT_VOCAB_NO_CHAIN, 0);\n\t\treturn;\n\t}\n\tmemcpy(cap.b",
		"\t\trefuse(out, FZN_ADMIT_CHAIN, FZN_ADMIT_VOCAB_CHAIN,\n\t\t       (int)FZN_CHAIN_ERR_UNKNOWN_TARGET);\n\t\treturn;\n\t}\n\tmemcpy(cap.b",
		"this is the defect the first draft of admit.c shipped, kept as a "
		"sabotage because it compiled and read well. A sender anchored to no "
		"root never reaches `chain/`, so there is no chain error to give -- "
		"and FZN_CHAIN_ERR_UNKNOWN_TARGET means something specific and "
		"different, an out-of-order revocation record, with a comment in "
		"chain.h warning that folding an ordinary absence into it \"would "
		"make ordinary propagation look like an attack\". sequence_test asserts "
		"the vocabulary, not just the step. sec 350",
	),
	(
		"index-requires-its-provenance",
		"catalog/index.c",
		"\t    || !prov_ok(ix->method, ix->method_len, FZN_CATALOG_METHOD_MAX))\n\t\treturn FZN_CATALOG_ERR_MALFORMED;",
		"\t    || 0)\n\t\treturn FZN_CATALOG_ERR_MALFORMED;",
		"C23c: nobody downstream can re-check an index against the register, "
		"so the importer's diligence is the only check there is and the "
		"METHOD is where it is recorded. An index that says only which "
		"register it came from asserts a fact with no method beside it, which "
		"is the one assertion C23c says an index must not be able to make -- "
		"so an empty method is refused rather than defaulted. index_test "
		"drives each of the three fields empty against a fully attributed "
		"control. sec 352",
	),
	(
		"index-provenance-survives-the-wire",
		"catalog/index.c",
		"\tif (n == 0 || n > FZN_CATALOG_METHOD_MAX || at + n > body_len)\n\t\treturn FZN_CATALOG_ERR_MALFORMED;",
		"\tif (n > FZN_CATALOG_METHOD_MAX || at + n > body_len)\n\t\treturn FZN_CATALOG_ERR_MALFORMED;",
		"the encoder refusing an empty method is half the rule; an index "
		"arrives from another host, which may not have used this encoder. A "
		"decoder that accepts a method length of zero lets the unattributed "
		"index C23c forbids into the estate through the only door that "
		"matters. index_test zeroes the method length in an otherwise sound "
		"encoded head. sec 352",
	),
	(
		"memo-a-revocation-invalidates-every-verdict",
		"chain/memo.c",
		"\t\tif (e->generation == 0 || e->generation != generation)\n\t\t\tcontinue;",
		"\t\tif (e->generation == 0)\n\t\t\tcontinue;",
		"the generation is the only thing connecting a cached verdict to the "
		"revocation store. Without the comparison a revoked peer keeps its "
		"cached authorisation for as long as the entry lives, which is "
		"exactly the wrong answer a cache exists to be suspected of. Coarse "
		"on purpose: every entry goes stale at once, because deciding per "
		"entry whether a revocation could have mattered is the verification "
		"being avoided. memo_test asserts the stale generation misses AND "
		"that the original still hits, so the miss is about the generation "
		"rather than the entry having been destroyed. sec 354",
	),
	(
		"memo-an-expired-chain-never-hits",
		"chain/memo.c",
		"\t\tif (e->expires_at != FZN_NO_EXPIRY && now >= e->expires_at)\n\t\t\tcontinue;",
		"\t\tif (0)\n\t\t\tcontinue;",
		"sec 4.7c names the revocation generation as the invalidator and "
		"stops there, and a memo built to that description alone goes on "
		"authorising a chain after it has expired -- no revocation need ever "
		"land for that to happen, because a verdict is a function of `now` "
		"too. The gap is in the specification rather than in an "
		"implementation of it. memo_test drives the expiry exactly, one "
		"second before it and long after, against a live chain as control. "
		"sec 354",
	),
	(
		"revocation-generation-moves-on-a-write",
		"chain/revocation.c",
		"\tstore->entries[store->used].withdrawn = 0;\n\tstore->entries[store->used].epoch = fzn_revocation_epoch(record);\n\tmemcpy(store->entries[store->used].held, id, FZN_REVOCATION_ID_LEN);\n\tmemcpy(store->entries[store->used].cut, fzn_revocation_cut(record), FZN_REVOCATION_ID_LEN);\n\tstore->used++;\n\t/* An answer this store gives may now differ; sec 354. */\n\tstore->generation++;",
		"\tstore->entries[store->used].withdrawn = 0;\n\tstore->entries[store->used].epoch = fzn_revocation_epoch(record);\n\tmemcpy(store->entries[store->used].held, id, FZN_REVOCATION_ID_LEN);\n\tmemcpy(store->entries[store->used].cut, fzn_revocation_cut(record), FZN_REVOCATION_ID_LEN);\n\tstore->used++;",
		"the store counts its own writes so a cache can tell an answer might "
		"have changed. A write that does not bump leaves every memo entry "
		"looking current, so a peer revoked a moment ago keeps its cached "
		"authorisation -- the store is right and the cache is confidently "
		"wrong. revocation_test asserts the number moves across an admit, "
		"because that is the suite with a real record to admit. sec 354",
	),
	(
		"revocation-generation-moves-on-an-un-withdrawal",
		"chain/revocation.c",
		"\t\t\tentry->withdrawn = 0;\n\t\t\tentry->epoch = fzn_revocation_epoch(record);\n\t\t\tstore->generation++;",
		"\t\t\tentry->withdrawn = 0;\n\t\t\tentry->epoch = fzn_revocation_epoch(record);",
		"a re-revocation over a withdrawal turns NOT REVOKED back into "
		"REVOKED, which is the largest answer this store can change -- and "
		"`fzn_revocation_lookup` answers on exactly this field. Without the "
		"bump a chain memo keeps authorising the peer that was just "
		"re-revoked, for as long as the entry lives. Found by an independent "
		"review of sec 354's own commit, two hours after it landed. "
		"revocation_test asserts the number moves across the exact "
		"re-revocation. sec 356",
	),
	(
		"facet-codec-encode-enforces-f18",
		"facet/codec.c",
		"\t\t\tif (i > 0 && member_cmp(&t->members[i - 1u],\n\t\t\t                        &t->members[i]) >= 0)\n\t\t\t\treturn FZN_FACET_ERR_MALFORMED;",
		"\t\t\tif (0)\n\t\t\t\treturn FZN_FACET_ERR_MALFORMED;",
		"`take_term` refuses an alternation whose members are out of order, "
		"and the encoder did not -- so it wrote bytes its own decoder "
		"rejects, and gave ONE alternation two encodings. That is the single "
		"thing F16 exists to prevent: an expression is hashed for identity, "
		"and two byte-strings for one expression are two identities. "
		"codec_test's two-member fixture is ascending for this reason. "
		"sec 356",
	),
	(
		"node-loop-uses-the-consumers-buffer",
		"node/serve.c",
		"\tsize_t reply_cap = state->reply ? state->reply_cap : sizeof(own);",
		"\tsize_t reply_cap = sizeof(own);",
		"a consumer that supplied a reply buffer gets its SIZE used too. "
		"Taking the pointer and the node's own 512 leaves a handler with "
		"answers larger than that unable to answer at all, which is the "
		"state raidcfgd reported and this change exists to end. "
		"provision_test drives a 3,230-byte reply over real loopback UDP. "
		"sec 363",
	),
	(
		"node-loop-sends-every-piece",
		"node/serve.c",
		"\t\tfor (i = 0; i < plan.chunks; i++) {",
		"\t\tfor (i = 0; i < 1u; i++) {",
		"every piece the plan names is sent. Sending only the first leaves "
		"a receiver holding one chunk of four for ever -- the message never "
		"completes, so the symptom is a reply that silently never arrives "
		"rather than a short one. sec 363",
	),
	(
		"node-loop-refuses-an-overclaimed-reply",
		"node/serve.c",
		"\tif (reply_len > reply_cap)\n\t\treply_len = 0;",
		"\tif (0)\n\t\treply_len = 0;",
		"a handler claiming more than its buffer is treated as having "
		"written nothing. Unlike the local seam's version of this bound, "
		"the cost is not a truncated reply: fzn_split_plan would plan over "
		"a length the buffer does not have and the send loop would read "
		"past it. The guard went untested in sec 362 and the sabotage run "
		"said so; provision_test reaches it now. sec 363",
	),
	(
		"node-reply-kind-follows-the-count",
		"node/remote.c",
		"\twhat.kind = (chunks == 1u) ? FZN_KIND_UNIT : FZN_KIND_CHUNK;",
		"\twhat.kind = FZN_KIND_UNIT;",
		"a reply of several pieces seals as CHUNK and a reply of one as "
		"UNIT, derived from the count rather than passed, so a caller "
		"cannot build a CHUNK frame claiming to be alone or a UNIT frame "
		"that is one of several. A receiver reads `kind` to know which it "
		"holds, and those two disagreeing is not a state this library "
		"should let anyone construct. remote_test drives raidcfgd's "
		"measured 3,230-byte status as four pieces. sec 362",
	),
	(
		"node-reply-piece-carries-its-index",
		"node/remote.c",
		"\twhat.index = index;",
		"\twhat.index = 0u;",
		"every piece of a chunked reply carries its own index. All-zero "
		"indices make reassembly see one piece repeated: it accepts the "
		"first, treats the rest as duplicates of it, and the message never "
		"completes -- so the symptom is a reply that silently never "
		"arrives rather than one that arrives wrong. sec 362",
	),
	(
		"vocabulary-compose-token-hides-no-separator",
		"local/vocabulary.c",
		"\t\tif (token[i] == (uint8_t)' ' || token[i] == (uint8_t)'\\n')",
		"\t\tif (0)",
		"a composed verb carries neither a space nor a newline. A verb of "
		"`get x` arrives at the server as `get` with an argument -- past "
		"any rule written for the whole string -- and one carrying a "
		"newline arrives as two request lines. Refused rather than "
		"escaped, because an escape is a second grammar. sec 364",
	),
	(
		"vocabulary-compose-keeps-the-empty-argument",
		"local/vocabulary.c",
		"\tif (arg) {\n\t\tout[(*out_len)++] = (uint8_t)' ';",
		"\tif (arg_len) {\n\t\tout[(*out_len)++] = (uint8_t)' ';",
		"`get ` and `get` are different requests -- the first asks for the "
		"empty subject -- and the separating space is the only thing that "
		"distinguishes them. fzn_vocabulary_split reads the difference "
		"back, so a composer that dropped it would make one request "
		"unsayable while the parser went on expecting it. sec 364",
	),
	(
		"client-asks-for-the-request-bound",
		"local/client.c",
		"\tswitch (fzn_vocabulary_compose(out, cap, FZN_REQUEST_MAX, out_len, verb,",
		"\tswitch (fzn_vocabulary_compose(out, cap, FZN_REPLY_MAX, out_len, verb,",
		"a line past FZN_REQUEST_MAX is refused here rather than sent. The "
		"server answers an overlong line with a DENIAL, so a client that "
		"let it go would turn its own framing mistake into what reads like "
		"an access decision -- and the operator would look at the policy. "
		"sec 364",
	),
	(
		"client-refuses-an-overlong-reply",
		"local/client.c",
		"\t\t\treturn FZN_CLIENT_ERR_REPLY_TOO_LONG;",
		"\t\t\treturn FZN_CLIENT_OK;",
		"a reply longer than the caller's buffer is refused whole. A "
		"prefix of a reply is a different reply, which is the refusal "
		"fzn_node_status_line makes by returning 0 and local/vocabulary.h "
		"makes by rejecting an overlong verb rather than cutting it to one "
		"a rule names. sec 364",
	),
	(
		"client-times-out-a-silent-daemon",
		"local/client.c",
		"\t\t\tif (errno == EAGAIN || errno == EWOULDBLOCK)\n"
		"\t\t\t\treturn FZN_CLIENT_ERR_TIMEOUT;",
		"\t\t\tif (0)\n\t\t\t\treturn FZN_CLIENT_ERR_TIMEOUT;",
		"a daemon that accepts and says nothing is reported as a timeout "
		"rather than as IO. The two want different responses -- a timeout "
		"says the daemon is there and wedged, IO says the socket broke -- "
		"and collapsing them sends an operator to the wrong half. The "
		"server sets the same receive timeout on its own side for the "
		"mirror-image reason. sec 364",
	),
	(
		"reply-ok-is-only-ok",
		"local/vocabulary.c",
		"\treturn reply == FZN_REPLY_OK;",
		"\treturn reply != FZN_REPLY_DENIED;",
		"only FZN_REPLY_OK reads as success, and FZN_REPLY_NONE -- a reply "
		"this library does not offer -- must not. The direction matters: "
		"the failure is a caller carrying on after something did not "
		"happen, so an unrecognised token answering 1 is the expensive way "
		"to be wrong. sec 365",
	),
	(
		"reply-parses-on-its-whole-length",
		"local/vocabulary.c",
		"\t\tif (REPLIES[i].name == NULL || REPLIES[i].len != token_len)",
		"\t\tif (REPLIES[i].name == NULL)",
		"a reply token parses only on its whole length. No reply token is a "
		"prefix of another, so unlike the verb set this has no natural "
		"collision and the test must CONSTRUCT one -- `o` against `ok`. "
		"The first version of the case did not, and this mutation went "
		"undetected until the sabotage run said so. sec 365",
	),
	(
		"compose-reads-the-wire-limit",
		"local/vocabulary.c",
		"\tif (need > limit)",
		"\tif (0)",
		"a line past the protocol's bound is refused as TOO_LONG. Distinct "
		"from the buffer bound below because they are different findings -- "
		"ask for less, against give me a bigger buffer -- and a caller told "
		"the wrong one looks in the wrong place. sec 365",
	),
	(
		"compose-reads-the-buffer-bound",
		"local/vocabulary.c",
		"\tif (need > cap)",
		"\tif (0)",
		"the other half of the same pair, and the one that writes out of "
		"bounds if it goes: `cap` is the caller's buffer, and a line longer "
		"than it is memcpy'd past the end. sec 365",
	),
	(
		"node-status-line-leads-with-a-reply-token",
		"node/local.c",
		"\t\tif (fzn_reply_compose((uint8_t *)out, cap - 1u, &len,\n"
		"\t\t                      FZN_REPLY_DENIED, NULL, 0u) != FZN_COMPOSE_OK)",
		"\t\tif (fzn_reply_compose((uint8_t *)out, cap - 1u, &len,\n"
		"\t\t                      FZN_REPLY_ERROR, NULL, 0u) != FZN_COMPOSE_OK)",
		"a refused caller is told `denied` and not `error`. They are "
		"different answers: one is an access decision about this caller and "
		"the other says the daemon tried and failed, and local_test reads "
		"the node's own line back with fzn_reply_of rather than matching a "
		"substring. sec 365",
	),
	(
		"node-peers-load-needs-a-list",
		"node/peer_persist.c",
		"\tif (!ops->list)\n\t\treturn FZN_PERSIST_ERR_BACKEND;",
		"\tif (0)\n\t\treturn FZN_PERSIST_ERR_BACKEND;",
		"a backend that cannot enumerate is reported rather than read as a "
		"store holding nobody. An empty set and `I cannot tell you` look "
		"identical to a caller and mean opposite things -- serve nobody, "
		"against something is wrong with the store. Removing it also "
		"dereferences a NULL op, so the suite dies rather than failing an "
		"assertion; both are the guard speaking. sec 367",
	),
	(
		"node-peers-load-checks-the-filing",
		"node/peer_persist.c",
		"\t\tif (memcmp(out[i].sender, subjects + (i * (size_t)FZN_PUBKEY_LEN),\n"
		"\t\t           FZN_PUBKEY_LEN) != 0)\n\t\t\treturn FZN_PERSIST_ERR_SHAPE;",
		"\t\tif (0)\n\t\t\treturn FZN_PERSIST_ERR_SHAPE;",
		"a record filed under one identity and carrying another is refused. "
		"Serving it means the node answers to a key its own store does not "
		"index -- findable by nothing and removable by nothing -- and the "
		"file is either a corrupted store or one somebody placed. sec 367",
	),
	(
		"persist-file-list-refuses-truncation",
		"persist/persist_file.c",
		"\t\tif (found >= max) {\n\t\t\t(void)closedir(d);\n\t\t\treturn 0;\n\t\t}",
		"\t\tif (found >= max) {\n\t\t\tbreak;\n\t\t}",
		"a store holding more than the caller's array fails rather than "
		"returning the first few. A node serving SOME of its peers with "
		"nothing saying which are missing is worse than one serving none, "
		"because the second shows and the first does not. sec 367",
	),
	(
		"persist-file-list-skips-a-half-written-save",
		"persist/persist_file.c",
		"\t\tif (strlen(n) != prefix_len + 64u)\n\t\t\tcontinue;",
		"\t\tif (0)\n\t\t\tcontinue;",
		"`file_save` writes `<name>.tmp` and renames, so an interrupted "
		"save leaves `<slot>-<64 hex>.tmp` -- the right prefix and a valid "
		"subject with four bytes glued on. Without the length check it "
		"lists as a peer, duplicating one already there. An UNRELATED file "
		"cannot drive this: it fails on the prefix first, which is why the "
		"first fixture reported MISSED. sec 367",
	),
	(
		"node-drops-a-fragment-without-a-table",
		"node/serve.c",
		"\t\tif (!state->reassembly)\n\t\t\treturn;",
		"\t\tif (0)\n\t\t\treturn;",
		"a node with no reassembly table drops a chunked request whole "
		"rather than handing a fragment up: a fragment is not the request "
		"anybody sent, and a handler that cannot tell one from a whole "
		"message is how a partial command gets executed. Observable only "
		"on the DENIED path -- `fzn_reasm_accept` refuses a NULL table "
		"itself, so the granted path returns either way, which is why the "
		"fixture is a denied chunked request. sec 370",
	),
	(
		"node-waits-for-the-whole-message",
		"node/serve.c",
		"\t\t\tif (!done)\n\t\t\t\treturn;\t/* accepted, not yet whole */",
		"\t\t\tif (0)\n\t\t\t\treturn;\t/* accepted, not yet whole */",
		"the handler is called once, when the message completes -- not "
		"per piece, and not with a slot that is not finished. sec 370",
	),
	(
		"node-hands-no-dropped-frame-up",
		"node/serve.c",
		"\tif (result != FZN_NODE_REMOTE_DROPPED)\n"
		"\t\tserve_reply(state, peer, &from, result, &opened);",
		"\tserve_reply(state, peer, &from, result, &opened);",
		"a frame that never authenticated reaches no handler. This guard "
		"was LOST for one build while `serve_reply` was being extracted: "
		"the call replaced an `if (result != DROPPED && state->on_remote)` "
		"and kept only the second half. The replay case caught it, which "
		"is what a test asserting a handler did NOT run is for. sec 370",
	),
	(
		"node-does-not-reassemble-denied-chunks",
		"node/serve.c",
		"\t\tif (result == FZN_NODE_REMOTE_DENIED) {\n"
		"\t\t\tif (opened.index != 0u)\n\t\t\t\treturn;",
		"\t\tif (0) {\n\t\t\t\tif (opened.index != 0u)\n\t\t\t\t\treturn;",
		"a caller the node has refused must not occupy reassembly slots by "
		"sending pieces, and is told once on the first piece rather than "
		"per chunk. THE HANDLER COUNT DOES NOT DISCRIMINATE: reassembled "
		"denied chunks still call it exactly once, on the last piece. What "
		"separates them is what it was handed -- the first piece alone, or "
		"the whole request a refused caller was allowed to build. sec 370",
	),
	(
		"caller-request-piece-carries-its-index",
		"node/caller.c",
		"\t\twhat.index = i;",
		"\t\twhat.index = 0u;",
		"every piece of a chunked request carries its own index. All-zero "
		"indices make the node's reassembly read the pieces as duplicates "
		"of the first, so the message never completes and the handler is "
		"never called -- a request that silently vanishes rather than one "
		"that arrives wrong. sec 370",
	),
	(
		"caller-skips-another-msgs-reply",
		"node/caller.c",
		"\t\tif (!any && opened.msg != *msg)\n\t\t\tcontinue;",
		"\t\tif (0)\n\t\t\tcontinue;",
		"a reply carrying another `msg` is skipped, not returned as the "
		"answer to this question. The socket can hold a late reply to an "
		"earlier ask. The fixture has to LEAVE one there -- the first "
		"version asked for an unsent msg with nothing queued and timed "
		"out whether or not the check existed. sec 369",
	),
	(
		"caller-refuses-past-the-reassembly-ceiling",
		"node/caller.c",
		"\tif (fzn_split_plan(payload_len ? payload_len : 1u,\n"
		"\t                   (size_t)FZN_SPLIT_MAX_PAYLOAD, &plan) != FZN_SPLIT_OK)\n"
		"\t\treturn FZN_CALLER_ERR_REQUEST_TOO_LONG;",
		"\tif (fzn_split_plan(payload_len ? payload_len : 1u,\n"
		"\t                   (size_t)FZN_SPLIT_MAX_PAYLOAD, &plan) == FZN_SPLIT_ERR_MALFORMED)\n"
		"\t\treturn FZN_CALLER_ERR_REQUEST_TOO_LONG;",
		"a request past what a RECEIVER will reassemble is refused rather "
		"than planned. sec 369 refused anything past ONE FRAME, because "
		"the node reassembled nothing; sec 370 gave the node step 8, so "
		"the ceiling moved to FZN_REASM_MAX_CHUNKS pieces and the entry "
		"moved with it -- a plan that plans is a request that can arrive. "
		"sec 370",
	),
	(
		"caller-refuses-a-reply-past-the-buffer",
		"node/caller.c",
		"\t\tif (done->bytes > reply_cap) {",
		"\t\tif (0) {",
		"a reply larger than the caller's buffer is refused whole rather "
		"than copied as far as it fits. A prefix of a reply is a different "
		"reply, which is the refusal fzn_node_status_line and the verb "
		"bound both already make. sec 369",
	),
	(
		"caller-releases-a-refused-reply",
		"node/caller.c",
		"\t\t\tfzn_reasm_release(done);\n\t\t\treturn FZN_CALLER_ERR_REPLY_TOO_LONG;",
		"\t\t\treturn FZN_CALLER_ERR_REPLY_TOO_LONG;",
		"a refused reply gives its reassembly slot back, or it holds one "
		"until the table expires it and the next ask finds the table full. "
		"The fixture uses a ONE-slot table: with two, a held slot still "
		"leaves one free and the leak cannot be seen. sec 369",
	),
	(
		"caller-reports-the-msg-it-sent",
		"node/caller.c",
		"\t*msg = caller->next_msg++;",
		"\t*msg = caller->next_msg++ + 1u;",
		"the msg handed back is the one that went out on the wire. It is "
		"the caller's only handle on its own answer, so a value that is "
		"off by anything means recv skips the reply it is waiting for and "
		"reports a timeout against a node that answered. sec 369",
	),
	(
		"node-peer-pack-bounds-the-hop-count",
		"node/peer_persist.c",
		"\tif (peer->hop_count > (size_t)FZN_CHAIN_MAX_HOPS)\n"
		"\t\treturn FZN_PERSIST_ERR_MALFORMED;",
		"\tif (0)\n\t\treturn FZN_PERSIST_ERR_MALFORMED;",
		"a peer with more hops than fzn_chain_verify accepts is not "
		"written down: the pack would read peer->hop_bytes one past an "
		"array of exactly FZN_CHAIN_MAX_HOPS. The first fixture could not "
		"see this -- a buffer of exactly FZN_NODE_PEER_BLOB_MAX makes the "
		"head writer refuse the over-large body on CAPACITY first, so the "
		"case is driven with an oversized buffer that lets the pack reach "
		"the guard. sec 366",
	),
	(
		"node-peer-open-bounds-the-hop-count",
		"node/peer_persist.c",
		"\tif (hop_count > (size_t)FZN_CHAIN_MAX_HOPS)\n"
		"\t\treturn FZN_PERSIST_ERR_SHAPE;",
		"\tif (0)\n\t\treturn FZN_PERSIST_ERR_SHAPE;",
		"the same bound where the count arrives from a FILE rather than "
		"from a caller, which is the case that matters. The forged blob "
		"has to be SELF-CONSISTENT -- a declared count of nine with a "
		"length that agrees with nine -- or the exactness check refuses it "
		"first and the bound is never reached. Without it out->hop_bytes "
		"is written one past its end from a crafted file. sec 366",
	),
	(
		"vocabulary-split-refuses-a-leading-space",
		"local/vocabulary.c",
		"\tif (i == 0 || i > FZN_VERB_MAX)",
		"\tif (i > FZN_VERB_MAX)",
		"a request line beginning with a space has no verb. Skipping the "
		"space instead makes ` destroy` and `destroy` the same request, "
		"which is the shape of every filter somebody gets past by adding "
		"whitespace -- and the verb that then reaches fzn_vocabulary_admit "
		"is the empty one, which no rule names, so the refusal would look "
		"like policy rather than a parse. sec 361",
	),
	(
		"vocabulary-split-bounds-the-verb",
		"local/vocabulary.c",
		"\tif (i == 0 || i > FZN_VERB_MAX)",
		"\tif (i == 0)",
		"the other half of the same guard. A verb longer than FZN_VERB_MAX "
		"is one no rule could name, so splitting it out and handing it on "
		"would let `split` and `admit` disagree about what a verb even is. "
		"The same bound fzn_verb_parse applies, for the same reason. "
		"sec 361",
	),
	(
		"vocabulary-parse-reads-the-whole-verb",
		"local/vocabulary.c",
		"\t\tif (VERBS[i].name == NULL || VERBS[i].len != verb_len)",
		"\t\tif (VERBS[i].name == NULL)",
		"a verb parses only on its whole length. Without the equality the "
		"compare runs over verb_len bytes of the table's spelling, so "
		"`stat` parses as STATUS and `get` as GET where a longer entry "
		"shares the prefix -- a request reaching a rule written for a verb "
		"it does not name. vocabulary_test drives the prefix and the "
		"superstring, which are the two a wholly different word cannot "
		"separate. sec 361",
	),
	(
		"node-local-handler-not-on-a-denial",
		"node/local.c",
		"\tif (on_local && verdict != FZN_AUTHZ_DENIED &&\n"
		"\t    fzn_vocabulary_split(line, line_len, &request)) {",
		"\tif (on_local &&\n"
		"\t    fzn_vocabulary_split(line, line_len, &request)) {",
		"the local handler seam is not consulted for a caller the node "
		"refused. on_remote is called for any result that is not DROPPED, "
		"a denied one included, and this deliberately differs: a denial is "
		"the node's whole answer on the local path, and a seam that could "
		"write to a refused caller would widen the decision it was given "
		"to observe. local_test drives a stranger with a handler that "
		"would answer, and requires the handler never to run. sec 360",
	),
	(
		"node-local-reply-bound-is-read",
		"node/local.c",
		"\t\tif (n > 0 && n <= sizeof(resp))",
		"\t\tif (n > 0)",
		"a handler claiming more than the cap it was given wrote nothing "
		"this function may send. Sending sizeof(resp) of it instead is a "
		"TRUNCATION -- a different reply rather than a shorter one, which "
		"is the failure fzn_node_status_line refuses by returning 0 and "
		"local/vocabulary.h refuses by rejecting an overlong verb rather "
		"than cutting it to one a rule names. sec 360",
	),
	(
		"node-local-handler-reply-reaches-the-wire",
		"node/local.c",
		"\t\tif (n > 0 && n <= sizeof(resp))\n\t\t\tresp_len = n;",
		"\t\tif (0)\n\t\t\tresp_len = n;",
		"the other direction of the same branch, and the reason the seam "
		"exists at all: what a handler wrote is what the caller gets. "
		"Discarding it leaves the node answering with its own status line "
		"and every handler inert -- which no existing case could see, "
		"because before sec 360 the status line was the only answer there "
		"was. sec 360",
	),
	(
		"revocation-a-gap-is-reported-not-drained",
		"chain/revocation.c",
		"\t\t\t\tif (fzn_ct_memeq(fzn_revocation_supersedes(record),\n\t\t\t\t                 NAMES_NOTHING, FZN_REVOCATION_ID_LEN))",
		"\t\t\t\tif (1)",
		"a re-revocation whose `supersedes` this host does not recognise means "
		"the chain moved on WITHOUT it, and this host is BEHIND. Refusing it "
		"leaves the pair unrevoked and cannot be healed: the bridging record "
		"is one nothing retains, because this store holds a hash and a flag "
		"rather than a record. So the host authorises a grantee the root has "
		"revoked, silently and for ever. revocation_test builds a converged "
		"peer, lets the victim fall a record behind, and requires the "
		"re-revocation to take. sec 358, sec 359",
	),
	(
		"revocation-drains-when-the-record-names-nothing",
		"chain/revocation.c",
		"\t\t\t\tif (fzn_ct_memeq(fzn_revocation_supersedes(record),\n\t\t\t\t                 NAMES_NOTHING, FZN_REVOCATION_ID_LEN))",
		"\t\t\t\tif (0)",
		"the other direction of the same branch, and the reason it is a branch "
		"at all. A ZERO `supersedes` is what fzn_revocation_issue writes: a "
		"peer that never heard the withdrawal, revoking the pair afresh. That "
		"peer is behind US, so the deficit must drain or the refusal and the "
		"re-fetch chase each other for ever. manifest_test's leg 2 is what "
		"catches it, and it caught the first version of the sec 358 fix, which "
		"stopped draining unconditionally. sec 358",
	),
	(
		"shard-absorbs-the-remainder",
		"catalog/shard.c",
		"\t\tif (i + 1u == shards)\n\t\t\tout[i].entries = count - at;\n\t\telse\n\t\t\tout[i].entries = min_entries;",
		"\t\tout[i].entries = min_entries;\n\t\tif (i + 1u == shards)\n\t\t\tout[i].entries = min_entries;",
		"C26 makes the shard size the anonymity set, so a shard smaller than "
		"min_entries is a range where a fetch reveals more than the number "
		"promises -- and the division's remainder puts it at the END of the "
		"key space, where nobody looks for it. Dropping the absorb leaves the "
		"tail uncovered instead, so keys past the last boundary belong to no "
		"shard. shard_test plans 3000 at 1024 and requires two shards "
		"totalling 3000. sec 337",
	),
	(
		"shard-a-small-register-is-one-shard",
		"catalog/shard.c",
		"\tif (shards == 0)\n\t\tshards = 1;",
		"\tif (0)\n\t\tshards = 1;",
		"a register smaller than one shard is ONE shard, not none: the whole "
		"register is then the anonymity set, which is the best available and "
		"is what a fetch already reveals. Without this a small register plans "
		"zero shards, so every key belongs to nothing and no fetch can be "
		"routed at all. shard_test plans ten keys and one key. sec 337",
	),
	(
		"shard-refuses-an-unsorted-register",
		"catalog/shard.c",
		"if (memcmp(keys[i - 1u].b, keys[i].b, FZN_CATALOG_SHARD_KEY_LEN) > 0)",
		"if (0)",
		"a shard is a key RANGE, so cutting an unsorted list produces ranges "
		"that OVERLAP -- and an index mapping overlapping ranges to blobs "
		"cannot say which blob holds a key. The check is one pass over data "
		"already in hand against a failure that is otherwise silent. "
		"shard_test swaps two keys, with a sorted control and an "
		"equal-adjacent-keys case that must still pass. sec 337",
	),
	(
		"purge-decode-refuses-a-second-spelling",
		"catalog/purge.c",
		"if (body_len != want)",
		"if (body_len < want)",
		"one canonical encoding (C8): the body must be EXACTLY what its host "
		"count says. Admitting a longer one lets two byte strings decode to "
		"the same purge command, and the signature is over those bytes -- so a "
		"peer could re-sign a different spelling of what a host queued. "
		"purge_test decodes at len+1 and len-1 and requires both refused. "
		"sec 336",
	),
	(
		"purge-agreement-binds-to-one-command",
		"catalog/purge.c",
		"\t\tif (!bytes_eq(a->value, a->value_len, purge_id, purge_id_len))\n\t\t\tcontinue;",
		"\t\tif (0)\n\t\t\tcontinue;",
		"an agreement's VALUE is the identity of the command it agrees to. "
		"Without the binding, agreement given to LAST week's purge of an "
		"entity counts towards this week's -- so the second purge closes on "
		"consent nobody gave to it, and the bytes go. purge_test has a third "
		"host agree to a different purge of the same entity. sec 336",
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
		"\tif (hop_count == 0 || hop_count > (size_t)FZN_CHAIN_MAX_HOPS)\n\t\treturn;\n",
		"\tif (hop_count == 0)\n\t\treturn;\n",
		"the only bound on a consumer walking a chain it parsed itself; since sec 397 it sits in the links form, which the chain form calls",
	),
	(
		"rev-entitled-only-from-ancestors",
		"chain/revocation.c",
		"\tfor (j = 0; j <= h->i; j++)\n",
		"\tfor (j = 0; j < h->hop_count; j++)\n",
		"entitlement starts at a key's FIRST grant, so a descendant may not revoke its ancestor; was rev-first-break until sec 397 rewrote the walk as a per-hop count",
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
		"\t\tif (!store->entries[e].withdrawn)\n\t\t\tlive++;\n",
		"\t\tlive++;\n",
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
		"\t} else if (!fzn_ct_memeq(fzn_hop_grantor(hops[0]), root, FZN_PUBKEY_LEN)) {\n",
		"\t} else if (0) {\n",
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
		"\t    && memcmp(file->issuer, issuer, FZN_PUBKEY_LEN) == 0)\n\t\treturn file->fd;",
		"\t    && memcmp(file->issuer, issuer, 1u) == 0)\n\t\treturn file->fd;",
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
	(
		"persist-identity-open-refuses-a-zero-seed",
		"persist/persist.c",
		"\tif (fzn_ct_memeq(bytes + OFF_BODY, ZERO_SEED, FZN_SIGN_SEED_LEN))\n\t\treturn FZN_PERSIST_ERR_SHAPE;\n",
		"",
		"an all-zero seed derives a key anybody can compute, and a stored file of zeroes is far likelier truncated than chosen -- opened, a host restores as an identity everyone can sign for -- sec 375",
	),
	(
		"persist-identity-pack-refuses-a-zero-seed",
		"persist/persist.c",
		"\tif (fzn_ct_memeq(seed, ZERO_SEED, FZN_SIGN_SEED_LEN))\n\t\treturn FZN_PERSIST_ERR_MALFORMED;\n",
		"",
		"a caller holding an unfilled seed buffer would store a key everybody holds, and the open side's refusal then turns a successful save into a host that cannot start -- refused where the mistake is made -- sec 375",
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
		"\treturn crypto_ed25519_check(sig, pubkey, msg, msg_len) == 0;\n",
		"\treturn 1;\n",
		"the whole of this binding is the polarity inversion in its comment, and a verifier that accepts everything is the one defect in this tree that nothing above it can catch",
	),
	(
		"sign-seat-copies-the-seed",
		"chain/sign_monocypher.c",
		"\tcrypto_ed25519_key_pair(state->secret_key, pubkey_out, scratch);\n",
		"\tcrypto_ed25519_key_pair(state->secret_key, pubkey_out, (uint8_t *)seed);\n",
		"crypto_ed25519_key_pair wipes the seed it is given, and the seed a caller seats is the store's only copy of a node's identity -- handed over directly, restoring an identity destroys it -- sec 375",
	),
	(
		"sign-is-rfc8032-ed25519",
		"chain/sign_monocypher.c",
		"\tcrypto_ed25519_sign(sig, state->secret_key, msg, msg_len);\n",
		"\tcrypto_eddsa_sign(sig, state->secret_key, msg, msg_len);\n",
		"signing with EdDSA-BLAKE2b is what this binding did until sec 390: every signature is well-formed, verifies nowhere standard, and only RFC 8032's own vector can tell -- sec 390",
	),
	(
		"sign-seat-arms-the-signer",
		"chain/sign_monocypher.c",
		"\tstate->can_sign = 1;\n\treturn 1;\n",
		"\treturn 1;\n",
		"a seat that derives the key and leaves can_sign clear reports success and then refuses every signature, so a node boots with an identity it cannot sign as -- sec 375",
	),
	(
		"identity-boot-refuses-a-partial-store",
		"node/identity.c",
		"\tif (absent == 3u) {\n",
		"\tif (absent >= 1u) {\n",
		"a store missing its anchor but holding its seed is a node that had joined an estate, and creating over it self-roots that node silently out of the estate -- the repair is the attack -- sec 375",
	),
	(
		"identity-boot-could-not-tell-is-not-absent",
		"node/identity.c",
		"\t\telse if (parts[i] == FZN_PERSIST_ERR_ABSENT)\n\t\t\tabsent++;\n",
		"\t\telse if (parts[i] != FZN_PERSIST_OK)\n\t\t\tabsent++;\n",
		"a disk that was briefly unreadable reads as a first run, and the node generates itself a new identity over the one it could not see -- sec 375",
	),
	(
		"identity-self-root-must-be-this-key",
		"node/identity.c",
		"\tif (fzn_trust_source_of(trust) == FZN_TRUST_SELF\n\t    && memcmp(root, pubkey, FZN_PUBKEY_LEN) != 0) {\n",
		"\tif (0) {\n",
		"a self-root naming another key means the store holds parts of two nodes, and loading it makes a node that verifies chains against somebody else's root while calling it its own -- sec 375",
	),
	(
		"identity-prekey-verified-by-its-signer",
		"node/identity.c",
		"\tif (fzn_prekey_open(record_bytes, sizeof(record_bytes), &record) != FZN_PREKEY_OK\n\t    || fzn_prekey_verify(record, env->sign) != FZN_PREKEY_OK)\n",
		"\tif (fzn_prekey_open(record_bytes, sizeof(record_bytes), &record) != FZN_PREKEY_OK)\n",
		"the env cannot enforce that sign is the signer seat armed, and without this check the record names one key and carries another's signature -- every card this node hands out fails to verify somewhere else -- sec 375",
	),
	(
		"identity-load-hands-over-only-on-success",
		"node/identity.c",
		"\tif (result == FZN_NODE_IDENTITY_OK)\n\t\thand_over(&sk, &tr, agree_secret, trust, out);\n",
		"\thand_over(&sk, &tr, agree_secret, trust, out);\n",
		"a refused load that writes the caller's secret and anchor anyway replaces a live identity with the parts of a store it just called unusable -- sec 375",
	),
	(
		"pair-refuses-a-node-that-is-not-root",
		"node/pair.c",
		"\t\tif (memcmp(root, id->pubkey, FZN_PUBKEY_LEN) != 0)\n\t\t\treturn FZN_NODE_PAIR_NOT_ROOT;\n",
		"",
		"a node that joined an estate mints grants with its own key as root, so the device pairs and is then refused on its first request by the root the node checks -- a failure that looks like the network -- sec 376",
	),
	(
		"pair-saves-before-the-card",
		"node/pair.c",
		"\tif (fzn_node_peer_save(store, &peer) != FZN_PERSIST_OK) {\n",
		"\tif (fzn_node_peer_save(store, &peer) != FZN_PERSIST_OK && 0) {\n",
		"a card handed out for a device the store refused is a pairing that works on the device's side and nowhere else -- sec 376",
	),
	(
		"accept-card-grant-must-be-this-device",
		"node/provision.c",
		"\t    || memcmp(chain.grantee, device->pubkey, FZN_PUBKEY_LEN) != 0)\n\t\treturn FZN_NODE_PROVISION_NOT_MINE;\n",
		"\t    )\n\t\treturn FZN_NODE_PROVISION_NOT_MINE;\n",
		"a device handed another device's card accepts it and derives a session the node has no peer for, then fails on its first request in a way that looks like the network -- sec 377",
	),
	(
		"pairing-open-capability-agrees-with-hop",
		"node/pair.c",
		"\tif (memcmp(bytes + OFF_CHAIN + (n - 1u) * FZN_HOP_LEN + FZN_HOP_OFF_CAPABILITY,\n\t           bytes + OFF_CAP, FZN_CAP_ID_LEN) != 0)\n\t\treturn FZN_PERSIST_ERR_SHAPE;\n",
		"",
		"two copies of the capability in one blob that need not agree are two encodings of it, and the device would present one grant while holding another -- sec 377",
	),
	(
		"pairing-load-node-matches-its-name",
		"node/pair.c",
		"\tif (memcmp(p.node, node, FZN_PUBKEY_LEN) != 0) {\n\t\tfzn_wipe(&p, sizeof(p));\n\t\treturn FZN_PERSIST_ERR_SHAPE;\n\t}\n",
		"",
		"a pairing filed under one node and naming another sends this device's requests under keys meant for somebody else -- sec 377",
	),
	(
		"admin-mutating-verb-needs-own-user",
		"node/admin.c",
		"\tif (fzn_verb_mutates(request->parsed) && origin != FZN_ORIGIN_SAME_USER)\n",
		"\tif (fzn_verb_mutates(request->parsed) && origin == FZN_ORIGIN_NONE)\n",
		"a group that may connect is not a group that may change the node -- raidcfgd's rule and the reason local/vocabulary.h exists; without it any service-group member pairs devices into the node -- sec 378",
	),
	(
		"admin-reloads-the-running-peer-set",
		"node/admin.c",
		"\tadmin->state->peers = admin->peers;\n\tadmin->state->peer_count = loaded;\n\tif (!log_grant(admin, record.host))",
		"\tif (!log_grant(admin, record.host))",
		"a device paired into a running node that the loop's peer set never learns of is paired on disk and refused on the wire until a restart -- the thing add peer exists to avoid -- sec 378",
	),
	(
		"admin-remove-reloads-the-running-set",
		"node/admin.c",
		"\tadmin->state->peers = admin->peers;\n\tadmin->state->peer_count = loaded;\n\treturn answer(reply, cap, FZN_REPLY_OK, (const char *)hex, hex_len);\n",
		"\treturn answer(reply, cap, FZN_REPLY_OK, (const char *)hex, hex_len);\n",
		"a device the store has forgotten and the running set still holds is cut off on paper and served on the wire until a restart -- the operator has just been told it is gone -- sec 379",
	),
	(
		"admin-list-refuses-past-the-end",
		"node/admin.c",
		"\tif (from > total)\n\t\treturn answer_text(reply, cap, FZN_REPLY_MALFORMED, \"past the last peer\");\n",
		"",
		"an offset past the end answered ok with no keys reads as a node holding nothing from there, so a caller walking pages from a stale offset is told the list ended rather than that it asked wrongly -- sec 379",
	),
	(
		"file-remove-absent-is-gone",
		"persist/persist_file.c",
		"\tif (unlink(path) == 0 || errno == ENOENT)\n",
		"\tif (unlink(path) == 0)\n",
		"a second removal answering failure makes a retry after a lost reply look like a fault, and the caller's question was whether it is gone -- sec 379",
	),
	(
		"file-list-matches-the-whole-prefix",
		"persist/persist_file.c",
		"\t\tif (memcmp(n, prefix, prefix_len) != 0)\n",
		"\t\tif (memcmp(n, prefix, 1u) != 0)\n",
		"slots of the same width differ only past their first digit, so a listing that compared less than the whole prefix would hand one slot's subjects to another's loader -- sec 382",
	),
	(
		"pair-authority-must-be-delegable",
		"node/pair.c",
		"\t\t    || !fzn_hop_delegable(views[own - 1u]))\n",
		"\t\t    )\n",
		"a node extending a grant it was not allowed to pass on mints chains the estate's verifier refuses, so every device it pairs is refused on its first request -- sec 383",
	),
	(
		"pair-authority-must-name-this-node",
		"node/pair.c",
		"\t\t    || memcmp(verdict.grantee, id->pubkey, FZN_PUBKEY_LEN) != 0\n",
		"",
		"a node extending another node's grant signs a hop whose grantor is not the previous grantee, a chain nothing verifies -- sec 383",
	),
	(
		"join-requires-a-delegable-grant",
		"node/pair.c",
		"\tif (!fzn_hop_delegable(hop))\n\t\treturn FZN_NODE_PAIR_CANNOT_JOIN;\n",
		"",
		"a node joined on a grant it cannot pass on is pinned to an estate it can serve nobody in, since a joined node serves only devices it pairs itself -- sec 383",
	),
	(
		"remote-consults-the-revocations",
		"node/remote.c",
		"\t\t                          sign, config->revocations, NULL);\n",
		"\t\t                          sign, NULL, NULL);\n",
		"the node holding a revocation and deciding without it honours every grant it has revoked, which is how the remote path stood until sec 380 -- sec 380",
	),
	(
		"revoke-saves-the-record",
		"node/revoke.c",
		"\tif (!store->save(store->ctx, FZN_PERSIST_ISSUED_REVOCATION, grantee, blob, sizeof(blob)))\n\t\treturn FZN_NODE_REVOKE_NOT_SAVED;\n",
		"",
		"a revocation in force and never saved is forgotten by the next start, and the device the operator revoked is served again -- sec 380",
	),
	(
		"revoke-already-is-already",
		"node/revoke.c",
		"\t\t\t\treturn FZN_NODE_REVOKE_ALREADY;\n\t\t\tif (!id->hash->hash(id->hash->ctx, target",
		"\t\t\t\t;\n\t\t\tif (!id->hash->hash(id->hash->ctx, target",
		"revoking a revoked grantee again must say so rather than mint a second record the store refuses as a stale copy, which an operator reads as the revocation having failed -- sec 380",
	),
	(
		"revocations-load-skips-pre-join",
		"node/revoke.c",
		"\t\t\telse\n\t\t\t\tcontinue;\t/* see the header */\n",
		"\t\t\telse\n\t\t\t\toffer = fzn_revocation_offer_root(rec);\n",
		"a record a node issued as its own root before it joined verifies against nothing it now trusts, so admitting it fails the whole load and the node will not start -- sec 383, 384",
	),
	(
		"votes-stale-copy-not-saved",
		"node/revoke.c",
		"\tif (err != FZN_CHAIN_OK || !holds_exactly(revocations, hash, pull->record, rec)) {\n",
		"\tif (err != FZN_CHAIN_OK) {\n",
		"a stale copy that admission accepts without taking would be saved over the withdrawal that superseded it, and a restart revokes again -- sec 399",
	),
	(
		"votes-refusal-does-not-stop-the-pull",
		"node/revoke.c",
		"\t\tpull->refused++;\n\t\treturn FZN_NODE_PULL_OK;\n",
		"\t\tpull->refused++;\n\t\treturn FZN_NODE_PULL_REFUSED;\n",
		"a pull from any peer that stops at the first vote it cannot admit lets one peer's junk keep this node from learning the rest -- sec 399",
	),
	(
		"votes-load-reads-learned-votes",
		"node/revoke.c",
		"\t\t\treturn FZN_PERSIST_ERR_BACKEND;\n\t\tfor (i = 0; i < found; i++) {\n\t\t\tuint8_t record[FZN_REVOCATION_LEN];\n\t\t\tfzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];\n",
		"\t\t\treturn FZN_PERSIST_ERR_BACKEND;\n\t\tfound = 0;\n\t\tfor (i = 0; i < found; i++) {\n\t\t\tuint8_t record[FZN_REVOCATION_LEN];\n\t\t\tfzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];\n",
		"a restart that does not re-admit learned votes forgets every vote it did not issue, and a revocation falls short of its quorum again -- sec 399",
	),
	(
		"votes-load-skips-only-the-superseded",
		"node/revoke.c",
		"\t\t\t\t                         fzn_revocation_grantee(rec)))\n\t\t\t\t\tcontinue;\n\t\t\t\treturn FZN_PERSIST_ERR_SHAPE;\n",
		"\t\t\t\t                         fzn_revocation_grantee(rec)))\n\t\t\t\t\tcontinue;\n\t\t\t\tcontinue;\n",
		"a learned vote that will not admit and whose triple nothing else holds is a store changed underneath the node, not a copy to skip -- sec 399",
	),
	(
		"votes-load-superseded-is-not-fatal",
		"node/revoke.c",
		"\t\t\t\t                         fzn_revocation_grantee(rec)))\n\t\t\t\t\tcontinue;\n",
		"\t\t\t\t                         fzn_revocation_grantee(rec)))\n\t\t\t\t\treturn FZN_PERSIST_ERR_SHAPE;\n",
		"a node whose own vote came back from a peer and was then withdrawn would refuse to start -- sec 399",
	),
	(
		"revoke-member-offers-its-chain",
		"node/revoke.c",
		"\t                            authority ? fzn_revocation_offer_chain(rec, hops,\n\t                                                                   authority->hop_count)\n\t                                      : fzn_revocation_offer_root(rec),\n",
		"\t                            fzn_revocation_offer_root(rec),\n",
		"a member's revocation offered as the root's names an issuer that is not the root, so the store refuses it and the member cannot cut off a device it paired -- sec 385",
	),
	(
		"revoke-member-needs-delegable",
		"node/revoke.c",
		"\t                     FZN_PUBKEY_LEN) != 0\n\t           || !fzn_hop_delegable(hops[authority->hop_count - 1u])) {\n",
		"\t                     FZN_PUBKEY_LEN) != 0) {\n",
		"a holder whose grant cannot be passed on is no grantor and has no standing to revoke; asking late reports the refusal as a full store -- sec 385",
	),
	(
		"revocations-load-admits-own-through-chain",
		"node/revoke.c",
		"\t\t\telse if (self && memcmp(fzn_revocation_issuer(rec), self, FZN_PUBKEY_LEN) == 0\n",
		"\t\t\telse if (0 && self && memcmp(fzn_revocation_issuer(rec), self, FZN_PUBKEY_LEN) == 0\n",
		"a member that does not re-admit its own revocations at start serves every device it cut off again after a restart -- sec 385",
	),
	(
		"revocations-load-own-capability-only",
		"node/revoke.c",
		"\t\t\telse if (self && memcmp(fzn_revocation_issuer(rec), self, FZN_PUBKEY_LEN) == 0\n\t\t\t         && memcmp(fzn_revocation_capability(rec), granted,\n\t\t\t                   sizeof(*granted)) == 0)\n",
		"\t\t\telse if (self && memcmp(fzn_revocation_issuer(rec), self, FZN_PUBKEY_LEN) == 0)\n",
		"a member's record for a capability its chain does not carry can never admit, and offering it fails the whole load, so the node will not start -- sec 385",
	),
	(
		"unrevoke-names-the-whole-record",
		"node/revoke.c",
		"\t\tif (!id->hash->hash(id->hash->ctx, target, sizeof(target), previous,\n\t\t                    sizeof(previous)))\n",
		"\t\tif (!id->hash->hash(id->hash->ctx, target, sizeof(target), previous,\n\t\t                    sizeof(previous) - 1u))\n",
		"a withdrawal names the record it undoes by the hash of all of it; any other hash names nothing the store holds, and the undo is refused -- sec 386",
	),
	(
		"unrevoke-only-what-is-in-force",
		"node/revoke.c",
		"\t\tif (!held || fzn_revocation_is_withdrawal(prev_rec))\n\t\t\treturn FZN_NODE_REVOKE_NOT_REVOKED;\n",
		"\t\tif (!held)\n\t\t\treturn FZN_NODE_REVOKE_NOT_REVOKED;\n",
		"undoing a withdrawal mints a withdrawal of a withdrawal, which admission refuses, and an operator is told the store failed rather than that there was nothing to undo -- sec 386",
	),
	(
		"admin-serves-remove-revocation",
		"node/admin.c",
		"\tif (request->parsed == FZN_VERB_REMOVE && subject_revocation(request, &rest, &rest_len)\n\t    && rest && admin->revocations)\n\t\treturn unrevoke_peer(admin, rest, rest_len, reply, reply_cap);\n",
		"",
		"with no verb to undo a revocation, an operator who revoked the wrong device can only re-pair it under a new key -- sec 386",
	),
	(
		"roster-a-suspension-is-not-active",
		"roster/roster.c",
		"\tif (distinct > 0u)\n\t\treturn FZN_ROSTER_SUSPENDED;\n",
		"",
		"a removal that does not suspend leaves the removed contact active until agreement, which is fuzzypickles' location leak -- sec 394",
	),
	(
		"roster-expiry-does-not-withdraw",
		"roster/roster.c",
		"\t                     authority->capability, latest, authority->sign, NULL, NULL, &verdict)\n",
		"\t                     authority->capability, (uint64_t)1000u, authority->sign, NULL, NULL, &verdict)\n",
		"judged against a clock, a record written while its grant held is refused once the grant expires, and only a revocation withdraws -- sec 394",
	),
	(
		"roster-revoked-writer-counts-for-nothing",
		"roster/roster.c",
		"\t\tif (revoked[i]\n\t\t    && !fzn_revocation_act_stands(",
		"\t\tif (0 && revoked[i]\n\t\t    && !fzn_revocation_act_stands(",
		"a writer counted whatever its revocations lets a revoked, stolen device add contacts and suspend or retire the user's roster -- sec 394",
	),
	(
		"roster-second-add-conflicts",
		"roster/roster.c",
		"\t\t\treturn FZN_ROSTER_OK;\t/* the same add, again */\n\t\treturn FZN_ROSTER_ERR_CONFLICT;\n",
		"\t\t\treturn FZN_ROSTER_OK;\t/* the same add, again */\n",
		"a second, different add of one incarnation silently rewrites which add it was, so the answer depends on which arrived last -- sec 388",
	),
	(
		"roster-verifies-under-writer",
		"roster/roster.c",
		"\tif (!authority->sign->verify(authority->sign->ctx, fzn_roster_writer(rec), rec.base,\n",
		"\tif (!authority->sign->verify(authority->sign->ctx, authority->root, rec.base,\n",
		"a record verified under any key but its own writer's lets one host speak as another, and standing is then checked for the wrong key -- sec 388",
	),
	(
		"roster-standing-names-the-writer",
		"roster/roster.c",
		"\treturn memcmp(verdict.grantee, writer, FZN_PUBKEY_LEN) == 0;\n",
		"\treturn 1;\n",
		"any valid chain from the root would give any writer standing, including one granted to somebody else -- sec 388",
	),
	(
		"roster-add-carries-no-body",
		"roster/roster.c",
		"\tif (object != (uint8_t)FZN_OBJECT_ROSTER_SET\n\t    && (body_len != 0u || bytes[FZN_ROSTER_OFF_SETTING] != 0u\n\t        || bytes[FZN_ROSTER_OFF_SETTING + 1u] != 0u))\n\t\treturn FZN_ROSTER_ERR_SHAPE;\n",
		"",
		"an add carrying a setting or a body is a second encoding of one statement, signed and read by nothing -- sec 388",
	),
	(
		"revocation-quorum-counts",
		"chain/revocation.c",
		"\tsize_t i, q = store->quorum ? store->quorum : 1u;\n",
		"\tsize_t i, q = 1u;\n",
		"a quorum nobody reads makes one entitled issuer enough, which is the single stolen admin sec 394's k-of-n exists to stop -- sec 397",
	),
	(
		"revocation-latch-holds",
		"chain/revocation.c",
		"\tif (cast >= q && left < q) {\n\t\tif (current)\n\t\t\t*current = epoch;\n\t\treturn HOP_LATCHED;\n\t}\n",
		"",
		"with no latch one withdrawal undoes a k-of-n revocation, so a single admin can reinstate what k agreed to remove -- sec 397",
	),
	(
		"revocation-second-stratum-drops-fallen-admins",
		"chain/revocation.c",
		"\tjudge_links(store, grantors, grantees, hop_count, capability, admin_ok, revoked);\n",
		"\tjudge_links(store, grantors, grantees, hop_count, capability, NULL, revoked);\n",
		"judged in one stratum, an admin whose own chain is revoked still votes, and two admins revoking each other leave an answer that depends on order -- sec 397",
	),
	(
		"revocation-admin-chain-names-the-issuer",
		"chain/revocation.c",
		"\tif (!fzn_ct_memeq(verdict.grantee, issuer, FZN_PUBKEY_LEN))\n\t\treturn FZN_CHAIN_ERR_CHAIN_INVALID;\n",
		"",
		"any admin's chain would let anybody vote as an admin by stapling it to their own record -- sec 397",
	),
	(
		"revocation-admin-second-chain-conflicts",
		"chain/revocation.c",
		"\t\treturn memcmp(&store->admins[a], &ad, sizeof(ad)) == 0 ? FZN_CHAIN_OK\n\t\t                                                        : FZN_CHAIN_ERR_CHAIN_INVALID;\n",
		"\t\treturn FZN_CHAIN_OK;\n",
		"an admin shown on two chains keeps whichever arrived first, so whether its vote survives a revocation of one road depends on arrival order -- sec 397",
	),
	(
		"revocation-quorum-refuses-zero",
		"chain/revocation.c",
		"\tif (!store || quorum == 0u)\n\t\treturn FZN_CHAIN_ERR_MALFORMED;\n\tif (admin_capability",
		"\tif (!store)\n\t\treturn FZN_CHAIN_ERR_MALFORMED;\n\tif (admin_capability",
		"a caller asking for quorum 0 has made a mistake, and reading it as 1 would hide it -- sec 397",
	),
	(
		"revocation-set-k-refuses-zero",
		"chain/revocation.c",
		"\tif (!store || quorum == 0u)\n\t\treturn FZN_CHAIN_ERR_MALFORMED;\n\tif (store->quorum != quorum) {",
		"\tif (!store)\n\t\treturn FZN_CHAIN_ERR_MALFORMED;\n\tif (store->quorum != quorum) {",
		"a k of 0 taken by the store reads as 1, so one issuer revokes alone -- sec 418",
	),
	(
		"revocation-epoch-closes-at-k",
		"chain/revocation.c",
		"\t\t    && (entry->epoch > epoch || (entry->epoch == epoch && entry->withdrawn)))\n\t\t\tleft++;\n\t}\n\treturn left >= q;\n",
		"\t\t    && (entry->epoch > epoch || (entry->epoch == epoch && entry->withdrawn)))\n\t\t\tleft++;\n\t}\n\treturn left >= 1u;\n",
		"an epoch one issuer can close is a latch one issuer can open, which is the single stolen admin the latch exists to stop -- sec 400",
	),
	(
		"revocation-epoch-past-counts-as-leaving",
		"chain/revocation.c",
		"\t\t    && (entry->epoch > epoch || (entry->epoch == epoch && entry->withdrawn)))\n",
		"\t\t    && (entry->epoch == epoch && entry->withdrawn))\n",
		"an issuer that has moved to a later epoch has left this one, and not counting it leaves an undone epoch shut for ever once its voters re-vote -- sec 400",
	),
	(
		"revocation-withdrawal-names-its-epoch",
		"chain/revocation.c",
		"\t\tif (store->entries[at].epoch != fzn_revocation_epoch(record))\n\t\t\treturn FZN_CHAIN_ERR_UNKNOWN_TARGET;\n",
		"",
		"a withdrawal that may name another epoch than its revocation's counts toward closing an epoch its vote was never in -- sec 400",
	),
	(
		"revocation-epoch-recorded-on-append",
		"chain/revocation.c",
		"\tstore->entries[store->used].epoch = fzn_revocation_epoch(record);\n\tmemcpy(store->entries[store->used].held, id, FZN_REVOCATION_ID_LEN);\n\tmemcpy(store->entries[store->used].cut, fzn_revocation_cut(record), FZN_REVOCATION_ID_LEN);\n\tstore->used++;\n\t/* An answer",
		"\tmemcpy(store->entries[store->used].held, id, FZN_REVOCATION_ID_LEN);\n\tmemcpy(store->entries[store->used].cut, fzn_revocation_cut(record), FZN_REVOCATION_ID_LEN);\n\tstore->used++;\n\t/* An answer",
		"an entry that does not keep its record's epoch is judged in whatever epoch its slot held -- sec 400",
	),
	(
		"revocation-epoch-recorded-on-re-revocation",
		"chain/revocation.c",
		"\t\t\tentry->withdrawn = 0;\n\t\t\tentry->epoch = fzn_revocation_epoch(record);\n",
		"\t\t\tentry->withdrawn = 0;\n",
		"a re-revocation left in its withdrawn vote's epoch re-shuts the latch an undo opened, which is the defect sec 399 found -- sec 400",
	),
	(
		"node-votes-in-the-open-epoch",
		"node/revoke.c",
		"\t\t\tcerr = fzn_revocation_reissue(\n\t\t\t        id->pubkey, capability, grantee, now,\n\t\t\t        fzn_revocation_current_epoch(revocations, root, capability, grantee),\n",
		"\t\t\tcerr = fzn_revocation_reissue(\n\t\t\t        id->pubkey, capability, grantee, now, 0u,\n",
		"a node re-voting in the epoch an undo closed is ignored under the root's floor, or re-shuts the latch on its own vote -- secs 400, 403",
	),
	(
		"revocation-root-revokes-alone",
		"chain/revocation.c",
		"\t\tif (!entry->withdrawn)\n\t\t\treturn 1;\n\t\tif (!h->has_floor || entry->epoch > h->floor)\n",
		"\t\tif (!h->has_floor || entry->epoch > h->floor)\n",
		"a root that is one vote of k cannot cut off a lost device from a lone surviving host -- sec 403",
	),
	(
		"revocation-root-undo-sets-the-floor",
		"chain/revocation.c",
		"\t\t\th->floor = entry->epoch;\n\t\th->has_floor = 1;\n",
		"\t\t\th->floor = entry->epoch;\n",
		"a root's undo that leaves the votes of its epoch counting cannot open a latch the admins shut -- sec 403",
	),
	(
		"revocation-root-undo-moves-the-next-vote",
		"chain/revocation.c",
		"\t\tfirst = h->floor + 1u;\n",
		"\t\tfirst = 0u;\n",
		"a vote cast after a root's undo into the undone epoch is ignored by the floor, so a re-vote would count for nothing -- sec 403",
	),
	(
		"roster-root-retires-alone",
		"roster/roster.c",
		"\t\tif (w->hop_count == 0u)\n\t\t\treturn FZN_ROSTER_RETIRED;\n",
		"",
		"a root that must find k - 1 others to retire a contact cannot act for the estate from a lone surviving host -- sec 403",
	),
	(
		"root-set-removed-acts-need-the-cut",
		"chain/root_log.c",
		"\t\tif (!acts || all_zero(c->cut, FZN_ROOT_ACT_ID_LEN)\n\t\t    || !acts->stands(acts->ctx, root, c->cut, act))\n\t\t\treturn 0;\n",
		"",
		"a removed root whose every act still counts is a stolen root that was never removed -- sec 405",
	),
	(
		"root-set-an-add-counts-as-an-act",
		"chain/root_log.c",
		"\t\t\tif (counts_in(set, acts, st, c->signer, c->id)) {\n",
		"\t\t\tif (member_in(set, st, c->signer)) {\n",
		"an add judged by who signed it rather than whether that act counts lets a thief's root, added after the cut, stand -- sec 405",
	),
	(
		"root-set-removal-needs-a-member",
		"chain/root_log.c",
		"\t\t\tif (!is_add(&set->changes[i])\n\t\t\t    && member_in(set, st, set->changes[i].signer))\n",
		"\t\t\tif (!is_add(&set->changes[i]))\n",
		"a removal counted from any signer lets a root the thief added after the cut remove the honest root -- sec 405",
	),
	(
		"root-set-genesis-is-a-member",
		"chain/root_log.c",
		"\tif (fzn_ct_memeq(set->genesis, key, FZN_PUBKEY_LEN))\n\t\treturn 1;\n",
		"",
		"a set whose genesis root is not a member has no root to start from -- sec 405",
	),
	(
		"root-set-unsettled-takes-every-removal",
		"chain/root_log.c",
		"\tmemcpy(st->rem_ok, seen, sizeof(seen));\n\tgrow_members(set, acts, st);\n",
		"",
		"a set that never settles, answered from whichever round came last, answers by the parity of its record count rather than toward removal -- sec 405",
	),
	(
		"chain-a-removed-roots-grant-must-count",
		"chain/chain.c",
		"\t\t                                     hops[0].base, FZN_HOP_LEN)\n\t\t    || !set->counts(set->ctx, fzn_hop_grantor(hops[0]), act))\n",
		"\t\t                                     hops[0].base, FZN_HOP_LEN))\n",
		"a chain from a removed root verifying whatever its cut says is a stolen root's grants still honoured -- sec 406",
	),
	(
		"revocation-admits-a-member-root",
		"chain/revocation.c",
		"\t    && !(store->roots\n\t         && store->roots->member(store->roots->ctx, fzn_revocation_issuer(record))))\n",
		"\t    && 1)\n",
		"a second root whose revocations are refused as another estate's cannot act alone for the estate -- sec 406",
	),
	(
		"revocation-a-root-entry-must-count",
		"chain/revocation.c",
		"\t\treturn store->roots->member(store->roots->ctx, entry->issuer)\n\t\t       && store->roots->counts(store->roots->ctx, entry->issuer, entry->held);\n",
		"\t\treturn store->roots->member(store->roots->ctx, entry->issuer);\n",
		"a removed root whose revocations after its cut still count is a thief whose removals still stand -- sec 406",
	),
	(
		"revocation-a-root-is-entitled-everywhere",
		"chain/revocation.c",
		"\tif (store->roots && store->roots->member(store->roots->ctx, entry->issuer))\n\t\treturn root_entry(store, entry, NULL);\n",
		"",
		"a root that may revoke only the chains it began is not the estate's full authority -- sec 406",
	),
	(
		"revocation-an-entry-holds-its-record",
		"chain/revocation.c",
		"\tmemcpy(store->entries[store->used].held, id, FZN_REVOCATION_ID_LEN);\n\tmemcpy(store->entries[store->used].cut, fzn_revocation_cut(record), FZN_REVOCATION_ID_LEN);\n\tstore->used++;\n",
		"\tmemcpy(store->entries[store->used].cut, fzn_revocation_cut(record), FZN_REVOCATION_ID_LEN);\n\tstore->used++;\n",
		"an entry that does not know which record it holds cannot be asked about a removed root's log, and its revocation before the cut stops counting -- sec 406",
	),
	(
		"root-view-counts-is-counts",
		"chain/root_log.c",
		"\treturn fzn_root_view_counts((const fzn_root_view_t *)ctx, root, act);\n",
		"\t(void)act;\n\treturn fzn_root_view_member((const fzn_root_view_t *)ctx, root);\n",
		"a view whose counts answers membership honours everything a removed root ever did -- sec 406",
	),
	(
		"node-roots-learn-refuses-what-will-not-admit",
		"node/roots.c",
		"\tif (admit(roots, bytes, len) != FZN_ROOT_LOG_OK)\n\t\treturn FZN_NODE_ROOTS_REFUSED;\n",
		"\t(void)admit(roots, bytes, len);\n",
		"a node that saves a root record nobody signed makes it count at the next restart -- sec 407",
	),
	(
		"node-roots-learn-settles-the-view",
		"node/roots.c",
		"\t\treturn FZN_NODE_ROOTS_REFUSED;\n\tsettle(roots);\n",
		"\t\treturn FZN_NODE_ROOTS_REFUSED;\n",
		"a root learned and not settled into the view is not a root until the node restarts -- sec 407",
	),
	(
		"node-roots-load-admits-or-fails",
		"node/roots.c",
		"\t\t    || admit(roots, blob + FZN_PERSIST_HEAD_LEN, body) != FZN_ROOT_LOG_OK)\n\t\t\treturn FZN_NODE_ROOTS_STORE;\n",
		"\t\t    || (admit(roots, blob + FZN_PERSIST_HEAD_LEN, body), 0))\n\t\t\treturn FZN_NODE_ROOTS_STORE;\n",
		"a stored root record that no longer verifies, skipped at start, is a changed store the node carries on over -- sec 407",
	),
	(
		"node-roots-own-key-acts-only-standing",
		"node/roots.c",
		"\tif (roots->key_held && fzn_root_view_stands(&roots->view, roots->key)) {\n",
		"\tif (roots->key_held) {\n",
		"a node that acts as a root with a key no root ever added makes itself a root -- sec 409",
	),
	(
		"node-roots-forked-log-is-not-extended",
		"node/roots.c",
		"\tif (roots->journal && fzn_node_journal_forked(roots->journal, pubkey))\n\t\treturn FZN_NODE_ROOTS_FORKED;\n",
		"",
		"extending a forked log picks a branch, which is the thief's choice to make as readily as the owner's -- sec 409",
	),
	(
		"node-roots-a-change-is-logged",
		"node/roots.c",
		"\terr = fzn_node_roots_log_act(roots, store, as, sign,\n",
		"\terr = FZN_NODE_ROOTS_OK;\n\tif (0) err = fzn_node_roots_log_act(roots, store, as, sign,\n",
		"a root change that is in the set and not in its root's log falls at that root's removal whatever the cut -- sec 409",
	),
	(
		"node-roots-one-key-per-node",
		"node/roots.c",
		"\tif (roots->key_held\n\t    || store->load(store->ctx, FZN_PERSIST_OWN_ROOT, NULL, probe, sizeof(probe), &len)) {\n",
		"\tif (0) {\n",
		"a second root key made over the first loses the first, and with it a root the estate still counts -- sec 409",
	),
	(
		"admin-a-root-revocation-is-logged",
		"node/revoke.c",
		"\tif (roots\n\t    && fzn_node_roots_log_signed(roots, store, id->pubkey, id->sign, id->pubkey,\n",
		"\tif (0\n\t    && fzn_node_roots_log_signed(roots, store, id->pubkey, id->sign, id->pubkey,\n",
		"a revocation not logged where it is made falls at its signer's removal whatever its cut, and never reaches the journal -- secs 409, 504",
	),
	(
		"admin-local-changes-roots",
		"node/admin.c",
		"\tif ((request->parsed == FZN_VERB_ADD || request->parsed == FZN_VERB_REMOVE)\n\t    && subject_word(request, \"root\", &rest, &rest_len) && rest && admin->roots)\n",
		"\tif (0)\n",
		"a node whose owner cannot add or remove a root has a root set nobody can change -- sec 409",
	),
	(
		"roster-tie-goes-to-greater-writer",
		"roster/roster.c",
		"\t              FZN_PUBKEY_LEN) > 0;\n",
		"\t              FZN_PUBKEY_LEN) < 0;\n",
		"two hosts must break a tie between live incarnations the same way, and the rule written down is the greater writer -- sec 388",
	),
	(
		"roster-writer-accessor-reads-the-writer",
		"roster/roster.h",
		"\treturn rec.base + FZN_ROSTER_OFF_WRITER;\n",
		"\treturn rec.base + FZN_ROSTER_OFF_SUBJECT;\n",
		"an accessor reading the subject as the writer verifies every record under the key it is about, not the key that signed it -- sec 388",
	),
	(
		"roster-retires-at-k",
		"roster/roster.c",
		"\tif (distinct >= k)\n\t\treturn FZN_ROSTER_RETIRED;\n",
		"\tif (distinct > k)\n\t\treturn FZN_ROSTER_RETIRED;\n",
		"retiring on one agreement more than the estate asks for leaves a removal suspended for good where the holder set k -- sec 394",
	),
	(
		"roster-retirement-counts-distinct-hosts",
		"roster/roster.c",
		"\t\tif (j == distinct)\n\t\t\tkeys[distinct++] = w->key;\n",
		"\t\tkeys[distinct++] = w->key;\n",
		"one host removing under two grants would count as two, and a single stolen device could retire what needs two -- sec 394",
	),
	(
		"roster-bundle-length-is-exact",
		"roster/roster.c",
		"\t    || record_len > FZN_ROSTER_MAX_LEN || len != FZN_ROSTER_BUNDLE_LEN(record_len, hop_count)\n",
		"\t    || record_len > FZN_ROSTER_MAX_LEN || len < FZN_ROSTER_BUNDLE_LEN(record_len, hop_count)\n",
		"a bundle with trailing bytes is a second encoding of one bundle, and a store keyed on the bytes holds both -- sec 389",
	),
	(
		"admin-remote-refuses-mutation",
		"node/admin.c",
		"\tif (fzn_verb_mutates(request.parsed))\n\t\treturn answer_text(out, reply_cap, FZN_REPLY_DENIED,\n\t\t                   \"a remote caller may not change this node\");\n",
		"",
		"a device's grant to use a node is not authority to change it; a remote caller told unsupported rather than denied has been told the verb is missing, not that it is refused -- sec 381",
	),
	(
		"admin-remote-silent-to-denied",
		"node/admin.c",
		"\tif (!admin || !admin->state || !req || !reply || result != FZN_NODE_REMOTE_GRANTED)\n",
		"\tif (!admin || !admin->state || !req || !reply || result == FZN_NODE_REMOTE_DROPPED)\n",
		"a caller the chain refused -- a revoked device among them -- would be answered, which tells it which node it reached and that the node is up -- sec 381",
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
		"spool-file-leaves-belong-to-this-blob",
		"spool/spool_file.c",
		"\tif (memcmp(head + BITS_OFF_ROOT, root, FZN_BLOB_HASH_LEN) != 0)\n\t\treturn FZN_SPOOL_ERR_ABSENT;\n",
		"\tif (0)\n\t\treturn FZN_SPOOL_ERR_ABSENT;\n",
		"a server asking whether it holds a root would read another blob's sidecar at that path as this blob held, and serve leaves that prove against nothing the asker named -- sec 424",
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
		"\"record/journal\", FLOG_CRIT,\n\t\t\t            \"journal full",
		"\"record/journal\", FLOG_WARN,\n\t\t\t            \"journal full",
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
		"\tif (!verifier->verify(verifier->ctx, sponsor, card.base,\n"
		"\t                      FZN_PROVISION_BODY_LEN(card.hop_count, card.proof_count),\n"
		"\t                      card.base + FZN_PROVISION_OFF_SIGNATURE(card.hop_count,\n"
		"\t                                                              card.proof_count)))\n"
		"\t\treturn FZN_PROVISION_ERR_SIGNATURE;\n",
		"\t(void)verifier;\n",
		"the three objects in a card are each public, so without the envelope anybody assembles a genuine hop with their own prekey record and the device sessions with them",
	),
	(
		"provision-tag-is-not-a-hop",
		"provision/provision.c",
		"\tif (bytes[FZN_PROVISION_OFF_OBJECT] != (uint8_t)FZN_OBJECT_CARD)\n"
		"\t\treturn FZN_PROVISION_ERR_SHAPE;\n",
		"",
		"a card's body opens with fields shared by other objects, so without the tag one signature could be read as more than one of them",
	),
	(
		"provision-chain-starts-at-root",
		"provision/provision.c",
		"\t\t    || memcmp(fzn_hop_grantor(hop), from, FZN_PUBKEY_LEN) != 0)\n",
		"\t\t    )\n",
		"a card naming a root its chain does not start at makes the device pin a root nobody granted it under -- sec 391, and since sec 410 the root its proof reaches",
	),
	(
		"cli-node-is-a-key",
		"cli/cli.c",
		"\t\tif (!parse_hex(value, NULL, FZN_PUBKEY_LEN))\n\t\t\treturn FZN_CLI_ERR_VALUE;\n",
		"",
		"a --node that is not 64 hex digits is taken as a key of zeroes, and the request goes to nobody's node -- sec 421",
	),
	(
		"cli-pair-is-a-prekey",
		"cli/cli.c",
		"\t\tif (!parse_hex(value, NULL, FZN_PREKEY_LEN_TOTAL))\n\t\t\treturn FZN_CLI_ERR_VALUE;\n",
		"",
		"a truncated prekey paste is taken as the option and refused later as some other failure -- sec 421",
	),
	(
		"cli-udp-port-is-a-port",
		"cli/cli.c",
		"\t\tif (!parse_u32(value, &number) || number > 65535u)\n",
		"\t\tif (!parse_u32(value, &number))\n",
		"a port past 65535 is cut to sixteen bits and the node serves on a port nobody named -- sec 421",
	),
	(
		"cli-flag-is-the-whole-word",
		"cli/cli.c",
		"\tif (strcmp(arg, \"--udp6\") == 0) {\n",
		"\tif (strncmp(arg, \"--udp6\", 6) == 0) {\n",
		"--udp6=no turns IPv6 on, and --udp6x is somebody else's option taken -- sec 421",
	),
	(
		"cli-node-option-once",
		"cli/cli.c",
		"\t\tif (cli->socket)\n\t\t\treturn FZN_CLI_ERR_DUPLICATE;\n",
		"",
		"two --socket values and the last silently wins: the operator reads one socket and the node serves another -- sec 421",
	),
	(
		"text-a-fresh-key",
		"notes/text.c",
		"\tif (!rng->fill(rng->ctx, key, sizeof(key)))\n\t\treturn FZN_NOTE_ERR_CRYPTO;\n",
		"\tmemset(key, 0, sizeof(key));\n",
		"one key over two texts repeats (key, index) pairs and breaks the AEAD -- sec 423",
	),
	(
		"text-open-names-this-blob",
		"notes/text.c",
		"\t    || !fzn_ct_memeq(spool->root, ref->root, FZN_BLOB_HASH_LEN) || spool->leaves != leaves)\n",
		"\t    || spool->leaves != leaves)\n",
		"another blob's leaves are opened as this note's text -- sec 423",
	),
	(
		"text-open-waits-for-all",
		"notes/text.c",
		"\tif (!fzn_spool_complete(spool))\n\t\treturn FZN_NOTE_ERR_ABSENT;\n",
		"",
		"a text not all here is read as a store failure rather than as not here yet -- sec 423",
	),
	(
		"text-last-leaf-own-length",
		"notes/text.c",
		"\t\tsize_t sealed_len = (i + 1u == leaves ? last : (size_t)FZN_BLOB_LEAF_SIZE)\n",
		"\t\tsize_t sealed_len = (size_t)FZN_BLOB_LEAF_SIZE\n",
		"a short last leaf opened at a whole slot's length never opens, so most long notes cannot be read -- sec 423",
	),
	(
		"text-state-names-this-blob",
		"notes/text.c",
		"\tif (!spool || !fzn_ct_memeq(spool->root, ref->root, FZN_BLOB_HASH_LEN)\n",
		"\tif (!spool\n",
		"a spool for another blob makes a note's text HERE when it is not -- sec 423",
	),
	(
		"text-state-broken-is-not-pending",
		"notes/text.c",
		"\t    || fzn_blob_geometry(ref->length, &leaves, &last) != FZN_BLOB_OK)\n\t\treturn FZN_NOTE_TEXT_BROKEN;\n",
		"\t    || fzn_blob_geometry(ref->length, &leaves, &last) != FZN_BLOB_OK)\n\t\treturn FZN_NOTE_TEXT_PENDING;\n",
		"a reference that names nothing waits for ever as pending, where it should say broken -- sec 423",
	),
	(
		"notes-policy-is-spelled",
		"notes/store.h",
		"\tp.spelled = 1;\n",
		"\tp.spelled = 0;\n",
		"the one constructor builds a policy that denies everything, and every note a host writes is refused -- sec 425",
	),
	(
		"notes-admit-unspelled-first",
		"notes/store.c",
		"\tif (!policy.spelled)\n\t\treturn deny(why, FZN_NOTES_DENIAL_POLICY_UNSPELLED);\n",
		"",
		"a zeroed policy reads as a decision, and only the empty admitted set behind it saves the host -- sec 425",
	),
	(
		"notes-admit-reads-kind",
		"notes/store.c",
		"\tif (fzn_record_kind(rec) != FZN_NOTE_KIND || fzn_record_stream(rec) != FZN_NOTE_STREAM)\n",
		"\tif (fzn_record_stream(rec) != FZN_NOTE_STREAM)\n",
		"a sibling's record of any other kind, with a body that parses as a node, becomes a note -- sec 425",
	),
	(
		"notes-admit-reads-stream",
		"notes/store.c",
		"\tif (fzn_record_kind(rec) != FZN_NOTE_KIND || fzn_record_stream(rec) != FZN_NOTE_STREAM)\n",
		"\tif (fzn_record_kind(rec) != FZN_NOTE_KIND)\n",
		"a note record on another stream is admitted, and its sequence is compared against a ruler it was never measured on -- sec 425",
	),
	(
		"notes-admit-verifies",
		"notes/store.c",
		"\tif (fzn_record_verify(rec, sign) != FZN_RECORD_OK)\n",
		"\tif (0)\n",
		"anyone may write a note under a sibling's name, since the issuer field is bytes until the signature checks -- sec 425",
	),
	(
		"notes-admit-needs-admitted",
		"notes/store.c",
		"\tif (!admitted)\n\t\treturn deny(why, FZN_NOTES_DENIAL_NOT_ADMITTED);\n",
		"",
		"a stranger with a good signature writes into the user's notes -- sec 425",
	),
	(
		"notes-put-admits-inside",
		"notes/store.c",
		"\tif (fzn_notes_admit(policy, record, record_len, sign, why) != FZN_NOTES_ADMITTED)\n\t\treturn FZN_NOTES_ERR_DENIED;\n",
		"",
		"put files whatever it is handed, and admission is a check beside the write that somebody forgets -- sec 425",
	),
	(
		"notes-put-refuses-equivocation",
		"notes/store.c",
		"\t\t    && !(held_len == record_len && memcmp(bytes, record, record_len) == 0))\n\t\t\treturn FZN_NOTES_ERR_EQUIVOCATION;\n",
		"\t\t    && 0)\n\t\t\treturn FZN_NOTES_ERR_EQUIVOCATION;\n",
		"two records one writer signed at one sequence are both taken in turn, and hosts disagree about which is current -- sec 425",
	),
	(
		"notes-put-keeps-newer",
		"notes/store.c",
		"\t\tif (fzn_record_seq(rec) <= fzn_record_seq(held_rec))\n\t\t\treturn FZN_NOTES_OK;\n",
		"",
		"an old record arriving late undoes an edit, and the user watches a note revert -- sec 425",
	),
	(
		"notes-put-bounds-claims",
		"notes/store.c",
		"\t\tif (count >= FZN_NOTES_MAX)\n\t\t\treturn FZN_NOTES_ERR_FULL;\n",
		"",
		"a host takes claims past what a view or a list can hold, and the next list fails for every note -- sec 425",
	),
	(
		"notes-get-checks-placement",
		"notes/store.c",
		"\tif (!fzn_ct_memeq(check, key, FZN_PUBKEY_LEN))\n\t\treturn FZN_NOTES_ERR_SHAPE;\n",
		"",
		"a backend handing back another claim's record, well signed, is read as the claim that was asked for -- sec 425",
	),
	(
		"notes-author-index-before-chain",
		"notes/author.c",
		"\terr = index_takes(a, id);\n\tif (err != FZN_NOTES_OK)\n\t\treturn err;\n",
		"",
		"a note record the index would refuse is chained into the history anyway -- sec 517",
	),
	(
		"notes-author-says-an-older-index",
		"notes/author.c",
		"\treturn wrote ? FZN_NOTES_OK : FZN_NOTES_ERR_SHAPE;\n",
		"\treturn FZN_NOTES_OK;\n",
		"an edit the index calls older than its own record is reported written, and silently lost -- sec 517",
	),
	(
		"node-notes-no-journal-said",
		"node/notes.c",
		"\tif (!n->chain)\n\t\treturn say(",
		"\tif (0)\n\t\treturn say(",
		"a node with no journal answers a well-formed write as malformed -- sec 517",
	),
	(
		"journal-write-hands-back-the-record",
		"node/journal.c",
		"\t*out_len = len;\n",
		"\t*out_len = 0;\n",
		"a note record chained into the journal never reaches the index -- sec 517",
	),
	(
		"notebook-view-counts-unreadable",
		"notes/view.c",
		"\t\t\tview->unreadable++;\n",
		"",
		"a damaged store looks like a smaller one, an absence reporting as a smaller success -- sec 425",
	),
	(
		"notebook-view-top-level-shows-unreachable",
		"notes/view.c",
		"\t\tif (view->mark[i])\n\t\t\tcontinue;\n",
		"\t\tif (1)\n\t\t\tcontinue;\n",
		"a note in a cycle, or waiting for its parent, is shown nowhere -- sec 425",
	),
	(
		"notebook-view-contested-needs-two-parents",
		"notes/view.c",
		"\t\t\t    && memcmp(view->nodes[j].parent, view->nodes[i].parent, FZN_TREE_ID_LEN)\n\t\t\t               != 0)\n",
		"\t\t\t    )\n",
		"two writers agreeing on where a note is are reported as a conflict -- sec 425",
	),
	(
		"notes-author-refuses-unreadable",
		"notes/author.c",
		"&h->meta)\n\t    != FZN_NOTE_OK)\n\t\treturn FZN_NOTES_ERR_SHAPE;\n",
		"&h->meta)\n\t    != FZN_NOTE_OK)\n\t\tmemset(&h->meta, 0, sizeof(h->meta));\n",
		"an edit of a note a newer host wrote in a type this build cannot read writes its fields back empty, deleting it -- sec 426",
	),
	(
		"notes-author-own-claim-first",
		"notes/author.c",
		"\tif (fzn_notes_get(a->store, id, a->issuer, record, sizeof(record), &len) == FZN_NOTES_OK\n",
		"\tif (0 && fzn_notes_get(a->store, id, a->issuer, record, sizeof(record), &len) == FZN_NOTES_OK\n",
		"an edit starts from whichever writer's claim the view meets first, and undoes this host's own last edit -- sec 426",
	),
	(
		"notes-edit-keeps-labels",
		"notes/author.c",
		"\t\t\treturn FZN_NOTES_ERR_SHAPE;\n\t\tif (which & FZN_NOTES_EDIT_TITLE) {\n",
		"\t\t\treturn FZN_NOTES_ERR_SHAPE;\n\t\tcontent.labels_len = 0;\n\t\tif (which & FZN_NOTES_EDIT_TITLE) {\n",
		"every edit drops a note's labels, which fuzzypickles' copy did until their sec 146 -- sec 426",
	),
	(
		"notes-edit-keeps-unnamed-text",
		"notes/author.c",
		"\tif (which & FZN_NOTES_EDIT_TEXT) {\n",
		"\tif (1) {\n",
		"renaming a note discards its text -- sec 426",
	),
	(
		"notes-edit-keeps-created",
		"notes/author.c",
		"\t/* The note's own creation time; only the edit time moves. */\n\tmeta.edited_at_ms = now_ms;\n",
		"\t/* The note's own creation time; only the edit time moves. */\n\tmeta.edited_at_ms = now_ms;\n\tmeta.created_at_ms = now_ms;\n",
		"every edit makes a note new, and the creation time a user sorts by becomes the last edit's -- sec 426",
	),
	(
		"notes-edit-pending-not-blanked",
		"notes/author.c",
		"\t\tif (!opened || len != h.meta.content.length)\n\t\t\treturn FZN_NOTES_ERR_PENDING;\n",
		"\t\tif (!opened || len != h.meta.content.length) {\n\t\t\tmemset(payload_in, 0, FZN_NOTE_PAYLOAD_HEADER_LEN);\n\t\t\tpayload_in[0] = 1u;\n\t\t\tlen = FZN_NOTE_PAYLOAD_HEADER_LEN;\n\t\t}\n",
		"a content edit of a note whose blob is not here writes its other fields back empty -- sec 514",
	),
	(
		"notes-edit-keeps-place",
		"notes/author.c",
		"\treturn write_note(author, id, h.parent, h.order, h.content_type, &meta, now_ms);\n",
		"\treturn write_note(author, id, author->issuer, h.order, h.content_type, &meta, now_ms);\n",
		"editing a note moves it -- sec 426",
	),
	(
		"notes-edit-set-clear-disjoint",
		"notes/author.c",
		"\t    || (clear & (uint8_t)~FZN_NOTES_EDIT_FLAGS) != 0u || (set & clear) != 0u\n",
		"\t    || (clear & (uint8_t)~FZN_NOTES_EDIT_FLAGS) != 0u\n",
		"a request to set and clear one flag is answered by quietly picking one -- sec 426",
	),
	(
		"notes-edit-flag-mask",
		"notes/author.c",
		"\t    || (set & (uint8_t)~FZN_NOTES_EDIT_FLAGS) != 0u\n",
		"",
		"the blob flag is set without a reference behind it, and the text reads as a reference it is not -- sec 426",
	),
	(
		"notes-create-id-not-root",
		"notes/author.c",
		"\tif (is_root(id_out))\n\t\tid_out[0] = 1u;\n",
		"",
		"a random source answering zeros writes a note as the root, which is not a node -- sec 426",
	),
	(
		"notes-move-not-own-parent",
		"notes/author.c",
		"\tif (memcmp(id, parent, FZN_TREE_ID_LEN) == 0)\n\t\treturn FZN_NOTES_ERR_MALFORMED;\n",
		"",
		"a note made its own parent leaves the tree for the top level, which nobody meant -- sec 426",
	),
	(
		"notes-purge-asking-spelled",
		"notes/purge.h",
		"\ta.spelled = 1;\n",
		"\ta.spelled = 0;\n",
		"the one constructor builds a set every purge refuses, and no trash is ever emptied -- sec 427",
	),
	(
		"notes-purge-refuses-unspelled",
		"notes/purge.c",
		"\tif (!asking.spelled || (asking.count && !asking.hosts))\n\t\treturn FZN_NOTES_ERR_MALFORMED;\n",
		"",
		"a sibling list that could not be read reaches the empty set, and every trashed note is erased with nobody asked -- fuzzypickles' sec 20 defect, sec 427",
	),
	(
		"notes-purge-dedups",
		"notes/purge.c",
		"\t\tif (seen)\n\t\t\tcontinue;\n",
		"",
		"a host named twice can be answered once, and the purge waits for ever -- fuzzypickles' sec 20 defect, sec 427",
	),
	(
		"notes-purge-keeps-pinned",
		"notes/purge.c",
		"\tif (fzn_notes_purge_pending(store, id))\n\t\treturn FZN_NOTES_OK;\n",
		"",
		"queuing a purge again re-pins its set, which is the set defined beforehand recomputed -- sec 427",
	),
	(
		"notes-purge-ignores-strangers",
		"notes/purge.c",
		"\t\tif (!p.answered[i] && fzn_ct_memeq(p.asked[i], host, FZN_PUBKEY_LEN)) {\n",
		"\t\tif (!p.answered[i]) {\n",
		"a host outside the pinned set answers for all of them, and a note is erased while siblings hold it -- sec 427",
	),
	(
		"notes-purge-needs-every-answer",
		"notes/purge.c",
		"\t*complete = done == p.asked_count;\n",
		"\t*complete = done > 0u;\n",
		"the first answer is taken as consent, and the note is erased while another host still holds it -- sec 427",
	),
	(
		"notes-purge-erases-every-claim",
		"notes/purge.c",
		"\t\t\treturn FZN_NOTES_ERR_BACKEND;\n\t\tgone++;\n",
		"\t\t\treturn FZN_NOTES_ERR_BACKEND;\n\t\tgone++;\n\t\tbreak;\n",
		"a purge erases one writer's claim and the note stays readable under another's -- sec 427",
	),
	(
		"notes-purge-erases-only-its-note",
		"notes/purge.c",
		"\t\t    || memcmp(fzn_record_subject(rec), id, FZN_TREE_ID_LEN) != 0)\n",
		"\t\t    )\n",
		"emptying one note erases every note held -- sec 427",
	),
	(
		"notes-purge-due-waits",
		"notes/purge.c",
		"\t\tif (p.last_push_ms != 0u && now_ms - p.last_push_ms < FZN_NOTES_PURGE_RETRY_MS\n",
		"\t\tif (0\n",
		"every sweep re-asks every host about every purge -- sec 427",
	),
	(
		"notes-purge-trash-only-own",
		"notes/purge.c",
		"\t\tif (!fzn_ct_memeq(view->writers[i], self, FZN_PUBKEY_LEN)\n\t\t    || fzn_note_meta_open(",
		"\t\tif (fzn_note_meta_open(",
		"a host empties a sibling's trash for it -- sec 427",
	),
	(
		"notes-purge-trash-only-trashed",
		"notes/purge.c",
		"\t\t    || !(meta.flags & FZN_NOTE_FLAG_TRASHED))\n",
		"\t\t    )\n",
		"emptying the trash erases notes that were never in it -- sec 427",
	),
	(
		"notes-purge-pending-unreadable",
		"notes/purge.c",
		"\treturn fzn_notes_purge_get(store, id, &p) != FZN_NOTES_ERR_ABSENT;\n",
		"\treturn fzn_notes_purge_get(store, id, &p) == FZN_NOTES_OK;\n",
		"a purge row that will not read lets its note back into view and back onto the wire -- sec 427",
	),
	(
		"notes-purge-bounded",
		"notes/purge.c",
		"\t    || count >= FZN_NOTES_PURGE_MAX)\n",
		"\t    )\n",
		"the purge queue grows past what a list can hold, and then no purge can be swept -- sec 427",
	),
	(
		"notes-purge-nobody-is-consent",
		"notes/purge.c",
		"\tif (p.asked_count == 0u) {\n\t\t*complete = 1;\n",
		"\tif (0) {\n\t\t*complete = 1;\n",
		"a host on its own queues a purge nobody can ever answer -- sec 427",
	),
	(
		"import-surrogate-pair",
		"notes/import.c",
		"\t\t\t\tcp = 0x10000u + ((cp - 0xd800u) << 10) + (low - 0xdc00u);\n",
		"\t\t\t\tcp = low;\n",
		"an emoji in a Keep title arrives as half a character -- sec 429",
	),
	(
		"import-lone-surrogate-refused",
		"notes/import.c",
		"\t\t\t\t    || !hex4(s, len, i + 3u, &low) || low < 0xdc00u || low > 0xdfffu)\n\t\t\t\t\treturn STR_BAD;\n",
		"\t\t\t\t    || !hex4(s, len, i + 3u, &low) || low < 0xdc00u || low > 0xdfffu) {\n\t\t\t\t\tput_utf8(out, cap, &n, cp, &over);\n\t\t\t\t\tcontinue;\n\t\t\t\t}\n",
		"a lone surrogate is written into a note as bytes no UTF-8 reader accepts -- sec 429",
	),
	(
		"import-top-level-only",
		"notes/import.c",
		"\t\tif (depth == 1u) {\n",
		"\t\tif (depth >= 1u) {\n",
		"an attachment's title is taken as the note's -- sec 429",
	),
	(
		"import-list-ticks",
		"notes/import.c",
		"\t\t\t\t\thead[0] = item_checked ? FZN_NOTE_ITEM_FLAG_CHECKED : 0u;\n",
		"\t\t\t\t\thead[0] = 0u;\n",
		"a checklist imports with every tick lost -- sec 429",
	),
	(
		"import-labels-separated",
		"notes/import.c",
		"\t\t\t\t\tif (n)\n\t\t\t\t\t\tput(labels, sizeof(labels), &n, &nul, 1u, &over);\n",
		"",
		"two labels import as one, run together -- sec 429",
	),
	(
		"import-too-long-refused",
		"notes/import.c",
		"\tif (too_long) {\n\t\trefuse(refused, refused_ctx, FZN_NOTES_IMPORT_TOO_LONG, title, e.title_len);\n",
		"\tif (0) {\n\t\trefuse(refused, refused_ctx, FZN_NOTES_IMPORT_TOO_LONG, title, e.title_len);\n",
		"a note too long to hold is imported cut short, and nothing says so -- sec 429",
	),
	(
		"import-empty-refused",
		"notes/import.c",
		"\tif (e.title_len == 0u && e.text_len == 0u) {\n\t\trefuse(refused, refused_ctx, FZN_NOTES_IMPORT_UNPARSED, title, 0u);\n\t\treturn FZN_NOTES_OK;\n",
		"\tif (0) {\n\t\trefuse(refused, refused_ctx, FZN_NOTES_IMPORT_UNPARSED, title, 0u);\n\t\treturn FZN_NOTES_OK;\n",
		"an empty Keep object imports as an empty note -- sec 429",
	),
	(
		"import-knotes-unfolds",
		"notes/import.c",
		"\t\tif (i < len && (s[i] == ' ' || s[i] == '\\t')) {\n\t\t\ti++;\n\t\t\tcontinue;\n\t\t}\n",
		"",
		"every long KNotes note imports as its first 75 octets -- sec 429",
	),
	(
		"import-knotes-resets",
		"notes/import.c",
		"\t\t\tmemset(&e, 0, sizeof(e));\n\t\t\te.content_type = FZN_NOTE_TYPE_NOTE;\n",
		"\t\t\te.content_type = FZN_NOTE_TYPE_NOTE;\n",
		"one journal's text and creation time carry into the next, which a re-import then matches wrongly -- sec 429",
	),
	(
		"import-knotes-unterminated",
		"notes/import.c",
		"\tif (in)\n\t\trefuse(refused, refused_ctx, FZN_NOTES_IMPORT_UNPARSED, title, e.title_len);\n",
		"",
		"a truncated file's last note vanishes without a word -- sec 429",
	),
	(
		"import-knotes-case",
		"notes/import.c",
		"\treturn (a >= 'a' && a <= 'z' ? (uint8_t)(a - 32) : a) == (uint8_t)b;\n",
		"\treturn a == (uint8_t)b;\n",
		"a property written in lower case, which RFC 5545 allows, is not read -- sec 429",
	),
	(
		"import-refuses-escaped-nul",
		"notes/import.c",
		"\t\t\tif (cp == 0u || (cp >= 0xdc00u && cp <= 0xdfffu))\n",
		"\t\t\tif (cp >= 0xdc00u && cp <= 0xdfffu)\n",
		"a \\u0000 writes a NUL into a title, which notes/note.h says holds none -- sec 429",
	),
	(
		"import-refuses-raw-nul",
		"notes/import.c",
		"\t\tif (c == 0u)\n\t\t\treturn STR_BAD;\n",
		"",
		"a raw NUL inside a Keep string reaches a title -- sec 429",
	),
	(
		"import-knotes-refuses-nul",
		"notes/import.c",
		"\t\tif (c == 0u)\n\t\t\treturn -1;\n",
		"",
		"a NUL in a KNotes value reaches a title -- sec 429",
	),
	(
		"import-run-dedups",
		"notes/import.c",
		"\tif (e->created_at_ms) {\n\t\tint before = imported_before(run, e);\n",
		"\tif (0) {\n\t\tint before = imported_before(run, e);\n",
		"a second import of the same export doubles every note -- sec 429",
	),
	(
		"import-run-dedup-by-title",
		"notes/import.c",
		"\t\t\tif (note.title_len == e->title_len\n\t\t\t    && memcmp(note.title, e->title, e->title_len) == 0)\n",
		"\t\t\tif (1)\n",
		"two notes made in one millisecond are one note to a re-import, and the second is never brought across -- sec 429",
	),
	(
		"import-run-keeps-created",
		"notes/import.c",
		"\t                             e->created_at_ms, run->now_ms, id);\n",
		"\t                             0u, run->now_ms, id);\n",
		"an imported note's creation time is the import's, so a re-import recognises nothing -- sec 429",
	),
	(
		"import-run-pending-is-refused",
		"notes/import.c",
		"\t\tif (before < 0) {\n",
		"\t\tif (0) {\n",
		"a re-import on a host still fetching a note's content takes it for a new note and writes a copy, which syncs to every device -- sec 577",
	),
	(
		"import-run-pending-is-told",
		"notes/import.c",
		"\t\t\tunknown = 1;\n",
		"",
		"a held note whose content is not here reads as no match, and the entry is imported again as a duplicate -- sec 577",
	),
	(
		"import-run-counts-pending",
		"notes/import.c",
		"\t\t\trun->pending++;\n",
		"",
		"a pending refusal is counted with the rest, so nobody is told that importing again will bring it -- sec 578",
	),
	(
		"node-notes-import-answers-pending",
		"node/notes.c",
		"\t             run.undated, run.refused, run.pending);\n",
		"\t             run.undated, run.refused, (size_t)0);\n",
		"the import reply says none of the refused are pending, and the notebook never tells the user to import again -- sec 578",
	),
	(
		"node-notes-own-user-only",
		"node/notes.c",
		"\tif (origin != FZN_ORIGIN_SAME_USER)\n\t\treturn say(reply, reply_cap, FZN_REPLY_DENIED, \"notes need this node's own user\");\n",
		"",
		"another user on the machine reads and writes this user's notes -- sec 431",
	),
	(
		"node-notes-escapes",
		"node/notes.c",
		"\t\tif (c <= 0x20u || c == '%' || c == ',' || c == 0x7fu) {\n",
		"\t\tif (c == '%') {\n",
		"a title with a space, a comma or a newline breaks the listing it is in -- sec 431",
	),
	(
		"node-notes-no-store-said",
		"node/notes.c",
		"\tif (!n->seal || !n->open)\n\t\treturn say(",
		"\tif (0)\n\t\treturn say(",
		"a node with no blob store answers a well-formed write as malformed -- sec 514",
	),
	(
		"node-notes-empty-asks-peers",
		"node/notes.c",
		"\tfor (i = 0; i < n->pull_count; i++)\n\t\tasked[n_asked++] = n->pulls[i];\n",
		"",
		"emptying the trash erases at once on a node whose pull peers still hold the notes -- sec 431",
	),
	(
		"node-notes-pending-not-read",
		"node/notes.c",
		"\tif (pending)\n\t\treturn say(reply, cap, FZN_REPLY_ERROR, \"the text is not here yet\");\n",
		"",
		"a note whose content is not here reads as an empty text -- sec 514",
	),
	(
		"node-notes-list-marks-pending",
		"node/notes.c",
		"\t\t\tflags = (uint8_t)(meta.flags | FZN_NODE_NOTES_LIST_PENDING);\n",
		"\t\t\tflags = meta.flags;\n",
		"a note whose content is not here lists as an untitled note, not a pending one -- sec 514",
	),
	(
		"reply-ok-room-leaves-ok",
		"local/vocabulary.c",
		"\treturn line > 4u ? line - 4u : 0u;\n",
		"\treturn line > 1u ? line - 1u : 0u;\n",
		"a page filled to the line's bound is refused whole, and the client hears nothing -- sec 514",
	),
	(
		"node-notes-file-private",
		"node/notes.c",
		"\t\tfd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0600);\n",
		"\t\tfd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);\n",
		"a note written out to a file is readable by every user on the machine -- sec 431",
	),
	(
		"notes-sync-index-skips-pending",
		"notes/sync.c",
		"\t\t    || fzn_notes_purge_pending(store, fzn_record_subject(rec))\n\t\t    || !in_scope(scope, fzn_record_subject(rec)))\n\t\t\tcontinue;\n\t\tif (n != i)\n",
		"\t\t    || !in_scope(scope, fzn_record_subject(rec)))\n\t\t\tcontinue;\n\t\tif (n != i)\n",
		"a sibling that has just erased a note for a purge is handed it again and keeps it -- fuzzypickles' resurrection defect, sec 432",
	),
	(
		"notes-sync-pull-asked-only",
		"notes/sync.c",
		"\t\tif (!asked || fzn_notes_purge_pending(store, fzn_record_subject(rec))) {\n",
		"\t\tif (fzn_notes_purge_pending(store, fzn_record_subject(rec))) {\n",
		"a peer pushes whatever records it likes through a pull -- sec 432",
	),
	(
		"notes-sync-pull-refuses-pending",
		"notes/sync.c",
		"\t\tif (!asked || fzn_notes_purge_pending(store, fzn_record_subject(rec))) {\n",
		"\t\tif (!asked) {\n",
		"a note this node is purging comes back from a peer that has not erased it yet -- sec 432",
	),
	(
		"notes-sync-pull-wants-newer-only",
		"notes/sync.c",
		"\treturn fzn_record_seq(rec) < seq;\n",
		"\treturn 1;\n",
		"every pull fetches every record a peer holds, whether or not this node already has it -- sec 432",
	),
	(
		"notes-sync-purge-erases-for-admitted",
		"notes/sync.c",
		"\tif (admits(policy, sender)\n\t    && fzn_notes_erase_note(store, request + 2, NULL) == FZN_NOTES_OK)\n",
		"\tif (fzn_notes_erase_note(store, request + 2, NULL) == FZN_NOTES_OK)\n",
		"any node that reaches this one can have its notes erased -- sec 433",
	),
	(
		"notes-sync-partner-recorded",
		"notes/sync.c",
		"\t\t * members stopped asking for the index. */\n\t\tif (admits(policy, sender))\n\t\t\tpartner_seen(store, sender, now_ms);\n",
		"\t\t * members stopped asking for the index. */\n",
		"a member asking for purges is never made a partner, so no purge pins it and it keeps a note the user emptied -- secs 433, 519",
	),
	(
		"notes-sync-take-only-admitted",
		"notes/sync.c",
		"\t\t\tif (!admits(policy, host) || fzn_notes_erase_note(store, id, NULL) != FZN_NOTES_OK) {\n",
		"\t\t\tif (fzn_notes_erase_note(store, id, NULL) != FZN_NOTES_OK) {\n",
		"a node erases notes for any host it pulls from, admitted or not -- sec 433",
	),
	(
		"notes-sync-finish-on-complete",
		"notes/sync.c",
		"\t\tif (complete) {\n\t\t\tif (fzn_notes_purge_finish(store, p.id) != FZN_NOTES_OK)\n",
		"\t\tif (0) {\n\t\t\tif (fzn_notes_purge_finish(store, p.id) != FZN_NOTES_OK)\n",
		"a purge every host consented to never finishes, and the note it emptied stays here -- sec 433",
	),
	(
		"node-notes-empty-asks-partners",
		"node/notes.c",
		"\t\tmemcpy(asked[n_asked++].key, partners[i], FZN_PUBKEY_LEN);\n\t}\n",
		"\t}\n",
		"a node that serves notes erases at once while the nodes that pulled from it keep copies -- sec 433",
	),
	(
		"node-notes-list-hides-pending",
		"node/notes.c",
		"\t\tif (!fzn_notes_purge_pending(store, out[i]->id))\n\t\t\tout[j++] = out[i];\n",
		"\t\tif (1)\n\t\t\tout[j++] = out[i];\n",
		"a note the user emptied comes back into view while a node that holds it has not answered -- sec 434",
	),
	(
		"node-notes-partner-ages",
		"node/notes.c",
		"\t\t    && now(n) > seen && now(n) - seen > FZN_NODE_NOTES_PARTNER_AGE_MS)\n",
		"\t\t    && 0)\n",
		"a partner gone for good is pinned by every later purge, which waits for ever -- sec 434",
	),
	(
		"contact-name-charset",
		"contact/contact.c",
		"\t\t      || c == '_'))\n",
		"\t\t      || c == '_' || c == ' '))\n",
		"a contact name with a space in it splits a command line into two words -- sec 435",
	),
	(
		"contact-one-name-one-key",
		"contact/contact.c",
		"\t\tif (all[i].name_len == name_len && memcmp(all[i].name, name, name_len) == 0)\n\t\t\treturn FZN_CONTACT_ERR_TAKEN;\n",
		"",
		"two keys under one name, and a person picking a contact by name gets whichever the list met first -- sec 435",
	),
	(
		"contact-rename-keeps-time",
		"contact/contact.c",
		"\t\t\tadded = all[i].added_at_ms;\n",
		"",
		"renaming a contact rewrites when it was added -- sec 435",
	),
	(
		"contact-bounded",
		"contact/contact.c",
		"\tif (!held && count >= FZN_CONTACTS_MAX)\n",
		"\tif (0)\n",
		"the list grows past what a list call can return, and then no contact can be found -- sec 435",
	),
	(
		"contact-list-refuses",
		"contact/contact.c",
		"\tif (!store->list(store->ctx, FZN_PERSIST_CONTACT, (uint8_t *)keys, FZN_CONTACTS_MAX, &held))\n\t\treturn FZN_CONTACT_ERR_BACKEND;\n",
		"\t(void)store->list(store->ctx, FZN_PERSIST_CONTACT, (uint8_t *)keys, FZN_CONTACTS_MAX, &held);\n",
		"a store that cannot list reads as empty, and a name already taken is given out again -- sec 435",
	),
	(
		"admin-contact-refuses-members",
		"node/admin.c",
		"\tif (is_member(admin, key))\n",
		"\tif (0)\n",
		"a member of the estate is filed as a contact, a key on both sides of the boundary -- sec 435",
	),
	(
		"admin-contact-own-user",
		"node/admin.c",
		"\t\tif (origin != FZN_ORIGIN_SAME_USER)\n\t\t\treturn answer_text(reply, reply_cap, FZN_REPLY_DENIED,\n\t\t\t                   \"contacts need this node's own user\");\n",
		"",
		"another user on the machine reads and edits this user's contacts -- sec 435",
	),
	(
		"share-index-in-scope",
		"notes/sync.c",
		"\t\t    || !in_scope(scope, fzn_record_subject(rec)))\n\t\t\tcontinue;\n\t\tif (n != i)",
		"\t\t    )\n\t\t\tcontinue;\n\t\tif (n != i)",
		"a contact is offered the index of every note, shared or not -- sec 436",
	),
	(
		"share-records-in-scope",
		"notes/sync.c",
		"\t\t    || !in_scope(scope, fzn_record_subject(rec)))\n\t\t\tcontinue;\n\t\tif (cap - used",
		"\t\t    )\n\t\t\tcontinue;\n\t\tif (cap - used",
		"a contact asking by key is sent notes nobody shared with it -- sec 436",
	),
	(
		"share-row-filed-under-its-key",
		"notes/share.c",
		"\tif (share_key(store, out->subtree, out->contact, check) != FZN_NOTES_OK\n\t    || !fzn_ct_memeq(check, key, FZN_PUBKEY_LEN))\n\t\treturn FZN_NOTES_ERR_SHAPE;\n",
		"",
		"a share row copied under another key is a share nobody made -- sec 436",
	),
	(
		"share-with-names-the-contact",
		"notes/share.c",
		"\t\tif (memcmp(all[i].contact, contact, FZN_PUBKEY_LEN) == 0)\n\t\t\tmemcpy(out[n++]",
		"\t\tif (1)\n\t\t\tmemcpy(out[n++]",
		"a subtree shared with one contact is served to every contact -- sec 436",
	),
	(
		"share-reach-below-only",
		"notes/share.c",
		"\t\t\tif (!under)\n\t\t\t\tcontinue;\n",
		"",
		"a share of one subtree reaches every note in the view -- sec 436",
	),
	(
		"share-add-keeps-time",
		"notes/share.c",
		"\tif (share_get(store, key, &held) == FZN_NOTES_OK)\n\t\treturn FZN_NOTES_OK;\n\terr = fzn_notes_share_list",
		"\terr = fzn_notes_share_list",
		"sharing again rewrites when a subtree was first shared -- sec 436",
	),
	(
		"remote-share-decided-as-share",
		"node/remote.c",
		"\tif (fzn_node_request_shared(config, opened->capability))\n",
		"\tif (0)\n",
		"a contact's request is decided against the estate's capability, and no share is ever served -- sec 436",
	),
	(
		"node-share-against-own-key",
		"node/node.c",
		"\treturn fzn_authz_decide(policy, FZN_ORIGIN_REMOTE, hops, hop_count, config->share_root,\n",
		"\treturn fzn_authz_decide(policy, FZN_ORIGIN_REMOTE, hops, hop_count, config->root,\n",
		"a share granted by this node's key is checked against the estate's root, and a node that is not the root can share nothing -- sec 436",
	),
	(
		"node-share-only-when-sharing",
		"node/node.c",
		"\treturn config && capability && config->has_share\n",
		"\treturn config && capability\n",
		"a node that shares nothing decides a member's request by a capability it never configured -- sec 436",
	),
	(
		"admin-contact-reaches-notes-only",
		"node/admin.c",
		"\tif (fzn_node_request_shared(&admin->state->config, req->capability)) {\n",
		"\tif (0) {\n",
		"a contact's request reaches the member verbs: it lists the estate's peers -- sec 436",
	),
	(
		"admin-contact-asks-as-shared",
		"node/admin.c",
		"req->sender, 1, req->payload,",
		"req->sender, 0, req->payload,",
		"a contact's notes request is answered as a member's, with every note -- sec 436",
	),
	(
		"admin-contact-is-no-member",
		"node/admin.c",
		"\t\t    && !fzn_node_peer_contact(&admin->state->config, &admin->state->peers[i]))\n",
		"\t\t    )\n",
		"a contact granted a share is counted a member of the estate -- sec 436",
	),
	(
		"admin-share-prekey-is-contacts",
		"node/admin.c",
		"\tif (memcmp(record.host, contact.key, FZN_PUBKEY_LEN) != 0)\n\t\treturn answer_text(reply, cap, FZN_REPLY_ERROR, \"that prekey is not the contact's\");\n",
		"",
		"a share is granted to whoever handed over a prekey, under a contact's name -- sec 436",
	),
	(
		"admin-share-needs-sharing",
		"node/admin.c",
		"\tif (!admin->state->config.has_share)\n\t\treturn answer_text(reply, cap, FZN_REPLY_ERROR, \"this node does not share notes\");\n",
		"",
		"a node that shares nothing pairs a contact for a capability it never configured -- sec 436",
	),
	(
		"peer-contact-by-capability",
		"node/remote.c",
		"\treturn memcmp(fzn_hop_capability(hop)->b, config->share_capability.b, FZN_CAP_ID_LEN) == 0;\n",
		"\treturn 1;\n",
		"every peer is a contact, and no member writes notes -- sec 436",
	),
	(
		"notes-share-not-top",
		"node/notes.c",
		"\tif (fzn_tree_is_root(subtree))\n\t\treturn say(reply, cap, FZN_REPLY_MALFORMED, \"share a note, not the top\");\n",
		"",
		"the top is taken for a subtree, sharing every note the node will ever hold -- sec 436",
	),
	(
		"notes-share-held-note",
		"node/notes.c",
		"\tif (!found)\n\t\treturn refuse(reply, cap, FZN_NOTES_ERR_ABSENT);\n",
		"",
		"a mistyped id is shared and served empty, and nothing says why -- sec 436",
	),
	(
		"notes-share-own-user",
		"node/notes.c",
		"\t\tif (origin != FZN_ORIGIN_SAME_USER)\n\t\t\treturn say(reply, reply_cap, FZN_REPLY_DENIED,\n\t\t\t           \"shares need this node's own user\");\n",
		"",
		"another user on the machine shares this user's notes -- sec 436",
	),
	(
		"notes-shared-answer-scoped",
		"node/notes.c",
		"\tif (shared)\n\t\treturn answer_shared(",
		"\tif (0)\n\t\treturn answer_shared(",
		"a contact's request is answered with every note -- sec 436",
	),
	(
		"received-list-filed-under-own-key",
		"notes/received.c",
		"\t\tif (!row_key(seam, prefix + FZN_PUBKEY_LEN, check)\n\t\t    || memcmp(check, keys[i], FZN_PUBKEY_LEN) != 0)\n\t\t\tcontinue;\n",
		"",
		"a shared note's row copied under another key names its claim twice -- sec 437",
	),
	(
		"received-forget-only-that-sharer",
		"notes/received.c",
		"\t\tif (!row_read(base, keys[i], row, &len)\n\t\t    || memcmp(row + FZN_PERSIST_HEAD_LEN, sharer, FZN_PUBKEY_LEN) != 0)\n\t\t\tcontinue;\n",
		"\t\tif (!row_read(base, keys[i], row, &len))\n\t\t\tcontinue;\n",
		"forgetting one sharer's tree erases every sharer's -- sec 437",
	),
	(
		"received-roots-parent-not-held",
		"notes/received.c",
		"\t\tif (parent_held)\n\t\t\tcontinue;\n",
		"",
		"every note of a sharer's tree is a root, and the shared folder reads flat -- sec 437",
	),
	(
		"sync-writers-each-once",
		"notes/sync.c",
		"\t\tif (seen)\n\t\t\tcontinue;\n\t\tif (n >= FZN_NOTES_SYNC_WRITERS_MAX)",
		"\t\tif (n >= FZN_NOTES_SYNC_WRITERS_MAX)",
		"a writer is named once per note, and a share written by a few fills the list -- sec 437",
	),
	(
		"sync-writers-length-matches-count",
		"notes/sync.c",
		"\t    || reply_len != FZN_NOTES_SYNC_LIST_HEAD_LEN + (count * FZN_PUBKEY_LEN))\n\t\treturn FZN_NOTES_SYNC_SHAPE;\n",
		"\t    )\n\t\treturn FZN_NOTES_SYNC_SHAPE;\n",
		"a writers answer shorter than its count admits keys read past what arrived -- sec 437",
	),
	(
		"notes-shared-top-is-roots",
		"node/notes.c",
		"\tif (fzn_tree_is_root(parent) && shared)\n",
		"\tif (0)\n",
		"the top of a sharer's tree lists every shared note, flat -- sec 437",
	),
	(
		"notes-shared-own-user",
		"node/notes.c",
		"\t\tif (origin != FZN_ORIGIN_SAME_USER)\n\t\t\treturn say(reply, reply_cap, FZN_REPLY_DENIED,\n\t\t\t           \"notes need this node's own user\");\n\t\treturn read_shared(",
		"\t\treturn read_shared(",
		"another user on the machine reads what contacts shared with this one -- sec 437",
	),
	(
		"admin-received-card-is-the-contacts",
		"node/admin.c",
		"\tif (opened.hop_count != 1u || memcmp(opened.root, contact.key, FZN_PUBKEY_LEN) != 0\n\t    || memcmp(fzn_hop_grantor(hop), contact.key, FZN_PUBKEY_LEN) != 0)\n",
		"\tif (0)\n",
		"one contact's share card is filed under another contact's name -- sec 437",
	),
	(
		"admin-received-card-is-a-share",
		"node/admin.c",
		"\tif (memcmp(fzn_hop_capability(hop)->b, admin->state->config.share_capability.b,\n\t           FZN_CAP_ID_LEN)\n\t    != 0)\n",
		"\tif (0)\n",
		"a card for another capability is taken as a share -- sec 437",
	),
	(
		"admin-received-needs-notes",
		"node/admin.c",
		"\t\treturn answer_text(reply, cap, FZN_REPLY_ERROR, \"this node keeps no notes to share\");\n",
		"\t\t;\n",
		"a node keeping no notes takes a share it has nowhere to put -- sec 437",
	),
	(
		"admin-received-tells-the-daemon",
		"node/admin.c",
		"\tadmin->received_fresh = 1;\n\treturn answer_text(reply, cap, FZN_REPLY_OK, NULL);\n}\n\n/* `list received`",
		"\treturn answer_text(reply, cap, FZN_REPLY_OK, NULL);\n}\n\n/* `list received`",
		"a share just accepted waits for a restart to be pulled -- sec 437",
	),
	(
		"admin-received-remove-forgets",
		"node/admin.c",
		"\tif (fzn_notes_received_forget(admin->store, admin->state->hash, contact.key, &gone)\n\t    != FZN_NOTES_OK)\n",
		"\tif (0)\n",
		"a share this node stopped taking stays readable from a copy nobody refreshes -- sec 437",
	),
	(
		"node-received-bounded",
		"node/received.c",
		"\tif (!held && count >= FZN_NODE_RECEIVED_MAX)\n\t\treturn FZN_NODE_RECEIVED_ERR_FULL;\n",
		"",
		"the accepted shares grow past what a list returns, and then none is pulled -- sec 437",
	),
	(
		"shelf-permitted-asks-the-permit",
		"node/shelf.c",
		"\tif (!permit(permit_ctx, root))\n\t\treturn 0;\n",
		"",
		"a contact fetches any text this node holds, shared or not -- sec 438",
	),
	(
		"notes-shares-blob-in-scope",
		"node/notes.c",
		"\t\tif (in && fzn_notes_ref_of(",
		"\t\tif (1 && fzn_notes_ref_of(",
		"a text is a contact's to fetch if any note anywhere has it -- sec 438",
	),
	(
		"notes-shares-blob-names-the-root",
		"node/notes.c",
		"\t\tif (in && fzn_notes_ref_of(&view.nodes[i], &ref)\n\t\t    && memcmp(ref.root, root, FZN_BLOB_HASH_LEN) == 0)\n",
		"\t\tif (in && fzn_notes_ref_of(&view.nodes[i], &ref))\n",
		"one shared note opens every text this node holds to the contact -- sec 438",
	),
	(
		"admin-contact-reaches-texts",
		"node/admin.c",
		"\t\tif (!n && admin->text_shared && req->payload)\n",
		"\t\tif (0)\n",
		"a contact receives a shared note whose text it can never fetch -- sec 438",
	),
	(
		"admin-contact-text-names-sender",
		"node/admin.c",
		"n = admin->text_shared(admin->text_shared_ctx, req->sender,",
		"n = admin->text_shared(admin->text_shared_ctx, NULL,",
		"a contact's text request is judged against nobody's share -- sec 438",
	),
	(
		"admin-member-includes-every-root",
		"node/admin.c",
		"\tif (admin->roots && fzn_root_view_stands(&admin->roots->view, key))\n\t\treturn 1;\n",
		"",
		"a root of the estate other than the one this node joined through is filed as a contact -- sec 438",
	),
	(
		"admin-list-peer-marks-contacts",
		"node/admin.c",
		"\t\tif (contact) {\n",
		"\t\tif (0) {\n",
		"a contact paired for a share is listed as a member of the estate -- sec 438",
	),
	(
		"notebook-view-says-the-node-is-silent",
		"gui/notebook_view.cpp",
		"\tif (!m_answered)\n\t\tset_status(",
		"\tif (0)\n\t\tset_status(",
		"a node that does not answer shows as an empty notebook, fuzzypickles' sec 112 defect -- sec 439",
	),
	(
		"notebook-view-keeps-the-readers-place",
		"gui/notebook_view.cpp",
		"\tif (bar)\n\t\tbar->setValue(keep);\n",
		"",
		"a refresh scrolls the reader back to the open note, fuzzypickles' b32b2c7 defect -- sec 439",
	),
	(
		"notebook-view-trash-is-its-own-view",
		"gui/notebook_view.cpp",
		"\t\t\tif (trashed != m_trash || (!m_trash",
		"\t\t\tif (0 || (!m_trash",
		"trashed notes sit among the live ones and the trash shows everything -- sec 439",
	),
	(
		"notebook-view-shared-tree-not-written",
		"gui/notebook_view.cpp",
		"\tif (shared() || one_line.isEmpty())\n\t\treturn false;\n\tif (ask(QStringLiteral(\"add note %1 %2\")",
		"\tif (one_line.isEmpty())\n\t\treturn false;\n\tif (ask(QStringLiteral(\"add note %1 %2\")",
		"a new note made while reading a contact's tree lands in this user's own -- sec 439",
	),
	(
		"notebook-view-warns-before-sharing",
		"gui/notebook_view.cpp",
		"\tm_warning->setVisible(editing);\n",
		"\tm_warning->setVisible(false);\n",
		"the un-share warning is not on screen when somebody shares -- sec 439",
	),
	(
		"notebook-view-saves-text-through-a-file",
		"gui/notebook_view.cpp",
		"\tif (m_body->isEnabled() && !m_is_list) {\n\t\tif (!file.open()",
		"\tif (0) {\n\t\tif (!file.open()",
		"Save keeps the title and drops the text -- sec 439",
	),
	(
		"notes-import-own-user",
		"node/notes.c",
		"\t\tif (origin != FZN_ORIGIN_SAME_USER)\n\t\t\treturn say(reply, reply_cap, FZN_REPLY_DENIED,\n\t\t\t           \"notes need this node's own user\");\n\t\treturn import(",
		"\t\treturn import(",
		"another user on the machine makes the node read a path of its choosing -- sec 440",
	),
	(
		"notes-import-into-a-held-folder",
		"node/notes.c",
		"\t\t    || !find(n, run.folder, &idx))\n\t\t\treturn refuse(reply, cap, FZN_NOTES_ERR_ABSENT);\n",
		"\t\t    )\n\t\t\treturn refuse(reply, cap, FZN_NOTES_ERR_ABSENT);\n",
		"an import lands under an id nobody holds, where no listing reaches it -- sec 440",
	),
	(
		"notes-import-names-the-refused",
		"node/notes.c",
		"\tif (names.used && limit - (size_t)k > names.used) {",
		"\tif (0 && limit - (size_t)k > names.used) {",
		"an import counts what it refused and never says which, while the user still has the export -- sec 440",
	),
	(
		"notes-import-file-bounded",
		"node/notes.c",
		"\tif (buf && *len > max) {",
		"\tif (0) {",
		"a file past the bound is read cut and its refusal named by nothing -- sec 440",
	),
	(
		"notes-import-takeout-reads-notes-only",
		"node/notes.c",
		"\t\t\tif (!ends_with(e->d_name, \".json\"))\n\t\t\t\tcontinue;\n",
		"",
		"every attachment in a Takeout is parsed as a note and refused -- sec 440",
	),
	(
		"notebook-view-imports-into-the-open-folder",
		"gui/notebook_view.cpp",
		"QStringLiteral(\"add import %1 %2\").arg(parent_id(), path)",
		"QStringLiteral(\"add import %1 %2\").arg(QStringLiteral(\"top\"), path)",
		"an export imported while a folder is open lands at the top -- sec 440",
	),
	(
		"notebook-view-tells-pending",
		"gui/notebook_view.cpp",
		"\t\tif (f.value(4).toInt() > 0)\n",
		"\t\tif (0)\n",
		"a note refused only because its content has not arrived reads as lost, though importing again brings it -- sec 578",
	),
	(
		"notebook-view-import-names-after-five",
		"gui/notebook_view.cpp",
		"\t\tfor (i = 5; i < f.size(); i++)\n",
		"\t\tfor (i = 4; i < f.size(); i++)\n",
		"the pending count is named as a refused note -- sec 578",
	),
	(
		"capture-escapes-control-bytes",
		"log/capture.c",
		"\t\t\tplain = in[i] >= 0x20u && in[i] < 0x7fu",
		"\t\t\tplain = in[i] < 0x7fu",
		"a tool's terminal escapes and newlines reach the log as themselves -- sec 441",
	),
	(
		"capture-escapes-c1-and-separators",
		"log/capture.c",
		"\treturn (cp >= 0x80u && cp <= 0x9fu) || cp == 0x2028u || cp == 0x2029u;\n",
		"\treturn 0;\n",
		"an 8-bit CSI encoded as valid UTF-8 steers a terminal reading the log -- sec 441",
	),
	(
		"capture-crlf-ends-a-line",
		"log/capture.c",
		"\t\telse if (b == '\\r')\n\t\t\tp->pending_cr = 1;\n",
		"\t\telse if (0)\n\t\t\tp->pending_cr = 1;\n",
		"every line a CRLF tool prints carries an escaped \\r -- sec 441",
	),
	(
		"capture-line-bound-counts-the-rest",
		"log/capture.c",
		"\telse\n\t\tp->cut++;\n",
		"\telse\n\t\t;\n",
		"a long line is cut with nothing saying how much -- sec 441",
	),
	(
		"capture-volume-bound",
		"log/capture.c",
		"\tif (c->volume_max && c->lines >= c->volume_max) {",
		"\tif (0) {",
		"a tool printing without end fills the log -- sec 441",
	),
	(
		"capture-finish-emits-the-last-line",
		"log/capture.c",
		"\t\tif (p->len || p->cut)\n\t\t\tend_line(",
		"\t\tif (0)\n\t\t\tend_line(",
		"a tool's last line with no newline is lost -- sec 441",
	),
	(
		"capture-summary-only-exit-0-succeeds",
		"log/capture.c",
		"\t*level = (end == FZN_CAPTURE_EXITED && code == 0) ?",
		"\t*level = (code == 0) ?",
		"a tool stopped at its deadline is logged as a success -- sec 441",
	),
	(
		"capture-argv-hides-secrets",
		"log/capture.c",
		"\t\tif (secret && secret[i]) {",
		"\t\tif (0) {",
		"a controller password in argv is written to the log -- sec 441",
	),
	(
		"capture-run-kills-the-group",
		"log/capture_run.c",
		"\t\t\t(void)kill(-pid, SIGKILL);",
		"\t\t\t(void)kill(pid, SIGKILL);",
		"what a tool started outlives the deadline that stopped the tool -- sec 441",
	),
	(
		"capture-run-not-run-is-said",
		"log/capture_run.c",
		"\tif (n == (ssize_t)sizeof(e)) {",
		"\tif (0) {",
		"a tool that is not installed reads as one that exited 127 -- sec 441",
	),
	(
		"capture-stderr-is-a-warning",
		"log/capture.h",
		"\tr.err = FZN_CAPTURE_WARNING;\n",
		"\tr.err = FZN_CAPTURE_INFO;\n",
		"a tool's complaints on stderr read as information, against sec 428's default -- sec 441",
	),
	(
		"notes-item-rewords",
		"node/notes.c",
		"\t\t\tif (text) {\n\t\t\t\tt = text;",
		"\t\t\tif (0) {\n\t\t\t\tt = text;",
		"rewording a checklist item keeps the old words and says it worked -- sec 442",
	),
	(
		"notes-item-removes",
		"node/notes.c",
		"\t\t\tif (drop)\n\t\t\t\tcontinue;\n",
		"",
		"removing a checklist item keeps it -- sec 442",
	),
	(
		"notes-item-appends-only-one-past",
		"node/notes.c",
		"\t\tif (which != i || drop || !text)",
		"\t\tif (drop || !text)",
		"rewording item 7 of a two-item list appends a third -- sec 442",
	),
	(
		"notes-items-only-on-a-checklist",
		"node/notes.c",
		"\tif (node->content_type != FZN_NOTE_TYPE_LIST)\n\t\treturn say(reply, cap, FZN_REPLY_ERROR, \"not a checklist\");\n",
		"",
		"items are written into a plain note's text -- sec 442",
	),
	(
		"note-item-length-fits-a-u16",
		"notes/note.c",
		"\tif (text_len > 0xffffu || *used > cap",
		"\tif (*used > cap",
		"an item past 65535 bytes is written with a length that wraps -- sec 442",
	),
	(
		"notebook-view-toggle-reads-the-tick",
		"gui/notebook_view.cpp",
		"m_ticks[index] ? QStringLiteral(\"uncheck\") : QStringLiteral(\"check\")",
		"QStringLiteral(\"check\")",
		"a ticked item cannot be unticked from the view -- sec 442",
	),
	(
		"notebook-view-list-saves-no-text",
		"gui/notebook_view.cpp",
		"\tif (m_body->isEnabled() && !m_is_list) {",
		"\tif (m_body->isEnabled()) {",
		"saving a checklist writes its displayed lines over its items -- sec 442",
	),
	(
		"notes-checklist-text-only-through-items",
		"node/notes.c",
		"&& (node = find(n, id, &idx)) != NULL && node->content_type == FZN_NOTE_TYPE_LIST)",
		"&& (node = find(n, id, &idx)) != NULL && 0)",
		"a checklist's items are overwritten by text no item verb can read -- sec 442",
	),
	(
		"shelf-collect-asks-what-is-kept",
		"node/shelf.c",
		"\t\tif (wanted(shelf, root) || keep(keep_ctx, root)) {",
		"\t\tif (wanted(shelf, root)) {",
		"collecting removes the text of a note this node still holds -- sec 443",
	),
	(
		"shelf-collect-keeps-what-is-wanted",
		"node/shelf.c",
		"\t\tif (wanted(shelf, root) || keep(keep_ctx, root)) {",
		"\t\tif (keep(keep_ctx, root)) {",
		"a text part way through its fetch is removed under it -- sec 443",
	),
	(
		"notes-collect-keeps-own-tree",
		"node/notes.c",
		"\tif (fzn_notes_view_load(&n->store, &view) != FZN_NOTES_OK || view_names(&view, root))\n\t\treturn 1;\n",
		"\tif (fzn_notes_view_load(&n->store, &view) != FZN_NOTES_OK)\n\t\treturn 1;\n",
		"the text of this node's own long note is collected -- sec 443",
	),
	(
		"notes-collect-keeps-sharer-trees",
		"node/notes.c",
		"\t\t    || fzn_notes_view_load(&tree, &view) != FZN_NOTES_OK || view_names(&view, root))\n\t\t\treturn 1;\n",
		"\t\t    || fzn_notes_view_load(&tree, &view) != FZN_NOTES_OK)\n\t\t\treturn 1;\n",
		"a shared note's text is collected while the share stands -- sec 443",
	),
	(
		"notes-collect-own-user",
		"node/notes.c",
		"\tif (is_word(subject, subject_len, \"text\") && request->parsed == FZN_VERB_REMOVE) {\n\t\tif (origin != FZN_ORIGIN_SAME_USER)\n\t\t\treturn say(reply, reply_cap, FZN_REPLY_DENIED, \"notes need this node's own user\");\n",
		"\tif (is_word(subject, subject_len, \"text\") && request->parsed == FZN_VERB_REMOVE) {\n",
		"another user on the machine removes this user's texts -- sec 443",
	),
	(
		"notebook-view-pinned-first",
		"gui/notebook_view.cpp",
		"\t\t\tif (pinned)\n\t\t\t\tm_list->insertItem(pinned_at++, item);",
		"\t\t\tif (0)\n\t\t\t\tm_list->insertItem(pinned_at++, item);",
		"a pinned note is listed where it falls, among the rest -- sec 444",
	),
	(
		"notebook-view-archive-is-its-own-view",
		"gui/notebook_view.cpp",
		"\t\t\tif (trashed != m_trash || (!m_trash && archived != m_archived))",
		"\t\t\tif (trashed != m_trash)",
		"archived notes sit among the live ones, and the archive shows everything -- sec 444",
	),
	(
		"members-answer-lists-no-contact",
		"node/members.c",
		"\t\tif (fzn_node_peer_contact(config, p))\n\t\t\tcontinue;\n",
		"",
		"a member asking for the estate's members is told every contact's key -- sec 445",
	),
	(
		"members-pull-admits-only-on-proof",
		"node/members.c",
		"\t\t\t\tif (!proves(key, reply + at + FZN_PUBKEY_LEN + 1u, hop_count, root,\n\t\t\t\t            capability, now, sign, revocations)\n\t\t\t\t    || *count >= cap)",
		"\t\t\t\tif (*count >= cap)",
		"any key a peer names is admitted as a writer -- sec 445",
	),
	(
		"members-chain-names-the-key",
		"node/members.c",
		"\t       && memcmp(verdict.grantee, key, FZN_PUBKEY_LEN) == 0;\n",
		"\t       ;\n",
		"a key listed beside another member's chain is admitted on that chain -- sec 445",
	),
	(
		"notes-members-replace-each-round",
		"node/notes.c",
		"\tnotes->admitted_count = notes->base_count;\n",
		"",
		"a member revoked or gone stays a writer for as long as the node runs -- sec 445",
	),
	(
		"node-notes-members-get-only-purges",
		"node/notes.c",
		"\t    || (request[1] != FZN_NOTES_SYNC_PURGE && request[1] != FZN_NOTES_SYNC_PURGE_ACK",
		"\t    || (0 && request[1] != FZN_NOTES_SYNC_PURGE && request[1] != FZN_NOTES_SYNC_PURGE_ACK",
		"a member is still handed the index its notes no longer come by -- sec 519",
	),
	(
		"notes-feed-waits-for-a-writer",
		"node/notes.c",
		"\t\t\tif (err == FZN_NOTES_ERR_DENIED) {\n\t\t\t\ttally->waiting = 1;\n\t\t\t\treturn FZN_NOTES_OK;\n\t\t\t}\n",
		"",
		"a member proved a round late has every note it wrote passed over for good -- sec 519",
	),
	(
		"notes-feed-purge-needs-admitted",
		"node/notes.c",
		"\t\t\tif (!node_admits(n, key)) {",
		"\t\t\tif (0) {",
		"any key with a stream here purges any note -- sec 519",
	),
	(
		"notes-purge-is-told",
		"node/notes.c",
		"\tif (!n->chain\n\t    || !n->chain(n->chain_ctx",
		"\tif (1\n\t    || !n->chain(n->chain_ctx",
		"a purge reaches no member joining after its conversation ended, who files the note again from history -- sec 519",
	),
	(
		"notes-mark-tells-once",
		"notes/store.c",
		"\tif (fzn_notes_purged(store, id))\n\t\treturn FZN_NOTES_OK;\n\tif (fzn_persist_head_write",
		"\tif (fzn_persist_head_write",
		"every retry of an erase writes another purge record into the history -- sec 519",
	),
	(
		"notes-text-push-vouches-for-the-sender",
		"node/notes.c",
		"\tif (request_len < TEXT_PUSH_HEAD || !n->place || !sender_admitted(n, sender))",
		"\tif (request_len < TEXT_PUSH_HEAD || !n->place)",
		"any node that can reach this one fills its shelf -- sec 448",
	),
	(
		"notes-text-push-only-for-a-held-note",
		"node/notes.c",
		"\tif (!own_note_names(n, root, length))\n\t\tgoto answer;\n",
		"",
		"a pushed text is taken for a note this node does not hold -- sec 448",
	),
	(
		"notes-text-push-at-the-notes-length",
		"node/notes.c",
		"\t\t    && memcmp(ref.root, root, FZN_BLOB_HASH_LEN) == 0 && ref.length == length)\n\t\t\treturn 1;\n\t}\n\treturn 0;\n}\n\nstatic int sender_admitted",
		"\t\t    && memcmp(ref.root, root, FZN_BLOB_HASH_LEN) == 0)\n\t\t\treturn 1;\n\t}\n\treturn 0;\n}\n\nstatic int sender_admitted",
		"a text pushed at a length no note names is taken, and served with proofs that do not verify -- sec 448",
	),
	(
		"shelf-pushed-span-is-proved",
		"node/shelf.c",
		"\tif (fzn_spool_place_span(&h->spool, shelf->hash, first, count, sealed, sealed_len, proof,\n\t                         siblings)\n\t    != FZN_SPOOL_OK)\n\t\treturn FZN_NODE_SHELF_ERR_UNVERIFIED;\n",
		"\t(void)fzn_spool_place_span(&h->spool, shelf->hash, first, count, sealed, sealed_len, proof,\n\t                           siblings);\n",
		"a span that does not prove is answered as placed -- sec 448",
	),
	(
		"shelf-fetch-checks-leaf-lengths",
		"node/shelf.c",
		"\tfor (i = 0; i < count; i++)\n\t\tif (sealed_len[i] != sealed_len_of(h, first + i))\n\t\t\treturn FZN_NODE_SHELF_ERR_UNVERIFIED;\n",
		"",
		"a note naming the wrong length for its text fetches it anyway, and the host writes the wrong length down and serves proofs at it that never verify -- sec 424",
	),
	(
		"shelf-serves-only-whole",
		"node/shelf.c",
		"\tif (!fzn_spool_complete(&h->spool)) {\n\t\tfzn_spool_file_close(&h->file);\n\t\treturn FZN_NODE_SHELF_ERR_ABSENT;\n\t}\n",
		"",
		"a host part way through a fetch offers a text whose proofs it cannot build, and calls a text it cannot open held -- sec 424",
	),
	(
		"shelf-held-last-leaf-keeps-its-length",
		"node/shelf.c",
		"\tif (had_length && before != length && fzn_spool_has(&h->spool, h->leaves - 1u)) {\n",
		"\tif (0) {\n",
		"a second note naming another length for the same root overwrites the length the last leaf proved, and the host then serves that text with proofs that do not verify -- sec 424",
	),
	(
		"shelf-want-is-fresh",
		"node/shelf.c",
		"\tshelf->fresh = 1;\n",
		"",
		"a text somebody just asked for waits out a whole pull period before anything asks a peer for it -- sec 424",
	),
	(
		"pack-settles-past-a-clock-set-back",
		"log/pack.c",
		"\t\tif (at <= now_us + settle_us && (now_us < at || now_us - at < settle_us))\n",
		"\t\tif (now_us < at || now_us - at < settle_us)\n",
		"a segment closed while the clock read later is left unpacked until the clock reaches it -- sec 470",
	),
	(
		"notes-partner-ages-from-a-clock-set-back",
		"notes/sync.c",
		"\tif (*ms > now_ms) {\n\t\tpartner_seen(store, key, now_ms);\n",
		"\tif (0) {\n\t\tpartner_seen(store, key, now_ms);\n",
		"a partner seen while the clock read years ahead stays pinned by every purge for those years, and the trash is never emptied -- sec 470",
	),
	(
		"notes-purge-due-survives-a-clock-set-back",
		"notes/purge.c",
		"\t\tif (p.last_push_ms != 0u && now_ms - p.last_push_ms < FZN_NOTES_PURGE_RETRY_MS\n\t\t    && now_ms >= p.last_push_ms)\n",
		"\t\tif (p.last_push_ms != 0u\n\t\t    && (now_ms < p.last_push_ms || now_ms - p.last_push_ms < FZN_NOTES_PURGE_RETRY_MS))\n",
		"a purge stamped in the future -- a clock set back -- is never asked again until the clock reaches the stamp, and the trashed note stays hidden and undeleted -- sec 469",
	),
	(
		"entries-view-says-a-silent-host",
		"gui/entries_view.cpp",
		"\tif (err == FZN_GATHER_ERR_NO_ANSWER)\n\t\tm_status->setText(QStringLiteral(\"The host did not answer.\"));\n\telse if",
		"\tif",
		"a host that does not answer reads as a host whose answer was not a log -- sec 468",
	),
	(
		"entries-view-shortens-when-asked",
		"gui/entries_view.cpp",
		"\t\tif (m_short->isChecked()\n",
		"\t\tif (false && m_short->isChecked()\n",
		"Short shows every line whole, hiding nothing -- sec 468",
	),
	(
		"view-hides-what-repeats",
		"log/view.c",
		"\t\twhile (from < 5u && strcmp(tree_cur[from], tree_prev[from]) == 0)\n\t\t\tfrom++;\n",
		"",
		"the shortened view shortens nothing, every line carrying the whole tree -- sec 467",
	),
	(
		"view-dates-a-new-day",
		"log/view.c",
		"\t    || memcmp(now, before, 10u) != 0) {\n",
		"\t    || 0) {\n",
		"lines from two days read as one, the time of day the only clue -- sec 467",
	),
	(
		"view-escapes-the-text",
		"log/view.c",
		"\t(void)fzn_capture_escape(cur->text, cur->text_len, text, sizeof(text));\n",
		"\tmemcpy(text, cur->text, cur->text_len);\n\ttext[cur->text_len] = '\\0';\n",
		"an entry's text reaches a terminal raw, a newline in it forging a line and an escape driving the terminal -- sec 467",
	),
	(
		"caller-sends-what-its-wrap-wrote",
		"node/caller.c",
		"\t\tif (n) {\n\t\t\tpayload = wrapped;\n\t\t\tpayload_len = n;\n\t\t}\n",
		"\t\t(void)n;\n",
		"a daemon's causes are written round a request and the request goes without them, so the roots and votes pulls are never traced -- sec 465",
	),
	(
		"gather-ring-past-the-cursor",
		"log/gather.c",
		"\tif (p->full || (p->started && e->name.position <= p->after))\n",
		"\tif (p->full)\n",
		"every page of a host's flight recorder starts again from its oldest entry -- sec 464",
	),
	(
		"gather-ring-fetch-moves-its-cursor",
		"log/gather.c",
		"\t\t\tafter = e.name.position;\n\t\t\tstarted = 1;\n",
		"",
		"the troubleshooter asks for the first page over and over, and sees each entry many times -- sec 464",
	),
	(
		"gather-keeps-to-the-window",
		"log/gather.c",
		"\t\t\tif (fzn_entry_line_time(line, len, &t) != FZN_ENTRY_OK || t < q.since_us\n\t\t\t    || t > q.until_us || (q.match[0] && !strstr(line, q.match)))\n",
		"\t\t\tif (fzn_entry_line_time(line, len, &t) != FZN_ENTRY_OK || t < q.since_us\n\t\t\t    || (q.match[0] && !strstr(line, q.match)))\n",
		"a troubleshooter asking for an hour gets everything after it too -- sec 463",
	),
	(
		"gather-keeps-to-the-match",
		"log/gather.c",
		"\t\t\t    || t > q.until_us || (q.match[0] && !strstr(line, q.match)))\n",
		"\t\t\t    || t > q.until_us)\n",
		"asking for an entry and what it caused returns the whole log -- sec 463",
	),
	(
		"gather-resumes-at-the-cursor",
		"log/gather.c",
		"\t\t\tif (here < start || line[0] == '#')\n",
		"\t\t\tif (line[0] == '#')\n",
		"every page after the first repeats its segment from the beginning -- sec 463",
	),
	(
		"admin-asks-the-logs-hook",
		"node/admin.c",
		"\t\tsize_t n = admin->logs_remote(admin->logs_ctx, req->sender, req->payload,\n\t\t                              req->payload_len, reply, reply_cap);\n",
		"\t\tsize_t n = 0;\n",
		"a member's gather query falls through to the verbs and is never answered -- sec 463",
	),
	(
		"admin-takes-the-causes-off",
		"node/admin.c",
		"\t\t\t\tadmin->caused(admin->caused_ctx, req->sender, &cause, &origin);\n\t\t\treq = &inner;\n",
		"\t\t\t\tadmin->caused(admin->caused_ctx, req->sender, &cause, &origin);\n",
		"every request a peer sends with its causes is handled as the envelope's bytes, and no pull, push or fetch between new nodes works -- sec 462",
	),
	(
		"admin-refuses-a-broken-envelope",
		"node/admin.c",
		"\t\tif (cerr == FZN_CAUSE_ERR_MALFORMED)\n\t\t\treturn answer_text(out, reply_cap, FZN_REPLY_MALFORMED,\n\t\t\t                   \"the request's causes do not read\");\n",
		"",
		"an envelope that does not read is handed on as a request nobody sent -- sec 462",
	),
	(
		"admin-tells-who-asked",
		"node/admin.c",
		"\t\t\tif (admin->caused)\n\t\t\t\tadmin->caused(admin->caused_ctx, req->sender, &cause, &origin);\n",
		"",
		"the answering node never learns which entry a request was made for, and the grep across hosts finds one end of the work -- sec 462",
	),
	(
		"cause-envelope-uses-every-byte",
		"log/cause.c",
		"\tif (n == 0u || len - at != n)\n",
		"\tif (n == 0u || len - at < n)\n",
		"an envelope with bytes past its request is taken, so what the frame carried and what was handled differ -- sec 462",
	),
	(
		"cause-envelope-is-version-3",
		"log/cause.c",
		"\tout[0] = FZN_CAUSE_VERSION;\n",
		"\tout[0] = 2u;\n",
		"a request with its causes goes out under the notes sync family's version and is answered as a notes message -- sec 462",
	),
	(
		"logger-falls-back-to-dbus-machine-id",
		"log/logger.c",
		"\tif (!f && !machine_id_path)\n\t\tf = fopen(\"/var/lib/dbus/machine-id\", \"r\");\n",
		"",
		"a machine without systemd has no log file at all, its daemon saying only that the machine would not read -- this tree's own did; caught only on such a machine -- sec 461",
	),
	(
		"retain-keep-expands",
		"log/retain.c",
		"\t\tremove[i] = (uint8_t)(remove[i] == FZN_RETAIN_MARK_PRUNED);\n",
		"\t\tremove[i] = (uint8_t)((remove[i] & FZN_RETAIN_MARK_PRUNED) != 0);\n",
		"a keep rule protects nothing, so 'keep 30 days' beside 'prune older than 7 days' keeps 7, the opposite of what the holder asked -- sec 460",
	),
	(
		"retain-size-keeps-the-straddling-segment",
		"log/retain.c",
		"\t\treturn before < r->value;\n",
		"\t\treturn before + seg->bytes <= r->value;\n",
		"a size limit removes the segment it begins inside, keeping less than it says -- sec 460",
	),
	(
		"retain-ranks-newest-first",
		"log/retain.c",
		"\t\t\tif (s[p].closed_us > s[k].closed_us\n",
		"\t\t\tif (s[p].closed_us < s[k].closed_us\n",
		"a count or size limit counts from the oldest segment, and prunes the newest -- sec 460",
	),
	(
		"retain-a-rule-has-no-stray-word",
		"log/retain.c",
		"\t\t} else {\n\t\t\treturn FZN_RETAIN_ERR_MALFORMED;\n\t\t}\n\t}\n\t/* A COPY IS KEPT",
		"\t\t} else {\n\t\t\tcontinue;\n\t\t}\n\t}\n\t/* A COPY IS KEPT",
		"a rule with a word that is no selector, or a selector named twice, is taken as if the word were not there -- secs 460, 474",
	),
	(
		"retain-a-rule-names-its-program",
		"log/retain.c",
		"\t\t\t\tif (!matches(rule, program) || fzn_retain_rule_selects_entries(rule))\n",
		"\t\t\t\tif (fzn_retain_rule_selects_entries(rule))\n",
		"a rule written for one program prunes every program's log -- sec 460",
	),
	(
		"pack-chains-from-the-previous-segment",
		"log/pack.c",
		"\tmemcpy(state, prev, sizeof(state));\n\twhile ((n = fread(chunk,",
		"\tmemset(state, 0, sizeof(state));\n\twhile ((n = fread(chunk,",
		"each segment's hash starts afresh, so removing or reordering a segment breaks nothing -- sec 459",
	),
	(
		"pack-verify-compares-the-hash",
		"log/pack.c",
		"\t    || memcmp(tr.hash, state, FZN_LOG_PACK_HASH_LEN) != 0)\n",
		"\t    )\n",
		"a packed segment whose bytes were edited and recompressed verifies, the trailer's hash never compared -- sec 459",
	),
	(
		"pack-oldest-first",
		"log/pack.c",
		"\t\treturn x->at < y->at ? -1 : 1;\n",
		"\t\treturn x->at < y->at ? 1 : -1;\n",
		"segments are chained newest first, so the chain says the opposite of the order they were written -- sec 459",
	),
	(
		"pack-waits-for-a-segment-to-settle",
		"log/pack.c",
		"\t\tif (at <= now_us + settle_us && (now_us < at || now_us - at < settle_us))\n\t\t\tcontinue;\n",
		"",
		"a segment is packed the moment it is closed, and a line another instance was still writing lands after the trailer or is lost -- sec 459",
	),
	(
		"pack-reads-the-chain-it-wrote",
		"log/pack.c",
		"\treturn n == 65 && t[64] == '\\n' && from_hex(t, prev, 32u);\n",
		"\treturn n == 66 && t[64] == '\\n' && from_hex(t, prev, 32u);\n",
		"every pass after the first refuses the chain file its predecessor wrote, and nothing more is ever packed -- sec 459",
	),
	(
		"caller-recv-any-names-its-message",
		"node/caller.c",
		"\t\t*msg = opened.msg;\n",
		"",
		"a reply taken by recv_any is filed under whatever message the caller last named, and a fetch places one span's leaves as another's -- sec 494",
	),
	(
		"files-range-waits-for-its-leaves",
		"node/files.c",
		"\tfor (i = first; i <= last && opened; i++)\n\t\tif (!fzn_spool_has(&h.spool, i))\n\t\t\tbreak;\n",
		"\ti = last + 1u;\n",
		"a range the fetch has not reached is read from leaves never placed, and fails part way rather than saying it has not arrived -- sec 495",
	),
	(
		"files-silent-peer-given-up",
		"node/files.c",
		"\t\t\t\t\tif (alive[out[k].peer] && ++failures[out[k].peer] >= 3u) {\n",
		"\t\t\t\t\tif (0) {\n",
		"a peer that never answers is sent spans for as long as the fetch runs, each waiting out its deadline -- sec 494",
	),
	(
		"files-lying-peer-given-up",
		"node/files.c",
		"\t\t\t\t\tif (++failures[k] >= 3u) {\n",
		"\t\t\t\t\tif (0) {\n",
		"a peer whose spans never prove is asked again and again, and every span it is given wasted -- sec 494",
	),
	(
		"files-contact-asks-only-what-is-shared",
		"node/files.c",
		"\tif (!fzn_node_files_shared_with(files, root, sender))\n\t\treturn 0;\n",
		"",
		"a contact is served every file this node holds, private ones included -- sec 493",
	),
	(
		"files-share-reaches-a-group-member",
		"node/files.c",
		"\t\t\tif (memcmp(grantees[i], groups[j], FZN_PUBKEY_LEN) == 0)\n\t\t\t\treturn 1;\n",
		"\t\t\tif (0)\n\t\t\t\treturn 1;\n",
		"a file shared with a group reaches none of its members -- sec 493",
	),
	(
		"files-share-row-under-its-own-key",
		"node/files.c",
		"\treturn share_key(files, root, grantee, again) && memcmp(again, key, FZN_PUBKEY_LEN) == 0;\n",
		"\treturn share_key(files, root, grantee, again);\n",
		"a share row copied under another key reads as a share nobody made -- sec 493",
	),
	(
		"files-removed-takes-its-shares",
		"node/files.c",
		"\t\tif (forget_rows(files, root, 1, &rows) != FZN_NODE_FILES_OK)\n",
		"\t\tif (0)\n",
		"a file deleted and put again later is public or shared as the old one was -- sec 493",
	),
	(
		"files-scrub-drops-only-what-differs",
		"node/files.c",
		"\t\t\t    && memcmp(leaf, kept, sizeof(leaf)) != 0)\n\t\t\t\t*dropped += fzn_spool_forget(&h.spool, i, 1u);\n",
		"\t\t\t    )\n\t\t\t\t*dropped += fzn_spool_forget(&h.spool, i, 1u);\n",
		"a scrub finding one leaf changed drops the whole file and fetches it all again -- sec 492",
	),
	(
		"files-scrub-rebuilds-a-wrong-tree",
		"node/files.c",
		"\t\terr = build_tree(files, &h, root);\n\t\tgoto out;\n",
		"\t\tgoto out;\n",
		"a tree changed at rest is passed over, and the next changed leaf costs the whole file -- sec 492",
	),
	(
		"files-scrub-forgets-what-folds-to-nothing",
		"node/files.c",
		"\t\t*dropped = fzn_spool_forget(&h.spool, 0, h.leaves);\n",
		"\t\t*dropped = 0;\n",
		"a file whose leaves and tree both fail is kept as whole and served wrong -- sec 492",
	),
	(
		"files-fetch-keeps-its-budget",
		"node/files.c",
		"\t\tfor (asks = 0, stop = 0; !stop && *placed < budget && asks < FZN_TRANSFER_MAX_ASSIGNS;) {\n\t\t\tint progress = 0;\n\n\t\t\tfor (j = 0; j < n_peers && !stop && *placed < budget; j++) {\n",
		"\t\tfor (asks = 0, stop = 0; !stop && asks < FZN_TRANSFER_MAX_ASSIGNS;) {\n\t\t\tint progress = 0;\n\n\t\t\tfor (j = 0; j < n_peers && !stop; j++) {\n",
		"a fetch takes the whole file in one round however large, and the node answers nothing else meanwhile -- sec 491",
	),
	(
		"files-wanted-ends-when-whole",
		"node/files.c",
		"\t\t    || fzn_node_files_held(files, root, &have) == FZN_NODE_FILES_OK\n\t\t    || !path_of(files, root, \".len\", len_path) || !read_length(len_path, &length))\n",
		"\t\t    || !path_of(files, root, \".len\", len_path) || !read_length(len_path, &length))\n",
		"a file fetched whole is still wanted, and asked for again every round for ever -- sec 491",
	),
	(
		"files-remove-says-absent",
		"node/files.c",
		"\treturn gone ? FZN_NODE_FILES_OK : FZN_NODE_FILES_ERR_ABSENT;\n",
		"\treturn FZN_NODE_FILES_OK;\n",
		"removing a file that is not here answers that it was removed -- sec 491",
	),
	(
		"levels-fold-left-then-right",
		"blob/levels.c",
		"\treturn fzn_blob_node_hash(levels->hash, left, out, out);\n",
		"\treturn fzn_blob_node_hash(levels->hash, out, left, out);\n",
		"a proof read from a file's tree folds its ragged edge the wrong way round, and every span past the last perfect subtree is refused -- sec 490",
	),
	(
		"levels-carry-a-right-child",
		"blob/levels.c",
		"\t\tif ((index & 1u) == 0u) {\n",
		"\t\tif ((index & 1u) != 0u) {\n",
		"a file's tree on disk holds the wrong nodes, and no span of it proves -- sec 490",
	),
	(
		"files-busy-is-not-deleted",
		"node/files.c",
		"\tif (is_busy(files, root))\n\t\treturn FZN_NODE_FILES_ERR_BUSY;\n\t/* THE SIDECAR FIRST",
		"\tif (0)\n\t\treturn FZN_NODE_FILES_ERR_BUSY;\n\t/* THE SIDECAR FIRST",
		"a file is deleted under a transfer still writing it -- sec 490",
	),
	(
		"files-export-writes-a-new-file",
		"node/files.c",
		"\t/* A NEW FILE, never one written over. */\n\tfd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);\n",
		"\t/* A NEW FILE, never one written over. */\n\tfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);\n",
		"an export writes over whatever was at its destination -- sec 490",
	),
	(
		"files-export-leaves-nothing-half",
		"node/files.c",
		"\t/* NOTHING HALF-EXPORTED is left at the destination. */\n\tif (err != FZN_NODE_FILES_OK)\n\t\t(void)remove(path);\n",
		"\t/* NOTHING HALF-EXPORTED is left at the destination. */\n",
		"an export that fails part way leaves half a file at its destination, read as the file -- sec 490",
	),
	(
		"files-held-needs-its-tree",
		"node/files.c",
		"\t    || h->leaves != leaves || stat(tree_path, &st) != 0\n\t    || (uint64_t)st.st_size != fzn_blob_levels_bytes(leaves))\n",
		"\t    || h->leaves != leaves)\n",
		"a blob whose tree is gone is held, and every span it is asked for has no proof -- sec 490",
	),
	(
		"roster-confirms-once-a-writer",
		"node/roster.c",
		"\t\tif (!mine) {\n",
		"\t\tif (1) {\n",
		"a member removing a contact it already removed writes another removal, which counts nothing and fills the store -- sec 489",
	),
	(
		"roster-learned-is-admitted",
		"node/revoke.c",
		"\t\tif (!pull->roster) {\n",
		"\t\tif (1) {\n",
		"every contact record a member pulls is refused, so a contact added or removed on one member never reaches another -- sec 489",
	),
	(
		"roster-written-is-logged",
		"node/roster.c",
		"\tif (nr->wrote && !nr->wrote(nr->wrote_ctx, record, len))\n",
		"\tif (0)\n",
		"a root's roster record is never in its log, and falls at the root's removal whatever the cut -- sec 489",
	),
	(
		"roster-retired-outranks-suspended",
		"node/roster.c",
		"\t\tif (s == FZN_ROSTER_RETIRED || (s == FZN_ROSTER_SUSPENDED && best == FZN_ROSTER_ABSENT))\n",
		"\t\tif (s == FZN_ROSTER_SUSPENDED && best == FZN_ROSTER_ABSENT)\n",
		"a retired contact is reported absent, as if nobody had ever removed it -- sec 489",
	),
	(
		"admin-serves-only-active-contacts",
		"node/admin.c",
		"\treturn !admin->roster\n\t       || fzn_node_roster_standing(admin->roster, key, admin->revocations, roster_k(admin))\n",
		"\treturn 1 || !admin->roster\n\t       || fzn_node_roster_standing(admin->roster, key, admin->revocations, roster_k(admin))\n",
		"a contact removed on another member of the estate is still served here on its name -- sec 489",
	),
	(
		"local-reply-without-sigpipe",
		"node/local.c",
		"\t\tssize_t n = write_quietly(fd, buf + off, len - off);\n",
		"\t\tssize_t n = write(fd, buf + off, len - off);\n",
		"a local client that closes before reading its answer ends the node with SIGPIPE -- sec 489",
	),
	(
		"retain-source-only-on-copies",
		"log/retain.c",
		"\tif (out->has_source && !out->copy)\n\t\treturn FZN_RETAIN_ERR_MALFORMED;\n",
		"",
		"a source on a rule for this node's own log is read, and the rule is then refused by every writer that checks it -- sec 487",
	),
	(
		"retain-source-selects-its-host",
		"log/retain.c",
		"\t\t    && (!in[i].has_source\n\t\t        || memcmp(in[i].source, source, sizeof(in[i].source)) == 0))\n",
		"\t\t    )\n",
		"a rule naming one host's copies removes every host's -- sec 487",
	),
	(
		"retain-source-written",
		"log/retain.c",
		"\t\tif (rule->has_source) {\n\t\t\tmemcpy(scope + m, \" source=\", 8u);\n",
		"\t\tif (0) {\n\t\t\tmemcpy(scope + m, \" source=\", 8u);\n",
		"a rule kept or sent as text loses its source and applies to every host's copies -- sec 487",
	),
	(
		"logger-programs-take-off-time-and-pid",
		"log/logger.c",
		"\tif (fields == 2u)\n\t\tlen = k;\n",
		"\tif (fields == 2u)\n\t\tlen = (size_t)(strchr(name, '.') - name);\n",
		"a program whose name holds a dot is tended under its first word, and its own segments are never packed or pruned -- sec 486",
	),
	(
		"logger-programs-refuse-a-lone-packed-file",
		"log/logger.c",
		"\telse if (packed) /* only a closed segment is packed */\n\t\treturn 0;\n",
		"",
		"a stray PROGRAM.log.zst names a program nothing logs as, and the node packs and prunes for it -- sec 486",
	),
	(
		"logger-programs-name-each-once",
		"log/logger.c",
		"\t\tif (k == *n)\n\t\t\tmemcpy(out[(*n)++], program, sizeof(program));\n",
		"\t\tmemcpy(out[(*n)++], program, sizeof(program));\n",
		"a program with many segments fills the list once per segment, and the programs past them are never tended -- sec 486",
	),
	(
		"logger-calls-the-rotated-hook",
		"log/logger.c",
		"\tif (l->rotated)\n\t\tl->rotated(l->rotated_ctx);\n",
		"",
		"a rotation never reaches the packer, and closed segments stay unpacked and unchained -- sec 459",
	),
	(
		"logger-keeps-only-its-levels",
		"log/logger.c",
		"\tkept = fzn_entry_level_letter(level) && level <= logger->keep;\n",
		"\tkept = fzn_entry_level_letter(level) != 0;\n",
		"every debug entry is formatted and written to the file, which is the noise the ring exists to take -- sec 458",
	),
	(
		"logger-follows-another-instances-rotation",
		"log/logger.c",
		"\t    && on_path.st_dev == held.st_dev && on_path.st_ino == held.st_ino)\n",
		"\t    && on_path.st_dev == held.st_dev)\n",
		"an instance goes on writing into a segment another instance has closed, after its trailer and out of its time -- sec 458",
	),
	(
		"logger-rotates-past-the-segment-size",
		"log/logger.c",
		"\tif (held.st_size <= 0 || (uint64_t)held.st_size + adding <= l->segment_max)\n",
		"\tif (1)\n",
		"a program's log grows without bound in one file, and nothing can be packed or pruned by segment -- sec 458",
	),
	(
		"logger-writes-the-header",
		"log/logger.c",
		"\t\tif (k <= 0 || (size_t)k >= sizeof(head) || write(fd, head, (size_t)k) != (ssize_t)k) {\n",
		"\t\tif (k <= 0 || (size_t)k >= sizeof(head)) {\n",
		"a log file does not say its format's version or which machine its host name is -- sec 458",
	),
	(
		"entry-record-uses-every-byte",
		"log/entry.c",
		"\tif (text_len > FZN_ENTRY_TEXT_MAX || (size_t)(end - at) != text_len)\n",
		"\tif (text_len > FZN_ENTRY_TEXT_MAX || (size_t)(end - at) < text_len)\n",
		"a record with bytes past its text unpacks, so two records run together read as one -- sec 457",
	),
	(
		"entry-record-carries-its-cause",
		"log/entry.c",
		"\t*at++ = entry->caused ? 2u : 0u;\n",
		"\t*at++ = 0u;\n",
		"a record says it has no cause while carrying two names, and the work it belongs to is lost in the ring -- sec 457",
	),
	(
		"ring-evicts-before-it-writes",
		"log/ring.c",
		"\twhile (FZN_RING_BYTES - ring->used < 2u + len)\n\t\tevict(ring);\n",
		"\tif (FZN_RING_BYTES - ring->used < 2u + len)\n\t\treturn;\n",
		"a full flight recorder drops the newest entries instead of the oldest, so the minutes before an error are the ones lost -- sec 457",
	),
	(
		"ring-counts-what-it-evicts",
		"log/ring.c",
		"\tring->held--;\n\tring->evicted++;\n",
		"\tring->held--;\n",
		"a dump cannot say how much was lost before it -- sec 457",
	),
	(
		"ring-dumps-both-spans",
		"log/ring.c",
		"\t\t*second_len = ring->used - tail;\n",
		"\t\t*second_len = 0;\n",
		"a crash dump of a ring that has wrapped stops at the buffer's end and loses the newest entries -- sec 457",
	),
	(
		"ring-load-reads-every-record",
		"log/ring.c",
		"\t\tif (len - off - 2u < n || fzn_entry_unpack(dump + off + 2u, n, &e) != FZN_ENTRY_OK)\n",
		"\t\tif (len - off - 2u < n)\n",
		"a dump holding bytes that are no record loads, and its walk stops silently at them -- sec 457",
	),
	(
		"entry-escapes-its-text",
		"log/entry.c",
		"\t(void)fzn_capture_escape(entry->text, entry->text_len, text, sizeof(text));\n",
		"\tmemcpy(text, entry->text, entry->text_len);\n\ttext[entry->text_len] = '\\0';\n",
		"a log entry's text is written raw, so a newline in it forges a second line in our own format -- sec 456",
	),
	(
		"entry-cause-and-origin-both-or-neither",
		"log/entry.c",
		"\t} else {\n\t\treturn FZN_ENTRY_ERR_MALFORMED;\n\t}\n\tif (!unescape(",
		"\t} else {\n\t\tout->caused = 0;\n\t}\n\tif (!unescape(",
		"a line with half a cause reads as an entry with none, and the work it was part of is lost to the grep -- sec 456",
	),
	(
		"entry-a-word-holds-no-space",
		"log/entry.c",
		"\t\tif (i >= max || !word_char(w[i]))\n",
		"\t\tif (i >= max)\n",
		"a user or program with a space in it moves every field after it, and the line reads back as another entry -- sec 456",
	),
	(
		"entry-no-leap-day-in-a-common-year",
		"log/entry.c",
		"\t    || (mo == 2u && d == 29u && !leap) || h > 23u",
		"\t    || h > 23u",
		"a time on 29 February of a common year is read as 1 March -- sec 456",
	),
	(
		"entry-four-digit-years",
		"log/entry.c",
		"\tif (y > 9999)\n\t\treturn 0;\n",
		"",
		"a time past 9999 is written five digits wide and shifts every field after it -- sec 456",
	),
	(
		"entry-a-line-that-does-not-fit-leaves-nothing",
		"log/entry.c",
		"\t\t/* NOTHING THAT COULD BE TAKEN FOR A LINE. */\n\t\tout[0] = '\\0';\n",
		"",
		"a line cut short by the buffer is left there, readable as a line with a shorter text -- sec 456",
	),
	(
		"admin-a-removed-contact-is-served-nothing",
		"node/admin.c",
		"\t    || fzn_contact_get(admin->store, key, &still) != FZN_CONTACT_OK)\n",
		"\t    || 0)\n",
		"a contact the user removed goes on fetching everything shared with it, and every change made after, and what it shares is still pulled -- secs 454, 576",
	),
	(
		"notes-move-not-under-a-descendant",
		"notes/author.c",
		"\tif (above(author->view, id, parent))\n\t\treturn FZN_NOTES_ERR_MALFORMED;\n",
		"",
		"a folder moved under its own descendant leaves the tree, with everything in it, for a cycle the view shows at the top -- sec 453",
	),
	(
		"notes-above-climbs-past-the-parent",
		"notes/author.c",
		"\t\t\tif (!seen[k] && memcmp(view->nodes[k].id, up, FZN_TREE_ID_LEN) == 0) {\n",
		"\t\t\tif (0) {\n",
		"a folder moved under its grandchild is let through, since only the destination's own parent is looked at -- sec 453",
	),
	(
		"notebook-view-moves-into-the-open-folder",
		"gui/notebook_view.cpp",
		"QStringLiteral(\"set note %1 parent %2\").arg(m_cut, parent_id())",
		"QStringLiteral(\"set note %1 parent %2\").arg(m_cut, QStringLiteral(\"top\"))",
		"Move here puts the note somewhere other than the folder the reader is looking at -- sec 453",
	),
	(
		"notebook-view-removes-the-item-asked-for",
		"gui/notebook_view.cpp",
		"QStringLiteral(\"remove item %1 %2\").arg(m_open).arg(index)",
		"QStringLiteral(\"remove item %1 %2\").arg(m_open).arg(index + 1)",
		"Remove item removes the item after the one at the cursor -- sec 453",
	),
	(
		"shelf-verify-compares-the-root",
		"node/shelf.c",
		"\tfolds = folds && fzn_blob_tree_root(shelf->hash, &tree, got) == FZN_BLOB_OK\n\t        && memcmp(got, root, FZN_BLOB_HASH_LEN) == 0;\n",
		"\tfolds = folds && fzn_blob_tree_root(shelf->hash, &tree, got) == FZN_BLOB_OK;\n",
		"a text rotted on disk passes its check at rest, and the node goes on serving bytes that no longer prove -- sec 452",
	),
	(
		"shelf-verify-forgets-the-leaves",
		"node/shelf.c",
		"\t(void)fzn_spool_forget(&h.spool, 0u, h.leaves);\n",
		"",
		"a text found rotted is still held, so it is served and never fetched again -- sec 452",
	),
	(
		"shelf-verify-checks-only-a-whole-text",
		"node/shelf.c",
		"\t*intact = 0;\n\terr = open_whole(shelf, root, &h);\n",
		"\t*intact = 0;\n\terr = open_held(shelf, root, &h);\n",
		"a text part way through its fetch is judged rotted for the leaves it has not got -- sec 452",
	),
	(
		"shelf-scrub-walks-past-the-cursor",
		"node/shelf.c",
		"\t\tif (memcmp(root, shelf->scrub_after, FZN_BLOB_HASH_LEN) > 0\n",
		"\t\tif (memcmp(root, shelf->scrub_after, FZN_BLOB_HASH_LEN) >= 0\n",
		"the scrub checks the same text every step and never reaches the rest of the shelf -- sec 452",
	),
	(
		"shelf-scrub-wraps",
		"node/shelf.c",
		"\tif (!have_next)\n\t\tmemcpy(next, first, FZN_BLOB_HASH_LEN);\n",
		"\tif (!have_next)\n\t\treturn FZN_NODE_SHELF_OK;\n",
		"the scrub walks the shelf once and then checks nothing for the rest of the daemon's life -- sec 452",
	),
	(
		"notes-trash-skips-a-partner-no-longer-admitted",
		"node/notes.c",
		"\t\tif (!sender_admitted(n, partners[i]))\n\t\t\tcontinue;\n",
		"",
		"a purge pins a device the user has un-paired, which will never be asked again, and waits for it until the month runs out -- sec 451",
	),
	(
		"roots-standing-leaves-out-the-removed",
		"node/roots.c",
		"\t\tif (fzn_root_view_stands(&roots->view, key))\n\t\t\tmemcpy",
		"\t\tif (1)\n\t\t\tmemcpy",
		"a root the estate removed still writes notes every node takes -- sec 450",
	),
	(
		"roots-standing-keeps-its-cap",
		"node/roots.c",
		"for (i = 0; i <= roots->set.used && n < cap; i++) {",
		"for (i = 0; i <= roots->set.used; i++) {",
		"an estate with more roots than the writer table holds writes past the table -- sec 450",
	),
	(
		"notes-write-marks-fresh",
		"node/notes.c",
		"detail_len) == FZN_REPLY_OK)\n\t\tn->fresh = 1;\n",
		"detail_len) == FZN_REPLY_OK)\n\t\t;\n",
		"a note written here waits out the daemon's whole pull period, up to a minute, before it is pushed to the node it pulls from -- sec 449",
	),
	(
		"notes-fresh-only-on-a-write",
		"node/notes.c",
		"if (line_len && n && fzn_verb_mutates(request->parsed)\n\t    && ",
		"if (line_len && n\n\t    && ",
		"every read through the socket starts a round with every peer, so a view listing notes converses with the estate each time it draws -- sec 449",
	),
	(
		"notes-fresh-only-on-ok",
		"node/notes.c",
		"&detail, &detail_len) == FZN_REPLY_OK)\n\t\tn->fresh",
		"&detail, &detail_len) != FZN_REPLY_NONE)\n\t\tn->fresh",
		"a refused write starts a round as though something had changed -- sec 449",
	),
	(
		"notes-fresh-reads-a-bare-ok",
		"node/notes.c",
		"\tif (line_len && reply[line_len - 1u] == '\\n')\n\t\tline_len--;\n",
		"",
		"an edit, whose reply is a bare ok, is not seen to have taken and waits for the next round -- sec 449",
	),
	(
		"admin-local-reaches-the-shelf",
		"node/admin.c",
		"\tif (admin->text_local) {\n",
		"\tif (0) {\n",
		"put, fetch and get text are unsupported on a node that has a shelf -- sec 424",
	),
	(
		"admin-remote-reaches-the-shelf",
		"node/admin.c",
		"\tif (admin->text_remote && req->payload) {\n",
		"\tif (0) {\n",
		"a node with a shelf answers no peer's blob message, so no text is ever fetched from it -- sec 424",
	),
	(
		"note-reserved-type-refused",
		"notes/note.c",
		"\tif (content_type == FZN_NOTE_TYPE_NONE)\n\t\treturn FZN_NOTE_ERR_TYPE;\n\tif (content_len < FZN_NOTE_META_LEN)\n",
		"\tif (content_len < FZN_NOTE_META_LEN)\n",
		"an all-zero header decodes as a valid node of a valid type -- sec 422",
	),
	(
		"note-field-fits-before-sum",
		"notes/note.c",
		"\tif (note->title_len > FZN_NOTE_TITLE_MAX || note->labels_len > FZN_NOTE_LABELS_MAX\n\t    || note->text_len > FZN_NOTE_PAYLOAD_MAX)\n\t\treturn FZN_NOTE_ERR_LEN;\n",
		"",
		"a length that wraps the sum reaches memcpy with nothing bounding it -- sec 422",
	),
	(
		"note-folder-holds-no-text",
		"notes/note.c",
		"\t\tif (note->text_len != 0 || note->labels_len != 0)\n\t\t\treturn FZN_NOTE_ERR_PARTITION;\n",
		"",
		"a folder carrying text renders as a note on one host and a container on another -- sec 422",
	),
	(
		"note-attachment-not-writable",
		"notes/note.c",
		"\tcase FZN_NOTE_TYPE_FOLDER:\n\t\treturn 1;\n\tdefault:\n\t\t/* ATTACHMENT lands here",
		"\tcase FZN_NOTE_TYPE_FOLDER:\n\tcase FZN_NOTE_TYPE_ATTACHMENT:\n\t\treturn 1;\n\tdefault:\n\t\t/* ATTACHMENT lands here",
		"this build originates attachments it cannot yet produce a blob for -- sec 422",
	),
	(
		"note-item-cannot-overrun",
		"notes/note.c",
		"\tif (len > note->text_len - at - 3u)\n\t\treturn FZN_NOTE_ERR_PARTITION;\n",
		"",
		"a checklist item claiming more than is there is read past the text into the labels -- sec 422",
	),
	(
		"note-reference-names-something",
		"notes/note.c",
		"\tif (ref->length == 0u)\n\t\treturn FZN_NOTE_ERR_BLOB_LEN;\n",
		"",
		"a reference to an empty blob is written, where every payload has a header -- sec 422",
	),
	(
		"scope-unknown-reads-private",
		"state/scope.c",
		"\treturn fzn_scope_known(byte) ? (fzn_scope_t)byte : FZN_SCOPE_HOST_PRIVATE;\n",
		"\treturn (fzn_scope_t)byte;\n",
		"a scope byte this build does not know, read as itself, travels however a later build meant -- sec 420",
	),
	(
		"scope-group-needs-membership",
		"state/scope.c",
		"\t\treturn in_group != 0;\n",
		"\t\treturn 1;\n",
		"a group value reaching every host publishes a zone's configuration to the whole estate -- sec 420",
	),
	(
		"scope-widens-for-non-members",
		"state/scope.c",
		"\t       || (fzn_scope_reaches(to, 0) && !fzn_scope_reaches(from, 0));\n",
		"\t       ;\n",
		"group to host reaches every non-member and is not called widening, so it is made without deliberation -- sec 420",
	),
	(
		"scope-private-has-no-subject",
		"state/scope.c",
		"\tif (scope == FZN_SCOPE_HOST_PRIVATE)\n\t\treturn FZN_SCOPE_ERR_PRIVATE;\n",
		"",
		"a host-private value given a subject has a cell, and a cell can be replicated -- sec 420",
	),
	(
		"scope-unknown-has-no-subject",
		"state/scope.c",
		"\tif ((unsigned)scope >= FZN_SCOPE_COUNT)\n\t\treturn FZN_SCOPE_ERR_MALFORMED;\n",
		"",
		"a scope this build does not know derives a subject, so its cell exists before anybody decided how far it goes -- sec 420",
	),
	(
		"scope-in-the-subject",
		"state/scope.c",
		"\tinput[sizeof(FZN_SCOPE_LABEL)] = (uint8_t)scope;\n",
		"\tinput[sizeof(FZN_SCOPE_LABEL)] = 0u;\n",
		"one id under two scopes is one subject, so a group whose id equals a host's key overwrites that host's cells -- sec 420",
	),
	(
		"node-pair-root-by-proof-ends-here",
		"node/pair.c",
		"\t\t            != FZN_PROVISION_OK\n\t\t    || memcmp(from, id->pubkey, FZN_PUBKEY_LEN) != 0)\n",
		"\t\t            != FZN_PROVISION_OK)\n",
		"a proof that some other key is a root lets this node mint a first hop the device will refuse -- sec 419",
	),
	(
		"node-roots-identity-root-not-genesis",
		"node/roots.c",
		"\tif (fzn_ct_memeq(roots->set.genesis, identity, FZN_PUBKEY_LEN)\n\t    || !fzn_root_view_stands(&roots->view, identity))\n",
		"\tif (!fzn_root_view_stands(&roots->view, identity))\n",
		"the genesis taken as a root by proof pairs with an empty proof and an authority that stands for nothing -- sec 419",
	),
	(
		"node-roots-identity-root-stands",
		"node/roots.c",
		"\tif (fzn_ct_memeq(roots->set.genesis, identity, FZN_PUBKEY_LEN)\n\t    || !fzn_root_view_stands(&roots->view, identity))\n",
		"\tif (fzn_ct_memeq(roots->set.genesis, identity, FZN_PUBKEY_LEN))\n",
		"a removed identity still pairs as a root, with a proof of the add its removal undid -- sec 419",
	),
	(
		"admin-root-by-identity-card-fits",
		"node/admin.c",
		"\t    && by_identity.proof_count <= ADMIN_CARD_PROOF)\n",
		"\t    )\n",
		"a card past one reply line is paired and then cannot be answered: the device saved, its card lost -- sec 419",
	),
	(
		"admin-root-by-identity-pairs",
		"node/admin.c",
		"\t    && by_identity.proof_count <= ADMIN_CARD_PROOF)\n\t\tauthority = &by_identity;\n",
		"\t    && by_identity.proof_count <= ADMIN_CARD_PROOF)\n\t\t;\n",
		"a node whose identity is a root cannot pair at the verb, though its card fits -- sec 419",
	),
	(
		"rootlog-quorum-higher-wins",
		"chain/root_log.c",
		"\t\t\tif (ki > kb || (ki == kb && memcmp(ids[i], ids[best], FZN_ROOT_ACT_ID_LEN) < 0))\n",
		"\t\t\tif (ki < kb || (ki == kb && memcmp(ids[i], ids[best], FZN_ROOT_ACT_ID_LEN) < 0))\n",
		"with the lower k winning a race, a thief lowers the bar by setting k beside the owner -- sec 418",
	),
	(
		"rootlog-quorum-replaced-is-not-current",
		"chain/root_log.c",
		"\t\tif (replaced)\n\t\t\tcontinue;\n",
		"",
		"a replaced setting that stays current makes k impossible to lower deliberately -- sec 418",
	),
	(
		"rootlog-quorum-counts-by-set",
		"chain/root_log.c",
		"\t\tcounts[i] = !roots\n\t\t            || roots->counts(roots->ctx, r + FZN_QUORUM_SET_OFF_SETTER, ids[i]);\n",
		"\t\tcounts[i] = 1;\n",
		"a removed root's setting after its cut goes on deciding k -- sec 418",
	),
	(
		"rootlog-quorum-zero-refused",
		"chain/root_log.c",
		"\t    || bytes[1] != (uint8_t)FZN_OBJECT_QUORUM_SET || bytes[FZN_QUORUM_SET_OFF_K] == 0u)\n",
		"\t    || bytes[1] != (uint8_t)FZN_OBJECT_QUORUM_SET)\n",
		"a signed k of 0 would read as a quorum nobody can meet, or as 1 where the store reads 0 as 1 -- sec 418",
	),
	(
		"node-roots-quorum-names-what-it-replaces",
		"node/roots.c",
		"\t\tfollows = replaces;\n",
		"\t\t;\n",
		"a setting that replaces nothing is concurrent with every other, so k can never be lowered -- sec 418",
	),
	(
		"node-roots-quorum-is-logged",
		"node/roots.c",
		"\t/* LOGGED FIRST, then learned, as a root change is. */\n\terr = fzn_node_roots_log_act(roots, store, as, sign, (uint8_t)FZN_ROOT_ACT_SETTING, record,\n",
		"\t/* LOGGED FIRST, then learned, as a root change is. */\n\terr = FZN_NODE_ROOTS_OK;\n\tif (0) err = fzn_node_roots_log_act(roots, store, as, sign, (uint8_t)FZN_ROOT_ACT_SETTING, record,\n",
		"a root's setting not in its log stops counting at the root's removal whatever the cut -- sec 418",
	),
	(
		"admin-quorum-in-force-at-once",
		"node/admin.c",
		"\t\t(void)fzn_revocation_store_set_k(\n\t\t        admin->revocations,\n\t\t        fzn_node_settings_quorum(admin->settings, fzn_node_roots_quorum(admin->roots, now)));\n",
		"\t\t(void)now;\n",
		"a k set and not applied leaves the running node judging by the old one until a restart -- sec 418",
	),
	(
		"rev-ancestor-chain-from-member-root",
		"chain/revocation.c",
		"\tif (offer.hop_count && offer.hops[0].base && store->roots\n",
		"\tif (0 && offer.hop_count && offer.hops[0].base && store->roots\n",
		"a voter granted by a root other than the genesis is refused at admission everywhere -- sec 417",
	),
	(
		"rev-admin-rooted-under-cut",
		"chain/revocation.c",
		"\treturn store->roots->counts(store->roots->ctx, ad->grantor[0], ad->first_act);\n",
		"\treturn 1;\n",
		"an admin a stolen root made after its theft goes on voting after the root's removal -- sec 417",
	),
	(
		"rev-admin-first-act-hashed",
		"chain/revocation.c",
		"\t    && !hash->hash(hash->ctx, ad.first_act, sizeof(ad.first_act), hops[0].base, FZN_HOP_LEN))\n",
		"\t    && 0)\n",
		"with no hash of its first hop, an admin a removed root made before its cut falls with the rest -- sec 417",
	),
	(
		"node-admin-chain-names-this-node",
		"node/revoke.c",
		"\t    || memcmp(verdict.grantee, id->pubkey, FZN_PUBKEY_LEN) != 0\n\t    || !fzn_hop_delegable(views[hop_count - 1u]))\n\t\treturn FZN_NODE_REVOKE_NOT_ADMIN;\n",
		"\t    || !fzn_hop_delegable(views[hop_count - 1u]))\n\t\treturn FZN_NODE_REVOKE_NOT_ADMIN;\n",
		"a node installing an admin chain naming another holds a chain it cannot vote on, and believes it is an admin -- sec 416",
	),
	(
		"node-admin-chain-ends-delegable",
		"node/revoke.c",
		"\t    || memcmp(verdict.grantee, id->pubkey, FZN_PUBKEY_LEN) != 0\n\t    || !fzn_hop_delegable(views[hop_count - 1u]))\n",
		"\t    || memcmp(verdict.grantee, id->pubkey, FZN_PUBKEY_LEN) != 0)\n",
		"an undelegable admin chain is held and then refused at every vote and every grant -- sec 416",
	),
	(
		"node-admin-root-grant-is-logged",
		"node/revoke.c",
		"\t\tif (fzn_node_roots_log_act(roots, store, as, sign, (uint8_t)FZN_ROOT_ACT_GRANT, out[0],\n",
		"\t\tif (0 && fzn_node_roots_log_act(roots, store, as, sign, (uint8_t)FZN_ROOT_ACT_GRANT, out[0],\n",
		"a root's admin grant not in its log falls at the root's removal whatever the cut -- sec 416",
	),
	(
		"node-admin-grant-carries-the-chain",
		"node/revoke.c",
		"\tfor (i = 0; i < mine->hop_count; i++)\n\t\tmemcpy(out[i], mine->hops[i], FZN_HOP_LEN);\n",
		"",
		"an admin's grant handed over without the admin's own chain verifies from no root -- sec 416",
	),
	(
		"node-admin-root-confirm-is-logged",
		"node/revoke.c",
		"\t\tif (fzn_node_roots_log_act(roots, store, as, sign, (uint8_t)FZN_ROOT_ACT_GRANT, record,\n",
		"\t\tif (0 && fzn_node_roots_log_act(roots, store, as, sign, (uint8_t)FZN_ROOT_ACT_GRANT, record,\n",
		"a root's confirmation not in its log stops counting at the root's removal whatever the cut -- sec 416",
	),
	(
		"node-admin-confirm-is-saved",
		"node/revoke.c",
		"\treturn fzn_node_confirm_save(store, id->hash, record, chain);\n",
		"\treturn FZN_NODE_REVOKE_OK;\n",
		"a confirmation admitted and not saved is neither served nor remembered past a restart -- sec 416",
	),
	(
		"node-admin-vote-reloads-on-its-chain",
		"node/revoke.c",
		"\t\t\telse if (admin_self\n",
		"\t\t\telse if (0 && admin_self\n",
		"an admin's own vote not re-admitted on its chain is skipped at every restart -- sec 416",
	),
	(
		"admin-confirm-names-an-admin-grant",
		"node/admin.c",
		"\tif (memcmp(fzn_hop_capability(view), &admin->state->config.admin_capability,\n\t           sizeof(fzn_cap_id_t)) != 0)\n\t\treturn answer_text(reply, cap, FZN_REPLY_ERROR, \"not a grant of admin\");\n",
		"",
		"a confirmation of any hop fills the table with records that confirm nothing -- sec 416",
	),
	(
		"admin-root-votes-as-root",
		"node/admin.c",
		"\tif (memcmp(admin->state->config.root, admin->id->pubkey, FZN_PUBKEY_LEN) == 0)\n\t\treturn admin->authority;\n",
		"",
		"a root that votes on an admin chain counts as one admin, not as the root that acts alone -- sec 416",
	),
	(
		"rev-admin-chain-from-member-root",
		"chain/revocation.c",
		"\t    && store->roots->member(store->roots->ctx, fzn_hop_grantor(hops[0])))\n\t\troot = fzn_hop_grantor(hops[0]);\n",
		"\t    && 0)\n\t\troot = fzn_hop_grantor(hops[0]);\n",
		"an admin granted by a root other than the genesis is refused as a voter everywhere -- sec 416",
	),
	(
		"node-confirm-learned-is-saved",
		"node/revoke.c",
		"\t\tif (!save_confirm(store, hash, pull->confirm,\n",
		"\t\tif (0 && !save_confirm(store, hash, pull->confirm,\n",
		"a confirmation learned and not saved is forgotten at restart, and the admin it stood up falls with it -- sec 415",
	),
	(
		"node-confirm-reloaded-at-start",
		"node/revoke.c",
		"\t\t\tif (fzn_revocation_confirm_admit(revocations, record, sizeof(record), opened, n,\n\t\t\t                                 root, sign)\n\t\t\t    != FZN_CHAIN_OK)\n\t\t\t\treturn FZN_PERSIST_ERR_SHAPE;\n",
		"",
		"stored confirmations not admitted at start leave every confirmed admin unconfirmed after a restart -- sec 415",
	),
	(
		"node-confirm-carries-its-chain",
		"node/revoke.c",
		"\t\terr = fzn_revocation_confirm_admit(revocations, pull->confirm, FZN_ADMIN_CONFIRM_LEN,\n\t\t                                   opened, pull->hop_count, root, sign);\n",
		"\t\terr = fzn_revocation_confirm_admit(revocations, pull->confirm, FZN_ADMIN_CONFIRM_LEN,\n\t\t                                   opened, 0, root, sign);\n",
		"a confirmation admitted without its confirmer's chain is refused unless a root made it, so no admin's confirmation ever travels -- sec 415",
	),
	(
		"rev-confirm-excludes-grantor",
		"chain/revocation.c",
		"\t\t\t\t\t    || fzn_ct_memeq(cf->confirmer, ad->grantor[h], FZN_PUBKEY_LEN))\n",
		"\t\t\t\t\t    )\n",
		"an admin confirming its own grant is the one vote the confirmations exist to stop being enough -- sec 414",
	),
	(
		"rev-confirm-starts-from-nothing",
		"chain/revocation.c",
		"\t\tconfirmed[a] = ((!store->confirm_hash || need == 0u)\n\t\t                && admin_rooted(store, &store->admins[a])) ? 1u : 0u;\n",
		"\t\tconfirmed[a] = 1u;\n",
		"with every admin confirmed from the start, no grant ever waits for anybody -- sec 414",
	),
	(
		"rev-confirm-needs-a-confirmed-confirmer",
		"chain/revocation.c",
		"\t\t\t\t\tif (b >= store->admins_used || !confirmed[b]\n",
		"\t\t\t\t\tif (b >= store->admins_used\n",
		"two unconfirmed admins confirming each other stand each other up, which is one grantor's two sock puppets -- sec 414",
	),
	(
		"rev-confirm-rechecked-after-strata",
		"chain/revocation.c",
		"\tconfirm_admins(store, admin_ok, confirmed);\n",
		"",
		"a revoked admin's confirmations go on holding up the admins it confirmed -- sec 414",
	),
	(
		"rev-confirm-root-alone",
		"chain/revocation.c",
		"\treturn fzn_ct_memeq(key, first, FZN_PUBKEY_LEN);\n}\n",
		"\treturn 0;\n}\n",
		"a root that must wait for k - 1 admins has lost the full power sec 403 gave it -- sec 414",
	),
	(
		"rev-confirm-admit-needs-standing",
		"chain/revocation.c",
		"\tif (hop_count == 0u && !fzn_ct_memeq(confirmer, root, FZN_PUBKEY_LEN)\n",
		"\tif (0 && !fzn_ct_memeq(confirmer, root, FZN_PUBKEY_LEN)\n",
		"a confirmation from a key that shows no chain is taken as a root's -- sec 414",
	),
	(
		"rev-confirm-table-before-admins",
		"chain/revocation.c",
		"\tif (!store || !table || capacity == 0u || !hash || !hash->hash || store->admins_used)\n",
		"\tif (!store || !table || capacity == 0u || !hash || !hash->hash)\n",
		"admins taken before the table have no hop ids, so no confirmation can ever stand them -- sec 414",
	),
	(
		"roster-member-root-writes-alone",
		"roster/roster.c",
		"\t\t       || (authority->roots && authority->roots->member(authority->roots->ctx, writer));\n",
		"\t\t       ;\n",
		"a root the set names is refused as a writer, so an estate with several roots has one that can edit the roster -- sec 413",
	),
	(
		"roster-chain-from-member-root",
		"roster/roster.c",
		"\t                                                  fzn_hop_grantor(hops[0])))\n",
		"\t                                                  fzn_hop_grantor(hops[0])) && 0)\n",
		"a chain from a member root is verified against the genesis and refused, so nobody a second root grants can write -- sec 413",
	),
	(
		"roster-root-record-counts-by-set",
		"roster/roster.c",
		"\t\t\treturn set->counts(set->ctx, w->key, act);\n",
		"\t\t\treturn 1;\n",
		"a removed root's records after its cut go on counting, which is the theft a removal exists to undo -- sec 413",
	),
	(
		"roster-chain-first-hop-counts",
		"roster/roster.c",
		"\t\tif (!set->counts(set->ctx, w->grantor[0], w->first_act))\n\t\t\treturn 0;\n",
		"",
		"a chain from a removed root, granted after its cut, keeps its writer counting -- sec 413",
	),
	(
		"roster-set-needs-hash",
		"roster/roster.c",
		"\t    || (authority->roots && !authority->hash)\n",
		"",
		"a set with no hash names every record as the zero act, which a removed root's cut cannot tell apart -- sec 413",
	),
	(
		"roster-removal-act-by-position",
		"roster/roster.c",
		"\t\tif (!counts(w, e->remover_act[i], revocations))\n",
		"\t\tif (!counts(w, e->add_act, revocations))\n",
		"a removal judged by the add's act counts wherever the add does, so a stolen root's removal survives its cut -- sec 413",
	),
	(
		"node-roots-self-grant-needs-standing-key",
		"node/roots.c",
		"\tif (!roots->key_held || !fzn_root_view_stands(&roots->view, roots->key))\n\t\treturn FZN_NODE_ROOTS_NOT_ROOT;\n",
		"\tif (!roots->key_held)\n\t\treturn FZN_NODE_ROOTS_NOT_ROOT;\n",
		"a key no standing root added grants as a root, and its node hands out cards no device will take -- sec 411",
	),
	(
		"node-roots-self-grant-logs-once",
		"node/roots.c",
		"\tif (!logged) {\n",
		"\tif (1) {\n",
		"a grant logged at every pairing fills a log that never evicts -- sec 411",
	),
	(
		"node-roots-proof-follows-accepted-adds",
		"node/roots.c",
		"\t\tif (c->object != (uint8_t)FZN_OBJECT_ROOT_ADD || !roots->view.add_ok[i]\n",
		"\t\tif (c->object != (uint8_t)FZN_OBJECT_ROOT_ADD\n",
		"a proof through an add that no longer counts rests the card on a removed root, which the device cannot yet know -- sec 411",
	),
	(
		"node-roots-no-proof-is-refused",
		"node/roots.c",
		"\t\tif (!*count)\n\t\t\treturn FZN_NODE_ROOTS_NO_PROOF;\n",
		"",
		"a key the genesis cannot reach in three adds would be granted with no proof, and the card refused by every device -- sec 411",
	),
	(
		"node-pair-verifies-from-the-proof-end",
		"node/pair.c",
		"\t\tif (fzn_chain_verify(views, own, from, cap, now, id->sign, NULL, NULL, &verdict)\n",
		"\t\tif (fzn_chain_verify(views, own, root, cap, now, id->sign, NULL, NULL, &verdict)\n",
		"an authority from a proven root checked against the genesis refuses every pairing through a root key -- sec 411",
	),
	(
		"admin-root-key-card-is-refused-first",
		"node/admin.c",
		"\t    && fzn_root_view_stands(&admin->roots->view, admin->roots->key))\n",
		"\t    && 0)\n",
		"a pairing through a root key that the verb cannot answer is a device saved with its card lost -- sec 411",
	),
	(
		"provision-proof-starts-at-the-root",
		"provision/provision.c",
		"\t\t    || memcmp(add + FZN_ROOT_SET_OFF_SIGNER, from, FZN_PUBKEY_LEN) != 0\n",
		"",
		"a proof whose first add is by anybody makes anybody's key a root of the estate the device pins -- sec 410",
	),
	(
		"provision-proof-add-is-signed",
		"provision/provision.c",
		"\t\t    || !verifier->verify(verifier->ctx, add + FZN_ROOT_SET_OFF_SIGNER, add,\n"
		"\t\t                         FZN_ROOT_ADD_BODY_LEN, add + FZN_ROOT_ADD_BODY_LEN))\n",
		"\t\t    )\n",
		"an unsigned add names the root as adder and proves nothing about it -- sec 410",
	),
	(
		"provision-proof-is-a-root-add",
		"provision/provision.c",
		"\t\t    || add[1] != (uint8_t)FZN_OBJECT_ROOT_ADD\n",
		"",
		"a root-remove carries its signer and subject where an add does, so without the tag a removal proves the removed key a root -- sec 410",
	),
	(
		"provision-proof-advances",
		"provision/provision.c",
		"\t\tfrom = add + FZN_ROOT_SET_OFF_SUBJECT;\n",
		"",
		"a walk that does not move to the added root checks every add against the genesis and the chain against it too, so no proof ever reaches another root -- sec 410",
	),
	(
		"node-accept-chain-from-proof-end",
		"node/provision.c",
		"\t\tchain_root = card.proof + (card.proof_count - 1u) * FZN_PROVISION_PROOF_ITEM_LEN\n"
		"\t\t             + FZN_ROOT_SET_OFF_SUBJECT;\n",
		"\t\t;\n",
		"a device that verifies the chain under the genesis refuses every card a proven root makes -- sec 410",
	),
	(
		"node-pairing-saves-the-proof",
		"node/pair.c",
		"\t\tif (fzn_node_roots_save(store, device->hash,\n",
		"\t\tif (0 && fzn_node_roots_save(store, device->hash,\n",
		"a pairing kept without the adds its chain starts from is refused by the node's own roots when they load -- sec 410",
	),
	(
		"provision-chain-is-unbroken",
		"provision/provision.c",
		"\t\t    || memcmp(fzn_hop_grantee(hop), fzn_hop_grantor(next), FZN_PUBKEY_LEN) != 0)\n",
		"\t\t    )\n",
		"a chain whose hops do not link lets anybody holding one genuine hop append their own grant and seal the card as its sponsor -- sec 391",
	),
	(
		"provision-sponsor-holds-the-prekey",
		"provision/provision.c",
		"\t    || memcmp(prekey.host, sponsor, FZN_PUBKEY_LEN) != 0)\n",
		"\t    )\n",
		"a sponsor-sealed card carrying another host's prekey sends the device's session to that host -- sec 391",
	),
	(
		"persist-route-core-is-core",
		"persist/persist.c",
		"\treturn fzn_persist_slot_is_core(slot) ? route->core : route->store;\n",
		"\treturn fzn_persist_slot_is_core(slot) ? route->store : route->core;\n",
		"a route with its directions swapped puts the identity and the revocations in the directory meant for what can be lost -- sec 392",
	),
	(
		"persist-unnamed-slot-is-core",
		"persist/persist.c",
		"\t\treturn 1;\t/* named or not: see persist.h */\n",
		"\t\treturn 0;\n",
		"a slot added without a decision about it would land where losing it costs availability, when it might be what keeps an attacker out -- sec 392",
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
		"rev-drain-chained-reissue",
		"chain/revocation.c",
		"\t\t\tmemcpy(entry->id, id, FZN_REVOCATION_ID_LEN);\n"
		"\t\t\tmemcpy(entry->held, id, FZN_REVOCATION_ID_LEN);\n"
		"\t\t\tmemcpy(entry->cut, fzn_revocation_cut(record), FZN_REVOCATION_ID_LEN);\n"
		"\t\t\tfzn_manifest_satisfy(manifest, fzn_revocation_issuer(record),\n"
		"\t\t\t                     fzn_revocation_capability(record),\n"
		"\t\t\t                     fzn_revocation_grantee(record));\n",
		"\t\t\tmemcpy(entry->id, id, FZN_REVOCATION_ID_LEN);\n"
		"\t\t\tmemcpy(entry->held, id, FZN_REVOCATION_ID_LEN);\n"
		"\t\t\tmemcpy(entry->cut, fzn_revocation_cut(record), FZN_REVOCATION_ID_LEN);\n",
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
		"\t\t    fzn_ct_memeq(fzn_revocation_supersedes(record), entry->id,\n",
		"\t\tif (0 && !fzn_ct_memeq(id, entry->id, FZN_REVOCATION_ID_LEN) &&\n"
		"\t\t    fzn_ct_memeq(fzn_revocation_supersedes(record), entry->id,\n",
		"a store that does not advance to the current revocation applies a "
		"withdrawal of the superseded one, which un-revokes a revoked pair",
	),
	(
		"rev-withdrawal-tombstone",
		"chain/revocation.c",
		"\t\t\tstore->entries[store->used].withdrawn = 1;\n"
		"\t\t\tstore->entries[store->used].epoch = fzn_revocation_epoch(record);\n"
		"\t\t\tmemcpy(store->entries[store->used].held, id, FZN_REVOCATION_ID_LEN);\n"
		"\t\t\t/* A tombstone undid a vote this host never saw, so it\n"
		"\t\t\t * keeps no line of that vote's. */\n"
		"\t\t\tmemset(store->entries[store->used].cut, 0, FZN_REVOCATION_ID_LEN);\n"
		"\t\t\tstore->used++;\n"
		"\t\t\tstore->generation++;\n\t\t\treturn FZN_CHAIN_OK;\n",
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
		"\t\t\t\tif (fzn_ct_memeq(fzn_revocation_supersedes(record),\n"
		"\t\t\t\t                 NAMES_NOTHING, FZN_REVOCATION_ID_LEN))",
		"\t\t\t\tif (fzn_ct_memeq(fzn_revocation_supersedes(record),\n"
		"\t\t\t\t                 NAMES_NOTHING, FZN_REVOCATION_ID_LEN - 1u))",
		"the whole-id read, moved in sec 359 onto the compare that now decides. "
		"A re-revocation over a withdrawal must NAME a predecessor, and a "
		"supersedes that is zero in every byte but its last names one. A "
		"prefix compare calls it nothing, refuses the record and drains the "
		"deficit -- the host stays unrevoked and stops asking. sec 326 put "
		"this on the exact-id compare; sec 359 removed that compare and the "
		"property came with it. sec 359",
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
		"FZN_ORIGIN_REMOTE, hops, peer->hop_count, now,\n",
		"FZN_ORIGIN_SAME_USER, hops, peer->hop_count, now,\n",
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
	(
		"group-add-draws-a-fresh-id",
		"contact/group.c",
		"\t    || fzn_group_get(store, g.id, &other) != FZN_CONTACT_ERR_ABSENT)\n",
		")\n",
		"a group is filed over another whose id was drawn again, and inherits its shares -- sec 516",
	),
	(
		"group-join-once",
		"contact/group.c",
		"\t\tif (memcmp(g.members[i], key, FZN_PUBKEY_LEN) == 0)\n\t\t\treturn FZN_CONTACT_OK;\n",
		"",
		"a contact joined twice is two members, and leaving once leaves it in -- sec 471",
	),
	(
		"group-leave-removes",
		"contact/group.c",
		"\t\t\tg.count--;\n",
		"",
		"a member who leaves is still served what the group was shared -- sec 471",
	),
	(
		"group-ids-of-members-only",
		"contact/group.c",
		"\t\t\tif (memcmp(all[i].members[j], key, FZN_PUBKEY_LEN) == 0) {\n",
		"\t\t\tif (1) {\n",
		"a contact in no group is served every group's shares -- sec 471",
	),
	(
		"group-scope-reads-membership",
		"node/notes.c",
		"\tif (fzn_group_ids_of(n->store.ops, sender, groups, FZN_GROUPS_MAX, &n_groups)\n\t    == FZN_CONTACT_OK)\n",
		"\tif (0)\n",
		"a subtree shared with a group reaches none of its members -- sec 471",
	),
	(
		"group-unshare-by-id",
		"node/notes.c",
		"\tif (!add && name_len == ID_HEX && parse_id(name, name_len, contact.key)) {\n",
		"\tif (0) {\n",
		"a share with a group since removed can never be taken away -- sec 516",
	),
	(
		"group-share-listed-by-name",
		"node/notes.c",
		"\t\t} else if (fzn_group_get(n->store.ops, all[i].contact, &group) == FZN_CONTACT_OK) {\n",
		"\t\t} else if (0 && fzn_group_get(n->store.ops, all[i].contact, &group) == FZN_CONTACT_OK) {\n",
		"a group's share lists as a bare key, and a person cannot tell it from a forgotten contact -- sec 471",
	),
	(
		"admin-group-own-user",
		"node/admin.c",
		"\t\tif (origin != FZN_ORIGIN_SAME_USER)\n\t\t\treturn answer_text(reply, reply_cap, FZN_REPLY_DENIED,\n\t\t\t                   \"groups need this node's own user\");\n",
		"",
		"another user on the machine edits who this user's shares reach -- sec 471",
	),
	(
		"purge-release-waits-the-age",
		"notes/purge.c",
		"\t\tif (now_ms - p.queued_at_ms <= age_ms)\n\t\t\tcontinue;\n",
		"",
		"a purge is released from a host the moment it is queued, before anyone could answer -- sec 472",
	),
	(
		"purge-release-spares-the-heard",
		"notes/purge.c",
		"\t\t\tif (!p.answered[j] && !heard(heard_ctx, p.asked[j], now_ms)) {\n",
		"\t\t\tif (!p.answered[j]) {\n",
		"a host still in touch is released and the note erased under it unasked -- sec 472",
	),
	(
		"purge-release-clamps-the-future",
		"notes/purge.c",
		"\t\tif (p.queued_at_ms > now_ms) {\n",
		"\t\tif (0) {\n",
		"a purge queued while the clock read ahead underflows its age and releases every host at once -- sec 472",
	),
	(
		"purge-release-finishes",
		"notes/purge.c",
		"\t\tif (done == p.asked_count) {\n\t\t\terr = fzn_notes_purge_finish(store, p.id);\n",
		"\t\tif (0) {\n\t\t\terr = fzn_notes_purge_finish(store, p.id);\n",
		"a purge every host is released from is never finished, and the trash never empties -- sec 472",
	),
	(
		"node-release-reads-partners",
		"node/notes.c",
		"\treturn now_ms <= seen || now_ms - seen <= FZN_NODE_NOTES_PARTNER_AGE_MS;\n",
		"\treturn 0;\n",
		"a partner that pulled yesterday is released from a month-old purge it was about to answer -- sec 472",
	),
	(
		"node-empty-trash-releases-first",
		"node/notes.c",
		"\t\tif (!fzn_node_notes_release_purges(n, &released, &finished))\n\t\t\treturn say(reply, cap, FZN_REPLY_ERROR, \"the purges would not read\");\n",
		"",
		"emptying the trash leaves a purge pinned to a node gone a month, waiting until the next round -- sec 472",
	),
	(
		"pack-hash-nonzero-is-success",
		"log/pack.c",
		"\treturn hash->hash(hash->ctx, state, FZN_LOG_PACK_HASH_LEN, fold, FZN_LOG_PACK_HASH_LEN + n)\n\t       != 0;\n",
		"\treturn hash->hash(hash->ctx, state, FZN_LOG_PACK_HASH_LEN, fold, FZN_LOG_PACK_HASH_LEN + n)\n\t       == 0;\n",
		"every real hash refuses the first chunk and fuzznetd never packs a segment -- sec 473",
	),
	(
		"retain-segment-plan-skips-entry-rules",
		"log/retain.c",
		"\t\t\t\tif (!matches(rule, program) || fzn_retain_rule_selects_entries(rule))\n",
		"\t\t\t\tif (!matches(rule, program))\n",
		"a rule for debug lines removes whole segments, info and errors with them -- sec 474",
	),
	(
		"retain-walk-selects-levels",
		"log/retain.c",
		"\t\tif (rule->levels && ((unsigned)level > 8u || !(rule->levels & (1u << (unsigned)level))))\n\t\t\tcontinue;\n",
		"",
		"a rule for debug lines prunes info and errors too -- sec 474",
	),
	(
		"retain-walk-subsystem-boundary",
		"log/retain.c",
		"\treturn strncmp(path, prefix, n) == 0 && (path[n] == '\\0' || path[n] == '/');\n",
		"\treturn strncmp(path, prefix, n) == 0;\n",
		"a rule for subsystem notes reaches notesx, a subsystem nobody named -- sec 474",
	),
	(
		"retain-walk-counts-newest-first",
		"log/retain.c",
		"\t\twalk->seen[r]++;\n",
		"",
		"a count over entries never counts, so 'keep the newest 100' keeps every entry and 'prune past 2' prunes none -- sec 474",
	),
	(
		"retain-walk-keep-expands",
		"log/retain.c",
		"\t\tif (in) {\n\t\t\tif (rule->kind == FZN_RETAIN_KEEP)\n\t\t\t\tkept = 1;\n",
		"\t\tif (in) {\n\t\t\tif (0)\n\t\t\t\tkept = 1;\n",
		"an entry keep rule protects nothing: 'keep errors 90 days' loses them with their segment -- sec 474",
	),
	(
		"pack-retain-carries-was",
		"log/pack.c",
		"\tmemcpy(tr.was, carried(old), FZN_LOG_PACK_HASH_LEN);\n",
		"\tmemcpy(tr.was, tr.hash, FZN_LOG_PACK_HASH_LEN);\n",
		"a repacked segment names a hash nobody chained from, and the next segment's prev no longer verifies -- sec 474",
	),
	(
		"pack-retain-verifies-before-repack",
		"log/pack.c",
		"\t\t\t           && memcmp(check, tr.hash, FZN_LOG_PACK_HASH_LEN) == 0;\n",
		"\t\t\t           ;\n",
		"a packed segment that does not verify is repacked under a fresh valid trailer, laundering whatever changed it -- sec 474",
	),
	(
		"pack-retain-headers-go-with-the-whole",
		"log/pack.c",
		"\t\tif (line[0] == '#')\n\t\t\tcontinue;\n\t\tif (fzn_entry_classic_parse",
		"\t\tif (fzn_entry_classic_parse",
		"a segment's header is judged as an entry, dropped with the rest, and a repacked segment no longer says whose log it is -- sec 474",
	),
	(
		"pack-retain-plain-waits",
		"log/pack.c",
		"\t\t} else if (readable && dropped && segs[i].packed) {\n",
		"\t\t} else if (readable && dropped) {\n",
		"a segment not yet packed is packed under a version-2 trailer out of turn, chaining from a prev it never had -- sec 474",
	),
	(
		"pack-trailer-v2-carried",
		"log/pack.c",
		"\treturn t->repacked ? t->was : t->hash;\n",
		"\treturn t->hash;\n",
		"a reader carries a repacked segment's new hash, and every segment after it stops verifying -- sec 474",
	),
	(
		"log-rules-filed-by-text",
		"log/rules.c",
		"\tif (!hash->hash(hash->ctx, subject, FZN_PUBKEY_LEN, in, sizeof(LABEL) + *len))\n",
		"\tif (!hash->hash(hash->ctx, subject, FZN_PUBKEY_LEN, in, sizeof(LABEL)))\n",
		"every rule is filed under one subject, so a second rule is refused as the first -- sec 475",
	),
	(
		"log-rules-held-once",
		"log/rules.c",
		"\tif (err == FZN_LOG_RULES_OK)\n\t\treturn FZN_LOG_RULES_ERR_TAKEN;\n",
		"",
		"adding a held rule again reports success, and the user is never told it was already in force -- sec 475",
	),
	(
		"log-rules-bounded",
		"log/rules.c",
		"\tif (count >= FZN_LOG_RULES_MAX)\n\t\treturn FZN_LOG_RULES_ERR_FULL;\n",
		"",
		"rules grow past what a list returns, and then the writer cannot read any of them -- sec 475",
	),
	(
		"log-rules-shape-refuses",
		"log/rules.c",
		"\t\tif (err != FZN_LOG_RULES_OK)\n\t\t\treturn err == FZN_LOG_RULES_ERR_ABSENT ? FZN_LOG_RULES_ERR_SHAPE : err;\n",
		"\t\tif (err != FZN_LOG_RULES_OK)\n\t\t\tcontinue;\n",
		"a held rule that will not read is silently dropped, and logs are kept or pruned against the user's word -- sec 475",
	),
	(
		"log-rules-hash-nonzero-is-success",
		"log/rules.c",
		"\tif (!hash->hash(hash->ctx, subject, FZN_PUBKEY_LEN, in, sizeof(LABEL) + *len))\n",
		"\tif (hash->hash(hash->ctx, subject, FZN_PUBKEY_LEN, in, sizeof(LABEL) + *len) != 0)\n",
		"every real hash refuses, and no rule can be kept -- sec 475",
	),
	(
		"admin-retention-own-user",
		"node/admin.c",
		"\t\t\tif (origin != FZN_ORIGIN_SAME_USER)\n\t\t\t\treturn answer_text(reply, reply_cap, FZN_REPLY_DENIED,\n\t\t\t\t                   \"retention rules need this node's own user\");\n",
		"",
		"another user on the machine prunes this user's logs -- sec 475",
	),
	(
		"admin-retention-one-word",
		"node/admin.c",
		"\t\t\tif (c < 0x21u || c == '%' || c == ',' || c == 0x7fu) {\n",
		"\t\t\tif (c == '%' || c == ',' || c == 0x7fu) {\n",
		"a listed rule spills over several words, and a client reads each word as a rule -- sec 475",
	),
	(
		"retain-text-largest-unit",
		"log/retain.c",
		"\t\t\tif (v % AGE[i].us == 0u) {\n\t\t\t\tv /= AGE[i].us;\n\t\t\t\tunit[0] = AGE[i].u;\n\t\t\t\tbreak;\n",
		"\t\t\tif (v % AGE[i].us == 0u) {\n\t\t\t\tv /= AGE[i].us;\n\t\t\t\tunit[0] = AGE[i].u;\n",
		"an age is divided by every unit in turn, and 'age 30d' is written as a different number -- sec 475",
	),
	(
		"retention-removal-names-a-rule",
		"chain/root_log.c",
		"\tif (n < 0\n\t    || (n == 0\n\t        && memcmp(bytes + FZN_RETENTION_SET_OFF_REPLACES, ZERO, FZN_ROOT_ACT_ID_LEN) == 0))\n",
		"\tif (n < 0)\n",
		"a record with no text replacing nothing is taken, a removal of nothing -- sec 476",
	),
	(
		"retention-padding-is-zero",
		"chain/root_log.c",
		"\tfor (i = n; i < FZN_RETENTION_SET_TEXT_MAX; i++)\n\t\tif (field[i] != 0u)\n\t\t\treturn -1;\n",
		"",
		"bytes after a rule's text are taken and signed, a channel no reader looks at -- sec 476",
	),
	(
		"retention-replaced-is-not-current",
		"chain/root_log.c",
		"\t\tcurrent[i] = (uint8_t)!replaced;\n",
		"\t\tcurrent[i] = 1u;\n",
		"a rule removed or changed by a root still applies on every host -- sec 476",
	),
	(
		"retention-counts-under-the-set",
		"chain/root_log.c",
		"\t\tif (!counts[i] || retention_text_len(records + (i * FZN_RETENTION_SET_LEN)\n",
		"\t\tif (retention_text_len(records + (i * FZN_RETENTION_SET_LEN)\n",
		"a removed root's rule, or one by a key that was never a root, prunes the estate's logs -- sec 476",
	),
	(
		"node-retention-held-once",
		"node/roots.c",
		"\tif (add && g.found)\n\t\treturn FZN_NODE_ROOTS_HELD;\n\tif (!add && !g.found)\n\t\treturn FZN_NODE_ROOTS_REFUSED;\n\tif (roots->retention_used >= FZN_NODE_ROOT_RETENTION_MAX)\n",
		"\tif (!add && !g.found)\n\t\treturn FZN_NODE_ROOTS_REFUSED;\n\tif (roots->retention_used >= FZN_NODE_ROOT_RETENTION_MAX)\n",
		"a rule already the estate's is minted and logged again, spending the root's records on nothing -- sec 476",
	),
	(
		"node-retention-removal-names-its-record",
		"node/roots.c",
		"\tif (!add && !g.found)\n\t\treturn FZN_NODE_ROOTS_REFUSED;\n\tif (roots->retention_used >= FZN_NODE_ROOT_RETENTION_MAX)\n",
		"\tif (roots->retention_used >= FZN_NODE_ROOT_RETENTION_MAX)\n",
		"removing a rule the estate does not have mints a record replacing nothing it can name -- sec 476",
	),
	(
		"node-retention-passed-over-is-counted",
		"node/roots.c",
		"\t*unread = g.unread + (g.count - *count);\n",
		"\t*unread = 0;\n",
		"an estate rule this build cannot read is dropped unseen, and the log kept against the estate's word -- sec 476",
	),
	(
		"node-retention-travels",
		"node/roots.c",
		"\tcase FZN_OBJECT_RETENTION_SET:\n\t\treturn (uint8_t)FZN_PERSIST_BLOB_RETENTION_SET;\n",
		"",
		"an estate rule is neither kept nor carried, and stays on the root that set it -- sec 476",
	),
	(
		"retain-walk-selects-text",
		"log/retain.c",
		"\t\tif (rule->match_len && !holds(text, text_len, rule->match, rule->match_len))\n\t\t\tcontinue;\n",
		"",
		"a rule for lines holding some text prunes every line -- sec 477",
	),
	(
		"retain-text-match-has-no-nul",
		"log/retain.c",
		"\t\t\tif (v == 0u)\n\t\t\t\treturn 0;\n",
		"",
		"a match holding a NUL is taken, and no reader can tell where it ends -- sec 477",
	),
	(
		"retain-text-match-is-escaped",
		"log/retain.c",
		"\t\t} else if (c < 0x21u || c == ',' || c == 0x7fu) {\n\t\t\treturn 0;\n",
		"\t\t} else if (0) {\n\t\t\treturn 0;\n",
		"a match with a bare comma is taken, and the same match has two spellings -- sec 477",
	),
	(
		"admin-group-removal-takes-shares",
		"node/admin.c",
		"\t\t    || fzn_notes_share_forget(&notes, group.id, &gone) != FZN_NOTES_OK\n",
		"\t\t    || 0\n",
		"a group made again under a removed one's name inherits its shares, serving them to whoever is in the new group -- sec 478",
	),
	(
		"notes-share-forget-names-its-contact",
		"notes/share.c",
		"\t\tif (!fzn_ct_memeq(all[i].contact, contact, FZN_PUBKEY_LEN))\n\t\t\tcontinue;\n\t\terr = fzn_notes_share_remove(store, all[i].subtree, contact);\n",
		"\t\terr = fzn_notes_share_remove(store, all[i].subtree, all[i].contact);\n",
		"removing one group unshares everything with everyone -- sec 478",
	),
	(
		"roots-retention-judges-admins",
		"node/roots.c",
		"\t       || (roots->revocations && fzn_revocation_admin_stands(roots->revocations, setter));\n",
		"\t       ;\n",
		"an admin's retention rule never counts, so the holder's 'admin (and root)' is root alone -- sec 479",
	),
	(
		"revocation-admin-stands-reads-the-strata",
		"chain/revocation.c",
		"\tstanding_admins(store, admin_ok);\n\treturn admin_ok[a] != 0u;\n",
		"\treturn 1;\n",
		"a revoked admin's rules go on pruning the estate's logs -- sec 479",
	),
	(
		"roots-admin-retention-admits-the-chain",
		"node/roots.c",
		"\tif (fzn_revocation_admin_admit(roots->revocations, record + FZN_RETENTION_SET_OFF_SETTER,\n\t                               opened, hop_count, root, roots->sign)\n\t    != FZN_CHAIN_OK)\n\t\treturn FZN_NODE_ROOTS_REFUSED;\n",
		"",
		"a rule signed by anybody, on anybody's admin chain, is taken as an admin's -- sec 479",
	),
	(
		"roots-admin-retention-stands-to-set",
		"node/roots.c",
		"\tif (!fzn_revocation_admin_stands(roots->revocations, identity)) {\n",
		"\tif (0) {\n",
		"a revoked admin mints and keeps rules nobody else will count -- sec 479",
	),
	(
		"roots-retention-readd-follows-removal",
		"node/roots.c",
		"\tif (add && follows_removal(roots, text, len, g.id))\n\t\tfollows = g.id;\n",
		"",
		"a rule removed and added again mints the record its removal already replaced, and is not added -- sec 479",
	),
	(
		"retain-scope-host-reaches-its-node",
		"log/retain.c",
		"\tif (rule->has_host && (!host || memcmp(rule->host, host, sizeof(rule->host)) != 0))\n\t\treturn 0;\n",
		"",
		"a rule an admin scoped to one host prunes every host's logs -- sec 480",
	),
	(
		"retain-scope-machine-reaches-its-machine",
		"log/retain.c",
		"\tif (rule->has_machine\n\t    && (!machine || memcmp(rule->machine, machine, sizeof(rule->machine)) != 0))\n\t\treturn 0;\n",
		"",
		"a rule scoped to one machine prunes every machine's logs -- sec 480",
	),
	(
		"retain-scope-hex-one-spelling",
		"log/retain.c",
		"\t\telse if (c >= 'a' && c <= 'f')\n\t\t\tv = (unsigned)(c - 'a' + 10);\n\t\telse\n\t\t\treturn 0;\n",
		"\t\telse if (c >= 'a' && c <= 'f')\n\t\t\tv = (unsigned)(c - 'a' + 10);\n\t\telse if (c >= 'A' && c <= 'F')\n\t\t\tv = (unsigned)(c - 'A' + 10);\n\t\telse\n\t\t\treturn 0;\n",
		"one scope has two spellings, and the same rule is kept twice -- sec 480",
	),
	(
		"revocation-epoch-skips-unstanding-admins",
		"chain/revocation.c",
		"\t\t\tif (a < store->admins_used && !h->admin_ok[a])\n\t\t\t\treturn 0;\n",
		"",
		"admins nobody confirmed close the epoch standing admins vote in, and a stolen key is never revoked -- sec 481",
	),
	(
		"revocation-epoch-knows-who-stands",
		"chain/revocation.c",
		"\t\tstanding_admins(store, admin_ok);\n\t\th.admin_ok = admin_ok;\n",
		"\t\tstanding_admins(store, admin_ok);\n",
		"the epoch is numbered by every admin's votes, standing or not -- sec 481",
	),
	(
		"pack-signature-checked",
		"log/pack.c",
		"\tif (!signature_holds(&tr, sign))\n\t\treturn FZN_LOG_PACK_ERR_SIGNATURE;\n",
		"",
		"a signed trailer whose signature was changed reads as signed, and signing proves nothing -- sec 482",
	),
	(
		"pack-signature-covers-the-line",
		"log/pack.c",
		"\tmemcpy(msg + sizeof(SIG_LABEL), base, n);\n\tif (!signer->sign->sign(signer->sign->ctx, sig, msg, sizeof(SIG_LABEL) + n))\n",
		"\tmemcpy(msg + sizeof(SIG_LABEL), base, n);\n\tif (!signer->sign->sign(signer->sign->ctx, sig, msg, sizeof(SIG_LABEL)))\n",
		"a signature over the label alone fits every trailer, and any can be moved onto any other -- sec 482",
	),
	(
		"pack-signed-when-a-signer-is-given",
		"log/pack.c",
		"\tif (signer) {\n\t\tif (!sign_line(signer, trailer, (size_t)k, trailer + k)) {\n",
		"\tif (0) {\n\t\tif (!sign_line(signer, trailer, (size_t)k, trailer + k)) {\n",
		"a node with a key packs its log unsigned, and nothing later can tell its trailers from a forger's -- sec 482",
	),
	(
		"pack-check-counts-other-signers",
		"log/pack.c",
		"\t\t\tif (report->signed_count && memcmp(key, report->signer, sizeof(key)) != 0)\n\t\t\t\treport->signers_differ = 1;\n",
		"",
		"a segment signed by another key reads as this node's -- sec 482",
	),
	(
		"retain-copy-rules-are-whole",
		"log/retain.c",
		"\tif (out->copy && (out->levels || out->subsystem[0] || out->match_len))\n\t\treturn FZN_RETAIN_ERR_MALFORMED;\n",
		"",
		"a copy rule thins a copy, which then holds neither the source's bytes nor its signature -- sec 483",
	),
	(
		"retain-own-log-skips-copy-rules",
		"log/retain.c",
		"\t\tif (in[i].data == FZN_RETAIN_LOG && !in[i].copy && !in[i].archived\n",
		"\t\tif (in[i].data == FZN_RETAIN_LOG && !in[i].archived\n",
		"a rule written for copies prunes this node's own log -- sec 483",
	),
	(
		"notes-full-purge-queue-said-as-one",
		"node/notes.c",
		"\tif (err == FZN_NOTES_ERR_FULL)\n\t\treturn say(reply, cap, FZN_REPLY_ERROR,\n",
		"\tif (0)\n\t\treturn say(reply, cap, FZN_REPLY_ERROR,\n",
		"a person emptying the trash is told there is no room for another note -- sec 484",
	),
	(
		"retention-view-unescapes-the-listing",
		"gui/retention_view.cpp",
		"\t\t\tif (ok) {\n\t\t\t\tout.append((char)v);\n\t\t\t\ti += 2;\n\t\t\t\tcontinue;\n\t\t\t}\n",
		"\t\t\tif (0) {\n\t\t\t\tout.append((char)v);\n\t\t\t\ti += 2;\n\t\t\t\tcontinue;\n\t\t\t}\n",
		"a rule is shown escaped twice, and removing it by its row names a rule the node does not hold -- sec 485",
	),
	(
		"retention-view-says-no-answer",
		"gui/retention_view.cpp",
		"\tlist->clear();\n\tif (r < 0) {\n\t\tstatus->setText(QStringLiteral(\"The node did not answer.\"));\n\t\treturn false;\n\t}\n",
		"\tlist->clear();\n",
		"a node that does not answer is shown as one with no rules -- sec 485",
	),
	(
		"retention-view-removes-the-row-selected",
		"gui/retention_view.cpp",
		"\tif (rule.isEmpty() && list->currentItem())\n\t\trule = list->currentItem()->text();\n",
		"",
		"a selected rule cannot be removed without typing it again -- sec 485",
	),
	(
		"revocation-a-cut-binds-every-vote",
		"chain/revocation.c",
		"\t\tbinding++;\n\t\tif (all_zero(entry->cut",
		"\t\tif (binding++ > 0u)\n\t\t\tcontinue;\n\t\tif (all_zero(entry->cut",
		"one vote's line read alone lets the widest cut win, so a thief's acts after a careful voter's line count on a careless one's -- sec 496",
	),
	(
		"revocation-a-withdrawal-draws-no-line",
		"chain/revocation.c",
		"\tif (bytes[FZN_REV_OFF_OBJECT] == (uint8_t)FZN_OBJECT_WITHDRAWAL &&\n\t    !all_zero(bytes + FZN_REV_OFF_CUT, FZN_REVOCATION_ID_LEN))\n\t\treturn FZN_CHAIN_ERR_SHAPE;\n",
		"",
		"a withdrawal carrying a cut is a second meaning for one field that nothing reads -- sec 496",
	),
	(
		"revocation-an-entry-keeps-its-cut",
		"chain/revocation.c",
		"\tmemcpy(store->entries[store->used].cut, fzn_revocation_cut(record), FZN_REVOCATION_ID_LEN);\n\tstore->used++;\n\t/* An answer",
		"\tstore->used++;\n\t/* An answer",
		"a store that drops a vote's cut keeps nothing a revoked key did, which is the revocation sec 496 replaced -- sec 496",
	),
	(
		"revocation-a-reissue-moves-the-line",
		"chain/revocation.c",
		"\t\t\tif (!fzn_ct_memeq(entry->cut, fzn_revocation_cut(record),\n",
		"\t\t\tif (0 && !fzn_ct_memeq(entry->cut, fzn_revocation_cut(record),\n",
		"a voter who learns more about a theft cannot say so without undoing its vote first -- sec 496",
	),
	(
		"revocation-a-free-hop-stands",
		"chain/revocation.c",
		"\tif (verdict == HOP_FREE)\n\t\treturn 1;\n",
		"",
		"an act of a key nobody revoked asked about a cut nobody drew stops counting -- sec 496",
	),
	(
		"roster-a-revoked-hop-asks-the-next-act",
		"roster/roster.c",
		"i + 1u < w->hop_count ? w->hop_act[i + 1u] : act))",
		"act))",
		"asking a revoked grantor's log about a record it never wrote drops every device it granted before the line -- sec 496",
	),
	(
		"roster-hashes-every-hop",
		"roster/roster.c",
		"\tfor (i = 0; hash && i < hop_count; i++)\n\t\tif (!hash->hash(hash->ctx, w.hop_act[i]",
		"\tfor (i = 0; hash && i < 1u && i < hop_count; i++)\n\t\tif (!hash->hash(hash->ctx, w.hop_act[i]",
		"a hop with no act cannot be found in its grantor's log, so a device granted before the cut falls -- sec 496",
	),
	(
		"roster-a-hash-needs-no-set",
		"roster/roster.c",
		"\t    || (authority->roots && !authority->hash)\n",
		"\t    || (!authority->roots != !authority->hash)\n",
		"a roster that names no acts without a root set keeps nothing of a revoked member's in a one-root estate -- sec 496",
	),
	(
		"node-roots-logs-the-identitys-acts",
		"node/roots.c",
		"\tif (identity && identity_sign && fzn_ct_memeq(signer, identity, FZN_PUBKEY_LEN))\n\t\treturn fzn_node_roots_log_act(",
		"\tif (identity && identity_sign && fzn_ct_memeq(signer, identity, FZN_PUBKEY_LEN))\n\t\treturn FZN_NODE_ROOTS_OK;\n\tif (0)\n\t\treturn fzn_node_roots_log_act(",
		"a member's act never logged falls at the member's revocation whatever the line, so every contact it added goes with the thief's -- sec 497",
	),
	(
		"node-roots-attach-sets-the-act-log",
		"node/roots.c",
		"\t               && fzn_revocation_store_set_acts(revocations,\n\t                                                roots->journal ? &roots->acts : NULL)",
		"\t               && fzn_revocation_store_set_acts(revocations, NULL)",
		"a node's store with no act log keeps nothing of a revoked member's, whatever its vote's line -- sec 497",
	),
	(
		"node-roster-hash-always",
		"node/roster.c",
		"\tnr->authority.hash = hash;\n",
		"\tnr->authority.hash = roots ? hash : NULL;\n",
		"a one-root estate's roster names no acts, so a revoked member's contacts fall at any line -- sec 497",
	),
	(
		"node-revoke-moves-the-line",
		"node/revoke.c",
		"\t\t\tif (!move\n",
		"\t\t\tif (1\n",
		"an owner who learns when a device was taken cannot move the line without undoing the vote first -- sec 497",
	),
	(
		"node-admin-no-cut-keeps-the-line",
		"node/admin.c",
		"\tif (!named && fzn_node_issued_revocation(admin->store, grantee, held)\n",
		"\tif (0 && !named && fzn_node_issued_revocation(admin->store, grantee, held)\n",
		"asking again with no cut widens the line to whatever a thief has logged since -- sec 497",
	),
	(
		"node-admin-logs-the-grant",
		"node/admin.c",
		"\tif (!log_grant(admin, record.host))\n",
		"\tif (0)\n",
		"a device a member paired falls at the member's revocation whatever the line, its grant never logged -- sec 497",
	),
	(
		"node-admin-grant-logged-as-admin",
		"node/revoke.c",
		"\t/* LOGGED AS AN ADMIN TOO, sec 497, as a root's grant is above. */\n\tif (roots\n",
		"\t/* LOGGED AS AN ADMIN TOO, sec 497, as a root's grant is above. */\n\tif (0\n",
		"an admin's grant never logged falls at the admin's revocation, so every admin it made goes too -- sec 497",
	),
	(
		"node-admin-confirm-logged-as-admin",
		"node/revoke.c",
		"\t\t * admin's line keeps counting after it is revoked. */\n\t\tif (roots\n",
		"\t\t * admin's line keeps counting after it is revoked. */\n\t\tif (0\n",
		"an admin's confirmation never logged falls at the admin's revocation whatever the line -- sec 497",
	),
	(
		"succession-a-key-is-not-its-own-successor",
		"chain/succession.c",
		"\tif (fzn_ct_memeq(bytes + FZN_SUCCESSION_OFF_OLD, bytes + FZN_SUCCESSION_OFF_NEW,\n\t                 FZN_PUBKEY_LEN))\n\t\treturn FZN_CHAIN_ERR_SHAPE;\n",
		"",
		"a key succeeded by itself moves no reference and is a cycle of one -- sec 498",
	),
	(
		"succession-a-chainless-issuer-is-a-root",
		"chain/succession.c",
		"\tif (hop_count == 0u && !fzn_ct_memeq(issuer, root, FZN_PUBKEY_LEN)\n",
		"\tif (0 && hop_count == 0u && !fzn_ct_memeq(issuer, root, FZN_PUBKEY_LEN)\n",
		"a stranger's succession admitted with no chain would move a device's references to a key of its choosing -- sec 498",
	),
	(
		"succession-the-issuer-signed-it",
		"chain/succession.c",
		"\tif (!sign->verify(sign->ctx, issuer, bytes, FZN_SUCCESSION_BODY_LEN,\n",
		"\tif (0 && !sign->verify(sign->ctx, issuer, bytes, FZN_SUCCESSION_BODY_LEN,\n",
		"a succession nobody signed is one any carrier can invent -- sec 498",
	),
	(
		"succession-kept-once",
		"chain/succession.c",
		"\tfor (i = 0; i < set->used; i++)\n\t\tif (fzn_ct_memeq(set->entries[i].id, id, sizeof(id)))\n\t\t\treturn FZN_CHAIN_OK;\n",
		"",
		"a succession kept once per arrival fills the set from one record -- sec 498",
	),
	(
		"succession-a-fork-names-nobody",
		"chain/succession.c",
		"\t\t\tif (next && !fzn_ct_memeq(next, e->new_key, FZN_PUBKEY_LEN))\n\t\t\t\treturn 0;\n",
		"",
		"a forked re-key resolving to either branch hands a device's references to whichever a thief signed -- sec 498",
	),
	(
		"succession-resolve-follows-the-chain",
		"chain/succession.c",
		"\t\tat = next;\n",
		"\t\tmemcpy(out, next, FZN_PUBKEY_LEN);\n\t\treturn 1;\n",
		"a re-key of a re-key stopping at the middle key names a key already revoked -- sec 498",
	),
	(
		"revocation-confirmed-not-by-its-issuer",
		"chain/revocation.c",
		"\t\tif (!fzn_ct_memeq(cf->grant, act, FZN_REVOCATION_ID_LEN)\n\t\t    || fzn_ct_memeq(cf->confirmer, issuer, FZN_PUBKEY_LEN))\n",
		"\t\tif (!fzn_ct_memeq(cf->grant, act, FZN_REVOCATION_ID_LEN))\n",
		"an admin confirming its own succession acts alone at any k -- sec 498",
	),
	(
		"revocation-confirmed-by-a-root",
		"chain/revocation.c",
		"\t\tif (root_confirms(store, cf->confirmer, root, cf->act))\n\t\t\treturn 1;\n\t\tb = find_admin(store, cf->confirmer);\n",
		"\t\tb = find_admin(store, cf->confirmer);\n",
		"a root's confirmation that does not settle an admin's succession leaves the estate's authority waiting on admins -- sec 498",
	),
	(
		"revocation-confirmed-issuer-stands",
		"chain/revocation.c",
		"\tif (!fzn_revocation_admin_stands(store, issuer))\n\t\treturn 0;\n\tneed = ",
		"\tneed = ",
		"a revoked admin's succession counting moves references on a stolen key's word -- sec 498",
	),
	(
		"succession-new-reads-new",
		"chain/succession.h",
		"\treturn r.base + FZN_SUCCESSION_OFF_NEW;\n",
		"\treturn r.base + FZN_SUCCESSION_OFF_OLD;\n",
		"a reader taking the old key for the new reads every reference through to the key being retired -- sec 498",
	),
	(
		"node-succession-saved",
		"node/succession.c",
		"\treturn save(store, ns->set.hash, record, hops, hop_count) ? FZN_NODE_REVOKE_OK\n",
		"\treturn (hop_count < FZN_CHAIN_MAX_HOPS || save) ? FZN_NODE_REVOKE_OK\n",
		"a succession held and never saved is forgotten at a restart, and the device's references go back to its revoked key -- sec 499",
	),
	(
		"node-succession-logged",
		"node/succession.c",
		"\tif (roots\n\t    && fzn_node_roots_log_act(roots, store, as, sign, (uint8_t)FZN_ROOT_ACT_GRANT, record,\n",
		"\tif (0\n\t    && fzn_node_roots_log_act(roots, store, as, sign, (uint8_t)FZN_ROOT_ACT_GRANT, record,\n",
		"a re-key never logged falls at its issuer's removal or revocation whatever the line -- sec 499",
	),
	(
		"node-succession-as-a-root",
		"node/succession.c",
		"\tif (roots && fzn_node_roots_acting(roots, id->pubkey, id->sign, &as, &sign)) {\n\t\tn = 0;\n",
		"\tif (0 && roots && fzn_node_roots_acting(roots, id->pubkey, id->sign, &as, &sign)) {\n\t\tn = 0;\n",
		"a root that cannot re-key a device leaves the owner nobody to re-key it -- sec 499",
	),
	(
		"node-succession-load-admits",
		"node/succession.c",
		"\t\t                             &n)\n\t\t    || admit(ns, revocations, root, sign, record, (const uint8_t (*)[FZN_HOP_LEN])hops,\n\t\t             n) != FZN_CHAIN_OK)\n",
		"\t\t                             &n))\n",
		"successions loaded from the store and never admitted read nobody through after a restart -- sec 499",
	),
	(
		"votes-absorb-learns-successions",
		"node/revoke.c",
		"\t\tpull->succeeding = 0;\n\t\tif (!pull->successions) {\n",
		"\t\tpull->succeeding = 0;\n\t\tif (1) {\n",
		"a member that refuses every succession it pulls never learns a device was re-keyed -- sec 499",
	),
	(
		"admin-rekey-mints-the-succession",
		"node/admin.c",
		"\tserr = fzn_node_succession_issue(admin->successions, admin->roots, admin->store, admin->id,\n",
		"\tserr = FZN_NODE_REVOKE_OK;\n\tif (0)\n\t\tserr = fzn_node_succession_issue(admin->successions, admin->roots, admin->store, admin->id,\n",
		"a re-key that pairs the new key and mints no succession leaves every reference on the revoked key -- sec 499",
	),
	(
		"admin-rekey-not-its-own-successor",
		"node/admin.c",
		"\tif (memcmp(record.host, old, FZN_PUBKEY_LEN) == 0)\n\t\treturn answer_text(reply, cap, FZN_REPLY_MALFORMED,\n",
		"\tif (0)\n\t\treturn answer_text(reply, cap, FZN_REPLY_MALFORMED,\n",
		"a device re-keyed to itself pairs again and revokes itself before the succession is refused -- sec 499",
	),
	(
		"record-a-first-record-names-nothing",
		"record/record.c",
		"\tif (fzn_get_be64(bytes + FZN_RECORD_OFF_SEQ) == 1u\n\t    && !prev_is_zero(bytes + FZN_RECORD_OFF_PREV))\n\t\treturn FZN_RECORD_ERR_SHAPE;\n",
		"",
		"a first record naming a predecessor opens, and a chain can start part way through somebody else's -- sec 500",
	),
	(
		"record-sign-writes-prev",
		"record/record.c",
		"\tif (prev)\n\t\tmemcpy(out + FZN_RECORD_OFF_PREV, prev, FZN_RECORD_ID_LEN);\n",
		"\tif (0)\n\t\tmemcpy(out + FZN_RECORD_OFF_PREV, prev, FZN_RECORD_ID_LEN);\n",
		"a record signed without the predecessor it was given is a chain of one record, and every cut over it fails -- sec 500",
	),
	(
		"record-is-open-first-names-nothing",
		"record/record.h",
		"\t\tif (acc != 0u)\n\t\t\treturn 0;\n\t}",
		"\t\t(void)acc;\n\t}",
		"is_open taking what open refuses lets a hand-built view through every gate that asks it -- sec 500",
	),
	(
		"journal-chained-checks-prev",
		"record/journal.c",
		"\tif (e && seq == e->received + 1u && e->has_head\n\t    && memcmp(e->head, prev, FZN_RECORD_ID_LEN) != 0) {\n",
		"\tif (0 && e && seq == e->received + 1u && e->has_head\n\t    && memcmp(e->head, prev, FZN_RECORD_ID_LEN) != 0) {\n",
		"a journal that admits a record naming another predecessor follows whichever branch of a fork arrives, which is the thief's as readily as the owner's -- sec 500",
	),
	(
		"journal-chained-sees-a-second-head",
		"record/journal.c",
		"\tif (e && e->has_head && seq == e->received && e->received != 0u\n",
		"\tif (0 && e && e->has_head && seq == e->received && e->received != 0u\n",
		"a second record at the head read as an echo hides the one fork a single kept id can see -- sec 500",
	),
	(
		"journal-chained-keeps-the-head",
		"record/journal.c",
		"\tmemcpy(e->head, id, FZN_RECORD_ID_LEN);\n\te->has_head = 1;\n",
		"\te->has_head = 1;\n",
		"a head that never moves refuses the honest next record as a fork -- sec 500",
	),
	(
		"journal-part-way-head-unknown",
		"record/journal.c",
		"\t * one this journal has seen, so the next is taken on its word. */\n\tmemset(e->head, 0, sizeof(e->head));\n\te->has_head = 0;\n",
		"\t * one this journal has seen, so the next is taken on its word. */\n",
		"a stream joined part way with a head of zero refuses every record it was anchored to receive -- sec 500",
	),
	(
		"journal-unchained-forgets-the-head",
		"record/journal.c",
		"\t * refused against a head that is no longer the head. */\n\tmemset(e->head, 0, sizeof(e->head));\n\te->has_head = 0;\n",
		"\t * refused against a head that is no longer the head. */\n",
		"a stream admitted unchained keeps a stale head, and its next chained record reads as a fork -- sec 500",
	),
	(
		"store-stands-checks-each-link",
		"record/store.c",
		"\t\t    || memcmp(got, want, sizeof(got)) != 0)\n\t\t\treturn 0;\n",
		"\t\t    || 0)\n\t\t\treturn 0;\n",
		"a cut walked without comparing each record to the id above it trusts whatever the untrusted store hands back -- sec 500",
	),
	(
		"exchange-pull-takes-the-next-one",
		"record/exchange.c",
		"\t\t    || fzn_record_stream(rec) != want->stream || fzn_record_seq(rec) != *next\n",
		"\t\t    || fzn_record_stream(rec) != want->stream\n",
		"a pull that takes whatever sequence comes back lets a peer skip a record the chain then never asks for -- sec 501",
	),
	(
		"exchange-pull-takes-the-issuer-asked",
		"record/exchange.c",
		"\t\t    || memcmp(fzn_record_issuer(rec), want->issuer, FZN_PUBKEY_LEN) != 0\n",
		"",
		"a pull that takes another issuer's record for the one asked about files it under a stream it does not belong to -- sec 501",
	),
	(
		"exchange-pull-verifies",
		"record/exchange.c",
		"\t\t    || fzn_record_stream(rec) != want->stream || fzn_record_seq(rec) != *next\n\t\t    || fzn_record_verify(rec, sign) != FZN_RECORD_OK\n",
		"\t\t    || fzn_record_stream(rec) != want->stream || fzn_record_seq(rec) != *next\n",
		"a record nobody signed, served by a peer, enters the journal as the issuer's -- sec 501",
	),
	(
		"exchange-pull-counts-a-fork",
		"record/exchange.c",
		"\t\tif (jerr == FZN_JOURNAL_ERR_FORK) {\n\t\t\ttally->forks++;\n",
		"\t\tif (jerr == FZN_JOURNAL_ERR_FORK) {\n",
		"a fork said as nothing hides the one sign a key was stolen -- sec 501",
	),
	(
		"node-journal-replay-verifies",
		"node/journal.c",
		"\t\tif (serr != FZN_RECORD_STORE_OK || fzn_record_verify(rec, nj->sign) != FZN_RECORD_OK\n",
		"\t\tif (serr != FZN_RECORD_STORE_OK\n",
		"a store edited underneath is believed at every start -- sec 501",
	),
	(
		"node-journal-append-names-the-head",
		"node/journal.c",
		"\tif (fzn_record_sign(issuer, subject, stream, kind, seq, seq == 1u ? NULL : e->head, now,\n",
		"\tif (fzn_record_sign(issuer, subject, stream, kind, seq, NULL, now,\n",
		"a record written without its predecessor is refused by the node's own chain, and nothing past the first act is kept -- sec 501",
	),
	(
		"roots-logged-hook-called",
		"node/roots.c",
		"\tif (roots->logged && !roots->logged(roots->logged_ctx, pubkey, sign, kind, act, record, len))",
		"\tif (0 && roots->logged && !roots->logged(roots->logged_ctx, pubkey, sign, kind, act, record, len))",
		"an act logged and never mirrored leaves the journal without it, and a cut judged on the journal drops it -- sec 501",
	),
	(
		"node-journal-object-is-a-library-tag",
		"node/journal.c",
		"\t    || !FZN_OBJECT_IS_LIBRARY(object[1])\n",
		"",
		"a record whose body is no signed object of this library's is carried as one, and a receiver applies it by a tag nobody assigned -- sec 502",
	),
	(
		"roots-logged-hook-gets-the-object",
		"node/roots.c",
		"\tif (roots->logged && !roots->logged(roots->logged_ctx, pubkey, sign, kind, act, record, len))",
		"\tif (roots->logged && !roots->logged(roots->logged_ctx, pubkey, sign, kind, act, NULL, 0u))",
		"a journal told only an act's hash carries nothing a receiver can apply -- sec 502",
	),
	(
		"apply-waits-for-a-chain",
		"node/apply.c",
		"\treturn tried ? REFUSED : WAIT;\n",
		"\treturn REFUSED;\n",
		"an object refused for a chain that has not arrived yet is skipped for good, though its grant comes a round later -- sec 503",
	),
	(
		"apply-marks-what-it-applied",
		"node/apply.c",
		"\t\t\t\t(void)fzn_journal_confirm(&ap->journal->journal, entry->issuer,\n\t\t\t\t                          FZN_NODE_JOURNAL_STREAM, seq);\n",
		"",
		"a journal never marked applied hands every object over again every round -- sec 503",
	),
	(
		"apply-passes-while-progressing",
		"node/apply.c",
		"\tfor (pass = 0; pass < FZN_NODE_APPLY_PASSES && progress; pass++) {\n",
		"\tfor (pass = 0; pass < 1u && progress; pass++) {\n",
		"one pass a round leaves a vote waiting on a grant applied in the same round, a round late every time -- sec 503",
	),
	(
		"admin-retention-is-an-act",
		"node/roots.c",
		"\treturn fzn_node_roots_log_act(roots, store, identity, identity_sign,\n\t                              (uint8_t)FZN_ROOT_ACT_SETTING, record, sizeof(record));\n}",
		"\treturn FZN_NODE_ROOTS_OK;\n}",
		"an admin's retention setting that is not logged never enters the admin's journal, and since the vote stream retired nothing else carries it: every other node keeps the estate's rules without it -- sec 505",
	),
	(
		"journal-head-fork-is-marked",
		"record/journal.c",
		"\t\t            \"in two places\",\n\t\t            (unsigned long long)seq, (unsigned long)stream);\n\t\te->forked = 1;\n",
		"\t\t            \"in two places\",\n\t\t            (unsigned long long)seq, (unsigned long)stream);\n",
		"a second record at a stream's head refused and left unmarked is a key that signed in two places whose held branch still offers a head every vote defaults its cut to -- sec 506",
	),
	(
		"journal-next-fork-is-marked",
		"record/journal.c",
		"\t\t            \"journal does not hold at its head\",\n\t\t            (unsigned long long)seq, (unsigned long)stream);\n\t\te->forked = 1;\n",
		"\t\t            \"journal does not hold at its head\",\n\t\t            (unsigned long long)seq, (unsigned long)stream);\n",
		"a record naming another predecessor than the head is a fork as surely as a second record at the head; unmarked, the stream goes on offering a head -- sec 506",
	),
	(
		"node-journal-head-refuses-a-fork",
		"node/journal.c",
		"\tif (!e || e->forked || !e->has_head || e->received == 0u)\n\t\treturn 0;\n\tmemcpy(id, e->head, FZN_RECORD_ID_LEN);",
		"\tif (!e || !e->has_head || e->received == 0u)\n\t\treturn 0;\n\tmemcpy(id, e->head, FZN_RECORD_ID_LEN);",
		"a forked stream that still offers a head lets a vote default its cut to one branch of a key used in two places -- whichever happened to arrive first -- sec 506",
	),
	(
		"node-journal-stands-checks-the-chain",
		"node/journal.c",
		"\t\tif (memcmp(got, want, sizeof(got)) != 0)\n\t\t\treturn 0;\n\t\tif (!below",
		"\t\tif (0)\n\t\t\treturn 0;\n\t\tif (!below",
		"a walk that does not check each record against the prev above it believes a store edited underneath, and an act inserted on disk stands under a cut that never covered it -- sec 506",
	),
	(
		"node-journal-stands-only-below-the-cut",
		"node/journal.c",
		"\tuint64_t seq;\n\tint below = 0;\n",
		"\tuint64_t seq;\n\tint below = 1;\n",
		"an act after the cut that stands is a thief's act counted under a line drawn before it -- the one thing a cut exists to stop -- sec 506",
	),
	(
		"node-roots-head-asks-the-journal",
		"node/roots.c",
		"\treturn roots->journal && fzn_node_journal_head(roots->journal, key, id);",
		"\treturn 0;",
		"roots judging by a journal that default a vote's cut from the root log name an id the journal does not hold, so nothing the revoked key did stands -- sec 506",
	),
	(
		"node-roots-judge-by-the-journal",
		"node/roots.c",
		"\tfzn_node_journal_acts(journal, &roots->acts);\n\troots->journal = journal;",
		"\troots->journal = journal;",
		"roots that keep the root log's act ops after a journal is set judge every cut by a log a remote node never receives, and a revoked member's acts before its line drop everywhere but where it was cast -- sec 506",
	),
	(
		"notes-sync-finishes-an-answered-purge",
		"notes/sync.c",
		"\t\t\tif (answered == p.asked_count) {",
		"\t\t\tif (0) {",
		"a purge whose erase failed after the last host answered is owed no question, so no round reaches it again: the note is never erased and holds its queue slot for good -- reported by fuzzypickles, sec 507",
	),
	(
		"notes-release-finishes-an-answered-purge",
		"notes/purge.c",
		"\t\tif (changed) {\n\t\t\terr = save(store, &p);\n\t\t\tif (err != FZN_NOTES_OK)\n\t\t\t\treturn err;\n\t\t}\n",
		"\t\tif (!changed)\n\t\t\tcontinue;\n\t\terr = save(store, &p);\n\t\tif (err != FZN_NOTES_OK)\n\t\t\treturn err;\n",
		"a release that only finishes purges whose answers it changed never retries one whose erase failed after its last answer -- sec 507",
	),
	(
		"node-roots-set-journal-repoints-the-store",
		"node/roots.c",
		"\tif (roots->revocations\n\t    && fzn_revocation_store_set_acts(roots->revocations, &roots->acts) != FZN_CHAIN_OK)\n\t\treturn FZN_NODE_ROOTS_MALFORMED;\n",
		"",
		"a store attached before the journal was set keeps asking no act log, and every cut drawn against it keeps nothing of the revoked key's -- sec 508",
	),
	(
		"exchange-push-verifies-what-arrives",
		"record/exchange.c",
		"\t\t    || fzn_record_open(request + at + 2u, len, &rec) != FZN_RECORD_OK\n\t\t    || fzn_record_verify(rec, sign) != FZN_RECORD_OK\n\t\t    || !hash->hash(hash->ctx, id, sizeof(id), rec.base, rec.len)) {\n\t\t\trefused++;",
		"\t\t    || fzn_record_open(request + at + 2u, len, &rec) != FZN_RECORD_OK\n\t\t    || !hash->hash(hash->ctx, id, sizeof(id), rec.base, rec.len)) {\n\t\t\trefused++;",
		"a push taken unverified writes a record nobody signed into a stream every follower then admits from this host -- sec 512",
	),
	(
		"exchange-push-stops-at-a-fork",
		"record/exchange.c",
		"\t\tif (jerr == FZN_JOURNAL_ERR_FORK) {\n\t\t\tforks++;\n\t\t\tbreak;\n\t\t}\n\t\tif (jerr == FZN_JOURNAL_ERR_DUPLICATE) {\n\t\t\theld++;",
		"\t\tif (jerr == FZN_JOURNAL_ERR_FORK) {\n\t\t\theld++;\n\t\t\tcontinue;\n\t\t}\n\t\tif (jerr == FZN_JOURNAL_ERR_DUPLICATE) {\n\t\t\theld++;",
		"a fork pushed and counted as held is a key signing in two places that nobody hears about -- sec 512",
	),
	(
		"notes-put-refuses-purged",
		"notes/store.c",
		"\tif (fzn_notes_purged(store, fzn_record_subject(rec)))\n\t\treturn FZN_NOTES_ERR_PURGED;\n",
		"",
		"a purged note is filed again from any record of it a peer or a journal offers -- sec 518",
	),
	(
		"notes-erase-marks-first",
		"notes/purge.c",
		"\terr = fzn_notes_mark_purged(store, id);\n\tif (err != FZN_NOTES_OK)\n\t\treturn err;\n",
		"",
		"a purge erases a note's claims and leaves nothing to stop its history filing it again -- sec 518",
	),
	(
		"note-wrap-pads-the-key",
		"notes/note.c",
		"\t\tout[i] = (uint8_t)(key[i] ^ pad[i]);",
		"\t\tout[i] = key[i];",
		"a content key goes into the record bare, and every shell of a purged note opens its content -- sec 520",
	),
	(
		"notes-wrap-first-stands",
		"notes/store.c",
		"\t\treturn same ? FZN_NOTES_OK : FZN_NOTES_ERR_EQUIVOCATION;\n\t}\n\tif (err != FZN_NOTES_ERR_ABSENT)",
		"\t\t(void)same;\n\t}\n\tif (err != FZN_NOTES_OK && err != FZN_NOTES_ERR_ABSENT)",
		"a peer's gift replaces the wrap key every record of a note unwraps under -- sec 520",
	),
	(
		"notes-history-trim-keep-wins",
		"notes/author.c",
		"\t\tif (kept || (!pruned && !drops))\n\t\t\tcontinue;\n\t\terr = fzn_notes_history_remove(",
		"\t\tif (!pruned && !drops)\n\t\t\tcontinue;\n\t\terr = fzn_notes_history_remove(",
		"a keep rule protects no version a prune rule takes, against the set semantics every kind has -- sec 582",
	),
	(
		"notes-history-trim-each-note-its-own-list",
		"notes/author.c",
		"\t\tif (i == 0 || memcmp(v->id, trim.at[i - 1u].id, FZN_SUBJECT_LEN) != 0)\n",
		"\t\tif (i == 0)\n",
		"a count or size rule weighs every note's versions as one list, and a busy note takes another's history -- sec 582",
	),
	(
		"notes-history-trim-keep-policy-wins",
		"notes/author.c",
		"\tif (keeps)\n\t\tdrops = 0;\n",
		"",
		"a drop policy beats a keep policy for history, where keep wins for every other kind -- sec 582",
	),
	(
		"notes-history-bound-lets-the-oldest-go",
		"notes/store.c",
		"\t    && count >= FZN_NOTES_HISTORY_MAX) {\n",
		"\t    && 0) {\n",
		"a store with no history rule grows its history without bound -- sec 581",
	),
	(
		"notes-history-bound-picks-the-oldest",
		"notes/store.c",
		"\tif (!p->any || fzn_record_issued_ms(rec) < p->oldest_ms) {\n",
		"\tif (!p->any || fzn_record_issued_ms(rec) > p->oldest_ms) {\n",
		"at the bound the newest version is let go, so a full history stops recording edits -- sec 581",
	),
	(
		"notes-history-kept-on-supersession",
		"notes/store.c",
		"\t\tif (store->history)\n\t\t\thistory_keep(store, bytes, held_len);\n",
		"",
		"an edit throws away the version it replaces, and a note has no history -- sec 581",
	),
	(
		"notes-history-goes-with-a-purge",
		"notes/store.c",
		"\tif (fzn_notes_history_forget(store, id) != FZN_NOTES_OK)\n\t\treturn FZN_NOTES_ERR_BACKEND;\n",
		"",
		"a purged note's earlier versions stay, texts and all, after the user asked it gone -- sec 581",
	),
	(
		"notes-wrap-refuses-purged",
		"notes/store.c",
		"\tif (fzn_notes_purged(store, id))\n\t\treturn FZN_NOTES_ERR_PURGED;\n\terr = fzn_notes_wrap_get(store, id, held);",
		"\terr = fzn_notes_wrap_get(store, id, held);",
		"a purged note's wrap key is taken back from a peer that still holds it -- sec 520",
	),
	(
		"notes-purge-destroys-wrap",
		"notes/purge.c",
		"\terr = fzn_notes_wrap_erase(store, id);\n\tif (err != FZN_NOTES_OK)\n\t\treturn err;\n",
		"",
		"a purge leaves the wrap key, and every shell of the note still unwraps its content -- sec 520",
	),
	(
		"sync-wraps-answers-members-only",
		"notes/sync.c",
		"\t\treturn admits(policy, sender)\n\t\t               ? answer_wraps(store, NULL,",
		"\t\treturn 1\n\t\t               ? answer_wraps(store, NULL,",
		"any host that asks is given every note's wrap key -- sec 520",
	),
	(
		"sync-give-only-indexed",
		"notes/sync.c",
		"\t\tif (listed((const uint8_t (*)[FZN_TREE_ID_LEN])ids, held, e)\n\t\t    && fzn_notes_wrap_put",
		"\t\tif (fzn_notes_wrap_put",
		"a member plants wrap keys for notes the taker does not hold -- sec 520",
	),
	(
		"sync-wraps-scoped",
		"notes/sync.c",
		"\t\tif (!in_scope(scope, id) || fzn_notes_purged(store, id)",
		"\t\tif (fzn_notes_purged(store, id)",
		"a contact is given the wrap key of any note it names by id, shared or not -- sec 520",
	),
	(
		"notes-read-unwraps",
		"notes/author.c",
		"\topened = open(ctx, &plain, buf, cap, &len) && len == meta->content.length;",
		"\topened = open(ctx, &meta->content, buf, cap, &len) && len == meta->content.length;",
		"a note is opened under its wrapped key, and nothing reads -- sec 520",
	),
	(
		"node-notes-title-cache-hits",
		"node/notes.c",
		"\t\t\tcached = title_at(meta.content.root);",
		"\t\t\tcached = NULL;",
		"every listing opens every note's blob, which sec 511 promised clients it would not -- sec 522",
	),
	(
		"node-notes-title-drop",
		"node/notes.c",
		"\tif (!named && root)\n\t\ttitle_drop(root);\n",
		"",
		"a purged note's title and labels outlive its blob in the listing cache -- sec 522",
	),
	(
		"node-notes-list-labels",
		"node/notes.c",
		"\t\t\tif (escape(labels, labels_len, detail + pos + 1u, limit - pos - 1u, &lwrote)",
		"\t\t\tif (escape(labels, 0u, detail + pos + 1u, limit - pos - 1u, &lwrote)",
		"a listing gives no labels, and a client cannot search them without opening every note -- sec 522",
	),
	(
		"gui-pending-says-so",
		"gui/notebook_view.cpp",
		"\t\t\tbool pending = (flags & FZN_NODE_NOTES_LIST_PENDING) != 0u;",
		"\t\t\tbool pending = false;",
		"a note whose content has not arrived is a row with nothing in it -- sec 522",
	),
	(
		"gui-pending-read-only",
		"gui/notebook_view.cpp",
		"\t\t\tpending = f.value(5) == QStringLiteral(\"pending\");",
		"\t\t\tpending = false;",
		"a pending note opens as an empty note to type into, and the save is refused -- sec 522",
	),
	(
		"opjournal-secrets-keep-nothing",
		"node/opjournal.c",
		"\tcase FZN_PERSIST_OWN_PREKEY:\n",
		"",
		"a superseded secret is kept in the operation journal, and forward secrecy with it is gone -- sec 523",
	),
	(
		"opjournal-removal-erases-history",
		"node/opjournal.c",
		"\t\t\t\t\terase_kept(oj, g, seq, &past);",
		"\t\t\t\t\t(void)past;",
		"a removed row stays readable in the operation journal, and a purge deletes nothing there -- sec 523",
	),
	(
		"opjournal-replay-checks-hash",
		"node/opjournal.c",
		"\t\t    || memcmp(check, e.hash, sizeof(check)) != 0) {",
		"\t\t    || 0) {",
		"replay believes whatever bytes the store hands over under an entry's hash -- sec 523",
	),
	(
		"journal-keeps-before-admitting",
		"node/journal.c",
		"\tif (fzn_record_store_put(&nj->store, rec) != FZN_RECORD_STORE_OK)\n\t\treturn FZN_NODE_JOURNAL_STORE;\n\tif (fzn_journal_admit_chained(&nj->journal, issuer, stream, seq, fzn_record_prev(rec), id)\n\t    != FZN_JOURNAL_OK)\n\t\treturn FZN_NODE_JOURNAL_REFUSED;\n",
		"\tif (fzn_journal_admit_chained(&nj->journal, issuer, stream, seq, fzn_record_prev(rec), id)\n\t    != FZN_JOURNAL_OK)\n\t\treturn FZN_NODE_JOURNAL_REFUSED;\n\tif (fzn_record_store_put(&nj->store, rec) != FZN_RECORD_STORE_OK)\n\t\treturn FZN_NODE_JOURNAL_STORE;\n",
		"a record the store refused is admitted, and every write after it chains to a record no follower can fetch -- sec 523",
	),
	(
		"opjournal-budget-bounds",
		"node/opjournal.c",
		"\twhile (oj->budget && oj->kept > oj->budget) {",
		"\twhile (0) {",
		"the operation journal keeps every byte it is ever handed, with no bound -- sec 523",
	),
	(
		"opjournal-snapshot-takes-rows",
		"node/opjournal.c",
		"\tfor (slot = 1u; slot < FZN_PERSIST_SLOT_END; slot++) {",
		"\tfor (slot = 1u; slot < 1u; slot++) {",
		"a generation opens with an empty snapshot, and replays to a state that was never the node's -- sec 524",
	),
	(
		"opjournal-snapshot-skips-secrets",
		"node/opjournal.c",
		"\t\tif (!fzn_opjournal_keeps((fzn_persist_slot_t)slot))\n\t\t\tcontinue;\n\t\tif (fzn_persist_slot_whole_host",
		"\t\tif (fzn_persist_slot_whole_host",
		"a snapshot copies the secrets and sessions, so every rotation keeps an old key forward secrecy needed gone -- sec 524",
	),
	(
		"opjournal-rotation-counts-writes",
		"node/opjournal.c",
		"\tuint64_t writes = held > oj->opened_at ? held - oj->opened_at : 0u;",
		"\tuint64_t writes = held;",
		"a snapshot counts toward its generation's size, and a state as large as a generation rotates on every write -- sec 524",
	),
	(
		"opjournal-rotation-retries-later",
		"node/opjournal.c",
		"\t\toj->retry_at = writes + (oj->rotate_at / 4u ? oj->rotate_at / 4u : 1u);",
		"\t\toj->retry_at = 0u;",
		"a rotation that cannot take its snapshot is tried again on every write, each attempt listing every slot -- sec 524",
	),
	(
		"opjournal-rotation-drops-past-keep",
		"node/opjournal.c",
		"\toj->retry_at = 0u;\n\twhile (oj->last - oj->first + 1u > oj->keep)\n\t\tdrop_generation(oj, oj->first);",
		"\toj->retry_at = 0u;",
		"generations are never dropped, so the entries grow without bound, which is what rotation is for -- sec 524",
	),
	(
		"opjournal-drop-erases-bytes",
		"node/opjournal.c",
		"\t\tif (entry_at(oj, g, seq, &e))\n\t\t\terase_kept(oj, g, seq, &e);\n\toj->generations.drop",
		"\toj->generations.drop",
		"a dropped generation's kept bytes stay behind with nothing naming them, and the budget counts them for ever -- sec 524",
	),
	(
		"opjournal-start-drops-cut-short",
		"node/opjournal.c",
		"\tif (oj->last && !opened_in(oj, oj->last))\n\t\tdrop_generation(oj, oj->last);",
		"\tif (0)\n\t\tdrop_generation(oj, oj->last);",
		"a snapshot a crash cut short stays the newest generation, entries are added to it, and it can never replay -- sec 524",
	),
	(
		"opjournal-start-recounts",
		"node/opjournal.c",
		"\toj->kept = 0u;\n\toj->oldest_generation = 0u;\n\toj->oldest = 0u;\n\tfor (g = oj->first; g <= oj->last; g++) {",
		"\toj->oldest_generation = 0u;\n\toj->oldest = 0u;\n\tfor (g = oj->first; g <= oj->last; g++) {",
		"a fresh snapshot's bytes are counted twice at start, and the budget erases history it had room for -- sec 524",
	),
	(
		"opjournal-replay-needs-opened",
		"node/opjournal.c",
		"\tif (!journal_of(oj, g) || !opened_in(oj, g))\n\t\treturn 0;",
		"\tif (!journal_of(oj, g))\n\t\treturn 0;",
		"a generation whose snapshot was cut short replays, to a state that was never the node's -- sec 524",
	),
	(
		"messages-aad-binds-direction",
		"messages/line.c",
		"\tout[at++] = direction;\n\tout[at++] = part;",
		"\tout[at++] = 0;\n\tout[at++] = part;",
		"a line's direction is not bound to its text, so a sent line can be shown as received -- sec 526",
	),
	(
		"messages-parts-tile-one-way",
		"messages/line.c",
		"\t    || (out->parts == 2u && out->part == 0u && text_len != FZN_MESSAGE_PART_MAX)",
		"\t    || 0",
		"a first part short of full reads, so one line has two encodings -- sec 526",
	),
	(
		"messages-epoch-counts-leap-years",
		"messages/line.c",
		"\tuint64_t year = yoe + era * 400u + (month <= 2u ? 1u : 0u);",
		"\tuint64_t year = yoe + era * 400u;",
		"January and February land in the previous year's months, under the wrong key epoch -- sec 526",
	),
	(
		"messages-key-per-month",
		"messages/messages.c",
		"\tepoch = fzn_message_epoch_of(now);",
		"\tepoch = 0u;",
		"every line shares one key, so a rule trimming a month takes every month with it -- sec 526",
	),
	(
		"messages-key-per-device",
		"messages/messages.c",
		"\tmemcpy(in + at + 4u, device, FZN_PUBKEY_LEN);",
		"\tmemset(in + at + 4u, 0, FZN_PUBKEY_LEN);",
		"two devices' keys for a month claim one row, and the one that arrives overwrites the other -- sec 526",
	),
	(
		"messages-forget-every-device",
		"messages/messages.c",
		"\tfor (d = 0; d < m->device_count; d++)\n\t\tif (!key_row(m, contact, epoch, m->devices[d], row)",
		"\tfor (d = 0; d < 0u; d++)\n\t\tif (!key_row(m, contact, epoch, m->devices[d], row)",
		"a trimmed month stays readable through the keys of the user's other devices -- sec 526",
	),
	(
		"messages-mark-sets-state",
		"messages/messages.c",
		"\tif (!set_state(m, contact, direction, id, state, now)\n",
		"\tif (0\n",
		"a mark is recorded and the line never shows it -- sec 521, sec 526",
	),
	(
		"messages-newest-mark-wins",
		"messages/messages.c",
		"\t    && len == STATE_LEN && fzn_get_be64(held + 1u) > at)",
		"\t    && len == STATE_LEN && 0)",
		"a line's state is whichever mark was read last, not the newest -- sec 526",
	),
	(
		"messages-reindex-clears",
		"messages/messages.c",
		"\t\t\t\t    || !m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_STATE, row))",
		"\t\t\t\t    || 0)",
		"a reindex keeps a state row the journal holds no mark for -- sec 526",
	),
	(
		"messages-page-shows-a-line-once",
		"messages/messages.c",
		"\tif (!index_entry(m, contact, i, &e) || seen_before(*n_seen, e.direction, contact, e.id))",
		"\tif (!index_entry(m, contact, i, &e) || 0)",
		"a line two devices both wrote is listed twice -- sec 526",
	),
	(
		"messages-first-key-stands",
		"messages/messages.c",
		"\t\treturn same ? FZN_MESSAGES_OK : FZN_MESSAGES_ERR_EQUIVOCATION;",
		"\t\treturn FZN_MESSAGES_OK;",
		"a different key for a row held is reported taken, so a giver is never told it equivocated -- sec 527",
	),
	(
		"messages-epoch-start-day",
		"messages/line.c",
		"\tuint64_t doy = (153u * mp + 2u) / 5u;",
		"\tuint64_t doy = (153u * mp + 2u) / 5u + 1u;",
		"a month starts a day late, so its first day's lines are aged as the month before's -- sec 531",
	),
	(
		"persist-view-every-slot-labelled",
		"gui/persist_view.cpp",
		"\tcase FZN_PERSIST_MESSAGE_INDEX:\n\t\treturn QStringLiteral(\"message index\");\n",
		"",
		"a slot added to persist.h is drawn as unknown, its -Wswitch warning unseen in an incremental build",
	),
	(
		"retain-contact-only-messages",
		"log/retain.c",
		"\t\t    && out->data == FZN_RETAIN_MESSAGES) {\n\t\t\tif (!hex_of(w[i] + 8,",
		"\t\t    ) {\n\t\t\tif (!hex_of(w[i] + 8,",
		"a log rule takes a contact= it can never act on, and reads as scoped when it is not -- sec 531",
	),
	(
		"retain-here-skips-message-rules",
		"log/retain.c",
		"\t\tif (in[i].data == FZN_RETAIN_LOG && !in[i].copy && !in[i].archived\n",
		"\t\tif (!in[i].copy && !in[i].archived\n",
		"a rule over conversations prunes the node's own log files -- sec 531",
	),
	(
		"retain-messages-reach-here",
		"log/retain.c",
		"\t\tif (in[i].data == FZN_RETAIN_MESSAGES && fzn_retain_reaches(&in[i], host, machine))",
		"\t\tif (in[i].data == FZN_RETAIN_MESSAGES)",
		"a rule over conversations scoped to another host trims this one's -- sec 531",
	),
	(
		"messages-trim-contact-scoped",
		"messages/messages.c",
		"\t\t\t             && (!rules[r].has_contact\n",
		"\t\t\t             && (1\n",
		"a rule naming one contact trims every conversation -- sec 531",
	),
	(
		"messages-trim-keep-protects",
		"messages/messages.c",
		"\t\t\t\tif (rules[r].kind == FZN_RETAIN_KEEP && within)\n\t\t\t\t\tkept = 1;",
		"\t\t\t\tif (rules[r].kind == FZN_RETAIN_KEEP && within)\n\t\t\t\t\tkept = 0;",
		"a keep rule protects nothing, and a prune deletes what the holder kept -- sec 531",
	),
	(
		"messages-trim-month-whole",
		"messages/messages.c",
		"\t\t\tif (kept || (!pruned && !drops))\n\t\t\t\tmonths[k].stays = 1;",
		"\t\t\tif (kept && (!pruned && !drops))\n\t\t\t\tmonths[k].stays = 1;",
		"a month goes while lines of it are still within the rules -- sec 531",
	),
	(
		"messages-trim-age-from-month-end",
		"messages/messages.c",
		"\t\tend_us = fzn_message_epoch_start(e->epoch + 1u) * 1000u;",
		"\t\tend_us = fzn_message_epoch_start(e->epoch) * 1000u;",
		"a month is aged from its first day, so lines younger than the rule go -- sec 531",
	),
	(
		"messages-trim-never-current",
		"messages/messages.c",
		"\t\t\tif (months[k].stays || months[k].epoch >= current\n",
		"\t\t\tif (months[k].stays\n",
		"the month new lines are sealed under is trimmed, its key with it -- sec 531",
	),
	(
		"messages-trim-gone-refuses-key",
		"messages/messages.c",
		"\tif (is_gone(m, contact, epoch))\n\t\treturn FZN_MESSAGES_ERR_GONE;\n\tif (key_of(",
		"\tif (0)\n\t\treturn FZN_MESSAGES_ERR_GONE;\n\tif (key_of(",
		"a member still holding a trimmed month's key undoes the trim at the next round -- sec 531",
	),
	(
		"messages-trim-gone-not-lacked",
		"messages/messages.c",
		"\t\tif (seen && !is_gone(m, contact, p.epoch)) {",
		"\t\tif (seen) {",
		"a trimmed month's lines are reported lacking, so its key is asked for again -- sec 531",
	),
	(
		"messages-trim-tombstone-kept",
		"messages/messages.c",
		"\t\t\tif (!set_gone(m, contact, months[k].epoch))\n\t\t\t\treturn FZN_MESSAGES_ERR_BACKEND;",
		"\t\t\tif (0)\n\t\t\t\treturn FZN_MESSAGES_ERR_BACKEND;",
		"a trim leaves no tombstone, so key carriage brings the month back -- sec 531",
	),
	(
		"node-messages-list-digit-key",
		"node/messages.c",
		"\t\tif (!all_digits(w, w_len) || w_len == 2u * FZN_PUBKEY_LEN) {",
		"\t\tif (!all_digits(w, w_len)) {",
		"a contact key whose hex is all decimal digits is read as a page offset and refused",
	),
	(
		"messages-page-reads-rows",
		"messages/messages.c",
		"\tif (!stored_load(m, e.device, e.seq, buf, &s)\n\t    || memcmp(s.contact, contact, FZN_PUBKEY_LEN) != 0)\n\t\treturn 0;\n\tfill(m, &s, &out[(*count)++]);",
		"\tif (!stored_load(m, e.device, e.seq, buf, &s) || 1)\n\t\treturn 0;\n\tfill(m, &s, &out[(*count)++]);",
		"a page lists no line from the store, only what the journal still holds -- sec 536",
	),
	(
		"messages-row-is-its-own-line",
		"messages/messages.c",
		"\tif (memcmp(s->device, device, FZN_PUBKEY_LEN) != 0 || s->seq != seq\n\t    || !direction_ok(s->direction)",
		"\tif (!direction_ok(s->direction)",
		"a row under another line's place is shown as that line -- sec 536",
	),
	(
		"messages-keep-once",
		"messages/messages.c",
		"\tif (line_marked(m, contact, last->direction, last->id)\n\t    || recently_indexed(m, contact, count_of(m, contact), last->direction, last->id))\n\t\treturn 1;\n\tmemcpy(s.contact, contact, FZN_PUBKEY_LEN);",
		"\tmemcpy(s.contact, contact, FZN_PUBKEY_LEN);",
		"a line two devices wrote is kept twice, a row nothing indexes -- sec 536",
	),
	(
		"messages-gone-month-keeps-head",
		"messages/messages.c",
		"\ts.held = (uint8_t)(held == last->parts && !is_gone(m, contact, last->epoch) ? held : 0u);",
		"\ts.held = (uint8_t)(held == last->parts ? held : 0u);",
		"a rebuild brings a trimmed month's sealed parts back into the store -- sec 536",
	),
	(
		"messages-trim-lets-parts-go",
		"messages/messages.c",
		"\t\ts.opened = 0u;\n\t\ts.text_len = 0;\n\t\ts.held = 0u;",
		"\t\ts.text_len = s.text_len;\n\t\ts.held = 0u;",
		"a trimmed month's text stays in the store, in the clear -- secs 536, 539",
	),
	(
		"messages-row-written-at",
		"messages/messages.c",
		"\t\t\tif (!keep_line(m, contact, device, seq, fzn_record_issued_at(rec), &p, body,",
		"\t\t\tif (!keep_line(m, contact, device, seq, 0u, &p, body,",
		"an absorbed line loses when it was written, and everyone's page its order of time -- sec 536",
	),
	(
		"messages-every-line-order",
		"messages/messages.c",
		"\t       && save_number(m, \"count\", contact, n + 1u) && all_append(m, contact, n)\n",
		"\t       && save_number(m, \"count\", contact, n + 1u)\n",
		"everyone's page lists nothing, its order never kept -- sec 536",
	),
	(
		"messages-upgrade-once",
		"messages/messages.c",
		"\tif (load_number(m, \"layout\", NOBODY) >= LAYOUT_ROWS)",
		"\tif (load_number(m, \"layout\", NOBODY) > LAYOUT_ROWS)",
		"every start rebuilds the store, which a cut journal would empty -- sec 536",
	),
	(
		"messages-earlier-part-kept",
		"messages/messages.c",
		"\tbody[0] = fzn_record_body(prev);\n\tbody_len[0] = fzn_record_body_len(prev);\n\treturn 1;",
		"\tbody[0] = fzn_record_body(rec);\n\tbody_len[0] = fzn_record_body_len(rec);\n\treturn 1;",
		"a two-part line is kept with its last part twice and its first lost -- sec 536",
	),
	(
		"messages-row-kept-opened",
		"messages/messages.c",
		"\tif (!s->opened && s->held && open_parts(m, s, text, &n)) {",
		"\tif (0 && open_parts(m, s, text, &n)) {",
		"a line whose key is here is kept sealed, its text lost with its key -- sec 539",
	),
	(
		"messages-key-opens-waiting",
		"messages/messages.c",
		"\t               && open_waiting(m, contact, epoch, device)\n",
		"",
		"a key arriving after its lines opens none of them: they stay shells -- sec 539",
	),
	(
		"messages-let-go-removes-first",
		"messages/messages.c",
		"\t\t    || !m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_LINE, row)\n\t\t    || !stored_save(m, &s))",
		"\t\t    || !stored_save(m, &s))",
		"a trim rewrites a row, so an operation journal keeps the text it held -- sec 539",
	),
	(
		"messages-forget-reaches-rows",
		"messages/messages.c",
		"\tif (!let_go(m, contact, epoch)\n",
		"\tif (0\n",
		"forgetting a month destroys its keys and leaves its text readable in the rows -- sec 539",
	),
	(
		"setting-key-alphabet",
		"state/setting.c",
		"\t\tif (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_'\n\t\t      || c == '/' || c == '-'))",
		"\t\tif (c == ' ')",
		"a key of capitals or punctuation is a cell, two spellings naming one setting -- sec 540",
	),
	(
		"setting-signed-by-setter",
		"state/setting.c",
		"\tif (!sign->verify(sign->ctx, bytes + FZN_SETTING_OFF_SETTER, bytes,\n\t                  len - (size_t)FZN_SIG_LEN, bytes + len - (size_t)FZN_SIG_LEN))\n\t\treturn FZN_SETTING_ERR_SIGNATURE;",
		"",
		"a setting nobody signed is opened as its named setter's -- sec 540",
	),
	(
		"setting-lengths-account",
		"state/setting.c",
		"\tif (len != at + 3u + value_len + (size_t)FZN_SIG_LEN || (bytes[at] == 0u && value_len)",
		"\tif (len < at + 3u + value_len + (size_t)FZN_SIG_LEN || (bytes[at] == 0u && value_len)",
		"a setting with bytes past its signature is opened -- sec 540",
	),
	(
		"setting-version-orders",
		"state/setting.c",
		"\tif (a->version != b->version)\n\t\treturn a->version > b->version;",
		"\tif (a->version != b->version)\n\t\treturn a->version < b->version;",
		"an older version of a cell stands over a newer at one rank -- sec 540",
	),
	(
		"settings-rank-in-force-highest",
		"node/settings.c",
		"\tfor (r = (int)FZN_SETTING_RANKS - 1; r >= 0; r--)",
		"\tfor (r = 0; r < (int)FZN_SETTING_RANKS; r++)",
		"a host's own value stands over an admin's -- sec 540",
	),
	(
		"settings-stale-refused",
		"node/settings.c",
		"\t\tif (!fzn_setting_supersedes(&s, &held))\n\t\t\treturn FZN_NODE_SETTINGS_STALE;",
		"",
		"an older setting replayed replaces the newer standing at its rank -- sec 540",
	),
	(
		"settings-write-judged-first",
		"node/settings.c",
		"\tif (fzn_node_apply_rank(ns->apply, ns->id->pubkey, scope, about, &rank) != 1)\n\t\treturn FZN_NODE_SETTINGS_REFUSED;",
		"\trank = FZN_SETTING_RANK_ROOT;",
		"a node writes, and keeps at a root's rank, a setting it may not make -- sec 540",
	),
	(
		"settings-row-is-its-cell",
		"node/settings.c",
		"\t    || !fzn_setting_cell(s, ns->hash, again) || memcmp(again, cell, FZN_SUBJECT_LEN) != 0)",
		"\t    || !fzn_setting_cell(s, ns->hash, again))",
		"a row under another cell's place answers for that cell -- sec 540",
	),
	(
		"apply-setting-signer-is-setter",
		"node/apply.c",
		"\tif (!ap->settings || fzn_setting_open(body, len, ap->sign, &s) != FZN_SETTING_OK\n\t    || !fzn_ct_memeq(s.setter, signer, FZN_PUBKEY_LEN))",
		"\tif (!ap->settings || fzn_setting_open(body, len, ap->sign, &s) != FZN_SETTING_OK)",
		"a setting rides another key's stream and is judged by that key's standing -- sec 540",
	),
	(
		"apply-rank-host-own-cell-only",
		"node/apply.c",
		"\tif (scope == FZN_SCOPE_HOST && fzn_ct_memeq(about, key, FZN_PUBKEY_LEN) && ap->capability",
		"\tif (ap->capability",
		"a member sets the estate's cells, or another host's, at a host's rank -- sec 540",
	),
	(
		"apply-rank-admin-admitted",
		"node/apply.c",
		"\t\tif (i == n\n\t\t    && fzn_revocation_admin_admit(ap->revocations, key, opened, n, ap->root, ap->sign)\n\t\t               == FZN_CHAIN_OK) {",
		"\t\tif (i == n) {",
		"any chain under the admin capability ranks as an admin's, unverified -- sec 540",
	),
	(
		"apply-rank-member-refused",
		"node/apply.c",
		"\tif (!found && ap->capability && fzn_node_apply_chain(ap, key, ap->capability, hops, &n) && n)\n\t\tfound = 1;",
		"",
		"a member's setting it may not make waits for ever, and stops its whole stream -- sec 540",
	),
	(
		"admin-retention-as-setting",
		"node/admin.c",
		"\tif (admin->settings) {\n\t\tint held = 1, legacy;",
		"\tif (0) {\n\t\tint held = 1, legacy;",
		"a rule added on a node with settings stays in its own slot, where no admin's node holds it -- sec 541",
	),
	(
		"admin-retention-remove-older-row",
		"node/admin.c",
		"\t\tlegacy = fzn_log_rules_remove(admin->store, admin->state->hash, &rule)\n\t\t         == FZN_LOG_RULES_OK;",
		"\t\tlegacy = 0;",
		"a rule left in the older slot can no longer be removed once settings are on -- sec 541",
	),
	(
		"admin-retention-list-settings",
		"node/admin.c",
		"\tif (admin->settings\n\t    && (fzn_node_settings_each(admin->settings, collect_rule, &l) != FZN_NODE_SETTINGS_OK",
		"\tif (0\n\t    && (fzn_node_settings_each(admin->settings, collect_rule, &l) != FZN_NODE_SETTINGS_OK",
		"this host's rules kept as settings are missing from its own listing -- sec 541",
	),
	(
		"admin-estate-retention-as-setting",
		"node/admin.c",
		"\tif (admin->settings && admin->settings->estate) {\n\t\tint held = 1;",
		"\tif (0) {\n\t\tint held = 1;",
		"an estate rule goes into the older records rather than the estate's settings -- sec 541",
	),
	(
		"settings-take-rules-out-of-slot",
		"node/settings.c",
		"\t\tif (fzn_log_rules_remove(ns->store, ns->hash, &held[i]) != FZN_LOG_RULES_OK)\n\t\t\treturn FZN_NODE_SETTINGS_BACKEND;\n",
		"",
		"a rule moved into settings stays in the older slot too, twice over -- sec 541",
	),
	(
		"settings-k-root-rank-only",
		"node/settings.c",
		"\t    || rank != FZN_SETTING_RANK_ROOT)\n\t\treturn fallback;\n\tk = count_of(value, len, 255u);",
		"\t    || 0)\n\t\treturn fallback;\n\tk = count_of(value, len, 255u);",
		"an admin sets the estate's k, which is a root's to set -- secs 418, 542",
	),
	(
		"settings-k-in-range",
		"node/settings.c",
		"\treturn k ? (uint8_t)k : fallback;",
		"\treturn (uint8_t)k;",
		"a k of 0 or past 255 is put in force -- sec 542",
	),
	(
		"admin-set-quorum-root-only",
		"node/admin.c",
		"\t\t    || rank != FZN_SETTING_RANK_ROOT)\n\t\t\treturn answer_text(reply, cap, FZN_REPLY_ERROR, \"the estate's k is a root's to set\");",
		"\t\t    && 0)\n\t\t\treturn answer_text(reply, cap, FZN_REPLY_ERROR, \"the estate's k is a root's to set\");",
		"a node that is no root writes the estate's k -- secs 418, 542",
	),
	(
		"admin-remote-needs-setting-on",
		"node/admin.c",
		"\t    || len != 2u || memcmp(value, \"on\", 2u) != 0)\n\t\treturn 0;",
		"\t    )\n\t\treturn 0;",
		"a node set to take no remote verbs takes them anyway -- sec 543",
	),
	(
		"admin-remote-needs-standing",
		"node/admin.c",
		"\treturn fzn_node_apply_rank(admin->settings->apply, sender, FZN_SCOPE_HOST, admin->id->pubkey,\n\t                           &rank)\n\t               == 1\n\t       && rank >= FZN_SETTING_RANK_ADMIN;",
		"\t(void)rank;\n\treturn 1;",
		"any member runs every verb remotely, not only an admin or a root -- sec 543",
	),
	(
		"admin-remote-logs-verb-only",
		"node/admin.c",
		"\t\t\tadmin->remote_ran(admin->remote_ran_ctx, req->sender, line, said);",
		"\t\t\tadmin->remote_ran(admin->remote_ran_ctx, req->sender, line, line_len);",
		"a remote verb's whole line, a key or a secret in it, goes to the log -- sec 543",
	),
	(
		"apply-grant-kept",
		"node/apply.c",
		"\tif (!grant_row(ap, body, row)\n\t    || !ap->store->save(ap->store->ctx, FZN_PERSIST_GRANT, row, body, FZN_HOP_LEN)) {",
		"\tif (0) {",
		"a grant lives only in memory, so a cut journal leaves no chain to rebuild -- sec 545",
	),
	(
		"apply-grant-row-is-its-hop",
		"node/apply.c",
		"\t\t    || len != FZN_HOP_LEN || !grant_row(ap, hop, again)\n\t\t    || memcmp(again, rows + (i * FZN_PUBKEY_LEN), FZN_PUBKEY_LEN) != 0)",
		"\t\t    || len != FZN_HOP_LEN)",
		"a hop filed under another's place is loaded as a grant -- sec 545",
	),
	(
		"journal-spine-id-is-checked",
		"node/journal.c",
		"\t\t\tmemcpy(got, entry, sizeof(got));",
		"\t\t\tmemcpy(got, want, sizeof(got));",
		"a spine entry edited underneath is walked through as if its id chained -- sec 546",
	),
	(
		"journal-spine-keeps-the-predecessor",
		"node/journal.c",
		"\tmemcpy(entry + FZN_RECORD_ID_LEN, fzn_record_prev(rec), FZN_RECORD_ID_LEN);",
		"\tmemcpy(entry + FZN_RECORD_ID_LEN, entry, FZN_RECORD_ID_LEN);",
		"the spine keeps no predecessor, so no walk passes a cut record -- sec 546",
	),
	(
		"journal-spine-entry-per-seq",
		"node/journal.c",
		"\tmemcpy(bytes + ((size_t)((seq - 1u) % SPINE_CHUNK) * SPINE_ENTRY), entry, SPINE_ENTRY);",
		"\tmemcpy(bytes, entry, SPINE_ENTRY);",
		"every kept entry lands on the row's first, so a cut stream answers for one record -- sec 546",
	),
	(
		"journal-follow-from-the-base",
		"node/journal.c",
		"\tbase = base_get(nj, key, stream, below);\n\tjerr = fzn_journal_anchor(",
		"\tbase = 1u;\n\tjerr = fzn_journal_anchor(",
		"a stream cut below its base is read from 1, stops at the hole, and reads as empty -- sec 547",
	),
	(
		"journal-base-is-the-head",
		"node/journal.c",
		"\t\tmemcpy(e->head, below, sizeof(below));\n\t\te->has_head = 1;",
		"\t\tmemcpy(e->head, below, sizeof(below));\n\t\te->has_head = 0;",
		"the first record held past a cut is taken on its word, whatever it names below it -- sec 547",
	),
	(
		"journal-cut-counts-as-applied",
		"node/journal.c",
		"\t\tif (fzn_journal_confirm(&nj->journal, key, stream, base - 1u) != FZN_JOURNAL_OK)",
		"\t\tif (0)",
		"what was cut is left unapplied, so apply reads records the store no longer holds -- sec 547",
	),
	(
		"journal-base-never-moves-down",
		"node/journal.c",
		"\t    || !(e = entry_of(nj, key, stream)) || base <= base_get(nj, key, stream, below)",
		"\t    || !(e = entry_of(nj, key, stream)) || (base_get(nj, key, stream, below), base < 2u)",
		"a base moves back below records already cut, and a reader starts in a hole -- sec 547",
	),
	(
		"journal-base-within-what-is-held",
		"node/journal.c",
		"\t    || base - 1u > e->received)\n\t\treturn FZN_NODE_JOURNAL_MALFORMED;",
		"\t    || 0)\n\t\treturn FZN_NODE_JOURNAL_MALFORMED;",
		"a base past what this journal received is attempted -- sec 547",
	),
	(
		"exchange-counts-a-peer-cut-below",
		"record/exchange.c",
		"\t\t}\n\t\ttally->missing++;\n\t\treturn 0;",
		"\t\t}\n\t\treturn 0;",
		"a peer that no longer holds what this host lacks goes unremarked, and the stream stalls silently -- sec 547",
	),
	(
		"record-store-cut-refuses-an-empty-range",
		"record/store.c",
		"\tif (!store || !store->ops || !store->ops->cut || !issuer || from == 0u || below <= from)",
		"\tif (!store || !store->ops || !store->ops->cut || !issuer || from == 0u)",
		"a cut of nothing reaches the backend and is reported as the store failing -- sec 548",
	),
	(
		"store-file-cut-zeroes-each-slot",
		"record/store_file.c",
		"\t\tif (pwrite(fd, zero, sizeof(zero), (off_t)((seq - 1u) * SLOT)) != (ssize_t)sizeof(zero))\n\t\t\treturn 0;\n",
		"\t\t(void)zero;\n",
		"a system that cannot punch keeps every cut record readable; only the build without the punch sees it -- sec 563",
	),
	(
		'buckets-drop-marks-gone',
		'node/buckets.c',
		'\t    || !b->store->save(b->store->ctx, FZN_PERSIST_BUCKET_IDS, row, gone, sizeof(gone)))\n\t\treturn FZN_BUCKETS_BACKEND;',
		'\t    || 0)\n\t\treturn FZN_BUCKETS_BACKEND;',
		"a month this node's rules let go is taken back from the next peer that holds it -- sec 564",
	),
	(
		'buckets-add-refuses-gone',
		'node/buckets.c',
		'\tif (fzn_buckets_gone(b, kind, subject, month))\n\t\treturn FZN_BUCKETS_GONE;\n\t/* TAKEN AND INDEXED',
		'\t/* TAKEN AND INDEXED',
		'an item of a month let go is kept again by whoever files it -- sec 564',
	),
	(
		'buckets-add-finds-the-last-counted',
		'node/buckets.c',
		'\t\tindexed = memcmp(chunk + last * FZN_BUCKETS_ID_LEN, id, FZN_BUCKETS_ID_LEN) == 0;',
		'\t\tindexed = 0;',
		'an item whose taking crashed after its count is counted twice, and its bucket never agrees again -- sec 564',
	),
	(
		'reconcile-bucket-item-is-its-id',
		'node/reconcile.c',
		'\t\t\tif (memcmp(id, ids[i], sizeof(id)) != 0) {',
		'\t\t\tif (0) {',
		"a peer's changed bytes are filed as the item asked for -- sec 564",
	),
	(
		'reconcile-bucket-passes-gone',
		'node/reconcile.c',
		'\t\t\tif (fzn_buckets_gone(b, kind, page[i].subject, page[i].month)) {\n\t\t\t\ttally->passed++;',
		'\t\t\tif (0) {\n\t\t\t\ttally->passed++;',
		'a month let go here is fetched from every peer every round -- sec 564',
	),
	(
		'reconcile-bucket-agreeing-is-skipped',
		'node/reconcile.c',
		'\t\t\tif (mine.count == page[i].count\n\t\t\t    && memcmp(mine.digest, page[i].digest, FZN_BUCKETS_ID_LEN) == 0)\n\t\t\t\tcontinue;\n',
		'',
		"every bucket's ids are listed every round, agreeing or not -- sec 564",
	),
	(
		'messages-file-verifies-each-record',
		'messages/messages.c',
		'\t\tif (fzn_record_verify(rec[i], m->sign) != FZN_RECORD_OK\n\t\t    || memcmp(fzn_record_issuer(rec[i]), device, FZN_PUBKEY_LEN) != 0',
		'\t\tif (0\n\t\t    || memcmp(fzn_record_issuer(rec[i]), device, FZN_PUBKEY_LEN) != 0',
		"a line a peer altered is filed as its writer's -- sec 564",
	),
	(
		'messages-file-only-the-user-s-devices',
		'messages/messages.c',
		'\tif (!is_device(m, device) || seq < parts)',
		'\tif (seq < parts)',
		"a line signed by a device not the user's is filed into a conversation -- sec 564",
	),
	(
		'node-messages-file-under-its-bucket',
		'node/messages.c',
		'\tif (err == FZN_MESSAGES_OK\n\t    && (!same_key(its_contact, contact) || its_epoch != epoch))',
		'\tif (0 && err == FZN_MESSAGES_OK\n\t    && (!same_key(its_contact, contact) || its_epoch != epoch))',
		'an item offered under another month is answered as filed there -- sec 564',
	),
	(
		'node-messages-file-not-into-gone',
		'node/messages.c',
		'\tif (fzn_buckets_gone(&nm->buckets, FZN_BUCKETS_MESSAGES, contact, epoch))\n\t\treturn FZN_MESSAGES_ERR_GONE;\n',
		'',
		"a trimmed month's line is filed again and its key asked for -- sec 564",
	),
	(
		'messages-absorb-replays-waits',
		'messages/messages.c',
		'\tif (seen && !waits_replay(m, seen, ctx))',
		'\tif (0 && seen && !waits_replay(m, seen, ctx))',
		"after a restart a reconciled line's key is never asked for, and it stays a shell -- sec 564",
	),
	(
		'messages-trim-drops-items',
		'messages/messages.c',
		'\t    || (m->items && m->items->drop && !m->items->drop(m->items->ctx, contact, epoch)))',
		'\t    || 0)',
		"a trimmed month's signed lines are still handed to every device that asks -- sec 564",
	),
	(
		'messages-absorb-keeps-items',
		'messages/messages.c',
		'\t\t\t    || (held && !item_keep(m, contact, p.epoch, device, seq, p.parts))\n',
		'',
		'a line absorbed from the journal is never handed on once the journal is cut -- sec 564',
	),
	(
		'messages-write-keeps-item',
		'messages/messages.c',
		'\t        || !item_keep(m, contact, epoch, m->issuer, own_head(m), (uint8_t)parts)\n',
		'',
		"a device's own lines are handed on by nobody once its journal is cut -- sec 564",
	),
	(
		'messages-backfill-runs-once',
		'messages/messages.c',
		'load_number(m, "itemsbf", NOBODY) == 1u',
		'load_number(m, "itemsbf", NOBODY) == 2u',
		"every start walks every device's journal again for items it already keeps -- sec 564",
	),
	(
		'retain-policy-keep-wins',
		'log/retain.c',
		'\t\tif (!rules[i].drop)\n\t\t\treturn 0;\n\t\tdrop = 1;',
		'\t\tdrop = 1;',
		'a host whose rules say both drop and keep drops: keep no longer wins -- sec 566',
	),
	(
		'retain-policy-is-no-limit-rule',
		'log/retain.c',
		'\tif (r->drop)\n\t\treturn 0;',
		'',
		'a prune or keep rule carrying a drop is written as a rule it is not -- sec 566',
	),
	(
		'retain-marks-drop-policy-prunes',
		'log/retain.c',
		': (pruned || drops ? FZN_RETAIN_MARK_PRUNED : 0u))',
		': (pruned ? FZN_RETAIN_MARK_PRUNED : 0u))',
		'a log under a drop policy keeps everything -- sec 566',
	),
	(
		'retain-copies-take-the-log-policy',
		'log/retain.c',
		'\t\tif (in[i].data == FZN_RETAIN_LOG\n\t\t    && (in[i].copy || in[i].kind == FZN_RETAIN_POLICY)',
		'\t\tif (in[i].data == FZN_RETAIN_LOG\n\t\t    && (in[i].copy)',
		"a log policy reaches this node's own log and not the copies it keeps -- sec 566",
	),
	(
		'retain-sources-take-the-log-policy',
		'log/retain.c',
		'\t\tif ((in[i].copy || in[i].kind == FZN_RETAIN_POLICY)',
		'\t\tif ((in[i].copy)',
		"a log policy reaches no source's copies -- sec 566",
	),
	(
		'messages-trim-drop-policy-holds-only-kept',
		'messages/messages.c',
		'\t\t\tif (kept || (!pruned && !drops))\n',
		'\t\t\tif (kept || !pruned)\n',
		'a drop policy beside other rules trims nothing they do not prune -- sec 566',
	),
	(
		'messages-trim-policy-alone-reaches',
		'messages/messages.c',
		'\t\tif (!any && !drops)\n\t\t\tcontinue;',
		'\t\tif (!any)\n\t\t\tcontinue;',
		'a drop policy alone trims no conversation -- sec 566',
	),
	(
		'messages-wanted-counts-what-is-newer',
		'messages/messages.c',
		'\t\tif (e.epoch <= epoch)\n\t\t\tcontinue;\n',
		'\t\tif (1)\n\t\t\tcontinue;\n',
		'a month past a count is fetched every round and trimmed every hour -- sec 566',
	),
	(
		'messages-wanted-not-a-gone-month',
		'messages/messages.c',
		'\tif (is_gone(m, contact, epoch))\n\t\treturn FZN_MESSAGES_OK;\n\t*wanted = 1;',
		'\t*wanted = 1;',
		'a month trimmed here is wanted again -- sec 566',
	),
	(
		'messages-wanted-the-current-month',
		'messages/messages.c',
		'\tif (epoch >= fzn_message_epoch_of(now_ms))\n\t\treturn FZN_MESSAGES_OK;',
		'\tif (0)\n\t\treturn FZN_MESSAGES_OK;',
		'under a drop policy the current month is not fetched, though the trim never takes it -- sec 566',
	),
	(
		'messages-wanted-under-drop',
		'messages/messages.c',
		'\t*wanted = kept || (!pruned && !drops);',
		'\t*wanted = kept || !pruned;',
		'a drop policy fetches months it would trim at once -- sec 566',
	),
	(
		'apply-holds-a-chain-verified-now',
		'node/apply.c',
		'\t       || (fzn_node_apply_chain(ap, key, capability, hops, &n)\n\t           && chain_proves(ap, key, (const uint8_t (*)[FZN_HOP_LEN])hops, n, capability));',
		'\t       || (fzn_node_apply_chain(ap, key, capability, hops, &n));',
		'an expired or revoked grant of the retention capability is still served everything -- sec 567',
	),
	(
		'reconcile-gate-filters-the-listing',
		'node/reconcile.c',
		'\tif (n != COUNT_FULL && gate) {',
		'\tif (0) {',
		'a caller without the retention capability is listed every bucket and takes them -- sec 567',
	),
	(
		'reconcile-gate-bars-ids',
		'node/reconcile.c',
		'\tif (served(gate, request[2], request + 3u)\n',
		'\tif (1\n',
		'a caller names a barred bucket and is given its ids -- sec 567',
	),
	(
		'reconcile-gate-bars-items',
		'node/reconcile.c',
		'\tif (err != FZN_BUCKETS_ABSENT && !served(gate, request[2], subject))\n\t\tlen = 0;\n',
		'',
		'a caller asking a barred item by its id is handed it -- sec 567',
	),
	(
		'admin-grant-retention-grants-retention',
		'node/admin.c',
		'\t                           &admin->state->config.retention_capability, grantee,',
		'\t                           &admin->state->config.admin_capability, grantee,',
		'`grant retention` hands out admin -- sec 567',
	),
	(
		'reconcile-put-is-its-id',
		'node/reconcile.c',
		'\tif (!fzn_buckets_id(srv->hash, st->bytes, st->total, got)\n\t    || memcmp(got, id, FZN_BUCKETS_ID_LEN) != 0) {',
		'\tif (0) {',
		'a pushed item with a changed byte is filed as the one named -- sec 569',
	),
	(
		'reconcile-put-judged-before-bytes',
		'node/reconcile.c',
		'\t\tif (fzn_buckets_gone(&b, (fzn_buckets_kind_t)kind, subject, month)\n\t\t    || (taker->wanted && !taker->wanted(taker->ctx, subject, month)))',
		'\t\tif (0)',
		'a month let go, or one the rules would not hold, is taken from a pusher -- sec 569',
	),
	(
		'reconcile-push-sends-only-what-is-lacked',
		'node/reconcile.c',
		'\t\t\t\tif (n_ids && bsearch(ids[j], peer_ids, n_ids, FZN_BUCKETS_ID_LEN, by_id))\n\t\t\t\t\tcontinue;\n',
		'',
		'a push offers the peer every item, held or not -- sec 569',
	),
	(
		'reconcile-push-agreeing-is-skipped',
		'node/reconcile.c',
		'\t\tif (theirs && theirs->count == k->count\n\t\t    && memcmp(theirs->digest, k->digest, FZN_BUCKETS_ID_LEN) == 0)\n\t\t\tcontinue;\n',
		'',
		"every bucket's ids are listed by every push, agreeing or not -- sec 569",
	),
	(
		'reconcile-push-asks-before-bytes',
		'node/reconcile.c',
		'\t\tif (asking)\n\t\t\tn = 0u;\n',
		'',
		'a push spends a piece on an item the peer will not take, and resends what it holds -- sec 569',
	),
	(
		'node-messages-pushed-owes-own-key',
		'node/messages.c',
		'\tmemset(key, 0, sizeof(key));\n\tnote_key(nm, nm->gives, &nm->n_gives, contact, epoch, device);',
		'\tmemset(key, 0, sizeof(key));',
		'a line pushed to a peer stays a shell there: its key is never given -- sec 569',
	),
	(
		'buckets-a-ref-is-no-row-item',
		'node/buckets.c',
		'\tif (what == 2)\n\t\treturn FZN_BUCKETS_LARGE;\n',
		'',
		"a ref row's bytes are served as if they were the item -- sec 570",
	),
	(
		'reconcile-serves-large-through-its-kind',
		'node/reconcile.c',
		'\t\tlen = (size_t)size;\n\t}\n\tif (err != FZN_BUCKETS_ABSENT',
		'\t\tlen = 0;\n\t}\n\tif (err != FZN_BUCKETS_ABSENT',
		'an item its kind keeps is served as not held -- sec 570',
	),
	(
		'reconcile-fetch-large-needs-its-kind',
		'node/reconcile.c',
		'\t\t\tif (*is_large && (!filer->stage || !filer->finish)) {',
		'\t\t\tif (0) {',
		"a kind with no large hooks is handed a large item's pieces -- sec 570",
	),
	(
		'reconcile-push-large-through-its-kind',
		'node/reconcile.c',
		'\t\tlen = (size_t)size;\n\t\tlarge = 1;',
		'\t\tlen = (size_t)size;\n\t\tlarge = 0;',
		'a large item is pushed from a row that does not hold it -- sec 570',
	),
	(
		'log-buckets-kept-only-signed-by-its-subject',
		'node/log_buckets.c',
		'\t    || !is_signed || memcmp(key, subject, 32u) != 0) {',
		'\t    || 0) {',
		"a segment signed by another key, or unsigned, is kept as the host's copy -- sec 571",
	),
	(
		'log-buckets-kept-under-its-month',
		'node/log_buckets.c',
		' || fzn_message_epoch_of(closed / 1000u) != month)',
		')',
		'a segment offered under another month is kept, and its bucket never agrees -- sec 571',
	),
	(
		'log-buckets-finish-checks-its-id',
		'node/log_buckets.c',
		'\t    || !fzn_buckets_id(lb->hash, lb->staging, lb->staged, got)\n\t    || memcmp(got, id, FZN_BUCKETS_ID_LEN) != 0)\n\t\treturn FZN_NODE_APPLY_REFUSED;\n\tlb->staged = 0;',
		'\t    )\n\t\treturn FZN_NODE_APPLY_REFUSED;\n\tlb->staged = 0;',
		'a segment renamed in flight is kept under the new name -- sec 571',
	),
	(
		'log-buckets-copy-rules-asked',
		'node/log_buckets.c',
		'\tn = fzn_retain_select_source(lb->copy_rules, lb->n_copy, subject, source);',
		'\tn = 0;',
		'copies are fetched whatever the copy rules say -- sec 571',
	),
	(
		'buckets-let-go-is-served-as-not-held',
		'node/buckets.c',
		'\tif (!what || what == 3 || bytes[I_INDEXED] != 1u)\n\t\treturn FZN_BUCKETS_ABSENT;',
		'\tif (!what || bytes[I_INDEXED] != 1u)\n\t\treturn FZN_BUCKETS_ABSENT;',
		'an item let go is still served, from a row that holds no item -- sec 572',
	),
	(
		'buckets-let-go-writes-the-tombstone',
		'node/buckets.c',
		'\tbytes[0] = LET_GO_VERSION;\n\treturn item_save(b, kind, id, bytes, L_LEN) ? FZN_BUCKETS_OK : FZN_BUCKETS_BACKEND;',
		'\tbytes[0] = LET_GO_VERSION;\n\treturn FZN_BUCKETS_OK;',
		'an item let go is still held and served -- sec 572',
	),
	(
		'log-buckets-scan-lets-the-repacked-go',
		'node/log_buckets.c',
		'\t\t\tgone = fzn_buckets_let_go(lb->b, FZN_BUCKETS_LOGS, id);',
		'\t\t\tgone = FZN_BUCKETS_OK;',
		"a repacked segment's old id names a file that no longer hashes to it, refused by every peer -- sec 572",
	),
	(
		'log-buckets-sweep-lets-the-removed-go',
		'node/log_buckets.c',
		'\t\t\t\tif (fzn_buckets_let_go(lb->b, FZN_BUCKETS_LOGS, ids[i]) != FZN_BUCKETS_OK)',
		'\t\t\t\tif (0)',
		'a segment the rules removed is still listed by a ref that reads nothing -- sec 572',
	),
	(
		'buckets-let-go-is-restored-by-its-kind',
		'node/buckets.c',
		'\t\trow_bytes[I_INDEXED] = 1u;\n\t\tif (!item_save(b, kind, id, row_bytes, row_len))\n\t\t\treturn FZN_BUCKETS_BACKEND;\n\t\tif (added)\n\t\t\t*added = 1;\n\t\treturn FZN_BUCKETS_OK;',
		'\t\tif (added)\n\t\t\t*added = 1;\n\t\treturn FZN_BUCKETS_OK;',
		"a log directory moved away and back leaves this host's own segments served as not held for good -- sec 572",
	),
	(
		'copy-name-is-a-packed-segment-s',
		'log/copy.c',
		'strcmp(name + n - 8u, ".log.zst") != 0',
		'0',
		'a file that is no packed segment is read as one, kept or served -- secs 483, 573',
	),
	(
		'copy-name-time-is-digits',
		'log/copy.c',
		"\t\tif (*t < '0' || *t > '9' || v > (UINT64_MAX - 9u) / 10u)",
		'\t\tif (v > (UINT64_MAX - 9u) / 10u)',
		'a segment whose time is not a number reads as closed at a made-up time -- secs 483, 573',
	),
	(
		'messages-a-marked-line-is-not-kept-again',
		'messages/messages.c',
		'\tif (line_marked(m, contact, last->direction, last->id)\n\t    || recently_indexed(',
		'\tif (0\n\t    || recently_indexed(',
		'a line two devices wrote, the second long after, is kept and listed twice -- sec 575',
	),
	(
		'messages-each-line-indexed-is-marked',
		'messages/messages.c',
		'\t       && line_mark(m, contact, direction, id, 1);\n}',
		'\t       ;\n}',
		'no line is ever marked, and a late copy from another device lists twice -- sec 575',
	),
	(
		'messages-a-cleared-index-takes-its-marks',
		'messages/messages.c',
		'\t\tif (!index_entry(m, contact, i, &e) || !line_mark(m, contact, e.direction, e.id, 0))',
		'\t\tif (!index_entry(m, contact, i, &e))',
		'a rebuilt index finds every line marked and lists none -- sec 575',
	),
	(
		'messages-upgrade-marks-old-lines',
		'messages/messages.c',
		'\t\t\tif (!index_entry(m, contact, i, &e) || !line_mark(m, contact, e.direction, e.id, 1))',
		'\t\t\tif (!index_entry(m, contact, i, &e))',
		"a line indexed before marks lists twice when another device's copy arrives late -- sec 575",
	),
	(
		"journal-cut-keeps-the-spine-first",
		"node/journal.c",
		"\tif (stream == FZN_NODE_JOURNAL_STREAM)\n\t\tfor (seq = base; seq < below; seq++)",
		"\tif (0)\n\t\tfor (seq = base; seq < below; seq++)",
		"estate acts are cut with nothing kept, and every act behind the cut stops standing -- sec 548",
	),
	(
		"journal-cut-point-stops-at-the-young",
		"node/journal.c",
		"\t\t    || fzn_record_issued_ms(rec) >= older_than_ms)",
		"\t\t    || 0)",
		"records inside the window are cut with the old -- sec 548",
	),
	(
		"journal-cut-point-stops-at-the-reader",
		"node/journal.c",
		"\tfor (; seq <= limit && seq <= e->received; seq++) {",
		"\tfor (; seq <= e->received; seq++) {",
		"records the reader has not taken in are cut, and what they carried is never kept -- sec 548",
	),
	(
		"messages-cut-keeps-a-line-whole",
		"node/messages.c",
		"\twhile (below > base && line_continues(nm, device, below - 1u))",
		"\twhile (0)",
		"a cut ends on a line's first part, and the line is lost when its last is taken in -- sec 548",
	),
	(
		"settings-window-is-bounded",
		"node/settings.c",
		"\treturn n <= max ? n : 0u;",
		"\treturn n;",
		"a window past 36500 days, or a k past 255, is taken -- sec 548",
	),
	(
		"settings-window-defaults",
		"node/settings.c",
		"\treturn days ? days : FZN_NODE_SETTINGS_WINDOW_DAYS;",
		"\treturn days;",
		"a window that is no count of days is zero days, and the whole journal is cut -- sec 548",
	),
	(
		"settings-clear-kept-for-the-window",
		"node/settings.c",
		"\t\tif (learned >= older_than)\n\t\t\tcontinue;",
		"\t\tif (0)\n\t\t\tcontinue;",
		"a clear is forgotten inside the window, and a late older set puts the value back -- sec 549",
	),
	(
		"settings-sets-never-forgotten",
		"node/settings.c",
		"\t\t    || fzn_setting_open(buf + at, len - at, ns->verify, &s) != FZN_SETTING_OK || s.set)\n\t\t\tcontinue;\n\t\t/* A CLEAR",
		"\t\t    || fzn_setting_open(buf + at, len - at, ns->verify, &s) != FZN_SETTING_OK)\n\t\t\tcontinue;\n\t\t/* A CLEAR",
		"a value in force is forgotten with the clears -- sec 549",
	),
	(
		"settings-unknown-learning-starts-the-window",
		"node/settings.c",
		"\t\tif (learned == 0u) {",
		"\t\tif (0) {",
		"a clear from before the stamp is forgotten at once rather than kept a window -- sec 549",
	),
	(
		"settings-learning-is-stamped",
		"node/settings.c",
		"\treturn row_save(ns, row, rank, ns->now ? ns->now() : 0u, bytes, len)",
		"\treturn row_save(ns, row, rank, 0u, bytes, len)",
		"every setting reads as learned at a time not known, and no clear is ever forgotten -- sec 549",
	),
	(
		"settings-version-floored-on-the-clock",
		"node/settings.c",
		"\tversion = ns->now();\n",
		"\tversion = 0;\n",
		"a write after a forgotten clear reuses a lower version, and a node still holding the clear refuses it for good -- sec 549",
	),
	(
		"holdings-digest-is-ordered",
		"node/holdings.c",
		"\tqsort(ids, c.n, FZN_HOLDINGS_ID_LEN, by_id);\n",
		"\n",
		"two nodes holding the same objects disagree on the digest by the order they learned them -- sec 550",
	),
	(
		"holdings-tag-is-the-class",
		"node/holdings.c",
		"\t\tif (row[start + 1u] == shape->tags[i]) {",
		"\t\tif (1) {",
		"a row holding another kind of object is counted in a class -- sec 550",
	),
	(
		"holdings-length-is-the-class",
		"node/holdings.c",
		"\tif (len - start < n || row[start] != (uint8_t)FZN_SIGNED_VERSION)",
		"\tif (row[start] != (uint8_t)FZN_SIGNED_VERSION)",
		"a row too short for its class's object is read past its end -- sec 550",
	),
	(
		"apply-object-hop-is-signed",
		"node/apply.c",
		"\tif (object[1] == (uint8_t)FZN_OBJECT_HOP) {\n\t\tfzn_chain_hop_t hop;",
		"\tif (0) {\n\t\tfzn_chain_hop_t hop;",
		"a lone hop nobody signed is indexed, kept and counted in every digest -- sec 550",
	),
	(
		"settings-row-setting-past-its-head",
		"node/settings.c",
		"\treturn row && row_read(row, len, &rank, &learned, &head) ? head : 0u;",
		"\treturn 1u;",
		"a stamped setting row is read from inside its head, and its setting is never offered -- sec 550",
	),
	(
		"reconcile-equal-digest-costs-nothing",
		"node/reconcile.c",
		"\t\tif (herr == FZN_HOLDINGS_OK && my_count == their_count[c]\n\t\t    && memcmp(mine, theirs[c], sizeof(mine)) == 0)\n\t\t\tcontinue;",
		"\t\tif (0)\n\t\t\tcontinue;",
		"a class both nodes hold alike is listed and compared every round -- sec 551",
	),
	(
		"reconcile-fetches-only-the-lacked",
		"node/reconcile.c",
		"\t\t\t\tif (!fzn_holdings_among((const uint8_t(*)[FZN_HOLDINGS_ID_LEN])ids_buf,\n\t\t\t\t                        n_mine, id))",
		"\t\t\t\tif (1)",
		"every object a peer holds is fetched again, whether this node holds it or not -- sec 551",
	),
	(
		"reconcile-asks-again-for-what-did-not-fit",
		"node/reconcile.c",
		"\t\t\tstart += batch - j;",
		"\t\t\tstart += batch;",
		"objects that did not fit one reply are dropped for the round -- sec 551",
	),
	(
		"reconcile-serves-only-what-was-asked",
		"node/reconcile.c",
		"\tif (i == s->n_wanted || len > FZN_RECONCILE_OBJECT_MAX)\n\t\treturn 1;",
		"\tif (len > FZN_RECONCILE_OBJECT_MAX)\n\t\treturn 1;",
		"a node answers an objects query with every object of the class -- sec 551",
	),
	(
		"journal-rebase-bridge-reaches-the-base",
		"node/journal.c",
		"\t\t    || memcmp(entries[n_entries - 1u], below, FZN_RECORD_ID_LEN) != 0)\n\t\t\treturn FZN_NODE_JOURNAL_REFUSED;",
		"\t\t    || 0)\n\t\t\treturn FZN_NODE_JOURNAL_REFUSED;",
		"a bridge ending anywhere is taken, and the next record's predecessor is never met -- sec 552",
	),
	(
		"journal-rebase-bridge-is-chained",
		"node/journal.c",
		"\t\t\tif (memcmp(entries[i] + FZN_RECORD_ID_LEN, entries[i - 1u], FZN_RECORD_ID_LEN) != 0)",
		"\t\t\tif (0)",
		"a bridge broken in the middle is taken into the spine -- sec 552",
	),
	(
		"journal-rebase-bridge-starts-at-the-head",
		"node/journal.c",
		"\t\tif (e->has_head && memcmp(entries[0] + FZN_RECORD_ID_LEN, e->head, FZN_RECORD_ID_LEN) != 0)",
		"\t\tif (0)",
		"a bridge from another branch is joined to this journal's head -- sec 552",
	),
	(
		"journal-rebase-keeps-what-it-held",
		"node/journal.c",
		"\t\tfor (seq = own_base; seq <= held; seq++)\n\t\t\tif ((err = fzn_node_journal_spine_keep(nj, key, seq)) != FZN_NODE_JOURNAL_OK)",
		"\t\tfor (seq = own_base; seq < own_base; seq++)\n\t\t\tif ((err = fzn_node_journal_spine_keep(nj, key, seq)) != FZN_NODE_JOURNAL_OK)",
		"the records a rebase puts below the base go without their spine, and their acts stop standing -- sec 552",
	),
	(
		"journal-rebase-counts-the-gap-applied",
		"node/journal.c",
		"\tif (fzn_journal_confirm(&nj->journal, key, stream, base - 1u) != FZN_JOURNAL_OK)\n\t\treturn FZN_NODE_JOURNAL_MALFORMED;\n\treturn FZN_NODE_JOURNAL_OK;\n}",
		"\treturn FZN_NODE_JOURNAL_OK;\n}",
		"apply reads records a rebase knows are gone -- sec 552",
	),
	(
		"reconcile-rebase-pages-on",
		"node/reconcile.c",
		"\t\tfzn_put_be64(request + 38u, held + 1u + have);",
		"\t\tfzn_put_be64(request + 38u, held + 1u);",
		"a bridge longer than one reply repeats its first page -- sec 552",
	),
	(
		"exchange-names-the-missed-stream",
		"record/exchange.c",
		"\t\t\tmemcpy(tally->missed[tally->missing].issuer, want->issuer, FZN_PUBKEY_LEN);",
		"\t\t\t;",
		"a pull counts a stream missing without saying which, and none is ever moved up -- sec 552",
	),
	(
		"reconcile-answer-lists-into-its-own-buffer",
		"node/reconcile.c",
		"\tif (fzn_holdings_ids(store, hash, (fzn_holdings_class_t)cls, served_ids, FZN_HOLDINGS_MAX,",
		"\tif (fzn_holdings_ids(store, hash, (fzn_holdings_class_t)cls, ids_buf, FZN_HOLDINGS_MAX,",
		"an answer overwrites the list a round in the same process is searching, and the round fetches what it holds -- sec 555",
	),
	(
		"reconcile-claims-go-to-the-notes-path",
		"node/reconcile.c",
		"\t\t\t\tswitch (cls == (uint8_t)FZN_HOLDINGS_NOTES",
		"\t\t\t\tswitch (0",
		"a note claim is judged as an estate object and refused -- sec 555",
	),
	(
		"node-notes-history-texts-kept",
		"node/notes.c",
		"\t\tif (memcmp(history_roots[i], root, FZN_BLOB_HASH_LEN) == 0)\n\t\t\treturn 1;\n",
		"\t\tif (memcmp(history_roots[i], root, FZN_BLOB_HASH_LEN) == 0)\n\t\t\tbreak;\n",
		"collection takes an earlier version's text, and the history lists a version nothing can open -- sec 581",
	),
	(
		"node-notes-history-pending-said",
		"node/notes.c",
		"fzn_record_issuer(rec)[7], here ? \"here\" : \"pending\");",
		"fzn_record_issuer(rec)[7], \"here\");",
		"a version whose text has not arrived is listed as here, with no title -- sec 581",
	),
	(
		"node-notes-collect-verb-reads-history",
		"node/notes.c",
		"\tfzn_node_notes_history_refresh(n);\n\tif (!n->collect(n->text_ctx, keep_named, n, &kept, &removed))",
		"\tif (!n->collect(n->text_ctx, keep_named, n, &kept, &removed))",
		"remove text unused weighs a history read by an earlier pass, and takes a version's text kept since -- sec 581",
	),
	(
		"node-notes-history-unread-keeps-all",
		"node/notes.c",
		"\tif (history_unread)\n\t\treturn 1;\n",
		"",
		"a history the store would not list is taken as none, and collection removes every earlier version's text -- sec 581",
	),
	(
		"node-notes-history-items-refused",
		"node/notes.c",
		"\t\tif (historical)\n\t\t\treturn say(reply, cap, FZN_REPLY_MALFORMED,",
		"\t\tif (0)\n\t\t\treturn say(reply, cap, FZN_REPLY_MALFORMED,",
		"an earlier version's items are answered with the current version's, as if they were its own -- sec 583",
	),
	(
		"node-notes-history-gets-the-version-asked",
		"node/notes.c",
		"\terr = fzn_notes_history_get(&n->store, v.at[nth].row, bytes, sizeof(bytes), &len);\n",
		"\terr = fzn_notes_history_get(&n->store, v.at[0].row, bytes, sizeof(bytes), &len);\n",
		"get history answers the oldest version whichever was asked -- sec 583",
	),
	(
		"notes-file-takes-only-claims",
		"node/notes.c",
		"\t    || fzn_record_stream(rec) != FZN_NOTE_STREAM || fzn_record_kind(rec) != FZN_NOTE_KIND)\n\t\treturn FZN_NOTES_ERR_MALFORMED;\n\treturn fzn_notes_put(",
		"\t    || fzn_record_stream(rec) != FZN_NOTE_STREAM)\n\t\treturn FZN_NOTES_ERR_MALFORMED;\n\treturn fzn_notes_put(",
		"a purge record handed over as a claim is filed as one -- sec 555",
	),
	(
		"reconcile-witness-disagreement-refuses",
		"node/reconcile.c",
		"\t\t\tif (memcmp(witnessed[i], bridge[i], FZN_NODE_JOURNAL_SPINE_ENTRY) != 0)\n\t\t\t\treturn FZN_RECONCILE_ERR_CONFLICT;",
		"\t\t\tif (0)\n\t\t\t\treturn FZN_RECONCILE_ERR_CONFLICT;",
		"a bridge a second peer tells otherwise moves the stream anyway -- sec 557",
	),
	(
		"reconcile-base-answer-reaches-the-records",
		"node/reconcile.c",
		"\t\tfor (seq = from; seq <= received && count < 0xffffu",
		"\t\tfor (seq = from; seq < base && count < 0xffffu",
		"a peer that cut less serves no entries, and witnesses nothing -- sec 557",
	),
	(
		"messages-reindex-refuses-a-window",
		"messages/messages.c",
		"\t\tif (fzn_node_journal_base(m->journal, m->devices[d], FZN_MESSAGE_STREAM) > 1u)\n\t\t\treturn FZN_MESSAGES_ERR_WINDOW;",
		"\t\tif (0)\n\t\t\treturn FZN_MESSAGES_ERR_WINDOW;",
		"a reindex clears the index and rebuilds it from a window, losing every line below the base -- sec 560",
	),
	(
		"record-issued-ms-scales-seconds",
		"record/record.h",
		"\treturn at < FZN_RECORD_SECONDS_BELOW ? at * 1000u : at;",
		"\treturn at;",
		"a record stamped in seconds is read as milliseconds, and looks fifty years old -- sec 561",
	),
	(
		"settings-record-stamped-in-ms",
		"node/settings.c",
		"\t                                   ns->now() * 1000u, NULL)",
		"\t                                   ns->now(), NULL)",
		"a setting's journal record is stamped in seconds while every other record is in milliseconds -- sec 561",
	),
	(
		"retain-archive-parse-refuses-selectors",
		"log/retain.c",
		"\tif (out->kind == FZN_RETAIN_ARCHIVE\n\t    && (out->data != FZN_RETAIN_LOG",
		"\tif (0 && out->kind == FZN_RETAIN_ARCHIVE\n\t    && (out->data != FZN_RETAIN_LOG",
		"an archive rule naming messages, history, an entry selector or a copy is taken -- sec 588",
	),
	(
		"retain-archive-rule-ok-refuses-selectors",
		"log/retain.c",
		"\tif (r->kind == FZN_RETAIN_ARCHIVE\n\t    && (r->data != FZN_RETAIN_LOG",
		"\tif (0 && r->kind == FZN_RETAIN_ARCHIVE\n\t    && (r->data != FZN_RETAIN_LOG",
		"an archive rule with an entry selector is weighed as one over whole segments -- sec 588",
	),
	(
		"retain-archive-wins-over-prune",
		"log/retain.c",
		"\t\t\t        (uint8_t)((archived ? FZN_RETAIN_MARK_ARCHIVED\n\t\t\t                            : (pruned || drops ? FZN_RETAIN_MARK_PRUNED : 0u))",
		"\t\t\t        (uint8_t)((archived ? FZN_RETAIN_MARK_ARCHIVED : 0u)\n\t\t\t                  | (pruned || drops ? FZN_RETAIN_MARK_PRUNED : 0u)",
		"a segment both an archive and a prune rule take is marked pruned too, and the entry walk may remove what was to be archived -- sec 588",
	),
	(
		"retain-live-log-leaves-archived-rules-out",
		"log/retain.c",
		"\t\tif (in[i].data == FZN_RETAIN_LOG && !in[i].copy && !in[i].archived\n",
		"\t\tif (in[i].data == FZN_RETAIN_LOG && !in[i].copy\n",
		"a rule meant for the archive prunes the live log, a five-year fossil rule taking this week's log -- sec 589",
	),
	(
		"retain-archive-selection-takes-archived-only",
		"log/retain.c",
		"\t\tif (in[i].data == FZN_RETAIN_LOG && in[i].archived\n",
		"\t\tif (in[i].data == FZN_RETAIN_LOG\n",
		"the live log's rules and its drop policy reach the archive, and empty the fossil class -- sec 589",
	),
	(
		"retain-archived-parse-refuses",
		"log/retain.c",
		"\tif (out->archived\n\t    && ((out->kind != FZN_RETAIN_PRUNE && out->kind != FZN_RETAIN_KEEP)",
		"\tif (0 && out->archived\n\t    && ((out->kind != FZN_RETAIN_PRUNE && out->kind != FZN_RETAIN_KEEP)",
		"a rule over the archive naming an entry selector, a copy or another kind's data is taken -- sec 589",
	),
	(
		"pack-archive-keep-holds",
		"log/pack.c",
		"\t\tif (!segs[i].packed || !(marks[i] & FZN_RETAIN_MARK_ARCHIVED)\n\t\t    || (marks[i] & FZN_RETAIN_MARK_KEPT))",
		"\t\tif (!segs[i].packed || !(marks[i] & FZN_RETAIN_MARK_ARCHIVED))",
		"a segment a keep rule covers is archived out of the live log anyway -- sec 588",
	),
	(
		"pack-archive-packed-only",
		"log/pack.c",
		"\t\tif (!segs[i].packed || !(marks[i] & FZN_RETAIN_MARK_ARCHIVED)\n",
		"\t\tif (!(marks[i] & FZN_RETAIN_MARK_ARCHIVED)\n",
		"a plain segment is archived before it is packed, so the archive holds a fossil with no trailer to verify -- sec 588",
	),
	(
		"log-buckets-archived-still-held",
		"node/log_buckets.c",
		"\t\tif (k > 0 && (size_t)k < PATH_MAX_ && lb->archive[0] && access(path, F_OK) != 0)\n\t\t\tk = snprintf(path, PATH_MAX_, \"%s/%s\", lb->archive, r + 2);",
		"\t\tif (0)\n\t\t\tk = snprintf(path, PATH_MAX_, \"%s/%s\", lb->archive, r + 2);",
		"an archived segment is let go as a file gone, and fetched back from a peer -- sec 588",
	),
	(
		"log-buckets-archived-copy-still-held",
		"node/log_buckets.c",
		"\t\tif (k > 0 && (size_t)k < PATH_MAX_ && lb->archive[0] && access(path, F_OK) != 0)\n\t\t\tk = snprintf(path, PATH_MAX_, \"%s/copy/%s/%s\", lb->archive",
		"\t\tif (0)\n\t\t\tk = snprintf(path, PATH_MAX_, \"%s/copy/%s/%s\", lb->archive",
		"a copy archived is let go as a file gone, and taken again from its host -- sec 590",
	),
	(
		"settings-address-port-in-range",
		"node/settings.c",
		"\tp = count_of(value + space + 1u, len - space - 1u, 65535u);\n\tif (!p)\n\t\treturn 0;\n",
		"\tp = count_of(value + space + 1u, len - space - 1u, 65535u);\n",
		"a member's address with port 0 or no port at all is taken, and its siblings send to port 0 -- sec 579",
	),
	(
		"settings-address-host-characters",
		"node/settings.c",
		"\t\t      || c == '.' || c == '-' || c == ':'))\n\t\t\treturn 0;\n",
		"\t\t      || c == '.' || c == '-' || c == ':'))\n\t\t\tcontinue;\n",
		"a member's address may hold any byte, and a host name with a slash or a control byte is handed to the resolver -- sec 579",
	),
	(
		"siblings-prekey-carried-by-its-host",
		"node/siblings.c",
		"\t    || !fzn_ct_memeq(record.host, carrier, FZN_PUBKEY_LEN)\n",
		"",
		"a member carries another host's prekey and every sibling pairs a key the member chose -- sec 579",
	),
	(
		"siblings-prekey-newest-kept",
		"node/siblings.c",
		"\t\tif (held.created_at >= record.created_at)\n\t\t\treturn FZN_NODE_SIBLINGS_STALE;\n",
		"",
		"an older prekey replayed replaces a sibling's newer one, and siblings pair a key it retired -- sec 579",
	),
	(
		"apply-prekey-waits-for-a-chain",
		"node/apply.c",
		"\tint judged = fzn_node_apply_rank(ap, signer, FZN_SCOPE_HOST, signer, &rank);\n\n\tif (judged == 0)\n\t\treturn WAIT;\n",
		"\tint judged = fzn_node_apply_rank(ap, signer, FZN_SCOPE_HOST, signer, &rank);\n\n\tif (judged == 0)\n\t\tjudged = 1;\n",
		"a stranger's prekey, carried in a stream with no chain, is kept as a sibling's and paired -- sec 579",
	),
	(
		"apply-chain-walks-a-delegable-grant-first",
		"node/apply.c",
		"\t\t\t    && ap->grants[i].hop[FZN_HOP_OFF_DELEGABLE] == 1u)\n",
		"\t\t\t    && 0)\n",
		"a member's chain is walked through a sibling's grant, and a revoked sibling takes the member's records with it -- sec 579",
	),
	(
		"pairing-from-grant-ends-at-this-device",
		"node/pair.c",
		"\t    || !fzn_ct_memeq(verified.grantee, device->pubkey, FZN_PUBKEY_LEN))\n\t\treturn FZN_NODE_PAIR_REFUSED;\n\t/* THE PREKEY IS THE GRANTOR'S",
		"\t    )\n\t\treturn FZN_NODE_PAIR_REFUSED;\n\t/* THE PREKEY IS THE GRANTOR'S",
		"a device builds a pairing from another device's grant, and a session the sponsor holds no peer for -- sec 579",
	),
	(
		"pairing-from-grant-prekey-is-the-grantors",
		"node/pair.c",
		"\t    || !fzn_ct_memeq(record.host, fzn_hop_grantor(hops[hop_count - 1u]), FZN_PUBKEY_LEN))\n",
		"\t    )\n",
		"a pairing to a sibling is built over another node's prekey, so its requests seal to a key the sibling does not hold -- sec 579",
	),
	(
		"admin-sibling-served-already-left",
		"node/admin.c",
		"\t\tif (fzn_ct_memeq(admin->state->peers[i].sender, record.host, FZN_PUBKEY_LEN))\n\t\t\treturn 0;\n",
		"",
		"a member this node admitted is paired again as a sibling, and loses the delegable grant it joined with -- sec 579",
	),
	(
		"apply-object-revocation-signer-is-its-issuer",
		"node/apply.c",
		"\t\tat = FZN_REV_OFF_ISSUER;",
		"\t\tat = 2u;",
		"a reconciled revocation is judged under its capability's bytes as a key, and never applies -- sec 562",
	),
	(
		"admin-remote-needs-admin-rank",
		"node/admin.c",
		"\t               == 1\n\t       && rank >= FZN_SETTING_RANK_ADMIN;",
		"\t               == 1;",
		"a member with only its own host's rank runs every verb remotely -- secs 543, 562",
	),
	(
		"admin-removal-says-a-higher-rank-keeps-it",
		"node/admin.c",
		"\t\treturn answer_text(reply, cap, FZN_REPLY_ERROR,\n\t\t                   \"a higher rank keeps the rule, which this node's clear does not reach\");",
		"\t\treturn answer_text(reply, cap, FZN_REPLY_OK, NULL);",
		"a removal a higher rank outlasts answers ok, and the operator believes the rule gone -- secs 541, 562",
	),
	(
		"node-messages-give-as-sender",
		"node/messages.c",
		"\t\tif (fzn_messages_key_take(&nm->m, e, fzn_get_be32(e + FZN_PUBKEY_LEN), sender,",
		"\t\tif (fzn_messages_key_take(&nm->m, e, fzn_get_be32(e + FZN_PUBKEY_LEN), nm->m.issuer,",
		"a key a member gives is kept as the taker's own, under a device that never drew it -- sec 527",
	),
	(
		"node-messages-take-only-asked",
		"node/messages.c",
		"\t\t\twas_asked = key_place_is(&asked[j], e, epoch, device);",
		"\t\t\twas_asked = 1;",
		"a KEYS answer plants a key for any place it names -- sec 527",
	),
	(
		"node-messages-answer-no-more-than-asked",
		"node/messages.c",
		"\t    || reply[1] != FZN_NODE_MESSAGES_KEYS || reply[2] > n",
		"\t    || reply[1] != FZN_NODE_MESSAGES_KEYS",
		"an answer carrying more keys than were asked is read -- sec 527",
	),
	(
		"node-messages-give-only-own",
		"node/messages.c",
		"\t} else if (held) {\n\t\tdrop_key(nm->lacks, &nm->n_lacks, contact, epoch, device);",
		"\t} else if (held) {\n\t\tnote_key(nm, nm->gives, &nm->n_gives, contact, epoch, device);\n\t\tdrop_key(nm->lacks, &nm->n_lacks, contact, epoch, device);",
		"another device's key is given as this node's own -- sec 527",
	),
	(
		"node-messages-cursor-kept",
		"node/messages.c",
		"\t\t\tif (same_key(nm->cursors[k].key, nm->devices[d]))",
		"\t\t\tif (0)",
		"every absorb reads every stream from the beginning again -- sec 527",
	),
	(
		"node-messages-own-user-only",
		"node/messages.c",
		"\tif (origin != FZN_ORIGIN_SAME_USER)\n\t\treturn say(reply, reply_cap, FZN_REPLY_DENIED, \"messages need this node's own user\");",
		"\tif (0)\n\t\treturn say(reply, reply_cap, FZN_REPLY_DENIED, \"messages need this node's own user\");",
		"another user on the machine reads and writes the conversations -- sec 527",
	),
	(
		"messages-page-from-the-index",
		"messages/messages.c",
		"\tif (contact) {\n\t\tfor (i = count_of(m, contact); i > 0u; i--)",
		"\tif (0) {\n\t\tfor (i = count_of(m, contact); i > 0u; i--)",
		"one conversation's page reads every conversation's records -- sec 528",
	),
	(
		"messages-absorb-past-the-cursor",
		"messages/messages.c",
		"\tint fresh = seq > *done;",
		"\tint fresh = 1;",
		"an absorb takes in again what was taken in, and indexes it twice -- sec 528",
	),
	(
		"messages-absorb-oldest-first",
		"messages/messages.c",
		"\t\t\t    || fzn_record_issued_at(heads[d]) < fzn_record_issued_at(heads[best]))",
		"\t\t\t    || 0)",
		"streams are taken in device by device, so a rebuilt conversation is out of order -- sec 528",
	),
	(
		"messages-newest-read-wins",
		"messages/messages.c",
		"\t    && len == READ_ROW_LEN && fzn_get_be64(held + FZN_MESSAGE_ID_LEN) > at)",
		"\t    && len == READ_ROW_LEN && 0)",
		"an older read position arriving later replaces a newer one -- sec 528",
	),
	(
		"messages-unread-stops-at-read",
		"messages/messages.c",
		"\t\tif (has_read && memcmp(e.id, read_id, FZN_MESSAGE_ID_LEN) == 0)",
		"\t\tif (0)",
		"unread counts every line in, read or not -- sec 528",
	),
	(
		"messages-import-checks-held",
		"messages/messages.c",
		"\tif (fzn_messages_held(m, contact, direction, id))\n\t\treturn FZN_MESSAGES_OK;",
		"\tif (0)\n\t\treturn FZN_MESSAGES_OK;",
		"an import writes a line the user's devices already hold, once per device that held it -- sec 528",
	),
	(
		"messages-own-line-indexed-at-once",
		"messages/messages.c",
		"\tif (took_own(m, before)\n\t    && (!fzn_message_line_read(bodies[parts - 1u], body_len[parts - 1u], &last)",
		"\tif (0\n\t    && (!fzn_message_line_read(bodies[parts - 1u], body_len[parts - 1u], &last)",
		"a line written here is not in its conversation until an absorb -- sec 528",
	),
	(
		"node-messages-write-is-fresh",
		"node/messages.c",
		"\tnm->fresh = 1;\n\treturn say(reply, cap, FZN_REPLY_OK, NULL);\n}\n\n/* `get message",
		"\treturn say(reply, cap, FZN_REPLY_OK, NULL);\n}\n\n/* `get message",
		"a write through the verbs waits for the next round to travel -- sec 528",
	),
	(
		"gui-empty-trash-asks-first",
		"gui/notebook_view.cpp",
		"\tconnect(m_empty, &QPushButton::clicked, this, [this]() { ask_empty_trash(); });",
		"\tconnect(m_empty, &QPushButton::clicked, this, [this]() { empty_trash(); });",
		"one click erases the trash, which cannot be undone -- sec 529",
	),
	(
		"gui-new-folder-asks-name",
		"gui/notebook_view.cpp",
		"\tconnect(m_new_folder, &QPushButton::clicked, this, [this]() { ask_new_folder(); });",
		"\tconnect(m_new_folder, &QPushButton::clicked, this, [this]() { new_folder(QStringLiteral(\"New folder\")); });",
		"every folder is made as \"New folder\", its name never asked -- sec 529",
	),
	(
		"gui-create-waits-for-a-name",
		"gui/notebook_view.cpp",
		"\t\tm_folder_create->setEnabled(false);\n",
		"",
		"Create is offered before a name is typed -- sec 529",
	),
	(
		"opjournal-refused-entry-takes-bytes-back",
		"node/opjournal.c",
		"\t\tif (e->flags & FZN_OPJOURNAL_BYTES_KEPT) {\n\t\t\t(void)oj->base->remove(oj->base->ctx, FZN_PERSIST_OP_BYTES, key);",
		"\t\tif (0) {\n\t\t\t(void)oj->base->remove(oj->base->ctx, FZN_PERSIST_OP_BYTES, key);",
		"bytes kept for an entry the journal refused stay, under a place the next entry then takes -- sec 524",
	),
	(
		"store-file-forget-closes-cache",
		"record/store_file.c",
		"\t\tfzn_record_store_file_close(file);\n\treturn unlink(path)",
		"\t\t;\n\treturn unlink(path)",
		"a forgotten stream's descriptor stays cached, and the next write to it lands in the unlinked file -- sec 524",
	),
	(
		"note-payload-partitions",
		"notes/note.c",
		"\tif (n2 > payload_len || FZN_NOTE_PAYLOAD_HEADER_LEN + n1 + n2 + n3 != payload_len)\n\t\treturn FZN_NOTE_ERR_PARTITION;",
		"\tif (n2 > payload_len || FZN_NOTE_PAYLOAD_HEADER_LEN + n1 + n2 + n3 > payload_len)\n\t\treturn FZN_NOTE_ERR_PARTITION;",
		"a payload whose lengths leave bytes over is two encodings of one note, and bytes nobody owns ride inside a sealed blob -- sec 513",
	),
	(
		"note-meta-is-exactly-its-length",
		"notes/note.c",
		"\tif (content_len != FZN_NOTE_META_LEN)\n\t\treturn FZN_NOTE_ERR_PARTITION;",
		"",
		"a meta with trailing bytes is a second encoding of one record's note -- sec 513",
	),
	(
		"note-meta-knows-its-flags",
		"notes/note.c",
		"\tif (content[FZN_NOTE_META_OFF_FLAGS] & ~FZN_NOTE_META_FLAGS_KNOWN)\n\t\treturn FZN_NOTE_ERR_TYPE;\n\tout->flags",
		"\tout->flags",
		"a version-2 note claiming TEXT_IS_BLOB, or a flag this build does not know, reads as one it does -- sec 513",
	),
	(
		"note-payload-bounds-the-title",
		"notes/note.c",
		"\tif (n1 > FZN_NOTE_TITLE_MAX || n3 > FZN_NOTE_LABELS_MAX)\n\t\treturn FZN_NOTE_ERR_LEN;\n\t/* THE PARTITION",
		"\t/* THE PARTITION",
		"a title or labels past the bounds a listing caches overflow the cache entry every note gets -- sec 513",
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
