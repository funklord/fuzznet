/*
 * ==========================================================================
 * THE SPECIFICATION, AND THE SETTLED IN-MEMORY CORE THAT IMPLEMENTS PART OF IT.
 * ==========================================================================
 *
 * This file was a specification only from 2026-09-10 (F1-F33 below, written
 * by the fuzzypickles session). On 2026-09-18 the copyright holder assigned
 * fuzznet the SETTLED core, and the declarations at the end of this file --
 * the model types, F19 one-spelling normalisation, F27 malformed-refusal and
 * the F20 collation key -- are implemented in `facet/facet.c`. project.md
 * sec 101 records the history and the assignment.
 *
 * NOTHING IS STILL ONLY PROSE, as of 2026-09-21. This paragraph listed four
 * unsettled things -- the wire encoding, the index interface, the collation
 * key's digit-run width and the module name -- and all four are answered:
 * `facet/codec.h` (sec 342), `fzn_facet_index_ops_t` with
 * `fzn_facet_evaluate` below, the width declared by the DIMENSION (sec 343),
 * and the name, which is `facet` (sec 344). Section 8 carries each answer.
 *
 * THE RULE THAT GOVERNED THE GAP IS WORTH KEEPING even with the gap closed,
 * because the next unsettled thing will want it. It is fuzzypickles'
 * `core/src/record_store_internal.h`, which learned it the expensive way:
 * "a header full of declarations reads as available machinery. Including it
 * compiled fine and failed at LINK time." So a function appears below ONLY
 * where `facet.c` or `codec.c` defines it; an unsettled operation has no
 * declaration to link against by accident, and its absence is the status
 * line.
 *
 * The normative statements F1-F33 stand unchanged and remain what any
 * implementation -- this partial one included -- must satisfy.
 */

/* Naming a set of catalogue nodes, in a form that means the same thing
 * everywhere.
 *
 * A consumer with a catalogue needs to say WHICH files it means -- for a view,
 * a playlist, a placement rule, a delete. project.md sec 101 records the
 * design and the arguments; this file is the specification, and states the
 * rules without re-arguing them. Where the two disagree, sec 101 is the
 * history and this is what an implementation must satisfy.
 *
 * WHAT THIS IS NOT. It is not a query engine and not a graph database. There
 * is no planner, no cost model, no relevance ranking and no traversal. Every
 * term is answerable from an index, so every expression is set arithmetic over
 * posting lists; a dependency closure -- MAME's cloneof, a BIOS set -- is a
 * different operation and is not expressible here, deliberately.
 *
 * MECHANISM, NEVER MEANING, which is `local/vocabulary.h`'s rule and
 * `chain.h`'s before it: a capability is 32 opaque bytes that the chain
 * verifies without learning what it permits, and a DIMENSION name is opaque
 * bytes that this module orders and intersects without learning what it
 * classifies. `genre`,
 * `year` and `format` belong to a media library; `system`, `region` and
 * `players` to an emulator front end. Sec 5 keeps command vocabularies out of
 * the core for the same reason.
 *
 * STATUS: the core, evaluation against an index and the wire encoding are all
 * implemented -- facet.c and codec.c -- and the module's name is `facet`,
 * settled by the copyright holder on 2026-09-21. The spec was settled
 * 2026-09-10 with fuzzypickles' copyright holder; what F19's single-child
 * RANGE collapse still cannot do without a taxonomy is pinned in section 8
 * rather than assumed.
 */

#ifndef FZN_FACET_H
#define FZN_FACET_H

/* =========================================================================
 * 1. THE MODEL
 * =========================================================================
 *
 * F1. A catalogue is a set of DIMENSIONS. Each dimension is a TREE of nodes,
 *     and each dimension contains every file in the catalogue. A file appears
 *     under a dimension once per value it has for that dimension, so it may
 *     appear several times within one.
 *
 * F2. A dimension whose values have no children is a tree of depth one. A
 *     KEY-VALUE CLASSIFICATION is therefore the degenerate case of the model
 *     and not a second mechanism.
 *
 *     It read "a key-value facet" until 2026-09-21, which made one word name
 *     both the model and its own special case -- and the module is called
 *     facet. Reworded rather than renamed when the name was settled: see
 *     section 8.
 *
 * F3. Every dimension is TOTAL: a file with no value for a dimension appears
 *     in that dimension's UNKNOWN node. Without F3 a dimension stops
 *     containing every file and the model's central property is lost.
 *
 * F4. A dimension is either CURATED or GENERATED. A generated dimension is
 *     derived from ground truth -- what a host holds, where a file sits -- and
 *     is recomputed rather than edited. A curated dimension is asserted by an
 *     issuer.
 *
 * =========================================================================
 * 2. TERMS
 * =========================================================================
 *
 * F5. A TERM denotes a set of files. Three kinds are specified:
 *
 *       PREFIX       a node; denotes every file at or beneath it
 *       RANGE        an ordered span of a node's children
 *       ALTERNATION  several siblings under one parent; their union
 *
 * F6. PREFIX rolls up: selecting `genre/house` includes a file whose only
 *     value is `genre/house/deep`.
 *
 * F7. RANGE compares by the child's COLLATION KEY (F20), with inclusive and
 *     exclusive bounds and either bound open.
 *
 * F8. ALTERNATION binds to a single dimension. A construction whose members
 *     lie in different dimensions is MALFORMED (F27); admitting it would be
 *     expression-level union, which F13 forbids.
 *
 * F9. The UNKNOWN node of F3 is NOT a member of a dimension's ordered value
 *     index. No RANGE term selects it, whatever its bounds, including open
 *     ones. A PREFIX term on the dimension root does select it, which is what
 *     makes F3 hold. Selecting "in this range, or unknown" is an ALTERNATION
 *     of a RANGE and the unknown node.
 *
 * F10. A term kind carries a TAG. Kinds may be added; see F26.
 *
 * =========================================================================
 * 3. EXPRESSIONS
 * =========================================================================
 *
 * F11. An EXPRESSION is a pair of term sets, written (P, N).
 *
 * F12. It denotes  (intersection of every term in P) minus (union of every
 *      term in N).
 *
 * F13. There is no expression-level union. Union exists only inside a term,
 *      as ALTERNATION. This is what keeps an expression order-independent:
 *      intersection and difference commute, union does not.
 *
 * F14. P MUST NOT be empty. There is no bare negation; difference subtracts
 *      from a set the expression itself selected. Note this constrains the
 *      LEFT side only -- a term in N may name any dimension, including one no
 *      term in P mentions.
 *
 * F15. A dimension root is a legal member of P, including the root of the
 *      whole catalogue. The guard against an unbounded result is F24, not a
 *      restriction on which node may be selected.
 *
 * =========================================================================
 * 4. CANONICAL FORM
 * =========================================================================
 *
 * An expression has exactly one encoding, so that equal expressions are
 * byte-equal and may be hashed for identity, deduplication and cache keys.
 *
 * F16. P and N are each sorted by BYTE-WISE COMPARISON of each term's
 *      canonical encoding: memcmp order, and where one encoding is a prefix
 *      of another the shorter sorts first.
 *
 * F17. Sorting uses the term's RAW bytes and MUST NOT use the collation key
 *      of F20. That key is lossy -- `7` and `07` share one -- so two distinct
 *      terms would sort equal and the order would not be total.
 *
 * F18. F16 applies recursively: ALTERNATION members are sorted and
 *      deduplicated by the same rule.
 *
 * F19. One spelling per thing. A single-member ALTERNATION MUST be encoded as
 *      a PREFIX term; a RANGE whose bounds denote one child MUST be encoded as
 *      a PREFIX term. Duplicate terms within P, or within N, are removed.
 *
 * F20. A COLLATION KEY is derived from a value by zero-padding each run of
 *      decimal digits to a fixed width, so that byte order matches the order a
 *      reader expects: `9` sorts before `10`, `720p` before `1080p`. A
 *      dimension may instead declare raw byte order where natural order is
 *      wrong for it. The key is used for F7 and for display, never for F16.
 *
 *      THE WIDTH IS DECLARED BY THE DIMENSION, settled by the copyright
 *      holder on 2026-09-21. A dimension already declares whether it is
 *      ordered naturally or by raw bytes, so the width joins the declaration
 *      it belongs beside: a year dimension pads to 4 and a file-size
 *      dimension to 10, and neither pays for the other's range. One number
 *      for the whole catalogue would have made every dimension accept one
 *      bet; see sec 343 for the measurement.
 *
 *      A RUN AT OR ABOVE THE WIDTH IS NOT PADDED, so the key is never lossy
 *      upward -- and it then MISORDERS against a longer run, because `9999`
 *      unpadded sorts after `10000` unpadded. No width removes that; it only
 *      moves where it starts. So `fzn_facet_collate` REPORTS it, and a caller
 *      doing F7 must treat the report as a refusal rather than compare the
 *      key: a RANGE evaluated on a misordering key selects the wrong files,
 *      which is what F25 forbids substituting for a refusal.
 *
 * F21. Canonicalisation is SYNTACTIC and MUST NOT be semantic. Terms that are
 *      semantically redundant are not simplified: `genre/house` beside
 *      `genre/house/deep` does not collapse, though the second is contained in
 *      the first. Collapsing would require the taxonomy, which would make
 *      identity depend on a taxonomy version and change under a re-parent.
 *      Two expressions selecting the same files may be different expressions.
 *
 * =========================================================================
 * 5. IDENTIFIERS
 * =========================================================================
 *
 * F22. A term in a CURATED dimension holds a node IDENTIFIER, not a path. A
 *      path is a route and an identifier is an identity, as a filesystem path
 *      is to an inode. A path is resolved to identifiers once, when the term
 *      is constructed.
 *
 *      Consequently a RENAME changes a label and a RE-PARENT changes a parent,
 *      and neither changes identity: an expression survives both, and after a
 *      re-parent still selects the same files.
 *
 * F23. Identifiers are allocated in the issuer's own namespace, as records
 *      already are per (issuer, stream). Where an external authority supplies
 *      one -- a MusicBrainz id, a TMDB id, a No-Intro entry -- that identifier
 *      is used, being stable by construction.
 *
 *      Identifiers do NOT survive a MERGE, where two nodes prove to be one and
 *      the loser is retired: identity genuinely changes there and only a
 *      forwarding record carries an expression across. A SPLIT cannot be
 *      resolved automatically at all -- the old identifier is ambiguous -- and
 *      MUST be surfaced rather than guessed.
 *
 *      A GENERATED dimension needs no identifiers. Its nodes are recomputed,
 *      and the ground truth is the identity.
 *
 * =========================================================================
 * 6. REFUSAL
 * =========================================================================
 *
 * The safety core. Each condition below is a case where evaluating would
 * return a set that is WRONG rather than incomplete, and a wrong set may drive
 * a placement or a deletion.
 *
 * F24. An implementation MUST refuse an expression when a term in N cannot be
 *      evaluated completely on this host.
 *
 *      The asymmetry is the reason. An incomplete term in P under-reports:
 *      rows are missing, which is an absence a person can see. An incomplete
 *      term in N OVER-reports, because subtracting an incomplete set removes
 *      too little, so files that should have been excluded appear and nothing
 *      says so.
 *
 * F25. An implementation MUST NOT substitute a partial answer for a refusal,
 *      and MUST NOT pin an expression to a stale index to make it evaluable.
 *      A pinned expression stops including files added later, which is a
 *      portable and wrong answer where refusing is neither.
 *
 * F26. An implementation MUST refuse an expression containing a term kind it
 *      does not know, and MUST NOT skip such a term. Skipping evaluates a
 *      DIFFERENT expression while reporting success. `record/record.h` already
 *      refuses a buffer for its shape or its version rather than skipping what
 *      it does not recognise; this is that convention applied.
 *
 * F27. An implementation MUST refuse a MALFORMED expression: P empty (F14),
 *      an ALTERNATION spanning dimensions (F8), a term present in both P and
 *      N, or an encoding violating F16 to F19.
 *
 *      A term in both P and N always denotes the empty set and cannot be
 *      produced by a tri-state editor, where a node is plus, minus or unset;
 *      it arrives only from a hand-written rendering, and refusing catches a
 *      mistake. This does NOT describe a parent in P with a child in N, which
 *      is a different term and is well formed.
 *
 * F28. A failed parse of a rendering is a refusal, never an approximation.
 *
 * =========================================================================
 * 7. RENDERINGS
 * =========================================================================
 *
 * F29. The canonical form is the STRUCTURED value. The path and text forms are
 *      renderings of it and are never what is stored, synced or hashed.
 *
 * F30. The PATH rendering is PARTIAL. Difference has no natural spelling in a
 *      path, so an expression with a non-empty N has no path form unless a
 *      consumer defines a segment convention for it. A filesystem view can
 *      therefore offer positive-only expressions.
 *
 * F31. The TEXT rendering is total, and parsing it is fallible: see F28. A
 *      text rendering resolves against the READER's taxonomy, so sharing a
 *      saved expression shares the structured form and not the text.
 *
 * F32. An editor's node states -- unset, plus, minus -- ARE P and N. An editor
 *      edits the structured value directly and does not round-trip through a
 *      rendering.
 *
 * F33. Two marks in ONE dimension combine as ALTERNATION; marks in different
 *      dimensions combine as intersection. An editor that made two marks in
 *      one dimension intersect would return the empty set for the commonest
 *      gesture a person makes.
 *
 * =========================================================================
 * 8. NOT SETTLED HERE
 * =========================================================================
 *
 * Named rather than guessed at, and all four are now answered. The list is
 * kept rather than deleted because what a spec DID NOT decide, and when it
 * was decided instead, is the part a later reader cannot reconstruct:
 *
 *   - THIS MODULE'S NAME: `facet`, 2026-09-21, and sec 344. Kept rather than
 *     changed. The one argument against it was internal -- F2 called a flat
 *     key-value classification "a facet", so the word named both the model
 *     and its own degenerate case -- and that is a sentence, fixed above,
 *     where a rename was 34 symbols, 21 macros and 682 occurrences. The word
 *     is also right: faceted classification is hierarchical in the field it
 *     comes from, which is F1's tree of dimensions exactly.
 *   - THE COLLATION KEY'S DIGIT-RUN WIDTH (F20): declared by the DIMENSION,
 *     2026-09-21, beside the raw-byte-order declaration a dimension may
 *     already make. `fzn_facet_dimension_t` below, and sec 343. It stays a
 *     parameter of `fzn_facet_collate` -- what changed is that the parameter
 *     now has an owner.
 *
 *   - THE WIRE ENCODING of a term and an expression: `facet/codec.h`, and
 *     project.md sec 342. It needed no decision -- F16 to F19 had already
 *     fixed the canonical form, the sort, the recursion into members and the
 *     one-spelling rules, leaving the byte layout and the arithmetic. Two of
 *     the spec's rules became STRUCTURAL there rather than checked: F8's one
 *     dimension per alternation is hoisted out of the members, so a spanning
 *     alternation cannot be spelled, and F7's `inclusive` is folded into a
 *     single bound byte, so "open and inclusive" is not a combination that
 *     exists.
 *   - THE INDEX INTERFACE an implementation evaluates against: it is
 *     `fzn_facet_index_ops_t` below, with `fzn_facet_evaluate` over it, and
 *     has been since the evaluation work landed. This list went on calling it
 *     open afterwards, which is the kind of sentence that sends the next
 *     reader at work already done. The property it fixed stands: prefix and
 *     range are the same operation on one ORDERED index, a prefix p being the
 *     range [p, p+0xFF...).
 *
 * WHAT THE ENCODING STILL CANNOT CHECK, pinned so nobody quotes it for more
 * than it gives: F19's single-child RANGE collapse needs the taxonomy, so a
 * decoded expression is canonical in every respect except that one.
 * `fzn_facet_normalize` defers it for the same reason.
 */

/* =========================================================================
 * THE SETTLED IN-MEMORY CORE
 * =========================================================================
 *
 * Everything below is implemented in facet/facet.c and satisfies the settled
 * parts of the spec above. It is the in-memory model, its structural checks,
 * and the collation key -- NOT the wire encoding, NOT evaluation against an
 * index, and NOT the F16 canonical sort (which needs the encoding). Terms hold
 * BORROWED views into the caller's bytes, fuzznet's zero-copy style: nothing
 * here allocates or copies, and every array is the caller's storage.
 */

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_facet_err {
	FZN_FACET_OK = 0,
	/* The caller's bug: a null, or an output buffer too small. */
	FZN_FACET_ERR_MALFORMED = 1,
	/* F27/F14: P is empty. */
	FZN_FACET_ERR_EMPTY_POS = 2,
	/* F27/F8: an alternation whose members span dimensions. */
	FZN_FACET_ERR_ALT_DIMENSION = 3,
	/* F27: a term present in both P and N. */
	FZN_FACET_ERR_BOTH_SIDES = 4,
	/* F26: a term kind this build does not know. */
	FZN_FACET_ERR_KIND = 5,
	/* The collation output buffer is too small for the padded key, or an
	 * evaluation result or scratch buffer is too small. */
	FZN_FACET_ERR_RANGE = 6,
	/* F24: a term in N could not be evaluated completely on this host, so
	 * subtracting it would over-include. Evaluation refuses rather than
	 * return a set that is wrong. */
	FZN_FACET_ERR_INCOMPLETE = 7,
} fzn_facet_err_t;

/* F5, F10: the term kinds this build knows. A tag; kinds may be added (F26),
 * and an unknown one is refused rather than skipped. */
typedef enum fzn_facet_kind {
	FZN_FACET_PREFIX = 1, /* F5, F6: a node; every file at or beneath it. */
	FZN_FACET_RANGE  = 2, /* F5, F7: an ordered span of a node's children. */
	FZN_FACET_ALT    = 3, /* F5, F8: siblings under one parent; their union. */
} fzn_facet_kind_t;

/* F22-F23: a node is an opaque IDENTIFIER within an opaque DIMENSION. This
 * module never learns what either classifies -- `local/vocabulary.h`'s rule.
 * Both are borrowed views; the caller owns the bytes. */
typedef struct fzn_facet_node {
	const uint8_t *dim;
	size_t         dim_len;
	const uint8_t *id;
	size_t         id_len;
} fzn_facet_node_t;

/* F7: a RANGE bound is a child of the range's parent, or OPEN. A bound with a
 * NULL `id` (or `id_len` 0) is open on that side; `inclusive` applies only to
 * a closed bound. Bounds are compared by collation key (F20), which is a
 * property of evaluation and so not exercised by this core. */
typedef struct fzn_facet_bound {
	const uint8_t *id;
	size_t         id_len;
	int            inclusive;
} fzn_facet_bound_t;

/* A term (F5). The active fields depend on `kind`:
 *   PREFIX  -- `node` is the node.
 *   RANGE   -- `node` is the parent; `lo` and `hi` are the bounds.
 *   ALT     -- `members` are the sibling nodes (F8: all one dimension);
 *              `node` is unused. */
typedef struct fzn_facet_term {
	fzn_facet_kind_t kind;
	fzn_facet_node_t node;
	fzn_facet_bound_t lo, hi;
	const fzn_facet_node_t *members;
	size_t                  member_count;
} fzn_facet_term_t;

/* An expression is the pair (P, N) (F11): borrowed views of the caller's two
 * term arrays. F14 requires P non-empty; fzn_facet_validate enforces it. */
typedef struct fzn_facet_expr {
	const fzn_facet_term_t *pos;
	size_t                  pos_count;
	const fzn_facet_term_t *neg;
	size_t                  neg_count;
} fzn_facet_expr_t;

/* Structural equality of two terms: same kind and same fields, with ALT
 * members compared as a SET (order-independent, per F18). This is the basis
 * for F19 dedup and the F27 both-sides check. It is NOT the F16 canonical
 * ordering, which compares canonical-encoding bytes the wire format has not
 * fixed; equality does not need an order, so it is settled and this is not. */
int fzn_facet_term_eq(const fzn_facet_term_t *a, const fzn_facet_term_t *b);

/* F27: refuse a malformed expression -- P empty (F14), an alternation
 * spanning dimensions (F8), a term in both P and N, or an unknown term kind
 * (F26). Read-only. Returns FZN_FACET_OK when the expression is well formed. */
fzn_facet_err_t fzn_facet_validate(const fzn_facet_expr_t *expr);

/* F19: one-spelling normalisation, in place over the caller's arrays.
 * Collapses a single-member alternation to a prefix and removes duplicate
 * terms within P and within N, comparing with `fzn_facet_term_eq` so that an
 * alternation's members count as a set. The reduced counts are written back
 * through `pos_count` and `neg_count`, and order is otherwise preserved.
 *
 * IT DOES NOT DEDUPLICATE AN ALTERNATION'S MEMBERS, and said for some time
 * that it did -- a claim `normalize_side` never satisfied. That is F18's
 * half, it orders by the canonical encoding, and it lives in
 * `fzn_facet_expr_sort` with the F16 term sort for that reason. Corrected
 * 2026-09-21; sec 346.
 *
 * NOR THE SINGLE-CHILD RANGE COLLAPSE of F19, which needs the taxonomy to
 * know that two bounds name one child. That one is still deferred, and
 * `facet/codec.h` pins it as the one respect in which a decoded expression
 * is not canonical. */
fzn_facet_err_t fzn_facet_normalize(fzn_facet_term_t *pos, size_t *pos_count,
                                    fzn_facet_term_t *neg, size_t *neg_count);

/* F20: how a dimension's values are ordered. A dimension declares this; this
 * module never learns what the dimension classifies, only how to sort it. */
typedef enum fzn_facet_collation {
	/* Digit runs are zero-padded to the dimension's width, so `9` sorts
	 * before `10` and `720p` before `1080p`. */
	FZN_FACET_COLLATE_NATURAL = 0,
	/* F20's alternative: raw byte order, for a dimension where natural
	 * order is wrong -- a catalogue number, a hash, a code. */
	FZN_FACET_COLLATE_RAW = 1
} fzn_facet_collation_t;

/* A dimension's declaration: its opaque name, and how its values order.
 *
 * TWO HOSTS MUST AGREE ABOUT THIS OR THEY EVALUATE THE SAME EXPRESSION TO
 * DIFFERENT SETS, because F7 compares RANGE bounds by collation key. It is
 * therefore a property of the dimension rather than of a host's preference,
 * which is why it lives beside the name. Where the declaration is carried is
 * the catalogue's business, not this module's -- `local/vocabulary.h`'s rule
 * again: mechanism, never meaning. */
typedef struct fzn_facet_dimension {
	const uint8_t        *name;
	size_t                name_len;
	fzn_facet_collation_t collation;
	/* NATURAL only, and must be non-zero: a width of zero pads nothing,
	 * which is RAW said a second way, and one spelling per thing (F19's
	 * instinct applied to a declaration). */
	unsigned              digit_width;
} fzn_facet_dimension_t;

/* The declaration for the dimension called `name`, or NULL when the table
 * has none. A term naming a dimension nobody declared is a term this host
 * cannot order, which is the caller's to refuse. */
const fzn_facet_dimension_t *fzn_facet_dimension_find(
        const fzn_facet_dimension_t *dims, size_t count, const uint8_t *name,
        size_t name_len);

/* F20: derive a value's collation key by zero-padding each run of decimal
 * digits to `digit_width`, so byte order matches natural order (`9` before
 * `10`, `720p` before `1080p`). Non-digit bytes are copied unchanged. Writes
 * the key to `out` and its length to `*out_len`; returns FZN_FACET_ERR_RANGE
 * if `out_cap` is too small.
 *
 * A RUN AT OR ABOVE `digit_width` IS NOT TRUNCATED, so the key is never lossy
 * upward -- and `*unpadded` is set non-zero when that happened, because such
 * a key MISORDERS: unpadded `9999` sorts after unpadded `10000`. `unpadded`
 * may be NULL for a caller that only wants a display order, but a caller
 * doing F7 MUST treat a set flag as a refusal. Comparing a misordering key
 * selects the wrong files for a RANGE, and F25 forbids substituting a wrong
 * answer for a refusal. */
fzn_facet_err_t fzn_facet_collate(const uint8_t *value, size_t value_len,
                                  unsigned digit_width,
                                  uint8_t *out, size_t out_cap, size_t *out_len,
                                  int *unpadded);

/* Collate `value` under `dim`'s own declaration, which is the call a consumer
 * with a dimension table wants. RAW copies the value unchanged and never sets
 * `*unpadded`, there being no padding to fall short. FZN_FACET_ERR_MALFORMED
 * for a null, an unknown collation (F26's instinct), or a NATURAL declaration
 * whose width is zero. */
fzn_facet_err_t fzn_facet_collate_for(const fzn_facet_dimension_t *dim,
                                      const uint8_t *value, size_t value_len,
                                      uint8_t *out, size_t out_cap,
                                      size_t *out_len, int *unpadded);

/* An entity a term selects -- a content hash the filestore knows a file by
 * (catalogue C1). Opaque bytes, a borrowed view; this module never learns what
 * an entity is beyond its identity. */
typedef struct fzn_facet_entity {
	const uint8_t *id;
	size_t         id_len;
} fzn_facet_entity_t;

/* The ordered index facet evaluates against. Section 8 leaves the index
 * interface open beyond one fixed property -- prefix and range are one
 * operation on an ordered index, a prefix p being the range [p, p+0xFF...].
 * This is that interface, a vtable a consumer binds exactly as it binds the
 * crypto ops: fuzznet owns the mechanism, the consumer owns the index. It is a
 * vtable and not a wire format, so its shape costs a recompile to change, not
 * the wire-format churn section 8 is careful about. */
typedef struct fzn_facet_index_ops {
	void *ctx;
	/* Fill `out` (capacity `out_cap` entities) with the entities the term
	 * selects -- a prefix's subtree, a range's span, an alternation's union --
	 * and write the count to `*out_count`. Set `*incomplete` nonzero when this
	 * host cannot answer the term COMPLETELY, which forces F24 for a term in N.
	 * Return FZN_FACET_OK, or FZN_FACET_ERR_RANGE if `out_cap` is too small.
	 * The returned ids are borrowed from the index and outlive the call. */
	fzn_facet_err_t (*postings)(void *ctx, const fzn_facet_term_t *term,
	                            fzn_facet_entity_t *out, size_t out_cap,
	                            size_t *out_count, int *incomplete);
} fzn_facet_index_ops_t;

/* F11-F13, F24-F26: evaluate an expression against an index -- the entities in
 * (intersection of every term in P) minus (union of every term in N). The
 * expression is validated first (F27). Fills `out` with the selected entities
 * and writes the count to `*out_count`; `scratch` (capacity `scratch_cap`)
 * holds one term's postings at a time and is the caller's, since this module
 * allocates nothing.
 *
 * The refusals are the safety core: FZN_FACET_ERR_INCOMPLETE if any term in N
 * is incomplete on this host (F24 -- an incomplete subtraction over-includes
 * and could drive a deletion), plus the F26/F27 refusals validate returns. A
 * term in P that is incomplete UNDER-includes, which is a visible absence, so
 * it is NOT refused -- the asymmetry F24 states. */
fzn_facet_err_t fzn_facet_evaluate(const fzn_facet_expr_t *expr,
                                   const fzn_facet_index_ops_t *index,
                                   fzn_facet_entity_t *out, size_t out_cap,
                                   size_t *out_count,
                                   fzn_facet_entity_t *scratch, size_t scratch_cap);

/* A stable, allocation-free name for an error. */
const char *fzn_facet_err_str(fzn_facet_err_t err);

#endif /* FZN_FACET_H */
