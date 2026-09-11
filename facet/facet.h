/*
 * ==========================================================================
 * A SPECIFICATION, NOT AN INTERFACE. NOTHING IMPLEMENTS ANY OF THIS.
 * ==========================================================================
 *
 * There is no .c beside this file and never has been. It declares NOTHING:
 * no type, no function, only an include guard round numbered prose. That is
 * deliberate, and the reason is fuzzypickles' `core/src/record_store_internal.h`,
 * a header in exactly this position which learned it the expensive way --
 * "a header full of declarations reads as available machinery. Including it
 * compiled fine and failed at LINK time, naming an undefined symbol -- a
 * diagnostic that describes the mechanism and leaves the reader to work out
 * that the feature was never written."
 *
 * So this one cannot be linked against by accident, and it says so at the
 * TOP rather than in a status line somebody skims past. It is listed in
 * SPEC_HDRS rather than HDRS, and `make install` does not ship it.
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
 * verifies without learning what it permits, and a facet name is opaque bytes
 * that this module intersects without learning what it classifies. `genre`,
 * `year` and `format` belong to a media library; `system`, `region` and
 * `players` to an emulator front end. Sec 5 keeps command vocabularies out of
 * the core for the same reason.
 *
 * STATUS: specification only. No implementation, no wire encoding fixed, and
 * the module name is provisional. Settled 2026-09-10 with fuzzypickles'
 * copyright holder; what is settled is marked normative below, and what is not
 * is named at the end rather than guessed at.
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
 *     key-value facet is therefore the degenerate case of the model and not a
 *     second mechanism.
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
 * Named rather than guessed at:
 *
 *   - the wire encoding of a term and an expression, beyond the ordering and
 *     one-spelling rules above;
 *   - the index interface an implementation evaluates against. Prefix and
 *     range are the same operation on one ORDERED index -- a prefix p is the
 *     range [p, p+0xFF...) -- which is the only property fixed so far;
 *   - the collation key's digit-run width (F20);
 *   - this module's name.
 */

#endif /* FZN_FACET_H */
