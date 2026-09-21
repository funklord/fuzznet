/*
 * ==========================================================================
 * THE SPECIFICATION, AND THE SETTLED MERGE CORE THAT IMPLEMENTS PART OF IT.
 * ==========================================================================
 *
 * This file was a specification only from 2026-09-10 (C1-C31 below, written
 * by the fuzzypickles session). On 2026-09-18 the copyright holder chose
 * "settle-then-build", and the declarations at the end of this file -- the
 * in-memory attribute model and the C5b merge resolution (AUTHORITATIVE,
 * UNION, DISTINCT), with its refusals -- are implemented in
 * `catalog/catalog.c`. project.md sec 101 records the history and the
 * assignment.
 *
 * WHAT IS STILL ONLY PROSE, and declares nothing on purpose: the BEHAVIOURAL
 * integration that is not a standalone algebra -- estate-wide deletion
 * consensus (C19a), importing and sharding (C23), and sources (C13-C22), which
 * need `record/`, sync and `blob/` rather than an in-memory set. The merge core
 * operates on assertions a caller has already decoded and marked live; deciding
 * WHICH are live from per-(issuer, stream) journal state (C5c) is the caller's,
 * not this file's. NO LONGER prose: the ATTRIBUTE assertion's wire encoding, and
 * the module name, both settled by the copyright holder on 2026-09-18 (below,
 * and section 7). The EDGE-equivalent membership encoding is facet/'s and blob
 * content is the filestore's, per "follow the new model".
 *
 * A function appears below ONLY where `catalog.c` defines it, so an
 * unsettled operation has no declaration to link against by accident -- the
 * reason fuzzypickles' `core/src/record_store_internal.h` gives: "a header
 * full of declarations reads as available machinery ... failed at LINK time".
 *
 * The normative statements C1-C31 stand unchanged and remain what any
 * implementation -- this partial one included -- must satisfy.
 */

/* What is known about a file, where it is, and who holds it.
 *
 * The layer between this library's filestore, which owns bytes and their
 * transfer, and a consumer's own use of a media library. project.md sec 101
 * records the design and the arguments; this file is the specification and
 * states the rules without re-arguing them. `facet/facet.h` specifies how a
 * set of these entries is NAMED; this file specifies what the entries are.
 *
 * WHAT THIS DOES NOT DO. It holds no bytes: an entity is a content hash and
 * the filestore holds what that hash names. It decides no vocabulary: `genre`
 * and `system` and `region` belong to consumers, per `local/vocabulary.h`'s
 * rule that this library carries mechanism and never meaning. And it makes no
 * placement decision on its own -- every act that destroys bytes is requested
 * by a person, per C17.
 *
 * STATUS: specification. What was settled with fuzzypickles' copyright holder
 * on 2026-09-10 is marked SETTLED. Nothing here now carries a PROPOSED
 * marker; what remains undecided is named in section 7 rather than sketched.
 * The merge core is implemented (catalog/catalog.c). The module name is
 * settled -- `catalog`, superseding the old catalog/ module (the copyright
 * holder, 2026-09-18) -- and so is the ATTRIBUTE wire encoding, "follow the
 * new model", implemented as catalog/attribute.situ and the encode/decode
 * below. project.md sec 314. The rename to `catalog` and the retirement of the
 * old catalog/ are a later migration; the symbols here stay fzn_catalog_*
 * until then, to avoid colliding with the old module's fzn_catalog_*.
 */

#ifndef FZN_CATALOG_H
#define FZN_CATALOG_H

/* =========================================================================
 * 1. ENTITIES AND WHAT MAY BE SAID ABOUT THEM
 * =========================================================================
 *
 * C1.  An ENTITY is a file, identified by the content hash the filestore knows
 *      it by. The catalogue holds no bytes.
 *
 * C2.  SETTLED. What may be asserted about an entity falls in three classes,
 *      and they differ by WHO CAN CHECK THEM:
 *
 *        LABEL       nobody can. A person asserted it -- a name, a media
 *                    type -- and there is no fact of the matter to check it
 *                    against. It is carried.
 *        FACT        the bytes determine it -- resolution, codec, channel
 *                    count. A host holding them computes it and is certain; a
 *                    host that does not can only be told, and cannot check.
 *        IDENTIFIER  a register determines it, and the bytes do not. It is
 *                    checkable, but only by fingerprinting and consulting an
 *                    authority this library does not own.
 *
 * C3.  A FACT is derived where the bytes are and is NOT carried, except where
 *      a person needs it BEFORE deciding to spend the bandwidth -- a duration
 *      distinguishes a four-minute track from a four-hour one, and a catalogue
 *      that could not answer until after the download would have the question
 *      backwards. A carried fact is a HINT: the holder's derived value
 *      supersedes it, and the two disagreeing is shown rather than resolved,
 *      because a holder that misdescribed a file is worth knowing about.
 *
 * C4.  An IDENTIFIER travels as a LABEL does -- carried, naming whoever
 *      asserted it -- and is upgraded to verified by a host that holds both
 *      the bytes and the register. Disagreement between an asserted identifier
 *      and a locally derived one is shown, by the same rule as C3.
 *
 * C5.  SETTLED 2026-09-10, EXTENDED 2026-09-11. An attribute declares THREE
 *      things and they vary independently: SCOPE (C5a), MERGE (C5b) and
 *      CAPABILITY (C5e).
 *
 *      The first draft offered one list of three -- authoritative,
 *      collaborative, local -- which conflated the first two: LOCAL says who
 *      may see a value and the others say how concurrent values combine. The
 *      third axis arrived on 2026-09-11 from the consumer's own model, which
 *      carried it before this file did.
 *
 *      These apply to LABELS and IDENTIFIERS. A FACT does not merge, being
 *      computed from the bytes by whoever holds them (C3).
 *
 *      PRIOR ART IN THE CONSUMER, found after this was settled and worth citing
 *      rather than leaving it looking freshly derived. fuzzypickles'
 *      `common/settings.h` already splits a setting on two independent axes --
 *      `fzp_setting_applies` for what it is ABOUT (`FZP_APPLIES_HOST_SELF`,
 *      `_HOST_NAMED`, `_USER`, `_PEER_NAMED`, `_GROUP_NAMED`) and
 *      `fzp_setting_distribution` for how far it TRAVELS (`FZP_DIST_LOCAL`,
 *      `FZP_DIST_SYNCED` and so on) -- and its own comment gives the reason:
 *      the two are "independent of how far it travels -- collapsing the two
 *      loses the distinction that makes 'configure one host from another'
 *      expressible at all."
 *
 *      Cited by name because it is their file and their decision, not
 *      described from memory. The mapping is partial: their DISTRIBUTION is
 *      this file's SCOPE, their APPLIES is a subject scope that a catalogue
 *      expresses through the entity instead, and their model has no merge axis
 *      because a setting has one writer per scope. What transfers is the
 *      principle and the fact that this tree's consumer paid for it first.

 * C5a. SCOPE, being who may see it:
 *
 *        HOST        never leaves the host that wrote it. A cache position,
 *                    a last-played offset on this machine.
 *        ESTATE      shared among the estate's hosts and no further.
 *        ADVERTISED  observable by PEERS outside the estate. Settled
 *                    2026-09-11; the name and the distinction are
 *                    fuzzypickles' `FZP_DIST_ADVERTISED`, whose gloss is why
 *                    it is a level and not a flag -- "a disclosure, not a
 *                    preference".
 *
 *      ADVERTISED is not a level somebody might want. An availability claim is
 *      already observable by peers, so a catalogue without it cannot record
 *      that an attribute leaves the estate: it would be describing its own
 *      behaviour in a vocabulary with no word for it.
 *
 *      This is the axis that is easy to forget and expensive to retrofit,
 *      because an attribute that should never have been shared cannot be
 *      un-shared once it has been -- and twice as true of the third level,
 *      where the audience is not even bounded by the estate.
 *
 * C5a-CLOSED. ~~Two divergences from the consumer's own model.~~ BOTH SETTLED
 *      2026-09-11 on the holder's instruction: the third scope level is at
 *      C5a above and the capability axis at C5e below.
 *
 *      They were found by citing `common/settings.h` for the two-axis split
 *      and then reading the rest of that file, which had three axes where this
 *      had two and three scope levels where this had two. The route is worth
 *      more than the finding: the consumer's WORKING CODE was a better source
 *      for this library's own model than either project's documents were, and
 *      it was opened while chasing an unrelated question about enum coverage
 *      whose numbers were never publishable.
 *
 * C5b. MERGE, being how concurrent assertions combine. Three rules, and the
 *      principle behind all of them is the one C3 and C11 already state: NEVER
 *      SILENTLY PICK A WINNER.
 *
 *        AUTHORITATIVE  a designated issuer takes PRECEDENCE WHERE IT SPEAKS.
 *                       Its silence is not an assertion, so where it says
 *                       nothing the field is open and another issuer's value
 *                       stands, marked as not the authority's. Precedence,
 *                       never exclusivity -- a register that does not cover an
 *                       obscure release must not make that release unlabellable.
 *        UNION          for a set-valued attribute -- tags, genres. The value
 *                       is the union of LIVE assertions.
 *        DISTINCT       for a single-valued attribute several issuers write.
 *                       Every assertion is retained, there is NO automatic
 *                       winner, and the disagreement is presented. Where one
 *                       value must be shown, it is chosen by a stated local
 *                       preference order, which is a DISPLAY choice and not a
 *                       truth claim -- AND THE VIEW MUST NAME WHOSE VALUE IT
 *                       IS SHOWING.
 *
 *                       That last clause is fuzzypickles'
 *                       `library_service_internal.h`, which built this rule
 *                       before it was written here: "nothing picks a winner",
 *                       this host's own claim is preferred "for the reason a
 *                       person would expect -- what you named it is what you
 *                       should see", and a `described_by` field says whose it
 *                       is. Calling a choice a display choice is not enough on
 *                       its own: without the attribution a reader cannot tell
 *                       a preference from a consensus, which is the thing the
 *                       rule exists to avoid claiming.
 *
 * C5c. AN ISSUER MAY RETRACT ONLY ITS OWN ASSERTION, which is what makes UNION
 *      need no conflict machinery. A "removal" is an issuer withdrawing what it
 *      said, never deleting what somebody else said, so concurrent add and
 *      remove cannot race: the set is the union of what is live, computed at
 *      read time from per (issuer, stream) state that already exists. No CRDT,
 *      no tombstone reconciliation, no add-wins versus remove-wins question,
 *      because the question cannot arise.
 *
 * C5a1. REPLICATION SCOPE IS NOT VISIBILITY SCOPE, and C5a is about the
 *      second. fuzzypickles' `library_sync_internal.h` draws the line: their
 *      catalogue is "global per estate", and that is "a statement about who
 *      REPLICATES it, not about who may SEE it".
 *
 *      C5a's ESTATE therefore answers who may see, and an attribute at
 *      ADVERTISED is seen beyond the hosts that replicate it. The two
 *      questions coincide for HOST and diverge at the top of the axis, which
 *      is where an implementation would assume they are one thing because
 *      below that they always were.
 *
 * C5f. WHAT THE CONSUMER'S CAPABILITY MODEL ALREADY TEACHES C5e, read
 *      2026-09-11 from `core/src/capability.h` and
 *      `core/src/config_sync_internal.h`. Four things, and two of them are
 *      mistakes that tree has already made and paid for.
 *
 *      1. AUTHORIZATION TRAVELS WITH THE CHANGE, never with the channel.
 *      Their config-sync header is explicit: "an authenticated link does NOT
 *      authorize what travels over it", so a change "carries its own proof,
 *      verifiable by the target without reference to how it arrived". A
 *      catalogue assertion at capability GRANTED must do the same. Accepting
 *      one because the peer is authenticated is confusing authentication with
 *      authorization, and the link being encrypted makes no difference to it.
 *
 *      2. DEFINE THE CAPABILITY FINE-GRAINED NOW, even if the interface stays
 *      coarse. Theirs is "a small fixed byte enum, defined fine-grained from
 *      the start even though the CLI stays coarse for now -- retrofitting a
 *      typed field into an already-deployed signed capability grant is exactly
 *      the kind of wire-format churn this project has already paid to avoid
 *      TWICE". So C5e's GRANTED should name WHICH capability rather than
 *      meaning "some capability": the coarse spelling is the one that cannot
 *      be refined later without breaking signatures.
 *
 *      3. GRANTING IS TWO QUESTIONS AND THEY ASKED ONE. "May you pass anything
 *      on at all" and "do you have this particular thing to pass" are
 *      different, "and for a while only the second was asked, which left
 *      CAP_ADMIN gating nothing and let any host promote any other host to its
 *      own capability set". Any delegation a catalogue grows has the same two
 *      questions and the same way of answering half of them.
 *
 *      4. A CHAIN IS SINGLE-TYPED BY CONSTRUCTION, the type sitting inside
 *      each hop's signed region with linkage requiring grantor == previous
 *      grantee, so a holder cannot mint a type it does not itself hold. C5e
 *      verifies through `chain/authz.h` and inherits this; it does not need
 *      its own notion of a master granter and should not acquire one.
 *
 * C5d. Because every assertion is RETAINED rather than resolved away, changing
 *      which issuer is authoritative for an attribute -- from one register to
 *      another -- re-resolves the view and loses nothing. That is a property
 *      of C5b's refusal to discard, and it is why the refusal is worth its
 *      storage.
 *
 * C5e. CAPABILITY, being what authority is needed to CHANGE it. Settled
 *      2026-09-11 on the holder's instruction, and taken from the consumer's
 *      `fzp_setting_capability` rather than invented: independent of who may
 *      SEE a value (C5a) and of how concurrent values combine (C5b).
 *
 *        NONE     any member of the estate may assert it -- a tag, a note.
 *                 C5c still binds: you may retract only your own.
 *        HOLDER   only a host that HOLDS THE BYTES may assert it.
 *        GRANTED  a named capability is required, verified through
 *                 `chain/authz.h` as any other is.
 *
 *      IT EXPLAINS C10 RATHER THAN SITTING BESIDE IT. An OBSERVED claim is the
 *      holder's own fact, and the reason nobody else may publish one is
 *      exactly capability HOLDER -- stated there as a property of that field
 *      and really an instance of this axis. A DESIRED placement is a request,
 *      and what authority it needs is a capability question that until now had
 *      no axis to live on.
 *
 *      AND C21 STOPS BEING A SPECIAL CASE ABOUT TWO VERBS. That ruling --
 *      reassignment and deletion must not share a permission -- is what this
 *      axis says generally: reassignment changes this library's own metadata,
 *      deletion destroys somebody's bytes, so they take different
 *      capabilities. C17 is unaffected and unaffectable: no capability makes a
 *      deletion implicit, because C17 forbids the CONSEQUENCE rather than the
 *      authority.
 *
 * =========================================================================
 * 2. DIMENSIONS AND LINKS
 * =========================================================================
 *
 * C6.  A DIMENSION is a tree that an entity is linked into; `facet/facet.h`
 *      F1-F4 specifies their shape and this file does not restate it. A
 *      dimension is CURATED or GENERATED.
 *
 * C7.  SETTLED. There is a GENERATED dimension keyed by host, and it makes the
 *      catalogue TOTAL: at least one node links every entity at all times,
 *      including one that matches no register at all. It holds structurally,
 *      because it is derived from what is on disk rather than curated, so it
 *      cannot be incomplete the way a hand-made view can.
 *
 * C8.  ~~Store one direction and derive the other.~~ CORRECTED 2026-09-11
 *      against fuzzypickles' `core/src/library_internal.h`, which is this
 *      design already built and does better: **NEITHER direction is stored.**
 *
 *      Their entry is a signed record whose SUBJECT is the blob root and whose
 *      ISSUER is a host that holds the file. From that pairing, in their
 *      words: "AVAILABILITY NEEDS NO SEPARATE RECORD. The set of issuers for a
 *      root IS the set of holders, so 'which hosts have it' is metadata of the
 *      file in the literal sense: it is the record set, not a table kept
 *      beside it."
 *
 *      So there is no relation to store and nothing to keep in step. A host
 *      that knows of a file without holding it issues nothing and sees
 *      everybody else's records, which is the state that makes streaming the
 *      point rather than an afterthought. This entry said store one and derive
 *      the other, which is the right instinct one step short of the answer.
 *
 * C8b. WHAT MAY LEAVE THE ESTATE IS A BIT, NEVER THE HOLDER LIST. C8 makes
 *      the issuer set the holder set, and C5a allows an attribute at
 *      ADVERTISED to be seen by peers outside the estate. Those two combine
 *      into a leak nobody decided on: advertising availability by publishing
 *      the claim set tells a peer WHICH OF THIS USER'S HOSTS HOLD WHAT, which
 *      is the estate's device topology.
 *
 *      fuzzypickles refused exactly this once already, in
 *      `core/src/settle_internal.h`: settled "is emitted to the sender as a
 *      SINGLE BIT -- never a per-host map, WHICH WOULD LEAK THE RECIPIENT'S
 *      DEVICE TOPOLOGY". The same answer applies here and for the same reason.
 *      Inside the estate the claim set is the availability metadata and costs
 *      nothing; crossing the boundary it becomes a disclosure, and what
 *      crosses is at most a bit, or a count with no names attached.
 *
 *      This is C5a1's divergence made concrete: replication scope and
 *      visibility scope coincide below ADVERTISED and part at it, and the
 *      holder list is the first thing that must not follow the attribute
 *      across.
 *
 * C8a. AND IT IS WHY C10 CONVERGES WITHOUT COORDINATION. "Each host is
 *      authoritative about itself and nothing else, so two hosts cannot
 *      disagree about a third, and a claim needs no coordination to
 *      converge." C10 separates observed from desired and says the observed
 *      field is the holder's own fact; this is the reason that costs nothing
 *      to maintain -- there is no conflict to resolve because no host can
 *      write another's claim, which is capability HOLDER (C5e) falling out of
 *      the record shape rather than being enforced on top of it.
 *
 * C9.  An entity may be linked from many places, and several times within one
 *      dimension. A link in a CURATED dimension is a REFERENCE. The generated
 *      host dimension is an OBSERVATION and not a reference: it reflects what
 *      is on disk, so while the entity exists the link exists, and severing it
 *      is not a catalogue edit but the delete gesture of C17 spelled where it
 *      is truthful.
 *
 * C9a. SHARING A SUBTREE IS NOT SYMMETRIC, and the two directions are named
 *      differently. Taken from fuzzypickles' `core/src/notes_share_internal.h`
 *      and their sec 22, settled there 2026-09-03, because a catalogue
 *      publishing part of a dimension is the same problem their notes already
 *      solved:
 *
 *        OUTGOING  a (subtree, PEER NAME) pair. It names a peer because that
 *                  is what a person shares with, and what a sender has to
 *                  resolve to an address.
 *        INCOMING  an (ISSUER KEY, subtree) pair. It names a key because that
 *                  is what arrives on a record, and what a gate can check
 *                  without a lookup that might fail.
 *
 *      A C5a ADVERTISED attribute has both directions and they are not one
 *      list read twice.
 *
 * C9b. CONTAINMENT MUST NOT BE CHECKED, and this is the one a catalogue would
 *      get wrong by being careful. The obvious gate -- admit an assertion only
 *      if its node is UNDER the shared subtree -- cannot be enforced and buys
 *      nothing.
 *
 *      It cannot be enforced because a child can arrive before its parent, so
 *      a recipient frequently cannot prove containment for an assertion that
 *      is perfectly legitimate. A gate demanding it would drop records and
 *      call it security.
 *
 *      It buys nothing because the property being defended is ONLY ITS OWNER
 *      WRITES IT, which is a statement about the ISSUER and is already checked.
 *      What is inside a share is the sharer's business.
 *
 *      That reasoning is fuzzypickles' and is quoted rather than re-derived.
 *      It transfers unchanged because this file's dimensions are trees and its
 *      terms are PREFIXES (`facet/facet.h` F5), so "is this node under that
 *      one" is exactly the question a prefix invites an implementer to ask at
 *      admission time -- and the answer is that admission is an issuer
 *      question, not a position question.
 *
 * =========================================================================
 * 3. HOLDERS: WHAT IS, AND WHAT WAS ASKED FOR
 * =========================================================================
 *
 * C10. SETTLED. Holding is TWO fields and they MUST NOT share one:
 *
 *        OBSERVED   the claim a host published about itself. Its own fact,
 *                   which its bytes settle.
 *        DESIRED    the placement somebody else asked for. A request from a
 *                   party that cannot make it true by saying so.
 *
 * C11. The two converge or they do not, and THE GAP IS PRESENTED rather than
 *      hidden: fetching, refused, out of space, host unreachable. This is C3's
 *      show-the-disagreement rule one layer out, and it is what keeps "add
 *      this host" honest about being a request.
 *
 * C12. A consumer MUST NOT render a desired placement as an accomplished one.
 *
 * =========================================================================
 * 4. SOURCES: WHERE BYTES ACTUALLY LIVE
 * =========================================================================
 *
 * C13. SETTLED. Bytes live in a SOURCE, which is named and carries a policy. A
 *      reference is (SOURCE, RELATIVE PATH) and never a bare absolute path: a
 *      bare path does not survive a second machine, cannot express
 *      relative-to-home, and is not a unit anything can grant or refuse.
 *
 * C14. The MANAGED root is a source marked writable -- one mechanism with a
 *      policy per entry, rather than two mechanisms. Only within a writable
 *      source may an organiser move, rename or delete.
 *
 * C15. A REFERENCED source is read-only to the organiser BY CONSTRUCTION. A
 *      person may point the catalogue at a collection built over decades and
 *      have it indexed rather than rearranged.
 *
 * C16. A PATH is a LABEL and a content hash is a FACT, which is C2 one layer
 *      out. A referenced file may be edited, moved or deleted by its owner at
 *      any moment, so a reference ASSERTS that a path holds a hash;
 *      (size, mtime, inode) is the cheap staleness check and a rehash settles
 *      it. Importing a source therefore costs a full hashing pass, once,
 *      proportional to the collection.
 *
 * C16a. A PATH IS LOCAL AND MUST NOT TRAVEL. From fuzzypickles'
 *      `core/src/file_ref.c` and their sec 11: what goes in a message is a
 *      NAME, "for display and for a default, NEVER A PATH TO WRITE", because
 *      it comes from whoever sent it and "a separator or a dot-dot in it would
 *      be a path traversal in any client that took it literally".
 *
 *      Their handling of a bad one is the part to carry: it is REFUSED AT
 *      PARSE RATHER THAN SANITISED, on the grounds that "a name that cannot be
 *      shown safely is a name this format does not carry". That is
 *      `facet/facet.h` F28's rule -- a failed parse refuses rather than
 *      approximates -- arriving from a different subsystem, which is a reason
 *      to trust it rather than a coincidence to note.
 *
 *      So C13's `(source, relative path)` is a LOCAL form. It is what a host
 *      records about its own disk; it is not what it publishes. An advertised
 *      attribute (C5a) carries a name and never a path, or it discloses the
 *      layout of somebody's filesystem to every peer that can see the claim.
 *
 * C17. SETTLED, and this is the safety core. A DELETION IS EXPLICIT AND NEVER
 *      A CONSEQUENCE OF METADATA GOING WRONG. No metadata error of any kind
 *      may destroy bytes: not a miscounted link, not a view rebuilt wrongly,
 *      not a merge upstream, not a bug in this library's own bookkeeping.
 *
 * C18. SETTLED, and the settlement is that it stands as written (the
 *      copyright holder, 2026-09-21). A reference count of zero is a REPORTED
 *      STATE -- "held here, in no view" -- and never a trigger. Showing it to
 *      a person is the only thing it may do on its own.
 *
 *      SO THERE IS NO AUTOMATIC RECLAMATION, and the grace period and pin
 *      granularity that section 7 held open with it do not arise. The sweep
 *      PLANS (catalog/sweep.h) and a person acts, which is C17.
 *
 *      THE ARGUMENT THAT DECIDED IT came from building the planner rather
 *      than from the principle. `fzn_catalog_referenced` was found counting a
 *      HOLDER assertion as a reference (project.md sec 321), so it reported
 *      entities as referenced that nothing curated. Under this rule that
 *      defect was a planner that planned nothing: visible, harmless, and
 *      fixed the same day. The identical class of defect wired to automatic
 *      deletion destroys bytes -- which is precisely what C17 forbids, and
 *      C17 names "a bug in this library's own bookkeeping" among the errors
 *      it forbids destroying bytes. One had just occurred.
 *
 *      AND IT IS STRUCTURAL RATHER THAN A PROMISE. The four planning modules
 *      -- sweep, copy, filing, retention -- include only <string.h>. They
 *      reach no filesystem, so they cannot reclaim anything whatever a future
 *      caller asks of them. Every unlink in this library removes a file the
 *      library itself just created: a socket's temporary name, a persist or
 *      spool temporary. None removes an entity's bytes.
 *
 * C19. Removing the FINAL holder of an entity is a distinct act from removing
 *      a redundant copy. It destroys the entity estate-wide and is
 *      unrecoverable, so it MUST NOT share a gesture with dropping a spare.
 *
 * C19a. HOW AN ESTATE-WIDE DELETION ACTUALLY HAPPENS, which C17 to C19 say
 *      must be explicit without saying by what mechanism. From fuzzypickles'
 *      `core/src/notes_purge_internal.h`, settled by their holder 2026-09-05,
 *      and their statement of why the obvious answers fail is the useful half:
 *      "A local delete is undone by the next sibling to sync. A tombstone that
 *      lives for ever trades a note for a smaller permanent thing, which is
 *      not a saving -- and deleting exists to save space, so an answer that
 *      keeps something indefinitely has missed the point."
 *
 *      Their answer: a deletion is a QUEUED COMMAND eliminated once consensus
 *      is attained. "No earlier, because a host that has not yet agreed still
 *      holds a copy and will re-send it. No later, because the queue entry is
 *      itself the thing being paid for."
 *
 *      **And the consensus set is PINNED WHEN THE PURGE IS QUEUED, not
 *      recomputed as hosts come and go.** That is the detail an implementation
 *      would get wrong by being helpful: a set recomputed against the current
 *      estate can never close while a host is away, or closes early when one
 *      leaves.
 *
 *      THE PINNED SET IS THE HOSTS THAT ACTUALLY HOLD, not every sibling.
 *      Their settlement policy draws this line and the reason transfers
 *      exactly: "a message is settled once every one of this user's own hosts
 *      that DOES CHAT RETENTION holds it. Not every sibling -- relay and
 *      retention are independent, host-by-host choices, so a host that only
 *      forwards never stores and MUST NEVER BE WAITED ON." A consensus set
 *      that includes hosts which never hold anything is a set that cannot
 *      close, and the symptom is a purge queue that grows for ever while every
 *      host in it behaves correctly.
 *
 *      It is the same shape as their message settlement
 *      (`core/src/settle_internal.h`), which is their own note and worth
 *      keeping: one mechanism already carries this in that tree, so a
 *      catalogue adopting it is reusing rather than inventing.
 *
 * C20. In a REFERENCED source, unlinking means FORGETTING the reference. The
 *      bytes belong to whoever put them there and are never deleted by the
 *      catalogue, whatever the link count says and whoever asked.
 *
 * C21. SETTLED. Reassignment and deletion MUST NOT share a permission.
 *      Reassigning changes which node an entity is linked from -- this
 *      library's own metadata, with nothing on disk moving. Deleting bytes
 *      outside a writable source destroys what a person put there, at the
 *      request of a machine that cannot see what it is destroying.
 *
 * C22. SETTLED. The on-disk layout of a managed source is MATERIALISED when an
 *      entity is placed and re-derived only when asked for. A catalogue may
 *      change hourly, and a layout that tracked it would silently rearrange a
 *      person's disk from a rename nobody here made.
 *
 * =========================================================================
 * 5. IMPORTING AN EXTERNAL CATALOGUE
 * =========================================================================
 *
 * SETTLED 2026-09-10: an external register IS consulted. What remains open is
 * narrower and is stated at C23a -- whether this project pins another party's
 * SIGNING KEY to do it, which is a trust-root decision and does not follow
 * from the ruling above.
 *
 * C23a. SETTLED 2026-09-10. CONSULT WITHOUT PINNING: an
 *      importing host fetches from the register, checks whatever the register
 *      itself offers, and PUBLISHES THE SHARD INDEX AS A RECORD IN ITS OWN
 *      ISSUER STREAM. Every other host then trusts it exactly as far as it
 *      already trusts that host.
 *
 *      Three things follow. No foreign trust root is added, so the estate's
 *      keys stay the estate's. A bad import is ATTRIBUTABLE to a host inside
 *      the estate rather than to an anonymous mirror. And the currency problem
 *      of C24 largely collapses into machinery that already exists:
 *      `record/journal.h` keeps a position per (issuer, stream) and refuses
 *      gaps, so a rollback is a sequence going backwards and is already
 *      refused. TUF's shape (C25) stays relevant INSIDE the importer, as its
 *      own concern when talking to the register, rather than as an
 *      estate-wide mechanism.
 *
 *      THE COST, stated rather than buried: the importing host becomes a
 *      trusted party for catalogue content, and compromising it lets it
 *      publish a wrong catalogue. A pinned publisher key would prevent that
 *      particular forgery.
 *
 *      THE ARGUMENT FOR TAKING THE TRADE: that host already holds the files
 *      and can delete them. A party able to destroy bytes mislabelling them is
 *      not a new exposure, while pinning a foreign key is one, and a permanent
 *      one.
 *
 *      A privacy consequence worth having either way: only the importing host
 *      talks to the register. The rest of the estate fetches from it, so one
 *      host is exposed rather than all of them.
 *
 * C23b. SHARDING MUST BE DETERMINISTIC, and this follows from C23a rather than
 *      being a preference. With no pinned publisher there may be several
 *      importers of one register, and if two of them shard a snapshot
 *      differently they produce different roots for identical data: the estate
 *      then stores two copies of the same catalogue, deduplication fails, and
 *      a host holding one importer's shard cannot serve the other's. Given the
 *      same snapshot and the same shard size, two independent importers MUST
 *      produce the same shard roots, so that their indices differ only in
 *      provenance and the bytes converge.
 *
 * C23c. AN INDEX MUST CARRY ITS PROVENANCE: which register, which snapshot of
 *      it, and WHAT THE IMPORTER VERIFIED -- the register's own signature or
 *      checksums, and the snapshot's stated version and date. Nobody
 *      downstream can re-check against the register, so the importer's
 *      diligence is the only check there is, and recording what was checked is
 *      what lets a reader judge it. An index that says only "this is
 *      MusicBrainz" asserts a fact with no method beside it.
 *
 * C23d. CORRECTION AND COMPROMISE NEED NO NEW MECHANISM. A bad index is
 *      superseded by a later record in the same issuer stream, which the
 *      journal already orders. A compromised importer is handled by revoking
 *      its issuer key, which `chain/revocation.h` already does. The recovery
 *      path for C23a's cost therefore exists before the feature does.
 *
 * C23. A register is imported as SHARDS: an ordinary blob per
 *      key-range, with a signed INDEX mapping range to blob root. The index is
 *      small enough to replicate to every host while the shards are fetched on
 *      demand. A shard is whole-or-nothing, so its have-set is one node --
 *      which is the point, since a have-set encodes LOCALITY and random point
 *      lookup over one large blob would exceed it and then silently
 *      under-claim.
 *
 * C24. Three trusts separate, and after C23a only the first two reach the
 *      estate at all:
 *
 *        CONTENT       free. A shard root is a content hash, so a mirror can
 *                      withhold and cannot forge. A server need not be
 *                      trusted for correctness.
 *        AVAILABILITY  what a server supplies -- and once any host in an
 *                      estate holds a shard, this library's transfer serves it
 *                      to the rest. The server is a SEED, not a dependency:
 *                      losing it keeps everything already held and merely
 *                      stops new entries arriving.
 *        CURRENCY      hard between the IMPORTER and the register, and
 *                      solved inside the estate by C23a. A server may serve
 *                      an old, validly signed snapshot and no byte betrays
 *                      it -- but the importer re-signs into its own stream,
 *                      and `record/journal.h` keeps a position per (issuer,
 *                      stream) and refuses gaps, so a rollback published to
 *                      the estate is a sequence going backwards and is
 *                      already refused. What remains is the importer's own
 *                      problem, at C25.
 *
 * C25. THE IMPORTER'S OWN CHECK, not an estate mechanism. When talking to a
 *      register it wants the shape TUF already settled rather than a new one: a signed snapshot carrying a MONOTONIC VERSION and an EXPIRY,
 *      with each host remembering the HIGHEST VERSION IT HAS SEEN -- so a
 *      rollback is caught inside the estate even while the publisher is
 *      unreachable, and expiry bounds how long a withheld update hides. This
 *      is the importer satisfying itself before it vouches; nothing
 *      downstream depends on it, which is the point of C23a.
 *
 * C26. Shard size is the privacy control and is one number: a fetch
 *      reveals interest in a KEY RANGE rather than an entry. Asking a peer
 *      before a server makes the estate the anonymity set as well as the
 *      cache.
 *
 * C26a. WHICH register is a consumer's decision and not this library's, by
 *      `local/vocabulary.h`'s rule: MusicBrainz and AcoustID for recorded
 *      music, No-Intro or Redump for game dumps, TMDB for film. What this
 *      library carries is the mechanism -- fetch, shard, sign, publish, serve
 *      -- and never which authority is right about what.
 *
 * C27. An imported identifier is subject to C4: it is an assertion by the
 *      register, not a fact about the bytes, until a host checks it.
 *
 * C27a. STORE THE SIGNED RECORD, NOT THE PARSED ENTRY, and the reason is
 *      forward compatibility rather than tidiness. From their
 *      `library_store_internal.h`: "a host must RE-PUBLISH WHAT IT CANNOT
 *      READ, and re-encoding from a parsed struct cannot do that -- a field
 *      this build does not know is a field it cannot write back, and the
 *      signature would not survive it anyway." So the store is a byte store
 *      and interpretation happens on the way out.
 *
 *      Their index shape follows: ONE CLAIM PER (ROOT, ISSUER), which is also
 *      the whole of C8 above.
 *
 * C27b. AND THIS DOES NOT CONTRADICT `facet/facet.h` F26, though it looks as
 *      though it must. F26 says an unknown TERM KIND makes an expression
 *      refuse; C27a says an unknown FIELD must still be stored and relayed.
 *      They are different operations on different objects:
 *
 *        EVALUATING  an expression you do not fully understand yields a
 *                    DIFFERENT SET while reporting success. Refuse.
 *        RELAYING    a record you cannot parse costs nothing and losing it
 *                    costs somebody else's data. Store and re-publish.
 *
 *      An implementation that took one rule for both would either drop records
 *      an older build cannot read, or evaluate an expression it half
 *      understands. Both are one-line mistakes and neither is visible from
 *      the output.
 *
 * =========================================================================
 * 6. REFUSAL
 * =========================================================================
 *
 * C28. An implementation MUST refuse rather than return a partial answer
 *      wherever a partial answer would be WRONG rather than incomplete.
 *      `facet/facet.h` F24-F28 states the cases for selection, and the same
 *      rule governs here: a set that over-includes may drive a placement or a
 *      deletion, and C17 forbids reaching that by an error.
 *
 * C29. An identifier whose register has RETIRED it -- two entries proving to
 *      be one -- is followed through a forwarding record, or refused. It is
 *      never silently treated as absent. A SPLIT cannot be followed at all and
 *      is surfaced, per `facet/facet.h` F23.
 *
 * C29a. DO NOT REUSE ANOTHER SUBSYSTEM'S FRAMES, however well the shapes
 *      match. From `library_sync_internal.h`, which considered it and refused:
 *      reusing the notes frames "would mean a library record arriving at the
 *      notes handler, WHICH WOULD ADMIT IT -- fzp_notes_admit checks the
 *      signature, the issuer and the subject, and deliberately does NOT check
 *      `kind`" -- and then store it as a node whose body no decoder there can
 *      read.
 *
 *      The trap is that the admitting check is CORRECT: it is not supposed to
 *      check kind, because kind is not what it is defending. Two subsystems
 *      sharing a frame family means each one's permissive-by-design admission
 *      is the other's contamination. The routing byte is where the separation
 *      belongs, and a catalogue that grows its own frames should not economise
 *      here.
 *
 * C30. THE STATE IS THE CALLER'S AND NOTHING HERE ALLOCATES. From
 *      fuzzypickles' `library_play_internal.h`, whose player is "four fields
 *      and a cursor, so there is nothing to allocate and nothing to destroy. A
 *      player that dies mid-file leaks nothing and a resumed one starts by
 *      seeking."
 *
 *      It is recorded as a constraint on any implementation of this file and
 *      of `facet/facet.h` because a selection evaluator is exactly the thing
 *      that reaches for an allocator by reflex -- posting lists want to be
 *      malloc'd, and an intersection wants a scratch buffer. This library's own
 *      logging went the same way and back: flog was made allocation-free with
 *      the API unchanged, so the house answer to "but it needs a buffer" is
 *      that the caller has one.
 *
 * C31. AND A LESSON FROM THAT SAME HEADER, about this file's open list rather
 *      than its rules. They record underrun-is-a-stall as having been "open
 *      until the project was found to have DECIDED IT ALREADY UNDER ANOTHER
 *      NAME" -- their sec 6's copy-stream and pure-stream split answered it
 *      without anybody connecting the two.
 *
 *      Every item in section 7 deserves that question asked of it before it is
 *      deserves being asked of the holder. One has already yielded: the
 *      mechanism half of reclamation is settled by C19a and was never open.
 *
 * =========================================================================
 * 7. NOT SETTLED HERE
 * =========================================================================
 *
 *   - ~~the layout template of a managed source (C22)~~ SETTLED 2026-09-21: a
 *     substitution pattern over the entity's attributes, catalog/materialise.h
 *     and sec 338. The SOURCE it produces a relative path INSIDE (C13) is
 *     still not built: no source type, no managed/referenced distinction, no
 *     (SOURCE, RELATIVE PATH) reference. The word is free for it -- what used
 *     to be `fzn_catalog_source_t` is `fzn_catalog_issuer_t`, which is what it
 *     always meant (sec 339). ~~the shard size (C26)~~
 *     SETTLED 2026-09-21: the one number is ENTRIES PER SHARD, defaulting to
 *     FZN_CATALOG_SHARD_ENTRIES_MIN, because that number IS the anonymity set
 *     C26 says the shard size is. catalog/shard.h, sec 337;
 *     Checked rather than assumed, and the negative is worth recording with
 *     it: fuzzypickles' `daemon/log_retention.h` is NOT this decision under
 *     another name. It caps lines in a log file, which is a bound on growth
 *     rather than a removal needing agreement, and adopting it here would
 *     answer a question nobody asked;
 *   - whether a referenced entity may be promoted into a managed source in
 *     place rather than by copying (C15);
 *   - the wire encoding of the SHARD and SOURCE machinery, which waits on the
 *     two items above. The RECLAMATION half is settled and built: a purge
 *     command is FZN_CATALOG_OBJECT_PURGE carrying its pinned set, and an
 *     agreement is an attribute whose issuer set IS the agreement set, C8's
 *     own move (catalog/purge.h, sec 336). The ATTRIBUTE assertion's own
 *     encoding is SETTLED and below;
 *     the module name is SETTLED, `catalog` (the copyright holder, 2026-09-18).
 */

/* =========================================================================
 * THE SETTLED MERGE CORE
 * =========================================================================
 *
 * Implemented in catalog/catalog.c: the in-memory attribute model and the
 * C5b merge resolution. Assertions hold BORROWED views into the caller's
 * bytes, fuzznet's zero-copy style (C30: nothing here allocates). This is not
 * the wire encoding (section 7), not the deletion, import or source machinery
 * (those need record/, sync and blob/), and not the "which are live"
 * determination, which is the caller's from journal state (C5c).
 */

#include <stddef.h>
#include <stdint.h>

/* For FZN_RECORD_BODY_MAX only: an ATTRIBUTE assertion is carried IN a record
 * body (C5c/C8), so the value it can hold is bounded by what a body holds. The
 * accessors record.h declares are inline, so naming this constant adds no link
 * dependency -- catalog.c calls no record function; the record->fields bridge
 * is the caller's, where record/ is already a dependency. */
#include "../record/record.h"

typedef enum fzn_catalog_err {
	FZN_CATALOG_OK = 0,
	/* The caller's bug: a null, or an output buffer too small. */
	FZN_CATALOG_ERR_MALFORMED = 1,
	/* C28: a resolution set whose assertions are not all about one
	 * (entity, attribute) -- different entity, name, class, scope, merge or
	 * capability -- which would resolve a mixture as if it were one thing. */
	FZN_CATALOG_ERR_NOT_ONE_ATTRIBUTE = 2,
	/* An enum field carries a value this build does not know (C28's rule,
	 * facet's F26): refused, never skipped. */
	FZN_CATALOG_ERR_KIND = 3,
	/* AUTHORITATIVE resolution was asked for without naming the authority. */
	FZN_CATALOG_ERR_NO_AUTHORITY = 4,
	/* The output buffer cannot hold the resolved set, or a value is longer
	 * than the field that has to carry it. */
	FZN_CATALOG_ERR_RANGE = 5,
	/* The records do not assert what the caller named -- a filing on a link
	 * nothing curates, say. A legitimate state rather than a caller's bug,
	 * which is why it is not MALFORMED: the two call for different
	 * responses, and a caller that could not tell them apart would treat a
	 * catalogue it has not caught up with as a programming error. sec 323. */
	FZN_CATALOG_ERR_ABSENT = 6,
	/* The operation is refused because something is still under way -- a
	 * queued purge whose pinned hosts have not all agreed, say. Like
	 * ABSENT, a legitimate state rather than a caller's bug: the answer is
	 * to wait, not to fix a call. sec 335. */
	FZN_CATALOG_ERR_BUSY = 7,
} fzn_catalog_err_t;

/* C2: what may be asserted, by WHO CAN CHECK IT. */
typedef enum fzn_catalog_class {
	FZN_CATALOG_LABEL = 1,      /* nobody can check; carried. */
	FZN_CATALOG_FACT = 2,       /* the bytes settle it. */
	FZN_CATALOG_IDENTIFIER = 3, /* a register settles it. */
} fzn_catalog_class_t;

/* C5a: who may SEE a value. */
typedef enum fzn_catalog_scope {
	FZN_CATALOG_HOST = 1,       /* never leaves the host that wrote it. */
	FZN_CATALOG_ESTATE = 2,     /* the estate's hosts, no further. */
	FZN_CATALOG_ADVERTISED = 3, /* observable by peers outside the estate. */
} fzn_catalog_scope_t;

/* C5b: how concurrent assertions combine. */
typedef enum fzn_catalog_merge {
	FZN_CATALOG_AUTHORITATIVE = 1, /* a designated issuer takes precedence. */
	FZN_CATALOG_UNION = 2,         /* the union of live values (set-valued). */
	FZN_CATALOG_DISTINCT = 3,      /* all retained, no winner, disagreement shown. */
} fzn_catalog_merge_t;

/* C5e: what authority is needed to CHANGE it. The merge core carries this but
 * does not branch on it -- capability is an ADMISSION question (who may
 * assert), checked before an assertion is accepted, not a resolution one. */
typedef enum fzn_catalog_capability {
	FZN_CATALOG_CAP_NONE = 1,   /* any estate member may assert. */
	FZN_CATALOG_CAP_HOLDER = 2, /* only a host holding the bytes may. */
	FZN_CATALOG_CAP_GRANTED = 3,/* a named capability, via chain/authz.h. */
} fzn_catalog_capability_t;

/* One assertion: an issuer's value for an attribute about an entity (C1, C5).
 * The class/scope/merge/capability are the ATTRIBUTE's declaration (C5), so
 * every assertion about one attribute carries the same four; fzn_catalog_
 * validate refuses a set that does not agree. `live` is C5c's read-time state
 * the caller supplies (nonzero = live). All byte fields are borrowed views. */
typedef struct fzn_catalog_assertion {
	const uint8_t *issuer;   /* who asserted it -- a host key. */
	size_t         issuer_len;
	const uint8_t *entity;   /* the content hash the assertion is about (C1). */
	size_t         entity_len;
	const uint8_t *name;     /* attribute name, opaque (mechanism, not meaning). */
	size_t         name_len;
	const uint8_t *value;    /* the asserted value, opaque. */
	size_t         value_len;
	fzn_catalog_class_t      attr_class;
	fzn_catalog_scope_t      scope;
	fzn_catalog_merge_t      merge;
	fzn_catalog_capability_t capability;
	int            live;
} fzn_catalog_assertion_t;

/* A resolved entry: a value and WHOSE it is (C5b/C11 -- a view must name whose
 * value it shows). For AUTHORITATIVE, `authoritative` marks the designated
 * issuer's value; it is 0 for UNION and DISTINCT. */
typedef struct fzn_catalog_resolved {
	const uint8_t *value;
	size_t         value_len;
	const uint8_t *issuer;
	size_t         issuer_len;
	int            authoritative;
} fzn_catalog_resolved_t;

/* Structural equality of two assertions: same issuer, entity, name, value and
 * all four axes. `live` is not compared -- it is read-time state, not identity. */
int fzn_catalog_assertion_eq(const fzn_catalog_assertion_t *a,
                               const fzn_catalog_assertion_t *b);

/* C28: refuse a resolution set that is not all one attribute. Every assertion
 * must share entity, name, class, scope, merge and capability, and every enum
 * must be known (C28/F26). Read-only; FZN_CATALOG_OK when the set is sound.
 * An empty set is sound (it resolves to nothing). */
fzn_catalog_err_t fzn_catalog_validate(const fzn_catalog_assertion_t *set,
                                           size_t count);

/* C5b resolution over the LIVE assertions of one attribute. The rule is read
 * from the set itself (all agree, per validate). Fills `out` with the resolved
 * view and writes its length to `*out_count`:
 *   UNION         -- the distinct live values (a set; C5c makes it race-free).
 *   AUTHORITATIVE -- the authority's live value first, marked authoritative,
 *                    then the other distinct live values (precedence, not
 *                    exclusivity: where the authority is silent, others stand).
 *                    `authority` names the designated issuer and is required.
 *   DISTINCT      -- every live assertion retained with its issuer, no winner
 *                    (C5b: the disagreement is presented; the display pick by
 *                    a local preference is the caller's, a display choice).
 * The set is validated first. `authority`/`authority_len` are used only for
 * AUTHORITATIVE and may be NULL/0 otherwise. */
fzn_catalog_err_t fzn_catalog_resolve(const fzn_catalog_assertion_t *set,
                                          size_t count,
                                          const uint8_t *authority,
                                          size_t authority_len,
                                          fzn_catalog_resolved_t *out,
                                          size_t out_cap, size_t *out_count);

/* =========================================================================
 * THE ATTRIBUTE WIRE ENCODING
 * =========================================================================
 *
 * Settled by the copyright holder on 2026-09-18 ("follow the new model"), the
 * one section-7 item that decided the wire form: an ATTRIBUTE record body
 * supersedes catalog/'s NAME and inline CONTENT. Membership (catalog/'s EDGE)
 * is facet/'s, and blob content is the filestore's -- the entity IS the hash.
 * The layout is `catalog/attribute.situ`; project.md sec 314 records it.
 *
 * The body carries the four axes, the name and the value -- NOT the issuer or
 * the entity. Those come from the record: issuer from `fzn_record_issuer`,
 * entity from `fzn_record_subject` (record.h calls subject "what it is about",
 * which is exactly an attribute's entity). A body repeating either would let
 * the two disagree about a record that verified, which catalog/catalog.h
 * refuses for the same reason. So the caller of decode passes those two from
 * the record it already holds, and this module stays free of record/ at link
 * time (the include above is for one constant).
 *
 * ONE ENCODING OF EACH ASSERTION, ENFORCED: an axis outside its enum, a length
 * that does not match the bytes, or a trailing byte is refused, because the
 * signature is over these bytes (C8). */
#define FZN_CATALOG_OBJECT_ATTRIBUTE 1u

/* object + class + scope + merge + capability + name_len. */
#define FZN_CATALOG_ATTR_HEAD_LEN 6u

/* The longest name (the length field is one byte). */
#define FZN_CATALOG_ATTR_NAME_MAX 255u

/* The longest value that can be sent WITH AN EMPTY NAME. It is not
 * FZN_RECORD_BODY_MAX: the head and the two-byte value length come out of the
 * body first, and a name comes out too. catalog/ found this exact defect as
 * FZN_CATALOG_INLINE_MAX only by building its encoder; encode enforces the real
 * bound, 6 + name_len + 2 + value_len <= FZN_RECORD_BODY_MAX, and refuses when
 * it does not hold. */
#define FZN_CATALOG_ATTR_VALUE_MAX \
	((size_t)FZN_RECORD_BODY_MAX - FZN_CATALOG_ATTR_HEAD_LEN - 2u)

/* Lay out an assertion's ATTRIBUTE body: the four axes, then the name, then the
 * value. Reads only `attr_class`, `scope`, `merge`, `capability`, `name`/`_len`
 * and `value`/`_len` from `a` -- the issuer and entity are the record's, not the
 * body's. Refuses FZN_CATALOG_ERR_KIND for an axis outside its enum,
 * FZN_CATALOG_ERR_MALFORMED for a null or a name longer than the length field,
 * and FZN_CATALOG_ERR_RANGE when the body does not fit `cap` or a record body.
 * Writes nothing unless the whole body fits, and sets `*len_out` on success. */
fzn_catalog_err_t fzn_catalog_attribute_encode(const fzn_catalog_assertion_t *a,
                                                   uint8_t *out, size_t cap,
                                                   size_t *len_out);

/* Read an ATTRIBUTE body into `*out`, borrowing name and value from `body` and
 * issuer and entity from the caller's pointers (which come from the record: its
 * issuer and its subject). `out->live` is set to 0 -- liveness is read-time
 * state a caller derives from journal position (C5c), not a property of the
 * bytes. Enforces the one canonical encoding: refuses FZN_CATALOG_ERR_MALFORMED
 * for a wrong object tag or a truncated head, FZN_CATALOG_ERR_KIND for an
 * unknown axis, and FZN_CATALOG_ERR_RANGE for a body larger than a record can
 * carry, or a name or value length that runs past the body or leaves a trailing
 * byte. The body-size bound is symmetric with encode's, so a body that decodes
 * always re-encodes to the same bytes. */
fzn_catalog_err_t fzn_catalog_attribute_decode(const uint8_t *issuer, size_t issuer_len,
                                                   const uint8_t *entity, size_t entity_len,
                                                   const uint8_t *body, size_t body_len,
                                                   fzn_catalog_assertion_t *out);

/* =========================================================================
 * REACHABILITY OVER THE NEW MODEL (project.md sec 317, step 1)
 * =========================================================================
 *
 * The old catalog/'s reach.c computed reachability over an EDGE DAG by a
 * transitive walk from roots. Here it is LOCAL: the model separates entities
 * (leaves) from dimensions (trees), so there is no node-that-is-also-a-set to
 * walk -- an entity is REFERENCED exactly when a live assertion names it (C9),
 * computed over the assertions a caller holds. These take an assertion set the
 * way resolve does; deciding which are live is the caller's (C5c). */

/* An issuer the set depends on, and how many of its assertions are in it. */
typedef struct fzn_catalog_issuer {
	const uint8_t *issuer;
	size_t         issuer_len;
	size_t         assertions;
} fzn_catalog_issuer_t;

/* Is `entity` REFERENCED -- named by at least one LIVE CURATED assertion in
 * the set?
 *
 * C9: a curated link is a reference; the host observation (C7/C8) is derived,
 * not an assertion here, so an unreferenced entity may still exist on disk and
 * removing it is the explicit C17 gesture, never a consequence of this.
 *
 * A HOLDER-CAPABILITY ASSERTION IS THAT HOST OBSERVATION AND DOES NOT COUNT.
 * "I hold these bytes" says where they are; it does not say anything wants
 * them kept. So the same assertion is invisible here and decisive for
 * `fzn_catalog_holders` below, which is the pair working as intended rather
 * than an inconsistency -- one query asks what wants an entity, the other asks
 * who has it. Counting a holder assertion here made every entity a host holds
 * referenced BY THE FACT OF HOLDING IT, which no sweep can escape. sec 321. */
int fzn_catalog_referenced(const fzn_catalog_assertion_t *set, size_t count,
                             const uint8_t *entity, size_t entity_len);

/* The distinct issuers the set depends on, with a per-issuer assertion count,
 * written to `out` (capacity `out_cap`); `*out_count` gets how many were
 * written and `*dropped` how many distinct issuers did not fit. Every issuer
 * is counted, live or not -- catching up with an issuer must see its
 * retractions too (C5c). FZN_CATALOG_OK unless an argument is null. */
fzn_catalog_err_t fzn_catalog_issuers(const fzn_catalog_assertion_t *set,
                                          size_t count, fzn_catalog_issuer_t *out,
                                          size_t out_cap, size_t *out_count,
                                          size_t *dropped);

/* The distinct hosts that HOLD `entity` (C8), written to `out` as for issuers.
 * Derived, not stored: a holder is the issuer of a LIVE HOLDER-capability
 * assertion (C5e/C8a) naming the entity -- only a host holding the bytes may
 * make one. `*out_count` == 1 means a last copy; a caller answers
 * this-host-holds by finding its own key among the holders. This is what the
 * old catalog/'s holdings/last-copy seams asked a callback; here it falls out
 * of the record set. FZN_CATALOG_OK unless an argument is null. */
fzn_catalog_err_t fzn_catalog_holders(const fzn_catalog_assertion_t *set,
                                          size_t count, const uint8_t *entity,
                                          size_t entity_len,
                                          fzn_catalog_issuer_t *out, size_t out_cap,
                                          size_t *out_count, size_t *dropped);

/* A stable, allocation-free name for an error. */
const char *fzn_catalog_err_str(fzn_catalog_err_t err);

#endif /* FZN_CATALOG_H */
