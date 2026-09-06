/*
 * A catalogue: named sets whose members may belong to several of them.
 *
 * project.md sec 142. The copyright holder described "a tree file/text store
 * which has slots for different (named, unique by hierarchy/name) files", and
 * then the property that decides the shape: **both directories and files can
 * be linked from several parents, and several directories can be combined as
 * search terms.**
 *
 * THAT IS NOT A TREE, AND CALLING IT ONE COSTS THE DESIGN. A node with many
 * parents is a DAG, and combining directories as search terms is set
 * intersection. So a "directory" here is a NAMED SET and the hierarchy is a
 * VIEW OVER MEMBERSHIP rather than a place things live:
 *
 *     a node belongs to as many sets as somebody says it does
 *     a path names a set; it is not where a node is stored
 *     combining directories intersects their memberships
 *     editing adds and removes memberships, and moves nothing
 *
 * That is why it is easy to edit, and it is why a hierarchical key would not
 * do: a hierarchical key has one parent by construction.
 *
 * ONE NODE TYPE, NOT TWO. A directory and a file are ROLES rather than kinds
 * -- the holder's own statement is that both can be linked from several
 * parents, so anything that distinguished them would have to allow the same
 * operations on each anyway. A node that has members is being used as a
 * directory; one that has content is being used as a file; a node may be
 * both, and nothing here needs to know which.
 *
 * AN ID IS A NAME AND NOT A DIGEST, and the first version of this comment
 * said the opposite. It suggested a content-addressed entry could use its own
 * digest as its id -- which works only for something that never changes,
 * because editing the content would change the id and every edge pointing at
 * it would break. A catalogue the holder asked to be easy to EDIT cannot have
 * that. So an id is a stable name, and content is a separate versioned
 * assertion ABOUT that name; see `fzn_catalog_entry_t`. project.md sec 145.
 *
 * IT REFUSES LOUDLY AND EVICTS NEVER. sec 142: "a catalogue entry that
 * vanishes is a feature the consumer stops offering, silently." A full table
 * therefore answers FZN_CATALOG_ERR_FULL rather than dropping the oldest --
 * which is `record/journal.h`'s rule rather than `log/log.h`'s, and the
 * difference is that a log is a stream where losing the oldest is normal.
 *
 * NOTHING HERE RECURSES, SO NOTHING HERE REFUSES A CYCLE. `fzn_catalog_members`
 * is one level, and a cycle among sets is harmless to every query in this
 * file. A consumer that adds recursive traversal inherits the problem and
 * must carry its own visited set; that is said here rather than guarded
 * against, because a check this module cannot exercise is one it should not
 * claim.
 */
#ifndef FZN_CATALOG_H
#define FZN_CATALOG_H

#include "../blob/blob.h"
#include "../chain/chain.h"
#include "../record/record.h"

#include <stddef.h>
#include <stdint.h>

#define FZN_CATALOG_ID_LEN 32

/*
 * A node's identity, as a type rather than as thirty-two bytes.
 *
 * Wrapped for the reason `fzn_cap_id_t` is: a public key, a capability and a
 * digest are all thirty-two bytes here, so passing one where another belongs
 * compiles clean and means something else. A struct and a `const uint8_t *`
 * are incompatible in both directions.
 */
typedef struct fzn_catalog_id {
	uint8_t b[FZN_CATALOG_ID_LEN];
} fzn_catalog_id_t;

typedef enum fzn_catalog_err {
	FZN_CATALOG_OK = 0,
	/* A null argument, or a table whose `used` runs past its capacity. */
	FZN_CATALOG_ERR_MALFORMED = -1,
	/* No room for a new edge. LOUD RATHER THAN SILENT: see the header on
	 * why this refuses where a log evicts. */
	FZN_CATALOG_ERR_FULL = -2,
	/* An assertion that lost to the one already held. NOT A FAULT -- it is
	 * the normal outcome when two hosts describe the same edge and the
	 * resolver prefers what is here, and a caller that logged it as an
	 * error would fill a log on a working network. */
	FZN_CATALOG_ERR_STALE = -3,
	/* No such membership. A caller filing a node under a directory it does
	 * not belong to has the filing and the DAG out of step, and saying so
	 * is more use than quietly creating the edge. */
	FZN_CATALOG_ERR_ABSENT = -5,
	/* Bytes that are not a catalogue assertion, or are one written a way
	 * this build does not produce. Distinct from MALFORMED because that is
	 * the caller's bug and this is a PEER'S BYTES -- the same distinction
	 * `chain/chain.h` draws between MALFORMED and CHAIN_INVALID. */
	FZN_CATALOG_ERR_SHAPE = -4,
} fzn_catalog_err_t;

const char *fzn_catalog_err_str(fzn_catalog_err_t err);

/*
 * One assertion that a node is, or is not, a member of a set.
 *
 * AN UNLINK IS RETAINED RATHER THAN DELETED, which is the tombstone
 * `chain/revocation.c` keeps for the same reason: an edge removed from the
 * table entirely would be re-created by any stale assertion that arrived
 * afterwards, so a removal would undo itself on the next sync. `present`
 * carries the answer and the row stays.
 */
typedef struct fzn_catalog_edge {
	fzn_catalog_id_t parent;
	fzn_catalog_id_t child;
	/* Who said so, and where in their stream. Both are needed: a sequence
	 * is only comparable within one issuer's stream, which is what makes
	 * the resolver below a seam rather than a comparison. */
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint64_t seq;
	int present;
	/* THIS HOST'S FILING, AND IT DOES NOT TRAVEL. See the filing section
	 * below: at most one edge per child carries it, and no wire form has a
	 * bit for it, because where a host keeps its bytes is that host's
	 * business and not an assertion about the catalogue. */
	int filed;
} fzn_catalog_edge_t;

/*
 * Which of two assertions about one edge stands.
 *
 * A SEAM BECAUSE THE HOLDER ASKED FOR ONE -- "a wide variety of configurable
 * conflict resolution strategies" -- and because no fixed rule is defensible
 * here. A sequence orders one issuer's statements and says nothing about
 * another's, so "the later one wins" is not even expressible across issuers
 * without a policy that decides whose clock or whose authority counts.
 *
 * Returns NONZERO to take `offered`, zero to keep `held`.
 *
 * `fzn_catalog_add_wins` is supplied and is the useful default, for the
 * reason sec 142 records: memberships are sets, and adds commute. What is
 * genuinely contended is add against remove, and that is the one case a
 * strategy has to answer.
 */
typedef struct fzn_catalog_resolve_ops {
	int (*prefer)(void *ctx, const fzn_catalog_edge_t *held,
	              const fzn_catalog_edge_t *offered);
	void *ctx;
} fzn_catalog_resolve_ops_t;

/*
 * An issuer's later statement supersedes its own; between issuers, presence
 * wins.
 *
 * THE ORDER OF THOSE TWO IS THE WHOLE RULE, and getting it the other way
 * round makes a catalogue nothing can be removed from. Checking presence
 * first means an unlink never beats a link even from the same issuer that
 * wrote it -- which is a store that only grows, and the holder asked for one
 * that is easy to EDIT.
 *
 * So: one issuer restating its own edge is not a conflict at all, just a
 * later statement, and that is what makes a removal possible. A conflict is
 * across issuers, and there presence wins, which is where "add wins" means
 * something: two hosts adding a member agree whatever order the assertions
 * arrive in.
 *
 * WHAT THIS IS NOT is an observed-remove set. A proper OR-Set lets a remove
 * cancel exactly the adds it has SEEN, so a concurrent add survives a remove
 * that never knew about it -- and that needs causal metadata on every edge.
 * This rule is the honest first pass: it is total, it needs no extra state,
 * and it is a seam precisely so a consumer that needs the stronger semantics
 * can supply them without this module guessing.
 */
int fzn_catalog_add_wins(void *ctx, const fzn_catalog_edge_t *held,
                         const fzn_catalog_edge_t *offered);

typedef struct fzn_catalog {
	fzn_catalog_edge_t *edges;
	size_t capacity;
	size_t used;
	const fzn_catalog_resolve_ops_t *resolve;
	/* This host's filing root, and whether one has been set. Held rather
	 * than derived because there is nothing to derive it from: which node
	 * is the root is a choice, and a catalogue with several plausible ones
	 * would otherwise pick. */
	fzn_catalog_id_t filing_root;
	int filing_root_set;
	/* The content table, or nulls when a consumer uses this as structure
	 * only. See `fzn_catalog_content_init`. */
	struct fzn_catalog_entry *entries;
	size_t entry_capacity;
	size_t entry_used;
	const struct fzn_catalog_content_ops *content_resolve;
} fzn_catalog_t;

/* Point a catalogue at caller-owned rows, and zero them.
 *
 * A zero capacity is refused rather than accepted as an empty catalogue,
 * which is `fzn_journal_init`'s rule: a table that can hold nothing records
 * nothing and reports success while doing it. */
fzn_catalog_err_t fzn_catalog_init(fzn_catalog_t *catalog, fzn_catalog_edge_t *edges,
                                   size_t capacity, const fzn_catalog_resolve_ops_t *resolve);

/*
 * Assert that `child` is, or is not, a member of `parent`.
 *
 * ONE CALL FOR BOTH, because a link and an unlink are the same statement
 * about the same edge with a different answer -- and giving them separate
 * entry points would mean two paths through the resolver, which is where the
 * only interesting decision is made.
 *
 * An edge nobody has asserted is added. One already held goes to the
 * resolver, and FZN_CATALOG_ERR_STALE says the held assertion stood.
 */
fzn_catalog_err_t fzn_catalog_assert(fzn_catalog_t *catalog, const fzn_catalog_id_t *parent,
                                     const fzn_catalog_id_t *child,
                                     const uint8_t issuer[FZN_PUBKEY_LEN], uint64_t seq,
                                     int present);

/* Whether this catalogue holds `child` as a member of `parent`. Total: an
 * edge nobody asserted and one asserted absent both answer zero, because a
 * caller asking "is it a member" wants one answer and the difference between
 * never-said and said-no is `fzn_catalog_edge_of`'s question. */
int fzn_catalog_linked(const fzn_catalog_t *catalog, const fzn_catalog_id_t *parent,
                       const fzn_catalog_id_t *child);

/* The edge as held, or NULL when none was ever asserted -- which is how a
 * caller tells a tombstone from silence. */
const fzn_catalog_edge_t *fzn_catalog_edge_of(const fzn_catalog_t *catalog,
                                              const fzn_catalog_id_t *parent,
                                              const fzn_catalog_id_t *child);

/* Members of a set, and sets a node belongs to. Both write up to `cap` ids
 * and return how many were written; a caller wanting to know it was cut short
 * compares against `cap`. One level, never recursive -- see the header. */
size_t fzn_catalog_members(const fzn_catalog_t *catalog, const fzn_catalog_id_t *parent,
                           fzn_catalog_id_t *out, size_t cap);
size_t fzn_catalog_parents(const fzn_catalog_t *catalog, const fzn_catalog_id_t *child,
                           fzn_catalog_id_t *out, size_t cap);

/*
 * Nodes that belong to EVERY one of `parents`: directories combined as search
 * terms, which is the operation the multi-parent structure exists for.
 *
 * An empty `parent_count` returns nothing rather than everything. The other
 * reading -- an empty intersection is the universe -- is defensible in set
 * theory and wrong here, because the query means "show me what matches these
 * terms" and no terms is a caller that has not chosen yet.
 */
size_t fzn_catalog_intersect(const fzn_catalog_t *catalog, const fzn_catalog_id_t *parents,
                             size_t parent_count, fzn_catalog_id_t *out, size_t cap);


/*
 * WHAT A NODE HOLDS, WHICH IS ONE MECHANISM AND NOT TWO.
 *
 * project.md sec 142 asked whether an entry should be a record or a blob
 * reference, and sec 145 records why that was the wrong shape of question: a
 * blob reference IS content, and it has to be signed, ordered and synced like
 * any other statement -- so the record layer is required either way. What
 * differs is only what the record's payload says.
 *
 * So a node's content is one assertion with three possible answers:
 *
 *     NONE     a pure set. A directory is a node with members and no bytes,
 *              and that is not an error or an absence -- it is what most of
 *              a catalogue's structure is.
 *     INLINE   the bytes are here, bounded by FZN_RECORD_BODY_MAX. One round
 *              trip, no spool, and the ordinary case for a filter list or a
 *              short configuration.
 *     BLOB     a digest naming content in `spool/`. Unbounded, deduplicated
 *              across every consumer that wants the same bytes, and
 *              resumable -- at the cost of a second fetch, and of a name
 *              that resolves to nothing until the blob arrives.
 *
 * THE THRESHOLD IS NOT A POLICY THIS MODULE SETS. A caller that can fit its
 * bytes inline may still choose a blob, because it wants the deduplication or
 * expects the value to be shared; and one that cannot fit them has no choice.
 * What this refuses is an INLINE longer than a record body can carry, which
 * is a caller describing something it could never send.
 */
typedef enum fzn_catalog_content {
	FZN_CATALOG_CONTENT_NONE = 0,
	FZN_CATALOG_CONTENT_INLINE = 1,
	FZN_CATALOG_CONTENT_BLOB = 2,
} fzn_catalog_content_t;

const char *fzn_catalog_content_str(fzn_catalog_content_t kind);

typedef struct fzn_catalog_entry {
	fzn_catalog_id_t id;
	fzn_catalog_content_t kind;
	/* INLINE: the caller's bytes, not copied. A row points at what the
	 * caller holds, as everything in this library does, so the bytes must
	 * outlive the catalogue. */
	const uint8_t *bytes;
	size_t len;
	/* BLOB: the root, and the length so a consumer can decide whether to
	 * fetch BEFORE fetching. A name that resolves to nothing until the blob
	 * arrives is the cost of the indirection, and a size is what lets a
	 * caller weigh it. */
	uint8_t root[FZN_BLOB_HASH_LEN];
	uint64_t blob_len;
	/* Who said so, and where in their stream, as an edge carries. */
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint64_t seq;
} fzn_catalog_entry_t;

/*
 * Which of two statements about one node's content stands.
 *
 * A SECOND SEAM RATHER THAN THE EDGE ONE, because the question is different
 * and reusing it would answer the wrong one. An edge conflict has an
 * asymmetry to exploit -- presence against absence, where adds commute -- and
 * two contents have none: both are present, and neither is a superset of the
 * other. A resolver told to "prefer presence" would be deciding by a rule
 * that does not apply.
 *
 * Returns NONZERO to take `offered`.
 */
typedef struct fzn_catalog_content_ops {
	int (*prefer)(void *ctx, const fzn_catalog_entry_t *held,
	              const fzn_catalog_entry_t *offered);
	void *ctx;
} fzn_catalog_content_ops_t;

/* An issuer's later statement supersedes its own; between issuers, what is
 * held stands.
 *
 * KEEPING THE HELD ONE IS NOT A PREFERENCE FOR THE FIRST WRITER, it is the
 * only answer available that does not depend on arrival order: a sequence
 * orders one issuer's statements and says nothing about another's, so there
 * is no "later" to appeal to. A consumer that needs one -- highest authority,
 * a wall clock it trusts, a person asked -- supplies it, which is what the
 * seam is for. */
int fzn_catalog_content_held_wins(void *ctx, const fzn_catalog_entry_t *held,
                                  const fzn_catalog_entry_t *offered);

/* Point a catalogue's content table at caller-owned rows. Separate from
 * `fzn_catalog_init` so that a consumer using a catalogue purely as
 * structure -- tags over nodes whose content lives somewhere else entirely --
 * pays nothing for a table it will not fill. A catalogue with no content
 * table refuses every content call rather than silently doing nothing. */
fzn_catalog_err_t fzn_catalog_content_init(fzn_catalog_t *catalog,
                                           fzn_catalog_entry_t *entries, size_t capacity,
                                           const fzn_catalog_content_ops_t *resolve);

/* State what a node holds. `entry.id`, `kind` and the fields that kind uses
 * are read; the rest are ignored.
 *
 * FZN_CATALOG_ERR_MALFORMED for an INLINE past FZN_RECORD_BODY_MAX, an INLINE
 * with a length and no bytes, a BLOB of zero length, or a kind that is not
 * one of the three. */
fzn_catalog_err_t fzn_catalog_content_set(fzn_catalog_t *catalog,
                                          const fzn_catalog_entry_t *entry);

/* What a node holds, or NULL when nobody has said. A node with edges and no
 * content row is a pure set, and that is the common case rather than an
 * error. */
const fzn_catalog_entry_t *fzn_catalog_content_of(const fzn_catalog_t *catalog,
                                                  const fzn_catalog_id_t *id);


/*
 * THE WIRE FORM: a catalogue assertion as a record body.
 *
 * project.md sec 146. Everything above is an in-memory table, as
 * `record/journal.h` and `log/log.h` are; this is how one host tells another
 * what it holds.
 *
 * THE BODY DOES NOT REPEAT THE ISSUER OR THE SEQUENCE, and that is the whole
 * of why `fzn_catalog_apply` takes a RECORD rather than bytes. A record
 * already carries who signed it and where in their stream it sits; a body
 * repeating either would let the two disagree, and then a reader has to
 * choose which to believe about a record that verified. `record/store.h`
 * refuses the same thing for an address, and `chain/revocation.c` for a
 * record's identity: the fact comes out of what was signed rather than from
 * something beside it.
 *
 * THE BODY SAYS WHAT IT IS, because a record's `kind` is "the consumer's own
 * taxonomy" -- `record/record.h` says so -- and this library cannot assign
 * one. A leading tag means a consumer may put both assertions in one kind or
 * split them across two, and a reader needs no out-of-band agreement either
 * way.
 *
 *     edge, 66 bytes and fixed:
 *         [0]        FZN_CATALOG_OBJECT_EDGE
 *         [1..33)    parent
 *         [33..65)   child
 *         [65]       present, exactly 0 or 1
 *
 *     content, 34 bytes plus what the kind needs:
 *         [0]        FZN_CATALOG_OBJECT_CONTENT
 *         [1..33)    id
 *         [33]       kind
 *         NONE       nothing more; 34 bytes
 *         INLINE     the bytes; 34 + len
 *         BLOB       [34..66) root, [66..74) length; 74 bytes
 *
 * ONE ENCODING OF EACH ASSERTION, ENFORCED. A `present` outside {0,1}, a kind
 * outside the three, a length that does not match the kind -- each is refused
 * rather than absorbed. `chain/chain.h` gives the reason for `delegable` and
 * it is the same here: read loosely, 255 encodings of one statement exist,
 * the signature over each differs, and two implementations that both "work"
 * produce assertions the other rejects.
 */

#define FZN_CATALOG_OBJECT_EDGE 1u
#define FZN_CATALOG_OBJECT_CONTENT 2u

#define FZN_CATALOG_EDGE_BODY_LEN 66u
#define FZN_CATALOG_CONTENT_HEAD_LEN 34u
#define FZN_CATALOG_BLOB_BODY_LEN 74u

/*
 * The longest INLINE value that can actually be sent.
 *
 * IT IS NOT FZN_RECORD_BODY_MAX, AND THE TABLE ABOVE ACCEPTED THAT UNTIL
 * THIS EXISTED. An inline body is the value plus a 34-byte head, so a value
 * of exactly FZN_RECORD_BODY_MAX encodes to 546 and no record can carry it --
 * the in-memory bound admitted something the wire never could, which is a
 * defect that only building the encoder could show. project.md sec 146.
 */
#define FZN_CATALOG_INLINE_MAX ((size_t)FZN_RECORD_BODY_MAX - FZN_CATALOG_CONTENT_HEAD_LEN)

/* Lay out an edge assertion. `out` receives FZN_CATALOG_EDGE_BODY_LEN bytes.
 * Nothing is written unless the whole body fits. */
fzn_catalog_err_t fzn_catalog_edge_encode(const fzn_catalog_id_t *parent,
                                          const fzn_catalog_id_t *child, int present,
                                          uint8_t *out, size_t cap, size_t *len_out);

/* Lay out a content assertion. `entry`'s id, kind and the fields that kind
 * uses are read; its issuer and seq are NOT, because a record carries those.
 * FZN_CATALOG_ERR_MALFORMED for an INLINE past FZN_CATALOG_INLINE_MAX. */
fzn_catalog_err_t fzn_catalog_content_encode(const fzn_catalog_entry_t *entry, uint8_t *out,
                                             size_t cap, size_t *len_out);

/*
 * Apply a verified record to the catalogue.
 *
 * THE ISSUER AND SEQUENCE COME FROM THE RECORD, so there is no argument
 * through which to attribute an assertion to somebody who did not make it.
 *
 * IT DOES NOT VERIFY, AND A CALLER MUST -- `record/store.h` says the same at
 * length and for the same reason. A record's signature is checked with
 * `fzn_record_verify` against a key this module never sees; applying an
 * unverified record means anybody who can hand you bytes can edit your
 * catalogue.
 *
 * An INLINE entry's bytes are a VIEW INTO THE RECORD, not a copy, as
 * everything in this library is: the record's buffer must outlive the
 * catalogue row that points into it.
 *
 * FZN_CATALOG_ERR_SHAPE for bytes that are not a catalogue assertion;
 * otherwise whatever the assertion itself returns, FZN_CATALOG_ERR_STALE
 * included -- which is an answer rather than a fault.
 */
fzn_catalog_err_t fzn_catalog_apply(fzn_catalog_t *catalog, fzn_record_t record);


/*
 * THE FILING: the one tree, per host, that says where bytes actually live.
 *
 * project.md sec 147. Asked for by the copyright holder: one structure close
 * to the root is designated, **below it each file must exist exactly once**,
 * and that tree is the directory structure the host uses to store the files
 * on disk. It varies per host, and every host that stores the catalogue must
 * have one.
 *
 * WHY THE NAME. `layout` is this tree's word for a WIRE layout and is used
 * two hundred times that way; reusing it here would be two concepts sharing
 * one word, which `code-style.md` forbids. A filing is how a host files its
 * catalogue, the verb is what the mover does -- **refile** -- and the noun
 * survives being said out loud about a directory tree.
 *
 * IT IS A MARK ON AN EDGE, NOT A SECOND STRUCTURE. A node's filing parent is
 * one of the parents it already has, so a filing is a SUBSET of the
 * membership DAG rather than a tree beside it. That is what stops the two
 * disagreeing: a node cannot be filed under a directory it is not a member
 * of, because there would be no edge to mark.
 *
 * "EXACTLY ONCE" IS STRUCTURAL AND NOT CHECKED. At most one edge per child
 * carries the mark, and `fzn_catalog_file_under` clears any other as it sets
 * one -- so the invariant cannot be violated rather than being validated
 * afterwards. A check that walks the tree looking for a second path would be
 * a check somebody has to remember to run.
 *
 * AND IT DOES NOT TRAVEL. The wire form in the section above has no bit for
 * it and `fzn_catalog_apply` never sets one, which is what makes the setting
 * per host: two hosts sharing a catalogue agree about membership and choose
 * their own filing. A filing that synced would make one host's disk layout an
 * assertion the other had to accept.
 *
 * UNLINKING A FILED EDGE CLEARS THE FILING, because a node filed under a
 * directory it has left is a path to a place the catalogue no longer says it
 * belongs. The alternative -- keeping the mark on an absent edge -- leaves a
 * host computing a path from a membership nobody asserts.
 */

/* How deep a filing may go. A filing parent is one slot per node, so a cycle
 * is expressible -- file A under B and B under A -- and a walk needs a bound
 * rather than a promise. Refusing a cycle at the moment it is made would need
 * a walk per assertion; bounding the walk costs nothing and cannot be
 * forgotten. */
#define FZN_CATALOG_FILING_MAX_DEPTH 64u

/* Designate the node whose subtree is this host's filing.
 *
 * A CATALOGUE HAS NONE UNTIL THIS IS CALLED, and every path query then
 * refuses. The holder's requirement is that the tag must exist; a library
 * cannot make a caller supply one, so what it can do is refuse to answer
 * without it rather than inventing a root. */
fzn_catalog_err_t fzn_catalog_filing_root(fzn_catalog_t *catalog,
                                          const fzn_catalog_id_t *root);

/* The designated root, or NULL when none has been set. */
const fzn_catalog_id_t *fzn_catalog_filing_root_of(const fzn_catalog_t *catalog);

/*
 * File `child` under `parent`, replacing wherever it was filed before.
 *
 * The edge must already be a present membership, which is what keeps a
 * filing a subset of the DAG. FZN_CATALOG_ERR_ABSENT when it is not -- a
 * caller filing under a directory the node does not belong to has the two
 * out of step, and saying so is more use than quietly creating the edge.
 */
fzn_catalog_err_t fzn_catalog_file_under(fzn_catalog_t *catalog,
                                         const fzn_catalog_id_t *parent,
                                         const fzn_catalog_id_t *child);

/* Where a node is filed, or NULL when nowhere. A node with parents but no
 * filing is one this host has not placed on disk yet, which is an ordinary
 * state and not an error. */
const fzn_catalog_id_t *fzn_catalog_filed_under(const fzn_catalog_t *catalog,
                                                const fzn_catalog_id_t *child);

/*
 * The path from the filing root down to `node`, root first.
 *
 * Writes up to `cap` ids and returns how many. The node itself is the last,
 * so a node that IS the root gives a path of one.
 *
 * Zero means there is no path, and the reasons are worth telling apart in a
 * caller rather than here: no filing root has been set, the node is not filed
 * at all, the chain of filing parents does not reach the root, or it is
 * longer than FZN_CATALOG_FILING_MAX_DEPTH. All four are "this host cannot
 * say where that lives", which is one answer for a caller about to write a
 * file.
 */
size_t fzn_catalog_filed_path(const fzn_catalog_t *catalog, const fzn_catalog_id_t *node,
                              fzn_catalog_id_t *out, size_t cap);

#endif
