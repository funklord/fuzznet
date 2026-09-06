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
 * WHAT A NODE'S CONTENT IS, THIS MODULE DOES NOT SAY. sec 142 leaves the
 * record-or-blob question to the copyright holder, and this file is built so
 * that it stays open: an id is thirty-two bytes, so a content-addressed entry
 * can use its own digest as its id and a record-backed one can use anything
 * else. The structure is a membership relation either way.
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

#include "../chain/chain.h"

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

#endif
