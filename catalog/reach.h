/*
 * Which nodes nothing reaches, and the evidence needed to believe it.
 *
 * project.md sec 156. sec 155 built planned deletion on RETENTION -- what
 * this host has decided to keep -- and deliberately left reachability out,
 * naming the hazard: **an edge that has not arrived yet makes a live node
 * look orphaned**, and in a system whose shape is "ask again next round", not
 * having a record yet is the ordinary state rather than the exceptional one.
 * A host that swept on reachability would delete on the strength of a record
 * it has not received.
 *
 * THIS IS THE ANSWER TO THAT, AND IT IS NOT A BETTER WALK. The walk is the
 * easy half. What makes the answer usable is a discriminator between "nobody
 * links this" and "I have not caught up", and there is one:
 *
 *   **Reachability is relative to the issuers this host FOLLOWS, and that is
 *   exactly the set whose records shape this host's catalogue.**
 *
 * An issuer this host does not follow cannot link anything here, because its
 * records are never applied -- `fzn_journal_anchor` makes following an issuer
 * a decision, and `record/sync.h` refuses to fetch from a stranger a peer
 * merely mentioned. So a node no followed issuer links is unreachable in this
 * host's catalogue as a matter of fact rather than of guesswork, PROVIDED
 * this host has read everything those issuers have said.
 *
 * SO THE CALLER VOUCHES FOR A FRONTIER AND THIS REFUSES TO ANSWER WITHOUT
 * ONE. `fzn_catalog_unreachable` takes, per issuer, how far this host has
 * read -- which is what `fzn_sync_digest` already produces -- and refuses
 * with FZN_CATALOG_ERR_INCOMPLETE, naming the issuer, when the catalogue
 * depends on somebody the frontier does not account for.
 *
 * That converts "did you remember to check?" into a refusal. A caller can
 * still pass a frontier it has not earned, and no library can stop that; what
 * it cannot do is FORGET an issuer, which is the failure that actually
 * happens. `fzn_catalog_sources` is the other half: it says who a catalogue
 * depends on, which is a fact only the catalogue holds.
 *
 * WHAT THIS STILL CANNOT RULE OUT, said plainly because the whole module is
 * about not deleting on a guess: **a followed issuer may link the node
 * tomorrow.** Nothing observable today excludes that, and no amount of
 * catching up can. Reachability is a statement about now.
 *
 * WHICH IS WHY IT PROPOSES AND NEVER DELETES. This module answers a question.
 * Acting on the answer means marking a node FZN_CATALOG_RETAIN_DROP, and then
 * `catalog/sweep.h` removes bytes with its own two guards intact -- a blob a
 * retained node still needs is kept, and the last known copy is kept. So
 * being wrong about reachability costs a re-fetch where somebody else kept a
 * copy, which is the same cost as being wrong about retention, rather than a
 * new way to lose data.
 *
 * The three-step composition is the design:
 *
 *     fzn_catalog_unreachable   propose, with the frontier as evidence
 *     fzn_catalog_retain        the consumer decides, node by node
 *     fzn_catalog_sweep_*       remove bytes, guards unchanged
 */

#ifndef FZN_CATALOG_REACH_H
#define FZN_CATALOG_REACH_H

#include "catalog.h"

#include <stddef.h>
#include <stdint.h>

/*
 * One issuer a catalogue depends on, and how far this host has read them.
 *
 * `seq` is the highest this catalogue has APPLIED from that issuer, which is
 * not the same as the highest that exists -- see `fzn_catalog_unreachable`,
 * which is where the difference is checked.
 */
typedef struct fzn_catalog_source {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint64_t seq;
	/* How many rows -- edges, contents, names -- came from them. A hint
	 * for a consumer choosing whom to catch up with first, and nothing
	 * depends on it. */
	size_t rows;
} fzn_catalog_source_t;

/*
 * Who this catalogue depends on.
 *
 * Walks the edge, content and name tables and reports each distinct issuer
 * once. This is the fact only the catalogue holds, and it is the input to
 * "am I caught up": a consumer compares it against what its peers advertise.
 *
 * Returns how many were written, never more than `out_cap`. `dropped`
 * receives the number that did not fit and is REQUIRED -- `fzn_sync_digest`'s
 * rule, for its reason: the scan runs in table order, so a host that
 * overflows drops the same issuers every time and never learns it depends on
 * them.
 */
size_t fzn_catalog_sources(const fzn_catalog_t *catalog, fzn_catalog_source_t *out,
                           size_t out_cap, size_t *dropped);

/* What a caller vouches it has read. `fzn_sync_digest` produces the same
 * shape; `received` is the position, per issuer, this host has reached.
 *
 * PASS EVERY ISSUER THIS HOST FOLLOWS, not only those that have already
 * contributed. An issuer that has said nothing about this catalogue yet is
 * invisible to `fzn_catalog_sources` and is exactly the one whose unarrived
 * edge would make a live node look orphaned. Following it and being caught up
 * with it is what rules that out. */
typedef struct fzn_catalog_frontier {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint64_t received;
} fzn_catalog_frontier_t;

typedef struct fzn_catalog_reach {
	/* Known nodes the roots reach. */
	size_t reachable;
	/* Known nodes they do not, which is what `out` receives. */
	size_t unreachable;
	/* Unreachable, and `out_cap` had no room. SAFE TO COUNT rather than
	 * refuse: a short list of candidates is a smaller proposal, and the
	 * next walk finds the rest. Contrast the scratch array, which is not
	 * -- see the function. */
	size_t truncated;
	/* Roots that were named and walked from. */
	size_t roots;
	/* THE ISSUER THE FRONTIER DID NOT ACCOUNT FOR, when the answer is
	 * FZN_CATALOG_ERR_INCOMPLETE. Set with `unvouched_set`, so a caller is
	 * told WHICH rather than having to diff two lists to find out. */
	uint8_t unvouched[FZN_PUBKEY_LEN];
	int unvouched_set;
} fzn_catalog_reach_t;

/*
 * The nodes the named roots do not reach.
 *
 * A node is KNOWN when it is the parent or child of a PRESENT edge, or holds
 * content, or has a name. An absent edge is a tombstone -- sec 144 -- and
 * neither reaches anything nor makes its child known.
 *
 * `roots` ARE THE CALLER'S AND ARE NOT DERIVED. Which top-level sets matter
 * is a policy this module cannot see: the filing root is the obvious one and
 * a consumer may have several, or none of them may be the filing root at all.
 * Deriving them -- "every node with no parent is a root" -- would make the
 * answer vacuous, since then nothing is ever unreachable.
 *
 * A ROOT THE CATALOGUE DOES NOT KNOW IS REFUSED, with
 * FZN_CATALOG_ERR_ABSENT, and zero roots likewise with
 * FZN_CATALOG_ERR_MALFORMED. Both would otherwise report the entire
 * catalogue as garbage from a typo, and this is the one module where that
 * answer gets acted on.
 *
 * `scratch` HOLDS THE WALK and must fit every reachable node. Running out is
 * FZN_CATALOG_ERR_FULL and never a counter, which is the opposite of how
 * `out` truncating is treated, for a reason worth stating: a short scratch
 * makes reachable nodes look UNREACHABLE, so the failure direction is a
 * proposal to delete live data. A short `out` only proposes less.
 *
 * THE FRONTIER IS CHECKED, NOT TRUSTED, in the two directions that are
 * checkable from here:
 *
 *   - Every issuer this catalogue depends on must appear in it, or
 *     FZN_CATALOG_ERR_INCOMPLETE with the issuer named in the plan. This is
 *     the structural half: a caller cannot forget one.
 *   - A frontier behind this catalogue's own applied sequence for an issuer
 *     is incoherent -- the caller has applied records it says it has not
 *     read -- and is refused the same way.
 *
 * The third direction is NOT checkable here and is the caller's: a frontier
 * AHEAD of what the catalogue has applied is ordinary, because an issuer's
 * stream may carry records that are not catalogue assertions. Only the
 * consumer knows whether the gap is those or a backlog it has not applied.
 */
fzn_catalog_err_t fzn_catalog_unreachable(const fzn_catalog_t *catalog,
                                          const fzn_catalog_id_t *roots, size_t root_count,
                                          const fzn_catalog_frontier_t *frontier,
                                          size_t frontier_count, fzn_catalog_id_t *scratch,
                                          size_t scratch_cap, fzn_catalog_id_t *out,
                                          size_t out_cap, fzn_catalog_reach_t *plan);

/* How many distinct nodes this catalogue knows, so a caller can size
 * `scratch` and `out` before walking. Counted the same way the walk counts
 * them, so a scratch of this size cannot overflow. */
size_t fzn_catalog_nodes(const fzn_catalog_t *catalog);

#endif /* FZN_CATALOG_REACH_H */
