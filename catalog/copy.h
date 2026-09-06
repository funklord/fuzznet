/*
 * Copying a catalogue, and its contents, to another host.
 *
 * project.md sec 154. The copyright holder asked for "the cross host-copy of
 * a catalog and its contents" after sec 152 built retention. This is the
 * decision layer for the second half of that sentence; the first half was
 * already built and this header's first job is to say so, because the
 * expensive mistake here is writing a second replication path beside the one
 * that exists.
 *
 * THE STRUCTURE ALREADY TRAVELS AND NOTHING NEW IS NEEDED FOR IT. A
 * catalogue's edges, contents and names are record bodies -- sec 146 --
 * carried in an issuer's stream. So adopting a catalogue is three things this
 * library already does:
 *
 *     fzn_journal_anchor    follow the issuer, which is a decision and not
 *                           something a peer's advertisement may make
 *     fzn_sync_plan_fetch   ask for the records that are missing
 *     fzn_catalog_apply     apply each verified record
 *
 * A catalogue several people edit is several issuers and several anchors;
 * nothing here changes that.
 *
 * WHAT DOES NOT TRAVEL, AND WHY EACH IS DELIBERATE. The filing is per-host --
 * sec 147, where a host keeps its bytes is its own arrangement -- and the
 * retention table is per-host by sec 152, because a retention that synced
 * would make one host's disk budget an assertion every other host had to
 * accept. Neither has a wire form and neither gains one here. A copy is
 * therefore never a copy of the sender's arrangements: two hosts holding the
 * same catalogue may file it differently and keep different parts of it, and
 * both are correct.
 *
 * WHAT IS LEFT IS THE BYTES. An INLINE entry arrived inside the record that
 * asserted it, so a host that applied the record has the value. A BLOB entry
 * is a root and a length, and the bytes are somewhere else -- `spool/` fetches
 * them. This file answers the three questions around that fetch, and answers
 * nothing else:
 *
 *     what do I still need      fzn_catalog_copy_want
 *     what do I actually have   fzn_catalog_copy_holdings
 *     what can I give a peer    fzn_catalog_copy_offer
 *
 * IT DECIDES AND DOES NOT SEND, which is `record/sync.h`'s rule and is taken
 * from it deliberately rather than by imitation. The comparison this file
 * performs is identical in every consumer; the timers, the choice of peer and
 * the framing are not, and `wire/seal.h` and `chunk/` are already there for
 * the last of those. So there is no encoder here, exactly as there is none in
 * `record/sync.h`.
 *
 * A HOLDING IS A FACT AND A RETENTION IS AN INTENTION, AND SEC 152 RAN THEM
 * TOGETHER. That section said the retention table "is that map" -- the map of
 * which host stores which files -- and it is not, quite. Retention is what
 * this host has decided to keep; holdings are which bytes it actually has.
 * They diverge in both directions and each direction is ordinary rather than
 * exceptional: a node marked KEEP whose blob has not been fetched yet is
 * retained and not held, and a node marked DROP whose bytes are still on disk
 * is held and not retained.
 *
 * The distinction is not pedantry, because publishing the wrong one is a
 * different failure in each direction. Publish the intention and a peer
 * fetches from a host that has nothing to give it, once per node, for as long
 * as the intention outlives the gap. Publish the holdings and a peer learns
 * only what is true today, which is the thing it can act on. So
 * `fzn_catalog_copy_holdings` asks the seam below rather than reading the
 * retention table, and the two never share a code path.
 *
 * THE SEAM IS "DO YOU HAVE THESE BYTES", NOT "OPEN THEM". A consumer answers
 * from wherever its blobs live -- `spool/spool.h`, a content-addressed
 * directory, a database -- and this file never learns which. NONZERO means
 * held, as every ops callback in this library says yes with a nonzero, so a
 * consumer that returns a `bool` and one that returns a count both work.
 */

#ifndef FZN_CATALOG_COPY_H
#define FZN_CATALOG_COPY_H

#include "catalog.h"

#include <stddef.h>
#include <stdint.h>

/*
 * One blob a catalogue references: wanted, held, or offered.
 *
 * THE ROOT IS THE IDENTITY AND THE LENGTH IS CARRIED FOR THE FETCHER. A
 * consumer needs the length before it fetches -- `fzn_catalog_entry_t` says
 * why it is on the entry at all -- and a want list that omitted it would send
 * every consumer back to the catalogue for a second lookup it has already
 * done.
 *
 * SO A WANT CARRIES A LENGTH AND AN OFFER IGNORES THE PEER'S. When a peer
 * asks for a root this catalogue knows, the length answered is THIS
 * catalogue's, not the peer's: the catalogue is what is being copied, so its
 * own statement about its own entry is the one that stands. A peer whose
 * length disagrees is describing a different object under the same hash,
 * which is either a defect on their side or a claim nobody should take at
 * face value; either way it is not a reason to answer with their number.
 */
typedef struct fzn_catalog_blob {
	uint8_t root[FZN_BLOB_HASH_LEN];
	uint64_t len;
} fzn_catalog_blob_t;

/*
 * Whether this host has a blob's bytes.
 *
 * Returns NONZERO for held. A seam that cannot answer -- a store that is
 * offline, a directory that will not open -- says zero, and the consequence
 * is a want list that asks for something already present. That is the safe
 * direction: a redundant fetch costs bandwidth, while a false "held" makes a
 * host advertise bytes it cannot serve and quietly drops the node out of
 * every want list it will ever compute.
 */
typedef struct fzn_catalog_holdings_ops {
	int (*holds)(void *ctx, const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t len);
	void *ctx;
} fzn_catalog_holdings_ops_t;

/*
 * What a walk produced, including everything it could not fit or would not
 * take.
 *
 * ZEROED BEFORE THE ARGUMENTS ARE CHECKED, so a plan never holds the previous
 * round's numbers -- `fzn_sync_plan_t`'s rule, and for the same reason: a
 * caller that reads the counters after an error would otherwise read the last
 * successful walk's.
 *
 * `written` and `truncated` are the two a caller acts on. The rest are why
 * the rest of the catalogue is not in the list, and they are kept apart
 * rather than summed because they call for different actions: `not_retained`
 * is this host's own policy working, `already_held` is the copy making
 * progress, `inline_ready` is a node that never needed fetching, and
 * `unknown` is a peer asking for something outside the catalogue.
 *
 * THE COUNTERS ARE TWO GROUPS AND THE SUITE ASSERTS BOTH SUMS, because a
 * count that does not have to add up is a count nobody can check.
 *
 * CLASSIFICATION partitions what was examined, and every item lands in
 * exactly one counter:
 *
 *     examined = not_retained + inline_ready + no_content
 *              + already_held + missing + unknown
 *
 * WHAT IS EXAMINED DIFFERS AND THE SUM DOES NOT. A want or holdings walk
 * examines this catalogue's content entries; an offer examines the peer's
 * wants. So the three entry-shaped counters are zero in an offer and
 * `unknown` is zero in a walk, and one arithmetic covers both -- which is
 * what makes it worth asserting rather than two that each hold in one place.
 *
 * EMISSION says what became of the class that call selected, and the three
 * always account for it exactly:
 *
 *     written + truncated + duplicates = missing        (want)
 *                                      = already_held   (holdings, offer)
 *
 * `not_retained` is a want walk's alone. A holdings announcement never reads
 * the retention table, so it leaves that counter at zero -- which is the
 * difference between a fact and an intention showing up in the arithmetic.
 */
typedef struct fzn_catalog_copy {
	/* Blobs written to `out`. */
	size_t written;
	/* Wanted or offered, and `out_cap` had no room. Fixed by passing a
	 * bigger array; the next walk starts over rather than resuming, since
	 * a catalogue that changed under a cursor would resume into a
	 * different list.
	 *
	 * IT IS AN UPPER BOUND ONCE THE ARRAY IS FULL, NOT A COUNT, and the
	 * difference is worth a sentence because a bound quoted as a value is
	 * how a number stops being checkable. Deduplication compares against
	 * what has been WRITTEN, so two references to one blob that both
	 * arrive after the array filled are two truncations rather than one
	 * duplicate -- there is nowhere to remember the first, the caller's
	 * array being the only storage this module has.
	 *
	 * So `written + truncated` sizes an array that is certainly big
	 * enough and may be bigger than needed, and a second walk into that
	 * array reports the exact figure. That is the safe direction and it is
	 * not worth removing: the alternative is a scratch buffer this library
	 * does not allocate, to make a sizing pass exact on the one input --
	 * many shared blobs, no room for any of them -- where it is loosest. */
	size_t truncated;
	/* Entries this host has chosen not to keep. sec 152. */
	size_t not_retained;
	/* A blob whose bytes this host has. */
	size_t already_held;
	/* A blob whose bytes this host does not have. In a want walk this is
	 * the set that gets emitted; in a holdings walk it is how far the copy
	 * still has to go, which is worth a number rather than an absence. */
	size_t missing;
	/* Retained, and the value arrived inside the record that asserted it,
	 * so there is nothing to fetch. */
	size_t inline_ready;
	/* Nodes with no content at all -- a directory, or a node that is
	 * structure only. */
	size_t no_content;
	/* A second reference to a blob already written. Deduplicated rather
	 * than listed twice: the whole reason a caller may prefer a blob to an
	 * inline value is that several nodes share it. */
	size_t duplicates;
	/* OFFER ONLY: a peer asked for a root this catalogue does not
	 * reference. Counted rather than served, and that is the security
	 * property -- see `fzn_catalog_copy_offer`. */
	size_t unknown;
} fzn_catalog_copy_t;

/*
 * What this host still needs to hold everything it has chosen to keep.
 *
 * Walks the content table and writes a blob for every entry that is retained,
 * is a BLOB rather than an INLINE, and whose bytes this host does not have.
 * That list is what goes to a peer; it is the only thing about this host's
 * retention that ever leaves it, and it is a request the host chose to make
 * rather than a policy anybody else must accept.
 *
 * THE FILING HAS NO PART IN THIS. Where a host will put the bytes is settled
 * by sec 147 and does not decide whether to fetch them; a catalogue with no
 * filing root at all produces exactly the same want list.
 *
 * FZN_CATALOG_ERR_BUSY while ANY job holds the catalogue, which is sec 149's
 * rule that progress is the only question a held catalogue answers. A want
 * list computed mid-refile would be honest about the bytes and useless about
 * where they go, and one computed mid-sweep would ask for bytes that are
 * being deleted as it is written. sec 155 made the lock a kind rather than a
 * refile flag; this reads it as the one bit it cares about, which is whether
 * anybody holds it.
 *
 * `holdings` may be null, which means this host holds nothing yet -- the
 * state a host adopting a catalogue is actually in, and worth being the easy
 * case rather than requiring a stub that always says no.
 *
 * `now` IS HERE AND NOT ON THE OTHER TWO, and the asymmetry is sec 154's
 * argument showing up in the signatures. sec 157 gave retention a deadline,
 * so what a host has DECIDED to keep is a question with a moment in it. What
 * it HOLDS is not: a holdings announcement and an offer read the seam and
 * never the retention table, so there is no time at which their answer
 * differs. A `now` on those would be a parameter nothing could use, and the
 * day somebody made it do something the fact and the intention would have
 * started sharing a code path again.
 */
fzn_catalog_err_t fzn_catalog_copy_want(const fzn_catalog_t *catalog,
                                        const fzn_catalog_holdings_ops_t *holdings,
                                        uint64_t now, fzn_catalog_blob_t *out, size_t out_cap,
                                        fzn_catalog_copy_t *plan);

/*
 * What this host actually holds of this catalogue, to tell a peer.
 *
 * THE MAP SEC 152 SAID WAS MISSING, and it is derived from the seam rather
 * than from the retention table -- see the header comment, which is where
 * that correction is argued. Every blob this catalogue references and this
 * host has, whatever this host intends to do with it: a node marked DROP
 * whose bytes are still on disk is held, and a peer that wants it may have
 * it.
 *
 * `not_retained` is not consulted and stays zero. A holdings announcement is
 * a statement about bytes, and mixing policy into it would publish the
 * intention this file exists to keep private.
 */
fzn_catalog_err_t fzn_catalog_copy_holdings(const fzn_catalog_t *catalog,
                                            const fzn_catalog_holdings_ops_t *holdings,
                                            fzn_catalog_blob_t *out, size_t out_cap,
                                            fzn_catalog_copy_t *plan);

/*
 * What this host can give a peer, from what the peer asked for.
 *
 * `wants` is the list a peer produced with `fzn_catalog_copy_want`. The
 * answer is every want this catalogue references and this host holds.
 *
 * THE OFFER IS SCOPED TO THE CATALOGUE, AND THAT IS THE POINT RATHER THAN A
 * DETAIL. A want naming a root no entry in this catalogue references is
 * counted in `unknown` and never served. Without that, a want list is a
 * general "hand me any blob whose hash I can name" request, and a peer
 * authorised for one catalogue could read bytes out of every other one this
 * host holds -- a capability for a catalogue silently becoming a capability
 * for the blob store. What the peer learns instead is bounded by what it is
 * copying: which parts of THIS catalogue this host has, which is exactly what
 * copying it entitles it to know.
 *
 * A want the catalogue knows and this host does not hold is simply absent
 * from the offer. It is not an error and not counted apart: a peer asks
 * again next round, which is `record/sync.h`'s pull shape and survives loss
 * without acknowledgements.
 *
 * THE LENGTH ANSWERED IS THIS CATALOGUE'S. See `fzn_catalog_blob_t`.
 */
fzn_catalog_err_t fzn_catalog_copy_offer(const fzn_catalog_t *catalog,
                                         const fzn_catalog_holdings_ops_t *holdings,
                                         const fzn_catalog_blob_t *wants, size_t want_count,
                                         fzn_catalog_blob_t *out, size_t out_cap,
                                         fzn_catalog_copy_t *plan);

#endif /* FZN_CATALOG_COPY_H */
