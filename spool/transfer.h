/* Who was asked for what, and how fast to ask -- the multi-peer half.
 *
 * `spool/plan.h` names this file's job in the negative: it says rarest-first
 * "needs what the OTHER peers hold, which is not in this store and is the
 * multi-peer assignment problem this file does not solve." This solves the
 * part of that problem that does not need to know what other peers hold --
 * not choosing WHICH range is most valuable, but making sure two peers are
 * not sent the same one and that a peer which goes quiet does not take a
 * range with it.
 *
 * project.md sec 107 records what fuzzypickles' transfer holds, asked for
 * before this was designed. Four of their five properties are here; the
 * fifth, that a batch is the unit of request, verification, retry and
 * congestion at once, is the one this tree answers differently and sec 107
 * says why.
 *
 * TWO SETS, NOT ONE, AND ONLY ONE OF THEM IS NEW. `pending` is what has been
 * asked for; `held` is what has arrived. Their tree keeps both because an
 * abandoned batch must return to the want-list, which means forgetting the
 * ASK without forgetting the HOLDINGS -- a single set cannot express that,
 * since clearing it loses data and keeping it re-asks nothing.
 *
 * Here `held` already exists: it is the spool's bitmap. So only `pending` is
 * added, and **the return to the want-list needs no code at all** -- dropping
 * an assignment is forgetting the ask, and the holdings were never touched
 * because a batch that failed verification never reached the bitmap.
 * `fzn_spool_plan_want` re-emits the range on its next call by construction.
 *
 * PENDING IS AN ASSIGNMENT TABLE AND NOT A SECOND BITMAP, for two reasons
 * and the second is the one that decides it. A bitmap would cost another
 * 512 KiB at the blob ceiling to record something bounded by requests in
 * flight rather than by blob size. And a bitmap cannot say WHO was asked --
 * which is the whole of the abandon path, since a range is returned because
 * a particular peer went quiet.
 *
 * A PEER IS AN OPAQUE NUMBER THIS LIBRARY NEVER INTERPRETS. Sec 102 lists a
 * consumer's peer model first among the things that must not travel, and
 * `spool/message.h` declines the same question about the cookie for the same
 * reason. A caller that identifies peers by address, by public key, or by a
 * slot index passes whatever it uses; nothing here compares two peers except
 * for equality, and nothing here decides which peer to ask.
 *
 * THE RECORD GOES IN BEFORE THE NEXT PEER IS ASKED, and that ordering is the
 * entire mechanism. The requester is the only party with global knowledge,
 * so it must not consult a stale copy of its own intent. fuzzypickles marked
 * this property as reasoning rather than measurement when they sent it, then
 * sabotaged it and found their suite green -- because every test they had
 * used ONE peer, and with one peer the ordering cannot be observed at all.
 * `transfer_test.c` asks twice from two peers, which is the only arrangement
 * in which the question exists.
 *
 * THE RETRY UNIT IS THE REQUEST UNIT, WITHOUT ANYONE CHOOSING. An assignment
 * IS a range, so whatever granularity a caller asked at is what comes back
 * on failure. Sec 107 settles why that is a capability here rather than an
 * unmade decision: `fzn_spool_place` and `fzn_spool_place_span` both exist,
 * so the verification unit is a per-request choice, and a retry unit can
 * never be finer than the verification unit. A caller wanting fine retry
 * asks for small ranges and pays 62% proof overhead; one wanting cheap
 * proofs asks for spans and pays 0.68% and coarser retry. Sec 106 has the
 * curve. Nothing here has to know which they chose.
 *
 * NO CLOCK. `now` and a deadline are the caller's, as everywhere else in
 * this library -- `frame/freshness.h` and `chain/`'s expiry take the same
 * shape, and a module that called a clock could not be tested for the one
 * behaviour that matters, which is what happens at the boundary.
 */

#ifndef FZN_TRANSFER_H
#define FZN_TRANSFER_H

#include "plan.h"
#include "spool.h"

typedef enum fzn_transfer_err {
	FZN_TRANSFER_OK = 0,
	FZN_TRANSFER_ERR_MALFORMED,
	/* Nothing to ask for: the blob is complete, or every range this
	 * search looked at is already assigned. ORDINARY, and its own code so
	 * a caller can stop looping without treating it as a fault -- the
	 * same reason `fzn_spool_plan_want` answers a complete store with
	 * zero ranges rather than an error. */
	FZN_TRANSFER_NONE,
	/* The window is closed: as many batches are in flight as congestion
	 * control currently allows. Also ordinary, and DELIBERATELY DISTINCT
	 * from NONE -- they mean opposite things to a caller. NONE says stop
	 * asking; FULL says wait for a reply and ask again. */
	FZN_TRANSFER_FULL,
	/* Delivered or failed named an assignment this transfer does not
	 * hold, or `delivered` named leaves the store does not have. */
	FZN_TRANSFER_ERR_UNKNOWN,
} fzn_transfer_err_t;

const char *fzn_transfer_err_str(fzn_transfer_err_t err);

/* The most slots a caller may hand over, and therefore the widest window.
 *
 * A ceiling on a caller's number rather than on a peer's, which is the
 * weaker case -- but the search below scans a fixed candidate array sized
 * from this, so an unbounded `cap` would be an unbounded stack frame here.
 * 64 slots at a 64-leaf span is 4096 leaves in flight, which is generous for
 * anything these projects move. */
#define FZN_TRANSFER_MAX_SLOTS 64u

/* One outstanding request. The caller sizes the array of these, which is
 * what bounds both the memory and the window -- the same split `spool/`
 * already uses for its bitmap, and sec 107's conclusion that a batch bound
 * is a memory-holding decision rather than a protocol constant. */
typedef struct fzn_transfer_assign {
	uint64_t first;
	uint64_t count;
	uint64_t deadline;
	uint32_t peer;
	uint8_t live;
} fzn_transfer_assign_t;

typedef struct fzn_transfer {
	fzn_spool_t *spool;
	fzn_transfer_assign_t *slots;
	size_t cap;
	size_t in_flight;
	/* Batches, not bytes, and never zero. */
	unsigned window;
	/* Successes since the last increase. AIMD's additive half is one per
	 * WINDOW of successes rather than one per success: the latter doubles
	 * the window every window, which is slow start, and this deliberately
	 * does not do slow start. */
	unsigned successes;
} fzn_transfer_t;

/*
 * Opens a transfer over a caller's slot array.
 *
 * The window starts at one and `cap` is its ceiling: a transfer cannot have
 * more in flight than it has slots to record, so the caller's array is the
 * congestion bound as well as the memory bound.
 */
fzn_transfer_err_t fzn_transfer_open(fzn_transfer_t *transfer, fzn_spool_t *spool,
                                     fzn_transfer_assign_t *slots, size_t cap);

/*
 * The next range to ask `peer` for, recorded as pending before it returns.
 *
 * THE SEARCH IS A WINDOW AND NOT EXHAUSTIVE, which is what makes it
 * terminate without a loop over planner calls. It asks `fzn_spool_plan_want`
 * for a bounded number of candidate ranges and returns the first that no
 * live assignment overlaps. At most `cap` ranges can be pending, so a window
 * wider than `cap` finds a free range whenever one is nearby; when it does
 * not, FZN_TRANSFER_NONE says so and the caller waits rather than spinning.
 *
 * `max_per_range` is passed through and is the granularity decision above --
 * one leaf for fine retry, a span for cheap proofs.
 *
 * `from` IS THE CALLER'S AND THERE IS NO INTERNAL CURSOR, which is a change
 * made while writing the test for the property above. A cursor advancing
 * past each assignment was the obvious optimisation and it is a SECOND
 * mechanism producing disjoint ranges -- so the two-peer test passed with
 * the pending record removed, the cursor accounting for the disjointness on
 * its own. A property with two mechanisms where only one is load-bearing is
 * a property no test can hold; `plan.h` already treats `from` as a playhead
 * belonging to whoever is streaming, and this module has no business
 * choosing it.
 */
fzn_transfer_err_t fzn_transfer_next_want(fzn_transfer_t *transfer, uint32_t peer,
                                          uint64_t from, uint64_t max_per_range,
                                          uint64_t deadline, fzn_spool_range_t *out);

/*
 * The range arrived and was placed. Frees the slot and opens the window.
 *
 * VERIFIED AGAINST THE STORE RATHER THAN TAKEN ON TRUST. A caller claiming
 * delivery of leaves the bitmap does not hold gets FZN_TRANSFER_ERR_UNKNOWN,
 * because otherwise congestion control would open on work that did not
 * happen -- and the store is right there, one bit per leaf. It is the same
 * reasoning as `fzn_spool_open` recomputing `have` from the bits rather than
 * trusting a caller.
 */
fzn_transfer_err_t fzn_transfer_delivered(fzn_transfer_t *transfer, uint32_t peer,
                                          uint64_t first, uint64_t count);

/*
 * The range did not arrive, or arrived and failed verification.
 *
 * Frees the slot and halves the window. Nothing returns the range to the
 * want-list because nothing removed it: the store never saw those bytes, so
 * the next `fzn_spool_plan_want` emits it again.
 *
 * ONE BAD PEER COSTS ONE BATCH, NOT THE TRANSFER -- sec 107, and it is the
 * reason this takes a range rather than a peer: another peer supplies the
 * same range next time round, and nothing here bans the peer that failed,
 * because deciding that needs a peer model this library does not have.
 */
fzn_transfer_err_t fzn_transfer_failed(fzn_transfer_t *transfer, uint32_t peer,
                                       uint64_t first, uint64_t count);

/*
 * Drops every assignment whose deadline has passed, and returns how many.
 *
 * ONE DECREASE PER LOSS EVENT, not per assignment. A stalled peer holding
 * four batches is one failure and one halving; charging four would collapse
 * the window to its floor for a single event, which is the behaviour AIMD
 * exists to avoid.
 */
size_t fzn_transfer_expire(fzn_transfer_t *transfer, uint64_t now);

/*
 * The window never reaches zero, and that is a property rather than a
 * detail: a transfer that cannot ask for anything can never learn the path
 * recovered. `link/` demotes rather than deletes for the same reason.
 */
unsigned fzn_transfer_window(const fzn_transfer_t *transfer);
size_t fzn_transfer_in_flight(const fzn_transfer_t *transfer);

#endif /* FZN_TRANSFER_H */
