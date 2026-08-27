/* What to ask a peer for, and what to offer it.
 *
 * This is the distribution layer's decision and nothing else. It does not
 * send, does not schedule, does not encode, and does not decide whether a
 * record it fetches will turn out to be authorised. Given what this host
 * holds and what a peer says it holds, it answers: **which ranges are
 * missing, and which way round.**
 *
 * WHY THAT IS THE WHOLE OF IT. sec 2 keeps transport out of this library and
 * sec 5 keeps the permission graph's shape out. What is left when both are
 * removed is a comparison of two sets of positions -- and that comparison is
 * identical in all three consumers, which is exactly the test sec 5 sets for
 * admitting anything. A consumer supplies its own timers, its own choice of
 * peer, and its own framing; `wire/seal.h` and `chunk/` are already there for
 * the last of those.
 *
 * PULL, NOT PUSH, is the shape this supports first, because it survives loss
 * without acknowledgements: a host that missed a record asks again next time
 * it compares. `fzn_sync_plan_offer` exists for the other direction, so a
 * host that knows a peer is behind can send without being asked, but nothing
 * here requires it.
 *
 * A POSITION IS PER (ISSUER, STREAM). A peer reporting several streams from
 * one issuer reports several positions, and this compares each against the
 * matching one -- which is what lets a host follow an issuer's configuration
 * and not its telemetry, or its coarse track and not its precise one.
 *
 * A NEW ISSUER IS NOT FOLLOWED AUTOMATICALLY. If a peer advertises an issuer
 * this host has never seen, that is reported as a COUNT and never as a
 * request. Fetching from a stranger because a peer mentioned them is how one
 * compromised peer fills every journal in the network with issuers nobody
 * chose, and `record/journal.h` already makes adopting an issuer deliberate
 * -- `fzn_journal_anchor`. This file does not quietly undo that.
 *
 * THAT CLAIM IS NOW TRUE ON BOTH SIDES, AND WAS NOT WHEN IT WAS WRITTEN.
 * `fzn_journal_admit` used to open an entry for any unseen (issuer, stream)
 * arriving at sequence 1, so this file refused to ASK a stranger for anything
 * while a PUSHED record was adopted regardless -- and `fzn_sync_plan_offer`
 * means unsolicited pushes are part of the design, so the door this file
 * guards had a second one standing open beside it. Admission now refuses an
 * unfollowed stream with `FZN_JOURNAL_ERR_UNKNOWN_ISSUER`, whatever sequence
 * it carries. The wording above is unchanged because it was always the
 * intent; what changed is that the other half agrees with it.
 *
 * THE PLAN IS IN THIS HOST'S ORDER, NOT THE PEER'S -- see
 * `fzn_sync_plan_fetch`, which walks THIS host's journal and looks each entry
 * up in what the peer sent. It used to walk what the peer sent, which handed
 * the peer the ordering of a plan with a bound on it, and a bound whose
 * ordering the other side chooses is a bound the other side aims.
 *
 * AN OFFER ANSWERS A POSITION, NOT A SILENCE -- see `fzn_sync_plan_offer`. A
 * stream the peer did not mention is counted and never offered, because an
 * absent position used to read as a position of zero and a zero-length digest
 * therefore requested every record this host holds.
 *
 * EVERY BOUND IS REPORTED. A plan that did not fit says so, rather than
 * returning a short list that looks complete: a truncated plan silently
 * dropped is a range nobody asks for again. There are two such bounds and
 * they are counted separately, because they are the caller's fault and the
 * peer's respectively -- `truncated` and `positions_ignored` on
 * `fzn_sync_plan_t`.
 */

#ifndef FZN_SYNC_H
#define FZN_SYNC_H

#include "journal.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_sync_err {
	FZN_SYNC_OK = 0,
	FZN_SYNC_ERR_MALFORMED = -1,
} fzn_sync_err_t;

/* The most positions from a peer either planner will LOOK AT. Positions past
 * it are counted in `positions_ignored` and never compared against anything.
 *
 * WHY A CEILING EXISTS AT ALL. Both comparisons cost `their_count` times
 * `journal->used` compares of a 32-byte key, each constant-time and so
 * without an early exit, and `their_count` is a number the peer chooses.
 * Measured against a 64-entry journal: 200,000 positions -- 8.8 MB of digest
 * at the 44 bytes a position needs on the wire -- cost 2.05 seconds of CPU
 * and produced no requests at all, since every one of them named an issuer
 * this host does not follow. A peer that can spend a megabyte to buy a second
 * of somebody else's CPU has an amplifier, and repeating it is free.
 *
 * WHY 1024, WHICH IS A POLICY AND NOT A DERIVATION. It is bounded above by
 * what a consumer could deliver in one piece -- `chunk/split.h`'s
 * `FZN_SPLIT_MAX_PAYLOAD` and `chunk/reassembly.h`'s `FZN_REASM_MAX_CHUNKS`
 * put roughly 5,900 positions in the largest message this library will
 * reassemble -- and it is far above any journal in this tree, so an honest
 * digest never reaches it. At this ceiling the worst case against a 64-entry
 * journal is about 21 ms rather than unbounded.
 *
 * WHY NOT `journal->capacity`, WHICH LOOKS TIGHTER AND IS WRONG. A peer
 * legitimately follows more streams than this host does. A host following two
 * issuers would then examine two positions of a two-hundred-position digest
 * and find neither of its own -- a liar's cost paid by every honest peer with
 * a bigger journal, which is a correctness bug traded for a performance one.
 *
 * WHY IGNORING THE TAIL COSTS NOTHING THE PEER DID NOT ALREADY HAVE. The peer
 * chooses which positions land inside the ceiling, so it can bury a stream
 * past it -- but burying a position and omitting it are the same act, and
 * omitting it is a thing no comparison can prevent. What the ceiling does not
 * do, since `fzn_sync_plan_fetch` walks this host's journal, is let anything
 * the peer sends displace a request for a stream it did advertise. */
#define FZN_SYNC_MAX_POSITIONS 1024u

/* One issuer's position, as a peer reports it. This is what a host puts on
 * the wire to say what it has; how it is encoded is the consumer's, for the
 * reason `record.h` gives about signed regions. */
typedef struct fzn_sync_position {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t received;
} fzn_sync_position_t;

/* A range of one issuer's records, wanted or offered.
 *
 * `count` is bounded by the caller rather than left open, because "send me
 * everything from 1" is a request a stranger can make of every host at once.
 * The reply to a bounded request is a bounded amount of work, and the next
 * comparison asks for the next window. */
typedef struct fzn_sync_request {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t from;
	uint64_t count;
} fzn_sync_request_t;

/* What a comparison produced, including what it could not fit.
 *
 * ZEROED BEFORE THE ARGUMENTS ARE CHECKED, so that a plan is never left
 * holding the previous round's numbers -- see the two planners.
 *
 * `unknown_issuers` is issuers the peer follows and this host does not, for a
 * fetch, and the mirror for an offer: streams this host holds that the peer
 * did not mention. It is deliberately a number and not a list of requests:
 * adopting one is `fzn_journal_anchor`, which is a decision, and a consumer
 * that wants the identities can read them from the positions it was given. It
 * counts POSITIONS rather than distinct issuers, so a peer that repeats
 * itself inflates it; it is a hint and nothing depends on it. A position past
 * `FZN_SYNC_MAX_POSITIONS` was never examined and so cannot be classified: it
 * counts in `positions_ignored` and, for an offer, leaves the stream it named
 * looking unmentioned.
 *
 * `truncated` and `positions_ignored` are both bounds and are kept apart
 * because a caller can act on one and not the other. `truncated` is ranges
 * this host wanted that `out_cap` had no room for, which is the caller's own
 * sizing and is fixed by passing a bigger array -- `fzn_sync_plan_fetch` says
 * exactly how big is enough. `positions_ignored` is how much of the peer's
 * digest was past `FZN_SYNC_MAX_POSITIONS`, which no local sizing can fix and
 * which an honest peer never causes: it is a fact about that peer, and a
 * consumer may reasonably stop talking to one that keeps producing it.
 *
 * They were one counter, and the merged number was useless in exactly the
 * case it mattered. A peer padding a digest drove `truncated` up every round
 * while the caller's array was the right size and its own ranges were fine,
 * so the only symptom of a starving fetch was indistinguishable from a
 * caller that had under-sized a buffer. */
typedef struct fzn_sync_plan {
	size_t request_count;
	size_t unknown_issuers;
	size_t truncated;
	size_t positions_ignored;
} fzn_sync_plan_t;

/* This host's own positions, to send to a peer. Returns how many were
 * written, and never more than `out_cap`.
 *
 * `dropped` receives the number that did not fit, and is REQUIRED -- passing
 * NULL writes nothing and returns 0. An optional out-parameter is one every
 * caller ignores, and a digest that quietly does not fit is the failure the
 * bound-reporting rule above exists to prevent: the scan runs in journal
 * order, so a host that overflows drops the same streams every round and
 * never advertises them at all. */
size_t fzn_sync_digest(const fzn_journal_t *journal, fzn_sync_position_t *out, size_t out_cap,
                       size_t *dropped);

/* What this host should ask the peer for: ranges the peer has and it does
 * not, for issuers it already follows.
 *
 * `max_per_request` bounds each range. Zero is refused rather than meaning
 * unlimited, for the reason `fzn_reasm_init` refuses a zero quota: an
 * unlimited default is the one a caller gets by forgetting the field.
 *
 * ONE RANGE PER FOLLOWED (ISSUER, STREAM), IN JOURNAL ORDER, and that is the
 * security property rather than a detail of the loop. It follows from walking
 * this host's journal and looking each entry up in `theirs`, and it gives the
 * caller a number: `out_cap` of `journal->used` CANNOT truncate, whatever the
 * peer sends, so `truncated` becomes a fact about the caller's array and
 * nothing the peer can reach.
 *
 * IT USED TO WALK `theirs`, and every part of the damage came from that. The
 * plan was filled in the order the peer's positions arrived and the overflow
 * was counted in `truncated`, so a peer could aim the bound. Two shapes were
 * measured against a four-entry journal and two request slots:
 *
 *     a peer that named three followed issuers it had nothing for, then
 *     the one it was genuinely ahead on, filled both slots with the
 *     phantoms; request_count 2, truncated 2, and the real fetch was one
 *     of the two dropped -- identically every round, since the peer sends
 *     the same order every round.
 *
 *     a peer that repeated ONE followed issuer five times got five ranges
 *     for one stream; with four slots it took all four, and a second
 *     issuer this host was genuinely behind on was truncated.
 *
 * Neither is visible to the caller as anything but `truncated > 0`, which is
 * also what an under-sized array looks like -- hence the split in
 * `fzn_sync_plan_t`. The peer's numbers still decide what is worth asking
 * for; they no longer decide who gets asked about first, or how many times.
 *
 * A PER-ISSUER CAP WAS CONSIDERED AND REJECTED. Once the plan is built from
 * this host's own entries, an issuer occupies exactly the streams this host
 * chose to follow from it, one range each, and a cap on that would refuse a
 * fetch for a stream somebody deliberately anchored. `fzn_journal_anchor` is
 * where how much of this host's attention an issuer gets is decided; a second
 * limit here would silently un-follow what that decided, and it would bite
 * the host that legitimately follows six streams from one issuer, never the
 * liar -- who need only name six issuers instead. */
fzn_sync_err_t fzn_sync_plan_fetch(const fzn_journal_t *journal,
                                    const fzn_sync_position_t *theirs, size_t their_count,
                                    uint64_t max_per_request, fzn_sync_request_t *out,
                                    size_t out_cap, fzn_sync_plan_t *plan);

/* The mirror: ranges this host has and the peer does not, so it can send
 * without waiting to be asked. An issuer the peer has never seen IS offered
 * here -- offering is not adopting, and the peer still decides -- but it has
 * to have said so.
 *
 * A STREAM THE PEER DID NOT MENTION IS COUNTED, NEVER OFFERED. An absent
 * position used to mean `received = 0` and so "send me your whole history",
 * which made the safest-sounding operation in the file the amplifier in it: a
 * digest of ZERO positions, the cheapest message there is, asked for
 * everything. Measured against a 64-entry journal a million records deep,
 * with `max_per_request` at 512: a zero-length digest produced 64 ranges
 * covering 32,768 records -- at least 5 MB at `FZN_RECORD_MIN_LEN` and near
 * 22 MB at `FZN_RECORD_MAX_LEN`, from an input with nothing in it.
 *
 * A PEER THAT WANTS EVERYTHING FROM 1 SAYS SO, and there is an existing way
 * to say it. `fzn_journal_anchor` at sequence zero means "I follow this
 * stream and have nothing yet", the digest of such an entry carries
 * `received = 0`, and a position of zero is offered from 1 exactly as before.
 * So the capability is not lost; it moved from a silence to a statement,
 * which is the same move `fzn_journal_admit` made when it stopped adopting
 * issuers implicitly, and for the same reason -- the peer has to have decided
 * something before this host spends bandwidth on it.
 *
 * That other change is also why the old reasoning no longer holds. The
 * comment justifying the offer said `fzn_journal_admit` would refuse anything
 * past the peer's own position anyway; it now refuses ALL of it for a stream
 * the peer does not follow, with `FZN_JOURNAL_ERR_UNKNOWN_ISSUER`. Offering a
 * history to a peer that never mentioned the stream is not merely generous,
 * it is bytes that cannot be accepted at the far end. */
fzn_sync_err_t fzn_sync_plan_offer(const fzn_journal_t *journal,
                                    const fzn_sync_position_t *theirs, size_t their_count,
                                    uint64_t max_per_request, fzn_sync_request_t *out,
                                    size_t out_cap, fzn_sync_plan_t *plan);

/* A short name for `fzn_sync_err_t`. Never NULL. */
const char *fzn_sync_err_str(fzn_sync_err_t err);

#endif /* FZN_SYNC_H */
