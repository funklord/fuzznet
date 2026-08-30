/*
 * WHICH LEAVES TO ASK FOR, AND WHICH TO SEND -- the policy half of a blob
 * transfer, over a spool's bitmap and nothing else.
 *
 * NO WIRE FORMAT AND NO TRANSPORT. This produces and consumes ranges in a
 * caller's array; how they are framed, signed or sent is the consumer's, as
 * everything above `wire/` is. That is the same seam `record/sync.h` sits
 * on, and it is why this file can be core: no allocation, no I/O.
 *
 * WHY IT IS HERE AT ALL, WHICH IS A CORRECTION. project.md sec 16 staged the
 * transfer protocol out of stage 1 and said its blocker was a decision "this
 * tree has not taken", pointing at sec 13c -- which is about bounding
 * revocation admission and says nothing on the subject. **The decision had
 * been taken, under a different name, in `record/sync.c`**, which had already
 * met the identical problem for records: a cheap query must not buy an
 * expensive answer. Nobody cited it because nobody was looking for the shape,
 * only for the name.
 *
 * WHAT SYNC DECIDED, AND IS INHERITED HERE RATHER THAN RE-ARGUED:
 *
 *   - **A REQUEST THAT NAMES NOTHING GETS NOTHING.** This is sync's own
 *     measured defect and the reason this rule leads. An absent position used
 *     to mean "send me your whole history", which made the cheapest message
 *     in the protocol the amplifier in it -- a zero-length digest bought 64
 *     ranges over 32,768 records, at least 5 MB, from an input with nothing
 *     in it. The safest-sounding operation was the dangerous one. So an empty
 *     want here yields zero ranges, and a host wanting a whole blob says so
 *     by naming it.
 *   - **A CEILING, BECAUSE THE PEER CHOOSES THE NUMBER.** The work an offer
 *     costs is the peer's range count times the leaves in each, and both are
 *     the peer's to write down. Sync bounds its digest at 1024 positions for
 *     exactly this. Here the bound is two: `FZN_SPOOL_MAX_WANT` ranges
 *     examined, and `max_leaves` leaves offered in total.
 *   - **ZERO IS REFUSED RATHER THAN MEANING UNLIMITED.** A bound a caller
 *     forgot to set must not read as "no bound"; sync refuses a
 *     `max_per_request` of zero and so does this.
 *
 * WHAT IS STILL THE HOLDER'S, AND IS NOT DECIDED BY ANY OF THE ABOVE. Sec 16
 * says a WANT wants a RETURN-ROUTABILITY COOKIE, because a small query
 * answered with a large reply is a reflection at a spoofed victim. Bounding
 * the answer caps the GAIN and does not stop the reflection -- they are
 * different halves and only the first is settled here. What this file does
 * supply toward it is the property that makes the cheapest spoofable packet
 * worthless: an empty want buys nothing, so the gain on a zero-effort forgery
 * is zero rather than a blob. A cookie is about WHOM to answer; this is about
 * WHAT. Deciding the first is a protocol change and belongs to whoever owns
 * the transport.
 *
 * NOR IS THE BATCH HERE. Sec 16's stage 2 is "HAVE, WANT, the batch"; this
 * is the two planners, and the batch -- how many leaves ride in one message
 * and what carries them -- is `chunk/`'s question and the consumer's, since
 * it depends on a transport this library does not choose.
 */

#ifndef FZN_SPOOL_PLAN_H
#define FZN_SPOOL_PLAN_H

#include "spool.h"

/*
 * The most ranges an offer will examine from a peer, whatever its array
 * holds. A policy, like sync's 1024, and bounded above by what a consumer
 * could deliver in one message rather than derived from anything: at 16 bytes
 * a range this is 4 KiB of request, well inside a single datagram's worth of
 * chunks, and far above the handful of gaps a real transfer has.
 *
 * A peer that wants more asks again, which costs it a round trip -- the point
 * being that the cost lands on the asker rather than on the answerer.
 */
#define FZN_SPOOL_MAX_WANT 256u

/* A run of consecutive leaves. `count` is never zero in anything this file
 * produces -- an empty range is not a thing to send and would be a second
 * spelling of "nothing", which callers then have to test for. */
typedef struct fzn_spool_range {
	uint64_t first;
	uint64_t count;
} fzn_spool_range_t;

/*
 * The leaves this store still needs, as coalesced runs.
 *
 * `max_per_range` splits a long run so that no single range asks for more
 * than a peer should answer at once; zero is refused. Stops at `cap` ranges
 * and reports how many were written, so a caller with a small array gets the
 * lowest-numbered gaps -- which is the useful half, since a transfer that
 * fills from the bottom keeps its own bitmap compressible.
 *
 * A COMPLETE STORE PRODUCES ZERO RANGES rather than an error: "I need
 * nothing" is an answer and a caller should not have to distinguish it from a
 * failure.
 */
fzn_spool_err_t fzn_spool_plan_want(const fzn_spool_t *spool, uint64_t max_per_range,
                                    fzn_spool_range_t *out, size_t cap, size_t *count);

/*
 * The leaves this store can send in answer to a peer's want.
 *
 * Each wanted range is intersected with what this host actually holds, so a
 * peer asking for a leaf nobody has is answered with silence rather than an
 * error -- it is not a fault, and telling a stranger which leaves are absent
 * is a question this library does not have to answer.
 *
 * `max_leaves` is the total across all ranges and is the reflection bound;
 * zero is refused. Ranges past the blob's leaf count are CLIPPED rather than
 * refused, so a peer naming a trillion leaves costs a comparison -- the same
 * reasoning `fzn_spool_open` uses for its ceiling.
 *
 * `want_count` of zero yields zero ranges. See the header comment: that is
 * the whole of sync's measured defect, inherited as a rule rather than as a
 * warning.
 */
fzn_spool_err_t fzn_spool_plan_offer(const fzn_spool_t *spool, const fzn_spool_range_t *want,
                                     size_t want_count, uint64_t max_leaves,
                                     fzn_spool_range_t *out, size_t cap, size_t *count);

#endif /* FZN_SPOOL_PLAN_H */
