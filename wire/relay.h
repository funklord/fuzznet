/* The hop budget, which is the one part of relaying that is decidable today.
 *
 * `fzn_hop.hops_left` has been in every frame since the schema existed and
 * **nothing has ever read or written it** -- a byte on the wire paying for a
 * feature that did not exist. This is that feature's first half.
 *
 * IT IS OUTSIDE THE AUTHENTICATED REGION, NECESSARILY. The tag covers `head`
 * and the sealed region; `hop` is before both. It has to be: a relay
 * decrements the budget, and a field the tag covered could not be changed
 * without invalidating the frame. So the budget is **mutable in flight by
 * anyone**, and every property below follows from taking that seriously
 * rather than from wishing otherwise.
 *
 *   - **A receiver must clamp, never trust.** A stranger can write 255 into
 *     the budget of a frame it did not create. Trusting that number turns one
 *     datagram into as many forwards as the network has paths, which is an
 *     amplifier built out of a helpful default. `fzn_relay_budget` returns
 *     the smaller of what the frame claims and what this host allows.
 *   - **A stranger writing ZERO costs nothing new.** It drops the frame --
 *     which anyone able to rewrite a byte in flight could achieve by
 *     discarding it instead. A budget cannot defend availability against
 *     somebody already on the path, and pretending otherwise would be the
 *     wrong claim to make for it.
 *   - **What it DOES defend is the network against itself**: loops, and one
 *     misconfigured host multiplying traffic. That is a real property and a
 *     narrow one.
 *
 * WHAT IS NOT HERE, AND WHY IT IS NOT AN OVERSIGHT. **A relay cannot tell
 * where to send a frame**, because the frame has no recipient field. That is
 * deliberate: `wire/frame.situ` puts the capability inside the seal
 * specifically so an observer cannot see which authority is being exercised,
 * and a plaintext destination would give back most of what that bought. A
 * receiver knows a frame is its own because the key commitment matches a key
 * it derived, which is addressing by decryption.
 *
 * So routing needs one of three things, and choosing is a wire decision
 * rather than a coding one: an out-of-band hint a consumer already has,
 * flooding within a known set, or a destination field -- which costs bytes
 * against sec 13's budget, where a largest frame has 64 to spare under the
 * IPv6 minimum MTU. **Not invented here.** This file does the part that is
 * decidable without answering it, exactly as `record/sync.h` decides what to
 * fetch and never how to send it.
 */

#ifndef FZN_RELAY_H
#define FZN_RELAY_H

#include <stddef.h>
#include <stdint.h>

/* The most this library will forward, whatever a frame claims.
 *
 * Eight because a budget is a loop bound rather than a route length: it needs
 * to be larger than any plausible path and small enough that a loop dies
 * quickly. A consumer that knows its topology passes its own smaller number. */
#define FZN_RELAY_MAX_HOPS 8u

typedef enum fzn_relay_err {
	FZN_RELAY_OK = 0,
	FZN_RELAY_ERR_MALFORMED = -1,
	/* Not a frame this host can read the budget of -- too short, or a
	 * version it does not know. */
	FZN_RELAY_ERR_SHAPE = -2,
	/* The budget is spent. The frame stops here, and this is the ordinary
	 * end of a frame's life rather than a fault. */
	FZN_RELAY_ERR_EXHAUSTED = -3,
} fzn_relay_err_t;

/* What this host is willing to believe about a frame's remaining hops.
 *
 * `allowed` is this host's own ceiling; pass `FZN_RELAY_MAX_HOPS` for the
 * default. The answer is never larger than `allowed`, whatever the frame
 * says, which is the whole of the clamp. */
fzn_relay_err_t fzn_relay_budget(const uint8_t *frame, size_t frame_len, uint8_t allowed,
                                  uint8_t *out);

/* Spend one hop, in place, so the frame may be forwarded.
 *
 * Clamps first, then decrements, so a frame arriving with an inflated budget
 * leaves with a believable one -- an amplifier is stopped at the first honest
 * host rather than at the last. Refuses `FZN_RELAY_ERR_EXHAUSTED` at zero and
 * leaves the frame untouched, so a caller that ignores the return value
 * forwards something no worse than it received. */
fzn_relay_err_t fzn_relay_spend(uint8_t *frame, size_t frame_len, uint8_t allowed);

/* A short name for `fzn_relay_err_t`. Never NULL. */
const char *fzn_relay_err_str(fzn_relay_err_t err);

#endif /* FZN_RELAY_H */
