/* The hop budget, which is the one part of relaying that is decidable today.
 *
 * `fzn_hop.hops_left` has been in every frame since the schema existed and
 * for a long time **nothing read or wrote it** -- a byte on the wire paying
 * for a feature that did not exist. This file was the first half of that
 * feature and, until `fzn_send.hops`, the only half: `fzn_seal_build` memset
 * the frame and set `version` alone, so EVERY frame this library could build
 * carried a budget of zero and every one of the answers below was the same
 * answer. A consumer wanting a relayable frame had to write `frame[1]` by
 * hand, which is the raw-offset knowledge `wire/seal.h` exists to spare it.
 *
 * That is also why the seal -> relay -> open round trip went unwritten for as
 * long as it did: it could not be written against the public API at all, so
 * the property this whole file rests on -- that a frame survives having its
 * budget spent -- was asserted nowhere. `wire/test/seal_test.c` asserts it
 * now, by spending the entire budget between build and open and requiring the
 * payload and capability back byte-identical.
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
 * quickly. A consumer that knows its topology passes its own smaller number.
 *
 * AND IT IS HALF A FRAME-FORMAT DISCRIMINATOR IN A CONSUMER, WHICH IS NOT
 * WHAT IT WAS WRITTEN FOR. Reported by fuzzypickles 2026-09-01, during a
 * migration in which one UDP port carries both their format and this one.
 * Their demultiplexer works on offset 1 alone: this frame has
 * `fzn_hop.hops_left` there, which `fzn_seal_build` refuses above this bound,
 * so the byte is 0..8; theirs has a command byte whose lowest reaching value
 * is 0x0E. **Offset 0 cannot help** -- their version byte is 1 and
 * `fzn_hop.version` is `must_eq = 1`, so both are the byte 1. The whole
 * disambiguation rests on this constant staying below theirs.
 *
 * **Safe up to and including 13; 14 collides.** Raising it past that would
 * make their demultiplexer read this frame's hop count as their pairing
 * command -- silently, on a live path, with no compile error in either tree.
 * They have pinned the invariant on their side, which fails once somebody has
 * already changed this; **this paragraph is the half that fires first**,
 * because it is where the person raising the bound is looking.
 *
 * The coupling is theirs to hold and is not a constraint on this library --
 * a bound this small is not one anybody has a reason to raise, and if a
 * reason appears it is a message to send rather than a veto to obey. What
 * would be wrong is discovering it afterwards. */
#define FZN_RELAY_MAX_HOPS 8u

/* THE SUBSYSTEM HINT, and what a relay may know about a frame it cannot open.
 *
 * sec 153. `chain/service.h` makes the service mandatory in a capability, and
 * the capability is inside the sealed region -- which is deliberate, so that
 * an observer cannot see which authority is being exercised. A relay has no
 * key, so the authoritative service is exactly the thing it cannot read, and
 * a host asked to apply a policy per subsystem had nothing to apply one to.
 *
 * `fzn_hop.service_hint` is two of the three bytes that were reserved before
 * the hop header's alignment padding, so a frame is not one byte larger for
 * carrying it.
 *
 * IT IS A HINT AND THE WORD IS LOAD-BEARING. It is outside the authenticated
 * region for the same structural reason `hops_left` is -- everything a relay
 * reads must be readable before the tag can be checked -- so a sender may
 * write anything it likes there and nobody downstream can tell.
 *
 *   - **A lie buys the relay's own policy and nothing else.** A frame
 *     claiming a subsystem this host relays generously gets that budget. It
 *     does NOT get anything from the recipient, whose authorization comes
 *     from the sealed capability and never from this field: a frame claiming
 *     `log` while carrying a `catalog` capability is authorized as `catalog`,
 *     because that is the only service anybody authenticated. So the hint
 *     cannot escalate; it can only misspend a relay's capacity, which is the
 *     same thing a stranger achieves by sending more frames.
 *   - **A relay must not rewrite it.** Nothing here writes the hint, and that
 *     is a decision rather than an omission: a relay that could relabel a
 *     frame would be laundering one subsystem as another, and the next host's
 *     policy would be applied to a claim its neighbour invented rather than
 *     to one the sender made. The sender writes it once, through
 *     `fzn_send.service_hint`, and it travels unchanged.
 *   - **IT PUBLISHES THE SUBSYSTEM TO EVERYBODY ON THE PATH.** This is the
 *     real price and it is not recoverable by being careful: anything a relay
 *     can filter on is something an observer can read. A passive watcher
 *     learns that this datagram is log traffic, and traffic analysis over a
 *     labelled stream is a great deal easier than over an unlabelled one.
 *
 * SO ZERO IS THE DEFAULT AND MEANS UNCLASSIFIED. `memset` leaves it there,
 * every frame built before this field existed has it, and a sender who does
 * not want to be labelled simply never sets it. A host with a per-subsystem
 * policy decides what unclassified traffic is worth by putting
 * FZN_RELAY_SERVICE_NONE in its own table, rather than by this file guessing.
 */
#define FZN_RELAY_SERVICE_NONE 0u

/* The largest service that can be hinted.
 *
 * `chain/service.h` numbers services in a uint32 and bounds nothing, so a
 * service can exist that does not fit here. Such a service sends NO hint --
 * `fzn_seal_build` refuses `fzn_send.service_hint` above this rather than
 * truncating it, because a truncated hint is not a weaker hint but a
 * DIFFERENT one: two services agreeing in their low sixteen bits would be
 * indistinguishable to every relay on the path, and a policy written for one
 * would silently be applied to the other. No hint is honest; an aliased hint
 * is a wrong answer that nothing downstream can detect. */
#define FZN_RELAY_SERVICE_MAX 0xffffu

typedef enum fzn_relay_err {
	FZN_RELAY_OK = 0,
	FZN_RELAY_ERR_MALFORMED = -1,
	/* Not a frame this host can read the budget of -- too short, or a
	 * version it does not know. */
	FZN_RELAY_ERR_SHAPE = -2,
	/* The budget is spent. The frame stops here, and this is the ordinary
	 * end of a frame's life rather than a fault. */
	FZN_RELAY_ERR_EXHAUSTED = -3,
	/* This host does not carry this subsystem at all.
	 *
	 * DELIBERATELY NOT EXHAUSTED, though a zero allowance clamps to a zero
	 * budget and the frame stops either way. The two are different facts
	 * about different things: EXHAUSTED says the frame has travelled as far
	 * as it was sent to travel, which is every frame's ordinary end and
	 * says nothing about this host; REFUSED says this host declined a
	 * subsystem it could have carried, which is a policy decision somebody
	 * made and may want to see counted, logged or reconsidered. Collapsing
	 * them would make a misconfigured policy indistinguishable from normal
	 * traffic reaching the end of its budget. */
	FZN_RELAY_ERR_REFUSED = -4,
} fzn_relay_err_t;

/* One host's willingness to carry one subsystem.
 *
 * Caller-owned, like every table in this library: an array of these is the
 * whole of a relay policy and nothing here allocates one.
 *
 * `allowed` is a CEILING and not a grant. It goes in where
 * `fzn_relay_budget`'s `allowed` argument would, so the clamp is unchanged --
 * a frame still travels the smaller of what it claims and what this host
 * permits. Zero means this host does not relay this subsystem, and answers
 * FZN_RELAY_ERR_REFUSED rather than pretending the frame ran out. */
typedef struct fzn_relay_policy {
	uint16_t service;
	uint8_t  allowed;
} fzn_relay_policy_t;

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

/* The subsystem a frame CLAIMS, which is not the subsystem it carries.
 *
 * Reads `fzn_hop.service_hint` and nothing else -- no key, no tag check, no
 * capability. FZN_RELAY_SERVICE_NONE means the sender did not label it. See
 * the hint's own comment above before doing anything with the answer: it is
 * an unauthenticated claim, and the only thing it may decide is what THIS
 * host is willing to spend on the frame. */
fzn_relay_err_t fzn_relay_service(const uint8_t *frame, size_t frame_len, uint16_t *out);

/* `fzn_relay_budget`, with the ceiling chosen per subsystem.
 *
 * The frame's hint selects an entry from `policy`; FIRST MATCH WINS, so a
 * caller orders its own table and a duplicated service is that caller's
 * business rather than an error here. `fallback` is the ceiling for a hint
 * naming nothing in the table, which is how a host says what it does with
 * subsystems it has no opinion about -- pass zero and it carries only what it
 * has named.
 *
 * A null or empty table is not malformed: it means every frame takes
 * `fallback`, which is exactly `fzn_relay_budget` and is what a host with no
 * per-subsystem policy wants.
 *
 * ABOVE ZERO. A `fallback` of zero is a policy saying this host does not carry
 * the subsystem, so it answers FZN_RELAY_ERR_REFUSED where `fzn_relay_budget`
 * with an `allowed` of zero answers OK and a budget of zero. The CEILING is
 * the same and the status deliberately is not -- see FZN_RELAY_ERR_REFUSED,
 * which exists so that a host declining a subsystem is not counted as a frame
 * reaching its ordinary end. Stated because "exactly" read as unqualified:
 * `wire/test/relay_fuzz.c` asserted the equivalence flatly and failed on its
 * first run, against code that was right. project.md sec 233. */
fzn_relay_err_t fzn_relay_budget_policy(const uint8_t *frame, size_t frame_len,
                                         const fzn_relay_policy_t *policy, size_t policy_len,
                                         uint8_t fallback, uint8_t *out);

/* `fzn_relay_spend`, with the ceiling chosen per subsystem.
 *
 * Same clamp-then-decrement as `fzn_relay_spend`, and the same promise on
 * refusal: a frame this host will not carry leaves the buffer untouched, so a
 * caller that ignores the return value forwards what it received rather than
 * something corrupted. The hint is NOT rewritten -- see above. */
fzn_relay_err_t fzn_relay_spend_policy(uint8_t *frame, size_t frame_len,
                                        const fzn_relay_policy_t *policy, size_t policy_len,
                                        uint8_t fallback);

/* A short name for `fzn_relay_err_t`. Never NULL. */
const char *fzn_relay_err_str(fzn_relay_err_t err);

#endif /* FZN_RELAY_H */
