/* Big-endian reads and writes over caller-owned bytes.
 *
 * WHY THIS EXISTS, given `wire/generated/situ.h` already has these. That
 * header describes the DATAGRAM, and a consumer takes `frame/`, `chain/` or
 * `record/` without taking situ -- their independence from the schema is what
 * kept them buildable while the generator was blocked, and what lets somebody
 * link the replay window without a code generator. These four modules need
 * the same four operations and cannot reach situ's.
 *
 * project.md sec 7a assigns "4.1 framing and canonical encoding" wholesale to
 * situ. That is right for the frame and incomplete for the SIGNED OBJECTS,
 * which situ does not describe: there is no hop, revocation or record in
 * `wire/frame.situ`. This file is the half sec 7a's table does not cover, and
 * the row wants a second entry saying so.
 *
 * DELIBERATELY NAMED AFTER situ's. `fzn_get_be64` is `situ_get_be64` with a
 * different prefix and the same semantics, so that a later schema for these
 * objects replaces the bodies and not the call sites.
 *
 * BIG-ENDIAN, matching `frame.situ`'s `endian big`. Network order is the only
 * thing every implementation agrees on without being told, and a signed
 * object's bytes must mean one thing everywhere or a signature over them
 * means nothing.
 *
 * NO ALIGNMENT ASSUMPTION. Every access is byte-at-a-time, so a hop may sit
 * at any offset in a buffer somebody else framed. That is not caution: a
 * chain arrives inside a chunked message, at whatever offset the encoding put
 * it, and a cast to a wider type there is undefined behaviour on the
 * platforms this library targets rather than merely slow.
 */

#ifndef FZN_BYTES_H
#define FZN_BYTES_H

#include <stdint.h>

static inline uint16_t fzn_get_be16(const uint8_t *p)
{
	return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t fzn_get_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
	       (uint32_t)p[3];
}

static inline uint64_t fzn_get_be64(const uint8_t *p)
{
	return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) |
	       ((uint64_t)p[3] << 32) | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
	       ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static inline void fzn_put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static inline void fzn_put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static inline void fzn_put_be64(uint8_t *p, uint64_t v)
{
	p[0] = (uint8_t)(v >> 56);
	p[1] = (uint8_t)(v >> 48);
	p[2] = (uint8_t)(v >> 40);
	p[3] = (uint8_t)(v >> 32);
	p[4] = (uint8_t)(v >> 24);
	p[5] = (uint8_t)(v >> 16);
	p[6] = (uint8_t)(v >> 8);
	p[7] = (uint8_t)v;
}

/* THE VERSION AND THE OBJECT TAG, WHICH GO INSIDE EVERY SIGNED RANGE.
 *
 * `version` is `frame.situ`'s own `u8 version [must_eq = 1]` applied to
 * objects that outlive schema revisions harder than a frame does, because a
 * grant with no expiry outlives everything.
 *
 * `object` is DOMAIN SEPARATION. One root key signs hops, revocations and
 * records, and all three verify through the same seam over opaque bytes --
 * so without a tag, a signature made for one can be presented as another
 * wherever the encodings can be made to collide, and capability identifiers
 * are 32 opaque bytes an attacker often chooses.
 *
 * fuzzypickles paid for this. Its `core/src/signed_tag.h` exists because two
 * of its record types collided -- "Both are 73 bytes when the name is 30 long
 * ... and ONE SIGNATURE VERIFIES AS BOTH" -- and that file named its own
 * capability chain, whose version then sat OUTSIDE every hop signature, as
 * the remaining instance of the anti-pattern it was written to fix. This
 * library is writing its transcript from scratch and takes the tag inside
 * the signed range from the start rather than inheriting a shape its
 * sibling had already identified as wrong.
 *
 * THEIR INSTANCE IS FIXED as of 2026-08-28 and this comment said otherwise
 * until they read it. `capability.c` captures the hop's start BEFORE the
 * version byte and signs `r.pos - hop_start`, so version and tag are both
 * inside the span now. Verified in their source rather than taken from
 * their message, which is the rule that found it in the first place: they
 * looked because this comment cited them, and a claim about another tree
 * decays silently because only its owner can see it go stale.
 *
 * INSIDE THE SIGNED RANGE IS THE WHOLE POINT. A tag written outside it
 * separates nothing: an attacker rewrites it and the signature still checks.
 *
 * NEITHER *FIELD* CAN BE ADDED TO THE FORMAT LATER without invalidating
 * every signature already issued, which is why both are here before anything
 * is deployed. That is a statement about the two BYTES existing in the
 * transcript, and it says nothing about the enum below gaining enumerators:
 * a new tag invalidates nothing, because an existing object's signed bytes
 * do not change and every decoder refuses a tag that is not its own.
 *
 * IT IS SPELLED OUT BECAUSE THE OLD WORDING WAS READ THE OTHER WAY, by this
 * tree first and then by fuzzypickles, who made "their enum cannot be
 * extended, so four cannot carry our twelve" the top row of a critical-path
 * list before reading the header they vendor. Retracted the same day at both
 * ends. A sentence that two careful readers took to mean the stronger thing
 * is a sentence, not a reader, at fault.
 *
 *
 * THE TAG BYTE IS ONE NAMESPACE, SHARED BY THIS LIBRARY AND ITS CONSUMERS,
 * and that is forced rather than chosen. Separation only works across
 * EVERYTHING ONE KEY SIGNS -- and a consumer's root key signs this library's
 * hops and revocations alongside its own application objects, so a tag that
 * separated only within the library would leave exactly the collision the
 * byte exists to prevent, one layer out.
 *
 * SPLIT BY THE HIGH BIT. 1..127 belong to consumers, allocated in blocks and
 * recorded below; 128..255 are this library's own. So the bit says who
 * minted an object without anybody consulting a table, a third consumer
 * needs no renegotiation with the first two, and neither side can allocate
 * into the other's half by accident.
 *
 * WHY THE LIBRARY TOOK THE HIGH HALF AND NOT THE LOW ONE. fuzzypickles
 * already holds 1..12 and its own header forbids renumbering -- rightly: a
 * tag is part of a signature's meaning, so reusing one silently revalidates
 * an old signature as a new type. This library's four had the same numbers,
 * every one colliding with a DIFFERENT object over there (our HOP against
 * their HOST_RECORD, our REVOCATION against their PREKEY_RECORD, our RECORD
 * against their CONTACT_CARD, our MANIFEST against their PAIRING_REQUEST),
 * which is the failure the byte exists to prevent, arriving on the day the
 * two trees merge. One of the two sides had to move. Nothing depends on
 * these values here -- they appear symbolically and in two test literals --
 * and something does depend on theirs, so it was ours to move, and it is
 * free exactly once.
 *
 * A RETIRED TAG IS NEVER REUSED, which is fuzzypickles' rule adopted whole.
 * When their capability hops become this library's, their tag 10 retires; it
 * does not become anything else. That is why the merged object takes a
 * number from this half rather than inheriting theirs -- during a transition
 * both encodings exist, and they must not be able to verify as each other.
 *
 * THE CONSUMER HALF, as allocated today. This library never assigns into it;
 * the block is the consumer's to fill, and it is recorded here because a
 * registry both trees read has to live in one file, and the format is ours:
 *
 *   1..12    fuzzypickles, `core/src/signed_tag.h` -- host record, prekey
 *            record, contact card, pairing request, pairing response, join
 *            request, config record, peer-sync record, manifest statement,
 *            capability hop, capability revocation, group roster.
 *   13..31   held for fuzzypickles' growth during the transition.
 *   32..127  unallocated. A consumer asks; it is written here.
 *
 * The names are quoted from their header rather than derived, so that a
 * reader can check this table against the file that owns it. */
#define FZN_SIGNED_VERSION 1u

/* True for a tag this library minted. Not a validity check -- a decoder
 * still compares against its own constant -- but the predicate a merged
 * dispatcher needs, and the thing the split above is for. */
#define FZN_OBJECT_IS_LIBRARY(tag) (((unsigned)(tag) & 0x80u) != 0u)

typedef enum fzn_signed_object {
	FZN_OBJECT_HOP = 128u,
	FZN_OBJECT_REVOCATION = 129u,
	FZN_OBJECT_RECORD = 130u,
	/* A revocation manifest: one issuer's statement of every revocation it
	 * has issued. `chain/manifest.h` carries the layout and project.md
	 * sec 13d the design. It is the fourth object one root key signs
	 * through this seam, and it is the one that makes the paragraph above
	 * concrete rather than cautionary: a manifest of n pairs is 100 + 64n
	 * bytes, a record is 156 to 668, so a one-pair manifest and a record
	 * with an 8-byte body are both 164 -- and every manifest from one
	 * pair to eight has a record of exactly its length. Same seam, same
	 * key, colliding lengths, which is fuzzypickles' incident with the
	 * numbers changed. The tag is what separates them. */
	FZN_OBJECT_MANIFEST = 131u,
	/* A prekey record: a host's statement of its own key-agreement key,
	 * signed under its own long-term key. `prekey/prekey.h` carries the
	 * layout and project.md sec 18 the design.
	 *
	 * IT IS SELF-SIGNED, WHICH IS WHY IT NEEDS THE TAG AS MUCH AS ANY
	 * OTHER OBJECT AND NOT LESS. A self-signed record is one whose signer
	 * and subject are the same 32 bytes -- so without a tag, a host's
	 * prekey record and any other object that key signs are separated by
	 * nothing but their lengths, and this one is 138 bytes, which is
	 * inside a record's 156-to-668 range at no distance at all. */
	FZN_OBJECT_PREKEY = 132u,
	/* A withdrawal: the record that undoes a revocation, naming it by
	 * hash. `chain/revocation.h` carries the layout and project.md sec 56
	 * the design.
	 *
	 * IT IS ITS OWN TAG RATHER THAN A FLAG INSIDE THE REVOCATION, and the
	 * two records are byte-identical in every other field. That is exactly
	 * the case this table exists for: without the tag, the only thing
	 * separating "withdraw this capability" from "restore it" would be a
	 * bit somewhere in a body, and the two have the same length, the same
	 * signer and opposite meanings. A tag inside the signed range means a
	 * signature over one can never be read as the other. */
	FZN_OBJECT_WITHDRAWAL = 133u,

	/* A provisioning card: an anchor, a grant and a prekey record put
	 * together by one signature. See `provision/provision.h`.
	 *
	 * The tag earns its place the same way WITHDRAWAL's does. The card's
	 * body is a concatenation of three objects that are each signed
	 * already, so without a tag of its own the envelope signature covers
	 * bytes whose leading fields are a HOP's -- and a signature is only as
	 * unambiguous as the transcript it commits to. With the tag, a card can
	 * never be read as any of the three things inside it. */
	FZN_OBJECT_PROVISION = 134u,

	/* NOT A TAG. The next number available, computed by the compiler rather
	 * than written down, which is what makes the assertions below able to
	 * notice a tag added without touching them.
	 *
	 * It is the answer to the third sabotage: a chain catches a duplicate
	 * and catches an out-of-order value, and CANNOT catch an eighth
	 * enumerator appended while the chain still ends at the seventh --
	 * measured, and it compiled silently. With this marker the addition
	 * moves it, the assertion that pins it fails, and whoever added the tag
	 * is standing three lines from the chain they have to extend.
	 *
	 * Nothing sends it and nothing switches on it: this enum's type is
	 * declared here and used nowhere, the tags travelling as the single
	 * byte a transcript gives them, so a marker costs no `-Wswitch` arm. If
	 * that ever stops being true, the marker is what has to give, not the
	 * checking. */
	FZN_OBJECT_NEXT_FREE
} fzn_signed_object_t;

/* THE ALLOCATION DISCIPLINE, CHECKED BY THE COMPILER RATHER THAN BY A TEST,
 * because it is a property of the values themselves and there is nothing to
 * run. A tag added into the consumer half -- which is what "1, 2, 3" looks
 * like to somebody adding the fifth object without reading the table above --
 * fails to build here rather than colliding on the day the trees merge.
 *
 * Distinctness is asserted as a STRICTLY INCREASING CHAIN, in the enum's own
 * order, and not by counting: a count goes stale the moment somebody adds an
 * enumerator, and would stay true while being wrong.
 *
 * IT WAS PAIRWISE UNTIL 2026-09-04, WHICH WAS CORRECT AND UNCHECKABLE. Seven
 * tags need 21 clauses and eight need 28, so the block grows as the square
 * while the thing it protects grows linearly -- and nobody adding the eighth
 * tag can tell by looking whether the seven new clauses they wrote are the
 * seven that were missing. That is not hypothetical carelessness: this file's
 * 21 clauses were confirmed complete by a script rather than by reading,
 * after the PROVISION tag's six were added by hand. They were right. The
 * point is that reading could not have said so.
 *
 * A partial pairwise addition compiles, passes, and looks finished, which is
 * the failure mode that matters: the assertion that is wrong is the one
 * nobody can see is wrong.
 *
 * Reported by fuzzypickles 2026-09-04, who paid for it in the other
 * direction. They gave a notes frame `sub_type` a number an asset-key ack
 * already had, in a set declared across two hundred lines so that no two
 * members are visible at once. Every asset-key ack routed into the notes
 * handler and was refused; the sharer's owed-key ledger never retired and
 * would have re-sent for ever. Their unit gates all passed -- **a value clash
 * is not a type error** -- and one end-to-end scenario out of 74 caught it,
 * the one that happens to exercise both families. Their fix is the chain
 * below, over all eleven of their sub_types.
 *
 * THE CHAIN STATES THE RULE AS WELL AS CHECKING IT, which is the half a
 * pairwise block cannot do: tags here are allocated in ascending order, and
 * the chain says so. That is stronger than distinctness and deliberately so.
 * An out-of-order allocation -- reusing a retired number, say -- is refused
 * rather than accepted, and having to come here and argue for it is the
 * price of an assertion a reader can check against the enum above by running
 * one finger down each. */
_Static_assert(FZN_OBJECT_IS_LIBRARY(FZN_OBJECT_HOP)
               && FZN_OBJECT_IS_LIBRARY(FZN_OBJECT_REVOCATION)
               && FZN_OBJECT_IS_LIBRARY(FZN_OBJECT_RECORD)
               && FZN_OBJECT_IS_LIBRARY(FZN_OBJECT_MANIFEST)
               && FZN_OBJECT_IS_LIBRARY(FZN_OBJECT_PREKEY)
               && FZN_OBJECT_IS_LIBRARY(FZN_OBJECT_WITHDRAWAL)
               && FZN_OBJECT_IS_LIBRARY(FZN_OBJECT_PROVISION),
               "a signed-object tag has been allocated into the consumer half");
_Static_assert(FZN_OBJECT_HOP < FZN_OBJECT_REVOCATION
               && FZN_OBJECT_REVOCATION < FZN_OBJECT_RECORD
               && FZN_OBJECT_RECORD < FZN_OBJECT_MANIFEST
               && FZN_OBJECT_MANIFEST < FZN_OBJECT_PREKEY
               && FZN_OBJECT_PREKEY < FZN_OBJECT_WITHDRAWAL
               && FZN_OBJECT_WITHDRAWAL < FZN_OBJECT_PROVISION,
               "signed-object tags must be strictly increasing in the order "
               "they are declared: equal means two objects share a signature, "
               "and out of order means somebody reused a number");
/* Every real tag fits the one byte the transcript gives it. Stated through
 * the marker rather than through the newest tag, so that adding one does not
 * also mean remembering to rename this. */
_Static_assert(FZN_OBJECT_NEXT_FREE <= 256u,
               "a signed-object tag must fit the one byte the transcript gives it");

/* AND NOTHING WAS ADDED WITHOUT COMING THROUGH HERE. The chain above proves
 * the tags it names are distinct and ordered; it says nothing about a tag it
 * does not name. This is what makes the chain's coverage total rather than
 * merely correct -- an enumerator appended anywhere moves the marker, and the
 * only way to satisfy this line again is to extend the chain to reach it. */
_Static_assert(FZN_OBJECT_NEXT_FREE == FZN_OBJECT_PROVISION + 1u,
               "a signed-object tag was added without extending the chain above it");

#endif /* FZN_BYTES_H */
