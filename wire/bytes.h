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
 * ... and ONE SIGNATURE VERIFIES AS BOTH" -- and that file names its own
 * capability chain, whose version sits OUTSIDE every hop signature, as the
 * remaining instance of the anti-pattern it was written to fix. This library
 * is writing its transcript from scratch and takes the tag inside the signed
 * range from the start rather than inheriting a shape its sibling has already
 * identified as wrong.
 *
 * INSIDE THE SIGNED RANGE IS THE WHOLE POINT. A tag written outside it
 * separates nothing: an attacker rewrites it and the signature still checks.
 *
 * Neither byte can be added later without invalidating every signature
 * already issued, which is why they are here before anything is deployed. */
#define FZN_SIGNED_VERSION 1u

typedef enum fzn_signed_object {
	FZN_OBJECT_HOP = 1u,
	FZN_OBJECT_REVOCATION = 2u,
	FZN_OBJECT_RECORD = 3u,
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
	FZN_OBJECT_MANIFEST = 4u,
} fzn_signed_object_t;

#endif /* FZN_BYTES_H */
