/* Capability chains: the canonical encoding, verification, expiry and
 * revocation.
 *
 * project.md sec 4.2 is the design. This is the first real code in the
 * library and sec 10 step 3 says why it is: sec 7a reassigned most of sec 4
 * to situ once the layer ladder arrived, and this is the piece that stayed
 * ours through every scope change, because it is SEMANTICS rather than
 * layout or transport.
 *
 * A HOP IS A VIEW OVER BYTES, AND THAT IS A CORRECTION (2026-08-27).
 *
 * This header used to declare `fzn_chain_hop_t` as an opaque `signed_region`
 * and `signature` ALONGSIDE a set of decoded fields, and it said so
 * deliberately: reconstructing the signed bytes here "would mean encoding a
 * hop, which would put a second encoder in the tree for the schema to
 * disagree with later". The fields were documented as a decoded view of that
 * same region, "and the caller is responsible for their agreeing".
 *
 * They did not have to agree, nothing compared them, and every policy
 * decision was taken from the fields. So an attacker kept a genuine
 * root-signed `(signed_region, signature)` pair byte-identical and rewrote
 * `grantee` to their own key, `capability` to whatever they wanted,
 * `expires_at` to FZN_NO_EXPIRY and `delegable` to 1. A single-hop chain was
 * a total authorization bypass, needing one genuine triple that every
 * deployment has by construction. Reproduced against this tree with a real
 * keyed verifier:
 *
 *     mint: ok
 *     genuine verify: ok  grantee[0]=22 expires=1000
 *     forged verify:  ok  grantee[0]=ee cap[0]=ff expires=0
 *
 * THE STATED REASON HAD EXPIRED. There was no first encoder for the schema
 * to disagree with: no hop encoder or decoder existed anywhere in the tree,
 * `wire/frame.situ` describes neither a hop nor a revocation -- its
 * `fzn_hop` is the forwarder header, an unrelated object sharing a word --
 * and no consumer supplied one. Two consequences were already visible.
 * `fzn_chain_mint` took `signed_region` as an INPUT, so a caller had to have
 * encoded a hop before it could mint one, which is the boundary admitting it
 * does not work. And the simulation's signer memcpy'd the struct, padding
 * and all, which binds within one ABI and cannot cross a host.
 *
 * So the objects are VIEWS over a canonical encoding, and every field is an
 * accessor over the bytes the signature covers. Agreement stops being a
 * contract between a caller and this module, because there is no longer
 * anything left to disagree.
 *
 * WHAT DID NOT CHANGE, and why. `fzn_chain_t` is still a struct of decoded
 * fields, because it is the VERDICT: it is produced only by code that has
 * just checked, and it became MORE trustworthy rather than less, since its
 * fields now come from bytes a signature covered. `fzn_revocation_t` is the
 * same shape for the same reason. What was wrong was carrying decoded fields
 * as INPUT beside the bytes that were supposed to justify them.
 *
 * Three properties follow from sec 4.2 and are not negotiable:
 *
 *   - THE ROOT IS PINNED, NEVER ADOPTED. fuzzypickles' equivalent
 *     deliberately verifies structure without pinning, and lets each call
 *     site decide whether to pin or to adopt on first contact, because it
 *     has a TOFU bootstrap path. This library has no such path: sec 4.2
 *     says "verified against a pinned root rather than adopted", so the
 *     root is a required parameter and a chain rooted anywhere else is
 *     refused. There is no nullable-root variant on purpose -- one
 *     function with an optional pin is a function somebody calls without
 *     the pin.
 *
 *     STILL TRUE AFTER `trust/` (2026-08-26). TOFU was added at the
 *     copyright holder's instruction, because fuzzypickles needs it and
 *     this library is absorbing host management -- but it went into
 *     `trust/trust.h` rather than here, and this function is unchanged.
 *     `fzn_trust_root` hands over a root or NULL, and NULL is refused
 *     below, so an unanchored host cannot verify against nothing. What is
 *     adopted is the anchor; what is verified against is still a pinned
 *     root. The argument above is why TOFU did not arrive as an optional
 *     parameter.
 *   - CAPABILITIES ARE OPAQUE. sec 4.2: fuzzypickles has six types and
 *     netcfgd has three which are INDEPENDENT RATHER THAN A LADDER, so a
 *     library that assumed a total order would be wrong for netcfgd on its
 *     first day. A capability is 32 bytes this module compares and never
 *     interprets.
 *   - TIME IS A PARAMETER. Nothing here reads a clock. situ's
 *     suggestion/fuzznet.md asks the same of situ and gives the reason
 *     this library already paid for once: a fuzzypickles scenario failed
 *     under load because the test raced a deadline nobody had written
 *     down, and the fix cost a day.
 */

#ifndef FZN_CHAIN_H
#define FZN_CHAIN_H

#include <stddef.h>
#include <stdint.h>

#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#define FZN_PUBKEY_LEN 32
#define FZN_CAP_ID_LEN 32

/*
 * A CAPABILITY ID, AS A TYPE RATHER THAN AS THIRTY-TWO BYTES.
 *
 * `FZN_CAP_ID_LEN` and `FZN_PUBKEY_LEN` are both 32, so until this existed a
 * capability and a public key were the same type to the compiler and
 * swapping them at a call site produced no diagnostic. project.md sec 14
 * recorded that as unclosable -- "no test can do it" -- and it is right that
 * no test can: `fzn_chain_mint(root, capability, grantee, ...)` compiled
 * clean under -Wall -Wextra -Wpedantic -Wconversion and always had.
 *
 * WRAPPING ONE SIDE IS ENOUGH. A struct and a `const uint8_t *` are
 * incompatible in BOTH directions, so a key passed where a capability
 * belongs, and a capability passed where a key belongs, are both hard
 * errors. Keys stay byte arrays here; project.md sec 44 records why both
 * sides is the intended end state and this is the first half of it.
 *
 * BY POINTER, NOT BY VALUE, because this library's accessors return VIEWS
 * INTO WIRE BUFFERS -- `fzn_manifest_capability` points into the manifest's
 * own bytes and must not copy. The cast that produces such a view lives
 * inside the accessor, so no caller writes one; a caller that casts a raw
 * buffer to this type has defeated the check deliberately, which is the most
 * C offers and is still an improvement on the confusion being invisible.
 *
 * The layout is exactly the array it replaces -- a struct of one
 * `uint8_t[32]` has that size and alignment 1 -- so nothing on the wire
 * moves, and `wire/generated/` mentions neither constant.
 */
typedef struct fzn_cap_id {
	uint8_t b[FZN_CAP_ID_LEN];
} fzn_cap_id_t;
#define FZN_SIG_LEN 64

/* A ceiling on delegation depth, checked before any hop is looked at.
 *
 * It exists because hop_count arrives from the network and every hop costs
 * a signature verification, which is the expensive operation in this
 * module -- an unbounded count is a way to spend a receiver's CPU for the
 * price of one datagram. Eight is deliberately generous against the real
 * shapes: fuzzypickles' chains are user -> host -> host, and netcfgd's
 * agent is one hop from the user key. */
#define FZN_CHAIN_MAX_HOPS 8

/* A grant with no expiry, which is the DEFAULT and not a missing value.
 *
 * sec 4.3 is emphatic and it reads as a contradiction between the two
 * consumers until you see what each is talking about: GRANTS DO NOT
 * EXPIRE, COMMANDS DO. fuzzypickles' authority is ended by revocation
 * rather than by a clock, so that no expiry can silently disconnect a
 * host; netcfgd needs commands that go stale, because a command that
 * reconfigures a router an hour late was computed against a machine that
 * no longer exists. Those are statements about different objects. A
 * command's expiry lives in the frame (wire/frame.situ's `expires_at`); a
 * grant's lives here and defaults to absent.
 *
 * TWO NAMES FOR IT, AND THE PREFIXED ONE IS WHAT IS CHECKED.
 * `FZN_CHAIN_NO_EXPIRY` is this module's own copy of the value and is
 * defined unconditionally, so it is always the number this header wrote.
 * `FZN_NO_EXPIRY` is the public spelling a consumer uses and is an alias
 * for it, guarded because `frame/freshness.h` offers the same public name
 * for the same value and neither module may depend on the other.
 *
 * The split exists because the guard defeated the check that was supposed
 * to hold the two copies together. With both headers defining
 * `FZN_NO_EXPIRY` directly, whichever was read first won and the other's
 * definition never compiled, so `wire/test/constants_test.c` asserting on
 * the public name only ever saw one of them. It is `FZN_CHAIN_NO_EXPIRY`
 * against `FZN_FRESH_NO_EXPIRY` there now -- two unguarded names, both
 * present in that translation unit whatever the include order -- which is
 * how `FZN_NONCE_LEN` and `FZN_AEAD_NONCE_LEN` are already handled. */
#define FZN_CHAIN_NO_EXPIRY 0u
#ifndef FZN_NO_EXPIRY
#define FZN_NO_EXPIRY FZN_CHAIN_NO_EXPIRY
#endif

/* PREFIXED LIKE EVERY OTHER MODULE (renamed 2026-08-26). This was `fzn_err_t`
 * with bare `FZN_OK` and `FZN_ERR_*`, because `chain/` was the first module
 * and took the general name before there were others to collide with. Every
 * module since spells `FZN_<MODULE>_OK`, so the odd one out was the one whose
 * header a consumer is most likely to include first -- and a library that
 * hands out `FZN_OK` from one of sixteen modules is claiming a name it has no
 * particular right to. */
typedef enum fzn_chain_err {
	FZN_CHAIN_OK = 0,
	/* The caller handed us something structurally impossible -- a null
	 * pointer, a hop count of zero or past FZN_CHAIN_MAX_HOPS, a view
	 * that was never opened. Distinct from CHAIN_INVALID because it means
	 * the caller has a bug, not that a peer sent something bad. */
	FZN_CHAIN_ERR_MALFORMED = -1,
	/* The chain is well-formed and does not check out: a signature that
	 * does not verify, a break in the grantor/grantee linkage, a hop for a
	 * different capability, or a hop whose own dates are impossible. */
	FZN_CHAIN_ERR_CHAIN_INVALID = -2,
	/* The chain checks out but is rooted somewhere other than the pinned
	 * root. Kept separate from CHAIN_INVALID so a caller can tell "this is
	 * a valid chain belonging to somebody else" from "this is broken" --
	 * the first is a routine occurrence on a shared network and the second
	 * is worth logging loudly. */
	FZN_CHAIN_ERR_WRONG_ROOT = -3,
	/* A hop's expiry has passed. */
	FZN_CHAIN_ERR_EXPIRED = -4,
	/* Some hop's grant has been revoked. sec 4.2: revocation is what ends
	 * authority here, so this is the answer that matters most. */
	FZN_CHAIN_ERR_REVOKED = -5,
	/* Delegation was asked for from a chain whose last hop is not
	 * `delegable`. Its own error rather than NOT_AUTHORIZED or
	 * CHAIN_INVALID, because the chain is valid and the holder does hold
	 * it -- what is missing is permission to pass it on, and a caller that
	 * cannot tell those apart will report the wrong thing to a user. */
	FZN_CHAIN_ERR_NOT_DELEGABLE = -6,
	/* A revocation could not be recorded because the store is full. Its
	 * own error because it is the one refusal in this library that fails
	 * OPEN -- see revocation.h. */
	FZN_CHAIN_ERR_STORE_FULL = -7,
	/* These bytes are not the shape the layout describes: a wrong length,
	 * a version or object byte that is not ours, a `delegable` outside
	 * {0,1}.
	 *
	 * ITS OWN CODE RATHER THAN MALFORMED, and the distinction is the one
	 * MALFORMED already draws above. MALFORMED means the CALLER has a bug.
	 * Bytes from a peer that are the wrong length are not a caller bug --
	 * they are the ordinary hostile input this library exists to refuse,
	 * and a receiver that logged them as its own defect would be looking
	 * in the wrong place.
	 *
	 * It is also a code that could not have existed before 2026-08-27.
	 * Canonicality is not a question the parallel-fields design could ask
	 * at all, because there were no bytes to ask it of. */
	FZN_CHAIN_ERR_SHAPE = -8,
} fzn_chain_err_t;

/* THE HOP LAYOUT. Big-endian, fixed width, no padding, fixed fields first,
 * one encoding per value -- so that two implementations which agree on this
 * table cannot produce different bytes for the same grant, which is exactly
 * what a signature over them requires.
 *
 *     offset  size  field
 *          0     1  version    (= FZN_SIGNED_VERSION)
 *          1     1  object     (= FZN_OBJECT_HOP)
 *          2    32  grantor
 *         34    32  grantee
 *         66    32  capability
 *         98     8  issued_at
 *        106     8  expires_at
 *        114     1  delegable  (0 or 1, and nothing else)
 *        115    64  signature
 *
 * The signature covers bytes 0 through 114 -- the whole body, version and
 * object byte included. `wire/bytes.h` says why those two are inside the
 * signed range and why neither could be added later. */
#define FZN_HOP_BODY_LEN 115u
#define FZN_HOP_LEN (FZN_HOP_BODY_LEN + (size_t)FZN_SIG_LEN)

/* Named, so that a test mutating a field cites the header's own offset
 * rather than a number it worked out for itself. evidence.md: a derived
 * number is a measurement nobody is positioned to re-take. */
#define FZN_HOP_OFF_VERSION 0u
#define FZN_HOP_OFF_OBJECT 1u
#define FZN_HOP_OFF_GRANTOR 2u
#define FZN_HOP_OFF_GRANTEE 34u
#define FZN_HOP_OFF_CAPABILITY 66u
#define FZN_HOP_OFF_ISSUED_AT 98u
#define FZN_HOP_OFF_EXPIRES_AT 106u
#define FZN_HOP_OFF_DELEGABLE 114u
#define FZN_HOP_OFF_SIGNATURE FZN_HOP_BODY_LEN

/* One delegation step: grantor gives grantee this capability.
 *
 * A VIEW, and the pointer is the whole of it. `base` addresses FZN_HOP_LEN
 * bytes the caller owns and must keep alive for as long as the view is used
 * -- nothing here allocates or copies. Open it with `fzn_hop_open`, which is
 * the only thing that may set `base`, and read it with the accessors below.
 *
 * The struct is not opaque, because a consumer building an array of these on
 * the stack needs its size and hiding one pointer behind an allocator would
 * buy nothing. What matters is that there is no second copy of any field for
 * the bytes to disagree with. */
typedef struct fzn_chain_hop {
	const uint8_t *base;
} fzn_chain_hop_t;

/* Take a view over `len` bytes at `bytes`.
 *
 * PARSE CHECKS LAYOUT; VERIFY CHECKS SEMANTICS. This refuses a wrong length,
 * a version or object byte that is not ours, and a `delegable` outside
 * {0,1} -- all canonicality, all answerable from the bytes alone, and all
 * returning FZN_CHAIN_ERR_SHAPE.
 *
 * It deliberately does NOT check that `expires_at` is after `issued_at`.
 * That is a statement about the grant rather than about its shape, it has
 * its own place in `fzn_chain_verify`'s order, and the taxonomy there tells
 * a caller "this was never a grant" apart from "these are not our bytes".
 *
 * `delegable` is the one field whose canonicality has to be enforced rather
 * than absorbed. The accessor could read any nonzero byte as true, but then
 * 255 encodings of one grant exist, the signature over each is different,
 * and two implementations that both "work" produce hops the other rejects.
 * Refusing here leaves exactly one.
 *
 * Returns FZN_CHAIN_ERR_MALFORMED for a null argument, since that is the
 * caller's bug rather than a peer's bytes. */
fzn_chain_err_t fzn_hop_open(const uint8_t *bytes, size_t len, fzn_chain_hop_t *out);

/* Lay out a hop, unsigned. `out` receives FZN_HOP_LEN bytes: the body as the
 * table above describes it, and a signature left zeroed for a signer to
 * fill.
 *
 * THE ONLY ENCODER IN THE TREE, which is what makes the view design mean
 * anything. `fzn_chain_mint` and `fzn_chain_delegate` both come through
 * here, and so does anybody assembling a hop for a test. A second one would
 * be the thing the old design's comment feared, and this is where it would
 * have to be added deliberately rather than by accident. */
fzn_chain_err_t fzn_hop_encode(uint8_t *out, const uint8_t grantor[FZN_PUBKEY_LEN],
                               const uint8_t grantee[FZN_PUBKEY_LEN],
                               const fzn_cap_id_t *capability, uint64_t issued_at,
                               uint64_t expires_at, int delegable);

/* The accessors. Each reads the bytes the signature covers, so there is
 * nothing for a policy decision to be taken from except what was signed.
 *
 * They require an OPENED view: `fzn_hop_open` established the length and the
 * shape, and asking these to re-check it on every read would be the same
 * bounds test eight times per hop. A `base` that did not come from
 * `fzn_hop_open` is a caller bug of the kind FZN_CHAIN_ERR_MALFORMED names. */
static inline const uint8_t *fzn_hop_grantor(fzn_chain_hop_t hop)
{
	return hop.base + FZN_HOP_OFF_GRANTOR;
}

static inline const uint8_t *fzn_hop_grantee(fzn_chain_hop_t hop)
{
	return hop.base + FZN_HOP_OFF_GRANTEE;
}

/* Typed, like the manifest and revocation accessors: the cast that gives a
 * wire view its type is here so that no caller writes one. */
static inline const fzn_cap_id_t *fzn_hop_capability(fzn_chain_hop_t hop)
{
	return (const fzn_cap_id_t *)(hop.base + FZN_HOP_OFF_CAPABILITY);
}

static inline uint64_t fzn_hop_issued_at(fzn_chain_hop_t hop)
{
	return fzn_get_be64(hop.base + FZN_HOP_OFF_ISSUED_AT);
}

static inline uint64_t fzn_hop_expires_at(fzn_chain_hop_t hop)
{
	return fzn_get_be64(hop.base + FZN_HOP_OFF_EXPIRES_AT);
}

/* Whether the grantee may pass this capability on. Zero -- the default --
 * means it may not, and a chain that continues past a hop with it clear is
 * refused.
 *
 * HOLDING SOMETHING IS NOT ENTITLEMENT TO HAND IT OUT, and this bit is the
 * whole of that distinction. fuzzypickles found the same thing the expensive
 * way: its grant path asked only whether the granting host held the type it
 * was handing over, which "left CAP_ADMIN gating nothing and let any host
 * promote any other host to its own capability set". Its fix was to require
 * a second capability, `CAP_ADMIN`, alongside the one being granted.
 *
 * That fix is not available here and must not be imitated. sec 4.2 keeps
 * capabilities OPAQUE -- netcfgd's three are independent rather than a
 * ladder, and a library that knew which identifier meant "may grant" would
 * be interpreting them. So the entitlement travels as a bit on the hop
 * rather than as a capability with a special meaning, which says the same
 * thing without this library ever learning what any capability is.
 *
 * IT IS ALSO THE SHARPEST OF THE FIELDS THE OLD DESIGN LEFT UNBOUND.
 * Flipping it to 1 on a genuine non-delegable hop -- signature and signed
 * region untouched, because nothing read them -- let an attacker delegate
 * what nobody authorised, starting from a grant they had been legitimately
 * given. */
static inline int fzn_hop_delegable(fzn_chain_hop_t hop)
{
	return hop.base[FZN_HOP_OFF_DELEGABLE] != 0u;
}

static inline const uint8_t *fzn_hop_signature(fzn_chain_hop_t hop)
{
	return hop.base + FZN_HOP_OFF_SIGNATURE;
}

/* The bytes this hop's signature covers: the body, from the first byte.
 *
 * A function rather than two constants each caller applies for itself,
 * because the range is the one thing every field's integrity rests on and it
 * is worth stating exactly once. */
static inline void fzn_hop_signed_bytes(fzn_chain_hop_t hop, const uint8_t **at, size_t *len)
{
	*at = hop.base;
	*len = FZN_HOP_BODY_LEN;
}

/* THE CHAIN CONTAINER, which exists so that three consumers do not invent
 * three.
 *
 * A chain has to reach another host somehow, and the hops are the only part
 * that is signed -- so this is a framing rather than an object, and it
 * carries no object tag: there is no signature over it whose domain a tag
 * could separate. It carries a version because a container whose shape
 * changes with no way to say so is the failure `wire/bytes.h` describes for
 * the objects themselves.
 *
 *     offset  size  field
 *          0     1  version    (= FZN_SIGNED_VERSION)
 *          1     1  hop_count  (1..FZN_CHAIN_MAX_HOPS)
 *          2   ...  that many hops, each FZN_HOP_LEN bytes
 */
#define FZN_CHAIN_HEADER_LEN 2u
#define FZN_CHAIN_MAX_LEN (FZN_CHAIN_HEADER_LEN + FZN_CHAIN_MAX_HOPS * FZN_HOP_LEN)

/* Open a container, and every hop in it. `out` receives one view per hop and
 * `*hop_count` says how many.
 *
 * Refuses, with FZN_CHAIN_ERR_SHAPE: a length under the header, a version
 * that is not ours, a hop count of zero or past FZN_CHAIN_MAX_HOPS, a length
 * that is not exactly the header plus that many hops -- trailing bytes are a
 * refusal rather than something to ignore, because "ignore what you do not
 * understand" is how one encoding becomes several -- and any hop
 * `fzn_hop_open` refuses.
 *
 * It does NOT verify anything. `fzn_chain_verify` is still the only thing
 * that decides whether a chain authorises anybody, and keeping them apart is
 * what leaves the pinned root a required argument of the verification rather
 * than an optional argument of a parser. */
fzn_chain_err_t fzn_chain_open(const uint8_t *bytes, size_t len,
                               fzn_chain_hop_t out[FZN_CHAIN_MAX_HOPS], size_t *hop_count);

/* Write `hop_count` opened hops into a container at `out`, which holds `cap`
 * bytes, and report the length written through `*len`.
 *
 * The counterpart to `fzn_chain_open`, and it is here rather than left to
 * each consumer for the same reason the encoder is: a reader with no writer
 * is a writer everybody invents. */
fzn_chain_err_t fzn_chain_pack(const fzn_chain_hop_t *hops, size_t hop_count, uint8_t *out,
                               size_t cap, size_t *len);

/* The signature seam.
 *
 * sec 4.5 vendors Monocypher once here rather than three times, and sec 6
 * binds it to situ as an EXTERN CODEC rather than wrapping it. The same
 * boundary serves this module, for the reason situ's own extern codecs
 * exist: the schema names the operation and the implementation is supplied.
 *
 * Here it also buys the whole test strategy. A verifier is a function
 * pointer, so a test drives every path in this file -- broken linkage,
 * expired hop, wrong root, revoked grantee -- with a stub that answers
 * yes or no on demand, and never links a crypto library or generates a
 * key. That is the same property situ/suggestion/fuzznet.md asks situ to
 * preserve for protocol state: a value rather than a process, constructible
 * directly into states normal operation cannot reach.
 *
 * A STUB THAT IGNORES ITS MESSAGE CANNOT SEE THE BUG THE NOTE AT THE TOP OF
 * THIS FILE DESCRIBES, and every stub in the tree ignored it -- `(void)msg;`
 * appeared in all of them. The suite's stubs now answer over the message as
 * well as the key, because a verifier whose verdict does not depend on the
 * bytes makes "this field is inside the signed range" a question with no
 * observable answer.
 *
 * `verify` returns nonzero for a good signature and zero for a bad one.
 *
 * `sign` signs as WHOEVER THE CONTEXT IS -- it takes no key, because the
 * context holds one. That shape is deliberate and is the reason this module
 * has no secret-key parameter anywhere: sec 3 has fuzznet linked by an
 * unprivileged bridge that "never runs in the process holding CAP_NET_ADMIN,
 * a RAID controller, or a user's private keys beyond its own session
 * material", and an API that took a secret key would be an invitation to
 * hand one to it. A signer that owns its key can live behind a socket, in
 * another process, or in hardware, and none of that is visible here.
 *
 * It may be NULL when only verification is wanted; minting and delegation
 * refuse without it. */
typedef struct fzn_sign_ops {
	int (*verify)(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
	              size_t msg_len, const uint8_t sig[FZN_SIG_LEN]);
	int (*sign)(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len);
	void *ctx;
} fzn_sign_ops_t;

/* What a verified chain turned out to say.
 *
 * STILL A STRUCT OF DECODED FIELDS, and deliberately. It is the verdict
 * rather than the evidence: it is produced only by code that has just
 * checked, and every field in it was read out of bytes a signature covered.
 * The old hop struct was the opposite -- decoded fields presented as INPUT
 * beside bytes that were supposed to justify them. */
typedef struct fzn_chain {
	uint8_t root[FZN_PUBKEY_LEN];
	uint8_t grantee[FZN_PUBKEY_LEN];   /* who this chain authorises */
	fzn_cap_id_t capability;
	size_t hop_count;
	/* The soonest REAL expiry across all hops, or FZN_NO_EXPIRY when no
	 * hop sets one. A chain is only as strong as its weakest link, and an
	 * unlimited hop does not win this minimum -- it simply does not
	 * constrain it. */
	uint64_t expires_at;
} fzn_chain_t;

/* One thing a host knows to be revoked: a capability withdrawn from a key.
 *
 * This is the VERIFIED form -- what a host has already decided to believe,
 * and the same verdict-not-evidence argument as `fzn_chain_t` above. What
 * travels on the wire is `fzn_revocation_record_t`, a view over signed
 * bytes, checked once on admission; see revocation.h, which also records why
 * an earlier revision of this comment was wrong to say a signature was
 * unnecessary. The short version: an authenticated datagram attributes its
 * contents to the peer that sent it and to nobody further back, and
 * "carried on contact" means the carrier is not the issuer.
 *
 * IT KEEPS THE ISSUER, AND THAT IS A CORRECTION (2026-08-27). This struct
 * used to hold `capability` and `grantee` alone. `fzn_revocation_admit`
 * checked a record's issuer against the root it was handed and then threw
 * the issuer away, `fzn_revocation_covers` took no root at all, and
 * `fzn_chain_verify` takes `root` and this array as independent parameters
 * with nothing comparing them -- so a store holding root B's revocation
 * answered "revoked" about root A's realm. Confirmed by running it, not by
 * reading: B signs a revocation, it is admitted against B's own root, and
 * `covers` returns 1 for that pair with no root in the question. Every test
 * in the tree used a single root, so it was untested rather than
 * tested-and-passing, and project.md sec 14 carries the reproduction.
 *
 * THE FIX KEEPS THE ISSUER RATHER THAN BINDING THE STORE TO ONE ROOT, which
 * is the smaller-looking change and the wrong one. sec 13b records the
 * holder's answer of 2026-08-27: grantor-revokes-descendant IS coming, so a
 * store will hold entries from MANY issuers and a store bound to a single
 * root would have to be unbound again. An entry says WHO withdrew it, and
 * the query asks.
 *
 * IT CAME ON 2026-08-28, and the issuer field is what carries it: an entry
 * is matched against the grantors of the chain being verified, so a
 * grantor's withdrawal from its own descendant is honoured and a stranger's
 * is not. A store bound to one root could not have expressed that. */
typedef struct fzn_revocation {
	fzn_cap_id_t capability;
	uint8_t grantee[FZN_PUBKEY_LEN];
	/* Who withdrew it -- read from the record's own signed bytes on
	 * admission, never from what a caller supplied alongside them. */
	uint8_t issuer[FZN_PUBKEY_LEN];
} fzn_revocation_t;

/* The store, DECLARED here and DEFINED in revocation.h.
 *
 * `fzn_chain_verify` takes a store rather than an array and a count, and the
 * type it takes belongs to the module that owns admission, so this end holds
 * the name only. A consumer that has no revocations passes NULL and never
 * includes revocation.h; one that has any includes it and gets the fields.
 *
 * The incomplete type is the point rather than a compromise: nothing on this
 * side of the library may reach into a store, because reaching in is exactly
 * what the array-and-count signature used to invite. See `fzn_chain_verify`
 * below for what that cost. */
typedef struct fzn_revocation_store fzn_revocation_store_t;

/* Verify a chain against a pinned root, and report what it authorises.
 *
 * `hops` is an array of OPENED views, in delegation order: hops[0] is signed
 * by the root, and each later hop is signed by the previous hop's grantee.
 * `now` is the caller's clock. `revocations` is a store, and NULL means
 * "this host knows of no revocations" -- which is the whole of what the old
 * `NULL, 0` said.
 *
 * IT TAKES THE STORE, AND THAT IS A CORRECTION (2026-08-27, the second of
 * the day). It used to take `(const fzn_revocation_t *, size_t)`, while the
 * documented calling pattern everywhere -- in this header, in revocation.h,
 * in every consumer and every suite -- was `store.entries, store.used`. So
 * `used` bounded a loop over an array whose length is `capacity`, and this
 * function had no `capacity` to check it against.
 *
 * `fzn_revocation_covers` refuses to scan a store where `used > capacity`
 * and answers REVOKED, deliberately, because denying is the safe reply to
 * an authorization question -- and revocation_test.c asserts that state as
 * real rather than impossible. This function could not make the same
 * refusal, and reached one entry past the array instead. Reproduced under
 * AddressSanitizer with a two-entry store and `used = capacity + 1`:
 *
 *     ERROR: AddressSanitizer: heap-buffer-overflow
 *     READ of size 1 ... in fzn_ct_memeq constant_time/constant_time.c:38
 *       #1 hop_is_revoked chain/chain.c:24
 *       #2 fzn_chain_verify chain/chain.c:261
 *
 * A memory-safety fault on the authorization path, in the fail-open
 * direction, reached from a state the module's own suite calls reachable.
 *
 * THE REPAIR IS TO STOP HAVING TWO PREDICATES. The 2026-08-27 issuer fix
 * gave `fzn_revocation_covers` the same question this function was asking
 * privately, and corrupt-store handling became the only thing that differed
 * between them -- which is the shape a later simplification deletes the
 * wrong half of. There is one implementation now: this function calls that
 * one, and inherits its refusal by construction rather than by both being
 * kept in step.
 *
 * A second API break in one day, taken deliberately: the consumer that
 * vendors this library links no symbol from it yet and would rather take
 * breaks now than after it does.
 *
 * Every hop is checked, in this order, and the order is chosen so that the
 * cheap structural refusals happen before any signature verification:
 *
 *   1. hop_count within [1, FZN_CHAIN_MAX_HOPS]
 *   2. every hop names `capability` -- chains are single-capability by
 *      construction, so a chain that changes what it grants half way along
 *      is not a narrowing, it is two chains spliced
 *   3. linkage: hops[0].grantor is the pinned root, and each later hop's
 *      grantor is the previous hop's grantee -- which must also have been
 *      marked `delegable`, or the chain claims a delegation nobody
 *      authorised
 *   4. dates: expires_at, WHEN SET, must be after issued_at and after now
 *   5. revocation, against every hop rather than only the last -- revoking
 *      a host in the middle has to kill everything it went on to grant,
 *      which is the whole point of revoking it. A hop is revoked by the
 *      pinned root OR by any of that hop's ANCESTORS IN THIS CHAIN, which
 *      is a set this function derives from the hops it was handed and
 *      cannot be told wrong; `fzn_revocation_covers_chain` computes it,
 *      once, hoisted out of the loop
 *   6. signatures, last, because they are the expensive part
 *
 * Every one of those reads the bytes the signature covers, which is the
 * 2026-08-27 change stated as a property rather than as a design note: a
 * chain that passes step 6 has had steps 2 through 5 asked of exactly the
 * bytes step 6 authenticated.
 *
 * Returns FZN_CHAIN_OK and fills *out on success. On any failure *out is left
 * untouched, so a caller cannot half-read a rejected chain.
 *
 * ON EXPIRY, AND AN AMBIGUITY IN THE DOCUMENT: sec 4.3's second bullet
 * says a grant's expiry is optional and defaults to absent, and then that
 * "an expired or absent expiry never withdraws authority -- only a
 * revocation does". Read literally that makes a set expiry unenforceable
 * and the field pointless. Read as being about the DEFAULT -- that no
 * expiry is imposed where none was asked for -- it agrees with sec 4.2's
 * named reference implementation, which enforces a hop's expiry when one
 * is set. This implements the second reading and fails closed, which is
 * the safer direction for a library that reconfigures infrastructure
 * (sec 4.4a). Flagged rather than resolved: project.md wins over the code,
 * and which reading was meant is not this file's to decide. */
fzn_chain_err_t fzn_chain_verify(const fzn_chain_hop_t *hops, size_t hop_count,
                            const uint8_t root[FZN_PUBKEY_LEN],
                            const fzn_cap_id_t *capability, uint64_t now,
                            const fzn_sign_ops_t *sign,
                            const fzn_revocation_store_t *revocations, fzn_chain_t *out);

/* Mint hop 0: the root grants `capability` to `grantee`, directly. `out`
 * receives FZN_HOP_LEN bytes -- the encoded hop, signed.
 *
 * IT PRODUCES BYTES NOW, which is what makes it usable at all. It used to
 * take `signed_region` as an INPUT: a caller had to have encoded a hop
 * before it could mint one, from an encoder that did not exist anywhere.
 * What it returns is what goes on the wire, and `fzn_hop_open` over those
 * same bytes is what a receiver holds.
 *
 * Only the holder of the root key can do this, and this function does not
 * check that -- it cannot. `sign->sign` either produces a signature that
 * verifies under `root` or it does not, and the answer arrives when somebody
 * verifies the chain. Asking here would mean either taking the secret key
 * (which sec 3 forbids in spirit) or trusting a claim, and a self-assessed
 * claim is worth nothing. So the parameter is the root's PUBLIC key, used to
 * fill the hop's grantor, and being wrong about it produces a chain that
 * fails verification rather than one that lies.
 *
 * Returns FZN_CHAIN_ERR_MALFORMED on a missing argument or absent signer, and
 * FZN_CHAIN_ERR_CHAIN_INVALID if the signer refuses or the dates are
 * impossible. */
fzn_chain_err_t fzn_chain_mint(const uint8_t root[FZN_PUBKEY_LEN],
                          const uint8_t grantee[FZN_PUBKEY_LEN],
                          const fzn_cap_id_t *capability, uint64_t issued_at,
                          uint64_t expires_at, int delegable, const fzn_sign_ops_t *sign,
                          uint8_t *out);

/* Extend a chain by one hop: its current grantee grants onward. `out`
 * receives FZN_HOP_LEN bytes, the NEW hop only.
 *
 * The existing chain is RE-VERIFIED first, in full, against the pinned root
 * and the same revocation store a receiver would use. That is defence in
 * depth and it is not redundant: never delegate from a chain that has
 * expired, been revoked, or stopped checking out, because the result would
 * be a hop that looks freshly minted while resting on something dead.
 * fuzzypickles does the same and for the same reason.
 *
 * Two caps apply to the new hop, and both are the same idea -- a grantor
 * cannot hand out what it does not have:
 *
 *   - EXPIRY is capped at the existing chain's own `expires_at`. Asking for
 *     longer, or for none at all, silently yields the chain's. A host whose
 *     own authority lapses on Tuesday cannot grant until Friday.
 *   - DELEGATION requires the chain's last hop to be `delegable`. Without
 *     it this returns FZN_CHAIN_ERR_NOT_DELEGABLE, which is deliberately its own
 *     error rather than CHAIN_INVALID: the chain is perfectly valid, the
 *     caller simply may not do this with it.
 *
 * Depth is bounded too -- extending a chain already at FZN_CHAIN_MAX_HOPS
 * returns FZN_CHAIN_ERR_MALFORMED rather than producing something no verifier
 * would accept.
 *
 * Assembling the new hop onto the chain is the caller's, because this module
 * does not own the array's storage any more than it owns the bytes --
 * `fzn_chain_pack` is there for exactly that. */
fzn_chain_err_t fzn_chain_delegate(const fzn_chain_hop_t *hops, size_t hop_count,
                              const uint8_t root[FZN_PUBKEY_LEN],
                              const fzn_cap_id_t *capability, uint64_t now,
                              const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t expires_at,
                              int delegable, const fzn_sign_ops_t *sign,
                              const fzn_revocation_store_t *revocations, uint8_t *out);

/* Constant-time comparison comes from constant_time.h, which chain.h
 * includes so that existing users of fzn_ct_memeq keep compiling. New code
 * that wants only the comparison should include that header directly rather
 * than the capability model -- see the reasoning there. */

/* A short name for `fzn_chain_err_t`, for a log line or a message to a user.
 *
 * NEVER NULL, including for a value that is not one of the enumerators, so
 * that a caller may pass the result straight to a printf without a check.
 * An unrecognised value renders as "unknown", which is deliberately not any
 * real code's text -- a caller that cannot tell "we do not know" from a
 * genuine answer is the failure this whole library is careful about
 * elsewhere.
 *
 * The strings are lowercase, carry no trailing punctuation and name the
 * condition rather than restating the constant, on the same reasoning as
 * strerror: the caller supplies the sentence, this supplies the noun. */
const char *fzn_chain_err_str(fzn_chain_err_t err);

#endif /* FZN_CHAIN_H */
