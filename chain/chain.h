/* Capability chains: verification, expiry and revocation.
 *
 * project.md sec 4.2 is the design. This is the first real code in the
 * library and sec 10 step 3 says why it is: sec 7a reassigned most of sec 4
 * to situ once the layer ladder arrived, and this is the piece that stayed
 * ours through every scope change, because it is SEMANTICS rather than
 * layout or transport.
 *
 * That division is load-bearing here and shapes the whole interface. This
 * module never parses a byte. It is handed hops that somebody else decoded
 * -- the schema, once sec 10 step 4 picks a rung -- and answers one
 * question about them: does this chain authorise this grantee for this
 * capability, right now, under a root we already trust. Which bytes a hop
 * occupies, and which of them its signature covers, are the schema's
 * business and appear here only as a pointer and a length the caller
 * supplies.
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

#define FZN_PUBKEY_LEN 32
#define FZN_CAP_ID_LEN 32
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
 * grant's lives here and defaults to absent. */
#ifndef FZN_NO_EXPIRY
#define FZN_NO_EXPIRY 0u
#endif

typedef enum fzn_err {
	FZN_OK = 0,
	/* The caller handed us something structurally impossible -- a null
	 * pointer, a hop count of zero or past FZN_CHAIN_MAX_HOPS, a hop with
	 * no signed region. Distinct from CHAIN_INVALID because it means the
	 * caller has a bug, not that a peer sent something bad. */
	FZN_ERR_MALFORMED = -1,
	/* The chain is well-formed and does not check out: a signature that
	 * does not verify, a break in the grantor/grantee linkage, a hop for a
	 * different capability, or a hop whose own dates are impossible. */
	FZN_ERR_CHAIN_INVALID = -2,
	/* The chain checks out but is rooted somewhere other than the pinned
	 * root. Kept separate from CHAIN_INVALID so a caller can tell "this is
	 * a valid chain belonging to somebody else" from "this is broken" --
	 * the first is a routine occurrence on a shared network and the second
	 * is worth logging loudly. */
	FZN_ERR_WRONG_ROOT = -3,
	/* A hop's expiry has passed. */
	FZN_ERR_EXPIRED = -4,
	/* Some hop's grant has been revoked. sec 4.2: revocation is what ends
	 * authority here, so this is the answer that matters most. */
	FZN_ERR_REVOKED = -5,
	/* Delegation was asked for from a chain whose last hop is not
	 * `delegable`. Its own error rather than NOT_AUTHORIZED or
	 * CHAIN_INVALID, because the chain is valid and the holder does hold
	 * it -- what is missing is permission to pass it on, and a caller that
	 * cannot tell those apart will report the wrong thing to a user. */
	FZN_ERR_NOT_DELEGABLE = -6,
	/* A revocation could not be recorded because the store is full. Its
	 * own error because it is the one refusal in this library that fails
	 * OPEN -- see revocation.h. */
	FZN_ERR_STORE_FULL = -7,
} fzn_err_t;

/* One delegation step: grantor gives grantee this capability.
 *
 * `signed_region` is the bytes this hop's signature covers, and this module
 * takes it as opaque rather than reconstructing it. That is the layout
 * boundary in its most concrete form -- recomputing the signed bytes here
 * would mean encoding a hop, which would put a second encoder in the tree
 * for the schema to disagree with later. Whoever decoded the hop already
 * knows exactly which bytes they were and hands them over.
 *
 * The fields below are therefore a DECODED VIEW of that same region, and
 * the caller is responsible for their agreeing. A caller that fills these
 * from one hop and points signed_region at another gets a verdict about
 * neither; there is no way to check that from here without the encoder
 * this boundary exists to avoid. */
typedef struct fzn_chain_hop {
	uint8_t grantor[FZN_PUBKEY_LEN];
	uint8_t grantee[FZN_PUBKEY_LEN];
	uint8_t capability[FZN_CAP_ID_LEN];
	uint64_t issued_at;
	uint64_t expires_at; /* FZN_NO_EXPIRY (0) means never */
	/* Whether the grantee may pass this capability on. Zero -- the
	 * default -- means it may not, and a chain that continues past a hop
	 * with it clear is refused.
	 *
	 * HOLDING SOMETHING IS NOT ENTITLEMENT TO HAND IT OUT, and this bit is
	 * the whole of that distinction. fuzzypickles found the same thing the
	 * expensive way: its grant path asked only whether the granting host
	 * held the type it was handing over, which "left CAP_ADMIN gating
	 * nothing and let any host promote any other host to its own
	 * capability set". Its fix was to require a second capability,
	 * `CAP_ADMIN`, alongside the one being granted.
	 *
	 * That fix is not available here and must not be imitated. sec 4.2
	 * keeps capabilities OPAQUE -- netcfgd's three are independent rather
	 * than a ladder, and a library that knew which identifier meant
	 * "may grant" would be interpreting them. So the entitlement travels
	 * as a bit on the hop rather than as a capability with a special
	 * meaning, which says the same thing without this library ever
	 * learning what any capability is.
	 *
	 * Fail-closed on purpose: a decoder that forgets the field, or a
	 * caller that zeroes a hop and fills in what it knows about, produces
	 * a grant that cannot be delegated onward rather than one that can. */
	int delegable;
	uint8_t signature[FZN_SIG_LEN];
	const uint8_t *signed_region;
	size_t signed_region_len;
} fzn_chain_hop_t;

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

/* What a verified chain turned out to say. */
typedef struct fzn_chain {
	uint8_t root[FZN_PUBKEY_LEN];
	uint8_t grantee[FZN_PUBKEY_LEN];   /* who this chain authorises */
	uint8_t capability[FZN_CAP_ID_LEN];
	size_t hop_count;
	/* The soonest REAL expiry across all hops, or FZN_NO_EXPIRY when no
	 * hop sets one. A chain is only as strong as its weakest link, and an
	 * unlimited hop does not win this minimum -- it simply does not
	 * constrain it. */
	uint64_t expires_at;
} fzn_chain_t;

/* One thing a host knows to be revoked: a capability withdrawn from a key.
 *
 * This is the VERIFIED form -- what a host has already decided to believe.
 * What travels on the wire carries its issuer and a signature, and is
 * checked once on admission; see revocation.h, which also records why an
 * earlier revision of this comment was wrong to say a signature was
 * unnecessary. The short version: an authenticated datagram attributes its
 * contents to the peer that sent it and to nobody further back, and
 * "carried on contact" means the carrier is not the issuer. */
typedef struct fzn_revocation {
	uint8_t capability[FZN_CAP_ID_LEN];
	uint8_t grantee[FZN_PUBKEY_LEN];
} fzn_revocation_t;

/* Verify a chain against a pinned root, and report what it authorises.
 *
 * `hops` is in delegation order: hops[0] is signed by the root, and each
 * later hop is signed by the previous hop's grantee. `now` is the caller's
 * clock. `revocations` may be NULL with `revocation_count` 0.
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
 *      which is the whole point of revoking it
 *   6. signatures, last, because they are the expensive part
 *
 * Returns FZN_OK and fills *out on success. On any failure *out is left
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
fzn_err_t fzn_chain_verify(const fzn_chain_hop_t *hops, size_t hop_count,
                            const uint8_t root[FZN_PUBKEY_LEN],
                            const uint8_t capability[FZN_CAP_ID_LEN], uint64_t now,
                            const fzn_sign_ops_t *sign, const fzn_revocation_t *revocations,
                            size_t revocation_count, fzn_chain_t *out);

/* Mint hop 0: the root grants `capability` to `grantee`, directly.
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
 * `signed_region` is the encoded hop as the schema lays it out, and is the
 * same boundary fzn_chain_verify draws: this module signs bytes it is given
 * and does not encode them. A caller whose region disagrees with the fields
 * it also passes gets a hop that verifies against neither.
 *
 * Returns FZN_ERR_MALFORMED on a missing argument or absent signer, and
 * FZN_ERR_CHAIN_INVALID if the signer refuses. */
fzn_err_t fzn_chain_mint(const uint8_t root[FZN_PUBKEY_LEN],
                          const uint8_t grantee[FZN_PUBKEY_LEN],
                          const uint8_t capability[FZN_CAP_ID_LEN], uint64_t issued_at,
                          uint64_t expires_at, int delegable, const uint8_t *signed_region,
                          size_t signed_region_len, const fzn_sign_ops_t *sign,
                          fzn_chain_hop_t *out);

/* Extend a chain by one hop: its current grantee grants onward.
 *
 * The existing chain is RE-VERIFIED first, in full, against the pinned root
 * and the same revocation list a receiver would use. That is defence in
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
 *     it this returns FZN_ERR_NOT_DELEGABLE, which is deliberately its own
 *     error rather than CHAIN_INVALID: the chain is perfectly valid, the
 *     caller simply may not do this with it.
 *
 * Depth is bounded too -- extending a chain already at FZN_CHAIN_MAX_HOPS
 * returns FZN_ERR_MALFORMED rather than producing something no verifier
 * would accept.
 *
 * `out` receives only the NEW hop. Assembling it onto the chain is the
 * caller's, because this module does not own the array's storage any more
 * than it owns the bytes. */
fzn_err_t fzn_chain_delegate(const fzn_chain_hop_t *hops, size_t hop_count,
                              const uint8_t root[FZN_PUBKEY_LEN],
                              const uint8_t capability[FZN_CAP_ID_LEN], uint64_t now,
                              const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t expires_at,
                              int delegable, const uint8_t *signed_region,
                              size_t signed_region_len, const fzn_sign_ops_t *sign,
                              const fzn_revocation_t *revocations, size_t revocation_count,
                              fzn_chain_hop_t *out);

/* Constant-time comparison comes from constant_time.h, which chain.h
 * includes so that existing users of fzn_ct_memeq keep compiling. New code
 * that wants only the comparison should include that header directly rather
 * than the capability model -- see the reasoning there. */

/* A short name for `fzn_err_t`, for a log line or a message to a user.
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
const char *fzn_err_str(fzn_err_t err);

#endif /* FZN_CHAIN_H */
