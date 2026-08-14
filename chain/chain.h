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
 *     suggestions/fuzznet.md asks the same of situ and gives the reason
 *     this library already paid for once: a fuzzypickles scenario failed
 *     under load because the test raced a deadline nobody had written
 *     down, and the fix cost a day.
 */

#ifndef FZN_CHAIN_H
#define FZN_CHAIN_H

#include <stddef.h>
#include <stdint.h>

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
#define FZN_NO_EXPIRY 0u

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
 * key. That is the same property situ/suggestions/fuzznet.md asks situ to
 * preserve for protocol state: a value rather than a process, constructible
 * directly into states normal operation cannot reach.
 *
 * `verify` returns nonzero for a good signature and zero for a bad one. */
typedef struct fzn_sign_ops {
	int (*verify)(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
	              size_t msg_len, const uint8_t sig[FZN_SIG_LEN]);
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
 * Deliberately not a chain and not a signature. sec 4.2 has revocation
 * CARRIED ON CONTACT, so what travels is small and what verifies it is the
 * frame that carried it -- a revocation arriving inside an authenticated
 * datagram is already attributable. Making this self-authenticating would
 * duplicate the envelope's job. */
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
 *      grantor is the previous hop's grantee
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

/* Constant-time equality over `len` bytes. Nonzero when equal.
 *
 * sec 4.4a: "Key-committing AEAD is not optional, and neither is a
 * constant-time tag comparison. The extern codec owns the first; this
 * library owns the second and MUST NOT LEAVE IT TO THE CONSUMER." So it is
 * exported rather than kept static -- a consumer comparing a tag with
 * memcmp is the defect this sentence exists to prevent, and the only way
 * to prevent it is to hand them the right thing under an obvious name. */
int fzn_ct_memeq(const void *a, const void *b, size_t len);

#endif /* FZN_CHAIN_H */
