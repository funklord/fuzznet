/* Capability chain encoding and verification. See chain.h for the design and
 * project.md sec 4.2 for why this piece is the library's own. */

#include "chain.h"

/* FOR THE STORE'S DEFINITION AND FOR `fzn_revocation_covers`, which is the
 * one implementation of "is this revoked?" this file used to keep a second
 * copy of. chain.h declares the store as an incomplete type, so a consumer
 * with no revocations still needs nothing from here; this file is the
 * library, and the library may know both halves. */
#include "revocation.h"

#include <string.h>

fzn_chain_err_t fzn_hop_open(const uint8_t *bytes, size_t len, fzn_chain_hop_t *out)
{
	if (!bytes || !out)
		return FZN_CHAIN_ERR_MALFORMED;

	/* Exactly, not at least. A hop that is allowed to be followed by
	 * bytes nobody looks at is a hop two implementations can disagree
	 * about the length of, and the length is what a container's arithmetic
	 * rests on. */
	if (len != FZN_HOP_LEN)
		return FZN_CHAIN_ERR_SHAPE;

	/* Both bytes are INSIDE the signed range, which is what makes them
	 * worth checking -- see wire/bytes.h. A tag written outside it
	 * separates nothing, because an attacker rewrites it and the signature
	 * still checks. */
	if (bytes[FZN_HOP_OFF_VERSION] != FZN_SIGNED_VERSION)
		return FZN_CHAIN_ERR_SHAPE;
	if (bytes[FZN_HOP_OFF_OBJECT] != (uint8_t)FZN_OBJECT_HOP)
		return FZN_CHAIN_ERR_SHAPE;

	/* One encoding per value. Reading any nonzero byte as true would give
	 * 255 spellings of a delegable hop, each with its own signature, and
	 * the first implementation to canonicalise differently would produce
	 * grants this one rejects. */
	if (bytes[FZN_HOP_OFF_DELEGABLE] > 1u)
		return FZN_CHAIN_ERR_SHAPE;

	out->base = bytes;
	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_hop_encode(uint8_t *out, const uint8_t grantor[FZN_PUBKEY_LEN],
                               const uint8_t grantee[FZN_PUBKEY_LEN],
                               const uint8_t capability[FZN_CAP_ID_LEN], uint64_t issued_at,
                               uint64_t expires_at, int delegable)
{
	if (!out || !grantor || !grantee || !capability)
		return FZN_CHAIN_ERR_MALFORMED;

	out[FZN_HOP_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	out[FZN_HOP_OFF_OBJECT] = (uint8_t)FZN_OBJECT_HOP;
	memcpy(out + FZN_HOP_OFF_GRANTOR, grantor, FZN_PUBKEY_LEN);
	memcpy(out + FZN_HOP_OFF_GRANTEE, grantee, FZN_PUBKEY_LEN);
	memcpy(out + FZN_HOP_OFF_CAPABILITY, capability, FZN_CAP_ID_LEN);
	fzn_put_be64(out + FZN_HOP_OFF_ISSUED_AT, issued_at);
	fzn_put_be64(out + FZN_HOP_OFF_EXPIRES_AT, expires_at);
	/* Normalised here, so that the encoder cannot produce bytes its own
	 * parser would refuse -- a caller passing 2 for "true" gets the
	 * canonical 1 rather than a hop nobody can open. */
	out[FZN_HOP_OFF_DELEGABLE] = delegable ? 1u : 0u;

	/* The signature is the signer's to fill and is zeroed rather than left
	 * as whatever the caller's buffer held: a hop that failed to be signed
	 * must not carry a stale signature from the last one that was. */
	memset(out + FZN_HOP_OFF_SIGNATURE, 0, FZN_SIG_LEN);

	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_chain_open(const uint8_t *bytes, size_t len,
                               fzn_chain_hop_t out[FZN_CHAIN_MAX_HOPS], size_t *hop_count)
{
	size_t n;

	if (!bytes || !out || !hop_count)
		return FZN_CHAIN_ERR_MALFORMED;

	if (len < FZN_CHAIN_HEADER_LEN)
		return FZN_CHAIN_ERR_SHAPE;
	if (bytes[0] != FZN_SIGNED_VERSION)
		return FZN_CHAIN_ERR_SHAPE;

	n = bytes[1];
	if (n == 0 || n > FZN_CHAIN_MAX_HOPS)
		return FZN_CHAIN_ERR_SHAPE;

	/* Exactly the header plus that many hops. Trailing bytes are refused
	 * rather than ignored: "accept what you understand and skip the rest"
	 * is how one encoding quietly becomes several, and here it would also
	 * let a stranger append padding a receiver has to store. */
	if (len != (size_t)FZN_CHAIN_HEADER_LEN + n * FZN_HOP_LEN)
		return FZN_CHAIN_ERR_SHAPE;

	for (size_t i = 0; i < n; i++) {
		fzn_chain_err_t err =
		        fzn_hop_open(bytes + FZN_CHAIN_HEADER_LEN + i * FZN_HOP_LEN,
		                     FZN_HOP_LEN, &out[i]);

		if (err != FZN_CHAIN_OK)
			return err;
	}

	*hop_count = n;
	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_chain_pack(const fzn_chain_hop_t *hops, size_t hop_count, uint8_t *out,
                               size_t cap, size_t *len)
{
	size_t need;

	if (!hops || !out || !len)
		return FZN_CHAIN_ERR_MALFORMED;
	if (hop_count == 0 || hop_count > FZN_CHAIN_MAX_HOPS)
		return FZN_CHAIN_ERR_MALFORMED;

	need = (size_t)FZN_CHAIN_HEADER_LEN + hop_count * FZN_HOP_LEN;
	if (cap < need)
		return FZN_CHAIN_ERR_MALFORMED;

	for (size_t i = 0; i < hop_count; i++) {
		if (!hops[i].base)
			return FZN_CHAIN_ERR_MALFORMED;
	}

	out[0] = (uint8_t)FZN_SIGNED_VERSION;
	out[1] = (uint8_t)hop_count;
	for (size_t i = 0; i < hop_count; i++)
		memcpy(out + FZN_CHAIN_HEADER_LEN + i * FZN_HOP_LEN, hops[i].base, FZN_HOP_LEN);

	*len = need;
	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_chain_verify(const fzn_chain_hop_t *hops, size_t hop_count,
                            const uint8_t root[FZN_PUBKEY_LEN],
                            const uint8_t capability[FZN_CAP_ID_LEN], uint64_t now,
                            const fzn_sign_ops_t *sign,
                            const fzn_revocation_store_t *revocations, fzn_chain_t *out)
{
	uint64_t soonest = FZN_NO_EXPIRY;

	if (!hops || !root || !capability || !sign || !sign->verify || !out)
		return FZN_CHAIN_ERR_MALFORMED;

	/* NO CHECK ON THE STORE HERE, and its absence is the fix rather than an
	 * omission. This used to refuse `revocation_count > 0 && !revocations`,
	 * which is the only sanity a caller-split array-and-count admits of --
	 * and it could not check the one thing that mattered, because the bound
	 * stayed behind with the store. A store is judged by the function that
	 * owns it, once, below: NULL means no revocations are known, and a store
	 * whose count describes memory it does not have is refused there. */

	/* Bounded before a single hop is touched, so a hop_count off the wire
	 * cannot spend a verification it was never entitled to ask for. */
	if (hop_count == 0 || hop_count > FZN_CHAIN_MAX_HOPS)
		return FZN_CHAIN_ERR_MALFORMED;

	/* A view that was never opened. The accessors below index off `base`
	 * unconditionally -- deliberately, so that reading a field is not
	 * eight bounds tests per hop -- so this is where the pointer is
	 * established, once, before anything dereferences it. It is MALFORMED
	 * rather than SHAPE because bytes are not what is missing: the caller
	 * skipped `fzn_hop_open`. */
	for (size_t i = 0; i < hop_count; i++) {
		if (!hops[i].base)
			return FZN_CHAIN_ERR_MALFORMED;
	}

	/* The root is pinned, and this is the only place it is consulted. A
	 * chain that verifies perfectly under somebody else's root gets its
	 * own error, because on a shared network that is an ordinary event
	 * rather than an attack. */
	if (!fzn_ct_memeq(fzn_hop_grantor(hops[0]), root, FZN_PUBKEY_LEN))
		return FZN_CHAIN_ERR_WRONG_ROOT;

	/* Pass one: everything that costs nothing. Refusing here keeps a
	 * malformed chain from buying `hop_count` signature verifications,
	 * which is the only expensive thing this function does.
	 *
	 * Every read below goes through an accessor over the signed bytes, so
	 * a hop that survives pass two was judged on the bytes pass two
	 * authenticated. That is the whole of the 2026-08-27 fix; the checks
	 * themselves are unchanged. */
	for (size_t i = 0; i < hop_count; i++) {
		fzn_chain_hop_t hop = hops[i];
		uint64_t expires_at = fzn_hop_expires_at(hop);

		/* Single-capability by construction. A hop that changes what is
		 * being granted is not a narrowing of the one before it; it is
		 * two chains spliced at a point where nobody signed the join. */
		if (!fzn_ct_memeq(fzn_hop_capability(hop), capability, FZN_CAP_ID_LEN))
			return FZN_CHAIN_ERR_CHAIN_INVALID;

		/* Linkage. hops[0]'s grantor was pinned above; every later hop
		 * is granted by the one before it received, AND by a hop that
		 * said it could be passed on. Checking only the first half is
		 * what fuzzypickles' grant path did before it was fixed, and
		 * the consequence there was that holding a capability was the
		 * same as being allowed to hand it out. */
		if (i > 0) {
			if (!fzn_ct_memeq(fzn_hop_grantor(hop), fzn_hop_grantee(hops[i - 1]),
			                  FZN_PUBKEY_LEN))
				return FZN_CHAIN_ERR_CHAIN_INVALID;
			if (!fzn_hop_delegable(hops[i - 1]))
				return FZN_CHAIN_ERR_CHAIN_INVALID;
		}

		if (expires_at != FZN_NO_EXPIRY) {
			/* A hop that expires before it was issued never had a
			 * valid moment. That is a malformed grant rather than an
			 * expired one, and saying so keeps "your clock and mine
			 * disagree" separable from "this was never a grant".
			 *
			 * It stays HERE rather than moving into fzn_hop_open,
			 * even though the bytes alone could answer it: it is a
			 * statement about the grant, not about the shape, and
			 * the taxonomy is what a caller reads. */
			if (expires_at <= fzn_hop_issued_at(hop))
				return FZN_CHAIN_ERR_CHAIN_INVALID;
			if (expires_at <= now)
				return FZN_CHAIN_ERR_EXPIRED;

			/* Weakest link, and an unlimited hop does not win it. */
			if (soonest == FZN_NO_EXPIRY || expires_at < soonest)
				soonest = expires_at;
		}

		/* Every hop, not only the last. Revoking a host in the middle
		 * has to kill what it went on to grant, or revocation would be
		 * defeated by the victim having delegated onward first -- which
		 * is precisely what a stolen device would do.
		 *
		 * Asked on the TRIPLE rather than on the key alone. The two
		 * consumers' capabilities are independent rather than a ladder
		 * (sec 4.2): withdrawing netcfgd's `wifi` from a host must not
		 * withdraw its `observe`, and a match on key alone would do
		 * exactly that.
		 *
		 * THE ISSUER ASKED ABOUT IS THE PINNED ROOT, BECAUSE ROOT-ONLY
		 * REVOCATION IS WHAT IS IMPLEMENTED TODAY -- and that is the
		 * whole of the reason. This comment used to give a second one
		 * and it was FALSE: it said `fzn_revocation_admit` "refuses any
		 * record whose issuer is not the root it was handed, so an entry
		 * issued by anybody else cannot reach a store, and asking about
		 * the root is asking about every entry there can be". A store is
		 * not bound to a root. `root` is a per-call argument to
		 * `admit`, so two roots' revocations go into one store as
		 * readily as one root's -- admit(rec_A, root_A) and
		 * admit(rec_B, root_B) both return OK, `used` reaches 2, and
		 * `covers` answers 1 under either issuer. The same commit that
		 * wrote the false sentence wrote the true one: chain.h at
		 * `fzn_revocation_t` says "a store will hold entries from MANY
		 * issuers", which is why an entry keeps its issuer at all. The
		 * two contradicted each other from the day they landed, and
		 * this file carried both.
		 *
		 * So the line is right and its old justification was an
		 * invariant nothing enforces. What is true is narrower and
		 * weaker: the root is the only issuer whose entries this
		 * library will HONOUR, because nothing else is implemented yet.
		 * A store may hold an entry from any issuer a caller has fed it,
		 * and every such entry is ignored here.
		 *
		 * THAT MATTERS BECAUSE OF WHAT THE FALSE VERSION INVITED. Read
		 * as written, it says the issuer term is redundant -- that a
		 * store can only ever contain root entries, so comparing against
		 * the root cannot exclude anything. A later reader trusting it
		 * would drop the term as dead weight, and a store holding two
		 * roots' entries would then answer for both realms: exactly the
		 * defect the 2026-08-27 issuer fix was made to close, reopened
		 * on the authority of a comment.
		 *
		 * Grantor-revokes-descendant is PLANNED and is not built --
		 * project.md sec 13b and 13c, answered by the holder
		 * 2026-08-27 -- and this is the line that changes when it
		 * arrives: a hop would then be revoked by the root OR by any
		 * grantor above it in the chain, which is a walk over this
		 * function's own hops rather than one comparison. The set of
		 * entitled issuers widens; the fact that this function decides
		 * it, rather than the store, does not. */
		if (fzn_revocation_covers(revocations, root, fzn_hop_capability(hop),
		                          fzn_hop_grantee(hop)))
			return FZN_CHAIN_ERR_REVOKED;
	}

	/* Pass two: the expensive half, reached only by a chain that is
	 * already structurally sound. */
	for (size_t i = 0; i < hop_count; i++) {
		const uint8_t *msg;
		size_t msg_len;

		fzn_hop_signed_bytes(hops[i], &msg, &msg_len);
		if (!sign->verify(sign->ctx, fzn_hop_grantor(hops[i]), msg, msg_len,
		                  fzn_hop_signature(hops[i])))
			return FZN_CHAIN_ERR_CHAIN_INVALID;
	}

	/* Filled only now, so a caller cannot half-read a rejected chain. */
	memcpy(out->root, root, FZN_PUBKEY_LEN);
	memcpy(out->grantee, fzn_hop_grantee(hops[hop_count - 1]), FZN_PUBKEY_LEN);
	memcpy(out->capability, capability, FZN_CAP_ID_LEN);
	out->hop_count = hop_count;
	out->expires_at = soonest;

	return FZN_CHAIN_OK;
}

/* Encode and sign one hop. Shared by mint and delegate, which differ only in
 * who the grantor is and in what had to be true before they were allowed to
 * ask -- the hop they produce is the same shape and is signed the same way.
 *
 * IT ENCODES RATHER THAN BEING HANDED A REGION, which is the half of the
 * 2026-08-27 change that makes the other half usable. Signing bytes the
 * caller supplied, beside fields the caller supplied separately, is what let
 * the two disagree. */
static fzn_chain_err_t hop_sign(const uint8_t grantor[FZN_PUBKEY_LEN],
                          const uint8_t grantee[FZN_PUBKEY_LEN],
                          const uint8_t capability[FZN_CAP_ID_LEN], uint64_t issued_at,
                          uint64_t expires_at, int delegable, const fzn_sign_ops_t *sign,
                          uint8_t *out)
{
	fzn_chain_err_t err;
	fzn_chain_hop_t hop;
	const uint8_t *msg;
	size_t msg_len;

	if (!grantor || !grantee || !capability || !sign || !sign->sign || !out)
		return FZN_CHAIN_ERR_MALFORMED;

	/* A grant that expires before it was issued never had a valid moment,
	 * and fzn_chain_verify refuses one. Refusing to MINT it as well means
	 * the mistake is caught where it is made rather than at the far end of
	 * a network, by whoever cannot fix it. */
	if (expires_at != FZN_NO_EXPIRY && expires_at <= issued_at)
		return FZN_CHAIN_ERR_CHAIN_INVALID;

	err = fzn_hop_encode(out, grantor, grantee, capability, issued_at, expires_at,
	                     delegable);
	if (err != FZN_CHAIN_OK)
		return err;

	/* Opened from the bytes just written rather than assumed, so that the
	 * range handed to the signer is the same one a receiver's verifier
	 * will compute -- if the encoder and the accessors ever disagreed,
	 * this is where it would show, on the minting side, before anything
	 * was published. */
	err = fzn_hop_open(out, FZN_HOP_LEN, &hop);
	if (err != FZN_CHAIN_OK)
		return err;

	fzn_hop_signed_bytes(hop, &msg, &msg_len);
	if (!sign->sign(sign->ctx, out + FZN_HOP_OFF_SIGNATURE, msg, msg_len)) {
		/* A refused signing leaves no half-made hop behind. The encode
		 * above already wrote a body; without this a caller that
		 * ignored the return code would hold something that opens
		 * cleanly and carries a zero signature. */
		memset(out, 0, FZN_HOP_LEN);
		return FZN_CHAIN_ERR_CHAIN_INVALID;
	}

	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_chain_mint(const uint8_t root[FZN_PUBKEY_LEN],
                          const uint8_t grantee[FZN_PUBKEY_LEN],
                          const uint8_t capability[FZN_CAP_ID_LEN], uint64_t issued_at,
                          uint64_t expires_at, int delegable, const fzn_sign_ops_t *sign,
                          uint8_t *out)
{
	/* The root grants directly, so grantor IS the root. Nothing here
	 * establishes that the caller holds the matching secret key -- see
	 * chain.h; the signer either produces something that verifies under
	 * this key or it does not, and a wrong answer surfaces as a chain
	 * nobody accepts rather than as a chain that lies. */
	return hop_sign(root, grantee, capability, issued_at, expires_at, delegable, sign, out);
}

fzn_chain_err_t fzn_chain_delegate(const fzn_chain_hop_t *hops, size_t hop_count,
                              const uint8_t root[FZN_PUBKEY_LEN],
                              const uint8_t capability[FZN_CAP_ID_LEN], uint64_t now,
                              const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t expires_at,
                              int delegable, const fzn_sign_ops_t *sign,
                              const fzn_revocation_store_t *revocations, uint8_t *out)
{
	fzn_chain_t existing;
	fzn_chain_err_t err;

	if (!hops || !grantee || !sign || !sign->verify || !out)
		return FZN_CHAIN_ERR_MALFORMED;

	/* Bounded before anything else: a chain already at the ceiling cannot
	 * be extended into something no verifier would accept. */
	if (hop_count >= FZN_CHAIN_MAX_HOPS)
		return FZN_CHAIN_ERR_MALFORMED;

	/* Defence in depth. Never delegate from a chain that has expired, been
	 * revoked, or stopped checking out -- the new hop would look freshly
	 * minted while resting on something dead. */
	err = fzn_chain_verify(hops, hop_count, root, capability, now, sign, revocations,
	                       &existing);
	if (err != FZN_CHAIN_OK)
		return err;

	/* Holding is not entitlement to hand out. Its own error, because the
	 * chain is valid and the holder does hold it. */
	if (!fzn_hop_delegable(hops[hop_count - 1]))
		return FZN_CHAIN_ERR_NOT_DELEGABLE;

	/* A grantor cannot hand out more time than it has left. Asking for
	 * longer -- or for none at all, which is the easy mistake since
	 * FZN_NO_EXPIRY is zero and looks like "unset" -- yields the chain's
	 * own expiry rather than being refused, so a caller that does not care
	 * about expiry cannot accidentally widen one. */
	if (existing.expires_at != FZN_NO_EXPIRY &&
	    (expires_at == FZN_NO_EXPIRY || expires_at > existing.expires_at))
		expires_at = existing.expires_at;

	return hop_sign(existing.grantee, grantee, capability, now, expires_at, delegable, sign,
	                out);
}

/* See chain.h.
 *
 * NO `default:` LABEL, and that is the mechanism rather than an oversight.
 * `-Wswitch` -- which `-Wall` turns on -- warns about an enumerated switch
 * that omits a case only when there is no default, so leaving it out is what
 * makes the compiler notice a code added to fzn_chain_err_t and not rendered here. A
 * default would silence exactly the warning worth having and turn a new code
 * into a silent "unknown" in somebody's log.
 *
 * It did its job for FZN_CHAIN_ERR_SHAPE: the code was added to the enum and
 * the compiler refused to let the switch stay as it was.
 *
 * The fallback then lives after the switch, where it catches a value that is
 * not an enumerator at all -- which no amount of compiler help can rule out,
 * since the argument may have come from a cast or from the wire. */
const char *fzn_chain_err_str(fzn_chain_err_t err)
{
	switch (err) {
	case FZN_CHAIN_OK:
		return "ok";
	case FZN_CHAIN_ERR_MALFORMED:
		return "malformed argument";
	case FZN_CHAIN_ERR_CHAIN_INVALID:
		return "chain does not check out";
	case FZN_CHAIN_ERR_WRONG_ROOT:
		return "valid chain under a different root";
	case FZN_CHAIN_ERR_EXPIRED:
		return "a hop has expired";
	case FZN_CHAIN_ERR_REVOKED:
		return "a grant has been revoked";
	case FZN_CHAIN_ERR_NOT_DELEGABLE:
		return "last hop is not delegable";
	case FZN_CHAIN_ERR_STORE_FULL:
		return "revocation store is full";
	case FZN_CHAIN_ERR_SHAPE:
		return "not the shape the layout describes";
	}

	return "unknown";
}
