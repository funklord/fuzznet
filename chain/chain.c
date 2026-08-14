/* Capability chain verification. See chain.h for the design and project.md
 * sec 4.2 for why this piece is the library's own. */

#include "chain.h"

#include <string.h>

/* Constant time over the length, and over the DATA rather than over a
 * comparison that stops early. The accumulate-then-test shape is the point:
 * a memcmp returns as soon as two bytes differ, which turns "how long did
 * that take" into "how many leading bytes matched", and that is a tag
 * oracle wherever the attacker chooses one side.
 *
 * Written out rather than taken from a library because sec 4.5 vendors
 * exactly one dependency and this is four lines. `volatile` on the
 * accumulator is what stops a compiler noticing the result is a boolean and
 * reintroducing the early exit; -Os is an optimiser like any other. */
int fzn_ct_memeq(const void *a, const void *b, size_t len)
{
	const uint8_t *pa = (const uint8_t *)a;
	const uint8_t *pb = (const uint8_t *)b;
	volatile uint8_t diff = 0;

	for (size_t i = 0; i < len; i++)
		diff |= (uint8_t)(pa[i] ^ pb[i]);

	return diff == 0;
}

/* Whether `hop` grants something this revocation list has withdrawn.
 *
 * Matched on the pair rather than on the key alone. A revocation names a
 * capability AND a grantee because the two consumers' capabilities are
 * independent rather than a ladder (sec 4.2): withdrawing netcfgd's `wifi`
 * from a host must not withdraw its `observe`, and a match on key alone
 * would do exactly that. */
static int hop_is_revoked(const fzn_chain_hop_t *hop, const fzn_revocation_t *revocations,
                          size_t revocation_count)
{
	for (size_t i = 0; i < revocation_count; i++) {
		if (fzn_ct_memeq(revocations[i].capability, hop->capability, FZN_CAP_ID_LEN) &&
		    fzn_ct_memeq(revocations[i].grantee, hop->grantee, FZN_PUBKEY_LEN))
			return 1;
	}
	return 0;
}

fzn_err_t fzn_chain_verify(const fzn_chain_hop_t *hops, size_t hop_count,
                            const uint8_t root[FZN_PUBKEY_LEN],
                            const uint8_t capability[FZN_CAP_ID_LEN], uint64_t now,
                            const fzn_sign_ops_t *sign, const fzn_revocation_t *revocations,
                            size_t revocation_count, fzn_chain_t *out)
{
	uint64_t soonest = FZN_NO_EXPIRY;

	if (!hops || !root || !capability || !sign || !sign->verify || !out)
		return FZN_ERR_MALFORMED;
	if (revocation_count > 0 && !revocations)
		return FZN_ERR_MALFORMED;

	/* Bounded before a single hop is touched, so a hop_count off the wire
	 * cannot spend a verification it was never entitled to ask for. */
	if (hop_count == 0 || hop_count > FZN_CHAIN_MAX_HOPS)
		return FZN_ERR_MALFORMED;

	/* The root is pinned, and this is the only place it is consulted. A
	 * chain that verifies perfectly under somebody else's root gets its
	 * own error, because on a shared network that is an ordinary event
	 * rather than an attack. */
	if (!fzn_ct_memeq(hops[0].grantor, root, FZN_PUBKEY_LEN))
		return FZN_ERR_WRONG_ROOT;

	/* Pass one: everything that costs nothing. Refusing here keeps a
	 * malformed chain from buying `hop_count` signature verifications,
	 * which is the only expensive thing this function does. */
	for (size_t i = 0; i < hop_count; i++) {
		const fzn_chain_hop_t *hop = &hops[i];

		if (!hop->signed_region || hop->signed_region_len == 0)
			return FZN_ERR_MALFORMED;

		/* Single-capability by construction. A hop that changes what is
		 * being granted is not a narrowing of the one before it; it is
		 * two chains spliced at a point where nobody signed the join. */
		if (!fzn_ct_memeq(hop->capability, capability, FZN_CAP_ID_LEN))
			return FZN_ERR_CHAIN_INVALID;

		/* Linkage. hops[0].grantor was pinned above; every later hop is
		 * granted by the one before it received. */
		if (i > 0 &&
		    !fzn_ct_memeq(hop->grantor, hops[i - 1].grantee, FZN_PUBKEY_LEN))
			return FZN_ERR_CHAIN_INVALID;

		if (hop->expires_at != FZN_NO_EXPIRY) {
			/* A hop that expires before it was issued never had a
			 * valid moment. That is a malformed grant rather than an
			 * expired one, and saying so keeps "your clock and mine
			 * disagree" separable from "this was never a grant". */
			if (hop->expires_at <= hop->issued_at)
				return FZN_ERR_CHAIN_INVALID;
			if (hop->expires_at <= now)
				return FZN_ERR_EXPIRED;

			/* Weakest link, and an unlimited hop does not win it. */
			if (soonest == FZN_NO_EXPIRY || hop->expires_at < soonest)
				soonest = hop->expires_at;
		}

		/* Every hop, not only the last. Revoking a host in the middle
		 * has to kill what it went on to grant, or revocation would be
		 * defeated by the victim having delegated onward first -- which
		 * is precisely what a stolen device would do. */
		if (hop_is_revoked(hop, revocations, revocation_count))
			return FZN_ERR_REVOKED;
	}

	/* Pass two: the expensive half, reached only by a chain that is
	 * already structurally sound. */
	for (size_t i = 0; i < hop_count; i++) {
		const fzn_chain_hop_t *hop = &hops[i];

		if (!sign->verify(sign->ctx, hop->grantor, hop->signed_region,
		                  hop->signed_region_len, hop->signature))
			return FZN_ERR_CHAIN_INVALID;
	}

	/* Filled only now, so a caller cannot half-read a rejected chain. */
	memcpy(out->root, root, FZN_PUBKEY_LEN);
	memcpy(out->grantee, hops[hop_count - 1].grantee, FZN_PUBKEY_LEN);
	memcpy(out->capability, capability, FZN_CAP_ID_LEN);
	out->hop_count = hop_count;
	out->expires_at = soonest;

	return FZN_OK;
}
