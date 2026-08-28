/* See authz.h. */

#include "authz.h"

fzn_authz_verdict_t fzn_authz_decide(fzn_authz_policy_t policy, const fzn_chain_hop_t *hops,
                                     size_t hop_count, const uint8_t root[FZN_PUBKEY_LEN],
                                     uint64_t now, const fzn_sign_ops_t *sign,
                                     const fzn_revocation_store_t *revocations)
{
	fzn_chain_t proven;

	/* AN UNSPELLED POLICY DENIES. This is the line the header is about: a
	 * `memset` policy, a struct nobody filled, a global that was never
	 * initialised -- none of them may read as "this kind needs no
	 * capability". Only `fzn_authz_unguarded` says that, and it says it by
	 * setting `spelled`. */
	if (!policy.spelled)
		return FZN_AUTHZ_DENIED;

	if (!policy.guarded)
		return FZN_AUTHZ_GRANTED_UNGUARDED;

	/* A REQUIRED CAPABILITY WITH NO CHAIN IS A DENIAL, and it is the
	 * ordinary case rather than an exceptional one -- a host that has not
	 * been given this issuer's hops simply has not.
	 *
	 * REDUNDANT WITH `fzn_chain_verify`, MEASURED: deleting this line
	 * fails nothing, because that function already refuses a null `hops`
	 * and a zero `hop_count`. So it is prospective rather than
	 * load-bearing and is labelled as such, which is the fifth line in
	 * this session to need that distinction.
	 *
	 * IT IS A GUARD DUPLICATED BY A LOWER LAYER, which is the same class
	 * as an unobservable wipe and a wider one: the rule derived for wipes
	 * -- a guard over the CALLER's memory is testable, a guard over a
	 * local is not -- generalises to ANY guard the layer beneath already
	 * enforces. The test that would catch its removal is a test of the
	 * layer beneath, and there is one.
	 *
	 * Kept for two reasons that are not "it might matter one day". It
	 * states at the level where the DECISION is made that holding no
	 * chain is an ordinary state rather than an error, which is the
	 * distinction this whole file exists to keep visible. And it makes
	 * this function's answer independent of `fzn_chain_verify` continuing
	 * to refuse an empty chain -- a contract that file states and could
	 * relax without this one noticing. */
	if (!hops || hop_count == 0)
		return FZN_AUTHZ_DENIED;

	/* And everything below is `fzn_chain_verify`'s, which already refuses
	 * a null root and a null signer. Its answer is collapsed to a verdict
	 * here rather than passed through: a caller that needs the taxonomy
	 * calls it directly, and a caller that needs a decision must not be
	 * handed an error code it can treat as truthy. */
	if (fzn_chain_verify(hops, hop_count, root, policy.capability, now, sign, revocations,
	                     &proven) != FZN_CHAIN_OK)
		return FZN_AUTHZ_DENIED;

	return FZN_AUTHZ_GRANTED_BY_CHAIN;
}

/* See authz.h. No `default:`, so -Wswitch names a verdict added and not
 * rendered here. */
const char *fzn_authz_verdict_str(fzn_authz_verdict_t verdict)
{
	switch (verdict) {
	case FZN_AUTHZ_DENIED:
		return "denied";
	case FZN_AUTHZ_GRANTED_BY_CHAIN:
		return "granted by capability chain";
	case FZN_AUTHZ_GRANTED_UNGUARDED:
		return "granted: this kind requires no capability";
	}

	return "unknown";
}
