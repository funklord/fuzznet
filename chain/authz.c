/* See authz.h. */

#include "authz.h"

/*
 * FZN_ORIGIN_ANY IS A LIST, NOT A WILDCARD, and these hold it to that.
 *
 * Written as ~0u it would behave identically today and would silently admit
 * every origin added afterwards -- a fourth transport arriving already
 * permitted by every policy in every consumer, which is the widening nobody
 * decides and nobody sees. Spelling the three out means a new one has to be
 * admitted by name.
 *
 * These exist because no behaviour test can tell a list from a wildcard while
 * there are only three origins: measured, widening ANY to 0xffffffff left the
 * whole suite green. A property no test can hold is one an assertion has to.
 */
_Static_assert((FZN_ORIGIN_ANY & FZN_ORIGIN_BIT(FZN_ORIGIN_NONE)) == 0u,
               "FZN_ORIGIN_ANY admits FZN_ORIGIN_NONE, which means 'not observed'");
_Static_assert(FZN_ORIGIN_ANY
                       == (FZN_ORIGIN_BIT(FZN_ORIGIN_SAME_USER) | FZN_ORIGIN_BIT(FZN_ORIGIN_LOCAL)
                           | FZN_ORIGIN_BIT(FZN_ORIGIN_REMOTE)),
               "FZN_ORIGIN_ANY is not exactly the named origins -- admit a new one here "
               "deliberately rather than by widening a wildcard");

int fzn_authz_origin_permitted(fzn_authz_policy_t policy, fzn_origin_t origin)
{
	/* NOT STATED IS REFUSED BEFORE THE MASK IS CONSULTED, so a caller
	 * cannot admit it even by setting every bit. An origin a caller did
	 * not observe is not an origin, and bit 0 therefore means nothing. */
	if (origin == FZN_ORIGIN_NONE)
		return 0;
	return (policy.origins & FZN_ORIGIN_BIT(origin)) != 0u;
}

fzn_authz_verdict_t fzn_authz_decide(fzn_authz_policy_t policy, fzn_origin_t origin,
                                     const fzn_chain_hop_t *hops,
                                     size_t hop_count, const uint8_t root[FZN_PUBKEY_LEN],
                                     uint64_t now, const fzn_sign_ops_t *sign,
                                     const fzn_revocation_store_t *revocations,
                                     const fzn_manifest_state_t *manifest)
{
	fzn_chain_t proven;

	/* AN UNSPELLED POLICY DENIES. This is the line the header is about: a
	 * `memset` policy, a struct nobody filled, a global that was never
	 * initialised -- none of them may read as "this kind needs no
	 * capability". Only `fzn_authz_unguarded` says that, and it says it by
	 * setting `spelled`. */
	if (!policy.spelled)
		return FZN_AUTHZ_DENIED;

	/*
	 * THE ORIGIN IS CHECKED BEFORE THE CAPABILITY, AND BEFORE `guarded`,
	 * which is the ordering that makes it worth having.
	 *
	 * An unguarded kind is the case that matters: a consumer says "this
	 * needs no capability" meaning it locally, and without this line that
	 * sentence also admits the whole network. netcfgd's local policy is
	 * deliberately open enough that a distribution could put every user in
	 * its group, and the same policy reaching the wire is the failure its
	 * decision 0128 was written to prevent. Checking after `guarded` would
	 * have let exactly that through.
	 *
	 * It also means a policy that is reachable from nowhere denies whatever
	 * else it says, so a zeroed struct now fails on two independent counts.
	 */
	if (!fzn_authz_origin_permitted(policy, origin))
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
	if (fzn_chain_verify(hops, hop_count, root, &policy.capability, now, sign, revocations,
	                     manifest, &proven) != FZN_CHAIN_OK)
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
