#ifndef FZN_AUTHZ_H
#define FZN_AUTHZ_H

/*
 * Was this issuer allowed to say it?
 *
 * `record/record.h` splits authenticity from authorisation on purpose --
 * `fzn_record_verify` answers "is this what its issuer signed" and
 * deliberately not "was the issuer allowed to say it", because a consumer
 * authorising by capability chain and one authorising by local uid both need
 * the first and neither needs the other's answer.
 *
 * This is the second question, and it exists because of the shape of the
 * FIRST one's absence: the library said how a chain is verified and never
 * how a receiver decides it needs one.
 *
 * WHAT GOES WRONG WITHOUT IT, named by fuzzypickles and not by this tree. A
 * consumer that cannot distinguish "I hold no chain for this issuer" from
 * "this kind needs no capability" has THE VACUOUS PASS IN AUTHORIZATION
 * FORM. And nothing forced the question to be asked at all: a consumer that
 * decided a kind was unguarded never reached `fzn_chain_verify`, which is
 * the boundary that fails closed. The vacuum was upstream of every guard
 * this library had.
 *
 * Their words for it, kept because they are better than the paraphrase:
 * because no mechanism existed, the decision was written nowhere, so it
 * would be made implicitly by whoever wrote the first consumer -- the worst
 * available place for it.
 *
 * THE FIX IS THAT A ZEROED POLICY IS NOT "UNGUARDED", IT IS INVALID. There
 * are exactly two ways to spell a policy and both are a call:
 * `fzn_authz_requires` names a capability, `fzn_authz_unguarded` says out
 * loud that this kind needs none. A `memset` leaves neither, and
 * `fzn_authz_decide` denies it. So absence cannot read as not-required,
 * because absence is not a spelling -- which is this library's own "the
 * unsafe version has no spelling", pointed at a gap rather than at a field.
 *
 * WHAT THIS IS NOT. It does not fetch a chain and does not say how one
 * arrives; project.md sec 19 records why -- `record/sync.h` and
 * `fzn_journal_anchor` exist in order to refuse fetching from an issuer
 * nobody chose, which is exactly what chain delivery needs, so delivery is
 * pushed alongside the message or pulled as a scoped answer and is the
 * consumer's either way. This decides, given what a host holds.
 */

#include "chain.h"
#include "revocation.h"

/*
 * A verdict, and ZERO IS DENIAL.
 *
 * Not decoration: a zeroed struct, an uninitialised read, a `calloc` that
 * nobody filled, and a function whose failure path forgets to assign all
 * produce 0. Every one of those must land on "no". The polarity is the whole
 * reason this is an enum rather than an `int` -- fuzzypickles traced a defect
 * this week in which one function of three applied a correct fail-closed
 * discipline while meaning the opposite by 1, and the discipline was
 * faithfully applied in all three.
 */
typedef enum fzn_authz_verdict {
	FZN_AUTHZ_DENIED = 0,
	/* A chain was supplied, verified against the pinned root, and grants
	 * the capability this kind requires. */
	FZN_AUTHZ_GRANTED_BY_CHAIN = 1,
	/* The caller declared this kind needs no capability, in so many
	 * words. Distinct from the above because a consumer's log must be
	 * able to tell "authorised" from "not guarded", and because a policy
	 * that drifts to unguarded is a thing somebody has to be able to
	 * find. */
	FZN_AUTHZ_GRANTED_UNGUARDED = 2,
} fzn_authz_verdict_t;

const char *fzn_authz_verdict_str(fzn_authz_verdict_t verdict);

/*
 * What a kind requires. Built by one of the two constructors below and never
 * assembled field by field -- the same rule, and the same reason, as
 * `fzn_revocation_offer_t`: a struct half-filled by hand leaves the other
 * half holding whatever the stack held.
 *
 * `spelled` is not a redundant flag. It is what makes a zeroed policy
 * distinguishable from a deliberate one, and it is the field the whole
 * design rests on.
 */
typedef struct fzn_authz_policy {
	int spelled;
	int guarded;
	uint8_t capability[FZN_CAP_ID_LEN];
} fzn_authz_policy_t;

/* This kind requires `capability`. */
static inline fzn_authz_policy_t fzn_authz_requires(const uint8_t capability[FZN_CAP_ID_LEN])
{
	fzn_authz_policy_t policy;
	size_t i;

	policy.spelled = 1;
	policy.guarded = 1;
	for (i = 0; i < FZN_CAP_ID_LEN; i++)
		policy.capability[i] = capability ? capability[i] : 0u;
	/* A null capability is a caller that has not decided. It leaves
	 * `spelled` set and `guarded` set with a capability of zeroes, which
	 * `fzn_chain_verify` will refuse to match -- denial rather than a
	 * policy that quietly guards nothing. */
	return policy;
}

/*
 * This kind requires no capability, said out loud.
 *
 * THE ONLY WAY TO GET AN UNGUARDED VERDICT, and it is a call rather than a
 * default precisely so that it appears in a diff, in a grep, and in review.
 * A reader auditing what this consumer leaves unguarded greps for this name
 * and finds every instance; there is no way to arrive at the same place by
 * omission.
 */
static inline fzn_authz_policy_t fzn_authz_unguarded(void)
{
	fzn_authz_policy_t policy;
	size_t i;

	policy.spelled = 1;
	policy.guarded = 0;
	for (i = 0; i < FZN_CAP_ID_LEN; i++)
		policy.capability[i] = 0u;
	return policy;
}

/*
 * Decides.
 *
 * `hops` may be absent -- `hop_count` of zero is "I hold no chain for this
 * issuer", which is an ordinary state rather than an error, and is exactly
 * the case that must not be confusable with "no capability required".
 *
 * DENIES, RATHER THAN RETURNING AN ERROR, for everything that is not a
 * grant: an unspelled policy, a missing chain where one is required, a chain
 * that does not verify, a null root, a null signer. A caller that wants to
 * know WHY asks `fzn_chain_verify` itself; what this returns is the answer
 * to the question a caller actually has, and it has one shape so there is no
 * status to forget to check.
 */
fzn_authz_verdict_t fzn_authz_decide(fzn_authz_policy_t policy, const fzn_chain_hop_t *hops,
                                     size_t hop_count, const uint8_t root[FZN_PUBKEY_LEN],
                                     uint64_t now, const fzn_sign_ops_t *sign,
                                     const fzn_revocation_store_t *revocations);

#endif /* FZN_AUTHZ_H */
