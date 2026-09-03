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
/*
 * WHICH TRANSPORT A REQUEST ARRIVED OVER, and the holder's 2026-08-31
 * statement that this library serves three fundamentally different network
 * and auth types rather than one:
 *
 *   1. a user's client to a daemon running as that same user, many to one;
 *   2. a user's client to a ROOT daemon, many to one, authenticated by local
 *      means -- `local/peer.h` and `local/vocabulary.h` are that type;
 *   3. the encrypted decentralised protocol, many to many, authenticated by
 *      a signed capability chain -- the rest of this library.
 *
 * All three existed and NOTHING RELATED THEM. There was no way to say what a
 * request may do as a function of which one carried it, so both consumers
 * computed it in their own trees: netcfgd decided that "origin is which
 * socket you arrived on, and nothing a client says" (its decision 0128, read
 * at f7a7fdf), and fuzzypickles that a realm "is a verb, not a column",
 * recomputed per arrival. Two consumers independently building the same
 * missing thing is what says it belongs here.
 *
 * IT IS OBSERVED, NEVER CLAIMED, AND THAT IS STRUCTURAL. This type has no
 * wire encoding: it is absent from `wire/frame.situ`, so no frame can carry
 * one and no parser can produce one. A caller supplies it from what it
 * observed -- which socket accepted the connection, what `SO_PEERCRED` said,
 * that the bytes came off the network path -- and a peer has no field to
 * forge because there is no field. netcfgd reached that sentence first; what
 * changes by moving it here is that it stops being each consumer's discipline
 * and becomes a property of the type.
 *
 * ZERO IS "NOT STATED" AND ALWAYS DENIES, for the reason the verdict above
 * gives at length: a zeroed struct and a forgotten assignment must land on
 * no. A caller that did not observe an origin has not earned one.
 */
typedef enum fzn_origin {
	FZN_ORIGIN_NONE = 0,
	/*
	 * Type 1: a daemon running as the same user as its clients.
	 *
	 * IT IS NOT "NO AUTH", AND THE HOLDER SAID SO IN THOSE WORDS
	 * (2026-08-31): the local socket's access IS the authentication. The
	 * kernel enforced it, from the socket's path and mode, before a byte
	 * was parsed -- there is nothing further to check because the check
	 * already happened, not because none was required.
	 *
	 * The distinction is not pedantry. "No auth" invites somebody to move
	 * that socket somewhere world-writable, or to widen its mode for a
	 * convenience, and nothing then fails: every request still arrives,
	 * still names this origin, and is still admitted -- because the thing
	 * that was doing the work was the mode, and it was removed by a person
	 * who had been told there was no authentication to remove.
	 *
	 * So a consumer naming this origin is ASSERTING that the socket is so
	 * bounded. This library cannot check that for them, which is exactly
	 * why it is written down here rather than assumed.
	 */
	FZN_ORIGIN_SAME_USER = 1,
	/* Type 2. A local socket whose peer credentials were read -- see
	 * `local/peer.h`, whose tri-state exists because an unreadable group
	 * list must not read as "in no groups". */
	FZN_ORIGIN_LOCAL = 2,
	/* Type 3. Off the machine, authenticated by a chain rather than by
	 * the kernel. */
	FZN_ORIGIN_REMOTE = 3,
} fzn_origin_t;

/* The bit a mask sets for an origin. Bit 0 is FZN_ORIGIN_NONE's and is
 * meaningless: `fzn_authz_decide` refuses FZN_ORIGIN_NONE before consulting
 * the mask, so a caller cannot admit "not stated" even by setting every bit. */
#define FZN_ORIGIN_BIT(origin) (1u << (unsigned)(origin))

/* Reachable from anywhere a caller might observe. Spelled out rather than
 * written as ~0u so that adding an origin later does not silently widen every
 * policy that used it -- a new transport should have to be admitted by name. */
#define FZN_ORIGIN_ANY                                                    \
	(FZN_ORIGIN_BIT(FZN_ORIGIN_SAME_USER) | FZN_ORIGIN_BIT(FZN_ORIGIN_LOCAL) \
	 | FZN_ORIGIN_BIT(FZN_ORIGIN_REMOTE))

typedef struct fzn_authz_policy {
	int spelled;
	int guarded;
	/* Which origins may reach this kind AT ALL, before any question of
	 * capability. Zero reaches nothing, which is what a zeroed policy
	 * must mean -- so a forgotten policy now denies on two independent
	 * counts rather than one. */
	unsigned origins;
	fzn_cap_id_t capability;
} fzn_authz_policy_t;

/* This kind requires `capability`. */
/*
 * THE ARITY CHANGED RATHER THAN THE STRUCT GAINING A FIELD QUIETLY, and that
 * is deliberate. `origins` could have been added to the struct alone, and
 * every existing call site would have kept compiling while getting whatever
 * the default was -- either a policy reachable from nowhere, which fails
 * loudly but at run time, or one reachable from everywhere, which never fails
 * at all and silently retires the check. `wire/seal.h` records the identical
 * hazard for its commitment key and answers it the same way: an added
 * argument makes every call site fail to compile, which is the loud failure
 * and the only one C offers.
 */
static inline fzn_authz_policy_t fzn_authz_requires(const fzn_cap_id_t *capability,
                                                    unsigned origins)
{
	fzn_authz_policy_t policy;
	size_t i;

	policy.spelled = 1;
	policy.guarded = 1;
	policy.origins = origins;
	for (i = 0; i < FZN_CAP_ID_LEN; i++)
		policy.capability.b[i] = capability ? capability->b[i] : 0u;
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
static inline fzn_authz_policy_t fzn_authz_unguarded(unsigned origins)
{
	fzn_authz_policy_t policy;
	size_t i;

	policy.spelled = 1;
	policy.guarded = 0;
	policy.origins = origins;
	for (i = 0; i < FZN_CAP_ID_LEN; i++)
		policy.capability.b[i] = 0u;
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
/*
 * Whether `origin` may reach `policy` at all, capability aside.
 *
 * A SEPARATE PREDICATE RATHER THAN A SECOND DENIAL CODE. The verdict enum's
 * contract is that zero denies and every other value grants, and a consumer
 * reading it as a truth value is reading it correctly -- adding
 * DENIED_BY_ORIGIN as a nonzero enumerator would turn a refusal into a grant
 * at every such site. That is precisely the polarity defect the verdict's own
 * comment records fuzzypickles tracing. So the enforcement stays inside
 * `fzn_authz_decide`, which denies, and this exists so a consumer's LOG can
 * say which of the two reasons it was -- the same argument that keeps
 * GRANTED_UNGUARDED distinct from GRANTED_BY_CHAIN.
 *
 * It is an explanation, never a substitute: deciding with this and then
 * calling `fzn_authz_decide` without an origin is not possible, because the
 * origin is one of its arguments.
 */
int fzn_authz_origin_permitted(fzn_authz_policy_t policy, fzn_origin_t origin);

/* `manifest` is what this host has been told about revocations, or NULL if it
 * follows nobody. It is passed straight to `fzn_chain_verify`, whose stage-2
 * gate refuses a chain when this host knows it is missing revocations from
 * one of that chain's grantors -- see FZN_CHAIN_ERR_INCOMPLETE in chain.h.
 *
 * IT IS AN ARGUMENT AND NOT A FIELD ON THE POLICY, on the reasoning `origins`
 * already carries here: a field added to the struct leaves every existing
 * call site compiling while getting whatever the default was, and the default
 * that matters is "no gate". An added argument makes every call site fail to
 * compile, which is the loud failure.
 *
 * A DENIED verdict does not distinguish "revoked" from "I cannot tell", and
 * that is this function's existing contract rather than a new omission: it
 * answers a decision, and both answers are deny. A consumer that needs to
 * tell them apart calls `fzn_chain_verify` directly, which is what the code
 * comment above the call in authz.c already says about error codes. */
fzn_authz_verdict_t fzn_authz_decide(fzn_authz_policy_t policy, fzn_origin_t origin,
                                     const fzn_chain_hop_t *hops,
                                     size_t hop_count, const uint8_t root[FZN_PUBKEY_LEN],
                                     uint64_t now, const fzn_sign_ops_t *sign,
                                     const fzn_revocation_store_t *revocations,
                                     const fzn_manifest_state_t *manifest);

#endif /* FZN_AUTHZ_H */
