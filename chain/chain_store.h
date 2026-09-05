#ifndef FZN_CHAIN_STORE_H
#define FZN_CHAIN_STORE_H

/*
 * Where a verified chain lives between arriving and being needed.
 *
 * WHY THIS EXISTS. project.md sec 95 measured the gap: every other holdable
 * object in this library has a home -- `fzn_revocation_store_t`,
 * `fzn_state_t`, `fzn_journal_t`, `fzn_link_table_t`, `fzn_reasm_t`,
 * `fzn_spool_t` -- and a chain was the only signed object with nowhere to
 * go. The cost of that is not inconvenience: every consumer invents one,
 * differently, which is the duplication this library exists to remove.
 *
 * WHAT IT IS NOT, and this is the load-bearing half.
 *
 * FINDING A CHAIN HERE IS NOT BEING AUTHORISED BY IT. `fzn_chain_verify`
 * remains the only thing that decides, and `fzn_authz_decide` the only thing
 * that decides whether a chain was required at all. This store hands back
 * hops; it does not vouch for them.
 *
 * That is not fastidiousness. A chain that verified on admission can be
 * REVOKED afterwards -- that is what `chain/revocation.h` is for -- so a
 * store treated as a standing authorisation would answer yesterday's
 * question with today's confidence. The revocation state is consulted at
 * verification and nowhere else, so verification is where authorisation has
 * to happen. `fzn_chain_open` keeps the same distance from `fzn_chain_verify`
 * and for the same reason: it is what leaves the pinned root a required
 * argument of the verification rather than an optional argument of a parser.
 *
 * IT IS NOT AN ADOPTION PATH. Admitting a chain about an issuer says nothing
 * about following that issuer's records: `fzn_journal_anchor` remains the
 * only way a stream becomes followed, and nothing here touches a journal.
 * `record/sync.h` refuses to fetch about an issuer nobody chose because a
 * record's worth is its issuer's; a chain's worth is checked against a root
 * already pinned, so a forged chain is worthless rather than poisonous and
 * the refusal that governs records does not govern these. sec 95 has the
 * asymmetry in full. What must not happen is the two being wired together
 * later by somebody who has not read this paragraph -- `sync.h` already
 * records one instance of a guarded door with a second one open beside it.
 *
 * NOTHING HERE ALLOCATES. The caller supplies the entries, as everywhere
 * else in this library. An entry is large -- FZN_CHAIN_MAX_LEN is 1434
 * bytes, being eight hops of 179 plus a two-byte header -- and that is the
 * price of handing the bytes back rather than distilling them. A revocation
 * entry keeps facts because "is this pair revoked" is answerable from facts;
 * a chain has to be re-presented to a verifier and offered to a peer, so the
 * bytes are the thing.
 *
 * The alternative considered and rejected was an arena with offsets into it.
 * It saves memory on short chains and adds a second capacity, a second
 * failure mode and an invariant between two fields -- which is the shape
 * `fzn_revocation_t`'s own comment says this tree keeps paying for.
 */

#include "authz.h"
#include "chain.h"
#include "revocation.h"

/* One verified chain, and the bytes it was verified from.
 *
 * `chain` carries what verification concluded -- root, grantee, capability,
 * hop count and the soonest real expiry -- and every one of those is read
 * from the hops rather than from anything a caller passed alongside them.
 * That is `fzn_revocation_t`'s discipline: the facts come from the bytes a
 * signature covered. */
typedef struct fzn_chain_entry {
	fzn_chain_t chain;
	uint8_t bytes[FZN_CHAIN_MAX_LEN];
	size_t len;
} fzn_chain_entry_t;

typedef struct fzn_chain_store {
	fzn_chain_entry_t *entries;
	size_t capacity;
	size_t used;
} fzn_chain_store_t;

/* Point `store` at caller-owned entries.
 *
 * A zero capacity is refused rather than accepted as an empty store, for the
 * reason `fzn_revocation_store_init` refuses one: a table that can hold
 * nothing records nothing and reports success while doing it. */
fzn_chain_err_t fzn_chain_store_init(fzn_chain_store_t *store, fzn_chain_entry_t *entries,
                                     size_t capacity);

/*
 * Verify these hops and keep them if they hold.
 *
 * VERIFIED BEFORE STORED, so the store cannot be filled with junk by anyone
 * who can send bytes. The whole argument for fetching chains from strangers
 * is that a forged one is worthless, and it is only worthless if it is
 * checked at the door -- a store that kept unverified hops would have moved
 * the cost rather than removed it, and would have handed a consumer
 * something that looks like a chain and is not.
 *
 * The arguments after `hop_count` are `fzn_chain_verify`'s own, passed
 * through rather than remembered here: the pinned root, the capability the
 * chain must carry, the clock, the signature seam, and the revocation and
 * manifest state. Nothing is defaulted. A caller with no revocation store
 * passes NULL and `fzn_chain_verify` reads that as "no revocations known",
 * which is its documented meaning and not this file's to reinterpret.
 *
 * A chain for a triple already held REPLACES it, and does not refuse. Two
 * chains for the same (root, capability, grantee) are the same grant reached
 * by different delegations; keeping both would make lookup answer "which
 * one", which is a question no caller asked. The newer one wins because a
 * re-delegation is how a grant is extended after the first expires.
 *
 * Returns whatever `fzn_chain_verify` returned when it refused, so a caller
 * learns WHY rather than only that it failed, and FZN_CHAIN_ERR_STORE_FULL
 * when the chain holds and there is no room.
 */
fzn_chain_err_t fzn_chain_store_admit(fzn_chain_store_t *store, const fzn_chain_hop_t *hops,
                                      size_t hop_count, const uint8_t root[FZN_PUBKEY_LEN],
                                      const fzn_cap_id_t *capability, uint64_t now,
                                      const fzn_sign_ops_t *sign,
                                      const fzn_revocation_store_t *revocations,
                                      const fzn_manifest_state_t *manifest);

/*
 * The chain this host holds for (root, capability, subject), or nothing.
 *
 * `out_bytes` receives a pointer INTO the store rather than a copy, which is
 * the house style and is what lets a caller hand it straight to
 * `fzn_chain_open` or to a peer. It is valid until the entry is replaced.
 *
 * AN EXPIRED CHAIN IS NOT RETURNED. `now` is required for that and is not
 * optional: a store that handed back an expired chain would be inviting the
 * caller to spend a verification learning what the store already knew, and a
 * caller that forgot to check would be authorising on a dead grant. This is
 * the one judgement the store makes, and it makes it in the refusing
 * direction.
 *
 * Returns non-zero when a live chain was found. FINDING ONE IS NOT
 * AUTHORISATION -- see the header comment. The caller still verifies, and
 * still asks `fzn_authz_decide` whether a chain was required.
 */
int fzn_chain_store_lookup(const fzn_chain_store_t *store, const uint8_t root[FZN_PUBKEY_LEN],
                           const fzn_cap_id_t *capability,
                           const uint8_t subject[FZN_PUBKEY_LEN], uint64_t now,
                           const uint8_t **out_bytes, size_t *out_len);

/* How many entries are held. Zero for a store that cannot be scanned, which
 * is the same answer `fzn_state_count` gives and for the same reason: a
 * count from a corrupt table is invented rather than measured. */
size_t fzn_chain_store_count(const fzn_chain_store_t *store);

/*
 * ---- asking and answering -----------------------------------------------
 *
 * project.md sec 95 called chain delivery the fourth instance of a shape
 * this library has settled three times -- `record/sync.h`, `chain/manifest.h`
 * and `spool/plan.h` -- and the three rules they share are kept here because
 * a serve path is where a stranger chooses the number:
 *
 *   - A request naming nothing gets nothing. A `want_count` of zero is fine
 *     and answers zero, rather than reading as "send everything".
 *   - A ceiling, because the peer picks `want_count`. More wants than
 *     `holds_cap` are clipped to what fits, and `truncated` says so.
 *   - Zero is refused rather than meaning unlimited. A `holds_cap` of zero
 *     is MALFORMED, not an invitation.
 *
 * THERE IS NO `fzn_chain_plan_want`, AND THAT IS A FINDING RATHER THAN AN
 * OMISSION. `record/sync.h` has both because its two are different
 * computations over the peer's positions: ranges the peer has and this host
 * lacks, against ranges this host has and the peer lacks. Here both
 * directions are ONE predicate -- "do I hold a live chain for this triple" --
 * applied to a list the caller already has. A fetch path calls this against
 * its own needs and reads the zeroes; a serve path calls it against the
 * peer's request and reads the ones. A second entry point would be the same
 * loop with the answer inverted, which is a second thing to keep right for
 * no question it answers.
 */

/* One triple a host is asking about: the chain from `root` that authorises
 * `subject` for `capability`. The same shape as `fzn_manifest_deficit_t` with
 * the names its own question needs. */
typedef struct fzn_chain_want {
	uint8_t root[FZN_PUBKEY_LEN];
	fzn_cap_id_t capability;
	uint8_t subject[FZN_PUBKEY_LEN];
} fzn_chain_want_t;

typedef struct fzn_chain_offer {
	/* Wants this host holds a live chain for, and can therefore serve. */
	size_t held;
	/* Wants actually looked at. Less than `want_count` when the ceiling
	 * clipped the request. */
	size_t examined;
	/* Set when the peer named more than `holds_cap` could answer. The
	 * unexamined tail is NOT reported as "not held", because that is a
	 * different answer and a peer would act on it. */
	int truncated;
} fzn_chain_offer_t;

/*
 * Which of these does this host hold?
 *
 * `holds` receives one byte per want EXAMINED: 1 where a live chain is held,
 * 0 where it is not. Parallel to `wants` rather than a filtered copy, which
 * is `fzn_manifest_plan_offer`'s idiom and for its reason -- a caller that
 * wanted the triples already has them.
 *
 * `holds[i]` MEANS "LOOK THIS ONE UP AND SEND IT", not "here it is", even
 * though unlike the revocation store this one kept the bytes. Returning them
 * would mean returning many variable-length blobs, which needs an arena --
 * and sec 95 rejected an arena for this module on the grounds that it adds a
 * second capacity and an invariant between two fields. `fzn_chain_store_lookup`
 * is the second call, and it is one line.
 *
 * EXPIRY COUNTS AS NOT HELD, which is why `now` is required. Offering a chain
 * that has expired is offering bytes the peer will refuse, and the host
 * already knows it.
 *
 * AN UNSOUND STORE IS REFUSED RATHER THAN ANSWERED. `chain/manifest.h` makes
 * the argument in its own words: a store that cannot be scanned must not
 * promise to serve every triple a peer named. This module's `lookup` answers
 * "nothing held" for the same store, and that is the same polarity seen from
 * the other side -- there the caller learns nothing is available, here the
 * caller would otherwise publish a promise.
 */
fzn_chain_err_t fzn_chain_plan_offer(const fzn_chain_store_t *store,
                                     const fzn_chain_want_t *wants, size_t want_count,
                                     uint8_t *holds, size_t holds_cap, uint64_t now,
                                     fzn_chain_offer_t *plan);

#endif /* FZN_CHAIN_STORE_H */
