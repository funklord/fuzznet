/* Revocation: the record, the store, and what it takes to put something in
 * it.
 *
 * project.md sec 4.2 is half built without this. It says a capability chain
 * is "verified against a pinned root rather than adopted, WITH REVOCATION
 * CARRIED ON CONTACT", and netcfgd's brief calls that the part it most
 * wants, as a requirement rather than a preference: a stolen device is a
 * capability to revoke, not a password to change. chain.c consults a list of
 * revocations; nothing until now produced one.
 *
 * A REVOCATION IS SIGNED, AND AN EARLIER COMMENT IN chain.h SAID OTHERWISE.
 * That comment argued a revocation needs no signature of its own because it
 * "arrives inside an authenticated datagram and is already attributable",
 * and that making it self-authenticating "would duplicate the envelope's
 * job". It is wrong, and the word that makes it wrong is CONTACT.
 *
 * An authenticated datagram attributes its contents to the peer that sent
 * it, and to nobody further back. Carried on contact means a revocation
 * travels peer to peer -- sec 5 records that relays are the next thing
 * likely to move in, and sec 13 that a frame may be handed over by a relay
 * hours late. So the carrier is not the issuer, and a revocation trusted
 * because of who handed it over is one any carrier can invent. That is not
 * a small hole: inventing revocations is a denial of service against
 * exactly the hosts an attacker wants disconnected, and it needs no key.
 *
 * So a revocation carries its issuer's signature, verified against the same
 * pinned root a chain is, through the same seam. Then it can cross a
 * stranger and still mean something, which is the property "on contact"
 * actually requires.
 *
 * A RECORD IS A VIEW OVER BYTES (2026-08-27), and it had the same defect a
 * hop did, one layer worse. This struct used to carry `capability`,
 * `grantee`, `issuer` and `issued_at` as decoded fields beside an opaque
 * `signed_region` nothing compared them against, and `fzn_revocation_admit`
 * pinned the issuer, verified the signature over the region, and then stored
 * the FIELDS. So one genuine root-signed revocation could be replayed with
 * `grantee` rewritten to any host an attacker cared to name -- a permanent
 * forged revocation, since revocation entries are never evicted and nothing
 * expires them. chain.h's design note carries the reproduction and the
 * reasoning; this file is the same change.
 *
 * VERIFIED ONCE, ON ADMISSION. The store keeps only what has already been
 * checked, so the query on the hot path is a comparison rather than a
 * signature check, and the store itself is what `fzn_chain_verify` is
 * handed.
 */

#ifndef FZN_REVOCATION_H
#define FZN_REVOCATION_H

#include "chain.h"

/* For `fzn_hash_ops_t`: admission must compute a record's identity, and
 * `blob/blob.h` already reaches for the same seam from outside session/. */
#include "../session/commitment.h"

/* THE REVOCATION LAYOUT. Big-endian, fixed width, no padding, fixed fields
 * first -- the same rules as the hop, for the same reason.
 *
 *     offset  size  field
 *          0     1  version    (= FZN_SIGNED_VERSION)
 *          1     1  object     (= FZN_OBJECT_REVOCATION)
 *          2    32  capability
 *         34    32  grantee
 *         66    32  issuer
 *         98     8  issued_at
 *        106    64  signature
 *
 * The signature covers bytes 0 through 105. The object byte is what stops a
 * signature made over a hop being presented as a revocation, and vice versa;
 * wire/bytes.h records what it cost fuzzypickles to learn that two record
 * types of the same length can have ONE SIGNATURE THAT VERIFIES AS BOTH. */
#define FZN_REVOCATION_BODY_LEN 138u
#define FZN_REVOCATION_LEN (FZN_REVOCATION_BODY_LEN + (size_t)FZN_SIG_LEN)

#define FZN_REV_OFF_VERSION 0u
#define FZN_REV_OFF_OBJECT 1u
#define FZN_REV_OFF_CAPABILITY 2u
#define FZN_REV_OFF_GRANTEE 34u
#define FZN_REV_OFF_ISSUER 66u
#define FZN_REV_OFF_ISSUED_AT 98u
/* The record this one answers, by hash, or all-zero for none.
 *
 * ON A REVOCATION it is the PREVIOUS revocation of the same (issuer,
 * capability, grantee), and all-zero for the first. It exists to make a
 * re-revocation a different record: without it, revoking a pair, withdrawing
 * it and revoking it again produces bytes identical to the first revocation
 * -- same fields, same `issued_at` at one-second resolution, and a
 * deterministic signer -- which therefore hashes to the record the
 * withdrawal names, and is refused as the stale copy it is not. The pair
 * would be revocable once, withdrawable once, and never revocable again.
 *
 * ON A WITHDRAWAL it is the revocation being undone, and must not be zero.
 *
 * IT IS AN IDENTITY AND NEVER AN ORDER. `issued_at` above carries a NEVER
 * BECOME AN ORDERING KEY argument, and a per-pair counter here would be that
 * argument again under another name: a clock that cannot be bounded and a
 * counter that cannot be bounded are the same hazard. A hash is compared for
 * equality and never for magnitude, which is what makes it safe. */
#define FZN_REV_OFF_SUPERSEDES 106u
#define FZN_REV_OFF_SIGNATURE FZN_REVOCATION_BODY_LEN

/* A revocation as it travels: what is withdrawn, who says so, and the proof.
 *
 * A VIEW, exactly as `fzn_chain_hop_t` is. `base` addresses
 * FZN_REVOCATION_LEN bytes the caller owns, and every field is read from the
 * bytes the signature covers. */
typedef struct fzn_revocation_record {
	const uint8_t *base;
} fzn_revocation_record_t;

/* Take a view over `len` bytes.
 *
 * Refuses a wrong length, a version byte that is not ours, and an object
 * byte that is not FZN_OBJECT_REVOCATION -- all FZN_CHAIN_ERR_SHAPE. Null
 * arguments are FZN_CHAIN_ERR_MALFORMED, which is the caller's bug rather
 * than a peer's bytes.
 *
 * There is no `delegable` here, so this has one canonicality check fewer
 * than `fzn_hop_open`: every remaining field is a fixed-width opaque value
 * or an integer, and each of those has exactly one encoding already. */
fzn_chain_err_t fzn_revocation_open(const uint8_t *bytes, size_t len,
                                    fzn_revocation_record_t *out);

/* Lay out a revocation, unsigned. `out` receives FZN_REVOCATION_LEN bytes
 * with the signature zeroed. The only encoder for this object, on the same
 * argument `fzn_hop_encode` carries. */
/* `object` is FZN_OBJECT_REVOCATION or FZN_OBJECT_WITHDRAWAL; `supersedes`
 * is the record this one answers, or NULL for none, which writes zeros.
 *
 * BOTH ARE ARGUMENTS RATHER THAN A SECOND FUNCTION OR A DEFAULTED FIELD.
 * chain/authz.h records the reasoning at length for its own `origins`: a
 * field added to a struct leaves every existing call site compiling while
 * getting whatever the default was, and a default here is either "this is a
 * revocation" -- which silently mints the wrong object for a caller meaning
 * to withdraw -- or "supersedes nothing", which silently mints the
 * un-chained re-revocation the field exists to prevent. An added argument
 * makes every call site fail to compile, which is the loud failure. */
fzn_chain_err_t fzn_revocation_encode(uint8_t *out, uint8_t object,
                                      const uint8_t issuer[FZN_PUBKEY_LEN],
                                      const fzn_cap_id_t *capability,
                                      const uint8_t grantee[FZN_PUBKEY_LEN],
                                      uint64_t issued_at,
                                      const uint8_t supersedes[FZN_REVOCATION_ID_LEN]);

/* Encode and sign a revocation: `issuer` withdraws `capability` from
 * `grantee`. `out` receives FZN_REVOCATION_LEN bytes.
 *
 * The counterpart to `fzn_chain_mint`, and it exists for the same reason:
 * without it, the root has no way to produce a revocation and every consumer
 * -- and every test -- writes its own encoder, which is what the whole
 * change of 2026-08-27 was about removing.
 *
 * `issuer` is a PUBLIC key, used to fill the record's issuer field; whether
 * the signer actually holds the matching secret is not a question this can
 * ask, exactly as in `fzn_chain_mint`. */
fzn_chain_err_t fzn_revocation_issue(const uint8_t issuer[FZN_PUBKEY_LEN],
                                     const fzn_cap_id_t *capability,
                                     const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t issued_at,
                                     const fzn_sign_ops_t *sign, uint8_t *out);

/* THE THREE MINTING CALLS, and the split is the whole of how the chaining
 * rule is enforced rather than documented.
 *
 * `fzn_revocation_issue` above mints a FIRST revocation: `supersedes` is
 * zero. `fzn_revocation_reissue` mints one that supersedes a named earlier
 * revocation of the same triple. `fzn_revocation_issue_withdrawal` mints the
 * record that undoes one.
 *
 * A caller cannot get this wrong by omission, because a caller cannot omit
 * anything: re-revoking with `issue` produces a zero `supersedes`, and
 * `fzn_revocation_admit` REFUSES that against a store already holding a
 * withdrawal for the pair. The rule is a refusal at admission and not a
 * sentence in a header -- see the admission notes below.
 *
 * `target` for a withdrawal is the hash of the FZN_REVOCATION_LEN bytes of
 * the record being undone, and must be non-zero. Hashing the whole record
 * rather than its signed range is deliberate: what a peer holds and relays
 * is the whole record, so its identity is the thing that travelled.
 *
 * MINTING A WITHDRAWAL IS STRICT AND INSTALLING ONE IS NOT, and the two
 * rules must stay apart. Here the target may not be zero: a withdrawal
 * naming nothing could never be matched against anything later, so it would
 * pre-authorise the next revocation anybody issues for that pair -- a blank
 * cheque. At `fzn_revocation_admit` the opposite holds: a withdrawal for a
 * triple the store has never held is STORED, because it names ONE record by
 * hash and can only ever refuse that one. Tolerating any arrival order is
 * the whole point of it, and on a mesh a withdrawal overtaking its
 * revocation is ordinary rather than exceptional.
 *
 * Written as two rules because they look like one and somebody will
 * otherwise simplify them into "a withdrawal must name something real",
 * which is true of minting and wrong of installing. */
fzn_chain_err_t fzn_revocation_reissue(const uint8_t issuer[FZN_PUBKEY_LEN],
                                       const fzn_cap_id_t *capability,
                                       const uint8_t grantee[FZN_PUBKEY_LEN],
                                       uint64_t issued_at,
                                       const uint8_t supersedes[FZN_REVOCATION_ID_LEN],
                                       const fzn_sign_ops_t *sign, uint8_t *out);

fzn_chain_err_t fzn_revocation_issue_withdrawal(const uint8_t issuer[FZN_PUBKEY_LEN],
                                                const fzn_cap_id_t *capability,
                                                const uint8_t grantee[FZN_PUBKEY_LEN],
                                                uint64_t issued_at,
                                                const uint8_t target[FZN_REVOCATION_ID_LEN],
                                                const fzn_sign_ops_t *sign, uint8_t *out);

/*
 * ---- A WITHDRAWAL HAS NO DISTRIBUTION PATH IN THIS LIBRARY -------------
 *
 * STATED BECAUSE ITS ABSENCE READS AS AN OVERSIGHT. Everything above works
 * on the host that performs the withdrawal -- the record is minted, admitted
 * and stored, `fzn_revocation_covers` answers no, and a stale copy of the
 * withdrawn revocation is refused. None of that reaches another host by
 * itself, and nothing here tells another host it should ask.
 *
 * Two hosts, and the trace is the whole of it:
 *
 *   A revokes P and B learns it. Both hold P revoked.
 *   A withdraws P. A's entry says withdrawn; B's still says revoked.
 *   A's manifest OMITS P -- `fzn_manifest_issue` skips withdrawn entries,
 *     correctly, since a manifest states what IS revoked and publishing P
 *     would tell every receiver to revoke a pair A has restored, under A's
 *     own signature.
 *   B's manifest NAMES P. A admits it and answers `fzn_revocation_known`,
 *     so A records no deficit, asks for nothing, and says nothing.
 *   B stays revoked. So does every host but A.
 *
 * The deficit machinery is the wrong shape for this and not merely missing a
 * case: it computes what THIS host lacks from a peer's manifest, and a
 * withdrawal is a thing this host HAS that the peer lacks. There is no
 * "here is what you are holding that I have since undone" anywhere in
 * `chain/manifest.h`, and a manifest cannot carry one without becoming a
 * statement about two kinds of thing.
 *
 * WHAT A CONSUMER MUST DO TODAY: hand the withdrawal record to
 * `fzn_revocation_admit` on every host that needs it, by whatever path it
 * already uses to move records. Admission is idempotent, so re-delivery is
 * free and delivering to a host that never held the revocation is refused
 * with FZN_CHAIN_ERR_UNKNOWN_TARGET rather than mis-stored. What a consumer
 * CANNOT do is rely on the manifest exchange to converge it.
 *
 * THE DESIGN QUESTION IS OPEN and is not this header's to settle: whether a
 * manifest gains a second section, whether withdrawals get a manifest of
 * their own, or whether a pair's entry becomes a state rather than a set
 * membership. Each changes what a manifest means, so it is the copyright
 * holder's. Recorded here rather than left for the next reader to derive
 * from an absence -- which is how `record/sync.h`'s append-only
 * precondition came to cost a consumer a day.
 */

/* The accessors, over an OPENED record -- see chain.h's equivalent note. */
/* Typed, like `fzn_manifest_capability`: the cast that makes a wire view
 * carry its type lives in the accessor so that no caller writes one. */
static inline const fzn_cap_id_t *fzn_revocation_capability(fzn_revocation_record_t rec)
{
	return (const fzn_cap_id_t *)(rec.base + FZN_REV_OFF_CAPABILITY);
}

static inline const uint8_t *fzn_revocation_grantee(fzn_revocation_record_t rec)
{
	return rec.base + FZN_REV_OFF_GRANTEE;
}

static inline const uint8_t *fzn_revocation_supersedes(fzn_revocation_record_t rec)
{
	return rec.base + FZN_REV_OFF_SUPERSEDES;
}

/* WHICH OF THE TWO THIS IS, read from the signed tag rather than inferred.
 *
 * A withdrawal and a revocation are the same length and differ in one byte
 * and one field, so nothing about a record's shape distinguishes them. Every
 * reader that acts on a record must ask -- and in particular a store must
 * not treat the PRESENCE of an entry as the answer to "is this revoked",
 * because after a withdrawal the entry is still there and says the
 * opposite. */
static inline int fzn_revocation_is_withdrawal(fzn_revocation_record_t rec)
{
	return rec.base[FZN_REV_OFF_OBJECT] == (uint8_t)FZN_OBJECT_WITHDRAWAL;
}

/* Who issued it. The root, or a grantor withdrawing from its own descendant.
 *
 * IT ARRIVED (2026-08-28), and this comment used to describe it as planned.
 * project.md sec 13b records the copyright holder's answer of 2026-08-27 --
 * grantor-revokes-descendant is coming, on the reasoning that it is a denial
 * of service inside one user's estate rather than an escalation across users
 * -- and sec 13c is the design that was built from it.
 *
 * THE ENTITLED ISSUERS ARE NOT A WIDER PARAMETER BUT A NARROWER ONE. For a
 * hop, they are the root and that hop's ancestors IN THE CHAIN BEING
 * VERIFIED, which `fzn_chain_verify` already walks with every grantor in
 * hand -- see `fzn_revocation_covers_chain` below. It cannot be told the
 * wrong set because it is not told. */
static inline const uint8_t *fzn_revocation_issuer(fzn_revocation_record_t rec)
{
	return rec.base + FZN_REV_OFF_ISSUER;
}

/* When the issuer says it revoked. DISPLAY AND POLICY ONLY, and it MUST
 * NEVER BECOME AN ORDERING KEY.
 *
 * It is inside the signed range, so it cannot be rewritten in flight -- and
 * that is exactly what makes it tempting. NO LIBRARY CODE READS IT: the
 * only callers in the tree are three lines of revocation_test.c, and
 * `fzn_revocation_admit` stores the issuer, capability and grantee and not
 * this. A field that is signed, free to read and load-bearing nowhere is
 * one somebody makes load-bearing.
 *
 * project.md sec 13a rejects that move for `state/` and the reasoning is
 * worse here: nothing bounds a clock, so `issued_at = UINT64_MAX` can never
 * be superseded by anything the issuer publishes afterwards -- which would
 * freeze a REVOCATION out, unrecoverably, which is the one direction this
 * module must never fail in. sec 4.7b measured the same shape live, where
 * 4096 frames at `expires_at = UINT64_MAX` pinned a replay window
 * permanently and needed no key to do it. */
static inline uint64_t fzn_revocation_issued_at(fzn_revocation_record_t rec)
{
	return fzn_get_be64(rec.base + FZN_REV_OFF_ISSUED_AT);
}

static inline const uint8_t *fzn_revocation_signature(fzn_revocation_record_t rec)
{
	return rec.base + FZN_REV_OFF_SIGNATURE;
}

static inline void fzn_revocation_signed_bytes(fzn_revocation_record_t rec, const uint8_t **at,
                                               size_t *len)
{
	*at = rec.base;
	*len = FZN_REVOCATION_BODY_LEN;
}

/* A bounded set of verified revocations, over caller-owned storage.
 *
 * The signature is checked at admission and not at query, which is what
 * makes this a set of decided facts rather than of evidence: a chain
 * verification walks the whole set per hop, and re-checking a signature per
 * hop per revocation would make revocation cost grow with the square of
 * nothing useful.
 *
 * A CALLER PASSES THE STORE, AND THIS COMMENT USED TO SAY OTHERWISE. It said
 * "`entries` is exactly what fzn_chain_verify takes, so a caller passes
 * `store.entries, store.used` straight into it", and that pattern is what
 * every consumer and every suite in the tree followed. `used` is a count of
 * live entries and `capacity` is the length of the array; splitting them at
 * the call boundary handed the verifier the count and kept the bound behind,
 * and it read one entry past the array for any store where the two had
 * diverged -- a heap overflow on the authorization path, reproduced under
 * AddressSanitizer. chain.h carries the report. `fzn_chain_verify` takes a
 * `const fzn_revocation_store_t *` now, and the three fields travel
 * together because they only mean anything together. */
struct fzn_revocation_store {
	fzn_revocation_t *entries;
	size_t capacity;
	size_t used;
};

fzn_chain_err_t fzn_revocation_store_init(fzn_revocation_store_t *store, fzn_revocation_t *entries,
                                     size_t capacity);

/* The manifest state, DECLARED here and DEFINED in manifest.h.
 *
 * Admitting a revocation settles a deficit: what a manifest said this host
 * was missing, it now holds. So `fzn_revocation_admit` needs the NAME of that
 * table -- and nothing more than the name, because the only thing it does
 * with one is hand it to `fzn_manifest_satisfy`.
 *
 * The same arrangement `chain.h` uses for `fzn_revocation_store_t`, and the
 * incomplete type is the point rather than a compromise: a module that cannot
 * see a table's fields cannot grow a second copy of the rule for finding an
 * entry in it, which is what `chain.h` records a heap overflow for. */
typedef struct fzn_manifest_state fzn_manifest_state_t;

/* A REVOCATION AS IT IS OFFERED TO A STORE: the record, plus the standing of
 * whoever signed it.
 *
 * The root needs no standing -- it is the pin, and `hop_count == 0` says so.
 * Anybody else has to show the chain that makes them an ancestor of what
 * they are withdrawing, and `hops` is that chain, OPENED, exactly as
 * `fzn_chain_verify` takes one.
 *
 * WHY A STRUCT RATHER THAN TWO MORE PARAMETERS. `fzn_revocation_merge`
 * absorbs a BATCH, which is what "carried on contact" looks like, and a
 * batch whose members may each carry a different chain cannot be an array of
 * records with one chain beside it. The two halves travel together because
 * they only mean anything together -- the same argument that made
 * `fzn_chain_verify` take a store rather than an array and a count.
 *
 * `hop_count == 0` IS ROOT-ISSUED AND REPRODUCES THE OLD BEHAVIOUR EXACTLY:
 * the issuer is compared against the pinned root and nothing else is
 * consulted, which is every admission this library performed before
 * 2026-08-28. `hops` is then ignored and NULL is the honest spelling. */
typedef struct fzn_revocation_offer {
	fzn_revocation_record_t record;
	const fzn_chain_hop_t *hops;
	size_t hop_count;
} fzn_revocation_offer_t;

/* The two spellings of an offer, so that no caller assembles one field by
 * field and leaves the other holding whatever its stack held. An offer with
 * a stale `hops` and a zero `hop_count` is harmless; the reverse is a read
 * through a pointer nobody set. */
static inline fzn_revocation_offer_t fzn_revocation_offer_root(fzn_revocation_record_t record)
{
	fzn_revocation_offer_t offer;

	offer.record = record;
	offer.hops = NULL;
	offer.hop_count = 0;
	return offer;
}

static inline fzn_revocation_offer_t fzn_revocation_offer_chain(fzn_revocation_record_t record,
                                                                const fzn_chain_hop_t *hops,
                                                                size_t hop_count)
{
	fzn_revocation_offer_t offer;

	offer.record = record;
	offer.hops = hops;
	offer.hop_count = hop_count;
	return offer;
}

/* Verify a revocation and record it. Returns FZN_CHAIN_OK if it is now in the
 * store, including when it was already there -- admitting the same
 * revocation twice is what happens every time two peers both tell you, and
 * it is not an error.
 *
 * WHO MAY SPEND THE STORE, AND IT IS NOT AN AUTHORISATION DECISION.
 * project.md sec 13c is the design and its reframing is what decides the
 * shape: the old root check did two jobs, and only one of them was
 * authorisation. What is honoured is decided by `fzn_revocation_covers_chain`
 * at verification time; the worst a wrongly-admitted entry can do is occupy
 * 96 bytes of a table that never evicts and never expires. So this is an
 * ADMISSION BOUND, it is allowed to be coarse, and it must not try to be
 * verify.
 *
 * The bound: a non-root revocation is admitted exactly when its issuer
 * presents a chain that verifies against the pinned root FOR THE CAPABILITY
 * BEING WITHDRAWN, whose last hop's grantee is that issuer, and whose last
 * hop is `delegable`. Put sharply -- admit a revocation from a key if and
 * only if `fzn_chain_delegate` would let that key GRANT the thing it is
 * withdrawing. Revoking a descendant is the inverse of granting one and
 * takes the same standing.
 *
 * `delegable` IS NOT DECORATION. A key can only be an ancestor if it appears
 * as some hop's grantor, and `fzn_chain_verify` refuses any such hop whose
 * predecessor was not `delegable`. So a non-delegable holder can never be an
 * ancestor, its revocations can never be honoured, and admitting them is
 * pure waste -- which excludes every leaf in an estate, most keys, from
 * spending the store. The depth ceiling is the same argument: a chain
 * already at FZN_CHAIN_MAX_HOPS has no room for the hop that would make its
 * grantee somebody's ancestor, which is exactly why `fzn_chain_delegate`
 * refuses to extend one.
 *
 * THREE INVARIANTS, EACH CHEAP TO BREAK BY ACCIDENT AND INVISIBLE WHEN
 * BROKEN. All three exist to keep this a CRDT -- project.md sec 13b records
 * that a standalone revocation carries no sequence, that revocation is
 * monotone, and that merge is set union, so any number of holders of one
 * replicated key may emit concurrently and every host converges. Order
 * dependence anywhere in admission destroys that.
 *
 *   - ADMISSION IS REVOCATION-BLIND. The issuer's chain is verified with no
 *     revocations at all. Otherwise admitting the root's withdrawal from H1
 *     first would make H1's own earlier revocation inadmissible, and what a
 *     store ends up holding would depend on the order two peers happened to
 *     tell you things.
 *   - ADMISSION IS CLOCK-BLIND. There is no `now` parameter to pass wrongly.
 *     Refusing a revocation because the REVOKER'S OWN grant had lapsed would
 *     silently re-connect a revoked device, which is the one direction this
 *     module must never fail in.
 *   - THE STORE IS NOT A CACHE. "This issuer already has an entry, so skip
 *     the chain check" looks free and makes the outcome order-dependent.
 *     Every non-root admission carries its chain, every time, including one
 *     that turns out to be a duplicate.
 *
 * AND ONE SEMANTIC, SETTLED IN SEC 13C RATHER THAN DECIDED HERE: when the
 * revoking grantor is itself later revoked, ITS REVOCATION STANDS. If it
 * fell, adding an entry to a store would REMOVE a derivable fact, and an
 * attacker could arrange it -- steal a host, delegate onward, get caught,
 * and the root's clean-up revocation of the parent would RESCUE the stolen
 * descendant. A grant's validity is continuously re-evaluated; a revocation
 * is a withdrawal already performed, by a party entitled at the time, and
 * nothing re-evaluates it. Recovery is by re-granting AROUND the revoker --
 * the entry bites only chains in which that grantor appears -- and never by
 * un-revoking.
 *
 * WHAT IS STORED COMES OUT OF THE BYTES THE SIGNATURE COVERED, which is the
 * 2026-08-27 change stated as a property. The previous version verified a
 * region and then stored fields that had never been compared with it, so a
 * genuine root-signed record could be replayed naming any grantee an
 * attacker liked -- permanently, since nothing here evicts or expires.
 *
 * A FULL STORE IS THE DANGEROUS CASE, AND IT IS THE OPPOSITE OF THE REPLAY
 * WINDOW'S. frame/freshness.h refuses when full and that FAILS CLOSED: the
 * worst outcome is a legitimate frame rejected. Here, failing to record a
 * revocation FAILS OPEN -- the host goes on accepting a capability that was
 * withdrawn, which is precisely the stolen device sec 4.2 exists to shut
 * out, and it does so silently unless somebody is watching.
 *
 * Three consequences, and they are the whole reason this comment is long:
 *
 *   - FZN_CHAIN_ERR_STORE_FULL is not a condition to retry or ignore. A consumer
 *     that logs it at debug level has built the failure it was avoiding.
 *   - Revocations are NOT expired or evicted to make room. A revocation
 *     that lapses un-revokes a device; there is no safe eviction policy,
 *     because every entry is protecting against something.
 *   - The store therefore has to be sized for the whole revocation history
 *     a deployment will ever have, not for a working set. That is a real
 *     cost and it is stated here rather than discovered: revocations only
 *     accumulate, so this is the one bound in the library that a long-lived
 *     deployment can grow into. project.md sec 14 carries it as open.
 *
 * `manifest` IS OPTIONAL AND NULL PRESERVES THE OLD BEHAVIOUR EXACTLY. When
 * one is passed, a revocation that lands in the store also drops the matching
 * pair from that state's deficit table -- the host was told it was missing
 * this and now is not. Without it the deficit never drains, so every consumer
 * that follows a manifest wants to pass one; the parameter is optional rather
 * than required because `chain/manifest.h` is stage 1 of project.md sec 13d
 * and a consumer that has not adopted it must not be forced to.
 *
 * DRAINING HAPPENS ON THE ALREADY-HELD PATH TOO. Admitting a revocation a
 * second time returns FZN_CHAIN_OK without storing anything, which is what
 * "carried on contact" looks like every time it works -- and if only the
 * storing path drained, a host that received the revocation before the
 * manifest would keep reporting it as missing for ever, having held it all
 * along. The two orders must converge, because a set is what this is. */
/* `hash` computes a record's IDENTITY -- FZN_REVOCATION_ID_LEN bytes over
 * the whole FZN_REVOCATION_LEN record -- and admission cannot work without
 * it, which is why it is an argument rather than something a caller may
 * leave out. Three questions need it and all three are equality tests on 32
 * bytes: what a withdrawal targets, what a re-revocation supersedes, and
 * which arriving record is the stale copy of one already withdrawn.
 *
 * THE WHOLE RECORD RATHER THAN ITS SIGNED RANGE. What a peer holds and
 * relays is the whole record, so the identity that travels is the whole
 * record's -- and a peer cannot make two records with one identity by
 * varying only the signature, because the signature is deterministic over
 * bytes the rest of the identity already covers.
 *
 * ADMISSION IS WHERE THE CHAINING RULE IS ENFORCED and not in the minting
 * calls, which is the point of the split in `fzn_revocation_reissue`: a
 * caller that re-revokes with `fzn_revocation_issue` mints a zero
 * `supersedes`, and against a store holding a withdrawal for that triple
 * this refuses it with FZN_CHAIN_ERR_UNKNOWN_TARGET. The rule is a refusal
 * a consumer meets rather than a sentence it has to have read. */
fzn_chain_err_t fzn_revocation_admit(fzn_revocation_store_t *store,
                                fzn_revocation_offer_t offer,
                                const uint8_t root[FZN_PUBKEY_LEN],
                                const fzn_sign_ops_t *sign,
                                const fzn_hash_ops_t *hash,
                                fzn_manifest_state_t *manifest);

/* Absorb a batch, which is what "on contact" looks like. Returns the number
 * admitted and reports the first failure through *err, so a caller can tell
 * "your peer sent one bad record" from "my store is full" -- the first is
 * routine on a hostile network and the second is an alarm.
 *
 * Keeps going after a bad record rather than stopping: one forged entry in
 * a batch must not stop a host learning the genuine ones travelling with
 * it, which would make forging a record a way to suppress revocation.
 *
 * `manifest` is passed through to `fzn_revocation_admit` unchanged, and NULL
 * means what it means there. It is here rather than only on the single
 * admission because THIS is the call a batch arrives through: a merge that
 * could not settle a deficit would leave the drain wired to the path
 * consumers use least.
 *
 * IT TAKES OFFERS RATHER THAN RECORDS (2026-08-28), because each member of a
 * batch may be issued by a different key and so may need a different chain.
 * A batch of records with one chain beside it could only ever have carried
 * one issuer's, which is the old root-only world with extra parameters. */
size_t fzn_revocation_merge(fzn_revocation_store_t *store,
                             const fzn_revocation_offer_t *offers, size_t count,
                             const uint8_t root[FZN_PUBKEY_LEN], const fzn_sign_ops_t *sign,
                             const fzn_hash_ops_t *hash,
                             fzn_chain_err_t *err, fzn_manifest_state_t *manifest);

/* Whether `issuer` has withdrawn this capability from this key.
 *
 * IT ASKS WHO, AND IT DID NOT USED TO. This took no issuer and no root at
 * all, while `fzn_revocation_admit` verified a record's issuer and then
 * discarded it, so a store holding root B's revocation answered "revoked"
 * about root A's realm -- and `fzn_chain_verify` takes `root` and the
 * entries array as independent parameters with nothing comparing them.
 * Confirmed by running it: B signs a revocation, it is admitted against B's
 * own root, and the query returned 1 with no root in it. Nothing said a
 * store belonged to one root and the old signature actively invited the
 * mistake by not asking. chain.h records why the issuer is kept per entry
 * rather than the store being bound to a root.
 *
 * THREE ANSWERS, AND THE ORDER THEY ARE DECIDED IN IS PART OF THE CONTRACT:
 *
 *   - A NULL store answers 0. It means "this host knows of no revocations",
 *     which is what `fzn_chain_verify` relies on when a consumer holding no
 *     store passes NULL.
 *   - A CORRUPT store answers 1 -- `used` past `capacity`, or a nonzero
 *     `used` with no array. Entries that cannot be scanned may hold the
 *     answer, and denying is the safe reply to an authorization question.
 *     Decided BEFORE anything else, so nothing gets a "no" out of a store
 *     that cannot be read.
 *   - A missing issuer, capability or grantee answers 0, because the
 *     question has no subject rather than because the answer is permissive.
 *     revocation.c argues that at length and records the alternative.
 *
 * This is a QUERY and not a verification: everything in the store was
 * checked on admission.
 *
 * IT ANSWERS ABOUT ONE GRANTEE, AND A CHAIN IS NOT ONE GRANTEE.
 * `fzn_revocation_covers_chain` below takes the hops and writes a verdict
 * PER HOP, which is the question a caller holding a chain is actually
 * asking. Reaching for this one on a chain's final grantee tests the last
 * hop and misses a revoked intermediate -- and it returns a confident 0
 * while doing it, because the grantee it was asked about really is not
 * revoked.
 *
 * `fzn_chain_verify` uses the per-hop form, so a consumer that verifies
 * through it is already right. This matters for a consumer doing its own
 * walk, which is the case that has no compiler to help it.
 *
 * The pointer used to run only the other way -- the sibling names this
 * function and this one did not name the sibling -- which is the wrong
 * direction for the pair: **the weaker call is the one a reader arrives at
 * first and the one that has to say what it does not cover.** Found by
 * sweeping every public function here whose name is a prefix of another's,
 * after the same shape turned up twice in one day elsewhere. */
/* Whether this store holds ANY record for this triple, revocation or
 * withdrawal. The replication question, as against
 * `fzn_revocation_covers`'s authorization one -- see revocation.c for why
 * they must not be confused and what confusing them costs. */
int fzn_revocation_known(const fzn_revocation_store_t *store,
                          const uint8_t issuer[FZN_PUBKEY_LEN],
                          const fzn_cap_id_t *capability,
                          const uint8_t grantee[FZN_PUBKEY_LEN]);

int fzn_revocation_covers(const fzn_revocation_store_t *store,
                           const uint8_t issuer[FZN_PUBKEY_LEN],
                           const fzn_cap_id_t *capability,
                           const uint8_t grantee[FZN_PUBKEY_LEN]);

/* WHICH HOPS OF THIS CHAIN ARE REVOKED, by an issuer entitled to revoke
 * them. `revoked` receives FZN_CHAIN_MAX_HOPS bytes, one per hop position,
 * 1 where that hop's grant has been withdrawn and 0 where it has not;
 * positions at or past `hop_count` are always 0.
 *
 * THE ENTITLED SET IS DERIVED, NOT ACCEPTED, and that is the whole reason
 * this takes a chain rather than an issuer. The issuers entitled to revoke
 * hop `i` are the root and hop `i`'s ancestors IN THIS CHAIN -- exactly
 * `{fzn_hop_grantor(hops[j]) : j <= i}`, which includes the root because
 * `fzn_chain_verify` has pinned `hops[0]`'s grantor to it. There is no
 * parameter through which a caller could name a wrong set, because there is
 * no parameter: project.md sec 13b calls this derive-don't-accept applied to
 * the thing that actually varies.
 *
 * IT IS WRITTEN HOISTED, and the naive form is the obvious one. Asking, per
 * hop, about every ancestor of that hop is O(hops^2) queries and each query
 * scans the store, which is O(hops^2 * R) for a table project.md sec 14
 * says only grows. Turned inside out it is O(R * hops): each entry names one
 * issuer, so find the SMALLEST `j` whose grantor is that issuer and the
 * entry applies to every hop from `j` onward. One pass over the store, two
 * bounded walks of the chain inside it -- the same cost the single-issuer
 * loop already paid.
 *
 * THE THREE ANSWERS ARE `fzn_revocation_covers`' THREE ANSWERS, decided in
 * the same order and for the same reasons, because it is the same store
 * being read for the same kind of question:
 *
 *   - A NULL store revokes nothing. It means "this host knows of no
 *     revocations", which is what `fzn_chain_verify` relies on when a
 *     consumer holding no store passes NULL.
 *   - A CORRUPT store revokes EVERY hop -- `used` past `capacity`, or a
 *     nonzero `used` with no array. Entries that cannot be scanned may hold
 *     the answer, and denying is the safe reply to an authorization
 *     question. Decided before anything else.
 *   - A missing `hops` or `capability`, a zero `hop_count`, or one past
 *     FZN_CHAIN_MAX_HOPS revokes nothing, because the question has no
 *     subject rather than because the answer is permissive. `revocation.c`
 *     argues that at length for the sibling function.
 *
 * A NULL `revoked` is the one argument with nothing to say: there is
 * nowhere to write an answer, so it writes none. */
void fzn_revocation_covers_chain(const fzn_revocation_store_t *store,
                                  const fzn_chain_hop_t *hops, size_t hop_count,
                                  const fzn_cap_id_t *capability,
                                  uint8_t revoked[FZN_CHAIN_MAX_HOPS]);

#endif /* FZN_REVOCATION_H */
