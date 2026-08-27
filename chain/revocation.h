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
#define FZN_REVOCATION_BODY_LEN 106u
#define FZN_REVOCATION_LEN (FZN_REVOCATION_BODY_LEN + (size_t)FZN_SIG_LEN)

#define FZN_REV_OFF_VERSION 0u
#define FZN_REV_OFF_OBJECT 1u
#define FZN_REV_OFF_CAPABILITY 2u
#define FZN_REV_OFF_GRANTEE 34u
#define FZN_REV_OFF_ISSUER 66u
#define FZN_REV_OFF_ISSUED_AT 98u
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
fzn_chain_err_t fzn_revocation_encode(uint8_t *out, const uint8_t issuer[FZN_PUBKEY_LEN],
                                      const uint8_t capability[FZN_CAP_ID_LEN],
                                      const uint8_t grantee[FZN_PUBKEY_LEN],
                                      uint64_t issued_at);

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
                                     const uint8_t capability[FZN_CAP_ID_LEN],
                                     const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t issued_at,
                                     const fzn_sign_ops_t *sign, uint8_t *out);

/* The accessors, over an OPENED record -- see chain.h's equivalent note. */
static inline const uint8_t *fzn_revocation_capability(fzn_revocation_record_t rec)
{
	return rec.base + FZN_REV_OFF_CAPABILITY;
}

static inline const uint8_t *fzn_revocation_grantee(fzn_revocation_record_t rec)
{
	return rec.base + FZN_REV_OFF_GRANTEE;
}

/* Who issued it. Checked against the pinned root: only the root revokes,
 * today.
 *
 * A grantor revoking what it granted is NOT BUILT, and as of 2026-08-27 it
 * is PLANNED rather than an open question. This comment used to say the
 * extension was declined because "project.md does not say" whether letting
 * a compromised intermediate revoke its descendants is wanted or is the
 * attack. project.md says now: the copyright holder settled that grantor-
 * revokes-descendant is coming, on the reasoning that it is a denial of
 * service inside one user's estate rather than an escalation across users.
 * The code is unchanged and still correct; only the reason was stale.
 *
 * WHEN IT ARRIVES, THE ISSUER STOPS BEING THE ROOT, and the check that
 * replaces "issuer == root" is not a wider parameter but a narrower one:
 * the entitled issuers for a hop are the root and that hop's ancestors IN
 * THE CHAIN BEING VERIFIED, which `fzn_chain_verify` already walks with
 * every grantor in hand. It cannot be told the wrong set because it is not
 * told. See project.md sec 13b, which records where that shape came from. */
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

/* Verify a revocation and record it. Returns FZN_CHAIN_OK if it is now in the
 * store, including when it was already there -- admitting the same
 * revocation twice is what happens every time two peers both tell you, and
 * it is not an error.
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
 */
fzn_chain_err_t fzn_revocation_admit(fzn_revocation_store_t *store,
                                fzn_revocation_record_t record,
                                const uint8_t root[FZN_PUBKEY_LEN],
                                const fzn_sign_ops_t *sign);

/* Absorb a batch, which is what "on contact" looks like. Returns the number
 * admitted and reports the first failure through *err, so a caller can tell
 * "your peer sent one bad record" from "my store is full" -- the first is
 * routine on a hostile network and the second is an alarm.
 *
 * Keeps going after a bad record rather than stopping: one forged entry in
 * a batch must not stop a host learning the genuine ones travelling with
 * it, which would make forging a record a way to suppress revocation. */
size_t fzn_revocation_merge(fzn_revocation_store_t *store,
                             const fzn_revocation_record_t *records, size_t count,
                             const uint8_t root[FZN_PUBKEY_LEN], const fzn_sign_ops_t *sign,
                             fzn_chain_err_t *err);

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
 * checked on admission. */
int fzn_revocation_covers(const fzn_revocation_store_t *store,
                           const uint8_t issuer[FZN_PUBKEY_LEN],
                           const uint8_t capability[FZN_CAP_ID_LEN],
                           const uint8_t grantee[FZN_PUBKEY_LEN]);

#endif /* FZN_REVOCATION_H */
