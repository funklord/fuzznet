/* Revocation: the store, and what it takes to put something in it.
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
 * VERIFIED ONCE, ON ADMISSION. The store keeps only what has already been
 * checked, so the query on the hot path is a comparison rather than a
 * signature check, and what it keeps is exactly the array
 * fzn_chain_verify already takes.
 */

#ifndef FZN_REVOCATION_H
#define FZN_REVOCATION_H

#include "chain.h"

/* A revocation as it travels: what is withdrawn, who says so, and the
 * proof. `signed_region` is the encoded record as the schema lays it out,
 * the same layout boundary chain.h draws -- this module verifies bytes it
 * is given and does not encode them. */
typedef struct fzn_revocation_record {
	uint8_t capability[FZN_CAP_ID_LEN];
	uint8_t grantee[FZN_PUBKEY_LEN];
	/* Who issued it. Checked against the pinned root: only the root
	 * revokes, today.
	 *
	 * A grantor revoking what it granted is the obvious extension and is
	 * deliberately NOT built, because it is a real design question rather
	 * than an omission -- it would let a compromised intermediate revoke
	 * its own descendants, which may be wanted or may be the attack, and
	 * project.md does not say. Root-only fails closed and is the smaller
	 * claim. */
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint64_t issued_at;
	uint8_t signature[FZN_SIG_LEN];
	const uint8_t *signed_region;
	size_t signed_region_len;
} fzn_revocation_record_t;

/* A bounded set of verified revocations, over caller-owned storage.
 *
 * `entries` is exactly what fzn_chain_verify takes, so a caller passes
 * `store.entries, store.used` straight into it. That is the reason the
 * signature is checked at admission and not at query: a chain verification
 * walks the whole list, and re-checking a signature per hop per revocation
 * would make revocation cost grow with the square of nothing useful. */
typedef struct fzn_revocation_store {
	fzn_revocation_t *entries;
	size_t capacity;
	size_t used;
} fzn_revocation_store_t;

fzn_chain_err_t fzn_revocation_store_init(fzn_revocation_store_t *store, fzn_revocation_t *entries,
                                     size_t capacity);

/* Verify a revocation and record it. Returns FZN_CHAIN_OK if it is now in the
 * store, including when it was already there -- admitting the same
 * revocation twice is what happens every time two peers both tell you, and
 * it is not an error.
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
                                const fzn_revocation_record_t *record,
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

/* Whether this capability is withdrawn from this key. */
int fzn_revocation_covers(const fzn_revocation_store_t *store,
                           const uint8_t capability[FZN_CAP_ID_LEN],
                           const uint8_t grantee[FZN_PUBKEY_LEN]);

#endif /* FZN_REVOCATION_H */
