/* The revocation record and the store. See revocation.h. */

#include "revocation.h"

#include <string.h>

static int same(const fzn_revocation_t *entry, const uint8_t *issuer, const uint8_t *capability,
                const uint8_t *grantee)
{
	return fzn_ct_memeq(entry->issuer, issuer, FZN_PUBKEY_LEN) &&
	       fzn_ct_memeq(entry->capability, capability, FZN_CAP_ID_LEN) &&
	       fzn_ct_memeq(entry->grantee, grantee, FZN_PUBKEY_LEN);
}

fzn_chain_err_t fzn_revocation_open(const uint8_t *bytes, size_t len,
                                    fzn_revocation_record_t *out)
{
	if (!bytes || !out)
		return FZN_CHAIN_ERR_MALFORMED;

	if (len != FZN_REVOCATION_LEN)
		return FZN_CHAIN_ERR_SHAPE;

	if (bytes[FZN_REV_OFF_VERSION] != FZN_SIGNED_VERSION)
		return FZN_CHAIN_ERR_SHAPE;
	/* THE DOMAIN SEPARATION EARNING ITS PLACE. Without this byte -- and
	 * without it being inside the signed range -- one root key signing
	 * both hops and revocations through the same seam is one collision
	 * away from a signature that verifies as either. wire/bytes.h names
	 * the sibling project this already happened to. */
	if (bytes[FZN_REV_OFF_OBJECT] != (uint8_t)FZN_OBJECT_REVOCATION)
		return FZN_CHAIN_ERR_SHAPE;

	out->base = bytes;
	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_revocation_encode(uint8_t *out, const uint8_t issuer[FZN_PUBKEY_LEN],
                                      const uint8_t capability[FZN_CAP_ID_LEN],
                                      const uint8_t grantee[FZN_PUBKEY_LEN],
                                      uint64_t issued_at)
{
	if (!out || !issuer || !capability || !grantee)
		return FZN_CHAIN_ERR_MALFORMED;

	out[FZN_REV_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	out[FZN_REV_OFF_OBJECT] = (uint8_t)FZN_OBJECT_REVOCATION;
	memcpy(out + FZN_REV_OFF_CAPABILITY, capability, FZN_CAP_ID_LEN);
	memcpy(out + FZN_REV_OFF_GRANTEE, grantee, FZN_PUBKEY_LEN);
	memcpy(out + FZN_REV_OFF_ISSUER, issuer, FZN_PUBKEY_LEN);
	fzn_put_be64(out + FZN_REV_OFF_ISSUED_AT, issued_at);
	memset(out + FZN_REV_OFF_SIGNATURE, 0, FZN_SIG_LEN);

	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_revocation_issue(const uint8_t issuer[FZN_PUBKEY_LEN],
                                     const uint8_t capability[FZN_CAP_ID_LEN],
                                     const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t issued_at,
                                     const fzn_sign_ops_t *sign, uint8_t *out)
{
	fzn_chain_err_t err;
	fzn_revocation_record_t rec;
	const uint8_t *msg;
	size_t msg_len;

	if (!issuer || !capability || !grantee || !sign || !sign->sign || !out)
		return FZN_CHAIN_ERR_MALFORMED;

	err = fzn_revocation_encode(out, issuer, capability, grantee, issued_at);
	if (err != FZN_CHAIN_OK)
		return err;

	/* Opened from the bytes just written, so the range handed to the
	 * signer is the one a receiver's verifier will compute. */
	err = fzn_revocation_open(out, FZN_REVOCATION_LEN, &rec);
	if (err != FZN_CHAIN_OK)
		return err;

	fzn_revocation_signed_bytes(rec, &msg, &msg_len);
	if (!sign->sign(sign->ctx, out + FZN_REV_OFF_SIGNATURE, msg, msg_len)) {
		/* No half-made record: a refused signing must not leave
		 * something that opens cleanly behind. */
		memset(out, 0, FZN_REVOCATION_LEN);
		return FZN_CHAIN_ERR_CHAIN_INVALID;
	}

	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_revocation_store_init(fzn_revocation_store_t *store, fzn_revocation_t *entries,
                                     size_t capacity)
{
	if (!store || !entries || capacity == 0)
		return FZN_CHAIN_ERR_MALFORMED;

	store->entries = entries;
	store->capacity = capacity;
	store->used = 0;

	return FZN_CHAIN_OK;
}

int fzn_revocation_covers(const fzn_revocation_store_t *store,
                           const uint8_t issuer[FZN_PUBKEY_LEN],
                           const uint8_t capability[FZN_CAP_ID_LEN],
                           const uint8_t grantee[FZN_PUBKEY_LEN])
{
	if (!store || !store->entries || !issuer || !capability || !grantee)
		return 0;

	/* `used` bounds a loop over `entries`, which holds `capacity`. A store
	 * where it exceeds that is corrupt, and this answers an authorization
	 * question, so the safe reply is the one that denies: report the
	 * capability as revoked rather than scan memory that is not the store.
	 * Saying "not revoked" would be the fail-open answer. */
	if (store->used > store->capacity)
		return 1;

	for (size_t i = 0; i < store->used; i++) {
		if (same(&store->entries[i], issuer, capability, grantee))
			return 1;
	}
	return 0;
}

fzn_chain_err_t fzn_revocation_admit(fzn_revocation_store_t *store,
                                fzn_revocation_record_t record,
                                const uint8_t root[FZN_PUBKEY_LEN],
                                const fzn_sign_ops_t *sign)
{
	const uint8_t *msg;
	size_t msg_len;

	if (!store || !store->entries || !root || !sign || !sign->verify)
		return FZN_CHAIN_ERR_MALFORMED;
	/* A view that was never opened. MALFORMED rather than SHAPE for the
	 * reason chain.h gives: no bytes were wrong, the caller skipped
	 * `fzn_revocation_open`. */
	if (!record.base)
		return FZN_CHAIN_ERR_MALFORMED;

	/* Only the root revokes, today. Checked before the signature, because
	 * a record from the wrong issuer is refused whatever it is signed
	 * with, and verifying first would spend the expensive operation on
	 * something already decided. */
	if (!fzn_ct_memeq(fzn_revocation_issuer(record), root, FZN_PUBKEY_LEN))
		return FZN_CHAIN_ERR_WRONG_ROOT;

	fzn_revocation_signed_bytes(record, &msg, &msg_len);
	if (!sign->verify(sign->ctx, fzn_revocation_issuer(record), msg, msg_len,
	                  fzn_revocation_signature(record)))
		return FZN_CHAIN_ERR_CHAIN_INVALID;

	/* THE STORE'S OWN INTEGRITY, CHECKED HERE AND NOT BORROWED FROM
	 * `fzn_revocation_covers`.
	 *
	 * That function answers "is this revoked?", and for a corrupt store it
	 * answers **yes** on purpose -- denying is the safe reply to an
	 * authorization question. This function asks a different question, and
	 * the same 1 means "we hold it already" here. Reading one answer as the
	 * other made a corrupt store swallow every revocation offered to it and
	 * return FZN_CHAIN_OK: recorded nothing, reported success, and never
	 * reached the STORE_FULL test below.
	 *
	 * That is the failure revocation.h calls the one that fails OPEN -- a
	 * revoked device stays authorised -- with the alarm that exists for it
	 * suppressed. Worse than STORE_FULL rather than a variant of it, because
	 * STORE_FULL is at least visible.
	 *
	 * A conservative answer to one question is a wrong answer to another,
	 * and the two questions have to check separately. */
	if (store->used > store->capacity)
		return FZN_CHAIN_ERR_MALFORMED;

	/* Already known is success, not an error. Two peers both telling you
	 * is what "carried on contact" looks like every time it works, and a
	 * caller that treated the second as a failure would log an alarm on
	 * the system behaving correctly. */
	if (fzn_revocation_covers(store, fzn_revocation_issuer(record),
	                          fzn_revocation_capability(record),
	                          fzn_revocation_grantee(record)))
		return FZN_CHAIN_OK;

	/* Nothing is evicted to make room, and nothing expires. A revocation
	 * that lapses un-revokes a device, and every entry is protecting
	 * against something, so there is no entry it is safe to choose. The
	 * refusal is therefore final and it fails OPEN -- revocation.h says
	 * what that costs and why the caller must treat it as an alarm. */
	/* >= rather than ==. The guard at the top of this function now refuses
	 * `used > capacity` outright, so the two are equivalent for any store
	 * that reaches here -- and `>=` stays because it costs nothing and does
	 * not depend on that guard remaining the first thing this function
	 * does. An append writes at `entries[used]`; an equality test lets a
	 * corrupt `used` through and the write lands outside the array. */
	if (store->used >= store->capacity)
		return FZN_CHAIN_ERR_STORE_FULL;

	/* Copied from the record's own bytes, which are the bytes the
	 * signature above covered. That sentence is the whole of the fix: it
	 * used to copy decoded fields the caller supplied alongside them.
	 *
	 * THE ISSUER OBEYS THE SAME RULE, and it is the one field where the
	 * temptation to break it is real: `root` is right there in the
	 * argument list and equals the issuer today, because the check above
	 * has just insisted on it. Taking it from there would be storing what
	 * a caller supplied beside the bytes rather than what the bytes say --
	 * the exact shape this module was rewritten to remove -- and it stops
	 * being merely wrong-in-principle the moment a grantor may revoke its
	 * own descendants, when the issuer and the root are different keys. */
	memcpy(store->entries[store->used].capability, fzn_revocation_capability(record),
	       FZN_CAP_ID_LEN);
	memcpy(store->entries[store->used].grantee, fzn_revocation_grantee(record),
	       FZN_PUBKEY_LEN);
	memcpy(store->entries[store->used].issuer, fzn_revocation_issuer(record),
	       FZN_PUBKEY_LEN);
	store->used++;

	return FZN_CHAIN_OK;
}

size_t fzn_revocation_merge(fzn_revocation_store_t *store,
                             const fzn_revocation_record_t *records, size_t count,
                             const uint8_t root[FZN_PUBKEY_LEN], const fzn_sign_ops_t *sign,
                             fzn_chain_err_t *err)
{
	size_t admitted = 0;
	fzn_chain_err_t first = FZN_CHAIN_OK;

	if (!store || (count > 0 && !records)) {
		if (err)
			*err = FZN_CHAIN_ERR_MALFORMED;
		return 0;
	}

	for (size_t i = 0; i < count; i++) {
		fzn_chain_err_t one = fzn_revocation_admit(store, records[i], root, sign);

		if (one == FZN_CHAIN_OK) {
			admitted++;
			continue;
		}
		if (first == FZN_CHAIN_OK)
			first = one;

		/* Keep going. One forged record in a batch must not stop a host
		 * learning the genuine ones travelling with it -- otherwise
		 * appending a bad record to a batch is a way to suppress
		 * revocation, which is free and undetectable to the sender. */
	}

	if (err)
		*err = first;

	return admitted;
}
