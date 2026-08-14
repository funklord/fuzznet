/* The revocation store. See revocation.h. */

#include "revocation.h"

#include <string.h>

static int same(const fzn_revocation_t *entry, const uint8_t *capability,
                const uint8_t *grantee)
{
	return fzn_ct_memeq(entry->capability, capability, FZN_CAP_ID_LEN) &&
	       fzn_ct_memeq(entry->grantee, grantee, FZN_PUBKEY_LEN);
}

fzn_err_t fzn_revocation_store_init(fzn_revocation_store_t *store, fzn_revocation_t *entries,
                                     size_t capacity)
{
	if (!store || !entries || capacity == 0)
		return FZN_ERR_MALFORMED;

	store->entries = entries;
	store->capacity = capacity;
	store->used = 0;

	return FZN_OK;
}

int fzn_revocation_covers(const fzn_revocation_store_t *store,
                           const uint8_t capability[FZN_CAP_ID_LEN],
                           const uint8_t grantee[FZN_PUBKEY_LEN])
{
	if (!store || !store->entries || !capability || !grantee)
		return 0;

	for (size_t i = 0; i < store->used; i++) {
		if (same(&store->entries[i], capability, grantee))
			return 1;
	}
	return 0;
}

fzn_err_t fzn_revocation_admit(fzn_revocation_store_t *store,
                                const fzn_revocation_record_t *record,
                                const uint8_t root[FZN_PUBKEY_LEN],
                                const fzn_sign_ops_t *sign)
{
	if (!store || !store->entries || !record || !root || !sign || !sign->verify)
		return FZN_ERR_MALFORMED;
	if (!record->signed_region || record->signed_region_len == 0)
		return FZN_ERR_MALFORMED;

	/* Only the root revokes, today. Checked before the signature, because
	 * a record from the wrong issuer is refused whatever it is signed
	 * with, and verifying first would spend the expensive operation on
	 * something already decided. */
	if (!fzn_ct_memeq(record->issuer, root, FZN_PUBKEY_LEN))
		return FZN_ERR_WRONG_ROOT;

	if (!sign->verify(sign->ctx, record->issuer, record->signed_region,
	                  record->signed_region_len, record->signature))
		return FZN_ERR_CHAIN_INVALID;

	/* Already known is success, not an error. Two peers both telling you
	 * is what "carried on contact" looks like every time it works, and a
	 * caller that treated the second as a failure would log an alarm on
	 * the system behaving correctly. */
	if (fzn_revocation_covers(store, record->capability, record->grantee))
		return FZN_OK;

	/* Nothing is evicted to make room, and nothing expires. A revocation
	 * that lapses un-revokes a device, and every entry is protecting
	 * against something, so there is no entry it is safe to choose. The
	 * refusal is therefore final and it fails OPEN -- revocation.h says
	 * what that costs and why the caller must treat it as an alarm. */
	if (store->used == store->capacity)
		return FZN_ERR_STORE_FULL;

	memcpy(store->entries[store->used].capability, record->capability, FZN_CAP_ID_LEN);
	memcpy(store->entries[store->used].grantee, record->grantee, FZN_PUBKEY_LEN);
	store->used++;

	return FZN_OK;
}

size_t fzn_revocation_merge(fzn_revocation_store_t *store,
                             const fzn_revocation_record_t *records, size_t count,
                             const uint8_t root[FZN_PUBKEY_LEN], const fzn_sign_ops_t *sign,
                             fzn_err_t *err)
{
	size_t admitted = 0;
	fzn_err_t first = FZN_OK;

	if (!store || (count > 0 && !records)) {
		if (err)
			*err = FZN_ERR_MALFORMED;
		return 0;
	}

	for (size_t i = 0; i < count; i++) {
		fzn_err_t one = fzn_revocation_admit(store, &records[i], root, sign);

		if (one == FZN_OK) {
			admitted++;
			continue;
		}
		if (first == FZN_OK)
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
