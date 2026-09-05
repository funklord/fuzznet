/* The chain store. See chain_store.h for what it is and, more importantly,
 * for what finding a chain here does not mean. */

#include "chain_store.h"

#include "../constant_time/constant_time.h"

#include <string.h>

/* A store whose count exceeds its array, or whose count is nonzero with no
 * array at all, describes entries that cannot be scanned.
 *
 * The polarity here is NOT `fzn_revocation_covers`'s. That answers an
 * authorization question, so an unreadable store must deny -- any entry it
 * cannot read might be the revocation that refuses. This answers "do I hold
 * a chain", and the conservative answer is that it holds nothing: a caller
 * told yes would go looking for bytes that cannot be read, and a caller told
 * no fetches a chain it may already have, which costs a round trip and
 * nothing else. `chain/manifest.h` makes the same distinction between its
 * own readers and says so out loud. */
static int corrupt(const fzn_chain_store_t *store)
{
	return store->used > store->capacity || (store->used > 0 && !store->entries);
}

/* The index of the entry for this triple, or `used` when there is none.
 *
 * Constant-time comparison on all three, because a caller's timing should
 * not say which chains a host holds -- that is the same argument
 * `fzn_revocation_covers` makes for its own lookup, and the store is
 * consulted on a receive path where the input is somebody else's. */
static size_t find_entry(const fzn_chain_store_t *store, const uint8_t *root,
                         const fzn_cap_id_t *capability, const uint8_t *subject)
{
	size_t at;

	for (at = 0; at < store->used; at++) {
		const fzn_chain_entry_t *e = &store->entries[at];

		if (fzn_ct_memeq(e->chain.root, root, FZN_PUBKEY_LEN)
		    && fzn_ct_memeq(e->chain.capability.b, capability->b, FZN_CAP_ID_LEN)
		    && fzn_ct_memeq(e->chain.grantee, subject, FZN_PUBKEY_LEN))
			return at;
	}
	return store->used;
}

fzn_chain_err_t fzn_chain_store_init(fzn_chain_store_t *store, fzn_chain_entry_t *entries,
                                     size_t capacity)
{
	if (!store || !entries || capacity == 0)
		return FZN_CHAIN_ERR_MALFORMED;

	store->entries = entries;
	store->capacity = capacity;
	store->used = 0;
	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_chain_store_admit(fzn_chain_store_t *store, const fzn_chain_hop_t *hops,
                                      size_t hop_count, const uint8_t root[FZN_PUBKEY_LEN],
                                      const fzn_cap_id_t *capability, uint64_t now,
                                      const fzn_sign_ops_t *sign,
                                      const fzn_revocation_store_t *revocations,
                                      const fzn_manifest_state_t *manifest)
{
	fzn_chain_t verified;
	uint8_t packed[FZN_CHAIN_MAX_LEN];
	size_t packed_len = 0;
	fzn_chain_err_t err;
	size_t at;

	if (!store || !store->entries || !hops || !root || !capability)
		return FZN_CHAIN_ERR_MALFORMED;
	if (corrupt(store))
		return FZN_CHAIN_ERR_MALFORMED;

	/* VERIFIED FIRST, and the result is what the entry is keyed on. The
	 * grantee is read from the chain rather than taken as an argument,
	 * because a caller that supplied it could disagree with the bytes --
	 * and then a lookup would answer for a subject no signature named. */
	err = fzn_chain_verify(hops, hop_count, root, capability, now, sign, revocations,
	                       manifest, &verified);
	if (err != FZN_CHAIN_OK)
		return err;

	/* PACKED BEFORE ANYTHING IS WRITTEN INTO THE STORE, so a container
	 * this host cannot re-encode never displaces one that is already
	 * held. The refusal is somebody else's bytes failing to fit a form we
	 * define, which is a shape error and not a verification one. */
	err = fzn_chain_pack(hops, hop_count, packed, sizeof(packed), &packed_len);
	if (err != FZN_CHAIN_OK)
		return err;

	at = find_entry(store, verified.root, &verified.capability, verified.grantee);
	if (at == store->used) {
		if (store->used >= store->capacity)
			return FZN_CHAIN_ERR_STORE_FULL;
		store->used++;
	}

	store->entries[at].chain = verified;
	memcpy(store->entries[at].bytes, packed, packed_len);
	store->entries[at].len = packed_len;
	return FZN_CHAIN_OK;
}

int fzn_chain_store_lookup(const fzn_chain_store_t *store, const uint8_t root[FZN_PUBKEY_LEN],
                           const fzn_cap_id_t *capability,
                           const uint8_t subject[FZN_PUBKEY_LEN], uint64_t now,
                           const uint8_t **out_bytes, size_t *out_len)
{
	const fzn_chain_entry_t *e;
	size_t at;

	/* The out-parameters are cleared before any decision, so a caller that
	 * ignores the return value reads nothing rather than whatever its
	 * stack held. `fzn_revocation_covers_chain` clears for the same
	 * reason. */
	if (out_bytes)
		*out_bytes = NULL;
	if (out_len)
		*out_len = 0;

	if (!store || !out_bytes || !out_len)
		return 0;
	if (corrupt(store))
		return 0;
	if (!store->entries || !root || !capability || !subject)
		return 0;

	at = find_entry(store, root, capability, subject);
	if (at == store->used)
		return 0;

	e = &store->entries[at];
	/* EXPIRY IS THE ONE JUDGEMENT THIS FILE MAKES, and it refuses. A hop
	 * with no expiry does not constrain the minimum, which is why
	 * FZN_NO_EXPIRY is compared rather than arithmetic being done on it. */
	if (e->chain.expires_at != FZN_NO_EXPIRY && e->chain.expires_at <= now)
		return 0;

	*out_bytes = e->bytes;
	*out_len = e->len;
	return 1;
}

size_t fzn_chain_store_count(const fzn_chain_store_t *store)
{
	if (!store || corrupt(store))
		return 0;
	return store->used;
}

fzn_chain_err_t fzn_chain_plan_offer(const fzn_chain_store_t *store,
                                     const fzn_chain_want_t *wants, size_t want_count,
                                     uint8_t *holds, size_t holds_cap, uint64_t now,
                                     fzn_chain_offer_t *plan)
{
	size_t i;

	/* Nowhere to put an answer. Checked first because everything below
	 * writes, which is `fzn_revocation_covers_chain`'s order. */
	if (!plan)
		return FZN_CHAIN_ERR_MALFORMED;
	plan->held = 0;
	plan->examined = 0;
	plan->truncated = 0;

	/* Zero is refused rather than read as unlimited -- `record/sync.h`'s
	 * rule, inherited rather than re-decided. */
	if (!holds || holds_cap == 0u)
		return FZN_CHAIN_ERR_MALFORMED;
	/* A null list is honest only when it names nothing. */
	if (want_count > 0u && !wants)
		return FZN_CHAIN_ERR_MALFORMED;
	if (!store || corrupt(store))
		return FZN_CHAIN_ERR_MALFORMED;

	plan->examined = want_count < holds_cap ? want_count : holds_cap;
	plan->truncated = want_count > holds_cap;

	for (i = 0; i < plan->examined; i++) {
		const uint8_t *bytes = NULL;
		size_t len = 0;

		/* Asked through `lookup` rather than by reaching into the
		 * array, so the expiry rule and the constant-time compare are
		 * one implementation. A second scan here would be a second
		 * thing to keep in step with it. */
		if (fzn_chain_store_lookup(store, wants[i].root, &wants[i].capability,
		                           wants[i].subject, now, &bytes, &len)) {
			holds[i] = 1u;
			plan->held++;
		} else {
			holds[i] = 0u;
		}
	}

	return FZN_CHAIN_OK;
}
