/* See memo.h. */

#include "memo.h"

#include <string.h>

fzn_chain_err_t fzn_chain_memo_init(fzn_chain_memo_t *memo,
                                    fzn_chain_memo_entry_t *entries,
                                    size_t capacity)
{
	if (!memo)
		return FZN_CHAIN_ERR_MALFORMED;
	if (capacity > 0 && !entries)
		return FZN_CHAIN_ERR_MALFORMED;
	memo->entries = entries;
	memo->capacity = capacity;
	memo->cursor = 0;
	memo->hits = 0;
	memo->misses = 0;
	if (capacity > 0)
		memset(entries, 0, capacity * sizeof(*entries));
	return FZN_CHAIN_OK;
}

static int same_triple(const fzn_chain_memo_entry_t *e,
                       const uint8_t root[FZN_PUBKEY_LEN],
                       const uint8_t grantee[FZN_PUBKEY_LEN],
                       const fzn_cap_id_t *capability)
{
	return memcmp(e->root, root, FZN_PUBKEY_LEN) == 0
	       && memcmp(e->grantee, grantee, FZN_PUBKEY_LEN) == 0
	       && memcmp(e->capability.b, capability->b, FZN_CAP_ID_LEN) == 0;
}

int fzn_chain_memo_allows(fzn_chain_memo_t *memo, const uint8_t root[FZN_PUBKEY_LEN],
                          const uint8_t grantee[FZN_PUBKEY_LEN],
                          const fzn_cap_id_t *capability, uint64_t generation,
                          uint64_t now)
{
	size_t i;

	if (!memo || !root || !grantee || !capability)
		return 0;
	/* A generation of zero is what an unwritten slot carries, so accepting
	 * one as a query would let a caller that forgot to read the store hit
	 * every empty entry. */
	if (generation == 0) {
		memo->misses++;
		return 0;
	}
	for (i = 0; i < memo->capacity; i++) {
		const fzn_chain_memo_entry_t *e = &memo->entries[i];

		if (e->generation == 0 || e->generation != generation)
			continue;
		if (!same_triple(e, root, grantee, capability))
			continue;
		/* THE HALF sec 4.7c DOES NOT NAME. A verdict is a function of
		 * `now` as well as of the revocation store: a chain that has
		 * expired since it was verified must not hit, and no
		 * revocation need land for that to happen. */
		if (e->expires_at != FZN_NO_EXPIRY && now >= e->expires_at)
			continue;
		memo->hits++;
		return 1;
	}
	memo->misses++;
	return 0;
}

fzn_chain_err_t fzn_chain_memo_record(fzn_chain_memo_t *memo,
                                      const fzn_chain_t *verdict,
                                      uint64_t generation)
{
	size_t i, slot;

	if (!memo || !verdict || generation == 0)
		return FZN_CHAIN_ERR_MALFORMED;
	if (memo->capacity == 0)
		return FZN_CHAIN_OK;

	/* Prefer a slot that is empty or already stale -- a stale entry is
	 * dead and costs nothing to lose, where a live one is a verification
	 * somebody may still avoid. */
	slot = memo->capacity;
	for (i = 0; i < memo->capacity; i++) {
		const fzn_chain_memo_entry_t *e = &memo->entries[i];

		if (same_triple(e, verdict->root, verdict->grantee,
		                &verdict->capability)) {
			slot = i;   /* refresh this triple in place */
			break;
		}
		if (slot == memo->capacity
		    && (e->generation == 0 || e->generation != generation))
			slot = i;
	}
	if (slot == memo->capacity) {
		slot = memo->cursor;
		memo->cursor = (memo->cursor + 1u) % memo->capacity;
	}

	memcpy(memo->entries[slot].root, verdict->root, FZN_PUBKEY_LEN);
	memcpy(memo->entries[slot].grantee, verdict->grantee, FZN_PUBKEY_LEN);
	memo->entries[slot].capability = verdict->capability;
	memo->entries[slot].expires_at = verdict->expires_at;
	memo->entries[slot].generation = generation;
	return FZN_CHAIN_OK;
}

size_t fzn_chain_memo_live(const fzn_chain_memo_t *memo, uint64_t generation)
{
	size_t i, n = 0;

	if (!memo || generation == 0)
		return 0;
	for (i = 0; i < memo->capacity; i++) {
		if (memo->entries[i].generation == generation)
			n++;
	}
	return n;
}
