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

/* A slot whose chain is dead at `now`, or `used` when every one is live.
 *
 * ONLY CONSULTED UNDER PRESSURE, which is what keeps expiry a lookup
 * judgement rather than a deletion. A chain that has expired is still held,
 * still counted, and still refused by `lookup` -- until the store has no
 * room for a live one, at which point a dead entry is the obvious thing to
 * spend and refusing while holding nothing but corpses is not.
 *
 * The first dead slot wins rather than the longest-dead. Both are correct
 * and the choice is only ever between things already useless; scanning for
 * the oldest would be a second pass to pick between them, and the array
 * order is deterministic, so a test can say which one goes.
 *
 * AN UNEXPIRING CHAIN IS NEVER DEAD, which is the same comparison `lookup`
 * makes and for the same reason: FZN_NO_EXPIRY is 0, so arithmetic on it
 * rather than a test against it would make every unexpiring chain the
 * first thing evicted. */
static size_t find_expired(const fzn_chain_store_t *store, uint64_t now)
{
	size_t at;

	for (at = 0; at < store->used; at++) {
		const fzn_chain_t *c = &store->entries[at].chain;

		if (c->expires_at != FZN_NO_EXPIRY && c->expires_at <= now)
			return at;
	}
	return store->used;
}

fzn_chain_err_t fzn_chain_store_init(fzn_chain_store_t *store, fzn_chain_entry_t *entries,
                                     size_t capacity)
{
	if (!store || !entries || capacity == 0)
		return FZN_CHAIN_ERR_MALFORMED;

	/* THE CALLER'S ARRAY IS ZEROED, which project.md sec 39 settled for
	 * this family -- `fzn_state_init`, `fzn_link_table_init`,
	 * `fzn_log_init` and `fzn_journal_init` all do it and each is held by
	 * a sabotage entry. It matters more here than in any of them: those
	 * hold fixed fields or a borrowed pointer, and an entry here carries
	 * a COPIED 1434-byte buffer, so an untouched slot is that much of
	 * whatever the caller's memory held -- and that array is exactly what
	 * `lookup` hands pointers into. */
	memset(entries, 0, capacity * sizeof(*entries));

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
	 * define, which is a shape error and not a verification one.
	 *
	 * THE REFUSAL BELOW IS UNCOVERED ON PURPOSE and provably unreachable
	 * today: `fzn_chain_verify` has already refused a hop count past
	 * FZN_CHAIN_MAX_HOPS, and `packed` is FZN_CHAIN_MAX_LEN, which is the
	 * header plus that many hops -- so the pack cannot fail for want of
	 * room. It stays because it is the boundary between this file's
	 * arithmetic and `chain/chain.c`'s, and the day the two disagree this
	 * returns an error rather than writing a truncated container into the
	 * store. `wire/seal.c` keeps three of these for the same reason and
	 * says so in the same words, so a reader hunting the last branch in
	 * this file finds the argument rather than a gap. */
	err = fzn_chain_pack(hops, hop_count, packed, sizeof(packed), &packed_len);
	if (err != FZN_CHAIN_OK)
		return err;

	at = find_entry(store, verified.root, &verified.capability, verified.grantee);
	if (at == store->used) {
		if (store->used >= store->capacity) {
			/* A DEAD ENTRY IS SPENT BEFORE A LIVE CHAIN IS REFUSED.
			 * Without this a store whose entries have all expired
			 * answers STORE_FULL for ever, because expiry withholds
			 * at lookup and frees nothing -- and `chain/revocation.c`
			 * refuses rather than evicting too, but a revocation
			 * never expires, so no slot there is ever reclaimable
			 * and the precedent does not carry.
			 *
			 * Still a refusal when every entry is live: eviction is
			 * for the useless, and dropping a live grant to make
			 * room for another would make which chain a host holds
			 * depend on arrival order. */
			at = find_expired(store, now);
			if (at == store->used)
				return FZN_CHAIN_ERR_STORE_FULL;
		} else {
			store->used++;
		}
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
	/* A LENGTH THIS FILE DID NOT WRITE. `corrupt()` reaches store-level
	 * shape -- `used`, `capacity`, `entries` -- and nothing it checks
	 * says an entry's `len` is within its own buffer. Unreachable through
	 * this API, because `admit` only ever writes a `packed_len` that
	 * `fzn_chain_pack` bounded; reachable in exactly the state `corrupt()`
	 * exists for, which is a struct restored from a file.
	 *
	 * It is bounded here rather than left to the caller because the
	 * header says this view may go "straight to `fzn_chain_open` or to a
	 * peer": `fzn_chain_open` refuses a length that does not match its
	 * container, and a `write(fd, bytes, len)` does not. The pack refusal
	 * above keeps the same boundary on the way in, and this is it on the
	 * way out. */
	if (e->len > FZN_CHAIN_MAX_LEN)
		return 0;
	/* EXPIRY IS THE JUDGEMENT THIS FILE MAKES ABOUT A CHAIN'S CONTENTS,
	 * and it refuses. A hop
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
