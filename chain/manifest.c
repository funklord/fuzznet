/* The revocation manifest, the deficit table, and what they report. See
 * manifest.h. */

#include "manifest.h"

#include <string.h>

/* Order two 64-byte pairs.
 *
 * PLAIN `memcmp`, AND THE CHOICE IS DELIBERATE. Everything else in this
 * module that compares a key uses `fzn_ct_memeq`, because those comparisons
 * decide an authorization question and constant_time.h exists so that the
 * answer's timing does not leak which byte differed. This one decides whether
 * a peer's bytes are in canonical order, over a manifest that is public by
 * construction -- it is signed, freely readable, and carries nothing a
 * receiver did not already have to be told. There is also no ordering
 * primitive in constant_time.h to reach for, and inventing one for a
 * comparison whose operands are public would be spending effort where there
 * is nothing to protect.
 *
 * It reads the WHOLE 64 bytes. A prefix comparison would report two pairs
 * differing only in their last byte as equal, which `fzn_manifest_open` reads
 * as a duplicate and refuses -- so a truncation here does not fail open, it
 * refuses a legitimate manifest. `chain/test/manifest_test.c` carries the
 * near-miss pair that decides it, per project.md sec 11. */
static int pair_cmp(const uint8_t *a, const uint8_t *b)
{
	/* THE KEY, NOT THE ENTRY, and the distinction arrived with the state
	 * field. Comparing the whole entry would order and deduplicate on the
	 * id and the state as well, so one issuer could publish two entries
	 * for one pair differing only in what it says about it -- two
	 * contradictory opinions that the canonicality check would accept as
	 * two pairs. */
	return memcmp(a, b, FZN_MANIFEST_KEY_LEN);
}

/* The same order over the caller-facing struct, which is NOT the same as
 * comparing 64 bytes from `capability`: that would be reading across a struct
 * boundary on the assumption that no padding sits between two `uint8_t`
 * arrays. True on every compiler here and not a thing to rest an encoder's
 * canonicality on. Capability first, then grantee, which is the concatenation
 * order the wire uses. */
static int pair_struct_cmp(const fzn_manifest_pair_t *a, const fzn_manifest_pair_t *b)
{
	int cmp = memcmp(a->capability.b, b->capability.b, FZN_CAP_ID_LEN);

	if (cmp != 0)
		return cmp;
	return memcmp(a->grantee, b->grantee, FZN_PUBKEY_LEN);
}

/* Is a state one this module may walk?
 *
 * The same question `fzn_revocation_covers` asks of a store, and it is asked
 * separately by every entry point rather than once at the top of one of them:
 * a count past its array describes entries that cannot be scanned, and every
 * function here would otherwise read past the end of one. */
static int state_sound(const fzn_manifest_state_t *state)
{
	if (!state)
		return 0;
	if (state->issuer_used > state->issuer_capacity)
		return 0;
	if (state->deficit_used > state->deficit_capacity)
		return 0;
	if (state->issuer_used > 0 && !state->issuers)
		return 0;
	if (state->deficit_used > 0 && !state->deficit)
		return 0;
	return 1;
}

/* Is a store one whose answers may be believed?
 *
 * `fzn_revocation_covers` answers 1 -- REVOKED -- for a store it cannot scan,
 * because denying is the safe reply to an authorization question. This module
 * asks it a different question, "do we already hold this?", and that same 1
 * means every pair looks satisfied and the deficit comes out empty. So the
 * store's integrity is judged here rather than inherited, which is the
 * distinction `fzn_revocation_admit` had to learn the same way. */
static int store_sound(const fzn_revocation_store_t *store)
{
	if (!store)
		return 1; /* no store means no revocations known, which is an answer */
	if (store->used > store->capacity)
		return 0;
	if (store->used > 0 && !store->entries)
		return 0;
	return 1;
}

/* Where this issuer's entry is, or `issuer_used` for one that is not
 * followed.
 *
 * AN INDEX RATHER THAN A POINTER, so that one function serves both the const
 * and the mutating callers. The two-function version of this -- a pointer
 * finder and a const-pointer finder -- is two copies of one comparison rule,
 * which is the shape `chain.h` records paying for once. */
static size_t find_issuer(const fzn_manifest_state_t *state, const uint8_t *issuer)
{
	size_t i;

	for (i = 0; i < state->issuer_used; i++) {
		if (fzn_ct_memeq(state->issuers[i].issuer, issuer, FZN_PUBKEY_LEN))
			break;
	}
	return i;
}

/* Does the deficit table already name this triple? Every field is compared
 * whole, for the reason `fzn_revocation_covers`'s `same()` is: a prefix match
 * here reports a pair as already recorded and DROPS it, which under-reports
 * the deficit -- the fail-open direction, and the one with no alarm attached
 * to it. */
static int deficit_holds(const fzn_manifest_state_t *state, const uint8_t *issuer,
                         const fzn_cap_id_t *capability, const uint8_t *grantee)
{
	for (size_t i = 0; i < state->deficit_used; i++) {
		const fzn_manifest_deficit_t *d = &state->deficit[i];

		if (fzn_ct_memeq(d->issuer, issuer, FZN_PUBKEY_LEN) &&
		    fzn_ct_memeq(d->capability.b, capability->b, FZN_CAP_ID_LEN) &&
		    fzn_ct_memeq(d->grantee, grantee, FZN_PUBKEY_LEN))
			return 1;
	}
	return 0;
}
/* THE LAYOUT, ASSERTED FIELD BY FIELD.
 *
 * `record/record.c` has done this since it was written and states the reason
 * beside it: the offsets are checked individually rather than only the total,
 * because a total is the one thing that survives two fields swapping widths.
 * The reasoning was right and it was applied to exactly one module.
 *
 * MEASURED BEFORE BEING WRITTEN, which is why these are here rather than as
 * tidiness: this module had no compile-time layout check of any kind,
 * and both its neighbours' swaps survived. A manifest has no same-width pair
 * to exchange, so no mutation demonstrates it -- which is a reason to state
 * the layout rather than a reason not to.
 *
 * The numbers are literals. A constant checked against itself checks nothing,
 * and the point is that a peer cannot see this file -- project.md sec 45 makes
 * the same argument for the domain labels in their vectors.
 */
_Static_assert(FZN_MANIFEST_OFF_VERSION == 0u, "manifest layout: version moved");
_Static_assert(FZN_MANIFEST_OFF_OBJECT == 1u, "manifest layout: object moved");
_Static_assert(FZN_MANIFEST_OFF_ISSUER == 2u, "manifest layout: issuer moved");
_Static_assert(FZN_MANIFEST_OFF_COUNT == 34u, "manifest layout: count moved");
_Static_assert(FZN_MANIFEST_OFF_PAIRS == 36u, "manifest layout: the pairs moved");
_Static_assert(FZN_MANIFEST_HEADER_LEN == 36u,
               "manifest layout: the header is not 36 bytes");
_Static_assert(FZN_MANIFEST_KEY_LEN == 64u, "manifest layout: a key is not 64 bytes");
_Static_assert(FZN_MANIFEST_PAIR_LEN == 97u, "manifest layout: an entry is not 97 bytes");
_Static_assert(FZN_MANIFEST_OFF_ENTRY_ID == 64u, "manifest layout: the id moved");
_Static_assert(FZN_MANIFEST_OFF_ENTRY_STATE == 96u, "manifest layout: the state moved");
/* THE KEY IS A PREFIX OF THE ENTRY, which is what lets one comparison order
 * both a caller's struct and the wire form without either being told about
 * the other. If the state ever moved in front of the pair this would fail
 * here rather than in a sort nobody watches. */
_Static_assert(FZN_MANIFEST_KEY_LEN < FZN_MANIFEST_PAIR_LEN,
               "manifest layout: the sort key is not inside the entry");


fzn_manifest_err_t fzn_manifest_open(const uint8_t *bytes, size_t len,
                                     fzn_manifest_record_t *out)
{
	size_t count;

	if (!bytes || !out)
		return FZN_MANIFEST_ERR_MALFORMED;

	/* The header and the signature must both be there before the count can
	 * be read at all, which is why this is a floor rather than the exact
	 * test below: the exact test needs a count, and the count is inside
	 * the bytes this is checking for. */
	if (len < FZN_MANIFEST_MIN_LEN)
		return FZN_MANIFEST_ERR_SHAPE;

	if (bytes[FZN_MANIFEST_OFF_VERSION] != FZN_SIGNED_VERSION)
		return FZN_MANIFEST_ERR_SHAPE;
	/* THE DOMAIN SEPARATION EARNING ITS PLACE, and this object is the one
	 * that makes wire/bytes.h's argument concrete rather than cautionary:
	 * a one-pair manifest is 164 bytes and so is a record with an 8-byte
	 * body, signed by the same key through the same seam. */
	if (bytes[FZN_MANIFEST_OFF_OBJECT] != (uint8_t)FZN_OBJECT_MANIFEST)
		return FZN_MANIFEST_ERR_SHAPE;

	count = (size_t)fzn_get_be16(bytes + FZN_MANIFEST_OFF_COUNT);

	/* Refused before the length is computed from it, so the arithmetic
	 * below cannot be made to overflow by a count a stranger chose. */
	if (count > FZN_MANIFEST_MAX_PAIRS)
		return FZN_MANIFEST_ERR_SHAPE;

	/* Exact, not a minimum: trailing bytes are a refusal rather than
	 * something to ignore, because "ignore what you do not understand" is
	 * how one encoding becomes several. */
	if (len != FZN_MANIFEST_LEN(count))
		return FZN_MANIFEST_ERR_SHAPE;

	/* STRICTLY ASCENDING, which is this object's canonicality check and
	 * carries three properties at once -- manifest.h states them. A
	 * non-positive comparison covers both halves: equal is a duplicate, and
	 * negative is out of order.
	 *
	 * ON THE KEY AND NOT THE ENTRY, so a duplicate is a pair named twice
	 * whatever the issuer said about it either time. */
	for (size_t i = 1; i < count; i++) {
		const uint8_t *prev = bytes + FZN_MANIFEST_OFF_PAIRS +
		                      FZN_MANIFEST_PAIR_LEN * (i - 1u);

		if (pair_cmp(prev, prev + FZN_MANIFEST_PAIR_LEN) >= 0)
			return FZN_MANIFEST_ERR_SHAPE;
	}

	/* AND EVERY STATE BYTE IS ONE OF THE TWO. A third value is refused
	 * rather than read as either: the same rule this function applies to
	 * trailing bytes, and for the same reason -- a decoder that ignores
	 * what it does not understand is a second encoding waiting to be
	 * found by somebody else's. It also means a reader may test one value
	 * and trust the complement, which is what the accessor does. */
	for (size_t i = 0; i < count; i++) {
		uint8_t state = bytes[FZN_MANIFEST_OFF_PAIRS + FZN_MANIFEST_PAIR_LEN * i +
		                      FZN_MANIFEST_OFF_ENTRY_STATE];

		if (state != (uint8_t)FZN_MANIFEST_REVOKED &&
		    state != (uint8_t)FZN_MANIFEST_WITHDRAWN)
			return FZN_MANIFEST_ERR_SHAPE;
	}

	out->base = bytes;
	out->len = len;
	return FZN_MANIFEST_OK;
}

fzn_manifest_err_t fzn_manifest_encode(uint8_t *out, size_t out_cap,
                                       const uint8_t issuer[FZN_PUBKEY_LEN],
                                       const fzn_manifest_entry_t *entries, size_t count,
                                       size_t *out_len)
{
	uint8_t *at;

	if (!out || !issuer || !out_len || (count > 0 && !entries))
		return FZN_MANIFEST_ERR_MALFORMED;

	if (count > FZN_MANIFEST_MAX_PAIRS)
		return FZN_MANIFEST_ERR_SHAPE;
	if (out_cap < FZN_MANIFEST_LEN(count))
		return FZN_MANIFEST_ERR_MALFORMED;

	/* A STATE THIS FILE DOES NOT DEFINE IS REFUSED HERE TOO, on the same
	 * argument as the ordering below: an encoder able to emit bytes its
	 * own parser rejects is a second encoding waiting to be found. */
	for (size_t i = 0; i < count; i++) {
		if (entries[i].state != (uint8_t)FZN_MANIFEST_REVOKED &&
		    entries[i].state != (uint8_t)FZN_MANIFEST_WITHDRAWN)
			return FZN_MANIFEST_ERR_SHAPE;
	}

	/* THE ENCODER REFUSES WHAT THE PARSER WOULD. An encoder that can emit
	 * bytes its own `open` rejects is a second encoding waiting to be
	 * found by somebody else's decoder -- and here it would also be a
	 * manifest that no receiver can admit, produced without complaint. */
	for (size_t i = 1; i < count; i++) {
		if (pair_struct_cmp(&entries[i - 1u].pair, &entries[i].pair) >= 0)
			return FZN_MANIFEST_ERR_SHAPE;
	}

	out[FZN_MANIFEST_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	out[FZN_MANIFEST_OFF_OBJECT] = (uint8_t)FZN_OBJECT_MANIFEST;
	memcpy(out + FZN_MANIFEST_OFF_ISSUER, issuer, FZN_PUBKEY_LEN);
	fzn_put_be16(out + FZN_MANIFEST_OFF_COUNT, (uint16_t)count);

	at = out + FZN_MANIFEST_OFF_PAIRS;
	for (size_t i = 0; i < count; i++) {
		memcpy(at, entries[i].pair.capability.b, FZN_CAP_ID_LEN);
		memcpy(at + FZN_CAP_ID_LEN, entries[i].pair.grantee, FZN_PUBKEY_LEN);
		memcpy(at + FZN_MANIFEST_OFF_ENTRY_ID, entries[i].id,
		       FZN_REVOCATION_ID_LEN);
		at[FZN_MANIFEST_OFF_ENTRY_STATE] = entries[i].state;
		at += FZN_MANIFEST_PAIR_LEN;
	}
	memset(out + FZN_MANIFEST_BODY_LEN(count), 0, FZN_SIG_LEN);

	*out_len = FZN_MANIFEST_LEN(count);
	return FZN_MANIFEST_OK;
}

fzn_manifest_err_t fzn_manifest_issue(const uint8_t issuer[FZN_PUBKEY_LEN],
                                      const fzn_revocation_store_t *store,
                                      const fzn_sign_ops_t *sign, uint8_t *out, size_t out_cap,
                                      size_t *out_len)
{
	uint8_t *pairs;
	size_t count = 0;
	size_t entries;
	fzn_manifest_err_t err;
	fzn_manifest_record_t rec;
	const uint8_t *msg;
	size_t msg_len;

	if (!issuer || !sign || !sign->sign || !out || !out_len)
		return FZN_MANIFEST_ERR_MALFORMED;
	if (!store_sound(store))
		return FZN_MANIFEST_ERR_MALFORMED;
	if (out_cap < FZN_MANIFEST_MIN_LEN)
		return FZN_MANIFEST_ERR_MALFORMED;

	entries = store ? store->used : 0;
	pairs = out + FZN_MANIFEST_OFF_PAIRS;

	/* SORTED IN PLACE, IN THE OUTPUT BUFFER, because this module allocates
	 * nothing and a caller-supplied scratch array would be one more thing
	 * to size wrongly. Insertion by binary-free linear scan with a memmove
	 * for the tail: the store is a table a consumer sized for its own
	 * estate, and an O(n^2) sort over 64-byte moves at those sizes is not
	 * worth a second algorithm. It also gives the duplicate test for free,
	 * since the position search already found where an equal pair would
	 * be.
	 *
	 * The store's own dedup means an exact duplicate should be impossible;
	 * it is skipped rather than trusted absent, because the alternative is
	 * a signed manifest that no receiver's `open` will accept, produced by
	 * the one function that is meant to be unable to lie. */
	for (size_t i = 0; i < entries; i++) {
		const fzn_revocation_t *e = &store->entries[i];
		uint8_t candidate[FZN_MANIFEST_PAIR_LEN];
		size_t at;
		int duplicate = 0;

		if (!fzn_ct_memeq(e->issuer, issuer, FZN_PUBKEY_LEN))
			continue;
		/* A WITHDRAWN ENTRY IS IN THE MANIFEST, AND THAT REVERSES WHAT
		 * THIS LINE DID EARLIER TODAY.
		 *
		 * While an entry carried no state, publishing a withdrawn pair
		 * would have told every receiver to revoke a pair this issuer
		 * had restored, under this issuer's own signature -- so it was
		 * skipped. Now an entry SAYS which state it is in, and skipping
		 * it is what leaves every other host revoked for ever: the
		 * withdrawal has no other way to travel. sec 57 records why
		 * absence cannot carry it.
		 *
		 * The consequence is that this manifest never shrinks. A
		 * withdrawn pair stays in it, because a withdrawal that is
		 * forgotten cannot be propagated and there is no point at which
		 * forgetting is safe -- the argument `revocation.h` makes for
		 * never evicting an entry, arriving on the wire. */

		if (count >= FZN_MANIFEST_MAX_PAIRS)
			return FZN_MANIFEST_ERR_SHAPE;
		if (out_cap < FZN_MANIFEST_LEN(count + 1u))
			return FZN_MANIFEST_ERR_MALFORMED;

		memcpy(candidate, e->capability.b, FZN_CAP_ID_LEN);
		memcpy(candidate + FZN_CAP_ID_LEN, e->grantee, FZN_PUBKEY_LEN);
		/* The state travels with the pair rather than being derived at
		 * the far end, which is the whole of what sec 57 settled. */
		memcpy(candidate + FZN_MANIFEST_OFF_ENTRY_ID, e->id,
		       FZN_REVOCATION_ID_LEN);
		candidate[FZN_MANIFEST_OFF_ENTRY_STATE] =
		        e->withdrawn ? (uint8_t)FZN_MANIFEST_WITHDRAWN
		                     : (uint8_t)FZN_MANIFEST_REVOKED;

		for (at = 0; at < count; at++) {
			int cmp = pair_cmp(pairs + FZN_MANIFEST_PAIR_LEN * at, candidate);

			if (cmp == 0) {
				duplicate = 1;
				break;
			}
			if (cmp > 0)
				break;
		}
		if (duplicate)
			continue;

		memmove(pairs + FZN_MANIFEST_PAIR_LEN * (at + 1u),
		        pairs + FZN_MANIFEST_PAIR_LEN * at,
		        FZN_MANIFEST_PAIR_LEN * (count - at));
		memcpy(pairs + FZN_MANIFEST_PAIR_LEN * at, candidate, FZN_MANIFEST_PAIR_LEN);
		count++;
	}

	out[FZN_MANIFEST_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	out[FZN_MANIFEST_OFF_OBJECT] = (uint8_t)FZN_OBJECT_MANIFEST;
	memcpy(out + FZN_MANIFEST_OFF_ISSUER, issuer, FZN_PUBKEY_LEN);
	fzn_put_be16(out + FZN_MANIFEST_OFF_COUNT, (uint16_t)count);
	memset(out + FZN_MANIFEST_BODY_LEN(count), 0, FZN_SIG_LEN);

	/* Opened from the bytes just written, so the range handed to the
	 * signer is the one a receiver's verifier will compute -- and so that
	 * the ordering this function just produced is checked by the same code
	 * that will check it at the far end. */
	err = fzn_manifest_open(out, FZN_MANIFEST_LEN(count), &rec);
	if (err != FZN_MANIFEST_OK)
		return err;

	fzn_manifest_signed_bytes(rec, &msg, &msg_len);
	if (!sign->sign(sign->ctx, out + FZN_MANIFEST_BODY_LEN(count), msg, msg_len)) {
		/* No half-made record: a refused signing must not leave
		 * something that opens cleanly behind. */
		memset(out, 0, FZN_MANIFEST_LEN(count));
		return FZN_MANIFEST_ERR_SIGNATURE;
	}

	*out_len = FZN_MANIFEST_LEN(count);
	return FZN_MANIFEST_OK;
}

fzn_manifest_err_t fzn_manifest_init(fzn_manifest_state_t *state,
                                     fzn_manifest_issuer_t *issuers, size_t issuer_capacity,
                                     fzn_manifest_deficit_t *deficit, size_t deficit_capacity)
{
	if (!state || !issuers || !deficit || issuer_capacity == 0 || deficit_capacity == 0)
		return FZN_MANIFEST_ERR_MALFORMED;

	state->issuers = issuers;
	state->issuer_capacity = issuer_capacity;
	state->issuer_used = 0;
	state->deficit = deficit;
	state->deficit_capacity = deficit_capacity;
	state->deficit_used = 0;

	return FZN_MANIFEST_OK;
}

fzn_manifest_err_t fzn_manifest_follow(fzn_manifest_state_t *state,
                                       const uint8_t issuer[FZN_PUBKEY_LEN])
{
	fzn_manifest_issuer_t *entry;

	if (!issuer || !state_sound(state) || !state->issuers)
		return FZN_MANIFEST_ERR_MALFORMED;

	/* Already followed. Idempotent and INERT: this must not reset
	 * `overflowed` or `pairs_seen`, or a consumer re-following on every
	 * reconnect would erase the one marker that says its deficit is
	 * under-reported. */
	if (find_issuer(state, issuer) < state->issuer_used)
		return FZN_MANIFEST_OK;

	if (state->issuer_used >= state->issuer_capacity)
		return FZN_MANIFEST_ERR_FULL;

	entry = &state->issuers[state->issuer_used];
	memcpy(entry->issuer, issuer, FZN_PUBKEY_LEN);
	entry->pairs_seen = 0;
	entry->overflowed = 0;
	state->issuer_used++;

	return FZN_MANIFEST_OK;
}

fzn_manifest_err_t fzn_manifest_admit(fzn_manifest_state_t *state,
                                      const fzn_revocation_store_t *store,
                                      fzn_manifest_record_t record,
                                      const fzn_sign_ops_t *sign)
{
	fzn_manifest_issuer_t *entry;
	const uint8_t *issuer;
	const uint8_t *msg;
	size_t msg_len;
	size_t count;
	size_t which;
	int dropped = 0;

	if (!state_sound(state) || !state->issuers || !state->deficit)
		return FZN_MANIFEST_ERR_MALFORMED;
	if (!sign || !sign->verify)
		return FZN_MANIFEST_ERR_MALFORMED;
	/* A view that was never opened. MALFORMED rather than SHAPE for the
	 * reason chain.h gives: no bytes were wrong, the caller skipped
	 * `fzn_manifest_open`. */
	if (!record.base)
		return FZN_MANIFEST_ERR_MALFORMED;

	issuer = fzn_manifest_issuer(record);

	/* Followed, before anything expensive. A stranger must not be able to
	 * spend a signature verification, and the answer does not depend on
	 * what the record is signed with. */
	which = find_issuer(state, issuer);
	if (which >= state->issuer_used)
		return FZN_MANIFEST_ERR_UNKNOWN_ISSUER;
	entry = &state->issuers[which];

	/* Before its answers are believed rather than after -- manifest.h says
	 * what a corrupt store's conservative 1 does to this question. */
	if (!store_sound(store))
		return FZN_MANIFEST_ERR_MALFORMED;

	/* UNDER THE RECORD'S OWN ISSUER, never a key a caller supplied. A
	 * manifest is a key's statement about itself. */
	fzn_manifest_signed_bytes(record, &msg, &msg_len);
	if (!sign->verify(sign->ctx, issuer, msg, msg_len, fzn_manifest_signature(record)))
		return FZN_MANIFEST_ERR_SIGNATURE;

	count = fzn_manifest_count(record);

	for (size_t i = 0; i < count; i++) {
		const fzn_cap_id_t *capability = fzn_manifest_capability(record, i);
		const uint8_t *grantee = fzn_manifest_grantee(record, i);
		fzn_manifest_deficit_t *slot;

		/* AM I BEHIND THE ISSUER ABOUT THIS PAIR? which is a different
		 * question from "do I hold it" and became one when an entry
		 * started carrying state.
		 *
		 *   I hold nothing            -- behind, whatever they say
		 *   same record, same state   -- agreed, nothing to fetch
		 *   same record, they cleared -- behind: they have the
		 *                                withdrawal and I do not
		 *   same record, I cleared    -- AHEAD, and asking would fetch
		 *                                a record I would refuse
		 *   different records         -- neither of us can tell who is
		 *                                ahead from hashes alone, so
		 *                                ask; admission sorts it out
		 *
		 * THE LAST ROW IS WHY ADMISSION DRAINS ON ITS "I AM AHEAD"
		 * PATHS. Asking when I am in fact ahead fetches a record that
		 * is refused as stale or unchained, and without the drain this
		 * entry would be re-recorded on every comparison and re-fetched
		 * for ever against every peer that is behind. `revocation.c`
		 * calls `fzn_manifest_satisfy` on both of those refusals for
		 * exactly this. */
		{
			uint8_t mine[FZN_REVOCATION_ID_LEN];
			int mine_withdrawn = 0;
			int ahead;

			if (!fzn_revocation_lookup(store, issuer, capability, grantee,
			                           mine, &mine_withdrawn))
				ahead = 0;
			else if (memcmp(mine, fzn_manifest_id(record, i),
			                FZN_REVOCATION_ID_LEN) != 0)
				ahead = 0;
			else
				ahead = !(fzn_manifest_is_withdrawn(record, i) &&
				          !mine_withdrawn);

			if (ahead)
				continue;
		}
		if (deficit_holds(state, issuer, capability, grantee))
			continue;

		/* KEEP GOING, on `fzn_revocation_merge`'s rule: one pair that
		 * cannot be recorded must not stop the rest, or filling this
		 * table becomes a way to suppress everything behind the pair
		 * that filled it. The flag is what makes the drop visible. */
		if (state->deficit_used >= state->deficit_capacity) {
			entry->overflowed = 1;
			dropped = 1;
			continue;
		}

		slot = &state->deficit[state->deficit_used];
		memcpy(slot->issuer, issuer, FZN_PUBKEY_LEN);
		slot->capability = *capability;
		memcpy(slot->grantee, grantee, FZN_PUBKEY_LEN);
		state->deficit_used++;
	}

	/* THE HIGH-WATER MARK, AND WHY CLEARING NEEDS IT. Without this a
	 * REPLAYED OLDER MANIFEST clears the flag: a manifest is monotone, so
	 * an old one names a subset, every pair of that subset is already held
	 * or already listed, nothing is dropped -- and the host declares its
	 * deficit sound while the pairs that overflowed are still missing. An
	 * honest issuer's count never shrinks, because revocations only
	 * accumulate, so a smaller manifest is exactly the rollback case and
	 * cannot clear anything. */
	if (count >= entry->pairs_seen) {
		entry->pairs_seen = count;
		if (!dropped)
			entry->overflowed = 0;
	}

	return dropped ? FZN_MANIFEST_ERR_DEFICIT_FULL : FZN_MANIFEST_OK;
}

size_t fzn_manifest_satisfy(fzn_manifest_state_t *state, const uint8_t issuer[FZN_PUBKEY_LEN],
                            const fzn_cap_id_t *capability,
                            const uint8_t grantee[FZN_PUBKEY_LEN])
{
	size_t removed = 0;

	if (!state_sound(state) || !state->deficit)
		return 0;
	if (!issuer || !capability || !grantee)
		return 0;

	for (size_t i = 0; i < state->deficit_used;) {
		const fzn_manifest_deficit_t *d = &state->deficit[i];

		if (fzn_ct_memeq(d->issuer, issuer, FZN_PUBKEY_LEN) &&
		    fzn_ct_memeq(d->capability.b, capability->b, FZN_CAP_ID_LEN) &&
		    fzn_ct_memeq(d->grantee, grantee, FZN_PUBKEY_LEN)) {
			/* Compacted by moving the tail down, which keeps the
			 * table dense and the report's order the admission
			 * order. The index is not advanced, because what has
			 * just moved into it has not been looked at. */
			memmove(&state->deficit[i], &state->deficit[i + 1u],
			        (state->deficit_used - i - 1u) * sizeof(*state->deficit));
			state->deficit_used--;
			removed++;
			continue;
		}
		i++;
	}

	return removed;
}

size_t fzn_manifest_pending(const fzn_manifest_state_t *state,
                            const uint8_t issuer[FZN_PUBKEY_LEN])
{
	size_t n = 0;

	if (!state_sound(state) || !state->deficit || !issuer)
		return 0;

	for (size_t i = 0; i < state->deficit_used; i++) {
		if (fzn_ct_memeq(state->deficit[i].issuer, issuer, FZN_PUBKEY_LEN))
			n++;
	}
	return n;
}

int fzn_manifest_overflowed(const fzn_manifest_state_t *state,
                            const uint8_t issuer[FZN_PUBKEY_LEN])
{
	size_t which;

	/* A state that cannot be read, and an issuer nobody named, are the
	 * same fact as a dropped pair: this host cannot say what it is missing
	 * from that key. manifest.h says why this answers the opposite way
	 * round from `fzn_revocation_covers`. */
	if (!state_sound(state) || !state->issuers || !issuer)
		return 1;

	which = find_issuer(state, issuer);
	if (which >= state->issuer_used)
		return 1;

	return state->issuers[which].overflowed != 0;
}

fzn_manifest_err_t fzn_manifest_plan_offer(const fzn_revocation_store_t *store,
                                           const fzn_manifest_deficit_t *wants,
                                           size_t want_count, uint8_t *holds,
                                           size_t holds_cap,
                                           fzn_manifest_offer_t *plan)
{
	size_t i, n;

	if (!plan)
		return FZN_MANIFEST_ERR_MALFORMED;
	plan->held = 0;
	plan->examined = 0;
	plan->truncated = 0;

	/* Zero capacity is refused rather than read as unlimited -- the rule
	 * `spool/plan.h` states, and the one a serve path most needs, since
	 * the peer chose the number that would otherwise fill the buffer. */
	if (!holds || holds_cap == 0)
		return FZN_MANIFEST_ERR_MALFORMED;
	if (want_count > 0 && !wants)
		return FZN_MANIFEST_ERR_MALFORMED;
	/* Judged here rather than inherited from `fzn_revocation_covers`,
	 * whose answer for an unscannable store is 1 and would make this
	 * promise everything. See `store_sound`. */
	if (!store_sound(store))
		return FZN_MANIFEST_ERR_MALFORMED;

	n = want_count;
	if (n > holds_cap) {
		n = holds_cap;
		plan->truncated = 1;
	}

	for (i = 0; i < n; i++) {
		/* `known` for the same reason as the deficit above, from the
		 * other side: a peer's want list is answered with what this
		 * host has the history for. Saying "not held" for a pair we
		 * withdrew would keep us on that peer's want list for ever. */
		int have = fzn_revocation_known(store, wants[i].issuer,
		                                &wants[i].capability, wants[i].grantee);

		holds[i] = have ? 1u : 0u;
		if (have)
			plan->held++;
	}
	plan->examined = n;
	return FZN_MANIFEST_OK;
}

size_t fzn_manifest_deficit_from(const fzn_manifest_state_t *state,
                                const uint8_t issuer[FZN_PUBKEY_LEN], size_t from,
                                fzn_manifest_pair_t *out, size_t out_cap, size_t *dropped,
                                size_t *next)
{
	size_t total = 0;
	size_t written = 0;
	size_t pos = 0;

	/* REQUIRED, not optional, and refused first so that a caller which
	 * forgot it gets nothing rather than a report it cannot size. */
	if (!dropped)
		return 0;
	*dropped = 0;
	if (next)
		*next = 0;

	if (!state_sound(state) || !state->deficit || !issuer || (out_cap > 0 && !out))
		return 0;

	/* COUNTED BEFORE IT IS WALKED, because `from` is meaningless until
	 * there is a total to reduce it by. One extra pass over a table that
	 * is already bounded, and it removes every special case below. */
	for (size_t i = 0; i < state->deficit_used; i++)
		if (fzn_ct_memeq(state->deficit[i].issuer, issuer, FZN_PUBKEY_LEN))
			total++;
	if (total == 0)
		return 0;
	from %= total;

	/* THE ROTATION, done by arithmetic rather than by two sweeps. Each
	 * matching pair has a position `pos` in this issuer's run; its offset
	 * from the cursor is `(pos - from) mod total`, and it belongs in the
	 * output exactly when that offset is inside the window. Writing it
	 * straight to that index puts the window in cursor order without the
	 * caller sorting anything. */
	for (size_t i = 0; i < state->deficit_used; i++) {
		const fzn_manifest_deficit_t *d = &state->deficit[i];
		size_t rel;

		if (!fzn_ct_memeq(d->issuer, issuer, FZN_PUBKEY_LEN))
			continue;
		rel = (pos + total - from) % total;
		pos++;
		if (rel >= out_cap)
			continue;
		out[rel].capability = d->capability;
		memcpy(out[rel].grantee, d->grantee, FZN_PUBKEY_LEN);
		written++;
	}

	*dropped = total - written;
	if (next)
		*next = (from + written) % total;
	return written;
}

size_t fzn_manifest_deficit(const fzn_manifest_state_t *state,
                            const uint8_t issuer[FZN_PUBKEY_LEN], fzn_manifest_pair_t *out,
                            size_t out_cap, size_t *dropped)
{
	/* THE `from == 0` CASE, expressed as one rather than duplicated. Two
	 * copies of a scan is how two answers drift, and this file already
	 * argues that where `fzn_revocation_admit` calls `fzn_manifest_satisfy`
	 * rather than reaching into the table itself. */
	return fzn_manifest_deficit_from(state, issuer, 0, out, out_cap, dropped, NULL);
}

const char *fzn_manifest_err_str(fzn_manifest_err_t err)
{
	switch (err) {
	case FZN_MANIFEST_OK:
		return "ok";
	case FZN_MANIFEST_ERR_MALFORMED:
		return "malformed argument";
	case FZN_MANIFEST_ERR_SHAPE:
		return "not the shape the layout describes";
	case FZN_MANIFEST_ERR_SIGNATURE:
		return "signature does not check out";
	case FZN_MANIFEST_ERR_UNKNOWN_ISSUER:
		return "manifest from an issuer nobody follows";
	case FZN_MANIFEST_ERR_FULL:
		return "no room to follow another issuer";
	case FZN_MANIFEST_ERR_DEFICIT_FULL:
		return "deficit table is full";
	}

	return "unknown";
}
