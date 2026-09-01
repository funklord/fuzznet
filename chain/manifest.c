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
	return memcmp(a, b, FZN_MANIFEST_PAIR_LEN);
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
	 * negative is out of order. */
	for (size_t i = 1; i < count; i++) {
		const uint8_t *prev = bytes + FZN_MANIFEST_OFF_PAIRS +
		                      FZN_MANIFEST_PAIR_LEN * (i - 1u);

		if (pair_cmp(prev, prev + FZN_MANIFEST_PAIR_LEN) >= 0)
			return FZN_MANIFEST_ERR_SHAPE;
	}

	out->base = bytes;
	out->len = len;
	return FZN_MANIFEST_OK;
}

fzn_manifest_err_t fzn_manifest_encode(uint8_t *out, size_t out_cap,
                                       const uint8_t issuer[FZN_PUBKEY_LEN],
                                       const fzn_manifest_pair_t *pairs, size_t count,
                                       size_t *out_len)
{
	uint8_t *at;

	if (!out || !issuer || !out_len || (count > 0 && !pairs))
		return FZN_MANIFEST_ERR_MALFORMED;

	if (count > FZN_MANIFEST_MAX_PAIRS)
		return FZN_MANIFEST_ERR_SHAPE;
	if (out_cap < FZN_MANIFEST_LEN(count))
		return FZN_MANIFEST_ERR_MALFORMED;

	/* THE ENCODER REFUSES WHAT THE PARSER WOULD. An encoder that can emit
	 * bytes its own `open` rejects is a second encoding waiting to be
	 * found by somebody else's decoder -- and here it would also be a
	 * manifest that no receiver can admit, produced without complaint. */
	for (size_t i = 1; i < count; i++) {
		if (pair_struct_cmp(&pairs[i - 1u], &pairs[i]) >= 0)
			return FZN_MANIFEST_ERR_SHAPE;
	}

	out[FZN_MANIFEST_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	out[FZN_MANIFEST_OFF_OBJECT] = (uint8_t)FZN_OBJECT_MANIFEST;
	memcpy(out + FZN_MANIFEST_OFF_ISSUER, issuer, FZN_PUBKEY_LEN);
	fzn_put_be16(out + FZN_MANIFEST_OFF_COUNT, (uint16_t)count);

	at = out + FZN_MANIFEST_OFF_PAIRS;
	for (size_t i = 0; i < count; i++) {
		memcpy(at, pairs[i].capability.b, FZN_CAP_ID_LEN);
		memcpy(at + FZN_CAP_ID_LEN, pairs[i].grantee, FZN_PUBKEY_LEN);
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

		if (count >= FZN_MANIFEST_MAX_PAIRS)
			return FZN_MANIFEST_ERR_SHAPE;
		if (out_cap < FZN_MANIFEST_LEN(count + 1u))
			return FZN_MANIFEST_ERR_MALFORMED;

		memcpy(candidate, e->capability.b, FZN_CAP_ID_LEN);
		memcpy(candidate + FZN_CAP_ID_LEN, e->grantee, FZN_PUBKEY_LEN);

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

		/* THE COMPLETENESS PREDICATE IS `fzn_revocation_covers` ITSELF,
		 * which is sec 13d's reason for naming the pair rather than
		 * hashing the triple. There is no second predicate to drift
		 * from this one. */
		if (fzn_revocation_covers(store, issuer, capability, grantee))
			continue;
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

size_t fzn_manifest_deficit(const fzn_manifest_state_t *state,
                            const uint8_t issuer[FZN_PUBKEY_LEN], fzn_manifest_pair_t *out,
                            size_t out_cap, size_t *dropped)
{
	size_t written = 0;
	size_t missed = 0;

	/* REQUIRED, not optional, and refused first so that a caller which
	 * forgot it gets nothing rather than a report it cannot size. */
	if (!dropped)
		return 0;
	*dropped = 0;

	if (!state_sound(state) || !state->deficit || !issuer || (out_cap > 0 && !out))
		return 0;

	for (size_t i = 0; i < state->deficit_used; i++) {
		const fzn_manifest_deficit_t *d = &state->deficit[i];

		if (!fzn_ct_memeq(d->issuer, issuer, FZN_PUBKEY_LEN))
			continue;
		if (written >= out_cap) {
			missed++;
			continue;
		}
		out[written].capability = d->capability;
		memcpy(out[written].grantee, d->grantee, FZN_PUBKEY_LEN);
		written++;
	}

	*dropped = missed;
	return written;
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
