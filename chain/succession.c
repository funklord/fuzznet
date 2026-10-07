/* See succession.h. */

#include "succession.h"

#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#include <string.h>

/* THE LAYOUT, pinned as literals so a change has to be made twice and agree,
 * as revocation.c pins its own; chain/succession.situ states it a third time
 * and `make schema` compares that with situ's reading. */
_Static_assert(FZN_SUCCESSION_OFF_ISSUER == 2u, "succession layout: issuer moved");
_Static_assert(FZN_SUCCESSION_OFF_OLD == 34u, "succession layout: old moved");
_Static_assert(FZN_SUCCESSION_OFF_NEW == 66u, "succession layout: new moved");
_Static_assert(FZN_SUCCESSION_OFF_CUT == 98u, "succession layout: cut moved");
_Static_assert(FZN_SUCCESSION_OFF_SIGNATURE == 130u, "succession layout: the signature moved");
_Static_assert(FZN_SUCCESSION_LEN == 194u, "succession layout: a succession is not 194 bytes");
/* A CONFIRMATION NAMES ONE BY THE SAME 32 BYTES it names a hop by. */
_Static_assert(FZN_SUCCESSION_ID_LEN == FZN_REVOCATION_ID_LEN,
               "a confirmation could not name a succession");

fzn_chain_err_t fzn_succession_open(const uint8_t *bytes, size_t len,
                                    fzn_succession_record_t *out)
{
	if (!bytes || !out)
		return FZN_CHAIN_ERR_MALFORMED;
	if (len != FZN_SUCCESSION_LEN || bytes[FZN_SUCCESSION_OFF_VERSION] != FZN_SIGNED_VERSION
	    || bytes[FZN_SUCCESSION_OFF_OBJECT] != (uint8_t)FZN_OBJECT_SUCCESSION)
		return FZN_CHAIN_ERR_SHAPE;
	/* A KEY SUCCEEDED BY ITSELF moves no reference and would be a cycle of
	 * one; refused at `open` so no reader has to remember. */
	if (fzn_ct_memeq(bytes + FZN_SUCCESSION_OFF_OLD, bytes + FZN_SUCCESSION_OFF_NEW,
	                 FZN_PUBKEY_LEN))
		return FZN_CHAIN_ERR_SHAPE;
	out->base = bytes;
	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_succession_issue(const uint8_t issuer[FZN_PUBKEY_LEN],
                                     const uint8_t old[FZN_PUBKEY_LEN],
                                     const uint8_t new_key[FZN_PUBKEY_LEN],
                                     const uint8_t cut[FZN_SUCCESSION_ID_LEN],
                                     const fzn_sign_ops_t *sign, uint8_t *out)
{
	if (!issuer || !old || !new_key || !sign || !sign->sign || !out
	    || fzn_ct_memeq(old, new_key, FZN_PUBKEY_LEN))
		return FZN_CHAIN_ERR_MALFORMED;
	out[FZN_SUCCESSION_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	out[FZN_SUCCESSION_OFF_OBJECT] = (uint8_t)FZN_OBJECT_SUCCESSION;
	memcpy(out + FZN_SUCCESSION_OFF_ISSUER, issuer, FZN_PUBKEY_LEN);
	memcpy(out + FZN_SUCCESSION_OFF_OLD, old, FZN_PUBKEY_LEN);
	memcpy(out + FZN_SUCCESSION_OFF_NEW, new_key, FZN_PUBKEY_LEN);
	if (cut)
		memcpy(out + FZN_SUCCESSION_OFF_CUT, cut, FZN_SUCCESSION_ID_LEN);
	else
		memset(out + FZN_SUCCESSION_OFF_CUT, 0, FZN_SUCCESSION_ID_LEN);
	if (!sign->sign(sign->ctx, out + FZN_SUCCESSION_OFF_SIGNATURE, out,
	                FZN_SUCCESSION_BODY_LEN)) {
		/* No half-made record: one that opens and was never signed. */
		memset(out, 0, FZN_SUCCESSION_LEN);
		return FZN_CHAIN_ERR_CHAIN_INVALID;
	}
	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_succession_set_init(fzn_succession_set_t *set, fzn_succession_t *entries,
                                        size_t capacity, const fzn_hash_ops_t *hash)
{
	if (!set || !entries || capacity == 0u || !hash || !hash->hash)
		return FZN_CHAIN_ERR_MALFORMED;
	set->entries = entries;
	set->capacity = capacity;
	set->used = 0;
	set->hash = hash;
	return FZN_CHAIN_OK;
}

static int sound(const fzn_succession_set_t *set)
{
	return set && set->entries && set->hash && set->hash->hash && set->used <= set->capacity;
}

fzn_chain_err_t fzn_succession_admit(fzn_succession_set_t *set,
                                     fzn_revocation_store_t *revocations, const uint8_t *bytes,
                                     size_t len, const fzn_chain_hop_t *hops, size_t hop_count,
                                     const uint8_t root[FZN_PUBKEY_LEN],
                                     const fzn_sign_ops_t *sign)
{
	fzn_succession_record_t rec;
	fzn_succession_t *e;
	uint8_t id[FZN_SUCCESSION_ID_LEN];
	const uint8_t *issuer;
	size_t i;
	fzn_chain_err_t err;

	if (!sound(set) || !revocations || !bytes || !root || !sign || !sign->verify
	    || (hop_count > 0u && !hops))
		return FZN_CHAIN_ERR_MALFORMED;
	err = fzn_succession_open(bytes, len, &rec);
	if (err != FZN_CHAIN_OK)
		return err;
	issuer = fzn_succession_issuer(rec);
	/* A ROOT NEEDS NO CHAIN, as for a vote or a confirmation: the pinned
	 * root, or any member of the set, whose record counts as the set says
	 * when read. */
	if (hop_count == 0u && !fzn_ct_memeq(issuer, root, FZN_PUBKEY_LEN)
	    && !(revocations->roots && revocations->roots->member(revocations->roots->ctx, issuer)))
		return FZN_CHAIN_ERR_WRONG_ROOT;
	if (!sign->verify(sign->ctx, issuer, bytes, FZN_SUCCESSION_BODY_LEN,
	                  bytes + FZN_SUCCESSION_OFF_SIGNATURE))
		return FZN_CHAIN_ERR_CHAIN_INVALID;
	/* AN ADMIN SHOWS ITS ADMIN CHAIN, kept as a vote's would be. */
	if (hop_count > 0u) {
		err = fzn_revocation_admin_admit(revocations, issuer, hops, hop_count, root, sign);
		if (err != FZN_CHAIN_OK)
			return err;
	}
	if (!set->hash->hash(set->hash->ctx, id, sizeof(id), bytes, len))
		return FZN_CHAIN_ERR_MALFORMED;
	for (i = 0; i < set->used; i++)
		if (fzn_ct_memeq(set->entries[i].id, id, sizeof(id)))
			return FZN_CHAIN_OK;
	if (set->used >= set->capacity)
		return FZN_CHAIN_ERR_STORE_FULL;
	e = &set->entries[set->used++];
	memcpy(e->issuer, issuer, FZN_PUBKEY_LEN);
	memcpy(e->old, fzn_succession_old(rec), FZN_PUBKEY_LEN);
	memcpy(e->new_key, fzn_succession_new(rec), FZN_PUBKEY_LEN);
	memcpy(e->cut, fzn_succession_cut(rec), FZN_SUCCESSION_ID_LEN);
	memcpy(e->id, id, sizeof(id));
	return FZN_CHAIN_OK;
}

int fzn_succession_counts(const fzn_succession_set_t *set, size_t i,
                          const fzn_revocation_store_t *revocations,
                          const uint8_t root[FZN_PUBKEY_LEN])
{
	if (!sound(set) || i >= set->used || !revocations || !root)
		return 0;
	return fzn_revocation_confirmed(revocations, set->entries[i].issuer, set->entries[i].id,
	                                root);
}

int fzn_succession_resolve(const fzn_succession_set_t *set,
                           const fzn_revocation_store_t *revocations,
                           const uint8_t root[FZN_PUBKEY_LEN],
                           const uint8_t key[FZN_PUBKEY_LEN], uint8_t out[FZN_PUBKEY_LEN])
{
	const uint8_t *at = key;
	size_t depth, i;

	if (!sound(set) || !revocations || !root || !key || !out)
		return 0;
	/* A CYCLE NEEDS NO CHECK OF ITS OWN: it never reaches a key nothing
	 * succeeds, so it runs into the depth bound and names nobody, exactly as
	 * a chain too long to follow does. */
	for (depth = 0; depth <= FZN_SUCCESSION_DEPTH_MAX; depth++) {
		const uint8_t *next = NULL;

		/* EVERY COUNTING SUCCESSION OF THIS KEY: one names the next key,
		 * two naming different keys are a fork. */
		for (i = 0; i < set->used; i++) {
			const fzn_succession_t *e = &set->entries[i];

			if (!fzn_ct_memeq(e->old, at, FZN_PUBKEY_LEN)
			    || !fzn_succession_counts(set, i, revocations, root))
				continue;
			if (next && !fzn_ct_memeq(next, e->new_key, FZN_PUBKEY_LEN))
				return 0;
			next = e->new_key;
		}
		if (!next) {
			memcpy(out, at, FZN_PUBKEY_LEN);
			return 1;
		}
		at = next;
	}
	return 0;
}
