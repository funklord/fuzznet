/* The revocation record and the store. See revocation.h. */

#include "revocation.h"

/* For `fzn_manifest_satisfy` alone. revocation.h holds only the incomplete
 * type, so nothing in this file can reach into a deficit table -- it can only
 * tell the module that owns one that a pair has been settled. */
#include "manifest.h"

#include <string.h>
/* THE LAYOUT, ASSERTED FIELD BY FIELD.
 *
 * `record/record.c` has done this since it was written and states the reason
 * beside it: the offsets are checked individually rather than only the total,
 * because a total is the one thing that survives two fields swapping widths.
 * The reasoning was right and it was applied to exactly one module.
 *
 * MEASURED BEFORE BEING WRITTEN, which is why these are here rather than as
 * tidiness: exchanging FZN_REV_OFF_GRANTEE and FZN_REV_OFF_ISSUER --
 * both 32-byte public keys -- left the whole suite green. A revocation names
 * WHO IS REVOKED and WHO SAID SO, and nothing distinguished the two.
 *
 * The numbers are literals. A constant checked against itself checks nothing,
 * and the point is that a peer cannot see this file -- project.md sec 45 makes
 * the same argument for the domain labels in their vectors.
 */
_Static_assert(FZN_REV_OFF_VERSION == 0u, "revocation layout: version moved");
_Static_assert(FZN_REV_OFF_OBJECT == 1u, "revocation layout: object moved");
_Static_assert(FZN_REV_OFF_CAPABILITY == 2u, "revocation layout: capability moved");
_Static_assert(FZN_REV_OFF_GRANTEE == 34u, "revocation layout: grantee moved");
_Static_assert(FZN_REV_OFF_ISSUER == 66u, "revocation layout: issuer moved");
_Static_assert(FZN_REV_OFF_ISSUED_AT == 98u, "revocation layout: issued_at moved");
_Static_assert(FZN_REV_OFF_SUPERSEDES == 106u, "revocation layout: supersedes moved");
_Static_assert(FZN_REV_OFF_SIGNATURE == 138u, "revocation layout: the signature moved");
_Static_assert(FZN_REVOCATION_BODY_LEN == 138u,
               "revocation layout: the signed body is not 138 bytes");
_Static_assert(FZN_REVOCATION_LEN == 202u,
               "revocation layout: a revocation is not 202 bytes");
/* THE FIELD IS INSIDE THE SIGNED RANGE, which is the whole of what makes it
 * worth anything. A supersedes a peer could rewrite in flight would let one
 * relay turn a chained re-revocation into an un-chained one, or point a
 * withdrawal at a different revocation than the issuer named. The body ends
 * at the signature, so asserting the field is below FZN_REV_OFF_SIGNATURE
 * says it is covered. */
_Static_assert(FZN_REV_OFF_SUPERSEDES + FZN_REVOCATION_ID_LEN == FZN_REV_OFF_SIGNATURE,
               "revocation layout: supersedes is not the last signed field");


/* All-zero, which is how "names nothing" is spelled in a hash field.
 *
 * NOT `fzn_ct_memeq` AGAINST A ZERO BUFFER, because that would need a
 * 32-byte zero array in scope and this is not a secret comparison: a record's
 * supersedes field is public, travels in the clear, and its being zero is
 * already visible in its length-invariant position. Constant time here would
 * buy nothing and read as though it were protecting something.
 *
 * Accumulated rather than early-returned all the same, because the habit is
 * cheap and the next reader should not have to work out which comparisons in
 * this file are which. */
static int all_zero(const uint8_t *p, size_t len)
{
	uint8_t seen = 0;
	size_t i;

	for (i = 0; i < len; i++)
		seen |= p[i];
	return seen == 0;
}

static int same(const fzn_revocation_t *entry, const uint8_t *issuer,
                const fzn_cap_id_t *capability, const uint8_t *grantee)
{
	return fzn_ct_memeq(entry->issuer, issuer, FZN_PUBKEY_LEN) &&
	       fzn_ct_memeq(entry->capability.b, capability->b, FZN_CAP_ID_LEN) &&
	       fzn_ct_memeq(entry->grantee, grantee, FZN_PUBKEY_LEN);
}

/* `used` bounds a loop over `entries`, which holds `capacity`. A store where
 * the count exceeds the array, or where the count is nonzero and there is no
 * array at all, describes entries that cannot be scanned.
 *
 * ONE DEFINITION, because there are two readers of it now. `fzn_revocation_covers`
 * and `fzn_revocation_covers_chain` both answer authorization questions off
 * this store and both must deny when it cannot be read; two copies of that
 * rule is the shape chain.h records a heap overflow for, where a later
 * simplification deletes the wrong half. `fzn_revocation_admit` deliberately
 * keeps its OWN check with its own answer -- see the comment there, and note
 * that it is a different question with a different safe reply. */
static int corrupt(const fzn_revocation_store_t *store)
{
	return store->used > store->capacity || (store->used > 0 && !store->entries);
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
	if (bytes[FZN_REV_OFF_OBJECT] != (uint8_t)FZN_OBJECT_REVOCATION &&
	    bytes[FZN_REV_OFF_OBJECT] != (uint8_t)FZN_OBJECT_WITHDRAWAL)
		return FZN_CHAIN_ERR_SHAPE;
	/* A WITHDRAWAL MUST NAME SOMETHING, and this is the one canonicality
	 * check the pair does not share. A withdrawal whose target is all-zero
	 * names no revocation, so nothing can ever be matched against it --
	 * and a stored one would sit there answering "not revoked" for a pair
	 * whose revocation it never undid, which is a permanent grant nobody
	 * signed for. Refused at `open` so no reader has to remember. */
	if (bytes[FZN_REV_OFF_OBJECT] == (uint8_t)FZN_OBJECT_WITHDRAWAL &&
	    all_zero(bytes + FZN_REV_OFF_SUPERSEDES, FZN_REVOCATION_ID_LEN))
		return FZN_CHAIN_ERR_SHAPE;

	out->base = bytes;
	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_revocation_encode(uint8_t *out, uint8_t object,
                                      const uint8_t issuer[FZN_PUBKEY_LEN],
                                      const fzn_cap_id_t *capability,
                                      const uint8_t grantee[FZN_PUBKEY_LEN],
                                      uint64_t issued_at,
                                      const uint8_t supersedes[FZN_REVOCATION_ID_LEN])
{
	if (!out || !issuer || !capability || !grantee)
		return FZN_CHAIN_ERR_MALFORMED;
	if (object != (uint8_t)FZN_OBJECT_REVOCATION &&
	    object != (uint8_t)FZN_OBJECT_WITHDRAWAL)
		return FZN_CHAIN_ERR_MALFORMED;
	/* Refused here as well as at `open`, so the encoder cannot produce
	 * bytes its own parser rejects -- the argument chain.h makes about
	 * every encoder in this library. */
	if (object == (uint8_t)FZN_OBJECT_WITHDRAWAL &&
	    (!supersedes || all_zero(supersedes, FZN_REVOCATION_ID_LEN)))
		return FZN_CHAIN_ERR_MALFORMED;

	out[FZN_REV_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	out[FZN_REV_OFF_OBJECT] = object;
	memcpy(out + FZN_REV_OFF_CAPABILITY, capability, FZN_CAP_ID_LEN);
	memcpy(out + FZN_REV_OFF_GRANTEE, grantee, FZN_PUBKEY_LEN);
	memcpy(out + FZN_REV_OFF_ISSUER, issuer, FZN_PUBKEY_LEN);
	fzn_put_be64(out + FZN_REV_OFF_ISSUED_AT, issued_at);
	if (supersedes)
		memcpy(out + FZN_REV_OFF_SUPERSEDES, supersedes, FZN_REVOCATION_ID_LEN);
	else
		memset(out + FZN_REV_OFF_SUPERSEDES, 0, FZN_REVOCATION_ID_LEN);
	memset(out + FZN_REV_OFF_SIGNATURE, 0, FZN_SIG_LEN);

	return FZN_CHAIN_OK;
}

/* The one body behind the three public minting calls. They differ in the
 * object tag and in what they name, and in nothing else -- so there is one
 * encode-open-sign-or-wipe sequence rather than three that must be kept in
 * step, which is the shape chain.h records paying for once. */
static fzn_chain_err_t mint(uint8_t object, const uint8_t issuer[FZN_PUBKEY_LEN],
                            const fzn_cap_id_t *capability,
                            const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t issued_at,
                            const uint8_t supersedes[FZN_REVOCATION_ID_LEN],
                            const fzn_sign_ops_t *sign, uint8_t *out)
{
	fzn_chain_err_t err;
	fzn_revocation_record_t rec;
	const uint8_t *msg;
	size_t msg_len;

	if (!issuer || !capability || !grantee || !sign || !sign->sign || !out)
		return FZN_CHAIN_ERR_MALFORMED;

	err = fzn_revocation_encode(out, object, issuer, capability, grantee, issued_at,
	                            supersedes);
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

fzn_chain_err_t fzn_revocation_issue(const uint8_t issuer[FZN_PUBKEY_LEN],
                                     const fzn_cap_id_t *capability,
                                     const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t issued_at,
                                     const fzn_sign_ops_t *sign, uint8_t *out)
{
	return mint((uint8_t)FZN_OBJECT_REVOCATION, issuer, capability, grantee, issued_at,
	            NULL, sign, out);
}

fzn_chain_err_t fzn_revocation_reissue(const uint8_t issuer[FZN_PUBKEY_LEN],
                                       const fzn_cap_id_t *capability,
                                       const uint8_t grantee[FZN_PUBKEY_LEN],
                                       uint64_t issued_at,
                                       const uint8_t supersedes[FZN_REVOCATION_ID_LEN],
                                       const fzn_sign_ops_t *sign, uint8_t *out)
{
	/* A reissue naming nothing is `fzn_revocation_issue` spelled the long
	 * way, and a caller reaching for this one believes it is chaining. */
	if (!supersedes || all_zero(supersedes, FZN_REVOCATION_ID_LEN))
		return FZN_CHAIN_ERR_MALFORMED;
	return mint((uint8_t)FZN_OBJECT_REVOCATION, issuer, capability, grantee, issued_at,
	            supersedes, sign, out);
}

fzn_chain_err_t fzn_revocation_issue_withdrawal(const uint8_t issuer[FZN_PUBKEY_LEN],
                                                const fzn_cap_id_t *capability,
                                                const uint8_t grantee[FZN_PUBKEY_LEN],
                                                uint64_t issued_at,
                                                const uint8_t target[FZN_REVOCATION_ID_LEN],
                                                const fzn_sign_ops_t *sign, uint8_t *out)
{
	return mint((uint8_t)FZN_OBJECT_WITHDRAWAL, issuer, capability, grantee, issued_at,
	            target, sign, out);
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

/* Where this triple's entry is, or `used` for a triple this store has never
 * held. ONE ENTRY PER TRIPLE is the invariant that makes this a lookup
 * rather than a scan with a policy: a withdrawal replaces in place and a
 * re-revocation replaces in place, so nothing ever appends a second row for
 * a key that already has one. */
static size_t find_entry(const fzn_revocation_store_t *store, const uint8_t *issuer,
                         const fzn_cap_id_t *capability, const uint8_t *grantee)
{
	size_t i;

	for (i = 0; i < store->used; i++) {
		if (same(&store->entries[i], issuer, capability, grantee))
			break;
	}
	return i;
}

int fzn_revocation_covers(const fzn_revocation_store_t *store,
                           const uint8_t issuer[FZN_PUBKEY_LEN],
                           const fzn_cap_id_t *capability,
                           const uint8_t grantee[FZN_PUBKEY_LEN])
{
	/* AN ABSENT STORE IS AN ANSWER, NOT A MISSING ONE. A caller with no
	 * store knows of no revocations, and "no revocations known" is what
	 * NULL has always meant here -- it is the contract `fzn_chain_verify`
	 * rests on, since NULL is how a consumer holding none calls it. This
	 * is the one null case that is not a caller's mistake, and it is
	 * separated from the rest for exactly that reason. */
	if (!store)
		return 0;

	/* THE STORE'S INTEGRITY IS JUDGED BEFORE THE QUESTION IS, and the
	 * ORDER is load-bearing rather than incidental -- it used to come
	 * second, below a null guard that answered 0.
	 *
	 * `used` bounds a loop over `entries`, which holds `capacity`. A store
	 * where the count exceeds the array, or where the count is nonzero and
	 * there is no array at all, is corrupt: it describes entries that
	 * cannot be scanned, and any one of them may be the entry that answers
	 * this question. So the answer is the one that denies -- report the
	 * capability as revoked rather than scan memory that is not the store.
	 * Saying "not revoked" would be the fail-open answer, and failing open
	 * here means a withdrawn capability keeps working.
	 *
	 * Asked first so that NOTHING can be answered "no" against a corrupt
	 * store. Underneath the null guard, a caller that passed a corrupt
	 * store AND a null operand got 0 -- permitted -- which is the wrong
	 * answer arrived at by the more conservative-looking check being
	 * shadowed by the less. */
	if (corrupt(store))
		return 1;

	/* A MISSING TRIPLE OPERAND IS PERMITTED, DELIBERATELY, AND IT IS NOT
	 * THE SAME QUESTION AS THE ONE ABOVE.
	 *
	 * The store above is corrupt: the question is well formed, entries
	 * that might answer it exist, and we cannot read them -- so we must
	 * assume they say yes. Here the store is sound and readable, and what
	 * is missing is the question. There is no issuer, capability or
	 * grantee to match, so no entry in this store or any other names one,
	 * and 0 is not a permission being granted but the literal truth that
	 * nothing here matches what was asked.
	 *
	 * Denying instead would deny a triple nobody named. It cannot protect
	 * the grantee the caller meant, because the caller named no grantee;
	 * what it would do is turn one null pointer into a blanket refusal of
	 * every capability, reported as a revocation no issuer ever signed --
	 * an outage wearing policy's clothes, in a module whose entries are
	 * never evicted and never expire. A caller bug should look like a
	 * caller bug.
	 *
	 * THE GUARD IS NOT REDUNDANT, and the reason is not the null pointers.
	 * Deleting it leaves the suite green, because `fzn_ct_memeq` answers
	 * "not equal" for a NULL side and `same()` therefore fails for every
	 * entry anyway. But that is a promise constant_time.h makes about
	 * ITSELF -- made for callers asking an authorization question, where
	 * "not equal" is the conservative answer. It is not conservative here:
	 * this is the one caller in the library where "not equal" propagates
	 * to PERMIT, because the thing being matched is a prohibition rather
	 * than a credential. Resting on it would be resting on a guarantee
	 * that was reasoned about for the opposite polarity, and a
	 * constant-time comparison that stopped making it -- by delegating to
	 * memcmp, say -- would turn all three of these into a null
	 * dereference on the authorization path.
	 *
	 * The alternative -- denying, for consistency with the branch above --
	 * was weighed and is defensible. What settles it against is that the
	 * corrupt-store branch, now that it is asked first, already covers
	 * every case where denying protects something real: a store that may
	 * hold the answer. What is left is a question with no subject, and
	 * there is nothing there to protect. */
	if (!store->entries || !issuer || !capability || !grantee)
		return 0;

	/* PRESENCE IS NOT THE ANSWER; THE ENTRY'S ACTION IS.
	 *
	 * A withdrawal replaces the revocation at its key rather than removing
	 * it -- chain.h says why at length -- so an entry may be sitting here
	 * meaning the OPPOSITE of what it used to mean. A reader that stopped
	 * at `same()` would answer "revoked" for every pair that was ever
	 * revoked and has since been restored, which is the outage the whole
	 * withdrawal design exists to end.
	 *
	 * There is one entry per triple, so this returns on the first match
	 * either way; the answer it returns is the entry's action. */
	{
		size_t at = find_entry(store, issuer, capability, grantee);

		return at < store->used && !store->entries[at].withdrawn;
	}
}

/* IS THIS TRIPLE IN THE STORE AT ALL, whatever it now says.
 *
 * A SECOND PREDICATE, WHICH THE COMMENT IN chain/manifest.c WARNED AGAINST,
 * so it shares this one's matching rule rather than restating it: both go
 * through `find_entry` and differ only in what they make of the answer.
 * There is one definition of "same triple" and there always was.
 *
 * The two questions genuinely differ once a withdrawal can replace a
 * revocation in place. `fzn_revocation_covers` answers an AUTHORIZATION
 * question -- may this grantee act -- and must say no for a withdrawn
 * entry. This answers a REPLICATION question -- do I still need to fetch
 * this pair from a peer -- and must say yes, because the history is here
 * and fetching it again achieves nothing.
 *
 * Reading one as the other loops. A deficit computed with `covers` would
 * report every withdrawn pair as missing, the consumer would fetch the
 * revocation, admission would recognise the stale copy and store nothing,
 * and the deficit would report it missing again on the next comparison,
 * for ever, against every peer that had not heard the withdrawal. */
int fzn_revocation_known(const fzn_revocation_store_t *store,
                          const uint8_t issuer[FZN_PUBKEY_LEN],
                          const fzn_cap_id_t *capability,
                          const uint8_t grantee[FZN_PUBKEY_LEN])
{
	if (!store)
		return 0;
	/* A store that cannot be scanned may hold this triple, and the safe
	 * answer to "do I need to fetch it" is the one that does NOT generate
	 * traffic against a store nobody can read -- the opposite polarity to
	 * `fzn_revocation_covers`, and for the same kind of reason. */
	if (corrupt(store))
		return 1;
	if (!store->entries || !issuer || !capability || !grantee)
		return 0;

	return find_entry(store, issuer, capability, grantee) < store->used;
}

void fzn_revocation_covers_chain(const fzn_revocation_store_t *store,
                                  const fzn_chain_hop_t *hops, size_t hop_count,
                                  const fzn_cap_id_t *capability,
                                  uint8_t revoked[FZN_CHAIN_MAX_HOPS])
{
	/* Nowhere to put an answer. Checked first because everything below
	 * writes. */
	if (!revoked)
		return;

	/* Cleared before any decision, so that a caller reading a position it
	 * did not ask about reads 0 rather than whatever its stack held. */
	for (size_t i = 0; i < (size_t)FZN_CHAIN_MAX_HOPS; i++)
		revoked[i] = 0;

	/* An absent store is an answer and not a missing one -- the same
	 * contract `fzn_revocation_covers` states, and the one
	 * `fzn_chain_verify` rests on when a consumer holding no revocations
	 * passes NULL. */
	if (!store)
		return;

	/* THE STORE'S INTEGRITY IS JUDGED BEFORE THE QUESTION IS, and denying
	 * means denying EVERY hop: entries that cannot be scanned may hold the
	 * answer for any of them. Asked before the operands, so that nothing
	 * gets a "no" out of a store nobody can read. */
	if (corrupt(store)) {
		for (size_t i = 0; i < (size_t)FZN_CHAIN_MAX_HOPS; i++)
			revoked[i] = 1;
		return;
	}

	/* A question with no subject, permitted for the reason the sibling
	 * function argues at length: there is no chain and no capability to
	 * match, so no entry in this store or any other names one, and 0 is
	 * the literal truth rather than a permission being granted. A caller
	 * bug should look like a caller bug -- and `fzn_chain_verify` refuses
	 * each of these itself, with its own error, before ever asking. */
	if (!store->entries || !hops || !capability)
		return;
	if (hop_count == 0 || hop_count > (size_t)FZN_CHAIN_MAX_HOPS)
		return;

	/* HOISTED, AND THE NAIVE FORM IS THE OBVIOUS ONE. Asking per hop about
	 * every ancestor of that hop is O(hops^2) queries over a store of R
	 * entries -- O(hops^2 * R) -- because each query scans the whole
	 * store. Turned inside out, each entry names ONE issuer, so the entry
	 * is placed once: find the smallest `j` whose grantor is that issuer,
	 * and the entry then applies to every hop from `j` onward. One pass
	 * over the store, two bounded walks of the chain inside it, which is
	 * O(R * hops) -- the cost the single-issuer loop this replaced already
	 * paid. */
	for (size_t e = 0; e < store->used; e++) {
		const fzn_revocation_t *entry = &store->entries[e];
		size_t first = hop_count;

		/* A WITHDRAWN ENTRY REVOKES NOTHING, the same rule
		 * `fzn_revocation_covers` applies one question over. Both
		 * functions read this store to answer an authorization
		 * question and both must read the action rather than the
		 * presence; a walk that skipped this would keep a restored
		 * host locked out of every chain it appears in while the
		 * single-triple query said it was fine. */
		if (entry->withdrawn)
			continue;

		/* THE SMALLEST j, NOT ANY j, and the difference is the whole
		 * of the entitlement rule. An issuer that grants at hop `j` is
		 * an ancestor of every hop after it and of NOTHING BEFORE IT:
		 * a key deep in one branch must not be able to withdraw the
		 * root's own grant at hop 0. Smallest, because a key may
		 * legitimately appear more than once and its earliest
		 * appearance is where its authority starts. */
		for (size_t j = 0; j < hop_count; j++) {
			if (fzn_ct_memeq(fzn_hop_grantor(hops[j]), entry->issuer,
			                 FZN_PUBKEY_LEN)) {
				first = j;
				break;
			}
		}
		if (first == hop_count)
			continue;

		/* Asked once per entry rather than once per hop, which is what
		 * the hoisting buys. Every hop of a chain that reaches here
		 * names `capability` -- `fzn_chain_verify` refuses one that
		 * does not, hop by hop, before it reads this array -- so the
		 * caller's capability and each hop's own are the same value.
		 *
		 * Asked on the TRIPLE rather than on the key alone. The two
		 * consumers' capabilities are independent rather than a ladder
		 * (project.md sec 4.2): withdrawing netcfgd's `wifi` from a
		 * host must not withdraw its `observe`. */
		if (!fzn_ct_memeq(entry->capability.b, capability->b, FZN_CAP_ID_LEN))
			continue;

		/* Every hop from `first` on, not only the last. Revoking a
		 * host in the middle has to kill what it went on to grant, or
		 * revocation would be defeated by the victim having delegated
		 * onward first -- which is precisely what a stolen device
		 * would do. */
		for (size_t i = first; i < hop_count; i++) {
			if (fzn_ct_memeq(entry->grantee, fzn_hop_grantee(hops[i]),
			                 FZN_PUBKEY_LEN))
				revoked[i] = 1;
		}
	}
}

/* THE ADMISSION BOUND FOR A KEY THAT IS NOT THE ROOT. See revocation.h for
 * why this is a resource decision rather than an authorization one, and
 * project.md sec 13c for the reasoning it was built from.
 *
 * Split out so that the two invariants below are one place each rather than
 * two arguments buried in a longer function. Both are invisible when broken:
 * the suite still passes, and what changes is whether a store's contents
 * depend on the order things arrived in. */
static fzn_chain_err_t entitled_by_chain(fzn_revocation_offer_t offer,
                                         const uint8_t root[FZN_PUBKEY_LEN],
                                         const fzn_sign_ops_t *sign)
{
	fzn_chain_t issuers;
	fzn_chain_err_t err;

	/* A chain already at the ceiling has no room for the hop that would
	 * make its grantee an ancestor of anything, so nothing this key
	 * revokes could ever be honoured -- the same waste the `delegable`
	 * term below excludes, and the same refusal `fzn_chain_delegate`
	 * makes with the same code. Bounded before a signature is spent. */
	if (offer.hop_count >= (size_t)FZN_CHAIN_MAX_HOPS)
		return FZN_CHAIN_ERR_MALFORMED;

	/* THE TWO NUMBERS THAT ARE NOT PARAMETERS, AND THEY ARE THE INVARIANTS.
	 *
	 * `revocations = NULL` -- ADMISSION IS REVOCATION-BLIND. Handing this
	 * the caller's store would make admitting the root's withdrawal from
	 * H1 first turn H1's own earlier revocation away, so what a host ends
	 * up holding would depend on the order two peers told it things. That
	 * destroys the CRDT project.md sec 13b preserved: revocation is
	 * monotone and merge is set union only while nothing in admission can
	 * look at what has already been merged.
	 *
	 * `now = 0` -- ADMISSION IS CLOCK-BLIND, and this function takes no
	 * clock so that no caller can supply one. Refusing a revocation
	 * because the REVOKER'S OWN grant had lapsed would silently
	 * re-connect a revoked device, which is the one direction this module
	 * must never fail in.
	 *
	 * ZERO IS A MAGIC VALUE HERE AND IT IS DOING REAL WORK. `fzn_chain_verify`
	 * reads a hop's expiry as `if (expires_at != FZN_NO_EXPIRY) { ... if
	 * (expires_at <= now) return FZN_CHAIN_ERR_EXPIRED; }`, and
	 * FZN_NO_EXPIRY IS 0 -- so the only `expires_at` that could satisfy
	 * `<= 0` is the one the outer test has already excluded. At `now = 0`
	 * no hop can be expired, whatever it says, and that is what makes this
	 * a clock-blind verification rather than a verification at the dawn of
	 * time. If FZN_NO_EXPIRY ever stopped being zero, this line would
	 * start expiring grants and the failure would be a device quietly
	 * un-revoking itself. chain/test/revocation_test.c pins it. */
	err = fzn_chain_verify(offer.hops, offer.hop_count, root,
	                       fzn_revocation_capability(offer.record), 0, sign, NULL,
	                       &issuers);
	if (err != FZN_CHAIN_OK)
		return err;

	/* THE CHAIN HAS TO BE THIS ISSUER'S. Without this any key could
	 * present somebody else's perfectly good chain and revoke under it --
	 * the capability and the root would check out and the record would be
	 * signed by a key the chain never mentions. */
	if (!fzn_ct_memeq(issuers.grantee, fzn_revocation_issuer(offer.record), FZN_PUBKEY_LEN))
		return FZN_CHAIN_ERR_CHAIN_INVALID;

	/* Holding is not entitlement to hand out, and revoking a descendant is
	 * the inverse of granting one. `fzn_chain_delegate` makes exactly this
	 * refusal with exactly this code, which is the point: admit a
	 * revocation from a key if and only if delegate would let that key
	 * grant the thing it is withdrawing. */
	if (!fzn_hop_delegable(offer.hops[offer.hop_count - 1]))
		return FZN_CHAIN_ERR_NOT_DELEGABLE;

	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_revocation_admit(fzn_revocation_store_t *store,
                                fzn_revocation_offer_t offer,
                                const uint8_t root[FZN_PUBKEY_LEN],
                                const fzn_sign_ops_t *sign,
                                const fzn_hash_ops_t *hash,
                                fzn_manifest_state_t *manifest)
{
	fzn_revocation_record_t record = offer.record;
	const uint8_t *msg;
	uint8_t id[FZN_REVOCATION_ID_LEN];
	size_t msg_len;
	size_t at;

	if (!store || !store->entries || !root || !sign || !sign->verify)
		return FZN_CHAIN_ERR_MALFORMED;
	if (!hash || !hash->hash)
		return FZN_CHAIN_ERR_MALFORMED;
	/* A view that was never opened. MALFORMED rather than SHAPE for the
	 * reason chain.h gives: no bytes were wrong, the caller skipped
	 * `fzn_revocation_open`. */
	if (!record.base)
		return FZN_CHAIN_ERR_MALFORMED;
	/* A chain that was named and not supplied. The mirror of the offer
	 * constructors in revocation.h: `hop_count == 0` with a stale `hops`
	 * is harmless, and a count without an array is a read through a
	 * pointer nobody set. */
	if (offer.hop_count > 0 && !offer.hops)
		return FZN_CHAIN_ERR_MALFORMED;

	/* THE ROOT NEEDS NO STANDING -- it is the pin. Checked before the
	 * signature, because a record claiming to be the root's and issued by
	 * somebody else is refused whatever it is signed with, and verifying
	 * first would spend the expensive operation on something already
	 * decided. This is every admission this library performed before
	 * 2026-08-28, unchanged, and `hop_count == 0` is how a caller asks for
	 * it. */
	if (offer.hop_count == 0 &&
	    !fzn_ct_memeq(fzn_revocation_issuer(record), root, FZN_PUBKEY_LEN))
		return FZN_CHAIN_ERR_WRONG_ROOT;

	fzn_revocation_signed_bytes(record, &msg, &msg_len);
	if (!sign->verify(sign->ctx, fzn_revocation_issuer(record), msg, msg_len,
	                  fzn_revocation_signature(record)))
		return FZN_CHAIN_ERR_CHAIN_INVALID;

	/* THE EXPENSIVE HALF OF THE BOUND, AND IT SITS BELOW THE RECORD'S OWN
	 * SIGNATURE DELIBERATELY. A chain may carry FZN_CHAIN_MAX_HOPS - 1
	 * hops, so checking standing first would let one unsigned scrap of
	 * bytes with a long chain stapled to it buy seven signature
	 * verifications. One gate of one verification stands in front of it,
	 * and only a record somebody really signed reaches the walk.
	 *
	 * The root path above pays nothing for this ordering: its check is a
	 * comparison and still happens first. */
	if (offer.hop_count > 0) {
		fzn_chain_err_t err = entitled_by_chain(offer, root, sign);

		if (err != FZN_CHAIN_OK)
			return err;
	}

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
	 * the system behaving correctly.
	 *
	 * IT IS ASKED BELOW THE CHAIN WALK AND NOT ABOVE IT, WHICH LOOKS LIKE
	 * WASTE AND IS THE THIRD INVARIANT. Moving it up would skip the walk
	 * for anything already held -- free, obviously correct, and it turns
	 * the store into a cache of "this issuer checked out once". What a
	 * host then answers about a record depends on whether it happened to
	 * see that record before, which is the order dependence the other two
	 * invariants exist to prevent, arrived at from the third side. Every
	 * non-root admission carries its chain, every time. */
	/* THE RECORD'S IDENTITY, COMPUTED FROM THE BYTES THAT WERE SIGNED
	 * ABOVE and not from anything a caller supplied beside them -- the
	 * rule this module was rewritten around, applied to the one field
	 * that is new. Computed after the signature so a forged record never
	 * reaches the hash seam. */
	if (!hash->hash(hash->ctx, id, sizeof(id), record.base, FZN_REVOCATION_LEN))
		return FZN_CHAIN_ERR_MALFORMED;

	at = find_entry(store, fzn_revocation_issuer(record),
	                fzn_revocation_capability(record), fzn_revocation_grantee(record));

	/* A WITHDRAWAL FOR A TRIPLE THIS STORE HAS NEVER HELD IS STORED AS A
	 * TOMBSTONE, and this refused it until 2026-09-03.
	 *
	 * THE ORDERING IT FORCED IS NOT AN EDGE CASE. Refusing meant the
	 * withdrawal had to arrive after the revocation it undoes; if it
	 * arrived first it was dropped, the revocation then landed, and the
	 * host stayed revoked until somebody re-sent the withdrawal. On a mesh
	 * the withdrawal arriving first is simply what happens whenever the
	 * withdrawing host has a shorter path to a peer than the revoking host
	 * did. Reported by fuzzypickles, whose store keeps the unmatched
	 * record for exactly this reason.
	 *
	 * Stored, the sequence needs no ordering at all: the tombstone names
	 * one revocation by hash, that revocation arrives, its own hash
	 * matches, and it is refused below as the stale copy it is. The host
	 * never becomes revoked and never has to be un-revoked.
	 *
	 * IT IS NOT A BLANK CHEQUE, AND THE ASYMMETRY IS DELIBERATE ON BOTH
	 * SIDES. A tombstone names ONE record; only that exact revocation is
	 * refused, and a genuinely new revocation of the same pair is a
	 * different record with a different hash and applies normally.
	 * MINTING a withdrawal is the side that must be strict --
	 * `fzn_revocation_issue_withdrawal` refuses an all-zero target,
	 * because a withdrawal naming nothing could never be matched against
	 * anything later and WOULD pre-authorise the next revocation anybody
	 * issues. Two rules on one field, kept apart on purpose: somebody will
	 * otherwise simplify them into one.
	 *
	 * A MISMATCH AGAINST A HELD ENTRY IS STILL REFUSED, which is where
	 * this stops short of fuzzypickles' rule and does so knowingly. They
	 * hold one record per pair and a withdrawal overwrites it; this store
	 * tracks the chain in `id`, so a withdrawal naming something other
	 * than what is held is a withdrawal of a revocation that has already
	 * been superseded, and applying it would restore the pair on the
	 * authority of a record answering a different question.
	 *
	 * THE TWO ERRORS POINT OPPOSITE WAYS, which is what settles it.
	 * Accepting a mismatched withdrawal FAILS OPEN: a pair is restored on
	 * a record that withdrew something else, and a revoked host is
	 * authorised again. Refusing it fails CLOSED: a withdrawal that
	 * overtook a reissue is dropped and the pair stays revoked until the
	 * withdrawal is re-sent. The second is an outage and the first is a
	 * hole, so the second is the one to take -- and the cost is narrower
	 * than what was dropped before this branch existed, which was every
	 * withdrawal that overtook a FIRST revocation. */
	if (fzn_revocation_is_withdrawal(record)) {
		if (at == store->used) {
			if (store->used >= store->capacity)
				return FZN_CHAIN_ERR_STORE_FULL;
			store->entries[store->used].capability =
			        *fzn_revocation_capability(record);
			memcpy(store->entries[store->used].grantee,
			       fzn_revocation_grantee(record), FZN_PUBKEY_LEN);
			memcpy(store->entries[store->used].issuer,
			       fzn_revocation_issuer(record), FZN_PUBKEY_LEN);
			/* `id` is what the withdrawal NAMES, which is the same
			 * invariant a withdrawn entry always carries: the hash
			 * of the most recent revocation for this triple. The
			 * tombstone is not a special kind of entry. */
			memcpy(store->entries[store->used].id,
			       fzn_revocation_supersedes(record), FZN_REVOCATION_ID_LEN);
			store->entries[store->used].withdrawn = 1;
			store->used++;
			return FZN_CHAIN_OK;
		}
		if (!fzn_ct_memeq(store->entries[at].id, fzn_revocation_supersedes(record),
		                  FZN_REVOCATION_ID_LEN))
			return FZN_CHAIN_ERR_UNKNOWN_TARGET;
		/* Idempotent: a second copy of the same withdrawal is what
		 * "carried on contact" looks like when it works, exactly as
		 * for a second copy of a revocation. `id` is unchanged --
		 * it still names the revocation that was undone, which is
		 * what a later reissue must supersede. */
		store->entries[at].withdrawn = 1;
		return FZN_CHAIN_OK;
	}

	if (at < store->used) {
		fzn_revocation_t *entry = &store->entries[at];

		if (entry->withdrawn) {
			/* THE STALE COPY, AND IT IS RECOGNISED BY THE ARRIVING
			 * RECORD'S OWN IDENTITY rather than by anything it
			 * says about itself.
			 *
			 * A peer that has not heard the withdrawal relays the
			 * revocation again, and it will keep doing so; every
			 * peer that has not heard it does the same. Comparing
			 * the arriving record's hash against what we hold
			 * refuses it without needing the record to be honest
			 * about its own place in the sequence -- which is why
			 * this must NOT read `supersedes` here. That rule is
			 * fuzzypickles', from running it.
			 *
			 * Ignored rather than refused: nothing is wrong, a
			 * peer is behind. Reporting an error would make an
			 * alarm out of the network converging. */
			if (fzn_ct_memeq(id, entry->id, FZN_REVOCATION_ID_LEN))
				return FZN_CHAIN_OK;

			/* A GENUINELY NEW REVOCATION OVER A WITHDRAWAL MUST
			 * CHAIN TO IT. This is where the rule lives: minting
			 * with `fzn_revocation_issue` writes a zero
			 * `supersedes`, which cannot equal what we hold, so
			 * the un-chained re-revocation is refused here rather
			 * than warned about in a header. */
			if (!fzn_ct_memeq(fzn_revocation_supersedes(record), entry->id,
			                  FZN_REVOCATION_ID_LEN))
				return FZN_CHAIN_ERR_UNKNOWN_TARGET;

			entry->withdrawn = 0;
			memcpy(entry->id, id, FZN_REVOCATION_ID_LEN);
			fzn_manifest_satisfy(manifest, fzn_revocation_issuer(record),
			                     fzn_revocation_capability(record),
			                     fzn_revocation_grantee(record));
			return FZN_CHAIN_OK;
		}
	}

	if (at < store->used) {
		/* SETTLED HERE TOO, AND NOT ONLY WHERE SOMETHING IS STORED.
		 * A deficit entry can coexist with a stored revocation
		 * whenever the manifest was admitted against a different view
		 * of the store than this one -- NULL while a consumer was
		 * still wiring itself up, most obviously. From then on every
		 * arrival of that revocation takes this branch and no other,
		 * so a drain wired only to the storing path below would leave
		 * the host reporting for ever that it lacks something it
		 * holds. This is a set; the orders have to converge. */
		fzn_manifest_satisfy(manifest, fzn_revocation_issuer(record),
		                     fzn_revocation_capability(record),
		                     fzn_revocation_grantee(record));
		return FZN_CHAIN_OK;
	}

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
	store->entries[store->used].capability = *fzn_revocation_capability(record);
	memcpy(store->entries[store->used].grantee, fzn_revocation_grantee(record),
	       FZN_PUBKEY_LEN);
	memcpy(store->entries[store->used].issuer, fzn_revocation_issuer(record),
	       FZN_PUBKEY_LEN);
	/* The identity of the record just admitted, which is what a later
	 * withdrawal must target and what a later reissue must supersede.
	 * `withdrawn` is set explicitly rather than left to the caller's
	 * array: a store is caller-owned memory and an entry appended into a
	 * slot that happened to hold a nonzero byte here would be a revocation
	 * that answers "not revoked" from the moment it is stored. */
	memcpy(store->entries[store->used].id, id, FZN_REVOCATION_ID_LEN);
	store->entries[store->used].withdrawn = 0;
	store->used++;

	/* What a manifest said this host was missing, it now holds. NULL is
	 * the consumer that has not adopted the manifest, and this is the
	 * whole of what the parameter does. */
	fzn_manifest_satisfy(manifest, fzn_revocation_issuer(record),
	                     fzn_revocation_capability(record),
	                     fzn_revocation_grantee(record));

	return FZN_CHAIN_OK;
}

size_t fzn_revocation_merge(fzn_revocation_store_t *store,
                             const fzn_revocation_offer_t *offers, size_t count,
                             const uint8_t root[FZN_PUBKEY_LEN], const fzn_sign_ops_t *sign,
                             const fzn_hash_ops_t *hash,
                             fzn_chain_err_t *err, fzn_manifest_state_t *manifest)
{
	size_t admitted = 0;
	fzn_chain_err_t first = FZN_CHAIN_OK;

	if (!store || (count > 0 && !offers)) {
		if (err)
			*err = FZN_CHAIN_ERR_MALFORMED;
		return 0;
	}

	for (size_t i = 0; i < count; i++) {
		fzn_chain_err_t one =
		        fzn_revocation_admit(store, offers[i], root, sign, hash, manifest);

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
