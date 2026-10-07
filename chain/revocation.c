/* The revocation record and the store. See revocation.h. */

#include "revocation.h"

/* Diagnostics through flog, vendored and possibly absent. sec 209. */
#ifdef FZN_FLOG_ON
#include "flog.h"
#define REV_LOG(store, sub, sev, ...)                                                      \
	do {                                                                               \
		if ((store) && (store)->log)                                               \
			flog_printf((store)->log, sub, sev, FLOG_MSG_NONE, __VA_ARGS__);    \
	} while (0)
#else
#define REV_LOG(store, sub, sev, ...) ((void)0)
#endif

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
_Static_assert(FZN_REV_OFF_EPOCH == 138u, "revocation layout: epoch moved");
_Static_assert(FZN_REV_OFF_CUT == 146u, "revocation layout: cut moved");
_Static_assert(FZN_REV_OFF_SIGNATURE == 178u, "revocation layout: the signature moved");
_Static_assert(FZN_REVOCATION_BODY_LEN == 178u,
               "revocation layout: the signed body is not 178 bytes");
_Static_assert(FZN_REVOCATION_LEN == 242u,
               "revocation layout: a revocation is not 242 bytes");
/* THE FIELD IS INSIDE THE SIGNED RANGE, which is the whole of what makes it
 * worth anything. A supersedes a peer could rewrite in flight would let one
 * relay turn a chained re-revocation into an un-chained one, or point a
 * withdrawal at a different revocation than the issuer named. The body ends
 * at the signature, so asserting the field is below FZN_REV_OFF_SIGNATURE
 * says it is covered. */
_Static_assert(FZN_REV_OFF_SUPERSEDES + FZN_REVOCATION_ID_LEN == FZN_REV_OFF_EPOCH,
               "revocation layout: supersedes is not followed by the epoch");
/* THE EPOCH IS SIGNED TOO, sec 400: one a relay could rewrite would let it
 * move a withdrawal into an epoch its revocation was never in. */
_Static_assert(FZN_REV_OFF_EPOCH + 8u == FZN_REV_OFF_CUT,
               "revocation layout: the epoch is not followed by the cut");
/* AND THE CUT, sec 496: one a relay could widen would bring a thief's acts
 * back under a vote that drew the line before them. */
_Static_assert(FZN_REV_OFF_CUT + FZN_REVOCATION_ID_LEN == FZN_REV_OFF_SIGNATURE,
               "revocation layout: the cut is not the last signed field");


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
int fzn_revocation_store_sound(const fzn_revocation_store_t *store)
{
	if (!store)
		return 1;
	if (store->used > store->capacity)
		return 0;
	if (store->used > 0 && !store->entries)
		return 0;
	/* The k-of-n half (sec 397): an admin count past its array is a store
	 * whose answers cannot be computed. A quorum of 0 is not corrupt; it
	 * is a store initialised before the field existed, and reads as 1. */
	if (store->admins_used > store->admin_capacity
	    || (store->admins_used > 0u && !store->admins))
		return 0;
	/* The same for confirmations, sec 414. */
	if (store->confirms_used > store->confirm_capacity
	    || (store->confirms_used > 0u && !store->confirms))
		return 0;
	return 1;
}

/* The internal spelling, kept because every call site reads better as a
 * refusal. It is the public predicate negated and nothing else -- sec 183
 * moved the rule out so consumers could ask it too. */
static int corrupt(const fzn_revocation_store_t *store)
{
	return !fzn_revocation_store_sound(store);
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
	/* NOR MAY A WITHDRAWAL DRAW A LINE, sec 496: undoing a vote restores
	 * everything, and a cut on one would be a second meaning for one
	 * field that nothing reads. */
	if (bytes[FZN_REV_OFF_OBJECT] == (uint8_t)FZN_OBJECT_WITHDRAWAL &&
	    !all_zero(bytes + FZN_REV_OFF_CUT, FZN_REVOCATION_ID_LEN))
		return FZN_CHAIN_ERR_SHAPE;

	out->base = bytes;
	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_revocation_encode(uint8_t *out, uint8_t object,
                                      const uint8_t issuer[FZN_PUBKEY_LEN],
                                      const fzn_cap_id_t *capability,
                                      const uint8_t grantee[FZN_PUBKEY_LEN],
                                      uint64_t issued_at, uint64_t epoch,
                                      const uint8_t supersedes[FZN_REVOCATION_ID_LEN],
                                      const uint8_t cut[FZN_REVOCATION_ID_LEN])
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
	if (object == (uint8_t)FZN_OBJECT_WITHDRAWAL && cut && !all_zero(cut, FZN_REVOCATION_ID_LEN))
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
	fzn_put_be64(out + FZN_REV_OFF_EPOCH, epoch);
	if (cut)
		memcpy(out + FZN_REV_OFF_CUT, cut, FZN_REVOCATION_ID_LEN);
	else
		memset(out + FZN_REV_OFF_CUT, 0, FZN_REVOCATION_ID_LEN);
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
                            uint64_t epoch, const uint8_t supersedes[FZN_REVOCATION_ID_LEN],
                            const uint8_t cut[FZN_REVOCATION_ID_LEN],
                            const fzn_sign_ops_t *sign, uint8_t *out)
{
	fzn_chain_err_t err;
	fzn_revocation_record_t rec;
	const uint8_t *msg;
	size_t msg_len;

	if (!issuer || !capability || !grantee || !sign || !sign->sign || !out)
		return FZN_CHAIN_ERR_MALFORMED;

	err = fzn_revocation_encode(out, object, issuer, capability, grantee, issued_at, epoch,
	                            supersedes, cut);
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
                                     uint64_t epoch, const uint8_t cut[FZN_REVOCATION_ID_LEN],
                                     const fzn_sign_ops_t *sign, uint8_t *out)
{
	return mint((uint8_t)FZN_OBJECT_REVOCATION, issuer, capability, grantee, issued_at, epoch,
	            NULL, cut, sign, out);
}

fzn_chain_err_t fzn_revocation_reissue(const uint8_t issuer[FZN_PUBKEY_LEN],
                                       const fzn_cap_id_t *capability,
                                       const uint8_t grantee[FZN_PUBKEY_LEN],
                                       uint64_t issued_at, uint64_t epoch,
                                       const uint8_t supersedes[FZN_REVOCATION_ID_LEN],
                                       const uint8_t cut[FZN_REVOCATION_ID_LEN],
                                       const fzn_sign_ops_t *sign, uint8_t *out)
{
	/* A reissue naming nothing is `fzn_revocation_issue` spelled the long
	 * way, and a caller reaching for this one believes it is chaining. */
	if (!supersedes || all_zero(supersedes, FZN_REVOCATION_ID_LEN))
		return FZN_CHAIN_ERR_MALFORMED;
	return mint((uint8_t)FZN_OBJECT_REVOCATION, issuer, capability, grantee, issued_at, epoch,
	            supersedes, cut, sign, out);
}

fzn_chain_err_t fzn_revocation_issue_withdrawal(const uint8_t issuer[FZN_PUBKEY_LEN],
                                                const fzn_cap_id_t *capability,
                                                const uint8_t grantee[FZN_PUBKEY_LEN],
                                                uint64_t issued_at, uint64_t epoch,
                                                const uint8_t target[FZN_REVOCATION_ID_LEN],
                                                const fzn_sign_ops_t *sign, uint8_t *out)
{
	return mint((uint8_t)FZN_OBJECT_WITHDRAWAL, issuer, capability, grantee, issued_at, epoch,
	            target, NULL, sign, out);
}

void fzn_revocation_store_set_log(fzn_revocation_store_t *store, struct flog_t *log)
{
	if (!store)
		return;

	store->log = log;
}

fzn_chain_err_t fzn_revocation_store_init(fzn_revocation_store_t *store, fzn_revocation_t *entries,
                                     size_t capacity)
{
	if (!store || !entries || capacity == 0)
		return FZN_CHAIN_ERR_MALFORMED;

	store->entries = entries;
	store->capacity = capacity;
	store->used = 0;
	/* ONE, not zero: a memo entry left zero by memset must never match a
	 * live generation. sec 354. */
	store->generation = 1;
	/* Quiet unless somebody asks. */
	store->log = NULL;
	/* ONE ISSUER REVOKES, and no admins: every answer as before sec 397. */
	store->quorum = 1u;
	store->has_admin = 0;
	memset(&store->admin_capability, 0, sizeof(store->admin_capability));
	store->admins = NULL;
	store->admin_capacity = 0;
	store->admins_used = 0;
	/* One root, the one each call names: sec 406's set is opt-in. */
	store->roots = NULL;
	store->root_hash = NULL;
	/* No confirmations kept: every admin grant counts, sec 414. */
	store->confirms = NULL;
	store->confirm_capacity = 0;
	store->confirms_used = 0;
	store->confirm_hash = NULL;
	/* No act log: nothing a revoked key did stands, sec 496. */
	store->acts = NULL;

	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_revocation_store_set_confirmations(fzn_revocation_store_t *store,
                                                       fzn_revocation_confirm_t *table,
                                                       size_t capacity,
                                                       const fzn_hash_ops_t *hash)
{
	/* BEFORE ANY ADMIN: an admin's hop ids are taken as it is admitted,
	 * and one admitted without them could never be confirmed. */
	if (!store || !table || capacity == 0u || !hash || !hash->hash || store->admins_used)
		return FZN_CHAIN_ERR_MALFORMED;
	store->confirms = table;
	store->confirm_capacity = capacity;
	store->confirms_used = 0;
	store->confirm_hash = hash;
	store->generation++;
	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_admin_confirm_issue(const uint8_t confirmer[FZN_PUBKEY_LEN],
                                        const uint8_t grant[FZN_REVOCATION_ID_LEN],
                                        const fzn_sign_ops_t *sign, uint8_t *out)
{
	if (!confirmer || !grant || !sign || !sign->sign || !out)
		return FZN_CHAIN_ERR_MALFORMED;
	out[0] = (uint8_t)FZN_SIGNED_VERSION;
	out[1] = (uint8_t)FZN_OBJECT_ADMIN_CONFIRM;
	memcpy(out + FZN_ADMIN_CONFIRM_OFF_CONFIRMER, confirmer, FZN_PUBKEY_LEN);
	memcpy(out + FZN_ADMIN_CONFIRM_OFF_GRANT, grant, FZN_REVOCATION_ID_LEN);
	if (!sign->sign(sign->ctx, out + FZN_ADMIN_CONFIRM_BODY_LEN, out,
	                FZN_ADMIN_CONFIRM_BODY_LEN))
		return FZN_CHAIN_ERR_CHAIN_INVALID;
	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_revocation_store_set_roots(fzn_revocation_store_t *store,
                                               const fzn_root_ops_t *roots,
                                               const fzn_hash_ops_t *hash)
{
	if (!store)
		return FZN_CHAIN_ERR_MALFORMED;
	if (roots && (!roots->member || !roots->counts || !hash || !hash->hash))
		return FZN_CHAIN_ERR_MALFORMED;
	store->roots = roots;
	store->root_hash = roots ? hash : NULL;
	store->generation++;
	return FZN_CHAIN_OK;
}

/* The most admins a store judges: the second stratum needs a flag per admin
 * and this library allocates nothing, so the flags live on the stack. A
 * user's estate has a handful. */
#define REVOCATION_ADMINS_MAX 32u

fzn_chain_err_t fzn_revocation_store_set_k(fzn_revocation_store_t *store, size_t quorum)
{
	if (!store || quorum == 0u)
		return FZN_CHAIN_ERR_MALFORMED;
	if (store->quorum != quorum) {
		store->quorum = quorum;
		store->generation++;
	}
	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_revocation_store_set_quorum(fzn_revocation_store_t *store, size_t quorum,
                                                const fzn_cap_id_t *admin_capability,
                                                fzn_revocation_admin_t *admins,
                                                size_t admin_capacity)
{
	if (!store || quorum == 0u)
		return FZN_CHAIN_ERR_MALFORMED;
	if (admin_capability && (!admins || admin_capacity == 0u
	                         || admin_capacity > REVOCATION_ADMINS_MAX))
		return FZN_CHAIN_ERR_MALFORMED;
	store->quorum = quorum;
	store->has_admin = admin_capability != NULL;
	if (admin_capability)
		store->admin_capability = *admin_capability;
	store->admins = admin_capability ? admins : NULL;
	store->admin_capacity = admin_capability ? admin_capacity : 0u;
	store->admins_used = 0;
	store->generation++;
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
int fzn_revocation_lookup(const fzn_revocation_store_t *store,
                           const uint8_t issuer[FZN_PUBKEY_LEN],
                           const fzn_cap_id_t *capability,
                           const uint8_t grantee[FZN_PUBKEY_LEN],
                           uint8_t id_out[FZN_REVOCATION_ID_LEN], int *withdrawn_out)
{
	size_t at;

	if (!store || !id_out || !withdrawn_out)
		return 0;
	/* A store that cannot be scanned reports nothing rather than
	 * guessing. Unlike the two predicates above there is no conservative
	 * answer available here: the outputs would have to be invented, and a
	 * caller comparing views against invented state is worse off than one
	 * told nothing. `chain/manifest.c` judges soundness itself before it
	 * asks. */
	if (corrupt(store))
		return 0;
	if (!store->entries || !issuer || !capability || !grantee)
		return 0;

	at = find_entry(store, issuer, capability, grantee);
	if (at == store->used)
		return 0;

	memcpy(id_out, store->entries[at].id, FZN_REVOCATION_ID_LEN);
	*withdrawn_out = store->entries[at].withdrawn;
	return 1;
}

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

/* The admin-table slot for `key`, or `admins_used` for none. */
static size_t find_admin(const fzn_revocation_store_t *store, const uint8_t *key)
{
	size_t a;

	for (a = 0; a < store->admins_used; a++)
		if (fzn_ct_memeq(store->admins[a].key, key, FZN_PUBKEY_LEN))
			break;
	return a;
}

/* WHICH ENTRIES A HOP COUNTS: those naming its capability and grantee, from
 * an issuer entitled to revoke it -- the root or an ancestor, the grantor of
 * hop `j` for some `j <= i`, the smallest-j rule sec 13c settled -- or an
 * admin `admin_ok` lets count (NULL: every admin). With `any_issuer` every
 * issuer counts, which is the question a host asks before casting its own
 * vote rather than when judging a chain. */
struct hop_question {
	const uint8_t (*grantors)[FZN_PUBKEY_LEN];
	const uint8_t (*grantees)[FZN_PUBKEY_LEN];
	size_t i, hop_count;
	const fzn_cap_id_t *capability;
	const uint8_t *admin_ok;
	int any_issuer;
	/* THE ROOT'S PASS, sec 403: once the root's own entry has been read,
	 * the rest of the rule counts no vote cast in an epoch the root has
	 * undone (`floor`). The root's own withdrawn entry sits at the floor,
	 * so it is excluded with them. */
	int has_floor;
	uint64_t floor;
};

/* WHETHER AN ENTRY IS A ROOT'S THAT COUNTS. With a root set, sec 406: a
 * member root whose record the set says still counts -- the record held now,
 * so a removed root's withdrawal after its cut counts no more than its
 * revocation would. Without one: the root this question names. */
static int root_entry(const fzn_revocation_store_t *store, const fzn_revocation_t *entry,
                      const uint8_t *root_key)
{
	if (store->roots)
		return store->roots->member(store->roots->ctx, entry->issuer)
		       && store->roots->counts(store->roots->ctx, entry->issuer, entry->held);
	return root_key && fzn_ct_memeq(entry->issuer, root_key, FZN_PUBKEY_LEN);
}

static int counts(const fzn_revocation_store_t *store, const fzn_revocation_t *entry,
                  const struct hop_question *h)
{
	size_t j;

	if (!fzn_ct_memeq(entry->capability.b, h->capability->b, FZN_CAP_ID_LEN)
	    || !fzn_ct_memeq(entry->grantee, h->grantees[h->i], FZN_PUBKEY_LEN))
		return 0;
	if (h->has_floor && entry->epoch <= h->floor)
		return 0;
	/* EVERY ISSUER, BUT NOT AN ADMIN WHO DOES NOT STAND, sec 481: an
	 * unconfirmed or revoked admin's votes count for nothing, and counted
	 * here they could close an epoch the admins who stand are still
	 * voting in -- numbering the next vote past theirs, so the two never
	 * meet and a stolen key is never revoked. A root is never this. */
	if (h->any_issuer) {
		if (h->admin_ok && store->has_admin
		    && !(store->roots && store->roots->member(store->roots->ctx, entry->issuer))) {
			size_t a = find_admin(store, entry->issuer);

			if (a < store->admins_used && !h->admin_ok[a])
				return 0;
		}
		return 1;
	}
	/* A ROOT IS ENTITLED OVER EVERY HOP, sec 406: the set decides whether
	 * its record counts, ancestor or not. */
	if (store->roots && store->roots->member(store->roots->ctx, entry->issuer))
		return root_entry(store, entry, NULL);
	for (j = 0; j <= h->i; j++)
		if (fzn_ct_memeq(h->grantors[j], entry->issuer, FZN_PUBKEY_LEN))
			return 1;
	if (store->has_admin) {
		size_t a = find_admin(store, entry->issuer);

		return a < store->admins_used && (!h->admin_ok || h->admin_ok[a]);
	}
	return 0;
}

/* AN EPOCH IS CLOSED when `q` counted issuers have left it: withdrawn in it,
 * or cast a vote in a later one. One issuer counts once, whatever epoch it
 * names, which is why an issuer signing UINT64_MAX closes nothing alone. */
static int epoch_closed(const fzn_revocation_store_t *store, const struct hop_question *h,
                        uint64_t epoch, size_t q)
{
	size_t e, left = 0;

	for (e = 0; e < store->used; e++) {
		const fzn_revocation_t *entry = &store->entries[e];

		if (counts(store, entry, h)
		    && (entry->epoch > epoch || (entry->epoch == epoch && entry->withdrawn)))
			left++;
	}
	return left >= q;
}

/* THE LOWEST EPOCH NOT CLOSED. Closure depends only on how many counted
 * issuers sit at or past an epoch, which is constant between the epochs
 * entries name, so the answer is 0, an epoch some entry names, or one past
 * it; those are the only candidates asked. */
static uint64_t open_epoch(const fzn_revocation_store_t *store, const struct hop_question *h,
                           size_t q)
{
	uint64_t first = 0, best;
	int have;
	size_t e, k;

	/* Past the root's undo, if there is one: the epochs up to it are
	 * settled by the root and ask nothing of anybody. */
	if (h->has_floor) {
		if (h->floor == UINT64_MAX)
			return UINT64_MAX;
		first = h->floor + 1u;
	}
	best = first;
	have = !epoch_closed(store, h, first, q);

	for (e = 0; e < store->used; e++) {
		const fzn_revocation_t *entry = &store->entries[e];

		if (!counts(store, entry, h))
			continue;
		for (k = 0; k < 2u; k++) {
			uint64_t c = entry->epoch + (uint64_t)k;

			if (k == 1u && entry->epoch == UINT64_MAX)
				continue;
			if (c < first)
				continue;
			if ((!have || c < best) && !epoch_closed(store, h, c, q)) {
				best = c;
				have = 1;
			}
		}
	}
	return have ? best : UINT64_MAX;
}

/* THE ROOT'S PASS, sec 403. A root acts alone: its live revocation revokes
 * whatever anybody else holds, and its withdrawal in epoch E undoes the
 * decision in E -- every other vote cast in E or earlier stops counting, and
 * the next opens E + 1. 1 when the root's live revocation settles it; else
 * `h` is left excluding the root and anything its undo covers. */
static int root_pass(const fzn_revocation_store_t *store, struct hop_question *h,
                     const uint8_t *root_key)
{
	size_t e;

	h->has_floor = 0;
	h->floor = 0;
	if (!root_key && !store->roots)
		return 0;
	for (e = 0; e < store->used; e++) {
		const fzn_revocation_t *entry = &store->entries[e];

		if (!counts(store, entry, h) || !root_entry(store, entry, root_key))
			continue;
		if (!entry->withdrawn)
			return 1;
		if (!h->has_floor || entry->epoch > h->floor)
			h->floor = entry->epoch;
		h->has_floor = 1;
	}
	return 0;
}

/* THE RULE, one hop at a time, sec 397 and as corrected in sec 400.
 *
 * REVOKED while `quorum` counted issuers are live, whatever epochs they
 * name: a live vote always counts, which is what keeps an epoch from ever
 * making a device LESS revoked than its live votes say.
 *
 * LATCHED otherwise when, in the lowest epoch not closed, `quorum` issuers
 * cast votes and fewer than `quorum` of them have withdrawn. So once k have
 * withdrawn an epoch it is closed, and a vote cast afterwards opens the next
 * one and counts from one again -- the case sec 399 found one vote
 * re-revoking. At quorum 1 this is the old answer exactly: any live entry
 * revokes, and a latch at 1 is a live entry. */
/* HOW ONE HOP STANDS: free, revoked by the root's live vote or by live
 * votes, or held by the latch -- in which case `*current` is the epoch
 * holding it. `h->i` names the hop. */
enum hop_verdict { HOP_FREE = 0, HOP_ROOT, HOP_LIVE, HOP_LATCHED };

static enum hop_verdict judge_hop(const fzn_revocation_store_t *store, struct hop_question *h,
                                  const uint8_t *root_key, size_t q, uint64_t *current)
{
	size_t e, live = 0, total = 0, cast = 0, left = 0;
	uint64_t epoch;

	/* THE ROOT FIRST, sec 403: the chain's first grantor is the root it
	 * was verified from, and a root acts alone. */
	if (root_pass(store, h, root_key))
		return HOP_ROOT;
	for (e = 0; e < store->used; e++) {
		if (!counts(store, &store->entries[e], h))
			continue;
		total++;
		if (!store->entries[e].withdrawn)
			live++;
	}
	if (live >= q)
		return HOP_LIVE;
	/* No epoch can hold `q` votes when the whole store holds fewer, so the
	 * search below is only ever paid in a latch. */
	if (total < q)
		return HOP_FREE;
	epoch = open_epoch(store, h, q);
	for (e = 0; e < store->used; e++) {
		const fzn_revocation_t *entry = &store->entries[e];

		if (!counts(store, entry, h) || entry->epoch != epoch)
			continue;
		cast++;
		if (entry->withdrawn)
			left++;
	}
	if (cast >= q && left < q) {
		if (current)
			*current = epoch;
		return HOP_LATCHED;
	}
	return HOP_FREE;
}

static void judge_links(const fzn_revocation_store_t *store,
                        const uint8_t (*grantors)[FZN_PUBKEY_LEN],
                        const uint8_t (*grantees)[FZN_PUBKEY_LEN], size_t hop_count,
                        const fzn_cap_id_t *capability, const uint8_t *admin_ok,
                        uint8_t revoked[FZN_CHAIN_MAX_HOPS])
{
	size_t i, q = store->quorum ? store->quorum : 1u;
	struct hop_question h;

	h.grantors = grantors;
	h.grantees = grantees;
	h.hop_count = hop_count;
	h.capability = capability;
	h.admin_ok = admin_ok;
	h.any_issuer = 0;
	h.has_floor = 0;
	h.floor = 0;
	for (i = 0; i < hop_count; i++) {
		h.i = i;
		revoked[i] = judge_hop(store, &h, grantors[0], q, NULL) != HOP_FREE;
	}
}

static void standing_admins(const fzn_revocation_store_t *store,
                            uint8_t admin_ok[REVOCATION_ADMINS_MAX]);

uint64_t fzn_revocation_current_epoch(const fzn_revocation_store_t *store,
                                      const uint8_t root[FZN_PUBKEY_LEN],
                                      const fzn_cap_id_t *capability,
                                      const uint8_t grantee[FZN_PUBKEY_LEN])
{
	const uint8_t (*grantees)[FZN_PUBKEY_LEN] = (const uint8_t (*)[FZN_PUBKEY_LEN])grantee;
	uint8_t admin_ok[REVOCATION_ADMINS_MAX];
	struct hop_question h;

	if (!store || !capability || !grantee || corrupt(store) || !store->entries)
		return 0;
	h.grantors = NULL;
	h.grantees = grantees;
	h.i = 0;
	h.hop_count = 1u;
	h.capability = capability;
	/* WHICH ADMINS STAND, so one who does not cannot move the numbering.
	 * sec 481. */
	h.admin_ok = NULL;
	if (store->has_admin && store->admins_used) {
		standing_admins(store, admin_ok);
		h.admin_ok = admin_ok;
	}
	h.any_issuer = 1;
	/* A root's live revocation settles nothing about epochs; its undo
	 * moves the next vote past it. */
	(void)root_pass(store, &h, root);
	return open_epoch(store, &h, store->quorum ? store->quorum : 1u);
}

/* WHETHER `key` CONFIRMS AS A ROOT for an admin whose chain starts at
 * `first`: the chain's own root, or with a root set a member whose
 * confirmation `act` the set says counts. sec 414. */
static int root_confirms(const fzn_revocation_store_t *store, const uint8_t *key,
                         const uint8_t *first, const uint8_t *act)
{
	if (store->roots)
		return store->roots->member(store->roots->ctx, key)
		       && store->roots->counts(store->roots->ctx, key, act);
	return fzn_ct_memeq(key, first, FZN_PUBKEY_LEN);
}

/* WHETHER AN ADMIN'S CHAIN STILL STARTS AT A ROOT THAT COUNTS, sec 417: with
 * a root set, its first hop must count under its root's cut, as a chain's
 * does for `fzn_chain_verify` and a roster writer's for the roster. Without
 * a set, the pin it was verified under, which no removal reaches. */
static int admin_rooted(const fzn_revocation_store_t *store, const fzn_revocation_admin_t *ad)
{
	if (!store->roots || ad->hop_count == 0u)
		return 1;
	return store->roots->counts(store->roots->ctx, ad->grantor[0], ad->first_act);
}

/* WHICH ADMINS' GRANTS ARE CONFIRMED, sec 414: the least set closed under
 * "every hop of my chain a non-root granted has k - 1 confirmations from
 * other confirmed admins, or one from a root". Admins `eligible` does not
 * name (NULL: all) confirm nothing. Settled in rounds from nothing, so two
 * admins cannot confirm each other in, and arrival order decides nothing.
 * With no confirmations kept, or k = 1, every admin is confirmed. */
static void confirm_admins(const fzn_revocation_store_t *store, const uint8_t *eligible,
                           uint8_t confirmed[REVOCATION_ADMINS_MAX])
{
	size_t need = (store->quorum ? store->quorum : 1u) - 1u;
	size_t a, h, c, j, round;
	int changed;

	/* AN ADMIN WHOSE ROOT'S GRANT NO LONGER COUNTS is confirmed by nothing,
	 * and so confirms nothing either. sec 417. */
	for (a = 0; a < store->admins_used; a++)
		confirmed[a] = ((!store->confirm_hash || need == 0u)
		                && admin_rooted(store, &store->admins[a])) ? 1u : 0u;
	if (!store->confirm_hash || need == 0u)
		return;
	for (round = 0, changed = 1; changed && round <= store->admins_used; round++) {
		changed = 0;
		for (a = 0; a < store->admins_used; a++) {
			const fzn_revocation_admin_t *ad = &store->admins[a];
			int all = 1;

			if (confirmed[a] || !admin_rooted(store, ad))
				continue;
			/* HOP 0 IS THE ROOT'S, and a hop its own root granted again
			 * is the same authority. */
			for (h = 1; h < ad->hop_count && all; h++) {
				const uint8_t *seen[REVOCATION_ADMINS_MAX];
				size_t count = 0;
				int by_root = 0;

				if (fzn_ct_memeq(ad->grantor[h], ad->grantor[0], FZN_PUBKEY_LEN)
				    || (store->roots
				        && store->roots->member(store->roots->ctx, ad->grantor[h])))
					continue;
				for (c = 0; c < store->confirms_used && !by_root && count < need; c++) {
					const fzn_revocation_confirm_t *cf = &store->confirms[c];
					size_t b;

					/* NOT ITS GRANTOR. Its grantee needs no clause:
					 * one row per key, and a confirmer must stand, so
					 * a grantee counts here only once this hop stood
					 * without it -- measured, the clause's sabotage
					 * survived. */
					if (!fzn_ct_memeq(cf->grant, ad->hop_id[h], FZN_REVOCATION_ID_LEN)
					    || fzn_ct_memeq(cf->confirmer, ad->grantor[h], FZN_PUBKEY_LEN))
						continue;
					if (root_confirms(store, cf->confirmer, ad->grantor[0], cf->act)) {
						by_root = 1;
						continue;
					}
					b = find_admin(store, cf->confirmer);
					if (b >= store->admins_used || !confirmed[b]
					    || (eligible && !eligible[b]))
						continue;
					/* ONE PER KEY: a confirmer is kept once per grant,
					 * and this guards a table filled by hand. */
					for (j = 0; j < count; j++)
						if (fzn_ct_memeq(seen[j], cf->confirmer, FZN_PUBKEY_LEN))
							break;
					if (j == count)
						seen[count++] = cf->confirmer;
				}
				if (!by_root && count < need)
					all = 0;
			}
			if (all) {
				confirmed[a] = 1;
				changed = 1;
			}
		}
	}
}

static fzn_chain_err_t entitled_as_admin(fzn_revocation_store_t *store,
                                         const uint8_t issuer[FZN_PUBKEY_LEN],
                                         const fzn_chain_hop_t *hops, size_t hop_count,
                                         const uint8_t root[FZN_PUBKEY_LEN],
                                         const fzn_sign_ops_t *sign,
                                         const fzn_hash_ops_t *hash);

/* WHICH ADMINS STAND: confirmed, rooted, and not revoked by the admins
 * standing in the first stratum -- the answer every vote count starts from.
 * One implementation for `fzn_revocation_covers_links` and
 * `fzn_revocation_admin_stands`, so the two cannot disagree. */
static void standing_admins(const fzn_revocation_store_t *store,
                            uint8_t admin_ok[REVOCATION_ADMINS_MAX])
{
	uint8_t confirmed[REVOCATION_ADMINS_MAX];
	size_t a;

	/* WHOSE GRANT IS CONFIRMED, sec 414: an unconfirmed admin's votes
	 * count in neither stratum. */
	confirm_admins(store, NULL, confirmed);

	/* THE FIRST STRATUM: which admins' own chains are revoked, counting
	 * every confirmed admin's vote. The second counts only the admins left
	 * standing. Mutual revocation takes out both, which fails toward
	 * revocation; sec 397 records why one rule has no stable answer. */
	for (a = 0; a < store->admins_used; a++) {
		const fzn_revocation_admin_t *ad = &store->admins[a];
		uint8_t own[FZN_CHAIN_MAX_HOPS];
		size_t h;

		admin_ok[a] = confirmed[a];
		for (h = 0; h < FZN_CHAIN_MAX_HOPS; h++)
			own[h] = 0;
		judge_links(store, (const uint8_t (*)[FZN_PUBKEY_LEN])ad->grantor,
		            (const uint8_t (*)[FZN_PUBKEY_LEN])ad->grantee, ad->hop_count,
		            &store->admin_capability, confirmed, own);
		for (h = 0; h < ad->hop_count; h++)
			if (own[h])
				admin_ok[a] = 0;
	}
	/* AND CONFIRMED AGAIN BY THOSE STILL STANDING: a revoked admin's
	 * confirmations stop holding up anybody else. Only ever removes. */
	confirm_admins(store, admin_ok, confirmed);
	for (a = 0; a < store->admins_used; a++)
		admin_ok[a] = admin_ok[a] && confirmed[a];
}

int fzn_revocation_admin_stands(const fzn_revocation_store_t *store,
                                const uint8_t key[FZN_PUBKEY_LEN])
{
	uint8_t admin_ok[REVOCATION_ADMINS_MAX];
	size_t a;

	/* A STORE THAT CANNOT BE READ stands nobody up: this answers "may this
	 * key act as an admin", and the side that refuses is the safe one. */
	if (!store || !key || corrupt(store) || !store->has_admin)
		return 0;
	a = find_admin(store, key);
	if (a >= store->admins_used)
		return 0;
	standing_admins(store, admin_ok);
	return admin_ok[a] != 0u;
}

fzn_chain_err_t fzn_revocation_admin_admit(fzn_revocation_store_t *store,
                                           const uint8_t key[FZN_PUBKEY_LEN],
                                           const fzn_chain_hop_t *hops, size_t hop_count,
                                           const uint8_t root[FZN_PUBKEY_LEN],
                                           const fzn_sign_ops_t *sign)
{
	if (!store || !key || !hops || hop_count == 0u || !root || !sign || corrupt(store))
		return FZN_CHAIN_ERR_MALFORMED;
	if (!store->has_admin)
		return FZN_CHAIN_ERR_CHAIN_INVALID;
	return entitled_as_admin(store, key, hops, hop_count, root, sign, store->confirm_hash);
}

void fzn_revocation_covers_links(const fzn_revocation_store_t *store,
                                 const uint8_t (*grantors)[FZN_PUBKEY_LEN],
                                 const uint8_t (*grantees)[FZN_PUBKEY_LEN], size_t hop_count,
                                 const fzn_cap_id_t *capability,
                                 uint8_t revoked[FZN_CHAIN_MAX_HOPS])
{
	uint8_t admin_ok[REVOCATION_ADMINS_MAX];

	/* Nowhere to put an answer. Checked first because everything below
	 * writes. */
	if (!revoked)
		return;
	/* Cleared before any decision, so that a caller reading a position it
	 * did not ask about reads 0 rather than whatever its stack held. */
	for (size_t i = 0; i < (size_t)FZN_CHAIN_MAX_HOPS; i++)
		revoked[i] = 0;
	/* An absent store is an answer and not a missing one: it knows of no
	 * revocations, which is the contract `fzn_chain_verify` rests on. */
	if (!store)
		return;
	/* THE STORE'S INTEGRITY IS JUDGED BEFORE THE QUESTION IS, and denying
	 * means denying EVERY hop: entries that cannot be scanned may hold the
	 * answer for any of them. */
	if (corrupt(store)) {
		for (size_t i = 0; i < (size_t)FZN_CHAIN_MAX_HOPS; i++)
			revoked[i] = 1;
		return;
	}
	/* A question with no subject: nothing names it, and 0 is the literal
	 * truth rather than a permission. `fzn_revocation_covers` argues it. */
	if (!store->entries || !grantors || !grantees || !capability)
		return;
	if (hop_count == 0 || hop_count > (size_t)FZN_CHAIN_MAX_HOPS)
		return;

	standing_admins(store, admin_ok);
	judge_links(store, grantors, grantees, hop_count, capability, admin_ok, revoked);
}

fzn_chain_err_t fzn_revocation_store_set_acts(fzn_revocation_store_t *store,
                                              const fzn_act_log_ops_t *acts)
{
	if (!store || (acts && !acts->stands))
		return FZN_CHAIN_ERR_MALFORMED;
	store->acts = acts;
	store->generation++;
	return FZN_CHAIN_OK;
}

/* THE VOTES THAT DRAW THE LINE, sec 496: every counted vote still live, and
 * in a latch the votes of the epoch holding it, withdrawn ones included --
 * a withdrawn entry keeps the cut of the vote it undid. The root's undo is
 * applied first, so a vote the root has undone draws nothing. An act stands
 * under every one of their cuts, or not at all. */
int fzn_revocation_act_stands(const fzn_revocation_store_t *store,
                              const uint8_t (*grantors)[FZN_PUBKEY_LEN],
                              const uint8_t (*grantees)[FZN_PUBKEY_LEN], size_t hop_count,
                              const fzn_cap_id_t *capability, size_t i,
                              const uint8_t act[FZN_REVOCATION_ID_LEN])
{
	uint8_t admin_ok[REVOCATION_ADMINS_MAX];
	struct hop_question h;
	enum hop_verdict verdict;
	uint64_t current = 0;
	size_t e, q, binding = 0;

	if (!store || !act)
		return 0;
	if (corrupt(store))
		return 0;
	if (!store->entries || !grantors || !grantees || !capability || hop_count == 0
	    || hop_count > (size_t)FZN_CHAIN_MAX_HOPS || i >= hop_count)
		return 0;
	q = store->quorum ? store->quorum : 1u;
	standing_admins(store, admin_ok);
	h.grantors = grantors;
	h.grantees = grantees;
	h.hop_count = hop_count;
	h.capability = capability;
	h.admin_ok = admin_ok;
	h.any_issuer = 0;
	h.has_floor = 0;
	h.floor = 0;
	h.i = i;
	verdict = judge_hop(store, &h, grantors[0], q, &current);
	if (verdict == HOP_FREE)
		return 1;
	/* THE ROOT'S UNDO IN FULL: `root_pass` stops at the first live root
	 * vote, so the floor it left may be short of the highest undo. */
	h.has_floor = 0;
	h.floor = 0;
	for (e = 0; e < store->used; e++) {
		const fzn_revocation_t *entry = &store->entries[e];

		if (entry->withdrawn && counts(store, entry, &h) && root_entry(store, entry, grantors[0])
		    && (!h.has_floor || entry->epoch > h.floor)) {
			h.floor = entry->epoch;
			h.has_floor = 1;
		}
	}
	if (!store->acts)
		return 0;
	for (e = 0; e < store->used; e++) {
		const fzn_revocation_t *entry = &store->entries[e];

		if (!counts(store, entry, &h))
			continue;
		if (entry->withdrawn && !(verdict == HOP_LATCHED && entry->epoch == current))
			continue;
		binding++;
		if (all_zero(entry->cut, FZN_REVOCATION_ID_LEN)
		    || !store->acts->stands(store->acts->ctx, grantees[i], entry->cut, act))
			return 0;
	}
	return binding > 0u;
}

void fzn_revocation_covers_chain(const fzn_revocation_store_t *store,
                                  const fzn_chain_hop_t *hops, size_t hop_count,
                                  const fzn_cap_id_t *capability,
                                  uint8_t revoked[FZN_CHAIN_MAX_HOPS])
{
	uint8_t grantors[FZN_CHAIN_MAX_HOPS][FZN_PUBKEY_LEN];
	uint8_t grantees[FZN_CHAIN_MAX_HOPS][FZN_PUBKEY_LEN];
	size_t i;

	if (!revoked)
		return;
	/* NO HOPS IS A QUESTION WITH NO SUBJECT, answered as the links form
	 * answers it; checked here only because the copy below reads them.
	 * The STORE's guards are answered first as well: a null, corrupt or
	 * empty store needs no hop read, and the hops a consumer doing its own
	 * walk passes may be views over nothing -- revocation_test drives that. */
	if (!store || corrupt(store) || !store->entries || !capability ||
	    !hops || hop_count == 0 || hop_count > (size_t)FZN_CHAIN_MAX_HOPS) {
		fzn_revocation_covers_links(store, NULL, NULL, 0, capability, revoked);
		return;
	}
	/* THE CHAIN'S SHAPE, AND NOTHING ELSE, is what the rule reads: each
	 * hop's grantor and grantee. One implementation for both forms. */
	for (i = 0; i < hop_count; i++) {
		memcpy(grantors[i], fzn_hop_grantor(hops[i]), FZN_PUBKEY_LEN);
		memcpy(grantees[i], fzn_hop_grantee(hops[i]), FZN_PUBKEY_LEN);
	}
	fzn_revocation_covers_links(store, (const uint8_t (*)[FZN_PUBKEY_LEN])grantors,
	                            (const uint8_t (*)[FZN_PUBKEY_LEN])grantees, hop_count,
	                            capability, revoked);
}

/* THE ADMISSION BOUND FOR A KEY THAT IS NOT THE ROOT. See revocation.h for
 * why this is a resource decision rather than an authorization one, and
 * project.md sec 13c for the reasoning it was built from.
 *
 * Split out so that the two invariants below are one place each rather than
 * two arguments buried in a longer function. Both are invisible when broken:
 * the suite still passes, and what changes is whether a store's contents
 * depend on the order things arrived in. */
static fzn_chain_err_t entitled_by_chain(const fzn_revocation_store_t *store,
                                         fzn_revocation_offer_t offer,
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
	/* NULL MANIFEST, AND THIS ONE IS LOAD-BEARING RATHER THAN A DEFAULT.
	 * Stage 2's gate refuses a chain when this host knows it is missing
	 * revocations from one of its grantors -- and admitting a revocation
	 * is how a host stops missing them. Gating it would make catching up
	 * require being caught up: the deficit would refuse the very records
	 * that drain it, and a host that fell behind could never return. */
	/* FROM ANY MEMBER ROOT, sec 417, as an admin's chain may since sec 416:
	 * verified under its own first grantor when the store's set names it.
	 * Whether that root's grant still counts is the read's question. */
	if (offer.hop_count && offer.hops[0].base && store->roots
	    && store->roots->member(store->roots->ctx, fzn_hop_grantor(offer.hops[0])))
		root = fzn_hop_grantor(offer.hops[0]);
	err = fzn_chain_verify(offer.hops, offer.hop_count, root,
	                       fzn_revocation_capability(offer.record), 0, sign, NULL,
	                       NULL, &issuers);
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

/* AN ADMIN'S STANDING (sec 397): a chain from the root for the store's admin
 * capability, naming the issuer as its last grantee, checked with the same
 * two blindnesses as `entitled_by_chain` and for its reasons. It need not be
 * delegable -- an admin votes on revocations, it does not grant through this
 * chain. The admin is then kept in the store's table, its chain as each hop's
 * grantor and grantee, so its own revocation can be judged later. */
static fzn_chain_err_t entitled_as_admin(fzn_revocation_store_t *store,
                                         const uint8_t issuer[FZN_PUBKEY_LEN],
                                         const fzn_chain_hop_t *hops, size_t hop_count,
                                         const uint8_t root[FZN_PUBKEY_LEN],
                                         const fzn_sign_ops_t *sign,
                                         const fzn_hash_ops_t *hash)
{
	fzn_revocation_admin_t ad;
	fzn_chain_t verdict;
	fzn_chain_err_t err;
	size_t i, a;

	if (hop_count >= (size_t)FZN_CHAIN_MAX_HOPS || (hop_count && !hops[0].base))
		return FZN_CHAIN_ERR_MALFORMED;
	/* FROM ANY MEMBER ROOT, sec 416: the chain is verified under its own
	 * first grantor when the store's set names it, as a chain from a member
	 * root verifies anywhere else. Whether that root's grant still counts is
	 * asked when the store is read. */
	if (hop_count && store->roots
	    && store->roots->member(store->roots->ctx, fzn_hop_grantor(hops[0])))
		root = fzn_hop_grantor(hops[0]);
	err = fzn_chain_verify(hops, hop_count, root, &store->admin_capability, 0,
	                       sign, NULL, NULL, &verdict);
	if (err != FZN_CHAIN_OK)
		return err;
	if (!fzn_ct_memeq(verdict.grantee, issuer, FZN_PUBKEY_LEN))
		return FZN_CHAIN_ERR_CHAIN_INVALID;

	memset(&ad, 0, sizeof(ad));
	memcpy(ad.key, verdict.grantee, FZN_PUBKEY_LEN);
	ad.hop_count = hop_count;
	/* THE FIRST HOP AS ITS ROOT'S ACT, sec 417. */
	if (hop_count && hash && hash->hash
	    && !hash->hash(hash->ctx, ad.first_act, sizeof(ad.first_act), hops[0].base, FZN_HOP_LEN))
		return FZN_CHAIN_ERR_MALFORMED;
	for (i = 0; i < hop_count; i++) {
		memcpy(ad.grantor[i], fzn_hop_grantor(hops[i]), FZN_PUBKEY_LEN);
		memcpy(ad.grantee[i], fzn_hop_grantee(hops[i]), FZN_PUBKEY_LEN);
		/* WHAT A CONFIRMATION NAMES, when the store keeps them. */
		if (store->confirm_hash
		    && !store->confirm_hash->hash(store->confirm_hash->ctx, ad.hop_id[i],
		                                  FZN_REVOCATION_ID_LEN, hops[i].base, FZN_HOP_LEN))
			return FZN_CHAIN_ERR_MALFORMED;
	}
	/* ONE ROW PER ADMIN KEY. A second chain for a key already held is
	 * refused as a conflict rather than silently replacing the first: which
	 * chain an admin stands on decides whether its votes count, and letting
	 * the later arrival win would make that depend on arrival order. */
	a = find_admin(store, ad.key);
	if (a < store->admins_used)
		return memcmp(&store->admins[a], &ad, sizeof(ad)) == 0 ? FZN_CHAIN_OK
		                                                        : FZN_CHAIN_ERR_CHAIN_INVALID;
	if (store->admins_used >= store->admin_capacity)
		return FZN_CHAIN_ERR_STORE_FULL;
	store->admins[store->admins_used++] = ad;
	store->generation++;
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
	/* WITH A ROOT SET, ANY MEMBER ROOT, sec 406: whether its record still
	 * counts -- a removed root's after the cut does not -- is asked when
	 * the store is read, so arrival order decides nothing. */
	if (offer.hop_count == 0 &&
	    !fzn_ct_memeq(fzn_revocation_issuer(record), root, FZN_PUBKEY_LEN)
	    && !(store->roots
	         && store->roots->member(store->roots->ctx, fzn_revocation_issuer(record))))
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
		fzn_chain_err_t err;

		/* AN ADMIN'S VOTE carries its admin chain; anybody else's carries
		 * a chain for the capability it withdraws. Told apart by what the
		 * offered chain grants. */
		if (store->has_admin
		    && fzn_ct_memeq(fzn_hop_capability(offer.hops[0])->b,
		                    store->admin_capability.b, FZN_CAP_ID_LEN))
			err = entitled_as_admin(store, fzn_revocation_issuer(record), offer.hops,
			                        offer.hop_count, root, sign, hash);
		else
			err = entitled_by_chain(store, offer, root, sign);
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
			store->entries[store->used].epoch = fzn_revocation_epoch(record);
			memcpy(store->entries[store->used].held, id, FZN_REVOCATION_ID_LEN);
			/* A tombstone undid a vote this host never saw, so it
			 * keeps no line of that vote's. */
			memset(store->entries[store->used].cut, 0, FZN_REVOCATION_ID_LEN);
			store->used++;
			store->generation++;
			return FZN_CHAIN_OK;
		}
		if (!fzn_ct_memeq(store->entries[at].id, fzn_revocation_supersedes(record),
		                  FZN_REVOCATION_ID_LEN))
			return FZN_CHAIN_ERR_UNKNOWN_TARGET;
		/* A WITHDRAWAL CARRIES ITS TARGET'S EPOCH, sec 400. One naming the
		 * right record in another epoch is refused as a mismatch rather
		 * than moving the entry: accepting it would let a withdrawal
		 * count toward closing an epoch its revocation was never in. */
		if (store->entries[at].epoch != fzn_revocation_epoch(record))
			return FZN_CHAIN_ERR_UNKNOWN_TARGET;
		/* Idempotent: a second copy of the same withdrawal is what
		 * "carried on contact" looks like when it works, exactly as
		 * for a second copy of a revocation. `id` is unchanged --
		 * it still names the revocation that was undone, which is
		 * what a later reissue must supersede. */
		/* Bump only on a real change. A withdrawal that arrives twice
		 * writes the same 1 over the same 1, and bumping there throws
		 * a cache away for a record carrying no news -- which is the
		 * traffic the generation is meant to let a cache survive. */
		memcpy(store->entries[at].held, id, FZN_REVOCATION_ID_LEN);
		if (!store->entries[at].withdrawn) {
			store->entries[at].withdrawn = 1;
			store->generation++;
		}
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
			if (fzn_ct_memeq(id, entry->id, FZN_REVOCATION_ID_LEN)) {
				/* AND THE DEFICIT DRAINS, which is not obvious
				 * and is what stops a loop. A peer that has not
				 * heard the withdrawal keeps naming this pair
				 * as revoked, so a comparison keeps recording
				 * "I lack something about it" -- and the fetch
				 * lands here every time, changing nothing. The
				 * request is answered even though the store is
				 * not: this host demonstrably knows MORE about
				 * the pair than the peer that sent it. */
				fzn_manifest_satisfy(manifest,
				                     fzn_revocation_issuer(record),
				                     fzn_revocation_capability(record),
				                     fzn_revocation_grantee(record));
				return FZN_CHAIN_OK;
			}

			/* A GENUINELY NEW REVOCATION OVER A WITHDRAWAL MUST
			 * NAME A PREDECESSOR. Until sec 359 it had to name the one
			 * WE HOLD, and that rule authorised a revoked grantee.
			 *
			 * The exact compare reads right: a re-revocation chains to
			 * the withdrawal it answers, so require it to say so.
			 * `fzn_revocation_issue` writes a zero `supersedes`, which
			 * cannot equal what we hold, so the un-chained mint was
			 * refused here rather than warned about in a header. That
			 * much survives; what does not is requiring the name to be
			 * ours.
			 *
			 * WHAT IT COST. A host that missed one propagation round
			 * holds id1 where the issuer has since minted R2 and R3.
			 * R3 names id2, we hold id1, and the record that would
			 * bridge them is R2 -- which NOTHING RETAINS. This store
			 * holds `{pair, id, withdrawn}`: a hash and a flag, never a
			 * record. No peer can serve R2 because no peer keeps it. So
			 * the host stayed INCOMPLETE for that pair permanently, and
			 * sec 358 left "ask for it by id" as the open half on the
			 * assumption that something could answer. Measured: nothing
			 * can. There is no fetch to build.
			 *
			 * WHAT IT BOUGHT, MEASURED THE SAME WAY. The signature and
			 * the issuer's standing are settled at the top of this
			 * function, so every record reaching this branch is signed
			 * by a party already entitled to revoke this pair. A
			 * near-miss `supersedes` is therefore only mintable by
			 * somebody who could mint a correctly-chained one and revoke
			 * the pair anyway: the exact compare denies an entitled
			 * issuer nothing. What it does refuse is a THIRD PARTY's
			 * replay of a stale re-revocation -- and only at a distance
			 * of two or more, because a replay naming exactly what we
			 * hold was always accepted. It stopped the case it could
			 * heal from and let through the case it could not.
			 *
			 * SO THE DIRECTION OF THE ERROR DECIDES IT, which is F24's
			 * argument reaching the store. Accepting a stale
			 * re-revocation re-revokes a pair the root had restored:
			 * a denial, visible, and one the root undoes by withdrawing
			 * again -- that withdrawal names the id we just adopted, so
			 * it applies. Refusing a genuine one authorises a grantee
			 * the root revoked: silent, permanent, and the thing this
			 * store exists to prevent. A revocation store errs revoked.
			 *
			 * A ZERO `supersedes` still refuses, and still drains. That
			 * peer is BEHIND us -- it never heard the withdrawal and is
			 * revoking the pair afresh -- and the deficit must drain or
			 * the refusal and the re-fetch chase each other for ever.
			 * The compare is whole-length for the same reason the old
			 * one was: a `supersedes` that is zero in every byte but its
			 * last NAMES something, and a prefix read would call it
			 * nothing. */
			{
				static const uint8_t NAMES_NOTHING[FZN_REVOCATION_ID_LEN] = { 0 };

				if (fzn_ct_memeq(fzn_revocation_supersedes(record),
				                 NAMES_NOTHING, FZN_REVOCATION_ID_LEN)) {
					fzn_manifest_satisfy(manifest,
					                     fzn_revocation_issuer(record),
					                     fzn_revocation_capability(record),
					                     fzn_revocation_grantee(record));
					return FZN_CHAIN_ERR_UNKNOWN_TARGET;
				}
			}

			/* NOT REVOKED becomes REVOKED, which is the biggest
			 * answer this store can change -- and it went unbumped
			 * until sec 356. A cache holding an affirmative chain
			 * verdict for this pair would go on authorising a peer
			 * revoked a moment ago. */
			entry->withdrawn = 0;
			entry->epoch = fzn_revocation_epoch(record);
			store->generation++;
			memcpy(entry->id, id, FZN_REVOCATION_ID_LEN);
			memcpy(entry->held, id, FZN_REVOCATION_ID_LEN);
			memcpy(entry->cut, fzn_revocation_cut(record), FZN_REVOCATION_ID_LEN);
			fzn_manifest_satisfy(manifest, fzn_revocation_issuer(record),
			                     fzn_revocation_capability(record),
			                     fzn_revocation_grantee(record));
			return FZN_CHAIN_OK;
		}
	}

	if (at < store->used) {
		fzn_revocation_t *entry = &store->entries[at];

		/* A REISSUE OVER A LIVE REVOCATION ADVANCES THE ID, and it was
		 * dropped as "already known" until this existed.
		 *
		 * The authorization answer does not change -- the pair was
		 * revoked and stays revoked -- so it looks like nothing worth
		 * storing. But `id` is what a later withdrawal must name, and
		 * leaving it at the superseded record means the issuer's own
		 * withdrawal of the CURRENT one is refused as a mismatch. The
		 * pair would then be revocable, reissuable, and unwithdrawable.
		 *
		 * Chained only: a record naming something else is one this
		 * host cannot place, and the pair is already revoked either
		 * way, so the store is left alone. */
		if (!fzn_ct_memeq(id, entry->id, FZN_REVOCATION_ID_LEN) &&
		    fzn_ct_memeq(fzn_revocation_supersedes(record), entry->id,
		                 FZN_REVOCATION_ID_LEN)) {
			memcpy(entry->id, id, FZN_REVOCATION_ID_LEN);
			memcpy(entry->held, id, FZN_REVOCATION_ID_LEN);
			entry->epoch = fzn_revocation_epoch(record);
			/* A REISSUE MAY MOVE THE LINE, sec 496: how a voter
			 * who learns more about a theft says so without first
			 * undoing its vote. The answers change with it. */
			if (!fzn_ct_memeq(entry->cut, fzn_revocation_cut(record),
			                  FZN_REVOCATION_ID_LEN)) {
				memcpy(entry->cut, fzn_revocation_cut(record),
				       FZN_REVOCATION_ID_LEN);
				store->generation++;
			}
		}

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
	if (store->used >= store->capacity) {
		/* WORSE HERE THAN ANYWHERE ELSE IN THE LIBRARY, and the return
		 * value cannot say so. This store never evicts -- a revocation
		 * does not expire, so no slot is ever reclaimable -- which
		 * means a full store refuses every withdrawal from now on. The
		 * caller learns that one admission failed; what has actually
		 * happened is that this host has stopped being able to learn
		 * about revocations at all. */
		REV_LOG(store, "chain/revocation", FLOG_CRIT,
		        "revocation store full at %zu entries and nothing here expires, so "
		        "no further withdrawal can ever be admitted",
		        store->capacity);
		return FZN_CHAIN_ERR_STORE_FULL;
	}

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
	store->entries[store->used].epoch = fzn_revocation_epoch(record);
	memcpy(store->entries[store->used].held, id, FZN_REVOCATION_ID_LEN);
	memcpy(store->entries[store->used].cut, fzn_revocation_cut(record), FZN_REVOCATION_ID_LEN);
	store->used++;
	/* An answer this store gives may now differ; sec 354. */
	store->generation++;

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

uint64_t fzn_revocation_generation(const fzn_revocation_store_t *store)
{
	return store ? store->generation : 0;
}

fzn_chain_err_t fzn_revocation_confirm_admit(fzn_revocation_store_t *store,
                                             const uint8_t *bytes, size_t len,
                                             const fzn_chain_hop_t *hops, size_t hop_count,
                                             const uint8_t root[FZN_PUBKEY_LEN],
                                             const fzn_sign_ops_t *sign)
{
	const uint8_t *confirmer, *grant;
	uint8_t act[FZN_REVOCATION_ID_LEN];
	fzn_revocation_confirm_t *c;
	size_t i;

	if (!store || !store->confirms || !store->confirm_hash || !bytes || !root || !sign
	    || !sign->verify || (hop_count > 0u && !hops))
		return FZN_CHAIN_ERR_MALFORMED;
	if (corrupt(store))
		return FZN_CHAIN_ERR_MALFORMED;
	if (len != FZN_ADMIN_CONFIRM_LEN || bytes[0] != (uint8_t)FZN_SIGNED_VERSION
	    || bytes[1] != (uint8_t)FZN_OBJECT_ADMIN_CONFIRM)
		return FZN_CHAIN_ERR_SHAPE;
	confirmer = bytes + FZN_ADMIN_CONFIRM_OFF_CONFIRMER;
	grant = bytes + FZN_ADMIN_CONFIRM_OFF_GRANT;
	/* A ROOT NEEDS NO CHAIN, as for a vote: the pinned root, or any member
	 * of the set, whose confirmation counts as the set says when read. */
	if (hop_count == 0u && !fzn_ct_memeq(confirmer, root, FZN_PUBKEY_LEN)
	    && !(store->roots && store->roots->member(store->roots->ctx, confirmer)))
		return FZN_CHAIN_ERR_WRONG_ROOT;
	if (!sign->verify(sign->ctx, confirmer, bytes, FZN_ADMIN_CONFIRM_BODY_LEN,
	                  bytes + FZN_ADMIN_CONFIRM_BODY_LEN))
		return FZN_CHAIN_ERR_CHAIN_INVALID;
	/* AN ADMIN SHOWS ITS ADMIN CHAIN, and is kept as a vote would keep it. */
	if (hop_count > 0u) {
		fzn_chain_err_t err;

		if (!store->has_admin)
			return FZN_CHAIN_ERR_CHAIN_INVALID;
		err = entitled_as_admin(store, confirmer, hops, hop_count, root, sign,
		                        store->confirm_hash);
		if (err != FZN_CHAIN_OK)
			return err;
	}
	for (i = 0; i < store->confirms_used; i++)
		if (fzn_ct_memeq(store->confirms[i].confirmer, confirmer, FZN_PUBKEY_LEN)
		    && fzn_ct_memeq(store->confirms[i].grant, grant, FZN_REVOCATION_ID_LEN))
			return FZN_CHAIN_OK;
	if (store->confirms_used >= store->confirm_capacity)
		return FZN_CHAIN_ERR_STORE_FULL;
	if (!store->confirm_hash->hash(store->confirm_hash->ctx, act, sizeof(act), bytes, len))
		return FZN_CHAIN_ERR_MALFORMED;
	c = &store->confirms[store->confirms_used++];
	memcpy(c->confirmer, confirmer, FZN_PUBKEY_LEN);
	memcpy(c->grant, grant, FZN_REVOCATION_ID_LEN);
	memcpy(c->act, act, sizeof(act));
	store->generation++;
	return FZN_CHAIN_OK;
}
