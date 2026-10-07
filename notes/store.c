/* See store.h. */

#include "store.h"

#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#include <string.h>

/* Sixteen bytes, as this tree's other derivation labels are, so a claim key's
 * input collides with no other hash input here. */
static const char CLAIM_LABEL[16] = "fuzznet-note-v1\0";

#define NOTE_BLOB_MAX ((size_t)FZN_PERSIST_HEAD_LEN + FZN_RECORD_MAX_LEN)

const char *fzn_notes_err_str(fzn_notes_err_t err)
{
	switch (err) {
	case FZN_NOTES_OK:
		return "ok";
	case FZN_NOTES_ERR_MALFORMED:
		return "malformed";
	case FZN_NOTES_ERR_DENIED:
		return "not admitted as a note";
	case FZN_NOTES_ERR_FULL:
		return "no room for another note";
	case FZN_NOTES_ERR_EQUIVOCATION:
		return "one writer signed two records at one sequence";
	case FZN_NOTES_ERR_BACKEND:
		return "the store refused";
	case FZN_NOTES_ERR_ABSENT:
		return "not held here";
	case FZN_NOTES_ERR_SHAPE:
		return "the store returned something else";
	case FZN_NOTES_ERR_UNSUPPORTED:
		return "the store cannot forget";
	case FZN_NOTES_ERR_PENDING:
		return "the note's content is not here yet";
	case FZN_NOTES_ERR_PURGED:
		return "the note was purged here";
	}
	return "unknown";
}

const char *fzn_notes_denial_str(fzn_notes_denial_t why)
{
	switch (why) {
	case FZN_NOTES_DENIAL_NONE:
		return "admitted";
	case FZN_NOTES_DENIAL_POLICY_UNSPELLED:
		return "no policy was stated, so nothing is admitted";
	case FZN_NOTES_DENIAL_MALFORMED:
		return "not the shape of a record";
	case FZN_NOTES_DENIAL_KIND:
		return "a record, and not a note";
	case FZN_NOTES_DENIAL_SIGNATURE:
		return "not what its issuer signed";
	case FZN_NOTES_DENIAL_NOT_ADMITTED:
		return "this host accepts no notes from that key";
	}
	return "unknown";
}

static fzn_notes_verdict_t deny(fzn_notes_denial_t *why, fzn_notes_denial_t reason)
{
	if (why)
		*why = reason;
	return FZN_NOTES_DENIED;
}

fzn_notes_verdict_t fzn_notes_admit(fzn_notes_policy_t policy, const uint8_t *record,
                                    size_t record_len, const fzn_sign_ops_t *sign,
                                    fzn_notes_denial_t *why)
{
	fzn_record_t rec;
	size_t i;
	int admitted = 0;

	if (why)
		*why = FZN_NOTES_DENIAL_NONE;
	/* THE UNSPELLED POLICY FIRST: not deciding must not come out as yes. */
	if (!policy.spelled)
		return deny(why, FZN_NOTES_DENIAL_POLICY_UNSPELLED);
	if (!record || !sign || fzn_record_open(record, record_len, &rec) != FZN_RECORD_OK)
		return deny(why, FZN_NOTES_DENIAL_MALFORMED);
	if (fzn_record_kind(rec) != FZN_NOTE_KIND || fzn_record_stream(rec) != FZN_NOTE_STREAM)
		return deny(why, FZN_NOTES_DENIAL_KIND);
	if (fzn_record_verify(rec, sign) != FZN_RECORD_OK)
		return deny(why, FZN_NOTES_DENIAL_SIGNATURE);
	/* THE EMPTY SET DENIES BY THE LOOP, not by a special case. Constant
	 * time, because the issuer is a key an attacker chose compared against
	 * keys this host holds. */
	for (i = 0; i < policy.admitted_count; i++)
		if (fzn_ct_memeq(policy.admitted[i].key, fzn_record_issuer(rec), FZN_PUBKEY_LEN))
			admitted = 1;
	if (!admitted)
		return deny(why, FZN_NOTES_DENIAL_NOT_ADMITTED);
	return FZN_NOTES_ADMITTED;
}

fzn_notes_err_t fzn_notes_store_init(fzn_notes_store_t *store, const fzn_persist_ops_t *ops,
                                     const fzn_hash_ops_t *hash)
{
	if (!store || !ops || !ops->load || !ops->save || !ops->list || !hash || !hash->hash)
		return FZN_NOTES_ERR_MALFORMED;
	store->ops = ops;
	store->hash = hash;
	store->purged = NULL;
	store->purged_ctx = NULL;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_claim_key(const fzn_notes_store_t *store,
                                    const uint8_t id[FZN_SUBJECT_LEN],
                                    const uint8_t issuer[FZN_PUBKEY_LEN],
                                    uint8_t out[FZN_PUBKEY_LEN])
{
	uint8_t input[sizeof(CLAIM_LABEL) + FZN_SUBJECT_LEN + FZN_PUBKEY_LEN];

	if (!store || !store->hash || !id || !issuer || !out)
		return FZN_NOTES_ERR_MALFORMED;
	memcpy(input, CLAIM_LABEL, sizeof(CLAIM_LABEL));
	memcpy(input + sizeof(CLAIM_LABEL), id, FZN_SUBJECT_LEN);
	memcpy(input + sizeof(CLAIM_LABEL) + FZN_SUBJECT_LEN, issuer, FZN_PUBKEY_LEN);
	if (!store->hash->hash(store->hash->ctx, out, FZN_PUBKEY_LEN, input, sizeof(input)))
		return FZN_NOTES_ERR_BACKEND;
	return FZN_NOTES_OK;
}

/* The record under `key`, opened, its bytes in `blob` past the head. ABSENT
 * when nothing is there; SHAPE when what is there is no record. */
static fzn_notes_err_t load_key(const fzn_notes_store_t *store, const uint8_t key[FZN_PUBKEY_LEN],
                                uint8_t *blob, size_t cap, size_t *record_len, fzn_record_t *rec)
{
	size_t len = 0;

	if (!store->ops->load(store->ops->ctx, FZN_PERSIST_NOTE, key, blob, cap, &len))
		return FZN_NOTES_ERR_ABSENT;
	if (len <= FZN_PERSIST_HEAD_LEN
	    || fzn_persist_head_check(blob, len, len - FZN_PERSIST_HEAD_LEN, FZN_PERSIST_BLOB_NOTE)
	               != FZN_PERSIST_OK
	    || fzn_record_open(blob + FZN_PERSIST_HEAD_LEN, len - FZN_PERSIST_HEAD_LEN, rec)
	               != FZN_RECORD_OK)
		return FZN_NOTES_ERR_SHAPE;
	*record_len = len - FZN_PERSIST_HEAD_LEN;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_claims(const fzn_notes_store_t *store,
                                 uint8_t (*keys)[FZN_PUBKEY_LEN], size_t cap, size_t *count)
{
	if (!store || !store->ops || !keys || !count)
		return FZN_NOTES_ERR_MALFORMED;
	*count = 0;
	if (!store->ops->list(store->ops->ctx, FZN_PERSIST_NOTE, (uint8_t *)keys, cap, count))
		return FZN_NOTES_ERR_BACKEND;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_put(const fzn_notes_store_t *store, const uint8_t *record,
                              size_t record_len, fzn_notes_policy_t policy,
                              const fzn_sign_ops_t *sign, int *wrote, fzn_notes_denial_t *why)
{
	static uint8_t held[NOTE_BLOB_MAX], blob[NOTE_BLOB_MAX];
	static uint8_t keys[FZN_NOTES_MAX][FZN_PUBKEY_LEN];
	uint8_t key[FZN_PUBKEY_LEN];
	fzn_record_t rec, held_rec;
	size_t held_len = 0, count = 0;
	fzn_notes_err_t err;

	if (wrote)
		*wrote = 0;
	if (!store || !store->ops || !record || record_len > FZN_RECORD_MAX_LEN)
		return FZN_NOTES_ERR_MALFORMED;
	/* ADMISSION FIRST, AND INSIDE. */
	if (fzn_notes_admit(policy, record, record_len, sign, why) != FZN_NOTES_ADMITTED)
		return FZN_NOTES_ERR_DENIED;
	if (fzn_record_open(record, record_len, &rec) != FZN_RECORD_OK)
		return FZN_NOTES_ERR_MALFORMED;
	/* AFTER ADMISSION, so a refusal of who wrote it still reads as one. */
	if (fzn_notes_purged(store, fzn_record_subject(rec)))
		return FZN_NOTES_ERR_PURGED;
	err = fzn_notes_claim_key(store, fzn_record_subject(rec), fzn_record_issuer(rec), key);
	if (err != FZN_NOTES_OK)
		return err;

	err = load_key(store, key, held, sizeof(held), &held_len, &held_rec);
	if (err == FZN_NOTES_OK) {
		const uint8_t *bytes = held + FZN_PERSIST_HEAD_LEN;

		/* SUPERSESSION, BEFORE ANYTHING IS WRITTEN. */
		if (fzn_record_seq(rec) == fzn_record_seq(held_rec)
		    && !(held_len == record_len && memcmp(bytes, record, record_len) == 0))
			return FZN_NOTES_ERR_EQUIVOCATION;
		if (fzn_record_seq(rec) <= fzn_record_seq(held_rec))
			return FZN_NOTES_OK;
	} else if (err == FZN_NOTES_ERR_ABSENT) {
		/* A NEW CLAIM, AND THE BOUND IS CHECKED BEFORE IT IS WRITTEN. A
		 * backend holding more than the bound fails the list, which
		 * refuses too. */
		if (fzn_notes_claims(store, keys, FZN_NOTES_MAX, &count) != FZN_NOTES_OK)
			return FZN_NOTES_ERR_FULL;
		if (count >= FZN_NOTES_MAX)
			return FZN_NOTES_ERR_FULL;
	}
	/* SHAPE falls through: a held record that will not open is damage, and
	 * damage must not freeze a note against a good record replacing it. */

	if (fzn_persist_head_write(blob, sizeof(blob), record_len, FZN_PERSIST_BLOB_NOTE)
	    != FZN_PERSIST_OK)
		return FZN_NOTES_ERR_MALFORMED;
	memcpy(blob + FZN_PERSIST_HEAD_LEN, record, record_len);
	if (!store->ops->save(store->ops->ctx, FZN_PERSIST_NOTE, key, blob,
	                      FZN_PERSIST_HEAD_LEN + record_len))
		return FZN_NOTES_ERR_BACKEND;
	if (wrote)
		*wrote = 1;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_get_key(const fzn_notes_store_t *store,
                                  const uint8_t key[FZN_PUBKEY_LEN], uint8_t *out, size_t cap,
                                  size_t *out_len)
{
	static uint8_t blob[NOTE_BLOB_MAX];
	uint8_t check[FZN_PUBKEY_LEN];
	fzn_record_t rec;
	size_t len = 0;
	fzn_notes_err_t err;

	if (!store || !store->ops || !key || !out || !out_len)
		return FZN_NOTES_ERR_MALFORMED;
	err = load_key(store, key, blob, sizeof(blob), &len, &rec);
	if (err != FZN_NOTES_OK)
		return err;
	/* WHAT CAME BACK MUST BE FILED WHERE IT IS: its own (id, writer) must
	 * hash to the key it was found under, or the backend handed back
	 * another claim's record -- perhaps perfectly well signed. */
	err = fzn_notes_claim_key(store, fzn_record_subject(rec), fzn_record_issuer(rec), check);
	if (err != FZN_NOTES_OK)
		return err;
	if (!fzn_ct_memeq(check, key, FZN_PUBKEY_LEN))
		return FZN_NOTES_ERR_SHAPE;
	if (cap < len)
		return FZN_NOTES_ERR_MALFORMED;
	memcpy(out, blob + FZN_PERSIST_HEAD_LEN, len);
	*out_len = len;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_get(const fzn_notes_store_t *store, const uint8_t id[FZN_SUBJECT_LEN],
                              const uint8_t issuer[FZN_PUBKEY_LEN], uint8_t *out, size_t cap,
                              size_t *out_len)
{
	uint8_t key[FZN_PUBKEY_LEN];
	fzn_notes_err_t err = fzn_notes_claim_key(store, id, issuer, key);

	if (err != FZN_NOTES_OK)
		return err;
	return fzn_notes_get_key(store, key, out, cap, out_len);
}

#define PURGED_BODY 1u
#define PURGED_BLOB ((size_t)FZN_PERSIST_HEAD_LEN + PURGED_BODY)

fzn_notes_err_t fzn_notes_mark_purged(const fzn_notes_store_t *store,
                                      const uint8_t id[FZN_SUBJECT_LEN])
{
	uint8_t blob[PURGED_BLOB];

	if (!store || !store->ops || !store->ops->save || !id)
		return FZN_NOTES_ERR_MALFORMED;
	/* ONCE: a mark held already is a purge this host has told of, and the
	 * retries an erase is owed must not tell it again. */
	if (fzn_notes_purged(store, id))
		return FZN_NOTES_OK;
	if (fzn_persist_head_write(blob, sizeof(blob), PURGED_BODY, FZN_PERSIST_BLOB_NOTE_PURGED)
	    != FZN_PERSIST_OK)
		return FZN_NOTES_ERR_MALFORMED;
	blob[FZN_PERSIST_HEAD_LEN] = 1u;
	if (!store->ops->save(store->ops->ctx, FZN_PERSIST_NOTE_PURGED, id, blob, sizeof(blob)))
		return FZN_NOTES_ERR_BACKEND;
	if (store->purged)
		store->purged(store->purged_ctx, id);
	return FZN_NOTES_OK;
}

int fzn_notes_purged(const fzn_notes_store_t *store, const uint8_t id[FZN_SUBJECT_LEN])
{
	uint8_t blob[PURGED_BLOB + 1u];
	size_t len = 0;

	if (!store || !store->ops || !store->ops->load || !id)
		return 0;
	if (!store->ops->load(store->ops->ctx, FZN_PERSIST_NOTE_PURGED, id, blob, sizeof(blob),
	                      &len))
		return 0;
	/* ANY ROW IS A MARK: one that will not read as one is still a note a
	 * user asked to be gone. */
	(void)fzn_persist_head_check(blob, len, PURGED_BODY, FZN_PERSIST_BLOB_NOTE_PURGED);
	return 1;
}

fzn_notes_err_t fzn_notes_erase(const fzn_notes_store_t *store,
                                const uint8_t id[FZN_SUBJECT_LEN],
                                const uint8_t issuer[FZN_PUBKEY_LEN])
{
	uint8_t key[FZN_PUBKEY_LEN];
	fzn_notes_err_t err = fzn_notes_claim_key(store, id, issuer, key);

	if (err != FZN_NOTES_OK)
		return err;
	if (!store->ops->remove)
		return FZN_NOTES_ERR_UNSUPPORTED;
	if (!store->ops->remove(store->ops->ctx, FZN_PERSIST_NOTE, key))
		return FZN_NOTES_ERR_BACKEND;
	return FZN_NOTES_OK;
}
