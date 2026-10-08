/* See sync.h. */

#include "sync.h"

#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#include <stdlib.h>
#include <string.h>

const char *fzn_notes_sync_err_str(fzn_notes_sync_err_t err)
{
	switch (err) {
	case FZN_NOTES_SYNC_OK:
		return "ok";
	case FZN_NOTES_SYNC_MALFORMED:
		return "malformed";
	case FZN_NOTES_SYNC_NO_ANSWER:
		return "the peer did not answer";
	case FZN_NOTES_SYNC_SHAPE:
		return "the peer's answer does not parse";
	case FZN_NOTES_SYNC_STORE:
		return "this node's store refused";
	}
	return "unknown";
}

static void head(uint8_t *out, uint8_t type)
{
	out[0] = FZN_NOTES_SYNC_VERSION;
	out[1] = type;
}

static int is_type(const uint8_t *b, size_t len, uint8_t type)
{
	return len >= FZN_NOTES_SYNC_HEAD_LEN && b[0] == FZN_NOTES_SYNC_VERSION && b[1] == type;
}

static int key_order(const void *a, const void *b)
{
	return memcmp(a, b, FZN_PUBKEY_LEN);
}

/* ---- the server ---------------------------------------------------------- */

static int in_scope(const fzn_notes_sync_scope_t *scope, const uint8_t *id)
{
	size_t i;

	if (!scope)
		return 1;
	for (i = 0; i < scope->count; i++)
		if (memcmp(scope->ids[i], id, FZN_TREE_ID_LEN) == 0)
			return 1;
	return 0;
}

/* What this store offers: its claims, IN KEY ORDER so a page means the same
 * thing on every call, without a note pending purge, and within `scope`. */
static size_t offered(const fzn_notes_store_t *store, const fzn_notes_sync_scope_t *scope,
                      uint8_t (*keys)[FZN_PUBKEY_LEN], uint64_t *seqs)
{
	static uint8_t record[FZN_RECORD_MAX_LEN];
	size_t count = 0, i, n = 0;

	if (fzn_notes_claims(store, keys, FZN_NOTES_MAX, &count) != FZN_NOTES_OK)
		return 0;
	qsort(keys, count, FZN_PUBKEY_LEN, key_order);
	for (i = 0; i < count; i++) {
		fzn_record_t rec;
		size_t len = 0;

		if (fzn_notes_get_key(store, keys[i], record, sizeof(record), &len) != FZN_NOTES_OK
		    || fzn_record_open(record, len, &rec) != FZN_RECORD_OK
		    || fzn_notes_purge_pending(store, fzn_record_subject(rec))
		    || !in_scope(scope, fzn_record_subject(rec)))
			continue;
		if (n != i)
			memcpy(keys[n], keys[i], FZN_PUBKEY_LEN);
		seqs[n++] = fzn_record_seq(rec);
	}
	return n;
}

static size_t answer_index(const fzn_notes_store_t *store, const fzn_notes_sync_scope_t *scope,
                           const uint8_t *request, size_t request_len, uint8_t *reply,
                           size_t cap)
{
	static uint8_t keys[FZN_NOTES_MAX][FZN_PUBKEY_LEN];
	static uint64_t seqs[FZN_NOTES_MAX];
	size_t total, from, n = 0, i;

	if (request_len != FZN_NOTES_SYNC_INDEX_QUERY_LEN || cap < FZN_NOTES_SYNC_INDEX_HEAD_LEN)
		return 0;
	from = fzn_get_be16(request + 2);
	total = offered(store, scope, keys, seqs);
	if (from > total)
		from = total;
	for (i = from; i < total; i++) {
		uint8_t *at = reply + FZN_NOTES_SYNC_INDEX_HEAD_LEN + (n * FZN_NOTES_SYNC_CLAIM_LEN);

		if (cap - FZN_NOTES_SYNC_INDEX_HEAD_LEN < (n + 1u) * FZN_NOTES_SYNC_CLAIM_LEN)
			break;
		memcpy(at, keys[i], FZN_PUBKEY_LEN);
		fzn_put_be64(at + FZN_PUBKEY_LEN, seqs[i]);
		n++;
	}
	head(reply, FZN_NOTES_SYNC_INDEX);
	fzn_put_be16(reply + 2, (uint16_t)total);
	fzn_put_be16(reply + 4, (uint16_t)from);
	fzn_put_be16(reply + 6, (uint16_t)n);
	return FZN_NOTES_SYNC_INDEX_HEAD_LEN + (n * FZN_NOTES_SYNC_CLAIM_LEN);
}

static size_t answer_records(const fzn_notes_store_t *store,
                             const fzn_notes_sync_scope_t *scope, const uint8_t *request,
                             size_t request_len, uint8_t *reply, size_t cap)
{
	static uint8_t record[FZN_RECORD_MAX_LEN];
	size_t asked, i, used = FZN_NOTES_SYNC_LIST_HEAD_LEN, n = 0;

	if (request_len < FZN_NOTES_SYNC_LIST_HEAD_LEN || cap < FZN_NOTES_SYNC_LIST_HEAD_LEN)
		return 0;
	asked = request[2];
	if (asked == 0u || asked > FZN_NOTES_SYNC_KEYS_MAX
	    || request_len != FZN_NOTES_SYNC_LIST_HEAD_LEN + (asked * FZN_PUBKEY_LEN))
		return 0;
	for (i = 0; i < asked; i++) {
		const uint8_t *key = request + FZN_NOTES_SYNC_LIST_HEAD_LEN + (i * FZN_PUBKEY_LEN);
		fzn_record_t rec;
		size_t len = 0;

		/* Absent, damaged and pending purge are all left out: a peer
		 * asking for them gets the rest. */
		if (fzn_notes_get_key(store, key, record, sizeof(record), &len) != FZN_NOTES_OK
		    || fzn_record_open(record, len, &rec) != FZN_RECORD_OK
		    || fzn_notes_purge_pending(store, fzn_record_subject(rec))
		    || !in_scope(scope, fzn_record_subject(rec)))
			continue;
		if (cap - used < 2u + len)
			break;
		fzn_put_be16(reply + used, (uint16_t)len);
		memcpy(reply + used + 2u, record, len);
		used += 2u + len;
		n++;
	}
	head(reply, FZN_NOTES_SYNC_RECORDS);
	reply[2] = (uint8_t)n;
	return used;
}

static int admits(fzn_notes_policy_t policy, const uint8_t *key)
{
	size_t i;
	int found = 0;

	if (!policy.spelled || !key)
		return 0;
	for (i = 0; i < policy.admitted_count; i++)
		found |= fzn_ct_memeq(policy.admitted[i].key, key, FZN_PUBKEY_LEN);
	return found;
}

static size_t answer_purge(const fzn_notes_store_t *store, fzn_notes_policy_t policy,
                           const uint8_t *sender, const uint8_t *request, size_t request_len,
                           uint8_t *reply, size_t cap)
{
	uint8_t answer = FZN_NOTES_SYNC_NOT_ERASED;

	if (request_len != FZN_NOTES_SYNC_PURGE_LEN || cap < FZN_NOTES_SYNC_PURGE_ACK_LEN)
		return 0;
	/* ERASED ONLY FOR A WRITER THIS NODE ADMITS, and only when it really
	 * is gone: a store that cannot remove must not say erased. */
	if (admits(policy, sender)
	    && fzn_notes_erase_note(store, request + 2, NULL) == FZN_NOTES_OK)
		answer = FZN_NOTES_SYNC_ERASED;
	head(reply, FZN_NOTES_SYNC_PURGE_ACK);
	memcpy(reply + 2, request + 2, FZN_TREE_ID_LEN);
	reply[2 + FZN_TREE_ID_LEN] = answer;
	return FZN_NOTES_SYNC_PURGE_ACK_LEN;
}

/* ---- partners ------------------------------------------------------------- */

#define PARTNER_BODY 8u
#define PARTNER_BLOB ((size_t)FZN_PERSIST_HEAD_LEN + PARTNER_BODY)

/* A node pulled notes from this one at `now_ms`. Best effort: a partner not
 * recorded is asked about by no purge, which costs convergence, not safety. */
static void partner_seen(const fzn_notes_store_t *store, const uint8_t *key, uint64_t now_ms)
{
	uint8_t blob[PARTNER_BLOB];

	if (fzn_persist_head_write(blob, sizeof(blob), PARTNER_BODY, FZN_PERSIST_BLOB_NOTE_PARTNER)
	    != FZN_PERSIST_OK)
		return;
	fzn_put_be64(blob + FZN_PERSIST_HEAD_LEN, now_ms);
	(void)store->ops->save(store->ops->ctx, FZN_PERSIST_NOTE_PARTNER, key, blob, sizeof(blob));
}

fzn_notes_err_t fzn_notes_partners(const fzn_notes_store_t *store,
                                   uint8_t (*keys)[FZN_PUBKEY_LEN], size_t cap, size_t *count)
{
	if (!store || !store->ops || !keys || !count)
		return FZN_NOTES_ERR_MALFORMED;
	*count = 0;
	if (!store->ops->list
	    || !store->ops->list(store->ops->ctx, FZN_PERSIST_NOTE_PARTNER, (uint8_t *)keys, cap,
	                         count))
		return FZN_NOTES_ERR_BACKEND;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_partner_seen_at(const fzn_notes_store_t *store,
                                          const uint8_t key[FZN_PUBKEY_LEN], uint64_t *ms)
{
	uint8_t blob[PARTNER_BLOB];
	size_t len = 0;

	if (!store || !store->ops || !key || !ms)
		return FZN_NOTES_ERR_MALFORMED;
	if (!store->ops->load(store->ops->ctx, FZN_PERSIST_NOTE_PARTNER, key, blob, sizeof(blob),
	                      &len))
		return FZN_NOTES_ERR_ABSENT;
	if (fzn_persist_head_check(blob, len, PARTNER_BODY, FZN_PERSIST_BLOB_NOTE_PARTNER)
	    != FZN_PERSIST_OK)
		return FZN_NOTES_ERR_SHAPE;
	*ms = fzn_get_be64(blob + FZN_PERSIST_HEAD_LEN);
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_partner_seen_clamped(const fzn_notes_store_t *store,
                                               const uint8_t key[FZN_PUBKEY_LEN],
                                               uint64_t now_ms, uint64_t *ms)
{
	fzn_notes_err_t err = fzn_notes_partner_seen_at(store, key, ms);

	if (err != FZN_NOTES_OK)
		return err;
	if (*ms > now_ms) {
		partner_seen(store, key, now_ms);
		*ms = now_ms;
	}
	return FZN_NOTES_OK;
}

/* PURGES_QUERY: this store's purges that pin `sender` and it has not
 * answered. */
static size_t answer_purges(const fzn_notes_store_t *store, const uint8_t *sender,
                            uint8_t *reply, size_t cap)
{
	static uint8_t ids[FZN_NOTES_PURGE_MAX][FZN_TREE_ID_LEN];
	static fzn_notes_purge_t p;
	size_t count = 0, i, j, n = 0;

	if (cap < FZN_NOTES_SYNC_LIST_HEAD_LEN)
		return 0;
	if (sender && fzn_notes_purge_list(store, ids, FZN_NOTES_PURGE_MAX, &count) == FZN_NOTES_OK)
		for (i = 0; i < count && n < FZN_NOTES_SYNC_PURGES_MAX; i++) {
			int pinned = 0;

			if (fzn_notes_purge_get(store, ids[i], &p) != FZN_NOTES_OK)
				continue;
			for (j = 0; j < p.asked_count && !pinned; j++)
				pinned = !p.answered[j]
				         && fzn_ct_memeq(p.asked[j], sender, FZN_PUBKEY_LEN);
			if (!pinned || cap - FZN_NOTES_SYNC_LIST_HEAD_LEN < (n + 1u) * FZN_TREE_ID_LEN)
				continue;
			memcpy(reply + FZN_NOTES_SYNC_LIST_HEAD_LEN + (n * FZN_TREE_ID_LEN), p.id,
			       FZN_TREE_ID_LEN);
			n++;
		}
	head(reply, FZN_NOTES_SYNC_PURGES);
	reply[2] = (uint8_t)n;
	return FZN_NOTES_SYNC_LIST_HEAD_LEN + (n * FZN_TREE_ID_LEN);
}

/* PURGE_ACK as a request: `sender` erased a note this store is purging.
 * Recorded only when the purge pins `sender`; the purge finishes here once
 * every pinned host has answered. Echoed, with ERASED when recorded. */
static size_t answer_ack(const fzn_notes_store_t *store, const uint8_t *sender,
                         const uint8_t *request, size_t request_len, uint8_t *reply, size_t cap)
{
	uint8_t recorded = FZN_NOTES_SYNC_NOT_ERASED;
	int complete = 0;

	if (request_len != FZN_NOTES_SYNC_PURGE_ACK_LEN || cap < FZN_NOTES_SYNC_PURGE_ACK_LEN)
		return 0;
	if (sender && request[2 + FZN_TREE_ID_LEN] == FZN_NOTES_SYNC_ERASED
	    && fzn_notes_purge_answer(store, request + 2, sender, &complete) == FZN_NOTES_OK) {
		recorded = FZN_NOTES_SYNC_ERASED;
		if (complete)
			(void)fzn_notes_purge_finish(store, request + 2);
	}
	head(reply, FZN_NOTES_SYNC_PURGE_ACK);
	memcpy(reply + 2, request + 2, FZN_TREE_ID_LEN);
	reply[2 + FZN_TREE_ID_LEN] = recorded;
	return FZN_NOTES_SYNC_PURGE_ACK_LEN;
}

/* ---- wrap keys, sec 520 ---------------------------------------------------- */

/* The notes this store indexes, each once: every claim's subject. */
static size_t held_ids(const fzn_notes_store_t *store, uint8_t (*ids)[FZN_TREE_ID_LEN])
{
	static uint8_t keys[FZN_NOTES_MAX][FZN_PUBKEY_LEN];
	static uint8_t record[FZN_RECORD_MAX_LEN];
	size_t count = 0, i, j, n = 0;

	if (fzn_notes_claims(store, keys, FZN_NOTES_MAX, &count) != FZN_NOTES_OK)
		return 0;
	for (i = 0; i < count; i++) {
		fzn_record_t rec;
		size_t len = 0;
		int seen = 0;

		if (fzn_notes_get_key(store, keys[i], record, sizeof(record), &len) != FZN_NOTES_OK
		    || fzn_record_open(record, len, &rec) != FZN_RECORD_OK)
			continue;
		for (j = 0; j < n && !seen; j++)
			seen = memcmp(ids[j], fzn_record_subject(rec), FZN_TREE_ID_LEN) == 0;
		if (!seen)
			memcpy(ids[n++], fzn_record_subject(rec), FZN_TREE_ID_LEN);
	}
	return n;
}

static int listed(const uint8_t (*ids)[FZN_TREE_ID_LEN], size_t n, const uint8_t *id)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (memcmp(ids[i], id, FZN_TREE_ID_LEN) == 0)
			return 1;
	return 0;
}

/* WRAPS: the keys held for the notes asked about, within `scope`. */
static size_t answer_wraps(const fzn_notes_store_t *store, const fzn_notes_sync_scope_t *scope,
                           const uint8_t *request, size_t request_len, uint8_t *reply,
                           size_t cap)
{
	size_t count, i, at = FZN_NOTES_SYNC_LIST_HEAD_LEN, n = 0;

	if (request_len < FZN_NOTES_SYNC_LIST_HEAD_LEN)
		return 0;
	count = request[2];
	if (count > FZN_NOTES_SYNC_WRAPS_MAX
	    || request_len != FZN_NOTES_SYNC_LIST_HEAD_LEN + (count * FZN_TREE_ID_LEN)
	    || cap < FZN_NOTES_SYNC_LIST_HEAD_LEN + (count * FZN_NOTES_SYNC_WRAP_ENTRY_LEN))
		return 0;
	for (i = 0; i < count; i++) {
		const uint8_t *id = request + FZN_NOTES_SYNC_LIST_HEAD_LEN + (i * FZN_TREE_ID_LEN);

		if (!in_scope(scope, id) || fzn_notes_purged(store, id)
		    || fzn_notes_wrap_get(store, id, reply + at + FZN_TREE_ID_LEN) != FZN_NOTES_OK)
			continue;
		memcpy(reply + at, id, FZN_TREE_ID_LEN);
		at += FZN_NOTES_SYNC_WRAP_ENTRY_LEN;
		n++;
	}
	head(reply, FZN_NOTES_SYNC_WRAPS);
	reply[2] = (uint8_t)n;
	return at;
}

/* LACKS: the notes this store indexes with no key, the first that fit. */
static size_t answer_lacks(const fzn_notes_store_t *store, size_t request_len, uint8_t *reply,
                           size_t cap)
{
	static uint8_t ids[FZN_NOTES_MAX][FZN_TREE_ID_LEN];
	uint8_t key[FZN_NOTE_WRAP_KEY_LEN];
	size_t held, i, n = 0;

	if (request_len != FZN_NOTES_SYNC_HEAD_LEN
	    || cap < FZN_NOTES_SYNC_LIST_HEAD_LEN + (FZN_NOTES_SYNC_WRAPS_MAX * FZN_TREE_ID_LEN))
		return 0;
	held = held_ids(store, ids);
	for (i = 0; i < held && n < FZN_NOTES_SYNC_WRAPS_MAX; i++) {
		if (fzn_notes_purged(store, ids[i])
		    || fzn_notes_wrap_get(store, ids[i], key) != FZN_NOTES_ERR_ABSENT)
			continue;
		memcpy(reply + FZN_NOTES_SYNC_LIST_HEAD_LEN + (n * FZN_TREE_ID_LEN), ids[i],
		       FZN_TREE_ID_LEN);
		n++;
	}
	memset(key, 0, sizeof(key));
	head(reply, FZN_NOTES_SYNC_LACKS);
	reply[2] = (uint8_t)n;
	return FZN_NOTES_SYNC_LIST_HEAD_LEN + (n * FZN_TREE_ID_LEN);
}

/* Take `count` entries of `bytes` for the notes this store indexes. */
static size_t take_wraps(const fzn_notes_store_t *store, const uint8_t *bytes, size_t count,
                         size_t *refused)
{
	static uint8_t ids[FZN_NOTES_MAX][FZN_TREE_ID_LEN];
	size_t held = held_ids(store, ids), i, taken = 0;

	for (i = 0; i < count; i++) {
		const uint8_t *e = bytes + (i * FZN_NOTES_SYNC_WRAP_ENTRY_LEN);

		if (listed((const uint8_t (*)[FZN_TREE_ID_LEN])ids, held, e)
		    && fzn_notes_wrap_put(store, e, e + FZN_TREE_ID_LEN) == FZN_NOTES_OK)
			taken++;
		else if (refused)
			(*refused)++;
	}
	return taken;
}

/* GIVE, from an admitted member: taken for the notes indexed here. */
static size_t answer_give(const fzn_notes_store_t *store, const uint8_t *request,
                          size_t request_len, uint8_t *reply, size_t cap)
{
	size_t count;

	if (request_len < FZN_NOTES_SYNC_LIST_HEAD_LEN || cap < FZN_NOTES_SYNC_LIST_HEAD_LEN)
		return 0;
	count = request[2];
	if (count > FZN_NOTES_SYNC_WRAPS_MAX
	    || request_len
	               != FZN_NOTES_SYNC_LIST_HEAD_LEN + (count * FZN_NOTES_SYNC_WRAP_ENTRY_LEN))
		return 0;
	head(reply, FZN_NOTES_SYNC_GIVEN);
	reply[2] = (uint8_t)take_wraps(store, request + FZN_NOTES_SYNC_LIST_HEAD_LEN, count, NULL);
	return FZN_NOTES_SYNC_LIST_HEAD_LEN;
}

size_t fzn_notes_sync_answer(const fzn_notes_store_t *store, fzn_notes_policy_t policy,
                             const uint8_t *sender, uint64_t now_ms, const uint8_t *request,
                             size_t request_len, uint8_t *reply, size_t reply_cap)
{
	if (!store || !request || !reply)
		return 0;
	if (is_type(request, request_len, FZN_NOTES_SYNC_PURGE))
		return answer_purge(store, policy, sender, request, request_len, reply, reply_cap);
	if (is_type(request, request_len, FZN_NOTES_SYNC_PURGE_ACK))
		return answer_ack(store, admits(policy, sender) ? sender : NULL, request,
		                  request_len, reply, reply_cap);
	if (is_type(request, request_len, FZN_NOTES_SYNC_PURGES_QUERY)
	    && request_len == FZN_NOTES_SYNC_PURGES_QUERY_LEN) {
		/* A NODE THIS ONE ADMITS, ASKING FOR ITS PURGES, HOLDS COPIES: a
		 * partner. Every member asks this each round since sec 519, when
		 * members stopped asking for the index. */
		if (admits(policy, sender))
			partner_seen(store, sender, now_ms);
		return answer_purges(store, admits(policy, sender) ? sender : NULL, reply,
		                     reply_cap);
	}
	/* WRAP KEYS, sec 520: a member's, both ways. A sender this node does
	 * not admit is answered nothing. */
	if (is_type(request, request_len, FZN_NOTES_SYNC_WRAPS_QUERY))
		return admits(policy, sender)
		               ? answer_wraps(store, NULL, request, request_len, reply, reply_cap)
		               : 0;
	if (is_type(request, request_len, FZN_NOTES_SYNC_LACKS_QUERY))
		return admits(policy, sender) ? answer_lacks(store, request_len, reply, reply_cap) : 0;
	if (is_type(request, request_len, FZN_NOTES_SYNC_GIVE))
		return admits(policy, sender) ? answer_give(store, request, request_len, reply, reply_cap)
		                              : 0;
	if (is_type(request, request_len, FZN_NOTES_SYNC_INDEX_QUERY)) {
		/* A NODE THIS ONE ADMITS, PULLING, HOLDS COPIES: a partner. */
		if (admits(policy, sender))
			partner_seen(store, sender, now_ms);
		return answer_index(store, NULL, request, request_len, reply, reply_cap);
	}
	if (is_type(request, request_len, FZN_NOTES_SYNC_RECORDS_QUERY))
		return answer_records(store, NULL, request, request_len, reply, reply_cap);
	return 0;
}

/* The distinct writers of what `scope` reaches, sorted. 0 bytes past
 * FZN_NOTES_SYNC_WRITERS_MAX. */
static size_t answer_writers(const fzn_notes_store_t *store, const fzn_notes_sync_scope_t *scope,
                             size_t request_len, uint8_t *reply, size_t cap)
{
	static uint8_t keys[FZN_NOTES_MAX][FZN_PUBKEY_LEN];
	static uint64_t seqs[FZN_NOTES_MAX];
	static uint8_t writers[FZN_NOTES_SYNC_WRITERS_MAX][FZN_PUBKEY_LEN];
	static uint8_t record[FZN_RECORD_MAX_LEN];
	size_t total, i, j, n = 0;

	if (request_len != FZN_NOTES_SYNC_WRITERS_QUERY_LEN)
		return 0;
	total = offered(store, scope, keys, seqs);
	for (i = 0; i < total; i++) {
		fzn_record_t rec;
		size_t len = 0;
		int seen = 0;

		if (fzn_notes_get_key(store, keys[i], record, sizeof(record), &len) != FZN_NOTES_OK
		    || fzn_record_open(record, len, &rec) != FZN_RECORD_OK)
			continue;
		for (j = 0; j < n && !seen; j++)
			seen = memcmp(writers[j], fzn_record_issuer(rec), FZN_PUBKEY_LEN) == 0;
		if (seen)
			continue;
		if (n >= FZN_NOTES_SYNC_WRITERS_MAX)
			return 0;
		memcpy(writers[n++], fzn_record_issuer(rec), FZN_PUBKEY_LEN);
	}
	if (cap < FZN_NOTES_SYNC_LIST_HEAD_LEN + (n * FZN_PUBKEY_LEN))
		return 0;
	qsort(writers, n, FZN_PUBKEY_LEN, key_order);
	head(reply, FZN_NOTES_SYNC_WRITERS);
	reply[2] = (uint8_t)n;
	memcpy(reply + FZN_NOTES_SYNC_LIST_HEAD_LEN, writers, n * FZN_PUBKEY_LEN);
	return FZN_NOTES_SYNC_LIST_HEAD_LEN + (n * FZN_PUBKEY_LEN);
}

size_t fzn_notes_sync_answer_scoped(const fzn_notes_store_t *store,
                                    const fzn_notes_sync_scope_t *scope, const uint8_t *request,
                                    size_t request_len, uint8_t *reply, size_t reply_cap)
{
	if (!store || !scope || !request || !reply)
		return 0;
	if (is_type(request, request_len, FZN_NOTES_SYNC_INDEX_QUERY))
		return answer_index(store, scope, request, request_len, reply, reply_cap);
	if (is_type(request, request_len, FZN_NOTES_SYNC_RECORDS_QUERY))
		return answer_records(store, scope, request, request_len, reply, reply_cap);
	if (is_type(request, request_len, FZN_NOTES_SYNC_WRITERS_QUERY))
		return answer_writers(store, scope, request_len, reply, reply_cap);
	/* A CONTACT'S WRAP KEYS, sec 520: only for notes in its scope. */
	if (is_type(request, request_len, FZN_NOTES_SYNC_WRAPS_QUERY))
		return answer_wraps(store, scope, request, request_len, reply, reply_cap);
	return 0;
}

/* ---- the puller ---------------------------------------------------------- */

/* Whether this store lacks the claim `key`, or holds it below `seq`. */
static int wanted(const fzn_notes_store_t *store, const uint8_t key[FZN_PUBKEY_LEN], uint64_t seq)
{
	static uint8_t record[FZN_RECORD_MAX_LEN];
	fzn_record_t rec;
	size_t len = 0;
	fzn_notes_err_t err = fzn_notes_get_key(store, key, record, sizeof(record), &len);

	if (err == FZN_NOTES_ERR_ABSENT)
		return 1;
	/* A held record that will not read is damage: fetching replaces it. */
	if (err != FZN_NOTES_OK || fzn_record_open(record, len, &rec) != FZN_RECORD_OK)
		return 1;
	return fzn_record_seq(rec) < seq;
}

static fzn_notes_sync_err_t fetch(const fzn_notes_store_t *store, fzn_notes_policy_t policy,
                                  const fzn_sign_ops_t *sign, fzn_notes_sync_ask_t ask,
                                  void *ask_ctx, uint8_t (*keys)[FZN_PUBKEY_LEN], size_t count,
                                  fzn_notes_sync_tally_t *tally)
{
	static uint8_t request[FZN_NOTES_SYNC_LIST_HEAD_LEN
	                       + (FZN_NOTES_SYNC_KEYS_MAX * FZN_PUBKEY_LEN)];
	static uint8_t reply[FZN_NOTES_SYNC_REPLY_MAX];
	size_t reply_len = 0, at, i, n;

	head(request, FZN_NOTES_SYNC_RECORDS_QUERY);
	request[2] = (uint8_t)count;
	memcpy(request + FZN_NOTES_SYNC_LIST_HEAD_LEN, keys, count * FZN_PUBKEY_LEN);
	if (!ask(ask_ctx, request, FZN_NOTES_SYNC_LIST_HEAD_LEN + (count * FZN_PUBKEY_LEN), reply,
	         sizeof(reply), &reply_len))
		return FZN_NOTES_SYNC_NO_ANSWER;
	if (!is_type(reply, reply_len, FZN_NOTES_SYNC_RECORDS)
	    || reply_len < FZN_NOTES_SYNC_LIST_HEAD_LEN || reply[2] > count)
		return FZN_NOTES_SYNC_SHAPE;
	n = reply[2];
	at = FZN_NOTES_SYNC_LIST_HEAD_LEN;
	for (i = 0; i < n; i++) {
		uint8_t key[FZN_PUBKEY_LEN];
		fzn_record_t rec;
		size_t len, j;
		int asked = 0, wrote = 0;
		const uint8_t *record;

		if (reply_len - at < 2u)
			return FZN_NOTES_SYNC_SHAPE;
		len = fzn_get_be16(reply + at);
		if (len == 0u || len > FZN_RECORD_MAX_LEN || reply_len - at - 2u < len)
			return FZN_NOTES_SYNC_SHAPE;
		record = reply + at + 2u;
		at += 2u + len;
		tally->fetched++;
		/* ONLY WHAT WAS ASKED FOR: a pull is not a way to push. */
		if (fzn_record_open(record, len, &rec) != FZN_RECORD_OK
		    || fzn_notes_claim_key(store, fzn_record_subject(rec), fzn_record_issuer(rec), key)
		               != FZN_NOTES_OK) {
			tally->refused++;
			continue;
		}
		for (j = 0; j < count && !asked; j++)
			asked = memcmp(keys[j], key, FZN_PUBKEY_LEN) == 0;
		/* AND NOTHING THIS NODE IS PURGING: it asked for it to go. */
		if (!asked || fzn_notes_purge_pending(store, fzn_record_subject(rec))) {
			tally->refused++;
			continue;
		}
		if (fzn_notes_put(store, record, len, policy, sign, &wrote, NULL) != FZN_NOTES_OK)
			tally->refused++;
		else if (wrote)
			tally->learned++;
	}
	if (at != reply_len)
		return FZN_NOTES_SYNC_SHAPE;
	return FZN_NOTES_SYNC_OK;
}

fzn_notes_sync_err_t fzn_notes_sync_pull(const fzn_notes_store_t *store,
                                         fzn_notes_policy_t policy, const fzn_sign_ops_t *sign,
                                         fzn_notes_sync_ask_t ask, void *ask_ctx,
                                         fzn_notes_sync_tally_t *tally)
{
	static uint8_t reply[FZN_NOTES_SYNC_REPLY_MAX];
	static uint8_t want[FZN_NOTES_MAX][FZN_PUBKEY_LEN];
	uint8_t request[FZN_NOTES_SYNC_INDEX_QUERY_LEN];
	size_t from = 0, total = 0, n_want = 0, pages = 0, i;
	fzn_notes_sync_err_t err;

	if (!store || !sign || !ask || !tally)
		return FZN_NOTES_SYNC_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	/* THE INDEX, a page at a time. At most one page a claim, and a store
	 * this size: the bound is never the one that stops it. */
	do {
		size_t reply_len = 0, count;

		head(request, FZN_NOTES_SYNC_INDEX_QUERY);
		fzn_put_be16(request + 2, (uint16_t)from);
		if (!ask(ask_ctx, request, sizeof(request), reply, sizeof(reply), &reply_len))
			return FZN_NOTES_SYNC_NO_ANSWER;
		if (!is_type(reply, reply_len, FZN_NOTES_SYNC_INDEX)
		    || reply_len < FZN_NOTES_SYNC_INDEX_HEAD_LEN)
			return FZN_NOTES_SYNC_SHAPE;
		total = fzn_get_be16(reply + 2);
		count = fzn_get_be16(reply + 6);
		if (fzn_get_be16(reply + 4) != from
		    || reply_len != FZN_NOTES_SYNC_INDEX_HEAD_LEN + (count * FZN_NOTES_SYNC_CLAIM_LEN)
		    || count > total - from || (count == 0u && from < total))
			return FZN_NOTES_SYNC_SHAPE;
		for (i = 0; i < count; i++) {
			const uint8_t *c = reply + FZN_NOTES_SYNC_INDEX_HEAD_LEN
			                   + (i * FZN_NOTES_SYNC_CLAIM_LEN);

			if (n_want < FZN_NOTES_MAX && wanted(store, c, fzn_get_be64(c + FZN_PUBKEY_LEN)))
				memcpy(want[n_want++], c, FZN_PUBKEY_LEN);
		}
		from += count;
	} while (from < total && ++pages <= FZN_NOTES_MAX);
	tally->offered = total;

	/* THE RECORDS, a batch at a time. */
	for (i = 0; i < n_want; i += FZN_NOTES_SYNC_KEYS_MAX) {
		size_t batch = n_want - i < FZN_NOTES_SYNC_KEYS_MAX ? n_want - i
		                                                    : FZN_NOTES_SYNC_KEYS_MAX;

		err = fetch(store, policy, sign, ask, ask_ctx, want + i, batch, tally);
		if (err != FZN_NOTES_SYNC_OK)
			return err;
	}
	return FZN_NOTES_SYNC_OK;
}

/* ---- asking for purges --------------------------------------------------- */

fzn_notes_sync_err_t fzn_notes_sync_purges(const fzn_notes_store_t *store,
                                           fzn_notes_policy_t policy,
                                           const uint8_t host[FZN_PUBKEY_LEN],
                                           fzn_notes_sync_ask_t ask, void *ask_ctx,
                                           fzn_notes_purge_tally_t *tally)
{
	static uint8_t ids[FZN_NOTES_PURGE_MAX][FZN_TREE_ID_LEN];
	static fzn_notes_purge_t p;
	uint8_t request[FZN_NOTES_SYNC_PURGE_LEN], reply[FZN_NOTES_SYNC_PURGE_ACK_LEN + 1u];
	size_t count = 0, i, j;

	if (!store || !host || !ask || !tally)
		return FZN_NOTES_SYNC_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	if (fzn_notes_purge_list(store, ids, FZN_NOTES_PURGE_MAX, &count) != FZN_NOTES_OK)
		return FZN_NOTES_SYNC_STORE;
	for (i = 0; i < count; i++) {
		size_t reply_len = 0;
		int pinned = 0, complete = 0;

		if (fzn_notes_purge_get(store, ids[i], &p) != FZN_NOTES_OK)
			continue;
		/* EVERY HOST ANSWERED AND THE PURGE STILL QUEUED: the erase after
		 * the last answer failed, and no host is owed a question any more,
		 * so nothing below would ever reach it. Finish it first. Reported
		 * by fuzzypickles, whose purge had the same edge (their sec 191). */
		{
			size_t answered = 0;

			for (j = 0; j < p.asked_count; j++)
				answered += p.answered[j] ? 1u : 0u;
			if (answered == p.asked_count) {
				if (fzn_notes_purge_finish(store, p.id) != FZN_NOTES_OK)
					return FZN_NOTES_SYNC_STORE;
				tally->finished++;
				continue;
			}
		}
		/* ONLY A HOST THE PURGE PINNED, AND ONLY UNTIL IT ANSWERS. */
		for (j = 0; j < p.asked_count && !pinned; j++)
			pinned = !p.answered[j] && fzn_ct_memeq(p.asked[j], host, FZN_PUBKEY_LEN);
		if (!pinned)
			continue;
		head(request, FZN_NOTES_SYNC_PURGE);
		memcpy(request + 2, p.id, FZN_TREE_ID_LEN);
		tally->asked++;
		if (!ask(ask_ctx, request, sizeof(request), reply, sizeof(reply), &reply_len))
			return FZN_NOTES_SYNC_NO_ANSWER;
		if (!is_type(reply, reply_len, FZN_NOTES_SYNC_PURGE_ACK)
		    || reply_len != FZN_NOTES_SYNC_PURGE_ACK_LEN
		    || memcmp(reply + 2, p.id, FZN_TREE_ID_LEN) != 0
		    || reply[2 + FZN_TREE_ID_LEN] > FZN_NOTES_SYNC_ERASED)
			return FZN_NOTES_SYNC_SHAPE;
		if (reply[2 + FZN_TREE_ID_LEN] != FZN_NOTES_SYNC_ERASED) {
			tally->refused++;
			continue;
		}
		tally->erased++;
		if (fzn_notes_purge_answer(store, p.id, host, &complete) != FZN_NOTES_OK)
			return FZN_NOTES_SYNC_STORE;
		/* CONSENT COMPLETE: erase here too, then drop the entry. */
		if (complete) {
			if (fzn_notes_purge_finish(store, p.id) != FZN_NOTES_OK)
				return FZN_NOTES_SYNC_STORE;
			tally->finished++;
		}
	}

	/* THE HOST'S PURGES THAT PIN THIS NODE: erase, then say so. */
	{
		uint8_t list[FZN_NOTES_SYNC_LIST_HEAD_LEN
		             + (FZN_NOTES_SYNC_PURGES_MAX * FZN_TREE_ID_LEN)];
		uint8_t ack[FZN_NOTES_SYNC_PURGE_ACK_LEN];
		size_t list_len = 0, n;

		head(request, FZN_NOTES_SYNC_PURGES_QUERY);
		if (!ask(ask_ctx, request, FZN_NOTES_SYNC_PURGES_QUERY_LEN, list, sizeof(list),
		         &list_len))
			return FZN_NOTES_SYNC_NO_ANSWER;
		if (!is_type(list, list_len, FZN_NOTES_SYNC_PURGES)
		    || list_len < FZN_NOTES_SYNC_LIST_HEAD_LEN || list[2] > FZN_NOTES_SYNC_PURGES_MAX
		    || list_len != FZN_NOTES_SYNC_LIST_HEAD_LEN + ((size_t)list[2] * FZN_TREE_ID_LEN))
			return FZN_NOTES_SYNC_SHAPE;
		n = list[2];
		for (i = 0; i < n; i++) {
			const uint8_t *id = list + FZN_NOTES_SYNC_LIST_HEAD_LEN + (i * FZN_TREE_ID_LEN);
			size_t reply_len = 0;

			/* ERASED ONLY FOR A HOST THIS NODE ADMITS. A host it does not
			 * is not answered at all: its purge waits, as it should. */
			if (!admits(policy, host) || fzn_notes_erase_note(store, id, NULL) != FZN_NOTES_OK) {
				tally->declined++;
				continue;
			}
			head(ack, FZN_NOTES_SYNC_PURGE_ACK);
			memcpy(ack + 2, id, FZN_TREE_ID_LEN);
			ack[2 + FZN_TREE_ID_LEN] = FZN_NOTES_SYNC_ERASED;
			if (!ask(ask_ctx, ack, sizeof(ack), reply, sizeof(reply), &reply_len))
				return FZN_NOTES_SYNC_NO_ANSWER;
			if (!is_type(reply, reply_len, FZN_NOTES_SYNC_PURGE_ACK)
			    || reply_len != FZN_NOTES_SYNC_PURGE_ACK_LEN
			    || memcmp(reply + 2, id, FZN_TREE_ID_LEN) != 0)
				return FZN_NOTES_SYNC_SHAPE;
			tally->taken++;
		}
	}
	return FZN_NOTES_SYNC_OK;
}

fzn_notes_sync_err_t fzn_notes_sync_pull_shared(const fzn_notes_store_t *store,
                                                const fzn_sign_ops_t *sign,
                                                fzn_notes_sync_ask_t ask, void *ask_ctx,
                                                fzn_notes_sync_tally_t *tally)
{
	static uint8_t reply[FZN_NOTES_SYNC_REPLY_MAX];
	static fzn_notes_writer_t writers[FZN_NOTES_SYNC_WRITERS_MAX];
	uint8_t request[FZN_NOTES_SYNC_WRITERS_QUERY_LEN];
	size_t reply_len = 0, count, i;

	if (!store || !sign || !ask || !tally)
		return FZN_NOTES_SYNC_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	head(request, FZN_NOTES_SYNC_WRITERS_QUERY);
	if (!ask(ask_ctx, request, sizeof(request), reply, sizeof(reply), &reply_len))
		return FZN_NOTES_SYNC_NO_ANSWER;
	if (reply_len < FZN_NOTES_SYNC_LIST_HEAD_LEN
	    || !is_type(reply, reply_len, FZN_NOTES_SYNC_WRITERS))
		return FZN_NOTES_SYNC_SHAPE;
	count = reply[2];
	if (count > FZN_NOTES_SYNC_WRITERS_MAX
	    || reply_len != FZN_NOTES_SYNC_LIST_HEAD_LEN + (count * FZN_PUBKEY_LEN))
		return FZN_NOTES_SYNC_SHAPE;
	for (i = 0; i < count; i++)
		memcpy(writers[i].key, reply + FZN_NOTES_SYNC_LIST_HEAD_LEN + (i * FZN_PUBKEY_LEN),
		       FZN_PUBKEY_LEN);
	/* NOBODY WROTE ANYTHING SHARED: nothing to pull, and an empty policy
	 * denies, so there is no pull to make either. */
	if (count == 0u)
		return FZN_NOTES_SYNC_OK;
	return fzn_notes_sync_pull(store, fzn_notes_policy_writers(writers, count), sign, ask,
	                           ask_ctx, tally);
}

/* ---- the wrap puller, sec 520 ------------------------------------------------ */

fzn_notes_sync_err_t fzn_notes_sync_wraps(const fzn_notes_store_t *store,
                                          fzn_notes_sync_ask_t ask, void *ask_ctx, int give,
                                          fzn_notes_wrap_tally_t *tally)
{
	static uint8_t ids[FZN_NOTES_MAX][FZN_TREE_ID_LEN];
	static uint8_t lacking[FZN_NOTES_MAX][FZN_TREE_ID_LEN];
	static uint8_t request[FZN_NOTES_SYNC_WRAPS_REPLY_MAX];
	static uint8_t reply[FZN_NOTES_SYNC_WRAPS_REPLY_MAX];
	uint8_t key[FZN_NOTE_WRAP_KEY_LEN];
	size_t held, n_lacking = 0, i, from, reply_len = 0;

	if (!store || !ask || !tally)
		return FZN_NOTES_SYNC_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	held = held_ids(store, ids);
	for (i = 0; i < held; i++)
		if (!fzn_notes_purged(store, ids[i])
		    && fzn_notes_wrap_get(store, ids[i], key) == FZN_NOTES_ERR_ABSENT)
			memcpy(lacking[n_lacking++], ids[i], FZN_TREE_ID_LEN);
	memset(key, 0, sizeof(key));
	/* WHAT THIS STORE LACKS, asked a page at a time. */
	for (from = 0; from < n_lacking; from += FZN_NOTES_SYNC_WRAPS_MAX) {
		size_t count = n_lacking - from < FZN_NOTES_SYNC_WRAPS_MAX ? n_lacking - from
		                                                            : FZN_NOTES_SYNC_WRAPS_MAX;
		size_t got, j;

		head(request, FZN_NOTES_SYNC_WRAPS_QUERY);
		request[2] = (uint8_t)count;
		memcpy(request + FZN_NOTES_SYNC_LIST_HEAD_LEN, lacking[from], count * FZN_TREE_ID_LEN);
		tally->asked += count;
		if (!ask(ask_ctx, request, FZN_NOTES_SYNC_LIST_HEAD_LEN + (count * FZN_TREE_ID_LEN),
		         reply, sizeof(reply), &reply_len))
			return FZN_NOTES_SYNC_NO_ANSWER;
		if (!is_type(reply, reply_len, FZN_NOTES_SYNC_WRAPS)
		    || reply_len < FZN_NOTES_SYNC_LIST_HEAD_LEN || reply[2] > count
		    || reply_len != FZN_NOTES_SYNC_LIST_HEAD_LEN
		                            + ((size_t)reply[2] * FZN_NOTES_SYNC_WRAP_ENTRY_LEN))
			return FZN_NOTES_SYNC_SHAPE;
		got = reply[2];
		/* ONLY WHAT WAS ASKED: a key for a note not asked about is not
		 * taken, however this store might index it. */
		for (j = 0; j < got; j++)
			if (!listed((const uint8_t (*)[FZN_TREE_ID_LEN])lacking + from, count,
			            reply + FZN_NOTES_SYNC_LIST_HEAD_LEN
			                    + (j * FZN_NOTES_SYNC_WRAP_ENTRY_LEN)))
				return FZN_NOTES_SYNC_SHAPE;
		tally->taken += take_wraps(store, reply + FZN_NOTES_SYNC_LIST_HEAD_LEN, got,
		                           &tally->refused);
	}
	if (!give)
		return FZN_NOTES_SYNC_OK;
	/* WHAT THE PEER LACKS, given from what this store holds. */
	head(request, FZN_NOTES_SYNC_LACKS_QUERY);
	if (!ask(ask_ctx, request, FZN_NOTES_SYNC_HEAD_LEN, reply, sizeof(reply), &reply_len))
		return FZN_NOTES_SYNC_NO_ANSWER;
	if (!is_type(reply, reply_len, FZN_NOTES_SYNC_LACKS)
	    || reply_len < FZN_NOTES_SYNC_LIST_HEAD_LEN || reply[2] > FZN_NOTES_SYNC_WRAPS_MAX
	    || reply_len != FZN_NOTES_SYNC_LIST_HEAD_LEN + ((size_t)reply[2] * FZN_TREE_ID_LEN))
		return FZN_NOTES_SYNC_SHAPE;
	{
		size_t count = reply[2], at = FZN_NOTES_SYNC_LIST_HEAD_LEN, n = 0;

		for (i = 0; i < count; i++) {
			const uint8_t *id = reply + FZN_NOTES_SYNC_LIST_HEAD_LEN + (i * FZN_TREE_ID_LEN);

			if (fzn_notes_purged(store, id)
			    || fzn_notes_wrap_get(store, id, request + at + FZN_TREE_ID_LEN)
			               != FZN_NOTES_OK)
				continue;
			memcpy(request + at, id, FZN_TREE_ID_LEN);
			at += FZN_NOTES_SYNC_WRAP_ENTRY_LEN;
			n++;
		}
		if (n == 0u)
			return FZN_NOTES_SYNC_OK;
		head(request, FZN_NOTES_SYNC_GIVE);
		request[2] = (uint8_t)n;
		if (!ask(ask_ctx, request, at, reply, sizeof(reply), &reply_len)) {
			memset(request, 0, at);
			return FZN_NOTES_SYNC_NO_ANSWER;
		}
		memset(request, 0, at);
		if (!is_type(reply, reply_len, FZN_NOTES_SYNC_GIVEN)
		    || reply_len != FZN_NOTES_SYNC_LIST_HEAD_LEN || reply[2] > n)
			return FZN_NOTES_SYNC_SHAPE;
		tally->given = reply[2];
	}
	return FZN_NOTES_SYNC_OK;
}
