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

/* What this store offers: its claims, IN KEY ORDER so a page means the same
 * thing on every call, without a note pending purge. */
static size_t offered(const fzn_notes_store_t *store, uint8_t (*keys)[FZN_PUBKEY_LEN],
                      uint64_t *seqs)
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
		    || fzn_notes_purge_pending(store, fzn_record_subject(rec)))
			continue;
		if (n != i)
			memcpy(keys[n], keys[i], FZN_PUBKEY_LEN);
		seqs[n++] = fzn_record_seq(rec);
	}
	return n;
}

static size_t answer_index(const fzn_notes_store_t *store, const uint8_t *request,
                           size_t request_len, uint8_t *reply, size_t cap)
{
	static uint8_t keys[FZN_NOTES_MAX][FZN_PUBKEY_LEN];
	static uint64_t seqs[FZN_NOTES_MAX];
	size_t total, from, n = 0, i;

	if (request_len != FZN_NOTES_SYNC_INDEX_QUERY_LEN || cap < FZN_NOTES_SYNC_INDEX_HEAD_LEN)
		return 0;
	from = fzn_get_be16(request + 2);
	total = offered(store, keys, seqs);
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

static size_t answer_records(const fzn_notes_store_t *store, const uint8_t *request,
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
		    || fzn_notes_purge_pending(store, fzn_record_subject(rec)))
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
	    && request_len == FZN_NOTES_SYNC_PURGES_QUERY_LEN)
		return answer_purges(store, admits(policy, sender) ? sender : NULL, reply,
		                     reply_cap);
	if (is_type(request, request_len, FZN_NOTES_SYNC_INDEX_QUERY)) {
		/* A NODE THIS ONE ADMITS, PULLING, HOLDS COPIES: a partner. */
		if (admits(policy, sender))
			partner_seen(store, sender, now_ms);
		return answer_index(store, request, request_len, reply, reply_cap);
	}
	if (is_type(request, request_len, FZN_NOTES_SYNC_RECORDS_QUERY))
		return answer_records(store, request, request_len, reply, reply_cap);
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
