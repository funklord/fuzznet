/* See sync.h. */

#include "sync.h"

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

size_t fzn_notes_sync_answer(const fzn_notes_store_t *store, const uint8_t *request,
                             size_t request_len, uint8_t *reply, size_t reply_cap)
{
	if (!store || !request || !reply)
		return 0;
	if (is_type(request, request_len, FZN_NOTES_SYNC_INDEX_QUERY))
		return answer_index(store, request, request_len, reply, reply_cap);
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
