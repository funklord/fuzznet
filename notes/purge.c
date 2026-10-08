/* See purge.h. */

#include "purge.h"

#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#include <string.h>

#define OFF_QUEUED 0u
#define OFF_PUSH 8u
#define OFF_COUNT 16u
#define OFF_HOSTS 17u
#define HOST_LEN (FZN_PUBKEY_LEN + 1u)
#define BODY_LEN(n) ((size_t)OFF_HOSTS + ((size_t)(n) * HOST_LEN))
#define BLOB_MAX ((size_t)FZN_PERSIST_HEAD_LEN + BODY_LEN(FZN_NOTES_PURGE_ASK_MAX))

static fzn_notes_err_t save(const fzn_notes_store_t *store, const fzn_notes_purge_t *p)
{
	uint8_t blob[BLOB_MAX];
	uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	size_t i;

	if (fzn_persist_head_write(blob, sizeof(blob), BODY_LEN(p->asked_count),
	                           FZN_PERSIST_BLOB_NOTE_PURGE)
	    != FZN_PERSIST_OK)
		return FZN_NOTES_ERR_MALFORMED;
	fzn_put_be64(body + OFF_QUEUED, p->queued_at_ms);
	fzn_put_be64(body + OFF_PUSH, p->last_push_ms);
	body[OFF_COUNT] = (uint8_t)p->asked_count;
	for (i = 0; i < p->asked_count; i++) {
		memcpy(body + OFF_HOSTS + (i * HOST_LEN), p->asked[i], FZN_PUBKEY_LEN);
		body[OFF_HOSTS + (i * HOST_LEN) + FZN_PUBKEY_LEN] = p->answered[i] ? 1u : 0u;
	}
	if (!store->ops->save(store->ops->ctx, FZN_PERSIST_NOTE_PURGE, p->id, blob,
	                      FZN_PERSIST_HEAD_LEN + BODY_LEN(p->asked_count)))
		return FZN_NOTES_ERR_BACKEND;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_purge_get(const fzn_notes_store_t *store,
                                    const uint8_t id[FZN_TREE_ID_LEN], fzn_notes_purge_t *out)
{
	uint8_t blob[BLOB_MAX];
	const uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	size_t len = 0, n, i;

	if (!store || !store->ops || !id || !out)
		return FZN_NOTES_ERR_MALFORMED;
	if (!store->ops->load(store->ops->ctx, FZN_PERSIST_NOTE_PURGE, id, blob, sizeof(blob), &len))
		return FZN_NOTES_ERR_ABSENT;
	if (len < FZN_PERSIST_HEAD_LEN + OFF_HOSTS)
		return FZN_NOTES_ERR_SHAPE;
	n = body[OFF_COUNT];
	if (n == 0u || n > FZN_NOTES_PURGE_ASK_MAX
	    || fzn_persist_head_check(blob, len, BODY_LEN(n), FZN_PERSIST_BLOB_NOTE_PURGE)
	               != FZN_PERSIST_OK)
		return FZN_NOTES_ERR_SHAPE;
	memset(out, 0, sizeof(*out));
	memcpy(out->id, id, FZN_TREE_ID_LEN);
	out->queued_at_ms = fzn_get_be64(body + OFF_QUEUED);
	out->last_push_ms = fzn_get_be64(body + OFF_PUSH);
	out->asked_count = n;
	for (i = 0; i < n; i++) {
		const uint8_t *h = body + OFF_HOSTS + (i * HOST_LEN);

		if (h[FZN_PUBKEY_LEN] > 1u)
			return FZN_NOTES_ERR_SHAPE;
		memcpy(out->asked[i], h, FZN_PUBKEY_LEN);
		out->answered[i] = h[FZN_PUBKEY_LEN];
	}
	return FZN_NOTES_OK;
}

int fzn_notes_purge_pending(const fzn_notes_store_t *store, const uint8_t id[FZN_TREE_ID_LEN])
{
	static fzn_notes_purge_t p;

	/* A ROW THAT WILL NOT READ IS STILL A PURGE: it is kept out of view
	 * and out of what is pushed, the side that cannot bring a note back. */
	return fzn_notes_purge_get(store, id, &p) != FZN_NOTES_ERR_ABSENT;
}

fzn_notes_err_t fzn_notes_purge_add(const fzn_notes_store_t *store,
                                    const uint8_t id[FZN_TREE_ID_LEN], fzn_notes_asking_t asking,
                                    uint64_t now_ms, int *complete)
{
	static fzn_notes_purge_t p;
	static uint8_t ids[FZN_NOTES_PURGE_MAX][FZN_PUBKEY_LEN];
	size_t i, j, count = 0;

	if (complete)
		*complete = 0;
	if (!store || !store->ops || !id || !complete)
		return FZN_NOTES_ERR_MALFORMED;
	/* AN UNSPELLED SET IS NOT AN EMPTY ONE: see purge.h. */
	if (!asking.spelled || (asking.count && !asking.hosts))
		return FZN_NOTES_ERR_MALFORMED;
	if (fzn_notes_purge_pending(store, id))
		return FZN_NOTES_OK;

	memset(&p, 0, sizeof(p));
	memcpy(p.id, id, FZN_TREE_ID_LEN);
	p.queued_at_ms = now_ms;
	/* DEDUPLICATED: a host named twice could never be answered twice. */
	for (i = 0; i < asking.count; i++) {
		int seen = 0;

		for (j = 0; j < p.asked_count && !seen; j++)
			seen = fzn_ct_memeq(p.asked[j], asking.hosts[i].key, FZN_PUBKEY_LEN);
		if (seen)
			continue;
		if (p.asked_count == FZN_NOTES_PURGE_ASK_MAX)
			return FZN_NOTES_ERR_MALFORMED;
		memcpy(p.asked[p.asked_count++], asking.hosts[i].key, FZN_PUBKEY_LEN);
	}
	/* NOBODY TO ASK IS CONSENT, and nothing is queued for it: an entry
	 * with no host to answer is one nothing could ever clear. */
	if (p.asked_count == 0u) {
		*complete = 1;
		return FZN_NOTES_OK;
	}
	if (!store->ops->list
	    || !store->ops->list(store->ops->ctx, FZN_PERSIST_NOTE_PURGE, (uint8_t *)ids,
	                         FZN_NOTES_PURGE_MAX, &count)
	    || count >= FZN_NOTES_PURGE_MAX)
		return FZN_NOTES_ERR_FULL;
	return save(store, &p);
}

fzn_notes_err_t fzn_notes_purge_answer(const fzn_notes_store_t *store,
                                       const uint8_t id[FZN_TREE_ID_LEN],
                                       const uint8_t host[FZN_PUBKEY_LEN], int *complete)
{
	static fzn_notes_purge_t p;
	size_t i, done = 0;
	int changed = 0;
	fzn_notes_err_t err;

	if (complete)
		*complete = 0;
	if (!store || !id || !host || !complete)
		return FZN_NOTES_ERR_MALFORMED;
	err = fzn_notes_purge_get(store, id, &p);
	if (err != FZN_NOTES_OK)
		return err;
	for (i = 0; i < p.asked_count; i++) {
		if (!p.answered[i] && fzn_ct_memeq(p.asked[i], host, FZN_PUBKEY_LEN)) {
			p.answered[i] = 1u;
			changed = 1;
		}
		done += p.answered[i] ? 1u : 0u;
	}
	if (changed) {
		err = save(store, &p);
		if (err != FZN_NOTES_OK)
			return err;
	}
	*complete = done == p.asked_count;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_erase_note(const fzn_notes_store_t *store,
                                     const uint8_t id[FZN_TREE_ID_LEN], size_t *erased)
{
	static uint8_t keys[FZN_NOTES_MAX][FZN_PUBKEY_LEN];
	static uint8_t record[FZN_RECORD_MAX_LEN];
	size_t count = 0, i, gone = 0;
	fzn_notes_err_t err;

	if (erased)
		*erased = 0;
	if (!store || !store->ops || !id)
		return FZN_NOTES_ERR_MALFORMED;
	/* A BACKEND THAT CANNOT FORGET must not let a host answer "erased". */
	if (!store->ops->remove)
		return FZN_NOTES_ERR_UNSUPPORTED;
	/* THE MARK FIRST, sec 518: a crash after it leaves claims the index
	 * no longer adds to, and erasing them is retried; one before it leaves
	 * a note still whole. The other order leaves a note gone from the
	 * index and filed again from its writers' streams. */
	err = fzn_notes_mark_purged(store, id);
	if (err != FZN_NOTES_OK)
		return err;
	/* THE WRAP KEY GOES WITH IT, sec 520: every shell the note leaves holds
	 * a content key only this unwrapped. */
	err = fzn_notes_wrap_erase(store, id);
	if (err != FZN_NOTES_OK)
		return err;
	err = fzn_notes_claims(store, keys, FZN_NOTES_MAX, &count);
	if (err != FZN_NOTES_OK)
		return err;
	/* EVERY CLAIM ON THE NOTE: a node carries one per writer. */
	for (i = 0; i < count; i++) {
		fzn_record_t rec;
		size_t len = 0;

		if (fzn_notes_get_key(store, keys[i], record, sizeof(record), &len) != FZN_NOTES_OK
		    || fzn_record_open(record, len, &rec) != FZN_RECORD_OK
		    || memcmp(fzn_record_subject(rec), id, FZN_TREE_ID_LEN) != 0)
			continue;
		if (!store->ops->remove(store->ops->ctx, FZN_PERSIST_NOTE, keys[i]))
			return FZN_NOTES_ERR_BACKEND;
		gone++;
	}
	if (erased)
		*erased = gone;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_purge_finish(const fzn_notes_store_t *store,
                                       const uint8_t id[FZN_TREE_ID_LEN])
{
	fzn_notes_err_t err = fzn_notes_erase_note(store, id, NULL);

	if (err != FZN_NOTES_OK)
		return err;
	/* LAST: the entry is what remembers the note is still to go. */
	if (!store->ops->remove(store->ops->ctx, FZN_PERSIST_NOTE_PURGE, id))
		return FZN_NOTES_ERR_BACKEND;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_purge_list(const fzn_notes_store_t *store,
                                     uint8_t (*ids)[FZN_TREE_ID_LEN], size_t cap, size_t *count)
{
	if (!store || !store->ops || !ids || !count)
		return FZN_NOTES_ERR_MALFORMED;
	*count = 0;
	if (!store->ops->list
	    || !store->ops->list(store->ops->ctx, FZN_PERSIST_NOTE_PURGE, (uint8_t *)ids, cap, count))
		return FZN_NOTES_ERR_BACKEND;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_purge_due(const fzn_notes_store_t *store, uint64_t now_ms,
                                    uint8_t (*ids)[FZN_TREE_ID_LEN], size_t cap, size_t *count)
{
	static uint8_t keys[FZN_NOTES_PURGE_MAX][FZN_PUBKEY_LEN];
	static fzn_notes_purge_t p;
	size_t held = 0, i, n = 0;
	fzn_notes_err_t err;

	if (!store || !store->ops || !ids || !count)
		return FZN_NOTES_ERR_MALFORMED;
	*count = 0;
	if (!store->ops->list
	    || !store->ops->list(store->ops->ctx, FZN_PERSIST_NOTE_PURGE, (uint8_t *)keys,
	                         FZN_NOTES_PURGE_MAX, &held))
		return FZN_NOTES_ERR_BACKEND;
	for (i = 0; i < held && n < cap; i++) {
		if (fzn_notes_purge_get(store, keys[i], &p) != FZN_NOTES_OK)
			continue;
		if (p.last_push_ms != 0u && now_ms - p.last_push_ms < FZN_NOTES_PURGE_RETRY_MS
		    && now_ms >= p.last_push_ms)
			continue;
		p.last_push_ms = now_ms;
		err = save(store, &p);
		if (err != FZN_NOTES_OK)
			return err;
		memcpy(ids[n++], p.id, FZN_TREE_ID_LEN);
	}
	*count = n;
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_purge_release(const fzn_notes_store_t *store, uint64_t now_ms,
                                        uint64_t age_ms, fzn_notes_purge_heard_fn heard,
                                        void *heard_ctx, size_t *released, size_t *finished)
{
	static uint8_t keys[FZN_NOTES_PURGE_MAX][FZN_PUBKEY_LEN];
	static fzn_notes_purge_t p;
	size_t held = 0, i, j, done;
	fzn_notes_err_t err;

	if (!store || !store->ops || !heard || !released || !finished)
		return FZN_NOTES_ERR_MALFORMED;
	*released = 0;
	*finished = 0;
	if (!store->ops->list
	    || !store->ops->list(store->ops->ctx, FZN_PERSIST_NOTE_PURGE, (uint8_t *)keys,
	                         FZN_NOTES_PURGE_MAX, &held))
		return FZN_NOTES_ERR_BACKEND;
	for (i = 0; i < held; i++) {
		int changed = 0;

		if (fzn_notes_purge_get(store, keys[i], &p) != FZN_NOTES_OK)
			continue;
		/* STAMPED BY A CLOCK SINCE SET BACK: age it from now. */
		if (p.queued_at_ms > now_ms) {
			p.queued_at_ms = now_ms;
			err = save(store, &p);
			if (err != FZN_NOTES_OK)
				return err;
			continue;
		}
		if (now_ms - p.queued_at_ms <= age_ms)
			continue;
		for (j = 0, done = 0; j < p.asked_count; j++) {
			if (!p.answered[j] && !heard(heard_ctx, p.asked[j], now_ms)) {
				p.answered[j] = 1u;
				changed = 1;
				(*released)++;
			}
			done += p.answered[j] ? 1u : 0u;
		}
		if (changed) {
			err = save(store, &p);
			if (err != FZN_NOTES_OK)
				return err;
		}
		/* EVERY HOST ANSWERED, NOW OR IN AN EARLIER ROUND: an all-answered
		 * purge still queued is one whose erase failed after the last
		 * answer, and this is the retry nothing else would make. */
		if (done == p.asked_count) {
			err = fzn_notes_purge_finish(store, p.id);
			if (err != FZN_NOTES_OK)
				return err;
			(*finished)++;
		}
	}
	return FZN_NOTES_OK;
}

fzn_notes_err_t fzn_notes_purge_trash(const fzn_notes_store_t *store, fzn_notes_view_t *view,
                                      const uint8_t self[FZN_PUBKEY_LEN],
                                      fzn_notes_asking_t asking, uint64_t now_ms,
                                      size_t *queued)
{
	static uint8_t ids[FZN_NOTES_MAX][FZN_TREE_ID_LEN];
	size_t i, n = 0, started = 0;
	fzn_notes_err_t err;

	if (queued)
		*queued = 0;
	if (!store || !view || !self || !asking.spelled)
		return FZN_NOTES_ERR_MALFORMED;
	err = fzn_notes_view_load(store, view);
	if (err != FZN_NOTES_OK)
		return err;
	/* THIS HOST'S OWN TRASHED CLAIMS, the ids copied out before anything
	 * is erased under the view. */
	for (i = 0; i < view->count; i++) {
		fzn_note_meta_t meta;

		if (!fzn_ct_memeq(view->writers[i], self, FZN_PUBKEY_LEN)
		    || fzn_note_meta_open(view->nodes[i].content_type, view->nodes[i].content,
		                          view->nodes[i].content_len, &meta)
		               != FZN_NOTE_OK
		    || !(meta.flags & FZN_NOTE_FLAG_TRASHED))
			continue;
		memcpy(ids[n++], view->nodes[i].id, FZN_TREE_ID_LEN);
	}
	for (i = 0; i < n; i++) {
		int complete = 0;

		err = fzn_notes_purge_add(store, ids[i], asking, now_ms, &complete);
		if (err != FZN_NOTES_OK)
			return err;
		started++;
		if (complete) {
			err = fzn_notes_erase_note(store, ids[i], NULL);
			if (err != FZN_NOTES_OK)
				return err;
		}
	}
	if (queued)
		*queued = started;
	return FZN_NOTES_OK;
}
