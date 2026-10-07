/* See journal.h. */

#include "journal.h"

#include "../constant_time/constant_time.h"

#include <string.h>

const char *fzn_node_journal_err_str(fzn_node_journal_err_t err)
{
	switch (err) {
	case FZN_NODE_JOURNAL_OK:
		return "ok";
	case FZN_NODE_JOURNAL_MALFORMED:
		return "malformed argument";
	case FZN_NODE_JOURNAL_STORE:
		return "the record store would not open, read or write";
	case FZN_NODE_JOURNAL_FULL:
		return "no room to follow another stream";
	case FZN_NODE_JOURNAL_REFUSED:
		return "the record would not be signed or admitted";
	}
	return "unknown";
}

fzn_node_journal_err_t fzn_node_journal_init_store(fzn_node_journal_t *nj,
                                                   const fzn_record_store_ops_t *ops,
                                                   const fzn_sign_ops_t *sign,
                                                   const fzn_hash_ops_t *hash)
{
	if (!nj || !ops || !ops->get || !ops->put || !sign || !sign->verify || !hash || !hash->hash)
		return FZN_NODE_JOURNAL_MALFORMED;
	memset(nj, 0, sizeof(*nj));
	if (fzn_journal_init(&nj->journal, nj->entries, FZN_NODE_JOURNAL_STREAMS_MAX)
	    != FZN_JOURNAL_OK)
		return FZN_NODE_JOURNAL_MALFORMED;
	nj->store.ops = ops;
	nj->store.log = NULL;
	nj->sign = sign;
	nj->hash = hash;
	return FZN_NODE_JOURNAL_OK;
}

#ifdef FZN_RECORD_STORE_FILE_ON
fzn_node_journal_err_t fzn_node_journal_init(fzn_node_journal_t *nj, const char *dir,
                                             const fzn_sign_ops_t *sign,
                                             const fzn_hash_ops_t *hash)
{
	static fzn_record_store_file_t opening;
	const fzn_record_store_ops_t *ops;
	fzn_node_journal_err_t err;

	if (!nj || !dir)
		return FZN_NODE_JOURNAL_MALFORMED;
	/* OPENED BESIDE THE JOURNAL, THEN MOVED IN: init clears the struct, and
	 * the ops point into the file backend, so they must be re-pointed at
	 * the copy the journal keeps. */
	memset(&opening, 0, sizeof(opening));
	ops = fzn_record_store_file_open(&opening, dir);
	if (!ops)
		return FZN_NODE_JOURNAL_STORE;
	err = fzn_node_journal_init_store(nj, ops, sign, hash);
	if (err != FZN_NODE_JOURNAL_OK) {
		fzn_record_store_file_close(&opening);
		return err;
	}
	nj->file = opening;
	nj->file.ops.ctx = &nj->file;
	nj->store.ops = &nj->file.ops;
	nj->has_file = 1;
	return FZN_NODE_JOURNAL_OK;
}
#endif

void fzn_node_journal_close(fzn_node_journal_t *nj)
{
#ifdef FZN_RECORD_STORE_FILE_ON
	if (nj && nj->has_file)
		fzn_record_store_file_close(&nj->file);
#else
	(void)nj;
#endif
}

/* Whether this journal already follows `key`'s estate stream. */
static int followed(const fzn_node_journal_t *nj, const uint8_t key[FZN_PUBKEY_LEN])
{
	size_t i;

	for (i = 0; i < nj->journal.used; i++)
		if (nj->entries[i].stream == FZN_NODE_JOURNAL_STREAM
		    && fzn_ct_memeq(nj->entries[i].issuer, key, FZN_PUBKEY_LEN))
			return 1;
	return 0;
}

fzn_node_journal_err_t fzn_node_journal_follow(fzn_node_journal_t *nj,
                                               const uint8_t key[FZN_PUBKEY_LEN],
                                               size_t *replayed)
{
	uint8_t buf[FZN_RECORD_MAX_LEN], id[FZN_RECORD_ID_LEN];
	fzn_journal_err_t jerr;
	uint64_t seq;
	size_t n = 0;

	if (replayed)
		*replayed = 0;
	if (!nj || !key)
		return FZN_NODE_JOURNAL_MALFORMED;
	if (followed(nj, key))
		return FZN_NODE_JOURNAL_OK;
	jerr = fzn_journal_anchor(&nj->journal, key, FZN_NODE_JOURNAL_STREAM, 0);
	if (jerr == FZN_JOURNAL_ERR_FULL)
		return FZN_NODE_JOURNAL_FULL;
	if (jerr != FZN_JOURNAL_OK)
		return FZN_NODE_JOURNAL_MALFORMED;
	/* WHAT THE STORE HOLDS, through the same checks a pull applies: a
	 * record edited on disk stops the stream there rather than being
	 * believed. */
	for (seq = 1;; seq++) {
		fzn_record_t rec;
		fzn_record_store_err_t serr;

		serr = fzn_record_store_get(&nj->store, key, FZN_NODE_JOURNAL_STREAM, seq, buf,
		                            sizeof(buf), &rec);
		if (serr == FZN_RECORD_STORE_ERR_ABSENT)
			break;
		if (serr != FZN_RECORD_STORE_OK || fzn_record_verify(rec, nj->sign) != FZN_RECORD_OK
		    || !nj->hash->hash(nj->hash->ctx, id, sizeof(id), rec.base, rec.len)
		    || fzn_journal_admit_chained(&nj->journal, key, FZN_NODE_JOURNAL_STREAM, seq,
		                                 fzn_record_prev(rec), id) != FZN_JOURNAL_OK)
			break;
		n++;
	}
	if (replayed)
		*replayed = n;
	return FZN_NODE_JOURNAL_OK;
}

fzn_node_journal_err_t fzn_node_journal_append(fzn_node_journal_t *nj,
                                               const uint8_t issuer[FZN_PUBKEY_LEN],
                                               const fzn_sign_ops_t *sign, uint32_t kind,
                                               const uint8_t subject[FZN_SUBJECT_LEN],
                                               const uint8_t *body, size_t body_len,
                                               uint64_t now, uint8_t id_out[FZN_RECORD_ID_LEN])
{
	uint8_t buf[FZN_RECORD_MAX_LEN], id[FZN_RECORD_ID_LEN];
	const fzn_journal_entry_t *e = NULL;
	fzn_node_journal_err_t err;
	fzn_record_t rec;
	uint64_t seq;
	size_t len = 0, i;

	if (!nj || !issuer || !sign || !sign->sign || !subject || (body_len && !body))
		return FZN_NODE_JOURNAL_MALFORMED;
	err = fzn_node_journal_follow(nj, issuer, NULL);
	if (err != FZN_NODE_JOURNAL_OK)
		return err;
	for (i = 0; i < nj->journal.used && !e; i++)
		if (nj->entries[i].stream == FZN_NODE_JOURNAL_STREAM
		    && fzn_ct_memeq(nj->entries[i].issuer, issuer, FZN_PUBKEY_LEN))
			e = &nj->entries[i];
	/* THE HEAD MUST BE KNOWN to be named: a stream this node writes is
	 * followed from the beginning, so it always is. */
	if (!e || !e->has_head)
		return FZN_NODE_JOURNAL_REFUSED;
	seq = e->received + 1u;
	if (fzn_record_sign(issuer, subject, FZN_NODE_JOURNAL_STREAM, kind, seq,
	                    seq == 1u ? NULL : e->head, now, body, body_len, sign, buf, sizeof(buf),
	                    &len) != FZN_RECORD_OK
	    || fzn_record_open(buf, len, &rec) != FZN_RECORD_OK
	    || !nj->hash->hash(nj->hash->ctx, id, sizeof(id), buf, len)
	    || fzn_journal_admit_chained(&nj->journal, issuer, FZN_NODE_JOURNAL_STREAM, seq,
	                                 fzn_record_prev(rec), id) != FZN_JOURNAL_OK)
		return FZN_NODE_JOURNAL_REFUSED;
	if (fzn_record_store_put(&nj->store, rec) != FZN_RECORD_STORE_OK)
		return FZN_NODE_JOURNAL_STORE;
	if (id_out)
		memcpy(id_out, id, sizeof(id));
	return FZN_NODE_JOURNAL_OK;
}

fzn_node_journal_err_t fzn_node_journal_append_object(fzn_node_journal_t *nj,
                                                      const uint8_t issuer[FZN_PUBKEY_LEN],
                                                      const fzn_sign_ops_t *sign,
                                                      const uint8_t *object, size_t len,
                                                      uint64_t now,
                                                      uint8_t id[FZN_RECORD_ID_LEN])
{
	uint8_t subject[FZN_SUBJECT_LEN];

	if (!nj || !object || len < 2u || len > FZN_RECORD_BODY_MAX
	    || !FZN_OBJECT_IS_LIBRARY(object[1])
	    || !nj->hash->hash(nj->hash->ctx, subject, sizeof(subject), object, len))
		return FZN_NODE_JOURNAL_MALFORMED;
	return fzn_node_journal_append(nj, issuer, sign, object[1], subject, object, len, now, id);
}

size_t fzn_node_journal_answer(fzn_node_journal_t *nj, const uint8_t *request,
                               size_t request_len, uint8_t *reply, size_t reply_cap)
{
	if (!nj)
		return 0;
	return fzn_exchange_answer(&nj->journal, &nj->store, request, request_len, reply,
	                           reply_cap);
}

fzn_exchange_err_t fzn_node_journal_pull(fzn_node_journal_t *nj, fzn_exchange_ask_t ask,
                                         void *ask_ctx, uint8_t *reply, size_t reply_cap,
                                         fzn_exchange_tally_t *tally)
{
	if (!nj)
		return FZN_EXCHANGE_ERR_MALFORMED;
	return fzn_exchange_pull(&nj->journal, &nj->store, nj->sign, nj->hash,
	                         FZN_NODE_JOURNAL_WINDOW, ask, ask_ctx, reply, reply_cap, tally);
}
