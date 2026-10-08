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

/* `key`'s position on `stream`, or NULL when not followed. */
static fzn_journal_entry_t *entry_of(const fzn_node_journal_t *nj,
                                     const uint8_t key[FZN_PUBKEY_LEN], uint32_t stream)
{
	size_t i;

	for (i = 0; i < nj->journal.used; i++)
		if (nj->entries[i].stream == stream
		    && fzn_ct_memeq(nj->entries[i].issuer, key, FZN_PUBKEY_LEN))
			return (fzn_journal_entry_t *)&nj->entries[i];
	return NULL;
}

fzn_node_journal_err_t fzn_node_journal_follow(fzn_node_journal_t *nj,
                                               const uint8_t key[FZN_PUBKEY_LEN],
                                               size_t *replayed)
{
	return fzn_node_journal_follow_stream(nj, key, FZN_NODE_JOURNAL_STREAM, replayed);
}

fzn_node_journal_err_t fzn_node_journal_follow_stream(fzn_node_journal_t *nj,
                                                      const uint8_t key[FZN_PUBKEY_LEN],
                                                      uint32_t stream, size_t *replayed)
{
	uint8_t buf[FZN_RECORD_MAX_LEN], id[FZN_RECORD_ID_LEN];
	fzn_journal_err_t jerr;
	uint64_t seq;
	size_t n = 0;

	if (replayed)
		*replayed = 0;
	if (!nj || !key)
		return FZN_NODE_JOURNAL_MALFORMED;
	if (entry_of(nj, key, stream))
		return FZN_NODE_JOURNAL_OK;
	jerr = fzn_journal_anchor(&nj->journal, key, stream, 0);
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

		serr = fzn_record_store_get(&nj->store, key, stream, seq, buf, sizeof(buf), &rec);
		if (serr == FZN_RECORD_STORE_ERR_ABSENT)
			break;
		if (serr != FZN_RECORD_STORE_OK || fzn_record_verify(rec, nj->sign) != FZN_RECORD_OK
		    || !nj->hash->hash(nj->hash->ctx, id, sizeof(id), rec.base, rec.len)
		    || fzn_journal_admit_chained(&nj->journal, key, stream, seq, fzn_record_prev(rec),
		                                 id) != FZN_JOURNAL_OK)
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
	return fzn_node_journal_append_on(nj, issuer, FZN_NODE_JOURNAL_STREAM, sign, kind, subject,
	                                  body, body_len, now, id_out);
}

fzn_node_journal_err_t fzn_node_journal_append_on(fzn_node_journal_t *nj,
                                                  const uint8_t issuer[FZN_PUBKEY_LEN],
                                                  uint32_t stream, const fzn_sign_ops_t *sign,
                                                  uint32_t kind,
                                                  const uint8_t subject[FZN_SUBJECT_LEN],
                                                  const uint8_t *body, size_t body_len,
                                                  uint64_t now,
                                                  uint8_t id_out[FZN_RECORD_ID_LEN])
{
	uint8_t buf[FZN_RECORD_MAX_LEN];
	size_t len = 0;

	return fzn_node_journal_write(nj, issuer, stream, sign, kind, subject, body, body_len, now,
	                              buf, sizeof(buf), &len, id_out);
}

fzn_node_journal_err_t fzn_node_journal_write(fzn_node_journal_t *nj,
                                              const uint8_t issuer[FZN_PUBKEY_LEN],
                                              uint32_t stream, const fzn_sign_ops_t *sign,
                                              uint32_t kind,
                                              const uint8_t subject[FZN_SUBJECT_LEN],
                                              const uint8_t *body, size_t body_len, uint64_t now,
                                              uint8_t *buf, size_t cap, size_t *out_len,
                                              uint8_t id_out[FZN_RECORD_ID_LEN])
{
	uint8_t id[FZN_RECORD_ID_LEN];
	const fzn_journal_entry_t *e;
	fzn_node_journal_err_t err;
	fzn_record_t rec;
	uint64_t seq;
	size_t len = 0;

	if (!nj || !issuer || !sign || !sign->sign || !subject || (body_len && !body) || !buf
	    || !out_len || cap < FZN_RECORD_MAX_LEN)
		return FZN_NODE_JOURNAL_MALFORMED;
	err = fzn_node_journal_follow_stream(nj, issuer, stream, NULL);
	if (err != FZN_NODE_JOURNAL_OK)
		return err;
	e = entry_of(nj, issuer, stream);
	/* THE HEAD MUST BE KNOWN to be named: a stream this node writes is
	 * followed from the beginning, so it always is. */
	if (!e || !e->has_head)
		return FZN_NODE_JOURNAL_REFUSED;
	seq = e->received + 1u;
	if (fzn_record_sign(issuer, subject, stream, kind, seq, seq == 1u ? NULL : e->head, now,
	                    body, body_len, sign, buf, cap, &len) != FZN_RECORD_OK
	    || fzn_record_open(buf, len, &rec) != FZN_RECORD_OK
	    || !nj->hash->hash(nj->hash->ctx, id, sizeof(id), buf, len))
		return FZN_NODE_JOURNAL_REFUSED;
	/* KEPT, THEN ADMITTED, sec 523: admitted first, a store that refused
	 * the record left the chain naming a head nothing holds, and every
	 * write after it chained to a record no follower could fetch. The
	 * stream's own next record, at the head's sequence plus one and naming
	 * the head, is one the chain takes. */
	if (fzn_record_store_put(&nj->store, rec) != FZN_RECORD_STORE_OK)
		return FZN_NODE_JOURNAL_STORE;
	if (fzn_journal_admit_chained(&nj->journal, issuer, stream, seq, fzn_record_prev(rec), id)
	    != FZN_JOURNAL_OK)
		return FZN_NODE_JOURNAL_REFUSED;
	*out_len = len;
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

/* ---- the act log, sec 506 --------------------------------------------- */

static fzn_journal_entry_t *estate_entry(const fzn_node_journal_t *nj,
                                          const uint8_t key[FZN_PUBKEY_LEN])
{
	return entry_of(nj, key, FZN_NODE_JOURNAL_STREAM);
}

uint64_t fzn_node_journal_received(const fzn_node_journal_t *nj,
                                   const uint8_t key[FZN_PUBKEY_LEN], uint32_t stream)
{
	const fzn_journal_entry_t *e;

	if (!nj || !key)
		return 0;
	e = entry_of(nj, key, stream);
	return e ? e->received : 0u;
}

int fzn_node_journal_forked(const fzn_node_journal_t *nj, const uint8_t key[FZN_PUBKEY_LEN])
{
	const fzn_journal_entry_t *e;

	if (!nj || !key)
		return 0;
	e = estate_entry(nj, key);
	return e && e->forked;
}

int fzn_node_journal_head(const fzn_node_journal_t *nj, const uint8_t key[FZN_PUBKEY_LEN],
                          uint8_t id[FZN_RECORD_ID_LEN])
{
	const fzn_journal_entry_t *e;

	if (!nj || !key || !id)
		return 0;
	e = estate_entry(nj, key);
	if (!e || e->forked || !e->has_head || e->received == 0u)
		return 0;
	memcpy(id, e->head, FZN_RECORD_ID_LEN);
	return 1;
}

int fzn_node_journal_stands(fzn_node_journal_t *nj, const uint8_t key[FZN_PUBKEY_LEN],
                            const uint8_t cut[FZN_RECORD_ID_LEN],
                            const uint8_t act[FZN_SUBJECT_LEN])
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];
	uint8_t want[FZN_RECORD_ID_LEN], got[FZN_RECORD_ID_LEN];
	const fzn_journal_entry_t *e;
	fzn_record_t rec;
	uint64_t seq;
	int below = 0;

	if (!nj || !key || !cut || !act)
		return 0;
	e = estate_entry(nj, key);
	if (!e || !e->has_head || e->received == 0u)
		return 0;
	/* DOWN FROM THE HEAD THIS JOURNAL ADMITTED, each record hashed against
	 * the id the one above it names -- the store is not trusted, as
	 * `fzn_record_store_stands` does not trust it -- until the cut, then on
	 * down looking for the act. */
	memcpy(want, e->head, sizeof(want));
	for (seq = e->received; seq >= 1u; seq--) {
		if (fzn_record_store_get(&nj->store, key, FZN_NODE_JOURNAL_STREAM, seq, buf,
		                         sizeof(buf), &rec) != FZN_RECORD_STORE_OK
		    || !nj->hash->hash(nj->hash->ctx, got, sizeof(got), rec.base, rec.len)
		    || memcmp(got, want, sizeof(got)) != 0)
			return 0;
		if (!below && memcmp(got, cut, sizeof(got)) == 0)
			below = 1;
		if (below && memcmp(fzn_record_subject(rec), act, FZN_SUBJECT_LEN) == 0)
			return 1;
		memcpy(want, fzn_record_prev(rec), sizeof(want));
	}
	return 0;
}

static int acts_stands(void *ctx, const uint8_t key[FZN_PUBKEY_LEN],
                       const uint8_t cut[FZN_REVOCATION_ID_LEN],
                       const uint8_t act[FZN_REVOCATION_ID_LEN])
{
	return fzn_node_journal_stands((fzn_node_journal_t *)ctx, key, cut, act);
}

void fzn_node_journal_acts(fzn_node_journal_t *nj, fzn_act_log_ops_t *ops)
{
	if (!ops)
		return;
	ops->stands = acts_stands;
	ops->ctx = nj;
}

size_t fzn_node_journal_answer(fzn_node_journal_t *nj, const uint8_t *request,
                               size_t request_len, uint8_t *reply, size_t reply_cap)
{
	size_t n;

	if (!nj)
		return 0;
	/* A PUSH IS TAKEN HERE, where the signer and the hash are: the
	 * exchange's own answer reads and never admits. sec 512. */
	n = fzn_exchange_take_push(&nj->journal, &nj->store, nj->sign, nj->hash, request,
	                           request_len, reply, reply_cap);
	if (n)
		return n;
	return fzn_exchange_answer(&nj->journal, &nj->store, request, request_len, reply,
	                           reply_cap);
}

fzn_exchange_err_t fzn_node_journal_push(fzn_node_journal_t *nj, fzn_exchange_ask_t ask,
                                         void *ask_ctx, uint8_t *reply, size_t reply_cap,
                                         fzn_exchange_push_tally_t *tally)
{
	if (!nj)
		return FZN_EXCHANGE_ERR_MALFORMED;
	return fzn_exchange_push(&nj->journal, &nj->store, ask, ask_ctx, reply, reply_cap, tally);
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
