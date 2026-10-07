/* See exchange.h. */

#include "exchange.h"

#include "../wire/bytes.h"

#include <string.h>

/* THE OFFSETS, pinned as literals against `record/exchange.situ`, which
 * `make schema` compares with situ's own reading of it. */
_Static_assert(FZN_EXCHANGE_POSITION_LEN == 32u + 4u + 8u, "exchange: a position is not 44 bytes");
_Static_assert(FZN_EXCHANGE_RECORDS_QUERY_LEN == 2u + 32u + 4u + 8u + 2u,
               "exchange: a records query is not 48 bytes");

const char *fzn_exchange_err_str(fzn_exchange_err_t err)
{
	switch (err) {
	case FZN_EXCHANGE_OK:
		return "ok";
	case FZN_EXCHANGE_ERR_MALFORMED:
		return "malformed argument";
	case FZN_EXCHANGE_ERR_NO_ANSWER:
		return "the peer did not answer";
	case FZN_EXCHANGE_ERR_SHAPE:
		return "the peer's answer is not a journal message";
	case FZN_EXCHANGE_ERR_STORE:
		return "a record was admitted and not kept";
	}
	return "unknown";
}

static int is(const uint8_t *m, size_t len, uint8_t type)
{
	return m && len >= 2u && m[0] == (uint8_t)FZN_EXCHANGE_VERSION && m[1] == type;
}

/* ---- the server ------------------------------------------------------ */

static size_t answer_digest(const fzn_journal_t *journal, const uint8_t *request,
                            size_t request_len, uint8_t *reply, size_t reply_cap)
{
	static fzn_sync_position_t held[FZN_SYNC_MAX_POSITIONS];
	size_t total, dropped = 0, from, room, i, at;

	if (request_len != FZN_EXCHANGE_DIGEST_QUERY_LEN || reply_cap < FZN_EXCHANGE_DIGEST_HEAD_LEN)
		return 0;
	total = fzn_sync_digest(journal, held, FZN_SYNC_MAX_POSITIONS, &dropped);
	from = fzn_get_be16(request + 2);
	if (from > total)
		from = total;
	room = (reply_cap - FZN_EXCHANGE_DIGEST_HEAD_LEN) / FZN_EXCHANGE_POSITION_LEN;
	reply[0] = (uint8_t)FZN_EXCHANGE_VERSION;
	reply[1] = (uint8_t)FZN_EXCHANGE_DIGEST;
	fzn_put_be16(reply + 2, (uint16_t)total);
	fzn_put_be16(reply + 4, (uint16_t)from);
	at = FZN_EXCHANGE_DIGEST_HEAD_LEN;
	for (i = from; i < total && i - from < room; i++) {
		memcpy(reply + at, held[i].issuer, FZN_PUBKEY_LEN);
		fzn_put_be32(reply + at + 32u, held[i].stream);
		fzn_put_be64(reply + at + 36u, held[i].received);
		at += FZN_EXCHANGE_POSITION_LEN;
	}
	fzn_put_be16(reply + 6, (uint16_t)(i - from));
	return at;
}

static size_t answer_records(const fzn_journal_t *journal, fzn_record_store_t *store,
                             const uint8_t *request, size_t request_len, uint8_t *reply,
                             size_t reply_cap)
{
	uint8_t buf[FZN_RECORD_MAX_LEN];
	const uint8_t *issuer;
	uint32_t stream;
	uint64_t from, max, last, seq;
	size_t at = FZN_EXCHANGE_RECORDS_HEAD_LEN, count = 0;
	fzn_record_t rec;

	if (request_len != FZN_EXCHANGE_RECORDS_QUERY_LEN || reply_cap < FZN_EXCHANGE_RECORDS_HEAD_LEN)
		return 0;
	issuer = request + 2;
	stream = fzn_get_be32(request + 34);
	from = fzn_get_be64(request + 38);
	max = fzn_get_be16(request + 46);
	if (from == 0u || max == 0u)
		return 0;
	/* ONLY WHAT THE JOURNAL HAS RECEIVED: a record the store holds past the
	 * position is one this host has not admitted, so it is not offered. */
	last = fzn_journal_next(journal, issuer, stream) - 1u;
	for (seq = from; seq <= last && count < max && count < 0xffffu; seq++) {
		if (fzn_record_store_get(store, issuer, stream, seq, buf, sizeof(buf), &rec)
		    != FZN_RECORD_STORE_OK)
			break;
		if (reply_cap - at < 2u + rec.len)
			break;
		fzn_put_be16(reply + at, (uint16_t)rec.len);
		memcpy(reply + at + 2u, rec.base, rec.len);
		at += 2u + rec.len;
		count++;
	}
	reply[0] = (uint8_t)FZN_EXCHANGE_VERSION;
	reply[1] = (uint8_t)FZN_EXCHANGE_RECORDS;
	fzn_put_be16(reply + 2, (uint16_t)count);
	return at;
}

size_t fzn_exchange_answer(const fzn_journal_t *journal, fzn_record_store_t *store,
                           const uint8_t *request, size_t request_len, uint8_t *reply,
                           size_t reply_cap)
{
	if (!journal || !store || !request || !reply)
		return 0;
	if (is(request, request_len, (uint8_t)FZN_EXCHANGE_DIGEST_QUERY))
		return answer_digest(journal, request, request_len, reply, reply_cap);
	if (is(request, request_len, (uint8_t)FZN_EXCHANGE_RECORDS_QUERY))
		return answer_records(journal, store, request, request_len, reply, reply_cap);
	return 0;
}

/* ---- the client ------------------------------------------------------ */

/* One RECORDS reply against the range it answers: every record admitted
 * that can be, from `*next` on. 1 to ask again, 0 when the stream is done for
 * the round -- empty, a refusal, or a fork. */
static int take_records(fzn_journal_t *journal, fzn_record_store_t *store,
                        const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash,
                        const fzn_sync_request_t *want, const uint8_t *reply, size_t reply_len,
                        uint64_t *next, uint64_t *left, fzn_exchange_tally_t *tally,
                        fzn_exchange_err_t *err)
{
	uint8_t id[FZN_RECORD_ID_LEN];
	size_t count, at = FZN_EXCHANGE_RECORDS_HEAD_LEN, i;

	if (!is(reply, reply_len, (uint8_t)FZN_EXCHANGE_RECORDS)
	    || reply_len < FZN_EXCHANGE_RECORDS_HEAD_LEN) {
		*err = FZN_EXCHANGE_ERR_SHAPE;
		return 0;
	}
	count = fzn_get_be16(reply + 2);
	if (count == 0u)
		return 0;
	for (i = 0; i < count; i++) {
		fzn_record_t rec;
		size_t len;
		fzn_journal_err_t jerr;

		if (reply_len - at < 2u) {
			*err = FZN_EXCHANGE_ERR_SHAPE;
			return 0;
		}
		len = fzn_get_be16(reply + at);
		if (reply_len - at - 2u < len) {
			*err = FZN_EXCHANGE_ERR_SHAPE;
			return 0;
		}
		/* EXACTLY THE NEXT ONE ASKED FOR, of the stream asked about,
		 * signed by its issuer: anything else ends the stream's round. */
		if (fzn_record_open(reply + at + 2u, len, &rec) != FZN_RECORD_OK
		    || memcmp(fzn_record_issuer(rec), want->issuer, FZN_PUBKEY_LEN) != 0
		    || fzn_record_stream(rec) != want->stream || fzn_record_seq(rec) != *next
		    || fzn_record_verify(rec, sign) != FZN_RECORD_OK
		    || !hash->hash(hash->ctx, id, sizeof(id), rec.base, rec.len)) {
			tally->refused++;
			return 0;
		}
		at += 2u + len;
		jerr = fzn_journal_admit_chained(journal, want->issuer, want->stream, *next,
		                                 fzn_record_prev(rec), id);
		if (jerr == FZN_JOURNAL_ERR_FORK) {
			tally->forks++;
			return 0;
		}
		if (jerr == FZN_JOURNAL_OK) {
			/* ADMITTED, THEN STORED: see the header. */
			if (fzn_record_store_put(store, rec) != FZN_RECORD_STORE_OK) {
				*err = FZN_EXCHANGE_ERR_STORE;
				return 0;
			}
			tally->learned++;
		} else if (jerr != FZN_JOURNAL_ERR_DUPLICATE) {
			tally->refused++;
			return 0;
		}
		(*next)++;
		if (--(*left) == 0u)
			return 0;
	}
	return 1;
}

fzn_exchange_err_t fzn_exchange_pull(fzn_journal_t *journal, fzn_record_store_t *store,
                                     const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash,
                                     uint64_t max_per_request, fzn_exchange_ask_t ask,
                                     void *ask_ctx, uint8_t *reply, size_t reply_cap,
                                     fzn_exchange_tally_t *tally)
{
	static fzn_sync_position_t theirs[FZN_SYNC_MAX_POSITIONS];
	static fzn_sync_request_t plan_out[FZN_SYNC_MAX_POSITIONS];
	uint8_t request[FZN_EXCHANGE_RECORDS_QUERY_LEN];
	size_t n = 0, total = 0, pages = 0, reply_len, i;
	fzn_sync_plan_t plan;
	fzn_exchange_err_t err = FZN_EXCHANGE_OK;

	if (!journal || !store || !sign || !sign->verify || !hash || !hash->hash || !ask || !reply
	    || !tally || reply_cap < FZN_EXCHANGE_REPLY_MIN || max_per_request == 0u)
		return FZN_EXCHANGE_ERR_MALFORMED;
	memset(tally, 0, sizeof(*tally));

	/* THE PEER'S POSITIONS, a page at a time, bounded by what a planner
	 * will look at. */
	do {
		size_t count;

		request[0] = (uint8_t)FZN_EXCHANGE_VERSION;
		request[1] = (uint8_t)FZN_EXCHANGE_DIGEST_QUERY;
		fzn_put_be16(request + 2, (uint16_t)n);
		reply_len = 0;
		if (!ask(ask_ctx, request, FZN_EXCHANGE_DIGEST_QUERY_LEN, reply, reply_cap, &reply_len))
			return FZN_EXCHANGE_ERR_NO_ANSWER;
		if (!is(reply, reply_len, (uint8_t)FZN_EXCHANGE_DIGEST)
		    || reply_len < FZN_EXCHANGE_DIGEST_HEAD_LEN)
			return FZN_EXCHANGE_ERR_SHAPE;
		total = fzn_get_be16(reply + 2);
		count = fzn_get_be16(reply + 6);
		if (fzn_get_be16(reply + 4) != n
		    || reply_len != FZN_EXCHANGE_DIGEST_HEAD_LEN + (count * FZN_EXCHANGE_POSITION_LEN)
		    || count > total - n || (count == 0u && n < total))
			return FZN_EXCHANGE_ERR_SHAPE;
		for (i = 0; i < count && n < FZN_SYNC_MAX_POSITIONS; i++, n++) {
			const uint8_t *p = reply + FZN_EXCHANGE_DIGEST_HEAD_LEN
			                   + (i * FZN_EXCHANGE_POSITION_LEN);

			memcpy(theirs[n].issuer, p, FZN_PUBKEY_LEN);
			theirs[n].stream = fzn_get_be32(p + 32u);
			theirs[n].received = fzn_get_be64(p + 36u);
		}
	} while (n < total && n < FZN_SYNC_MAX_POSITIONS && ++pages <= FZN_SYNC_MAX_POSITIONS);
	tally->positions = n;

	if (fzn_sync_plan_fetch(journal, theirs, n, max_per_request, plan_out,
	                        FZN_SYNC_MAX_POSITIONS, &plan) != FZN_SYNC_OK)
		return FZN_EXCHANGE_ERR_MALFORMED;
	tally->requested = plan.request_count;

	for (i = 0; i < plan.request_count; i++) {
		const fzn_sync_request_t *want = &plan_out[i];
		uint64_t next = want->from, left = want->count;

		while (left) {
			request[0] = (uint8_t)FZN_EXCHANGE_VERSION;
			request[1] = (uint8_t)FZN_EXCHANGE_RECORDS_QUERY;
			memcpy(request + 2, want->issuer, FZN_PUBKEY_LEN);
			fzn_put_be32(request + 34, want->stream);
			fzn_put_be64(request + 38, next);
			fzn_put_be16(request + 46, (uint16_t)(left > 0xffffu ? 0xffffu : left));
			reply_len = 0;
			if (!ask(ask_ctx, request, sizeof(request), reply, reply_cap, &reply_len))
				return FZN_EXCHANGE_ERR_NO_ANSWER;
			if (!take_records(journal, store, sign, hash, want, reply, reply_len, &next,
			                  &left, tally, &err))
				break;
		}
		if (err != FZN_EXCHANGE_OK)
			return err;
	}
	return FZN_EXCHANGE_OK;
}
