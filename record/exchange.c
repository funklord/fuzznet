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
	if (count == 0u) {
		if (tally->missing < FZN_EXCHANGE_MISSED_MAX) {
			memcpy(tally->missed[tally->missing].issuer, want->issuer, FZN_PUBKEY_LEN);
			tally->missed[tally->missing].stream = want->stream;
		}
		tally->missing++;
		return 0;
	}
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

/* ---- the digest, paged: a pull's and a push's first requests ---------- */

static void digest_query(const fzn_exchange_digest_t *d, uint8_t *request, size_t *len)
{
	request[0] = (uint8_t)FZN_EXCHANGE_VERSION;
	request[1] = (uint8_t)FZN_EXCHANGE_DIGEST_QUERY;
	fzn_put_be16(request + 2, (uint16_t)d->n);
	*len = FZN_EXCHANGE_DIGEST_QUERY_LEN;
}

static void digest_begin(fzn_exchange_digest_t *d, uint8_t *request, size_t *len)
{
	d->n = d->total = d->pages = 0;
	digest_query(d, request, len);
}

/* A DIGEST PAGE taken into `d`, bounded by what a planner will look at:
 * -1 when it is not one, 1 with the next page's query in `request`, 0 when
 * the digest is read. */
static int digest_take(fzn_exchange_digest_t *d, const uint8_t *reply, size_t reply_len,
                       uint8_t *request, size_t *request_len)
{
	size_t i, count;

	if (!is(reply, reply_len, (uint8_t)FZN_EXCHANGE_DIGEST)
	    || reply_len < FZN_EXCHANGE_DIGEST_HEAD_LEN)
		return -1;
	d->total = fzn_get_be16(reply + 2);
	count = fzn_get_be16(reply + 6);
	if (fzn_get_be16(reply + 4) != d->n
	    || reply_len != FZN_EXCHANGE_DIGEST_HEAD_LEN + (count * FZN_EXCHANGE_POSITION_LEN)
	    || count > d->total - d->n || (count == 0u && d->n < d->total))
		return -1;
	for (i = 0; i < count && d->n < FZN_SYNC_MAX_POSITIONS; i++, d->n++) {
		const uint8_t *at = reply + FZN_EXCHANGE_DIGEST_HEAD_LEN + (i * FZN_EXCHANGE_POSITION_LEN);

		memcpy(d->theirs[d->n].issuer, at, FZN_PUBKEY_LEN);
		d->theirs[d->n].stream = fzn_get_be32(at + 32u);
		d->theirs[d->n].received = fzn_get_be64(at + 36u);
	}
	if (d->n < d->total && d->n < FZN_SYNC_MAX_POSITIONS
	    && ++d->pages <= FZN_SYNC_MAX_POSITIONS) {
		digest_query(d, request, request_len);
		return 1;
	}
	return 0;
}

/* ---- the pull as steps, sec 636 ------------------------------------------ */

enum { PULL_DIGEST = 1, PULL_RECORDS = 2, PULL_DONE = 3 };

static void records_query(const fzn_exchange_pulling_t *p, uint8_t *request, size_t *len)
{
	const fzn_sync_request_t *want = &p->plan_out[p->want];

	request[0] = (uint8_t)FZN_EXCHANGE_VERSION;
	request[1] = (uint8_t)FZN_EXCHANGE_RECORDS_QUERY;
	memcpy(request + 2, want->issuer, FZN_PUBKEY_LEN);
	fzn_put_be32(request + 34, want->stream);
	fzn_put_be64(request + 38, p->next);
	fzn_put_be16(request + 46, (uint16_t)(p->left > 0xffffu ? 0xffffu : p->left));
	*len = FZN_EXCHANGE_RECORDS_QUERY_LEN;
}

/* THE PLAN'S NEXT REQUEST with anything to page, from `p->want` on; the
 * pull done when none is left. */
static void next_want(fzn_exchange_pulling_t *p, uint8_t *request, size_t *len, int *done)
{
	for (; p->want < p->plan.request_count; p->want++) {
		p->next = p->plan_out[p->want].from;
		p->left = p->plan_out[p->want].count;
		if (p->left) {
			records_query(p, request, len);
			return;
		}
	}
	p->phase = PULL_DONE;
	*done = 1;
}

fzn_exchange_err_t fzn_exchange_pull_begin(fzn_exchange_pulling_t *p, fzn_journal_t *journal,
                                           fzn_record_store_t *store, const fzn_sign_ops_t *sign,
                                           const fzn_hash_ops_t *hash, uint64_t max_per_request,
                                           uint8_t *request, size_t cap, size_t *request_len)
{
	if (!p || !journal || !store || !sign || !sign->verify || !hash || !hash->hash || !request
	    || cap < FZN_EXCHANGE_RECORDS_QUERY_LEN || !request_len || max_per_request == 0u)
		return FZN_EXCHANGE_ERR_MALFORMED;
	memset(&p->tally, 0, sizeof(p->tally));
	p->journal = journal;
	p->store = store;
	p->sign = sign;
	p->hash = hash;
	p->max_per_request = max_per_request;
	p->phase = PULL_DIGEST;
	p->want = 0;
	digest_begin(&p->digest, request, request_len);
	return FZN_EXCHANGE_OK;
}

fzn_exchange_err_t fzn_exchange_pull_step(fzn_exchange_pulling_t *p, const uint8_t *reply,
                                          size_t reply_len, uint8_t *request, size_t cap,
                                          size_t *request_len, int *done)
{
	fzn_exchange_err_t err = FZN_EXCHANGE_OK;

	if (!p || !request || cap < FZN_EXCHANGE_RECORDS_QUERY_LEN || !request_len || !done
	    || (p->phase != PULL_DIGEST && p->phase != PULL_RECORDS))
		return FZN_EXCHANGE_ERR_MALFORMED;
	*done = 0;
	if (!reply) {
		p->phase = PULL_DONE;
		return FZN_EXCHANGE_ERR_NO_ANSWER;
	}
	if (p->phase == PULL_DIGEST) {
		int more = digest_take(&p->digest, reply, reply_len, request, request_len);

		if (more < 0) {
			p->phase = PULL_DONE;
			return FZN_EXCHANGE_ERR_SHAPE;
		}
		if (more)
			return FZN_EXCHANGE_OK;
		p->tally.positions = p->digest.n;
		if (fzn_sync_plan_fetch(p->journal, p->digest.theirs, p->digest.n, p->max_per_request,
		                        p->plan_out, FZN_SYNC_MAX_POSITIONS, &p->plan)
		    != FZN_SYNC_OK) {
			p->phase = PULL_DONE;
			return FZN_EXCHANGE_ERR_MALFORMED;
		}
		p->tally.requested = p->plan.request_count;
		p->phase = PULL_RECORDS;
		p->want = 0;
		next_want(p, request, request_len, done);
		return FZN_EXCHANGE_OK;
	}
	/* RECORDS: the answer taken; the same request paged on, or the next. */
	if (take_records(p->journal, p->store, p->sign, p->hash, &p->plan_out[p->want], reply,
	                 reply_len, &p->next, &p->left, &p->tally, &err)
	    && p->left) {
		records_query(p, request, request_len);
		return FZN_EXCHANGE_OK;
	}
	if (err != FZN_EXCHANGE_OK) {
		p->phase = PULL_DONE;
		return err;
	}
	p->want++;
	next_want(p, request, request_len, done);
	return FZN_EXCHANGE_OK;
}

/* THE PULL, the steps above driven by `ask` one request at a time. */
fzn_exchange_err_t fzn_exchange_pull(fzn_journal_t *journal, fzn_record_store_t *store,
                                     const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash,
                                     uint64_t max_per_request, fzn_exchange_ask_t ask,
                                     void *ask_ctx, uint8_t *reply, size_t reply_cap,
                                     fzn_exchange_tally_t *tally)
{
	static fzn_exchange_pulling_t p;
	uint8_t request[FZN_EXCHANGE_RECORDS_QUERY_LEN];
	size_t request_len = 0, reply_len;
	fzn_exchange_err_t err;
	int done = 0, answered;

	if (!ask || !reply || !tally || reply_cap < FZN_EXCHANGE_REPLY_MIN)
		return FZN_EXCHANGE_ERR_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	err = fzn_exchange_pull_begin(&p, journal, store, sign, hash, max_per_request, request,
	                              sizeof(request), &request_len);
	if (err != FZN_EXCHANGE_OK)
		return err;
	while (err == FZN_EXCHANGE_OK && !done) {
		/* ASKED FIRST, apart from the step: in one call's arguments the
		 * order is unspecified, and `reply_len` could be read before the
		 * answer set it. */
		reply_len = 0;
		answered = ask(ask_ctx, request, request_len, reply, reply_cap, &reply_len);
		err = fzn_exchange_pull_step(&p, answered ? reply : NULL, reply_len, request,
		                             sizeof(request), &request_len, &done);
	}
	*tally = p.tally;
	return err;
}

/* ---- the push, sec 512 ------------------------------------------------- */

_Static_assert(FZN_EXCHANGE_PUSHED_LEN == 2u + (4u * 2u), "exchange: PUSHED is not 10 bytes");

size_t fzn_exchange_take_push(fzn_journal_t *journal, fzn_record_store_t *store,
                              const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash,
                              const uint8_t *request, size_t request_len, uint8_t *reply,
                              size_t reply_cap)
{
	size_t count, at = FZN_EXCHANGE_PUSH_HEAD_LEN, i;
	unsigned taken = 0, held = 0, refused = 0, forks = 0;

	if (!journal || !store || !sign || !sign->verify || !hash || !hash->hash || !reply
	    || !is(request, request_len, (uint8_t)FZN_EXCHANGE_PUSH)
	    || request_len < FZN_EXCHANGE_PUSH_HEAD_LEN || reply_cap < FZN_EXCHANGE_PUSHED_LEN)
		return 0;
	count = fzn_get_be16(request + 2);
	for (i = 0; i < count; i++) {
		uint8_t id[FZN_RECORD_ID_LEN];
		const uint8_t *issuer;
		fzn_journal_err_t jerr;
		fzn_record_t rec;
		uint32_t stream;
		uint64_t seq;
		size_t len;

		if (request_len - at < 2u
		    || request_len - at - 2u < (len = fzn_get_be16(request + at))
		    || fzn_record_open(request + at + 2u, len, &rec) != FZN_RECORD_OK
		    || fzn_record_verify(rec, sign) != FZN_RECORD_OK
		    || !hash->hash(hash->ctx, id, sizeof(id), rec.base, rec.len)) {
			refused++;
			break;
		}
		at += 2u + len;
		issuer = fzn_record_issuer(rec);
		stream = fzn_record_stream(rec);
		seq = fzn_record_seq(rec);
		/* THE NEXT ONE OR NOTHING: a record ahead of the position is a gap
		 * the pusher should not have left, and one behind it is held. */
		if (seq < fzn_journal_next(journal, issuer, stream)) {
			held++;
			continue;
		}
		jerr = fzn_journal_admit_chained(journal, issuer, stream, seq, fzn_record_prev(rec), id);
		if (jerr == FZN_JOURNAL_ERR_FORK) {
			forks++;
			break;
		}
		if (jerr == FZN_JOURNAL_ERR_DUPLICATE) {
			held++;
			continue;
		}
		/* ADMITTED, THEN STORED, as a pull stores. */
		if (jerr != FZN_JOURNAL_OK || fzn_record_store_put(store, rec) != FZN_RECORD_STORE_OK) {
			refused++;
			break;
		}
		taken++;
	}
	reply[0] = (uint8_t)FZN_EXCHANGE_VERSION;
	reply[1] = (uint8_t)FZN_EXCHANGE_PUSHED;
	fzn_put_be16(reply + 2, (uint16_t)taken);
	fzn_put_be16(reply + 4, (uint16_t)held);
	fzn_put_be16(reply + 6, (uint16_t)refused);
	fzn_put_be16(reply + 8, (uint16_t)forks);
	return FZN_EXCHANGE_PUSHED_LEN;
}

/* ---- the push as steps, sec 636 ------------------------------------------ */

enum { PUSH_DIGEST = 1, PUSH_OFFERS = 2, PUSH_DONE = 3 };

/* THE BOUNDS OF POSITION `p->at`: the peer's next, and this host's last. */
static void offer_bounds(fzn_exchange_pushing_t *p)
{
	const fzn_sync_position_t *theirs = &p->digest.theirs[p->at];

	if (p->at >= p->digest.n)
		return;
	p->mine = fzn_journal_next(p->journal, theirs->issuer, theirs->stream) - 1u;
	p->seq = theirs->received + 1u;
}

/* THE NEXT PUSH, from `p->at`'s next record on: as many records as fit in
 * `cap`. A position with nothing to offer -- none held further, or its
 * next not in the store, or too large for `cap` -- is passed over; the push
 * done when none is left. */
static void next_offer(fzn_exchange_pushing_t *p, uint8_t *message, size_t cap, size_t *len,
                       int *done)
{
	for (; p->at < p->digest.n; p->at++, offer_bounds(p)) {
		const fzn_sync_position_t *theirs = &p->digest.theirs[p->at];
		size_t at = FZN_EXCHANGE_PUSH_HEAD_LEN, count = 0;

		while (p->seq <= p->mine && count < 0xffffu) {
			uint8_t buf[FZN_RECORD_MAX_LEN];
			fzn_record_t rec;

			if (fzn_record_store_get(p->store, theirs->issuer, theirs->stream, p->seq, buf,
			                         sizeof(buf), &rec) != FZN_RECORD_STORE_OK
			    || cap - at < 2u + rec.len)
				break;
			fzn_put_be16(message + at, (uint16_t)rec.len);
			memcpy(message + at + 2u, rec.base, rec.len);
			at += 2u + rec.len;
			count++;
			p->seq++;
		}
		if (count) {
			message[0] = (uint8_t)FZN_EXCHANGE_VERSION;
			message[1] = (uint8_t)FZN_EXCHANGE_PUSH;
			fzn_put_be16(message + 2, (uint16_t)count);
			p->tally.offered += count;
			*len = at;
			return;
		}
	}
	p->phase = PUSH_DONE;
	*done = 1;
}

fzn_exchange_err_t fzn_exchange_push_begin(fzn_exchange_pushing_t *p, fzn_journal_t *journal,
                                           fzn_record_store_t *store, uint8_t *message,
                                           size_t cap, size_t *message_len)
{
	if (!p || !journal || !store || !message || cap < FZN_EXCHANGE_REPLY_MIN || !message_len)
		return FZN_EXCHANGE_ERR_MALFORMED;
	memset(&p->tally, 0, sizeof(p->tally));
	p->journal = journal;
	p->store = store;
	p->phase = PUSH_DIGEST;
	p->at = 0;
	digest_begin(&p->digest, message, message_len);
	return FZN_EXCHANGE_OK;
}

fzn_exchange_err_t fzn_exchange_push_step(fzn_exchange_pushing_t *p, const uint8_t *reply,
                                          size_t reply_len, uint8_t *message, size_t cap,
                                          size_t *message_len, int *done)
{
	if (!p || !message || cap < FZN_EXCHANGE_REPLY_MIN || !message_len || !done
	    || (p->phase != PUSH_DIGEST && p->phase != PUSH_OFFERS))
		return FZN_EXCHANGE_ERR_MALFORMED;
	*done = 0;
	if (!reply) {
		p->phase = PUSH_DONE;
		return FZN_EXCHANGE_ERR_NO_ANSWER;
	}
	if (p->phase == PUSH_DIGEST) {
		int more = digest_take(&p->digest, reply, reply_len, message, message_len);

		if (more < 0) {
			p->phase = PUSH_DONE;
			return FZN_EXCHANGE_ERR_SHAPE;
		}
		if (more)
			return FZN_EXCHANGE_OK;
		/* EVERY STREAM THE PEER LISTS that this journal holds further. */
		p->tally.positions = p->digest.n;
		p->phase = PUSH_OFFERS;
		p->at = 0;
		offer_bounds(p);
		next_offer(p, message, cap, message_len, done);
		return FZN_EXCHANGE_OK;
	}
	if (!is(reply, reply_len, (uint8_t)FZN_EXCHANGE_PUSHED)
	    || reply_len != FZN_EXCHANGE_PUSHED_LEN) {
		p->phase = PUSH_DONE;
		return FZN_EXCHANGE_ERR_SHAPE;
	}
	p->tally.taken += fzn_get_be16(reply + 2);
	p->tally.held += fzn_get_be16(reply + 4);
	p->tally.refused += fzn_get_be16(reply + 6);
	p->tally.forks += fzn_get_be16(reply + 8);
	/* A MESSAGE NOT WHOLLY TAKEN ends the stream for the round: whatever
	 * came after the refusal would be refused too. */
	if (fzn_get_be16(reply + 6) || fzn_get_be16(reply + 8)) {
		p->at++;
		offer_bounds(p);
	}
	next_offer(p, message, cap, message_len, done);
	return FZN_EXCHANGE_OK;
}

fzn_exchange_err_t fzn_exchange_push(fzn_journal_t *journal, fzn_record_store_t *store,
                                     fzn_exchange_ask_t ask, void *ask_ctx, uint8_t *reply,
                                     size_t reply_cap, fzn_exchange_push_tally_t *tally)
{
	static fzn_exchange_pushing_t p;
	static uint8_t message[FZN_EXCHANGE_PUSH_HEAD_LEN + 16u * (2u + FZN_RECORD_MAX_LEN)];
	/* A message as large as the smaller of the caller's buffer and this
	 * one, so the peer can answer it in a reply of the same size. */
	size_t cap = reply_cap < sizeof(message) ? reply_cap : sizeof(message);
	size_t message_len = 0, reply_len;
	fzn_exchange_err_t err;
	int done = 0, answered;

	if (!ask || !reply || !tally || reply_cap < FZN_EXCHANGE_REPLY_MIN)
		return FZN_EXCHANGE_ERR_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	err = fzn_exchange_push_begin(&p, journal, store, message, cap, &message_len);
	if (err != FZN_EXCHANGE_OK)
		return err;
	while (err == FZN_EXCHANGE_OK && !done) {
		/* Asked first, apart from the step, as the pull's driver does. */
		reply_len = 0;
		answered = ask(ask_ctx, message, message_len, reply, reply_cap, &reply_len);
		err = fzn_exchange_push_step(&p, answered ? reply : NULL, reply_len, message, cap,
		                             &message_len, &done);
	}
	*tally = p.tally;
	return err;
}
