/* See reconcile.h. */

#include "reconcile.h"

#include "../wire/bytes.h"

#include <string.h>

/* A class too large to list answers this count, and no digest. */
#define COUNT_FULL 0xffffffffu

const char *fzn_reconcile_err_str(fzn_reconcile_err_t err)
{
	switch (err) {
	case FZN_RECONCILE_OK:
		return "ok";
	case FZN_RECONCILE_ERR_MALFORMED:
		return "malformed";
	case FZN_RECONCILE_ERR_NO_ANSWER:
		return "the peer did not answer";
	case FZN_RECONCILE_ERR_SHAPE:
		return "the peer answered something that is not a reconciliation message";
	case FZN_RECONCILE_ERR_STORE:
		return "this node's store would not list or keep";
	case FZN_RECONCILE_ERR_CONFLICT:
		return "a second peer tells the stream otherwise";
	}
	return "unknown";
}

static int is(const uint8_t *m, size_t len, uint8_t type)
{
	return m && len >= 2u && m[0] == (uint8_t)FZN_RECONCILE_VERSION && m[1] == type;
}

/* ---- the server ------------------------------------------------------------ */

/* One class's ids, ascending: the answer's, and the round's own. TWO
 * BUFFERS, NOT ONE SHARED: a node answering a peer while it is in the middle
 * of its own round -- or one process playing both sides, as a suite does --
 * would otherwise overwrite the list the round is searching, and fetch what
 * it holds. 128 KiB each is not stack. sec 555. */
static uint8_t served_ids[FZN_HOLDINGS_MAX][FZN_HOLDINGS_ID_LEN];
static uint8_t ids_buf[FZN_HOLDINGS_MAX][FZN_HOLDINGS_ID_LEN];

static size_t answer_digest(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                            uint8_t *reply, size_t reply_cap)
{
	size_t at = FZN_RECONCILE_DIGEST_HEAD_LEN, c;

	if (reply_cap < FZN_RECONCILE_DIGEST_HEAD_LEN
	                        + (size_t)FZN_HOLDINGS_CLASSES * FZN_RECONCILE_CLASS_LEN)
		return 0;
	for (c = 0; c < FZN_HOLDINGS_CLASSES; c++) {
		size_t count = 0;
		fzn_holdings_err_t err;

		reply[at] = (uint8_t)c;
		err = fzn_holdings_digest(store, hash, (fzn_holdings_class_t)c, reply + at + 5u, &count);
		if (err == FZN_HOLDINGS_FULL) {
			fzn_put_be32(reply + at + 1u, COUNT_FULL);
			memset(reply + at + 5u, 0, FZN_HOLDINGS_ID_LEN);
		} else if (err != FZN_HOLDINGS_OK) {
			return 0;
		} else {
			fzn_put_be32(reply + at + 1u, (uint32_t)count);
		}
		at += FZN_RECONCILE_CLASS_LEN;
	}
	reply[0] = (uint8_t)FZN_RECONCILE_VERSION;
	reply[1] = (uint8_t)FZN_RECONCILE_DIGEST;
	reply[2] = (uint8_t)FZN_HOLDINGS_CLASSES;
	return at;
}

static size_t answer_ids(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                         const uint8_t *request, size_t request_len, uint8_t *reply,
                         size_t reply_cap)
{
	size_t n = 0, from, count, room;
	uint8_t cls;

	if (request_len != FZN_RECONCILE_IDS_QUERY_LEN || request[2] >= FZN_HOLDINGS_CLASSES
	    || reply_cap < FZN_RECONCILE_IDS_HEAD_LEN)
		return 0;
	cls = request[2];
	from = fzn_get_be32(request + 3u);
	if (fzn_holdings_ids(store, hash, (fzn_holdings_class_t)cls, served_ids, FZN_HOLDINGS_MAX,
	                     &n) != FZN_HOLDINGS_OK)
		return 0;
	count = from < n ? n - from : 0u;
	room = (reply_cap - FZN_RECONCILE_IDS_HEAD_LEN) / FZN_HOLDINGS_ID_LEN;
	if (count > room)
		count = room;
	if (count > 0xffffu)
		count = 0xffffu;
	reply[0] = (uint8_t)FZN_RECONCILE_VERSION;
	reply[1] = (uint8_t)FZN_RECONCILE_IDS;
	reply[2] = cls;
	fzn_put_be32(reply + 3u, (uint32_t)n);
	fzn_put_be32(reply + 7u, (uint32_t)from);
	fzn_put_be16(reply + 11u, (uint16_t)count);
	if (count)
		memcpy(reply + FZN_RECONCILE_IDS_HEAD_LEN, served_ids[from], count * FZN_HOLDINGS_ID_LEN);
	return FZN_RECONCILE_IDS_HEAD_LEN + (count * FZN_HOLDINGS_ID_LEN);
}

struct serving {
	const uint8_t *wanted;  /* the ids asked for */
	size_t n_wanted;
	uint8_t *reply;
	size_t at, cap, count;
};

static int serve_one(void *ctx, const uint8_t id[FZN_HOLDINGS_ID_LEN], const uint8_t *object,
                     size_t len)
{
	struct serving *s = (struct serving *)ctx;
	size_t i;

	for (i = 0; i < s->n_wanted; i++)
		if (memcmp(s->wanted + (i * FZN_HOLDINGS_ID_LEN), id, FZN_HOLDINGS_ID_LEN) == 0)
			break;
	if (i == s->n_wanted || len > FZN_RECONCILE_OBJECT_MAX)
		return 1;
	/* AS MANY AS FIT: the asker asks again for the rest. */
	if (s->cap - s->at < 2u + len)
		return 0;
	fzn_put_be16(s->reply + s->at, (uint16_t)len);
	memcpy(s->reply + s->at + 2u, object, len);
	s->at += 2u + len;
	s->count++;
	return 1;
}

static size_t answer_objects(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                             const uint8_t *request, size_t request_len, uint8_t *reply,
                             size_t reply_cap)
{
	struct serving s;
	size_t n;

	if (request_len < FZN_RECONCILE_OBJECTS_QUERY_HEAD_LEN || request[2] >= FZN_HOLDINGS_CLASSES
	    || reply_cap < FZN_RECONCILE_OBJECTS_HEAD_LEN)
		return 0;
	n = request[3];
	if (n == 0u || n > FZN_RECONCILE_ASK_MAX
	    || request_len != FZN_RECONCILE_OBJECTS_QUERY_HEAD_LEN + (n * FZN_HOLDINGS_ID_LEN))
		return 0;
	s.wanted = request + FZN_RECONCILE_OBJECTS_QUERY_HEAD_LEN;
	s.n_wanted = n;
	s.reply = reply;
	s.at = FZN_RECONCILE_OBJECTS_HEAD_LEN;
	s.cap = reply_cap;
	s.count = 0;
	if (fzn_holdings_each(store, hash, (fzn_holdings_class_t)request[2], serve_one, &s, NULL)
	    != FZN_HOLDINGS_OK)
		return 0;
	reply[0] = (uint8_t)FZN_RECONCILE_VERSION;
	reply[1] = (uint8_t)FZN_RECONCILE_OBJECTS;
	reply[2] = request[2];
	fzn_put_be16(reply + 3u, (uint16_t)s.count);
	return s.at;
}

/* A STREAM'S BASE, the id below it, and its spine from `from`: as many
 * entries as fit, up to what this journal has received -- from the spine
 * below its base and from the records above it, so a peer that cut less is
 * a witness to a bridge another peer serves (sec 557) -- stopping at the
 * first it cannot give. */
static size_t answer_base(fzn_node_journal_t *journal, const uint8_t *request, size_t request_len,
                          uint8_t *reply, size_t reply_cap)
{
	uint8_t below[FZN_RECORD_ID_LEN];
	uint64_t base, from, seq, received;
	size_t at = FZN_RECONCILE_BASE_HEAD_LEN, count = 0;
	uint32_t stream;

	if (!journal || request_len != FZN_RECONCILE_BASE_QUERY_LEN
	    || reply_cap < FZN_RECONCILE_BASE_HEAD_LEN)
		return 0;
	stream = fzn_get_be32(request + 34u);
	from = fzn_get_be64(request + 38u);
	if (from == 0u)
		return 0;
	base = fzn_node_journal_base_below(journal, request + 2u, stream, below);
	received = fzn_node_journal_received(journal, request + 2u, stream);
	if (stream == FZN_NODE_JOURNAL_STREAM)
		for (seq = from; seq <= received && count < 0xffffu
		                 && reply_cap - at >= FZN_NODE_JOURNAL_SPINE_ENTRY;
		     seq++) {
			if (!fzn_node_journal_spine_entry(journal, request + 2u, seq, reply + at))
				break;
			at += FZN_NODE_JOURNAL_SPINE_ENTRY;
			count++;
		}
	reply[0] = (uint8_t)FZN_RECONCILE_VERSION;
	reply[1] = (uint8_t)FZN_RECONCILE_BASE;
	fzn_put_be64(reply + 2u, base);
	memcpy(reply + 10u, below, sizeof(below));
	fzn_put_be64(reply + 42u, from);
	fzn_put_be16(reply + 50u, (uint16_t)count);
	return at;
}

size_t fzn_reconcile_answer(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                            fzn_node_journal_t *journal, const uint8_t *request,
                            size_t request_len, uint8_t *reply, size_t reply_cap)
{
	if (!store || !hash || !hash->hash || !request || !reply || request_len < 2u
	    || request[0] != (uint8_t)FZN_RECONCILE_VERSION)
		return 0;
	if (request[1] == (uint8_t)FZN_RECONCILE_BASE_QUERY)
		return answer_base(journal, request, request_len, reply, reply_cap);
	if (request[1] == (uint8_t)FZN_RECONCILE_DIGEST_QUERY)
		return request_len == FZN_RECONCILE_DIGEST_QUERY_LEN
		               ? answer_digest(store, hash, reply, reply_cap)
		               : 0u;
	if (request[1] == (uint8_t)FZN_RECONCILE_IDS_QUERY)
		return answer_ids(store, hash, request, request_len, reply, reply_cap);
	if (request[1] == (uint8_t)FZN_RECONCILE_OBJECTS_QUERY)
		return answer_objects(store, hash, request, request_len, reply, reply_cap);
	return 0;
}

/* ---- the round ------------------------------------------------------------- */

/* What this node lacks of one class, fetched and applied. */
static uint8_t lacked[FZN_HOLDINGS_MAX][FZN_HOLDINGS_ID_LEN];

/* Fetch and apply `lacked[0 .. n)`, `FZN_RECONCILE_ASK_MAX` at a time: each
 * object hashed to one of the ids asked, so a peer sends nothing it was not
 * asked for; what does not fit is asked again; a batch that brings nothing
 * is given up on for the round -- the peer no longer holds it. */
static fzn_reconcile_err_t fetch(fzn_node_apply_t *ap, const fzn_reconcile_notes_t *notes,
                                 fzn_reconcile_ask_t ask, void *ask_ctx, uint8_t cls, size_t n,
                                 uint8_t *reply, size_t reply_cap, fzn_reconcile_tally_t *tally)
{
	uint8_t request[FZN_RECONCILE_OBJECTS_QUERY_HEAD_LEN
	                + (size_t)FZN_RECONCILE_ASK_MAX * FZN_HOLDINGS_ID_LEN];
	uint8_t got[FZN_RECONCILE_ASK_MAX];
	size_t start = 0;

	while (start < n) {
		size_t batch = n - start < FZN_RECONCILE_ASK_MAX ? n - start : FZN_RECONCILE_ASK_MAX;
		size_t reply_len = 0, at = FZN_RECONCILE_OBJECTS_HEAD_LEN, count, i, j, kept = 0;
		fzn_node_apply_tally_t t;

		request[0] = (uint8_t)FZN_RECONCILE_VERSION;
		request[1] = (uint8_t)FZN_RECONCILE_OBJECTS_QUERY;
		request[2] = cls;
		request[3] = (uint8_t)batch;
		memcpy(request + FZN_RECONCILE_OBJECTS_QUERY_HEAD_LEN, lacked[start],
		       batch * FZN_HOLDINGS_ID_LEN);
		if (!ask(ask_ctx, request, FZN_RECONCILE_OBJECTS_QUERY_HEAD_LEN
		                                   + (batch * FZN_HOLDINGS_ID_LEN),
		         reply, reply_cap, &reply_len))
			return FZN_RECONCILE_ERR_NO_ANSWER;
		if (!is(reply, reply_len, (uint8_t)FZN_RECONCILE_OBJECTS)
		    || reply_len < FZN_RECONCILE_OBJECTS_HEAD_LEN || reply[2] != cls)
			return FZN_RECONCILE_ERR_SHAPE;
		count = fzn_get_be16(reply + 3u);
		memset(got, 0, sizeof(got));
		for (i = 0; i < count; i++) {
			uint8_t id[FZN_HOLDINGS_ID_LEN];
			size_t len;

			if (reply_len - at < 2u
			    || reply_len - at - 2u < (len = fzn_get_be16(reply + at)))
				return FZN_RECONCILE_ERR_SHAPE;
			at += 2u;
			if (!ap->hash->hash(ap->hash->ctx, id, sizeof(id), reply + at, len))
				return FZN_RECONCILE_ERR_STORE;
			for (j = 0; j < batch; j++)
				if (!got[j] && memcmp(lacked[start + j], id, sizeof(id)) == 0)
					break;
			if (j == batch) {
				/* UNASKED, or asked once and sent twice. */
				tally->refused++;
			} else {
				got[j] = 1;
				kept++;
				memset(&t, 0, sizeof(t));
				switch (cls == (uint8_t)FZN_HOLDINGS_NOTES
				                ? notes->file(notes->ctx, reply + at, len)
				                : fzn_node_apply_object(ap, reply + at, len, &t)) {
				case FZN_NODE_APPLY_APPLIED:
					tally->applied++;
					break;
				case FZN_NODE_APPLY_WAITING:
					tally->waiting++;
					break;
				case FZN_NODE_APPLY_NOT_SAVED:
					return FZN_RECONCILE_ERR_STORE;
				case FZN_NODE_APPLY_REFUSED:
					tally->refused++;
					break;
				}
			}
			at += len;
		}
		if (at != reply_len)
			return FZN_RECONCILE_ERR_SHAPE;
		if (kept == 0u) {
			start += batch;
			continue;
		}
		/* WHAT DID NOT FIT IS ASKED AGAIN: moved to the batch's end, so the
		 * next request starts at it and the rest follows unbroken. */
		{
			uint8_t later[FZN_RECONCILE_ASK_MAX][FZN_HOLDINGS_ID_LEN];

			for (i = 0, j = 0; i < batch; i++)
				if (!got[i])
					memcpy(later[j++], lacked[start + i], FZN_HOLDINGS_ID_LEN);
			start += batch - j;
			if (j)
				memcpy(lacked[start], later, j * FZN_HOLDINGS_ID_LEN);
		}
	}
	return FZN_RECONCILE_OK;
}

fzn_reconcile_err_t fzn_reconcile_round(fzn_node_apply_t *ap, const fzn_reconcile_notes_t *notes,
                                        fzn_reconcile_ask_t ask, void *ask_ctx, uint8_t *reply,
                                        size_t reply_cap, fzn_reconcile_tally_t *tally)
{
	uint8_t theirs[FZN_HOLDINGS_CLASSES][FZN_HOLDINGS_ID_LEN];
	uint32_t their_count[FZN_HOLDINGS_CLASSES];
	uint8_t request[FZN_RECONCILE_IDS_QUERY_LEN];
	size_t reply_len = 0, n, c;
	int listed[FZN_HOLDINGS_CLASSES];

	if (!ap || !ap->store || !ap->hash || !ap->hash->hash || !ask || !reply || !tally
	    || reply_cap < FZN_RECONCILE_REPLY_MIN)
		return FZN_RECONCILE_ERR_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	request[0] = (uint8_t)FZN_RECONCILE_VERSION;
	request[1] = (uint8_t)FZN_RECONCILE_DIGEST_QUERY;
	if (!ask(ask_ctx, request, FZN_RECONCILE_DIGEST_QUERY_LEN, reply, reply_cap, &reply_len))
		return FZN_RECONCILE_ERR_NO_ANSWER;
	if (!is(reply, reply_len, (uint8_t)FZN_RECONCILE_DIGEST)
	    || reply_len < FZN_RECONCILE_DIGEST_HEAD_LEN
	    || reply_len != FZN_RECONCILE_DIGEST_HEAD_LEN + (size_t)reply[2] * FZN_RECONCILE_CLASS_LEN)
		return FZN_RECONCILE_ERR_SHAPE;
	memset(listed, 0, sizeof(listed));
	for (n = 0; n < reply[2]; n++) {
		const uint8_t *e = reply + FZN_RECONCILE_DIGEST_HEAD_LEN + (n * FZN_RECONCILE_CLASS_LEN);

		/* A CLASS THIS BUILD DOES NOT KNOW is a newer peer's, passed over. */
		if (e[0] >= FZN_HOLDINGS_CLASSES)
			continue;
		listed[e[0]] = 1;
		their_count[e[0]] = fzn_get_be32(e + 1u);
		memcpy(theirs[e[0]], e + 5u, FZN_HOLDINGS_ID_LEN);
	}
	for (c = 0; c < FZN_HOLDINGS_CLASSES; c++) {
		uint8_t mine[FZN_HOLDINGS_ID_LEN];
		size_t my_count = 0, n_mine = 0, n_lacked = 0, from = 0, total;
		fzn_holdings_err_t herr;
		fzn_reconcile_err_t err;

		if (!listed[c] || their_count[c] == 0u)
			continue;
		/* NOTE CLAIMS ONLY WHERE THERE IS A NOTES STORE to file them. */
		if (c == FZN_HOLDINGS_NOTES && (!notes || !notes->file))
			continue;
		if (their_count[c] == COUNT_FULL) {
			tally->full++;
			continue;
		}
		herr = fzn_holdings_digest(ap->store, ap->hash, (fzn_holdings_class_t)c, mine,
		                           &my_count);
		if (herr == FZN_HOLDINGS_OK && my_count == their_count[c]
		    && memcmp(mine, theirs[c], sizeof(mine)) == 0)
			continue;
		if (herr == FZN_HOLDINGS_FULL) {
			tally->full++;
			continue;
		}
		if (herr != FZN_HOLDINGS_OK
		    || fzn_holdings_ids(ap->store, ap->hash, (fzn_holdings_class_t)c, ids_buf,
		                        FZN_HOLDINGS_MAX, &n_mine) != FZN_HOLDINGS_OK)
			return FZN_RECONCILE_ERR_STORE;
		tally->classes++;
		total = their_count[c];
		/* THEIR IDS, A PAGE AT A TIME, each this node does not hold
		 * noted. A page that brings none ends the listing: a peer whose
		 * class shrank since its digest is asked again next round. */
		while (from < total) {
			size_t count, i;

			request[1] = (uint8_t)FZN_RECONCILE_IDS_QUERY;
			request[2] = (uint8_t)c;
			fzn_put_be32(request + 3u, (uint32_t)from);
			if (!ask(ask_ctx, request, FZN_RECONCILE_IDS_QUERY_LEN, reply, reply_cap,
			         &reply_len))
				return FZN_RECONCILE_ERR_NO_ANSWER;
			if (!is(reply, reply_len, (uint8_t)FZN_RECONCILE_IDS)
			    || reply_len < FZN_RECONCILE_IDS_HEAD_LEN || reply[2] != (uint8_t)c
			    || fzn_get_be32(reply + 7u) != from
			    || reply_len != FZN_RECONCILE_IDS_HEAD_LEN
			                            + (size_t)fzn_get_be16(reply + 11u) * FZN_HOLDINGS_ID_LEN)
				return FZN_RECONCILE_ERR_SHAPE;
			count = fzn_get_be16(reply + 11u);
			if (count == 0u)
				break;
			for (i = 0; i < count && n_lacked < FZN_HOLDINGS_MAX; i++) {
				const uint8_t *id = reply + FZN_RECONCILE_IDS_HEAD_LEN + (i * FZN_HOLDINGS_ID_LEN);

				if (!fzn_holdings_among((const uint8_t(*)[FZN_HOLDINGS_ID_LEN])ids_buf,
				                        n_mine, id))
					memcpy(lacked[n_lacked++], id, FZN_HOLDINGS_ID_LEN);
			}
			from += count;
		}
		tally->lacked += n_lacked;
		err = fetch(ap, notes, ask, ask_ctx, (uint8_t)c, n_lacked, reply, reply_cap, tally);
		if (err != FZN_RECONCILE_OK)
			return err;
	}
	return FZN_RECONCILE_OK;
}

/* ---- a stream behind a peer's base ------------------------------------- */

static uint8_t bridge[FZN_RECONCILE_BRIDGE_MAX][FZN_NODE_JOURNAL_SPINE_ENTRY];
static uint8_t witnessed[FZN_RECONCILE_BRIDGE_MAX][FZN_NODE_JOURNAL_SPINE_ENTRY];

/* ONE PEER'S BRIDGE for `issuer`'s `stream` from `held` + 1: its base and the
 * id below it into `*base` and `below`, and up to `want` entries -- or, with
 * `want` of 0, as many as reach just below its base -- into `out`, `*n` of
 * them. A peer that runs out of entries early ends the bridge there. */
static fzn_reconcile_err_t bridge_of(fzn_reconcile_ask_t ask, void *ask_ctx,
                                     const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                                     uint64_t held, uint64_t want, uint8_t *reply,
                                     size_t reply_cap, uint64_t *base,
                                     uint8_t below[FZN_RECORD_ID_LEN],
                                     uint8_t (*out)[FZN_NODE_JOURNAL_SPINE_ENTRY], size_t *n)
{
	uint8_t request[FZN_RECONCILE_BASE_QUERY_LEN];
	size_t have = 0;
	int first = 1;

	*n = 0;
	*base = 0;
	request[0] = (uint8_t)FZN_RECONCILE_VERSION;
	request[1] = (uint8_t)FZN_RECONCILE_BASE_QUERY;
	memcpy(request + 2u, issuer, FZN_PUBKEY_LEN);
	fzn_put_be32(request + 34u, stream);
	for (;;) {
		size_t reply_len = 0, count;

		fzn_put_be64(request + 38u, held + 1u + have);
		if (!ask(ask_ctx, request, sizeof(request), reply, reply_cap, &reply_len))
			return FZN_RECONCILE_ERR_NO_ANSWER;
		if (!is(reply, reply_len, (uint8_t)FZN_RECONCILE_BASE)
		    || reply_len < FZN_RECONCILE_BASE_HEAD_LEN
		    || fzn_get_be64(reply + 42u) != held + 1u + have
		    || reply_len != FZN_RECONCILE_BASE_HEAD_LEN
		                            + (size_t)fzn_get_be16(reply + 50u)
		                                      * FZN_NODE_JOURNAL_SPINE_ENTRY)
			return FZN_RECONCILE_ERR_SHAPE;
		if (first) {
			*base = fzn_get_be64(reply + 2u);
			memcpy(below, reply + 10u, FZN_RECORD_ID_LEN);
			if (!want) {
				/* THE PEER'S OWN BRIDGE: to just below its base, or
				 * nothing for a peer not ahead of this journal. */
				if (*base < 2u || *base - 1u <= held || stream != FZN_NODE_JOURNAL_STREAM)
					return FZN_RECONCILE_OK;
				want = *base - 1u - held;
			}
			if (want > FZN_RECONCILE_BRIDGE_MAX)
				return FZN_RECONCILE_ERR_STORE;
			first = 0;
		} else if (fzn_get_be64(reply + 2u) != *base) {
			/* THE PEER CUT AGAIN between two pages: next round. */
			*n = 0;
			return FZN_RECONCILE_OK;
		}
		count = fzn_get_be16(reply + 50u);
		if (count > want - have)
			count = (size_t)(want - have);
		memcpy(out[have], reply + FZN_RECONCILE_BASE_HEAD_LEN,
		       count * FZN_NODE_JOURNAL_SPINE_ENTRY);
		have += count;
		*n = have;
		if (have >= want || count == 0u)
			return FZN_RECONCILE_OK;
	}
}

fzn_reconcile_err_t fzn_reconcile_rebase(fzn_node_journal_t *journal, fzn_reconcile_ask_t ask,
                                         void *ask_ctx, const fzn_reconcile_witness_t *witnesses,
                                         size_t n_witnesses, const uint8_t issuer[FZN_PUBKEY_LEN],
                                         uint32_t stream, uint8_t *reply, size_t reply_cap,
                                         uint64_t *base, size_t *confirmed)
{
	uint8_t below[FZN_RECORD_ID_LEN], their_below[FZN_RECORD_ID_LEN];
	uint64_t held, theirs = 0, other = 0;
	size_t have = 0, w;
	fzn_reconcile_err_t err;

	if (base)
		*base = 0;
	if (confirmed)
		*confirmed = 0;
	if (!journal || !ask || !issuer || !reply || reply_cap < FZN_RECONCILE_REPLY_MIN
	    || (n_witnesses && !witnesses))
		return FZN_RECONCILE_ERR_MALFORMED;
	held = fzn_node_journal_received(journal, issuer, stream);
	err = bridge_of(ask, ask_ctx, issuer, stream, held, 0u, reply, reply_cap, &theirs, below,
	                bridge, &have);
	if (err != FZN_RECONCILE_OK)
		return err;
	if (theirs < 2u || theirs - 1u <= held)
		return FZN_RECONCILE_OK;
	if (stream == FZN_NODE_JOURNAL_STREAM && have != theirs - 1u - held)
		return have ? FZN_RECONCILE_ERR_SHAPE : FZN_RECONCILE_OK;
	/* EVERY OTHER PEER OF THE ESTATE IS A WITNESS, sec 557: the subjects
	 * are the one part of a bridge its ends do not check, so each entry a
	 * witness can give for the same sequence must be the same -- id,
	 * predecessor and subject. A witness that disagrees anywhere refuses
	 * the move; one that cannot answer, or gives none, confirms nothing. */
	for (w = 0; w < n_witnesses && have; w++) {
		size_t got = 0, i;

		if (bridge_of(witnesses[w].ask, witnesses[w].ctx, issuer, stream, held, have, reply,
		              reply_cap, &other, their_below, witnessed, &got)
		    != FZN_RECONCILE_OK
		    || got == 0u)
			continue;
		for (i = 0; i < got; i++)
			if (memcmp(witnessed[i], bridge[i], FZN_NODE_JOURNAL_SPINE_ENTRY) != 0)
				return FZN_RECONCILE_ERR_CONFLICT;
		if (confirmed)
			(*confirmed)++;
	}
	if (fzn_node_journal_rebase(journal, issuer, stream, theirs, below,
	                            (const uint8_t(*)[FZN_NODE_JOURNAL_SPINE_ENTRY])bridge, have)
	    != FZN_NODE_JOURNAL_OK)
		return FZN_RECONCILE_ERR_STORE;
	if (base)
		*base = theirs;
	return FZN_RECONCILE_OK;
}
