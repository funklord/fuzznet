/* See reconcile.h. */

#include "reconcile.h"

#include "../wire/bytes.h"

#include <stdlib.h>
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

/* ---- append-only kinds, by bucket, sec 564 --------------------------------- */

/* Every bucket of a kind, the answer's. Not the round's: a round lists none
 * of its own, asking for each of the peer's in turn. */
static fzn_bucket_t served_buckets[FZN_BUCKETS_MAX];

static int served(const fzn_reconcile_gate_t *gate, uint8_t kind,
                  const uint8_t subject[FZN_PUBKEY_LEN])
{
	return !gate || (gate->serves && gate->serves(gate->ctx, (fzn_buckets_kind_t)kind, subject));
}

static size_t answer_buckets(const fzn_buckets_t *b, const fzn_reconcile_gate_t *gate,
                             const uint8_t *request, size_t request_len, uint8_t *reply,
                             size_t reply_cap)
{
	size_t n = 0, from, count, room, i, at = FZN_RECONCILE_BUCKETS_HEAD_LEN;

	if (request_len != FZN_RECONCILE_BUCKETS_QUERY_LEN || request[2] >= FZN_BUCKETS_KINDS
	    || reply_cap < FZN_RECONCILE_BUCKETS_HEAD_LEN)
		return 0;
	/* TOO MANY TO LIST answers a count this cannot reach and no buckets,
	 * so the asker counts it full rather than taking a part for the whole. */
	switch (fzn_buckets_list(b, (fzn_buckets_kind_t)request[2], served_buckets, FZN_BUCKETS_MAX,
	                         &n)) {
	case FZN_BUCKETS_OK:
		break;
	case FZN_BUCKETS_FULL:
		n = COUNT_FULL;
		break;
	default:
		return 0;
	}
	/* ONLY WHAT THE CALLER MAY HOLD, before paging, so the positions it
	 * pages by are the same each time it asks. */
	if (n != COUNT_FULL && gate) {
		size_t kept = 0;

		for (i = 0; i < n; i++)
			if (served(gate, request[2], served_buckets[i].subject))
				served_buckets[kept++] = served_buckets[i];
		n = kept;
	}
	from = fzn_get_be32(request + 3u);
	count = n != COUNT_FULL && from < n ? n - from : 0u;
	room = (reply_cap - FZN_RECONCILE_BUCKETS_HEAD_LEN) / FZN_RECONCILE_BUCKET_LEN;
	if (count > room)
		count = room;
	for (i = 0; i < count; i++, at += FZN_RECONCILE_BUCKET_LEN) {
		const fzn_bucket_t *k = &served_buckets[from + i];

		memcpy(reply + at, k->subject, FZN_PUBKEY_LEN);
		fzn_put_be32(reply + at + 32u, k->month);
		fzn_put_be64(reply + at + 36u, k->count);
		memcpy(reply + at + 44u, k->digest, FZN_BUCKETS_ID_LEN);
	}
	reply[0] = (uint8_t)FZN_RECONCILE_VERSION;
	reply[1] = (uint8_t)FZN_RECONCILE_BUCKETS;
	reply[2] = request[2];
	fzn_put_be32(reply + 3u, (uint32_t)n);
	fzn_put_be32(reply + 7u, (uint32_t)from);
	fzn_put_be16(reply + 11u, (uint16_t)count);
	return at;
}

static size_t answer_bucket_ids(const fzn_buckets_t *b, const fzn_reconcile_gate_t *gate,
                                const uint8_t *request, size_t request_len, uint8_t *reply,
                                size_t reply_cap)
{
	uint64_t total = 0;
	size_t count = 0, room;
	uint32_t month, from;

	if (request_len != FZN_RECONCILE_BUCKET_IDS_QUERY_LEN || request[2] >= FZN_BUCKETS_KINDS
	    || reply_cap < FZN_RECONCILE_BUCKET_IDS_HEAD_LEN)
		return 0;
	month = fzn_get_be32(request + 35u);
	from = fzn_get_be32(request + 39u);
	room = (reply_cap - FZN_RECONCILE_BUCKET_IDS_HEAD_LEN) / FZN_BUCKETS_ID_LEN;
	if (room > 0xffffu)
		room = 0xffffu;
	/* A BUCKET THE CALLER MAY NOT HOLD names no ids, as one not held. */
	if (served(gate, request[2], request + 3u)
	    && (fzn_buckets_ids(b, (fzn_buckets_kind_t)request[2], request + 3u, month, from,
	                        (uint8_t(*)[FZN_BUCKETS_ID_LEN])(reply
	                                                         + FZN_RECONCILE_BUCKET_IDS_HEAD_LEN),
	                        room, &count, &total)
	                != FZN_BUCKETS_OK
	        || total > 0xffffffffu))
		return 0;
	reply[0] = (uint8_t)FZN_RECONCILE_VERSION;
	reply[1] = (uint8_t)FZN_RECONCILE_BUCKET_IDS;
	memcpy(reply + 2u, request + 2u, 1u + FZN_PUBKEY_LEN + 4u);
	fzn_put_be32(reply + 39u, (uint32_t)total);
	fzn_put_be32(reply + 43u, from);
	fzn_put_be16(reply + 47u, (uint16_t)count);
	return FZN_RECONCILE_BUCKET_IDS_HEAD_LEN + count * FZN_BUCKETS_ID_LEN;
}

static uint8_t served_item[FZN_BUCKETS_ITEM_MAX];

static size_t answer_item(const fzn_reconcile_server_t *srv, const fzn_buckets_t *b,
                          const fzn_reconcile_gate_t *gate, const uint8_t *request,
                          size_t request_len, uint8_t *reply, size_t reply_cap)
{
	uint8_t subject[FZN_PUBKEY_LEN], ref[FZN_BUCKETS_REF_MAX];
	size_t len = 0, n = 0, ref_len = 0;
	uint64_t size = 0;
	uint32_t offset;
	fzn_buckets_err_t err;
	const struct fzn_reconcile_filer *kind_filer;

	if (request_len != FZN_RECONCILE_ITEM_QUERY_LEN || request[2] >= FZN_BUCKETS_KINDS
	    || reply_cap < FZN_RECONCILE_ITEM_HEAD_LEN)
		return 0;
	offset = fzn_get_be32(request + 35u);
	err = fzn_buckets_item(b, (fzn_buckets_kind_t)request[2], request + 3u, served_item,
	                       sizeof(served_item), &len, subject, NULL);
	if (err != FZN_BUCKETS_OK && err != FZN_BUCKETS_ABSENT && err != FZN_BUCKETS_LARGE)
		return 0;
	kind_filer = srv ? srv->takers[request[2]] : NULL;
	/* ONE ITS KIND KEEPS is read through the kind, sec 570; a kind that
	 * cannot read it serves it as not held. */
	if (err == FZN_BUCKETS_LARGE) {
		if (!kind_filer || !kind_filer->read
		    || fzn_buckets_ref(b, (fzn_buckets_kind_t)request[2], request + 3u, ref, &ref_len,
		                       &size)
		               != FZN_BUCKETS_OK)
			size = 0;
		len = (size_t)size;
	}
	if (err != FZN_BUCKETS_ABSENT && !served(gate, request[2], subject))
		len = 0;
	/* NOT HELD answers 0 of 0; an offset past the end, nothing of all. */
	if (offset < len) {
		n = len - offset;
		if (n > reply_cap - FZN_RECONCILE_ITEM_HEAD_LEN)
			n = reply_cap - FZN_RECONCILE_ITEM_HEAD_LEN;
		if (n > 0xffffu)
			n = 0xffffu;
		if (err == FZN_BUCKETS_LARGE) {
			if (!kind_filer->read(kind_filer->ctx, ref, ref_len, offset,
			                      reply + FZN_RECONCILE_ITEM_HEAD_LEN, n))
				return 0;
		} else {
			memcpy(reply + FZN_RECONCILE_ITEM_HEAD_LEN, served_item + offset, n);
		}
	}
	reply[0] = (uint8_t)FZN_RECONCILE_VERSION;
	reply[1] = (uint8_t)FZN_RECONCILE_ITEM;
	memcpy(reply + 2u, request + 2u, 1u + FZN_BUCKETS_ID_LEN);
	fzn_put_be32(reply + 35u, (uint32_t)len);
	fzn_put_be32(reply + 39u, offset);
	fzn_put_be16(reply + 43u, (uint16_t)n);
	return FZN_RECONCILE_ITEM_HEAD_LEN + n;
}

/* ---- push, the receiver's half, sec 569 ---------------------------------- */

/* PIECES HELD OF ITEMS PUSHED, one per sender and item: a push resumes from
 * what is held, and a slot wanted when all are taken is the oldest's. */
static struct staged {
	int used;
	uint64_t age;
	uint8_t sender[FZN_PUBKEY_LEN];
	uint8_t kind;
	uint8_t id[FZN_BUCKETS_ID_LEN];
	uint32_t total, held;
	uint8_t bytes[FZN_BUCKETS_ITEM_MAX];
} staged[FZN_RECONCILE_STAGED_MAX];
static uint64_t staged_clock;

static size_t answer_took(uint8_t *reply, size_t reply_cap, uint8_t kind, const uint8_t *id,
                          fzn_reconcile_took_t took, uint32_t held)
{
	if (reply_cap < FZN_RECONCILE_ITEM_TOOK_LEN)
		return 0;
	reply[0] = (uint8_t)FZN_RECONCILE_VERSION;
	reply[1] = (uint8_t)FZN_RECONCILE_ITEM_TOOK;
	reply[2] = kind;
	memcpy(reply + 3u, id, FZN_BUCKETS_ID_LEN);
	reply[35] = (uint8_t)took;
	fzn_put_be32(reply + 36u, held);
	return FZN_RECONCILE_ITEM_TOOK_LEN;
}

static struct staged *staged_for(const uint8_t *sender, uint8_t kind, const uint8_t *id)
{
	size_t i;

	for (i = 0; i < FZN_RECONCILE_STAGED_MAX; i++)
		if (staged[i].used && staged[i].kind == kind
		    && memcmp(staged[i].sender, sender, FZN_PUBKEY_LEN) == 0
		    && memcmp(staged[i].id, id, FZN_BUCKETS_ID_LEN) == 0)
			return &staged[i];
	return NULL;
}

static struct staged *staged_take(void)
{
	struct staged *oldest = &staged[0];
	size_t i;

	for (i = 0; i < FZN_RECONCILE_STAGED_MAX; i++) {
		if (!staged[i].used)
			return &staged[i];
		if (staged[i].age < oldest->age)
			oldest = &staged[i];
	}
	return oldest;
}

static void staged_free(struct staged *st)
{
	if (st->total <= FZN_BUCKETS_ITEM_MAX)
		memset(st->bytes, 0, st->held);
	st->used = 0;
}

static size_t answer_put(const fzn_reconcile_server_t *srv, const uint8_t *request,
                         size_t request_len, uint8_t *reply, size_t reply_cap)
{
	const struct fzn_reconcile_filer *taker;
	fzn_buckets_t b = { srv->store, srv->hash };
	const uint8_t *subject = request + 3u, *id = request + 39u;
	uint8_t kind = request[2], got[FZN_BUCKETS_ID_LEN];
	uint32_t month, total, offset;
	struct staged *st;
	size_t n;

	if (request_len < FZN_RECONCILE_ITEM_PUT_HEAD_LEN || kind >= FZN_BUCKETS_KINDS)
		return 0;
	month = fzn_get_be32(request + 35u);
	total = fzn_get_be32(request + 71u);
	offset = fzn_get_be32(request + 75u);
	n = fzn_get_be16(request + 79u);
	if (request_len != FZN_RECONCILE_ITEM_PUT_HEAD_LEN + n || total == 0u
	    || total > FZN_BUCKETS_LARGE_MAX || offset > total || n > total - offset)
		return 0;
	taker = srv->takers[kind];
	/* A NODE THAT TAKES NO PUSHES OF THE KIND, or none so large, says so,
	 * rather than falling through. */
	if (!taker || !taker->file || !srv->sender
	    || (total > FZN_BUCKETS_ITEM_MAX && (!taker->stage || !taker->finish)))
		return answer_took(reply, reply_cap, kind, id, FZN_RECONCILE_TOOK_NOT_WANTED, 0u);
	st = staged_for(srv->sender, kind, id);
	/* JUDGED BEFORE ANY BYTE IS KEPT: held already, a bucket let go, or one
	 * this node's rules would not hold. */
	if (!st) {
		if (fzn_buckets_has(&b, (fzn_buckets_kind_t)kind, id))
			return answer_took(reply, reply_cap, kind, id, FZN_RECONCILE_TOOK_HELD, 0u);
		if (fzn_buckets_gone(&b, (fzn_buckets_kind_t)kind, subject, month)
		    || (taker->wanted && !taker->wanted(taker->ctx, subject, month)))
			return answer_took(reply, reply_cap, kind, id, FZN_RECONCILE_TOOK_NOT_WANTED,
			                   0u);
		/* AN EMPTY FIRST PIECE asks only where to start: nothing is staged
		 * until bytes come. */
		if (offset != 0u || n == 0u)
			return answer_took(reply, reply_cap, kind, id, FZN_RECONCILE_TOOK_MORE, 0u);
		st = staged_take();
		if (st->used)
			staged_free(st);
		st->used = 1;
		memcpy(st->sender, srv->sender, FZN_PUBKEY_LEN);
		st->kind = kind;
		memcpy(st->id, id, FZN_BUCKETS_ID_LEN);
		st->total = total;
		st->held = 0u;
	}
	st->age = ++staged_clock;
	/* ONE ITEM, ONE LENGTH, in order: anything else is answered with what
	 * is held, and the pusher goes on from there. */
	if (total != st->total) {
		staged_free(st);
		return answer_took(reply, reply_cap, kind, id, FZN_RECONCILE_TOOK_MORE, 0u);
	}
	if (offset != st->held)
		return answer_took(reply, reply_cap, kind, id, FZN_RECONCILE_TOOK_MORE, st->held);
	/* A LARGE ITEM'S PIECES go to its kind, sec 570; this keeps only how
	 * far it is. */
	if (st->total > FZN_BUCKETS_ITEM_MAX) {
		if (!taker->stage(taker->ctx, id, st->total, st->held,
		                  request + FZN_RECONCILE_ITEM_PUT_HEAD_LEN, n)) {
			staged_free(st);
			return answer_took(reply, reply_cap, kind, id, FZN_RECONCILE_TOOK_REFUSED, 0u);
		}
	} else {
		memcpy(st->bytes + st->held, request + FZN_RECONCILE_ITEM_PUT_HEAD_LEN, n);
	}
	st->held += (uint32_t)n;
	if (st->held < st->total)
		return answer_took(reply, reply_cap, kind, id, FZN_RECONCILE_TOOK_MORE, st->held);
	if (st->total > FZN_BUCKETS_ITEM_MAX) {
		fzn_node_apply_outcome_t out = taker->finish(taker->ctx, subject, month, id, st->total);

		st->held = 0u;
		staged_free(st);
		return answer_took(reply, reply_cap, kind, id,
		                   out == FZN_NODE_APPLY_APPLIED || out == FZN_NODE_APPLY_WAITING
		                           ? FZN_RECONCILE_TOOK_KEPT
		                           : FZN_RECONCILE_TOOK_REFUSED,
		                   out == FZN_NODE_APPLY_APPLIED || out == FZN_NODE_APPLY_WAITING
		                           ? total
		                           : 0u);
	}
	/* WHOLE: its id's, or nothing; then judged as an item fetched. */
	if (!fzn_buckets_id(srv->hash, st->bytes, st->total, got)
	    || memcmp(got, id, FZN_BUCKETS_ID_LEN) != 0) {
		staged_free(st);
		return answer_took(reply, reply_cap, kind, id, FZN_RECONCILE_TOOK_REFUSED, 0u);
	}
	switch (taker->file(taker->ctx, subject, month, st->bytes, st->total)) {
	case FZN_NODE_APPLY_APPLIED:
	case FZN_NODE_APPLY_WAITING:
		staged_free(st);
		return answer_took(reply, reply_cap, kind, id, FZN_RECONCILE_TOOK_KEPT, total);
	default:
		/* REFUSED, or this store would not keep it: either way the pusher
		 * is told no, and a store that failed is offered it again next
		 * round, since it still lacks it. */
		staged_free(st);
		return answer_took(reply, reply_cap, kind, id, FZN_RECONCILE_TOOK_REFUSED, 0u);
	}
}

size_t fzn_reconcile_answer(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                            fzn_node_journal_t *journal, const uint8_t *request,
                            size_t request_len, uint8_t *reply, size_t reply_cap)
{
	return fzn_reconcile_answer_gated(store, hash, journal, NULL, request, request_len, reply,
	                                  reply_cap);
}

size_t fzn_reconcile_answer_gated(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                  fzn_node_journal_t *journal, const fzn_reconcile_gate_t *gate,
                                  const uint8_t *request, size_t request_len, uint8_t *reply,
                                  size_t reply_cap)
{
	fzn_reconcile_server_t srv;

	memset(&srv, 0, sizeof(srv));
	srv.store = store;
	srv.hash = hash;
	srv.journal = journal;
	srv.gate = gate;
	return fzn_reconcile_serve(&srv, request, request_len, reply, reply_cap);
}

size_t fzn_reconcile_serve(const fzn_reconcile_server_t *srv, const uint8_t *request,
                           size_t request_len, uint8_t *reply, size_t reply_cap)
{
	const fzn_persist_ops_t *store = srv ? srv->store : NULL;
	const fzn_hash_ops_t *hash = srv ? srv->hash : NULL;
	fzn_node_journal_t *journal = srv ? srv->journal : NULL;
	const fzn_reconcile_gate_t *gate = srv ? srv->gate : NULL;

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
	{
		fzn_buckets_t b = { store, hash };

		if (request[1] == (uint8_t)FZN_RECONCILE_BUCKETS_QUERY)
			return answer_buckets(&b, gate, request, request_len, reply, reply_cap);
		if (request[1] == (uint8_t)FZN_RECONCILE_BUCKET_IDS_QUERY)
			return answer_bucket_ids(&b, gate, request, request_len, reply, reply_cap);
		if (request[1] == (uint8_t)FZN_RECONCILE_ITEM_QUERY)
			return answer_item(srv, &b, gate, request, request_len, reply, reply_cap);
		if (request[1] == (uint8_t)FZN_RECONCILE_ITEM_PUT)
			return answer_put(srv, request, request_len, reply, reply_cap);
	}
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

/* ---- append-only kinds, the round's half --------------------------------- */

/* Buckets and ids taken from a reply before the next request reuses it. */
#define BUCKETS_PER 32u
#define IDS_PER 64u

static uint8_t fetched_item[FZN_BUCKETS_ITEM_MAX];

/* ONE ITEM BY ID, whole, in as many pieces as the replies take: its bytes
 * into fetched_item, `*len` of them, 0 when the peer no longer holds it. */
/* ONE ITEM BY ID, whole, in as many pieces as the replies take. One that
 * fits a row lands in fetched_item, `*len` bytes, 0 when the peer no longer
 * holds it. One past FZN_BUCKETS_ITEM_MAX goes piece by piece to the kind's
 * STAGE and then FINISH (sec 570), its outcome in `*large` with `*len` 0; a
 * kind that takes none, or a stage that refuses, is REFUSED and asked no
 * more. */
fzn_reconcile_err_t fzn_reconcile_peer_holds(fzn_buckets_kind_t kind,
                                             const uint8_t id[FZN_BUCKETS_ID_LEN],
                                             fzn_reconcile_ask_t ask, void *ask_ctx,
                                             uint8_t *reply, size_t reply_cap, int *held)
{
	uint8_t request[FZN_RECONCILE_ITEM_QUERY_LEN];
	size_t reply_len = 0;

	if (!held)
		return FZN_RECONCILE_ERR_MALFORMED;
	*held = 0;
	if (!id || !ask || !reply || reply_cap < FZN_RECONCILE_ITEM_HEAD_LEN
	    || (unsigned)kind >= FZN_BUCKETS_KINDS)
		return FZN_RECONCILE_ERR_MALFORMED;
	request[0] = (uint8_t)FZN_RECONCILE_VERSION;
	request[1] = (uint8_t)FZN_RECONCILE_ITEM_QUERY;
	request[2] = (uint8_t)kind;
	memcpy(request + 3u, id, FZN_BUCKETS_ID_LEN);
	/* PAST ANY END: the length, and no byte. */
	fzn_put_be32(request + 35u, 0xffffffffu);
	if (!ask(ask_ctx, request, sizeof(request), reply, reply_cap, &reply_len))
		return FZN_RECONCILE_ERR_NO_ANSWER;
	if (!is(reply, reply_len, (uint8_t)FZN_RECONCILE_ITEM)
	    || reply_len < FZN_RECONCILE_ITEM_HEAD_LEN || reply[2] != (uint8_t)kind
	    || memcmp(reply + 3u, id, FZN_BUCKETS_ID_LEN) != 0
	    || fzn_get_be32(reply + 39u) != 0xffffffffu
	    || reply_len != FZN_RECONCILE_ITEM_HEAD_LEN + (size_t)fzn_get_be16(reply + 43u))
		return FZN_RECONCILE_ERR_SHAPE;
	*held = fzn_get_be32(reply + 35u) > 0u;
	return FZN_RECONCILE_OK;
}

static fzn_reconcile_err_t fetch_item(fzn_buckets_kind_t kind,
                                      const uint8_t id[FZN_BUCKETS_ID_LEN],
                                      const fzn_reconcile_filer_t *filer,
                                      const uint8_t *subject, uint32_t month,
                                      fzn_reconcile_ask_t ask, void *ask_ctx, uint8_t *reply,
                                      size_t reply_cap, size_t *len, int *is_large,
                                      fzn_node_apply_outcome_t *large)
{
	uint8_t request[FZN_RECONCILE_ITEM_QUERY_LEN];
	size_t got = 0, total = 0, reply_len = 0, n;

	*len = 0;
	*is_large = 0;
	request[0] = (uint8_t)FZN_RECONCILE_VERSION;
	request[1] = (uint8_t)FZN_RECONCILE_ITEM_QUERY;
	request[2] = (uint8_t)kind;
	memcpy(request + 3u, id, FZN_BUCKETS_ID_LEN);
	do {
		fzn_put_be32(request + 35u, (uint32_t)got);
		if (!ask(ask_ctx, request, sizeof(request), reply, reply_cap, &reply_len))
			return FZN_RECONCILE_ERR_NO_ANSWER;
		if (!is(reply, reply_len, (uint8_t)FZN_RECONCILE_ITEM)
		    || reply_len < FZN_RECONCILE_ITEM_HEAD_LEN || reply[2] != (uint8_t)kind
		    || memcmp(reply + 3u, id, FZN_BUCKETS_ID_LEN) != 0
		    || fzn_get_be32(reply + 39u) != got
		    || reply_len != FZN_RECONCILE_ITEM_HEAD_LEN + (size_t)fzn_get_be16(reply + 43u))
			return FZN_RECONCILE_ERR_SHAPE;
		/* ONE LENGTH FOR THE WHOLE ITEM: a peer that changes it part way
		 * is answering for another item. */
		if (got == 0u) {
			total = fzn_get_be32(reply + 35u);
			if (total > FZN_BUCKETS_LARGE_MAX)
				return FZN_RECONCILE_ERR_SHAPE;
			*is_large = total > FZN_BUCKETS_ITEM_MAX;
			if (*is_large && (!filer->stage || !filer->finish)) {
				*large = FZN_NODE_APPLY_REFUSED;
				return FZN_RECONCILE_OK;
			}
		} else if (fzn_get_be32(reply + 35u) != total) {
			return FZN_RECONCILE_ERR_SHAPE;
		}
		if (total == 0u)
			return FZN_RECONCILE_OK;
		n = fzn_get_be16(reply + 43u);
		/* A PIECE THAT MOVES NOTHING ends it, or a peer could keep this
		 * asking for ever. */
		if (n == 0u || n > total - got)
			return FZN_RECONCILE_ERR_SHAPE;
		if (*is_large) {
			if (!filer->stage(filer->ctx, id, total, got, reply + FZN_RECONCILE_ITEM_HEAD_LEN,
			                  n)) {
				*large = FZN_NODE_APPLY_REFUSED;
				return FZN_RECONCILE_OK;
			}
		} else {
			memcpy(fetched_item + got, reply + FZN_RECONCILE_ITEM_HEAD_LEN, n);
		}
		got += n;
	} while (got < total);
	if (*is_large)
		*large = filer->finish(filer->ctx, subject, month, id, total);
	else
		*len = total;
	return FZN_RECONCILE_OK;
}

/* ONE OF THE PEER'S BUCKETS that differs from this node's: its ids paged,
 * and each this node lacks fetched, checked against its id, and filed. */
static fzn_reconcile_err_t take_bucket(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                       const fzn_reconcile_filer_t *filer, const uint8_t *subject,
                                       uint32_t month, fzn_reconcile_ask_t ask, void *ask_ctx,
                                       uint8_t *reply, size_t reply_cap,
                                       fzn_reconcile_bucket_tally_t *tally)
{
	uint8_t request[FZN_RECONCILE_BUCKET_IDS_QUERY_LEN];
	uint8_t ids[IDS_PER][FZN_BUCKETS_ID_LEN];
	uint64_t from = 0, total;
	size_t reply_len = 0, count, i;

	request[0] = (uint8_t)FZN_RECONCILE_VERSION;
	request[1] = (uint8_t)FZN_RECONCILE_BUCKET_IDS_QUERY;
	request[2] = (uint8_t)kind;
	memcpy(request + 3u, subject, FZN_PUBKEY_LEN);
	fzn_put_be32(request + 35u, month);
	do {
		fzn_put_be32(request + 39u, (uint32_t)from);
		if (!ask(ask_ctx, request, sizeof(request), reply, reply_cap, &reply_len))
			return FZN_RECONCILE_ERR_NO_ANSWER;
		if (!is(reply, reply_len, (uint8_t)FZN_RECONCILE_BUCKET_IDS)
		    || reply_len < FZN_RECONCILE_BUCKET_IDS_HEAD_LEN
		    || memcmp(reply + 2u, request + 2u, 1u + FZN_PUBKEY_LEN + 4u) != 0
		    || fzn_get_be32(reply + 43u) != from
		    || reply_len != FZN_RECONCILE_BUCKET_IDS_HEAD_LEN
		                            + (size_t)fzn_get_be16(reply + 47u) * FZN_BUCKETS_ID_LEN)
			return FZN_RECONCILE_ERR_SHAPE;
		total = fzn_get_be32(reply + 39u);
		count = fzn_get_be16(reply + 47u);
		/* A PAGE THAT BRINGS NONE ends the listing: a bucket that shrank
		 * since is asked again next round. */
		if (count == 0u)
			break;
		if (count > IDS_PER)
			count = IDS_PER;
		memcpy(ids, reply + FZN_RECONCILE_BUCKET_IDS_HEAD_LEN, count * FZN_BUCKETS_ID_LEN);
		from += count;
		for (i = 0; i < count; i++) {
			uint8_t id[FZN_BUCKETS_ID_LEN];
			size_t len = 0;
			int is_large = 0;
			fzn_node_apply_outcome_t outcome = FZN_NODE_APPLY_REFUSED;
			fzn_reconcile_err_t err;

			if (fzn_buckets_has(b, kind, ids[i]))
				continue;
			tally->lacked++;
			err = fetch_item(kind, ids[i], filer, subject, month, ask, ask_ctx, reply, reply_cap,
			                 &len, &is_large, &outcome);
			if (err != FZN_RECONCILE_OK)
				return err;
			if (!is_large) {
				if (len == 0u)
					continue;
				/* WHAT WAS ASKED FOR, or nothing: an item is its id's. A
				 * large one the kind checked in FINISH. */
				if (!fzn_buckets_id(b->hash, fetched_item, len, id))
					return FZN_RECONCILE_ERR_STORE;
				if (memcmp(id, ids[i], sizeof(id)) != 0) {
					tally->refused++;
					continue;
				}
				outcome = filer->file(filer->ctx, subject, month, fetched_item, len);
			}
			switch (outcome) {
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
	} while (from < total);
	return FZN_RECONCILE_OK;
}

fzn_reconcile_err_t fzn_reconcile_buckets(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                          const fzn_reconcile_filer_t *filer,
                                          fzn_reconcile_ask_t ask, void *ask_ctx,
                                          uint8_t *reply, size_t reply_cap,
                                          fzn_reconcile_bucket_tally_t *tally)
{
	uint8_t request[FZN_RECONCILE_BUCKETS_QUERY_LEN];
	struct {
		uint8_t subject[FZN_PUBKEY_LEN];
		uint32_t month;
		uint64_t count;
		uint8_t digest[FZN_BUCKETS_ID_LEN];
	} page[BUCKETS_PER];
	uint64_t from = 0, total;
	size_t reply_len = 0, count, i;

	if (!b || !b->store || !b->hash || !b->hash->hash || (unsigned)kind >= FZN_BUCKETS_KINDS
	    || !filer || !filer->file || !ask || !reply || !tally
	    || reply_cap < FZN_RECONCILE_REPLY_MIN)
		return FZN_RECONCILE_ERR_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	request[0] = (uint8_t)FZN_RECONCILE_VERSION;
	request[1] = (uint8_t)FZN_RECONCILE_BUCKETS_QUERY;
	request[2] = (uint8_t)kind;
	do {
		fzn_put_be32(request + 3u, (uint32_t)from);
		if (!ask(ask_ctx, request, sizeof(request), reply, reply_cap, &reply_len))
			return FZN_RECONCILE_ERR_NO_ANSWER;
		if (!is(reply, reply_len, (uint8_t)FZN_RECONCILE_BUCKETS)
		    || reply_len < FZN_RECONCILE_BUCKETS_HEAD_LEN || reply[2] != (uint8_t)kind
		    || fzn_get_be32(reply + 7u) != from
		    || reply_len != FZN_RECONCILE_BUCKETS_HEAD_LEN
		                            + (size_t)fzn_get_be16(reply + 11u) * FZN_RECONCILE_BUCKET_LEN)
			return FZN_RECONCILE_ERR_SHAPE;
		total = fzn_get_be32(reply + 3u);
		if (total == COUNT_FULL) {
			tally->full = 1;
			return FZN_RECONCILE_OK;
		}
		count = fzn_get_be16(reply + 11u);
		if (count == 0u)
			break;
		if (count > BUCKETS_PER)
			count = BUCKETS_PER;
		for (i = 0; i < count; i++) {
			const uint8_t *e = reply + FZN_RECONCILE_BUCKETS_HEAD_LEN + i * FZN_RECONCILE_BUCKET_LEN;

			memcpy(page[i].subject, e, FZN_PUBKEY_LEN);
			page[i].month = fzn_get_be32(e + 32u);
			page[i].count = fzn_get_be64(e + 36u);
			memcpy(page[i].digest, e + 44u, FZN_BUCKETS_ID_LEN);
		}
		from += count;
		for (i = 0; i < count; i++) {
			fzn_bucket_t mine;
			fzn_reconcile_err_t err;

			if (page[i].count == 0u)
				continue;
			if (fzn_buckets_gone(b, kind, page[i].subject, page[i].month)) {
				tally->passed++;
				continue;
			}
			if (fzn_buckets_bucket(b, kind, page[i].subject, page[i].month, &mine)
			    != FZN_BUCKETS_OK)
				return FZN_RECONCILE_ERR_STORE;
			if (mine.count == page[i].count
			    && memcmp(mine.digest, page[i].digest, FZN_BUCKETS_ID_LEN) == 0)
				continue;
			/* THE RULES ARE ASKED ONLY OF A BUCKET THAT DIFFERS: asking costs
			 * the kind a walk of what it holds, and one that agrees needs
			 * nothing fetched either way. sec 566. */
			if (filer->wanted && !filer->wanted(filer->ctx, page[i].subject, page[i].month)) {
				tally->passed++;
				continue;
			}
			tally->buckets++;
			err = take_bucket(b, kind, filer, page[i].subject, page[i].month, ask, ask_ctx,
			                  reply, reply_cap, tally);
			if (err != FZN_RECONCILE_OK)
				return err;
		}
	} while (from < total);
	return FZN_RECONCILE_OK;
}

/* ---- push, the pusher's half, sec 569 ------------------------------------- */

static fzn_bucket_t own_buckets[FZN_BUCKETS_MAX];
static fzn_bucket_t peer_buckets[FZN_BUCKETS_MAX];
static uint8_t peer_ids[FZN_RECONCILE_PEER_IDS_MAX][FZN_BUCKETS_ID_LEN];
static uint8_t pushed_item[FZN_BUCKETS_ITEM_MAX];

static int by_id(const void *a, const void *b)
{
	return memcmp(a, b, FZN_BUCKETS_ID_LEN);
}

/* ONE ITEM SENT, a piece at a time from wherever the peer says it holds,
 * until it says kept, held, refused or not wanted. THE FIRST PIECE IS
 * EMPTY: it asks where to start, so an item the peer holds or will not
 * take costs no bytes, and a push broken off resumes without resending
 * what arrived. Bounded: a peer that moves backward or not at all is given
 * three times the pieces the item takes, and then the item is left for the
 * next round. */
static fzn_reconcile_err_t push_item(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                     const fzn_bucket_t *k, const uint8_t id[FZN_BUCKETS_ID_LEN],
                                     const fzn_reconcile_filer_t *filer,
                                     const fzn_reconcile_sent_t *sent, fzn_reconcile_ask_t ask,
                                     void *ask_ctx, uint8_t *reply, size_t reply_cap,
                                     fzn_reconcile_bucket_tally_t *tally)
{
	static uint8_t request[FZN_RECONCILE_ITEM_PUT_HEAD_LEN + FZN_RECONCILE_PIECE_MAX];
	uint8_t ref[FZN_BUCKETS_REF_MAX];
	size_t len = 0, offset = 0, reply_len = 0, tries, sends = 0, ref_len = 0;
	uint64_t size = 0;
	int asking = 1, large = 0;
	fzn_buckets_err_t got;

	got = fzn_buckets_item(b, kind, id, pushed_item, sizeof(pushed_item), &len, NULL, NULL);
	/* ONE ITS KIND KEEPS is read through the kind, piece by piece. */
	if (got == FZN_BUCKETS_LARGE) {
		if (!filer || !filer->read
		    || fzn_buckets_ref(b, kind, id, ref, &ref_len, &size) != FZN_BUCKETS_OK)
			return FZN_RECONCILE_OK;
		len = (size_t)size;
		large = 1;
	} else if (got != FZN_BUCKETS_OK) {
		return FZN_RECONCILE_OK; /* let go since it was listed */
	}
	tries = 3u * (len / FZN_RECONCILE_PIECE_MAX + 2u);
	request[0] = (uint8_t)FZN_RECONCILE_VERSION;
	request[1] = (uint8_t)FZN_RECONCILE_ITEM_PUT;
	request[2] = (uint8_t)kind;
	memcpy(request + 3u, k->subject, FZN_PUBKEY_LEN);
	fzn_put_be32(request + 35u, k->month);
	memcpy(request + 39u, id, FZN_BUCKETS_ID_LEN);
	fzn_put_be32(request + 71u, (uint32_t)len);
	while (sends++ < tries) {
		size_t n = len - offset < FZN_RECONCILE_PIECE_MAX ? len - offset : FZN_RECONCILE_PIECE_MAX;
		uint32_t held;

		if (asking)
			n = 0u;
		asking = 0;
		fzn_put_be32(request + 75u, (uint32_t)offset);
		fzn_put_be16(request + 79u, (uint16_t)n);
		if (large) {
			if (n && !filer->read(filer->ctx, ref, ref_len, offset,
			                      request + FZN_RECONCILE_ITEM_PUT_HEAD_LEN, n))
				return FZN_RECONCILE_ERR_STORE;
		} else {
			memcpy(request + FZN_RECONCILE_ITEM_PUT_HEAD_LEN, pushed_item + offset, n);
		}
		if (!ask(ask_ctx, request, FZN_RECONCILE_ITEM_PUT_HEAD_LEN + n, reply, reply_cap,
		         &reply_len))
			return FZN_RECONCILE_ERR_NO_ANSWER;
		if (!is(reply, reply_len, (uint8_t)FZN_RECONCILE_ITEM_TOOK)
		    || reply_len != FZN_RECONCILE_ITEM_TOOK_LEN || reply[2] != (uint8_t)kind
		    || memcmp(reply + 3u, id, FZN_BUCKETS_ID_LEN) != 0)
			return FZN_RECONCILE_ERR_SHAPE;
		held = fzn_get_be32(reply + 36u);
		switch (reply[35]) {
		case FZN_RECONCILE_TOOK_MORE:
			if (held > len)
				return FZN_RECONCILE_ERR_SHAPE;
			offset = held;
			continue;
		case FZN_RECONCILE_TOOK_KEPT:
			tally->sent++;
			/* THE SENT HOOK SEES A ROW'S ITEM; a large one it is not shown. */
			if (sent && sent->kept && !large)
				sent->kept(sent->ctx, k->subject, k->month, pushed_item, len);
			return FZN_RECONCILE_OK;
		case FZN_RECONCILE_TOOK_HELD:
			tally->held++;
			return FZN_RECONCILE_OK;
		case FZN_RECONCILE_TOOK_REFUSED:
			tally->refused++;
			return FZN_RECONCILE_OK;
		case FZN_RECONCILE_TOOK_NOT_WANTED:
			tally->passed++;
			return FZN_RECONCILE_OK;
		default:
			return FZN_RECONCILE_ERR_SHAPE;
		}
	}
	return FZN_RECONCILE_OK;
}

fzn_reconcile_err_t fzn_reconcile_push(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                       const fzn_reconcile_gate_t *gate,
                                       const fzn_reconcile_filer_t *filer,
                                       const fzn_reconcile_sent_t *sent,
                                       fzn_reconcile_ask_t ask, void *ask_ctx, uint8_t *reply,
                                       size_t reply_cap, fzn_reconcile_bucket_tally_t *tally)
{
	uint8_t request[FZN_RECONCILE_BUCKETS_QUERY_LEN];
	size_t n_own = 0, n_peer = 0, reply_len = 0, i, p = 0;
	uint64_t total = 0, from = 0;

	if (!b || !b->store || !b->hash || !b->hash->hash || (unsigned)kind >= FZN_BUCKETS_KINDS
	    || !ask || !reply || !tally || reply_cap < FZN_RECONCILE_REPLY_MIN)
		return FZN_RECONCILE_ERR_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	switch (fzn_buckets_list(b, kind, own_buckets, FZN_BUCKETS_MAX, &n_own)) {
	case FZN_BUCKETS_OK:
		break;
	case FZN_BUCKETS_FULL:
		tally->full = 1;
		return FZN_RECONCILE_OK;
	default:
		return FZN_RECONCILE_ERR_STORE;
	}
	if (n_own == 0u)
		return FZN_RECONCILE_OK;
	/* THE PEER'S BUCKETS, every page: what it would be served of this kind
	 * is what it is compared on. */
	request[0] = (uint8_t)FZN_RECONCILE_VERSION;
	request[1] = (uint8_t)FZN_RECONCILE_BUCKETS_QUERY;
	request[2] = (uint8_t)kind;
	do {
		size_t count;

		fzn_put_be32(request + 3u, (uint32_t)from);
		if (!ask(ask_ctx, request, sizeof(request), reply, reply_cap, &reply_len))
			return FZN_RECONCILE_ERR_NO_ANSWER;
		if (!is(reply, reply_len, (uint8_t)FZN_RECONCILE_BUCKETS)
		    || reply_len < FZN_RECONCILE_BUCKETS_HEAD_LEN || reply[2] != (uint8_t)kind
		    || fzn_get_be32(reply + 7u) != from
		    || reply_len != FZN_RECONCILE_BUCKETS_HEAD_LEN
		                            + (size_t)fzn_get_be16(reply + 11u) * FZN_RECONCILE_BUCKET_LEN)
			return FZN_RECONCILE_ERR_SHAPE;
		total = fzn_get_be32(reply + 3u);
		if (total == COUNT_FULL || total > FZN_BUCKETS_MAX) {
			tally->full = 1;
			return FZN_RECONCILE_OK;
		}
		count = fzn_get_be16(reply + 11u);
		if (count == 0u)
			break;
		for (i = 0; i < count && n_peer < FZN_BUCKETS_MAX; i++) {
			const uint8_t *e = reply + FZN_RECONCILE_BUCKETS_HEAD_LEN + i * FZN_RECONCILE_BUCKET_LEN;

			memcpy(peer_buckets[n_peer].subject, e, FZN_PUBKEY_LEN);
			peer_buckets[n_peer].month = fzn_get_be32(e + 32u);
			peer_buckets[n_peer].count = fzn_get_be64(e + 36u);
			memcpy(peer_buckets[n_peer].digest, e + 44u, FZN_BUCKETS_ID_LEN);
			n_peer++;
		}
		from += count;
	} while (from < total);
	/* BOTH ASCENDING by subject and then month, so one walk pairs them. */
	for (i = 0; i < n_own; i++) {
		const fzn_bucket_t *k = &own_buckets[i];
		const fzn_bucket_t *theirs = NULL;
		uint8_t ids[64][FZN_BUCKETS_ID_LEN];
		size_t n_ids = 0, got, j;
		uint64_t at = 0, mine = 0;
		fzn_reconcile_err_t err;
		int overflow = 0;

		while (p < n_peer) {
			int d = memcmp(peer_buckets[p].subject, k->subject, FZN_PUBKEY_LEN);

			if (d > 0 || (d == 0 && peer_buckets[p].month >= k->month))
				break;
			p++;
		}
		if (p < n_peer && memcmp(peer_buckets[p].subject, k->subject, FZN_PUBKEY_LEN) == 0
		    && peer_buckets[p].month == k->month)
			theirs = &peer_buckets[p];
		if (theirs && theirs->count == k->count
		    && memcmp(theirs->digest, k->digest, FZN_BUCKETS_ID_LEN) == 0)
			continue;
		/* NOT THE PEER'S TO BE GIVEN, by this node's own gate. */
		if (gate && (!gate->serves || !gate->serves(gate->ctx, kind, k->subject))) {
			tally->passed++;
			continue;
		}
		tally->buckets++;
		/* WHAT IT HOLDS OF THIS BUCKET, sorted to be searched. */
		if (theirs) {
			uint8_t q[FZN_RECONCILE_BUCKET_IDS_QUERY_LEN];
			uint64_t their_total = 0, f = 0;

			q[0] = (uint8_t)FZN_RECONCILE_VERSION;
			q[1] = (uint8_t)FZN_RECONCILE_BUCKET_IDS_QUERY;
			q[2] = (uint8_t)kind;
			memcpy(q + 3u, k->subject, FZN_PUBKEY_LEN);
			fzn_put_be32(q + 35u, k->month);
			do {
				size_t count;

				fzn_put_be32(q + 39u, (uint32_t)f);
				if (!ask(ask_ctx, q, sizeof(q), reply, reply_cap, &reply_len))
					return FZN_RECONCILE_ERR_NO_ANSWER;
				if (!is(reply, reply_len, (uint8_t)FZN_RECONCILE_BUCKET_IDS)
				    || reply_len < FZN_RECONCILE_BUCKET_IDS_HEAD_LEN
				    || memcmp(reply + 2u, q + 2u, 1u + FZN_PUBKEY_LEN + 4u) != 0
				    || fzn_get_be32(reply + 43u) != f
				    || reply_len != FZN_RECONCILE_BUCKET_IDS_HEAD_LEN
				                            + (size_t)fzn_get_be16(reply + 47u)
				                                      * FZN_BUCKETS_ID_LEN)
					return FZN_RECONCILE_ERR_SHAPE;
				their_total = fzn_get_be32(reply + 39u);
				count = fzn_get_be16(reply + 47u);
				if (count == 0u)
					break;
				if (n_ids + count > FZN_RECONCILE_PEER_IDS_MAX) {
					overflow = 1;
					break;
				}
				memcpy(peer_ids[n_ids], reply + FZN_RECONCILE_BUCKET_IDS_HEAD_LEN,
				       count * FZN_BUCKETS_ID_LEN);
				n_ids += count;
				f += count;
			} while (f < their_total);
			/* TOO MANY TO COMPARE: the bucket is left, not half sent. */
			if (overflow) {
				tally->full = 1;
				continue;
			}
			qsort(peer_ids, n_ids, FZN_BUCKETS_ID_LEN, by_id);
		}
		/* EACH OF THIS NODE'S IT LACKS, sent. */
		do {
			if (fzn_buckets_ids(b, kind, k->subject, k->month, at, ids, 64u, &got, &mine)
			    != FZN_BUCKETS_OK)
				return FZN_RECONCILE_ERR_STORE;
			for (j = 0; j < got; j++) {
				if (n_ids && bsearch(ids[j], peer_ids, n_ids, FZN_BUCKETS_ID_LEN, by_id))
					continue;
				tally->lacked++;
				err = push_item(b, kind, k, ids[j], filer, sent, ask, ask_ctx, reply,
				                reply_cap, tally);
				if (err != FZN_RECONCILE_OK)
					return err;
			}
			at += got;
		} while (got && at < mine);
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
