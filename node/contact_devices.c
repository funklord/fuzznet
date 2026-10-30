/* A contact's devices: project.md sec 614, and the header. */
#include "contact_devices.h"

#include <stdlib.h>
#include <string.h>

#include "../wire/bytes.h"

const char *fzn_contact_device_err_str(fzn_contact_device_err_t err)
{
	switch (err) {
	case FZN_CONTACT_DEVICE_OK:
		return "ok";
	case FZN_CONTACT_DEVICE_ERR_MALFORMED:
		return "malformed";
	case FZN_CONTACT_DEVICE_ERR_SHAPE:
		return "not a contact's device";
	case FZN_CONTACT_DEVICE_ERR_REFUSED:
		return "its record or chain does not hold";
	case FZN_CONTACT_DEVICE_ERR_STALE:
		return "the record kept is newer";
	case FZN_CONTACT_DEVICE_ERR_ABSENT:
		return "none kept";
	case FZN_CONTACT_DEVICE_ERR_BACKEND:
		return "the store refused";
	case FZN_CONTACT_DEVICE_ERR_ROOM:
		return "more devices kept than the caller had room for";
	}
	return "unknown";
}

const uint8_t *fzn_contact_device_key(const fzn_contact_device_t *d)
{
	return d ? d->record + FZN_PREKEY_OFF_HOST : NULL;
}

/* An address as `net/address` takes one: letters, digits and `.-:`. */
static int address_ok(const char *a, size_t len)
{
	size_t i;

	if (len == 0u || len > FZN_CONTACT_DEVICE_ADDRESS_MAX)
		return 0;
	for (i = 0; i < len; i++) {
		char c = a[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		      || c == '.' || c == '-' || c == ':'))
			return 0;
	}
	return 1;
}

fzn_contact_device_err_t fzn_contact_device_encode(const fzn_contact_device_t *d, uint8_t *out,
                                                   size_t cap, size_t *len)
{
	size_t n, at;

	if (!d || !out || !len || d->hop_count > FZN_CHAIN_MAX_HOPS
	    || (d->port == 0u) != (d->address_len == 0u)
	    || (d->address_len && !address_ok(d->address, d->address_len)))
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	n = FZN_CONTACT_DEVICE_HEAD_LEN + 1u + d->address_len + 2u + 1u + d->hop_count * FZN_HOP_LEN;
	if (n > cap)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	out[0] = FZN_CONTACT_DEVICE_VERSION;
	memcpy(out + 1, d->owner, FZN_PUBKEY_LEN);
	memcpy(out + 1 + FZN_PUBKEY_LEN, d->record, FZN_PREKEY_LEN_TOTAL);
	at = FZN_CONTACT_DEVICE_HEAD_LEN;
	out[at++] = (uint8_t)d->address_len;
	memcpy(out + at, d->address, d->address_len);
	at += d->address_len;
	fzn_put_be16(out + at, d->port);
	at += 2u;
	out[at++] = (uint8_t)d->hop_count;
	memcpy(out + at, d->hops, d->hop_count * FZN_HOP_LEN);
	*len = n;
	return FZN_CONTACT_DEVICE_OK;
}

fzn_contact_device_err_t fzn_contact_device_decode(const uint8_t *bytes, size_t len,
                                                   fzn_contact_device_t *out)
{
	fzn_prekey_record_t record;
	size_t at, address_len, hop_count;

	if (!bytes || !out)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	if (len < FZN_CONTACT_DEVICE_HEAD_LEN + 1u || bytes[0] != FZN_CONTACT_DEVICE_VERSION)
		return FZN_CONTACT_DEVICE_ERR_SHAPE;
	memcpy(out->owner, bytes + 1, FZN_PUBKEY_LEN);
	memcpy(out->record, bytes + 1 + FZN_PUBKEY_LEN, FZN_PREKEY_LEN_TOTAL);
	if (fzn_prekey_open(out->record, FZN_PREKEY_LEN_TOTAL, &record) != FZN_PREKEY_OK)
		return FZN_CONTACT_DEVICE_ERR_SHAPE;
	at = FZN_CONTACT_DEVICE_HEAD_LEN;
	address_len = bytes[at++];
	if (address_len > FZN_CONTACT_DEVICE_ADDRESS_MAX || len < at + address_len + 3u)
		return FZN_CONTACT_DEVICE_ERR_SHAPE;
	memcpy(out->address, bytes + at, address_len);
	out->address[address_len] = '\0';
	out->address_len = address_len;
	at += address_len;
	out->port = fzn_get_be16(bytes + at);
	at += 2u;
	hop_count = bytes[at++];
	/* EXACTLY ITS LENGTH, and an address with a port or neither. */
	if (hop_count > FZN_CHAIN_MAX_HOPS || len != at + hop_count * FZN_HOP_LEN
	    || (out->port == 0u) != (address_len == 0u)
	    || (address_len && !address_ok(out->address, address_len)))
		return FZN_CONTACT_DEVICE_ERR_SHAPE;
	memcpy(out->hops, bytes + at, hop_count * FZN_HOP_LEN);
	out->hop_count = hop_count;
	return FZN_CONTACT_DEVICE_OK;
}

fzn_contact_device_err_t fzn_contact_device_verify(const fzn_contact_device_t *d,
                                                   const fzn_sign_ops_t *sign,
                                                   const fzn_cap_id_t *member, uint64_t now)
{
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	fzn_prekey_record_t record;
	fzn_chain_t chain;
	size_t i;

	if (!d || !sign || !sign->verify || !member || d->hop_count > FZN_CHAIN_MAX_HOPS)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	/* THE RECORD IS ITS HOST'S. */
	if (fzn_prekey_open(d->record, FZN_PREKEY_LEN_TOTAL, &record) != FZN_PREKEY_OK
	    || fzn_prekey_verify(record, sign) != FZN_PREKEY_OK)
		return FZN_CONTACT_DEVICE_ERR_REFUSED;
	/* AND ITS HOST IS THE OWNER, or the owner's member by a chain. */
	if (d->hop_count == 0u)
		return memcmp(record.host, d->owner, FZN_PUBKEY_LEN) == 0
		               ? FZN_CONTACT_DEVICE_OK
		               : FZN_CONTACT_DEVICE_ERR_REFUSED;
	for (i = 0; i < d->hop_count; i++)
		if (fzn_hop_open(d->hops[i], FZN_HOP_LEN, &hops[i]) != FZN_CHAIN_OK)
			return FZN_CONTACT_DEVICE_ERR_REFUSED;
	if (fzn_chain_verify(hops, d->hop_count, d->owner, member, now, sign, NULL, NULL, &chain)
	            != FZN_CHAIN_OK
	    || memcmp(chain.grantee, record.host, FZN_PUBKEY_LEN) != 0)
		return FZN_CONTACT_DEVICE_ERR_REFUSED;
	return FZN_CONTACT_DEVICE_OK;
}

static uint64_t created_at(const uint8_t record[FZN_PREKEY_LEN_TOTAL])
{
	return fzn_get_be64(record + FZN_PREKEY_OFF_CREATED_AT);
}

fzn_contact_device_err_t fzn_contact_device_keep(const fzn_persist_ops_t *store,
                                                 const fzn_contact_device_t *d)
{
	static uint8_t bytes[FZN_CONTACT_DEVICE_MAX];
	fzn_contact_device_t held;
	size_t len = 0;

	if (!store || !store->save || !d)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	if (fzn_contact_device_get(store, fzn_contact_device_key(d), &held) == FZN_CONTACT_DEVICE_OK
	    && created_at(held.record) > created_at(d->record))
		return FZN_CONTACT_DEVICE_ERR_STALE;
	if (fzn_contact_device_encode(d, bytes, sizeof(bytes), &len) != FZN_CONTACT_DEVICE_OK)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	return store->save(store->ctx, FZN_PERSIST_CONTACT_DEVICE, fzn_contact_device_key(d), bytes,
	                   len)
	               ? FZN_CONTACT_DEVICE_OK
	               : FZN_CONTACT_DEVICE_ERR_BACKEND;
}

fzn_contact_device_err_t fzn_contact_device_get(const fzn_persist_ops_t *store,
                                                const uint8_t key[FZN_PUBKEY_LEN],
                                                fzn_contact_device_t *out)
{
	static uint8_t bytes[FZN_CONTACT_DEVICE_MAX];
	size_t len = 0;

	if (!store || !store->load || !key || !out)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	if (!store->load(store->ctx, FZN_PERSIST_CONTACT_DEVICE, key, bytes, sizeof(bytes), &len))
		return FZN_CONTACT_DEVICE_ERR_ABSENT;
	/* KEPT UNDER ITS OWN KEY, or it is a row nobody kept. */
	if (fzn_contact_device_decode(bytes, len, out) != FZN_CONTACT_DEVICE_OK
	    || memcmp(fzn_contact_device_key(out), key, FZN_PUBKEY_LEN) != 0)
		return FZN_CONTACT_DEVICE_ERR_ABSENT;
	return FZN_CONTACT_DEVICE_OK;
}

/* ONE DEVICE, walked: into the caller's room while there is any, and
 * counted past it. A row that will not read is passed over, as the list
 * always passed it over. */
struct devices_walk {
	const fzn_persist_ops_t *store;
	fzn_contact_device_t *out;
	size_t cap, n;
};

static int device_walked(void *arg, const uint8_t key[FZN_PUBKEY_LEN])
{
	static fzn_contact_device_t past;
	struct devices_walk *w = arg;

	if (fzn_contact_device_get(w->store, key, w->n < w->cap ? &w->out[w->n] : &past)
	    == FZN_CONTACT_DEVICE_OK)
		w->n++;
	return 1;
}

fzn_contact_device_err_t fzn_contact_device_list(const fzn_persist_ops_t *store,
                                                 fzn_contact_device_t *out, size_t cap,
                                                 size_t *count)
{
	struct devices_walk w;

	if (!count)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	*count = 0;
	if (!store || (!out && cap))
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	w.store = store;
	w.out = out;
	w.cap = cap;
	w.n = 0;
	if (!fzn_persist_each(store, FZN_PERSIST_CONTACT_DEVICE, device_walked, &w))
		return FZN_CONTACT_DEVICE_ERR_BACKEND;
	*count = w.n;
	return w.n > cap ? FZN_CONTACT_DEVICE_ERR_ROOM : FZN_CONTACT_DEVICE_OK;
}

fzn_contact_device_err_t fzn_contact_device_remove(const fzn_persist_ops_t *store,
                                                   const uint8_t key[FZN_PUBKEY_LEN])
{
	fzn_contact_device_t held;

	if (!store || !store->remove || !key)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	if (fzn_contact_device_get(store, key, &held) != FZN_CONTACT_DEVICE_OK)
		return FZN_CONTACT_DEVICE_ERR_ABSENT;
	return store->remove(store->ctx, FZN_PERSIST_CONTACT_DEVICE, key)
	               ? FZN_CONTACT_DEVICE_OK
	               : FZN_CONTACT_DEVICE_ERR_BACKEND;
}

/* ---- the messages -------------------------------------------------------- */

_Static_assert(FZN_CONTACT_DEVICES_LIST_HEAD_LEN + 2u + FZN_CONTACT_DEVICE_MAX
                       <= FZN_CONTACT_DEVICES_REPLY_MAX,
               "the largest entry does not fit an empty page");

int fzn_contact_devices_offer_request(const fzn_contact_device_t *d, uint8_t *request,
                                      size_t cap, size_t *request_len)
{
	size_t len = 0;

	if (!d || !request || cap < 2u || !request_len
	    || fzn_contact_device_encode(d, request + 2, cap - 2u, &len) != FZN_CONTACT_DEVICE_OK)
		return 0;
	request[0] = FZN_CONTACT_DEVICES_VERSION;
	request[1] = FZN_CONTACT_DEVICES_OFFER;
	*request_len = 2u + len;
	return 1;
}

int fzn_contact_devices_offer_reply(const uint8_t *reply, size_t reply_len)
{
	if (!reply || reply_len != FZN_CONTACT_DEVICES_TAKEN_LEN
	    || reply[0] != FZN_CONTACT_DEVICES_VERSION || reply[1] != FZN_CONTACT_DEVICES_TAKEN
	    || reply[2] > 1u)
		return -1;
	return reply[2];
}

int fzn_contact_devices_offer(const fzn_contact_device_t *d, fzn_contact_devices_ask_t ask,
                              void *ctx)
{
	static uint8_t request[FZN_CONTACT_DEVICES_OFFER_MAX];
	uint8_t reply[FZN_CONTACT_DEVICES_TAKEN_LEN + 8u];
	size_t len = 0, reply_len = 0;

	if (!ask || !fzn_contact_devices_offer_request(d, request, sizeof(request), &len)
	    || !ask(ctx, request, len, reply, sizeof(reply), &reply_len))
		return -1;
	return fzn_contact_devices_offer_reply(reply, reply_len);
}

size_t fzn_contact_devices_offer_answer(const uint8_t *request, size_t request_len,
                                        int (*take)(void *ctx, const fzn_contact_device_t *d),
                                        void *ctx, uint8_t *reply, size_t reply_cap)
{
	static fzn_contact_device_t d;

	if (!request || !take || !reply || request_len < 2u
	    || request[0] != FZN_CONTACT_DEVICES_VERSION || request[1] != FZN_CONTACT_DEVICES_OFFER
	    || reply_cap < FZN_CONTACT_DEVICES_TAKEN_LEN)
		return 0;
	reply[0] = FZN_CONTACT_DEVICES_VERSION;
	reply[1] = FZN_CONTACT_DEVICES_TAKEN;
	reply[2] = fzn_contact_device_decode(request + 2, request_len - 2u, &d)
	                           == FZN_CONTACT_DEVICE_OK
	                   && take(ctx, &d)
	           ? 1u
	           : 0u;
	return FZN_CONTACT_DEVICES_TAKEN_LEN;
}

/* ---- the query as steps, sec 636 ----------------------------------------- */

static void devices_query(const fzn_contact_devices_querying_t *q, uint8_t *request,
                          size_t *request_len)
{
	request[0] = FZN_CONTACT_DEVICES_VERSION;
	request[1] = FZN_CONTACT_DEVICES_QUERY;
	request[2] = (uint8_t)q->from;
	request[3] = (uint8_t)q->whose;
	*request_len = FZN_CONTACT_DEVICES_QUERY_LEN;
}

int fzn_contact_devices_query_begin(fzn_contact_devices_querying_t *q, int whose,
                                    void (*take)(void *ctx, const fzn_contact_device_t *d),
                                    void *take_ctx, uint8_t *request, size_t cap,
                                    size_t *request_len)
{
	if (!q || !take || !request || cap < FZN_CONTACT_DEVICES_QUERY_LEN || !request_len
	    || (whose != FZN_CONTACT_DEVICES_HOSTS && whose != FZN_CONTACT_DEVICES_KEPT))
		return 0;
	q->whose = whose;
	q->take = take;
	q->take_ctx = take_ctx;
	q->from = 0;
	q->count = 0;
	q->live = 1;
	devices_query(q, request, request_len);
	return 1;
}

int fzn_contact_devices_query_step(fzn_contact_devices_querying_t *q, const uint8_t *reply,
                                   size_t reply_len, uint8_t *request, size_t cap,
                                   size_t *request_len, int *done)
{
	static fzn_contact_device_t d;
	size_t at, k, n, len;

	if (!q || !q->live || !request || cap < FZN_CONTACT_DEVICES_QUERY_LEN || !request_len
	    || !done)
		return 0;
	*done = 1;
	q->live = 0;
	if (!reply || reply_len < FZN_CONTACT_DEVICES_LIST_HEAD_LEN
	    || reply[0] != FZN_CONTACT_DEVICES_VERSION || reply[1] != FZN_CONTACT_DEVICES_LIST
	    || reply[2] != q->from || reply[4] > 1u)
		return 0;
	n = reply[3];
	at = FZN_CONTACT_DEVICES_LIST_HEAD_LEN;
	for (k = 0; k < n; k++) {
		if (reply_len < at + 2u)
			return 0;
		len = fzn_get_be16(reply + at);
		at += 2u;
		if (reply_len < at + len
		    || fzn_contact_device_decode(reply + at, len, &d) != FZN_CONTACT_DEVICE_OK)
			return 0;
		at += len;
		q->take(q->take_ctx, &d);
		q->count++;
	}
	/* EXACTLY ITS ENTRIES, and a page that says more names some. */
	if (at != reply_len || (reply[4] && n == 0u))
		return 0;
	if (!reply[4])
		return 1;
	q->from += n;
	if (q->from > 255u)
		return 1;
	*done = 0;
	q->live = 1;
	devices_query(q, request, request_len);
	return 1;
}

int fzn_contact_devices_query(int whose, fzn_contact_devices_ask_t ask, void *ctx,
                              void (*take)(void *ctx, const fzn_contact_device_t *d),
                              void *take_ctx, size_t *count)
{
	static uint8_t reply[FZN_CONTACT_DEVICES_REPLY_MAX];
	fzn_contact_devices_querying_t q;
	uint8_t request[FZN_CONTACT_DEVICES_QUERY_LEN];
	size_t request_len = 0, reply_len;
	int ok, done = 0, answered;

	if (count)
		*count = 0;
	if (!ask || !count)
		return 0;
	ok = fzn_contact_devices_query_begin(&q, whose, take, take_ctx, request, sizeof(request),
	                                     &request_len);
	while (ok && !done) {
		/* Asked first, apart from the step: see `record/exchange.c`. */
		reply_len = 0;
		answered = ask(ctx, request, request_len, reply, sizeof(reply), &reply_len);
		ok = fzn_contact_devices_query_step(&q, answered ? reply : NULL, reply_len, request,
		                                    sizeof(request), &request_len, &done);
	}
	*count = q.count;
	return ok;
}

size_t fzn_contact_devices_query_answer(const uint8_t *request, size_t request_len,
                                        int (*hosts_at)(void *ctx, size_t i,
                                                        fzn_contact_device_t *out),
                                        int (*kept_at)(void *ctx, size_t i,
                                                       fzn_contact_device_t *out),
                                        void *ctx, uint8_t *reply, size_t reply_cap)
{
	static fzn_contact_device_t d;
	int (*entry_at)(void *, size_t, fzn_contact_device_t *);
	size_t at = FZN_CONTACT_DEVICES_LIST_HEAD_LEN, i, n = 0, len;

	if (!request || !reply || request_len != FZN_CONTACT_DEVICES_QUERY_LEN
	    || request[0] != FZN_CONTACT_DEVICES_VERSION || request[1] != FZN_CONTACT_DEVICES_QUERY)
		return 0;
	entry_at = request[3] == FZN_CONTACT_DEVICES_HOSTS  ? hosts_at
	           : request[3] == FZN_CONTACT_DEVICES_KEPT ? kept_at
	                                                     : NULL;
	if (!entry_at || reply_cap < FZN_CONTACT_DEVICES_LIST_HEAD_LEN)
		return 0;
	if (reply_cap > FZN_CONTACT_DEVICES_REPLY_MAX)
		reply_cap = FZN_CONTACT_DEVICES_REPLY_MAX;
	reply[0] = FZN_CONTACT_DEVICES_VERSION;
	reply[1] = FZN_CONTACT_DEVICES_LIST;
	reply[2] = request[2];
	reply[4] = 0u;
	for (i = request[2]; entry_at(ctx, i, &d); i++) {
		if (n == 255u
		    || fzn_contact_device_encode(&d, reply + at + 2u,
		                                 reply_cap > at + 2u ? reply_cap - at - 2u : 0u, &len)
		               != FZN_CONTACT_DEVICE_OK) {
			/* ONE THAT WILL NOT FIT IS THE NEXT PAGE'S. Every entry fits
			 * an empty page, so one that does not there will never
			 * encode, and the list ends rather than skip it -- a
			 * skipped index would put the asker's `from` out of step. */
			reply[4] = n ? 1u : 0u;
			break;
		}
		fzn_put_be16(reply + at, (uint16_t)len);
		at += 2u + len;
		n++;
	}
	reply[3] = (uint8_t)n;
	return at;
}

/* ---- a contact's revocations, sec 776 ------------------------------------ */

static void revoked_query(const fzn_contact_revoked_querying_t *q, uint8_t *request,
                          size_t *request_len)
{
	request[0] = FZN_CONTACT_DEVICES_VERSION;
	request[1] = FZN_CONTACT_DEVICES_REVOKED;
	fzn_put_be32(request + 2, q->from);
	*request_len = FZN_CONTACT_DEVICES_REVOKED_LEN;
}

int fzn_contact_revoked_query_begin(fzn_contact_revoked_querying_t *q,
                                    void (*take)(void *ctx,
                                                 const uint8_t record[FZN_REVOCATION_LEN]),
                                    void *take_ctx, uint8_t *request, size_t cap,
                                    size_t *request_len)
{
	if (!q || !take || !request || cap < FZN_CONTACT_DEVICES_REVOKED_LEN || !request_len)
		return 0;
	q->take = take;
	q->take_ctx = take_ctx;
	q->from = 0;
	q->count = 0;
	q->live = 1;
	revoked_query(q, request, request_len);
	return 1;
}

int fzn_contact_revoked_query_step(fzn_contact_revoked_querying_t *q, const uint8_t *reply,
                                   size_t reply_len, uint8_t *request, size_t cap,
                                   size_t *request_len, int *done)
{
	size_t k, n;

	if (!q || !q->live || !request || cap < FZN_CONTACT_DEVICES_REVOKED_LEN || !request_len
	    || !done)
		return 0;
	*done = 1;
	q->live = 0;
	if (!reply || reply_len < FZN_CONTACT_DEVICES_RECORDS_HEAD_LEN
	    || reply[0] != FZN_CONTACT_DEVICES_VERSION || reply[1] != FZN_CONTACT_DEVICES_RECORDS
	    || fzn_get_be32(reply + 2) != q->from || reply[7] > 1u)
		return 0;
	n = reply[6];
	/* EXACTLY ITS RECORDS, and a page that says more names some. */
	if (reply_len != FZN_CONTACT_DEVICES_RECORDS_HEAD_LEN + n * FZN_REVOCATION_LEN
	    || (reply[7] && n == 0u))
		return 0;
	for (k = 0; k < n; k++) {
		q->take(q->take_ctx,
		        reply + FZN_CONTACT_DEVICES_RECORDS_HEAD_LEN + k * FZN_REVOCATION_LEN);
		q->count++;
	}
	if (!reply[7])
		return 1;
	if (q->from > UINT32_MAX - n)
		return 1;
	q->from += (uint32_t)n;
	*done = 0;
	q->live = 1;
	revoked_query(q, request, request_len);
	return 1;
}

size_t fzn_contact_revoked_answer(const uint8_t *request, size_t request_len,
                                  int (*record_at)(void *ctx, size_t i,
                                                   uint8_t out[FZN_REVOCATION_LEN]),
                                  void *ctx, uint8_t *reply, size_t reply_cap)
{
	uint8_t record[FZN_REVOCATION_LEN];
	size_t at = FZN_CONTACT_DEVICES_RECORDS_HEAD_LEN, i, n = 0;
	uint32_t from;

	if (!request || !record_at || !reply || request_len != FZN_CONTACT_DEVICES_REVOKED_LEN
	    || request[0] != FZN_CONTACT_DEVICES_VERSION
	    || request[1] != FZN_CONTACT_DEVICES_REVOKED
	    || reply_cap < FZN_CONTACT_DEVICES_RECORDS_HEAD_LEN)
		return 0;
	if (reply_cap > FZN_CONTACT_DEVICES_REPLY_MAX)
		reply_cap = FZN_CONTACT_DEVICES_REPLY_MAX;
	from = fzn_get_be32(request + 2);
	reply[0] = FZN_CONTACT_DEVICES_VERSION;
	reply[1] = FZN_CONTACT_DEVICES_RECORDS;
	fzn_put_be32(reply + 2, from);
	reply[7] = 0u;
	for (i = from; record_at(ctx, i, record); i++) {
		/* ONE PAST THE ROOM IS THE NEXT PAGE'S. */
		if (n == 255u || at + FZN_REVOCATION_LEN > reply_cap) {
			reply[7] = 1u;
			break;
		}
		memcpy(reply + at, record, FZN_REVOCATION_LEN);
		at += FZN_REVOCATION_LEN;
		n++;
	}
	reply[6] = (uint8_t)n;
	return at;
}

#define REVOCATION_ROW_LEN ((size_t)FZN_PERSIST_HEAD_LEN + FZN_REVOCATION_LEN)

/* A ROW'S KEY: its triple, hashed, so one triple has one row. */
static int revocation_key(const fzn_hash_ops_t *hash, fzn_revocation_record_t rec,
                          uint8_t key[FZN_PUBKEY_LEN])
{
	uint8_t triple[FZN_PUBKEY_LEN * 2u + sizeof(fzn_cap_id_t)];

	memcpy(triple, fzn_revocation_issuer(rec), FZN_PUBKEY_LEN);
	memcpy(triple + FZN_PUBKEY_LEN, fzn_revocation_capability(rec), sizeof(fzn_cap_id_t));
	memcpy(triple + FZN_PUBKEY_LEN + sizeof(fzn_cap_id_t), fzn_revocation_grantee(rec),
	       FZN_PUBKEY_LEN);
	return hash->hash(hash->ctx, key, FZN_PUBKEY_LEN, triple, sizeof(triple));
}

/* IS WHAT `revocations` HOLDS FOR `rec`'s TRIPLE EXACTLY `rec`? A revocation
 * holds its own hash, live; a withdrawal the hash it names, withdrawn. As
 * `node/revoke.c` asks before saving a vote, so a stale copy admission took
 * without storing is not saved over the newer record. */
static int holds_exactly(const fzn_revocation_store_t *revocations, const fzn_hash_ops_t *hash,
                         const uint8_t record[FZN_REVOCATION_LEN], fzn_revocation_record_t rec)
{
	uint8_t id[FZN_REVOCATION_ID_LEN], mine[FZN_REVOCATION_ID_LEN];
	int withdrawn = 0;

	if (!fzn_revocation_lookup(revocations, fzn_revocation_issuer(rec),
	                           fzn_revocation_capability(rec), fzn_revocation_grantee(rec), id,
	                           &withdrawn))
		return 0;
	if (fzn_revocation_is_withdrawal(rec))
		return withdrawn && memcmp(id, fzn_revocation_supersedes(rec), sizeof(id)) == 0;
	if (!hash->hash(hash->ctx, mine, sizeof(mine), record, FZN_REVOCATION_LEN))
		return 0;
	return !withdrawn && memcmp(id, mine, sizeof(id)) == 0;
}

fzn_contact_device_err_t fzn_contact_revocation_take(fzn_revocation_store_t *revocations,
                                                     const fzn_persist_ops_t *store,
                                                     const uint8_t owner[FZN_PUBKEY_LEN],
                                                     const fzn_cap_id_t *member,
                                                     const uint8_t record[FZN_REVOCATION_LEN],
                                                     const fzn_sign_ops_t *sign,
                                                     const fzn_hash_ops_t *hash)
{
	uint8_t row[REVOCATION_ROW_LEN], key[FZN_PUBKEY_LEN];
	fzn_revocation_record_t rec;
	fzn_chain_err_t cerr;

	if (!revocations || !store || !store->save || !owner || !member || !record || !sign
	    || !hash || !hash->hash)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	/* FOR THE MEMBER CAPABILITY, or nothing of this. */
	if (fzn_revocation_open(record, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK
	    || memcmp(fzn_revocation_capability(rec), member, sizeof(*member)) != 0)
		return FZN_CONTACT_DEVICE_ERR_REFUSED;
	/* AND THE OWNER'S: a root's offer is refused unless its issuer is the
	 * root named, and this store names no root set to widen that. */
	cerr = fzn_revocation_admit(revocations, fzn_revocation_offer_root(rec), owner, sign, hash,
	                            NULL);
	if (cerr == FZN_CHAIN_ERR_STORE_FULL)
		return FZN_CONTACT_DEVICE_ERR_ROOM;
	if (cerr != FZN_CHAIN_OK)
		return FZN_CONTACT_DEVICE_ERR_REFUSED;
	if (!holds_exactly(revocations, hash, record, rec))
		return FZN_CONTACT_DEVICE_OK;
	if (!revocation_key(hash, rec, key)
	    || fzn_persist_head_write(row, sizeof(row), FZN_REVOCATION_LEN,
	                              FZN_PERSIST_BLOB_REVOCATION)
	               != FZN_PERSIST_OK)
		return FZN_CONTACT_DEVICE_ERR_BACKEND;
	memcpy(row + FZN_PERSIST_HEAD_LEN, record, FZN_REVOCATION_LEN);
	return store->save(store->ctx, FZN_PERSIST_CONTACT_REVOCATION, key, row, sizeof(row))
	               ? FZN_CONTACT_DEVICE_OK
	               : FZN_CONTACT_DEVICE_ERR_BACKEND;
}

struct revocations_walk {
	fzn_revocation_store_t *revocations;
	const fzn_persist_ops_t *store;
	const fzn_sign_ops_t *sign;
	const fzn_hash_ops_t *hash;
	size_t count, skipped;
	int full;
};

static int revocation_walked(void *arg, const uint8_t key[FZN_PUBKEY_LEN])
{
	struct revocations_walk *w = arg;
	uint8_t row[REVOCATION_ROW_LEN], filed[FZN_PUBKEY_LEN];
	fzn_revocation_record_t rec;
	fzn_chain_err_t cerr;
	size_t len = 0;

	/* FILED UNDER ITS OWN TRIPLE, or a row nobody here wrote. */
	if (!w->store->load(w->store->ctx, FZN_PERSIST_CONTACT_REVOCATION, key, row, sizeof(row),
	                    &len)
	    || fzn_persist_head_check(row, len, FZN_REVOCATION_LEN, FZN_PERSIST_BLOB_REVOCATION)
	               != FZN_PERSIST_OK
	    || fzn_revocation_open(row + FZN_PERSIST_HEAD_LEN, FZN_REVOCATION_LEN, &rec)
	               != FZN_CHAIN_OK
	    || !revocation_key(w->hash, rec, filed) || memcmp(filed, key, FZN_PUBKEY_LEN) != 0) {
		w->skipped++;
		return 1;
	}
	cerr = fzn_revocation_admit(w->revocations, fzn_revocation_offer_root(rec),
	                            fzn_revocation_issuer(rec), w->sign, w->hash, NULL);
	if (cerr == FZN_CHAIN_ERR_STORE_FULL) {
		w->full = 1;
		return 0;
	}
	if (cerr != FZN_CHAIN_OK)
		w->skipped++;
	else
		w->count++;
	return 1;
}

fzn_contact_device_err_t fzn_contact_revocations_load(fzn_revocation_store_t *revocations,
                                                      const fzn_persist_ops_t *store,
                                                      const fzn_sign_ops_t *sign,
                                                      const fzn_hash_ops_t *hash, size_t *count,
                                                      size_t *skipped)
{
	struct revocations_walk w;

	if (count)
		*count = 0;
	if (skipped)
		*skipped = 0;
	if (!revocations || !store || !store->load || !sign || !hash || !hash->hash || !count
	    || !skipped)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	memset(&w, 0, sizeof(w));
	w.revocations = revocations;
	w.store = store;
	w.sign = sign;
	w.hash = hash;
	if (!fzn_persist_each(store, FZN_PERSIST_CONTACT_REVOCATION, revocation_walked, &w)
	    && !w.full)
		return FZN_CONTACT_DEVICE_ERR_BACKEND;
	*count = w.count;
	*skipped = w.skipped;
	return w.full ? FZN_CONTACT_DEVICE_ERR_ROOM : FZN_CONTACT_DEVICE_OK;
}

/* ONE ROW, walked into the caller's room while there is any. */
struct revocations_listing {
	const fzn_persist_ops_t *store;
	const fzn_hash_ops_t *hash;
	uint8_t (*out)[FZN_REVOCATION_LEN];
	size_t cap, n;
};

static int revocation_listed(void *arg, const uint8_t key[FZN_PUBKEY_LEN])
{
	struct revocations_listing *l = arg;
	uint8_t row[REVOCATION_ROW_LEN], filed[FZN_PUBKEY_LEN];
	fzn_revocation_record_t rec;
	size_t len = 0;

	if (!l->store->load(l->store->ctx, FZN_PERSIST_CONTACT_REVOCATION, key, row, sizeof(row),
	                    &len)
	    || fzn_persist_head_check(row, len, FZN_REVOCATION_LEN, FZN_PERSIST_BLOB_REVOCATION)
	               != FZN_PERSIST_OK
	    || fzn_revocation_open(row + FZN_PERSIST_HEAD_LEN, FZN_REVOCATION_LEN, &rec)
	               != FZN_CHAIN_OK
	    || !revocation_key(l->hash, rec, filed) || memcmp(filed, key, FZN_PUBKEY_LEN) != 0)
		return 1;
	if (l->n < l->cap)
		memcpy(l->out[l->n], row + FZN_PERSIST_HEAD_LEN, FZN_REVOCATION_LEN);
	l->n++;
	return 1;
}

fzn_contact_device_err_t fzn_contact_revocations_list(const fzn_persist_ops_t *store,
                                                      const fzn_hash_ops_t *hash,
                                                      uint8_t (*out)[FZN_REVOCATION_LEN],
                                                      size_t cap, size_t *count)
{
	struct revocations_listing l;

	if (!count)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	*count = 0;
	if (!store || !store->load || !hash || !hash->hash || (!out && cap))
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	memset(&l, 0, sizeof(l));
	l.store = store;
	l.hash = hash;
	l.out = out;
	l.cap = cap;
	if (!fzn_persist_each(store, FZN_PERSIST_CONTACT_REVOCATION, revocation_listed, &l))
		return FZN_CONTACT_DEVICE_ERR_BACKEND;
	*count = l.n;
	return l.n > cap ? FZN_CONTACT_DEVICE_ERR_ROOM : FZN_CONTACT_DEVICE_OK;
}

/* THE OWNER'S LIVE REVOCATION OF `key`, if the store holds one: 1, with
 * whether it draws a line. */
static int owner_revoked(const fzn_revocation_store_t *revocations,
                         const uint8_t owner[FZN_PUBKEY_LEN], const fzn_cap_id_t *member,
                         const uint8_t key[FZN_PUBKEY_LEN], int *lined)
{
	static const uint8_t NOTHING[FZN_REVOCATION_ID_LEN] = { 0 };
	size_t i;

	for (i = 0; i < revocations->used; i++) {
		const fzn_revocation_t *e = &revocations->entries[i];

		if (!e->withdrawn && memcmp(e->issuer, owner, FZN_PUBKEY_LEN) == 0
		    && memcmp(e->grantee, key, FZN_PUBKEY_LEN) == 0
		    && memcmp(&e->capability, member, sizeof(*member)) == 0) {
			*lined = memcmp(e->cut, NOTHING, sizeof(NOTHING)) != 0;
			return 1;
		}
	}
	return 0;
}

int fzn_contact_device_revoked(const fzn_contact_device_t *d,
                               const fzn_revocation_store_t *revocations,
                               const fzn_cap_id_t *member)
{
	fzn_chain_hop_t hop;
	size_t i;
	int lined = 0;

	if (!d || !revocations || !member || !fzn_revocation_store_sound(revocations)
	    || d->hop_count > FZN_CHAIN_MAX_HOPS)
		return 0;
	/* EACH KEY THE CHAIN GRANTS, the device last: the device's own
	 * revocation drops it whatever its line; a key above it only when that
	 * vote trusts none of its acts, its grant of the device among them. */
	for (i = 0; i < d->hop_count; i++) {
		if (fzn_hop_open(d->hops[i], FZN_HOP_LEN, &hop) != FZN_CHAIN_OK)
			return 0;
		if (owner_revoked(revocations, d->owner, member, fzn_hop_grantee(hop), &lined)
		    && (i + 1u == d->hop_count || !lined))
			return 1;
	}
	return 0;
}

/* ---- a contact's estate, sec 781 ----------------------------------------- */

fzn_contact_device_err_t fzn_contact_estate_item_encode(const fzn_contact_estate_item_t *item,
                                                        uint8_t *out, size_t cap, size_t *len)
{
	size_t n;

	if (!item || !out || !len || item->record_len == 0u
	    || item->record_len > FZN_CONTACT_ESTATE_RECORD_MAX
	    || item->hop_count > FZN_CHAIN_MAX_HOPS)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	n = 1u + 2u + item->record_len + 1u + item->hop_count * FZN_HOP_LEN;
	if (n > cap)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	out[0] = item->kind;
	fzn_put_be16(out + 1, (uint16_t)item->record_len);
	memcpy(out + 3, item->record, item->record_len);
	out[3 + item->record_len] = (uint8_t)item->hop_count;
	memcpy(out + 4 + item->record_len, item->hops, item->hop_count * FZN_HOP_LEN);
	*len = n;
	return FZN_CONTACT_DEVICE_OK;
}

fzn_contact_device_err_t fzn_contact_estate_item_decode(const uint8_t *bytes, size_t len,
                                                        fzn_contact_estate_item_t *out)
{
	size_t record_len, hop_count;

	if (!bytes || !out)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	if (len < 4u)
		return FZN_CONTACT_DEVICE_ERR_SHAPE;
	record_len = fzn_get_be16(bytes + 1);
	if (record_len == 0u || record_len > FZN_CONTACT_ESTATE_RECORD_MAX || len < 4u + record_len)
		return FZN_CONTACT_DEVICE_ERR_SHAPE;
	hop_count = bytes[3 + record_len];
	/* EXACTLY ITS LENGTH, and a kind this reads. */
	if (hop_count > FZN_CHAIN_MAX_HOPS || len != 4u + record_len + hop_count * FZN_HOP_LEN
	    || bytes[0] < FZN_CONTACT_ESTATE_CHANGE || bytes[0] > FZN_CONTACT_ESTATE_CONFIRM)
		return FZN_CONTACT_DEVICE_ERR_SHAPE;
	out->kind = bytes[0];
	out->record_len = record_len;
	memcpy(out->record, bytes + 3, record_len);
	out->hop_count = hop_count;
	memcpy(out->hops, bytes + 4 + record_len, hop_count * FZN_HOP_LEN);
	return FZN_CONTACT_DEVICE_OK;
}

static void estate_query(const fzn_contact_estate_querying_t *q, uint8_t *request,
                         size_t *request_len)
{
	request[0] = FZN_CONTACT_DEVICES_VERSION;
	request[1] = FZN_CONTACT_DEVICES_ESTATE;
	fzn_put_be32(request + 2, q->from);
	*request_len = FZN_CONTACT_DEVICES_ESTATE_LEN;
}

int fzn_contact_estate_query_begin(fzn_contact_estate_querying_t *q,
                                   void (*take)(void *ctx, const fzn_contact_estate_item_t *item),
                                   void *take_ctx, uint8_t *request, size_t cap,
                                   size_t *request_len)
{
	if (!q || !take || !request || cap < FZN_CONTACT_DEVICES_ESTATE_LEN || !request_len)
		return 0;
	q->take = take;
	q->take_ctx = take_ctx;
	q->from = 0;
	q->count = 0;
	q->k = 0;
	q->live = 1;
	estate_query(q, request, request_len);
	return 1;
}

int fzn_contact_estate_query_step(fzn_contact_estate_querying_t *q, const uint8_t *reply,
                                  size_t reply_len, uint8_t *request, size_t cap,
                                  size_t *request_len, int *done)
{
	static fzn_contact_estate_item_t item;
	size_t at, k, n, len;

	if (!q || !q->live || !request || cap < FZN_CONTACT_DEVICES_ESTATE_LEN || !request_len
	    || !done)
		return 0;
	*done = 1;
	q->live = 0;
	if (!reply || reply_len < FZN_CONTACT_DEVICES_ITEMS_HEAD_LEN
	    || reply[0] != FZN_CONTACT_DEVICES_VERSION || reply[1] != FZN_CONTACT_DEVICES_ITEMS
	    || fzn_get_be32(reply + 2) != q->from || reply[7] > 1u || reply[8] == 0u)
		return 0;
	n = reply[6];
	at = FZN_CONTACT_DEVICES_ITEMS_HEAD_LEN;
	/* EVERY ITEM READ BEFORE ANY IS TAKEN: a page that will not read gives
	 * nothing, rather than its first half. */
	for (k = 0; k < n; k++) {
		if (reply_len < at + 2u)
			return 0;
		len = fzn_get_be16(reply + at);
		if (reply_len < at + 2u + len
		    || fzn_contact_estate_item_decode(reply + at + 2u, len, &item)
		               != FZN_CONTACT_DEVICE_OK)
			return 0;
		at += 2u + len;
	}
	if (at != reply_len || (reply[7] && n == 0u))
		return 0;
	if (reply[8] > q->k)
		q->k = reply[8];
	for (at = FZN_CONTACT_DEVICES_ITEMS_HEAD_LEN, k = 0; k < n; k++) {
		len = fzn_get_be16(reply + at);
		(void)fzn_contact_estate_item_decode(reply + at + 2u, len, &item);
		at += 2u + len;
		q->take(q->take_ctx, &item);
		q->count++;
	}
	if (!reply[7] || q->from > UINT32_MAX - n)
		return 1;
	q->from += (uint32_t)n;
	*done = 0;
	q->live = 1;
	estate_query(q, request, request_len);
	return 1;
}

size_t fzn_contact_estate_answer(const uint8_t *request, size_t request_len,
                                 int (*item_at)(void *ctx, size_t i,
                                                fzn_contact_estate_item_t *out),
                                 uint8_t k, void *ctx, uint8_t *reply, size_t reply_cap)
{
	static fzn_contact_estate_item_t item;
	static uint8_t bytes[FZN_CONTACT_ESTATE_ITEM_MAX];
	size_t at = FZN_CONTACT_DEVICES_ITEMS_HEAD_LEN, i, n = 0, len = 0;
	uint32_t from;

	if (!request || !item_at || !reply || request_len != FZN_CONTACT_DEVICES_ESTATE_LEN
	    || request[0] != FZN_CONTACT_DEVICES_VERSION || request[1] != FZN_CONTACT_DEVICES_ESTATE
	    || reply_cap < FZN_CONTACT_DEVICES_ITEMS_HEAD_LEN)
		return 0;
	if (reply_cap > FZN_CONTACT_DEVICES_REPLY_MAX)
		reply_cap = FZN_CONTACT_DEVICES_REPLY_MAX;
	from = fzn_get_be32(request + 2);
	reply[0] = FZN_CONTACT_DEVICES_VERSION;
	reply[1] = FZN_CONTACT_DEVICES_ITEMS;
	fzn_put_be32(reply + 2, from);
	reply[7] = 0u;
	reply[8] = k ? k : 1u;
	for (i = from; item_at(ctx, i, &item); i++) {
		/* ONE THAT WILL NOT ENCODE IS PASSED OVER as nothing; one past the
		 * room is the next page's. */
		if (fzn_contact_estate_item_encode(&item, bytes, sizeof(bytes), &len)
		    != FZN_CONTACT_DEVICE_OK)
			len = 0;
		if (n == 255u || at + 2u + len > reply_cap) {
			reply[7] = 1u;
			break;
		}
		if (!len)
			break;
		fzn_put_be16(reply + at, (uint16_t)len);
		memcpy(reply + at + 2u, bytes, len);
		at += 2u + len;
		n++;
	}
	reply[6] = (uint8_t)n;
	return at;
}

/* ITS RECORD IS THE SHAPE ITS KIND SAYS, SIGNED BY ITS SIGNER. */
static int item_signed(const fzn_contact_estate_item_t *item, const fzn_sign_ops_t *sign,
                       const fzn_hash_ops_t *hash)
{
	fzn_revocation_record_t rec;
	fzn_root_change_t one[1];
	fzn_root_set_t scratch;
	static const uint8_t NOBODY[FZN_PUBKEY_LEN] = { 0 };

	switch (item->kind) {
	case FZN_CONTACT_ESTATE_CHANGE:
		if (item->hop_count)
			return 0;
		if (item->record_len == FZN_QUORUM_SET_LEN)
			return fzn_quorum_set_check(item->record, item->record_len, sign)
			       == FZN_ROOT_LOG_OK;
		return fzn_root_set_init(&scratch, NOBODY, one, 1u) == FZN_ROOT_LOG_OK
		       && fzn_root_set_admit(&scratch, item->record, item->record_len, sign, hash)
		                  == FZN_ROOT_LOG_OK;
	case FZN_CONTACT_ESTATE_VOTE:
		return item->record_len == FZN_REVOCATION_LEN
		       && fzn_revocation_open(item->record, item->record_len, &rec) == FZN_CHAIN_OK
		       && sign->verify(sign->ctx, fzn_revocation_issuer(rec), item->record,
		                       FZN_REVOCATION_BODY_LEN, fzn_revocation_signature(rec));
	case FZN_CONTACT_ESTATE_CONFIRM:
		return item->record_len == FZN_ADMIN_CONFIRM_LEN
		       && item->record[0] == FZN_SIGNED_VERSION
		       && item->record[1] == (uint8_t)FZN_OBJECT_ADMIN_CONFIRM
		       && sign->verify(sign->ctx, item->record + FZN_ADMIN_CONFIRM_OFF_CONFIRMER,
		                       item->record, FZN_ADMIN_CONFIRM_BODY_LEN,
		                       item->record + FZN_ADMIN_CONFIRM_BODY_LEN);
	}
	return 0;
}

#define ESTATE_ROW_MAX (FZN_PUBKEY_LEN + FZN_CONTACT_ESTATE_ITEM_MAX)
/* THE k ROW'S KIND: no item's, so it never reads as one. */
#define ESTATE_K_KIND 0xffu
/* THE k ROW: owner, kind, k, and when this node or the member it came
 * through heard it from the contact's host, ms (sec 782). */
#define ESTATE_K_ROW_LEN (FZN_PUBKEY_LEN + 2u + 8u)

static int estate_key(const fzn_hash_ops_t *hash, const uint8_t *row, size_t len,
                      uint8_t key[FZN_PUBKEY_LEN])
{
	/* THE k ROW IS ONE PER OWNER, keyed by the owner and its kind alone. */
	if (len == ESTATE_K_ROW_LEN && row[FZN_PUBKEY_LEN] == ESTATE_K_KIND)
		len = FZN_PUBKEY_LEN + 1u;
	return hash->hash(hash->ctx, key, FZN_PUBKEY_LEN, row, len);
}

fzn_contact_device_err_t fzn_contact_estate_keep(const fzn_persist_ops_t *store,
                                                 const fzn_hash_ops_t *hash,
                                                 const fzn_sign_ops_t *sign,
                                                 const uint8_t owner[FZN_PUBKEY_LEN],
                                                 const fzn_contact_estate_item_t *item)
{
	static uint8_t row[ESTATE_ROW_MAX];
	uint8_t key[FZN_PUBKEY_LEN];
	size_t len = 0;

	if (!store || !store->save || !hash || !hash->hash || !sign || !sign->verify || !owner
	    || !item)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	if (!item_signed(item, sign, hash))
		return FZN_CONTACT_DEVICE_ERR_REFUSED;
	memcpy(row, owner, FZN_PUBKEY_LEN);
	if (fzn_contact_estate_item_encode(item, row + FZN_PUBKEY_LEN, sizeof(row) - FZN_PUBKEY_LEN,
	                                   &len)
	            != FZN_CONTACT_DEVICE_OK
	    || !estate_key(hash, row, FZN_PUBKEY_LEN + len, key))
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	return store->save(store->ctx, FZN_PERSIST_CONTACT_ESTATE, key, row, FZN_PUBKEY_LEN + len)
	               ? FZN_CONTACT_DEVICE_OK
	               : FZN_CONTACT_DEVICE_ERR_BACKEND;
}

fzn_contact_device_err_t fzn_contact_estate_keep_k(const fzn_persist_ops_t *store,
                                                   const fzn_hash_ops_t *hash,
                                                   const uint8_t owner[FZN_PUBKEY_LEN],
                                                   uint8_t k, uint64_t heard_ms)
{
	uint8_t row[ESTATE_K_ROW_LEN], key[FZN_PUBKEY_LEN];

	if (!store || !store->save || !hash || !hash->hash || !owner || k == 0u)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	memcpy(row, owner, FZN_PUBKEY_LEN);
	row[FZN_PUBKEY_LEN] = ESTATE_K_KIND;
	row[FZN_PUBKEY_LEN + 1u] = k;
	fzn_put_be64(row + FZN_PUBKEY_LEN + 2u, heard_ms);
	if (!estate_key(hash, row, sizeof(row), key))
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	return store->save(store->ctx, FZN_PERSIST_CONTACT_ESTATE, key, row, sizeof(row))
	               ? FZN_CONTACT_DEVICE_OK
	               : FZN_CONTACT_DEVICE_ERR_BACKEND;
}

/* ---- passed on between members, sec 782 ---------------------------------- */

struct estate_each_walk {
	const fzn_persist_ops_t *store;
	const fzn_hash_ops_t *hash;
	int (*fn)(void *ctx, const uint8_t *row, size_t len);
	void *ctx;
	int stopped;
};

static int estate_each_walked(void *arg, const uint8_t key[FZN_PUBKEY_LEN])
{
	static uint8_t row[ESTATE_ROW_MAX];
	struct estate_each_walk *w = arg;
	uint8_t filed[FZN_PUBKEY_LEN];
	size_t len = 0;

	if (!w->store->load(w->store->ctx, FZN_PERSIST_CONTACT_ESTATE, key, row, sizeof(row), &len)
	    || len < FZN_PUBKEY_LEN + 2u || !estate_key(w->hash, row, len, filed)
	    || memcmp(filed, key, FZN_PUBKEY_LEN) != 0)
		return 1;
	if (!w->fn(w->ctx, row, len)) {
		w->stopped = 1;
		return 0;
	}
	return 1;
}

fzn_contact_device_err_t fzn_contact_estate_each(const fzn_persist_ops_t *store,
                                                 const fzn_hash_ops_t *hash,
                                                 int (*fn)(void *ctx, const uint8_t *row,
                                                           size_t len),
                                                 void *ctx)
{
	struct estate_each_walk w;

	if (!store || !store->load || !hash || !hash->hash || !fn)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	memset(&w, 0, sizeof(w));
	w.store = store;
	w.hash = hash;
	w.fn = fn;
	w.ctx = ctx;
	if (!fzn_persist_each(store, FZN_PERSIST_CONTACT_ESTATE, estate_each_walked, &w)
	    && !w.stopped)
		return FZN_CONTACT_DEVICE_ERR_BACKEND;
	return FZN_CONTACT_DEVICE_OK;
}

const uint8_t *fzn_contact_estate_row_owner(const uint8_t *row, size_t len)
{
	return row && len >= FZN_PUBKEY_LEN + 2u ? row : NULL;
}

/* WHEN THE k KEPT FOR `owner` WAS HEARD from its host: 1 with it in
 * `*heard_ms`, 0 for none kept. */
static int kept_k_heard(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                        const uint8_t owner[FZN_PUBKEY_LEN], uint64_t *heard_ms)
{
	uint8_t row[ESTATE_K_ROW_LEN], key[FZN_PUBKEY_LEN], got[ESTATE_K_ROW_LEN];
	size_t len = 0;

	memset(row, 0, sizeof(row));
	memcpy(row, owner, FZN_PUBKEY_LEN);
	row[FZN_PUBKEY_LEN] = ESTATE_K_KIND;
	if (!estate_key(hash, row, sizeof(row), key)
	    || !store->load(store->ctx, FZN_PERSIST_CONTACT_ESTATE, key, got, sizeof(got), &len)
	    || len != sizeof(got) || memcmp(got, owner, FZN_PUBKEY_LEN) != 0
	    || got[FZN_PUBKEY_LEN] != ESTATE_K_KIND)
		return 0;
	*heard_ms = fzn_get_be64(got + FZN_PUBKEY_LEN + 2u);
	return 1;
}

fzn_contact_device_err_t fzn_contact_estate_take_row(const fzn_persist_ops_t *store,
                                                     const fzn_hash_ops_t *hash,
                                                     const fzn_sign_ops_t *sign,
                                                     const uint8_t *row, size_t len)
{
	static fzn_contact_estate_item_t item;

	if (!store || !store->load || !hash || !hash->hash || !sign || !row)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	if (len < FZN_PUBKEY_LEN + 2u)
		return FZN_CONTACT_DEVICE_ERR_REFUSED;
	/* A k ONLY WHEN HEARD LATER than the one kept: a member's copy may be
	 * older than the host's word, and the host's lowering of k must still
	 * reach every member. */
	if (len == ESTATE_K_ROW_LEN && row[FZN_PUBKEY_LEN] == ESTATE_K_KIND) {
		uint64_t heard = fzn_get_be64(row + FZN_PUBKEY_LEN + 2u), kept = 0;

		if (row[FZN_PUBKEY_LEN + 1u] == 0u)
			return FZN_CONTACT_DEVICE_ERR_REFUSED;
		if (kept_k_heard(store, hash, row, &kept) && heard <= kept)
			return FZN_CONTACT_DEVICE_OK;
		return fzn_contact_estate_keep_k(store, hash, row, row[FZN_PUBKEY_LEN + 1u], heard);
	}
	if (fzn_contact_estate_item_decode(row + FZN_PUBKEY_LEN, len - FZN_PUBKEY_LEN, &item)
	    != FZN_CONTACT_DEVICE_OK)
		return FZN_CONTACT_DEVICE_ERR_REFUSED;
	return fzn_contact_estate_keep(store, hash, sign, row, &item);
}

static void rows_query(const fzn_contact_rows_querying_t *q, uint8_t *request,
                       size_t *request_len)
{
	request[0] = FZN_CONTACT_DEVICES_VERSION;
	request[1] = FZN_CONTACT_DEVICES_KEPT_ESTATE;
	fzn_put_be32(request + 2, q->from);
	*request_len = FZN_CONTACT_DEVICES_KEPT_ESTATE_LEN;
}

int fzn_contact_rows_query_begin(fzn_contact_rows_querying_t *q,
                                 void (*take)(void *ctx, const uint8_t *row, size_t len),
                                 void *take_ctx, uint8_t *request, size_t cap,
                                 size_t *request_len)
{
	if (!q || !take || !request || cap < FZN_CONTACT_DEVICES_KEPT_ESTATE_LEN || !request_len)
		return 0;
	q->take = take;
	q->take_ctx = take_ctx;
	q->from = 0;
	q->count = 0;
	q->live = 1;
	rows_query(q, request, request_len);
	return 1;
}

int fzn_contact_rows_query_step(fzn_contact_rows_querying_t *q, const uint8_t *reply,
                                size_t reply_len, uint8_t *request, size_t cap,
                                size_t *request_len, int *done)
{
	size_t at, k, n, len;

	if (!q || !q->live || !request || cap < FZN_CONTACT_DEVICES_KEPT_ESTATE_LEN || !request_len
	    || !done)
		return 0;
	*done = 1;
	q->live = 0;
	if (!reply || reply_len < FZN_CONTACT_DEVICES_KEPT_ROWS_HEAD_LEN
	    || reply[0] != FZN_CONTACT_DEVICES_VERSION || reply[1] != FZN_CONTACT_DEVICES_KEPT_ROWS
	    || fzn_get_be32(reply + 2) != q->from || reply[7] > 1u)
		return 0;
	n = reply[6];
	/* EVERY ROW'S LENGTH READ BEFORE ANY IS TAKEN. */
	for (at = FZN_CONTACT_DEVICES_KEPT_ROWS_HEAD_LEN, k = 0; k < n; k++) {
		if (reply_len < at + 2u)
			return 0;
		len = fzn_get_be16(reply + at);
		if (len < FZN_PUBKEY_LEN + 2u || len > FZN_CONTACT_ESTATE_ROW_MAX
		    || reply_len < at + 2u + len)
			return 0;
		at += 2u + len;
	}
	if (at != reply_len || (reply[7] && n == 0u))
		return 0;
	for (at = FZN_CONTACT_DEVICES_KEPT_ROWS_HEAD_LEN, k = 0; k < n; k++) {
		len = fzn_get_be16(reply + at);
		q->take(q->take_ctx, reply + at + 2u, len);
		q->count++;
		at += 2u + len;
	}
	if (!reply[7] || q->from > UINT32_MAX - n)
		return 1;
	q->from += (uint32_t)n;
	*done = 0;
	q->live = 1;
	rows_query(q, request, request_len);
	return 1;
}

size_t fzn_contact_rows_answer(const uint8_t *request, size_t request_len,
                               int (*row_at)(void *ctx, size_t i, uint8_t *out, size_t *len),
                               void *ctx, uint8_t *reply, size_t reply_cap)
{
	static uint8_t row[FZN_CONTACT_ESTATE_ROW_MAX];
	size_t at = FZN_CONTACT_DEVICES_KEPT_ROWS_HEAD_LEN, i, n = 0, len = 0;
	uint32_t from;

	if (!request || !row_at || !reply || request_len != FZN_CONTACT_DEVICES_KEPT_ESTATE_LEN
	    || request[0] != FZN_CONTACT_DEVICES_VERSION
	    || request[1] != FZN_CONTACT_DEVICES_KEPT_ESTATE
	    || reply_cap < FZN_CONTACT_DEVICES_KEPT_ROWS_HEAD_LEN)
		return 0;
	if (reply_cap > FZN_CONTACT_DEVICES_REPLY_MAX)
		reply_cap = FZN_CONTACT_DEVICES_REPLY_MAX;
	from = fzn_get_be32(request + 2);
	reply[0] = FZN_CONTACT_DEVICES_VERSION;
	reply[1] = FZN_CONTACT_DEVICES_KEPT_ROWS;
	fzn_put_be32(reply + 2, from);
	reply[7] = 0u;
	for (i = from; row_at(ctx, i, row, &len); i++) {
		if (len < FZN_PUBKEY_LEN + 2u || len > sizeof(row))
			break;
		/* ONE PAST THE ROOM IS THE NEXT PAGE'S. */
		if (n == 255u || at + 2u + len > reply_cap) {
			reply[7] = 1u;
			break;
		}
		fzn_put_be16(reply + at, (uint16_t)len);
		memcpy(reply + at + 2u, row, len);
		at += 2u + len;
		n++;
	}
	reply[6] = (uint8_t)n;
	return at;
}

/* ---- the estate built ---------------------------------------------------- */

struct fzn_contact_estate {
	uint8_t owner[FZN_PUBKEY_LEN];
	fzn_cap_id_t member;
	uint8_t k;
	fzn_root_set_t set;
	fzn_root_change_t *changes;
	uint8_t *flags;
	fzn_root_view_t view;
	fzn_root_ops_t ops;
	fzn_revocation_store_t store;
	fzn_revocation_t *entries;
	fzn_revocation_admin_t *admins;
	fzn_revocation_confirm_t *confirms;
	/* What the walk gathered for the owner, admitted once the tables are
	 * sized. */
	fzn_contact_estate_item_t *items;
	size_t n_items, cap_items;
};

struct estate_walk {
	const fzn_persist_ops_t *store;
	const fzn_hash_ops_t *hash;
	fzn_contact_estate_t *e;
	int failed;
};

static int estate_add(fzn_contact_estate_t *e, const fzn_contact_estate_item_t *item)
{
	if (e->n_items == e->cap_items) {
		size_t cap = e->cap_items ? e->cap_items * 2u : 16u;
		fzn_contact_estate_item_t *more = realloc(e->items, cap * sizeof(*more));

		if (!more)
			return 0;
		e->items = more;
		e->cap_items = cap;
	}
	e->items[e->n_items++] = *item;
	return 1;
}

static int estate_row_walked(void *arg, const uint8_t key[FZN_PUBKEY_LEN])
{
	static uint8_t row[ESTATE_ROW_MAX];
	static fzn_contact_estate_item_t item;
	struct estate_walk *w = arg;
	uint8_t filed[FZN_PUBKEY_LEN];
	size_t len = 0;

	/* FILED UNDER ITSELF, and the owner's, or passed over. */
	if (!w->store->load(w->store->ctx, FZN_PERSIST_CONTACT_ESTATE, key, row, sizeof(row), &len)
	    || len < FZN_PUBKEY_LEN + 2u || !estate_key(w->hash, row, len, filed)
	    || memcmp(filed, key, FZN_PUBKEY_LEN) != 0
	    || memcmp(row, w->e->owner, FZN_PUBKEY_LEN) != 0)
		return 1;
	if (len == ESTATE_K_ROW_LEN && row[FZN_PUBKEY_LEN] == ESTATE_K_KIND) {
		w->e->k = row[FZN_PUBKEY_LEN + 1u] > w->e->k ? row[FZN_PUBKEY_LEN + 1u] : w->e->k;
		return 1;
	}
	if (fzn_contact_estate_item_decode(row + FZN_PUBKEY_LEN, len - FZN_PUBKEY_LEN, &item)
	    != FZN_CONTACT_DEVICE_OK)
		return 1;
	if (!estate_add(w->e, &item)) {
		w->failed = 1;
		return 0;
	}
	return 1;
}

/* THE ROOT'S OWN RECORDS, sec 776's slot, as votes with no chain. */
static int estate_root_walked(void *arg, const uint8_t key[FZN_PUBKEY_LEN])
{
	static fzn_contact_estate_item_t item;
	struct estate_walk *w = arg;
	uint8_t row[REVOCATION_ROW_LEN];
	fzn_revocation_record_t rec;
	size_t len = 0;

	(void)key;
	if (!w->store->load(w->store->ctx, FZN_PERSIST_CONTACT_REVOCATION, key, row, sizeof(row),
	                    &len)
	    || fzn_persist_head_check(row, len, FZN_REVOCATION_LEN, FZN_PERSIST_BLOB_REVOCATION)
	               != FZN_PERSIST_OK
	    || fzn_revocation_open(row + FZN_PERSIST_HEAD_LEN, FZN_REVOCATION_LEN, &rec)
	               != FZN_CHAIN_OK
	    || memcmp(fzn_revocation_issuer(rec), w->e->owner, FZN_PUBKEY_LEN) != 0)
		return 1;
	memset(&item, 0, sizeof(item));
	item.kind = FZN_CONTACT_ESTATE_VOTE;
	item.record_len = FZN_REVOCATION_LEN;
	memcpy(item.record, row + FZN_PERSIST_HEAD_LEN, FZN_REVOCATION_LEN);
	if (!estate_add(w->e, &item)) {
		w->failed = 1;
		return 0;
	}
	return 1;
}

static int open_hops(const fzn_contact_estate_item_t *item, fzn_chain_hop_t *hops)
{
	size_t i;

	for (i = 0; i < item->hop_count; i++)
		if (fzn_hop_open(item->hops[i], FZN_HOP_LEN, &hops[i]) != FZN_CHAIN_OK)
			return 0;
	return 1;
}

fzn_contact_estate_t *fzn_contact_estate_open(const fzn_persist_ops_t *store,
                                              const uint8_t owner[FZN_PUBKEY_LEN],
                                              const fzn_cap_id_t *member,
                                              const fzn_cap_id_t *admin,
                                              const fzn_sign_ops_t *sign,
                                              const fzn_hash_ops_t *hash)
{
	fzn_contact_estate_t *e;
	struct estate_walk w;
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	uint8_t *settings = NULL;
	size_t i, n_changes = 0, n_settings = 0, n_confirms = 0, n_votes = 0, room;
	uint8_t resolved;

	if (!store || !store->load || !owner || !member || !admin || !sign || !hash || !hash->hash)
		return NULL;
	e = calloc(1u, sizeof(*e));
	if (!e)
		return NULL;
	memcpy(e->owner, owner, FZN_PUBKEY_LEN);
	e->member = *member;
	memset(&w, 0, sizeof(w));
	w.store = store;
	w.hash = hash;
	w.e = e;
	if (!fzn_persist_each(store, FZN_PERSIST_CONTACT_ESTATE, estate_row_walked, &w) || w.failed
	    || !fzn_persist_each(store, FZN_PERSIST_CONTACT_REVOCATION, estate_root_walked, &w)
	    || w.failed)
		goto fail;
	for (i = 0; i < e->n_items; i++) {
		const fzn_contact_estate_item_t *it = &e->items[i];

		if (it->kind == FZN_CONTACT_ESTATE_CHANGE)
			*(it->record_len == FZN_QUORUM_SET_LEN ? &n_settings : &n_changes) += 1u;
		else if (it->kind == FZN_CONTACT_ESTATE_CONFIRM)
			n_confirms++;
		else
			n_votes++;
	}
	/* THE ROOT SET, the owner its genesis, and a view of it with no act log:
	 * nothing a removed root did stands here. */
	room = n_changes + 1u;
	e->changes = calloc(room, sizeof(*e->changes));
	e->flags = calloc(FZN_ROOT_VIEW_FLAGS(room), 1u);
	if (!e->changes || !e->flags
	    || fzn_root_set_init(&e->set, owner, e->changes, room) != FZN_ROOT_LOG_OK)
		goto fail;
	for (i = 0; i < e->n_items; i++)
		if (e->items[i].kind == FZN_CONTACT_ESTATE_CHANGE
		    && e->items[i].record_len != FZN_QUORUM_SET_LEN)
			(void)fzn_root_set_admit(&e->set, e->items[i].record, e->items[i].record_len, sign,
			                         hash);
	if (fzn_root_view_init_with(&e->view, &e->set, NULL, e->flags, room) != FZN_ROOT_LOG_OK)
		goto fail;
	fzn_root_view_ops(&e->view, &e->ops);
	/* k: THE LARGER of what the roots' settings resolve to and the host's. */
	if (n_settings) {
		size_t at = 0;

		settings = calloc(n_settings, FZN_QUORUM_SET_LEN);
		if (!settings)
			goto fail;
		for (i = 0; i < e->n_items; i++)
			if (e->items[i].kind == FZN_CONTACT_ESTATE_CHANGE
			    && e->items[i].record_len == FZN_QUORUM_SET_LEN)
				memcpy(settings + (at++) * FZN_QUORUM_SET_LEN, e->items[i].record,
				       FZN_QUORUM_SET_LEN);
	}
	resolved = n_settings <= FZN_ROOT_SET_MAX
	                   ? fzn_quorum_resolve(settings, n_settings, &e->ops, hash, 1u)
	                   : 1u;
	free(settings);
	if (resolved > e->k)
		e->k = resolved;
	if (!e->k)
		e->k = 1u;
	/* THE STORE: the root set, k and the admin capability, confirmations. */
	room = n_votes + n_confirms + 8u;
	e->entries = calloc(room, sizeof(*e->entries));
	e->admins = calloc(room, sizeof(*e->admins));
	e->confirms = calloc(n_confirms + 8u, sizeof(*e->confirms));
	if (!e->entries || !e->admins || !e->confirms
	    || fzn_revocation_store_init(&e->store, e->entries, room) != FZN_CHAIN_OK
	    || fzn_revocation_store_set_quorum(&e->store, e->k, admin, e->admins, room)
	               != FZN_CHAIN_OK
	    || fzn_revocation_store_set_roots(&e->store, &e->ops, hash) != FZN_CHAIN_OK
	    || fzn_revocation_store_set_confirmations(&e->store, e->confirms, n_confirms + 8u, hash)
	               != FZN_CHAIN_OK)
		goto fail;
	/* CONFIRMATIONS, THEN VOTES, each with its signer's chain; one that will
	 * not admit -- a stranger's, a stale copy -- is passed over. */
	for (i = 0; i < e->n_items; i++) {
		const fzn_contact_estate_item_t *it = &e->items[i];

		if (it->kind == FZN_CONTACT_ESTATE_CONFIRM && open_hops(it, hops))
			(void)fzn_revocation_confirm_admit(&e->store, it->record, it->record_len, hops,
			                                   it->hop_count, owner, sign);
	}
	for (i = 0; i < e->n_items; i++) {
		const fzn_contact_estate_item_t *it = &e->items[i];
		fzn_revocation_record_t rec;

		if (it->kind != FZN_CONTACT_ESTATE_VOTE || !open_hops(it, hops)
		    || fzn_revocation_open(it->record, it->record_len, &rec) != FZN_CHAIN_OK)
			continue;
		(void)fzn_revocation_admit(&e->store,
		                           it->hop_count
		                                   ? fzn_revocation_offer_chain(rec, hops, it->hop_count)
		                                   : fzn_revocation_offer_root(rec),
		                           owner, sign, hash, NULL);
	}
	free(e->items);
	e->items = NULL;
	e->n_items = e->cap_items = 0;
	return e;
fail:
	fzn_contact_estate_close(e);
	return NULL;
}

/* EVERY LIVE VOTE AGAINST `key` TRUSTS NONE OF ITS ACTS: 1 when at least one
 * is held and none draws a line. */
static int unlined(const fzn_contact_estate_t *e, const uint8_t key[FZN_PUBKEY_LEN])
{
	static const uint8_t NOTHING[FZN_REVOCATION_ID_LEN] = { 0 };
	size_t i, live = 0;

	for (i = 0; i < e->store.used; i++) {
		const fzn_revocation_t *v = &e->store.entries[i];

		if (v->withdrawn || memcmp(v->grantee, key, FZN_PUBKEY_LEN) != 0
		    || memcmp(&v->capability, &e->member, sizeof(e->member)) != 0)
			continue;
		if (memcmp(v->cut, NOTHING, sizeof(NOTHING)) != 0)
			return 0;
		live++;
	}
	return live > 0u;
}

int fzn_contact_estate_revoked(const fzn_contact_estate_t *e, const fzn_contact_device_t *d)
{
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	uint8_t revoked[FZN_CHAIN_MAX_HOPS];
	size_t i;

	if (!e || !d || d->hop_count == 0u || d->hop_count > FZN_CHAIN_MAX_HOPS
	    || memcmp(d->owner, e->owner, FZN_PUBKEY_LEN) != 0)
		return 0;
	for (i = 0; i < d->hop_count; i++)
		if (fzn_hop_open(d->hops[i], FZN_HOP_LEN, &hops[i]) != FZN_CHAIN_OK)
			return 0;
	fzn_revocation_covers_chain(&e->store, hops, d->hop_count, &e->member, revoked);
	/* THE DEVICE'S OWN GRANT, as its estate judges it; a key above it only
	 * with no line drawn. */
	if (revoked[d->hop_count - 1u])
		return 1;
	for (i = 0; i + 1u < d->hop_count; i++)
		if (revoked[i] && unlined(e, fzn_hop_grantee(hops[i])))
			return 1;
	return 0;
}

uint8_t fzn_contact_estate_k(const fzn_contact_estate_t *e)
{
	return e ? e->k : 0u;
}

void fzn_contact_estate_close(fzn_contact_estate_t *e)
{
	if (!e)
		return;
	free(e->items);
	free(e->changes);
	free(e->flags);
	free(e->entries);
	free(e->admins);
	free(e->confirms);
	free(e);
}
