/* A contact's devices: project.md sec 614, and the header. */
#include "contact_devices.h"

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

fzn_contact_device_err_t fzn_contact_device_list(const fzn_persist_ops_t *store,
                                                 fzn_contact_device_t *out, size_t cap,
                                                 size_t *count)
{
	static uint8_t keys[FZN_CONTACT_DEVICES_MAX][FZN_PUBKEY_LEN];
	size_t n = 0, i;

	if (!count)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	*count = 0;
	if (!store || !store->list || !out || cap > FZN_CONTACT_DEVICES_MAX)
		return FZN_CONTACT_DEVICE_ERR_MALFORMED;
	if (!store->list(store->ctx, FZN_PERSIST_CONTACT_DEVICE, (uint8_t *)keys, cap, &n))
		return FZN_CONTACT_DEVICE_ERR_BACKEND;
	for (i = 0; i < n; i++)
		if (fzn_contact_device_get(store, keys[i], &out[*count]) == FZN_CONTACT_DEVICE_OK)
			(*count)++;
	return FZN_CONTACT_DEVICE_OK;
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

int fzn_contact_devices_offer(const fzn_contact_device_t *d, fzn_contact_devices_ask_t ask,
                              void *ctx)
{
	static uint8_t request[2u + FZN_CONTACT_DEVICE_MAX];
	uint8_t reply[FZN_CONTACT_DEVICES_TAKEN_LEN + 8u];
	size_t len = 0, reply_len = 0;

	if (!d || !ask
	    || fzn_contact_device_encode(d, request + 2, sizeof(request) - 2u, &len)
	               != FZN_CONTACT_DEVICE_OK)
		return -1;
	request[0] = FZN_CONTACT_DEVICES_VERSION;
	request[1] = FZN_CONTACT_DEVICES_OFFER;
	if (!ask(ctx, request, 2u + len, reply, sizeof(reply), &reply_len)
	    || reply_len != FZN_CONTACT_DEVICES_TAKEN_LEN || reply[0] != FZN_CONTACT_DEVICES_VERSION
	    || reply[1] != FZN_CONTACT_DEVICES_TAKEN || reply[2] > 1u)
		return -1;
	return reply[2];
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
