/* A contact request: project.md sec 619, and the header. */
#include "contact_request.h"

#include <string.h>

#include "../wire/bytes.h"

const char *fzn_contact_request_err_str(fzn_contact_request_err_t err)
{
	switch (err) {
	case FZN_CONTACT_REQUEST_OK:
		return "ok";
	case FZN_CONTACT_REQUEST_ERR_MALFORMED:
		return "malformed";
	case FZN_CONTACT_REQUEST_ERR_SHAPE:
		return "not a contact request";
	case FZN_CONTACT_REQUEST_ERR_REFUSED:
		return "its card or signature does not hold";
	case FZN_CONTACT_REQUEST_ERR_NOT_HERE:
		return "for another host";
	case FZN_CONTACT_REQUEST_ERR_EXPIRED:
		return "expired, or claims too long a life";
	case FZN_CONTACT_REQUEST_ERR_ABSENT:
		return "none held";
	case FZN_CONTACT_REQUEST_ERR_BACKEND:
		return "the store refused";
	}
	return "unknown";
}

/* Everything the signature covers, into `out`; its length, or 0. */
static size_t body(const fzn_contact_request_t *r, uint8_t *out, size_t cap)
{
	size_t card_len = 0, at;

	if (cap < 2u + FZN_PUBKEY_LEN + 2u
	    || fzn_contact_card_encode(&r->card, out + 2u + FZN_PUBKEY_LEN + 2u,
	                               cap - (2u + FZN_PUBKEY_LEN + 2u), &card_len)
	               != FZN_CONTACT_CARD_OK)
		return 0;
	out[0] = FZN_CONTACT_REQUEST_VERSION;
	out[1] = (uint8_t)FZN_OBJECT_CONTACT_REQUEST;
	memcpy(out + 2, r->target, FZN_PUBKEY_LEN);
	fzn_put_be16(out + 2 + FZN_PUBKEY_LEN, (uint16_t)card_len);
	at = 2u + FZN_PUBKEY_LEN + 2u + card_len;
	if (at + FZN_CONTACT_REQUEST_NONCE_LEN + 8u > cap)
		return 0;
	memcpy(out + at, r->nonce, FZN_CONTACT_REQUEST_NONCE_LEN);
	at += FZN_CONTACT_REQUEST_NONCE_LEN;
	fzn_put_be64(out + at, r->expires_at);
	return at + 8u;
}

fzn_contact_request_err_t fzn_contact_request_sign(fzn_contact_request_t *r,
                                                   const fzn_sign_ops_t *sign)
{
	static uint8_t bytes[FZN_CONTACT_REQUEST_MAX];
	size_t n;

	if (!r || !sign || !sign->sign)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	n = body(r, bytes, sizeof(bytes));
	if (!n || !sign->sign(sign->ctx, r->sig, bytes, n))
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	return FZN_CONTACT_REQUEST_OK;
}

fzn_contact_request_err_t fzn_contact_request_encode(const fzn_contact_request_t *r,
                                                     uint8_t *out, size_t cap, size_t *len)
{
	size_t n;

	if (!r || !out || !len)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	n = body(r, out, cap);
	if (!n || n + FZN_SIG_LEN > cap)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	memcpy(out + n, r->sig, FZN_SIG_LEN);
	*len = n + FZN_SIG_LEN;
	return FZN_CONTACT_REQUEST_OK;
}

fzn_contact_request_err_t fzn_contact_request_decode(const uint8_t *bytes, size_t len,
                                                     fzn_contact_request_t *out)
{
	size_t card_len, at;

	if (!bytes || !out)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	if (len < 2u + FZN_PUBKEY_LEN + 2u || bytes[0] != FZN_CONTACT_REQUEST_VERSION
	    || bytes[1] != (uint8_t)FZN_OBJECT_CONTACT_REQUEST)
		return FZN_CONTACT_REQUEST_ERR_SHAPE;
	memcpy(out->target, bytes + 2, FZN_PUBKEY_LEN);
	card_len = fzn_get_be16(bytes + 2 + FZN_PUBKEY_LEN);
	at = 2u + FZN_PUBKEY_LEN + 2u;
	/* EXACTLY ITS LENGTH: one request, one encoding. */
	if (len != at + card_len + FZN_CONTACT_REQUEST_NONCE_LEN + 8u + FZN_SIG_LEN
	    || fzn_contact_card_decode(bytes + at, card_len, &out->card) != FZN_CONTACT_CARD_OK)
		return FZN_CONTACT_REQUEST_ERR_SHAPE;
	at += card_len;
	memcpy(out->nonce, bytes + at, FZN_CONTACT_REQUEST_NONCE_LEN);
	at += FZN_CONTACT_REQUEST_NONCE_LEN;
	out->expires_at = fzn_get_be64(bytes + at);
	at += 8u;
	memcpy(out->sig, bytes + at, FZN_SIG_LEN);
	return FZN_CONTACT_REQUEST_OK;
}

fzn_contact_request_err_t fzn_contact_request_verify(const fzn_contact_request_t *r,
                                                     const fzn_sign_ops_t *sign,
                                                     const fzn_cap_id_t *member,
                                                     const uint8_t self[FZN_PUBKEY_LEN],
                                                     uint64_t now)
{
	static uint8_t bytes[FZN_CONTACT_REQUEST_MAX];
	size_t n;

	if (!r || !sign || !sign->verify || !member || !self)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	if (memcmp(r->target, self, FZN_PUBKEY_LEN) != 0)
		return FZN_CONTACT_REQUEST_ERR_NOT_HERE;
	if (fzn_contact_card_verify(&r->card, sign, member, now) != FZN_CONTACT_CARD_OK)
		return FZN_CONTACT_REQUEST_ERR_REFUSED;
	n = body(r, bytes, sizeof(bytes));
	if (!n || !sign->verify(sign->ctx, fzn_contact_device_key(&r->card.host), bytes, n, r->sig))
		return FZN_CONTACT_REQUEST_ERR_REFUSED;
	if (r->expires_at < now || r->expires_at - now > FZN_CONTACT_REQUEST_LIFE_MAX)
		return FZN_CONTACT_REQUEST_ERR_EXPIRED;
	return FZN_CONTACT_REQUEST_OK;
}

/* ---- asked of this user ------------------------------------------------- */

#define HELD_MAX (8u + FZN_CONTACT_REQUEST_MAX)

fzn_contact_request_err_t fzn_contact_request_get(const fzn_persist_ops_t *store,
                                                  const uint8_t root[FZN_PUBKEY_LEN],
                                                  fzn_contact_request_held_t *out)
{
	static uint8_t bytes[HELD_MAX];
	size_t len = 0;

	if (!store || !store->load || !root || !out)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	if (!store->load(store->ctx, FZN_PERSIST_CONTACT_REQUEST, root, bytes, sizeof(bytes), &len)
	    || len < 8u
	    || fzn_contact_request_decode(bytes + 8, len - 8u, &out->request)
	               != FZN_CONTACT_REQUEST_OK
	    /* FILED UNDER ITS ASKER'S ROOT, or a row nobody kept. */
	    || memcmp(out->request.card.host.owner, root, FZN_PUBKEY_LEN) != 0)
		return FZN_CONTACT_REQUEST_ERR_ABSENT;
	out->received_at = fzn_get_be64(bytes);
	return FZN_CONTACT_REQUEST_OK;
}

fzn_contact_request_err_t fzn_contact_request_list(const fzn_persist_ops_t *store,
                                                   fzn_contact_request_held_t *out, size_t cap,
                                                   size_t *count)
{
	static uint8_t keys[FZN_CONTACT_REQUESTS_MAX + 1u][FZN_PUBKEY_LEN];
	size_t n = 0, i, j;

	if (!count)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	*count = 0;
	if (!store || !store->list || !out || cap > FZN_CONTACT_REQUESTS_MAX + 1u)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	if (!store->list(store->ctx, FZN_PERSIST_CONTACT_REQUEST, (uint8_t *)keys,
	                 FZN_CONTACT_REQUESTS_MAX + 1u, &n))
		return FZN_CONTACT_REQUEST_ERR_BACKEND;
	for (i = 0; i < n && *count < cap; i++)
		if (fzn_contact_request_get(store, keys[i], &out[*count]) == FZN_CONTACT_REQUEST_OK)
			(*count)++;
	/* OLDEST FIRST: insertion, sixteen at most. */
	for (i = 1; i < *count; i++)
		for (j = i; j > 0 && out[j - 1u].received_at > out[j].received_at; j--) {
			fzn_contact_request_held_t t = out[j - 1u];

			out[j - 1u] = out[j];
			out[j] = t;
		}
	return FZN_CONTACT_REQUEST_OK;
}

fzn_contact_request_err_t fzn_contact_request_keep(const fzn_persist_ops_t *store,
                                                   const fzn_contact_request_t *r, uint64_t now)
{
	static uint8_t bytes[HELD_MAX];
	static fzn_contact_request_held_t held[FZN_CONTACT_REQUESTS_MAX + 1u];
	fzn_contact_request_held_t same;
	size_t len = 0, n = 0, i;

	if (!store || !store->save || !store->remove || !r)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	if (fzn_contact_request_encode(r, bytes + 8, sizeof(bytes) - 8u, &len)
	    != FZN_CONTACT_REQUEST_OK)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	fzn_put_be64(bytes, now);
	/* ROOM FOR A NEW ONE: the oldest goes when full, unless this one only
	 * replaces its asker's earlier request. */
	if (fzn_contact_request_get(store, r->card.host.owner, &same) != FZN_CONTACT_REQUEST_OK) {
		if (fzn_contact_request_list(store, held, FZN_CONTACT_REQUESTS_MAX + 1u, &n)
		    != FZN_CONTACT_REQUEST_OK)
			return FZN_CONTACT_REQUEST_ERR_BACKEND;
		for (i = 0; n - i >= FZN_CONTACT_REQUESTS_MAX; i++)
			if (!store->remove(store->ctx, FZN_PERSIST_CONTACT_REQUEST,
			                   held[i].request.card.host.owner))
				return FZN_CONTACT_REQUEST_ERR_BACKEND;
	}
	return store->save(store->ctx, FZN_PERSIST_CONTACT_REQUEST, r->card.host.owner, bytes,
	                   8u + len)
	               ? FZN_CONTACT_REQUEST_OK
	               : FZN_CONTACT_REQUEST_ERR_BACKEND;
}

fzn_contact_request_err_t fzn_contact_request_drop(const fzn_persist_ops_t *store,
                                                   const uint8_t root[FZN_PUBKEY_LEN])
{
	fzn_contact_request_held_t held;

	if (!store || !store->remove || !root)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	if (fzn_contact_request_get(store, root, &held) != FZN_CONTACT_REQUEST_OK)
		return FZN_CONTACT_REQUEST_ERR_ABSENT;
	return store->remove(store->ctx, FZN_PERSIST_CONTACT_REQUEST, root)
	               ? FZN_CONTACT_REQUEST_OK
	               : FZN_CONTACT_REQUEST_ERR_BACKEND;
}

/* ---- asked by this user ------------------------------------------------- */

#define ASKED_MAX (1u + 2u + FZN_CONTACT_CARD_MAX + FZN_CONTACT_REQUEST_MAX)

fzn_contact_request_err_t fzn_contact_asked_get(const fzn_persist_ops_t *store,
                                                const uint8_t root[FZN_PUBKEY_LEN],
                                                fzn_contact_asked_t *out)
{
	static uint8_t bytes[ASKED_MAX];
	size_t len = 0, card_len;

	if (!store || !store->load || !root || !out)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	if (!store->load(store->ctx, FZN_PERSIST_CONTACT_ASKED, root, bytes, sizeof(bytes), &len)
	    || len < 3u || bytes[0] > 1u)
		return FZN_CONTACT_REQUEST_ERR_ABSENT;
	card_len = fzn_get_be16(bytes + 1);
	if (len < 3u + card_len
	    || fzn_contact_card_decode(bytes + 3, card_len, &out->card) != FZN_CONTACT_CARD_OK
	    || fzn_contact_request_decode(bytes + 3 + card_len, len - 3u - card_len, &out->request)
	               != FZN_CONTACT_REQUEST_OK
	    || memcmp(out->card.host.owner, root, FZN_PUBKEY_LEN) != 0)
		return FZN_CONTACT_REQUEST_ERR_ABSENT;
	out->answered = bytes[0];
	return FZN_CONTACT_REQUEST_OK;
}

fzn_contact_request_err_t fzn_contact_asked_keep(const fzn_persist_ops_t *store,
                                                 const fzn_contact_asked_t *a)
{
	static uint8_t bytes[ASKED_MAX];
	static uint8_t keys[FZN_CONTACT_ASKED_MAX + 1u][FZN_PUBKEY_LEN];
	fzn_contact_asked_t held;
	size_t card_len = 0, req_len = 0, n = 0;

	if (!store || !store->save || !store->list || !a)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	if (fzn_contact_card_encode(&a->card, bytes + 3, sizeof(bytes) - 3u, &card_len)
	            != FZN_CONTACT_CARD_OK
	    || fzn_contact_request_encode(&a->request, bytes + 3 + card_len,
	                                  sizeof(bytes) - 3u - card_len, &req_len)
	               != FZN_CONTACT_REQUEST_OK)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	bytes[0] = a->answered ? 1u : 0u;
	fzn_put_be16(bytes + 1, (uint16_t)card_len);
	if (fzn_contact_asked_get(store, a->card.host.owner, &held) != FZN_CONTACT_REQUEST_OK
	    && (!store->list(store->ctx, FZN_PERSIST_CONTACT_ASKED, (uint8_t *)keys,
	                     FZN_CONTACT_ASKED_MAX + 1u, &n)
	        || n >= FZN_CONTACT_ASKED_MAX))
		return FZN_CONTACT_REQUEST_ERR_BACKEND;
	return store->save(store->ctx, FZN_PERSIST_CONTACT_ASKED, a->card.host.owner, bytes,
	                   3u + card_len + req_len)
	               ? FZN_CONTACT_REQUEST_OK
	               : FZN_CONTACT_REQUEST_ERR_BACKEND;
}

fzn_contact_request_err_t fzn_contact_asked_list(const fzn_persist_ops_t *store,
                                                 fzn_contact_asked_t *out, size_t cap,
                                                 size_t *count)
{
	static uint8_t keys[FZN_CONTACT_ASKED_MAX + 1u][FZN_PUBKEY_LEN];
	size_t n = 0, i;

	if (!count)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	*count = 0;
	if (!store || !store->list || !out)
		return FZN_CONTACT_REQUEST_ERR_MALFORMED;
	if (!store->list(store->ctx, FZN_PERSIST_CONTACT_ASKED, (uint8_t *)keys,
	                 FZN_CONTACT_ASKED_MAX + 1u, &n))
		return FZN_CONTACT_REQUEST_ERR_BACKEND;
	for (i = 0; i < n && *count < cap; i++)
		if (fzn_contact_asked_get(store, keys[i], &out[*count]) == FZN_CONTACT_REQUEST_OK)
			(*count)++;
	return FZN_CONTACT_REQUEST_OK;
}

fzn_contact_request_err_t fzn_contact_asked_answered(const fzn_persist_ops_t *store,
                                                     const uint8_t root[FZN_PUBKEY_LEN])
{
	static fzn_contact_asked_t a;

	if (fzn_contact_asked_get(store, root, &a) != FZN_CONTACT_REQUEST_OK)
		return FZN_CONTACT_REQUEST_ERR_ABSENT;
	if (a.answered)
		return FZN_CONTACT_REQUEST_OK;
	a.answered = 1;
	return fzn_contact_asked_keep(store, &a);
}
