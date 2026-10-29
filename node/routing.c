/* See routing.h. */

#include "routing.h"

#include <string.h>

#include "../wire/bytes.h"

#define LABEL "fuzznet.routing"

const char *fzn_routing_err_str(fzn_routing_err_t err)
{
	switch (err) {
	case FZN_ROUTING_OK:
		return "ok";
	case FZN_ROUTING_ERR_MALFORMED:
		return "malformed";
	case FZN_ROUTING_ERR_SHAPE:
		return "not a routing manifest";
	case FZN_ROUTING_ERR_REFUSED:
		return "its hash, chain or signature does not hold";
	case FZN_ROUTING_ERR_STALE:
		return "no newer than the one kept";
	case FZN_ROUTING_ERR_ABSENT:
		return "none kept";
	case FZN_ROUTING_ERR_BACKEND:
		return "the store refused";
	case FZN_ROUTING_ERR_FULL:
		return "full, of entries no worse";
	}
	return "unknown";
}

static int address_ok(const char *a, size_t n)
{
	size_t i;

	if (!a || n == 0u || n > FZN_ROUTING_ADDRESS_MAX)
		return 0;
	for (i = 0; i < n; i++) {
		char c = a[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		      || c == '.' || c == '-' || c == ':'))
			return 0;
	}
	return 1;
}

/* Canonical order: metric, then address bytes, then port. */
static int cmp(const fzn_routing_entry_t *a, const fzn_routing_entry_t *b)
{
	size_t n = a->address_len < b->address_len ? a->address_len : b->address_len;
	int d;

	if (a->metric != b->metric)
		return a->metric < b->metric ? -1 : 1;
	d = memcmp(a->address, b->address, n);
	if (d)
		return d;
	if (a->address_len != b->address_len)
		return a->address_len < b->address_len ? -1 : 1;
	if (a->port != b->port)
		return a->port < b->port ? -1 : 1;
	return 0;
}

fzn_routing_err_t fzn_routing_add(fzn_routing_t *r, const char *address, size_t address_len,
                                  uint16_t port, uint8_t transport, uint8_t metric)
{
	fzn_routing_entry_t e;
	size_t at, i;

	if (!r || r->n >= FZN_ROUTING_ENTRIES_MAX || !address_ok(address, address_len) || !port)
		return FZN_ROUTING_ERR_MALFORMED;
	memset(&e, 0, sizeof(e));
	memcpy(e.address, address, address_len);
	e.address_len = address_len;
	e.port = port;
	e.transport = transport;
	e.metric = metric;
	for (at = 0; at < r->n && cmp(&r->entries[at], &e) < 0; at++)
		;
	/* THE SAME ADDRESS AND PORT ONCE, whatever its metric. */
	for (i = 0; i < r->n; i++)
		if (r->entries[i].port == port && r->entries[i].address_len == address_len
		    && memcmp(r->entries[i].address, address, address_len) == 0)
			return FZN_ROUTING_ERR_MALFORMED;
	memmove(&r->entries[at + 1u], &r->entries[at], (r->n - at) * sizeof(e));
	r->entries[at] = e;
	r->n++;
	return FZN_ROUTING_OK;
}

fzn_routing_err_t fzn_routing_offer(fzn_routing_t *r, const char *address, size_t address_len,
                                    uint16_t port, uint8_t transport, uint8_t metric)
{
	fzn_routing_entry_t e;
	size_t i;

	if (!r || r->n > FZN_ROUTING_ENTRIES_MAX || !address_ok(address, address_len) || !port)
		return FZN_ROUTING_ERR_MALFORMED;
	if (r->n < FZN_ROUTING_ENTRIES_MAX)
		return fzn_routing_add(r, address, address_len, port, transport, metric);
	for (i = 0; i < r->n; i++)
		if (r->entries[i].port == port && r->entries[i].address_len == address_len
		    && memcmp(r->entries[i].address, address, address_len) == 0)
			return FZN_ROUTING_ERR_MALFORMED;
	memset(&e, 0, sizeof(e));
	memcpy(e.address, address, address_len);
	e.address_len = address_len;
	e.port = port;
	e.transport = transport;
	e.metric = metric;
	/* THE WORST IS THE LAST: the entries are kept in canonical order. */
	if (cmp(&e, &r->entries[r->n - 1u]) >= 0)
		return FZN_ROUTING_ERR_FULL;
	r->n--;
	return fzn_routing_add(r, address, address_len, port, transport, metric);
}

/* The document's bytes, `public_relay` to the last entry, into `out`. */
static size_t document(const fzn_routing_t *r, uint8_t *out, size_t cap)
{
	size_t at = 0, i;

	if (cap < 2u)
		return 0;
	out[at++] = r->public_relay ? 1u : 0u;
	out[at++] = (uint8_t)r->n;
	for (i = 0; i < r->n; i++) {
		const fzn_routing_entry_t *e = &r->entries[i];

		if (cap - at < 1u + e->address_len + 4u)
			return 0;
		out[at++] = (uint8_t)e->address_len;
		memcpy(out + at, e->address, e->address_len);
		at += e->address_len;
		fzn_put_be16(out + at, e->port);
		at += 2u;
		out[at++] = e->transport;
		out[at++] = e->metric;
	}
	return at;
}

int fzn_routing_content_hash(const fzn_routing_t *r, const fzn_hash_ops_t *hash,
                             uint8_t out[FZN_ROUTING_HASH_LEN])
{
	uint8_t doc[2u + FZN_ROUTING_ENTRIES_MAX * (1u + FZN_ROUTING_ADDRESS_MAX + 4u)];
	size_t n;

	if (!r || !hash || !hash->hash || !out || r->n > FZN_ROUTING_ENTRIES_MAX)
		return 0;
	n = document(r, doc, sizeof(doc));
	return n && hash->hash(hash->ctx, out, FZN_ROUTING_HASH_LEN, doc, n);
}

/* The statement as signed: the label and its NUL, then the 82 bytes. */
static size_t statement(const fzn_routing_t *r, uint8_t out[sizeof(LABEL) + FZN_ROUTING_STATEMENT_LEN])
{
	uint8_t *s = out + sizeof(LABEL);

	memcpy(out, LABEL, sizeof(LABEL));
	s[0] = 1u;
	s[1] = 1u;
	fzn_put_be64(s + 2, r->generation);
	fzn_put_be64(s + 10, r->timestamp_ms);
	memcpy(s + 18, r->content_hash, FZN_ROUTING_HASH_LEN);
	memcpy(s + 50, r->signer, FZN_PUBKEY_LEN);
	return sizeof(LABEL) + FZN_ROUTING_STATEMENT_LEN;
}

fzn_routing_err_t fzn_routing_sign(fzn_routing_t *r, const fzn_hash_ops_t *hash,
                                   const fzn_sign_ops_t *sign,
                                   const uint8_t signer[FZN_PUBKEY_LEN],
                                   const uint8_t (*hops)[FZN_HOP_LEN], size_t hop_count,
                                   uint64_t generation, uint64_t now_ms)
{
	uint8_t msg[sizeof(LABEL) + FZN_ROUTING_STATEMENT_LEN];

	if (!r || !sign || !sign->sign || !signer || hop_count > FZN_CHAIN_MAX_HOPS
	    || (hop_count && !hops))
		return FZN_ROUTING_ERR_MALFORMED;
	if (!fzn_routing_content_hash(r, hash, r->content_hash))
		return FZN_ROUTING_ERR_MALFORMED;
	r->generation = generation;
	r->timestamp_ms = now_ms;
	memcpy(r->signer, signer, FZN_PUBKEY_LEN);
	if (hop_count)
		memcpy(r->hops, hops, hop_count * FZN_HOP_LEN);
	r->hop_count = hop_count;
	if (!sign->sign(sign->ctx, r->sig, msg, statement(r, msg)))
		return FZN_ROUTING_ERR_MALFORMED;
	return FZN_ROUTING_OK;
}

fzn_routing_err_t fzn_routing_verify(const fzn_routing_t *r, const fzn_hash_ops_t *hash,
                                     const fzn_sign_ops_t *sign,
                                     const uint8_t root[FZN_PUBKEY_LEN],
                                     const fzn_cap_id_t *admin, uint64_t now)
{
	uint8_t msg[sizeof(LABEL) + FZN_ROUTING_STATEMENT_LEN], got[FZN_ROUTING_HASH_LEN];
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	fzn_chain_t chain;
	size_t i;

	if (!r || !hash || !sign || !sign->verify || !root || r->hop_count > FZN_CHAIN_MAX_HOPS)
		return FZN_ROUTING_ERR_MALFORMED;
	/* THE DOCUMENT IS THE ONE THE STATEMENT NAMES. */
	if (!fzn_routing_content_hash(r, hash, got)
	    || memcmp(got, r->content_hash, FZN_ROUTING_HASH_LEN) != 0)
		return FZN_ROUTING_ERR_REFUSED;
	/* THE SIGNER IS THE ROOT, or an admin by a chain from it. */
	if (r->hop_count == 0u) {
		if (memcmp(r->signer, root, FZN_PUBKEY_LEN) != 0)
			return FZN_ROUTING_ERR_REFUSED;
	} else {
		if (!admin)
			return FZN_ROUTING_ERR_REFUSED;
		for (i = 0; i < r->hop_count; i++)
			if (fzn_hop_open(r->hops[i], FZN_HOP_LEN, &hops[i]) != FZN_CHAIN_OK)
				return FZN_ROUTING_ERR_REFUSED;
		if (fzn_chain_verify(hops, r->hop_count, root, admin, now, sign, NULL, NULL, &chain)
		            != FZN_CHAIN_OK
		    || memcmp(chain.grantee, r->signer, FZN_PUBKEY_LEN) != 0)
			return FZN_ROUTING_ERR_REFUSED;
	}
	if (!sign->verify(sign->ctx, r->signer, msg, statement(r, msg), r->sig))
		return FZN_ROUTING_ERR_REFUSED;
	return FZN_ROUTING_OK;
}

int fzn_routing_newer(const fzn_routing_t *a, const fzn_routing_t *b)
{
	if (a->generation != b->generation)
		return a->generation > b->generation;
	return memcmp(a->signer, b->signer, FZN_PUBKEY_LEN) > 0;
}

fzn_routing_err_t fzn_routing_encode(const fzn_routing_t *r, uint8_t *out, size_t cap,
                                     size_t *len)
{
	uint8_t msg[sizeof(LABEL) + FZN_ROUTING_STATEMENT_LEN];
	size_t at, n;

	if (len)
		*len = 0;
	if (!r || !out || !len || r->n > FZN_ROUTING_ENTRIES_MAX
	    || r->hop_count > FZN_CHAIN_MAX_HOPS || cap < FZN_ROUTING_STATEMENT_LEN)
		return FZN_ROUTING_ERR_MALFORMED;
	(void)statement(r, msg);
	memcpy(out, msg + sizeof(LABEL), FZN_ROUTING_STATEMENT_LEN);
	at = FZN_ROUTING_STATEMENT_LEN;
	n = document(r, out + at, cap - at);
	if (!n)
		return FZN_ROUTING_ERR_MALFORMED;
	at += n;
	if (cap - at < 1u + r->hop_count * FZN_HOP_LEN + FZN_SIG_LEN)
		return FZN_ROUTING_ERR_MALFORMED;
	out[at++] = (uint8_t)r->hop_count;
	memcpy(out + at, r->hops, r->hop_count * FZN_HOP_LEN);
	at += r->hop_count * FZN_HOP_LEN;
	memcpy(out + at, r->sig, FZN_SIG_LEN);
	*len = at + FZN_SIG_LEN;
	return FZN_ROUTING_OK;
}

fzn_routing_err_t fzn_routing_decode(const uint8_t *bytes, size_t len, fzn_routing_t *out)
{
	fzn_routing_t r;
	size_t at, count, i;

	if (!bytes || !out)
		return FZN_ROUTING_ERR_MALFORMED;
	memset(&r, 0, sizeof(r));
	if (len < FZN_ROUTING_STATEMENT_LEN + 2u || bytes[0] != 1u || bytes[1] != 1u)
		return FZN_ROUTING_ERR_SHAPE;
	r.generation = fzn_get_be64(bytes + 2);
	r.timestamp_ms = fzn_get_be64(bytes + 10);
	memcpy(r.content_hash, bytes + 18, FZN_ROUTING_HASH_LEN);
	memcpy(r.signer, bytes + 50, FZN_PUBKEY_LEN);
	at = FZN_ROUTING_STATEMENT_LEN;
	if (bytes[at] > 1u)
		return FZN_ROUTING_ERR_SHAPE;
	r.public_relay = bytes[at++];
	count = bytes[at++];
	if (count > FZN_ROUTING_ENTRIES_MAX)
		return FZN_ROUTING_ERR_SHAPE;
	/* IN CANONICAL ORDER, EACH ADDRESS AND PORT ONCE: one document has one
	 * encoding, so one hash. */
	for (i = 0; i < count; i++) {
		fzn_routing_entry_t e;
		size_t alen, k;

		if (at >= len || (alen = bytes[at]) == 0u || len - at < 1u + alen + 4u
		    || !address_ok((const char *)bytes + at + 1u, alen))
			return FZN_ROUTING_ERR_SHAPE;
		memset(&e, 0, sizeof(e));
		memcpy(e.address, bytes + at + 1u, alen);
		e.address_len = alen;
		e.port = fzn_get_be16(bytes + at + 1u + alen);
		e.transport = bytes[at + 3u + alen];
		e.metric = bytes[at + 4u + alen];
		if (!e.port || (r.n > 0u && cmp(&r.entries[r.n - 1u], &e) >= 0))
			return FZN_ROUTING_ERR_SHAPE;
		for (k = 0; k < r.n; k++)
			if (r.entries[k].port == e.port && r.entries[k].address_len == alen
			    && memcmp(r.entries[k].address, e.address, alen) == 0)
				return FZN_ROUTING_ERR_SHAPE;
		r.entries[r.n++] = e;
		at += 1u + alen + 4u;
	}
	if (at >= len || bytes[at] > FZN_CHAIN_MAX_HOPS)
		return FZN_ROUTING_ERR_SHAPE;
	r.hop_count = bytes[at++];
	if (len - at != r.hop_count * FZN_HOP_LEN + FZN_SIG_LEN)
		return FZN_ROUTING_ERR_SHAPE;
	memcpy(r.hops, bytes + at, r.hop_count * FZN_HOP_LEN);
	at += r.hop_count * FZN_HOP_LEN;
	memcpy(r.sig, bytes + at, FZN_SIG_LEN);
	*out = r;
	return FZN_ROUTING_OK;
}

fzn_routing_err_t fzn_routing_keep(const fzn_persist_ops_t *store,
                                   const uint8_t root[FZN_PUBKEY_LEN], const fzn_routing_t *r)
{
	static uint8_t bytes[FZN_ROUTING_MAX];
	fzn_routing_t held;
	size_t len = 0;

	if (!store || !store->save || !root || !r)
		return FZN_ROUTING_ERR_MALFORMED;
	if (fzn_routing_load(store, root, &held) == FZN_ROUTING_OK && !fzn_routing_newer(r, &held))
		return FZN_ROUTING_ERR_STALE;
	if (fzn_routing_encode(r, bytes, sizeof(bytes), &len) != FZN_ROUTING_OK)
		return FZN_ROUTING_ERR_MALFORMED;
	return store->save(store->ctx, FZN_PERSIST_ROUTING, root, bytes, len)
	               ? FZN_ROUTING_OK
	               : FZN_ROUTING_ERR_BACKEND;
}

fzn_routing_err_t fzn_routing_load(const fzn_persist_ops_t *store,
                                   const uint8_t root[FZN_PUBKEY_LEN], fzn_routing_t *out)
{
	static uint8_t bytes[FZN_ROUTING_MAX];
	size_t len = 0;

	if (!store || !store->load || !root || !out)
		return FZN_ROUTING_ERR_MALFORMED;
	if (!store->load(store->ctx, FZN_PERSIST_ROUTING, root, bytes, sizeof(bytes), &len))
		return FZN_ROUTING_ERR_ABSENT;
	return fzn_routing_decode(bytes, len, out) == FZN_ROUTING_OK ? FZN_ROUTING_OK
	                                                               : FZN_ROUTING_ERR_ABSENT;
}
