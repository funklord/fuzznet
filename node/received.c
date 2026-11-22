/* See received.h. */

#include "received.h"
#include "../wire/generated/persist_wire.h"
#include "../wire/generated/persist_wire_build.h"

#include "../wire/bytes.h"

#include <stdlib.h>
#include <string.h>

#define BODY_LEN(n) (1u + (size_t)(n) + 2u + 8u)
#define BLOB_MAX ((size_t)FZN_PERSIST_HEAD_LEN + BODY_LEN(FZN_NODE_RECEIVED_HOST_MAX))

const char *fzn_node_received_err_str(fzn_node_received_err_t err)
{
	switch (err) {
	case FZN_NODE_RECEIVED_OK:
		return "ok";
	case FZN_NODE_RECEIVED_ERR_MALFORMED:
		return "not a host and port";
	case FZN_NODE_RECEIVED_ERR_FULL:
		return "no room for another share";
	case FZN_NODE_RECEIVED_ERR_ABSENT:
		return "no share accepted from that contact";
	case FZN_NODE_RECEIVED_ERR_BACKEND:
		return "the store refused";
	case FZN_NODE_RECEIVED_ERR_SHAPE:
		return "an accepted share will not read";
	}
	return "unknown";
}

int fzn_node_received_host_ok(const char *host, size_t len)
{
	size_t i;

	if (!host || len == 0u || len > FZN_NODE_RECEIVED_HOST_MAX)
		return 0;
	for (i = 0; i < len; i++)
		if ((unsigned char)host[i] <= 0x20u || (unsigned char)host[i] >= 0x7fu)
			return 0;
	return 1;
}

fzn_node_received_err_t fzn_node_received_get(const fzn_persist_ops_t *store,
                                              const uint8_t sharer[FZN_PUBKEY_LEN],
                                              fzn_node_received_t *out)
{
	uint8_t blob[BLOB_MAX];
	const uint8_t *body = blob + FZN_PERSIST_HEAD_LEN, *host;
	size_t len = 0, n;
	situ_msg_t m;
	situ_view_t b;
	uint32_t need = 0;

	if (!store || !store->load || !sharer || !out)
		return FZN_NODE_RECEIVED_ERR_MALFORMED;
	if (!store->load(store->ctx, FZN_PERSIST_RECEIVED_SHARE, sharer, blob, sizeof(blob), &len))
		return FZN_NODE_RECEIVED_ERR_ABSENT;
	/* READ AS THE SCHEMA SAYS, sec 1398: a host of 1 to 253 bytes and a
	 * port not 0, then the host's own rule. */
	if (len < FZN_PERSIST_HEAD_LEN + 1u
	    || fzn_persist_wire_fzn_persist_received_share_body_required(body, (uint32_t)(len - FZN_PERSIST_HEAD_LEN), &need) != SITU_OK
	    || fzn_persist_head_check(blob, len, need, FZN_PERSIST_BLOB_RECEIVED_SHARE) != FZN_PERSIST_OK)
		return FZN_NODE_RECEIVED_ERR_SHAPE;
	situ_msg_init(&m, blob, (uint32_t)len);
	if (fzn_persist_wire_fzn_persist_received_share_body_view(&m, FZN_PERSIST_HEAD_LEN, need, &b) != SITU_OK
	    || fzn_persist_wire_fzn_persist_received_share_body_validate(b) != SITU_OK)
		return FZN_NODE_RECEIVED_ERR_SHAPE;
	n = fzn_persist_wire_fzn_persist_received_share_body_host_len_get(b);
	host = fzn_persist_wire_fzn_persist_received_share_body_host_ptr(b);
	if (n > FZN_NODE_RECEIVED_HOST_MAX || !fzn_node_received_host_ok((const char *)host, n))
		return FZN_NODE_RECEIVED_ERR_SHAPE;
	memset(out, 0, sizeof(*out));
	memcpy(out->sharer, sharer, FZN_PUBKEY_LEN);
	memcpy(out->host, host, n);
	out->host_len = n;
	out->port = fzn_persist_wire_fzn_persist_received_share_body_port_get(b);
	out->accepted_at_ms = fzn_persist_wire_fzn_persist_received_share_body_accepted_at_get(b);
	if (out->port == 0u)
		return FZN_NODE_RECEIVED_ERR_SHAPE;
	return FZN_NODE_RECEIVED_OK;
}

/* EVERY ROW'S KEY, into room grown until the list holds them: a list asked
 * for fewer keys than it holds fails whole. */
static uint8_t *listed_keys;
static size_t listed_room;

static fzn_node_received_err_t received_keys(const fzn_persist_ops_t *store, size_t *held)
{
	size_t max = listed_room ? listed_room : 64u;

	*held = 0;
	for (;;) {
		if (max > listed_room) {
			uint8_t *more = realloc(listed_keys, max * FZN_PUBKEY_LEN);

			if (!more)
				return FZN_NODE_RECEIVED_ERR_BACKEND;
			listed_keys = more;
			listed_room = max;
		}
		if (store->list(store->ctx, FZN_PERSIST_RECEIVED_SHARE, listed_keys, max, held))
			return FZN_NODE_RECEIVED_OK;
		if (max > ((size_t)1 << 24))
			return FZN_NODE_RECEIVED_ERR_BACKEND;
		max *= 2u;
	}
}

fzn_node_received_err_t fzn_node_received_list(const fzn_persist_ops_t *store,
                                               fzn_node_received_t *out, size_t cap,
                                               size_t *count)
{
	size_t held = 0, i, n = 0;
	fzn_node_received_err_t err;

	if (!store || !store->list || !out || !count)
		return FZN_NODE_RECEIVED_ERR_MALFORMED;
	*count = 0;
	err = received_keys(store, &held);
	if (err != FZN_NODE_RECEIVED_OK)
		return err;
	for (i = 0; i < held && n < cap; i++)
		if (fzn_node_received_get(store, listed_keys + i * FZN_PUBKEY_LEN, &out[n])
		    == FZN_NODE_RECEIVED_OK)
			n++;
	*count = n;
	return FZN_NODE_RECEIVED_OK;
}

fzn_node_received_err_t fzn_node_received_all(const fzn_persist_ops_t *store,
                                              fzn_node_received_t **out, size_t *room,
                                              size_t *count)
{
	size_t held = 0, i, n = 0;
	fzn_node_received_err_t err;

	if (!store || !store->list || !out || !room || !count)
		return FZN_NODE_RECEIVED_ERR_MALFORMED;
	*count = 0;
	err = received_keys(store, &held);
	if (err != FZN_NODE_RECEIVED_OK)
		return err;
	if (held > *room) {
		fzn_node_received_t *more = realloc(*out, held * sizeof(**out));

		if (!more)
			return FZN_NODE_RECEIVED_ERR_BACKEND;
		*out = more;
		*room = held;
	}
	for (i = 0; i < held; i++)
		if (fzn_node_received_get(store, listed_keys + i * FZN_PUBKEY_LEN, &(*out)[n])
		    == FZN_NODE_RECEIVED_OK)
			n++;
	*count = n;
	return FZN_NODE_RECEIVED_OK;
}

fzn_node_received_err_t fzn_node_received_add(const fzn_persist_ops_t *store,
                                              const uint8_t sharer[FZN_PUBKEY_LEN],
                                              const char *host, size_t host_len, uint16_t port,
                                              uint64_t now_ms)
{
	uint8_t blob[BLOB_MAX];
	uint32_t wrote = 0;

	/* AS MANY AS ARE ACCEPTED, sec 960: none counted, as none is a bound. */
	if (!store || !store->save || !sharer || !fzn_node_received_host_ok(host, host_len)
	    || port == 0u)
		return FZN_NODE_RECEIVED_ERR_MALFORMED;
	/* THE BODY BUILT BY THE GENERATED BUILDER, sec 1398. */
	if (fzn_persist_head_write(blob, sizeof(blob), BODY_LEN(host_len),
	                           FZN_PERSIST_BLOB_RECEIVED_SHARE)
	            != FZN_PERSIST_OK
	    || fzn_persist_wire_fzn_persist_received_share_body_build(blob + FZN_PERSIST_HEAD_LEN, (uint32_t)BODY_LEN(host_len),
	                                                  (const uint8_t *)host, (uint32_t)host_len, port, now_ms,
	                                                  &wrote)
	               != SITU_OK)
		return FZN_NODE_RECEIVED_ERR_MALFORMED;
	if (!store->save(store->ctx, FZN_PERSIST_RECEIVED_SHARE, sharer, blob,
	                 FZN_PERSIST_HEAD_LEN + BODY_LEN(host_len)))
		return FZN_NODE_RECEIVED_ERR_BACKEND;
	return FZN_NODE_RECEIVED_OK;
}

fzn_node_received_err_t fzn_node_received_remove(const fzn_persist_ops_t *store,
                                                 const uint8_t sharer[FZN_PUBKEY_LEN])
{
	fzn_node_received_t held;
	fzn_node_received_err_t err;

	if (!store || !sharer)
		return FZN_NODE_RECEIVED_ERR_MALFORMED;
	if (!store->remove)
		return FZN_NODE_RECEIVED_ERR_BACKEND;
	err = fzn_node_received_get(store, sharer, &held);
	if (err == FZN_NODE_RECEIVED_ERR_ABSENT)
		return err;
	if (!store->remove(store->ctx, FZN_PERSIST_RECEIVED_SHARE, sharer))
		return FZN_NODE_RECEIVED_ERR_BACKEND;
	return FZN_NODE_RECEIVED_OK;
}
