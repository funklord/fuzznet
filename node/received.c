/* See received.h. */

#include "received.h"

#include "../wire/bytes.h"

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
	const uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	size_t len = 0, n;

	if (!store || !store->load || !sharer || !out)
		return FZN_NODE_RECEIVED_ERR_MALFORMED;
	if (!store->load(store->ctx, FZN_PERSIST_RECEIVED_SHARE, sharer, blob, sizeof(blob), &len))
		return FZN_NODE_RECEIVED_ERR_ABSENT;
	if (len < FZN_PERSIST_HEAD_LEN + 1u)
		return FZN_NODE_RECEIVED_ERR_SHAPE;
	n = body[0];
	if (fzn_persist_head_check(blob, len, BODY_LEN(n), FZN_PERSIST_BLOB_RECEIVED_SHARE)
	            != FZN_PERSIST_OK
	    || !fzn_node_received_host_ok((const char *)body + 1, n))
		return FZN_NODE_RECEIVED_ERR_SHAPE;
	memset(out, 0, sizeof(*out));
	memcpy(out->sharer, sharer, FZN_PUBKEY_LEN);
	memcpy(out->host, body + 1, n);
	out->host_len = n;
	out->port = fzn_get_be16(body + 1 + n);
	out->accepted_at_ms = fzn_get_be64(body + 1 + n + 2);
	if (out->port == 0u)
		return FZN_NODE_RECEIVED_ERR_SHAPE;
	return FZN_NODE_RECEIVED_OK;
}

fzn_node_received_err_t fzn_node_received_list(const fzn_persist_ops_t *store,
                                               fzn_node_received_t *out, size_t cap,
                                               size_t *count)
{
	uint8_t keys[FZN_NODE_RECEIVED_MAX][FZN_PUBKEY_LEN];
	size_t held = 0, i, n = 0;

	if (!store || !store->list || !out || !count)
		return FZN_NODE_RECEIVED_ERR_MALFORMED;
	*count = 0;
	if (!store->list(store->ctx, FZN_PERSIST_RECEIVED_SHARE, (uint8_t *)keys,
	                 FZN_NODE_RECEIVED_MAX, &held))
		return FZN_NODE_RECEIVED_ERR_BACKEND;
	for (i = 0; i < held && n < cap; i++)
		if (fzn_node_received_get(store, keys[i], &out[n]) == FZN_NODE_RECEIVED_OK)
			n++;
	*count = n;
	return FZN_NODE_RECEIVED_OK;
}

fzn_node_received_err_t fzn_node_received_add(const fzn_persist_ops_t *store,
                                              const uint8_t sharer[FZN_PUBKEY_LEN],
                                              const char *host, size_t host_len, uint16_t port,
                                              uint64_t now_ms)
{
	fzn_node_received_t all[FZN_NODE_RECEIVED_MAX];
	uint8_t blob[BLOB_MAX];
	uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	size_t count = 0, i;
	int held = 0;
	fzn_node_received_err_t err;

	if (!store || !store->save || !sharer || !fzn_node_received_host_ok(host, host_len)
	    || port == 0u)
		return FZN_NODE_RECEIVED_ERR_MALFORMED;
	err = fzn_node_received_list(store, all, FZN_NODE_RECEIVED_MAX, &count);
	if (err != FZN_NODE_RECEIVED_OK)
		return err;
	for (i = 0; i < count; i++)
		held |= memcmp(all[i].sharer, sharer, FZN_PUBKEY_LEN) == 0;
	if (!held && count >= FZN_NODE_RECEIVED_MAX)
		return FZN_NODE_RECEIVED_ERR_FULL;
	if (fzn_persist_head_write(blob, sizeof(blob), BODY_LEN(host_len),
	                           FZN_PERSIST_BLOB_RECEIVED_SHARE)
	    != FZN_PERSIST_OK)
		return FZN_NODE_RECEIVED_ERR_MALFORMED;
	body[0] = (uint8_t)host_len;
	memcpy(body + 1, host, host_len);
	fzn_put_be16(body + 1 + host_len, port);
	fzn_put_be64(body + 1 + host_len + 2, now_ms);
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
