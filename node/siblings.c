#include "siblings.h"

#include <string.h>

#include "../constant_time/constant_time.h"

const char *fzn_node_siblings_err_str(fzn_node_siblings_err_t err)
{
	switch (err) {
	case FZN_NODE_SIBLINGS_OK:
		return "ok";
	case FZN_NODE_SIBLINGS_MALFORMED:
		return "malformed";
	case FZN_NODE_SIBLINGS_REFUSED:
		return "not a prekey its carrier signed about itself";
	case FZN_NODE_SIBLINGS_STALE:
		return "a newer prekey is kept for that host";
	case FZN_NODE_SIBLINGS_BACKEND:
		return "the store would not";
	case FZN_NODE_SIBLINGS_ROOM:
		return "more siblings are kept than the room given";
	}
	return "unknown";
}

fzn_node_siblings_err_t fzn_node_siblings_learn(const fzn_persist_ops_t *store,
                                                const fzn_sign_ops_t *verify,
                                                const uint8_t *bytes, size_t len,
                                                const uint8_t carrier[FZN_PUBKEY_LEN])
{
	uint8_t kept[FZN_PREKEY_LEN_TOTAL];
	fzn_prekey_record_t record, held;
	size_t kept_len = 0;

	if (!store || !store->load || !store->save || !verify || !bytes || !carrier)
		return FZN_NODE_SIBLINGS_MALFORMED;
	if (len != FZN_PREKEY_LEN_TOTAL || fzn_prekey_open(bytes, len, &record) != FZN_PREKEY_OK
	    || !fzn_ct_memeq(record.host, carrier, FZN_PUBKEY_LEN)
	    || fzn_prekey_verify(record, verify) != FZN_PREKEY_OK)
		return FZN_NODE_SIBLINGS_REFUSED;
	/* THE NEWEST PER HOST: a row that will not open is replaced, as one
	 * nobody could have used. */
	if (store->load(store->ctx, FZN_PERSIST_SIBLING_PREKEY, record.host, kept, sizeof(kept),
	                &kept_len)
	    && kept_len == FZN_PREKEY_LEN_TOTAL
	    && fzn_prekey_open(kept, kept_len, &held) == FZN_PREKEY_OK) {
		if (memcmp(kept, bytes, len) == 0)
			return FZN_NODE_SIBLINGS_OK;
		if (held.created_at >= record.created_at)
			return FZN_NODE_SIBLINGS_STALE;
	}
	return store->save(store->ctx, FZN_PERSIST_SIBLING_PREKEY, record.host, bytes, len)
	               ? FZN_NODE_SIBLINGS_OK
	               : FZN_NODE_SIBLINGS_BACKEND;
}

fzn_node_siblings_err_t fzn_node_siblings_prekey(const fzn_persist_ops_t *store,
                                                 const uint8_t host[FZN_PUBKEY_LEN],
                                                 uint8_t out[FZN_PREKEY_LEN_TOTAL])
{
	fzn_prekey_record_t record;
	size_t len = 0;

	if (!store || !store->load || !host || !out)
		return FZN_NODE_SIBLINGS_MALFORMED;
	/* WHAT IT SAYS IT IS, under its own place: a record filed under another
	 * host is not that host's. */
	if (!store->load(store->ctx, FZN_PERSIST_SIBLING_PREKEY, host, out, FZN_PREKEY_LEN_TOTAL,
	                 &len)
	    || len != FZN_PREKEY_LEN_TOTAL || fzn_prekey_open(out, len, &record) != FZN_PREKEY_OK
	    || !fzn_ct_memeq(record.host, host, FZN_PUBKEY_LEN))
		return FZN_NODE_SIBLINGS_BACKEND;
	return FZN_NODE_SIBLINGS_OK;
}

/* WALKED, sec 704: every host counted, as many as fit kept. */
struct siblings_into {
	uint8_t (*hosts)[FZN_PUBKEY_LEN];
	size_t cap, n;
};

static int sibling_into(void *arg, const uint8_t host[FZN_PUBKEY_LEN])
{
	struct siblings_into *in = arg;

	if (in->n < in->cap)
		memcpy(in->hosts[in->n], host, FZN_PUBKEY_LEN);
	in->n++;
	return 1;
}

fzn_node_siblings_err_t fzn_node_siblings_list(const fzn_persist_ops_t *store,
                                               uint8_t (*hosts)[FZN_PUBKEY_LEN], size_t cap,
                                               size_t *count)
{
	struct siblings_into in;

	if (!count)
		return FZN_NODE_SIBLINGS_MALFORMED;
	*count = 0;
	if (!store || (!store->list && !store->each) || (!hosts && cap))
		return FZN_NODE_SIBLINGS_MALFORMED;
	in.hosts = hosts;
	in.cap = cap;
	in.n = 0;
	if (!fzn_persist_each(store, FZN_PERSIST_SIBLING_PREKEY, sibling_into, &in))
		return FZN_NODE_SIBLINGS_BACKEND;
	*count = in.n;
	return in.n > cap ? FZN_NODE_SIBLINGS_ROOM : FZN_NODE_SIBLINGS_OK;
}
