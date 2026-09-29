/* See roots.h. */

#include "roots.h"

#include "../wire/bytes.h"

#include <string.h>

#define ENTRY_BLOB ((size_t)FZN_PERSIST_HEAD_LEN + FZN_ROOT_ACT_LEN)
#define CHANGE_BLOB_MAX ((size_t)FZN_PERSIST_HEAD_LEN + FZN_ROOT_REMOVE_LEN)

const char *fzn_node_roots_err_str(fzn_node_roots_err_t err)
{
	switch (err) {
	case FZN_NODE_ROOTS_OK:
		return "ok";
	case FZN_NODE_ROOTS_MALFORMED:
		return "malformed";
	case FZN_NODE_ROOTS_REFUSED:
		return "the root record would not admit";
	case FZN_NODE_ROOTS_NOT_SAVED:
		return "known until a restart: the root record was not saved";
	case FZN_NODE_ROOTS_STORE:
		return "a stored root record would not read or admit again";
	}
	return "unknown";
}

fzn_node_roots_err_t fzn_node_roots_init(fzn_node_roots_t *roots,
                                         const uint8_t genesis[FZN_PUBKEY_LEN],
                                         const fzn_sign_ops_t *sign,
                                         const fzn_hash_ops_t *hash)
{
	if (!roots || !genesis || !sign || !sign->verify || !hash || !hash->hash)
		return FZN_NODE_ROOTS_MALFORMED;
	memset(roots, 0, sizeof(*roots));
	if (fzn_root_log_init(&roots->log, roots->entries, FZN_NODE_ROOT_LOG_MAX)
	            != FZN_ROOT_LOG_OK
	    || fzn_root_set_init(&roots->set, genesis, roots->changes, FZN_ROOT_SET_MAX)
	               != FZN_ROOT_LOG_OK
	    || fzn_root_view_init(&roots->view, &roots->set, &roots->log) != FZN_ROOT_LOG_OK)
		return FZN_NODE_ROOTS_MALFORMED;
	fzn_root_view_ops(&roots->view, &roots->ops);
	roots->sign = sign;
	roots->hash = hash;
	return FZN_NODE_ROOTS_OK;
}

/* The blob tag and the admission a record takes, by its object byte. 0 for
 * anything that is not a root record. */
static uint8_t tag_of(const uint8_t *bytes, size_t len)
{
	if (len < 2u)
		return 0;
	switch (bytes[1]) {
	case FZN_OBJECT_ROOT_ACT:
		return (uint8_t)FZN_PERSIST_BLOB_ROOT_ENTRY;
	case FZN_OBJECT_ROOT_ADD:
		return (uint8_t)FZN_PERSIST_BLOB_ROOT_ADD;
	case FZN_OBJECT_ROOT_REMOVE:
		return (uint8_t)FZN_PERSIST_BLOB_ROOT_REMOVE;
	}
	return 0;
}

static fzn_root_log_err_t admit(fzn_node_roots_t *roots, const uint8_t *bytes, size_t len)
{
	if (tag_of(bytes, len) == (uint8_t)FZN_PERSIST_BLOB_ROOT_ENTRY)
		return fzn_root_log_admit(&roots->log, bytes, len, roots->sign, roots->hash);
	return fzn_root_set_admit(&roots->set, bytes, len, roots->sign, roots->hash);
}

/* Settle the view again over what is held now. The ops point at it and
 * need no refresh. */
static void settle(fzn_node_roots_t *roots)
{
	(void)fzn_root_view_init(&roots->view, &roots->set, &roots->log);
}

fzn_node_roots_err_t fzn_node_roots_learn(fzn_node_roots_t *roots,
                                          const fzn_persist_ops_t *store,
                                          const uint8_t *bytes, size_t len)
{
	uint8_t blob[CHANGE_BLOB_MAX > ENTRY_BLOB ? CHANGE_BLOB_MAX : ENTRY_BLOB];
	uint8_t id[FZN_ROOT_ACT_ID_LEN];
	uint8_t tag;
	fzn_persist_slot_t slot;

	if (!roots || !store || !store->save || !bytes)
		return FZN_NODE_ROOTS_MALFORMED;
	tag = tag_of(bytes, len);
	if (!tag || len > sizeof(blob) - FZN_PERSIST_HEAD_LEN)
		return FZN_NODE_ROOTS_REFUSED;
	if (admit(roots, bytes, len) != FZN_ROOT_LOG_OK)
		return FZN_NODE_ROOTS_REFUSED;
	settle(roots);
	/* SAVED UNDER THE RECORD'S OWN ID, the hash every reference to it
	 * names, so one record has one row however often it is learned. */
	slot = (tag == (uint8_t)FZN_PERSIST_BLOB_ROOT_ENTRY) ? FZN_PERSIST_ROOT_ENTRY
	                                                    : FZN_PERSIST_ROOT_CHANGE;
	if (!roots->hash->hash(roots->hash->ctx, id, sizeof(id), bytes, len)
	    || fzn_persist_head_write(blob, sizeof(blob), len, tag) != FZN_PERSIST_OK)
		return FZN_NODE_ROOTS_NOT_SAVED;
	memcpy(blob + FZN_PERSIST_HEAD_LEN, bytes, len);
	if (!store->save(store->ctx, slot, id, blob, (size_t)FZN_PERSIST_HEAD_LEN + len))
		return FZN_NODE_ROOTS_NOT_SAVED;
	return FZN_NODE_ROOTS_OK;
}

/* One slot's records, admitted. Entries are admitted before changes by the
 * caller's order, though nothing here depends on it: both are sets. */
static fzn_node_roots_err_t load_slot(fzn_node_roots_t *roots, const fzn_persist_ops_t *store,
                                      fzn_persist_slot_t slot, size_t *count)
{
	static uint8_t subjects[FZN_NODE_ROOT_LOG_MAX * FZN_PUBKEY_LEN];
	size_t found = 0, i;

	if (!store->list(store->ctx, slot, subjects, FZN_NODE_ROOT_LOG_MAX, &found))
		return FZN_NODE_ROOTS_STORE;
	for (i = 0; i < found; i++) {
		uint8_t blob[CHANGE_BLOB_MAX > ENTRY_BLOB ? CHANGE_BLOB_MAX : ENTRY_BLOB];
		size_t len = 0, body;
		uint8_t tag;

		if (!store->load(store->ctx, slot, subjects + (i * (size_t)FZN_PUBKEY_LEN), blob,
		                 sizeof(blob), &len)
		    || len <= FZN_PERSIST_HEAD_LEN)
			return FZN_NODE_ROOTS_STORE;
		body = len - FZN_PERSIST_HEAD_LEN;
		tag = tag_of(blob + FZN_PERSIST_HEAD_LEN, body);
		/* THE SLOT AND THE TAG MUST AGREE: an entry filed as a change, or
		 * the reverse, is a store that was written by something else. */
		if (!tag || (slot == FZN_PERSIST_ROOT_ENTRY) != (tag == FZN_PERSIST_BLOB_ROOT_ENTRY)
		    || fzn_persist_head_check(blob, len, body, tag) != FZN_PERSIST_OK
		    || admit(roots, blob + FZN_PERSIST_HEAD_LEN, body) != FZN_ROOT_LOG_OK)
			return FZN_NODE_ROOTS_STORE;
		(*count)++;
	}
	return FZN_NODE_ROOTS_OK;
}

fzn_node_roots_err_t fzn_node_roots_load(fzn_node_roots_t *roots,
                                         const fzn_persist_ops_t *store, size_t *count)
{
	fzn_node_roots_err_t err;

	if (!roots || !store || !store->load || !store->list || !count)
		return FZN_NODE_ROOTS_MALFORMED;
	*count = 0;
	err = load_slot(roots, store, FZN_PERSIST_ROOT_ENTRY, count);
	if (err == FZN_NODE_ROOTS_OK)
		err = load_slot(roots, store, FZN_PERSIST_ROOT_CHANGE, count);
	settle(roots);
	return err;
}

fzn_node_roots_err_t fzn_node_roots_attach(fzn_node_roots_t *roots,
                                           fzn_revocation_store_t *revocations)
{
	if (!roots || !revocations)
		return FZN_NODE_ROOTS_MALFORMED;
	return fzn_revocation_store_set_roots(revocations, &roots->ops, roots->hash)
	               == FZN_CHAIN_OK
	               ? FZN_NODE_ROOTS_OK
	               : FZN_NODE_ROOTS_MALFORMED;
}
