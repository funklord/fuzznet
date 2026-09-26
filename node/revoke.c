/* See revoke.h. */

#include "revoke.h"

#include <string.h>

#define BLOB_LEN ((size_t)FZN_PERSIST_HEAD_LEN + FZN_REVOCATION_LEN)

const char *fzn_node_revoke_err_str(fzn_node_revoke_err_t err)
{
	switch (err) {
	case FZN_NODE_REVOKE_OK:
		return "ok";
	case FZN_NODE_REVOKE_MALFORMED:
		return "malformed";
	case FZN_NODE_REVOKE_NOT_ROOT:
		return "this node is not its own root, so it cannot revoke as one";
	case FZN_NODE_REVOKE_ALREADY:
		return "already revoked by this node";
	case FZN_NODE_REVOKE_STORE_REFUSED:
		return "the revocation would not mint or the store would not take it";
	case FZN_NODE_REVOKE_NOT_SAVED:
		return "revoked until a restart: the record was not saved";
	}
	return "unknown";
}

/* The latest record this node issued for `grantee`, into `out`. 1 when one
 * was loaded and opens, 0 when the store has none or cannot say. */
static int load_issued(const fzn_persist_ops_t *store, const uint8_t grantee[FZN_PUBKEY_LEN],
                       uint8_t out[FZN_REVOCATION_LEN])
{
	uint8_t blob[BLOB_LEN];
	fzn_revocation_record_t rec;
	size_t len = 0;

	if (!store->load(store->ctx, FZN_PERSIST_ISSUED_REVOCATION, grantee, blob, sizeof(blob),
	                 &len))
		return 0;
	if (fzn_persist_head_check(blob, len, FZN_REVOCATION_LEN, FZN_PERSIST_BLOB_REVOCATION)
	            != FZN_PERSIST_OK
	    || fzn_revocation_open(blob + FZN_PERSIST_HEAD_LEN, FZN_REVOCATION_LEN, &rec)
	               != FZN_CHAIN_OK
	    || memcmp(fzn_revocation_grantee(rec), grantee, FZN_PUBKEY_LEN) != 0)
		return 0;
	memcpy(out, blob + FZN_PERSIST_HEAD_LEN, FZN_REVOCATION_LEN);
	return 1;
}

fzn_node_revoke_err_t fzn_node_revoke(const fzn_node_identity_t *id,
                                      const uint8_t root[FZN_PUBKEY_LEN],
                                      const fzn_cap_id_t *capability,
                                      const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                      fzn_revocation_store_t *revocations,
                                      const fzn_persist_ops_t *store)
{
	uint8_t previous[FZN_REVOCATION_LEN];
	uint8_t record[FZN_REVOCATION_LEN];
	uint8_t blob[BLOB_LEN];
	fzn_revocation_record_t prev_rec, rec;
	fzn_chain_err_t cerr;

	if (!id || !id->sign || !id->hash || !root || !capability || !grantee || !revocations
	    || !store || !store->load || !store->save)
		return FZN_NODE_REVOKE_MALFORMED;
	if (memcmp(root, id->pubkey, FZN_PUBKEY_LEN) != 0)
		return FZN_NODE_REVOKE_NOT_ROOT;

	/* A FIRST REVOCATION, OR ONE NAMING WHAT IT FOLLOWS. The store refuses
	 * a zero `supersedes` over a withdrawn pair (revocation.h), so after a
	 * withdrawal the re-revocation names the revocation that withdrawal
	 * undid -- a predecessor, which is all admission requires. */
	if (load_issued(store, grantee, previous)
	    && fzn_revocation_open(previous, sizeof(previous), &prev_rec) == FZN_CHAIN_OK) {
		if (!fzn_revocation_is_withdrawal(prev_rec))
			return FZN_NODE_REVOKE_ALREADY;
		cerr = fzn_revocation_reissue(id->pubkey, capability, grantee, now,
		                              fzn_revocation_supersedes(prev_rec), id->sign,
		                              record);
	} else {
		cerr = fzn_revocation_issue(id->pubkey, capability, grantee, now, id->sign, record);
	}
	if (cerr != FZN_CHAIN_OK
	    || fzn_revocation_open(record, sizeof(record), &rec) != FZN_CHAIN_OK
	    || fzn_revocation_admit(revocations, fzn_revocation_offer_root(rec), root, id->sign,
	                            id->hash, NULL)
	               != FZN_CHAIN_OK)
		return FZN_NODE_REVOKE_STORE_REFUSED;

	if (fzn_persist_head_write(blob, sizeof(blob), FZN_REVOCATION_LEN,
	                           FZN_PERSIST_BLOB_REVOCATION)
	            != FZN_PERSIST_OK)
		return FZN_NODE_REVOKE_NOT_SAVED;
	memcpy(blob + FZN_PERSIST_HEAD_LEN, record, FZN_REVOCATION_LEN);
	if (!store->save(store->ctx, FZN_PERSIST_ISSUED_REVOCATION, grantee, blob, sizeof(blob)))
		return FZN_NODE_REVOKE_NOT_SAVED;
	return FZN_NODE_REVOKE_OK;
}

fzn_persist_err_t fzn_node_revocations_load(const fzn_persist_ops_t *store,
                                            fzn_revocation_store_t *revocations,
                                            const uint8_t root[FZN_PUBKEY_LEN],
                                            const fzn_sign_ops_t *sign,
                                            const fzn_hash_ops_t *hash, size_t *count)
{
	uint8_t subjects[FZN_NODE_REVOCATIONS_MAX * FZN_PUBKEY_LEN];
	size_t found = 0, i;

	if (!store || !store->load || !revocations || !root || !sign || !hash || !count)
		return FZN_PERSIST_ERR_MALFORMED;
	*count = 0;
	if (!store->list)
		return FZN_PERSIST_ERR_BACKEND;
	if (!store->list(store->ctx, FZN_PERSIST_ISSUED_REVOCATION, subjects,
	                 FZN_NODE_REVOCATIONS_MAX, &found))
		return FZN_PERSIST_ERR_BACKEND;

	for (i = 0; i < found; i++) {
		uint8_t record[FZN_REVOCATION_LEN];
		fzn_revocation_record_t rec;

		/* FILED UNDER ONE GRANTEE AND NAMING ANOTHER is refused inside
		 * `load_issued`, the check every per-subject load here makes. */
		if (!load_issued(store, subjects + (i * (size_t)FZN_PUBKEY_LEN), record))
			return FZN_PERSIST_ERR_SHAPE;
		if (fzn_revocation_open(record, sizeof(record), &rec) != FZN_CHAIN_OK
		    || fzn_revocation_admit(revocations, fzn_revocation_offer_root(rec), root, sign,
		                            hash, NULL)
		               != FZN_CHAIN_OK)
			return FZN_PERSIST_ERR_SHAPE;
	}
	*count = found;
	return FZN_PERSIST_OK;
}
