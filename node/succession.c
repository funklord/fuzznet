/* See succession.h. */

#include "succession.h"
#include "roots.h"

#include <string.h>

#define BODY_MAX (FZN_SUCCESSION_LEN + 1u + (FZN_CHAIN_MAX_HOPS * (size_t)FZN_HOP_LEN))
#define BLOB_MAX ((size_t)FZN_PERSIST_HEAD_LEN + BODY_MAX)

fzn_node_revoke_err_t fzn_node_successions_init(fzn_node_successions_t *ns,
                                                const fzn_hash_ops_t *hash)
{
	if (!ns || !hash || !hash->hash)
		return FZN_NODE_REVOKE_MALFORMED;
	memset(ns, 0, sizeof(*ns));
	return fzn_succession_set_init(&ns->set, ns->entries, FZN_NODE_SUCCESSIONS_MAX, hash)
	               == FZN_CHAIN_OK
	               ? FZN_NODE_REVOKE_OK
	               : FZN_NODE_REVOKE_MALFORMED;
}

int fzn_node_succession_get(const fzn_persist_ops_t *store, const uint8_t subject[FZN_PUBKEY_LEN],
                            uint8_t record[FZN_SUCCESSION_LEN],
                            uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], size_t *hop_count)
{
	uint8_t blob[BLOB_MAX];
	const uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	fzn_chain_hop_t hop;
	size_t len = 0, n, i;

	if (!store || !store->load || !subject || !record || !hops || !hop_count
	    || !store->load(store->ctx, FZN_PERSIST_SUCCESSION, subject, blob, sizeof(blob), &len)
	    || len < FZN_PERSIST_HEAD_LEN + FZN_SUCCESSION_LEN + 1u)
		return 0;
	n = body[FZN_SUCCESSION_LEN];
	if (n >= FZN_CHAIN_MAX_HOPS
	    || fzn_persist_head_check(blob, len, FZN_SUCCESSION_LEN + 1u + (n * FZN_HOP_LEN),
	                              FZN_PERSIST_BLOB_SUCCESSION)
	               != FZN_PERSIST_OK)
		return 0;
	for (i = 0; i < n; i++) {
		const uint8_t *h = body + FZN_SUCCESSION_LEN + 1u + (i * FZN_HOP_LEN);

		if (fzn_hop_open(h, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK)
			return 0;
		memcpy(hops[i], h, FZN_HOP_LEN);
	}
	memcpy(record, body, FZN_SUCCESSION_LEN);
	*hop_count = n;
	return 1;
}

/* Saved under the record's hash, so one succession has one row. */
static int save(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                const uint8_t record[FZN_SUCCESSION_LEN], const uint8_t (*hops)[FZN_HOP_LEN],
                size_t hop_count)
{
	uint8_t blob[BLOB_MAX], subject[FZN_PUBKEY_LEN];
	size_t body = FZN_SUCCESSION_LEN + 1u + (hop_count * FZN_HOP_LEN), i;

	if (hop_count >= FZN_CHAIN_MAX_HOPS || !store->save
	    || !hash->hash(hash->ctx, subject, sizeof(subject), record, FZN_SUCCESSION_LEN)
	    || fzn_persist_head_write(blob, sizeof(blob), body, FZN_PERSIST_BLOB_SUCCESSION)
	               != FZN_PERSIST_OK)
		return 0;
	memcpy(blob + FZN_PERSIST_HEAD_LEN, record, FZN_SUCCESSION_LEN);
	blob[FZN_PERSIST_HEAD_LEN + FZN_SUCCESSION_LEN] = (uint8_t)hop_count;
	for (i = 0; i < hop_count; i++)
		memcpy(blob + FZN_PERSIST_HEAD_LEN + FZN_SUCCESSION_LEN + 1u + (i * FZN_HOP_LEN),
		       hops[i], FZN_HOP_LEN);
	return store->save(store->ctx, FZN_PERSIST_SUCCESSION, subject, blob,
	                   (size_t)FZN_PERSIST_HEAD_LEN + body);
}

/* Admit one with its chain: the shared half of loading and learning. */
static fzn_chain_err_t admit(fzn_node_successions_t *ns, fzn_revocation_store_t *revocations,
                             const uint8_t root[FZN_PUBKEY_LEN], const fzn_sign_ops_t *sign,
                             const uint8_t record[FZN_SUCCESSION_LEN],
                             const uint8_t (*hops)[FZN_HOP_LEN], size_t hop_count)
{
	fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];
	size_t i;

	if (hop_count >= FZN_CHAIN_MAX_HOPS)
		return FZN_CHAIN_ERR_MALFORMED;
	for (i = 0; i < hop_count; i++)
		if (fzn_hop_open(hops[i], FZN_HOP_LEN, &opened[i]) != FZN_CHAIN_OK)
			return FZN_CHAIN_ERR_SHAPE;
	return fzn_succession_admit(&ns->set, revocations, record, FZN_SUCCESSION_LEN,
	                            hop_count ? opened : NULL, hop_count, root, sign);
}

fzn_persist_err_t fzn_node_successions_load(fzn_node_successions_t *ns,
                                            const fzn_persist_ops_t *store,
                                            fzn_revocation_store_t *revocations,
                                            const uint8_t root[FZN_PUBKEY_LEN],
                                            const fzn_sign_ops_t *sign, size_t *count)
{
	static uint8_t rows[FZN_NODE_SUCCESSIONS_MAX * FZN_PUBKEY_LEN];
	static uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	size_t found = 0, i, n = 0;

	if (!ns || !store || !store->load || !revocations || !root || !sign || !count)
		return FZN_PERSIST_ERR_MALFORMED;
	*count = 0;
	if (!store->list)
		return FZN_PERSIST_ERR_BACKEND;
	if (!store->list(store->ctx, FZN_PERSIST_SUCCESSION, rows, FZN_NODE_SUCCESSIONS_MAX, &found))
		return FZN_PERSIST_ERR_BACKEND;
	for (i = 0; i < found; i++) {
		uint8_t record[FZN_SUCCESSION_LEN];

		if (!fzn_node_succession_get(store, rows + (i * (size_t)FZN_PUBKEY_LEN), record, hops,
		                             &n)
		    || admit(ns, revocations, root, sign, record, (const uint8_t (*)[FZN_HOP_LEN])hops,
		             n) != FZN_CHAIN_OK)
			return FZN_PERSIST_ERR_SHAPE;
		(*count)++;
	}
	return FZN_PERSIST_OK;
}

fzn_node_revoke_err_t fzn_node_successions_learn(fzn_node_successions_t *ns,
                                                 const fzn_persist_ops_t *store,
                                                 fzn_revocation_store_t *revocations,
                                                 const uint8_t root[FZN_PUBKEY_LEN],
                                                 const fzn_sign_ops_t *sign,
                                                 const uint8_t record[FZN_SUCCESSION_LEN],
                                                 const uint8_t (*hops)[FZN_HOP_LEN],
                                                 size_t hop_count)
{
	if (!ns || !store || !revocations || !root || !sign || !record || (hop_count && !hops))
		return FZN_NODE_REVOKE_MALFORMED;
	if (admit(ns, revocations, root, sign, record, hops, hop_count) != FZN_CHAIN_OK)
		return FZN_NODE_REVOKE_STORE_REFUSED;
	return save(store, ns->set.hash, record, hops, hop_count) ? FZN_NODE_REVOKE_OK
	                                                         : FZN_NODE_REVOKE_NOT_SAVED;
}

fzn_node_revoke_err_t fzn_node_succession_issue(fzn_node_successions_t *ns,
                                                struct fzn_node_roots *roots,
                                                const fzn_persist_ops_t *store,
                                                const fzn_node_identity_t *id,
                                                const fzn_node_admin_chain_t *mine,
                                                fzn_revocation_store_t *revocations,
                                                const uint8_t root[FZN_PUBKEY_LEN],
                                                const uint8_t old[FZN_PUBKEY_LEN],
                                                const uint8_t new_key[FZN_PUBKEY_LEN],
                                                const uint8_t cut[FZN_SUCCESSION_ID_LEN],
                                                uint8_t id_out[FZN_SUCCESSION_ID_LEN])
{
	uint8_t record[FZN_SUCCESSION_LEN];
	const uint8_t *as = NULL;
	const fzn_sign_ops_t *sign = NULL;
	size_t n = 0;
	fzn_node_revoke_err_t err;

	if (!ns || !store || !id || !id->sign || !revocations || !root || !old || !new_key)
		return FZN_NODE_REVOKE_MALFORMED;
	/* AS A ROOT, the node's acting root (sec 409); else AS AN ADMIN, on
	 * its admin chain (sec 416). A root's needs no chain. */
	if (roots && fzn_node_roots_acting(roots, id->pubkey, id->sign, &as, &sign)) {
		n = 0;
	} else if (mine && mine->hop_count) {
		as = id->pubkey;
		sign = id->sign;
		n = mine->hop_count;
	} else {
		return FZN_NODE_REVOKE_NOT_ROOT;
	}
	if (fzn_succession_issue(as, old, new_key, cut, sign, record) != FZN_CHAIN_OK)
		return FZN_NODE_REVOKE_MALFORMED;
	/* LOGGED UNDER ITS SIGNER, as every act is since sec 497: a re-key a
	 * stolen admin signed after its own line falls with it. */
	if (roots
	    && fzn_node_roots_log_act(roots, store, as, sign, (uint8_t)FZN_ROOT_ACT_GRANT, record,
	                              sizeof(record))
	               != FZN_NODE_ROOTS_OK)
		return FZN_NODE_REVOKE_NOT_SAVED;
	err = fzn_node_successions_learn(ns, store, revocations, root, id->sign, record,
	                                 n ? (const uint8_t (*)[FZN_HOP_LEN])mine->hops : NULL, n);
	if (err == FZN_NODE_REVOKE_OK && id_out
	    && !ns->set.hash->hash(ns->set.hash->ctx, id_out, FZN_SUCCESSION_ID_LEN, record,
	                           sizeof(record)))
		return FZN_NODE_REVOKE_MALFORMED;
	return err;
}

int fzn_node_successions_resolve(const fzn_node_successions_t *ns,
                                 const fzn_revocation_store_t *revocations,
                                 const uint8_t root[FZN_PUBKEY_LEN],
                                 const uint8_t key[FZN_PUBKEY_LEN],
                                 uint8_t out[FZN_PUBKEY_LEN])
{
	if (!ns)
		return 0;
	return fzn_succession_resolve(&ns->set, revocations, root, key, out);
}
