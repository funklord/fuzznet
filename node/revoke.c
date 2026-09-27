/* See revoke.h. */

#include "revoke.h"

#include "../local/vocabulary.h"

#include <stdio.h>
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

/* The record under `slot` for `grantee`, into `out`. 1 when one was loaded,
 * opens and names that grantee; 0 when the store has none or cannot say. */
static int load_slot(const fzn_persist_ops_t *store, fzn_persist_slot_t slot,
                     const uint8_t grantee[FZN_PUBKEY_LEN], uint8_t out[FZN_REVOCATION_LEN])
{
	uint8_t blob[BLOB_LEN];
	fzn_revocation_record_t rec;
	size_t len = 0;

	if (!store->load(store->ctx, slot, grantee, blob, sizeof(blob), &len))
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
	if (load_slot(store, FZN_PERSIST_ISSUED_REVOCATION, grantee, previous)
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

int fzn_node_issued_revocation(const fzn_persist_ops_t *store,
                               const uint8_t grantee[FZN_PUBKEY_LEN],
                               uint8_t record[FZN_REVOCATION_LEN])
{
	if (!store || !store->load || !grantee || !record)
		return 0;
	return load_slot(store, FZN_PERSIST_ISSUED_REVOCATION, grantee, record);
}

static int save_slot(const fzn_persist_ops_t *store, fzn_persist_slot_t slot,
                     const uint8_t grantee[FZN_PUBKEY_LEN],
                     const uint8_t record[FZN_REVOCATION_LEN])
{
	uint8_t blob[BLOB_LEN];

	if (fzn_persist_head_write(blob, sizeof(blob), FZN_REVOCATION_LEN,
	                           FZN_PERSIST_BLOB_REVOCATION)
	    != FZN_PERSIST_OK)
		return 0;
	memcpy(blob + FZN_PERSIST_HEAD_LEN, record, FZN_REVOCATION_LEN);
	return store->save(store->ctx, slot, grantee, blob, sizeof(blob));
}

fzn_persist_err_t fzn_node_revocations_load(const fzn_persist_ops_t *store,
                                            fzn_revocation_store_t *revocations,
                                            const uint8_t root[FZN_PUBKEY_LEN],
                                            const fzn_sign_ops_t *sign,
                                            const fzn_hash_ops_t *hash, size_t *count)
{
	static const fzn_persist_slot_t SLOTS[2] = { FZN_PERSIST_ISSUED_REVOCATION,
		                                     FZN_PERSIST_LEARNED_REVOCATION };
	uint8_t subjects[FZN_NODE_REVOCATIONS_MAX * FZN_PUBKEY_LEN];
	size_t total = 0, s, i;

	if (!store || !store->load || !revocations || !root || !sign || !hash || !count)
		return FZN_PERSIST_ERR_MALFORMED;
	*count = 0;
	if (!store->list)
		return FZN_PERSIST_ERR_BACKEND;

	for (s = 0; s < 2u; s++) {
		size_t found = 0;

		if (!store->list(store->ctx, SLOTS[s], subjects, FZN_NODE_REVOCATIONS_MAX, &found))
			return FZN_PERSIST_ERR_BACKEND;
		for (i = 0; i < found; i++) {
			uint8_t record[FZN_REVOCATION_LEN];
			fzn_revocation_record_t rec;

			/* FILED UNDER ONE GRANTEE AND NAMING ANOTHER is refused
			 * inside `load_slot`, the check every load here makes. */
			if (!load_slot(store, SLOTS[s], subjects + (i * (size_t)FZN_PUBKEY_LEN), record)
			    || fzn_revocation_open(record, sizeof(record), &rec) != FZN_CHAIN_OK)
				return FZN_PERSIST_ERR_SHAPE;
			/* From before a join: see the header. */
			if (memcmp(fzn_revocation_issuer(rec), root, FZN_PUBKEY_LEN) != 0)
				continue;
			if (fzn_revocation_admit(revocations, fzn_revocation_offer_root(rec), root, sign,
			                         hash, NULL)
			    != FZN_CHAIN_OK)
				return FZN_PERSIST_ERR_SHAPE;
			total++;
		}
	}
	*count = total;
	return FZN_PERSIST_OK;
}

const char *fzn_node_pull_err_str(fzn_node_pull_err_t err)
{
	switch (err) {
	case FZN_NODE_PULL_OK:
		return "ok";
	case FZN_NODE_PULL_MALFORMED:
		return "malformed";
	case FZN_NODE_PULL_NO_ANSWER:
		return "the root did not answer, or did not answer ok";
	case FZN_NODE_PULL_SHAPE:
		return "the root's answer did not parse as a page of revocations";
	case FZN_NODE_PULL_REFUSED:
		return "a revocation would not admit as the root's, or the store is full";
	case FZN_NODE_PULL_NOT_SAVED:
		return "learned until a restart: a revocation was not saved";
	}
	return "unknown";
}

static int unhex_record(const uint8_t *text, uint8_t out[FZN_REVOCATION_LEN])
{
	size_t i;

	for (i = 0; i < (size_t)FZN_REVOCATION_LEN * 2u; i++) {
		uint8_t c = text[i];
		unsigned v;

		if (c >= '0' && c <= '9')
			v = (unsigned)(c - '0');
		else if (c >= 'a' && c <= 'f')
			v = 10u + (unsigned)(c - 'a');
		else
			return 0;
		if (i % 2u == 0u)
			out[i / 2u] = (uint8_t)(v << 4);
		else
			out[i / 2u] = (uint8_t)(out[i / 2u] | v);
	}
	return 1;
}

/* A decimal count off the front of `text`, and where it ended. */
static int take_count(const uint8_t *text, size_t len, size_t *at, size_t *value)
{
	size_t v = 0, start = *at;

	while (*at < len && text[*at] >= '0' && text[*at] <= '9') {
		if (v > FZN_NODE_REVOCATIONS_MAX * 16u)
			return 0;
		v = (v * 10u) + (size_t)(text[*at] - '0');
		(*at)++;
	}
	*value = v;
	return *at > start;
}

fzn_node_pull_err_t fzn_node_revocations_absorb(const uint8_t *reply, size_t reply_len,
                                                size_t from,
                                                const uint8_t root[FZN_PUBKEY_LEN],
                                                const fzn_sign_ops_t *sign,
                                                const fzn_hash_ops_t *hash,
                                                fzn_revocation_store_t *revocations,
                                                const fzn_persist_ops_t *store,
                                                size_t *learned, size_t *next, size_t *total)
{
	const uint8_t *detail = NULL;
	size_t detail_len = 0, at = 0, off = 0, on_page = 0;

	if (!reply || !root || !sign || !hash || !revocations || !store || !store->save
	    || !learned || !next || !total)
		return FZN_NODE_PULL_MALFORMED;
	if (fzn_reply_of(reply, reply_len, &detail, &detail_len) != FZN_REPLY_OK)
		return FZN_NODE_PULL_NO_ANSWER;
	if (detail_len && detail[detail_len - 1u] == '\n')
		detail_len--;

	/* `TOTAL FROM` and then records, each a space and 404 hex. */
	if (!take_count(detail, detail_len, &at, total) || at >= detail_len
	    || detail[at++] != ' ' || !take_count(detail, detail_len, &at, &off) || off != from
	    || *total > FZN_NODE_REVOCATIONS_MAX)
		return FZN_NODE_PULL_SHAPE;
	while (at < detail_len) {
		uint8_t record[FZN_REVOCATION_LEN];
		fzn_revocation_record_t rec;

		if (detail[at] != ' ' || detail_len - at < 1u + (FZN_REVOCATION_LEN * 2u)
		    || !unhex_record(detail + at + 1u, record)
		    || fzn_revocation_open(record, sizeof(record), &rec) != FZN_CHAIN_OK)
			return FZN_NODE_PULL_SHAPE;
		at += 1u + (FZN_REVOCATION_LEN * 2u);
		if (fzn_revocation_admit(revocations, fzn_revocation_offer_root(rec), root, sign,
		                         hash, NULL)
		    != FZN_CHAIN_OK)
			return FZN_NODE_PULL_REFUSED;
		if (!save_slot(store, FZN_PERSIST_LEARNED_REVOCATION, fzn_revocation_grantee(rec),
		               record))
			return FZN_NODE_PULL_NOT_SAVED;
		(*learned)++;
		on_page++;
	}
	*next = from + on_page;
	/* A PAGE THAT ADVANCES NOTHING short of the total is a root that will
	 * never finish, and asking again would ask the same thing. */
	if (on_page == 0u && *next < *total)
		return FZN_NODE_PULL_SHAPE;
	return FZN_NODE_PULL_OK;
}

fzn_node_pull_err_t fzn_node_revocations_pull(fzn_caller_t *caller,
                                              const uint8_t root[FZN_PUBKEY_LEN],
                                              const fzn_sign_ops_t *sign,
                                              const fzn_hash_ops_t *hash, uint64_t now,
                                              fzn_revocation_store_t *revocations,
                                              const fzn_persist_ops_t *store,
                                              size_t *learned)
{
	static uint8_t reply[FZN_REPLY_MAX + 1u];
	size_t from = 0, pages = 0;

	if (!caller || !learned)
		return FZN_NODE_PULL_MALFORMED;
	*learned = 0;

	/* BOUNDED BY THE PAGES A FULL STORE COULD NEED, not by the root's
	 * word: a root answering a total it never delivers must not keep a
	 * member asking for ever. */
	while (pages++ <= FZN_NODE_REVOCATIONS_MAX) {
		char ask[32];
		size_t reply_len = 0, next = 0, total = 0;
		uint32_t msg = 0;
		fzn_node_pull_err_t err;
		int n;

		n = snprintf(ask, sizeof(ask), "get revocation %zu", from);
		if (n < 0 || (size_t)n >= sizeof(ask))
			return FZN_NODE_PULL_MALFORMED;
		if (fzn_caller_send(caller, (const uint8_t *)ask, (size_t)n, now + 300u, &msg)
		            != FZN_CALLER_OK
		    || fzn_caller_recv(caller, msg, reply, sizeof(reply), &reply_len, 3000u)
		               != FZN_CALLER_OK)
			return FZN_NODE_PULL_NO_ANSWER;
		err = fzn_node_revocations_absorb(reply, reply_len, from, root, sign, hash,
		                                  revocations, store, learned, &next, &total);
		if (err != FZN_NODE_PULL_OK)
			return err;
		if (next >= total)
			return FZN_NODE_PULL_OK;
		from = next;
	}
	return FZN_NODE_PULL_SHAPE;
}
