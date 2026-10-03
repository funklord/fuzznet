/* See revoke.h. */

#include "revoke.h"
#include "roots.h"

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
		return "this node is not its own root and holds no chain it may grant through";
	case FZN_NODE_REVOKE_ALREADY:
		return "already revoked by this node";
	case FZN_NODE_REVOKE_STORE_REFUSED:
		return "the revocation would not mint or the store would not take it";
	case FZN_NODE_REVOKE_NOT_SAVED:
		return "in force until a restart: the record was not saved";
	case FZN_NODE_REVOKE_NOT_REVOKED:
		return "this node holds no revocation of that grantee to undo";
	case FZN_NODE_REVOKE_NOT_ADMIN:
		return "the admin chain does not verify from a root to this node, delegable";
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

/* `authority` opened into `hops`. 1 when every hop opens. Standing is
 * decided by the caller and by admission, not here. */
static int open_authority(const fzn_node_authority_t *authority,
                          fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS])
{
	size_t i;

	if (!authority->hops || authority->hop_count == 0u
	    || authority->hop_count > FZN_CHAIN_MAX_HOPS)
		return 0;
	for (i = 0; i < authority->hop_count; i++)
		if (fzn_hop_open(authority->hops[i], FZN_HOP_LEN, &hops[i]) != FZN_CHAIN_OK)
			return 0;
	return 1;
}

/* Revoke, or with `withdraw` undo the revocation held for `grantee`: one
 * path, so standing, admission and the save are the same for both. A
 * withdrawal takes its capability from the record it undoes. */
static fzn_node_revoke_err_t issue(const fzn_node_identity_t *id,
                                   const uint8_t root[FZN_PUBKEY_LEN],
                                   const fzn_node_authority_t *authority,
                                   const fzn_cap_id_t *capability,
                                   const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                   fzn_revocation_store_t *revocations,
                                   const fzn_persist_ops_t *store, int withdraw)
{
	uint8_t previous[FZN_REVOCATION_LEN];
	uint8_t record[FZN_REVOCATION_LEN];
	uint8_t blob[BLOB_LEN];
	fzn_revocation_record_t prev_rec, rec;
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	fzn_chain_err_t cerr;
	int held;

	if (!id || !id->sign || !id->hash || !id->hash->hash || !root
	    || (!withdraw && !capability) || !grantee || !revocations || !store || !store->load
	    || !store->save)
		return FZN_NODE_REVOKE_MALFORMED;
	/* STANDING BEFORE ANYTHING IS MINTED: the root is its own, and a member
	 * shows a delegable chain naming it as the last grantee. Admission
	 * would refuse a record without standing anyway; asking first keeps a
	 * refused revoke from being reported as a full store. */
	if (!authority) {
		if (memcmp(root, id->pubkey, FZN_PUBKEY_LEN) != 0)
			return FZN_NODE_REVOKE_NOT_ROOT;
	} else if (!open_authority(authority, hops)
	           || memcmp(fzn_hop_grantee(hops[authority->hop_count - 1u]), id->pubkey,
	                     FZN_PUBKEY_LEN) != 0
	           || !fzn_hop_delegable(hops[authority->hop_count - 1u])) {
		return FZN_NODE_REVOKE_NOT_ROOT;
	}

	held = load_slot(store, FZN_PERSIST_ISSUED_REVOCATION, grantee, previous)
	       && fzn_revocation_open(previous, sizeof(previous), &prev_rec) == FZN_CHAIN_OK;

	/* A WITHDRAWAL NAMES THE WHOLE RECORD IT UNDOES, by its hash -- the
	 * identity admission compares (revocation.h). Only a revocation this
	 * node holds in force can be undone: nothing held, or a withdrawal
	 * held, is a grantee this node has not revoked. */
	if (withdraw) {
		uint8_t target[FZN_REVOCATION_ID_LEN];

		if (!held || fzn_revocation_is_withdrawal(prev_rec))
			return FZN_NODE_REVOKE_NOT_REVOKED;
		if (!id->hash->hash(id->hash->ctx, target, sizeof(target), previous,
		                    sizeof(previous)))
			return FZN_NODE_REVOKE_STORE_REFUSED;
		cerr = fzn_revocation_issue_withdrawal(id->pubkey,
		                                       fzn_revocation_capability(prev_rec),
		                                       grantee, now, fzn_revocation_epoch(prev_rec),
		                                       target, id->sign, record);
	} else if (held) {
		/* A FIRST REVOCATION, OR ONE NAMING WHAT IT FOLLOWS. The store
		 * refuses a zero `supersedes` over a withdrawn pair
		 * (revocation.h), so after a withdrawal the re-revocation names
		 * the revocation that withdrawal undid -- a predecessor, which is
		 * all admission requires. */
		if (!fzn_revocation_is_withdrawal(prev_rec))
			return FZN_NODE_REVOKE_ALREADY;
		cerr = fzn_revocation_reissue(id->pubkey, capability, grantee, now,
		                              fzn_revocation_current_epoch(revocations, root, capability,
		                                                           grantee),
		                              fzn_revocation_supersedes(prev_rec), id->sign,
		                              record);
	} else {
		cerr = fzn_revocation_issue(id->pubkey, capability, grantee, now,
		                            fzn_revocation_current_epoch(revocations, root, capability,
		                                                         grantee),
		                            id->sign, record);
	}
	if (cerr != FZN_CHAIN_OK
	    || fzn_revocation_open(record, sizeof(record), &rec) != FZN_CHAIN_OK
	    || fzn_revocation_admit(revocations,
	                            authority ? fzn_revocation_offer_chain(rec, hops,
	                                                                   authority->hop_count)
	                                      : fzn_revocation_offer_root(rec),
	                            root, id->sign, id->hash, NULL)
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

fzn_node_revoke_err_t fzn_node_revoke(const fzn_node_identity_t *id,
                                      const uint8_t root[FZN_PUBKEY_LEN],
                                      const fzn_node_authority_t *authority,
                                      const fzn_cap_id_t *capability,
                                      const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                      fzn_revocation_store_t *revocations,
                                      const fzn_persist_ops_t *store)
{
	return issue(id, root, authority, capability, grantee, now, revocations, store, 0);
}

fzn_node_revoke_err_t fzn_node_unrevoke(const fzn_node_identity_t *id,
                                        const uint8_t root[FZN_PUBKEY_LEN],
                                        const fzn_node_authority_t *authority,
                                        const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                        fzn_revocation_store_t *revocations,
                                        const fzn_persist_ops_t *store)
{
	return issue(id, root, authority, NULL, grantee, now, revocations, store, 1);
}

int fzn_node_issued_revocation(const fzn_persist_ops_t *store,
                               const uint8_t grantee[FZN_PUBKEY_LEN],
                               uint8_t record[FZN_REVOCATION_LEN])
{
	if (!store || !store->load || !grantee || !record)
		return 0;
	return load_slot(store, FZN_PERSIST_ISSUED_REVOCATION, grantee, record);
}

static int load_vote(const fzn_persist_ops_t *store, const uint8_t subject[FZN_PUBKEY_LEN],
                     uint8_t record[FZN_REVOCATION_LEN],
                     uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], size_t *hop_count);
static int load_confirm(const fzn_persist_ops_t *store, const uint8_t subject[FZN_PUBKEY_LEN],
                        uint8_t record[FZN_ADMIN_CONFIRM_LEN],
                        uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], size_t *hop_count);

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
                                            const fzn_node_authority_t *authority,
                                            const fzn_node_authority_t *admin,
                                            const fzn_sign_ops_t *sign,
                                            const fzn_hash_ops_t *hash, size_t *count)
{
	static const fzn_persist_slot_t SLOTS[2] = { FZN_PERSIST_ISSUED_REVOCATION,
		                                     FZN_PERSIST_LEARNED_REVOCATION };
	uint8_t subjects[FZN_NODE_REVOCATIONS_MAX * FZN_PUBKEY_LEN];
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS], admin_hops[FZN_CHAIN_MAX_HOPS];
	const uint8_t *self = NULL, *admin_self = NULL;
	const fzn_cap_id_t *granted = NULL;
	size_t total = 0, s, i;

	if (!store || !store->load || !revocations || !root || !sign || !hash || !count)
		return FZN_PERSIST_ERR_MALFORMED;
	if (authority) {
		if (!open_authority(authority, hops))
			return FZN_PERSIST_ERR_MALFORMED;
		self = fzn_hop_grantee(hops[authority->hop_count - 1u]);
		granted = fzn_hop_capability(hops[authority->hop_count - 1u]);
	}
	/* THIS NODE'S ADMIN CHAIN, sec 416, used only by a store that knows the
	 * admin capability it carries. */
	if (admin) {
		if (!open_authority(admin, admin_hops))
			return FZN_PERSIST_ERR_MALFORMED;
		if (revocations->has_admin
		    && memcmp(fzn_hop_capability(admin_hops[admin->hop_count - 1u]),
		              &revocations->admin_capability, sizeof(fzn_cap_id_t)) == 0)
			admin_self = fzn_hop_grantee(admin_hops[admin->hop_count - 1u]);
	}
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
			fzn_revocation_offer_t offer;

			/* AN ADMIN CHAIN FIRST, sec 416: an admin's vote counts for
			 * any grantee, and it is the chain the node votes on. */
			if (memcmp(fzn_revocation_issuer(rec), root, FZN_PUBKEY_LEN) == 0)
				offer = fzn_revocation_offer_root(rec);
			else if (admin_self
			         && memcmp(fzn_revocation_issuer(rec), admin_self, FZN_PUBKEY_LEN) == 0)
				offer = fzn_revocation_offer_chain(rec, admin_hops, admin->hop_count);
			else if (self && memcmp(fzn_revocation_issuer(rec), self, FZN_PUBKEY_LEN) == 0
			         && memcmp(fzn_revocation_capability(rec), granted,
			                   sizeof(*granted)) == 0)
				offer = fzn_revocation_offer_chain(rec, hops, authority->hop_count);
			else
				continue;	/* see the header */
			if (fzn_revocation_admit(revocations, offer, root, sign, hash, NULL)
			    != FZN_CHAIN_OK)
				return FZN_PERSIST_ERR_SHAPE;
			total++;
		}
	}

	/* THE VOTES LEARNED FROM PEERS, each with the chain it came with, and
	 * each refused as fatally as the two slots above: it was admitted once
	 * and saved only because it was, so one that will not admit again is a
	 * store that changed underneath this node. sec 399. */
	{
		static uint8_t votes[FZN_NODE_REVOCATIONS_MAX * FZN_PUBKEY_LEN];
		static uint8_t vote_hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
		size_t found = 0, n = 0, h;

		if (!store->list(store->ctx, FZN_PERSIST_VOTE, votes, FZN_NODE_REVOCATIONS_MAX,
		                 &found))
			return FZN_PERSIST_ERR_BACKEND;
		for (i = 0; i < found; i++) {
			uint8_t record[FZN_REVOCATION_LEN];
			fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];
			fzn_revocation_record_t rec;

			if (!load_vote(store, votes + (i * (size_t)FZN_PUBKEY_LEN), record, vote_hops,
			               &n)
			    || fzn_revocation_open(record, sizeof(record), &rec) != FZN_CHAIN_OK)
				return FZN_PERSIST_ERR_SHAPE;
			for (h = 0; h < n; h++)
				if (fzn_hop_open(vote_hops[h], FZN_HOP_LEN, &opened[h]) != FZN_CHAIN_OK)
					return FZN_PERSIST_ERR_SHAPE;
			/* A COPY SUPERSEDED IN ANOTHER SLOT is not a changed store:
			 * this node's own vote comes back from a peer and is kept
			 * here, and a later withdrawal of it lands in slot 9, which
			 * was admitted above. Refused with the triple already held,
			 * it is skipped; refused with nothing held, it is fatal. */
			if (fzn_revocation_admit(revocations,
			                         n ? fzn_revocation_offer_chain(rec, opened, n)
			                           : fzn_revocation_offer_root(rec),
			                         root, sign, hash, NULL)
			    != FZN_CHAIN_OK) {
				if (fzn_revocation_known(revocations, fzn_revocation_issuer(rec),
				                         fzn_revocation_capability(rec),
				                         fzn_revocation_grantee(rec)))
					continue;
				return FZN_PERSIST_ERR_SHAPE;
			}
			total++;
		}
	}

	/* THE CONFIRMATIONS, sec 415, as fatally as the votes -- each admitted
	 * once and saved because it was -- and only into a store that keeps a
	 * table for them. One that does not skips them; they stay stored, and
	 * this node still serves them onward. */
	if (revocations->confirms) {
		static uint8_t rows[FZN_NODE_REVOCATIONS_MAX * FZN_PUBKEY_LEN];
		static uint8_t confirm_hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
		size_t found = 0, n = 0, h;

		if (!store->list(store->ctx, FZN_PERSIST_ADMIN_CONFIRM, rows,
		                 FZN_NODE_REVOCATIONS_MAX, &found))
			return FZN_PERSIST_ERR_BACKEND;
		for (i = 0; i < found; i++) {
			uint8_t record[FZN_ADMIN_CONFIRM_LEN];
			fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];

			if (!load_confirm(store, rows + (i * (size_t)FZN_PUBKEY_LEN), record,
			                  confirm_hops, &n))
				return FZN_PERSIST_ERR_SHAPE;
			for (h = 0; h < n; h++)
				if (fzn_hop_open(confirm_hops[h], FZN_HOP_LEN, &opened[h]) != FZN_CHAIN_OK)
					return FZN_PERSIST_ERR_SHAPE;
			if (fzn_revocation_confirm_admit(revocations, record, sizeof(record), opened, n,
			                                 root, sign)
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
		return "the peer did not answer, or did not answer ok";
	case FZN_NODE_PULL_SHAPE:
		return "the peer's answer did not parse as a page of revocations or votes";
	case FZN_NODE_PULL_REFUSED:
		return "a revocation would not admit, or the store is full";
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

	/* `TOTAL FROM` and then records, each a space and 420 hex. */
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

/* ---- votes, sec 399 --------------------------------------------------- */

#define VOTE_BODY_MAX (FZN_REVOCATION_LEN + 1u + (FZN_CHAIN_MAX_HOPS * (size_t)FZN_HOP_LEN))
#define VOTE_BLOB_MAX ((size_t)FZN_PERSIST_HEAD_LEN + VOTE_BODY_MAX)

/* The slot-11 subject for a record: a hash of the triple it names, so that one
 * triple has one row however many records it has seen. */
static int vote_subject(const fzn_hash_ops_t *hash, fzn_revocation_record_t rec,
                        uint8_t subject[FZN_PUBKEY_LEN])
{
	uint8_t triple[(2u * FZN_PUBKEY_LEN) + FZN_CAP_ID_LEN];

	memcpy(triple, fzn_revocation_issuer(rec), FZN_PUBKEY_LEN);
	memcpy(triple + FZN_PUBKEY_LEN, fzn_revocation_capability(rec)->b, FZN_CAP_ID_LEN);
	memcpy(triple + FZN_PUBKEY_LEN + FZN_CAP_ID_LEN, fzn_revocation_grantee(rec),
	       FZN_PUBKEY_LEN);
	return hash->hash(hash->ctx, subject, FZN_PUBKEY_LEN, triple, sizeof(triple));
}

/* A slot-11 row under `subject`: its record and chain. 1 when it loaded and
 * every part opens. */
static int load_vote(const fzn_persist_ops_t *store, const uint8_t subject[FZN_PUBKEY_LEN],
                     uint8_t record[FZN_REVOCATION_LEN],
                     uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], size_t *hop_count)
{
	uint8_t blob[VOTE_BLOB_MAX];
	const uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	fzn_revocation_record_t rec;
	fzn_chain_hop_t hop;
	size_t len = 0, n, i;

	if (!store->load(store->ctx, FZN_PERSIST_VOTE, subject, blob, sizeof(blob), &len)
	    || len < FZN_PERSIST_HEAD_LEN + FZN_REVOCATION_LEN + 1u)
		return 0;
	n = body[FZN_REVOCATION_LEN];
	if (n >= FZN_CHAIN_MAX_HOPS
	    || fzn_persist_head_check(blob, len, FZN_REVOCATION_LEN + 1u + (n * FZN_HOP_LEN),
	                              FZN_PERSIST_BLOB_VOTE)
	               != FZN_PERSIST_OK
	    || fzn_revocation_open(body, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
		return 0;
	for (i = 0; i < n; i++) {
		const uint8_t *h = body + FZN_REVOCATION_LEN + 1u + (i * FZN_HOP_LEN);

		if (fzn_hop_open(h, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK)
			return 0;
		memcpy(hops[i], h, FZN_HOP_LEN);
	}
	memcpy(record, body, FZN_REVOCATION_LEN);
	*hop_count = n;
	return 1;
}

static int save_vote(const fzn_persist_ops_t *store, const uint8_t subject[FZN_PUBKEY_LEN],
                     const uint8_t record[FZN_REVOCATION_LEN],
                     const uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], size_t hop_count)
{
	uint8_t blob[VOTE_BLOB_MAX];
	size_t body = FZN_REVOCATION_LEN + 1u + (hop_count * FZN_HOP_LEN), i;

	if (hop_count >= FZN_CHAIN_MAX_HOPS
	    || fzn_persist_head_write(blob, sizeof(blob), body, FZN_PERSIST_BLOB_VOTE)
	               != FZN_PERSIST_OK)
		return 0;
	memcpy(blob + FZN_PERSIST_HEAD_LEN, record, FZN_REVOCATION_LEN);
	blob[FZN_PERSIST_HEAD_LEN + FZN_REVOCATION_LEN] = (uint8_t)hop_count;
	for (i = 0; i < hop_count; i++)
		memcpy(blob + FZN_PERSIST_HEAD_LEN + FZN_REVOCATION_LEN + 1u + (i * FZN_HOP_LEN),
		       hops[i], FZN_HOP_LEN);
	return store->save(store->ctx, FZN_PERSIST_VOTE, subject, blob,
	                   (size_t)FZN_PERSIST_HEAD_LEN + body);
}

/* Is what `revocations` holds for `rec`'s triple exactly `rec`? A revocation
 * holds its own hash, not withdrawn; a withdrawal holds the hash it names,
 * withdrawn. This is what keeps a stale copy that admission accepted without
 * taking from being saved over the record that superseded it. */
static int holds_exactly(const fzn_revocation_store_t *revocations, const fzn_hash_ops_t *hash,
                         const uint8_t record[FZN_REVOCATION_LEN], fzn_revocation_record_t rec)
{
	uint8_t id[FZN_REVOCATION_ID_LEN], mine[FZN_REVOCATION_ID_LEN];
	int withdrawn = 0;

	if (!fzn_revocation_lookup(revocations, fzn_revocation_issuer(rec),
	                           fzn_revocation_capability(rec), fzn_revocation_grantee(rec), id,
	                           &withdrawn))
		return 0;
	if (fzn_revocation_is_withdrawal(rec))
		return withdrawn && memcmp(id, fzn_revocation_supersedes(rec), sizeof(id)) == 0;
	if (!hash->hash(hash->ctx, mine, sizeof(mine), record, FZN_REVOCATION_LEN))
		return 0;
	return !withdrawn && memcmp(id, mine, sizeof(id)) == 0;
}

/* ---- admin confirmations, sec 415 ------------------------------------ */

#define CONFIRM_BODY_MAX (FZN_ADMIN_CONFIRM_LEN + 1u + (FZN_CHAIN_MAX_HOPS * (size_t)FZN_HOP_LEN))
#define CONFIRM_BLOB_MAX ((size_t)FZN_PERSIST_HEAD_LEN + CONFIRM_BODY_MAX)

/* A slot-15 row: the confirmation and the confirmer's admin chain. 1 when it
 * loaded and every part opens; the record's own shape is admission's. */
static int load_confirm(const fzn_persist_ops_t *store, const uint8_t subject[FZN_PUBKEY_LEN],
                        uint8_t record[FZN_ADMIN_CONFIRM_LEN],
                        uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], size_t *hop_count)
{
	uint8_t blob[CONFIRM_BLOB_MAX];
	const uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	fzn_chain_hop_t hop;
	size_t len = 0, n, i;

	if (!store->load(store->ctx, FZN_PERSIST_ADMIN_CONFIRM, subject, blob, sizeof(blob), &len)
	    || len < FZN_PERSIST_HEAD_LEN + FZN_ADMIN_CONFIRM_LEN + 1u)
		return 0;
	n = body[FZN_ADMIN_CONFIRM_LEN];
	if (n >= FZN_CHAIN_MAX_HOPS
	    || fzn_persist_head_check(blob, len, FZN_ADMIN_CONFIRM_LEN + 1u + (n * FZN_HOP_LEN),
	                              FZN_PERSIST_BLOB_ADMIN_CONFIRM)
	               != FZN_PERSIST_OK)
		return 0;
	for (i = 0; i < n; i++) {
		const uint8_t *h = body + FZN_ADMIN_CONFIRM_LEN + 1u + (i * FZN_HOP_LEN);

		if (fzn_hop_open(h, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK)
			return 0;
		memcpy(hops[i], h, FZN_HOP_LEN);
	}
	memcpy(record, body, FZN_ADMIN_CONFIRM_LEN);
	*hop_count = n;
	return 1;
}

/* Saved under the record's hash, so one confirmation has one row. */
static int save_confirm(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                        const uint8_t record[FZN_ADMIN_CONFIRM_LEN],
                        const uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], size_t hop_count)
{
	uint8_t blob[CONFIRM_BLOB_MAX], subject[FZN_PUBKEY_LEN];
	size_t body = FZN_ADMIN_CONFIRM_LEN + 1u + (hop_count * FZN_HOP_LEN), i;

	if (hop_count >= FZN_CHAIN_MAX_HOPS
	    || !hash->hash(hash->ctx, subject, sizeof(subject), record, FZN_ADMIN_CONFIRM_LEN)
	    || fzn_persist_head_write(blob, sizeof(blob), body, FZN_PERSIST_BLOB_ADMIN_CONFIRM)
	               != FZN_PERSIST_OK)
		return 0;
	memcpy(blob + FZN_PERSIST_HEAD_LEN, record, FZN_ADMIN_CONFIRM_LEN);
	blob[FZN_PERSIST_HEAD_LEN + FZN_ADMIN_CONFIRM_LEN] = (uint8_t)hop_count;
	for (i = 0; i < hop_count; i++)
		memcpy(blob + FZN_PERSIST_HEAD_LEN + FZN_ADMIN_CONFIRM_LEN + 1u + (i * FZN_HOP_LEN),
		       hops[i], FZN_HOP_LEN);
	return store->save(store->ctx, FZN_PERSIST_ADMIN_CONFIRM, subject, blob,
	                   (size_t)FZN_PERSIST_HEAD_LEN + body);
}

fzn_node_revoke_err_t fzn_node_confirm_save(const fzn_persist_ops_t *store,
                                            const fzn_hash_ops_t *hash,
                                            const uint8_t record[FZN_ADMIN_CONFIRM_LEN],
                                            const fzn_node_authority_t *authority)
{
	uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	size_t n = authority ? authority->hop_count : 0u, i;

	if (!store || !store->save || !hash || !hash->hash || !record || n >= FZN_CHAIN_MAX_HOPS
	    || (n && !authority->hops))
		return FZN_NODE_REVOKE_MALFORMED;
	for (i = 0; i < n; i++)
		memcpy(hops[i], authority->hops[i], FZN_HOP_LEN);
	return save_confirm(store, hash, record, (const uint8_t (*)[FZN_HOP_LEN])hops, n)
	               ? FZN_NODE_REVOKE_OK
	               : FZN_NODE_REVOKE_NOT_SAVED;
}

/* The lists a page walks, filled once per page. */
struct vote_lists {
	uint8_t subjects[5][FZN_NODE_REVOCATIONS_MAX * FZN_PUBKEY_LEN];
	size_t count[5];
};

/* The fifth, sec 479: admins' retention records, which ride here because
 * their chains must. A
 * page's record buffer is sized for the longest of the three. */
FZN_STATIC_ASSERT(FZN_RETENTION_SET_LEN >= FZN_REVOCATION_LEN
                          && FZN_RETENTION_SET_LEN >= FZN_ADMIN_CONFIRM_LEN,
                  "the vote page's record buffer holds every record it carries");
static const fzn_persist_slot_t VOTE_SLOTS[5] = { FZN_PERSIST_ISSUED_REVOCATION,
	                                          FZN_PERSIST_LEARNED_REVOCATION,
	                                          FZN_PERSIST_VOTE,
	                                          FZN_PERSIST_ADMIN_CONFIRM,
	                                          FZN_PERSIST_ADMIN_RETENTION };

/* Vote `i` of list `s`: its record and chain. A record this node issued
 * carries the node's authority chain when it was issued under that authority
 * -- by the chain's grantee, for the capability it grants -- and none
 * otherwise, the rule `fzn_node_revocations_load` applies. */
static int vote_at(const fzn_persist_ops_t *store, const fzn_node_authority_t *authority,
                   const fzn_node_authority_t *admin, const struct vote_lists *lists, size_t s,
                   size_t i,
                   uint8_t record[FZN_REVOCATION_LEN],
                   uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], size_t *hop_count)
{
	const uint8_t *subject = lists->subjects[s] + (i * (size_t)FZN_PUBKEY_LEN);
	fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];
	fzn_revocation_record_t rec;
	size_t h;

	*hop_count = 0;
	if (s == 2u)
		return load_vote(store, subject, record, hops, hop_count);
	if (!load_slot(store, VOTE_SLOTS[s], subject, record)
	    || fzn_revocation_open(record, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
		return 0;
	/* A RECORD THIS NODE ISSUED, AS AN ADMIN VOTE FIRST, sec 416: its
	 * admin chain, when it holds one naming the record's issuer -- the
	 * chain it votes on, and the one that counts for any grantee. */
	if (s == 0u && admin && admin->hop_count < FZN_CHAIN_MAX_HOPS
	    && open_authority(admin, opened)
	    && memcmp(fzn_revocation_issuer(rec), fzn_hop_grantee(opened[admin->hop_count - 1u]),
	              FZN_PUBKEY_LEN) == 0) {
		for (h = 0; h < admin->hop_count; h++)
			memcpy(hops[h], admin->hops[h], FZN_HOP_LEN);
		*hop_count = admin->hop_count;
		return 1;
	}
	if (s == 0u && authority && authority->hop_count < FZN_CHAIN_MAX_HOPS
	    && open_authority(authority, opened)
	    && memcmp(fzn_revocation_issuer(rec),
	              fzn_hop_grantee(opened[authority->hop_count - 1u]), FZN_PUBKEY_LEN) == 0
	    && memcmp(fzn_revocation_capability(rec),
	              fzn_hop_capability(opened[authority->hop_count - 1u]),
	              sizeof(fzn_cap_id_t)) == 0) {
		for (h = 0; h < authority->hop_count; h++)
			memcpy(hops[h], authority->hops[h], FZN_HOP_LEN);
		*hop_count = authority->hop_count;
	}
	return 1;
}

static void put_hex_bytes(char *out, const uint8_t *bytes, size_t len)
{
	static const char DIGITS[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[2u * i] = DIGITS[bytes[i] >> 4];
		out[(2u * i) + 1u] = DIGITS[bytes[i] & 15u];
	}
}

int fzn_node_votes_page(const fzn_persist_ops_t *store, const fzn_node_authority_t *authority,
                        const fzn_node_authority_t *admin, size_t from, char *out, size_t cap,
                        size_t *len, size_t *total)
{
	static struct vote_lists lists;
	static uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	size_t s, i, h, item = 0, at = 0, hop_count;
	int full = 0;

	if (!store || !store->load || !store->list || !out || !len || !total)
		return 0;
	for (s = 0; s < 5u; s++)
		if (!store->list(store->ctx, VOTE_SLOTS[s], lists.subjects[s],
		                 FZN_NODE_REVOCATIONS_MAX, &lists.count[s]))
			return 0;

	/* ONE WALK FOR THE TOTAL AND THE PAGE: every vote is read to count its
	 * hops, and the ones at or past `from` are written while they fit. */
	for (s = 0; s < 5u; s++) {
		for (i = 0; i < lists.count[s]; i++) {
			uint8_t record[FZN_RETENTION_SET_LEN];
			size_t record_len = (s == 4u)   ? FZN_RETENTION_SET_LEN
			                    : (s == 3u) ? FZN_ADMIN_CONFIRM_LEN
			                                : FZN_REVOCATION_LEN;
			const uint8_t *subject = lists.subjects[s] + (i * (size_t)FZN_PUBKEY_LEN);

			if (s == 4u ? !fzn_node_roots_admin_retention_get(store, subject, record, hops,
			                                                  &hop_count)
			    : s == 3u ? !load_confirm(store, subject, record, hops, &hop_count)
			              : !vote_at(store, authority, admin, &lists, s, i, record, hops,
			                         &hop_count))
				return 0;
			for (h = 0; h <= hop_count; h++, item++) {
				size_t need = 2u + (h ? FZN_HOP_LEN : record_len) * 2u;

				if (item < from || full)
					continue;
				if (at + need > cap) {
					full = 1;
					continue;
				}
				out[at++] = ' ';
				out[at++] = h ? 'h' : (s == 4u ? 't' : s == 3u ? 'c' : 'r');
				if (h)
					put_hex_bytes(out + at, hops[h - 1u], FZN_HOP_LEN);
				else
					put_hex_bytes(out + at, record, record_len);
				at += need - 2u;
			}
		}
	}
	*len = at;
	*total = item;
	return 1;
}

static int unhex_bytes(const uint8_t *text, uint8_t *out, size_t len)
{
	size_t i;

	for (i = 0; i < len * 2u; i++) {
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

/* Admit the vote `pull` has assembled, and save it when the store now holds
 * exactly it. OK for a vote refused and counted; REFUSED for a full store;
 * NOT_SAVED when it admitted and would not save. */
static fzn_node_pull_err_t finish_vote(fzn_node_vote_pull_t *pull,
                                       const uint8_t root[FZN_PUBKEY_LEN],
                                       const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash,
                                       fzn_revocation_store_t *revocations,
                                       const fzn_persist_ops_t *store)
{
	fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];
	fzn_revocation_record_t rec;
	uint8_t subject[FZN_PUBKEY_LEN];
	fzn_chain_err_t err;
	size_t i;

	if (!pull->pending)
		return FZN_NODE_PULL_OK;
	pull->pending = 0;
	for (i = 0; i < pull->hop_count; i++)
		if (fzn_hop_open(pull->hops[i], FZN_HOP_LEN, &opened[i]) != FZN_CHAIN_OK)
			return FZN_NODE_PULL_SHAPE;
	/* AN ADMIN'S RETENTION RECORD, sec 479: learned with its chain into the
	 * roots, which admit the chain into the revocations they are attached
	 * to. With no roots to learn into, refused and counted. */
	if (pull->retaining) {
		fzn_node_roots_err_t rerr;

		pull->retaining = 0;
		if (!pull->roots) {
			pull->refused++;
			return FZN_NODE_PULL_OK;
		}
		rerr = fzn_node_roots_learn_admin_retention(
		        pull->roots, store, pull->retention, FZN_RETENTION_SET_LEN,
		        (const uint8_t (*)[FZN_HOP_LEN])pull->hops, pull->hop_count, root);
		if (rerr == FZN_NODE_ROOTS_NOT_SAVED)
			return FZN_NODE_PULL_NOT_SAVED;
		if (rerr != FZN_NODE_ROOTS_OK)
			pull->refused++;
		else
			pull->learned++;
		return FZN_NODE_PULL_OK;
	}
	/* A CONFIRMATION, sec 415: admitted with its confirmer's chain. A
	 * store that keeps no table for it answers MALFORMED, which is counted
	 * as refused below like any other refusal. */
	if (pull->confirming) {
		pull->confirming = 0;
		err = fzn_revocation_confirm_admit(revocations, pull->confirm, FZN_ADMIN_CONFIRM_LEN,
		                                   opened, pull->hop_count, root, sign);
		if (err == FZN_CHAIN_ERR_STORE_FULL)
			return FZN_NODE_PULL_REFUSED;
		if (err != FZN_CHAIN_OK) {
			pull->refused++;
			return FZN_NODE_PULL_OK;
		}
		if (!save_confirm(store, hash, pull->confirm,
		                  (const uint8_t (*)[FZN_HOP_LEN])pull->hops, pull->hop_count))
			return FZN_NODE_PULL_NOT_SAVED;
		pull->learned++;
		return FZN_NODE_PULL_OK;
	}
	if (fzn_revocation_open(pull->record, FZN_REVOCATION_LEN, &rec) != FZN_CHAIN_OK)
		return FZN_NODE_PULL_SHAPE;
	err = fzn_revocation_admit(revocations,
	                           pull->hop_count
	                                   ? fzn_revocation_offer_chain(rec, opened, pull->hop_count)
	                                   : fzn_revocation_offer_root(rec),
	                           root, sign, hash, NULL);
	if (err == FZN_CHAIN_ERR_STORE_FULL)
		return FZN_NODE_PULL_REFUSED;
	if (err != FZN_CHAIN_OK || !holds_exactly(revocations, hash, pull->record, rec)) {
		pull->refused++;
		return FZN_NODE_PULL_OK;
	}
	if (!vote_subject(hash, rec, subject)
	    || !save_vote(store, subject, pull->record,
	                  (const uint8_t (*)[FZN_HOP_LEN])pull->hops, pull->hop_count))
		return FZN_NODE_PULL_NOT_SAVED;
	pull->learned++;
	return FZN_NODE_PULL_OK;
}

fzn_node_pull_err_t fzn_node_votes_absorb(fzn_node_vote_pull_t *pull, const uint8_t *reply,
                                          size_t reply_len, size_t from,
                                          const uint8_t root[FZN_PUBKEY_LEN],
                                          const fzn_sign_ops_t *sign,
                                          const fzn_hash_ops_t *hash,
                                          fzn_revocation_store_t *revocations,
                                          const fzn_persist_ops_t *store, size_t *next,
                                          size_t *total)
{
	const uint8_t *detail = NULL;
	size_t detail_len = 0, at = 0, off = 0, on_page = 0;
	fzn_node_pull_err_t err;

	if (!pull || !reply || !root || !sign || !hash || !hash->hash || !revocations || !store
	    || !store->save || !next || !total)
		return FZN_NODE_PULL_MALFORMED;
	if (fzn_reply_of(reply, reply_len, &detail, &detail_len) != FZN_REPLY_OK)
		return FZN_NODE_PULL_NO_ANSWER;
	if (detail_len && detail[detail_len - 1u] == '\n')
		detail_len--;

	/* `TOTAL FROM` and then items. The total is bounded by what the stream
	 * could hold, so a peer cannot name a stream this node would page
	 * through for ever. */
	if (!take_count(detail, detail_len, &at, total) || at >= detail_len
	    || detail[at++] != ' ' || !take_count(detail, detail_len, &at, &off) || off != from
	    || *total > FZN_NODE_VOTES_MAX * FZN_CHAIN_MAX_HOPS)
		return FZN_NODE_PULL_SHAPE;
	while (at < detail_len) {
		size_t body;

		if (detail[at] != ' ' || detail_len - at < 2u)
			return FZN_NODE_PULL_SHAPE;
		if (detail[at + 1u] == 'r') {
			err = finish_vote(pull, root, sign, hash, revocations, store);
			if (err != FZN_NODE_PULL_OK)
				return err;
			body = FZN_REVOCATION_LEN;
			if (detail_len - at < 2u + (body * 2u)
			    || !unhex_bytes(detail + at + 2u, pull->record, body))
				return FZN_NODE_PULL_SHAPE;
			pull->pending = 1;
			pull->confirming = 0;
			pull->retaining = 0;
			pull->hop_count = 0;
		} else if (detail[at + 1u] == 'c') {
			err = finish_vote(pull, root, sign, hash, revocations, store);
			if (err != FZN_NODE_PULL_OK)
				return err;
			body = FZN_ADMIN_CONFIRM_LEN;
			if (detail_len - at < 2u + (body * 2u)
			    || !unhex_bytes(detail + at + 2u, pull->confirm, body))
				return FZN_NODE_PULL_SHAPE;
			pull->pending = 1;
			pull->confirming = 1;
			pull->retaining = 0;
			pull->hop_count = 0;
		} else if (detail[at + 1u] == 't') {
			err = finish_vote(pull, root, sign, hash, revocations, store);
			if (err != FZN_NODE_PULL_OK)
				return err;
			body = FZN_RETENTION_SET_LEN;
			if (detail_len - at < 2u + (body * 2u)
			    || !unhex_bytes(detail + at + 2u, pull->retention, body))
				return FZN_NODE_PULL_SHAPE;
			pull->pending = 1;
			pull->confirming = 0;
			pull->retaining = 1;
			pull->hop_count = 0;
		} else if (detail[at + 1u] == 'h') {
			/* A HOP WITH NO RECORD BEFORE IT, or one past the most an
			 * offered chain may carry, is a stream that does not parse. */
			body = FZN_HOP_LEN;
			if (!pull->pending || pull->hop_count >= FZN_CHAIN_MAX_HOPS - 1u
			    || detail_len - at < 2u + (body * 2u)
			    || !unhex_bytes(detail + at + 2u, pull->hops[pull->hop_count], body))
				return FZN_NODE_PULL_SHAPE;
			pull->hop_count++;
		} else {
			return FZN_NODE_PULL_SHAPE;
		}
		at += 2u + (body * 2u);
		on_page++;
	}
	*next = from + on_page;
	if (on_page == 0u && *next < *total)
		return FZN_NODE_PULL_SHAPE;
	if (*next >= *total)
		return finish_vote(pull, root, sign, hash, revocations, store);
	return FZN_NODE_PULL_OK;
}

fzn_node_pull_err_t fzn_node_votes_pull(fzn_caller_t *caller, const uint8_t root[FZN_PUBKEY_LEN],
                                        const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash,
                                        uint64_t now, fzn_revocation_store_t *revocations,
                                        struct fzn_node_roots *roots,
                                        const fzn_persist_ops_t *store, size_t *learned,
                                        size_t *refused)
{
	static uint8_t reply[FZN_REPLY_MAX + 1u];
	static fzn_node_vote_pull_t pull;
	size_t from = 0, pages = 0;

	if (!caller || !learned || !refused)
		return FZN_NODE_PULL_MALFORMED;
	memset(&pull, 0, sizeof(pull));
	pull.roots = roots;
	*learned = 0;
	*refused = 0;

	/* BOUNDED BY THE PAGES THE LONGEST STREAM COULD NEED, at one item a
	 * page, not by the peer's word. */
	while (pages++ <= FZN_NODE_VOTES_MAX * FZN_CHAIN_MAX_HOPS) {
		char ask[32];
		size_t reply_len = 0, next = 0, total = 0;
		uint32_t msg = 0;
		fzn_node_pull_err_t err;
		int n;

		n = snprintf(ask, sizeof(ask), "get vote %zu", from);
		if (n < 0 || (size_t)n >= sizeof(ask))
			return FZN_NODE_PULL_MALFORMED;
		if (fzn_caller_send(caller, (const uint8_t *)ask, (size_t)n, now + 300u, &msg)
		            != FZN_CALLER_OK
		    || fzn_caller_recv(caller, msg, reply, sizeof(reply), &reply_len, 3000u)
		               != FZN_CALLER_OK)
			return FZN_NODE_PULL_NO_ANSWER;
		err = fzn_node_votes_absorb(&pull, reply, reply_len, from, root, sign, hash,
		                            revocations, store, &next, &total);
		*learned = pull.learned;
		*refused = pull.refused;
		if (err != FZN_NODE_PULL_OK)
			return err;
		if (next >= total)
			return FZN_NODE_PULL_OK;
		from = next;
	}
	return FZN_NODE_PULL_SHAPE;
}

/* ---- admins at the node, sec 416 ------------------------------------- */

#define OWN_ADMIN_BODY_MAX (1u + (FZN_CHAIN_MAX_HOPS * (size_t)FZN_HOP_LEN))
#define OWN_ADMIN_BLOB_MAX ((size_t)FZN_PERSIST_HEAD_LEN + OWN_ADMIN_BODY_MAX)

const fzn_node_authority_t *fzn_node_admin_chain_view(fzn_node_admin_chain_t *chain)
{
	if (!chain || chain->hop_count == 0u)
		return NULL;
	chain->authority.hops = (const uint8_t (*)[FZN_HOP_LEN])chain->hops;
	chain->authority.hop_count = chain->hop_count;
	chain->authority.proof = NULL;
	chain->authority.proof_count = 0;
	return &chain->authority;
}

int fzn_node_admin_chain_load(const fzn_persist_ops_t *store, fzn_node_admin_chain_t *out)
{
	uint8_t blob[OWN_ADMIN_BLOB_MAX];
	fzn_chain_hop_t hop;
	size_t len = 0, n, i;

	if (!store || !store->load || !out)
		return -1;
	memset(out, 0, sizeof(*out));
	if (!store->load(store->ctx, FZN_PERSIST_OWN_ADMIN, NULL, blob, sizeof(blob), &len))
		return 0;
	if (len < FZN_PERSIST_HEAD_LEN + 1u)
		return -1;
	n = blob[FZN_PERSIST_HEAD_LEN];
	if (n == 0u || n >= FZN_CHAIN_MAX_HOPS
	    || fzn_persist_head_check(blob, len, 1u + (n * FZN_HOP_LEN), FZN_PERSIST_BLOB_OWN_ADMIN)
	               != FZN_PERSIST_OK)
		return -1;
	for (i = 0; i < n; i++) {
		const uint8_t *h = blob + FZN_PERSIST_HEAD_LEN + 1u + (i * FZN_HOP_LEN);

		if (fzn_hop_open(h, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK)
			return -1;
		memcpy(out->hops[i], h, FZN_HOP_LEN);
	}
	out->hop_count = n;
	(void)fzn_node_admin_chain_view(out);
	return 1;
}

fzn_node_revoke_err_t fzn_node_admin_chain_set(const fzn_persist_ops_t *store,
                                               const fzn_revocation_store_t *revocations,
                                               const fzn_node_identity_t *id,
                                               const uint8_t root[FZN_PUBKEY_LEN],
                                               const fzn_cap_id_t *admin_capability,
                                               const uint8_t (*hops)[FZN_HOP_LEN],
                                               size_t hop_count, uint64_t now,
                                               fzn_node_admin_chain_t *out)
{
	fzn_chain_hop_t views[FZN_CHAIN_MAX_HOPS];
	uint8_t blob[OWN_ADMIN_BLOB_MAX];
	fzn_chain_t verdict;
	size_t i, body = 1u + (hop_count * FZN_HOP_LEN);

	if (!store || !store->save || !id || !id->sign || !root || !admin_capability || !hops
	    || !out || hop_count == 0u || hop_count >= FZN_CHAIN_MAX_HOPS)
		return FZN_NODE_REVOKE_MALFORMED;
	for (i = 0; i < hop_count; i++)
		if (fzn_hop_open(hops[i], FZN_HOP_LEN, &views[i]) != FZN_CHAIN_OK)
			return FZN_NODE_REVOKE_NOT_ADMIN;
	/* VERIFIED AS A VOTE ON IT WOULD BE: from a root of the estate, with
	 * the revocations this node holds, so a revoked grant is not taken. */
	if (fzn_chain_verify(views, hop_count, root, admin_capability, now, id->sign, revocations,
	                     NULL, &verdict)
	            != FZN_CHAIN_OK
	    || memcmp(verdict.grantee, id->pubkey, FZN_PUBKEY_LEN) != 0
	    || !fzn_hop_delegable(views[hop_count - 1u]))
		return FZN_NODE_REVOKE_NOT_ADMIN;
	if (fzn_persist_head_write(blob, sizeof(blob), body, FZN_PERSIST_BLOB_OWN_ADMIN)
	    != FZN_PERSIST_OK)
		return FZN_NODE_REVOKE_MALFORMED;
	blob[FZN_PERSIST_HEAD_LEN] = (uint8_t)hop_count;
	for (i = 0; i < hop_count; i++)
		memcpy(blob + FZN_PERSIST_HEAD_LEN + 1u + (i * FZN_HOP_LEN), hops[i], FZN_HOP_LEN);
	if (!store->save(store->ctx, FZN_PERSIST_OWN_ADMIN, NULL, blob,
	                 (size_t)FZN_PERSIST_HEAD_LEN + body))
		return FZN_NODE_REVOKE_NOT_SAVED;
	memset(out, 0, sizeof(*out));
	for (i = 0; i < hop_count; i++)
		memcpy(out->hops[i], hops[i], FZN_HOP_LEN);
	out->hop_count = hop_count;
	(void)fzn_node_admin_chain_view(out);
	return FZN_NODE_REVOKE_OK;
}

fzn_node_revoke_err_t fzn_node_admin_grant(struct fzn_node_roots *roots,
                                           const fzn_persist_ops_t *store,
                                           const fzn_node_identity_t *id,
                                           const fzn_node_admin_chain_t *mine,
                                           const fzn_cap_id_t *admin_capability,
                                           const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                           uint8_t out[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN],
                                           size_t *out_count)
{
	const uint8_t *as = NULL;
	const fzn_sign_ops_t *sign = NULL;
	size_t i;

	if (!store || !id || !id->sign || !admin_capability || !grantee || !out || !out_count)
		return FZN_NODE_REVOKE_MALFORMED;
	*out_count = 0;
	/* AS A ROOT, one hop, and logged: a root's grant that is not in its
	 * log falls at the root's removal whatever the cut. */
	if (roots && fzn_node_roots_acting(roots, id->pubkey, id->sign, &as, &sign)) {
		if (fzn_chain_mint(as, grantee, admin_capability, now, FZN_NO_EXPIRY, 1, sign, out[0])
		            != FZN_CHAIN_OK)
			return FZN_NODE_REVOKE_STORE_REFUSED;
		if (fzn_node_roots_log_act(roots, store, as, sign, (uint8_t)FZN_ROOT_ACT_GRANT, out[0],
		                           FZN_HOP_LEN)
		    != FZN_NODE_ROOTS_OK)
			return FZN_NODE_REVOKE_NOT_SAVED;
		*out_count = 1u;
		return FZN_NODE_REVOKE_OK;
	}
	/* AS AN ADMIN, its own chain and a hop more. */
	if (!mine || mine->hop_count == 0u)
		return FZN_NODE_REVOKE_NOT_ROOT;
	if (mine->hop_count + 1u >= FZN_CHAIN_MAX_HOPS)
		return FZN_NODE_REVOKE_MALFORMED;
	for (i = 0; i < mine->hop_count; i++)
		memcpy(out[i], mine->hops[i], FZN_HOP_LEN);
	if (fzn_chain_mint(id->pubkey, grantee, admin_capability, now, FZN_NO_EXPIRY, 1, id->sign,
	                   out[mine->hop_count])
	    != FZN_CHAIN_OK)
		return FZN_NODE_REVOKE_STORE_REFUSED;
	*out_count = mine->hop_count + 1u;
	return FZN_NODE_REVOKE_OK;
}

fzn_node_revoke_err_t fzn_node_admin_confirm(struct fzn_node_roots *roots,
                                             const fzn_persist_ops_t *store,
                                             const fzn_node_identity_t *id,
                                             const fzn_node_admin_chain_t *mine,
                                             const uint8_t root[FZN_PUBKEY_LEN],
                                             const uint8_t hop[FZN_HOP_LEN],
                                             fzn_revocation_store_t *revocations)
{
	fzn_chain_hop_t views[FZN_CHAIN_MAX_HOPS];
	uint8_t grant[FZN_REVOCATION_ID_LEN], record[FZN_ADMIN_CONFIRM_LEN];
	const uint8_t *as = NULL;
	const fzn_sign_ops_t *sign = NULL;
	fzn_node_admin_chain_t shown;
	const fzn_node_authority_t *chain = NULL;
	size_t i, n = 0;

	if (!store || !id || !id->sign || !id->hash || !id->hash->hash || !root || !hop
	    || !revocations)
		return FZN_NODE_REVOKE_MALFORMED;
	if (!id->hash->hash(id->hash->ctx, grant, sizeof(grant), hop, FZN_HOP_LEN))
		return FZN_NODE_REVOKE_MALFORMED;
	if (roots && fzn_node_roots_acting(roots, id->pubkey, id->sign, &as, &sign)) {
		/* AS A ROOT: no chain, and logged. */
		if (fzn_admin_confirm_issue(as, grant, sign, record) != FZN_CHAIN_OK)
			return FZN_NODE_REVOKE_STORE_REFUSED;
		if (fzn_node_roots_log_act(roots, store, as, sign, (uint8_t)FZN_ROOT_ACT_GRANT, record,
		                           sizeof(record))
		    != FZN_NODE_ROOTS_OK)
			return FZN_NODE_REVOKE_NOT_SAVED;
	} else if (mine && mine->hop_count) {
		shown = *mine;
		chain = fzn_node_admin_chain_view(&shown);
		n = mine->hop_count;
		for (i = 0; i < n; i++)
			if (fzn_hop_open(mine->hops[i], FZN_HOP_LEN, &views[i]) != FZN_CHAIN_OK)
				return FZN_NODE_REVOKE_MALFORMED;
		if (fzn_admin_confirm_issue(id->pubkey, grant, id->sign, record) != FZN_CHAIN_OK)
			return FZN_NODE_REVOKE_STORE_REFUSED;
	} else {
		return FZN_NODE_REVOKE_NOT_ROOT;
	}
	if (fzn_revocation_confirm_admit(revocations, record, sizeof(record), n ? views : NULL, n,
	                                 root, id->sign)
	    != FZN_CHAIN_OK)
		return FZN_NODE_REVOKE_STORE_REFUSED;
	return fzn_node_confirm_save(store, id->hash, record, chain);
}
