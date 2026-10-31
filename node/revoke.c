/* See revoke.h. */

#include "revoke.h"

#include "roots.h"
#include "roster.h"
#include "succession.h"

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
	case FZN_NODE_REVOKE_FULL:
		return "a table is full";
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
static fzn_node_revoke_err_t issue(struct fzn_node_roots *roots, const fzn_node_identity_t *id,
                                   const uint8_t root[FZN_PUBKEY_LEN],
                                   const fzn_node_authority_t *authority,
                                   const fzn_cap_id_t *capability,
                                   const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                   fzn_revocation_store_t *revocations,
                                   const fzn_persist_ops_t *store, int withdraw,
                                   const uint8_t cut[FZN_REVOCATION_ID_LEN], int move)
{
	static const uint8_t NOTHING[FZN_REVOCATION_ID_LEN] = { 0 };
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
		if (!fzn_revocation_is_withdrawal(prev_rec)) {
			uint8_t target[FZN_REVOCATION_ID_LEN];

			/* A LIVE VOTE, AND A LINE TO MOVE, sec 497: a reissue naming
			 * the held vote, in its epoch, with the new cut. */
			if (!move
			    || memcmp(fzn_revocation_cut(prev_rec), cut ? cut : NOTHING,
			              FZN_REVOCATION_ID_LEN) == 0)
				return FZN_NODE_REVOKE_ALREADY;
			if (!id->hash->hash(id->hash->ctx, target, sizeof(target), previous,
			                    sizeof(previous)))
				return FZN_NODE_REVOKE_STORE_REFUSED;
			cerr = fzn_revocation_reissue(id->pubkey, fzn_revocation_capability(prev_rec),
			                              grantee, now, fzn_revocation_epoch(prev_rec),
			                              target, cut, id->sign, record);
		} else {
			cerr = fzn_revocation_reissue(
			        id->pubkey, capability, grantee, now,
			        fzn_revocation_current_epoch(revocations, root, capability, grantee),
			        fzn_revocation_supersedes(prev_rec), cut, id->sign, record);
		}
	} else {
		cerr = fzn_revocation_issue(id->pubkey, capability, grantee, now,
		                            fzn_revocation_current_epoch(revocations, root, capability,
		                                                         grantee), cut,
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
	/* LOGGED WHERE IT IS MADE, sec 504, under its issuer: a vote not in its
	 * signer's log falls at the signer's revocation whatever the line, and a
	 * vote not in its signer's journal reaches nobody. */
	if (roots
	    && fzn_node_roots_log_signed(roots, store, id->pubkey, id->sign, id->pubkey,
	                                 (uint8_t)FZN_ROOT_ACT_REVOCATION, record, sizeof(record))
	               != FZN_NODE_ROOTS_OK)
		return FZN_NODE_REVOKE_NOT_SAVED;
	return FZN_NODE_REVOKE_OK;
}

fzn_node_revoke_err_t fzn_node_revoke(struct fzn_node_roots *roots, const fzn_node_identity_t *id,
                                      const uint8_t root[FZN_PUBKEY_LEN],
                                      const fzn_node_authority_t *authority,
                                      const fzn_cap_id_t *capability,
                                      const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                      fzn_revocation_store_t *revocations,
                                      const fzn_persist_ops_t *store)
{
	return issue(roots, id, root, authority, capability, grantee, now, revocations, store, 0, NULL,
	             0);
}

fzn_node_revoke_err_t fzn_node_revoke_at(struct fzn_node_roots *roots, const fzn_node_identity_t *id,
                                         const uint8_t root[FZN_PUBKEY_LEN],
                                         const fzn_node_authority_t *authority,
                                         const fzn_cap_id_t *capability,
                                         const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                         const uint8_t cut[FZN_REVOCATION_ID_LEN],
                                         fzn_revocation_store_t *revocations,
                                         const fzn_persist_ops_t *store)
{
	return issue(roots, id, root, authority, capability, grantee, now, revocations, store, 0, cut,
	             1);
}

fzn_node_revoke_err_t fzn_node_unrevoke(struct fzn_node_roots *roots, const fzn_node_identity_t *id,
                                        const uint8_t root[FZN_PUBKEY_LEN],
                                        const fzn_node_authority_t *authority,
                                        const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                        fzn_revocation_store_t *revocations,
                                        const fzn_persist_ops_t *store)
{
	return issue(roots, id, root, authority, NULL, grantee, now, revocations, store, 1, NULL, 0);
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

/* ONE PASS OF THE LOAD, over a slot walked: what it judges by, and the
 * first failure, which stops the walk. sec 704. */
struct revocations_walk {
	const fzn_persist_ops_t *store;
	fzn_revocation_store_t *revocations;
	const uint8_t *root;
	const fzn_sign_ops_t *sign;
	const fzn_hash_ops_t *hash;
	const fzn_chain_hop_t *hops, *admin_hops;
	size_t hop_count, admin_hop_count;
	const uint8_t *self, *admin_self;
	const fzn_cap_id_t *granted;
	size_t total;
	fzn_persist_err_t err;
};

/* FULL FOR WANT OF AN ADMIN'S PLACE, sec 704: the entries and the
 * confirmations have room, so it is the admins' table, which the core
 * bounds and no caller grows. The record is refused rather than waited on:
 * waited on, it would hold every later record of its stream for ever. A
 * person's admin devices are few, so this is rare, and it is counted. */
static int admins_full(const fzn_revocation_store_t *rs, fzn_chain_err_t cerr)
{
	return cerr == FZN_CHAIN_ERR_STORE_FULL && rs->used < rs->capacity
	       && (!rs->confirms || rs->confirms_used < rs->confirm_capacity)
	       && rs->admins_used >= rs->admin_capacity;
}

/* A STORE FULL is ROOM, not a changed store: told, the caller gives it
 * larger tables. */
static int walk_failed(struct revocations_walk *w, fzn_chain_err_t cerr)
{
	/* AN ADMIN PAST THE ADMINS' TABLE is passed over, as a vote that will
	 * not admit is, rather than refusing to start. */
	if (admins_full(w->revocations, cerr))
		return 1;
	w->err = cerr == FZN_CHAIN_ERR_STORE_FULL ? FZN_PERSIST_ERR_ROOM : FZN_PERSIST_ERR_SHAPE;
	return 0;
}

static int issued_walked(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	struct revocations_walk *w = arg;
	uint8_t record[FZN_REVOCATION_LEN];
	fzn_revocation_record_t rec;
	fzn_revocation_offer_t offer;
	fzn_chain_err_t cerr;

	/* FILED UNDER ONE GRANTEE AND NAMING ANOTHER is refused inside
	 * `load_slot`, the check every load here makes. */
	if (!load_slot(w->store, FZN_PERSIST_ISSUED_REVOCATION, subject, record)
	    || fzn_revocation_open(record, sizeof(record), &rec) != FZN_CHAIN_OK) {
		w->err = FZN_PERSIST_ERR_SHAPE;
		return 0;
	}
	/* AN ADMIN CHAIN FIRST, sec 416: an admin's vote counts for any
	 * grantee, and it is the chain the node votes on. */
	if (memcmp(fzn_revocation_issuer(rec), w->root, FZN_PUBKEY_LEN) == 0)
		offer = fzn_revocation_offer_root(rec);
	else if (w->admin_self
	         && memcmp(fzn_revocation_issuer(rec), w->admin_self, FZN_PUBKEY_LEN) == 0)
		offer = fzn_revocation_offer_chain(rec, w->admin_hops, w->admin_hop_count);
	else if (w->self && memcmp(fzn_revocation_issuer(rec), w->self, FZN_PUBKEY_LEN) == 0
	         && memcmp(fzn_revocation_capability(rec), w->granted, sizeof(*w->granted)) == 0)
		offer = fzn_revocation_offer_chain(rec, w->hops, w->hop_count);
	else
		return 1;	/* see the header */
	cerr = fzn_revocation_admit(w->revocations, offer, w->root, w->sign, w->hash, NULL);
	if (cerr != FZN_CHAIN_OK)
		return walk_failed(w, cerr);
	w->total++;
	return 1;
}

static int vote_walked(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	static uint8_t vote_hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	struct revocations_walk *w = arg;
	uint8_t record[FZN_REVOCATION_LEN];
	fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];
	fzn_revocation_record_t rec;
	fzn_chain_err_t cerr;
	size_t n = 0, h;

	if (!load_vote(w->store, subject, record, vote_hops, &n)
	    || fzn_revocation_open(record, sizeof(record), &rec) != FZN_CHAIN_OK) {
		w->err = FZN_PERSIST_ERR_SHAPE;
		return 0;
	}
	for (h = 0; h < n; h++)
		if (fzn_hop_open(vote_hops[h], FZN_HOP_LEN, &opened[h]) != FZN_CHAIN_OK) {
			w->err = FZN_PERSIST_ERR_SHAPE;
			return 0;
		}
	/* A COPY SUPERSEDED IN ANOTHER SLOT is not a changed store: this
	 * node's own vote comes back from a peer and is kept here, and a later
	 * withdrawal of it lands in slot 9, which was admitted first. Refused
	 * with the triple already held, it is skipped; refused with nothing
	 * held, it is fatal -- unless the store is full. */
	cerr = fzn_revocation_admit(w->revocations,
	                            n ? fzn_revocation_offer_chain(rec, opened, n)
	                              : fzn_revocation_offer_root(rec),
	                            w->root, w->sign, w->hash, NULL);
	if (cerr != FZN_CHAIN_OK) {
		if (cerr != FZN_CHAIN_ERR_STORE_FULL
		    && fzn_revocation_known(w->revocations, fzn_revocation_issuer(rec),
		                            fzn_revocation_capability(rec),
		                            fzn_revocation_grantee(rec)))
			return 1;
		return walk_failed(w, cerr);
	}
	w->total++;
	return 1;
}

static int confirm_walked(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	static uint8_t confirm_hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	struct revocations_walk *w = arg;
	uint8_t record[FZN_ADMIN_CONFIRM_LEN];
	fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];
	fzn_chain_err_t cerr;
	size_t n = 0, h;

	if (!load_confirm(w->store, subject, record, confirm_hops, &n)) {
		w->err = FZN_PERSIST_ERR_SHAPE;
		return 0;
	}
	for (h = 0; h < n; h++)
		if (fzn_hop_open(confirm_hops[h], FZN_HOP_LEN, &opened[h]) != FZN_CHAIN_OK) {
			w->err = FZN_PERSIST_ERR_SHAPE;
			return 0;
		}
	cerr = fzn_revocation_confirm_admit(w->revocations, record, sizeof(record), opened, n,
	                                    w->root, w->sign);
	if (cerr != FZN_CHAIN_OK)
		return walk_failed(w, cerr);
	w->total++;
	return 1;
}

static fzn_persist_err_t walk_slot(struct revocations_walk *w, fzn_persist_slot_t slot,
                                   int (*fn)(void *arg, const uint8_t subject[FZN_PUBKEY_LEN]))
{
	if (!fzn_persist_each(w->store, slot, fn, w))
		return FZN_PERSIST_ERR_BACKEND;
	return w->err;
}

fzn_persist_err_t fzn_node_revocations_load(const fzn_persist_ops_t *store,
                                            fzn_revocation_store_t *revocations,
                                            const uint8_t root[FZN_PUBKEY_LEN],
                                            const fzn_node_authority_t *authority,
                                            const fzn_node_authority_t *admin,
                                            const fzn_sign_ops_t *sign,
                                            const fzn_hash_ops_t *hash, size_t *count)
{
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS], admin_hops[FZN_CHAIN_MAX_HOPS];
	struct revocations_walk w;
	fzn_persist_err_t err;

	if (!store || !store->load || !revocations || !root || !sign || !hash || !count)
		return FZN_PERSIST_ERR_MALFORMED;
	memset(&w, 0, sizeof(w));
	if (authority) {
		if (!open_authority(authority, hops))
			return FZN_PERSIST_ERR_MALFORMED;
		w.self = fzn_hop_grantee(hops[authority->hop_count - 1u]);
		w.granted = fzn_hop_capability(hops[authority->hop_count - 1u]);
		w.hops = hops;
		w.hop_count = authority->hop_count;
	}
	/* THIS NODE'S ADMIN CHAIN, sec 416, used only by a store that knows the
	 * admin capability it carries. */
	if (admin) {
		if (!open_authority(admin, admin_hops))
			return FZN_PERSIST_ERR_MALFORMED;
		if (revocations->has_admin
		    && memcmp(fzn_hop_capability(admin_hops[admin->hop_count - 1u]),
		              &revocations->admin_capability, sizeof(fzn_cap_id_t)) == 0) {
			w.admin_self = fzn_hop_grantee(admin_hops[admin->hop_count - 1u]);
			w.admin_hops = admin_hops;
			w.admin_hop_count = admin->hop_count;
		}
	}
	*count = 0;
	if (!store->list && !store->each)
		return FZN_PERSIST_ERR_BACKEND;
	w.store = store;
	w.revocations = revocations;
	w.root = root;
	w.sign = sign;
	w.hash = hash;
	w.err = FZN_PERSIST_OK;

	/* SLOT 9 ALONE since sec 506: slot 10 held what a member pulled from
	 * its root with `get revocation`, and nothing has written it since the
	 * journal took that carriage. A root's vote arrives as any vote does,
	 * into slot 11 below. WALKED, sec 704: however many are held. */
	err = walk_slot(&w, FZN_PERSIST_ISSUED_REVOCATION, issued_walked);
	/* THE VOTES LEARNED FROM PEERS, each with the chain it came with, and
	 * each refused as fatally as the slot above: it was admitted once and
	 * saved only because it was, so one that will not admit again is a
	 * store that changed underneath this node. sec 399. */
	if (err == FZN_PERSIST_OK)
		err = walk_slot(&w, FZN_PERSIST_VOTE, vote_walked);
	/* THE CONFIRMATIONS, sec 415, as fatally as the votes -- each admitted
	 * once and saved because it was -- and only into a store that keeps a
	 * table for them. One that does not skips them; they stay stored, and
	 * this node still serves them onward. */
	if (err == FZN_PERSIST_OK && revocations->confirms)
		err = walk_slot(&w, FZN_PERSIST_ADMIN_CONFIRM, confirm_walked);
	if (err != FZN_PERSIST_OK)
		return err;
	*count = w.total;
	return FZN_PERSIST_OK;
}

/* HOW MANY ROWS A LOAD WILL READ: slot 9 and the votes, which make at most
 * one entry each, and the confirmations. sec 704: what a caller sizes the
 * store's tables by before loading. */
static int row_counted(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	(void)subject;
	(*(size_t *)arg)++;
	return 1;
}

fzn_persist_err_t fzn_node_revocations_rows(const fzn_persist_ops_t *store, size_t *entries,
                                            size_t *confirms)
{
	if (!store || !entries || !confirms)
		return FZN_PERSIST_ERR_MALFORMED;
	*entries = *confirms = 0;
	if (!fzn_persist_each(store, FZN_PERSIST_ISSUED_REVOCATION, row_counted, entries)
	    || !fzn_persist_each(store, FZN_PERSIST_VOTE, row_counted, entries)
	    || !fzn_persist_each(store, FZN_PERSIST_ADMIN_CONFIRM, row_counted, confirms))
		return FZN_PERSIST_ERR_BACKEND;
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
/* ONE OF THE ROOT'S RECORDS, walked: into the caller's room while there is
 * any, counted past it. A row that will not read is passed over. */
struct root_records_walk {
	const fzn_persist_ops_t *store;
	const uint8_t *root;
	const fzn_cap_id_t *capability;
	uint8_t (*out)[FZN_REVOCATION_LEN];
	size_t cap, n;
	int votes;
};

static int root_record_walked(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	static uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	struct root_records_walk *w = arg;
	uint8_t record[FZN_REVOCATION_LEN];
	fzn_revocation_record_t rec;
	size_t hop_count = 0;

	if (!(w->votes ? load_vote(w->store, subject, record, hops, &hop_count)
	               : load_slot(w->store, FZN_PERSIST_ISSUED_REVOCATION, subject, record))
	    || fzn_revocation_open(record, sizeof(record), &rec) != FZN_CHAIN_OK
	    || hop_count != 0u || memcmp(fzn_revocation_issuer(rec), w->root, FZN_PUBKEY_LEN) != 0
	    || memcmp(fzn_revocation_capability(rec), w->capability, sizeof(*w->capability)) != 0)
		return 1;
	if (w->n < w->cap)
		memcpy(w->out[w->n], record, FZN_REVOCATION_LEN);
	w->n++;
	return 1;
}

fzn_persist_err_t fzn_node_root_records(const fzn_persist_ops_t *store,
                                        const uint8_t root[FZN_PUBKEY_LEN],
                                        const fzn_cap_id_t *capability,
                                        uint8_t (*out)[FZN_REVOCATION_LEN], size_t cap,
                                        size_t *count)
{
	struct root_records_walk w;

	if (!count)
		return FZN_PERSIST_ERR_MALFORMED;
	*count = 0;
	if (!store || !store->load || !root || !capability || (!out && cap))
		return FZN_PERSIST_ERR_MALFORMED;
	memset(&w, 0, sizeof(w));
	w.store = store;
	w.root = root;
	w.capability = capability;
	w.out = out;
	w.cap = cap;
	if (!fzn_persist_each(store, FZN_PERSIST_ISSUED_REVOCATION, root_record_walked, &w))
		return FZN_PERSIST_ERR_BACKEND;
	w.votes = 1;
	if (!fzn_persist_each(store, FZN_PERSIST_VOTE, root_record_walked, &w))
		return FZN_PERSIST_ERR_BACKEND;
	*count = w.n;
	return w.n > cap ? FZN_PERSIST_ERR_ROOM : FZN_PERSIST_OK;
}

/* ---- this estate's records for a contact, sec 781 ------------------------- */

/* The kinds `node/contact_devices.h` names, as its estate items carry them. */
#define ESTATE_CHANGE 1u
#define ESTATE_VOTE 2u
#define ESTATE_CONFIRM 3u

struct estate_records_walk {
	const fzn_persist_ops_t *store;
	fzn_node_estate_record_fn fn;
	void *ctx;
	int stopped;
};

static int estate_change_walked(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	struct estate_records_walk *w = arg;
	uint8_t blob[FZN_PERSIST_HEAD_LEN + FZN_ROOT_REMOVE_LEN + FZN_QUORUM_SET_LEN];
	size_t len = 0;

	if (!w->store->load(w->store->ctx, FZN_PERSIST_ROOT_CHANGE, subject, blob, sizeof(blob),
	                    &len)
	    || len <= FZN_PERSIST_HEAD_LEN)
		return 1;
	/* ROOT CHANGES AND SETTINGS OF k; the other records slot 13 holds -- a
	 * retention setting -- are no estate item's. */
	if (blob[FZN_PERSIST_HEAD_LEN + 1u] != (uint8_t)FZN_OBJECT_ROOT_ADD
	    && blob[FZN_PERSIST_HEAD_LEN + 1u] != (uint8_t)FZN_OBJECT_ROOT_REMOVE
	    && blob[FZN_PERSIST_HEAD_LEN + 1u] != (uint8_t)FZN_OBJECT_QUORUM_SET)
		return 1;
	if (!w->fn(w->ctx, ESTATE_CHANGE, blob + FZN_PERSIST_HEAD_LEN, len - FZN_PERSIST_HEAD_LEN,
	           NULL, 0u, 0)) {
		w->stopped = 1;
		return 0;
	}
	return 1;
}

static int estate_vote_walked(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	static uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	struct estate_records_walk *w = arg;
	uint8_t record[FZN_REVOCATION_LEN];
	size_t n = 0;

	if (!load_vote(w->store, subject, record, hops, &n))
		return 1;
	if (!w->fn(w->ctx, ESTATE_VOTE, record, sizeof(record), (const uint8_t(*)[FZN_HOP_LEN])hops,
	           n, 0)) {
		w->stopped = 1;
		return 0;
	}
	return 1;
}

static int estate_issued_walked(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	struct estate_records_walk *w = arg;
	uint8_t record[FZN_REVOCATION_LEN];

	if (!load_slot(w->store, FZN_PERSIST_ISSUED_REVOCATION, subject, record))
		return 1;
	if (!w->fn(w->ctx, ESTATE_VOTE, record, sizeof(record), NULL, 0u, 1)) {
		w->stopped = 1;
		return 0;
	}
	return 1;
}

static int estate_confirm_walked(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	static uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	struct estate_records_walk *w = arg;
	uint8_t record[FZN_ADMIN_CONFIRM_LEN];
	size_t n = 0;

	if (!load_confirm(w->store, subject, record, hops, &n))
		return 1;
	if (!w->fn(w->ctx, ESTATE_CONFIRM, record, sizeof(record),
	           (const uint8_t(*)[FZN_HOP_LEN])hops, n, 0)) {
		w->stopped = 1;
		return 0;
	}
	return 1;
}

fzn_persist_err_t fzn_node_estate_records(const fzn_persist_ops_t *store,
                                          fzn_node_estate_record_fn fn, void *ctx)
{
	struct estate_records_walk w;
	static const fzn_persist_slot_t slots[] = { FZN_PERSIST_ROOT_CHANGE, FZN_PERSIST_ADMIN_CONFIRM,
		                                    FZN_PERSIST_VOTE, FZN_PERSIST_ISSUED_REVOCATION };
	int (*walked[])(void *, const uint8_t *) = { estate_change_walked, estate_confirm_walked,
		                                     estate_vote_walked, estate_issued_walked };
	size_t i;

	if (!store || !store->load || !fn)
		return FZN_PERSIST_ERR_MALFORMED;
	memset(&w, 0, sizeof(w));
	w.store = store;
	w.fn = fn;
	w.ctx = ctx;
	for (i = 0; i < sizeof(slots) / sizeof(slots[0]) && !w.stopped; i++)
		if (!fzn_persist_each(store, slots[i], walked[i], &w) && !w.stopped)
			return FZN_PERSIST_ERR_BACKEND;
	return FZN_PERSIST_OK;
}

struct held_cut {
	const uint8_t *key;
	int held;
};

static int held_cut_listed(void *ctx, uint8_t kind, const uint8_t *record, size_t len,
                           const uint8_t (*hops)[FZN_HOP_LEN], size_t hop_count, int issued)
{
	static const uint8_t NOTHING[FZN_REVOCATION_ID_LEN] = { 0 };
	struct held_cut *h = ctx;
	fzn_revocation_record_t rec;

	(void)hops;
	(void)hop_count;
	(void)issued;
	/* A WITHDRAWAL IS NEVER ONE: it carries no line, `fzn_revocation_open`
	 * refusing one that does, so the line's test below excludes it. */
	if (kind == ESTATE_VOTE && fzn_revocation_open(record, len, &rec) == FZN_CHAIN_OK
	    && memcmp(fzn_revocation_grantee(rec), h->key, FZN_PUBKEY_LEN) == 0
	    && memcmp(fzn_revocation_cut(rec), NOTHING, sizeof(NOTHING)) != 0)
		h->held = 1;
	if (kind == ESTATE_CHANGE && len == FZN_ROOT_REMOVE_LEN
	    && record[1] == (uint8_t)FZN_OBJECT_ROOT_REMOVE
	    && memcmp(record + FZN_ROOT_SET_OFF_SUBJECT, h->key, FZN_PUBKEY_LEN) == 0
	    && memcmp(record + FZN_ROOT_SET_OFF_CUT, NOTHING, sizeof(NOTHING)) != 0)
		h->held = 1;
	return !h->held;
}

int fzn_node_estate_cut_held(const fzn_persist_ops_t *store, const uint8_t key[FZN_PUBKEY_LEN])
{
	struct held_cut h;

	if (!store || !key)
		return -1;
	h.key = key;
	h.held = 0;
	if (fzn_node_estate_records(store, held_cut_listed, &h) != FZN_PERSIST_OK)
		return -1;
	return h.held;
}

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
	/* A SUCCESSION, sec 499: learned with its issuer's chain into the
	 * successions, which check its standing as they admit it. With none to
	 * learn into, refused and counted. */
	if (pull->succeeding) {
		fzn_node_revoke_err_t serr;

		pull->succeeding = 0;
		if (!pull->successions) {
			pull->refused++;
			return FZN_NODE_PULL_OK;
		}
		serr = fzn_node_successions_learn(pull->successions, store, revocations, root, sign,
		                                  pull->succession,
		                                  (const uint8_t (*)[FZN_HOP_LEN])pull->hops,
		                                  pull->hop_count);
		if (serr == FZN_NODE_REVOKE_NOT_SAVED)
			return FZN_NODE_PULL_NOT_SAVED;
		/* A FULL SET STOPS IT, sec 704, as a full roster does: counted and
		 * skipped, the re-key would be lost for good. */
		if (serr == FZN_NODE_REVOKE_FULL)
			return FZN_NODE_PULL_REFUSED;
		if (serr != FZN_NODE_REVOKE_OK)
			pull->refused++;
		else
			pull->learned++;
		return FZN_NODE_PULL_OK;
	}
	/* A CONTACT'S ROSTER RECORD, sec 489: learned with its writer's chain
	 * into the roster, which checks standing as it admits. With no roster
	 * to learn into, refused and counted. */
	if (pull->rostering) {
		fzn_node_roster_err_t rerr;

		pull->rostering = 0;
		if (!pull->roster) {
			pull->refused++;
			return FZN_NODE_PULL_OK;
		}
		rerr = fzn_node_roster_learn(pull->roster, store, pull->roster_record,
		                             FZN_ROSTER_MIN_LEN,
		                             (const uint8_t (*)[FZN_HOP_LEN])pull->hops,
		                             pull->hop_count);
		if (rerr == FZN_NODE_ROSTER_NOT_SAVED)
			return FZN_NODE_PULL_NOT_SAVED;
		/* A FULL TABLE STOPS IT, sec 704, as a full roots table does: counted
		 * and skipped, the contact's record would be lost for good. */
		if (rerr == FZN_NODE_ROSTER_FULL)
			return FZN_NODE_PULL_REFUSED;
		if (rerr != FZN_NODE_ROSTER_OK)
			pull->refused++;
		else
			pull->learned++;
		return FZN_NODE_PULL_OK;
	}
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
		/* A FULL TABLE STOPS IT, sec 703, as a full revocation store does:
		 * counted and skipped, the admin's record would be lost for good. */
		if (rerr == FZN_NODE_ROOTS_FULL)
			return FZN_NODE_PULL_REFUSED;
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
		if (err == FZN_CHAIN_ERR_STORE_FULL && !admins_full(revocations, err))
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
	if (err == FZN_CHAIN_ERR_STORE_FULL && !admins_full(revocations, err))
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

fzn_node_pull_err_t fzn_node_votes_take(fzn_node_vote_pull_t *pull, char item,
                                        const uint8_t *object, size_t len,
                                        const uint8_t (*hops)[FZN_HOP_LEN], size_t hop_count,
                                        const uint8_t root[FZN_PUBKEY_LEN],
                                        const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash,
                                        fzn_revocation_store_t *revocations,
                                        const fzn_persist_ops_t *store)
{
	size_t i;

	if (!pull || !object || !root || !sign || !hash || !hash->hash || !revocations || !store
	    || !store->save || hop_count >= FZN_CHAIN_MAX_HOPS || (hop_count && !hops))
		return FZN_NODE_PULL_MALFORMED;
	pull->pending = 0;
	pull->confirming = 0;
	pull->retaining = 0;
	pull->rostering = 0;
	pull->succeeding = 0;
	/* EACH KIND AT ITS OWN LENGTH. */
	switch (item) {
	case 'r':
		if (len != FZN_REVOCATION_LEN)
			return FZN_NODE_PULL_SHAPE;
		memcpy(pull->record, object, len);
		break;
	case 'c':
		if (len != FZN_ADMIN_CONFIRM_LEN)
			return FZN_NODE_PULL_SHAPE;
		memcpy(pull->confirm, object, len);
		pull->confirming = 1;
		break;
	case 't':
		if (len != FZN_RETENTION_SET_LEN)
			return FZN_NODE_PULL_SHAPE;
		memcpy(pull->retention, object, len);
		pull->retaining = 1;
		break;
	case 'o':
		if (len != FZN_ROSTER_MIN_LEN)
			return FZN_NODE_PULL_SHAPE;
		memcpy(pull->roster_record, object, len);
		pull->rostering = 1;
		break;
	case 's':
		if (len != FZN_SUCCESSION_LEN)
			return FZN_NODE_PULL_SHAPE;
		memcpy(pull->succession, object, len);
		pull->succeeding = 1;
		break;
	default:
		return FZN_NODE_PULL_MALFORMED;
	}
	for (i = 0; i < hop_count; i++)
		memcpy(pull->hops[i], hops[i], FZN_HOP_LEN);
	pull->hop_count = hop_count;
	pull->pending = 1;
	return finish_vote(pull, root, sign, hash, revocations, store);
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
	/* LOGGED AS AN ADMIN TOO, sec 497, as a root's grant is above. */
	if (roots
	    && fzn_node_roots_log_act(roots, store, id->pubkey, id->sign, (uint8_t)FZN_ROOT_ACT_GRANT,
	                              out[mine->hop_count], FZN_HOP_LEN)
	               != FZN_NODE_ROOTS_OK)
		return FZN_NODE_REVOKE_NOT_SAVED;
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
	uint8_t grant[FZN_REVOCATION_ID_LEN];

	if (!id || !id->hash || !id->hash->hash || !hop)
		return FZN_NODE_REVOKE_MALFORMED;
	if (!id->hash->hash(id->hash->ctx, grant, sizeof(grant), hop, FZN_HOP_LEN))
		return FZN_NODE_REVOKE_MALFORMED;
	return fzn_node_confirm_act(roots, store, id, mine, root, grant, revocations);
}

fzn_node_revoke_err_t fzn_node_confirm_act(struct fzn_node_roots *roots,
                                           const fzn_persist_ops_t *store,
                                           const fzn_node_identity_t *id,
                                           const fzn_node_admin_chain_t *mine,
                                           const uint8_t root[FZN_PUBKEY_LEN],
                                           const uint8_t grant[FZN_REVOCATION_ID_LEN],
                                           fzn_revocation_store_t *revocations)
{
	fzn_chain_hop_t views[FZN_CHAIN_MAX_HOPS];
	uint8_t record[FZN_ADMIN_CONFIRM_LEN];
	const uint8_t *as = NULL;
	const fzn_sign_ops_t *sign = NULL;
	fzn_node_admin_chain_t shown;
	const fzn_node_authority_t *chain = NULL;
	size_t i, n = 0;

	if (!store || !id || !id->sign || !id->hash || !id->hash->hash || !root || !grant
	    || !revocations)
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
		/* AS AN ADMIN, logged too, sec 497: a confirmation before this
		 * admin's line keeps counting after it is revoked. */
		if (roots
		    && fzn_node_roots_log_act(roots, store, id->pubkey, id->sign,
		                              (uint8_t)FZN_ROOT_ACT_GRANT, record, sizeof(record))
		               != FZN_NODE_ROOTS_OK)
			return FZN_NODE_REVOKE_NOT_SAVED;
	} else {
		return FZN_NODE_REVOKE_NOT_ROOT;
	}
	if (fzn_revocation_confirm_admit(revocations, record, sizeof(record), n ? views : NULL, n,
	                                 root, id->sign)
	    != FZN_CHAIN_OK)
		return FZN_NODE_REVOKE_STORE_REFUSED;
	return fzn_node_confirm_save(store, id->hash, record, chain);
}
