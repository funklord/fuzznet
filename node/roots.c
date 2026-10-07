/* See roots.h. */

#include "roots.h"
#include "journal.h"

#include "../wire/bytes.h"
#include "../local/vocabulary.h"

#include "../constant_time/constant_time.h"

#include <stdio.h>

#include <string.h>

/* The longest change: a retention record, sec 476. */
#define CHANGE_BLOB_MAX ((size_t)FZN_PERSIST_HEAD_LEN + FZN_RETENTION_SET_LEN)
FZN_STATIC_ASSERT(FZN_RETENTION_SET_LEN >= FZN_ROOT_REMOVE_LEN
                          && FZN_RETENTION_SET_LEN >= FZN_ROOT_ADD_LEN
                          && FZN_RETENTION_SET_LEN >= FZN_QUORUM_SET_LEN,
                  "the retention record is the longest a root record gets");
/* EVERY ROW SLOT 13 CAN HOLD: the set's changes, the settings of k and the
 * retention records, each bounded where it is kept. */
#define CHANGES_HELD_MAX \
	((size_t)FZN_ROOT_SET_MAX + FZN_NODE_ROOT_SETTINGS_MAX + FZN_NODE_ROOT_RETENTION_MAX)

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
	case FZN_NODE_ROOTS_NOT_ROOT:
		return "this node holds no key that stands as a root";
	case FZN_NODE_ROOTS_FORKED:
		return "this key's stream has forked, and extending it would pick a branch";
	case FZN_NODE_ROOTS_HELD:
		return "this node already holds a root key";
	case FZN_NODE_ROOTS_NO_PROOF:
		return "no root-adds this node holds reach from the estate's root to its root key";
	}
	return "unknown";
}

/* A RETENTION RECORD COUNTS, sec 479, when its setter's act counts under
 * the set -- a root's -- or its setter stands as an admin in the attached
 * revocations. */
static int judge_member(void *ctx, const uint8_t key[FZN_PUBKEY_LEN])
{
	const fzn_node_roots_t *roots = ctx;

	return fzn_root_view_member(&roots->view, key);
}

static int judge_counts(void *ctx, const uint8_t setter[FZN_PUBKEY_LEN],
                        const uint8_t act[FZN_ROOT_ACT_ID_LEN])
{
	const fzn_node_roots_t *roots = ctx;

	return fzn_root_view_counts(&roots->view, setter, act)
	       || (roots->revocations && fzn_revocation_admin_stands(roots->revocations, setter));
}

fzn_node_roots_err_t fzn_node_roots_init(fzn_node_roots_t *roots,
                                         const uint8_t genesis[FZN_PUBKEY_LEN],
                                         const fzn_sign_ops_t *sign,
                                         const fzn_hash_ops_t *hash)
{
	if (!roots || !genesis || !sign || !sign->verify || !hash || !hash->hash)
		return FZN_NODE_ROOTS_MALFORMED;
	memset(roots, 0, sizeof(*roots));
	/* NO ACT LOG UNTIL A JOURNAL IS SET, sec 508: without one nothing a
	 * removed root did can be shown to stand, which errs toward removal. */
	if (fzn_root_set_init(&roots->set, genesis, roots->changes, FZN_ROOT_SET_MAX)
	            != FZN_ROOT_LOG_OK
	    || fzn_root_view_init(&roots->view, &roots->set, NULL) != FZN_ROOT_LOG_OK)
		return FZN_NODE_ROOTS_MALFORMED;
	fzn_root_view_ops(&roots->view, &roots->ops);
	roots->judge.member = judge_member;
	roots->judge.counts = judge_counts;
	roots->judge.ctx = roots;
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
	case FZN_OBJECT_ROOT_ADD:
		return (uint8_t)FZN_PERSIST_BLOB_ROOT_ADD;
	case FZN_OBJECT_ROOT_REMOVE:
		return (uint8_t)FZN_PERSIST_BLOB_ROOT_REMOVE;
	case FZN_OBJECT_QUORUM_SET:
		return (uint8_t)FZN_PERSIST_BLOB_QUORUM_SET;
	case FZN_OBJECT_RETENTION_SET:
		return (uint8_t)FZN_PERSIST_BLOB_RETENTION_SET;
	}
	return 0;
}

static fzn_root_log_err_t admit(fzn_node_roots_t *roots, const uint8_t *bytes, size_t len)
{
	/* A SETTING OF k, sec 418: checked and kept once. Whether it counts is
	 * the resolution's question, asked of the set when k is read. */
	if (tag_of(bytes, len) == (uint8_t)FZN_PERSIST_BLOB_QUORUM_SET) {
		fzn_root_log_err_t err = fzn_quorum_set_check(bytes, len, roots->sign);
		size_t i;

		if (err != FZN_ROOT_LOG_OK)
			return err;
		for (i = 0; i < roots->settings_used; i++)
			if (memcmp(roots->settings[i], bytes, FZN_QUORUM_SET_LEN) == 0)
				return FZN_ROOT_LOG_OK;
		if (roots->settings_used >= FZN_NODE_ROOT_SETTINGS_MAX)
			return FZN_ROOT_LOG_ERR_FULL;
		memcpy(roots->settings[roots->settings_used++], bytes, FZN_QUORUM_SET_LEN);
		return FZN_ROOT_LOG_OK;
	}
	/* A RETENTION RECORD, sec 476: as a setting of k. */
	if (tag_of(bytes, len) == (uint8_t)FZN_PERSIST_BLOB_RETENTION_SET) {
		fzn_root_log_err_t err = fzn_retention_set_check(bytes, len, roots->sign);
		size_t i;

		if (err != FZN_ROOT_LOG_OK)
			return err;
		for (i = 0; i < roots->retention_used; i++)
			if (memcmp(roots->retention[i], bytes, FZN_RETENTION_SET_LEN) == 0)
				return FZN_ROOT_LOG_OK;
		if (roots->retention_used >= FZN_NODE_ROOT_RETENTION_MAX)
			return FZN_ROOT_LOG_ERR_FULL;
		memcpy(roots->retention[roots->retention_used++], bytes, FZN_RETENTION_SET_LEN);
		return FZN_ROOT_LOG_OK;
	}
	return fzn_root_set_admit(&roots->set, bytes, len, roots->sign, roots->hash);
}

/* Settle the view again over what is held now. The ops point at it and
 * need no refresh. */
static void settle(fzn_node_roots_t *roots)
{
	(void)fzn_root_view_init(&roots->view, &roots->set, roots->journal ? &roots->acts : NULL);
}

fzn_node_roots_err_t fzn_node_roots_set_journal(fzn_node_roots_t *roots,
                                                struct fzn_node_journal *journal)
{
	if (!roots || !journal)
		return FZN_NODE_ROOTS_MALFORMED;
	/* IN PLACE: a store attached before this holds a pointer to `acts` or,
	 * attached with no journal, none; either way it asks the journal now. */
	fzn_node_journal_acts(journal, &roots->acts);
	roots->journal = journal;
	if (roots->revocations
	    && fzn_revocation_store_set_acts(roots->revocations, &roots->acts) != FZN_CHAIN_OK)
		return FZN_NODE_ROOTS_MALFORMED;
	settle(roots);
	return FZN_NODE_ROOTS_OK;
}

fzn_node_roots_err_t fzn_node_roots_learn(fzn_node_roots_t *roots,
                                          const fzn_persist_ops_t *store,
                                          const uint8_t *bytes, size_t len)
{
	size_t room = CHANGE_BLOB_MAX;
	uint8_t tag;

	if (!roots || !store || !store->save || !bytes)
		return FZN_NODE_ROOTS_MALFORMED;
	tag = tag_of(bytes, len);
	if (!tag || len > room - FZN_PERSIST_HEAD_LEN)
		return FZN_NODE_ROOTS_REFUSED;
	if (admit(roots, bytes, len) != FZN_ROOT_LOG_OK)
		return FZN_NODE_ROOTS_REFUSED;
	settle(roots);
	return fzn_node_roots_save(store, roots->hash, bytes, len);
}

fzn_node_roots_err_t fzn_node_roots_save(const fzn_persist_ops_t *store,
                                         const fzn_hash_ops_t *hash, const uint8_t *bytes,
                                         size_t len)
{
	uint8_t blob[CHANGE_BLOB_MAX];
	uint8_t id[FZN_ROOT_ACT_ID_LEN];
	uint8_t tag;

	if (!store || !store->save || !hash || !hash->hash || !bytes)
		return FZN_NODE_ROOTS_MALFORMED;
	tag = tag_of(bytes, len);
	if (!tag || len > sizeof(blob) - FZN_PERSIST_HEAD_LEN)
		return FZN_NODE_ROOTS_REFUSED;
	/* SAVED UNDER THE RECORD'S OWN ID, the hash every reference to it
	 * names, so one record has one row however often it is learned. */
	if (!hash->hash(hash->ctx, id, sizeof(id), bytes, len)
	    || fzn_persist_head_write(blob, sizeof(blob), len, tag) != FZN_PERSIST_OK)
		return FZN_NODE_ROOTS_NOT_SAVED;
	memcpy(blob + FZN_PERSIST_HEAD_LEN, bytes, len);
	if (!store->save(store->ctx, FZN_PERSIST_ROOT_CHANGE, id, blob,
	                 (size_t)FZN_PERSIST_HEAD_LEN + len))
		return FZN_NODE_ROOTS_NOT_SAVED;
	return FZN_NODE_ROOTS_OK;
}

/* Slot 13's records, admitted. */
static fzn_node_roots_err_t load_slot(fzn_node_roots_t *roots, const fzn_persist_ops_t *store,
                                      fzn_persist_slot_t slot, size_t *count)
{
	static uint8_t subjects[CHANGES_HELD_MAX * FZN_PUBKEY_LEN];
	size_t found = 0, i;

	if (!store->list(store->ctx, slot, subjects, CHANGES_HELD_MAX, &found))
		return FZN_NODE_ROOTS_STORE;
	for (i = 0; i < found; i++) {
		uint8_t blob[CHANGE_BLOB_MAX];
		size_t len = 0, body;
		uint8_t tag;

		if (!store->load(store->ctx, slot, subjects + (i * (size_t)FZN_PUBKEY_LEN), blob,
		                 sizeof(blob), &len)
		    || len <= FZN_PERSIST_HEAD_LEN)
			return FZN_NODE_ROOTS_STORE;
		body = len - FZN_PERSIST_HEAD_LEN;
		tag = tag_of(blob + FZN_PERSIST_HEAD_LEN, body);
		/* A ROW THAT NAMES NO ROOT RECORD, a root-log entry of before sec
		 * 507 among them, is a store written by something else. */
		if (!tag || fzn_persist_head_check(blob, len, body, tag) != FZN_PERSIST_OK
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
	err = load_slot(roots, store, FZN_PERSIST_ROOT_CHANGE, count);
	settle(roots);
	return err;
}

fzn_node_roots_err_t fzn_node_roots_attach(fzn_node_roots_t *roots,
                                           fzn_revocation_store_t *revocations)
{
	if (!roots || !revocations)
		return FZN_NODE_ROOTS_MALFORMED;
	roots->revocations = revocations;
	return fzn_revocation_store_set_roots(revocations, &roots->ops, roots->hash)
	                       == FZN_CHAIN_OK
	               && fzn_revocation_store_set_acts(revocations,
	                                                roots->journal ? &roots->acts : NULL)
	                          == FZN_CHAIN_OK
	               ? FZN_NODE_ROOTS_OK
	               : FZN_NODE_ROOTS_MALFORMED;
}

/* ---- a node's own root key and its acts, sec 409 --------------------- */

#define OWN_ROOT_BLOB ((size_t)FZN_PERSIST_HEAD_LEN + FZN_SIGN_SEED_LEN)

fzn_node_roots_err_t fzn_node_roots_key_load(fzn_node_roots_t *roots,
                                             const fzn_persist_ops_t *store,
                                             const fzn_sign_seat_t *seat,
                                             const fzn_sign_ops_t *sign)
{
	uint8_t blob[OWN_ROOT_BLOB];
	size_t len = 0;
	fzn_node_roots_err_t err = FZN_NODE_ROOTS_OK;

	if (!roots || !store || !store->load || !seat || !seat->install || !sign)
		return FZN_NODE_ROOTS_MALFORMED;
	roots->key_held = 0;
	if (!store->load(store->ctx, FZN_PERSIST_OWN_ROOT, NULL, blob, sizeof(blob), &len))
		return FZN_NODE_ROOTS_OK;
	/* NEVER ALL ZERO, as the identity seed never is: a zeroed file is a
	 * store that lost its bytes, not a key. */
	{
		uint8_t acc = 0;
		size_t i;

		for (i = FZN_PERSIST_HEAD_LEN; i < len; i++)
			acc = (uint8_t)(acc | blob[i]);
		if (fzn_persist_head_check(blob, len, FZN_SIGN_SEED_LEN, FZN_PERSIST_BLOB_OWN_ROOT)
		            != FZN_PERSIST_OK
		    || acc == 0u)
			err = FZN_NODE_ROOTS_STORE;
	}
	if (err == FZN_NODE_ROOTS_OK
	    && !seat->install(seat->ctx, blob + FZN_PERSIST_HEAD_LEN, roots->key))
		err = FZN_NODE_ROOTS_STORE;
	fzn_wipe(blob, sizeof(blob));
	if (err != FZN_NODE_ROOTS_OK)
		return err;
	roots->key_held = 1;
	roots->key_sign = sign;
	return FZN_NODE_ROOTS_OK;
}

fzn_node_roots_err_t fzn_node_roots_key_create(fzn_node_roots_t *roots,
                                               const fzn_persist_ops_t *store,
                                               const fzn_random_ops_t *rng,
                                               const fzn_sign_seat_t *seat,
                                               const fzn_sign_ops_t *sign)
{
	uint8_t blob[OWN_ROOT_BLOB], probe[OWN_ROOT_BLOB];
	size_t len = 0;
	int saved;

	if (!roots || !store || !store->load || !store->save || !rng || !rng->fill || !seat
	    || !seat->install || !sign)
		return FZN_NODE_ROOTS_MALFORMED;
	if (roots->key_held
	    || store->load(store->ctx, FZN_PERSIST_OWN_ROOT, NULL, probe, sizeof(probe), &len)) {
		fzn_wipe(probe, sizeof(probe));
		return FZN_NODE_ROOTS_HELD;
	}
	if (fzn_persist_head_write(blob, sizeof(blob), FZN_SIGN_SEED_LEN, FZN_PERSIST_BLOB_OWN_ROOT)
	            != FZN_PERSIST_OK
	    || !rng->fill(rng->ctx, blob + FZN_PERSIST_HEAD_LEN, FZN_SIGN_SEED_LEN)) {
		fzn_wipe(blob, sizeof(blob));
		return FZN_NODE_ROOTS_STORE;
	}
	/* SAVED BEFORE SEATED: a key that signs and is not stored is a root
	 * the next restart has lost. */
	saved = store->save(store->ctx, FZN_PERSIST_OWN_ROOT, NULL, blob, sizeof(blob));
	if (!saved || !seat->install(seat->ctx, blob + FZN_PERSIST_HEAD_LEN, roots->key)) {
		fzn_wipe(blob, sizeof(blob));
		return saved ? FZN_NODE_ROOTS_STORE : FZN_NODE_ROOTS_NOT_SAVED;
	}
	fzn_wipe(blob, sizeof(blob));
	roots->key_held = 1;
	roots->key_sign = sign;
	return FZN_NODE_ROOTS_OK;
}

size_t fzn_node_roots_standing(const fzn_node_roots_t *roots, uint8_t (*out)[FZN_PUBKEY_LEN],
                               size_t cap)
{
	size_t i, n = 0;

	if (!roots || !out)
		return 0;
	/* THE CANDIDATES are the genesis and every change's subject; the view
	 * says which stand, so a removed root drops out however it was added. */
	for (i = 0; i <= roots->set.used && n < cap; i++) {
		const uint8_t *key = i == 0u ? roots->set.genesis : roots->set.changes[i - 1u].subject;

		if (fzn_root_view_stands(&roots->view, key))
			memcpy(out[n++], key, FZN_PUBKEY_LEN);
	}
	return n;
}

int fzn_node_roots_acting(const fzn_node_roots_t *roots, const uint8_t identity[FZN_PUBKEY_LEN],
                          const fzn_sign_ops_t *identity_sign, const uint8_t **pubkey,
                          const fzn_sign_ops_t **sign)
{
	if (!roots || !pubkey || !sign)
		return 0;
	if (roots->key_held && fzn_root_view_stands(&roots->view, roots->key)) {
		*pubkey = roots->key;
		*sign = roots->key_sign;
		return 1;
	}
	if (identity && identity_sign && fzn_root_view_stands(&roots->view, identity)) {
		*pubkey = identity;
		*sign = identity_sign;
		return 1;
	}
	return 0;
}

fzn_node_roots_err_t fzn_node_roots_log_act(fzn_node_roots_t *roots,
                                            const fzn_persist_ops_t *store,
                                            const uint8_t pubkey[FZN_PUBKEY_LEN],
                                            const fzn_sign_ops_t *sign, uint8_t kind,
                                            const uint8_t *record, size_t len)
{
	uint8_t act[FZN_ROOT_ACT_ID_LEN];

	if (!roots || !store || !pubkey || !sign || !record)
		return FZN_NODE_ROOTS_MALFORMED;
	/* A STREAM THAT HAS FORKED is a key used in two places, and extending
	 * either branch would be choosing one. */
	if (roots->journal && fzn_node_journal_forked(roots->journal, pubkey))
		return FZN_NODE_ROOTS_FORKED;
	if (!roots->hash->hash(roots->hash->ctx, act, sizeof(act), record, len))
		return FZN_NODE_ROOTS_REFUSED;
	/* INTO THE JOURNAL, the act log since sec 508: the record is the act,
	 * and the stream's order is the log's. */
	if (roots->logged && !roots->logged(roots->logged_ctx, pubkey, sign, kind, act, record, len))
		return FZN_NODE_ROOTS_NOT_SAVED;
	return FZN_NODE_ROOTS_OK;
}

fzn_node_roots_err_t fzn_node_roots_log_signed(fzn_node_roots_t *roots,
                                               const fzn_persist_ops_t *store,
                                               const uint8_t identity[FZN_PUBKEY_LEN],
                                               const fzn_sign_ops_t *identity_sign,
                                               const uint8_t signer[FZN_PUBKEY_LEN],
                                               uint8_t kind, const uint8_t *record,
                                               size_t len)
{
	if (!roots || !store || !signer || !record)
		return FZN_NODE_ROOTS_MALFORMED;
	if (identity && identity_sign && fzn_ct_memeq(signer, identity, FZN_PUBKEY_LEN))
		return fzn_node_roots_log_act(roots, store, identity, identity_sign, kind, record,
		                              len);
	if (roots->key_held && roots->key_sign && fzn_ct_memeq(signer, roots->key, FZN_PUBKEY_LEN))
		return fzn_node_roots_log_act(roots, store, roots->key, roots->key_sign, kind, record,
		                              len);
	return FZN_NODE_ROOTS_OK;
}

int fzn_node_roots_head(const fzn_node_roots_t *roots, const uint8_t key[FZN_PUBKEY_LEN],
                        uint8_t id[FZN_ROOT_ACT_ID_LEN])
{
	if (!roots || !key || !id)
		return 0;
	/* THE JOURNAL'S HEAD, sec 506: a cut is a record id. */
	return roots->journal && fzn_node_journal_head(roots->journal, key, id);
}

fzn_node_roots_err_t fzn_node_roots_change(fzn_node_roots_t *roots,
                                           const fzn_persist_ops_t *store,
                                           const uint8_t identity[FZN_PUBKEY_LEN],
                                           const fzn_sign_ops_t *identity_sign, int remove,
                                           const uint8_t subject[FZN_PUBKEY_LEN],
                                           const uint8_t cut[FZN_ROOT_ACT_ID_LEN])
{
	uint8_t record[FZN_ROOT_REMOVE_LEN];
	const uint8_t *as = NULL;
	const fzn_sign_ops_t *sign = NULL;
	size_t len = remove ? FZN_ROOT_REMOVE_LEN : FZN_ROOT_ADD_LEN;
	fzn_node_roots_err_t err;

	if (!roots || !store || !subject)
		return FZN_NODE_ROOTS_MALFORMED;
	if (!fzn_node_roots_acting(roots, identity, identity_sign, &as, &sign))
		return FZN_NODE_ROOTS_NOT_ROOT;
	if ((remove ? fzn_root_remove_issue(as, subject, cut, sign, record)
	            : fzn_root_add_issue(as, subject, sign, record)) != FZN_ROOT_LOG_OK)
		return FZN_NODE_ROOTS_REFUSED;
	/* LOGGED FIRST, then learned: an act that is in the set and not in its
	 * root's log would fall at the root's own removal, whatever its cut. */
	err = fzn_node_roots_log_act(roots, store, as, sign,
	                             (uint8_t)(remove ? FZN_ROOT_ACT_ROOT_REMOVE
	                                              : FZN_ROOT_ACT_ROOT_ADD),
	                             record, len);
	if (err != FZN_NODE_ROOTS_OK)
		return err;
	return fzn_node_roots_learn(roots, store, record, len);
}

/* A path of accepted adds from `from` to `to`, at most `left` long, as change
 * indices into `path` from position `depth`; its length, or 0 with none. An
 * add is followed only where the settled view accepted it, so a proof never
 * rests on an add this node judged its signer could not make. */
static size_t find_path(const fzn_node_roots_t *roots, const uint8_t *from, const uint8_t *to,
                        size_t depth, size_t left, size_t path[FZN_PROVISION_PROOF_MAX])
{
	size_t i, n;

	for (i = 0; left && i < roots->set.used; i++) {
		const fzn_root_change_t *c = &roots->set.changes[i];

		if (c->object != (uint8_t)FZN_OBJECT_ROOT_ADD || !roots->view.add_ok[i]
		    || !fzn_ct_memeq(c->signer, from, FZN_PUBKEY_LEN))
			continue;
		path[depth] = i;
		if (fzn_ct_memeq(c->subject, to, FZN_PUBKEY_LEN))
			return depth + 1u;
		n = find_path(roots, c->subject, to, depth + 1u, left - 1u, path);
		if (n)
			return n;
	}
	return 0;
}

/* THE PROOF THAT `target` IS A ROOT: the adds from the genesis to it, from the
 * store's copies -- the set keeps their fields and not their signatures.
 * None for the genesis itself. */
static fzn_node_roots_err_t build_proof(const fzn_node_roots_t *roots,
                                        const fzn_persist_ops_t *store,
                                        const uint8_t target[FZN_PUBKEY_LEN],
                                        uint8_t proof[FZN_PROVISION_PROOF_MAX]
                                                    [FZN_PROVISION_PROOF_ITEM_LEN],
                                        size_t *count)
{
	size_t path[FZN_PROVISION_PROOF_MAX];
	size_t i;

	*count = 0;
	if (!fzn_ct_memeq(roots->set.genesis, target, FZN_PUBKEY_LEN)) {
		*count = find_path(roots, roots->set.genesis, target, 0, FZN_PROVISION_PROOF_MAX,
		                   path);
		if (!*count)
			return FZN_NODE_ROOTS_NO_PROOF;
	}
	for (i = 0; i < *count; i++) {
		uint8_t blob[CHANGE_BLOB_MAX];
		size_t len = 0;

		if (!store->load(store->ctx, FZN_PERSIST_ROOT_CHANGE, roots->set.changes[path[i]].id,
		                 blob, sizeof(blob), &len)
		    || len != (size_t)FZN_PERSIST_HEAD_LEN + FZN_ROOT_ADD_LEN
		    || fzn_persist_head_check(blob, len, FZN_ROOT_ADD_LEN,
		                              (uint8_t)FZN_PERSIST_BLOB_ROOT_ADD) != FZN_PERSIST_OK)
			return FZN_NODE_ROOTS_STORE;
		memcpy(proof[i], blob + FZN_PERSIST_HEAD_LEN, FZN_ROOT_ADD_LEN);
	}
	return FZN_NODE_ROOTS_OK;
}

fzn_node_roots_err_t fzn_node_roots_identity_root(fzn_node_roots_t *roots,
                                                  const fzn_persist_ops_t *store,
                                                  const uint8_t identity[FZN_PUBKEY_LEN],
                                                  uint8_t proof[FZN_PROVISION_PROOF_MAX]
                                                              [FZN_PROVISION_PROOF_ITEM_LEN],
                                                  fzn_node_authority_t *authority)
{
	size_t count = 0;
	fzn_node_roots_err_t err;

	if (!roots || !store || !store->load || !identity || !proof || !authority)
		return FZN_NODE_ROOTS_MALFORMED;
	/* THE GENESIS NEEDS NO PROOF and pairs as it always has. */
	if (fzn_ct_memeq(roots->set.genesis, identity, FZN_PUBKEY_LEN)
	    || !fzn_root_view_stands(&roots->view, identity))
		return FZN_NODE_ROOTS_NOT_ROOT;
	err = build_proof(roots, store, identity, proof, &count);
	if (err != FZN_NODE_ROOTS_OK)
		return err;
	memset(authority, 0, sizeof(*authority));
	authority->proof = (const uint8_t (*)[FZN_PROVISION_PROOF_ITEM_LEN])proof;
	authority->proof_count = count;
	return FZN_NODE_ROOTS_OK;
}

fzn_node_roots_err_t fzn_node_roots_self_grant(fzn_node_roots_t *roots,
                                               const fzn_persist_ops_t *store,
                                               const uint8_t identity[FZN_PUBKEY_LEN],
                                               const fzn_cap_id_t *cap,
                                               uint8_t hop[FZN_HOP_LEN],
                                               uint8_t proof[FZN_PROVISION_PROOF_MAX]
                                                           [FZN_PROVISION_PROOF_ITEM_LEN],
                                               fzn_node_authority_t *authority)
{
	uint8_t act[FZN_ROOT_ACT_ID_LEN], head[FZN_ROOT_ACT_ID_LEN];
	size_t count = 0;
	int logged;
	fzn_node_roots_err_t err;

	if (!roots || !store || !store->load || !identity || !cap || !hop || !proof || !authority)
		return FZN_NODE_ROOTS_MALFORMED;
	if (!roots->key_held || !fzn_root_view_stands(&roots->view, roots->key))
		return FZN_NODE_ROOTS_NOT_ROOT;

	err = build_proof(roots, store, roots->key, proof, &count);
	if (err != FZN_NODE_ROOTS_OK)
		return err;

	/* THE GRANT, logged once. */
	if (fzn_chain_mint(roots->key, identity, cap, 0u, FZN_NO_EXPIRY, 1, roots->key_sign, hop)
	            != FZN_CHAIN_OK
	    || !roots->hash->hash(roots->hash->ctx, act, sizeof(act), hop, FZN_HOP_LEN))
		return FZN_NODE_ROOTS_REFUSED;
	/* ONCE: already in the key's stream, it is not appended again. */
	logged = roots->journal && fzn_node_journal_head(roots->journal, roots->key, head)
	         && fzn_node_journal_stands(roots->journal, roots->key, head, act);
	if (!logged) {
		err = fzn_node_roots_log_act(roots, store, roots->key, roots->key_sign,
		                             (uint8_t)FZN_ROOT_ACT_GRANT, hop, FZN_HOP_LEN);
		if (err != FZN_NODE_ROOTS_OK)
			return err;
	}

	memset(authority, 0, sizeof(*authority));
	authority->hops = (const uint8_t (*)[FZN_HOP_LEN])hop;
	authority->hop_count = 1u;
	authority->proof = (const uint8_t (*)[FZN_PROVISION_PROOF_ITEM_LEN])proof;
	authority->proof_count = count;
	return FZN_NODE_ROOTS_OK;
}

/* ---- the estate's k, sec 418 ----------------------------------------- */

uint8_t fzn_node_roots_quorum(const fzn_node_roots_t *roots, uint8_t fallback)
{
	if (!roots || roots->settings_used == 0u)
		return fallback;
	return fzn_quorum_resolve((const uint8_t *)roots->settings, roots->settings_used,
	                          &roots->ops, roots->hash, fallback);
}

fzn_node_roots_err_t fzn_node_roots_set_quorum(fzn_node_roots_t *roots,
                                               const fzn_persist_ops_t *store,
                                               const uint8_t identity[FZN_PUBKEY_LEN],
                                               const fzn_sign_ops_t *identity_sign, uint8_t k)
{
	uint8_t record[FZN_QUORUM_SET_LEN], replaces[FZN_ROOT_ACT_ID_LEN];
	const uint8_t *as = NULL, *follows = NULL;
	const fzn_sign_ops_t *sign = NULL;
	uint8_t current = 0;
	fzn_node_roots_err_t err;

	if (!roots || !store || k == 0u)
		return FZN_NODE_ROOTS_MALFORMED;
	if (!fzn_node_roots_acting(roots, identity, identity_sign, &as, &sign))
		return FZN_NODE_ROOTS_NOT_ROOT;
	/* WHAT IT REPLACES: the setting that wins now, so the change supersedes
	 * what this root saw -- lowering k included. */
	if (roots->settings_used
	    && fzn_quorum_winner((const uint8_t *)roots->settings, roots->settings_used,
	                         &roots->ops, roots->hash, &current, replaces))
		follows = replaces;
	if (fzn_quorum_set_issue(as, k, follows, sign, record) != FZN_ROOT_LOG_OK)
		return FZN_NODE_ROOTS_REFUSED;
	/* LOGGED FIRST, then learned, as a root change is. */
	err = fzn_node_roots_log_act(roots, store, as, sign, (uint8_t)FZN_ROOT_ACT_SETTING, record,
	                             sizeof(record));
	if (err != FZN_NODE_ROOTS_OK)
		return err;
	return fzn_node_roots_learn(roots, store, record, sizeof(record));
}

/* ---- the estate's retention rules, sec 476 ------------------------------ */

struct gather {
	fzn_retain_rule_t *out;
	size_t cap, count, unread;
	/* For a removal: the canonical text sought, and the record found. */
	const char *seek;
	int found;
	uint8_t id[FZN_ROOT_ACT_ID_LEN];
};

static void gather_one(void *ctx, const char *text, size_t len,
                       const uint8_t id[FZN_ROOT_ACT_ID_LEN])
{
	struct gather *g = ctx;
	fzn_retain_rule_t rule;

	if (g->seek) {
		if (!g->found && strcmp(text, g->seek) == 0) {
			g->found = 1;
			memcpy(g->id, id, FZN_ROOT_ACT_ID_LEN);
		}
		return;
	}
	if (fzn_retain_parse(text, len, &rule) != FZN_RETAIN_OK) {
		g->unread++;
		return;
	}
	if (g->count < g->cap)
		g->out[g->count] = rule;
	g->count++;
}

fzn_node_roots_err_t fzn_node_roots_retention(const fzn_node_roots_t *roots,
                                              fzn_retain_rule_t *out, size_t cap, size_t *count,
                                              size_t *unread)
{
	struct gather g;

	if (!roots || (!out && cap) || !count || !unread)
		return FZN_NODE_ROOTS_MALFORMED;
	memset(&g, 0, sizeof(g));
	g.out = out;
	g.cap = cap;
	if (fzn_retention_current((const uint8_t *)roots->retention, roots->retention_used,
	                          &roots->judge, roots->hash, gather_one, &g)
	    < 0)
		return FZN_NODE_ROOTS_STORE;
	/* PASSED OVER, not dropped unseen: a rule past `cap` counts with one
	 * that will not read. */
	*count = g.count < cap ? g.count : cap;
	*unread = g.unread + (g.count - *count);
	return FZN_NODE_ROOTS_OK;
}

/* A RULE ADDED AGAIN after its removal must not be the record it was the
 * first time: signatures are deterministic, so the same setter, text and
 * `replaces` mint the same bytes, which its removal already replaces, and
 * the add would change nothing. So an add follows the removal of the same
 * text, when one stands unreplaced, and names it. sec 479. */
static int follows_removal(const fzn_node_roots_t *roots, const char *text, size_t len,
                           uint8_t id[FZN_ROOT_ACT_ID_LEN])
{
	static uint8_t ids[FZN_NODE_ROOT_RETENTION_MAX][FZN_ROOT_ACT_ID_LEN];
	size_t i, j, k;

	for (i = 0; i < roots->retention_used; i++)
		if (!roots->hash->hash(roots->hash->ctx, ids[i], FZN_ROOT_ACT_ID_LEN,
		                       roots->retention[i], FZN_RETENTION_SET_LEN))
			return 0;
	for (i = 0; i < roots->retention_used; i++) {
		const uint8_t *r = roots->retention[i];
		int replaced = 0;

		/* A REMOVAL: no text. */
		if (r[FZN_RETENTION_SET_OFF_TEXT] != 0u)
			continue;
		for (k = 0; k < roots->retention_used && !replaced; k++)
			replaced = memcmp(roots->retention[k] + FZN_RETENTION_SET_OFF_REPLACES, ids[i],
			                  FZN_ROOT_ACT_ID_LEN)
			           == 0;
		if (replaced)
			continue;
		/* OF THIS TEXT: the record it removed carries it. */
		for (j = 0; j < roots->retention_used; j++) {
			const uint8_t *t = roots->retention[j] + FZN_RETENTION_SET_OFF_TEXT;

			if (memcmp(ids[j], r + FZN_RETENTION_SET_OFF_REPLACES, FZN_ROOT_ACT_ID_LEN) == 0
			    && memcmp(t, text, len) == 0 && (len == FZN_RETENTION_SET_TEXT_MAX || t[len] == 0u)) {
				memcpy(id, ids[i], FZN_ROOT_ACT_ID_LEN);
				return 1;
			}
		}
	}
	return 0;
}

fzn_node_roots_err_t fzn_node_roots_set_retention(fzn_node_roots_t *roots,
                                                  const fzn_persist_ops_t *store,
                                                  const uint8_t identity[FZN_PUBKEY_LEN],
                                                  const fzn_sign_ops_t *identity_sign,
                                                  const fzn_retain_rule_t *rule, int add)
{
	uint8_t record[FZN_RETENTION_SET_LEN];
	char text[FZN_RETAIN_TEXT_MAX];
	const uint8_t *as = NULL, *follows = NULL;
	const fzn_sign_ops_t *sign = NULL;
	struct gather g;
	size_t len = 0;
	fzn_node_roots_err_t err;

	if (!roots || !store || !rule
	    || fzn_retain_text(rule, text, sizeof(text), &len) != FZN_RETAIN_OK
	    || len >= FZN_RETENTION_SET_TEXT_MAX)
		return FZN_NODE_ROOTS_MALFORMED;
	if (!fzn_node_roots_acting(roots, identity, identity_sign, &as, &sign))
		return FZN_NODE_ROOTS_NOT_ROOT;
	/* IS IT CURRENT: by its canonical text, which is how it was minted. */
	memset(&g, 0, sizeof(g));
	g.seek = text;
	if (fzn_retention_current((const uint8_t *)roots->retention, roots->retention_used,
	                          &roots->judge, roots->hash, gather_one, &g)
	    < 0)
		return FZN_NODE_ROOTS_STORE;
	if (add && g.found)
		return FZN_NODE_ROOTS_HELD;
	if (!add && !g.found)
		return FZN_NODE_ROOTS_REFUSED;
	if (roots->retention_used >= FZN_NODE_ROOT_RETENTION_MAX)
		return FZN_NODE_ROOTS_REFUSED;
	/* A REMOVAL REPLACES THE RECORD THAT CARRIES THE RULE, with no text;
	 * an add again follows the removal it undoes. */
	if (add && follows_removal(roots, text, len, g.id))
		follows = g.id;
	else if (!add)
		follows = g.id;
	if (fzn_retention_set_issue(as, add ? text : NULL, add ? len : 0u, follows, sign, record)
	    != FZN_ROOT_LOG_OK)
		return FZN_NODE_ROOTS_REFUSED;
	/* LOGGED FIRST, then learned, as a setting of k is. */
	err = fzn_node_roots_log_act(roots, store, as, sign, (uint8_t)FZN_ROOT_ACT_SETTING, record,
	                             sizeof(record));
	if (err != FZN_NODE_ROOTS_OK)
		return err;
	return fzn_node_roots_learn(roots, store, record, sizeof(record));
}

/* ---- an admin's retention records, sec 479 ------------------------------ */

#define ADMIN_HOPS_MAX ((size_t)FZN_CHAIN_MAX_HOPS - 1u)
#define ADMIN_RETENTION_BODY(n) ((size_t)FZN_RETENTION_SET_LEN + 1u + ((size_t)(n) * FZN_HOP_LEN))
#define ADMIN_RETENTION_BLOB_MAX ((size_t)FZN_PERSIST_HEAD_LEN + ADMIN_RETENTION_BODY(ADMIN_HOPS_MAX))

/* Keep one record in memory, once. */
static fzn_root_log_err_t keep_retention(fzn_node_roots_t *roots, const uint8_t *record)
{
	size_t i;

	for (i = 0; i < roots->retention_used; i++)
		if (memcmp(roots->retention[i], record, FZN_RETENTION_SET_LEN) == 0)
			return FZN_ROOT_LOG_OK;
	if (roots->retention_used >= FZN_NODE_ROOT_RETENTION_MAX)
		return FZN_ROOT_LOG_ERR_FULL;
	memcpy(roots->retention[roots->retention_used++], record, FZN_RETENTION_SET_LEN);
	return FZN_ROOT_LOG_OK;
}

/* Check one, admit its chain, and keep it in memory. */
static fzn_node_roots_err_t admit_admin_retention(fzn_node_roots_t *roots, const uint8_t *record,
                                                  size_t len, const uint8_t (*hops)[FZN_HOP_LEN],
                                                  size_t hop_count,
                                                  const uint8_t root[FZN_PUBKEY_LEN])
{
	fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];
	size_t i;

	if (!roots->revocations || !hops || hop_count == 0u || hop_count > ADMIN_HOPS_MAX)
		return FZN_NODE_ROOTS_REFUSED;
	if (fzn_retention_set_check(record, len, roots->sign) != FZN_ROOT_LOG_OK)
		return FZN_NODE_ROOTS_REFUSED;
	for (i = 0; i < hop_count; i++)
		if (fzn_hop_open(hops[i], FZN_HOP_LEN, &opened[i]) != FZN_CHAIN_OK)
			return FZN_NODE_ROOTS_REFUSED;
	/* THE CHAIN NAMES THE SETTER: `fzn_revocation_admin_admit` holds the
	 * chain's grantee to the key given, which is the record's setter. */
	if (fzn_revocation_admin_admit(roots->revocations, record + FZN_RETENTION_SET_OFF_SETTER,
	                               opened, hop_count, root, roots->sign)
	    != FZN_CHAIN_OK)
		return FZN_NODE_ROOTS_REFUSED;
	if (keep_retention(roots, record) != FZN_ROOT_LOG_OK)
		return FZN_NODE_ROOTS_REFUSED;
	return FZN_NODE_ROOTS_OK;
}

static fzn_node_roots_err_t save_admin_retention(const fzn_node_roots_t *roots,
                                                 const fzn_persist_ops_t *store,
                                                 const uint8_t *record,
                                                 const uint8_t (*hops)[FZN_HOP_LEN],
                                                 size_t hop_count)
{
	static uint8_t blob[ADMIN_RETENTION_BLOB_MAX];
	uint8_t id[FZN_ROOT_ACT_ID_LEN];
	uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	size_t i;

	if (!store->save
	    || !roots->hash->hash(roots->hash->ctx, id, sizeof(id), record, FZN_RETENTION_SET_LEN)
	    || fzn_persist_head_write(blob, sizeof(blob), ADMIN_RETENTION_BODY(hop_count),
	                              FZN_PERSIST_BLOB_ADMIN_RETENTION)
	               != FZN_PERSIST_OK)
		return FZN_NODE_ROOTS_NOT_SAVED;
	memcpy(body, record, FZN_RETENTION_SET_LEN);
	body[FZN_RETENTION_SET_LEN] = (uint8_t)hop_count;
	for (i = 0; i < hop_count; i++)
		memcpy(body + FZN_RETENTION_SET_LEN + 1u + (i * FZN_HOP_LEN), hops[i], FZN_HOP_LEN);
	/* FILED UNDER THE RECORD'S OWN ID, as a root record is. */
	if (!store->save(store->ctx, FZN_PERSIST_ADMIN_RETENTION, id, blob,
	                 FZN_PERSIST_HEAD_LEN + ADMIN_RETENTION_BODY(hop_count)))
		return FZN_NODE_ROOTS_NOT_SAVED;
	return FZN_NODE_ROOTS_OK;
}

int fzn_node_roots_admin_retention_get(const fzn_persist_ops_t *store,
                                       const uint8_t subject[FZN_PUBKEY_LEN],
                                       uint8_t record[FZN_RETENTION_SET_LEN],
                                       uint8_t (*hops)[FZN_HOP_LEN], size_t *hop_count)
{
	static uint8_t blob[ADMIN_RETENTION_BLOB_MAX];
	const uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	size_t len = 0, n, i;

	if (!store || !store->load || !subject || !record || !hops || !hop_count
	    || !store->load(store->ctx, FZN_PERSIST_ADMIN_RETENTION, subject, blob, sizeof(blob),
	                    &len)
	    || len < FZN_PERSIST_HEAD_LEN + ADMIN_RETENTION_BODY(1))
		return 0;
	n = body[FZN_RETENTION_SET_LEN];
	if (n == 0u || n > ADMIN_HOPS_MAX
	    || fzn_persist_head_check(blob, len, ADMIN_RETENTION_BODY(n),
	                              FZN_PERSIST_BLOB_ADMIN_RETENTION)
	               != FZN_PERSIST_OK)
		return 0;
	memcpy(record, body, FZN_RETENTION_SET_LEN);
	for (i = 0; i < n; i++)
		memcpy(hops[i], body + FZN_RETENTION_SET_LEN + 1u + (i * FZN_HOP_LEN), FZN_HOP_LEN);
	*hop_count = n;
	return 1;
}

fzn_node_roots_err_t fzn_node_roots_learn_admin_retention(
        fzn_node_roots_t *roots, const fzn_persist_ops_t *store, const uint8_t *record,
        size_t len, const uint8_t (*hops)[FZN_HOP_LEN], size_t hop_count,
        const uint8_t root[FZN_PUBKEY_LEN])
{
	fzn_node_roots_err_t err;

	if (!roots || !store || !record || !root)
		return FZN_NODE_ROOTS_MALFORMED;
	err = admit_admin_retention(roots, record, len, hops, hop_count, root);
	if (err != FZN_NODE_ROOTS_OK)
		return err;
	return save_admin_retention(roots, store, record, hops, hop_count);
}

fzn_node_roots_err_t fzn_node_roots_load_admin_retention(fzn_node_roots_t *roots,
                                                         const fzn_persist_ops_t *store,
                                                         const uint8_t root[FZN_PUBKEY_LEN],
                                                         size_t *count)
{
	static uint8_t subjects[FZN_NODE_ROOT_RETENTION_MAX * FZN_PUBKEY_LEN];
	static uint8_t hops[ADMIN_HOPS_MAX][FZN_HOP_LEN];
	uint8_t record[FZN_RETENTION_SET_LEN];
	size_t found = 0, i, n = 0;

	if (!roots || !store || !store->list || !root || !count)
		return FZN_NODE_ROOTS_MALFORMED;
	*count = 0;
	if (!store->list(store->ctx, FZN_PERSIST_ADMIN_RETENTION, subjects,
	                 FZN_NODE_ROOT_RETENTION_MAX, &found))
		return FZN_NODE_ROOTS_STORE;
	for (i = 0; i < found; i++) {
		if (!fzn_node_roots_admin_retention_get(store, subjects + (i * (size_t)FZN_PUBKEY_LEN),
		                                        record, hops, &n)
		    || admit_admin_retention(roots, record, sizeof(record),
		                             (const uint8_t (*)[FZN_HOP_LEN])hops, n, root)
		               != FZN_NODE_ROOTS_OK)
			return FZN_NODE_ROOTS_STORE;
		(*count)++;
	}
	return FZN_NODE_ROOTS_OK;
}

fzn_node_roots_err_t fzn_node_roots_set_retention_as_admin(
        fzn_node_roots_t *roots, const fzn_persist_ops_t *store,
        const uint8_t identity[FZN_PUBKEY_LEN], const fzn_sign_ops_t *identity_sign,
        const uint8_t (*hops)[FZN_HOP_LEN], size_t hop_count, const uint8_t root[FZN_PUBKEY_LEN],
        const fzn_retain_rule_t *rule, int add)
{
	uint8_t record[FZN_RETENTION_SET_LEN];
	char text[FZN_RETAIN_TEXT_MAX];
	struct gather g;
	size_t len = 0, before;
	fzn_node_roots_err_t err;

	if (!roots || !store || !identity || !identity_sign || !hops || !hop_count || !root || !rule
	    || fzn_retain_text(rule, text, sizeof(text), &len) != FZN_RETAIN_OK
	    || len >= FZN_RETENTION_SET_TEXT_MAX)
		return FZN_NODE_ROOTS_MALFORMED;
	memset(&g, 0, sizeof(g));
	g.seek = text;
	if (fzn_retention_current((const uint8_t *)roots->retention, roots->retention_used,
	                          &roots->judge, roots->hash, gather_one, &g)
	    < 0)
		return FZN_NODE_ROOTS_STORE;
	if (add && g.found)
		return FZN_NODE_ROOTS_HELD;
	if (!add && !g.found)
		return FZN_NODE_ROOTS_REFUSED;
	if (fzn_retention_set_issue(identity, add ? text : NULL, add ? len : 0u,
	                            (!add || follows_removal(roots, text, len, g.id)) ? g.id : NULL,
	                            identity_sign, record)
	    != FZN_ROOT_LOG_OK)
		return FZN_NODE_ROOTS_REFUSED;
	before = roots->retention_used;
	err = admit_admin_retention(roots, record, sizeof(record), hops, hop_count, root);
	if (err != FZN_NODE_ROOTS_OK)
		return err;
	/* STANDING, not merely holding a chain: a record by an admin the
	 * revocations do not stand up would be minted and count for nothing.
	 * The chain admitted stays; the record kept is let go. */
	if (!fzn_revocation_admin_stands(roots->revocations, identity)) {
		roots->retention_used = before;
		return FZN_NODE_ROOTS_NOT_ROOT;
	}
	err = save_admin_retention(roots, store, record, hops, hop_count);
	if (err != FZN_NODE_ROOTS_OK)
		return err;
	/* AND LOGGED AS THE ADMIN'S ACT, sec 505, which puts it in the
	 * admin's journal: the vote stream carried it until the journal took
	 * over, and nothing logged it, so with the stream gone it would never
	 * have left this node. */
	return fzn_node_roots_log_act(roots, store, identity, identity_sign,
	                              (uint8_t)FZN_ROOT_ACT_SETTING, record, sizeof(record));
}
