/* See roots.h. */

#include "roots.h"

#include "../wire/bytes.h"
#include "../local/vocabulary.h"

#include "../constant_time/constant_time.h"

#include <stdio.h>

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
	case FZN_NODE_ROOTS_NOT_ROOT:
		return "this node holds no key that stands as a root";
	case FZN_NODE_ROOTS_FORKED:
		return "this root's log has forked, and extending it would pick a branch";
	case FZN_NODE_ROOTS_HELD:
		return "this node already holds a root key";
	case FZN_NODE_ROOTS_NO_PROOF:
		return "no root-adds this node holds reach from the estate's root to its root key";
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
	size_t room = (CHANGE_BLOB_MAX > ENTRY_BLOB ? CHANGE_BLOB_MAX : ENTRY_BLOB);
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
	uint8_t blob[CHANGE_BLOB_MAX > ENTRY_BLOB ? CHANGE_BLOB_MAX : ENTRY_BLOB];
	uint8_t id[FZN_ROOT_ACT_ID_LEN];
	uint8_t tag;
	fzn_persist_slot_t slot;

	if (!store || !store->save || !hash || !hash->hash || !bytes)
		return FZN_NODE_ROOTS_MALFORMED;
	tag = tag_of(bytes, len);
	if (!tag || len > sizeof(blob) - FZN_PERSIST_HEAD_LEN)
		return FZN_NODE_ROOTS_REFUSED;
	/* SAVED UNDER THE RECORD'S OWN ID, the hash every reference to it
	 * names, so one record has one row however often it is learned. */
	slot = (tag == (uint8_t)FZN_PERSIST_BLOB_ROOT_ENTRY) ? FZN_PERSIST_ROOT_ENTRY
	                                                    : FZN_PERSIST_ROOT_CHANGE;
	if (!hash->hash(hash->ctx, id, sizeof(id), bytes, len)
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

/* ---- carriage, sec 408 ----------------------------------------------- */

/* THE MOST ITEMS A STREAM CAN CARRY: both slots full. */
#define ITEMS_MAX (2u * FZN_NODE_ROOT_LOG_MAX)

/* The letter an item takes, by blob tag. */
static char letter_of(uint8_t tag)
{
	switch (tag) {
	case FZN_PERSIST_BLOB_ROOT_ENTRY:
		return 'e';
	case FZN_PERSIST_BLOB_ROOT_ADD:
		return 'a';
	case FZN_PERSIST_BLOB_ROOT_REMOVE:
		return 'x';
	}
	return 0;
}

/* The record length an item letter carries. */
static size_t length_of(uint8_t letter)
{
	switch (letter) {
	case 'e':
		return FZN_ROOT_ACT_LEN;
	case 'a':
		return FZN_ROOT_ADD_LEN;
	case 'x':
		return FZN_ROOT_REMOVE_LEN;
	}
	return 0;
}

static void put_hex(char *out, const uint8_t *bytes, size_t len)
{
	static const char DIGITS[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[2u * i] = DIGITS[bytes[i] >> 4];
		out[(2u * i) + 1u] = DIGITS[bytes[i] & 15u];
	}
}

static int unhex(const uint8_t *text, uint8_t *out, size_t len)
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

static int take_count(const uint8_t *text, size_t len, size_t *at, size_t *value)
{
	size_t v = 0, start = *at;

	while (*at < len && text[*at] >= '0' && text[*at] <= '9') {
		if (v > ITEMS_MAX * 16u)
			return 0;
		v = (v * 10u) + (size_t)(text[*at] - '0');
		(*at)++;
	}
	*value = v;
	return *at > start;
}

int fzn_node_roots_page(const fzn_persist_ops_t *store, size_t from, char *out, size_t cap,
                        size_t *len, size_t *total)
{
	static uint8_t subjects[2][FZN_NODE_ROOT_LOG_MAX * FZN_PUBKEY_LEN];
	static const fzn_persist_slot_t SLOTS[2] = { FZN_PERSIST_ROOT_ENTRY,
		                                     FZN_PERSIST_ROOT_CHANGE };
	size_t count[2], s, i, item = 0, at = 0;
	int full = 0;

	if (!store || !store->load || !store->list || !out || !len || !total)
		return 0;
	for (s = 0; s < 2u; s++)
		if (!store->list(store->ctx, SLOTS[s], subjects[s], FZN_NODE_ROOT_LOG_MAX, &count[s]))
			return 0;
	for (s = 0; s < 2u; s++) {
		for (i = 0; i < count[s]; i++, item++) {
			uint8_t blob[CHANGE_BLOB_MAX > ENTRY_BLOB ? CHANGE_BLOB_MAX : ENTRY_BLOB];
			size_t blen = 0, body, need;
			char letter;

			if (item < from || full)
				continue;
			if (!store->load(store->ctx, SLOTS[s], subjects[s] + (i * (size_t)FZN_PUBKEY_LEN),
			                 blob, sizeof(blob), &blen)
			    || blen <= FZN_PERSIST_HEAD_LEN)
				return 0;
			body = blen - FZN_PERSIST_HEAD_LEN;
			letter = letter_of(tag_of(blob + FZN_PERSIST_HEAD_LEN, body));
			if (!letter || length_of((uint8_t)letter) != body)
				return 0;
			need = 2u + (body * 2u);
			if (at + need > cap) {
				full = 1;
				continue;
			}
			out[at++] = ' ';
			out[at++] = letter;
			put_hex(out + at, blob + FZN_PERSIST_HEAD_LEN, body);
			at += body * 2u;
		}
	}
	*len = at;
	*total = item;
	return 1;
}

fzn_node_pull_err_t fzn_node_roots_absorb(fzn_node_roots_t *roots,
                                          const fzn_persist_ops_t *store,
                                          const uint8_t *reply, size_t reply_len, size_t from,
                                          size_t *next, size_t *total, size_t *learned,
                                          size_t *refused)
{
	const uint8_t *detail = NULL;
	size_t detail_len = 0, at = 0, off = 0, on_page = 0;

	if (!roots || !store || !reply || !next || !total || !learned || !refused)
		return FZN_NODE_PULL_MALFORMED;
	if (fzn_reply_of(reply, reply_len, &detail, &detail_len) != FZN_REPLY_OK)
		return FZN_NODE_PULL_NO_ANSWER;
	if (detail_len && detail[detail_len - 1u] == '\n')
		detail_len--;
	if (!take_count(detail, detail_len, &at, total) || at >= detail_len
	    || detail[at++] != ' ' || !take_count(detail, detail_len, &at, &off) || off != from
	    || *total > ITEMS_MAX)
		return FZN_NODE_PULL_SHAPE;
	while (at < detail_len) {
		uint8_t record[FZN_ROOT_ACT_LEN > FZN_ROOT_REMOVE_LEN ? FZN_ROOT_ACT_LEN
		                                                    : FZN_ROOT_REMOVE_LEN];
		size_t body;
		fzn_node_roots_err_t err;

		if (detail[at] != ' ' || detail_len - at < 2u)
			return FZN_NODE_PULL_SHAPE;
		body = length_of(detail[at + 1u]);
		if (!body || detail_len - at < 2u + (body * 2u)
		    || !unhex(detail + at + 2u, record, body)
		    || tag_of(record, body) == 0
		    || letter_of(tag_of(record, body)) != (char)detail[at + 1u])
			return FZN_NODE_PULL_SHAPE;
		at += 2u + (body * 2u);
		on_page++;
		err = fzn_node_roots_learn(roots, store, record, body);
		if (err == FZN_NODE_ROOTS_OK)
			(*learned)++;
		else if (err == FZN_NODE_ROOTS_REFUSED)
			(*refused)++;
		else
			return FZN_NODE_PULL_NOT_SAVED;
	}
	*next = from + on_page;
	if (on_page == 0u && *next < *total)
		return FZN_NODE_PULL_SHAPE;
	return FZN_NODE_PULL_OK;
}

fzn_node_pull_err_t fzn_node_roots_pull(fzn_node_roots_t *roots, const fzn_persist_ops_t *store,
                                        fzn_caller_t *caller, uint64_t now, size_t *learned,
                                        size_t *refused)
{
	static uint8_t reply[FZN_REPLY_MAX + 1u];
	size_t from = 0, pages = 0;

	if (!roots || !caller || !learned || !refused)
		return FZN_NODE_PULL_MALFORMED;
	*learned = 0;
	*refused = 0;
	/* BOUNDED BY THE ITEMS A FULL STORE COULD HOLD, at one a page. */
	while (pages++ <= ITEMS_MAX) {
		char ask[32];
		size_t reply_len = 0, next = 0, total = 0;
		uint32_t msg = 0;
		fzn_node_pull_err_t err;
		int n;

		n = snprintf(ask, sizeof(ask), "get root %zu", from);
		if (n < 0 || (size_t)n >= sizeof(ask))
			return FZN_NODE_PULL_MALFORMED;
		if (fzn_caller_send(caller, (const uint8_t *)ask, (size_t)n, now + 300u, &msg)
		            != FZN_CALLER_OK
		    || fzn_caller_recv(caller, msg, reply, sizeof(reply), &reply_len, 3000u)
		               != FZN_CALLER_OK)
			return FZN_NODE_PULL_NO_ANSWER;
		err = fzn_node_roots_absorb(roots, store, reply, reply_len, from, &next, &total,
		                            learned, refused);
		if (err != FZN_NODE_PULL_OK)
			return err;
		if (next >= total)
			return FZN_NODE_PULL_OK;
		from = next;
	}
	return FZN_NODE_PULL_SHAPE;
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
	const fzn_root_log_entry_t *head = NULL;
	uint8_t act[FZN_ROOT_ACT_ID_LEN], entry[FZN_ROOT_ACT_LEN];
	size_t i;

	if (!roots || !store || !pubkey || !sign || !record)
		return FZN_NODE_ROOTS_MALFORMED;
	if (fzn_root_log_forked(&roots->log, pubkey))
		return FZN_NODE_ROOTS_FORKED;
	/* THE HEAD: this root's entry at the greatest seq. With no fork there
	 * is exactly one there. */
	for (i = 0; i < roots->log.used; i++) {
		const fzn_root_log_entry_t *e = &roots->log.entries[i];

		if (fzn_ct_memeq(e->root, pubkey, FZN_PUBKEY_LEN) && (!head || e->seq > head->seq))
			head = e;
	}
	if (!roots->hash->hash(roots->hash->ctx, act, sizeof(act), record, len)
	    || fzn_root_act_issue(pubkey, head ? head->seq + 1u : 0u, head ? head->id : NULL, kind,
	                          act, sign, entry) != FZN_ROOT_LOG_OK)
		return FZN_NODE_ROOTS_REFUSED;
	return fzn_node_roots_learn(roots, store, entry, sizeof(entry));
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

fzn_node_roots_err_t fzn_node_roots_self_grant(fzn_node_roots_t *roots,
                                               const fzn_persist_ops_t *store,
                                               const uint8_t identity[FZN_PUBKEY_LEN],
                                               const fzn_cap_id_t *cap,
                                               uint8_t hop[FZN_HOP_LEN],
                                               uint8_t proof[FZN_PROVISION_PROOF_MAX]
                                                           [FZN_PROVISION_PROOF_ITEM_LEN],
                                               fzn_node_authority_t *authority)
{
	size_t path[FZN_PROVISION_PROOF_MAX];
	uint8_t act[FZN_ROOT_ACT_ID_LEN];
	size_t count = 0, i;
	int logged = 0;
	fzn_node_roots_err_t err;

	if (!roots || !store || !store->load || !identity || !cap || !hop || !proof || !authority)
		return FZN_NODE_ROOTS_MALFORMED;
	if (!roots->key_held || !fzn_root_view_stands(&roots->view, roots->key))
		return FZN_NODE_ROOTS_NOT_ROOT;

	/* THE PROOF, from the store's copies of the adds the set holds: the set
	 * keeps their fields and not their signatures. */
	if (!fzn_ct_memeq(roots->set.genesis, roots->key, FZN_PUBKEY_LEN)) {
		count = find_path(roots, roots->set.genesis, roots->key, 0, FZN_PROVISION_PROOF_MAX,
		                  path);
		if (!count)
			return FZN_NODE_ROOTS_NO_PROOF;
	}
	for (i = 0; i < count; i++) {
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

	/* THE GRANT, logged once. */
	if (fzn_chain_mint(roots->key, identity, cap, 0u, FZN_NO_EXPIRY, 1, roots->key_sign, hop)
	            != FZN_CHAIN_OK
	    || !roots->hash->hash(roots->hash->ctx, act, sizeof(act), hop, FZN_HOP_LEN))
		return FZN_NODE_ROOTS_REFUSED;
	for (i = 0; i < roots->log.used && !logged; i++)
		logged = fzn_ct_memeq(roots->log.entries[i].root, roots->key, FZN_PUBKEY_LEN)
		         && fzn_ct_memeq(roots->log.entries[i].act, act, sizeof(act));
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
