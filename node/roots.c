/* See roots.h. */

#include "roots.h"

#include "../wire/bytes.h"
#include "../local/vocabulary.h"

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
