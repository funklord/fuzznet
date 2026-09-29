/* See root_log.h. */

#include "root_log.h"
#include "revocation.h"

#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#include <string.h>

/* THE LAYOUT, pinned as literals for the reason revocation.c gives: a
 * constant checked against itself checks nothing. */
_Static_assert(FZN_ROOT_ACT_OFF_VERSION == 0u, "root act layout: version moved");
_Static_assert(FZN_ROOT_ACT_OFF_OBJECT == 1u, "root act layout: object moved");
_Static_assert(FZN_ROOT_ACT_OFF_ROOT == 2u, "root act layout: root moved");
_Static_assert(FZN_ROOT_ACT_OFF_SEQ == 34u, "root act layout: seq moved");
_Static_assert(FZN_ROOT_ACT_OFF_PREV == 42u, "root act layout: prev moved");
_Static_assert(FZN_ROOT_ACT_OFF_KIND == 74u, "root act layout: kind moved");
_Static_assert(FZN_ROOT_ACT_OFF_ACT == 75u, "root act layout: act moved");
_Static_assert(FZN_ROOT_ACT_OFF_SIGNATURE == 107u, "root act layout: the signature moved");
_Static_assert(FZN_ROOT_ACT_LEN == 171u, "root act layout: an entry is not 171 bytes");

const char *fzn_root_log_err_str(fzn_root_log_err_t err)
{
	switch (err) {
	case FZN_ROOT_LOG_OK:
		return "ok";
	case FZN_ROOT_LOG_ERR_MALFORMED:
		return "malformed";
	case FZN_ROOT_LOG_ERR_SHAPE:
		return "not a root log entry";
	case FZN_ROOT_LOG_ERR_SIGNATURE:
		return "the entry is not signed by the root it names";
	case FZN_ROOT_LOG_ERR_FULL:
		return "the log is full, and a log never evicts";
	case FZN_ROOT_LOG_ERR_CRYPTO:
		return "the signer or the hash would not run";
	}
	return "unknown";
}

static int all_zero(const uint8_t *p, size_t n)
{
	uint8_t acc = 0;
	size_t i;

	for (i = 0; i < n; i++)
		acc = (uint8_t)(acc | p[i]);
	return acc == 0u;
}

static int kind_known(uint8_t kind)
{
	return kind >= (uint8_t)FZN_ROOT_ACT_GRANT && kind <= (uint8_t)FZN_ROOT_ACT_ROOT_REMOVE;
}

fzn_root_log_err_t fzn_root_act_open(const uint8_t *bytes, size_t len, fzn_root_act_t *out)
{
	uint64_t seq;
	int no_prev;

	if (!bytes || !out)
		return FZN_ROOT_LOG_ERR_MALFORMED;
	if (len != FZN_ROOT_ACT_LEN || bytes[FZN_ROOT_ACT_OFF_VERSION] != (uint8_t)FZN_SIGNED_VERSION
	    || bytes[FZN_ROOT_ACT_OFF_OBJECT] != (uint8_t)FZN_OBJECT_ROOT_ACT
	    || !kind_known(bytes[FZN_ROOT_ACT_OFF_KIND]))
		return FZN_ROOT_LOG_ERR_SHAPE;
	/* THE FIRST ENTRY NAMES NO PREDECESSOR AND EVERY LATER ONE NAMES ONE: a
	 * later entry with a zero `prev` would be a second start to the chain,
	 * and a first one with a `prev` would claim a history that is not
	 * there. */
	seq = fzn_get_be64(bytes + FZN_ROOT_ACT_OFF_SEQ);
	no_prev = all_zero(bytes + FZN_ROOT_ACT_OFF_PREV, FZN_ROOT_ACT_ID_LEN);
	if ((seq == 0u) != no_prev)
		return FZN_ROOT_LOG_ERR_SHAPE;
	out->base = bytes;
	return FZN_ROOT_LOG_OK;
}

fzn_root_log_err_t fzn_root_act_issue(const uint8_t root[FZN_PUBKEY_LEN], uint64_t seq,
                                      const uint8_t prev[FZN_ROOT_ACT_ID_LEN], uint8_t kind,
                                      const uint8_t act[FZN_ROOT_ACT_ID_LEN],
                                      const fzn_sign_ops_t *sign, uint8_t *out)
{
	fzn_root_act_t view;

	if (!root || !act || !sign || !sign->sign || !out)
		return FZN_ROOT_LOG_ERR_MALFORMED;
	if (!kind_known(kind) || (seq > 0u && (!prev || all_zero(prev, FZN_ROOT_ACT_ID_LEN))))
		return FZN_ROOT_LOG_ERR_MALFORMED;
	out[FZN_ROOT_ACT_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	out[FZN_ROOT_ACT_OFF_OBJECT] = (uint8_t)FZN_OBJECT_ROOT_ACT;
	memcpy(out + FZN_ROOT_ACT_OFF_ROOT, root, FZN_PUBKEY_LEN);
	fzn_put_be64(out + FZN_ROOT_ACT_OFF_SEQ, seq);
	if (seq > 0u)
		memcpy(out + FZN_ROOT_ACT_OFF_PREV, prev, FZN_ROOT_ACT_ID_LEN);
	else
		memset(out + FZN_ROOT_ACT_OFF_PREV, 0, FZN_ROOT_ACT_ID_LEN);
	out[FZN_ROOT_ACT_OFF_KIND] = kind;
	memcpy(out + FZN_ROOT_ACT_OFF_ACT, act, FZN_ROOT_ACT_ID_LEN);
	/* Opened from the bytes just written, so what is signed is what a
	 * reader will verify. */
	if (fzn_root_act_open(out, FZN_ROOT_ACT_LEN, &view) != FZN_ROOT_LOG_OK
	    || !sign->sign(sign->ctx, out + FZN_ROOT_ACT_OFF_SIGNATURE, out,
	                   FZN_ROOT_ACT_BODY_LEN)) {
		memset(out, 0, FZN_ROOT_ACT_LEN);
		return FZN_ROOT_LOG_ERR_CRYPTO;
	}
	return FZN_ROOT_LOG_OK;
}

static int sound(const fzn_root_log_t *log)
{
	return log && log->entries && log->used <= log->capacity;
}

fzn_root_log_err_t fzn_root_log_init(fzn_root_log_t *log, fzn_root_log_entry_t *entries,
                                     size_t capacity)
{
	if (!log || !entries || capacity == 0u)
		return FZN_ROOT_LOG_ERR_MALFORMED;
	log->entries = entries;
	log->capacity = capacity;
	log->used = 0;
	return FZN_ROOT_LOG_OK;
}

/* The entry with this id, or NULL. */
static const fzn_root_log_entry_t *by_id(const fzn_root_log_t *log,
                                         const uint8_t id[FZN_ROOT_ACT_ID_LEN])
{
	size_t i;

	for (i = 0; i < log->used; i++)
		if (fzn_ct_memeq(log->entries[i].id, id, FZN_ROOT_ACT_ID_LEN))
			return &log->entries[i];
	return NULL;
}

fzn_root_log_err_t fzn_root_log_admit(fzn_root_log_t *log, const uint8_t *bytes, size_t len,
                                      const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash)
{
	fzn_root_log_entry_t e;
	fzn_root_act_t view;
	fzn_root_log_err_t err;

	if (!sound(log) || !sign || !sign->verify || !hash || !hash->hash)
		return FZN_ROOT_LOG_ERR_MALFORMED;
	err = fzn_root_act_open(bytes, len, &view);
	if (err != FZN_ROOT_LOG_OK)
		return err;
	if (!sign->verify(sign->ctx, fzn_root_act_root(view), bytes, FZN_ROOT_ACT_BODY_LEN,
	                  bytes + FZN_ROOT_ACT_OFF_SIGNATURE))
		return FZN_ROOT_LOG_ERR_SIGNATURE;
	memset(&e, 0, sizeof(e));
	if (!hash->hash(hash->ctx, e.id, sizeof(e.id), bytes, FZN_ROOT_ACT_LEN))
		return FZN_ROOT_LOG_ERR_CRYPTO;
	if (by_id(log, e.id))
		return FZN_ROOT_LOG_OK;
	if (log->used >= log->capacity)
		return FZN_ROOT_LOG_ERR_FULL;
	memcpy(e.root, fzn_root_act_root(view), FZN_PUBKEY_LEN);
	e.seq = fzn_root_act_seq(view);
	memcpy(e.prev, fzn_root_act_prev(view), FZN_ROOT_ACT_ID_LEN);
	e.kind = fzn_root_act_kind(view);
	memcpy(e.act, fzn_root_act_act(view), FZN_ROOT_ACT_ID_LEN);
	log->entries[log->used++] = e;
	return FZN_ROOT_LOG_OK;
}

int fzn_root_log_stands(const fzn_root_log_t *log, const uint8_t root[FZN_PUBKEY_LEN],
                        const uint8_t cut[FZN_ROOT_ACT_ID_LEN],
                        const uint8_t act[FZN_ROOT_ACT_ID_LEN])
{
	const fzn_root_log_entry_t *at;
	size_t steps;

	if (!sound(log) || !root || !cut || !act)
		return 0;
	at = by_id(log, cut);
	/* BOUNDED BY THE LOG, not by the chain's word: each step is one seq
	 * lower and a log of n entries can be walked at most n times. */
	for (steps = 0; at && steps <= log->used; steps++) {
		const fzn_root_log_entry_t *prev;

		if (!fzn_ct_memeq(at->root, root, FZN_PUBKEY_LEN))
			return 0;
		if (fzn_ct_memeq(at->act, act, FZN_ROOT_ACT_ID_LEN))
			return 1;
		if (at->seq == 0u)
			return 0;
		prev = by_id(log, at->prev);
		/* A LINK THAT DOES NOT DESCEND BY ONE is not this chain, whatever
		 * it names: a predecessor must be the root's own entry at the seq
		 * below. */
		if (!prev || prev->seq + 1u != at->seq)
			return 0;
		at = prev;
	}
	return 0;
}

int fzn_root_log_forked(const fzn_root_log_t *log, const uint8_t root[FZN_PUBKEY_LEN])
{
	size_t i, j;

	if (!sound(log) || !root)
		return 0;
	for (i = 0; i < log->used; i++) {
		if (!fzn_ct_memeq(log->entries[i].root, root, FZN_PUBKEY_LEN))
			continue;
		for (j = i + 1u; j < log->used; j++)
			if (log->entries[j].seq == log->entries[i].seq
			    && fzn_ct_memeq(log->entries[j].root, root, FZN_PUBKEY_LEN))
				return 1;
	}
	return 0;
}

/* ---- the root set, sec 405 ------------------------------------------- */

_Static_assert(FZN_ROOT_ADD_LEN == 130u, "root-add layout: a record is not 130 bytes");
_Static_assert(FZN_ROOT_REMOVE_LEN == 162u, "root-remove layout: a record is not 162 bytes");

/* Lay out and sign a root-set record: `body` bytes then the signature. */
static fzn_root_log_err_t sign_change(uint8_t object, const uint8_t signer[FZN_PUBKEY_LEN],
                                      const uint8_t subject[FZN_PUBKEY_LEN],
                                      const uint8_t *cut, size_t body,
                                      const fzn_sign_ops_t *sign, uint8_t *out)
{
	if (!signer || !subject || !sign || !sign->sign || !out)
		return FZN_ROOT_LOG_ERR_MALFORMED;
	out[0] = (uint8_t)FZN_SIGNED_VERSION;
	out[1] = object;
	memcpy(out + FZN_ROOT_SET_OFF_SIGNER, signer, FZN_PUBKEY_LEN);
	memcpy(out + FZN_ROOT_SET_OFF_SUBJECT, subject, FZN_PUBKEY_LEN);
	if (object == (uint8_t)FZN_OBJECT_ROOT_REMOVE) {
		if (cut)
			memcpy(out + FZN_ROOT_SET_OFF_CUT, cut, FZN_ROOT_ACT_ID_LEN);
		else
			memset(out + FZN_ROOT_SET_OFF_CUT, 0, FZN_ROOT_ACT_ID_LEN);
	}
	if (!sign->sign(sign->ctx, out + body, out, body)) {
		memset(out, 0, body + (size_t)FZN_SIG_LEN);
		return FZN_ROOT_LOG_ERR_CRYPTO;
	}
	return FZN_ROOT_LOG_OK;
}

fzn_root_log_err_t fzn_root_add_issue(const uint8_t adder[FZN_PUBKEY_LEN],
                                      const uint8_t added[FZN_PUBKEY_LEN],
                                      const fzn_sign_ops_t *sign, uint8_t *out)
{
	return sign_change((uint8_t)FZN_OBJECT_ROOT_ADD, adder, added, NULL, FZN_ROOT_ADD_BODY_LEN,
	                   sign, out);
}

fzn_root_log_err_t fzn_root_remove_issue(const uint8_t remover[FZN_PUBKEY_LEN],
                                         const uint8_t removed[FZN_PUBKEY_LEN],
                                         const uint8_t cut[FZN_ROOT_ACT_ID_LEN],
                                         const fzn_sign_ops_t *sign, uint8_t *out)
{
	return sign_change((uint8_t)FZN_OBJECT_ROOT_REMOVE, remover, removed, cut,
	                   FZN_ROOT_REMOVE_BODY_LEN, sign, out);
}

static int set_sound(const fzn_root_set_t *set)
{
	return set && set->changes && set->capacity <= FZN_ROOT_SET_MAX
	       && set->used <= set->capacity;
}

fzn_root_log_err_t fzn_root_set_init(fzn_root_set_t *set, const uint8_t genesis[FZN_PUBKEY_LEN],
                                     fzn_root_change_t *changes, size_t capacity)
{
	if (!set || !genesis || !changes || capacity == 0u || capacity > FZN_ROOT_SET_MAX)
		return FZN_ROOT_LOG_ERR_MALFORMED;
	memcpy(set->genesis, genesis, FZN_PUBKEY_LEN);
	set->changes = changes;
	set->capacity = capacity;
	set->used = 0;
	return FZN_ROOT_LOG_OK;
}

fzn_root_log_err_t fzn_root_set_admit(fzn_root_set_t *set, const uint8_t *bytes, size_t len,
                                      const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash)
{
	fzn_root_change_t c;
	size_t body, i;

	if (!set_sound(set) || !bytes || !sign || !sign->verify || !hash || !hash->hash)
		return FZN_ROOT_LOG_ERR_MALFORMED;
	if (len < 2u || bytes[0] != (uint8_t)FZN_SIGNED_VERSION)
		return FZN_ROOT_LOG_ERR_SHAPE;
	if (bytes[1] == (uint8_t)FZN_OBJECT_ROOT_ADD)
		body = FZN_ROOT_ADD_BODY_LEN;
	else if (bytes[1] == (uint8_t)FZN_OBJECT_ROOT_REMOVE)
		body = FZN_ROOT_REMOVE_BODY_LEN;
	else
		return FZN_ROOT_LOG_ERR_SHAPE;
	if (len != body + (size_t)FZN_SIG_LEN)
		return FZN_ROOT_LOG_ERR_SHAPE;
	if (!sign->verify(sign->ctx, bytes + FZN_ROOT_SET_OFF_SIGNER, bytes, body, bytes + body))
		return FZN_ROOT_LOG_ERR_SIGNATURE;
	memset(&c, 0, sizeof(c));
	c.object = bytes[1];
	memcpy(c.signer, bytes + FZN_ROOT_SET_OFF_SIGNER, FZN_PUBKEY_LEN);
	memcpy(c.subject, bytes + FZN_ROOT_SET_OFF_SUBJECT, FZN_PUBKEY_LEN);
	if (c.object == (uint8_t)FZN_OBJECT_ROOT_REMOVE)
		memcpy(c.cut, bytes + FZN_ROOT_SET_OFF_CUT, FZN_ROOT_ACT_ID_LEN);
	if (!hash->hash(hash->ctx, c.id, sizeof(c.id), bytes, len))
		return FZN_ROOT_LOG_ERR_CRYPTO;
	for (i = 0; i < set->used; i++)
		if (fzn_ct_memeq(set->changes[i].id, c.id, FZN_ROOT_ACT_ID_LEN))
			return FZN_ROOT_LOG_OK;
	if (set->used >= set->capacity)
		return FZN_ROOT_LOG_ERR_FULL;
	set->changes[set->used++] = c;
	return FZN_ROOT_LOG_OK;
}

/* What a reading of the set settles, which adds and which removals count,
 * is kept in a `fzn_root_view_t`. */
#define settled fzn_root_view

static int is_add(const fzn_root_change_t *c)
{
	return c->object == (uint8_t)FZN_OBJECT_ROOT_ADD;
}

static int member_in(const fzn_root_set_t *set, const struct settled *st, const uint8_t *key)
{
	size_t i;

	if (fzn_ct_memeq(set->genesis, key, FZN_PUBKEY_LEN))
		return 1;
	for (i = 0; i < set->used; i++)
		if (is_add(&set->changes[i]) && st->add_ok[i]
		    && fzn_ct_memeq(set->changes[i].subject, key, FZN_PUBKEY_LEN))
			return 1;
	return 0;
}

static int removed_in(const fzn_root_set_t *set, const struct settled *st, const uint8_t *key)
{
	size_t i;

	for (i = 0; i < set->used; i++)
		if (!is_add(&set->changes[i]) && st->rem_ok[i]
		    && fzn_ct_memeq(set->changes[i].subject, key, FZN_PUBKEY_LEN))
			return 1;
	return 0;
}

/* THE ACT RULE, under the removals `st` holds: a member not removed, or an
 * act that stands under the cut of every counting removal of its root. A
 * removal naming no cut leaves nothing standing, and without a log nothing a
 * removed root did can be shown to stand. */
static int counts_in(const fzn_root_set_t *set, const fzn_root_log_t *log,
                     const struct settled *st, const uint8_t *root, const uint8_t *act)
{
	size_t i;

	if (!member_in(set, st, root))
		return 0;
	for (i = 0; i < set->used; i++) {
		const fzn_root_change_t *c = &set->changes[i];

		if (is_add(c) || !st->rem_ok[i] || !fzn_ct_memeq(c->subject, root, FZN_PUBKEY_LEN))
			continue;
		if (!log || all_zero(c->cut, FZN_ROOT_ACT_ID_LEN)
		    || !fzn_root_log_stands(log, root, c->cut, act))
			return 0;
	}
	return 1;
}

/* Membership as the least fixed point from the genesis root, with the
 * removals in `st` held fixed. Monotone, so it ends within `used` passes. */
static void grow_members(const fzn_root_set_t *set, const fzn_root_log_t *log, struct settled *st)
{
	size_t i;
	int changed = 1;

	memset(st->add_ok, 0, sizeof(st->add_ok));
	while (changed) {
		changed = 0;
		for (i = 0; i < set->used; i++) {
			const fzn_root_change_t *c = &set->changes[i];

			if (!is_add(c) || st->add_ok[i])
				continue;
			if (counts_in(set, log, st, c->signer, c->id)) {
				st->add_ok[i] = 1;
				changed = 1;
			}
		}
	}
}

/* THE ROUNDS: fix the removals, grow membership, recompute the removals
 * from it, until they stop changing. Bounded by the records: a set that has
 * not settled in `used + 1` rounds takes every removal any round saw. */
static void settle(const fzn_root_set_t *set, const fzn_root_log_t *log, struct settled *st)
{
	uint8_t seen[FZN_ROOT_SET_MAX], next[FZN_ROOT_SET_MAX];
	size_t round, i;

	memset(st, 0, sizeof(*st));
	st->set = set;
	st->log = log;
	memset(seen, 0, sizeof(seen));
	for (round = 0; round <= set->used; round++) {
		grow_members(set, log, st);
		memset(next, 0, sizeof(next));
		for (i = 0; i < set->used; i++)
			if (!is_add(&set->changes[i])
			    && member_in(set, st, set->changes[i].signer))
				next[i] = 1;
		for (i = 0; i < set->used; i++)
			seen[i] = (uint8_t)(seen[i] | next[i]);
		if (memcmp(next, st->rem_ok, sizeof(next)) == 0)
			return;
		memcpy(st->rem_ok, next, sizeof(next));
	}
	memcpy(st->rem_ok, seen, sizeof(seen));
	grow_members(set, log, st);
}

int fzn_root_set_counts(const fzn_root_set_t *set, const fzn_root_log_t *log,
                        const uint8_t root[FZN_PUBKEY_LEN],
                        const uint8_t act[FZN_ROOT_ACT_ID_LEN])
{
	struct settled st;

	if (!set_sound(set) || !root || !act)
		return 0;
	settle(set, log, &st);
	return counts_in(set, log, &st, root, act);
}

int fzn_root_set_stands(const fzn_root_set_t *set, const fzn_root_log_t *log,
                        const uint8_t key[FZN_PUBKEY_LEN])
{
	struct settled st;

	if (!set_sound(set) || !key)
		return 0;
	settle(set, log, &st);
	return member_in(set, &st, key) && !removed_in(set, &st, key);
}

int fzn_root_set_member(const fzn_root_set_t *set, const fzn_root_log_t *log,
                        const uint8_t key[FZN_PUBKEY_LEN])
{
	struct settled st;

	if (!set_sound(set) || !key)
		return 0;
	settle(set, log, &st);
	return member_in(set, &st, key);
}

fzn_root_log_err_t fzn_root_view_init(fzn_root_view_t *view, const fzn_root_set_t *set,
                                      const fzn_root_log_t *log)
{
	if (!view || !set_sound(set))
		return FZN_ROOT_LOG_ERR_MALFORMED;
	settle(set, log, view);
	return FZN_ROOT_LOG_OK;
}

int fzn_root_view_counts(const fzn_root_view_t *view, const uint8_t root[FZN_PUBKEY_LEN],
                         const uint8_t act[FZN_ROOT_ACT_ID_LEN])
{
	if (!view || !set_sound(view->set) || !root || !act)
		return 0;
	return counts_in(view->set, view->log, view, root, act);
}

int fzn_root_view_stands(const fzn_root_view_t *view, const uint8_t key[FZN_PUBKEY_LEN])
{
	if (!view || !set_sound(view->set) || !key)
		return 0;
	return member_in(view->set, view, key) && !removed_in(view->set, view, key);
}

int fzn_root_view_member(const fzn_root_view_t *view, const uint8_t key[FZN_PUBKEY_LEN])
{
	if (!view || !set_sound(view->set) || !key)
		return 0;
	return member_in(view->set, view, key);
}

static int ops_member(void *ctx, const uint8_t key[FZN_PUBKEY_LEN])
{
	return fzn_root_view_member((const fzn_root_view_t *)ctx, key);
}

static int ops_counts(void *ctx, const uint8_t root[FZN_PUBKEY_LEN],
                      const uint8_t act[FZN_ROOT_ACT_ID_LEN])
{
	return fzn_root_view_counts((const fzn_root_view_t *)ctx, root, act);
}

void fzn_root_view_ops(const fzn_root_view_t *view, struct fzn_root_ops *ops)
{
	if (!ops)
		return;
	ops->member = ops_member;
	ops->counts = ops_counts;
	ops->ctx = (void *)(uintptr_t)view;
}
