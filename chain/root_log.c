/* See root_log.h. */

#include "root_log.h"
#include "revocation.h"

#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#include <string.h>

const char *fzn_root_log_err_str(fzn_root_log_err_t err)
{
	switch (err) {
	case FZN_ROOT_LOG_OK:
		return "ok";
	case FZN_ROOT_LOG_ERR_MALFORMED:
		return "malformed";
	case FZN_ROOT_LOG_ERR_SHAPE:
		return "not a root record";
	case FZN_ROOT_LOG_ERR_SIGNATURE:
		return "the record is not signed by the root it names";
	case FZN_ROOT_LOG_ERR_FULL:
		return "no room for another root record";
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
 * removal naming no cut leaves nothing standing, and without a log of acts
 * nothing a removed root did can be shown to stand. */
static int counts_in(const fzn_root_set_t *set, const struct fzn_act_log_ops *acts,
                     const struct settled *st, const uint8_t *root, const uint8_t *act)
{
	size_t i;

	if (!member_in(set, st, root))
		return 0;
	for (i = 0; i < set->used; i++) {
		const fzn_root_change_t *c = &set->changes[i];

		if (is_add(c) || !st->rem_ok[i] || !fzn_ct_memeq(c->subject, root, FZN_PUBKEY_LEN))
			continue;
		if (!acts || all_zero(c->cut, FZN_ROOT_ACT_ID_LEN)
		    || !acts->stands(acts->ctx, root, c->cut, act))
			return 0;
	}
	return 1;
}

/* Membership as the least fixed point from the genesis root, with the
 * removals in `st` held fixed. Monotone, so it ends within `used` passes. */
static void grow_members(const fzn_root_set_t *set, const struct fzn_act_log_ops *acts, struct settled *st)
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
			if (counts_in(set, acts, st, c->signer, c->id)) {
				st->add_ok[i] = 1;
				changed = 1;
			}
		}
	}
}

/* THE ROUNDS: fix the removals, grow membership, recompute the removals
 * from it, until they stop changing. Bounded by the records: a set that has
 * not settled in `used + 1` rounds takes every removal any round saw. */
static void settle(const fzn_root_set_t *set, const struct fzn_act_log_ops *acts, struct settled *st)
{
	uint8_t seen[FZN_ROOT_SET_MAX], next[FZN_ROOT_SET_MAX];
	size_t round, i;

	memset(st, 0, sizeof(*st));
	st->set = set;
	st->acts = acts;
	memset(seen, 0, sizeof(seen));
	for (round = 0; round <= set->used; round++) {
		grow_members(set, acts, st);
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
	grow_members(set, acts, st);
}

int fzn_root_set_counts(const fzn_root_set_t *set, const struct fzn_act_log_ops *acts,
                        const uint8_t root[FZN_PUBKEY_LEN],
                        const uint8_t act[FZN_ROOT_ACT_ID_LEN])
{
	struct settled st;

	if (!set_sound(set) || !root || !act)
		return 0;
	settle(set, acts, &st);
	return counts_in(set, acts, &st, root, act);
}

int fzn_root_set_stands(const fzn_root_set_t *set, const struct fzn_act_log_ops *acts,
                        const uint8_t key[FZN_PUBKEY_LEN])
{
	struct settled st;

	if (!set_sound(set) || !key)
		return 0;
	settle(set, acts, &st);
	return member_in(set, &st, key) && !removed_in(set, &st, key);
}

int fzn_root_set_member(const fzn_root_set_t *set, const struct fzn_act_log_ops *acts,
                        const uint8_t key[FZN_PUBKEY_LEN])
{
	struct settled st;

	if (!set_sound(set) || !key)
		return 0;
	settle(set, acts, &st);
	return member_in(set, &st, key);
}

fzn_root_log_err_t fzn_root_view_init(fzn_root_view_t *view, const fzn_root_set_t *set,
                                      const struct fzn_act_log_ops *acts)
{
	if (!view || !set_sound(set))
		return FZN_ROOT_LOG_ERR_MALFORMED;
	settle(set, acts, view);
	return FZN_ROOT_LOG_OK;
}

int fzn_root_view_counts(const fzn_root_view_t *view, const uint8_t root[FZN_PUBKEY_LEN],
                         const uint8_t act[FZN_ROOT_ACT_ID_LEN])
{
	if (!view || !set_sound(view->set) || !root || !act)
		return 0;
	return counts_in(view->set, view->acts, view, root, act);
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

/* ---- the estate's k, sec 418 ----------------------------------------- */

fzn_root_log_err_t fzn_quorum_set_issue(const uint8_t setter[FZN_PUBKEY_LEN], uint8_t k,
                                        const uint8_t replaces[FZN_ROOT_ACT_ID_LEN],
                                        const fzn_sign_ops_t *sign, uint8_t *out)
{
	if (!setter || k == 0u || !sign || !sign->sign || !out)
		return FZN_ROOT_LOG_ERR_MALFORMED;
	out[0] = (uint8_t)FZN_SIGNED_VERSION;
	out[1] = (uint8_t)FZN_OBJECT_QUORUM_SET;
	memcpy(out + FZN_QUORUM_SET_OFF_SETTER, setter, FZN_PUBKEY_LEN);
	if (replaces)
		memcpy(out + FZN_QUORUM_SET_OFF_REPLACES, replaces, FZN_ROOT_ACT_ID_LEN);
	else
		memset(out + FZN_QUORUM_SET_OFF_REPLACES, 0, FZN_ROOT_ACT_ID_LEN);
	out[FZN_QUORUM_SET_OFF_K] = k;
	if (!sign->sign(sign->ctx, out + FZN_QUORUM_SET_BODY_LEN, out, FZN_QUORUM_SET_BODY_LEN))
		return FZN_ROOT_LOG_ERR_SIGNATURE;
	return FZN_ROOT_LOG_OK;
}

fzn_root_log_err_t fzn_quorum_set_check(const uint8_t *bytes, size_t len,
                                        const fzn_sign_ops_t *sign)
{
	if (!bytes || !sign || !sign->verify)
		return FZN_ROOT_LOG_ERR_MALFORMED;
	if (len != FZN_QUORUM_SET_LEN || bytes[0] != (uint8_t)FZN_SIGNED_VERSION
	    || bytes[1] != (uint8_t)FZN_OBJECT_QUORUM_SET || bytes[FZN_QUORUM_SET_OFF_K] == 0u)
		return FZN_ROOT_LOG_ERR_SHAPE;
	if (!sign->verify(sign->ctx, bytes + FZN_QUORUM_SET_OFF_SETTER, bytes,
	                  FZN_QUORUM_SET_BODY_LEN, bytes + FZN_QUORUM_SET_BODY_LEN))
		return FZN_ROOT_LOG_ERR_SIGNATURE;
	return FZN_ROOT_LOG_OK;
}

/* The most settings one resolution judges: a flag each on the stack. */
#define QUORUM_SETTINGS_MAX 64u

int fzn_quorum_winner(const uint8_t *records, size_t count, const struct fzn_root_ops *roots,
                      const fzn_hash_ops_t *hash, uint8_t *k,
                      uint8_t winner[FZN_ROOT_ACT_ID_LEN])
{
	uint8_t ids[QUORUM_SETTINGS_MAX][FZN_ROOT_ACT_ID_LEN];
	uint8_t counts[QUORUM_SETTINGS_MAX];
	size_t i, j, best = count;

	if (!records || count == 0u || count > QUORUM_SETTINGS_MAX || !hash || !hash->hash || !k)
		return 0;
	/* WHICH COUNT: the setter's act, under the set. */
	for (i = 0; i < count; i++) {
		const uint8_t *r = records + (i * FZN_QUORUM_SET_LEN);

		if (!hash->hash(hash->ctx, ids[i], FZN_ROOT_ACT_ID_LEN, r, FZN_QUORUM_SET_LEN))
			return 0;
		counts[i] = !roots
		            || roots->counts(roots->ctx, r + FZN_QUORUM_SET_OFF_SETTER, ids[i]);
	}
	/* THE CURRENT ONES: counting, and replaced by no counting setting. The
	 * higher k among them wins; between equal k, the lower id, so the
	 * answer does not depend on the order the settings are held in. */
	for (i = 0; i < count; i++) {
		int replaced = 0;
		uint8_t ki = records[(i * FZN_QUORUM_SET_LEN) + FZN_QUORUM_SET_OFF_K];

		if (!counts[i])
			continue;
		for (j = 0; j < count && !replaced; j++)
			replaced = j != i && counts[j]
			           && fzn_ct_memeq(records + (j * FZN_QUORUM_SET_LEN)
			                                   + FZN_QUORUM_SET_OFF_REPLACES,
			                           ids[i], FZN_ROOT_ACT_ID_LEN);
		if (replaced)
			continue;
		if (best == count) {
			best = i;
			continue;
		}
		{
			uint8_t kb = records[(best * FZN_QUORUM_SET_LEN) + FZN_QUORUM_SET_OFF_K];

			if (ki > kb || (ki == kb && memcmp(ids[i], ids[best], FZN_ROOT_ACT_ID_LEN) < 0))
				best = i;
		}
	}
	if (best == count)
		return 0;
	*k = records[(best * FZN_QUORUM_SET_LEN) + FZN_QUORUM_SET_OFF_K];
	if (winner)
		memcpy(winner, ids[best], FZN_ROOT_ACT_ID_LEN);
	return 1;
}

uint8_t fzn_quorum_resolve(const uint8_t *records, size_t count,
                           const struct fzn_root_ops *roots, const fzn_hash_ops_t *hash,
                           uint8_t fallback)
{
	uint8_t k = 0;

	return fzn_quorum_winner(records, count, roots, hash, &k, NULL) ? k : fallback;
}

/* ---- the estate's retention rules, sec 476 ------------------------------ */

/* The most retention records one resolution judges. */
#define RETENTION_RECORDS_MAX 64u

fzn_root_log_err_t fzn_retention_set_issue(const uint8_t setter[FZN_PUBKEY_LEN],
                                           const char *text, size_t len,
                                           const uint8_t replaces[FZN_ROOT_ACT_ID_LEN],
                                           const fzn_sign_ops_t *sign, uint8_t *out)
{
	size_t i;

	if (!setter || (!text && len) || len >= FZN_RETENTION_SET_TEXT_MAX || (!len && !replaces)
	    || !sign || !sign->sign || !out)
		return FZN_ROOT_LOG_ERR_MALFORMED;
	for (i = 0; i < len; i++)
		if ((unsigned char)text[i] < 0x20u || (unsigned char)text[i] > 0x7eu)
			return FZN_ROOT_LOG_ERR_MALFORMED;
	out[0] = (uint8_t)FZN_SIGNED_VERSION;
	out[1] = (uint8_t)FZN_OBJECT_RETENTION_SET;
	memcpy(out + FZN_RETENTION_SET_OFF_SETTER, setter, FZN_PUBKEY_LEN);
	if (replaces)
		memcpy(out + FZN_RETENTION_SET_OFF_REPLACES, replaces, FZN_ROOT_ACT_ID_LEN);
	else
		memset(out + FZN_RETENTION_SET_OFF_REPLACES, 0, FZN_ROOT_ACT_ID_LEN);
	memset(out + FZN_RETENTION_SET_OFF_TEXT, 0, FZN_RETENTION_SET_TEXT_MAX);
	if (len)
		memcpy(out + FZN_RETENTION_SET_OFF_TEXT, text, len);
	if (!sign->sign(sign->ctx, out + FZN_RETENTION_SET_BODY_LEN, out,
	                FZN_RETENTION_SET_BODY_LEN))
		return FZN_ROOT_LOG_ERR_SIGNATURE;
	return FZN_ROOT_LOG_OK;
}

/* The text's length: printable bytes, then NUL padding to the end. 0 for
 * none, -1 for a field that is neither. */
static int retention_text_len(const uint8_t *field)
{
	size_t n = 0, i;

	while (n < FZN_RETENTION_SET_TEXT_MAX && field[n] >= 0x20u && field[n] <= 0x7eu)
		n++;
	for (i = n; i < FZN_RETENTION_SET_TEXT_MAX; i++)
		if (field[i] != 0u)
			return -1;
	return n == FZN_RETENTION_SET_TEXT_MAX ? -1 : (int)n;
}

fzn_root_log_err_t fzn_retention_set_check(const uint8_t *bytes, size_t len,
                                           const fzn_sign_ops_t *sign)
{
	static const uint8_t ZERO[FZN_ROOT_ACT_ID_LEN] = { 0 };
	int n;

	if (!bytes || !sign || !sign->verify)
		return FZN_ROOT_LOG_ERR_MALFORMED;
	if (len != FZN_RETENTION_SET_LEN || bytes[0] != (uint8_t)FZN_SIGNED_VERSION
	    || bytes[1] != (uint8_t)FZN_OBJECT_RETENTION_SET)
		return FZN_ROOT_LOG_ERR_SHAPE;
	n = retention_text_len(bytes + FZN_RETENTION_SET_OFF_TEXT);
	/* A REMOVAL NAMES WHAT IT REMOVES: a record with no text replacing
	 * nothing would be a rule of nothing. */
	if (n < 0
	    || (n == 0
	        && memcmp(bytes + FZN_RETENTION_SET_OFF_REPLACES, ZERO, FZN_ROOT_ACT_ID_LEN) == 0))
		return FZN_ROOT_LOG_ERR_SHAPE;
	if (!sign->verify(sign->ctx, bytes + FZN_RETENTION_SET_OFF_SETTER, bytes,
	                  FZN_RETENTION_SET_BODY_LEN, bytes + FZN_RETENTION_SET_BODY_LEN))
		return FZN_ROOT_LOG_ERR_SIGNATURE;
	return FZN_ROOT_LOG_OK;
}

int fzn_retention_current(const uint8_t *records, size_t count, const struct fzn_root_ops *roots,
                          const fzn_hash_ops_t *hash, fzn_retention_each_fn each, void *ctx)
{
	uint8_t ids[RETENTION_RECORDS_MAX][FZN_ROOT_ACT_ID_LEN];
	uint8_t counts[RETENTION_RECORDS_MAX], current[RETENTION_RECORDS_MAX];
	size_t i, j, handed = 0;

	if ((!records && count) || count > RETENTION_RECORDS_MAX || !hash || !hash->hash || !each)
		return -1;
	for (i = 0; i < count; i++) {
		const uint8_t *r = records + (i * FZN_RETENTION_SET_LEN);

		if (!hash->hash(hash->ctx, ids[i], FZN_ROOT_ACT_ID_LEN, r, FZN_RETENTION_SET_LEN))
			return -1;
		counts[i] = !roots
		            || roots->counts(roots->ctx, r + FZN_RETENTION_SET_OFF_SETTER, ids[i]);
	}
	/* CURRENT: counting, replaced by no counting record, and carrying a
	 * rule -- a removal is current only as the absence it leaves. */
	for (i = 0; i < count; i++) {
		int replaced = 0;

		current[i] = 0;
		if (!counts[i] || retention_text_len(records + (i * FZN_RETENTION_SET_LEN)
		                                     + FZN_RETENTION_SET_OFF_TEXT)
		                          <= 0)
			continue;
		for (j = 0; j < count && !replaced; j++)
			replaced = j != i && counts[j]
			           && fzn_ct_memeq(records + (j * FZN_RETENTION_SET_LEN)
			                                   + FZN_RETENTION_SET_OFF_REPLACES,
			                           ids[i], FZN_ROOT_ACT_ID_LEN);
		current[i] = (uint8_t)!replaced;
	}
	/* IN THE ORDER OF THEIR HASHES: each pass hands the least not handed. */
	for (;;) {
		size_t least = count;

		for (i = 0; i < count; i++)
			if (current[i]
			    && (least == count || memcmp(ids[i], ids[least], FZN_ROOT_ACT_ID_LEN) < 0))
				least = i;
		if (least == count)
			break;
		{
			const uint8_t *t = records + (least * FZN_RETENTION_SET_LEN)
			                   + FZN_RETENTION_SET_OFF_TEXT;
			char text[FZN_RETENTION_SET_TEXT_MAX];
			int n = retention_text_len(t);

			memcpy(text, t, (size_t)n);
			text[n] = '\0';
			each(ctx, text, (size_t)n, ids[least]);
		}
		current[least] = 0;
		handed++;
	}
	return (int)handed;
}
