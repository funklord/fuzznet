/* See root_log.h. */

#include "root_log.h"

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
