/* See setting.h. */

#include "setting.h"

#include "../wire/bytes.h"
#include "../wire/generated/setting_record.h"

#include <string.h>

/* Sixteen bytes, as `scope.c`'s label is, so a cell's input collides with no
 * other derivation. */
static const char FZN_SETTING_LABEL[16] = "fuzznet-cell-v1.";

const char *fzn_setting_err_str(fzn_setting_err_t err)
{
	switch (err) {
	case FZN_SETTING_OK:
		return "ok";
	case FZN_SETTING_ERR_MALFORMED:
		return "malformed";
	case FZN_SETTING_ERR_SHAPE:
		return "not a setting";
	case FZN_SETTING_ERR_SIGNATURE:
		return "its setter did not sign it";
	case FZN_SETTING_ERR_SCOPE:
		return "a scope with no cell, or one not served";
	}
	return "unknown";
}

int fzn_setting_key_ok(const uint8_t *key, size_t len)
{
	size_t i;

	if (!key || len == 0u || len > FZN_SETTING_KEY_MAX)
		return 0;
	for (i = 0; i < len; i++) {
		uint8_t c = key[i];

		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_'
		      || c == '/' || c == '-'))
			return 0;
	}
	return 1;
}

static int value_ok(const uint8_t *value, size_t len)
{
	size_t i;

	if (len > FZN_SETTING_VALUE_MAX || (len && !value))
		return 0;
	for (i = 0; i < len; i++)
		if (value[i] < 0x20u || value[i] > 0x7eu)
			return 0;
	return 1;
}

/* The scopes this build serves cells for. */
static int scope_served(fzn_scope_t scope)
{
	/* GROUP SINCE sec 868: a cell about a group of hosts, its id the
	 * group's name (`fzn_scope_group_id`). */
	return scope == FZN_SCOPE_HOST || scope == FZN_SCOPE_GROUP || scope == FZN_SCOPE_ESTATE;
}

/* Both shapes: `rank` -1 writes none, as before sec 728. */
static fzn_setting_err_t issue(const uint8_t setter[FZN_PUBKEY_LEN], const fzn_sign_ops_t *sign,
                               fzn_scope_t scope, const uint8_t about[FZN_SUBJECT_LEN],
                               uint64_t version, const uint8_t *key, size_t key_len, int set,
                               const uint8_t *value, size_t value_len, int rank, uint8_t *out,
                               size_t *out_len)
{
	size_t at;

	if (!out_len)
		return FZN_SETTING_ERR_MALFORMED;
	*out_len = 0;
	if (!setter || !sign || !sign->sign || !about || !out || !fzn_setting_key_ok(key, key_len)
	    || (set != 0 && set != 1) || (!set && value_len) || !value_ok(value, value_len)
	    || rank < -1 || rank >= (int)FZN_SETTING_RANKS)
		return FZN_SETTING_ERR_MALFORMED;
	if (!scope_served(scope))
		return FZN_SETTING_ERR_SCOPE;
	out[0] = (uint8_t)FZN_SIGNED_VERSION;
	out[1] = (uint8_t)FZN_OBJECT_SETTING;
	memcpy(out + FZN_SETTING_OFF_SETTER, setter, FZN_PUBKEY_LEN);
	out[FZN_SETTING_OFF_SCOPE] = (uint8_t)scope;
	memcpy(out + FZN_SETTING_OFF_ABOUT, about, FZN_SUBJECT_LEN);
	fzn_put_be64(out + FZN_SETTING_OFF_VERSION, version);
	out[FZN_SETTING_OFF_KEY_LEN] = (uint8_t)key_len;
	memcpy(out + FZN_SETTING_OFF_KEY, key, key_len);
	at = FZN_SETTING_OFF_KEY + key_len;
	out[at++] = (uint8_t)set;
	fzn_put_be16(out + at, (uint16_t)value_len);
	at += 2u;
	if (value_len)
		memcpy(out + at, value, value_len);
	at += value_len;
	if (rank >= 0)
		out[at++] = (uint8_t)rank;
	if (!sign->sign(sign->ctx, out + at, out, at))
		return FZN_SETTING_ERR_SIGNATURE;
	*out_len = at + (size_t)FZN_SIG_LEN;
	return FZN_SETTING_OK;
}

fzn_setting_err_t fzn_setting_issue(const uint8_t setter[FZN_PUBKEY_LEN],
                                    const fzn_sign_ops_t *sign, fzn_scope_t scope,
                                    const uint8_t about[FZN_SUBJECT_LEN], uint64_t version,
                                    const uint8_t *key, size_t key_len, int set,
                                    const uint8_t *value, size_t value_len, uint8_t *out,
                                    size_t *out_len)
{
	return issue(setter, sign, scope, about, version, key, key_len, set, value, value_len, -1,
	             out, out_len);
}

fzn_setting_err_t fzn_setting_issue_ranked(const uint8_t setter[FZN_PUBKEY_LEN],
                                           const fzn_sign_ops_t *sign, fzn_scope_t scope,
                                           const uint8_t about[FZN_SUBJECT_LEN],
                                           uint64_t version, const uint8_t *key, size_t key_len,
                                           int set, const uint8_t *value, size_t value_len,
                                           fzn_setting_rank_t rank, uint8_t *out,
                                           size_t *out_len)
{
	if ((unsigned)rank >= FZN_SETTING_RANKS) {
		if (out_len)
			*out_len = 0;
		return FZN_SETTING_ERR_MALFORMED;
	}
	return issue(setter, sign, scope, about, version, key, key_len, set, value, value_len,
	             (int)rank, out, out_len);
}

fzn_setting_err_t fzn_setting_open(const uint8_t *bytes, size_t len, const fzn_sign_ops_t *sign,
                                   fzn_setting_t *out)
{
	situ_msg_t m;
	situ_view_t v, arm;
	uint32_t need = 0;
	int ranked;

	if (!bytes || !sign || !sign->verify || !out)
		return FZN_SETTING_ERR_MALFORMED;
	/* READ AS THE SCHEMA SAYS (sec 1342): `state/setting_record.situ`'s
	 * generated code checks the version and object, the key's and value's
	 * letters and bounds, that a clear carries no value, and that THE
	 * LENGTHS ACCOUNT FOR EVERY BYTE -- the two shapes, with the rank its
	 * setter states (sec 728) or without, being the arms of `tail` the
	 * length selects. The rank is signed with the rest. */
	if (len < FZN_SETTING_MIN || len > FZN_SETTING_MAX
	    || fzn_setting_record_fzn_setting_required(bytes, (uint32_t)len, &need) != SITU_OK || need != len)
		return FZN_SETTING_ERR_SHAPE;
	situ_msg_init(&m, (uint8_t *)(uintptr_t)bytes, (uint32_t)len);
	if (fzn_setting_record_fzn_setting_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_setting_record_fzn_setting_validate(v) != SITU_OK)
		return FZN_SETTING_ERR_SHAPE;
	ranked = fzn_setting_record_fzn_setting_tail_ranked_view(v, &arm) == SITU_OK;
	if (!scope_served((fzn_scope_t)fzn_setting_record_fzn_setting_scope_get(v)))
		return FZN_SETTING_ERR_SCOPE;
	if (!sign->verify(sign->ctx, fzn_setting_record_fzn_setting_setter_ptr(v), bytes,
	                  len - (size_t)FZN_SIG_LEN, bytes + len - (size_t)FZN_SIG_LEN))
		return FZN_SETTING_ERR_SIGNATURE;
	out->setter = fzn_setting_record_fzn_setting_setter_ptr(v);
	out->scope = (fzn_scope_t)fzn_setting_record_fzn_setting_scope_get(v);
	out->about = fzn_setting_record_fzn_setting_about_ptr(v);
	out->version = fzn_setting_record_fzn_setting_version_no_get(v);
	out->key = fzn_setting_record_fzn_setting_key_ptr(v);
	out->key_len = fzn_setting_record_fzn_setting_key_len_get(v);
	out->set = fzn_setting_record_fzn_setting_op_get(v);
	out->value = fzn_setting_record_fzn_setting_value_ptr(v);
	out->value_len = fzn_setting_record_fzn_setting_value_len_get(v);
	out->rank = ranked ? (int)fzn_setting_record_fzn_setting_ranked_rank_get(arm) : -1;
	return FZN_SETTING_OK;
}

int fzn_setting_cell_of(fzn_scope_t scope, const uint8_t about[FZN_SUBJECT_LEN],
                        const uint8_t *key, size_t key_len, const fzn_hash_ops_t *hash,
                        uint8_t cell[FZN_SUBJECT_LEN])
{
	uint8_t in[sizeof(FZN_SETTING_LABEL) + 1u + FZN_SUBJECT_LEN + 1u + FZN_SETTING_KEY_MAX];
	uint8_t subject[FZN_SUBJECT_LEN];
	size_t at = sizeof(FZN_SETTING_LABEL);

	if (!about || !hash || !hash->hash || !cell || !fzn_setting_key_ok(key, key_len)
	    || fzn_scope_subject(scope, about, hash, subject) != FZN_SCOPE_OK)
		return 0;
	memcpy(in, FZN_SETTING_LABEL, at);
	in[at++] = (uint8_t)scope;
	memcpy(in + at, subject, FZN_SUBJECT_LEN);
	at += FZN_SUBJECT_LEN;
	/* THE KEY'S LENGTH BEFORE IT, so no key is a prefix of another's
	 * input. */
	in[at++] = (uint8_t)key_len;
	memcpy(in + at, key, key_len);
	at += key_len;
	return hash->hash(hash->ctx, cell, FZN_SUBJECT_LEN, in, at);
}

int fzn_setting_cell(const fzn_setting_t *s, const fzn_hash_ops_t *hash,
                     uint8_t cell[FZN_SUBJECT_LEN])
{
	return s && fzn_setting_cell_of(s->scope, s->about, s->key, s->key_len, hash, cell);
}

int fzn_setting_supersedes(const fzn_setting_t *a, const fzn_setting_t *b)
{
	int c;

	if (!a || !b)
		return 0;
	if (a->version != b->version)
		return a->version > b->version;
	c = memcmp(a->setter, b->setter, FZN_PUBKEY_LEN);
	if (c != 0)
		return c > 0;
	/* ONE SETTER, ONE VERSION, TWO STATEMENTS: an equivocation, settled the
	 * same way on every host -- a set over a clear, then the greater value
	 * -- so the estate converges whatever order the two arrive in. */
	if (a->set != b->set)
		return a->set > b->set;
	if (a->value_len != b->value_len)
		return a->value_len > b->value_len;
	return a->value_len && memcmp(a->value, b->value, a->value_len) > 0;
}
