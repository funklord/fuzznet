/* See setting.h. */

#include "setting.h"

#include "../wire/bytes.h"

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
	return scope == FZN_SCOPE_HOST || scope == FZN_SCOPE_ESTATE;
}

fzn_setting_err_t fzn_setting_issue(const uint8_t setter[FZN_PUBKEY_LEN],
                                    const fzn_sign_ops_t *sign, fzn_scope_t scope,
                                    const uint8_t about[FZN_SUBJECT_LEN], uint64_t version,
                                    const uint8_t *key, size_t key_len, int set,
                                    const uint8_t *value, size_t value_len, uint8_t *out,
                                    size_t *out_len)
{
	size_t at;

	if (!out_len)
		return FZN_SETTING_ERR_MALFORMED;
	*out_len = 0;
	if (!setter || !sign || !sign->sign || !about || !out || !fzn_setting_key_ok(key, key_len)
	    || (set != 0 && set != 1) || (!set && value_len) || !value_ok(value, value_len))
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
	if (!sign->sign(sign->ctx, out + at, out, at))
		return FZN_SETTING_ERR_SIGNATURE;
	*out_len = at + (size_t)FZN_SIG_LEN;
	return FZN_SETTING_OK;
}

fzn_setting_err_t fzn_setting_open(const uint8_t *bytes, size_t len, const fzn_sign_ops_t *sign,
                                   fzn_setting_t *out)
{
	size_t at, key_len, value_len;

	if (!bytes || !sign || !sign->verify || !out)
		return FZN_SETTING_ERR_MALFORMED;
	if (len < FZN_SETTING_MIN || len > FZN_SETTING_MAX || bytes[0] != (uint8_t)FZN_SIGNED_VERSION
	    || bytes[1] != (uint8_t)FZN_OBJECT_SETTING)
		return FZN_SETTING_ERR_SHAPE;
	key_len = bytes[FZN_SETTING_OFF_KEY_LEN];
	at = FZN_SETTING_OFF_KEY + key_len;
	/* THE LENGTHS ACCOUNT FOR EVERY BYTE: key, op, value length, value and
	 * signature, and nothing after. */
	if (!fzn_setting_key_ok(bytes + FZN_SETTING_OFF_KEY, key_len)
	    || len < at + 3u + (size_t)FZN_SIG_LEN || bytes[at] > 1u)
		return FZN_SETTING_ERR_SHAPE;
	value_len = fzn_get_be16(bytes + at + 1u);
	if (len != at + 3u + value_len + (size_t)FZN_SIG_LEN || (bytes[at] == 0u && value_len)
	    || !value_ok(bytes + at + 3u, value_len))
		return FZN_SETTING_ERR_SHAPE;
	if (!scope_served((fzn_scope_t)bytes[FZN_SETTING_OFF_SCOPE]))
		return FZN_SETTING_ERR_SCOPE;
	if (!sign->verify(sign->ctx, bytes + FZN_SETTING_OFF_SETTER, bytes,
	                  len - (size_t)FZN_SIG_LEN, bytes + len - (size_t)FZN_SIG_LEN))
		return FZN_SETTING_ERR_SIGNATURE;
	out->setter = bytes + FZN_SETTING_OFF_SETTER;
	out->scope = (fzn_scope_t)bytes[FZN_SETTING_OFF_SCOPE];
	out->about = bytes + FZN_SETTING_OFF_ABOUT;
	out->version = fzn_get_be64(bytes + FZN_SETTING_OFF_VERSION);
	out->key = bytes + FZN_SETTING_OFF_KEY;
	out->key_len = key_len;
	out->set = bytes[at];
	out->value = bytes + at + 3u;
	out->value_len = value_len;
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
