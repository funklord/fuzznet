/* A group act: project.md sec 626, and the header. */
#include "group_act.h"

#include <string.h>

#include "../wire/bytes.h"

const char *fzn_group_act_err_str(fzn_group_act_err_t err)
{
	switch (err) {
	case FZN_GROUP_ACT_OK:
		return "ok";
	case FZN_GROUP_ACT_ERR_MALFORMED:
		return "malformed";
	case FZN_GROUP_ACT_ERR_SHAPE:
		return "not a group act";
	case FZN_GROUP_ACT_ERR_REFUSED:
		return "its signature or its signer's proof does not hold";
	}
	return "unknown";
}

static int kind_known(uint8_t kind)
{
	return kind >= FZN_GROUP_ACT_CREATE && kind <= FZN_GROUP_ACT_KEYS;
}

/* Everything the signature covers, into `out`; its length, or 0. */
static size_t body(const fzn_group_act_t *a, uint8_t *out, size_t cap)
{
	size_t signer_len = 0, at = 0;

	if (!kind_known(a->kind) || a->payload_len > FZN_GROUP_ACT_PAYLOAD_MAX
	    || cap < FZN_GROUP_ACT_HEAD_LEN + a->payload_len
	    || fzn_contact_device_encode(&a->signer, out + FZN_GROUP_ACT_HEAD_LEN + a->payload_len,
	                                 cap - FZN_GROUP_ACT_HEAD_LEN - a->payload_len, &signer_len)
	               != FZN_CONTACT_DEVICE_OK
	    || signer_len > 0xffffu)
		return 0;
	out[at++] = FZN_GROUP_ACT_VERSION;
	out[at++] = (uint8_t)FZN_OBJECT_GROUP_ACT;
	out[at++] = a->kind;
	fzn_put_be32(out + at, a->seq);
	at += 4u;
	memcpy(out + at, a->group, FZN_GROUP_ID_LEN);
	at += FZN_GROUP_ID_LEN;
	memcpy(out + at, a->prev, 32u);
	at += 32u;
	memcpy(out + at, a->subject, FZN_PUBKEY_LEN);
	at += FZN_PUBKEY_LEN;
	out[at++] = a->setting;
	fzn_put_be64(out + at, a->value);
	at += 8u;
	fzn_put_be64(out + at, a->at);
	at += 8u;
	fzn_put_be16(out + at, (uint16_t)a->payload_len);
	at += 2u;
	memcpy(out + at, a->payload, a->payload_len);
	at += a->payload_len;
	fzn_put_be16(out + at, (uint16_t)signer_len);
	at += 2u;
	return at + signer_len;
}

fzn_group_act_err_t fzn_group_act_sign(fzn_group_act_t *a, const fzn_sign_ops_t *sign)
{
	static uint8_t bytes[FZN_GROUP_ACT_MAX];
	size_t n;

	if (!a || !sign || !sign->sign)
		return FZN_GROUP_ACT_ERR_MALFORMED;
	n = body(a, bytes, sizeof(bytes));
	if (!n || !sign->sign(sign->ctx, a->sig, bytes, n))
		return FZN_GROUP_ACT_ERR_MALFORMED;
	return FZN_GROUP_ACT_OK;
}

fzn_group_act_err_t fzn_group_act_encode(const fzn_group_act_t *a, uint8_t *out, size_t cap,
                                         size_t *len)
{
	size_t n;

	if (!a || !out || !len)
		return FZN_GROUP_ACT_ERR_MALFORMED;
	n = body(a, out, cap);
	if (!n || n + FZN_SIG_LEN > cap)
		return FZN_GROUP_ACT_ERR_MALFORMED;
	memcpy(out + n, a->sig, FZN_SIG_LEN);
	*len = n + FZN_SIG_LEN;
	return FZN_GROUP_ACT_OK;
}

fzn_group_act_err_t fzn_group_act_decode(const uint8_t *bytes, size_t len, fzn_group_act_t *out)
{
	size_t at = 2u, signer_len;

	if (!bytes || !out)
		return FZN_GROUP_ACT_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	if (len < FZN_GROUP_ACT_HEAD_LEN + FZN_SIG_LEN || bytes[0] != FZN_GROUP_ACT_VERSION
	    || bytes[1] != (uint8_t)FZN_OBJECT_GROUP_ACT || !kind_known(bytes[2]))
		return FZN_GROUP_ACT_ERR_SHAPE;
	out->kind = bytes[at++];
	out->seq = fzn_get_be32(bytes + at);
	at += 4u;
	memcpy(out->group, bytes + at, FZN_GROUP_ID_LEN);
	at += FZN_GROUP_ID_LEN;
	memcpy(out->prev, bytes + at, 32u);
	at += 32u;
	memcpy(out->subject, bytes + at, FZN_PUBKEY_LEN);
	at += FZN_PUBKEY_LEN;
	out->setting = bytes[at++];
	out->value = fzn_get_be64(bytes + at);
	at += 8u;
	out->at = fzn_get_be64(bytes + at);
	at += 8u;
	out->payload_len = fzn_get_be16(bytes + at);
	at += 2u;
	if (out->payload_len > FZN_GROUP_ACT_PAYLOAD_MAX || len - at < out->payload_len + 2u)
		return FZN_GROUP_ACT_ERR_SHAPE;
	memcpy(out->payload, bytes + at, out->payload_len);
	at += out->payload_len;
	signer_len = fzn_get_be16(bytes + at);
	at += 2u;
	/* EXACTLY ITS LENGTH: one act, one encoding, one hash. */
	if (len != at + signer_len + FZN_SIG_LEN
	    || fzn_contact_device_decode(bytes + at, signer_len, &out->signer)
	               != FZN_CONTACT_DEVICE_OK)
		return FZN_GROUP_ACT_ERR_SHAPE;
	at += signer_len;
	memcpy(out->sig, bytes + at, FZN_SIG_LEN);
	return FZN_GROUP_ACT_OK;
}

fzn_group_act_err_t fzn_group_act_verify(const fzn_group_act_t *a, const fzn_sign_ops_t *sign,
                                         const fzn_cap_id_t *member)
{
	static uint8_t bytes[FZN_GROUP_ACT_MAX];
	size_t n;

	if (!a || !sign || !sign->verify || !member)
		return FZN_GROUP_ACT_ERR_MALFORMED;
	if (fzn_contact_device_verify(&a->signer, sign, member, a->at) != FZN_CONTACT_DEVICE_OK)
		return FZN_GROUP_ACT_ERR_REFUSED;
	n = body(a, bytes, sizeof(bytes));
	if (!n || !sign->verify(sign->ctx, fzn_contact_device_key(&a->signer), bytes, n, a->sig))
		return FZN_GROUP_ACT_ERR_REFUSED;
	return FZN_GROUP_ACT_OK;
}

fzn_group_act_err_t fzn_group_act_hash(const fzn_group_act_t *a, const fzn_hash_ops_t *hash,
                                       uint8_t out[32])
{
	static uint8_t bytes[FZN_GROUP_ACT_MAX];
	size_t n = 0;

	if (!a || !hash || !hash->hash || !out)
		return FZN_GROUP_ACT_ERR_MALFORMED;
	if (fzn_group_act_encode(a, bytes, sizeof(bytes), &n) != FZN_GROUP_ACT_OK
	    || !hash->hash(hash->ctx, out, 32u, bytes, n))
		return FZN_GROUP_ACT_ERR_MALFORMED;
	return FZN_GROUP_ACT_OK;
}
