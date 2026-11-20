/* A group act: project.md sec 626, and the header. */
#include "group_act.h"

#include <string.h>

#include "../wire/bytes.h"
#include "../wire/generated/group_act_record.h"
#include "../wire/generated/group_act_record_build.h"

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

/* THE ACT, built by the code situ generates from `node/group_act_record.situ`
 * (sec 1323) with `sig` as its signature: its whole length, or 0. The
 * signature covers every byte before it, the last FZN_SIG_LEN. */
static size_t build(const fzn_group_act_t *a, const uint8_t sig[FZN_SIG_LEN], uint8_t *out, size_t cap)
{
	static uint8_t signer[FZN_CONTACT_DEVICE_MAX];
	size_t signer_len = 0;
	uint32_t wrote = 0;

	if (!kind_known(a->kind) || a->payload_len > FZN_GROUP_ACT_PAYLOAD_MAX
	    || fzn_contact_device_encode(&a->signer, signer, sizeof(signer), &signer_len) != FZN_CONTACT_DEVICE_OK
	    || signer_len > 0xffffu || cap > UINT32_MAX
	    || fzn_group_act_record_fzn_group_act_build(out, (uint32_t)cap, FZN_GROUP_ACT_VERSION,
	                                                (uint8_t)FZN_OBJECT_GROUP_ACT, a->kind, a->seq, a->group,
	                                                a->prev, a->subject, a->setting, a->value, a->at, a->payload,
	                                                (uint32_t)a->payload_len, signer, (uint32_t)signer_len, sig,
	                                                &wrote)
	               != SITU_OK)
		return 0;
	return wrote;
}

fzn_group_act_err_t fzn_group_act_sign(fzn_group_act_t *a, const fzn_sign_ops_t *sign)
{
	static uint8_t bytes[FZN_GROUP_ACT_MAX];
	static const uint8_t unsigned_yet[FZN_SIG_LEN];
	size_t n;

	if (!a || !sign || !sign->sign)
		return FZN_GROUP_ACT_ERR_MALFORMED;
	n = build(a, unsigned_yet, bytes, sizeof(bytes));
	if (!n || !sign->sign(sign->ctx, a->sig, bytes, n - FZN_SIG_LEN))
		return FZN_GROUP_ACT_ERR_MALFORMED;
	return FZN_GROUP_ACT_OK;
}

fzn_group_act_err_t fzn_group_act_encode(const fzn_group_act_t *a, uint8_t *out, size_t cap,
                                         size_t *len)
{
	size_t n;

	if (!a || !out || !len)
		return FZN_GROUP_ACT_ERR_MALFORMED;
	n = build(a, a->sig, out, cap);
	if (!n)
		return FZN_GROUP_ACT_ERR_MALFORMED;
	*len = n;
	return FZN_GROUP_ACT_OK;
}

fzn_group_act_err_t fzn_group_act_decode(const uint8_t *bytes, size_t len, fzn_group_act_t *out)
{
	situ_msg_t m;
	situ_view_t v;
	uint32_t need = 0;

	if (!bytes || !out)
		return FZN_GROUP_ACT_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	/* READ AS THE SCHEMA SAYS, EXACTLY ITS LENGTH: one act, one encoding,
	 * one hash. Its version, tag, kind and payload bound, and the signer
	 * as a contact device entry, are the generated validate's to check. */
	if (len > UINT32_MAX
	    || fzn_group_act_record_fzn_group_act_required(bytes, (uint32_t)len, &need) != SITU_OK || need != len)
		return FZN_GROUP_ACT_ERR_SHAPE;
	situ_msg_init(&m, (uint8_t *)(uintptr_t)bytes, (uint32_t)len);
	if (fzn_group_act_record_fzn_group_act_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_group_act_record_fzn_group_act_validate(v) != SITU_OK)
		return FZN_GROUP_ACT_ERR_SHAPE;
	out->kind = fzn_group_act_record_fzn_group_act_kind_get(v);
	out->seq = fzn_group_act_record_fzn_group_act_seq_get(v);
	memcpy(out->group, fzn_group_act_record_fzn_group_act_group_ptr(v), FZN_GROUP_ID_LEN);
	memcpy(out->prev, fzn_group_act_record_fzn_group_act_prev_ptr(v), 32u);
	memcpy(out->subject, fzn_group_act_record_fzn_group_act_subject_ptr(v), FZN_PUBKEY_LEN);
	out->setting = fzn_group_act_record_fzn_group_act_setting_get(v);
	out->value = fzn_group_act_record_fzn_group_act_value_get(v);
	out->at = fzn_group_act_record_fzn_group_act_at_get(v);
	out->payload_len = fzn_group_act_record_fzn_group_act_payload_len_get(v);
	memcpy(out->payload, fzn_group_act_record_fzn_group_act_payload_ptr(v), out->payload_len);
	if (fzn_contact_device_decode(fzn_group_act_record_fzn_group_act_signer_ptr(v),
	                              fzn_group_act_record_fzn_group_act_signer_len_get(v), &out->signer)
	    != FZN_CONTACT_DEVICE_OK)
		return FZN_GROUP_ACT_ERR_SHAPE;
	memcpy(out->sig, fzn_group_act_record_fzn_group_act_sig_ptr(v), FZN_SIG_LEN);
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
	n = build(a, a->sig, bytes, sizeof(bytes));
	if (!n || !sign->verify(sign->ctx, fzn_contact_device_key(&a->signer), bytes, n - FZN_SIG_LEN, a->sig))
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
