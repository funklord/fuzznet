/* A group line in transit: project.md sec 628, and the header. */
#include "group_line.h"

#include <string.h>

#include "../wire/bytes.h"
#include "../wire/generated/group_line_wire.h"
#include "../wire/generated/group_line_wire_build.h"

const char *fzn_group_line_err_str(fzn_group_line_err_t err)
{
	switch (err) {
	case FZN_GROUP_LINE_OK:
		return "ok";
	case FZN_GROUP_LINE_ERR_MALFORMED:
		return "malformed";
	case FZN_GROUP_LINE_ERR_SHAPE:
		return "not a group line";
	case FZN_GROUP_LINE_ERR_OPEN:
		return "not sealed under this secret, or altered";
	case FZN_GROUP_LINE_ERR_STRANGER:
		return "its sender or host is not the group's";
	case FZN_GROUP_LINE_ERR_OPS:
		return "the hash, the AEAD or the randomness refused";
	}
	return "unknown";
}

/* ONE KEY PER HOST PER EPOCH. */
static int line_key(const fzn_hash_ops_t *hash, const uint8_t *secret, const uint8_t *host,
                    uint8_t key[FZN_AEAD_KEY_LEN])
{
	static const char label[] = "fuzznet group line";
	uint8_t in[sizeof(label) - 1u + FZN_GROUP_SECRET_LEN + FZN_PUBKEY_LEN];
	int ok;

	memcpy(in, label, sizeof(label) - 1u);
	memcpy(in + sizeof(label) - 1u, secret, FZN_GROUP_SECRET_LEN);
	memcpy(in + sizeof(label) - 1u + FZN_GROUP_SECRET_LEN, host, FZN_PUBKEY_LEN);
	ok = hash->hash(hash->ctx, key, FZN_AEAD_KEY_LEN, in, sizeof(in));
	memset(in, 0, sizeof(in));
	return ok;
}

fzn_group_line_err_t fzn_group_line_seal(const fzn_group_line_t *line,
                                         const uint8_t secret[FZN_GROUP_SECRET_LEN],
                                         const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                         const fzn_random_ops_t *rng, uint8_t *out, size_t cap,
                                         size_t *len)
{
	static const uint8_t no_tag[FZN_AEAD_TAG_LEN];
	uint8_t key[FZN_AEAD_KEY_LEN], nonce[FZN_AEAD_NONCE_LEN];
	uint8_t *text;
	uint32_t wrote = 0;
	int ok;

	if (!line || !secret || !hash || !hash->hash || !aead || !aead->seal || !rng || !rng->fill
	    || !out || !len || line->text_len > FZN_GROUP_LINE_TEXT_MAX || cap > UINT32_MAX)
		return FZN_GROUP_LINE_ERR_MALFORMED;
	if (!rng->fill(rng->ctx, nonce, FZN_AEAD_NONCE_LEN))
		return FZN_GROUP_LINE_ERR_OPS;
	/* THE LINE AS THE SCHEMA LAYS IT OUT (sec 1326), its text in the clear
	 * and its tag empty; then the text sealed in place, the head -- every
	 * byte before the nonce -- its associated data. */
	if (fzn_group_line_wire_fzn_group_line_build(out, (uint32_t)cap, FZN_GROUP_LINE_VERSION, line->group,
	                                             line->epoch, line->sender, line->host, line->id, line->stime,
	                                             nonce, (const uint8_t *)line->text, (uint32_t)line->text_len,
	                                             no_tag, &wrote)
	    != SITU_OK)
		return FZN_GROUP_LINE_ERR_MALFORMED;
	text = out + FZN_GROUP_LINE_HEAD_LEN + FZN_AEAD_NONCE_LEN + 2u;
	if (!line_key(hash, secret, line->host, key))
		return FZN_GROUP_LINE_ERR_OPS;
	ok = aead->seal(aead->ctx, key, out + FZN_GROUP_LINE_HEAD_LEN, out, FZN_GROUP_LINE_HEAD_LEN, text,
	                line->text_len, text + line->text_len);
	memset(key, 0, sizeof(key));
	if (!ok)
		return FZN_GROUP_LINE_ERR_OPS;
	*len = wrote;
	return FZN_GROUP_LINE_OK;
}

fzn_group_line_err_t fzn_group_line_peek(const uint8_t *bytes, size_t len,
                                         fzn_group_line_t *out)
{
	situ_msg_t m;
	situ_view_t v;
	uint32_t need = 0;

	if (!bytes || !out)
		return FZN_GROUP_LINE_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	/* READ AS THE SCHEMA SAYS (sec 1326), EXACTLY ITS LENGTH: its version
	 * and its text's bound the generated validate's to check. */
	if (len > UINT32_MAX || fzn_group_line_wire_fzn_group_line_required(bytes, (uint32_t)len, &need) != SITU_OK
	    || need != len)
		return FZN_GROUP_LINE_ERR_SHAPE;
	situ_msg_init(&m, (uint8_t *)(uintptr_t)bytes, (uint32_t)len);
	if (fzn_group_line_wire_fzn_group_line_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_group_line_wire_fzn_group_line_validate(v) != SITU_OK)
		return FZN_GROUP_LINE_ERR_SHAPE;
	memcpy(out->group, fzn_group_line_wire_fzn_group_line_group_ptr(v), FZN_GROUP_ID_LEN);
	out->epoch = fzn_group_line_wire_fzn_group_line_epoch_get(v);
	memcpy(out->sender, fzn_group_line_wire_fzn_group_line_sender_ptr(v), FZN_PUBKEY_LEN);
	memcpy(out->host, fzn_group_line_wire_fzn_group_line_host_ptr(v), FZN_PUBKEY_LEN);
	memcpy(out->id, fzn_group_line_wire_fzn_group_line_id_ptr(v), FZN_GROUP_LINE_ID_LEN);
	out->stime = fzn_group_line_wire_fzn_group_line_stime_get(v);
	return FZN_GROUP_LINE_OK;
}

fzn_group_line_err_t fzn_group_line_open(const uint8_t *bytes, size_t len,
                                         const uint8_t secret[FZN_GROUP_SECRET_LEN],
                                         const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                         fzn_group_line_t *out)
{
	uint8_t key[FZN_AEAD_KEY_LEN];
	const uint8_t *nonce;
	fzn_group_line_err_t err;
	int ok;

	if (!secret || !hash || !hash->hash || !aead || !aead->open)
		return FZN_GROUP_LINE_ERR_MALFORMED;
	err = fzn_group_line_peek(bytes, len, out);
	if (err != FZN_GROUP_LINE_OK)
		return err;
	nonce = bytes + FZN_GROUP_LINE_HEAD_LEN;
	out->text_len = fzn_get_be16(nonce + FZN_AEAD_NONCE_LEN);
	memcpy(out->text, nonce + FZN_AEAD_NONCE_LEN + 2u, out->text_len);
	if (!line_key(hash, secret, out->host, key))
		return FZN_GROUP_LINE_ERR_OPS;
	ok = aead->open(aead->ctx, key, nonce, bytes, FZN_GROUP_LINE_HEAD_LEN, out->text,
	                out->text_len, nonce + FZN_AEAD_NONCE_LEN + 2u + out->text_len);
	memset(key, 0, sizeof(key));
	if (!ok) {
		memset(out->text, 0, out->text_len);
		out->text_len = 0;
		return FZN_GROUP_LINE_ERR_OPEN;
	}
	return FZN_GROUP_LINE_OK;
}

fzn_group_line_err_t fzn_group_line_admit(const fzn_group_t *g, const fzn_group_line_t *line)
{
	const fzn_group_host_t *h;

	if (!g || !line)
		return FZN_GROUP_LINE_ERR_MALFORMED;
	if (memcmp(g->id, line->group, FZN_GROUP_ID_LEN) != 0 || line->epoch == 0u
	    || line->epoch > g->epoch)
		return FZN_GROUP_LINE_ERR_STRANGER;
	if (line->epoch < g->epoch)
		return FZN_GROUP_LINE_OK;
	h = fzn_group_host(g, line->host);
	if (!fzn_group_is_member(g, line->sender) || !h
	    || memcmp(h->owner, line->sender, FZN_PUBKEY_LEN) != 0)
		return FZN_GROUP_LINE_ERR_STRANGER;
	return FZN_GROUP_LINE_OK;
}
