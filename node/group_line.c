/* A group line in transit: project.md sec 628, and the header. */
#include "group_line.h"

#include <string.h>

#include "../wire/bytes.h"

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

/* THE HEAD, the AEAD's associated data. */
static void head(const fzn_group_line_t *l, uint8_t out[FZN_GROUP_LINE_HEAD_LEN])
{
	size_t at = 0;

	out[at++] = FZN_GROUP_LINE_VERSION;
	memcpy(out + at, l->group, FZN_GROUP_ID_LEN);
	at += FZN_GROUP_ID_LEN;
	fzn_put_be32(out + at, l->epoch);
	at += 4u;
	memcpy(out + at, l->sender, FZN_PUBKEY_LEN);
	at += FZN_PUBKEY_LEN;
	memcpy(out + at, l->host, FZN_PUBKEY_LEN);
	at += FZN_PUBKEY_LEN;
	memcpy(out + at, l->id, FZN_GROUP_LINE_ID_LEN);
	at += FZN_GROUP_LINE_ID_LEN;
	fzn_put_be64(out + at, l->stime);
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
	uint8_t key[FZN_AEAD_KEY_LEN];
	uint8_t *nonce, *text;
	size_t need;
	int ok;

	if (!line || !secret || !hash || !hash->hash || !aead || !aead->seal || !rng || !rng->fill
	    || !out || !len || line->text_len > FZN_GROUP_LINE_TEXT_MAX)
		return FZN_GROUP_LINE_ERR_MALFORMED;
	need = FZN_GROUP_LINE_HEAD_LEN + FZN_AEAD_NONCE_LEN + 2u + line->text_len + FZN_AEAD_TAG_LEN;
	if (cap < need)
		return FZN_GROUP_LINE_ERR_MALFORMED;
	head(line, out);
	nonce = out + FZN_GROUP_LINE_HEAD_LEN;
	fzn_put_be16(nonce + FZN_AEAD_NONCE_LEN, (uint16_t)line->text_len);
	text = nonce + FZN_AEAD_NONCE_LEN + 2u;
	memcpy(text, line->text, line->text_len);
	if (!rng->fill(rng->ctx, nonce, FZN_AEAD_NONCE_LEN) || !line_key(hash, secret, line->host, key))
		return FZN_GROUP_LINE_ERR_OPS;
	ok = aead->seal(aead->ctx, key, nonce, out, FZN_GROUP_LINE_HEAD_LEN, text, line->text_len,
	                text + line->text_len);
	memset(key, 0, sizeof(key));
	if (!ok)
		return FZN_GROUP_LINE_ERR_OPS;
	*len = need;
	return FZN_GROUP_LINE_OK;
}

fzn_group_line_err_t fzn_group_line_peek(const uint8_t *bytes, size_t len,
                                         fzn_group_line_t *out)
{
	size_t at = 1u, text_len;

	if (!bytes || !out)
		return FZN_GROUP_LINE_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	if (len < FZN_GROUP_LINE_HEAD_LEN + FZN_AEAD_NONCE_LEN + 2u + FZN_AEAD_TAG_LEN
	    || bytes[0] != FZN_GROUP_LINE_VERSION)
		return FZN_GROUP_LINE_ERR_SHAPE;
	text_len = fzn_get_be16(bytes + FZN_GROUP_LINE_HEAD_LEN + FZN_AEAD_NONCE_LEN);
	/* EXACTLY ITS LENGTH. */
	if (text_len > FZN_GROUP_LINE_TEXT_MAX
	    || len != FZN_GROUP_LINE_HEAD_LEN + FZN_AEAD_NONCE_LEN + 2u + text_len + FZN_AEAD_TAG_LEN)
		return FZN_GROUP_LINE_ERR_SHAPE;
	memcpy(out->group, bytes + at, FZN_GROUP_ID_LEN);
	at += FZN_GROUP_ID_LEN;
	out->epoch = fzn_get_be32(bytes + at);
	at += 4u;
	memcpy(out->sender, bytes + at, FZN_PUBKEY_LEN);
	at += FZN_PUBKEY_LEN;
	memcpy(out->host, bytes + at, FZN_PUBKEY_LEN);
	at += FZN_PUBKEY_LEN;
	memcpy(out->id, bytes + at, FZN_GROUP_LINE_ID_LEN);
	at += FZN_GROUP_LINE_ID_LEN;
	out->stime = fzn_get_be64(bytes + at);
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
