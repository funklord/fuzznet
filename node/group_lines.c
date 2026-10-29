/* A group's lines as a host holds them: project.md sec 629, and the header. */
#include "group_lines.h"

#include <string.h>

#include "../wire/bytes.h"

const char *fzn_group_lines_err_str(fzn_group_lines_err_t err)
{
	switch (err) {
	case FZN_GROUP_LINES_OK:
		return "ok";
	case FZN_GROUP_LINES_ERR_MALFORMED:
		return "malformed";
	case FZN_GROUP_LINES_ERR_HELD:
		return "already held";
	case FZN_GROUP_LINES_ERR_GAP:
		return "the line before it is not held";
	case FZN_GROUP_LINES_ERR_ABSENT:
		return "no such line";
	case FZN_GROUP_LINES_ERR_BACKEND:
		return "the store refused";
	}
	return "unknown";
}

/* VERSION 2 CARRIES A BASE, sec 664; a version 1 head reads as base 0. */
#define HEAD_VERSION 2u
#define HEAD_LEN_V1 (1u + FZN_GROUP_ID_LEN + FZN_PUBKEY_LEN + 4u + 4u)
#define HEAD_LEN (HEAD_LEN_V1 + 4u)

/* A ROW'S SUBJECT: the hash of a label and the parts that name it. */
static int subject_of(const fzn_hash_ops_t *hash, char kind, const uint8_t *group,
                      const uint8_t *key, uint32_t n, uint8_t out[FZN_PUBKEY_LEN])
{
	uint8_t in[1u + FZN_GROUP_ID_LEN + FZN_PUBKEY_LEN + 4u];

	in[0] = (uint8_t)kind;
	memcpy(in + 1, group, FZN_GROUP_ID_LEN);
	memcpy(in + 1 + FZN_GROUP_ID_LEN, key, FZN_PUBKEY_LEN);
	fzn_put_be32(in + 1 + FZN_GROUP_ID_LEN + FZN_PUBKEY_LEN, n);
	return hash->hash(hash->ctx, out, FZN_PUBKEY_LEN, in, sizeof(in));
}

static int usable(const fzn_group_lines_t *l)
{
	return l && l->store && l->store->load && l->store->save && l->hash && l->hash->hash;
}

static int head_decode(const uint8_t *in, size_t len, fzn_group_line_head_t *out)
{
	if (!((len == HEAD_LEN && in[0] == HEAD_VERSION) || (len == HEAD_LEN_V1 && in[0] == 1u)))
		return 0;
	memcpy(out->group, in + 1, FZN_GROUP_ID_LEN);
	memcpy(out->host, in + 1 + FZN_GROUP_ID_LEN, FZN_PUBKEY_LEN);
	out->have = fzn_get_be32(in + 1 + FZN_GROUP_ID_LEN + FZN_PUBKEY_LEN);
	out->filed = fzn_get_be32(in + 1 + FZN_GROUP_ID_LEN + FZN_PUBKEY_LEN + 4u);
	out->base = len == HEAD_LEN ? fzn_get_be32(in + HEAD_LEN_V1) : 0u;
	return out->filed <= out->have && out->base <= out->have;
}

static fzn_group_lines_err_t head_save(const fzn_group_lines_t *l, const fzn_group_line_head_t *h)
{
	uint8_t bytes[HEAD_LEN], subject[FZN_PUBKEY_LEN];

	bytes[0] = HEAD_VERSION;
	memcpy(bytes + 1, h->group, FZN_GROUP_ID_LEN);
	memcpy(bytes + 1 + FZN_GROUP_ID_LEN, h->host, FZN_PUBKEY_LEN);
	fzn_put_be32(bytes + 1 + FZN_GROUP_ID_LEN + FZN_PUBKEY_LEN, h->have);
	fzn_put_be32(bytes + 1 + FZN_GROUP_ID_LEN + FZN_PUBKEY_LEN + 4u, h->filed);
	fzn_put_be32(bytes + HEAD_LEN_V1, h->base);
	if (!subject_of(l->hash, 'h', h->group, h->host, 0u, subject)
	    || !l->store->save(l->store->ctx, FZN_PERSIST_GROUP_LINE_HEAD, subject, bytes,
	                       sizeof(bytes)))
		return FZN_GROUP_LINES_ERR_BACKEND;
	return FZN_GROUP_LINES_OK;
}

fzn_group_lines_err_t fzn_group_lines_head(const fzn_group_lines_t *l,
                                           const uint8_t group[FZN_GROUP_ID_LEN],
                                           const uint8_t host[FZN_PUBKEY_LEN],
                                           fzn_group_line_head_t *out)
{
	uint8_t bytes[HEAD_LEN], subject[FZN_PUBKEY_LEN];
	size_t n = 0;

	/* NB: `bytes` is a version 2 head's size, which a version 1 fits. */
	if (!usable(l) || !group || !host || !out)
		return FZN_GROUP_LINES_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	memcpy(out->group, group, FZN_GROUP_ID_LEN);
	memcpy(out->host, host, FZN_PUBKEY_LEN);
	if (!subject_of(l->hash, 'h', group, host, 0u, subject))
		return FZN_GROUP_LINES_ERR_BACKEND;
	if (!l->store->load(l->store->ctx, FZN_PERSIST_GROUP_LINE_HEAD, subject, bytes, sizeof(bytes),
	                    &n))
		return FZN_GROUP_LINES_OK;
	return head_decode(bytes, n, out) ? FZN_GROUP_LINES_OK : FZN_GROUP_LINES_ERR_BACKEND;
}

fzn_group_lines_err_t fzn_group_lines_heads(const fzn_group_lines_t *l,
                                            const uint8_t group[FZN_GROUP_ID_LEN],
                                            fzn_group_line_head_t *out, size_t cap,
                                            size_t *count)
{
	static uint8_t subjects[FZN_GROUP_LINE_HEADS_MAX][FZN_PUBKEY_LEN];
	uint8_t bytes[HEAD_LEN];
	size_t n = 0, i, len = 0;

	if (!usable(l) || !group || !out || !count)
		return FZN_GROUP_LINES_ERR_MALFORMED;
	*count = 0;
	if (!l->store->list
	    || !l->store->list(l->store->ctx, FZN_PERSIST_GROUP_LINE_HEAD, (uint8_t *)subjects,
	                       FZN_GROUP_LINE_HEADS_MAX, &n))
		return FZN_GROUP_LINES_ERR_BACKEND;
	for (i = 0; i < n && *count < cap; i++)
		if (l->store->load(l->store->ctx, FZN_PERSIST_GROUP_LINE_HEAD, subjects[i], bytes,
		                   sizeof(bytes), &len)
		    && head_decode(bytes, len, &out[*count])
		    && memcmp(out[*count].group, group, FZN_GROUP_ID_LEN) == 0)
			(*count)++;
	return FZN_GROUP_LINES_OK;
}

fzn_group_lines_err_t fzn_group_lines_put(const fzn_group_lines_t *l, uint32_t n,
                                          const uint8_t *bytes, size_t len)
{
	static fzn_group_line_t peeked;
	fzn_group_line_head_t h;
	uint8_t subject[FZN_PUBKEY_LEN];
	fzn_group_lines_err_t err;

	if (!usable(l) || !bytes || n == 0u
	    || fzn_group_line_peek(bytes, len, &peeked) != FZN_GROUP_LINE_OK)
		return FZN_GROUP_LINES_ERR_MALFORMED;
	err = fzn_group_lines_head(l, peeked.group, peeked.host, &h);
	if (err != FZN_GROUP_LINES_OK)
		return err;
	if (n <= h.have)
		return FZN_GROUP_LINES_ERR_HELD;
	if (n != h.have + 1u)
		return FZN_GROUP_LINES_ERR_GAP;
	/* THE LINE FIRST, then the head: a head never names a line not held. */
	if (!subject_of(l->hash, 'l', peeked.group, peeked.host, n, subject)
	    || !l->store->save(l->store->ctx, FZN_PERSIST_GROUP_LINE, subject, bytes, len))
		return FZN_GROUP_LINES_ERR_BACKEND;
	h.have = n;
	return head_save(l, &h);
}

fzn_group_lines_err_t fzn_group_lines_trim(const fzn_group_lines_t *l,
                                           const uint8_t group[FZN_GROUP_ID_LEN],
                                           const uint8_t host[FZN_PUBKEY_LEN], uint32_t upto,
                                           size_t *removed)
{
	fzn_group_line_head_t h;
	uint8_t subject[FZN_PUBKEY_LEN];
	fzn_group_lines_err_t err;
	uint32_t s;

	if (removed)
		*removed = 0;
	if (!usable(l) || !group || !host || !l->store->remove)
		return FZN_GROUP_LINES_ERR_MALFORMED;
	err = fzn_group_lines_head(l, group, host, &h);
	if (err != FZN_GROUP_LINES_OK || upto <= h.base)
		return err;
	/* THE LINES FIRST, then the head, sec 746, as a conversation's trim
	 * removes a row before saving its head (sec 523): the text goes
	 * whatever happens after. The head was saved first, so a head never
	 * named a line it would serve and not find; but a removal refused, or
	 * a crash between, left lines below the base, which no later trim
	 * reaches, and their text stayed past its rule for good. Now such a
	 * crash leaves the old base naming lines gone, ABSENT as a line not
	 * yet held is, and the next trim starts from it again. */
	{
		uint32_t from = h.base + 1u, held_to = h.have < upto ? h.have : upto;

		/* THE LINES HELD BETWEEN the old base and `upto`, and no others. */
		for (s = from; s <= held_to; s++) {
			if (!subject_of(l->hash, 'l', group, host, s, subject))
				return FZN_GROUP_LINES_ERR_BACKEND;
			if (!l->store->remove(l->store->ctx, FZN_PERSIST_GROUP_LINE, subject))
				return FZN_GROUP_LINES_ERR_BACKEND;
			if (removed)
				(*removed)++;
		}
		h.base = upto;
		if (h.have < upto)
			h.have = upto;
		if (h.filed < upto)
			h.filed = upto;
		err = head_save(l, &h);
		if (err != FZN_GROUP_LINES_OK)
			return err;
	}
	return FZN_GROUP_LINES_OK;
}

fzn_group_lines_err_t fzn_group_lines_put_from(const fzn_group_lines_t *l, uint32_t n,
                                               const uint8_t *bytes, size_t len)
{
	static fzn_group_line_t peeked;
	fzn_group_line_head_t h;
	fzn_group_lines_err_t err;

	if (!usable(l) || !bytes || n == 0u
	    || fzn_group_line_peek(bytes, len, &peeked) != FZN_GROUP_LINE_OK)
		return FZN_GROUP_LINES_ERR_MALFORMED;
	err = fzn_group_lines_head(l, peeked.group, peeked.host, &h);
	if (err != FZN_GROUP_LINES_OK)
		return err;
	if (n > h.have + 1u) {
		err = fzn_group_lines_trim(l, peeked.group, peeked.host, n - 1u, NULL);
		if (err != FZN_GROUP_LINES_OK)
			return err;
	}
	return fzn_group_lines_put(l, n, bytes, len);
}

fzn_group_lines_err_t fzn_group_lines_get(const fzn_group_lines_t *l,
                                          const uint8_t group[FZN_GROUP_ID_LEN],
                                          const uint8_t host[FZN_PUBKEY_LEN], uint32_t n,
                                          uint8_t *out, size_t cap, size_t *len)
{
	uint8_t subject[FZN_PUBKEY_LEN];

	if (!usable(l) || !group || !host || !out || !len)
		return FZN_GROUP_LINES_ERR_MALFORMED;
	if (!subject_of(l->hash, 'l', group, host, n, subject)
	    || !l->store->load(l->store->ctx, FZN_PERSIST_GROUP_LINE, subject, out, cap, len))
		return FZN_GROUP_LINES_ERR_ABSENT;
	return FZN_GROUP_LINES_OK;
}

fzn_group_lines_err_t fzn_group_lines_filed(const fzn_group_lines_t *l,
                                            const uint8_t group[FZN_GROUP_ID_LEN],
                                            const uint8_t host[FZN_PUBKEY_LEN], uint32_t filed)
{
	fzn_group_line_head_t h;
	fzn_group_lines_err_t err = fzn_group_lines_head(l, group, host, &h);

	if (err != FZN_GROUP_LINES_OK)
		return err;
	if (filed > h.have)
		return FZN_GROUP_LINES_ERR_MALFORMED;
	h.filed = filed;
	return head_save(l, &h);
}

int fzn_group_lines_filed_id(const fzn_hash_ops_t *hash, const uint8_t host[FZN_PUBKEY_LEN],
                             const uint8_t id[FZN_GROUP_LINE_ID_LEN],
                             uint8_t out[FZN_GROUP_LINE_ID_LEN])
{
	static const char label[] = "fuzznet group line filed";
	uint8_t in[sizeof(label) - 1u + FZN_PUBKEY_LEN + FZN_GROUP_LINE_ID_LEN];

	if (!hash || !hash->hash || !host || !id || !out)
		return 0;
	memcpy(in, label, sizeof(label) - 1u);
	memcpy(in + sizeof(label) - 1u, host, FZN_PUBKEY_LEN);
	memcpy(in + sizeof(label) - 1u + FZN_PUBKEY_LEN, id, FZN_GROUP_LINE_ID_LEN);
	return hash->hash(hash->ctx, out, FZN_GROUP_LINE_ID_LEN, in, sizeof(in));
}

fzn_group_lines_err_t fzn_group_lines_sender_keep(const fzn_group_lines_t *l,
                                                  const uint8_t group[FZN_GROUP_ID_LEN],
                                                  const uint8_t filed_id[FZN_GROUP_LINE_ID_LEN],
                                                  const uint8_t sender[FZN_PUBKEY_LEN])
{
	uint8_t key[FZN_PUBKEY_LEN], subject[FZN_PUBKEY_LEN];

	if (!usable(l) || !group || !filed_id || !sender)
		return FZN_GROUP_LINES_ERR_MALFORMED;
	memset(key, 0, sizeof(key));
	memcpy(key, filed_id, FZN_GROUP_LINE_ID_LEN);
	if (!subject_of(l->hash, 's', group, key, 0u, subject)
	    || !l->store->save(l->store->ctx, FZN_PERSIST_GROUP_LINE_SENDER, subject, sender,
	                       FZN_PUBKEY_LEN))
		return FZN_GROUP_LINES_ERR_BACKEND;
	return FZN_GROUP_LINES_OK;
}

fzn_group_lines_err_t fzn_group_lines_sender(const fzn_group_lines_t *l,
                                             const uint8_t group[FZN_GROUP_ID_LEN],
                                             const uint8_t filed_id[FZN_GROUP_LINE_ID_LEN],
                                             uint8_t sender[FZN_PUBKEY_LEN])
{
	uint8_t key[FZN_PUBKEY_LEN], subject[FZN_PUBKEY_LEN];
	size_t n = 0;

	if (!usable(l) || !group || !filed_id || !sender)
		return FZN_GROUP_LINES_ERR_MALFORMED;
	memset(key, 0, sizeof(key));
	memcpy(key, filed_id, FZN_GROUP_LINE_ID_LEN);
	if (!subject_of(l->hash, 's', group, key, 0u, subject)
	    || !l->store->load(l->store->ctx, FZN_PERSIST_GROUP_LINE_SENDER, subject, sender,
	                       FZN_PUBKEY_LEN, &n)
	    || n != FZN_PUBKEY_LEN)
		return FZN_GROUP_LINES_ERR_ABSENT;
	return FZN_GROUP_LINES_OK;
}
