/* See invite.h. */

#include "invite.h"

#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#include <string.h>

static const char BASE32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const uint8_t MARK_ASK[FZN_INVITE_MARK_LEN] = { 'F', 'Z', 'I', 1u };
static const uint8_t MARK_ANSWER[FZN_INVITE_MARK_LEN] = { 'F', 'Z', 'I', 2u };

static int where_ok(const char *w, size_t len)
{
	size_t i;

	if (!len || len > FZN_INVITE_WHERE_MAX)
		return 0;
	for (i = 0; i < len; i++) {
		char c = w[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		      || c == '.' || c == '-' || c == ':'))
			return 0;
	}
	return 1;
}

size_t fzn_invite_text(const fzn_invite_t *in, char *out, size_t cap)
{
	uint8_t raw[FZN_INVITE_FIXED_LEN + FZN_INVITE_WHERE_MAX];
	size_t n = 0, at, i;
	uint32_t bits = 0;
	unsigned held = 0;

	if (!in || !out || cap < FZN_INVITE_TEXT_MAX || !in->port || !where_ok(in->where, in->where_len))
		return 0;
	memcpy(raw + n, in->host, FZN_PUBKEY_LEN);
	n += FZN_PUBKEY_LEN;
	memcpy(raw + n, in->agree, FZN_PUBKEY_LEN);
	n += FZN_PUBKEY_LEN;
	memcpy(raw + n, in->secret, FZN_INVITE_SECRET_LEN);
	n += FZN_INVITE_SECRET_LEN;
	fzn_put_be16(raw + n, in->port);
	n += 2u;
	memcpy(raw + n, in->where, in->where_len);
	n += in->where_len;
	memcpy(out, FZN_INVITE_TEXT_PREFIX, FZN_INVITE_TEXT_PREFIX_LEN);
	at = FZN_INVITE_TEXT_PREFIX_LEN;
	for (i = 0; i < n; i++) {
		bits = (bits << 8) | raw[i];
		held += 8u;
		while (held >= 5u) {
			held -= 5u;
			out[at++] = BASE32[(bits >> held) & 31u];
		}
	}
	if (held)
		out[at++] = BASE32[(bits << (5u - held)) & 31u];
	out[at] = '\0';
	fzn_wipe(raw, sizeof(raw));
	return at;
}

int fzn_invite_parse(const char *text, size_t len, fzn_invite_t *out)
{
	uint8_t raw[FZN_INVITE_FIXED_LEN + FZN_INVITE_WHERE_MAX + 1u];
	size_t n = 0, i;
	uint32_t bits = 0;
	unsigned held = 0;

	if (!text || !out || len <= FZN_INVITE_TEXT_PREFIX_LEN
	    || memcmp(text, FZN_INVITE_TEXT_PREFIX, FZN_INVITE_TEXT_PREFIX_LEN) != 0)
		return 0;
	for (i = FZN_INVITE_TEXT_PREFIX_LEN; i < len; i++) {
		const char *c = text[i] ? strchr(BASE32, text[i]) : NULL;

		if (!c)
			return 0;
		bits = (bits << 5) | (uint32_t)(c - BASE32);
		held += 5u;
		if (held >= 8u) {
			held -= 8u;
			if (n == sizeof(raw))
				return 0;
			raw[n++] = (uint8_t)(bits >> held);
		}
	}
	/* ONE ENCODING: what is left over is padding, under a byte and nought. */
	if (held >= 5u || (bits & ((1u << held) - 1u)) != 0u)
		return 0;
	if (n <= FZN_INVITE_FIXED_LEN || n > FZN_INVITE_FIXED_LEN + FZN_INVITE_WHERE_MAX)
		return 0;
	memset(out, 0, sizeof(*out));
	memcpy(out->host, raw, FZN_PUBKEY_LEN);
	memcpy(out->agree, raw + FZN_PUBKEY_LEN, FZN_PUBKEY_LEN);
	memcpy(out->secret, raw + 2u * FZN_PUBKEY_LEN, FZN_INVITE_SECRET_LEN);
	out->port = fzn_get_be16(raw + 2u * FZN_PUBKEY_LEN + FZN_INVITE_SECRET_LEN);
	out->where_len = n - FZN_INVITE_FIXED_LEN;
	memcpy(out->where, raw + FZN_INVITE_FIXED_LEN, out->where_len);
	fzn_wipe(raw, sizeof(raw));
	return out->port != 0u && where_ok(out->where, out->where_len);
}

int fzn_invite_kind(const uint8_t *plain, size_t len)
{
	if (!plain || len < FZN_INVITE_MARK_LEN)
		return 0;
	if (memcmp(plain, MARK_ASK, FZN_INVITE_MARK_LEN) == 0 && len == FZN_INVITE_ASK_LEN)
		return 1;
	if (memcmp(plain, MARK_ANSWER, FZN_INVITE_MARK_LEN) == 0 && len > FZN_INVITE_ANSWER_HEAD
	    && len <= FZN_INVITE_ANSWER_MAX)
		return 2;
	return 0;
}

void fzn_invite_ask(const uint8_t secret[FZN_INVITE_SECRET_LEN],
                    const uint8_t record[FZN_PREKEY_LEN_TOTAL], uint8_t out[FZN_INVITE_ASK_LEN])
{
	memcpy(out, MARK_ASK, FZN_INVITE_MARK_LEN);
	memcpy(out + FZN_INVITE_MARK_LEN, secret, FZN_INVITE_SECRET_LEN);
	memcpy(out + FZN_INVITE_MARK_LEN + FZN_INVITE_SECRET_LEN, record, FZN_PREKEY_LEN_TOTAL);
}

size_t fzn_invite_answer(const uint8_t secret[FZN_INVITE_SECRET_LEN], const uint8_t *card,
                         size_t card_len, size_t part, uint8_t *out)
{
	size_t parts = FZN_INVITE_PARTS(card_len), at = part * FZN_INVITE_PART_MAX, n;

	if (!card || !card_len || part >= parts || parts > 255u)
		return 0;
	n = card_len - at < FZN_INVITE_PART_MAX ? card_len - at : FZN_INVITE_PART_MAX;
	memcpy(out, MARK_ANSWER, FZN_INVITE_MARK_LEN);
	memcpy(out + FZN_INVITE_MARK_LEN, secret, FZN_INVITE_SECRET_LEN);
	out[FZN_INVITE_MARK_LEN + FZN_INVITE_SECRET_LEN] = (uint8_t)part;
	out[FZN_INVITE_MARK_LEN + FZN_INVITE_SECRET_LEN + 1u] = (uint8_t)parts;
	memcpy(out + FZN_INVITE_ANSWER_HEAD, card + at, n);
	return FZN_INVITE_ANSWER_HEAD + n;
}

int fzn_invite_card_take(fzn_invite_card_t *c, const uint8_t secret[FZN_INVITE_SECRET_LEN],
                         const uint8_t *plain, size_t len)
{
	size_t part, parts, n, i, at;

	if (!c || !secret || fzn_invite_kind(plain, len) != 2
	    || !fzn_ct_memeq(plain + FZN_INVITE_MARK_LEN, secret, FZN_INVITE_SECRET_LEN))
		return 0;
	part = plain[FZN_INVITE_MARK_LEN + FZN_INVITE_SECRET_LEN];
	parts = plain[FZN_INVITE_MARK_LEN + FZN_INVITE_SECRET_LEN + 1u];
	n = len - FZN_INVITE_ANSWER_HEAD;
	at = part * FZN_INVITE_PART_MAX;
	if (!parts || part >= parts || parts > sizeof(c->have) || at + n > sizeof(c->bytes)
	    || (part + 1u < parts && n != FZN_INVITE_PART_MAX) || (c->parts && parts != c->parts))
		return 0;
	c->parts = parts;
	memcpy(c->bytes + at, plain + FZN_INVITE_ANSWER_HEAD, n);
	c->have[part] = 1u;
	if (part + 1u == parts)
		c->len = at + n;
	for (i = 0; i < parts; i++)
		if (!c->have[i])
			return 0;
	return 1;
}

static int live(const fzn_invite_open_t *r, uint64_t now)
{
	return r->used && (r->claimed || r->expires_at > now);
}

fzn_invite_open_t *fzn_invites_add(fzn_invites_t *t, const uint8_t secret[FZN_INVITE_SECRET_LEN],
                                   int delegable, uint64_t now, uint64_t expires_at)
{
	size_t i;

	if (!t || !secret)
		return NULL;
	for (i = 0; i < FZN_INVITES_MAX; i++) {
		fzn_invite_open_t *r = &t->rows[i];

		/* A CLAIMED ROW lives to answer its device again, and gives way
		 * once its life has passed. */
		if (live(r, now) && r->expires_at > now)
			continue;
		fzn_wipe(r, sizeof(*r));
		r->used = 1;
		memcpy(r->secret, secret, FZN_INVITE_SECRET_LEN);
		r->expires_at = expires_at;
		r->delegable = delegable;
		return r;
	}
	return NULL;
}

fzn_invite_open_t *fzn_invites_find(fzn_invites_t *t, const uint8_t secret[FZN_INVITE_SECRET_LEN],
                                    const uint8_t device[FZN_PUBKEY_LEN], uint64_t now)
{
	size_t i;

	if (!t || !secret || !device)
		return NULL;
	for (i = 0; i < FZN_INVITES_MAX; i++) {
		fzn_invite_open_t *r = &t->rows[i];

		if (!r->used || !fzn_ct_memeq(r->secret, secret, FZN_INVITE_SECRET_LEN))
			continue;
		if (r->claimed)
			return fzn_ct_memeq(r->device, device, FZN_PUBKEY_LEN) ? r : NULL;
		return r->expires_at > now ? r : NULL;
	}
	return NULL;
}

size_t fzn_invites_clear(fzn_invites_t *t, uint64_t now)
{
	size_t i, n = 0;

	if (!t)
		return 0;
	for (i = 0; i < FZN_INVITES_MAX; i++) {
		if (live(&t->rows[i], now) && !t->rows[i].claimed)
			n++;
		fzn_wipe(&t->rows[i], sizeof(t->rows[i]));
	}
	return n;
}

size_t fzn_invites_live(const fzn_invites_t *t, uint64_t now)
{
	size_t i, n = 0;

	if (!t)
		return 0;
	for (i = 0; i < FZN_INVITES_MAX; i++)
		if (live(&t->rows[i], now) && !t->rows[i].claimed)
			n++;
	return n;
}
