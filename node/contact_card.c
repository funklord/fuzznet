/* A contact card: project.md sec 617, and the header. */
#include "contact_card.h"

#include <string.h>

#include "../contact/contact.h"
#include "../wire/bytes.h"

const char *fzn_contact_card_err_str(fzn_contact_card_err_t err)
{
	switch (err) {
	case FZN_CONTACT_CARD_OK:
		return "ok";
	case FZN_CONTACT_CARD_ERR_MALFORMED:
		return "malformed";
	case FZN_CONTACT_CARD_ERR_SHAPE:
		return "not a contact card";
	case FZN_CONTACT_CARD_ERR_REFUSED:
		return "its signature, record or chain does not hold";
	case FZN_CONTACT_CARD_ERR_EXPIRED:
		return "expired";
	}
	return "unknown";
}

/* An address as `net/address` takes one: letters, digits and `.-:`. */
static int address_ok(const char *a, size_t len)
{
	size_t i;

	if (len == 0u || len > FZN_CONTACT_DEVICE_ADDRESS_MAX)
		return 0;
	for (i = 0; i < len; i++) {
		char c = a[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		      || c == '.' || c == '-' || c == ':'))
			return 0;
	}
	return 1;
}

/* Whether the fields are in range, as a card is signed or read. */
static int fields_ok(const fzn_contact_card_t *card)
{
	size_t i;

	if (card->n_seeds > FZN_CONTACT_CARD_SEEDS_MAX || card->name_len > FZN_CONTACT_CARD_NAME_MAX
	    || (card->name_len && !fzn_contact_name_ok(card->name, card->name_len)))
		return 0;
	for (i = 0; i < card->n_seeds; i++)
		if (card->seeds[i].port == 0u
		    || !address_ok(card->seeds[i].address, card->seeds[i].address_len))
			return 0;
	/* SOMEWHERE TO ASK: the host's own address, or a seed. */
	return card->host.port != 0u || card->n_seeds > 0u;
}

/* Everything the signature covers, into `out`; its length. 0 when it will
 * not fit or the host entry will not encode. */
static size_t body(const fzn_contact_card_t *card, uint8_t *out, size_t cap)
{
	size_t at = 4u, host_len = 0, i;

	if (cap < 4u
	    || fzn_contact_device_encode(&card->host, out + 4, cap - 4u, &host_len)
	               != FZN_CONTACT_DEVICE_OK)
		return 0;
	out[0] = FZN_CONTACT_CARD_VERSION;
	out[1] = (uint8_t)FZN_OBJECT_CONTACT_CARD;
	fzn_put_be16(out + 2, (uint16_t)host_len);
	at += host_len;
	if (at + 1u > cap)
		return 0;
	out[at++] = (uint8_t)card->n_seeds;
	for (i = 0; i < card->n_seeds; i++) {
		const fzn_contact_card_seed_t *s = &card->seeds[i];

		if (at + 1u + s->address_len + 4u > cap)
			return 0;
		out[at++] = (uint8_t)s->address_len;
		memcpy(out + at, s->address, s->address_len);
		at += s->address_len;
		fzn_put_be16(out + at, s->port);
		out[at + 2u] = s->transport;
		out[at + 3u] = s->metric;
		at += 4u;
	}
	if (at + 1u + card->name_len + 8u > cap)
		return 0;
	out[at++] = (uint8_t)card->name_len;
	memcpy(out + at, card->name, card->name_len);
	at += card->name_len;
	fzn_put_be64(out + at, card->expires_at);
	return at + 8u;
}

fzn_contact_card_err_t fzn_contact_card_sign(fzn_contact_card_t *card, const fzn_sign_ops_t *sign)
{
	static uint8_t bytes[FZN_CONTACT_CARD_MAX];
	size_t n;

	if (!card || !sign || !sign->sign || !fields_ok(card))
		return FZN_CONTACT_CARD_ERR_MALFORMED;
	n = body(card, bytes, sizeof(bytes));
	if (!n || !sign->sign(sign->ctx, card->sig, bytes, n))
		return FZN_CONTACT_CARD_ERR_MALFORMED;
	return FZN_CONTACT_CARD_OK;
}

fzn_contact_card_err_t fzn_contact_card_encode(const fzn_contact_card_t *card, uint8_t *out,
                                               size_t cap, size_t *len)
{
	size_t n;

	if (!card || !out || !len || !fields_ok(card))
		return FZN_CONTACT_CARD_ERR_MALFORMED;
	n = body(card, out, cap);
	if (!n || n + FZN_SIG_LEN > cap)
		return FZN_CONTACT_CARD_ERR_MALFORMED;
	memcpy(out + n, card->sig, FZN_SIG_LEN);
	*len = n + FZN_SIG_LEN;
	return FZN_CONTACT_CARD_OK;
}

fzn_contact_card_err_t fzn_contact_card_decode(const uint8_t *bytes, size_t len,
                                               fzn_contact_card_t *out)
{
	size_t at, host_len, i;

	if (!bytes || !out)
		return FZN_CONTACT_CARD_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	if (len < 4u || bytes[0] != FZN_CONTACT_CARD_VERSION
	    || bytes[1] != (uint8_t)FZN_OBJECT_CONTACT_CARD)
		return FZN_CONTACT_CARD_ERR_SHAPE;
	host_len = fzn_get_be16(bytes + 2);
	if (len < 4u + host_len + 1u
	    || fzn_contact_device_decode(bytes + 4, host_len, &out->host) != FZN_CONTACT_DEVICE_OK)
		return FZN_CONTACT_CARD_ERR_SHAPE;
	at = 4u + host_len;
	out->n_seeds = bytes[at++];
	if (out->n_seeds > FZN_CONTACT_CARD_SEEDS_MAX)
		return FZN_CONTACT_CARD_ERR_SHAPE;
	for (i = 0; i < out->n_seeds; i++) {
		fzn_contact_card_seed_t *s = &out->seeds[i];

		if (len < at + 1u)
			return FZN_CONTACT_CARD_ERR_SHAPE;
		s->address_len = bytes[at++];
		if (s->address_len > FZN_CONTACT_DEVICE_ADDRESS_MAX || len < at + s->address_len + 4u)
			return FZN_CONTACT_CARD_ERR_SHAPE;
		memcpy(s->address, bytes + at, s->address_len);
		s->address[s->address_len] = '\0';
		at += s->address_len;
		s->port = fzn_get_be16(bytes + at);
		s->transport = bytes[at + 2u];
		s->metric = bytes[at + 3u];
		at += 4u;
	}
	if (len < at + 1u)
		return FZN_CONTACT_CARD_ERR_SHAPE;
	out->name_len = bytes[at++];
	if (out->name_len > FZN_CONTACT_CARD_NAME_MAX || len < at + out->name_len + 8u)
		return FZN_CONTACT_CARD_ERR_SHAPE;
	memcpy(out->name, bytes + at, out->name_len);
	out->name[out->name_len] = '\0';
	at += out->name_len;
	out->expires_at = fzn_get_be64(bytes + at);
	at += 8u;
	/* EXACTLY ITS LENGTH, and its fields in range: one card, one encoding. */
	if (len != at + FZN_SIG_LEN || !fields_ok(out))
		return FZN_CONTACT_CARD_ERR_SHAPE;
	memcpy(out->sig, bytes + at, FZN_SIG_LEN);
	return FZN_CONTACT_CARD_OK;
}

fzn_contact_card_err_t fzn_contact_card_verify(const fzn_contact_card_t *card,
                                               const fzn_sign_ops_t *sign,
                                               const fzn_cap_id_t *member, uint64_t now)
{
	static uint8_t bytes[FZN_CONTACT_CARD_MAX];
	size_t n;

	if (!card || !sign || !sign->verify || !member)
		return FZN_CONTACT_CARD_ERR_MALFORMED;
	if (fzn_contact_device_verify(&card->host, sign, member, now) != FZN_CONTACT_DEVICE_OK)
		return FZN_CONTACT_CARD_ERR_REFUSED;
	n = body(card, bytes, sizeof(bytes));
	if (!n
	    || !sign->verify(sign->ctx, fzn_contact_device_key(&card->host), bytes, n, card->sig))
		return FZN_CONTACT_CARD_ERR_REFUSED;
	if (now != 0u && card->expires_at != 0u && card->expires_at < now)
		return FZN_CONTACT_CARD_ERR_EXPIRED;
	return FZN_CONTACT_CARD_OK;
}

/* ---- text: RFC 4648 base32, uppercase, unpadded, as provision/ writes ---- */

static const char B32[32] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fzn_contact_card_err_t fzn_contact_card_text(const uint8_t *bytes, size_t len, char *out,
                                             size_t cap)
{
	size_t i, n = FZN_CONTACT_CARD_TEXT_PREFIX_LEN;
	uint32_t acc = 0;
	unsigned bits = 0;

	if (!bytes || !out || len > FZN_CONTACT_CARD_MAX
	    || cap < FZN_CONTACT_CARD_TEXT_PREFIX_LEN + (len * 8u + 4u) / 5u + 1u)
		return FZN_CONTACT_CARD_ERR_MALFORMED;
	memcpy(out, FZN_CONTACT_CARD_TEXT_PREFIX, FZN_CONTACT_CARD_TEXT_PREFIX_LEN);
	for (i = 0; i < len; i++) {
		acc = (acc << 8) | bytes[i];
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			out[n++] = B32[(acc >> bits) & 0x1fu];
		}
	}
	if (bits > 0)
		out[n++] = B32[(acc << (5u - bits)) & 0x1fu];
	out[n] = '\0';
	return FZN_CONTACT_CARD_OK;
}

static int b32_value(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= '2' && c <= '7')
		return 26 + (c - '2');
	return -1;
}

fzn_contact_card_err_t fzn_contact_card_from_text(const char *text, size_t text_len,
                                                  uint8_t *out, size_t cap, size_t *len)
{
	size_t i, n = 0, body_len;
	uint32_t acc = 0;
	unsigned bits = 0;

	if (!text || !out || !len)
		return FZN_CONTACT_CARD_ERR_MALFORMED;
	if (text_len < FZN_CONTACT_CARD_TEXT_PREFIX_LEN
	    || memcmp(text, FZN_CONTACT_CARD_TEXT_PREFIX, FZN_CONTACT_CARD_TEXT_PREFIX_LEN) != 0)
		return FZN_CONTACT_CARD_ERR_SHAPE;
	body_len = text_len - FZN_CONTACT_CARD_TEXT_PREFIX_LEN;
	for (i = 0; i < body_len; i++) {
		int v = b32_value(text[FZN_CONTACT_CARD_TEXT_PREFIX_LEN + i]);

		/* LOWERCASE REFUSED, as `provision/` refuses it: a QR code in
		 * alphanumeric mode carries none, and two strings must not name
		 * one card. */
		if (v < 0)
			return FZN_CONTACT_CARD_ERR_SHAPE;
		acc = (acc << 5) | (uint32_t)v;
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			if (n == cap)
				return FZN_CONTACT_CARD_ERR_SHAPE;
			out[n++] = (uint8_t)((acc >> bits) & 0xffu);
		}
	}
	/* NO SPARE CHARACTER, and the spare bits zero: either would make two
	 * strings of one card. */
	if (body_len != (n * 8u + 4u) / 5u || (bits > 0 && (acc & ((1u << bits) - 1u)) != 0u))
		return FZN_CONTACT_CARD_ERR_SHAPE;
	*len = n;
	return FZN_CONTACT_CARD_OK;
}
