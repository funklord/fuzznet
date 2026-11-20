/* A contact card: project.md sec 617, and the header. */
#include "contact_card.h"

#include "../wire/generated/contact_card_record.h"
#include "../wire/generated/contact_card_record_build.h"

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

/* THE CARD, built by the code situ generates from
 * `node/contact_card_record.situ` (sec 1334) with `sig` as its signature:
 * its whole length, or 0 when it will not fit or the host entry will not
 * encode. The signature covers every byte before it. */
static size_t build(const fzn_contact_card_t *card, const uint8_t sig[FZN_SIG_LEN], uint8_t *out, size_t cap)
{
	static uint8_t host[FZN_CONTACT_DEVICE_MAX];
	uint8_t seeds[FZN_CONTACT_CARD_SEEDS_MAX * (1u + FZN_CONTACT_DEVICE_ADDRESS_MAX + 4u)];
	size_t host_len = 0, i;
	uint32_t at = 0, wrote = 0;

	if (cap > UINT32_MAX
	    || fzn_contact_device_encode(&card->host, host, sizeof(host), &host_len) != FZN_CONTACT_DEVICE_OK
	    || host_len > 0xffffu)
		return 0;
	for (i = 0; i < card->n_seeds; i++) {
		const fzn_contact_card_seed_t *sd = &card->seeds[i];
		uint32_t one = 0;

		if (fzn_contact_card_record_fzn_contact_card_seed_build(seeds + at, (uint32_t)(sizeof(seeds) - at),
		                                                        (const uint8_t *)sd->address,
		                                                        (uint32_t)sd->address_len, sd->port,
		                                                        sd->transport, sd->metric, &one)
		    != SITU_OK)
			return 0;
		at += one;
	}
	if (fzn_contact_card_record_fzn_contact_card_build(out, (uint32_t)cap, FZN_CONTACT_CARD_VERSION,
	                                                   (uint8_t)FZN_OBJECT_CONTACT_CARD, host, (uint32_t)host_len,
	                                                   seeds, at, (const uint8_t *)card->name,
	                                                   (uint32_t)card->name_len, card->expires_at, sig, &wrote)
	    != SITU_OK)
		return 0;
	return wrote;
}

fzn_contact_card_err_t fzn_contact_card_sign(fzn_contact_card_t *card, const fzn_sign_ops_t *sign)
{
	static uint8_t bytes[FZN_CONTACT_CARD_MAX];
	static const uint8_t unsigned_yet[FZN_SIG_LEN];
	size_t n;

	if (!card || !sign || !sign->sign || !fields_ok(card))
		return FZN_CONTACT_CARD_ERR_MALFORMED;
	n = build(card, unsigned_yet, bytes, sizeof(bytes));
	if (!n || !sign->sign(sign->ctx, card->sig, bytes, n - FZN_SIG_LEN))
		return FZN_CONTACT_CARD_ERR_MALFORMED;
	return FZN_CONTACT_CARD_OK;
}

fzn_contact_card_err_t fzn_contact_card_encode(const fzn_contact_card_t *card, uint8_t *out,
                                               size_t cap, size_t *len)
{
	size_t n;

	if (!card || !out || !len || !fields_ok(card))
		return FZN_CONTACT_CARD_ERR_MALFORMED;
	n = build(card, card->sig, out, cap);
	if (!n)
		return FZN_CONTACT_CARD_ERR_MALFORMED;
	*len = n;
	return FZN_CONTACT_CARD_OK;
}

fzn_contact_card_err_t fzn_contact_card_decode(const uint8_t *bytes, size_t len,
                                               fzn_contact_card_t *out)
{
	situ_msg_t m;
	situ_view_t v;
	uint32_t need = 0;
	size_t i;

	if (!bytes || !out)
		return FZN_CONTACT_CARD_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	/* READ AS THE SCHEMA SAYS, EXACTLY ITS LENGTH (sec 1334): its version,
	 * tag, host entry, seeds' addresses and bounds the generated validate's;
	 * then its fields in range -- one card, one encoding. */
	if (len > UINT32_MAX
	    || fzn_contact_card_record_fzn_contact_card_required(bytes, (uint32_t)len, &need) != SITU_OK || need != len)
		return FZN_CONTACT_CARD_ERR_SHAPE;
	situ_msg_init(&m, (uint8_t *)(uintptr_t)bytes, (uint32_t)len);
	if (fzn_contact_card_record_fzn_contact_card_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_contact_card_record_fzn_contact_card_validate(v) != SITU_OK
	    || fzn_contact_device_decode(fzn_contact_card_record_fzn_contact_card_host_ptr(v),
	                                 fzn_contact_card_record_fzn_contact_card_host_len_get(v), &out->host)
	               != FZN_CONTACT_DEVICE_OK)
		return FZN_CONTACT_CARD_ERR_SHAPE;
	out->n_seeds = fzn_contact_card_record_fzn_contact_card_seed_count_get(v);
	if (out->n_seeds > FZN_CONTACT_CARD_SEEDS_MAX)
		return FZN_CONTACT_CARD_ERR_SHAPE;
	for (i = 0; i < out->n_seeds; i++) {
		fzn_contact_card_seed_t *sd = &out->seeds[i];
		situ_view_t one;

		if (fzn_contact_card_record_fzn_contact_card_seeds_at(v, (uint32_t)i, &one) != SITU_OK)
			return FZN_CONTACT_CARD_ERR_SHAPE;
		sd->address_len = fzn_contact_card_record_fzn_contact_card_seed_address_len_get(one);
		if (sd->address_len > FZN_CONTACT_DEVICE_ADDRESS_MAX)
			return FZN_CONTACT_CARD_ERR_SHAPE;
		memcpy(sd->address, fzn_contact_card_record_fzn_contact_card_seed_address_ptr(one), sd->address_len);
		sd->address[sd->address_len] = '\0';
		sd->port = fzn_contact_card_record_fzn_contact_card_seed_port_get(one);
		sd->transport = fzn_contact_card_record_fzn_contact_card_seed_transport_get(one);
		sd->metric = fzn_contact_card_record_fzn_contact_card_seed_metric_get(one);
	}
	out->name_len = fzn_contact_card_record_fzn_contact_card_name_len_get(v);
	memcpy(out->name, fzn_contact_card_record_fzn_contact_card_name_ptr(v), out->name_len);
	out->name[out->name_len] = '\0';
	out->expires_at = fzn_contact_card_record_fzn_contact_card_expires_at_get(v);
	memcpy(out->sig, fzn_contact_card_record_fzn_contact_card_sig_ptr(v), FZN_SIG_LEN);
	if (!fields_ok(out))
		return FZN_CONTACT_CARD_ERR_SHAPE;
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
	n = build(card, card->sig, bytes, sizeof(bytes));
	if (!n
	    || !sign->verify(sign->ctx, fzn_contact_device_key(&card->host), bytes, n - FZN_SIG_LEN, card->sig))
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
