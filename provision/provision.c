/* See provision.h. */

#include "provision.h"

#include "../wire/bytes.h"

#include <string.h>

/* THE LAYOUT IS PINNED HERE, not merely computed in the header. The offsets
 * are a chain of additions, so a change to any one length moves every field
 * after it silently and the card still compiles -- and a card whose fields
 * moved is a card that verifies against nothing, which surfaces as a signature
 * failure a long way from its cause. Following `prekey.c`, which pins its own
 * for the same reason. Pinned at one hop, the card a root issues. */
_Static_assert(FZN_PROVISION_OFF_ROOT == 2u, "provision layout: root moved");
_Static_assert(FZN_PROVISION_OFF_HOP_COUNT == 34u, "provision layout: hop_count moved");
_Static_assert(FZN_PROVISION_OFF_CHAIN == 35u, "provision layout: the chain moved");
_Static_assert(FZN_PROVISION_OFF_PREKEY(1) == 214u, "provision layout: prekey moved");
_Static_assert(FZN_PROVISION_OFF_EXPIRES_AT(1) == 352u, "provision layout: expires_at moved");
_Static_assert(FZN_PROVISION_OFF_SIGNATURE(1) == 360u, "provision layout: signature moved");
_Static_assert(FZN_PROVISION_MIN_LEN == 424u, "provision layout: the one-hop card changed size");
_Static_assert(FZN_PROVISION_MAX_LEN == 1677u, "provision layout: the longest card changed size");

fzn_provision_err_t fzn_provision_pack(const uint8_t root[FZN_PUBKEY_LEN],
                                       const uint8_t (*chain)[FZN_HOP_LEN], size_t hop_count,
                                       const uint8_t prekey[FZN_PREKEY_LEN_TOTAL],
                                       uint64_t expires_at, const fzn_sign_ops_t *sign,
                                       uint8_t *out, size_t out_cap, size_t *out_len)
{
	size_t i;

	if (!root || !chain || !prekey || !out || !out_len)
		return FZN_PROVISION_ERR_MALFORMED;
	if (hop_count == 0u || hop_count > FZN_CHAIN_MAX_HOPS)
		return FZN_PROVISION_ERR_SHAPE;
	if (out_cap < FZN_PROVISION_LEN(hop_count))
		return FZN_PROVISION_ERR_MALFORMED;
	if (!sign || !sign->sign)
		return FZN_PROVISION_ERR_SIGNER;

	out[FZN_PROVISION_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	out[FZN_PROVISION_OFF_OBJECT] = (uint8_t)FZN_OBJECT_CARD;
	memcpy(out + FZN_PROVISION_OFF_ROOT, root, FZN_PUBKEY_LEN);
	out[FZN_PROVISION_OFF_HOP_COUNT] = (uint8_t)hop_count;
	for (i = 0; i < hop_count; i++)
		memcpy(out + FZN_PROVISION_OFF_CHAIN + i * FZN_HOP_LEN, chain[i], FZN_HOP_LEN);
	memcpy(out + FZN_PROVISION_OFF_PREKEY(hop_count), prekey, FZN_PREKEY_LEN_TOTAL);
	fzn_put_be64(out + FZN_PROVISION_OFF_EXPIRES_AT(hop_count), expires_at);

	/* NONZERO IS SUCCESS, which is `chain.h`'s convention for this seam and
	 * not C's usual one for an int return. Written the other way round
	 * first, and it would have inverted every signature in the file. */
	if (!sign->sign(sign->ctx, out + FZN_PROVISION_OFF_SIGNATURE(hop_count), out,
	                FZN_PROVISION_BODY_LEN(hop_count)))
		return FZN_PROVISION_ERR_SIGNER;

	*out_len = FZN_PROVISION_LEN(hop_count);
	return FZN_PROVISION_OK;
}

fzn_provision_err_t fzn_provision_open(const uint8_t *bytes, size_t len,
                                       fzn_provision_card_t *out)
{
	size_t n;

	if (!bytes || !out)
		return FZN_PROVISION_ERR_MALFORMED;

	memset(out, 0, sizeof(*out));

	if (len < FZN_PROVISION_MIN_LEN)
		return FZN_PROVISION_ERR_SHAPE;
	if (bytes[FZN_PROVISION_OFF_VERSION] != (uint8_t)FZN_SIGNED_VERSION)
		return FZN_PROVISION_ERR_SHAPE;
	if (bytes[FZN_PROVISION_OFF_OBJECT] != (uint8_t)FZN_OBJECT_CARD)
		return FZN_PROVISION_ERR_SHAPE;
	n = bytes[FZN_PROVISION_OFF_HOP_COUNT];
	/* EXACTLY, not at least. The hop count fixes the length, so a longer
	 * buffer is not a card with something after it -- it is a caller who has
	 * lost track of what they hold, and the trailing bytes would be outside
	 * everything the signature covers. */
	if (n == 0u || n > FZN_CHAIN_MAX_HOPS || len != FZN_PROVISION_LEN(n))
		return FZN_PROVISION_ERR_SHAPE;

	out->base = bytes;
	out->len = len;
	out->root = bytes + FZN_PROVISION_OFF_ROOT;
	out->hop_count = n;
	out->chain = bytes + FZN_PROVISION_OFF_CHAIN;
	out->hop = out->chain + (n - 1u) * FZN_HOP_LEN;
	out->prekey = bytes + FZN_PROVISION_OFF_PREKEY(n);
	out->expires_at = fzn_get_be64(bytes + FZN_PROVISION_OFF_EXPIRES_AT(n));

	return FZN_PROVISION_OK;
}

fzn_provision_err_t fzn_provision_verify(fzn_provision_card_t card,
                                         const fzn_sign_ops_t *verifier, uint64_t now)
{
	fzn_chain_hop_t hop, next;
	fzn_prekey_record_t prekey;
	const uint8_t *sponsor;
	size_t i;

	if (!card.base || !card.root || !card.chain || !card.prekey || card.hop_count == 0u
	    || card.hop_count > FZN_CHAIN_MAX_HOPS)
		return FZN_PROVISION_ERR_MALFORMED;
	if (!verifier || !verifier->verify)
		return FZN_PROVISION_ERR_SIGNER;

	/* ONE SPONSOR, AND AN UNBROKEN CHAIN FROM THE ROOT. Structure first,
	 * because the signature is checked under a key read out of the card: the
	 * sponsor is whoever granted the last hop, and it must also be the
	 * prekey's host, or the envelope would be verified under a key the
	 * session is not established with. */
	if (fzn_hop_open(card.chain, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK
	    || memcmp(fzn_hop_grantor(hop), card.root, FZN_PUBKEY_LEN) != 0)
		return FZN_PROVISION_ERR_SIGNATURE;
	for (i = 1; i < card.hop_count; i++) {
		if (fzn_hop_open(card.chain + i * FZN_HOP_LEN, FZN_HOP_LEN, &next) != FZN_CHAIN_OK
		    || memcmp(fzn_hop_grantee(hop), fzn_hop_grantor(next), FZN_PUBKEY_LEN) != 0)
			return FZN_PROVISION_ERR_SIGNATURE;
		hop = next;
	}
	sponsor = fzn_hop_grantor(hop);
	if (fzn_prekey_open(card.prekey, FZN_PREKEY_LEN_TOTAL, &prekey) != FZN_PREKEY_OK
	    || memcmp(prekey.host, sponsor, FZN_PUBKEY_LEN) != 0)
		return FZN_PROVISION_ERR_SIGNATURE;

	/* THE SIGNATURE BEFORE THE EXPIRY, and the order is the point.
	 * `expires_at` is inside the signed body, so checking it first would be
	 * acting on a number an attacker can choose. Nothing in an unverified
	 * card is a fact yet. */
	if (!verifier->verify(verifier->ctx, sponsor, card.base,
	                      FZN_PROVISION_BODY_LEN(card.hop_count),
	                      card.base + FZN_PROVISION_OFF_SIGNATURE(card.hop_count)))
		return FZN_PROVISION_ERR_SIGNATURE;

	if (now != 0u && card.expires_at != 0u && card.expires_at < now)
		return FZN_PROVISION_ERR_EXPIRED;

	return FZN_PROVISION_OK;
}

/* RFC 4648 base32, uppercase. */
static const char b32[32] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fzn_provision_err_t fzn_provision_text(const uint8_t *bytes, size_t len, char *out,
                                       size_t out_cap)
{
	size_t i;
	size_t n = 0;
	uint32_t acc = 0;
	unsigned bits = 0;

	if (!bytes || !out)
		return FZN_PROVISION_ERR_MALFORMED;
	if (len < FZN_PROVISION_MIN_LEN || len > FZN_PROVISION_MAX_LEN)
		return FZN_PROVISION_ERR_SHAPE;
	if (out_cap < FZN_PROVISION_TEXT_PREFIX_LEN + FZN_PROVISION_TEXT_BODY_LEN(len) + 1u)
		return FZN_PROVISION_ERR_MALFORMED;

	memcpy(out, FZN_PROVISION_TEXT_PREFIX, FZN_PROVISION_TEXT_PREFIX_LEN);
	n = FZN_PROVISION_TEXT_PREFIX_LEN;

	for (i = 0; i < len; i++) {
		acc = (acc << 8) | bytes[i];
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			out[n++] = b32[(acc >> bits) & 0x1fu];
		}
	}

	/* THE TAIL IS PADDED WITH ZERO BITS, not dropped. A one-hop card is 424
	 * bytes, 3392 bits: 678 whole groups of five with TWO bits over, so the
	 * last character carries those two and three zeros -- 679 characters in
	 * all. The decoder checks the spare bits are zero rather than ignoring
	 * them (see `fzn_provision_from_text`), because otherwise TWO strings
	 * decode to the same card and "the code I scanned" stops naming one
	 * thing. */
	if (bits > 0)
		out[n++] = b32[(acc << (5u - bits)) & 0x1fu];

	out[n] = '\0';
	return FZN_PROVISION_OK;
}

/* The alphabet's inverse, or -1. A table rather than a search so the lookup
 * does not depend on where in the alphabet a character sits. */
static int b32_value(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= '2' && c <= '7')
		return 26 + (c - '2');
	return -1;
}

fzn_provision_err_t fzn_provision_from_text(const char *text, uint8_t *out, size_t out_cap,
                                            size_t *out_len)
{
	size_t i, body_len;
	size_t n = 0;
	uint32_t acc = 0;
	unsigned bits = 0;

	if (!text || !out || !out_len)
		return FZN_PROVISION_ERR_MALFORMED;

	if (strncmp(text, FZN_PROVISION_TEXT_PREFIX, FZN_PROVISION_TEXT_PREFIX_LEN) != 0)
		return FZN_PROVISION_ERR_SHAPE;

	/* THE LENGTH IS CHECKED BEFORE THE ALPHABET, so a string of no card's
	 * length is SHAPE rather than being decoded into a short buffer and
	 * refused later for a reason that does not name what is wrong with it.
	 * A card's length is one of eight; its text is one length for each. */
	body_len = strlen(text) - FZN_PROVISION_TEXT_PREFIX_LEN;
	for (i = 1; i <= FZN_CHAIN_MAX_HOPS; i++)
		if (body_len == FZN_PROVISION_TEXT_BODY_LEN(FZN_PROVISION_LEN(i)))
			break;
	if (i > FZN_CHAIN_MAX_HOPS)
		return FZN_PROVISION_ERR_SHAPE;
	if (out_cap < FZN_PROVISION_LEN(i))
		return FZN_PROVISION_ERR_MALFORMED;

	for (i = 0; i < body_len; i++) {
		int v = b32_value(text[FZN_PROVISION_TEXT_PREFIX_LEN + i]);

		/* LOWERCASE IS REFUSED RATHER THAN FOLDED. QR alphanumeric mode
		 * has no lowercase in it, so a lowercase card did not come out
		 * of a code this library wrote, and accepting it would mean two
		 * strings for one card. */
		if (v < 0)
			return FZN_PROVISION_ERR_SHAPE;

		acc = (acc << 5) | (uint32_t)v;
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			out[n++] = (uint8_t)((acc >> bits) & 0xffu);
		}
	}

	/* The spare bits of the last character must be zero. See
	 * `fzn_provision_text`: without this, two strings decode to one card. */
	if (bits > 0 && (acc & ((1u << bits) - 1u)) != 0u)
		return FZN_PROVISION_ERR_SHAPE;

	*out_len = n;
	return FZN_PROVISION_OK;
}

const char *fzn_provision_err_str(fzn_provision_err_t err)
{
	switch (err) {
	case FZN_PROVISION_OK:
		return "ok";
	case FZN_PROVISION_ERR_MALFORMED:
		return "malformed argument";
	case FZN_PROVISION_ERR_SHAPE:
		return "not a provisioning card";
	case FZN_PROVISION_ERR_SIGNATURE:
		return "the card's parts do not name one sponsor reaching the root";
	case FZN_PROVISION_ERR_SIGNER:
		return "no signer";
	case FZN_PROVISION_ERR_EXPIRED:
		return "the card has expired";
	}

	return "unknown";
}
