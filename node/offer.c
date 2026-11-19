/* A host found by a device that knows nothing of it: the two datagrams,
 * sec 1288. */
#include "offer.h"

#include <string.h>

void fzn_offer_probe(const uint8_t nonce[FZN_OFFER_NONCE_LEN], uint8_t out[FZN_OFFER_PROBE_LEN])
{
	memset(out, 0, FZN_OFFER_PROBE_LEN);
	out[0] = FZN_OFFER_PROBE_MARK;
	out[1] = FZN_OFFER_VERSION;
	memcpy(out + 2, nonce, FZN_OFFER_NONCE_LEN);
}

int fzn_offer_probe_read(const uint8_t *in, size_t len, uint8_t nonce[FZN_OFFER_NONCE_LEN])
{
	size_t i;

	if (!in || !nonce || len != FZN_OFFER_PROBE_LEN || in[0] != FZN_OFFER_PROBE_MARK
	    || in[1] != FZN_OFFER_VERSION)
		return 0;
	/* THE PADDING IS ZERO: one spelling, and nothing hidden in it. */
	for (i = 2u + FZN_OFFER_NONCE_LEN; i < len; i++)
		if (in[i])
			return 0;
	memcpy(nonce, in + 2, FZN_OFFER_NONCE_LEN);
	return 1;
}

static int name_ok(const char *s, size_t n)
{
	size_t i;

	if (!n || n > FZN_OFFER_NAME_MAX)
		return 0;
	for (i = 0; i < n; i++)
		if ((unsigned char)s[i] < 0x20u || (unsigned char)s[i] == 0x7fu)
			return 0;
	return 1;
}

static int code_ok(const char *s, size_t n)
{
	fzn_invite_t inv;

	return n && n <= FZN_INVITE_TEXT_MAX && fzn_invite_parse(s, n, &inv);
}

size_t fzn_offer_answer(const fzn_offer_t *o, uint8_t *out, size_t cap)
{
	const size_t len = 2u + FZN_OFFER_NONCE_LEN + 1u + (o ? o->name_len : 0u) + 2u + (o ? o->code_len : 0u);

	if (!o || !out || !name_ok(o->name, o->name_len) || !code_ok(o->code, o->code_len)
	    || len > FZN_OFFER_PROBE_LEN || len > cap)
		return 0;
	out[0] = FZN_OFFER_ANSWER_MARK;
	out[1] = FZN_OFFER_VERSION;
	memcpy(out + 2, o->nonce, FZN_OFFER_NONCE_LEN);
	out[2 + FZN_OFFER_NONCE_LEN] = (uint8_t)o->name_len;
	memcpy(out + 3 + FZN_OFFER_NONCE_LEN, o->name, o->name_len);
	out[3 + FZN_OFFER_NONCE_LEN + o->name_len] = (uint8_t)(o->code_len >> 8);
	out[4 + FZN_OFFER_NONCE_LEN + o->name_len] = (uint8_t)o->code_len;
	memcpy(out + 5 + FZN_OFFER_NONCE_LEN + o->name_len, o->code, o->code_len);
	return len;
}

int fzn_offer_answer_read(const uint8_t *in, size_t len, const uint8_t nonce[FZN_OFFER_NONCE_LEN], fzn_offer_t *out)
{
	size_t at = 2u + FZN_OFFER_NONCE_LEN, name_len, code_len;

	if (!in || !nonce || !out || len < at + 3u || len > FZN_OFFER_PROBE_LEN || in[0] != FZN_OFFER_ANSWER_MARK
	    || in[1] != FZN_OFFER_VERSION || memcmp(in + 2, nonce, FZN_OFFER_NONCE_LEN) != 0)
		return 0;
	name_len = in[at++];
	if (at + name_len + 2u > len)
		return 0;
	code_len = (size_t)in[at + name_len] << 8 | in[at + name_len + 1u];
	/* EXACTLY ITS LENGTH: nothing after the code. */
	if (at + name_len + 2u + code_len != len || !name_ok((const char *)in + at, name_len)
	    || !code_ok((const char *)in + at + name_len + 2u, code_len))
		return 0;
	memset(out, 0, sizeof(*out));
	memcpy(out->nonce, nonce, FZN_OFFER_NONCE_LEN);
	memcpy(out->name, in + at, name_len);
	out->name_len = name_len;
	memcpy(out->code, in + at + name_len + 2u, code_len);
	out->code_len = code_len;
	return 1;
}
