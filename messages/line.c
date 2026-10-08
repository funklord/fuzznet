/* See line.h. */

#include "line.h"

#include "../wire/bytes.h"

#include <string.h>

_Static_assert(FZN_MESSAGE_PART_MAX * FZN_MESSAGE_PARTS_MAX >= FZN_MESSAGE_TEXT_MAX,
               "two parts hold the longest text a line takes");
_Static_assert(FZN_MESSAGE_MARK_OFF_ID + FZN_MESSAGE_ID_LEN == FZN_MESSAGE_MARK_LEN,
               "a mark is its fields and nothing past them");

/* What each part's tag covers besides its text. */
#define DOMAIN "fuzznet.message.line.v1"
#define AAD_LEN (sizeof(DOMAIN) - 1u + FZN_PUBKEY_LEN + 3u + FZN_MESSAGE_ID_LEN + 8u + 4u)

size_t fzn_message_parts_for(size_t len)
{
	if (len > FZN_MESSAGE_TEXT_MAX)
		return 0;
	return len > FZN_MESSAGE_PART_MAX ? 2u : 1u;
}

uint32_t fzn_message_epoch_of(uint64_t ms)
{
	/* Days to a civil year and month, after Howard Hinnant's
	 * civil_from_days, for days on or after 1970-01-01. */
	uint64_t z = ms / 86400000u + 719468u;
	uint64_t era = z / 146097u;
	uint64_t doe = z - era * 146097u;
	uint64_t yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
	uint64_t doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
	uint64_t mp = (5u * doy + 2u) / 153u;
	uint64_t month = mp < 10u ? mp + 3u : mp - 9u;
	uint64_t year = yoe + era * 400u + (month <= 2u ? 1u : 0u);

	return (uint32_t)((year - 1970u) * 12u + (month - 1u));
}

/* Where part `part` of a text of `len` bytes starts, and how long it is. */
static int part_span(size_t len, uint8_t part, uint8_t parts, size_t *at, size_t *n)
{
	if (parts == 0u || parts != fzn_message_parts_for(len) || part >= parts)
		return 0;
	*at = part == 0u ? 0u : FZN_MESSAGE_PART_MAX;
	*n = parts == 1u ? len : part == 0u ? FZN_MESSAGE_PART_MAX : len - FZN_MESSAGE_PART_MAX;
	return 1;
}

static void aad_of(const uint8_t contact[FZN_PUBKEY_LEN], uint8_t direction, uint8_t part,
                   uint8_t parts, const uint8_t id[FZN_MESSAGE_ID_LEN], uint64_t stime,
                   uint32_t epoch, uint8_t out[AAD_LEN])
{
	size_t at = sizeof(DOMAIN) - 1u;

	memcpy(out, DOMAIN, at);
	memcpy(out + at, contact, FZN_PUBKEY_LEN);
	at += FZN_PUBKEY_LEN;
	out[at++] = direction;
	out[at++] = part;
	out[at++] = parts;
	memcpy(out + at, id, FZN_MESSAGE_ID_LEN);
	at += FZN_MESSAGE_ID_LEN;
	fzn_put_be64(out + at, stime);
	fzn_put_be32(out + at + 8u, epoch);
}

static int direction_ok(uint8_t d)
{
	return d == FZN_MESSAGE_OUT || d == FZN_MESSAGE_IN;
}

int fzn_message_line_seal(const fzn_aead_ops_t *aead, const uint8_t key[FZN_CONVERSATION_KEY_LEN],
                          const uint8_t contact[FZN_PUBKEY_LEN], uint8_t direction,
                          const uint8_t id[FZN_MESSAGE_ID_LEN], uint64_t stime, uint32_t epoch,
                          const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *text,
                          size_t len, uint8_t part, uint8_t parts, uint8_t *body,
                          size_t *body_len)
{
	uint8_t aad[AAD_LEN];
	size_t at = 0, n = 0;

	if (!aead || !aead->seal || !key || !contact || !id || !nonce || (!text && len) || !body
	    || !body_len || !direction_ok(direction) || !part_span(len, part, parts, &at, &n))
		return 0;
	body[FZN_MESSAGE_LINE_OFF_VERSION] = FZN_MESSAGE_VERSION;
	body[FZN_MESSAGE_LINE_OFF_DIRECTION] = direction;
	body[FZN_MESSAGE_LINE_OFF_PART] = part;
	body[FZN_MESSAGE_LINE_OFF_PARTS] = parts;
	memcpy(body + FZN_MESSAGE_LINE_OFF_ID, id, FZN_MESSAGE_ID_LEN);
	fzn_put_be64(body + FZN_MESSAGE_LINE_OFF_STIME, stime);
	fzn_put_be32(body + FZN_MESSAGE_LINE_OFF_EPOCH, epoch);
	memcpy(body + FZN_MESSAGE_LINE_OFF_NONCE, nonce, FZN_AEAD_NONCE_LEN);
	if (n)
		memcpy(body + FZN_MESSAGE_LINE_HEAD, text + at, n);
	aad_of(contact, direction, part, parts, id, stime, epoch, aad);
	if (!aead->seal(aead->ctx, key, nonce, aad, sizeof(aad), body + FZN_MESSAGE_LINE_HEAD, n,
	                body + FZN_MESSAGE_LINE_OFF_TAG)) {
		/* THE PLAINTEXT WAS COPIED IN HERE, so it is wiped here. */
		memset(body, 0, FZN_MESSAGE_LINE_HEAD + n);
		return 0;
	}
	*body_len = FZN_MESSAGE_LINE_HEAD + n;
	return 1;
}

int fzn_message_line_read(const uint8_t *body, size_t len, fzn_message_part_t *out)
{
	size_t text_len;

	if (!body || !out || len < FZN_MESSAGE_LINE_HEAD || len > FZN_RECORD_BODY_MAX
	    || body[FZN_MESSAGE_LINE_OFF_VERSION] != FZN_MESSAGE_VERSION
	    || !direction_ok(body[FZN_MESSAGE_LINE_OFF_DIRECTION]))
		return 0;
	text_len = len - FZN_MESSAGE_LINE_HEAD;
	out->direction = body[FZN_MESSAGE_LINE_OFF_DIRECTION];
	out->part = body[FZN_MESSAGE_LINE_OFF_PART];
	out->parts = body[FZN_MESSAGE_LINE_OFF_PARTS];
	/* THE PARTS TILE THE TEXT ONE WAY ONLY: one part is the whole text, and
	 * of two the first is full. Anything else is two encodings of a line. */
	if (out->parts == 0u || out->parts > FZN_MESSAGE_PARTS_MAX || out->part >= out->parts
	    || (out->parts == 2u && out->part == 0u && text_len != FZN_MESSAGE_PART_MAX)
	    || (out->parts == 2u && out->part == 1u
	        && (text_len == 0u || text_len > FZN_MESSAGE_TEXT_MAX - FZN_MESSAGE_PART_MAX)))
		return 0;
	memcpy(out->id, body + FZN_MESSAGE_LINE_OFF_ID, FZN_MESSAGE_ID_LEN);
	out->stime = fzn_get_be64(body + FZN_MESSAGE_LINE_OFF_STIME);
	out->epoch = fzn_get_be32(body + FZN_MESSAGE_LINE_OFF_EPOCH);
	memcpy(out->nonce, body + FZN_MESSAGE_LINE_OFF_NONCE, FZN_AEAD_NONCE_LEN);
	memcpy(out->tag, body + FZN_MESSAGE_LINE_OFF_TAG, FZN_AEAD_TAG_LEN);
	out->text = body + FZN_MESSAGE_LINE_HEAD;
	out->text_len = text_len;
	return 1;
}

int fzn_message_line_open(const fzn_aead_ops_t *aead, const uint8_t key[FZN_CONVERSATION_KEY_LEN],
                          const uint8_t contact[FZN_PUBKEY_LEN], const fzn_message_part_t *p,
                          uint8_t *out, size_t cap, size_t *out_len)
{
	uint8_t aad[AAD_LEN];

	if (!aead || !aead->open || !key || !contact || !p || !out || !out_len
	    || p->text_len > cap)
		return 0;
	memcpy(out, p->text, p->text_len);
	aad_of(contact, p->direction, p->part, p->parts, p->id, p->stime, p->epoch, aad);
	if (!aead->open(aead->ctx, key, p->nonce, aad, sizeof(aad), out, p->text_len, p->tag)) {
		memset(out, 0, p->text_len);
		return 0;
	}
	*out_len = p->text_len;
	return 1;
}

int fzn_message_mark_write(const fzn_message_mark_t *m, uint8_t out[FZN_MESSAGE_MARK_LEN])
{
	if (!m || !out || !direction_ok(m->direction) || m->state < FZN_MESSAGE_DELIVERED
	    || m->state > FZN_MESSAGE_NOT_DELIVERED)
		return 0;
	out[FZN_MESSAGE_MARK_OFF_VERSION] = FZN_MESSAGE_VERSION;
	out[FZN_MESSAGE_MARK_OFF_DIRECTION] = m->direction;
	out[FZN_MESSAGE_MARK_OFF_STATE] = m->state;
	memcpy(out + FZN_MESSAGE_MARK_OFF_ID, m->id, FZN_MESSAGE_ID_LEN);
	return 1;
}

int fzn_message_mark_read(const uint8_t *body, size_t len, fzn_message_mark_t *out)
{
	if (!body || !out || len != FZN_MESSAGE_MARK_LEN
	    || body[FZN_MESSAGE_MARK_OFF_VERSION] != FZN_MESSAGE_VERSION
	    || !direction_ok(body[FZN_MESSAGE_MARK_OFF_DIRECTION])
	    || body[FZN_MESSAGE_MARK_OFF_STATE] < FZN_MESSAGE_DELIVERED
	    || body[FZN_MESSAGE_MARK_OFF_STATE] > FZN_MESSAGE_NOT_DELIVERED)
		return 0;
	out->direction = body[FZN_MESSAGE_MARK_OFF_DIRECTION];
	out->state = body[FZN_MESSAGE_MARK_OFF_STATE];
	memcpy(out->id, body + FZN_MESSAGE_MARK_OFF_ID, FZN_MESSAGE_ID_LEN);
	return 1;
}
