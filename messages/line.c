/* See line.h. */

#include "line.h"
#include "../wire/generated/line_record.h"
#include "../wire/generated/line_record_build.h"

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

uint64_t fzn_message_epoch_start(uint32_t epoch)
{
	/* A civil date to days, after Howard Hinnant's days_from_civil, for
	 * the first of the month. */
	uint64_t year = 1970u + epoch / 12u, month = 1u + epoch % 12u;
	uint64_t y = month <= 2u ? year - 1u : year;
	uint64_t era = y / 400u;
	uint64_t yoe = y - era * 400u;
	uint64_t mp = month > 2u ? month - 3u : month + 9u;
	uint64_t doy = (153u * mp + 2u) / 5u;
	uint64_t doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;

	return (era * 146097u + doe - 719468u) * 86400000u;
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
	static const uint8_t no_tag[FZN_AEAD_TAG_LEN];
	uint8_t aad[AAD_LEN];
	size_t at = 0, n = 0;
	uint32_t wrote = 0;

	if (!aead || !aead->seal || !key || !contact || !id || !nonce || (!text && len) || !body
	    || !body_len || !direction_ok(direction) || !part_span(len, part, parts, &at, &n))
		return 0;
	/* BUILT BY THE CODE situ GENERATES from `messages/line_record.situ`
	 * (sec 1380), the plaintext in its place and the tag zero, then both
	 * sealed in place. */
	if (fzn_line_record_fzn_message_line_build(body, (uint32_t)(FZN_MESSAGE_LINE_HEAD + n), FZN_MESSAGE_VERSION,
	                                           (fzn_line_record_fzn_message_direction_t)direction, part, parts, id,
	                                           stime, epoch, nonce, no_tag, n ? text + at : NULL, (uint32_t)n,
	                                           &wrote)
	            != SITU_OK
	    || wrote != FZN_MESSAGE_LINE_HEAD + n) {
		memset(body, 0, FZN_MESSAGE_LINE_HEAD + n);
		return 0;
	}
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
	situ_msg_t m;
	situ_view_t v;
	size_t text_len;

	if (!body || !out || len < FZN_MESSAGE_LINE_HEAD || len > FZN_RECORD_BODY_MAX)
		return 0;
	/* READ AS THE SCHEMA SAYS, sec 1380: version, direction, part at most
	 * 1 and parts 1 or 2 the generated validate's; how the parts tile the
	 * text the codec's, below. */
	situ_msg_init(&m, (uint8_t *)(uintptr_t)body, (uint32_t)len);
	if (fzn_line_record_fzn_message_line_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_line_record_fzn_message_line_validate(v) != SITU_OK)
		return 0;
	text_len = len - FZN_MESSAGE_LINE_HEAD;
	out->direction = (uint8_t)fzn_line_record_fzn_message_line_direction_get(v);
	out->part = fzn_line_record_fzn_message_line_part_get(v);
	out->parts = fzn_line_record_fzn_message_line_parts_get(v);
	/* THE PARTS TILE THE TEXT ONE WAY ONLY: one part is the whole text, and
	 * of two the first is full. Anything else is two encodings of a line. */
	if (out->parts == 0u || out->parts > FZN_MESSAGE_PARTS_MAX || out->part >= out->parts
	    || (out->parts == 2u && out->part == 0u && text_len != FZN_MESSAGE_PART_MAX)
	    || (out->parts == 2u && out->part == 1u
	        && (text_len == 0u || text_len > FZN_MESSAGE_TEXT_MAX - FZN_MESSAGE_PART_MAX)))
		return 0;
	memcpy(out->id, fzn_line_record_fzn_message_line_id_ptr(v), FZN_MESSAGE_ID_LEN);
	out->stime = fzn_line_record_fzn_message_line_stime_get(v);
	out->epoch = fzn_line_record_fzn_message_line_epoch_get(v);
	memcpy(out->nonce, fzn_line_record_fzn_message_line_nonce_ptr(v), FZN_AEAD_NONCE_LEN);
	memcpy(out->tag, fzn_line_record_fzn_message_line_tag_ptr(v), FZN_AEAD_TAG_LEN);
	out->text = fzn_line_record_fzn_message_line_text_ptr(v);
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

/* A FIXED RECORD READ AS THE SCHEMA SAYS, sec 1380: exactly its length,
 * then the generated view and validate. */
#define READ_FIXED(kind, body, len, want, v)                                                          \
	do {                                                                                          \
		situ_msg_t m_;                                                                        \
                                                                                                      \
		if (!(body) || (len) != (want))                                                       \
			return 0;                                                                     \
		situ_msg_init(&m_, (uint8_t *)(uintptr_t)(body), (uint32_t)(len));                    \
		if (fzn_line_record_fzn_message_##kind##_view(&m_, 0u, &(v)) != SITU_OK               \
		    || fzn_line_record_fzn_message_##kind##_validate(v) != SITU_OK)                   \
			return 0;                                                                     \
	} while (0)

int fzn_message_mark_write(const fzn_message_mark_t *m, uint8_t out[FZN_MESSAGE_MARK_LEN])
{
	uint32_t wrote = 0;

	/* BUILT BY THE GENERATED CODE, sec 1380, which refuses a direction or
	 * a state outside its enum. */
	return m && out
	       && fzn_line_record_fzn_message_mark_build(out, FZN_MESSAGE_MARK_LEN, FZN_MESSAGE_VERSION,
	                                                 (fzn_line_record_fzn_message_direction_t)m->direction,
	                                                 (fzn_line_record_fzn_message_state_t)m->state, m->id, &wrote)
	                  == SITU_OK;
}

int fzn_message_position_write(const uint8_t id[FZN_MESSAGE_ID_LEN],
                               uint8_t out[FZN_MESSAGE_READ_LEN])
{
	uint32_t wrote = 0;

	return id && out
	       && fzn_line_record_fzn_message_read_build(out, FZN_MESSAGE_READ_LEN, FZN_MESSAGE_VERSION, id, &wrote)
	                  == SITU_OK;
}

int fzn_message_position_read(const uint8_t *body, size_t len, uint8_t id[FZN_MESSAGE_ID_LEN])
{
	situ_view_t v;

	if (!id)
		return 0;
	READ_FIXED(read, body, len, FZN_MESSAGE_READ_LEN, v);
	memcpy(id, fzn_line_record_fzn_message_read_id_ptr(v), FZN_MESSAGE_ID_LEN);
	return 1;
}

int fzn_message_seen_write(const uint8_t id[FZN_MESSAGE_ID_LEN], uint64_t stime, uint8_t out[FZN_MESSAGE_SEEN_LEN])
{
	uint32_t wrote = 0;

	return id && out
	       && fzn_line_record_fzn_message_seen_build(out, FZN_MESSAGE_SEEN_LEN, FZN_MESSAGE_VERSION, id, stime, &wrote)
	                  == SITU_OK;
}

int fzn_message_seen_read(const uint8_t *body, size_t len, uint8_t id[FZN_MESSAGE_ID_LEN], uint64_t *stime)
{
	situ_view_t v;

	if (!id || !stime)
		return 0;
	READ_FIXED(seen, body, len, FZN_MESSAGE_SEEN_LEN, v);
	memcpy(id, fzn_line_record_fzn_message_seen_id_ptr(v), FZN_MESSAGE_ID_LEN);
	*stime = fzn_line_record_fzn_message_seen_stime_get(v);
	return 1;
}

int fzn_message_member_seen_write(const uint8_t member[32], uint64_t stime, uint8_t out[FZN_MESSAGE_MEMBER_SEEN_LEN])
{
	uint32_t wrote = 0;

	return member && out
	       && fzn_line_record_fzn_message_member_seen_build(out, FZN_MESSAGE_MEMBER_SEEN_LEN, FZN_MESSAGE_VERSION,
	                                                        member, stime, &wrote)
	                  == SITU_OK;
}

int fzn_message_member_seen_read(const uint8_t *body, size_t len, uint8_t member[32], uint64_t *stime)
{
	situ_view_t v;

	if (!member || !stime)
		return 0;
	READ_FIXED(member_seen, body, len, FZN_MESSAGE_MEMBER_SEEN_LEN, v);
	memcpy(member, fzn_line_record_fzn_message_member_seen_member_ptr(v), 32u);
	*stime = fzn_line_record_fzn_message_member_seen_stime_get(v);
	return 1;
}

int fzn_message_call_write(const fzn_message_call_t *c, uint8_t out[FZN_MESSAGE_CALL_LEN])
{
	uint32_t wrote = 0;

	/* BUILT BY THE GENERATED CODE, sec 1380, which refuses a direction or
	 * an outcome outside its enum and kinds outside 1 to 3. */
	return c && out
	       && fzn_line_record_fzn_message_call_build(
	                  out, FZN_MESSAGE_CALL_LEN, FZN_MESSAGE_VERSION,
	                  (fzn_line_record_fzn_message_direction_t)c->direction, c->kinds,
	                  (fzn_line_record_fzn_message_call_outcome_kind_t)c->outcome, c->id, c->started, c->seconds, &wrote)
	                  == SITU_OK;
}

int fzn_message_call_read(const uint8_t *body, size_t len, fzn_message_call_t *out)
{
	situ_view_t v;

	if (!out)
		return 0;
	READ_FIXED(call, body, len, FZN_MESSAGE_CALL_LEN, v);
	out->direction = (uint8_t)fzn_line_record_fzn_message_call_direction_get(v);
	out->kinds = fzn_line_record_fzn_message_call_kinds_get(v);
	out->outcome = (uint8_t)fzn_line_record_fzn_message_call_outcome_get(v);
	memcpy(out->id, fzn_line_record_fzn_message_call_id_ptr(v), FZN_MESSAGE_CALL_ID_LEN);
	out->started = fzn_line_record_fzn_message_call_started_get(v);
	out->seconds = fzn_line_record_fzn_message_call_seconds_get(v);
	return 1;
}

int fzn_message_mark_read(const uint8_t *body, size_t len, fzn_message_mark_t *out)
{
	situ_view_t v;

	if (!out)
		return 0;
	READ_FIXED(mark, body, len, FZN_MESSAGE_MARK_LEN, v);
	out->direction = (uint8_t)fzn_line_record_fzn_message_mark_direction_get(v);
	out->state = (uint8_t)fzn_line_record_fzn_message_mark_state_get(v);
	memcpy(out->id, fzn_line_record_fzn_message_mark_id_ptr(v), FZN_MESSAGE_ID_LEN);
	return 1;
}
