/* A line about another line: a reply and a reaction, sec 1282, and an unsend, sec 1284. */
#include "reply.h"

#include <string.h>

#include "../hex/hex.h"

static int lower_hex(unsigned char c, unsigned *v)
{
	if (c >= '0' && c <= '9')
		*v = c - '0';
	else if (c >= 'a' && c <= 'f')
		*v = c - 'a' + 10u;
	else
		return 0;
	return 1;
}

/* THE SCHEME AND THE ID after it, `scheme_len` bytes of scheme: 1 with the
 * id, or 0. */
static int head(const char *text, size_t len, const char *scheme, size_t scheme_len,
                uint8_t id[FZN_MESSAGE_ID_LEN])
{
	size_t i;

	if (!text || len < scheme_len + 2u * FZN_MESSAGE_ID_LEN || memcmp(text, scheme, scheme_len) != 0)
		return 0;
	for (i = 0; i < FZN_MESSAGE_ID_LEN; i++) {
		unsigned hi, lo;

		if (!lower_hex((unsigned char)text[scheme_len + 2u * i], &hi)
		    || !lower_hex((unsigned char)text[scheme_len + 2u * i + 1u], &lo))
			return 0;
		id[i] = (uint8_t)(hi << 4 | lo);
	}
	return 1;
}

static size_t put_head(const char *scheme, size_t scheme_len, const uint8_t id[FZN_MESSAGE_ID_LEN],
                       char *out)
{
	size_t i;

	memcpy(out, scheme, scheme_len);
	for (i = 0; i < FZN_MESSAGE_ID_LEN; i++)
		fzn_hex_byte(id[i], out + scheme_len + 2u * i);
	return scheme_len + 2u * FZN_MESSAGE_ID_LEN;
}

size_t fzn_message_reply_write(const uint8_t id[FZN_MESSAGE_ID_LEN], const char *text, size_t text_len,
                               char *out, size_t cap)
{
	size_t at;

	if (!id || !text || !text_len || !out || cap <= FZN_MESSAGE_REPLY_HEAD_LEN
	    || text_len >= cap - FZN_MESSAGE_REPLY_HEAD_LEN)
		return 0;
	at = put_head(FZN_MESSAGE_REPLY_SCHEME, sizeof(FZN_MESSAGE_REPLY_SCHEME) - 1u, id, out);
	out[at++] = ' ';
	memcpy(out + at, text, text_len);
	at += text_len;
	out[at] = '\0';
	return at;
}

int fzn_message_reply_parse(const char *text, size_t len, uint8_t id[FZN_MESSAGE_ID_LEN], size_t *at)
{
	uint8_t got[FZN_MESSAGE_ID_LEN];

	if (!id || !at || !head(text, len, FZN_MESSAGE_REPLY_SCHEME, sizeof(FZN_MESSAGE_REPLY_SCHEME) - 1u, got)
	    || len <= FZN_MESSAGE_REPLY_HEAD_LEN || text[FZN_MESSAGE_REPLY_HEAD_LEN - 1u] != ' ')
		return 0;
	memcpy(id, got, sizeof(got));
	*at = FZN_MESSAGE_REPLY_HEAD_LEN;
	return 1;
}

const char *fzn_message_own_text(const char *text, size_t len, size_t *own_len)
{
	uint8_t answered[FZN_MESSAGE_ID_LEN];
	size_t at = 0;

	if (!own_len)
		return text;
	if (text && fzn_message_reply_parse(text, len, answered, &at) && at <= len) {
		*own_len = len - at;
		return text + at;
	}
	*own_len = len;
	return text;
}

/* A REACTION'S BYTES: 1 to FZN_MESSAGE_REACTION_MAX, no space, no control, no DEL. */
static int reaction_ok(const char *r, size_t n)
{
	size_t i;

	if (!n || n > FZN_MESSAGE_REACTION_MAX)
		return 0;
	for (i = 0; i < n; i++)
		if ((unsigned char)r[i] <= 0x20u || (unsigned char)r[i] == 0x7fu)
			return 0;
	return 1;
}

size_t fzn_message_reaction_write(const uint8_t id[FZN_MESSAGE_ID_LEN], const char *reaction,
                                  size_t reaction_len, char *out, size_t cap)
{
	const size_t scheme_len = sizeof(FZN_MESSAGE_REACTION_SCHEME) - 1u;
	size_t at, need = scheme_len + 2u * FZN_MESSAGE_ID_LEN + (reaction_len ? 1u + reaction_len : 0u);

	if (!id || !out || (reaction_len && (!reaction || !reaction_ok(reaction, reaction_len)))
	    || need >= cap)
		return 0;
	at = put_head(FZN_MESSAGE_REACTION_SCHEME, scheme_len, id, out);
	if (reaction_len) {
		out[at++] = ' ';
		memcpy(out + at, reaction, reaction_len);
		at += reaction_len;
	}
	out[at] = '\0';
	return at;
}

int fzn_message_reaction_parse(const char *text, size_t len, uint8_t id[FZN_MESSAGE_ID_LEN], size_t *at,
                               size_t *reaction_len)
{
	const size_t scheme_len = sizeof(FZN_MESSAGE_REACTION_SCHEME) - 1u, end = scheme_len + 2u * FZN_MESSAGE_ID_LEN;
	uint8_t got[FZN_MESSAGE_ID_LEN];

	if (!id || !at || !reaction_len || !head(text, len, FZN_MESSAGE_REACTION_SCHEME, scheme_len, got))
		return 0;
	if (len == end) {
		*at = end;
		*reaction_len = 0;
	} else if (text[end] == ' ' && reaction_ok(text + end + 1u, len - end - 1u)) {
		*at = end + 1u;
		*reaction_len = len - end - 1u;
	} else {
		return 0;
	}
	memcpy(id, got, sizeof(got));
	return 1;
}

size_t fzn_message_unsend_write(const uint8_t id[FZN_MESSAGE_ID_LEN], char *out, size_t cap)
{
	size_t at;

	if (!id || !out || cap <= FZN_MESSAGE_UNSEND_LEN)
		return 0;
	at = put_head(FZN_MESSAGE_UNSEND_SCHEME, sizeof(FZN_MESSAGE_UNSEND_SCHEME) - 1u, id, out);
	out[at] = '\0';
	return at;
}

int fzn_message_unsend_parse(const char *text, size_t len, uint8_t id[FZN_MESSAGE_ID_LEN])
{
	uint8_t got[FZN_MESSAGE_ID_LEN];

	if (!id || len != FZN_MESSAGE_UNSEND_LEN
	    || !head(text, len, FZN_MESSAGE_UNSEND_SCHEME, sizeof(FZN_MESSAGE_UNSEND_SCHEME) - 1u, got))
		return 0;
	memcpy(id, got, sizeof(got));
	return 1;
}
