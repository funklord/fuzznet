/* See attachment.h. */

#include "attachment.h"

#include "line.h"

#include <stdio.h>
#include <string.h>

/* A REFERENCE FITS THE LINE THAT CARRIES IT, checked here rather than found
 * on the one send whose name was full length. */
_Static_assert(FZN_ATTACHMENT_REF_MAX <= FZN_MESSAGE_TEXT_MAX,
               "an attachment's reference must fit in a line");

static const char SCHEME[] = "fzn:file/";
static const char FZP_SCHEME[] = "fzp:file/";
#define SCHEME_LEN (sizeof(SCHEME) - 1u)

static int name_carried(const char *name, size_t len)
{
	size_t i;

	if (len == 0u || len > FZN_ATTACHMENT_NAME_MAX || name[0] == '.' || name[0] == ' '
	    || name[len - 1u] == ' ')
		return 0;
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)name[i];

		if (c < 0x20u || c == 0x7fu || c == '/' || c == '\\')
			return 0;
	}
	return 1;
}

static int nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* `n` bytes of hex at `*p`, then `end_with`. */
static int hex_field(const char **p, const char *end, uint8_t *out, size_t n, char end_with)
{
	size_t i;

	if ((size_t)(end - *p) < 2u * n + 1u)
		return 0;
	for (i = 0; i < n; i++) {
		int hi = nibble((*p)[2u * i]), lo = nibble((*p)[2u * i + 1u]);

		if (hi < 0 || lo < 0)
			return 0;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	if ((*p)[2u * n] != end_with)
		return 0;
	*p += 2u * n + 1u;
	return 1;
}

int fzn_attachment_format(const fzn_attachment_t *a, char *out, size_t cap, size_t *len)
{
	size_t at = SCHEME_LEN, i;
	int n;

	if (!a || !out || !len || !name_carried(a->name, a->name_len)
	    || cap < SCHEME_LEN + 2u * (FZN_ATTACHMENT_ROOT_LEN + FZN_ATTACHMENT_KEY_LEN) + 3u)
		return 0;
	memcpy(out, SCHEME, SCHEME_LEN);
	for (i = 0; i < FZN_ATTACHMENT_ROOT_LEN; i++, at += 2u)
		(void)snprintf(out + at, 3u, "%02x", a->root[i]);
	out[at++] = '/';
	for (i = 0; i < FZN_ATTACHMENT_KEY_LEN; i++, at += 2u)
		(void)snprintf(out + at, 3u, "%02x", a->key[i]);
	out[at++] = '/';
	n = snprintf(out + at, cap - at, "%llu %.*s", (unsigned long long)a->size,
	             (int)a->name_len, a->name);
	if (n < 0 || (size_t)n >= cap - at)
		return 0;
	*len = at + (size_t)n;
	return 1;
}

int fzn_attachment_parse(const char *text, size_t len, fzn_attachment_t *out)
{
	const char *p, *end, *digits;
	uint64_t size = 0;
	size_t n_digits = 0, name_len;

	if (!text || !out || len <= SCHEME_LEN || len > FZN_ATTACHMENT_REF_MAX
	    || (memcmp(text, SCHEME, SCHEME_LEN) != 0 && memcmp(text, FZP_SCHEME, SCHEME_LEN) != 0))
		return 0;
	memset(out, 0, sizeof(*out));
	p = text + SCHEME_LEN;
	end = text + len;
	if (!hex_field(&p, end, out->root, FZN_ATTACHMENT_ROOT_LEN, '/')
	    || !hex_field(&p, end, out->key, FZN_ATTACHMENT_KEY_LEN, '/'))
		return 0;
	/* THE SIZE, bounded by its digits: twenty is what a u64 holds, and the
	 * twenty-first is refused before it can wrap. No leading zero. */
	digits = p;
	while (p < end && *p >= '0' && *p <= '9') {
		if (++n_digits > 20u)
			return 0;
		size = size * 10u + (uint64_t)(*p - '0');
		p++;
	}
	if (n_digits == 0u || (n_digits > 1u && digits[0] == '0')
	    || (n_digits == 20u && memcmp(digits, "18446744073709551615", 20u) > 0) || p >= end
	    || *p != ' ')
		return 0;
	p++;
	name_len = (size_t)(end - p);
	if (!name_carried(p, name_len))
		return 0;
	out->size = size;
	memcpy(out->name, p, name_len);
	out->name[name_len] = '\0';
	out->name_len = name_len;
	return 1;
}
