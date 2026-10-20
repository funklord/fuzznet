/* The local grammar's %XX escape, sec 668. */

#include "escape.h"

static int nibble(uint8_t c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

size_t fzn_escape(const uint8_t *in, size_t n, char *out, size_t cap, size_t *written)
{
	static const char HEX[] = "0123456789abcdef";
	size_t i, w = 0;

	for (i = 0; in && out && i < n; i++) {
		uint8_t c = in[i];

		if (c <= 0x20u || c == '%' || c == ',' || c == 0x7fu) {
			if (cap - w < 3u)
				break;
			out[w++] = '%';
			out[w++] = HEX[c >> 4];
			out[w++] = HEX[c & 15u];
		} else {
			if (cap - w < 1u)
				break;
			out[w++] = (char)c;
		}
	}
	if (written)
		*written = w;
	return i;
}

int fzn_unescape(const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *len)
{
	size_t i, w = 0;

	if (!len || (n && (!in || !out)))
		return 0;
	for (i = 0; i < n; i++) {
		uint8_t c = in[i];

		if (c == '%') {
			int hi, lo;

			if (i + 2u >= n)
				return 0;
			hi = nibble(in[i + 1u]);
			lo = nibble(in[i + 2u]);
			if (hi < 0 || lo < 0)
				return 0;
			c = (uint8_t)((hi << 4) | lo);
			i += 2u;
		}
		if (w >= cap)
			return 0;
		out[w++] = c;
	}
	*len = w;
	return 1;
}
