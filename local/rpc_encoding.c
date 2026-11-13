#include "rpc_encoding.h"

#include <string.h>

const char *fzn_rpc_tty_escape(const char *s, size_t len, char *out, size_t out_cap) {
	if (out_cap == 0) return "";
	size_t o = 0;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];
		/* A C1 control as UTF-8 (sec 139): C2 then 80..9F. */
		if (c == 0xC2 && i + 1 < len && (unsigned char)s[i + 1] >= 0x80 &&
		    (unsigned char)s[i + 1] <= 0x9F) {
			if (o + 4 + 1 > out_cap) break;
			out[o++] = 'M';
			out[o++] = '-';
			out[o++] = '^';
			out[o++] = (char)(((unsigned char)s[i + 1] - 0x80) ^ 0x40);
			i++;
			continue;
		}
		int is_ctrl = (c < 0x20 || c == 0x7f);
		size_t need = is_ctrl ? 2 : 1;
		if (o + need + 1 > out_cap) break; /* +1 leaves room for the NUL */
		if (is_ctrl) {
			out[o++] = '^';
			out[o++] = (char)(c ^ 0x40);
		} else {
			out[o++] = (char)c;
		}
	}
	out[o] = '\0';
	return out;
}
