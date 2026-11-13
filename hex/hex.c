#include "hex.h"

#include <string.h>

void fzn_hex_encode(const uint8_t *data, size_t data_len, char *out) {
	static const char hex_digits[] = "0123456789abcdef";
	for (size_t i = 0; i < data_len; i++) {
		out[i * 2] = hex_digits[data[i] >> 4];
		out[i * 2 + 1] = hex_digits[data[i] & 0x0F];
	}
	out[data_len * 2] = '\0';
}

static int hex_nibble(char c, int *out) {
	if (c >= '0' && c <= '9') {
		*out = c - '0';
	} else if (c >= 'a' && c <= 'f') {
		*out = c - 'a' + 10;
	} else if (c >= 'A' && c <= 'F') {
		*out = c - 'A' + 10;
	} else {
		return -1;
	}
	return 0;
}

int fzn_hex_decode(const char *hex, uint8_t *out, size_t out_len) {
	if (strlen(hex) != out_len * 2) return -1;
	for (size_t i = 0; i < out_len; i++) {
		int hi, lo;
		if (hex_nibble(hex[i * 2], &hi) != 0) return -1;
		if (hex_nibble(hex[i * 2 + 1], &lo) != 0) return -1;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

int fzn_hex_decode_var(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len) {
	size_t hex_len = strlen(hex);
	if (hex_len % 2 != 0) return -1;
	size_t n = hex_len / 2;
	if (n == 0 || n > out_cap) return -1;
	if (fzn_hex_decode(hex, out, n) != 0) return -1;
	*out_len = n;
	return 0;
}
