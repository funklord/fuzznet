#ifndef FZN_HEX_HEX_H
#define FZN_HEX_HEX_H

#include <stddef.h>
#include <stdint.h>

/*
 * Hex, lower-case: the public codec every module here keeps a private copy
 * of, taken from fuzzypickles' common/encoding (the text below is its own).
 */

/* Hex encode/decode -- unchanged from the CLI's pre-existing local
 * helpers (host-join/capability/sibling's established convention), moved
 * here so every flow shares one implementation instead of cli/main.c's
 * static copies. */
void fzn_hex_encode(const uint8_t *data, size_t data_len, char *out);

/* ONE BYTE AS ITS TWO DIGITS at `out`, and no NUL: for an escaper writing
 * `%XX` into a line, and a writer filling a field with no room for a
 * terminator. The digits fzn_hex_encode writes, from the same table, so
 * the tree keeps one (fuzznet sec 1146). INLINE, so a module that writes
 * hex gains no object to link: some hundred test binaries name theirs by
 * hand. */
static inline void fzn_hex_byte(uint8_t byte, char out[2])
{
	static const char digits[] = "0123456789abcdef";
	out[0] = digits[byte >> 4];
	out[1] = digits[byte & 0x0Fu];
}

/* Fixed-length decode: hex string must decode to exactly out_len bytes. */
int fzn_hex_decode(const char *hex, uint8_t *out, size_t out_len);

/* Variable-length decode: decodes to however many bytes the (even-length)
 * hex string implies, up to out_cap. */
int fzn_hex_decode_var(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* FZN_HEX_HEX_H */
