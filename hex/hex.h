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

/* Fixed-length decode: hex string must decode to exactly out_len bytes. */
int fzn_hex_decode(const char *hex, uint8_t *out, size_t out_len);

/* Variable-length decode: decodes to however many bytes the (even-length)
 * hex string implies, up to out_cap. */
int fzn_hex_decode_var(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* FZN_HEX_HEX_H */
