/*
 * THE LOCAL GRAMMAR'S %XX ESCAPE, one copy, sec 668: a byte up to a space,
 * a `%`, a comma or DEL written as `%` and two hex digits, lower case; read
 * back in either case (sec 654). What `list message`, `list note`, a setting
 * and `list catalog` write, and a client of the local socket reads and
 * writes -- four copies in this tree and a fifth in fuzzypickles, until
 * fuzzypickles asked for one (inbox message 20261021T0200Z).
 */
#ifndef FZN_LOCAL_ESCAPE_H
#define FZN_LOCAL_ESCAPE_H

#include <stddef.h>
#include <stdint.h>

/* ESCAPE `in`, `n` bytes, into `out`, `cap` bytes, as far as it fits:
 * the input bytes taken, `*written` the output's length. Whole when the
 * result is `n`. */
size_t fzn_escape(const uint8_t *in, size_t n, char *out, size_t cap, size_t *written);

/* UNESCAPE `in`, `n` bytes, into `out`, at most `cap`: 1 with `*len`, 0
 * for a malformed escape or an output past `cap`. Either case of hex. */
int fzn_unescape(const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *len);

#endif /* FZN_LOCAL_ESCAPE_H */
