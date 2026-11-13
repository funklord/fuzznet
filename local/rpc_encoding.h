#ifndef FZN_RPC_COMMON_ENCODING_H
#define FZN_RPC_COMMON_ENCODING_H

#include <stddef.h>
#include <stdint.h>

/*
 * A terminal-safe rendering of untrusted text: the typed client's own need,
 * from fuzzypickles' common/encoding.h. Its hex is fuzznet's public codec,
 * `hex/hex.h`, included here so a caller of this header keeps it (sec 1098:
 * the copy that came with the client was the same functions, except that
 * its variable-length decode never said how many bytes it decoded). Its
 * Base58 and Base58Check stayed in fuzzypickles -- its card text from before
 * the node's FZC1 card, whose checksum needs a hash this module may not
 * include.
 */
#include "../hex/hex.h"

/*
 * Renders untrusted text safe to print to a terminal: every C0 control byte
 * (0x00-0x1f) and DEL (0x7f) becomes caret notation (^@ .. ^_, ^?), so an
 * escape sequence a peer put in a chat message, note or log line cannot reach
 * the terminal live -- the display side of project.md sec 28's log-forgery /
 * terminal-injection class.
 *
 * AND THE C1 CONTROLS, U+0080 to U+009F, which are two-byte UTF-8 (C2 80 ..
 * C2 9F) and become "M-" plus the caret form of the C0 control they shadow:
 * U+009B, the one-character CSI, is "M-^[". This said until 2026-10-01 that
 * bytes >= 0x80 could pass because valid UTF-8 holds no standalone control;
 * that is true of BYTES and false of code points, and xterm acts on a C1 CSI
 * received as UTF-8 exactly as on ESC [ -- measured: U+009B then "31m" turned
 * the following text red (project.md sec 139). Every other high byte, which
 * is part of an ordinary multibyte character, passes through unchanged. The
 * plain-stdout CLI has no ncurses to do any of this, so it calls this.
 *
 * Output is at most twice the input: a C0 control is two bytes for one, a C1
 * control four for two. Writes at most out_cap-1 bytes plus a NUL, truncating
 * on a whole character boundary rather than overflowing (a control byte is
 * emitted as both caret
 * characters or neither, never a lone '^'). Returns out, or "" when out_cap is
 * 0. `len` is the input length in bytes; the input need not be NUL-terminated.
 */
const char *fzn_rpc_tty_escape(const char *s, size_t len, char *out, size_t out_cap);

#endif /* FZN_RPC_COMMON_ENCODING_H */
