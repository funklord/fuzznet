/* An external program's output, made into log entries. sec 441, the first
 * built piece of sec 428's design.
 *
 * netcfgd runs `ip`, raidcfgd runs `mdadm` and `ossacli`, and what they
 * print belongs in the log of the daemon that ran them. Sec 428 settled that
 * this is ONE shared function rather than something each daemon hand-rolls,
 * and settled its rules; this is them, independent of the questions sec 428
 * leaves open -- the classic line's fields and the ring's layout -- because
 * an entry here is handed to the caller's own log, whatever that writes.
 *
 * ONE CAPTURED LINE IS EXACTLY ONE ENTRY, and its text is UNTRUSTED. `\n`,
 * `\r`, every control byte, a backslash, terminal escapes, NUL, invalid UTF-8
 * and the C1 controls are written `\xNN`, so a tool's output cannot forge a
 * line in a log, move a terminal's cursor, or smuggle a byte a viewer would
 * act on. Sec 233 met the same forgery in record viewers. A line ending in
 * `\r\n` ends at the `\n`; a lone `\r` is text and escaped.
 *
 * BOUNDED TWICE, and both bounds are said rather than silent:
 *   - a LINE keeps FZN_CAPTURE_LINE_MAX bytes and counts the rest, so the
 *     entry says how much of it was not kept;
 *   - an INVOCATION emits `volume_max` lines, and every line past it is
 *     counted and named in the summary rather than emitted. Sec 428 sends
 *     those to the flight recorder, which is not built; until it is, the
 *     count is what survives of them.
 *
 * NO GUESSED SEVERITY. A tool has no levels, and reading its text for
 * "error" is a heuristic that will be wrong. An entry carries the stream it
 * came on, and its level is the caller's rule for that stream -- stdout
 * information and stderr a warning unless the caller says otherwise. The
 * summary is an error when the tool failed.
 *
 * THE INVOCATION IS LOGGED REDACTED BY THE CALLER, per argument: argv can
 * carry a passphrase or a controller's password, and only the caller knows
 * which argument is the secret.
 *
 * TWO LIMITS, STATED: stdout and stderr on two pipes lose their relative
 * order, and a tool that writes to syslog or the journal itself is not
 * captured at all. Neither is fixable here.
 *
 * NO I/O. This splits, escapes, counts and words; running the tool is the
 * caller's, so this is testable without a process and portable to anything.
 */

#ifndef FZN_LOG_CAPTURE_H
#define FZN_LOG_CAPTURE_H

#include <stddef.h>
#include <stdint.h>

/* Bytes of one captured line kept; the rest is counted. */
#define FZN_CAPTURE_LINE_MAX 4096u
/* An escaped line's worst case: four characters a byte, and its NUL. */
#define FZN_CAPTURE_TEXT_MAX ((FZN_CAPTURE_LINE_MAX * 4u) + 1u)

typedef enum fzn_capture_err {
	FZN_CAPTURE_OK = 0,
	FZN_CAPTURE_ERR_MALFORMED = -1, /* a null, or a stream that is neither */
	FZN_CAPTURE_ERR_ROOM = -2       /* what was asked for does not fit `cap` */
} fzn_capture_err_t;

const char *fzn_capture_err_str(fzn_capture_err_t err);

typedef enum fzn_capture_stream {
	FZN_CAPTURE_STDOUT = 1,
	FZN_CAPTURE_STDERR = 2
} fzn_capture_stream_t;

/* The caller's levels, named here only so a rule can say which. */
typedef enum fzn_capture_level {
	FZN_CAPTURE_DEBUG = 1,
	FZN_CAPTURE_INFO = 2,
	FZN_CAPTURE_WARNING = 3,
	FZN_CAPTURE_ERROR = 4
} fzn_capture_level_t;

/* Which level each stream's lines carry. */
typedef struct fzn_capture_rule {
	fzn_capture_level_t out;
	fzn_capture_level_t err;
} fzn_capture_rule_t;

/* Sec 428's default: stdout information, stderr a warning. */
static inline fzn_capture_rule_t fzn_capture_rule_default(void)
{
	fzn_capture_rule_t r;

	r.out = FZN_CAPTURE_INFO;
	r.err = FZN_CAPTURE_WARNING;
	return r;
}

/* One entry, valid only during the callback it is handed to. */
typedef struct fzn_capture_entry {
	fzn_capture_stream_t stream;
	fzn_capture_level_t level;
	const char *text; /* escaped, NUL-terminated */
	size_t text_len;
	size_t cut;       /* bytes of the line past FZN_CAPTURE_LINE_MAX, not kept */
	int unterminated; /* the tool's last line on this stream had no newline */
} fzn_capture_entry_t;

typedef void (*fzn_capture_emit_fn)(void *ctx, const fzn_capture_entry_t *entry);

typedef struct fzn_capture_part {
	uint8_t bytes[FZN_CAPTURE_LINE_MAX];
	size_t len;
	size_t cut;
	int pending_cr; /* a `\r` was the last byte seen; it ends the line if `\n` follows */
} fzn_capture_part_t;

/* One invocation's capture. Large -- two line buffers -- so a caller keeps
 * it static or on the heap rather than on a small stack. */
typedef struct fzn_capture {
	fzn_capture_emit_fn emit;
	void *ctx;
	fzn_capture_rule_t rule;
	size_t volume_max; /* lines emitted at most; 0 is no bound */
	fzn_capture_part_t part[2];
	size_t lines;         /* lines emitted */
	size_t dropped_lines; /* lines past `volume_max`, counted and not emitted */
	size_t dropped_bytes;
	size_t cut_bytes;     /* bytes past the line bound, over every line */
} fzn_capture_t;

fzn_capture_err_t fzn_capture_init(fzn_capture_t *capture, fzn_capture_emit_fn emit, void *ctx,
                                   fzn_capture_rule_t rule, size_t volume_max);

/* `len` bytes the tool wrote on `stream`, in any pieces: a line split across
 * two calls is one entry. */
fzn_capture_err_t fzn_capture_feed(fzn_capture_t *capture, fzn_capture_stream_t stream,
                                   const uint8_t *bytes, size_t len);

/* The tool has finished: a last line with no newline is emitted, marked so. */
fzn_capture_err_t fzn_capture_finish(fzn_capture_t *capture);

/* Escape `len` untrusted bytes into `out`, NUL-terminated; the characters
 * written. An escape is written whole or not at all, so a short `cap` gives
 * a shorter text and never half of `\xNN`. */
size_t fzn_capture_escape(const uint8_t *in, size_t len, char *out, size_t cap);

/* How the tool ended, as the waiting caller learned it. */
typedef enum fzn_capture_end {
	FZN_CAPTURE_EXITED = 1,   /* `code` is its exit status */
	FZN_CAPTURE_SIGNALLED = 2, /* `code` is the signal */
	FZN_CAPTURE_TIMED_OUT = 3, /* the caller stopped it at its deadline */
	FZN_CAPTURE_NOT_RUN = 4    /* it could not be started; `code` is errno */
} fzn_capture_end_t;

/* The closing entry's text and level: "exit 2 after 14 ms, 1 line", and
 * what was not kept when anything was. An error for any end but exit 0. */
fzn_capture_err_t fzn_capture_summary(const fzn_capture_t *capture, fzn_capture_end_t end,
                                      int code, uint64_t elapsed_ms, char *out, size_t cap,
                                      fzn_capture_level_t *level);

/* The invocation as one escaped line, each argument whose `secret[i]` is set
 * written `***`. `secret` may be NULL when none is. */
fzn_capture_err_t fzn_capture_argv(const char *const *argv, size_t argc,
                                   const unsigned char *secret, char *out, size_t cap);

#endif /* FZN_LOG_CAPTURE_H */
