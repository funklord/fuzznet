/* See capture.h. */

#include "capture.h"

#include <stdio.h>
#include <string.h>

const char *fzn_capture_err_str(fzn_capture_err_t err)
{
	switch (err) {
	case FZN_CAPTURE_OK:
		return "ok";
	case FZN_CAPTURE_ERR_MALFORMED:
		return "malformed";
	case FZN_CAPTURE_ERR_ROOM:
		return "does not fit";
	}
	return "unknown";
}

/* ---- escaping ------------------------------------------------------------ */

/* The length of the valid UTF-8 sequence at `in`, or 0. Overlong forms,
 * surrogates and code points past U+10FFFF are not valid. `*cp` gets the
 * code point. */
static size_t utf8_sequence(const uint8_t *in, size_t len, uint32_t *cp)
{
	uint8_t b = in[0];
	size_t need, i;
	uint32_t v;

	if (b >= 0xc2u && b <= 0xdfu) {
		need = 2;
		v = b & 0x1fu;
	} else if (b >= 0xe0u && b <= 0xefu) {
		need = 3;
		v = b & 0x0fu;
	} else if (b >= 0xf0u && b <= 0xf4u) {
		need = 4;
		v = b & 0x07u;
	} else {
		return 0;
	}
	if (len < need)
		return 0;
	for (i = 1; i < need; i++) {
		if ((in[i] & 0xc0u) != 0x80u)
			return 0;
		v = (v << 6) | (in[i] & 0x3fu);
	}
	if ((need == 3 && v < 0x800u) || (need == 4 && v < 0x10000u) || v > 0x10ffffu
	    || (v >= 0xd800u && v <= 0xdfffu))
		return 0;
	*cp = v;
	return need;
}

/* Whether a valid code point is still escaped: the C1 controls, which a
 * terminal may act on as 8-bit escapes, and the two Unicode line separators,
 * which some viewers break a line at. */
static int unsafe_code_point(uint32_t cp)
{
	return (cp >= 0x80u && cp <= 0x9fu) || cp == 0x2028u || cp == 0x2029u;
}

static size_t escape_impl(const uint8_t *in, size_t len, char *out, size_t cap, int space)
{
	static const char HEX[] = "0123456789abcdef";
	size_t i = 0, w = 0;

	if (!out || cap == 0u)
		return 0;
	while (i < len) {
		uint32_t cp = 0;
		size_t n = utf8_sequence(in + i, len - i, &cp);
		size_t k, take = n ? n : 1u;
		int plain;

		if (n)
			plain = !unsafe_code_point(cp);
		else
			plain = in[i] >= 0x20u && in[i] < 0x7fu && in[i] != '\\'
			        && !(space && in[i] == ' ');
		if (plain) {
			if (cap - w <= take)
				break;
			memcpy(out + w, in + i, take);
			w += take;
		} else {
			/* EVERY BYTE OF IT, so an unsafe sequence reads back as
			 * the bytes the tool wrote. Whole or not at all. */
			if (cap - w <= 4u * take)
				break;
			for (k = 0; k < take; k++) {
				out[w++] = '\\';
				out[w++] = 'x';
				out[w++] = HEX[in[i + k] >> 4];
				out[w++] = HEX[in[i + k] & 0x0fu];
			}
		}
		i += take;
	}
	out[w] = '\0';
	return w;
}

/* The characters `escape_impl` writes for all of `in`, with room for it. */
static size_t escaped_len(const uint8_t *in, size_t len, int space)
{
	size_t i = 0, n = 0;

	while (i < len) {
		uint32_t cp = 0;
		size_t k = utf8_sequence(in + i, len - i, &cp), take = k ? k : 1u;
		int plain = k ? !unsafe_code_point(cp)
		              : (in[i] >= 0x20u && in[i] < 0x7fu && in[i] != '\\'
		                 && !(space && in[i] == ' '));

		n += plain ? take : 4u * take;
		i += take;
	}
	return n;
}

size_t fzn_capture_escape(const uint8_t *in, size_t len, char *out, size_t cap)
{
	if (!in && len)
		return 0;
	return escape_impl(in, len, out, cap, 0);
}

/* ---- splitting into lines ------------------------------------------------ */

fzn_capture_err_t fzn_capture_init(fzn_capture_t *capture, fzn_capture_emit_fn emit, void *ctx,
                                   fzn_capture_rule_t rule, size_t volume_max)
{
	if (!capture || !emit)
		return FZN_CAPTURE_ERR_MALFORMED;
	memset(capture, 0, sizeof(*capture));
	capture->emit = emit;
	capture->ctx = ctx;
	capture->rule = rule;
	capture->volume_max = volume_max;
	return FZN_CAPTURE_OK;
}

static void keep(fzn_capture_part_t *p, uint8_t b)
{
	if (p->len < FZN_CAPTURE_LINE_MAX)
		p->bytes[p->len++] = b;
	else
		p->cut++;
}

static void end_line(fzn_capture_t *c, fzn_capture_stream_t stream, int unterminated)
{
	static char text[FZN_CAPTURE_TEXT_MAX];
	fzn_capture_part_t *p = &c->part[stream - 1];
	fzn_capture_entry_t e;

	c->cut_bytes += p->cut;
	/* PAST THE VOLUME BOUND, counted rather than emitted: the summary
	 * says how much. */
	if (c->volume_max && c->lines >= c->volume_max) {
		c->dropped_lines++;
		c->dropped_bytes += p->len + p->cut;
	} else {
		e.stream = stream;
		e.level = stream == FZN_CAPTURE_STDOUT ? c->rule.out : c->rule.err;
		e.text_len = escape_impl(p->bytes, p->len, text, sizeof(text), 0);
		e.text = text;
		e.cut = p->cut;
		e.unterminated = unterminated;
		c->lines++;
		c->emit(c->ctx, &e);
	}
	p->len = 0;
	p->cut = 0;
	p->pending_cr = 0;
}

fzn_capture_err_t fzn_capture_feed(fzn_capture_t *capture, fzn_capture_stream_t stream,
                                   const uint8_t *bytes, size_t len)
{
	fzn_capture_part_t *p;
	size_t i;

	if (!capture || (!bytes && len)
	    || (stream != FZN_CAPTURE_STDOUT && stream != FZN_CAPTURE_STDERR))
		return FZN_CAPTURE_ERR_MALFORMED;
	p = &capture->part[stream - 1];
	for (i = 0; i < len; i++) {
		uint8_t b = bytes[i];

		/* `\r\n` ENDS A LINE AS `\n` DOES; a `\r` anywhere else is
		 * text, escaped like any control byte. */
		if (p->pending_cr) {
			p->pending_cr = 0;
			if (b == '\n') {
				end_line(capture, stream, 0);
				continue;
			}
			keep(p, '\r');
		}
		if (b == '\n')
			end_line(capture, stream, 0);
		else if (b == '\r')
			p->pending_cr = 1;
		else
			keep(p, b);
	}
	return FZN_CAPTURE_OK;
}

fzn_capture_err_t fzn_capture_finish(fzn_capture_t *capture)
{
	unsigned s;

	if (!capture)
		return FZN_CAPTURE_ERR_MALFORMED;
	for (s = FZN_CAPTURE_STDOUT; s <= FZN_CAPTURE_STDERR; s++) {
		fzn_capture_part_t *p = &capture->part[s - 1];

		if (p->pending_cr) {
			p->pending_cr = 0;
			keep(p, '\r');
		}
		if (p->len || p->cut)
			end_line(capture, (fzn_capture_stream_t)s, 1);
	}
	return FZN_CAPTURE_OK;
}

/* ---- the closing entry, and the invocation ------------------------------ */

fzn_capture_err_t fzn_capture_summary(const fzn_capture_t *capture, fzn_capture_end_t end,
                                      int code, uint64_t elapsed_ms, char *out, size_t cap,
                                      fzn_capture_level_t *level)
{
	size_t total, used;
	int n;

	if (!capture || !out || !level)
		return FZN_CAPTURE_ERR_MALFORMED;
	switch (end) {
	case FZN_CAPTURE_EXITED:
		n = snprintf(out, cap, "exit %d after %llu ms", code, (unsigned long long)elapsed_ms);
		break;
	case FZN_CAPTURE_SIGNALLED:
		n = snprintf(out, cap, "killed by signal %d after %llu ms", code,
		             (unsigned long long)elapsed_ms);
		break;
	case FZN_CAPTURE_TIMED_OUT:
		n = snprintf(out, cap, "stopped at its deadline after %llu ms",
		             (unsigned long long)elapsed_ms);
		break;
	case FZN_CAPTURE_NOT_RUN:
		n = snprintf(out, cap, "could not be started, errno %d", code);
		break;
	default:
		return FZN_CAPTURE_ERR_MALFORMED;
	}
	if (n < 0 || (size_t)n >= cap)
		return FZN_CAPTURE_ERR_ROOM;
	used = (size_t)n;
	total = capture->lines + capture->dropped_lines;
	if (end != FZN_CAPTURE_NOT_RUN) {
		n = snprintf(out + used, cap - used, ", %zu line%s", total, total == 1u ? "" : "s");
		if (n < 0 || (size_t)n >= cap - used)
			return FZN_CAPTURE_ERR_ROOM;
		used += (size_t)n;
	}
	/* WHAT WAS NOT KEPT IS SAID, in the entry a reader looks at last. */
	if (capture->dropped_lines) {
		n = snprintf(out + used, cap - used, "; %zu line%s, %zu bytes past the bound not kept",
		             capture->dropped_lines, capture->dropped_lines == 1u ? "" : "s",
		             capture->dropped_bytes);
		if (n < 0 || (size_t)n >= cap - used)
			return FZN_CAPTURE_ERR_ROOM;
		used += (size_t)n;
	}
	if (capture->cut_bytes) {
		n = snprintf(out + used, cap - used, "; %zu bytes of long lines not kept",
		             capture->cut_bytes);
		if (n < 0 || (size_t)n >= cap - used)
			return FZN_CAPTURE_ERR_ROOM;
	}
	*level = (end == FZN_CAPTURE_EXITED && code == 0) ? FZN_CAPTURE_INFO : FZN_CAPTURE_ERROR;
	return FZN_CAPTURE_OK;
}

fzn_capture_err_t fzn_capture_argv(const char *const *argv, size_t argc,
                                   const unsigned char *secret, char *out, size_t cap)
{
	size_t used = 0, i, len, w;

	if (!out || cap == 0u || (!argv && argc))
		return FZN_CAPTURE_ERR_MALFORMED;
	out[0] = '\0';
	for (i = 0; i < argc; i++) {
		if (!argv[i])
			return FZN_CAPTURE_ERR_MALFORMED;
		if (i) {
			if (cap - used < 2u)
				return FZN_CAPTURE_ERR_ROOM;
			out[used++] = ' ';
			out[used] = '\0';
		}
		if (secret && secret[i]) {
			if (cap - used < 4u)
				return FZN_CAPTURE_ERR_ROOM;
			memcpy(out + used, "***", 4u);
			used += 3u;
			continue;
		}
		/* A SPACE INSIDE AN ARGUMENT IS ESCAPED, so the line splits
		 * back into the arguments that were passed. AN ARGUMENT CUT SHORT
		 * WOULD READ AS THE WHOLE ONE, so one that does not fit is
		 * refused rather than written cut. */
		len = strlen(argv[i]);
		if (escaped_len((const uint8_t *)argv[i], len, 1) >= cap - used) {
			out[used] = '\0';
			return FZN_CAPTURE_ERR_ROOM;
		}
		w = escape_impl((const uint8_t *)argv[i], len, out + used, cap - used, 1);
		used += w;
	}
	return FZN_CAPTURE_OK;
}
