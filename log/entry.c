/* See entry.h. */

#include "entry.h"

#include "capture.h"

#include <stdio.h>
#include <string.h>

static const char HEX[] = "0123456789abcdef";
static const char LETTERS[] = "CEWNIVDT";

const char *fzn_entry_err_str(fzn_entry_err_t err)
{
	switch (err) {
	case FZN_ENTRY_OK:
		return "ok";
	case FZN_ENTRY_ERR_MALFORMED:
		return "malformed";
	case FZN_ENTRY_ERR_ROOM:
		return "the line does not fit";
	}
	return "unknown";
}

char fzn_entry_level_letter(fzn_entry_level_t level)
{
	if (level < FZN_ENTRY_CRITICAL || level > FZN_ENTRY_TRACE)
		return 0;
	return LETTERS[level - 1];
}

static int level_of(char c, fzn_entry_level_t *out)
{
	const char *at = c ? strchr(LETTERS, c) : NULL;

	if (!at)
		return 0;
	*out = (fzn_entry_level_t)((at - LETTERS) + 1);
	return 1;
}

/* ---- words --------------------------------------------------------------- */

/* A user, a program or a host: what those names hold, and no space. */
static int word_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
	       || c == '-' || c == '.' || c == '+' || c == '$';
}

static int is_word(const char *w, size_t max)
{
	size_t i;

	if (!w || !w[0])
		return 0;
	for (i = 0; w[i]; i++)
		if (i >= max || !word_char(w[i]))
			return 0;
	return 1;
}

/* `notes/sync`: words joined by single slashes, none empty. */
static int is_subsystem(const char *s)
{
	size_t i;

	if (!s || !s[0] || s[0] == '/')
		return 0;
	for (i = 0; s[i]; i++) {
		if (i >= FZN_ENTRY_SUBSYSTEM_MAX)
			return 0;
		if (s[i] == '/') {
			if (s[i + 1u] == '/' || s[i + 1u] == '\0')
				return 0;
		} else if (!word_char(s[i])) {
			return 0;
		}
	}
	return 1;
}

static int copy_word(const char *from, size_t len, char *to, size_t max, int subsystem)
{
	if (len == 0u || len > max)
		return 0;
	memcpy(to, from, len);
	to[len] = '\0';
	return subsystem ? is_subsystem(to) : is_word(to, max);
}

/* ---- numbers ------------------------------------------------------------- */

/* Decimal digits of `text`, no sign and no leading zero but for 0 itself,
 * at most 20 of them and within a u64. */
static int parse_u64(const char *text, size_t len, uint64_t *out)
{
	uint64_t v = 0;
	size_t i;

	if (len == 0u || len > 20u || (len > 1u && text[0] == '0'))
		return 0;
	for (i = 0; i < len; i++) {
		unsigned d;

		if (text[i] < '0' || text[i] > '9')
			return 0;
		d = (unsigned)(text[i] - '0');
		if (v > (UINT64_MAX - d) / 10u)
			return 0;
		v = (v * 10u) + d;
	}
	*out = v;
	return 1;
}

/* ---- time ---------------------------------------------------------------- */

/* Days since 1970-01-01 to a civil date and back, proleptic Gregorian. */
static void civil_from_days(int64_t z, int64_t *y, unsigned *m, unsigned *d)
{
	int64_t era, yoe, doy, mp;

	z += 719468;
	era = (z >= 0 ? z : z - 146096) / 146097;
	yoe = z - (era * 146097);
	yoe = (yoe - (yoe / 1460) + (yoe / 36524) - (yoe / 146096)) / 365;
	doy = (z - (era * 146097)) - ((365 * yoe) + (yoe / 4) - (yoe / 100));
	mp = ((5 * doy) + 2) / 153;
	*d = (unsigned)(doy - (((153 * mp) + 2) / 5) + 1);
	*m = (unsigned)(mp < 10 ? mp + 3 : mp - 9);
	*y = yoe + (era * 400) + (*m <= 2u ? 1 : 0);
}

static int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
	int64_t era, yoe, doy, doe;

	y -= m <= 2u ? 1 : 0;
	era = (y >= 0 ? y : y - 399) / 400;
	yoe = y - (era * 400);
	doy = (((153 * (int64_t)(m > 2u ? m - 3u : m + 9u)) + 2) / 5) + (int64_t)d - 1;
	doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy;
	return (era * 146097) + doe - 719468;
}

/* `2026-10-02T12:34:56.789123Z`, 27 characters; years 1970 to 9999. */
#define TIME_LEN 27u

static int time_text(uint64_t us, char out[TIME_LEN + 1u])
{
	uint64_t secs = us / 1000000u, days = secs / 86400u, rem = secs % 86400u;
	int64_t y;
	unsigned m, d;

	civil_from_days((int64_t)days, &y, &m, &d);
	if (y > 9999)
		return 0;
	(void)snprintf(out, TIME_LEN + 1u, "%04u-%02u-%02uT%02u:%02u:%02u.%06uZ", (unsigned)y, m,
	               d, (unsigned)(rem / 3600u), (unsigned)((rem / 60u) % 60u),
	               (unsigned)(rem % 60u), (unsigned)(us % 1000000u));
	return 1;
}

static int digits(const char *t, size_t n, unsigned *out)
{
	unsigned v = 0;
	size_t i;

	for (i = 0; i < n; i++) {
		if (t[i] < '0' || t[i] > '9')
			return 0;
		v = (v * 10u) + (unsigned)(t[i] - '0');
	}
	*out = v;
	return 1;
}

static int time_parse(const char *t, size_t len, uint64_t *us)
{
	unsigned y, mo, d, h, mi, s, frac;
	static const unsigned mdays[12] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	int leap;
	int64_t days;

	if (len != TIME_LEN || t[4] != '-' || t[7] != '-' || t[10] != 'T' || t[13] != ':'
	    || t[16] != ':' || t[19] != '.' || t[26] != 'Z' || !digits(t, 4u, &y)
	    || !digits(t + 5, 2u, &mo) || !digits(t + 8, 2u, &d) || !digits(t + 11, 2u, &h)
	    || !digits(t + 14, 2u, &mi) || !digits(t + 17, 2u, &s) || !digits(t + 20, 6u, &frac))
		return 0;
	leap = (y % 4u == 0u && y % 100u != 0u) || y % 400u == 0u;
	if (y < 1970u || mo < 1u || mo > 12u || d < 1u || d > mdays[mo - 1u]
	    || (mo == 2u && d == 29u && !leap) || h > 23u || mi > 59u || s > 59u)
		return 0;
	days = days_from_civil((int64_t)y, mo, d);
	*us = (((uint64_t)days * 86400u) + (h * 3600u) + (mi * 60u) + s) * 1000000u + frac;
	return 1;
}

/* ---- names --------------------------------------------------------------- */

fzn_entry_err_t fzn_entry_machine_parse(const char *text, size_t len,
                                          uint8_t out[FZN_ENTRY_MACHINE_LEN])
{
	size_t i;

	if (!text || !out)
		return FZN_ENTRY_ERR_MALFORMED;
	if (len == 33u && text[32] == '\n')
		len = 32u;
	if (len != 32u)
		return FZN_ENTRY_ERR_MALFORMED;
	for (i = 0; i < 32u; i++) {
		const char *h = strchr(HEX, text[i]);

		if (!text[i] || !h)
			return FZN_ENTRY_ERR_MALFORMED;
		if (i % 2u == 0u)
			out[i / 2u] = (uint8_t)((h - HEX) << 4);
		else
			out[i / 2u] = (uint8_t)(out[i / 2u] | (uint8_t)(h - HEX));
	}
	return FZN_ENTRY_OK;
}

static int name_ok(const fzn_entry_name_t *n)
{
	return is_word(n->user, FZN_ENTRY_WORD_MAX) && is_word(n->program, FZN_ENTRY_WORD_MAX);
}

/* `PID@START#POS`, the instance field and the tail of every name. */
static int instance_text(const fzn_entry_name_t *n, char *out, size_t cap)
{
	int k = snprintf(out, cap, "%lu@%llu#%llu", (unsigned long)n->pid,
	                 (unsigned long long)n->start_ms, (unsigned long long)n->position);

	return k > 0 && (size_t)k < cap ? k : -1;
}

static int instance_parse(const char *t, size_t len, fzn_entry_name_t *n)
{
	const char *at = memchr(t, '@', len), *hash;
	uint64_t pid = 0;

	if (!at)
		return 0;
	hash = memchr(at, '#', len - (size_t)(at - t));
	return hash && parse_u64(t, (size_t)(at - t), &pid) && pid <= UINT32_MAX
	       && parse_u64(at + 1, (size_t)(hash - at - 1), &n->start_ms)
	       && parse_u64(hash + 1, len - (size_t)(hash - t) - 1u, &n->position)
	       && ((n->pid = (uint32_t)pid), 1);
}

fzn_entry_err_t fzn_entry_name_text(const fzn_entry_name_t *name, char *out, size_t cap,
                                      size_t *len)
{
	char machine[(FZN_ENTRY_MACHINE_LEN * 2u) + 1u], inst[64];
	size_t i;
	int k;

	if (!name || !out || !len || !name_ok(name))
		return FZN_ENTRY_ERR_MALFORMED;
	for (i = 0; i < FZN_ENTRY_MACHINE_LEN; i++) {
		machine[i * 2u] = HEX[name->machine[i] >> 4];
		machine[(i * 2u) + 1u] = HEX[name->machine[i] & 0x0fu];
	}
	machine[FZN_ENTRY_MACHINE_LEN * 2u] = '\0';
	if (instance_text(name, inst, sizeof(inst)) < 0)
		return FZN_ENTRY_ERR_MALFORMED;
	k = snprintf(out, cap, "%s/%s/%s/%s", machine, name->user, name->program, inst);
	if (k < 0 || (size_t)k >= cap) {
		if (cap)
			out[0] = '\0';
		return FZN_ENTRY_ERR_ROOM;
	}
	*len = (size_t)k;
	return FZN_ENTRY_OK;
}

fzn_entry_err_t fzn_entry_name_parse(const char *text, size_t len, fzn_entry_name_t *out)
{
	const char *p[3];
	size_t i, n = 0;

	if (!text || !out)
		return FZN_ENTRY_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	for (i = 0; i < len && n < 3u; i++)
		if (text[i] == '/')
			p[n++] = text + i;
	if (n != 3u || fzn_entry_machine_parse(text, (size_t)(p[0] - text), out->machine)
	                       != FZN_ENTRY_OK
	    || !copy_word(p[0] + 1, (size_t)(p[1] - p[0] - 1), out->user, FZN_ENTRY_WORD_MAX, 0)
	    || !copy_word(p[1] + 1, (size_t)(p[2] - p[1] - 1), out->program, FZN_ENTRY_WORD_MAX, 0)
	    || !instance_parse(p[2] + 1, len - (size_t)(p[2] + 1 - text), out))
		return FZN_ENTRY_ERR_MALFORMED;
	return FZN_ENTRY_OK;
}

/* ---- the classic line ---------------------------------------------------- */

fzn_entry_err_t fzn_entry_classic(const fzn_entry_t *entry, const char *host, char *out,
                                    size_t cap, size_t *len)
{
	/* THE WORST CASE, so the escaper never cuts: it cuts silently. */
	static char text[(FZN_ENTRY_TEXT_MAX * 4u) + 1u];
	char when[TIME_LEN + 1u], inst[64];
	char cause[(FZN_ENTRY_MACHINE_LEN * 2u) + (2u * FZN_ENTRY_WORD_MAX) + 72u] = "-";
	char origin[sizeof(cause)] = "-";
	char letter;
	size_t ignored = 0;
	int k;

	if (!entry || !host || !out || !len || cap == 0u)
		return FZN_ENTRY_ERR_MALFORMED;
	out[0] = '\0';
	letter = fzn_entry_level_letter(entry->level);
	if (!name_ok(&entry->name) || !is_word(host, FZN_ENTRY_WORD_MAX)
	    || !is_subsystem(entry->subsystem) || !letter || (!entry->text && entry->text_len)
	    || entry->text_len > FZN_ENTRY_TEXT_MAX || !time_text(entry->time_us, when)
	    || instance_text(&entry->name, inst, sizeof(inst)) < 0)
		return FZN_ENTRY_ERR_MALFORMED;
	if (entry->caused
	    && (fzn_entry_name_text(&entry->cause, cause + 1, sizeof(cause) - 1u, &ignored)
	                != FZN_ENTRY_OK
	        || fzn_entry_name_text(&entry->origin, origin + 2, sizeof(origin) - 2u, &ignored)
	                   != FZN_ENTRY_OK))
		return FZN_ENTRY_ERR_MALFORMED;
	if (entry->caused) {
		cause[0] = '<';
		origin[0] = '<';
		origin[1] = '<';
	}
	(void)fzn_capture_escape(entry->text, entry->text_len, text, sizeof(text));
	k = snprintf(out, cap, "%s %s %s %s %s %c %s %s %s %s\n", when, host, entry->name.user,
	             entry->name.program, inst, letter, entry->subsystem, cause, origin, text);
	if (k < 0 || (size_t)k >= cap) {
		/* NOTHING THAT COULD BE TAKEN FOR A LINE. */
		out[0] = '\0';
		return FZN_ENTRY_ERR_ROOM;
	}
	*len = (size_t)k;
	return FZN_ENTRY_OK;
}

/* `\xNN` back to its byte; any other backslash is no escape of ours. */
static int unescape(const char *t, size_t len, uint8_t *out, size_t cap, size_t *n)
{
	size_t i = 0, w = 0;

	while (i < len) {
		uint8_t b;

		if (t[i] == '\\') {
			const char *hi, *lo;

			if (len - i < 4u || t[i + 1u] != 'x' || !t[i + 2u] || !t[i + 3u]
			    || !(hi = strchr(HEX, t[i + 2u])) || !(lo = strchr(HEX, t[i + 3u])))
				return 0;
			b = (uint8_t)(((hi - HEX) << 4) | (lo - HEX));
			i += 4u;
		} else {
			if ((unsigned char)t[i] < 0x20u || t[i] == 0x7f)
				return 0;
			b = (uint8_t)t[i];
			i++;
		}
		if (w >= cap)
			return 0;
		out[w++] = b;
	}
	*n = w;
	return 1;
}

fzn_entry_err_t fzn_entry_classic_parse(const char *line, size_t len,
                                          const uint8_t machine[FZN_ENTRY_MACHINE_LEN],
                                          fzn_entry_t *out, char host[FZN_ENTRY_WORD_MAX + 1u],
                                          uint8_t *text_buf, size_t text_cap)
{
	const char *f[9], *at;
	size_t flen[9], i, text_len = 0;
	const char *end;

	if (!line || !machine || !out || !host || (!text_buf && text_cap))
		return FZN_ENTRY_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	host[0] = '\0';
	if (len && line[len - 1u] == '\n')
		len--;
	end = line + len;
	/* NINE FIELDS, each ended by one space; the text is the rest. */
	at = line;
	for (i = 0; i < 9u; i++) {
		const char *sp = memchr(at, ' ', (size_t)(end - at));

		if (!sp || sp == at)
			return FZN_ENTRY_ERR_MALFORMED;
		f[i] = at;
		flen[i] = (size_t)(sp - at);
		at = sp + 1;
	}
	memcpy(out->name.machine, machine, FZN_ENTRY_MACHINE_LEN);
	if (!time_parse(f[0], flen[0], &out->time_us)
	    || !copy_word(f[1], flen[1], host, FZN_ENTRY_WORD_MAX, 0)
	    || !copy_word(f[2], flen[2], out->name.user, FZN_ENTRY_WORD_MAX, 0)
	    || !copy_word(f[3], flen[3], out->name.program, FZN_ENTRY_WORD_MAX, 0)
	    || !instance_parse(f[4], flen[4], &out->name) || flen[5] != 1u
	    || !level_of(f[5][0], &out->level)
	    || !copy_word(f[6], flen[6], out->subsystem, FZN_ENTRY_SUBSYSTEM_MAX, 1))
		return FZN_ENTRY_ERR_MALFORMED;
	/* CAUSE AND ORIGIN, both or neither. */
	if (flen[7] == 1u && f[7][0] == '-' && flen[8] == 1u && f[8][0] == '-') {
		out->caused = 0;
	} else if (flen[7] > 1u && f[7][0] == '<' && f[7][1] != '<' && flen[8] > 2u
	           && f[8][0] == '<' && f[8][1] == '<'
	           && fzn_entry_name_parse(f[7] + 1, flen[7] - 1u, &out->cause) == FZN_ENTRY_OK
	           && fzn_entry_name_parse(f[8] + 2, flen[8] - 2u, &out->origin)
	                      == FZN_ENTRY_OK) {
		out->caused = 1;
	} else {
		return FZN_ENTRY_ERR_MALFORMED;
	}
	if (!unescape(at, (size_t)(end - at), text_buf, text_cap, &text_len)
	    || text_len > FZN_ENTRY_TEXT_MAX)
		return FZN_ENTRY_ERR_MALFORMED;
	out->text = text_buf;
	out->text_len = text_len;
	return FZN_ENTRY_OK;
}
