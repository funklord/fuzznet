/* See import.h. */

#include "import.h"

#include "text.h"
#include "../wire/bytes.h"

#include <string.h>

/* A title and labels must fit inline with whatever text a note carries; the
 * text alone may be a blob. These bound the scratch, not what is accepted:
 * `fzn_note_content` is what refuses a note that will not fit. */
#define TITLE_CAP FZN_NOTE_CONTENT_MAX
#define LABELS_CAP FZN_NOTE_CONTENT_MAX
#define ITEM_CAP 0xffffu

/* The scratch a parsed note lives in while its callback runs. */
static uint8_t title[TITLE_CAP], text[FZN_NOTE_TEXT_MAX], labels[LABELS_CAP];
static uint8_t item[ITEM_CAP];

static void refuse(fzn_notes_import_refused_fn fn, void *ctx, fzn_notes_import_refusal_t why,
                   const uint8_t *t, size_t t_len)
{
	if (fn)
		fn(ctx, why, t, t_len);
}

/* ---- Keep: just enough JSON ---------------------------------------------- */

typedef enum str_result { STR_OK, STR_LONG, STR_BAD } str_result_t;

static int is_space(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static int hex4(const uint8_t *s, size_t len, size_t at, unsigned *out)
{
	unsigned v = 0;
	size_t i;

	if (len < at + 4u)
		return 0;
	for (i = 0; i < 4u; i++) {
		uint8_t c = s[at + i];

		v <<= 4;
		if (c >= '0' && c <= '9')
			v |= (unsigned)(c - '0');
		else if (c >= 'a' && c <= 'f')
			v |= (unsigned)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F')
			v |= (unsigned)(c - 'A' + 10);
		else
			return 0;
	}
	*out = v;
	return 1;
}

/* Append `n` bytes, or note that the value ran past `cap`. */
static void put(uint8_t *out, size_t cap, size_t *n, const uint8_t *b, size_t k, int *over)
{
	if (*over || !out || cap - *n < k) {
		*over = 1;
		return;
	}
	memcpy(out + *n, b, k);
	*n += k;
}

static void put_utf8(uint8_t *out, size_t cap, size_t *n, unsigned cp, int *over)
{
	uint8_t b[4];
	size_t k;

	if (cp < 0x80u) {
		b[0] = (uint8_t)cp;
		k = 1;
	} else if (cp < 0x800u) {
		b[0] = (uint8_t)(0xc0u | (cp >> 6));
		b[1] = (uint8_t)(0x80u | (cp & 0x3fu));
		k = 2;
	} else if (cp < 0x10000u) {
		b[0] = (uint8_t)(0xe0u | (cp >> 12));
		b[1] = (uint8_t)(0x80u | ((cp >> 6) & 0x3fu));
		b[2] = (uint8_t)(0x80u | (cp & 0x3fu));
		k = 3;
	} else {
		b[0] = (uint8_t)(0xf0u | (cp >> 18));
		b[1] = (uint8_t)(0x80u | ((cp >> 12) & 0x3fu));
		b[2] = (uint8_t)(0x80u | ((cp >> 6) & 0x3fu));
		b[3] = (uint8_t)(0x80u | (cp & 0x3fu));
		k = 4;
	}
	put(out, cap, n, b, k, over);
}

/*
 * Decode the string at `*at` (its opening quote) into `out`, leaving `*at`
 * past its closing quote. LONG when it ran past `cap` -- the whole string is
 * still walked, so the caller can go on -- and BAD when it is not a string.
 * `out` may be NULL to skip one.
 */
static str_result_t json_string(const uint8_t *s, size_t len, size_t *at, uint8_t *out,
                                size_t cap, size_t *out_len)
{
	size_t i = *at, n = 0;
	int over = 0;

	if (i >= len || s[i] != '"')
		return STR_BAD;
	for (i++; i < len; i++) {
		uint8_t c = s[i];
		unsigned cp, low;

		if (c == '"') {
			*at = i + 1u;
			if (out_len)
				*out_len = n;
			return out && over ? STR_LONG : STR_OK;
		}
		if (c != '\\') {
			put(out, cap, &n, &c, 1u, &over);
			continue;
		}
		if (++i >= len)
			return STR_BAD;
		switch (s[i]) {
		case 'n': c = '\n'; break;
		case 't': c = '\t'; break;
		case 'r': c = '\r'; break;
		case 'b': c = '\b'; break;
		case 'f': c = '\f'; break;
		case '"': c = '"'; break;
		case '\\': c = '\\'; break;
		case '/': c = '/'; break;
		case 'u':
			/* \uXXXX, and a surrogate pair as one code point. A lone
			 * surrogate is no character, so the note is refused rather
			 * than given one. */
			if (!hex4(s, len, i + 1u, &cp))
				return STR_BAD;
			i += 4u;
			if (cp >= 0xdc00u && cp <= 0xdfffu)
				return STR_BAD;
			if (cp >= 0xd800u && cp <= 0xdbffu) {
				if (len < i + 7u || s[i + 1u] != '\\' || s[i + 2u] != 'u'
				    || !hex4(s, len, i + 3u, &low) || low < 0xdc00u || low > 0xdfffu)
					return STR_BAD;
				i += 6u;
				cp = 0x10000u + ((cp - 0xd800u) << 10) + (low - 0xdc00u);
			}
			put_utf8(out, cap, &n, cp, &over);
			continue;
		default:
			return STR_BAD;
		}
		put(out, cap, &n, &c, 1u, &over);
	}
	return STR_BAD; /* unterminated */
}

/* After a key string ending at `at`: the value's start past its colon, or 0
 * when it was no key. */
static size_t key_value(const uint8_t *s, size_t len, size_t at)
{
	while (at < len && is_space(s[at]))
		at++;
	if (at >= len || s[at] != ':')
		return 0;
	for (at++; at < len && is_space(s[at]); at++)
		;
	return at;
}

static int key_is(const uint8_t *k, size_t k_len, const char *name)
{
	return k_len == strlen(name) && memcmp(k, name, k_len) == 0;
}

static int is_true(const uint8_t *s, size_t len, size_t at)
{
	return len - at >= 4u && memcmp(s + at, "true", 4u) == 0;
}

static uint64_t parse_uint(const uint8_t *s, size_t len, size_t at)
{
	uint64_t v = 0;
	size_t n = 0;

	for (; at < len && s[at] >= '0' && s[at] <= '9'; at++, n++) {
		if (v > (UINT64_MAX - (uint64_t)(s[at] - '0')) / 10u)
			return 0; /* absurd: as absent */
		v = (v * 10u) + (uint64_t)(s[at] - '0');
	}
	return n ? v : 0u;
}

enum { IN_NONE, IN_LIST, IN_LABELS };

fzn_notes_err_t fzn_notes_import_keep(const uint8_t *json, size_t len, fzn_notes_import_fn fn,
                                      void *ctx, fzn_notes_import_refused_fn refused,
                                      void *refused_ctx)
{
	fzn_notes_import_entry_t e;
	size_t i = 0, depth = 0, in_depth = 0, item_len = 0;
	int in = IN_NONE, pending = IN_NONE, have_list = 0, item_checked = 0, have_item = 0;
	int bad = 0, too_long = 0;

	if (!json || !fn)
		return FZN_NOTES_ERR_MALFORMED;
	memset(&e, 0, sizeof(e));
	e.content_type = FZN_NOTE_TYPE_NOTE;
	e.title = title;
	e.text = text;
	e.labels = labels;

	while (i < len && !bad) {
		uint8_t c = json[i];
		size_t v;
		uint8_t key[32];
		size_t key_len = 0;
		str_result_t r;

		if (c == '{' || c == '[') {
			depth++;
			if (c == '[' && pending != IN_NONE && depth == 2u) {
				in = pending;
				in_depth = depth;
			}
			pending = IN_NONE;
			if (c == '{' && in != IN_NONE && depth == in_depth + 1u) {
				item_len = 0;
				item_checked = 0;
				have_item = 0;
			}
			i++;
			continue;
		}
		if (c == '}' || c == ']') {
			if (c == '}' && in != IN_NONE && depth == in_depth + 1u && have_item) {
				if (in == IN_LIST) {
					/* flags (u8) | text_len (u16) | text, notes/note.h */
					uint8_t head[3];
					size_t n = e.text_len;
					int over = 0;

					head[0] = item_checked ? FZN_NOTE_ITEM_FLAG_CHECKED : 0u;
					fzn_put_be16(head + 1, (uint16_t)item_len);
					put(text, sizeof(text), &n, head, 3u, &over);
					put(text, sizeof(text), &n, item, item_len, &over);
					too_long |= over;
					e.text_len = n;
				} else if (item_len > 0u) {
					size_t n = e.labels_len;
					int over = 0;
					const uint8_t nul = 0;

					/* A label with a NUL in it would split into two. */
					if (memchr(item, 0, item_len))
						bad = 1;
					if (n)
						put(labels, sizeof(labels), &n, &nul, 1u, &over);
					put(labels, sizeof(labels), &n, item, item_len, &over);
					too_long |= over;
					e.labels_len = n;
				}
			}
			if (c == ']' && in != IN_NONE && depth == in_depth)
				in = IN_NONE;
			if (depth)
				depth--;
			i++;
			continue;
		}
		if (c != '"') {
			i++;
			continue;
		}
		/* A string: a key when a colon follows it. */
		{
			size_t at = i;

			r = json_string(json, len, &at, key, sizeof(key), &key_len);
			if (r == STR_BAD) {
				bad = 1;
				break;
			}
			v = key_value(json, len, at);
			if (!v || r == STR_LONG) {
				i = at;
				continue;
			}
			i = v;
		}
		if (depth == 1u) {
			if (key_is(key, key_len, "title"))
				r = json_string(json, len, &i, title, sizeof(title), &e.title_len);
			else if (key_is(key, key_len, "textContent") && !have_list)
				r = json_string(json, len, &i, text, sizeof(text), &e.text_len);
			else if (key_is(key, key_len, "listContent")) {
				/* THE LIST WINS over any text beside it: Keep writes one or
				 * the other, and a list's items are what the note is. */
				have_list = 1;
				e.content_type = FZN_NOTE_TYPE_LIST;
				e.text_len = 0;
				pending = IN_LIST;
				continue;
			} else if (key_is(key, key_len, "labels")) {
				pending = IN_LABELS;
				continue;
			} else if (key_is(key, key_len, "isPinned")) {
				e.flags |= is_true(json, len, i) ? FZN_NOTE_FLAG_PINNED : 0u;
				continue;
			} else if (key_is(key, key_len, "isArchived")) {
				e.flags |= is_true(json, len, i) ? FZN_NOTE_FLAG_ARCHIVED : 0u;
				continue;
			} else if (key_is(key, key_len, "isTrashed")) {
				e.flags |= is_true(json, len, i) ? FZN_NOTE_FLAG_TRASHED : 0u;
				continue;
			} else if (key_is(key, key_len, "createdTimestampUsec")) {
				e.created_at_ms = parse_uint(json, len, i) / 1000u;
				continue;
			} else {
				continue;
			}
		} else if (in != IN_NONE && depth == in_depth + 1u
		           && ((in == IN_LIST && key_is(key, key_len, "text"))
		               || (in == IN_LABELS && key_is(key, key_len, "name")))) {
			r = json_string(json, len, &i, item, sizeof(item), &item_len);
			have_item = 1;
		} else if (in == IN_LIST && depth == in_depth + 1u
		           && key_is(key, key_len, "isChecked")) {
			item_checked = is_true(json, len, i);
			have_item = 1;
			continue;
		} else {
			continue;
		}
		/* A value that is not a string, where one was expected. */
		if (r == STR_BAD) {
			if (i < len && json[i] != '"')
				continue;
			bad = 1;
		}
		too_long |= r == STR_LONG;
	}

	if (bad) {
		refuse(refused, refused_ctx, FZN_NOTES_IMPORT_UNPARSED, title, e.title_len);
		return FZN_NOTES_OK;
	}
	if (too_long) {
		refuse(refused, refused_ctx, FZN_NOTES_IMPORT_TOO_LONG, title, e.title_len);
		return FZN_NOTES_OK;
	}
	if (e.title_len == 0u && e.text_len == 0u) {
		refuse(refused, refused_ctx, FZN_NOTES_IMPORT_UNPARSED, title, 0u);
		return FZN_NOTES_OK;
	}
	return fn(ctx, &e) ? FZN_NOTES_ERR_FULL : FZN_NOTES_OK;
}

/* ---- KNotes: iCalendar VJOURNAL ---------------------------------------- */

/* A logical line, unfolded: room for an escaped text at the bound. */
static uint8_t line[(2u * FZN_NOTE_TEXT_MAX) + 1024u];

/* Unfold the line at `*at` into `line`; 0 when it ran past the buffer, and
 * the rest of it is still consumed. */
static int ics_line(const uint8_t *s, size_t len, size_t *at, size_t *line_len)
{
	size_t i = *at, n = 0;
	int fits = 1;

	for (;;) {
		for (; i < len && s[i] != '\n'; i++) {
			if (s[i] == '\r')
				continue;
			if (n < sizeof(line))
				line[n++] = s[i];
			else
				fits = 0;
		}
		if (i < len)
			i++;
		/* A line starting with a space or a tab continues the last. */
		if (i < len && (s[i] == ' ' || s[i] == '\t')) {
			i++;
			continue;
		}
		break;
	}
	*at = i;
	*line_len = n;
	return fits;
}

static int upper_eq(uint8_t a, char b)
{
	return (a >= 'a' && a <= 'z' ? (uint8_t)(a - 32) : a) == (uint8_t)b;
}

/* The value of property `name` -- its parameters skipped -- or NULL. Names
 * are case-insensitive (RFC 5545 section 3.1). */
static const uint8_t *ics_value(size_t line_len, const char *name, size_t *v_len)
{
	size_t n = strlen(name), i;

	if (line_len <= n)
		return NULL;
	for (i = 0; i < n; i++)
		if (!upper_eq(line[i], name[i]))
			return NULL;
	if (line[n] != ':' && line[n] != ';')
		return NULL;
	for (i = n; i < line_len && line[i] != ':'; i++)
		;
	if (i >= line_len)
		return NULL;
	*v_len = line_len - i - 1u;
	return line + i + 1u;
}

/* TEXT unescaping (RFC 5545 section 3.3.11): \n, \N, and an escaped
 * character as itself. 0 when it ran past `cap`. */
static int ics_unescape(const uint8_t *v, size_t v_len, uint8_t *out, size_t cap,
                        size_t *out_len)
{
	size_t i, n = 0;

	for (i = 0; i < v_len; i++) {
		uint8_t c = v[i];

		if (c == '\\' && i + 1u < v_len) {
			c = v[++i];
			if (c == 'n' || c == 'N')
				c = '\n';
		}
		if (n == cap)
			return 0;
		out[n++] = c;
	}
	*out_len = n;
	return 1;
}

/* YYYYMMDDTHHMMSSZ, UTC only; 0 for anything else. */
static uint64_t ics_datetime_ms(const uint8_t *v, size_t len)
{
	unsigned y, mo, d, h, mi, s;
	long long era, yoe, doy, doe, days;
	unsigned ye;
	size_t i;

	if (len != 16u || v[8] != 'T' || v[15] != 'Z')
		return 0;
	for (i = 0; i < 15u; i++)
		if (i != 8u && (v[i] < '0' || v[i] > '9'))
			return 0;
#define D2(a) (((unsigned)(v[a] - '0') * 10u) + (unsigned)(v[(a) + 1] - '0'))
	y = (D2(0) * 100u) + D2(2);
	mo = D2(4);
	d = D2(6);
	h = D2(9);
	mi = D2(11);
	s = D2(13);
#undef D2
	if (mo < 1u || mo > 12u || d < 1u || d > 31u || h > 23u || mi > 59u || s > 60u)
		return 0;
	/* Days from the civil date, Howard Hinnant's algorithm, as theirs. */
	ye = mo <= 2u ? y - 1u : y;
	era = (long long)ye / 400;
	yoe = (long long)ye - (era * 400);
	doy = ((153 * ((long long)mo + (mo > 2u ? -3 : 9)) + 2) / 5) + d - 1;
	doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy;
	days = (era * 146097) + doe - 719468;
	if (days < 0)
		return 0;
	return (((uint64_t)days * 86400u) + (h * 3600u) + (mi * 60u) + s) * 1000u;
}

fzn_notes_err_t fzn_notes_import_knotes(const uint8_t *ics, size_t len, fzn_notes_import_fn fn,
                                        void *ctx, fzn_notes_import_refused_fn refused,
                                        void *refused_ctx)
{
	fzn_notes_import_entry_t e;
	size_t at = 0, line_len = 0;
	int in = 0, too_long = 0;

	if (!ics || !fn)
		return FZN_NOTES_ERR_MALFORMED;
	memset(&e, 0, sizeof(e));
	while (at < len) {
		const uint8_t *v;
		size_t v_len = 0;
		int fits = ics_line(ics, len, &at, &line_len);

		if (line_len >= 14u && memcmp(line, "BEGIN:VJOURNAL", 14u) == 0) {
			/* RESET WHOLE, the time included, or one entry's key becomes
			 * the next one's and a re-import matches the wrong note. */
			memset(&e, 0, sizeof(e));
			e.content_type = FZN_NOTE_TYPE_NOTE;
			e.title = title;
			e.text = text;
			e.labels = labels;
			in = 1;
			too_long = 0;
			continue;
		}
		if (!in)
			continue;
		if (line_len >= 12u && memcmp(line, "END:VJOURNAL", 12u) == 0) {
			in = 0;
			if (too_long)
				refuse(refused, refused_ctx, FZN_NOTES_IMPORT_TOO_LONG, title, e.title_len);
			else if (e.title_len == 0u && e.text_len == 0u)
				refuse(refused, refused_ctx, FZN_NOTES_IMPORT_UNPARSED, title, 0u);
			else if (fn(ctx, &e))
				return FZN_NOTES_ERR_FULL;
			continue;
		}
		/* NOTHING CUT: a line past the buffer is this note refused. */
		if (!fits) {
			too_long = 1;
			continue;
		}
		if ((v = ics_value(line_len, "SUMMARY", &v_len)) != NULL)
			too_long |= !ics_unescape(v, v_len, title, sizeof(title), &e.title_len);
		else if ((v = ics_value(line_len, "DESCRIPTION", &v_len)) != NULL)
			too_long |= !ics_unescape(v, v_len, text, sizeof(text), &e.text_len);
		else if ((v = ics_value(line_len, "CREATED", &v_len)) != NULL)
			e.created_at_ms = ics_datetime_ms(v, v_len);
		/* DTSTAMP IS NOT TAKEN. fuzzypickles used it when CREATED was
		 * absent; it is when the export was written, the same for every
		 * note in a file, so it would be stored as each note's creation
		 * time -- a date the note does not have. Undated is the honest
		 * answer, and is counted. */
	}
	/* A VJOURNAL begun and never ended is a truncated file: refused, since
	 * half a note stored as a whole one is the silent loss this refuses. */
	if (in)
		refuse(refused, refused_ctx, FZN_NOTES_IMPORT_UNPARSED, title, e.title_len);
	return FZN_NOTES_OK;
}

/* ---- the run ------------------------------------------------------------- */

void fzn_notes_import_refuse(void *ctx, fzn_notes_import_refusal_t why, const uint8_t *t,
                             size_t t_len)
{
	fzn_notes_import_run_t *run = (fzn_notes_import_run_t *)ctx;

	if (!run)
		return;
	run->refused++;
	if (run->on_refused)
		run->on_refused(run->refused_ctx, why, t, t_len);
}

/* Whether a note with this creation time and title is held already. */
static int imported_before(const fzn_notes_import_run_t *run,
                           const fzn_notes_import_entry_t *e)
{
	const fzn_notes_view_t *view = run->author->view;
	size_t i;

	if (fzn_notes_view_load(run->author->store, run->author->view) != FZN_NOTES_OK)
		return 0;
	for (i = 0; i < view->count; i++) {
		fzn_note_t note;

		if (fzn_note_open(view->nodes[i].content_type, view->nodes[i].content,
		                  view->nodes[i].content_len, &note)
		            == FZN_NOTE_OK
		    && note.created_at_ms == e->created_at_ms && note.title_len == e->title_len
		    && memcmp(note.title, e->title, e->title_len) == 0)
			return 1;
	}
	return 0;
}

int fzn_notes_import_take(void *ctx, const fzn_notes_import_entry_t *e)
{
	fzn_notes_import_run_t *run = (fzn_notes_import_run_t *)ctx;
	uint8_t id[FZN_TREE_ID_LEN], ref_bytes[FZN_NOTE_BLOB_REF_LEN];
	fzn_note_t note;
	fzn_notes_err_t err;
	size_t ignored = 0;
	static uint8_t probe[FZN_TREE_CONTENT_MAX];

	if (!run || !run->author || !e)
		return 1;
	if (e->created_at_ms && imported_before(run, e)) {
		run->already++;
		return 0;
	}
	memset(&note, 0, sizeof(note));
	note.title = e->title;
	note.title_len = e->title_len;
	note.text = e->text;
	note.text_len = e->text_len;
	note.labels = e->labels;
	note.labels_len = e->labels_len;
	note.flags = e->flags;
	/* INLINE WHEN IT FITS; otherwise the text is sealed and the note
	 * carries its reference. Nothing is shortened to make it fit. */
	if (fzn_note_content(&note, probe, sizeof(probe), &ignored) != FZN_NOTE_OK) {
		fzn_note_blob_ref_t ref;

		if (!run->seal) {
			fzn_notes_import_refuse(run, FZN_NOTES_IMPORT_NO_SEAL, e->title, e->title_len);
			return 0;
		}
		if (!run->seal(run->seal_ctx, e->text, e->text_len, &ref)
		    || fzn_note_blob_ref_write(&ref, ref_bytes) != FZN_NOTE_OK) {
			fzn_notes_import_refuse(run, FZN_NOTES_IMPORT_FAILED, e->title, e->title_len);
			return 0;
		}
		note.text = ref_bytes;
		note.text_len = sizeof(ref_bytes);
		note.flags |= FZN_NOTE_FLAG_TEXT_IS_BLOB;
	}
	err = fzn_notes_create_dated(run->author, run->folder, e->content_type, &note,
	                             e->created_at_ms, run->now_ms, id);
	if (err != FZN_NOTES_OK) {
		/* A title and labels too long to sit beside a reference land
		 * here, as does a store that refused: named either way. */
		fzn_notes_import_refuse(run, err == FZN_NOTES_ERR_MALFORMED ? FZN_NOTES_IMPORT_TOO_LONG
		                                                             : FZN_NOTES_IMPORT_FAILED,
		                        e->title, e->title_len);
		return err == FZN_NOTES_ERR_FULL;
	}
	run->imported++;
	if (!e->created_at_ms)
		run->undated++;
	return 0;
}
