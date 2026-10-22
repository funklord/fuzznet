#include "pack.h"

#include "../wire/bytes.h"

#include <stdio.h>
#include <string.h>

/* ---- bytes in and out ------------------------------------------------- */

/* A WRITER THAT COUNTS where there is nowhere to write, so one walk sizes
 * a pack and the next writes it. */
typedef struct {
	uint8_t *buf;
	size_t cap, len;
	int over;
} writer_t;

static void put(writer_t *w, const void *b, size_t n)
{
	if (w->buf) {
		if (w->len > w->cap || n > w->cap - w->len)
			w->over = 1;
		else if (n)
			memcpy(w->buf + w->len, b, n);
	}
	w->len += n;
}

static void put8(writer_t *w, unsigned v)
{
	uint8_t b = (uint8_t)v;

	put(w, &b, 1u);
}

static void put16(writer_t *w, unsigned v)
{
	uint8_t b[2];

	fzn_put_be16(b, (uint16_t)v);
	put(w, b, 2u);
}

static void put32(writer_t *w, uint32_t v)
{
	uint8_t b[4];

	fzn_put_be32(b, v);
	put(w, b, 4u);
}

typedef struct {
	const uint8_t *p;
	size_t left;
	int bad;
} reader_t;

static const uint8_t *take(reader_t *r, size_t n)
{
	const uint8_t *at = r->p;

	if (r->bad || n > r->left) {
		r->bad = 1;
		return NULL;
	}
	r->p += n;
	r->left -= n;
	return at;
}

static unsigned get8(reader_t *r)
{
	const uint8_t *b = take(r, 1u);

	return b ? b[0] : 0u;
}

static unsigned get16(reader_t *r)
{
	const uint8_t *b = take(r, 2u);

	return b ? fzn_get_be16(b) : 0u;
}

static uint32_t get32(reader_t *r)
{
	const uint8_t *b = take(r, 4u);

	return b ? fzn_get_be32(b) : 0u;
}

/* TEXT A PERSON READS: no control character and no DEL. Stricter than
 * fuzzypickles' decoder, which took any bytes; their reference refused a
 * line break in a description, and a description is what a reference
 * carries, so a pack holding one made stickers nobody could send. */
static int text_ok(const char *s, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if ((unsigned char)s[i] < 0x20u || (unsigned char)s[i] == 0x7fu)
			return 0;
	return 1;
}

/* ---- a pack ------------------------------------------------------------ */

static void write_pack(writer_t *w, const fzn_sticker_manifest_t *m,
                       const uint32_t art_len[][FZN_STICKER_RENDITIONS_MAX],
                       const uint32_t sound_len[], const uint8_t *const art[][FZN_STICKER_RENDITIONS_MAX],
                       const uint8_t *const sound[], int with_data)
{
	uint32_t at = 0;
	size_t i, k, r;

	put8(w, FZN_STICKER_VERSION);
	put8(w, (unsigned)m->name_len);
	put(w, m->name, m->name_len);
	put8(w, (unsigned)m->count);
	for (i = 0; i < m->count; i++) {
		const fzn_sticker_entry_t *e = &m->entries[i];
		uint32_t audio_at;

		put16(w, e->id);
		put8(w, e->type);
		put16(w, e->flags);
		put8(w, (unsigned)e->description_len);
		put(w, e->description, e->description_len);
		put8(w, (unsigned)e->keyword_count);
		for (k = 0; k < e->keyword_count; k++) {
			put8(w, (unsigned)e->keyword_lens[k]);
			put(w, e->keywords[k], e->keyword_lens[k]);
		}
		put16(w, e->text_limit);
		put16(w, e->text_x);
		put16(w, e->text_y);
		put16(w, e->text_w);
		put16(w, e->text_h);
		/* THE DATA IN ENTRY ORDER: renditions, then the sound. */
		audio_at = at;
		for (r = 0; r < e->rendition_count; r++)
			audio_at += art_len[i][r];
		put32(w, sound_len[i] ? audio_at : 0u);
		put32(w, sound_len[i]);
		put8(w, (unsigned)e->rendition_count);
		for (r = 0; r < e->rendition_count; r++) {
			const fzn_sticker_rendition_t *x = &e->renditions[r];

			put8(w, x->role);
			put8(w, x->format);
			put16(w, x->width);
			put16(w, x->height);
			put32(w, at);
			put32(w, art_len[i][r]);
			at += art_len[i][r];
		}
		at += sound_len[i];
	}
	put32(w, at);
	if (!with_data)
		return;
	for (i = 0; i < m->count; i++) {
		for (r = 0; r < m->entries[i].rendition_count; r++)
			put(w, art[i][r], art_len[i][r]);
		if (sound_len[i])
			put(w, sound[i], sound_len[i]);
	}
}

int fzn_sticker_pack_build(const fzn_sticker_manifest_t *m,
                           const uint8_t *const art[][FZN_STICKER_RENDITIONS_MAX],
                           const uint32_t art_len[][FZN_STICKER_RENDITIONS_MAX],
                           const uint8_t *const sound[], const uint32_t sound_len[],
                           uint8_t *out, size_t cap, size_t *len)
{
	static fzn_sticker_manifest_t check;
	writer_t w;
	uint64_t total = 0;
	size_t i, r;
	const uint8_t *data;
	size_t data_len;

	if (!m || !art || !art_len || !sound || !sound_len || !len || m->count == 0u
	    || m->count > FZN_STICKER_PER_PACK_MAX)
		return 0;
	for (i = 0; i < m->count; i++) {
		if (m->entries[i].rendition_count > FZN_STICKER_RENDITIONS_MAX)
			return 0;
		for (r = 0; r < m->entries[i].rendition_count; r++) {
			if (!art[i][r] || !art_len[i][r])
				return 0;
			total += art_len[i][r];
		}
		if (sound_len[i] && !sound[i])
			return 0;
		total += sound_len[i];
	}
	if (total > FZN_STICKER_PACK_MAX_LEN)
		return 0;
	memset(&w, 0, sizeof(w));
	write_pack(&w, m, art_len, sound_len, art, sound, 1);
	if (w.len > FZN_STICKER_PACK_MAX_LEN)
		return 0;
	*len = w.len;
	if (!out)
		return 1;
	if (cap < w.len)
		return 0;
	memset(&w, 0, sizeof(w));
	w.buf = out;
	w.cap = cap;
	write_pack(&w, m, art_len, sound_len, art, sound, 1);
	/* OPENED AGAIN: a pack built is a pack accepted, or nothing is said to
	 * have been built -- an empty or a repeated description stops here, not
	 * in somebody's conversation. */
	if (w.over || !fzn_sticker_pack_open(out, w.len, &check, &data, &data_len)) {
		/* NOTHING HALF-BUILT LEFT for a caller to take for a pack. */
		memset(out, 0, w.len <= cap ? w.len : cap);
		return 0;
	}
	return 1;
}

static int role_ok(unsigned v)
{
	return v >= FZN_STICKER_THUMB && v <= FZN_STICKER_POPUP_ART;
}

static int format_ok(unsigned v)
{
	return v >= FZN_STICKER_LOTTIE && v <= FZN_STICKER_PNG;
}

static int type_ok(unsigned v)
{
	return v >= FZN_STICKER_STATIC && v <= FZN_STICKER_EMOJI;
}

int fzn_sticker_pack_open(const uint8_t *pack, size_t len, fzn_sticker_manifest_t *out,
                          const uint8_t **data, size_t *data_len)
{
	reader_t rd;
	const uint8_t *b;
	uint32_t dl;
	size_t i, j, k, r;

	if (!pack || !out || !data || !data_len || len > FZN_STICKER_PACK_MAX_LEN)
		return 0;
	memset(out, 0, sizeof(*out));
	rd.p = pack;
	rd.left = len;
	rd.bad = 0;
	if (get8(&rd) != FZN_STICKER_VERSION)
		return 0;
	out->name_len = get8(&rd);
	if (out->name_len > FZN_STICKER_NAME_MAX || !(b = take(&rd, out->name_len)))
		return 0;
	memcpy(out->name, b, out->name_len);
	if (!text_ok(out->name, out->name_len))
		return 0;
	out->count = get8(&rd);
	if (out->count == 0u || out->count > FZN_STICKER_PER_PACK_MAX)
		return 0;
	for (i = 0; i < out->count && !rd.bad; i++) {
		fzn_sticker_entry_t *e = &out->entries[i];

		e->id = (uint16_t)get16(&rd);
		e->type = (uint8_t)get8(&rd);
		e->flags = (uint16_t)get16(&rd);
		e->description_len = get8(&rd);
		if (!type_ok(e->type) || (e->flags & ~FZN_STICKER_FLAGS_KNOWN)
		    || e->description_len == 0u || e->description_len > FZN_STICKER_DESC_MAX
		    || !(b = take(&rd, e->description_len)))
			return 0;
		memcpy(e->description, b, e->description_len);
		if (!text_ok(e->description, e->description_len))
			return 0;
		e->keyword_count = get8(&rd);
		if (e->keyword_count > FZN_STICKER_KEYWORDS_MAX)
			return 0;
		for (k = 0; k < e->keyword_count; k++) {
			e->keyword_lens[k] = get8(&rd);
			if (e->keyword_lens[k] == 0u || e->keyword_lens[k] > FZN_STICKER_KEYWORD_MAX
			    || !(b = take(&rd, e->keyword_lens[k])))
				return 0;
			memcpy(e->keywords[k], b, e->keyword_lens[k]);
			if (!text_ok(e->keywords[k], e->keyword_lens[k]))
				return 0;
		}
		e->text_limit = (uint16_t)get16(&rd);
		e->text_x = (uint16_t)get16(&rd);
		e->text_y = (uint16_t)get16(&rd);
		e->text_w = (uint16_t)get16(&rd);
		e->text_h = (uint16_t)get16(&rd);
		e->audio_offset = get32(&rd);
		e->audio_len = get32(&rd);
		e->rendition_count = get8(&rd);
		if (e->rendition_count == 0u || e->rendition_count > FZN_STICKER_RENDITIONS_MAX)
			return 0;
		for (r = 0; r < e->rendition_count; r++) {
			fzn_sticker_rendition_t *x = &e->renditions[r];

			x->role = (uint8_t)get8(&rd);
			x->format = (uint8_t)get8(&rd);
			x->width = (uint16_t)get16(&rd);
			x->height = (uint16_t)get16(&rd);
			x->offset = get32(&rd);
			x->len = get32(&rd);
			if (!role_ok(x->role) || !format_ok(x->format) || !x->width || !x->height
			    || !x->len)
				return 0;
		}
		/* A SOUND CLAIMED IS A SOUND CARRIED, or the pack fails silently at
		 * the worst moment; a message or name sticker has a box to fill;
		 * an emoji is drawn at text size, so never big. */
		if ((e->flags & FZN_STICKER_FLAG_SOUND) && !e->audio_len)
			return 0;
		if ((e->type == FZN_STICKER_MESSAGE || e->type == FZN_STICKER_NAMED)
		    && (!e->text_limit || !e->text_w || !e->text_h))
			return 0;
		if (e->type == FZN_STICKER_EMOJI && (e->flags & FZN_STICKER_FLAG_BIG))
			return 0;
	}
	dl = get32(&rd);
	if (rd.bad || !(b = take(&rd, dl)) || rd.left)
		return 0;
	/* EVERY RANGE INSIDE THE DATA, in 64 bits so a sum cannot wrap. */
	for (i = 0; i < out->count; i++) {
		const fzn_sticker_entry_t *e = &out->entries[i];

		if (e->audio_len && (uint64_t)e->audio_offset + e->audio_len > dl)
			return 0;
		for (r = 0; r < e->rendition_count; r++)
			if ((uint64_t)e->renditions[r].offset + e->renditions[r].len > dl)
				return 0;
	}
	/* A REFERENCE NAMES A STICKER BY ID, and a person tells two apart by
	 * description: both distinct, or a reference is ambiguous and a screen
	 * reader says the same thing twice. */
	for (i = 0; i < out->count; i++)
		for (j = i + 1u; j < out->count; j++)
			if (out->entries[i].id == out->entries[j].id
			    || (out->entries[i].description_len == out->entries[j].description_len
			        && memcmp(out->entries[i].description, out->entries[j].description,
			                  out->entries[i].description_len) == 0))
				return 0;
	*data = b;
	*data_len = dl;
	return 1;
}

const fzn_sticker_rendition_t *fzn_sticker_pick(const fzn_sticker_entry_t *e,
                                                fzn_sticker_role_t role)
{
	static const uint8_t order[] = { FZN_STICKER_INLINE, FZN_STICKER_MAIN, FZN_STICKER_THUMB,
	                                 FZN_STICKER_POPUP_ART };
	size_t i, o;

	if (!e || !e->rendition_count)
		return NULL;
	for (i = 0; i < e->rendition_count; i++)
		if (e->renditions[i].role == (uint8_t)role)
			return &e->renditions[i];
	for (o = 0; o < sizeof(order); o++)
		for (i = 0; i < e->rendition_count; i++)
			if (e->renditions[i].role == order[o])
				return &e->renditions[i];
	return &e->renditions[0];
}

/* ---- what a kind has --------------------------------------------------- */

int fzn_sticker_field_applies(uint8_t type, uint16_t flags, fzn_sticker_field_t field)
{
	switch (field) {
	case FZN_STICKER_FIELD_DESCRIPTION:
	case FZN_STICKER_FIELD_KEYWORDS:
		return 1;
	case FZN_STICKER_FIELD_AUDIO:
		return (flags & FZN_STICKER_FLAG_SOUND) ? 1 : 0;
	case FZN_STICKER_FIELD_TEXT_BOX:
	case FZN_STICKER_FIELD_TEXT_LIMIT:
		return type == FZN_STICKER_MESSAGE || type == FZN_STICKER_NAMED;
	case FZN_STICKER_FIELD_FLAG_ANIMATED:
		return type != FZN_STICKER_ANIMATED;
	case FZN_STICKER_FIELD_FLAG_BIG:
		return type != FZN_STICKER_EMOJI;
	case FZN_STICKER_FIELD_ROLE_POPUP:
		return type == FZN_STICKER_POPUP;
	}
	/* A FIELD THIS BUILD DOES NOT KNOW applies to nothing, so no editor is
	 * told to offer it. */
	return 0;
}

/* ---- a spec ------------------------------------------------------------ */

int fzn_sticker_path_ok(const char *p, size_t len)
{
	size_t i;

	if (!p || len == 0u || len > FZN_STICKER_PATH_MAX || p[0] == '/' || p[0] == '.')
		return 0;
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)p[i];

		if (c < 0x20u || c == 0x7fu || c == '\\' || c == ':')
			return 0;
		if (c == '.' && i + 1u < len && p[i + 1u] == '.')
			return 0;
	}
	return 1;
}

/* THE NAMES A PERSON TYPES and the values they mean, side by side, read in
 * both directions so the parser and the writer cannot drift apart. */
struct spec_name {
	const char *name;
	unsigned value;
};

static const struct spec_name spec_types[] = {
	{ "static", FZN_STICKER_STATIC },   { "animated", FZN_STICKER_ANIMATED },
	{ "popup", FZN_STICKER_POPUP },     { "effect", FZN_STICKER_EFFECT },
	{ "message", FZN_STICKER_MESSAGE }, { "name", FZN_STICKER_NAMED },
	{ "emoji", FZN_STICKER_EMOJI },     { NULL, 0 },
};

static const struct spec_name spec_flags[] = {
	{ "sound", FZN_STICKER_FLAG_SOUND },
	{ "big", FZN_STICKER_FLAG_BIG },
	{ "animated", FZN_STICKER_FLAG_ANIMATED },
	{ NULL, 0 },
};

static const struct spec_name spec_roles[] = {
	{ "thumb", FZN_STICKER_THUMB }, { "inline", FZN_STICKER_INLINE },
	{ "main", FZN_STICKER_MAIN },   { "popup", FZN_STICKER_POPUP_ART },
	{ NULL, 0 },
};

static const struct spec_name spec_formats[] = {
	{ "lottie", FZN_STICKER_LOTTIE }, { "apng", FZN_STICKER_APNG },
	{ "webp", FZN_STICKER_WEBP },     { "png", FZN_STICKER_PNG },
	{ NULL, 0 },
};

static int is_word(const char *w, size_t n, const char *lit)
{
	return strlen(lit) == n && memcmp(w, lit, n) == 0;
}

static int lookup(const struct spec_name *t, const char *w, size_t n, unsigned *out)
{
	size_t i;

	for (i = 0; t[i].name; i++)
		if (is_word(w, n, t[i].name)) {
			*out = t[i].value;
			return 1;
		}
	return 0;
}

static const char *name_of(const struct spec_name *t, unsigned value)
{
	size_t i;

	for (i = 0; t[i].name; i++)
		if (t[i].value == value)
			return t[i].name;
	return NULL;
}

static size_t word(const char **p, const char *end, const char **w)
{
	const char *s = *p;

	while (s < end && (*s == ' ' || *s == '\t'))
		s++;
	*w = s;
	while (s < end && *s != ' ' && *s != '\t')
		s++;
	*p = s;
	return (size_t)(s - *w);
}

/* THE REST OF THE LINE, blanks trimmed both ends: prose keeps its spaces. */
static size_t rest(const char **p, const char *end, const char **out)
{
	const char *s = *p;
	size_t n;

	while (s < end && (*s == ' ' || *s == '\t'))
		s++;
	*out = s;
	*p = end;
	n = (size_t)(end - s);
	while (n && (s[n - 1u] == ' ' || s[n - 1u] == '\t'))
		n--;
	return n;
}

static int number(const char *w, size_t n, unsigned long limit, unsigned long *out)
{
	unsigned long v = 0;
	size_t i;

	if (n == 0u || n > 10u)
		return 0;
	for (i = 0; i < n; i++) {
		if (w[i] < '0' || w[i] > '9')
			return 0;
		v = v * 10u + (unsigned long)(w[i] - '0');
		if (v > limit)
			return 0;
	}
	*out = v;
	return 1;
}

static int fail(char *err, size_t cap, size_t line, const char *why)
{
	if (err && cap)
		(void)snprintf(err, cap, "line %zu: %s", line, why);
	return 0;
}

int fzn_sticker_spec_parse(const char *text, size_t len, fzn_sticker_manifest_t *out, char *err,
                           size_t err_cap)
{
	fzn_sticker_entry_t *cur = NULL;
	const char *p = text, *text_end = text + len;
	size_t line = 0;

	if (!text || !out)
		return 0;
	if (err && err_cap)
		err[0] = '\0';
	memset(out, 0, sizeof(*out));
	while (p < text_end) {
		const char *nl = memchr(p, '\n', (size_t)(text_end - p));
		const char *end = nl ? nl : text_end, *cursor = p, *kw, *w, *v;
		size_t kw_len, n;

		/* A CR IS THE LINE'S ENDING, not the last word's: trimmed once,
		 * here, for every reader below. */
		if (end > p && end[-1] == '\r')
			end--;
		p = nl ? nl + 1 : text_end;
		line++;
		kw_len = word(&cursor, end, &kw);
		if (kw_len == 0u || kw[0] == '#')
			continue;
		if (is_word(kw, kw_len, "name")) {
			n = rest(&cursor, end, &v);
			if (n == 0u || n > FZN_STICKER_NAME_MAX || !text_ok(v, n))
				return fail(err, err_cap, line, "pack name is empty or too long");
			memcpy(out->name, v, n);
			out->name[n] = '\0';
			out->name_len = n;
			continue;
		}
		if (is_word(kw, kw_len, "sticker")) {
			unsigned long id = 0;
			unsigned type = 0;
			size_t i;

			if (out->count >= FZN_STICKER_PER_PACK_MAX)
				return fail(err, err_cap, line, "too many stickers in one pack");
			n = word(&cursor, end, &w);
			if (!number(w, n, 65535u, &id))
				return fail(err, err_cap, line, "sticker needs a numeric id");
			for (i = 0; i < out->count; i++)
				if (out->entries[i].id == (uint16_t)id)
					return fail(err, err_cap, line, "two stickers share one id");
			n = word(&cursor, end, &w);
			if (!lookup(spec_types, w, n, &type))
				return fail(err, err_cap, line, "unknown sticker type");
			cur = &out->entries[out->count++];
			memset(cur, 0, sizeof(*cur));
			cur->id = (uint16_t)id;
			cur->type = (uint8_t)type;
			while ((n = word(&cursor, end, &w)) > 0u) {
				unsigned flag = 0;

				if (!lookup(spec_flags, w, n, &flag))
					return fail(err, err_cap, line, "unknown flag");
				cur->flags = (uint16_t)(cur->flags | flag);
			}
			continue;
		}
		if (!cur)
			return fail(err, err_cap, line, "line comes before any sticker");
		if (is_word(kw, kw_len, "description")) {
			n = rest(&cursor, end, &v);
			if (n == 0u || n > FZN_STICKER_DESC_MAX || !text_ok(v, n))
				return fail(err, err_cap, line, "description is empty or too long");
			memcpy(cur->description, v, n);
			cur->description[n] = '\0';
			cur->description_len = n;
			continue;
		}
		if (is_word(kw, kw_len, "keyword")) {
			size_t k;

			if (cur->keyword_count >= FZN_STICKER_KEYWORDS_MAX)
				return fail(err, err_cap, line, "too many keywords on one sticker");
			n = rest(&cursor, end, &v);
			if (n == 0u || n > FZN_STICKER_KEYWORD_MAX || !text_ok(v, n))
				return fail(err, err_cap, line, "keyword is empty or too long");
			k = cur->keyword_count++;
			memcpy(cur->keywords[k], v, n);
			cur->keywords[k][n] = '\0';
			cur->keyword_lens[k] = n;
			continue;
		}
		if (is_word(kw, kw_len, "sound")) {
			n = rest(&cursor, end, &v);
			if (!fzn_sticker_path_ok(v, n))
				return fail(err, err_cap, line, "sound path is empty, too long or not inside the spec's directory");
			memcpy(cur->audio_path, v, n);
			cur->audio_path[n] = '\0';
			cur->audio_path_len = n;
			continue;
		}
		if (is_word(kw, kw_len, "text")) {
			unsigned long t[5];
			size_t i;

			for (i = 0; i < 5u; i++) {
				n = word(&cursor, end, &w);
				if (!number(w, n, 65535u, &t[i]))
					return fail(err, err_cap, line,
					            "text needs limit, x, y, width and height");
			}
			cur->text_limit = (uint16_t)t[0];
			cur->text_x = (uint16_t)t[1];
			cur->text_y = (uint16_t)t[2];
			cur->text_w = (uint16_t)t[3];
			cur->text_h = (uint16_t)t[4];
			continue;
		}
		/* A RENDITION: ROLE FORMAT W H PATH. */
		{
			unsigned role = 0, format = 0;
			unsigned long dim[2];
			fzn_sticker_rendition_t *x;
			size_t i;

			if (!lookup(spec_roles, kw, kw_len, &role))
				return fail(err, err_cap, line, "unknown keyword");
			if (cur->rendition_count >= FZN_STICKER_RENDITIONS_MAX)
				return fail(err, err_cap, line, "too many renditions on one sticker");
			n = word(&cursor, end, &w);
			if (!lookup(spec_formats, w, n, &format))
				return fail(err, err_cap, line, "unknown image format");
			for (i = 0; i < 2u; i++) {
				n = word(&cursor, end, &w);
				if (!number(w, n, 65535u, &dim[i]) || dim[i] == 0u)
					return fail(err, err_cap, line, "a rendition needs a width and a height");
			}
			n = rest(&cursor, end, &v);
			/* A PATH IS A FILE BESIDE THE SPEC, never above it: what
			 * builds a pack reads it. */
			if (!fzn_sticker_path_ok(v, n))
				return fail(err, err_cap, line, "rendition path is empty, too long or not inside the spec's directory");
			x = &cur->renditions[cur->rendition_count++];
			x->role = (uint8_t)role;
			x->format = (uint8_t)format;
			x->width = (uint16_t)dim[0];
			x->height = (uint16_t)dim[1];
			memcpy(x->path, v, n);
			x->path[n] = '\0';
			x->path_len = n;
		}
	}
	if (out->name_len == 0u)
		return fail(err, err_cap, line, "the pack has no name");
	if (out->count == 0u)
		return fail(err, err_cap, line, "the pack has no stickers");
	return 1;
}

typedef struct {
	char *buf;
	size_t cap, len;
} spec_out_t;

static void say(spec_out_t *o, const char *s, size_t n)
{
	if (o->buf && o->len <= o->cap && n <= o->cap - o->len)
		memcpy(o->buf + o->len, s, n);
	o->len += n;
}

static void lit(spec_out_t *o, const char *s)
{
	say(o, s, strlen(s));
}

static void num(spec_out_t *o, unsigned v)
{
	char t[8];
	int n = snprintf(t, sizeof(t), "%u", v);

	say(o, t, n > 0 ? (size_t)n : 0u);
}

/* WHY A VALUE CANNOT COME BACK UNCHANGED, or NULL: a line break splits
 * it, and blanks around it are trimmed away. */
static const char *unwritable(const char *s, size_t n)
{
	size_t i;

	if (!n)
		return NULL;
	for (i = 0; i < n; i++)
		if (s[i] == '\n' || s[i] == '\r')
			return "contains a line break";
	if (s[0] == ' ' || s[0] == '\t' || s[n - 1u] == ' ' || s[n - 1u] == '\t')
		return "begins or ends with a space";
	return NULL;
}

static int format_fail(char *err, size_t cap, const fzn_sticker_entry_t *e, const char *what,
                       const char *why)
{
	if (err && cap) {
		if (e)
			(void)snprintf(err, cap, "sticker %u: the %s %s", (unsigned)e->id, what, why);
		else
			(void)snprintf(err, cap, "%s %s", what, why);
	}
	return 0;
}

static int emit(const fzn_sticker_manifest_t *m, spec_out_t *o, char *err, size_t err_cap)
{
	const char *why;
	size_t i, k, r, f;

	if (!m->name_len)
		return format_fail(err, err_cap, NULL, "the pack", "has no name");
	if (!m->count)
		return format_fail(err, err_cap, NULL, "the pack", "has no stickers");
	if ((why = unwritable(m->name, m->name_len)))
		return format_fail(err, err_cap, NULL, "the pack name", why);
	lit(o, "name ");
	say(o, m->name, m->name_len);
	lit(o, "\n");
	for (i = 0; i < m->count; i++) {
		const fzn_sticker_entry_t *e = &m->entries[i];
		const char *type_name = name_of(spec_types, e->type);

		if (!type_name)
			return format_fail(err, err_cap, e, "kind", "has no name in this build");
		if (e->flags & ~FZN_STICKER_FLAGS_KNOWN)
			return format_fail(err, err_cap, e, "flags", "include one this build cannot name");
		lit(o, "\nsticker ");
		num(o, e->id);
		lit(o, " ");
		lit(o, type_name);
		/* IN TABLE ORDER, so two saves of one pack differ nowhere. */
		for (f = 0; spec_flags[f].name; f++)
			if (e->flags & spec_flags[f].value) {
				lit(o, " ");
				lit(o, spec_flags[f].name);
			}
		lit(o, "\n");
		if (e->description_len) {
			if ((why = unwritable(e->description, e->description_len)))
				return format_fail(err, err_cap, e, "description", why);
			lit(o, "description ");
			say(o, e->description, e->description_len);
			lit(o, "\n");
		}
		for (k = 0; k < e->keyword_count; k++) {
			if (!e->keyword_lens[k])
				continue;
			if ((why = unwritable(e->keywords[k], e->keyword_lens[k])))
				return format_fail(err, err_cap, e, "keyword", why);
			lit(o, "keyword ");
			say(o, e->keywords[k], e->keyword_lens[k]);
			lit(o, "\n");
		}
		for (r = 0; r < e->rendition_count; r++) {
			const fzn_sticker_rendition_t *x = &e->renditions[r];
			const char *role_name = name_of(spec_roles, x->role);
			const char *format_name = name_of(spec_formats, x->format);

			if (!role_name || !format_name)
				return format_fail(err, err_cap, e, "rendition", "has no name in this build");
			if (!x->width || !x->height)
				return format_fail(err, err_cap, e, "rendition", "has no size");
			if (!x->path_len)
				return format_fail(err, err_cap, e, "rendition", "names no file");
			if ((why = unwritable(x->path, x->path_len)))
				return format_fail(err, err_cap, e, "rendition path", why);
			lit(o, role_name);
			lit(o, " ");
			lit(o, format_name);
			lit(o, " ");
			num(o, x->width);
			lit(o, " ");
			num(o, x->height);
			lit(o, " ");
			say(o, x->path, x->path_len);
			lit(o, "\n");
		}
		if (e->audio_path_len) {
			if ((why = unwritable(e->audio_path, e->audio_path_len)))
				return format_fail(err, err_cap, e, "sound path", why);
			lit(o, "sound ");
			say(o, e->audio_path, e->audio_path_len);
			lit(o, "\n");
		}
		/* EVERYTHING SET, whether its kind uses it or not: a box kept
		 * across a change of kind is work not lost. */
		if (e->text_limit || e->text_x || e->text_y || e->text_w || e->text_h) {
			lit(o, "text ");
			num(o, e->text_limit);
			lit(o, " ");
			num(o, e->text_x);
			lit(o, " ");
			num(o, e->text_y);
			lit(o, " ");
			num(o, e->text_w);
			lit(o, " ");
			num(o, e->text_h);
			lit(o, "\n");
		}
	}
	return 1;
}

int fzn_sticker_spec_format(const fzn_sticker_manifest_t *m, char *out, size_t cap, size_t *len,
                            char *err, size_t err_cap)
{
	spec_out_t sizing = { NULL, 0, 0 }, writing;

	if (!m || !len)
		return 0;
	if (err && err_cap)
		err[0] = '\0';
	/* COUNTED FIRST, where every refusal happens, so a manifest that cannot
	 * be written is refused before a byte of the caller's is touched. */
	if (!emit(m, &sizing, err, err_cap))
		return 0;
	*len = sizing.len;
	if (!out)
		return 1;
	if (sizing.len > cap)
		return 0;
	writing.buf = out;
	writing.cap = cap;
	writing.len = 0;
	return emit(m, &writing, err, err_cap);
}

/* ---- a reference ------------------------------------------------------- */

static const char SCHEME[] = "fzn:sticker/";
static const char OLD_SCHEME[] = "fzp:sticker/";
#define SCHEME_LEN 12u

int fzn_sticker_ref_format(const fzn_sticker_ref_t *ref, char *out, size_t cap, size_t *len)
{
	static const char HEX[] = "0123456789abcdef";
	char root[2u * FZN_STICKER_ROOT_LEN + 1u], key[2u * FZN_STICKER_KEY_LEN + 1u];
	size_t i;
	int n;

	if (!ref || !out || !len || !ref->length || ref->description_len == 0u
	    || ref->description_len > FZN_STICKER_DESC_MAX)
		return 0;
	for (i = 0; i < ref->description_len; i++)
		if (ref->description[i] == '\n' || ref->description[i] == '\r'
		    || ref->description[i] == '\0')
			return 0;
	for (i = 0; i < FZN_STICKER_ROOT_LEN; i++) {
		root[2u * i] = HEX[ref->root[i] >> 4];
		root[2u * i + 1u] = HEX[ref->root[i] & 15u];
		key[2u * i] = HEX[ref->key[i] >> 4];
		key[2u * i + 1u] = HEX[ref->key[i] & 15u];
	}
	root[2u * FZN_STICKER_ROOT_LEN] = key[2u * FZN_STICKER_KEY_LEN] = '\0';
	n = snprintf(out, cap, "%s%s/%s/%llu/%u %.*s", SCHEME, root, key,
	             (unsigned long long)ref->length, (unsigned)ref->id, (int)ref->description_len,
	             ref->description);
	if (n < 0 || (size_t)n >= cap)
		return 0;
	*len = (size_t)n;
	return 1;
}

static int hex_field(const char **p, const char *end, uint8_t *out, size_t n)
{
	size_t i;

	for (i = 0; i < 2u * n; i++) {
		char c;
		int v;

		if (*p >= end)
			return 0;
		c = *(*p)++;
		v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
		if (v < 0)
			return 0;
		if (i % 2u == 0u)
			out[i / 2u] = (uint8_t)(v << 4);
		else
			out[i / 2u] = (uint8_t)(out[i / 2u] | v);
	}
	if (*p >= end || **p != '/')
		return 0;
	(*p)++;
	return 1;
}

int fzn_sticker_ref_parse(const char *text, size_t len, fzn_sticker_ref_t *out)
{
	const char *p, *end;
	unsigned id = 0;
	size_t digits = 0, desc_len, i;
	int ours;

	if (!text || !out || len <= SCHEME_LEN || len > FZN_STICKER_REF_MAX)
		return 0;
	ours = memcmp(text, SCHEME, SCHEME_LEN) == 0;
	if (!ours && memcmp(text, OLD_SCHEME, SCHEME_LEN) != 0)
		return 0;
	memset(out, 0, sizeof(*out));
	p = text + SCHEME_LEN;
	end = text + len;
	if (!hex_field(&p, end, out->root, FZN_STICKER_ROOT_LEN)
	    || !hex_field(&p, end, out->key, FZN_STICKER_KEY_LEN))
		return 0;
	/* THE LENGTH, ours alone: at most twenty digits, past which it would
	 * overflow, and never 0. */
	if (ours) {
		uint64_t length = 0;

		while (p < end && *p >= '0' && *p <= '9') {
			unsigned d = (unsigned)(*p++ - '0');

			if (++digits > 20u || length > (UINT64_MAX - d) / 10u)
				return 0;
			length = length * 10u + d;
		}
		if (!digits || !length || p >= end || *p != '/')
			return 0;
		p++;
		out->length = length;
		digits = 0;
	}
	while (p < end && *p >= '0' && *p <= '9') {
		/* FIVE DIGITS AT MOST, which cannot overflow. */
		if (++digits > 5u)
			return 0;
		id = id * 10u + (unsigned)(*p++ - '0');
	}
	if (!digits || id > 0xffffu || p >= end || *p != ' ')
		return 0;
	p++;
	desc_len = (size_t)(end - p);
	if (desc_len == 0u || desc_len > FZN_STICKER_DESC_MAX)
		return 0;
	/* WHAT FORMAT REFUSES, PARSE REFUSES: a description no client could
	 * have written is no reference. */
	for (i = 0; i < desc_len; i++)
		if (p[i] == '\n' || p[i] == '\r' || p[i] == '\0')
			return 0;
	out->id = (uint16_t)id;
	memcpy(out->description, p, desc_len);
	out->description[desc_len] = '\0';
	out->description_len = desc_len;
	return 1;
}
