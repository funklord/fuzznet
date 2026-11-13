#include "pack.h"

#include "../wire/bytes.h"
#include "../hex/hex.h"

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

static void put64(writer_t *w, uint64_t v)
{
	uint8_t b[8];

	fzn_put_be64(b, v);
	put(w, b, 8u);
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

static uint64_t get64(reader_t *r)
{
	const uint8_t *b = take(r, 8u);

	return b ? fzn_get_be64(b) : 0u;
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
	put64(w, m->id);
	put64(w, m->line_package);
	put8(w, (unsigned)m->name_len);
	put(w, m->name, m->name_len);
	put32(w, (uint32_t)m->count);
	for (i = 0; i < m->count; i++) {
		const fzn_sticker_entry_t *e = &m->entries[i];
		uint32_t audio_at;

		put64(w, e->id);
		put64(w, e->line_id);
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
		put32(w, e->text_fill);
		put32(w, e->text_ink);
		put16(w, e->text_turn);
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

static int open_pack(const uint8_t *pack, size_t len, fzn_sticker_manifest_t *out,
                     const uint8_t **data, size_t *data_len);

int fzn_sticker_pack_why(const fzn_sticker_manifest_t *m,
                         const uint8_t *const art[][FZN_STICKER_RENDITIONS_MAX],
                         const uint32_t art_len[][FZN_STICKER_RENDITIONS_MAX],
                         const uint8_t *const sound[], const uint32_t sound_len[], char *why,
                         size_t cap)
{
	size_t i, j, r;

	if (!m || !m->entries || !art || !art_len || !sound || !sound_len || !why || !cap)
		return 0;
	why[0] = '\0';
	for (i = 0; i < m->count; i++) {
		const fzn_sticker_entry_t *e = &m->entries[i];

		if (!e->id) {
			(void)snprintf(why, cap, "sticker %zu has no id", i + 1u);
			return 1;
		}
		for (j = i + 1u; j < m->count; j++)
			if (e->id == m->entries[j].id) {
				(void)snprintf(why, cap,
				               "stickers %zu and %zu have one id, %llu (the same art, or "
				               "the same number given twice)",
				               i + 1u, j + 1u, (unsigned long long)e->id);
				return 1;
			}
		for (r = 0; r < e->rendition_count && r < FZN_STICKER_RENDITIONS_MAX; r++)
			if (!art[i][r] || !art_len[i][r]) {
				(void)snprintf(why, cap, "sticker %zu (id %llu) has no art for its rendition %zu",
				               i + 1u, (unsigned long long)e->id, r + 1u);
				return 1;
			}
		if ((sound_len[i] && !sound[i]) || ((e->flags & FZN_STICKER_FLAG_SOUND) && !sound_len[i])) {
			(void)snprintf(why, cap, "sticker %zu (id %llu) is flagged sound and has none",
			               i + 1u, (unsigned long long)e->id);
			return 1;
		}
		if ((e->type == FZN_STICKER_MESSAGE || e->type == FZN_STICKER_NAMED)
		    && (!e->text_limit || !e->text_w || !e->text_h)) {
			(void)snprintf(why, cap, "sticker %zu (id %llu, %s) has no text box", i + 1u,
			               (unsigned long long)e->id,
			               e->type == FZN_STICKER_MESSAGE ? "message" : "name");
			return 1;
		}
		if (e->type == FZN_STICKER_EMOJI && (e->flags & FZN_STICKER_FLAG_BIG)) {
			(void)snprintf(why, cap, "sticker %zu (id %llu) is an emoji and cannot be big",
			               i + 1u, (unsigned long long)e->id);
			return 1;
		}
	}
	return 0;
}

int fzn_sticker_pack_build(const fzn_sticker_manifest_t *m,
                           const uint8_t *const art[][FZN_STICKER_RENDITIONS_MAX],
                           const uint32_t art_len[][FZN_STICKER_RENDITIONS_MAX],
                           const uint8_t *const sound[], const uint32_t sound_len[],
                           uint8_t *out, size_t cap, size_t *len)
{
	writer_t w;
	uint64_t total = 0;
	size_t i, j, r;

	/* THE PACK'S OWN ID nonzero, sec 859: `fzn_sticker_derive_ids` sets it
	 * from the art, and a pack is never built without one. */
	if (!m || !m->entries || !art || !art_len || !sound || !sound_len || !len || m->count == 0u
	    || m->count > m->cap || m->count > UINT32_MAX || !m->id)
		return 0;
	/* IDS NONZERO AND DISTINCT, checked on the caller's entries: the pack
	 * opened again below is read one sticker at a time into no room. */
	for (i = 0; i < m->count; i++) {
		if (!m->entries[i].id)
			return 0;
		for (j = i + 1u; j < m->count; j++)
			if (m->entries[i].id == m->entries[j].id)
				return 0;
	}
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
	 * have been built -- a sound flag with no sound, or a message sticker
	 * with no box, stops here, not in somebody's conversation. */
	if (w.over || !open_pack(out, w.len, NULL, NULL, NULL)) {
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

/* ONE STICKER read into `e`, version `v`'s layout: 1, or 0. */
static int read_entry(reader_t *rd, unsigned v, fzn_sticker_entry_t *e)
{
	const uint8_t *b;
	size_t k, r;

	memset(e, 0, sizeof(*e));
	if (v == FZN_STICKER_VERSION_1) {
		e->id = get16(rd);
	} else {
		e->id = get64(rd);
		e->line_id = get64(rd);
	}
	e->type = (uint8_t)get8(rd);
	e->flags = (uint16_t)get16(rd);
	e->description_len = get8(rd);
	/* A DESCRIPTION OPTIONAL SINCE VERSION 2, sec 702; an id nonzero. */
	if (rd->bad || !e->id || !type_ok(e->type) || (e->flags & ~FZN_STICKER_FLAGS_KNOWN)
	    || (v == FZN_STICKER_VERSION_1 && e->description_len == 0u)
	    || e->description_len > FZN_STICKER_DESC_MAX || !(b = take(rd, e->description_len)))
		return 0;
	if (e->description_len)
		memcpy(e->description, b, e->description_len);
	if (!text_ok(e->description, e->description_len))
		return 0;
	e->keyword_count = get8(rd);
	if (e->keyword_count > FZN_STICKER_KEYWORDS_MAX)
		return 0;
	for (k = 0; k < e->keyword_count; k++) {
		e->keyword_lens[k] = get8(rd);
		if (e->keyword_lens[k] == 0u || e->keyword_lens[k] > FZN_STICKER_KEYWORD_MAX
		    || !(b = take(rd, e->keyword_lens[k])))
			return 0;
		memcpy(e->keywords[k], b, e->keyword_lens[k]);
		if (!text_ok(e->keywords[k], e->keyword_lens[k]))
			return 0;
	}
	e->text_limit = (uint16_t)get16(rd);
	e->text_x = (uint16_t)get16(rd);
	e->text_y = (uint16_t)get16(rd);
	e->text_w = (uint16_t)get16(rd);
	e->text_h = (uint16_t)get16(rd);
	/* THE BOX'S PAINT, version 3's, sec 859; a turn past a full circle is
	 * no turn anybody drew. */
	if (v >= FZN_STICKER_VERSION) {
		e->text_fill = get32(rd);
		e->text_ink = get32(rd);
		e->text_turn = (uint16_t)get16(rd);
		if (e->text_turn > FZN_STICKER_TURN_MAX)
			return 0;
	}
	e->audio_offset = get32(rd);
	e->audio_len = get32(rd);
	e->rendition_count = get8(rd);
	if (e->rendition_count == 0u || e->rendition_count > FZN_STICKER_RENDITIONS_MAX)
		return 0;
	for (r = 0; r < e->rendition_count; r++) {
		fzn_sticker_rendition_t *x = &e->renditions[r];

		x->role = (uint8_t)get8(rd);
		x->format = (uint8_t)get8(rd);
		x->width = (uint16_t)get16(rd);
		x->height = (uint16_t)get16(rd);
		x->offset = get32(rd);
		x->len = get32(rd);
		if (!role_ok(x->role) || !format_ok(x->format) || !x->width || !x->height || !x->len)
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
	return !rd->bad;
}

/* EVERY RANGE OF `e` INSIDE THE DATA, in 64 bits so a sum cannot wrap. */
static int inside(const fzn_sticker_entry_t *e, uint32_t dl)
{
	size_t r;

	if (e->audio_len && (uint64_t)e->audio_offset + e->audio_len > dl)
		return 0;
	for (r = 0; r < e->rendition_count; r++)
		if ((uint64_t)e->renditions[r].offset + e->renditions[r].len > dl)
			return 0;
	return 1;
}

/* THE PACK OPENED, into `out`'s room -- or, `out` NULL, only checked, each
 * sticker read into one entry here and let go, which is how a build checks
 * what it wrote with no room of its own (fuzzypickles' 140d719 does so). */
static int open_pack(const uint8_t *pack, size_t len, fzn_sticker_manifest_t *out,
                     const uint8_t **data, size_t *data_len)
{
	static fzn_sticker_entry_t one;
	reader_t rd, first;
	const uint8_t *b;
	uint32_t dl;
	uint64_t line_package = 0, pack_id = 0;
	size_t name_len, count, i, j;
	unsigned v;

	if (!pack || len > FZN_STICKER_PACK_MAX_LEN)
		return 0;
	rd.p = pack;
	rd.left = len;
	rd.bad = 0;
	v = get8(&rd);
	if (v != FZN_STICKER_VERSION && v != FZN_STICKER_VERSION_2 && v != FZN_STICKER_VERSION_1)
		return 0;
	/* THE PACK'S OWN ID, version 3's and nonzero, sec 859. */
	if (v >= FZN_STICKER_VERSION) {
		pack_id = get64(&rd);
		if (!pack_id)
			return 0;
	}
	if (v >= FZN_STICKER_VERSION_2)
		line_package = get64(&rd);
	name_len = get8(&rd);
	if (name_len > FZN_STICKER_NAME_MAX || !(b = take(&rd, name_len))
	    || !text_ok((const char *)b, name_len))
		return 0;
	if (out) {
		out->id = pack_id;
		out->line_package = line_package;
		out->name_len = name_len;
		if (name_len)
			memcpy(out->name, b, name_len);
		out->name[name_len] = '\0';
	}
	count = v >= FZN_STICKER_VERSION_2 ? get32(&rd) : get8(&rd);
	if (rd.bad || count == 0u || (v == FZN_STICKER_VERSION_1 && count > FZN_STICKER_PER_PACK_MAX_1))
		return 0;
	/* NO ROOM FOR THEM is said, never a truncated pack: the count needed. */
	if (out) {
		out->count = count;
		if (count > out->cap || !out->entries)
			return 0;
	}
	first = rd;
	for (i = 0; i < count; i++)
		if (!read_entry(&rd, v, out ? &out->entries[i] : &one))
			return 0;
	dl = get32(&rd);
	if (rd.bad || !(b = take(&rd, dl)) || rd.left)
		return 0;
	if (out) {
		for (i = 0; i < count; i++)
			if (!inside(&out->entries[i], dl))
				return 0;
	} else {
		/* READ AGAIN, now the data's length is known. */
		for (i = 0; i < count; i++)
			if (!read_entry(&first, v, &one) || !inside(&one, dl))
				return 0;
	}
	/* A REFERENCE NAMES A STICKER BY ID: distinct, or a reference is
	 * ambiguous. Descriptions may repeat since version 2, being optional;
	 * version 1's were distinct, and a pack of it still holds to that. */
	if (out)
		for (i = 0; i < count; i++)
			for (j = i + 1u; j < count; j++)
				if (out->entries[i].id == out->entries[j].id
				    || (v == FZN_STICKER_VERSION_1
				        && out->entries[i].description_len
				                   == out->entries[j].description_len
				        && memcmp(out->entries[i].description, out->entries[j].description,
				                  out->entries[i].description_len)
				                   == 0))
					return 0;
	if (data)
		*data = b;
	if (data_len)
		*data_len = dl;
	return 1;
}

int fzn_sticker_pack_open(const uint8_t *pack, size_t len, fzn_sticker_manifest_t *out,
                          const uint8_t **data, size_t *data_len)
{
	fzn_sticker_entry_t *entries;
	size_t cap;

	if (!pack || !out || !data || !data_len)
		return 0;
	entries = out->entries;
	cap = out->cap;
	memset(out, 0, sizeof(*out));
	out->entries = entries;
	out->cap = cap;
	if (open_pack(pack, len, out, data, data_len))
		return 1;
	/* WANTING ROOM ALONE keeps the count asked for; anything else is no
	 * pack, and says nothing to size. */
	if (!(out->count > out->cap))
		out->count = 0;
	return 0;
}

int fzn_sticker_derive_ids(fzn_sticker_manifest_t *m,
                           const uint8_t *const art[][FZN_STICKER_RENDITIONS_MAX],
                           const uint32_t art_len[][FZN_STICKER_RENDITIONS_MAX],
                           const uint8_t *const sound[], const uint32_t sound_len[],
                           const fzn_hash_ops_t *hash, uint8_t *scratch, size_t scratch_cap)
{
	size_t i, r;

	if (!m || !m->entries || m->count > m->cap || !art || !art_len || !sound || !sound_len
	    || !hash || !hash->hash || !scratch)
		return 0;
	for (i = 0; i < m->count; i++) {
		fzn_sticker_entry_t *e = &m->entries[i];
		uint8_t digest[32];
		size_t at = 0;
		uint64_t id = 0;

		if (e->id)
			continue;
		if (e->rendition_count > FZN_STICKER_RENDITIONS_MAX)
			return 0;
		for (r = 0; r <= e->rendition_count; r++) {
			const uint8_t *bytes = r < e->rendition_count ? art[i][r] : sound[i];
			size_t n = r < e->rendition_count ? art_len[i][r] : sound_len[i];

			if (!n)
				continue;
			if (!bytes || n > scratch_cap - at)
				return 0;
			memcpy(scratch + at, bytes, n);
			at += n;
		}
		/* THE SEAM'S OWN CONVENTION, 1 for a hash (session/commitment.h). */
		if (hash->hash(hash->ctx, digest, sizeof(digest), scratch, at) != 1)
			return 0;
		for (r = 0; r < 8u; r++)
			id = (id << 8) | digest[r];
		e->id = id ? id : 1u;
	}
	return fzn_sticker_pack_id(m, art, art_len, sound, sound_len, hash, scratch, scratch_cap,
	                           &m->id);
}

int fzn_sticker_pack_id(const fzn_sticker_manifest_t *m,
                        const uint8_t *const art[][FZN_STICKER_RENDITIONS_MAX],
                        const uint32_t art_len[][FZN_STICKER_RENDITIONS_MAX],
                        const uint8_t *const sound[], const uint32_t sound_len[],
                        const fzn_hash_ops_t *hash, uint8_t *scratch, size_t scratch_cap,
                        uint64_t *id)
{
	uint8_t sum[32], digest[32];
	size_t i, r;
	uint64_t v = 0;

	if (!m || !m->entries || m->count > m->cap || !art || !art_len || !sound || !sound_len
	    || !hash || !hash->hash || !scratch || !id)
		return 0;
	memset(sum, 0, sizeof(sum));
	for (i = 0; i < m->count; i++) {
		const fzn_sticker_entry_t *e = &m->entries[i];
		size_t at = 0;
		unsigned carry = 0;

		if (e->rendition_count > FZN_STICKER_RENDITIONS_MAX)
			return 0;
		for (r = 0; r <= e->rendition_count; r++) {
			const uint8_t *bytes = r < e->rendition_count ? art[i][r] : sound[i];
			size_t n = r < e->rendition_count ? art_len[i][r] : sound_len[i];

			if (!n)
				continue;
			if (!bytes || n > scratch_cap - at)
				return 0;
			memcpy(scratch + at, bytes, n);
			at += n;
		}
		if (hash->hash(hash->ctx, digest, sizeof(digest), scratch, at) != 1)
			return 0;
		/* ADDED, little endian, modulo 2^256: the order of the stickers
		 * plays no part. */
		for (r = 0; r < sizeof(sum); r++) {
			carry += (unsigned)sum[r] + digest[r];
			sum[r] = (uint8_t)carry;
			carry >>= 8;
		}
	}
	if (hash->hash(hash->ctx, digest, sizeof(digest), sum, sizeof(sum)) != 1)
		return 0;
	for (r = 0; r < 8u; r++)
		v = (v << 8) | digest[r];
	*id = v ? v : 1u;
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

/* RRGGBBAA, eight hex digits of either case, sec 859. */
static int rgba(const char *w, size_t n, uint32_t *out)
{
	size_t i;
	uint32_t v = 0;

	if (n != 8u)
		return 0;
	for (i = 0; i < n; i++) {
		char c = w[i];
		unsigned d = c >= '0' && c <= '9'   ? (unsigned)(c - '0')
		             : c >= 'a' && c <= 'f' ? (unsigned)(c - 'a' + 10)
		             : c >= 'A' && c <= 'F' ? (unsigned)(c - 'A' + 10)
		                                    : 16u;

		if (d > 15u)
			return 0;
		v = (v << 4) | d;
	}
	*out = v;
	return 1;
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

/* A 64-BIT DECIMAL, nonzero, no leading zero, overflow refused. */
static int number64(const char *w, size_t n, uint64_t *out)
{
	uint64_t v = 0;
	size_t i;

	if (n == 0u || n > 20u || w[0] == '0')
		return 0;
	for (i = 0; i < n; i++) {
		unsigned d;

		if (w[i] < '0' || w[i] > '9')
			return 0;
		d = (unsigned)(w[i] - '0');
		if (v > (UINT64_MAX - d) / 10u)
			return 0;
		v = v * 10u + d;
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

/* A SPEC REFUSED for what it says, not for room: no count left that reads
 * as FZN_STICKER_TOO_SMALL. */
static int refuse(fzn_sticker_manifest_t *out, char *err, size_t cap, size_t line, const char *why)
{
	out->count = 0;
	return fail(err, cap, line, why);
}

int fzn_sticker_spec_parse(const char *text, size_t len, fzn_sticker_manifest_t *out, char *err,
                           size_t err_cap)
{
	/* PAST THE ROOM, each further sticker is read here and let go, so its
	 * lines are still checked and the count still made. */
	static fzn_sticker_entry_t spare;
	fzn_sticker_entry_t *cur = NULL, *entries;
	const char *p = text, *text_end;
	size_t line = 0, cap;

	/* THE END AFTER THE CHECK: `text + len` on a null `text` is arithmetic
	 * on a null pointer, undefined however large `len` (cppcheck). */
	if (!text || !out)
		return 0;
	text_end = text + len;
	if (err && err_cap)
		err[0] = '\0';
	entries = out->entries;
	cap = out->cap;
	memset(out, 0, sizeof(*out));
	out->entries = entries;
	out->cap = cap;
	if (!entries)
		cap = out->cap = 0;
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
				return refuse(out, err, err_cap, line, "pack name is empty or too long");
			memcpy(out->name, v, n);
			out->name[n] = '\0';
			out->name_len = n;
			continue;
		}
		/* LINE'S PACKAGE, the pack's alone, sec 702. */
		if (is_word(kw, kw_len, "line_package")) {
			n = word(&cursor, end, &w);
			if (!number64(w, n, &out->line_package) || word(&cursor, end, &v))
				return refuse(out, err, err_cap, line, "line_package needs LINE's package number");
			continue;
		}
		if (is_word(kw, kw_len, "sticker")) {
			uint64_t id = 0;
			unsigned type = 0;
			size_t i;

			/* THE ID OPTIONAL, sec 702: `sticker 7 static` keeps 7, and
			 * `sticker static` takes one from its art when it is built. */
			n = word(&cursor, end, &w);
			if (n && w[0] >= '0' && w[0] <= '9') {
				if (!number64(w, n, &id))
					return refuse(out, err, err_cap, line,
					            "a sticker id is a number from 1 to 2^64-1");
				for (i = 0; i < out->count && i < cap; i++)
					if (out->entries[i].id == id)
						return refuse(out, err, err_cap, line, "two stickers share one id");
				n = word(&cursor, end, &w);
			}
			if (!lookup(spec_types, w, n, &type))
				return refuse(out, err, err_cap, line, "unknown sticker type");
			cur = out->count < cap ? &out->entries[out->count] : &spare;
			out->count++;
			memset(cur, 0, sizeof(*cur));
			cur->id = id;
			cur->type = (uint8_t)type;
			while ((n = word(&cursor, end, &w)) > 0u) {
				unsigned flag = 0;

				if (!lookup(spec_flags, w, n, &flag))
					return refuse(out, err, err_cap, line, "unknown flag");
				cur->flags = (uint16_t)(cur->flags | flag);
			}
			continue;
		}
		if (!cur)
			return refuse(out, err, err_cap, line, "line comes before any sticker");
		if (is_word(kw, kw_len, "line_id")) {
			n = word(&cursor, end, &w);
			if (!number64(w, n, &cur->line_id) || word(&cursor, end, &v))
				return refuse(out, err, err_cap, line, "line_id needs LINE's sticker number");
			continue;
		}
		if (is_word(kw, kw_len, "description")) {
			n = rest(&cursor, end, &v);
			if (n == 0u || n > FZN_STICKER_DESC_MAX || !text_ok(v, n))
				return refuse(out, err, err_cap, line, "description is empty or too long");
			memcpy(cur->description, v, n);
			cur->description[n] = '\0';
			cur->description_len = n;
			continue;
		}
		if (is_word(kw, kw_len, "keyword")) {
			size_t k;

			if (cur->keyword_count >= FZN_STICKER_KEYWORDS_MAX)
				return refuse(out, err, err_cap, line, "too many keywords on one sticker");
			n = rest(&cursor, end, &v);
			if (n == 0u || n > FZN_STICKER_KEYWORD_MAX || !text_ok(v, n))
				return refuse(out, err, err_cap, line, "keyword is empty or too long");
			k = cur->keyword_count++;
			memcpy(cur->keywords[k], v, n);
			cur->keywords[k][n] = '\0';
			cur->keyword_lens[k] = n;
			continue;
		}
		if (is_word(kw, kw_len, "sound")) {
			n = rest(&cursor, end, &v);
			if (!fzn_sticker_path_ok(v, n))
				return refuse(out, err, err_cap, line, "sound path is empty, too long or not inside the spec's directory");
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
					return refuse(out, err, err_cap, line,
					            "text needs limit, x, y, width and height");
			}
			/* AND THE BOX'S FILL, INK AND TURN, each optional in that
			 * order, sec 859 -- fuzzypickles' grammar: RRGGBBAA twice,
			 * 00000000 none, so an ink is given alone behind a fill of
			 * none; then 0 to 359 degrees clockwise. */
			{
				const char *x;
				unsigned long turn = 0;
				uint32_t paint[2] = { 0, 0 };
				size_t k;

				for (k = 0; k < 2u; k++) {
					n = word(&cursor, end, &x);
					if (!n)
						break;
					if (!rgba(x, n, &paint[k]))
						return refuse(out, err, err_cap, line,
						              k ? "a text ink is RRGGBBAA" : "a text fill is RRGGBBAA");
				}
				if (k == 2u && (n = word(&cursor, end, &x)) != 0
				    && !number(x, n, FZN_STICKER_TURN_MAX, &turn))
					return refuse(out, err, err_cap, line, "a text turn is 0 to 359 degrees");
				cur->text_fill = paint[0];
				cur->text_ink = paint[1];
				cur->text_turn = (uint16_t)turn;
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
				return refuse(out, err, err_cap, line, "unknown keyword");
			if (cur->rendition_count >= FZN_STICKER_RENDITIONS_MAX)
				return refuse(out, err, err_cap, line, "too many renditions on one sticker");
			n = word(&cursor, end, &w);
			if (!lookup(spec_formats, w, n, &format))
				return refuse(out, err, err_cap, line, "unknown image format");
			for (i = 0; i < 2u; i++) {
				n = word(&cursor, end, &w);
				if (!number(w, n, 65535u, &dim[i]) || dim[i] == 0u)
					return refuse(out, err, err_cap, line, "a rendition needs a width and a height");
			}
			n = rest(&cursor, end, &v);
			/* A PATH IS A FILE BESIDE THE SPEC, never above it: what
			 * builds a pack reads it. */
			if (!fzn_sticker_path_ok(v, n))
				return refuse(out, err, err_cap, line, "rendition path is empty, too long or not inside the spec's directory");
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
	if (out->count == 0u)
		return refuse(out, err, err_cap, line, "the pack has no stickers");
	/* NO ROOM FOR THEM ALL: said, with the count needed. */
	if (out->count > cap)
		return fail(err, err_cap, line, "more stickers than the room given");
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

static void num(spec_out_t *o, uint64_t v)
{
	char t[24];
	int n = snprintf(t, sizeof(t), "%llu", (unsigned long long)v);

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
			(void)snprintf(err, cap, "sticker %llu: the %s %s", (unsigned long long)e->id,
			               what, why);
		else
			(void)snprintf(err, cap, "%s %s", what, why);
	}
	return 0;
}

static int emit(const fzn_sticker_manifest_t *m, spec_out_t *o, char *err, size_t err_cap)
{
	const char *why;
	size_t i, k, r, f;

	if (!m->count || !m->entries || m->count > m->cap)
		return format_fail(err, err_cap, NULL, "the pack", "has no stickers");
	if ((why = unwritable(m->name, m->name_len)))
		return format_fail(err, err_cap, NULL, "the pack name", why);
	/* A NAME AND LINE'S PACKAGE ONLY WHERE SET, sec 702. */
	if (m->name_len) {
		lit(o, "name ");
		say(o, m->name, m->name_len);
		lit(o, "\n");
	}
	if (m->line_package) {
		lit(o, "line_package ");
		num(o, m->line_package);
		lit(o, "\n");
	}
	for (i = 0; i < m->count; i++) {
		const fzn_sticker_entry_t *e = &m->entries[i];
		const char *type_name = name_of(spec_types, e->type);

		if (!type_name)
			return format_fail(err, err_cap, e, "kind", "has no name in this build");
		if (e->flags & ~FZN_STICKER_FLAGS_KNOWN)
			return format_fail(err, err_cap, e, "flags", "include one this build cannot name");
		lit(o, "\nsticker ");
		/* AN ID NOT YET DERIVED is left out, as a person writes it. */
		if (e->id) {
			num(o, e->id);
			lit(o, " ");
		}
		lit(o, type_name);
		/* IN TABLE ORDER, so two saves of one pack differ nowhere. */
		for (f = 0; spec_flags[f].name; f++)
			if (e->flags & spec_flags[f].value) {
				lit(o, " ");
				lit(o, spec_flags[f].name);
			}
		lit(o, "\n");
		if (e->line_id) {
			lit(o, "line_id ");
			num(o, e->line_id);
			lit(o, "\n");
		}
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
			/* THE PAINT, as far as the last one set, sec 859. */
			if (e->text_fill || e->text_ink || e->text_turn) {
				char paint[12];

				(void)snprintf(paint, sizeof(paint), " %08lX", (unsigned long)e->text_fill);
				lit(o, paint);
				if (e->text_ink || e->text_turn) {
					(void)snprintf(paint, sizeof(paint), " %08lX",
					               (unsigned long)e->text_ink);
					lit(o, paint);
				}
				if (e->text_turn) {
					lit(o, " ");
					num(o, e->text_turn);
				}
			}
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

/* An upper-case hex digit's value, or -1: a lower-case escape is another
 * spelling of the same words, and refused. */
static int upper_hex(char c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

/* A BYTE A STICKER'S WORDS WRITE PLAIN, fuzzypickles' unreserved set. */
static int text_plain(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
	       || c == '.' || c == '_' || c == '~';
}

/* WORDS A PERSON COULD HAVE TYPED: well-formed UTF-8, no overlong form or
 * surrogate, and no control character, C1 included -- what every client
 * can draw. Not empty. */
static int text_valid(const unsigned char *t, size_t n)
{
	size_t i = 0;

	if (n == 0u || n > FZN_STICKER_TEXT_MAX)
		return 0;
	while (i < n) {
		unsigned c = t[i], cp, need, k;

		if (c < 0x80u) {
			if (c < 0x20u || c == 0x7fu)
				return 0;
			i++;
			continue;
		}
		if (c >= 0xc2u && c <= 0xdfu)
			need = 1u, cp = c & 0x1fu;
		else if (c >= 0xe0u && c <= 0xefu)
			need = 2u, cp = c & 0x0fu;
		else if (c >= 0xf0u && c <= 0xf4u)
			need = 3u, cp = c & 0x07u;
		else
			return 0;
		/* ITS CONTINUATION BYTES, all of them inside the words. */
		if (n - i <= need)
			return 0;
		for (k = 1u; k <= need; k++) {
			if ((t[i + k] & 0xc0u) != 0x80u)
				return 0;
			cp = (cp << 6) | (t[i + k] & 0x3fu);
		}
		if ((need == 2u && cp < 0x800u) || (need == 3u && (cp < 0x10000u || cp > 0x10ffffu))
		    || (cp >= 0xd800u && cp <= 0xdfffu) || (cp >= 0x80u && cp <= 0x9fu))
			return 0;
		i += 1u + need;
	}
	return 1;
}

int fzn_sticker_ref_format(const fzn_sticker_ref_t *ref, char *out, size_t cap, size_t *len)
{
	char root[2u * FZN_STICKER_ROOT_LEN + 1u], key[2u * FZN_STICKER_KEY_LEN + 1u];
	size_t i;
	int n;

	if (!ref || !out || !len || !ref->length || !ref->id
	    || ref->description_len > FZN_STICKER_DESC_MAX)
		return 0;
	for (i = 0; i < ref->description_len; i++)
		if (ref->description[i] == '\n' || ref->description[i] == '\r'
		    || ref->description[i] == '\0')
			return 0;
	for (i = 0; i < FZN_STICKER_ROOT_LEN; i++) {
		fzn_hex_byte(ref->root[i], root + 2u * i);
		fzn_hex_byte(ref->key[i], key + 2u * i);
	}
	root[2u * FZN_STICKER_ROOT_LEN] = key[2u * FZN_STICKER_KEY_LEN] = '\0';
	if (ref->text_len && !text_valid((const unsigned char *)ref->text, ref->text_len))
		return 0;
	n = snprintf(out, cap, "%s%s/%s/%llu/%llu", SCHEME, root, key,
	             (unsigned long long)ref->length, (unsigned long long)ref->id);
	if (n < 0 || (size_t)n >= cap)
		return 0;
	/* THE WORDS, sec 830, escaped as fuzzypickles escapes them. */
	if (ref->text_len) {
		size_t at = (size_t)n;

		if (at + 1u >= cap)
			return 0;
		out[at++] = ':';
		for (i = 0; i < ref->text_len; i++) {
			unsigned char c = (unsigned char)ref->text[i];

			if (text_plain(c)) {
				if (at + 1u >= cap)
					return 0;
				out[at++] = (char)c;
			} else {
				if (at + 3u >= cap)
					return 0;
				out[at++] = '%';
				out[at++] = "0123456789ABCDEF"[c >> 4];
				out[at++] = "0123456789ABCDEF"[c & 15u];
			}
		}
		n = (int)at;
	}
	/* THE DESCRIPTION WHERE THERE IS ONE, sec 702: without, the reference
	 * ends at the id or the words. SHORTENED TO FIT what a message carries,
	 * sec 980, at a character's start: the most words a sticker may have,
	 * escaped, and the longest description came to 533 bytes, and the
	 * reference was refused where the words and the art it names were fine.
	 * The description is a reader's aid; the words are the sticker's. */
	if (ref->description_len && (size_t)n + 1u < FZN_STICKER_REF_SENT_MAX) {
		size_t keep = ref->description_len, room = FZN_STICKER_REF_SENT_MAX - (size_t)n - 1u;

		if (keep > room) {
			keep = room;
			while (keep && ((unsigned char)ref->description[keep] & 0xC0u) == 0x80u)
				keep--;
		}
		if (keep) {
			if ((size_t)n + 1u + keep >= cap)
				return 0;
			out[n++] = ' ';
			memcpy(out + n, ref->description, keep);
			n += (int)keep;
		}
	}
	out[n] = '\0';
	if ((size_t)n > FZN_STICKER_REF_SENT_MAX)
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
	const char *p, *end, *first;
	uint64_t id = 0;
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
	 * overflow. NO LEADING ZERO, here or in the id, so one sticker has one
	 * spelling, as an attachment's size does (sec 794) -- which, for the
	 * length, also refuses 0. */
	if (ours) {
		uint64_t length = 0;

		first = p;
		while (p < end && *p >= '0' && *p <= '9') {
			unsigned d = (unsigned)(*p++ - '0');

			if (++digits > 20u || length > (UINT64_MAX - d) / 10u)
				return 0;
			length = length * 10u + d;
		}
		if (!digits || *first == '0' || p >= end || *p != '/')
			return 0;
		p++;
		out->length = length;
		digits = 0;
	}
	/* THE ID, 64 bits since sec 702, overflow refused digit by digit, and
	 * never 0. */
	first = p;
	while (p < end && *p >= '0' && *p <= '9') {
		unsigned d = (unsigned)(*p++ - '0');

		if (++digits > 20u || id > (UINT64_MAX - d) / 10u)
			return 0;
		id = id * 10u + d;
	}
	if (!digits || *first == '0' || (p < end && *p != ' ' && *p != ':'))
		return 0;
	/* THE WORDS, sec 830: one spelling each, as format writes them -- an
	 * escape in upper case, of a byte not written plain, and every other
	 * byte plain -- so what parses formats back to itself. A reference
	 * may end at its id since sec 702, so `p` may be its end already. */
	if (p < end && *p == ':') {
		size_t t = 0;

		p++;
		while (p < end && *p != ' ') {
			unsigned char c = (unsigned char)*p;

			if (t == FZN_STICKER_TEXT_MAX)
				return 0;
			if (c == '%') {
				int hi, lo;

				if (end - p < 3)
					return 0;
				hi = upper_hex(p[1]);
				lo = upper_hex(p[2]);
				if (hi < 0 || lo < 0 || text_plain((unsigned char)(hi * 16 + lo)))
					return 0;
				out->text[t++] = (char)(hi * 16 + lo);
				p += 3;
			} else {
				if (!text_plain(c))
					return 0;
				out->text[t++] = (char)c;
				p++;
			}
		}
		if (!text_valid((const unsigned char *)out->text, t))
			return 0;
		out->text[t] = '\0';
		out->text_len = t;
	}
	out->id = id;
	/* NO DESCRIPTION, sec 702: the reference ends here. */
	if (p == end)
		return 1;
	if (*p != ' ')
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
	memcpy(out->description, p, desc_len);
	out->description[desc_len] = '\0';
	out->description_len = desc_len;
	return 1;
}
