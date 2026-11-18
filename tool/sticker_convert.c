/*
 * AN OLD STICKER PACK BUILT AGAIN AS THE CURRENT ONE, sec 1278:
 * `sticker_convert OLD NEW`.
 *
 * `sticker/pack.c` reads version 5 and nothing else, the holder's of
 * 2026-11-18. A pack of version 1 to 4 is read here, under the caps it was
 * written to, and built again as 5 by `fzn_sticker_pack_build` -- its
 * stickers, art and sound as they were, and a pack id from its art where
 * 1 and 2 carried none. The build checks every rule a current pack holds
 * to, so what this writes is a pack the reader opens.
 *
 * A PROGRAM OF ITS OWN so that it goes without touching anything else:
 * once nobody holds a pack from before version 5, delete this file, its
 * test `tool/sticker_convert_test.c`, and their lines in the Makefile.
 *
 * Exit 0 with NEW written (or nothing written for a pack already of
 * version 5, which says so), 1 for anything that is no old pack, 2 on
 * usage.
 */
#include "../sticker/pack.h"
#include "../session/hash_monocypher.h"
#include "../wire/bytes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* THE OLD VERSIONS' CAPS: version 1's 64 stickers, 16-bit ids and
 * descriptions of 1 to 96, distinct; 2's and 3's 32 phrases of 24; 4's 128
 * of 64; a name of 48 and a description of 96 in all four. 1 and 2 carry
 * no pack id, 1 and 2 no paint on a box. */
#define NAME_MAX_OLD 48u
#define DESC_MAX_OLD 96u
#define PER_PACK_MAX_1 64u

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

/* ONE STICKER of version `v` into `e`, its layout and caps: 1, or 0. The
 * rules about kinds, sounds and boxes are the build's to hold. */
static int read_entry(reader_t *rd, unsigned v, fzn_sticker_entry_t *e)
{
	const size_t phrases = v == 4u ? 128u : 32u, phrase = v == 4u ? 64u : 24u;
	const uint8_t *b;
	size_t k, r;

	memset(e, 0, sizeof(*e));
	if (v == 1u) {
		e->id = get16(rd);
	} else {
		e->id = get64(rd);
		e->line_id = get64(rd);
	}
	e->type = (uint8_t)get8(rd);
	e->flags = (uint16_t)get16(rd);
	e->description_len = get8(rd);
	if (rd->bad || (v == 1u && e->description_len == 0u) || e->description_len > DESC_MAX_OLD
	    || !(b = take(rd, e->description_len)))
		return 0;
	memcpy(e->description, b, e->description_len);
	e->keyword_count = get8(rd);
	if (e->keyword_count > phrases)
		return 0;
	for (k = 0; k < e->keyword_count; k++) {
		e->keyword_lens[k] = get8(rd);
		if (e->keyword_lens[k] == 0u || e->keyword_lens[k] > phrase
		    || !(b = take(rd, e->keyword_lens[k])))
			return 0;
		memcpy(e->keywords[k], b, e->keyword_lens[k]);
	}
	e->text_limit = (uint16_t)get16(rd);
	e->text_x = (uint16_t)get16(rd);
	e->text_y = (uint16_t)get16(rd);
	e->text_w = (uint16_t)get16(rd);
	e->text_h = (uint16_t)get16(rd);
	if (v >= 3u) {
		e->text_fill = get32(rd);
		e->text_ink = get32(rd);
		e->text_turn = (uint16_t)get16(rd);
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
	}
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

/* AN OLD PACK OPENED into `m`, its entries allocated here, the data area's
 * start in `*data`: 1, or 0. Version 1's descriptions distinct, as it
 * held them. */
static int open_old(const uint8_t *pack, size_t len, fzn_sticker_manifest_t *m, const uint8_t **data)
{
	reader_t rd = { pack, len, 0 };
	const uint8_t *b;
	uint32_t dl;
	size_t count, i, j;
	unsigned v = get8(&rd);

	memset(m, 0, sizeof(*m));
	if (v < 1u || v > 4u)
		return 0;
	if (v >= 3u && !(m->id = get64(&rd)))
		return 0;
	if (v >= 2u)
		m->line_package = get64(&rd);
	m->name_len = get8(&rd);
	if (m->name_len > NAME_MAX_OLD || !(b = take(&rd, m->name_len)))
		return 0;
	memcpy(m->name, b, m->name_len);
	count = v >= 2u ? get32(&rd) : get8(&rd);
	if (rd.bad || count == 0u || (v == 1u && count > PER_PACK_MAX_1)
	    || count > len / 30u || !(m->entries = calloc(count, sizeof(m->entries[0]))))
		return 0;
	m->cap = m->count = count;
	for (i = 0; i < count; i++)
		if (!read_entry(&rd, v, &m->entries[i]))
			return 0;
	dl = get32(&rd);
	if (rd.bad || !(*data = take(&rd, dl)) || rd.left)
		return 0;
	for (i = 0; i < count; i++) {
		if (!inside(&m->entries[i], dl))
			return 0;
		for (j = i + 1u; v == 1u && j < count; j++)
			if (m->entries[i].description_len == m->entries[j].description_len
			    && !memcmp(m->entries[i].description, m->entries[j].description,
			               m->entries[i].description_len))
				return 0;
	}
	return 1;
}

/* THE OLD PACK BUILT AGAIN AS 5: the bytes, `*out_len`, the caller's to
 * free; NULL for no old pack, or one its build refuses. */
static uint8_t *convert(const uint8_t *old, size_t old_len, size_t *out_len)
{
	const uint8_t *data = NULL, *(*art)[FZN_STICKER_RENDITIONS_MAX] = NULL, **sound = NULL;
	uint32_t(*art_len)[FZN_STICKER_RENDITIONS_MAX] = NULL, *sound_len = NULL;
	fzn_sticker_manifest_t m;
	fzn_hash_ops_t hash;
	uint8_t *out = NULL, *scratch = NULL;
	size_t largest = 1u, i, r;

	fzn_hash_monocypher_init(&hash);
	if (!open_old(old, old_len, &m, &data))
		goto done;
	art = calloc(m.count, sizeof(*art));
	art_len = calloc(m.count, sizeof(*art_len));
	sound = calloc(m.count, sizeof(*sound));
	sound_len = calloc(m.count, sizeof(*sound_len));
	if (!art || !art_len || !sound || !sound_len)
		goto done;
	for (i = 0; i < m.count; i++) {
		const fzn_sticker_entry_t *e = &m.entries[i];
		size_t one = e->audio_len;

		for (r = 0; r < e->rendition_count; r++) {
			art[i][r] = data + e->renditions[r].offset;
			art_len[i][r] = e->renditions[r].len;
			one += e->renditions[r].len;
		}
		if (e->audio_len) {
			sound[i] = data + e->audio_offset;
			sound_len[i] = e->audio_len;
		}
		if (one > largest)
			largest = one;
	}
	/* A PACK ID FROM ITS ART, sec 859, where versions 1 and 2 had none. */
	if (!m.id
	    && (!(scratch = malloc(largest))
	        || !fzn_sticker_pack_id(&m, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                                (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                                (const uint8_t *const *)sound, sound_len, &hash, scratch,
	                                largest, &m.id)))
		goto done;
	if (!fzn_sticker_pack_build(&m, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                            (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                            (const uint8_t *const *)sound, sound_len, NULL, 0, out_len)
	    || !(out = malloc(*out_len)))
		goto done;
	if (!fzn_sticker_pack_build(&m, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                            (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                            (const uint8_t *const *)sound, sound_len, out, *out_len, out_len)) {
		free(out);
		out = NULL;
	}
done:
	free(scratch);
	free(art);
	free(art_len);
	free(sound);
	free(sound_len);
	free(m.entries);
	return out;
}

int main(int argc, char **argv)
{
	uint8_t *old, *made;
	size_t old_len = 0, made_len = 0;
	long size;
	FILE *f;

	if (argc != 3) {
		fprintf(stderr, "usage: sticker_convert OLD NEW\n");
		return 2;
	}
	if (!(f = fopen(argv[1], "rb")) || fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) <= 0
	    || (unsigned long)size > FZN_STICKER_PACK_MAX_LEN || fseek(f, 0, SEEK_SET) != 0
	    || !(old = malloc((size_t)size)) || fread(old, 1u, (size_t)size, f) != (size_t)size) {
		fprintf(stderr, "sticker_convert: %s would not read\n", argv[1]);
		if (f)
			(void)fclose(f);
		return 1;
	}
	(void)fclose(f);
	old_len = (size_t)size;
	if (old[0] == FZN_STICKER_VERSION) {
		printf("sticker_convert: %s is already version %u; nothing written\n", argv[1],
		       FZN_STICKER_VERSION);
		free(old);
		return 0;
	}
	made = convert(old, old_len, &made_len);
	free(old);
	if (!made) {
		fprintf(stderr, "sticker_convert: %s is no sticker pack of version 1 to 4\n", argv[1]);
		return 1;
	}
	if (!(f = fopen(argv[2], "wb")) || fwrite(made, 1u, made_len, f) != made_len || fclose(f) != 0) {
		fprintf(stderr, "sticker_convert: %s would not write\n", argv[2]);
		free(made);
		return 1;
	}
	free(made);
	printf("sticker_convert: %s written, version %u\n", argv[2], FZN_STICKER_VERSION);
	return 0;
}
