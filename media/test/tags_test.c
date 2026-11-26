/*
 * tags_test -- what a file says of itself, project.md sec 1447: the fixtures
 * tool/media_fixtures.py wrote with other tools' hands (ffmpeg, mutagen,
 * metaflac, Pillow) read back name by name -- ID3v2.4 and v2.3 in three
 * encodings, FLAC's comments past a picture block, a big- and a little-endian
 * EXIF with GPS, a JPEG with none, Ogg Vorbis and Opus -- and then each cut at every length and mangled
 * 20000 ways, seeded: nothing read past the bytes given (which `sancheck`
 * turns into a failure), and every value read UTF-8 with no control
 * character. Run from the tree's root, where the fixtures are.
 */
#include "../tags.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                  \
	do {                                                                               \
		checks++;                                                                  \
		if (!(cond)) {                                                             \
			failures++;                                                        \
			fprintf(stderr, "  FAIL tags_test.c:%d: %s\n", __LINE__, what);   \
		}                                                                          \
	} while (0)

static uint8_t *slurp(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	uint8_t *b;
	long n;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) <= 0 || fseek(f, 0, SEEK_SET) != 0
	    || !(b = malloc((size_t)n))) {
		fclose(f);
		return NULL;
	}
	*len = fread(b, 1, (size_t)n, f);
	fclose(f);
	return b;
}

/* `name` read as `want`. */
static int is(const fzn_media_tags_t *t, const char *name, const char *want)
{
	const fzn_media_tag_t *g = fzn_media_tag_find(t, name);

	if (!g || strcmp(g->value, want) != 0) {
		fprintf(stderr, "    %s: read \"%s\", want \"%s\"\n", name, g ? g->value : "(none)", want);
		return 0;
	}
	return 1;
}

static int absent(const fzn_media_tags_t *t, const char *name)
{
	return fzn_media_tag_find(t, name) == NULL;
}

/* Every value well formed: UTF-8, no control character, no space at
 * either end, not empty, within bounds; each name once. */
static int well_formed(const fzn_media_tags_t *t)
{
	size_t i, k, j;

	if (t->count > FZN_MEDIA_TAGS_MAX)
		return 0;
	for (i = 0; i < t->count; i++) {
		const fzn_media_tag_t *g = &t->tags[i];
		const uint8_t *v = (const uint8_t *)g->value;

		if (!g->name || !g->value_len || g->value_len > FZN_MEDIA_TAG_VALUE_MAX || v[g->value_len]
		    || v[0] == ' ' || v[g->value_len - 1] == ' ' || strlen(g->value) != g->value_len)
			return 0;
		for (j = 0; j < i; j++)
			if (strcmp(t->tags[j].name, g->name) == 0)
				return 0;
		for (k = 0; k < g->value_len;) {
			size_t n = v[k] < 0x80u ? 1 : (v[k] & 0xE0u) == 0xC0u ? 2 : (v[k] & 0xF0u) == 0xE0u ? 3
			                                                            : (v[k] & 0xF8u) == 0xF0u ? 4 : 0;
			if (!n || k + n > g->value_len || (n == 1 && (v[k] < 0x20u || v[k] == 0x7Fu)))
				return 0;
			for (j = 1; j < n; j++)
				if ((v[k + j] & 0xC0u) != 0x80u)
					return 0;
			k += n;
		}
	}
	return 1;
}

struct served;
static size_t serve(void *ctx, uint64_t offset, uint8_t *buf, size_t len);
static unsigned by_ranges(const uint8_t *b, size_t len);

/* Cut at every length, then mangled: a byte, a four-byte field, a run
 * copied over -- each read into a buffer of exactly its size, so a read
 * past it is ASan's to see. */
static unsigned mangle(const uint8_t *whole, size_t len, uint64_t *rng, unsigned cases)
{
	unsigned bad = 0, c;
	size_t cut;

	for (cut = 0; cut <= len; cut++) {
		uint8_t *b = malloc(cut ? cut : 1u);
		fzn_media_tags_t t;

		memcpy(b, whole, cut);
		(void)fzn_media_tags_read(b, cut, &t);
		bad += !well_formed(&t);
		free(b);
	}
	for (c = 0; c < cases; c++) {
		uint8_t *b = malloc(len);
		fzn_media_tags_t t;
		size_t at, k;

		memcpy(b, whole, len);
		*rng ^= *rng << 13, *rng ^= *rng >> 7, *rng ^= *rng << 17;
		at = (size_t)(*rng % len);
		switch ((*rng >> 40) % 3u) {
		case 0:
			b[at] = (uint8_t)(*rng >> 48);
			break;
		case 1:
			for (k = 0; k < 4u && at + k < len; k++)
				b[at + k] = (uint8_t)(*rng >> (32 + 8 * k));
			break;
		default:
			for (k = 0; k < 16u && at + k < len; k++)
				b[at + k] = whole[(at * 7u + k) % len];
			break;
		}
		(void)fzn_media_tags_read(b, len, &t);
		bad += !well_formed(&t);
		bad += by_ranges(b, len);
		free(b);
	}
	return bad;
}

/* A FILE SERVED BY RANGES, sec 1452: `base` as it is, or -- `grow` set --
 * with the box at `grow_at` (an MP4's media data) made `grow` bytes longer,
 * its size field patched and its new bytes zeros, so the movie box after it
 * stands a gigabyte further on. Counts what was asked for. */
struct served {
	const uint8_t *base;
	size_t len;
	uint64_t grow;
	size_t grow_at;
	uint64_t asked;
	unsigned reads;
};

static size_t serve(void *ctx, uint64_t offset, uint8_t *buf, size_t len)
{
	struct served *f = (struct served *)ctx;
	const uint64_t whole = f->len + f->grow;
	size_t i;

	f->reads++;
	f->asked += len;
	if (offset >= whole)
		return 0;
	if (len > whole - offset)
		len = (size_t)(whole - offset);
	for (i = 0; i < len; i++) {
		const uint64_t at = offset + i;
		uint8_t v;

		if (!f->grow || at < f->grow_at + 8u) {
			v = f->base[at];
			/* THE GROWN BOX'S SIZE, a u32 at its start. */
			if (f->grow && at >= f->grow_at && at < f->grow_at + 4u) {
				const uint32_t size = ((uint32_t)f->base[f->grow_at] << 24 | (uint32_t)f->base[f->grow_at + 1] << 16
				                       | (uint32_t)f->base[f->grow_at + 2] << 8 | f->base[f->grow_at + 3])
				                      + (uint32_t)f->grow;
				v = (uint8_t)(size >> (8u * (3u - (unsigned)(at - f->grow_at))));
			}
		} else if (at < f->grow_at + 8u + f->grow) {
			v = 0;
		} else {
			v = f->base[at - f->grow];
		}
		buf[i] = v;
	}
	return len;
}

/* The same bytes read by ranges, as an MP4 is walked: 1 when what it read
 * is not well formed. */
static unsigned by_ranges(const uint8_t *b, size_t len)
{
	struct served f = { b, len, 0, 0, 0, 0 };
	fzn_media_tags_t t;

	(void)fzn_media_tags_read_file(serve, &f, len, &t);
	return !well_formed(&t);
}

int main(void)
{
	static const char *files[] = { "media/test/fixture/v24.mp3", "media/test/fixture/v23.mp3",
	                               "media/test/fixture/song.flac", "media/test/fixture/photo.jpg",
	                               "media/test/fixture/plain.jpg", "media/test/fixture/photo_le.jpg",
	                               "media/test/fixture/song.ogg", "media/test/fixture/memo.opus",
	                               "media/test/fixture/song.m4a", "media/test/fixture/song_fast.m4a" };
	fzn_media_tags_t t;
	uint8_t *b[10];
	size_t len[10], i;
	uint64_t rng = 0x1447u;
	unsigned bad = 0;

	for (i = 0; i < 10u; i++) {
		b[i] = slurp(files[i], &len[i]);
		if (!b[i]) {
			fprintf(stderr, "tags_test: cannot read %s; run from the tree's root\n", files[i]);
			return 1;
		}
	}

	/* ID3v2.4, ffmpeg's: UTF-8, TDRC, a track and a disc of totals. */
	(void)fzn_media_tags_read(b[0], len[0], &t);
	CHECK(t.format == FZN_MEDIA_ID3 && is(&t, "title", "Night Drive") && is(&t, "artist", "Svalbard Echo")
	              && is(&t, "album", "Polar Lights") && is(&t, "album_artist", "Various")
	              && is(&t, "genre", "Synthwave") && is(&t, "track", "3/12") && is(&t, "disc", "1/2")
	              && is(&t, "year", "2019"),
	      "an ID3v2.4 tag was not read as ffmpeg wrote it");

	/* ID3v2.3, mutagen's: plain u32 frame sizes, UTF-16 with a byte order
	 * mark past Latin-1 and the BMP's edge, Latin-1, TYER, TLEN. */
	(void)fzn_media_tags_read(b[1], len[1], &t);
	CHECK(t.format == FZN_MEDIA_ID3 && is(&t, "title", "F\xc3\xb6rl\xc3\xa5t \xe2\x80\x94 \xe5\xa4\x9c")
	              && is(&t, "artist", "Bj\xc3\xb6rk") && is(&t, "album", "Homogenic (Deluxe Edition, Remastered in 2024, with the Bonus Tracks and Live Recordings)") && is(&t, "track", "7")
	              && is(&t, "year", "1997") && is(&t, "duration", "250"),
	      "an ID3v2.3 tag was not read as mutagen wrote it");

	/* FLAC: the length from STREAMINFO (0.25 s at 8 kHz), names in any
	 * case, the track and its total joined, the comments after a picture. */
	(void)fzn_media_tags_read(b[2], len[2], &t);
	CHECK(t.format == FZN_MEDIA_FLAC && is(&t, "duration", "250") && is(&t, "title", "Waltz for Debby")
	              && is(&t, "artist", "Bill Evans") && is(&t, "album", "Sunday at the Village Vanguard")
	              && is(&t, "track", "2/6") && is(&t, "year", "1961-06-25"),
	      "a FLAC file's comments were not read as metaflac wrote them");

	/* EXIF, big-endian: the original time over the file's, the maker once,
	 * the EXIF size over the frame's, GPS north and east in degrees. */
	(void)fzn_media_tags_read(b[3], len[3], &t);
	CHECK(t.format == FZN_MEDIA_JPEG && is(&t, "taken", "2023-07-14T21:45:30")
	              && is(&t, "camera", "Canon EOS 5D Mark IV") && is(&t, "orientation", "6")
	              && is(&t, "width", "4000") && is(&t, "height", "3000")
	              && is(&t, "place", "67.8560000,20.2250000"),
	      "a photograph's EXIF was not read as Pillow wrote it");

	/* No EXIF: the frame's own size, and nothing else claimed. */
	(void)fzn_media_tags_read(b[4], len[4], &t);
	CHECK(t.format == FZN_MEDIA_JPEG && t.count == 2u && is(&t, "width", "17") && is(&t, "height", "9")
	              && absent(&t, "taken") && absent(&t, "camera"),
	      "a JPEG with no EXIF was not read for its frame alone");

	/* EXIF little-endian: south and west negative, the file's time where
	 * there is no original, a maker's trailing spaces gone. */
	(void)fzn_media_tags_read(b[5], len[5], &t);
	CHECK(t.format == FZN_MEDIA_JPEG && is(&t, "taken", "2025-12-31T23:59:58") && is(&t, "camera", "OnePlus")
	              && is(&t, "place", "-33.8650000,-70.6500000") && is(&t, "width", "8"),
	      "a little-endian EXIF was not read as Pillow wrote it");

	/* OGG, sec 1451: Vorbis's comments in the stream's second packet, and
	 * Opus's after "OpusTags". */
	(void)fzn_media_tags_read(b[6], len[6], &t);
	CHECK(t.format == FZN_MEDIA_OGG && is(&t, "title", "Snow on the Fjord") && is(&t, "artist", "Kvist")
	              && is(&t, "album", "Vinter") && is(&t, "track", "4") && is(&t, "year", "2021"),
	      "an Ogg Vorbis stream's comments were not read as ffmpeg wrote them");
	(void)fzn_media_tags_read(b[7], len[7], &t);
	CHECK(t.format == FZN_MEDIA_OGG && is(&t, "title", "Voice memo") && is(&t, "artist", "Anna"),
	      "an Ogg Opus stream's tags were not read as ffmpeg wrote them");

	/* MP4, sec 1452, read by ranges: the movie box after the media and
	 * before it, ffmpeg's item list, and the length from the movie header. */
	for (i = 8; i < 10u; i++) {
		struct served f = { b[i], len[i], 0, 0, 0, 0 };

		(void)fzn_media_tags_read_file(serve, &f, len[i], &t);
		CHECK(t.format == FZN_MEDIA_MP4 && is(&t, "title", "Midnight Sun") && is(&t, "artist", "Lumo")
		              && is(&t, "album_artist", "Various") && is(&t, "album", "Arctic Nights")
		              && is(&t, "track", "2/9") && is(&t, "disc", "1/1") && is(&t, "year", "2018")
		              && is(&t, "genre", "Ambient") && is(&t, "duration", "250"),
		      "an MP4's items were not read as ffmpeg wrote them");
	}
	/* A GIGABYTE OF MEDIA BEFORE THE MOVIE BOX, walked over and not read:
	 * what was asked for stays small. */
	{
		const uint8_t *mdat = NULL;
		size_t k;

		for (k = 0; k + 4u <= len[8] && !mdat; k++)
			if (memcmp(b[8] + k, "mdat", 4) == 0)
				mdat = b[8] + k;
		struct served f = { b[8], len[8], (uint64_t)1 << 30, mdat ? (size_t)(mdat - b[8]) - 4u : 0, 0, 0 };

		(void)fzn_media_tags_read_file(serve, &f, len[8] + f.grow, &t);
		CHECK(mdat && is(&t, "title", "Midnight Sun") && f.asked < 4u * FZN_MEDIA_TAGS_HEAD,
		      "an MP4's movie box past a gigabyte of media was not reached by its sizes alone");
		printf("  an MP4 with a gigabyte before its movie box: %u reads, %llu bytes asked\n", f.reads,
		       (unsigned long long)f.asked);
	}
	/* THE OTHER FORMATS by ranges read their head as before. */
	{
		struct served f = { b[1], len[1], 0, 0, 0, 0 };

		(void)fzn_media_tags_read_file(serve, &f, len[1], &t);
		CHECK(t.format == FZN_MEDIA_ID3 && is(&t, "artist", "Bj\xc3\xb6rk") && f.reads == 1u,
		      "a file read by ranges that is no MP4 was not read by its head alone");
	}

	/* A HEAD CUT SHORT still reads what is whole in it: the ID3v2.4 tag's
	 * first frames, from a buffer ending inside the tag. */
	(void)fzn_media_tags_read(b[0], 40u, &t);
	CHECK(t.format == FZN_MEDIA_ID3 && well_formed(&t) && absent(&t, "year"),
	      "a tag cut short was read past its end, or not as a tag");

	/* Nothing a catalogue reads. */
	CHECK(fzn_media_tags_read((const uint8_t *)"RIFF....WAVE", 12u, &t) == 0 && t.format == FZN_MEDIA_UNKNOWN
	              && fzn_media_tags_read(NULL, 0, &t) == 0,
	      "a file of no format read was taken as one");

	for (i = 0; i < 10u; i++)
		bad += mangle(b[i], len[i], &rng, 4000u);
	CHECK(bad == 0, "a file cut short or mangled read a value that is not well formed");
	printf("  ten files cut at every length and mangled 40000 ways: %u ill-formed\n", bad);

	for (i = 0; i < 10u; i++)
		free(b[i]);
	printf("tags_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
