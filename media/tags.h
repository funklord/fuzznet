/*
 * WHAT A FILE SAYS OF ITSELF, project.md sec 1447: a photograph's EXIF, an
 * MP3's ID3v2 tag, a FLAC file's STREAMINFO and Vorbis comments, an Ogg
 * Vorbis or Opus stream's comments (sec 1451), read from
 * the first bytes of the file into the catalogue's names (`title`,
 * `artist`, `taken`, `place` ... -- the table in sec 1447).
 *
 * READ THROUGH SITU'S CODE: the layouts are media/exif.situ, media/id3.situ,
 * media/flac.situ and media/ogg.situ; this file keeps the walks over them
 * and the turning of what they hold into text -- an encoding into UTF-8, a
 * rational into degrees, a colon-separated date into ISO 8601.
 *
 * THE BYTES ARE ANYBODY'S. A file stored into the library came from
 * wherever its owner got it, so every length is checked against the bytes
 * given, nothing reads past `len`, and what does not parse yields fewer
 * tags rather than an error: a file nothing can be read from is still a
 * file. A value is UTF-8 with no control character, trimmed, at most
 * FZN_MEDIA_TAG_VALUE_MAX bytes cut at a character's edge; one that comes
 * to nothing is left out.
 *
 * THE HEAD, NOT THE FILE: a caller hands the first bytes it has -- the node
 * reads FZN_MEDIA_TAGS_HEAD -- and a tag or block reaching past them is read
 * as far as it is whole. EXIF, ID3v2 and FLAC's metadata all stand at the
 * start; a JPEG's frame size may follow a large EXIF, and is then not read.
 */
#ifndef FZN_MEDIA_TAGS_H
#define FZN_MEDIA_TAGS_H

#include <stddef.h>
#include <stdint.h>

#define FZN_MEDIA_TAGS_HEAD (256u * 1024u)
#define FZN_MEDIA_TAG_VALUE_MAX 255u
#define FZN_MEDIA_TAGS_MAX 16u

typedef enum fzn_media_format {
	FZN_MEDIA_UNKNOWN = 0,
	FZN_MEDIA_JPEG = 1,
	FZN_MEDIA_ID3 = 2,  /* an MP3, or anything else an ID3v2 tag opens */
	FZN_MEDIA_FLAC = 3,
	FZN_MEDIA_OGG = 4,  /* Ogg Vorbis or Opus, sec 1451 */
	FZN_MEDIA_MP4 = 5   /* MP4, M4A, a phone's recording, sec 1452 */
} fzn_media_format_t;

typedef struct fzn_media_tag {
	const char *name; /* one of the catalogue's names, a string constant */
	char value[FZN_MEDIA_TAG_VALUE_MAX + 1u]; /* UTF-8, NUL-terminated */
	size_t value_len;
} fzn_media_tag_t;

typedef struct fzn_media_tags {
	fzn_media_format_t format;
	fzn_media_tag_t tags[FZN_MEDIA_TAGS_MAX];
	size_t count;
} fzn_media_tags_t;

/* `head`, the first `len` bytes of a file, read into `out`: the number of
 * tags found, each name once, the first a file states winning. 0 for a
 * format this does not read, or one that says nothing. */
size_t fzn_media_tags_read(const uint8_t *head, size_t len, fzn_media_tags_t *out);

/* A FILE READ BY RANGES, sec 1452: `read` asked for `len` bytes from
 * `offset`, answering how many it gave. The head as above; and an MP4,
 * whose movie box may stand after gigabytes of media, walked box by box
 * where its sizes put each header -- a few hundred small reads at most,
 * never the file through. */
typedef size_t (*fzn_media_read_t)(void *ctx, uint64_t offset, uint8_t *buf, size_t len);
size_t fzn_media_tags_read_file(fzn_media_read_t read, void *ctx, uint64_t file_len, fzn_media_tags_t *out);

/* A PHOTOGRAPH'S OWN THUMBNAIL, sec 1455: the small JPEG a camera writes
 * into EXIF (IFD1), where `head` holds it whole -- 1 with its place in
 * `head`, 0 for none. A list shows it without decoding the photograph. */
int fzn_media_exif_thumbnail(const uint8_t *head, size_t len, size_t *offset, size_t *thumb_len);

/* The value read for `name`, or NULL. */
const fzn_media_tag_t *fzn_media_tag_find(const fzn_media_tags_t *tags, const char *name);

#endif
