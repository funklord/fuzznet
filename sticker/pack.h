/*
 * A STICKER PACK, ITS SPEC AND A REFERENCE TO ONE, sec 680: fuzzypickles'
 * sticker format moved into fuzznet (sec 679), as the holder decided --
 * the manifest's fields and every rule its decoder kept are theirs
 * (`core/src/sticker_internal.h` and `sticker.c`, read at their 51e789e),
 * the container is this tree's: one situ layout, `sticker/pack.situ`, in
 * place of a stored zip of a CBOR manifest.
 *
 * A PACK is a name, up to 64 stickers and one data area. A sticker is an
 * id, a type, flags, a required description, keywords, an optional text
 * box, an optional sound and one to six renditions; a rendition or a sound
 * is an offset and a length into the data area, so there is no file name
 * inside a pack to resolve or to refuse.
 *
 * A SPEC is the pack as text, written by a person beside the art and kept
 * in version control -- its grammar fuzzypickles', unchanged:
 *
 *     name  cats and their moods
 *     sticker 1 static
 *     description a ginger cat waving hello
 *     keyword wave
 *     inline png 128 128 art/wave.png
 *     sticker 2 animated big sound
 *     description the same cat spinning very fast
 *     main lottie 320 320 art/spin.json
 *     sound art/spin.ogg
 *
 * There a rendition or a sound names a FILE, relative to the spec and never
 * above it; building reads those files into the data area.
 *
 * A REFERENCE is what a message carries in its text, so a sticker rides
 * delivery like any line and a client that cannot draw one shows its
 * description:
 *
 *     fzn:sticker/ROOT/KEY/LENGTH/ID DESCRIPTION
 *
 * ROOT, KEY and LENGTH the pack's file's reference (`node/files.h`): a
 * fetch wants the length, which a peer's HAVE does not give. ID the
 * sticker's. One written by fuzzypickles, `fzp:sticker/ROOT/KEY/ID ...`,
 * is read as one of these with LENGTH 0, so a sticker in a message already
 * sent is known for one and shows its description; its pack, a blob of
 * fuzzypickles' own format, is not one fuzznet can fetch (sec 490).
 */
#ifndef FZN_STICKER_PACK_H
#define FZN_STICKER_PACK_H

#include <stddef.h>
#include <stdint.h>

#define FZN_STICKER_VERSION 1u

#define FZN_STICKER_NAME_MAX 48u
#define FZN_STICKER_PER_PACK_MAX 64u
#define FZN_STICKER_DESC_MAX 96u
#define FZN_STICKER_KEYWORDS_MAX 32u
#define FZN_STICKER_KEYWORD_MAX 24u
#define FZN_STICKER_RENDITIONS_MAX 6u
#define FZN_STICKER_PATH_MAX 96u
/* The longest pack this builds or opens: sixteen MiB of art and manifest,
 * past which a pack is a library rather than a set of stickers. */
#define FZN_STICKER_PACK_MAX_LEN (16u * 1024u * 1024u)

typedef enum fzn_sticker_type {
	FZN_STICKER_STATIC = 1,
	FZN_STICKER_ANIMATED = 2,
	FZN_STICKER_POPUP = 3,     /* plays across the chat screen */
	FZN_STICKER_EFFECT = 4,    /* plays behind the text */
	FZN_STICKER_MESSAGE = 5,   /* the sender types into its text box */
	FZN_STICKER_NAMED = 6,     /* the sender's name, composited in */
	FZN_STICKER_EMOJI = 7      /* drawn inline at text size */
} fzn_sticker_type_t;

/* WHAT A STICKER ALSO DOES, orthogonal to what it is. */
#define FZN_STICKER_FLAG_SOUND 0x0001u
#define FZN_STICKER_FLAG_BIG 0x0002u
#define FZN_STICKER_FLAG_ANIMATED 0x0004u
#define FZN_STICKER_FLAGS_KNOWN 0x0007u

typedef enum fzn_sticker_role {
	FZN_STICKER_THUMB = 1,
	FZN_STICKER_INLINE = 2,
	FZN_STICKER_MAIN = 3,
	FZN_STICKER_POPUP_ART = 4
} fzn_sticker_role_t;

typedef enum fzn_sticker_format {
	FZN_STICKER_LOTTIE = 1,
	FZN_STICKER_APNG = 2,
	FZN_STICKER_WEBP = 3,
	FZN_STICKER_PNG = 4
} fzn_sticker_format_t;

typedef struct fzn_sticker_rendition {
	uint8_t role;
	uint8_t format;
	uint16_t width;
	uint16_t height;
	uint32_t offset;	/* into the data area; set by building */
	uint32_t len;
	char path[FZN_STICKER_PATH_MAX + 1u];	/* a spec's file; empty in a pack */
	size_t path_len;
} fzn_sticker_rendition_t;

typedef struct fzn_sticker_entry {
	uint16_t id;
	uint8_t type;
	uint16_t flags;
	char description[FZN_STICKER_DESC_MAX + 1u];
	size_t description_len;
	char keywords[FZN_STICKER_KEYWORDS_MAX][FZN_STICKER_KEYWORD_MAX + 1u];
	size_t keyword_lens[FZN_STICKER_KEYWORDS_MAX];
	size_t keyword_count;
	uint16_t text_limit, text_x, text_y, text_w, text_h;
	uint32_t audio_offset, audio_len;
	char audio_path[FZN_STICKER_PATH_MAX + 1u];
	size_t audio_path_len;
	fzn_sticker_rendition_t renditions[FZN_STICKER_RENDITIONS_MAX];
	size_t rendition_count;
} fzn_sticker_entry_t;

typedef struct fzn_sticker_manifest {
	char name[FZN_STICKER_NAME_MAX + 1u];
	size_t name_len;
	fzn_sticker_entry_t entries[FZN_STICKER_PER_PACK_MAX];
	size_t count;
} fzn_sticker_manifest_t;

/* ---- a pack ------------------------------------------------------------ */

/* BUILD `m` into `out`, `cap` bytes: each rendition's and sound's bytes the
 * caller's, `art[i][r]` and `art_len[i][r]` for entry i's rendition r and
 * `sound[i]`, `sound_len[i]` for its sound (NULL and 0 for none). The
 * offsets are this call's to set. The pack is opened again before this
 * answers, so a pack it builds is one it accepts. 1 with `*len`, or 0. A
 * NULL `out` asks the length and answers 1 with it. */
int fzn_sticker_pack_build(const fzn_sticker_manifest_t *m,
                           const uint8_t *const art[][FZN_STICKER_RENDITIONS_MAX],
                           const uint32_t art_len[][FZN_STICKER_RENDITIONS_MAX],
                           const uint8_t *const sound[], const uint32_t sound_len[],
                           uint8_t *out, size_t cap, size_t *len);

/* OPEN `len` bytes of a pack into `out`, every rule fuzzypickles' decoder
 * kept: a known version, a name of at most 48 bytes, one to 64 stickers
 * with distinct ids and distinct descriptions; each sticker a known type,
 * no flag unknown, a description of 1 to 96 bytes and keywords of 1 to 24,
 * none holding a control character; one to six renditions of a known role
 * and format, sized, each inside the data area; a sound flag only beside a
 * sound; a message or name sticker with a text limit and a box; no big
 * emoji. And nothing after the data area. `*data`, `*data_len` the data
 * area, which offsets index. 1, or 0. */
int fzn_sticker_pack_open(const uint8_t *pack, size_t len, fzn_sticker_manifest_t *out,
                          const uint8_t **data, size_t *data_len);

/* The rendition of `role`, or the nearest it has -- inline, main, thumb,
 * then the popup art -- never none for an entry with renditions. */
const fzn_sticker_rendition_t *fzn_sticker_pick(const fzn_sticker_entry_t *e,
                                                fzn_sticker_role_t role);

/* ---- what a kind has --------------------------------------------------- */

typedef enum fzn_sticker_field {
	FZN_STICKER_FIELD_DESCRIPTION = 1,
	FZN_STICKER_FIELD_KEYWORDS,
	FZN_STICKER_FIELD_AUDIO,
	FZN_STICKER_FIELD_TEXT_BOX,
	FZN_STICKER_FIELD_TEXT_LIMIT,
	FZN_STICKER_FIELD_FLAG_ANIMATED,
	FZN_STICKER_FIELD_FLAG_BIG,
	FZN_STICKER_FIELD_ROLE_POPUP
} fzn_sticker_field_t;

/* 1 when `field` means anything for a sticker of `type` with `flags` --
 * what an editor greys out and a validator reads. Not applying is not
 * having to be zero: a message sticker switched to static keeps its box. */
int fzn_sticker_field_applies(uint8_t type, uint16_t flags, fzn_sticker_field_t field);

/* ---- a spec ------------------------------------------------------------ */

/* PARSE `len` bytes of spec text into `out`, the paths kept, nothing read.
 * 1, or 0 with `err` saying the line and why -- a person wrote it. */
int fzn_sticker_spec_parse(const char *text, size_t len, fzn_sticker_manifest_t *out, char *err,
                           size_t err_cap);

/* WRITE `m` as spec text into `out`, everything set written whether or not
 * its kind uses it; refused, with `err` naming the sticker, for a value the
 * text cannot carry back unchanged. 1 with `*len`, or 0. A NULL `out` asks
 * the length. Not NUL ended. */
int fzn_sticker_spec_format(const fzn_sticker_manifest_t *m, char *out, size_t cap, size_t *len,
                            char *err, size_t err_cap);

/* A spec's path: relative, inside its directory, no control character, no
 * `..`, no backslash or colon. */
int fzn_sticker_path_ok(const char *path, size_t len);

/* ---- a reference ------------------------------------------------------- */

#define FZN_STICKER_KEY_LEN 32u
#define FZN_STICKER_ROOT_LEN 32u
/* "fzn:sticker/", two hex fields, a length of at most twenty digits, an id
 * of at most five, a space and the description. */
#define FZN_STICKER_REF_MAX (12u + 64u + 1u + 64u + 1u + 20u + 1u + 5u + 1u + FZN_STICKER_DESC_MAX)

typedef struct fzn_sticker_ref {
	uint8_t root[FZN_STICKER_ROOT_LEN];
	uint8_t key[FZN_STICKER_KEY_LEN];
	uint64_t length;	/* the pack's bytes; 0 for an fzp reference */
	uint16_t id;
	char description[FZN_STICKER_DESC_MAX + 1u];
	size_t description_len;
} fzn_sticker_ref_t;

/* `fzn:sticker/...` into `out`, NUL ended: 1 with `*len`, or 0 for a
 * length of 0, an empty description, one too long or one holding a line
 * break. */
int fzn_sticker_ref_format(const fzn_sticker_ref_t *ref, char *out, size_t cap, size_t *len);

/* `fzn:sticker/...` or fuzzypickles' `fzp:sticker/...` back: 1, or 0 for
 * anything not a whole, well-formed reference -- the text is then the
 * ordinary message it is. Every message a client shows passes here. */
int fzn_sticker_ref_parse(const char *text, size_t len, fzn_sticker_ref_t *out);

#endif /* FZN_STICKER_PACK_H */
