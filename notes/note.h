/* A note, inside the opaque content `tree/` refuses to interpret. sec 422.
 *
 * WHOSE IT IS. The copyright holder decided 2026-09-29 that everything to do
 * with notes is fuzznet's, the GUI widget included, and 2026-10-01 that the
 * code moves here from fuzzypickles, which consumes it as a vendored
 * component. This is the first piece moved: the body format, ported from
 * fuzzypickles' `core/src/notes.c` and `notes_internal.h` at b419405 with its
 * rules intact, and with the one thing that layout could not do -- hold a note
 * longer than a sticky note -- built in.
 *
 * WHERE THE LINE IS. `tree/` owns which node is a node's parent and where it
 * sits among its siblings, and calls everything else `content` with a
 * two-byte `content_type` whose registry it will not define. That refusal is
 * right: a title, a colour, a checklist and a pin are a notes model, and mean
 * nothing to a router holding an annotation against an interface. So the
 * registry and this layout are this module's, and `tree/` stays generic.
 *
 * 470 BYTES DOES NOT HOLD A NOTE. FZN_RECORD_BODY_MAX is 512 and tree/'s own
 * header takes 42, so content is 470. Version 1 put title, text and labels in
 * it, inline, with a long text as a blob; since sec 514 every note's content
 * is a blob, and the record holds its META -- flags, colour, times and the
 * blob reference -- below. A purge then destroys the blob and its key and
 * leaves the record, which a chained stream cannot lose, as a shell (sec
 * 511). Version 1 is refused on read: no store held it past sec 514.
 *
 * THE BLOB REFERENCE: the root `blob/` names the sealed payload by, the
 * content key that opens it, and the payload's length -- 72 bytes.
 *
 * THE KEY TRAVELS IN THE NOTE, and that is the confidentiality decision. A
 * note's content is exactly as private as its record: whoever holds the
 * signed record can read it, and a host serving the blob without the
 * record holds ciphertext it cannot open (`blob/`'s whole design). It follows
 * that sharing a long note shares a permanent capability to fetch its text
 * from anyone serving it, and un-sharing cannot take that back -- which the
 * UI must say BEFORE a person shares (fuzzypickles' requirement, sec 422).
 * Every edit is a new blob under a new key: `blob/` forbids reusing a key
 * across different content.
 *
 * The layout is version 2's, below.
 */

#ifndef FZN_NOTE_H
#define FZN_NOTE_H

#include <stddef.h>
#include <stdint.h>

#include "../blob/blob.h"
#include "../tree/tree.h"

/* The content-type registry: flat, not a ladder. `kind` at the record level
 * separates a note node from any other consumer's node, so these need only be
 * unique among notes. */
enum fzn_note_content_type {
	/* RESERVED AND REFUSED ON READ: an all-zero header must not decode as a
	 * valid node of a valid type. */
	FZN_NOTE_TYPE_NONE = 0x0000,
	FZN_NOTE_TYPE_NOTE = 0x0001,       /* text */
	FZN_NOTE_TYPE_LIST = 0x0002,       /* a checklist; items in place of text */
	FZN_NOTE_TYPE_FOLDER = 0x0003,     /* a container: header only */
	FZN_NOTE_TYPE_ATTACHMENT = 0x0004  /* a blob reference, as a child node */
};

/* AN UNKNOWN CONTENT TYPE IS SHOWN, NEVER DROPPED. A user's hosts do not
 * upgrade together, so an older host meets a type a newer one wrote; it keeps
 * the node, renders a placeholder and re-publishes it unchanged. A host that
 * dropped what it could not read would delete a newer host's notes on every
 * sync. So this is not a validity test, and nothing refuses a body for being
 * of an unknown type. */
int fzn_note_type_known(uint16_t content_type);

/* Whether THIS BUILD may write a node of this type: narrower than known,
 * because a writer has no newer self to defer to. ATTACHMENT is known and not
 * yet writable: attachments are the second requirement, named and not yet
 * asked for. */
int fzn_note_type_writable(uint16_t content_type);

#define FZN_NOTE_FLAG_PINNED       0x01u
#define FZN_NOTE_FLAG_ARCHIVED     0x02u
/* TRASHED IS A FLAG RATHER THAN A DELETION because nothing here deletes: a
 * note removed on one host reappears as trashed rather than vanishing when an
 * older host syncs. */
#define FZN_NOTE_FLAG_TRASHED      0x04u
/* 0x08 was TEXT_IS_BLOB, version 1's; a meta carrying it is refused. */

/* The blob reference, as a meta carries it at FZN_NOTE_META_OFF_REF. */
#define FZN_NOTE_REF_OFF_ROOT 0u
#define FZN_NOTE_REF_OFF_KEY  (FZN_NOTE_REF_OFF_ROOT + FZN_BLOB_HASH_LEN)
#define FZN_NOTE_REF_OFF_LEN  (FZN_NOTE_REF_OFF_KEY + FZN_BLOB_KEY_LEN)
#define FZN_NOTE_BLOB_REF_LEN (FZN_NOTE_REF_OFF_LEN + 8u)

typedef enum fzn_note_err {
	FZN_NOTE_OK = 0,
	FZN_NOTE_ERR_NULL = -1,      /* a null pointer where one is required */
	FZN_NOTE_ERR_SHORT = -2,     /* too short to hold the header at all; or a clean end */
	FZN_NOTE_ERR_VERSION = -3,   /* a version this build does not know */
	FZN_NOTE_ERR_PARTITION = -4, /* the three lengths do not tile the body */
	FZN_NOTE_ERR_CAPACITY = -5,  /* the output buffer is too small */
	FZN_NOTE_ERR_LEN = -6,       /* the fields do not fit a node's content */
	FZN_NOTE_ERR_BLOB_LEN = -7,  /* a reference no payload could have */
	FZN_NOTE_ERR_TYPE = -8,      /* the reserved type, or a shape its type forbids */
	/* For a note's sealed content, `notes/text.h` (sec 423): */
	FZN_NOTE_ERR_CRYPTO = -9,    /* the random source, the seal or the hash refused */
	FZN_NOTE_ERR_STORE = -10,    /* the spool refused a leaf, or could not be read */
	FZN_NOTE_ERR_ABSENT = -11,   /* the text is not all here yet */
	FZN_NOTE_ERR_MISMATCH = -12  /* the spool holds another blob, or the text is not its length */
} fzn_note_err_t;

/* A note's fields as a VIEW: every pointer aims into the payload it was
 * parsed from, which must outlive this -- tree/'s rule, and record/'s before
 * it. The times, colour and flags are what a writer hands the author; read
 * back, they are the meta's and zero here. */
typedef struct fzn_note {
	const uint8_t *title;
	const uint8_t *text;
	const uint8_t *labels;
	size_t title_len;
	size_t text_len;
	size_t labels_len;
	uint64_t created_at_ms;
	uint64_t edited_at_ms;
	uint32_t colour;
	uint8_t flags;
} fzn_note_t;

/* Whether a note's fields are the shape its type requires, checked when this
 * host CREATES one and not when it reads one: a folder holds no text or
 * labels, a list's items parse, and only known flags are set. */
fzn_note_err_t fzn_note_shape_ok(uint16_t content_type, const fzn_note_t *note);

/* Labels: NUL-separated, no trailing NUL. The count, and label `index`. */
size_t fzn_note_label_count(const fzn_note_t *note);
fzn_note_err_t fzn_note_label(const fzn_note_t *note, size_t index, const uint8_t **out,
                              size_t *out_len);

/* A checklist item: flags (u8) | text_len (u16) | text, packed in a LIST's
 * text field. */
#define FZN_NOTE_ITEM_FLAG_CHECKED 0x01u

typedef struct fzn_note_item {
	const uint8_t *text;
	size_t text_len;
	uint8_t flags;
} fzn_note_item_t;

/* Walk the items from `*cursor` (start at 0), advancing it. SHORT at a clean
 * end, PARTITION when an item runs past the end. */
fzn_note_err_t fzn_note_item_next(const fzn_note_t *note, size_t *cursor, fzn_note_item_t *out);

/* Append one item to `out` at `*used`, advancing it: the inverse of
 * `fzn_note_item_next`. LEN for a text past a u16's reach, CAPACITY when it
 * does not fit `cap`; nothing is written either way. sec 442. */
fzn_note_err_t fzn_note_item_put(uint8_t *out, size_t cap, size_t *used, uint8_t flags,
                                 const uint8_t *text, size_t text_len);

/* THE BLOB REFERENCE. */
typedef struct fzn_note_blob_ref {
	uint8_t root[FZN_BLOB_HASH_LEN];
	uint8_t key[FZN_BLOB_KEY_LEN];
	uint64_t length;
} fzn_note_blob_ref_t;

/* The reference's FZN_NOTE_BLOB_REF_LEN bytes, as a meta and the shelf's
 * verbs carry them. A length of 0 is refused: a reference to nothing. */
fzn_note_err_t fzn_note_blob_ref_write(const fzn_note_blob_ref_t *ref,
                                       uint8_t out[FZN_NOTE_BLOB_REF_LEN]);

/*
 * VERSION 2: THE RECORD KEEPS NO CONTENT. project.md secs 511 and 513, stated
 * in `notes/note.situ`.
 *
 * A purge must still delete a note whose records stay in a chained stream,
 * so the record holds only what is not content, and a reference to a sealed
 * blob that holds the rest:
 *
 *      off  size  field            (the META, a node's content)
 *        0     1  version          (2)
 *        1     1  flags            PINNED | ARCHIVED | TRASHED
 *        2     4  colour           (0xRRGGBBAA; all-zero is "unset")
 *        6     8  created_at       (ms since epoch)
 *       14     8  edited_at        (ms since epoch)
 *       22    72  the content blob: root | key | length
 *
 *      off  size  field            (the PAYLOAD, the blob's plaintext)
 *        0     1  version          (1)
 *        1     2  title_len        n1, at most FZN_NOTE_TITLE_MAX
 *        3     2  labels_len       n3, at most FZN_NOTE_LABELS_MAX
 *        5     4  text_len         n2
 *        9    n1  title
 *             n2  text             (UTF-8, or a list's items)
 *             n3  labels           (NUL-separated, no trailing NUL)
 *
 * The payload partitions as version 1's content did: refused unless the
 * header and the three lengths are its whole length. Every note has a blob,
 * an empty one included, so its length is never below the header's 9.
 *
 * A PAYLOAD READS INTO `fzn_note_t`'s title, text and labels, and only those:
 * the label and item helpers above work on it unchanged. Flags, colour and
 * times are the meta's. Pinning, trashing and moving a note keep its
 * reference -- the same content under the same key, which is not a key
 * reused -- and an edit seals a new blob under a new key.
 */
#define FZN_NOTE_META_VERSION    2u
#define FZN_NOTE_META_OFF_VERSION 0u
#define FZN_NOTE_META_OFF_FLAGS   1u
#define FZN_NOTE_META_OFF_COLOUR  2u
#define FZN_NOTE_META_OFF_CREATED 6u
#define FZN_NOTE_META_OFF_EDITED  14u
#define FZN_NOTE_META_OFF_REF     22u
#define FZN_NOTE_META_LEN         (FZN_NOTE_META_OFF_REF + FZN_NOTE_BLOB_REF_LEN)
#define FZN_NOTE_META_FLAGS_KNOWN                                                             \
	(FZN_NOTE_FLAG_PINNED | FZN_NOTE_FLAG_ARCHIVED | FZN_NOTE_FLAG_TRASHED)

#define FZN_NOTE_PAYLOAD_VERSION         1u
#define FZN_NOTE_PAYLOAD_OFF_VERSION     0u
#define FZN_NOTE_PAYLOAD_OFF_TITLE_LEN   1u
#define FZN_NOTE_PAYLOAD_OFF_LABELS_LEN  3u
#define FZN_NOTE_PAYLOAD_OFF_TEXT_LEN    5u
#define FZN_NOTE_PAYLOAD_HEADER_LEN      9u
/* A title and labels a listing can cache beside every note (sec 511's
 * promise to clients): bounded, where the text need not be. */
#define FZN_NOTE_TITLE_MAX  255u
#define FZN_NOTE_LABELS_MAX 1024u
/* A payload is one blob, whose ceiling is `notes/text.h`'s FZN_NOTE_TEXT_MAX,
 * asserted equal there. */
#define FZN_NOTE_PAYLOAD_MAX (256u * 1024u)

typedef struct fzn_note_meta {
	uint64_t created_at_ms;
	uint64_t edited_at_ms;
	uint32_t colour;
	uint8_t flags;
	fzn_note_blob_ref_t content;
} fzn_note_meta_t;

/* Parse a node's content as a version-2 note: exactly FZN_NOTE_META_LEN
 * bytes, version 2, only known flags, and a reference to a payload at least
 * a header long. The reserved type is refused, an unknown one parses. */
fzn_note_err_t fzn_note_meta_open(uint16_t content_type, const uint8_t *content,
                                  size_t content_len, fzn_note_meta_t *out);

/* The counterpart: FZN_NOTE_META_LEN bytes into `out`, refusing what
 * `fzn_note_meta_open` would refuse. */
fzn_note_err_t fzn_note_meta_write(const fzn_note_meta_t *meta, uint8_t out[FZN_NOTE_META_LEN]);

/* Parse a blob's plaintext into `out`'s title, text and labels, every other
 * field zeroed; the pointers aim into `payload`, which must outlive `out`. */
fzn_note_err_t fzn_note_payload_open(const uint8_t *payload, size_t payload_len,
                                     fzn_note_t *out);

/* Write `note`'s title, text and labels as a payload: LEN for a title,
 * labels or whole past their bounds, CAPACITY when `out_cap` is short. */
fzn_note_err_t fzn_note_payload_write(const fzn_note_t *note, uint8_t *out, size_t out_cap,
                                      size_t *out_len);

/* A short name for an error. Never NULL. */
const char *fzn_note_err_str(fzn_note_err_t err);

#endif /* FZN_NOTE_H */
