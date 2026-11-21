/* See note.h. Ported from fuzzypickles' core/src/notes.c at b419405. */

#include "note.h"
#include "../wire/generated/note_row.h"
#include "../wire/generated/note_row_build.h"

#include "../session/commitment.h"

#include "../wire/bytes.h"

#include <string.h>

_Static_assert(FZN_NOTE_BLOB_REF_LEN == 72u, "the blob reference is not root, key and length");

int fzn_note_type_known(uint16_t content_type)
{
	switch (content_type) {
	case FZN_NOTE_TYPE_NOTE:
	case FZN_NOTE_TYPE_LIST:
	case FZN_NOTE_TYPE_FOLDER:
	case FZN_NOTE_TYPE_ATTACHMENT:
		return 1;
	default:
		/* Including the reserved type, and every type a newer host may
		 * write: not knowing one is no reason to refuse it. */
		return 0;
	}
}

int fzn_note_type_writable(uint16_t content_type)
{
	switch (content_type) {
	case FZN_NOTE_TYPE_NOTE:
	case FZN_NOTE_TYPE_LIST:
	case FZN_NOTE_TYPE_FOLDER:
	/* WRITABLE SINCE sec 1000: a file in a folder, for browsing. */
	case FZN_NOTE_TYPE_ATTACHMENT:
		return 1;
	default:
		return 0;
	}
}

fzn_note_err_t fzn_note_shape_ok(uint16_t content_type, const fzn_note_t *note)
{
	if (!note)
		return FZN_NOTE_ERR_NULL;
	if (note->flags & ~FZN_NOTE_META_FLAGS_KNOWN)
		return FZN_NOTE_ERR_TYPE;

	switch (content_type) {
	case FZN_NOTE_TYPE_FOLDER:
		/* A folder carrying text would render as a note on one host and a
		 * container on another. */
		if (note->text_len != 0 || note->labels_len != 0)
			return FZN_NOTE_ERR_PARTITION;
		return FZN_NOTE_OK;
	case FZN_NOTE_TYPE_LIST:
		/* The items must parse as items, or the list is a note wearing a
		 * list's type. */
		{
			size_t cursor = 0;
			fzn_note_item_t item;
			fzn_note_err_t e;

			while ((e = fzn_note_item_next(note, &cursor, &item)) == FZN_NOTE_OK)
				continue;
			return e == FZN_NOTE_ERR_SHORT ? FZN_NOTE_OK : e;
		}
	case FZN_NOTE_TYPE_NOTE:
		return FZN_NOTE_OK;
	case FZN_NOTE_TYPE_ATTACHMENT:
		/* ITS TEXT IS THE FILE'S REFERENCE, sec 1000: a blob reference's
		 * 72 bytes, root, key and a length that is not 0 -- what a reader
		 * fetches the file by. Anything else is no attachment. */
		if (note->text_len != FZN_NOTE_BLOB_REF_LEN || !note->text
		    || fzn_get_be64(note->text + FZN_BLOB_HASH_LEN + FZN_BLOB_KEY_LEN) == 0u)
			return FZN_NOTE_ERR_PARTITION;
		return FZN_NOTE_OK;
	default:
		return FZN_NOTE_ERR_TYPE;
	}
}

size_t fzn_note_label_count(const fzn_note_t *note)
{
	size_t count = 1, i;

	if (!note || note->labels_len == 0)
		return 0;
	for (i = 0; i < note->labels_len; i++)
		if (note->labels[i] == 0)
			count++;
	return count;
}

fzn_note_err_t fzn_note_label(const fzn_note_t *note, size_t index, const uint8_t **out,
                              size_t *out_len)
{
	size_t start = 0, seen = 0, i;

	if (!note || !out || !out_len)
		return FZN_NOTE_ERR_NULL;
	if (index >= fzn_note_label_count(note))
		return FZN_NOTE_ERR_SHORT;
	for (i = 0; i <= note->labels_len; i++) {
		if (i == note->labels_len || note->labels[i] == 0) {
			if (seen == index) {
				*out = note->labels + start;
				*out_len = i - start;
				return FZN_NOTE_OK;
			}
			seen++;
			start = i + 1;
		}
	}
	return FZN_NOTE_ERR_SHORT;
}

fzn_note_err_t fzn_note_item_next(const fzn_note_t *note, size_t *cursor, fzn_note_item_t *out)
{
	size_t at, len;

	if (!note || !cursor || !out)
		return FZN_NOTE_ERR_NULL;
	at = *cursor;
	if (at >= note->text_len)
		return FZN_NOTE_ERR_SHORT;	/* a clean end */
	/* A header that does not fit is a truncated item, not an end. */
	if (note->text_len - at < 3u)
		return FZN_NOTE_ERR_PARTITION;
	len = fzn_get_be16(note->text + at + 1u);
	if (len > note->text_len - at - 3u)
		return FZN_NOTE_ERR_PARTITION;
	out->flags = note->text[at];
	out->text = note->text + at + 3u;
	out->text_len = len;
	*cursor = at + 3u + len;
	return FZN_NOTE_OK;
}

fzn_note_err_t fzn_note_item_put(uint8_t *out, size_t cap, size_t *used, uint8_t flags,
                                 const uint8_t *text, size_t text_len)
{
	if (!out || !used || (!text && text_len))
		return FZN_NOTE_ERR_NULL;
	/* THE TEXT'S LENGTH IS A u16, and an item past it is refused rather
	 * than written with a length that wraps. */
	if (text_len > 0xffffu || *used > cap || cap - *used < 3u + text_len)
		return text_len > 0xffffu ? FZN_NOTE_ERR_LEN : FZN_NOTE_ERR_CAPACITY;
	out[*used] = flags;
	fzn_put_be16(out + *used + 1u, (uint16_t)text_len);
	if (text_len)
		memcpy(out + *used + 3u, text, text_len);
	*used += 3u + text_len;
	return FZN_NOTE_OK;
}

fzn_note_err_t fzn_note_blob_ref_write(const fzn_note_blob_ref_t *ref,
                                       uint8_t out[FZN_NOTE_BLOB_REF_LEN])
{
	if (!ref || !out)
		return FZN_NOTE_ERR_NULL;
	if (ref->length == 0u)
		return FZN_NOTE_ERR_BLOB_LEN;
	memcpy(out + FZN_NOTE_REF_OFF_ROOT, ref->root, FZN_BLOB_HASH_LEN);
	memcpy(out + FZN_NOTE_REF_OFF_KEY, ref->key, FZN_BLOB_KEY_LEN);
	fzn_put_be64(out + FZN_NOTE_REF_OFF_LEN, ref->length);
	return FZN_NOTE_OK;
}

/* ---- version 2, sec 513 ----------------------------------------------- */

/* THE LAYOUT, pinned as literals against `notes/note_row.situ`, from which
 * situ generates the code that writes and reads it (sec 1374). */
_Static_assert(FZN_NOTE_META_LEN == 94u, "a version-2 note's meta is not 94 bytes");
_Static_assert(FZN_NOTE_META_OFF_REF == 22u, "the content reference moved");
_Static_assert(FZN_NOTE_META_LEN <= FZN_TREE_CONTENT_MAX, "the meta does not fit a node's content");
_Static_assert(FZN_NOTE_PAYLOAD_HEADER_LEN == 9u, "a payload's header is not 9 bytes");

fzn_note_err_t fzn_note_meta_open(uint16_t content_type, const uint8_t *content,
                                  size_t content_len, fzn_note_meta_t *out)
{
	situ_msg_t msg;
	situ_view_t v;
	uint32_t which = 0;
	situ_err_t checked;

	if (!content || !out)
		return FZN_NOTE_ERR_NULL;
	if (content_type == FZN_NOTE_TYPE_NONE)
		return FZN_NOTE_ERR_TYPE;
	if (content_len < FZN_NOTE_META_LEN)
		return FZN_NOTE_ERR_SHORT;
	/* READ AS THE SCHEMA SAYS, sec 1374: `check` names the member it
	 * refused at, so each refusal keeps its answer -- the version, flags
	 * outside the three known, a payload shorter than its header. */
	situ_msg_init(&msg, (uint8_t *)(uintptr_t)content, (uint32_t)FZN_NOTE_META_LEN);
	if (fzn_note_row_fzn_note_meta_view(&msg, 0u, &v) != SITU_OK)
		return FZN_NOTE_ERR_SHORT;
	checked = fzn_note_row_fzn_note_meta_check(v, &which);
	if (checked != SITU_OK && which == FZN_NOTE_ROW_FZN_NOTE_META_VERSION_CHECK)
		return FZN_NOTE_ERR_VERSION;
	/* EXACTLY THE META: a trailing byte is a second encoding of one note. */
	if (content_len != FZN_NOTE_META_LEN)
		return FZN_NOTE_ERR_PARTITION;
	if (checked != SITU_OK)
		return which == FZN_NOTE_ROW_FZN_NOTE_META_FLAGS_CHECK ? FZN_NOTE_ERR_TYPE
		                                                       : FZN_NOTE_ERR_BLOB_LEN;
	out->flags = fzn_note_row_fzn_note_meta_flags_get(v);
	out->colour = fzn_note_row_fzn_note_meta_colour_get(v);
	out->created_at_ms = fzn_note_row_fzn_note_meta_created_at_get(v);
	out->edited_at_ms = fzn_note_row_fzn_note_meta_edited_at_get(v);
	memcpy(out->content.root, fzn_note_row_fzn_note_meta_root_ptr(v), FZN_BLOB_HASH_LEN);
	memcpy(out->content.key, fzn_note_row_fzn_note_meta_key_ptr(v), FZN_BLOB_KEY_LEN);
	out->content.length = fzn_note_row_fzn_note_meta_length_get(v);
	/* A PAYLOAD PAST ITS BOUND: the codec's, the schema saying only the
	 * least. */
	if (out->content.length > FZN_NOTE_PAYLOAD_MAX)
		return FZN_NOTE_ERR_BLOB_LEN;
	return FZN_NOTE_OK;
}

fzn_note_err_t fzn_note_meta_write(const fzn_note_meta_t *meta, uint8_t out[FZN_NOTE_META_LEN])
{
	if (!meta || !out)
		return FZN_NOTE_ERR_NULL;
	if (meta->flags & ~FZN_NOTE_META_FLAGS_KNOWN)
		return FZN_NOTE_ERR_TYPE;
	if (meta->content.length < FZN_NOTE_PAYLOAD_HEADER_LEN
	    || meta->content.length > FZN_NOTE_PAYLOAD_MAX)
		return FZN_NOTE_ERR_BLOB_LEN;
	/* BUILT BY THE CODE situ GENERATES, sec 1374. */
	{
		uint32_t wrote = 0;

		if (fzn_note_row_fzn_note_meta_build(out, FZN_NOTE_META_LEN, (uint8_t)FZN_NOTE_META_VERSION,
		                                     meta->flags, meta->colour, meta->created_at_ms,
		                                     meta->edited_at_ms, meta->content.root,
		                                     meta->content.key, meta->content.length, &wrote)
		            != SITU_OK
		    || wrote != FZN_NOTE_META_LEN)
			return FZN_NOTE_ERR_TYPE;
	}
	return FZN_NOTE_OK;
}

fzn_note_err_t fzn_note_payload_open(const uint8_t *payload, size_t payload_len,
                                     fzn_note_t *out)
{
	situ_msg_t msg;
	situ_view_t v;
	uint32_t which = 0, need = 0, len;
	situ_err_t checked;

	if (!payload || !out)
		return FZN_NOTE_ERR_NULL;
	if (payload_len < FZN_NOTE_PAYLOAD_HEADER_LEN)
		return FZN_NOTE_ERR_SHORT;
	/* READ AS THE SCHEMA SAYS, sec 1374, each refusal keeping its answer:
	 * the version first, then a payload past its bound, a title or labels
	 * past theirs, and -- THE PARTITION CHECK, equality and not "fits" --
	 * a part running past the end or bytes left after the last. A gap
	 * describes bytes nobody owns and an overlap the same bytes twice. The
	 * view is at most one byte past the bound, enough to read the version
	 * of anything longer. */
	len = payload_len > FZN_NOTE_PAYLOAD_MAX ? FZN_NOTE_PAYLOAD_MAX + 1u : (uint32_t)payload_len;
	situ_msg_init(&msg, (uint8_t *)(uintptr_t)payload, len);
	if (fzn_note_row_fzn_note_payload_view(&msg, 0u, len, &v) != SITU_OK)
		return FZN_NOTE_ERR_SHORT;
	checked = fzn_note_row_fzn_note_payload_check(v, &which);
	if (checked != SITU_OK && which == FZN_NOTE_ROW_FZN_NOTE_PAYLOAD_VERSION_CHECK)
		return FZN_NOTE_ERR_VERSION;
	if (payload_len > FZN_NOTE_PAYLOAD_MAX)
		return FZN_NOTE_ERR_LEN;
	if (checked != SITU_OK)
		return which == FZN_NOTE_ROW_FZN_NOTE_PAYLOAD_TITLE_LEN_CHECK
		                       || which == FZN_NOTE_ROW_FZN_NOTE_PAYLOAD_LABELS_LEN_CHECK
		               ? FZN_NOTE_ERR_LEN
		               : FZN_NOTE_ERR_PARTITION;
	if (fzn_note_row_fzn_note_payload_required(payload, len, &need) != SITU_OK || need != len)
		return FZN_NOTE_ERR_PARTITION;
	memset(out, 0, sizeof(*out));
	out->title = fzn_note_row_fzn_note_payload_title_ptr(v);
	out->title_len = fzn_note_row_fzn_note_payload_title_len_get(v);
	out->text = fzn_note_row_fzn_note_payload_text_ptr(v);
	out->text_len = fzn_note_row_fzn_note_payload_text_len_get(v);
	out->labels = fzn_note_row_fzn_note_payload_labels_ptr(v);
	out->labels_len = fzn_note_row_fzn_note_payload_labels_len_get(v);
	return FZN_NOTE_OK;
}

fzn_note_err_t fzn_note_payload_write(const fzn_note_t *note, uint8_t *out, size_t out_cap,
                                      size_t *out_len)
{
	size_t need;

	if (!note || !out || !out_len)
		return FZN_NOTE_ERR_NULL;
	if ((note->title_len && !note->title) || (note->text_len && !note->text)
	    || (note->labels_len && !note->labels))
		return FZN_NOTE_ERR_NULL;
	/* EACH BOUND BEFORE THE SUM, so no length is truncated by its field. */
	if (note->title_len > FZN_NOTE_TITLE_MAX || note->labels_len > FZN_NOTE_LABELS_MAX
	    || note->text_len > FZN_NOTE_PAYLOAD_MAX)
		return FZN_NOTE_ERR_LEN;
	need = FZN_NOTE_PAYLOAD_HEADER_LEN + note->title_len + note->text_len + note->labels_len;
	if (need > FZN_NOTE_PAYLOAD_MAX)
		return FZN_NOTE_ERR_LEN;
	if (need > out_cap)
		return FZN_NOTE_ERR_CAPACITY;
	/* BUILT BY THE CODE situ GENERATES, sec 1374: the lengths written
	 * from the parts, so they partition the payload by construction. */
	{
		uint32_t wrote = 0;

		if (fzn_note_row_fzn_note_payload_build(out, (uint32_t)need, (uint8_t)FZN_NOTE_PAYLOAD_VERSION,
		                                        note->title, (uint32_t)note->title_len, note->text,
		                                        (uint32_t)note->text_len, note->labels,
		                                        (uint32_t)note->labels_len, &wrote)
		            != SITU_OK
		    || wrote != need)
			return FZN_NOTE_ERR_LEN;
	}
	*out_len = need;
	return FZN_NOTE_OK;
}

_Static_assert(FZN_BLOB_KEY_LEN == 32u, "a pad is one hash; the key must be its width");

fzn_note_err_t fzn_note_wrap(const struct fzn_hash_ops *hash,
                             const uint8_t wrap_key[FZN_NOTE_WRAP_KEY_LEN],
                             const uint8_t root[FZN_BLOB_HASH_LEN],
                             const uint8_t key[FZN_BLOB_KEY_LEN], uint8_t out[FZN_BLOB_KEY_LEN])
{
	static const char LABEL[] = "fuzznet.note.wrap";
	uint8_t in[sizeof(LABEL) - 1u + FZN_NOTE_WRAP_KEY_LEN + FZN_BLOB_HASH_LEN];
	uint8_t pad[FZN_BLOB_KEY_LEN];
	size_t i;

	if (!hash || !hash->hash || !wrap_key || !root || !key || !out)
		return FZN_NOTE_ERR_NULL;
	memcpy(in, LABEL, sizeof(LABEL) - 1u);
	memcpy(in + sizeof(LABEL) - 1u, wrap_key, FZN_NOTE_WRAP_KEY_LEN);
	memcpy(in + sizeof(LABEL) - 1u + FZN_NOTE_WRAP_KEY_LEN, root, FZN_BLOB_HASH_LEN);
	/* NONZERO IS SUCCESS on this seam (`session/commitment.h`). */
	if (!hash->hash(hash->ctx, pad, sizeof(pad), in, sizeof(in)))
		return FZN_NOTE_ERR_CRYPTO;
	for (i = 0; i < FZN_BLOB_KEY_LEN; i++)
		out[i] = (uint8_t)(key[i] ^ pad[i]);
	/* THE PAD IS KEY MATERIAL, and goes with the call. */
	memset(pad, 0, sizeof(pad));
	return FZN_NOTE_OK;
}

const char *fzn_note_err_str(fzn_note_err_t err)
{
	switch (err) {
	case FZN_NOTE_OK:
		return "ok";
	case FZN_NOTE_ERR_NULL:
		return "null argument";
	case FZN_NOTE_ERR_SHORT:
		return "too short";
	case FZN_NOTE_ERR_VERSION:
		return "unknown version";
	case FZN_NOTE_ERR_PARTITION:
		return "lengths do not tile the body";
	case FZN_NOTE_ERR_CAPACITY:
		return "output too small";
	case FZN_NOTE_ERR_LEN:
		return "does not fit a node";
	case FZN_NOTE_ERR_BLOB_LEN:
		return "the text is not a blob reference";
	case FZN_NOTE_ERR_TYPE:
		return "reserved content type, or a shape its type forbids";
	case FZN_NOTE_ERR_CRYPTO:
		return "the random source, the seal or the hash refused";
	case FZN_NOTE_ERR_STORE:
		return "the spool refused or could not be read";
	case FZN_NOTE_ERR_ABSENT:
		return "the text is not here yet";
	case FZN_NOTE_ERR_MISMATCH:
		return "the spool's blob is not the one the note names";
	}
	return "unknown";
}
