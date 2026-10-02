/* See note.h. Ported from fuzzypickles' core/src/notes.c at b419405. */

#include "note.h"

#include "../wire/bytes.h"

#include <string.h>

_Static_assert(FZN_NOTE_CONTENT_MAX == 442u, "a note's content budget moved");
_Static_assert(FZN_NOTE_BLOB_REF_LEN == 72u, "the blob reference is not root, key and length");
_Static_assert(FZN_NOTE_BLOB_REF_LEN <= FZN_NOTE_CONTENT_MAX,
               "a blob reference does not fit a note's content");

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
		return 1;
	default:
		/* ATTACHMENT lands here, the one KNOWN type that does. */
		return 0;
	}
}

fzn_note_err_t fzn_note_shape_ok(uint16_t content_type, const fzn_note_t *note)
{
	if (!note)
		return FZN_NOTE_ERR_NULL;
	if (note->flags & ~FZN_NOTE_FLAGS_KNOWN)
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
		 * list's type -- unless they are in a blob, which is checked when
		 * it is opened. */
		if (note->flags & FZN_NOTE_FLAG_TEXT_IS_BLOB)
			return FZN_NOTE_OK;
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
	default:
		return FZN_NOTE_ERR_TYPE;
	}
}

fzn_note_err_t fzn_note_open(uint16_t content_type, const uint8_t *content, size_t content_len,
                             fzn_note_t *out)
{
	size_t n1, n2, n3;

	if (!content || !out)
		return FZN_NOTE_ERR_NULL;
	/* The reserved type is refused here and nowhere else. */
	if (content_type == FZN_NOTE_TYPE_NONE)
		return FZN_NOTE_ERR_TYPE;
	if (content_len < FZN_NOTE_HEADER_LEN)
		return FZN_NOTE_ERR_SHORT;
	if (content[FZN_NOTE_OFF_VERSION] != FZN_NOTE_VERSION)
		return FZN_NOTE_ERR_VERSION;

	n1 = fzn_get_be16(content + FZN_NOTE_OFF_TITLE_LEN);
	n2 = fzn_get_be16(content + FZN_NOTE_OFF_TEXT_LEN);
	n3 = fzn_get_be16(content + FZN_NOTE_OFF_LABELS_LEN);

	/* THE PARTITION CHECK: equality, not "fits". A gap describes bytes
	 * nobody owns and an overlap the same bytes twice; one comparison
	 * refuses both. */
	if (FZN_NOTE_HEADER_LEN + n1 + n2 + n3 != content_len)
		return FZN_NOTE_ERR_PARTITION;

	out->version = content[FZN_NOTE_OFF_VERSION];
	out->flags = content[FZN_NOTE_OFF_FLAGS];
	out->colour = fzn_get_be32(content + FZN_NOTE_OFF_COLOUR);
	out->created_at_ms = fzn_get_be64(content + FZN_NOTE_OFF_CREATED);
	out->edited_at_ms = fzn_get_be64(content + FZN_NOTE_OFF_EDITED);
	out->title = content + FZN_NOTE_HEADER_LEN;
	out->title_len = n1;
	out->text = out->title + n1;
	out->text_len = n2;
	out->labels = out->text + n2;
	out->labels_len = n3;

	/* A blob reference of the wrong width names nothing, so it is refused
	 * rather than shown -- after the partition, so the pointers above are
	 * known to be inside the buffer. */
	if ((out->flags & FZN_NOTE_FLAG_TEXT_IS_BLOB) && n2 != FZN_NOTE_BLOB_REF_LEN)
		return FZN_NOTE_ERR_BLOB_LEN;
	return FZN_NOTE_OK;
}

fzn_note_err_t fzn_note_content(const fzn_note_t *note, uint8_t *out, size_t out_cap,
                                size_t *out_len)
{
	size_t need;
	uint8_t *p;

	if (!note || !out || !out_len)
		return FZN_NOTE_ERR_NULL;
	if ((note->title_len && !note->title) || (note->text_len && !note->text)
	    || (note->labels_len && !note->labels))
		return FZN_NOTE_ERR_NULL;
	if ((note->flags & FZN_NOTE_FLAG_TEXT_IS_BLOB) && note->text_len != FZN_NOTE_BLOB_REF_LEN)
		return FZN_NOTE_ERR_BLOB_LEN;
	/* EACH LENGTH FITS ITS FIELD BEFORE THE SUM IS TRUSTED: 70000 would
	 * otherwise be truncated by the 16-bit write into a different note
	 * rather than refused, and the decoder cannot tell. */
	if (note->title_len > 0xFFFFu || note->text_len > 0xFFFFu || note->labels_len > 0xFFFFu)
		return FZN_NOTE_ERR_LEN;
	need = FZN_NOTE_HEADER_LEN + note->title_len + note->text_len + note->labels_len;
	if (need > (size_t)FZN_TREE_CONTENT_MAX)
		return FZN_NOTE_ERR_LEN;
	if (need > out_cap)
		return FZN_NOTE_ERR_CAPACITY;

	memset(out, 0, FZN_NOTE_HEADER_LEN);
	out[FZN_NOTE_OFF_VERSION] = FZN_NOTE_VERSION;
	out[FZN_NOTE_OFF_FLAGS] = note->flags;
	fzn_put_be32(out + FZN_NOTE_OFF_COLOUR, note->colour);
	fzn_put_be64(out + FZN_NOTE_OFF_CREATED, note->created_at_ms);
	fzn_put_be64(out + FZN_NOTE_OFF_EDITED, note->edited_at_ms);
	fzn_put_be16(out + FZN_NOTE_OFF_TITLE_LEN, (uint16_t)note->title_len);
	fzn_put_be16(out + FZN_NOTE_OFF_TEXT_LEN, (uint16_t)note->text_len);
	fzn_put_be16(out + FZN_NOTE_OFF_LABELS_LEN, (uint16_t)note->labels_len);

	p = out + FZN_NOTE_HEADER_LEN;
	if (note->title_len)
		memcpy(p, note->title, note->title_len);
	p += note->title_len;
	if (note->text_len)
		memcpy(p, note->text, note->text_len);
	p += note->text_len;
	if (note->labels_len)
		memcpy(p, note->labels, note->labels_len);
	*out_len = need;
	return FZN_NOTE_OK;
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
	if (note->flags & FZN_NOTE_FLAG_TEXT_IS_BLOB)
		return FZN_NOTE_ERR_SHORT;
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

fzn_note_err_t fzn_note_blob_ref(const fzn_note_t *note, fzn_note_blob_ref_t *out)
{
	if (!note || !out)
		return FZN_NOTE_ERR_NULL;
	if (!(note->flags & FZN_NOTE_FLAG_TEXT_IS_BLOB) || note->text_len != FZN_NOTE_BLOB_REF_LEN
	    || !note->text)
		return FZN_NOTE_ERR_BLOB_LEN;
	memcpy(out->root, note->text + FZN_NOTE_REF_OFF_ROOT, FZN_BLOB_HASH_LEN);
	memcpy(out->key, note->text + FZN_NOTE_REF_OFF_KEY, FZN_BLOB_KEY_LEN);
	out->length = fzn_get_be64(note->text + FZN_NOTE_REF_OFF_LEN);
	/* An empty text is inline, never a blob, so a reference to nothing is
	 * a malformed one. */
	if (out->length == 0u)
		return FZN_NOTE_ERR_BLOB_LEN;
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
