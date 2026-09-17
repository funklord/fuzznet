/* See line.h. */

#include "line.h"

#include <string.h>

/* Drop what has already been handed out.
 *
 * DEFERRED ON PURPOSE, and the first version of this file got it wrong in a
 * way worth recording: it shifted the remainder down inside `fzn_line_next`,
 * immediately after pointing the caller at the line -- so the memmove wrote
 * the next request over the line just returned, and the pointer was invalid
 * before the caller could read it. The header promised "valid until the next
 * call" and it was valid for none.
 *
 * Compacting here instead makes the promise true: the line stays where it is
 * until something else needs the space, and that something is always another
 * call. */
static void compact(fzn_line_t *reader)
{
	if (reader->start == 0)
		return;

	memmove(reader->buf, reader->buf + reader->start, reader->used - reader->start);
	reader->used -= reader->start;
	reader->start = 0;
}

fzn_line_err_t fzn_line_init(fzn_line_t *reader, uint8_t *buf, size_t cap)
{
	if (!reader || !buf || cap == 0)
		return FZN_LINE_ERR_MALFORMED;

	reader->buf = buf;
	reader->cap = cap;
	reader->used = 0;
	reader->start = 0;
	reader->refusing = 0;
	return FZN_LINE_OK;
}

fzn_line_err_t fzn_line_push(fzn_line_t *reader, const uint8_t *bytes, size_t len)
{
	if (!reader || !reader->buf || (!bytes && len > 0))
		return FZN_LINE_ERR_MALFORMED;
	if (reader->refusing)
		return FZN_LINE_ERR_OVERLONG;
	if (len == 0)
		return FZN_LINE_OK;

	compact(reader);

	/* WHOLE OR NOT AT ALL. Appending what fits and reporting the overflow
	 * separately would leave the caller holding bytes it cannot tell it
	 * still owns, and the natural next move -- pushing them again -- would
	 * duplicate whatever did fit. */
	if (len > reader->cap - reader->used) {
		reader->refusing = 1;
		return FZN_LINE_ERR_OVERLONG;
	}

	memcpy(reader->buf + reader->used, bytes, len);
	reader->used += len;
	return FZN_LINE_OK;
}

int fzn_line_next(fzn_line_t *reader, const uint8_t **line, size_t *line_len)
{
	uint8_t *nl;
	size_t held;

	if (!reader || !reader->buf || !line || !line_len)
		return 0;
	/* A refusing reader holds bytes that were never a complete line, and
	 * handing them over is the resynchronisation the header refuses. */
	if (reader->refusing)
		return 0;

	compact(reader);
	held = reader->used;
	if (held == 0)
		return 0;

	nl = memchr(reader->buf, '\n', held);
	if (!nl)
		return 0;

	*line = reader->buf;
	*line_len = (size_t)(nl - reader->buf);
	/* Consumed rather than removed: the line stays readable until the next
	 * call compacts over it. */
	reader->start = *line_len + 1u;
	return 1;
}
