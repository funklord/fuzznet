/* Vendored from situ's runtime/c/ at 8257f7f, unmodified below this
 * comment. `make schema SITU_DIR=...` re-copies both files and refuses on
 * drift, so this cannot quietly diverge.
 *
 * A DELIBERATE EXCEPTION to project.md sec 7's "submodule what you link",
 * and it is an exception rather than a case the rule did not cover: this
 * runtime IS linked -- `situ_view_sub` lives in situ.c and the generated
 * accessors call it. A first attempt at this file claimed the opposite,
 * having grepped rather than linked; the linker disagreed immediately.
 *
 * The reason for the exception is proportion. situ's C runtime is 76 lines
 * of situ.c and a header, inside a repository that is otherwise a Python
 * compiler. A submodule would drag the whole compiler into every clone of
 * this library, and into every consumer's tree, to obtain two files.
 * Monocypher is a submodule because it is a C library that is all runtime;
 * this is a runtime that is a rounding error inside a tool.
 *
 * What would change the answer: situ shipping its C runtime as its own
 * repository, or this runtime growing to the point where vendoring it is
 * copying a library rather than two files.
 */
/* situ.c -- out-of-line part of the situ runtime. */

#include "situ.h"

void situ_msg_init(situ_msg_t *msg, uint8_t *buf, uint32_t size)
{
	msg->base	= buf;
	msg->size	= size;
	msg->generation	= 1u;
	/* Clean: a freshly bound buffer holds whatever tags it arrived with, and
	 * they are correct for the bytes that are there. Marking it dirty would
	 * make every parse demand a recomputation it does not need. */
	msg->dirty	= 0u;
}

void situ_msg_touch(situ_msg_t *msg)
{
	msg->generation++;
	/* Generation 0 is reserved for a zero-initialised view, so skip it on
	 * wrap rather than letting such a view come back to life. */
	if (msg->generation == 0u) {
		msg->generation = 1u;
	}
}

situ_err_t situ_view_at(const situ_msg_t *msg, uint32_t offset, uint32_t extent, situ_view_t *out)
{
	/* Written to avoid overflowing offset+extent. */
	if (msg->base == NULL || extent > msg->size || offset > msg->size - extent) {
		return SITU_ERR_BOUNDS;
	}

	out->base	= msg->base + offset;
	out->limit	= extent;
	out->generation	= msg->generation;
	return SITU_OK;
}

situ_err_t situ_view_sub(situ_view_t view, uint32_t offset, uint32_t extent, situ_view_t *out)
{
	if (view.base == NULL || !situ_in_bounds(view, offset, extent)) {
		return SITU_ERR_BOUNDS;
	}

	out->base	= view.base + offset;
	out->limit	= extent;
	out->generation	= view.generation;
	return SITU_OK;
}

void situ_zeroize(void *buf, uint32_t len)
{
	/* Through a volatile pointer, so the writes are observable behaviour the
	 * compiler may not discard as dead stores to storage about to die. */
	volatile uint8_t *p = (volatile uint8_t *)buf;
	uint32_t i;

	for (i = 0; i < len; i++) {
		p[i] = 0u;
	}
}

const char *situ_err_str(situ_err_t err)
{
	switch (err) {
	case SITU_OK:			return "ok";
	case SITU_ERR_BOUNDS:		return "out of bounds";
	case SITU_ERR_CONSTRAINT:	return "constraint violated";
	case SITU_ERR_VERSION:		return "unknown version";
	case SITU_ERR_TAG:		return "tag stale or unverified";
	case SITU_ERR_STAGE:		return "stage gate not passed";
	case SITU_ERR_STALE:		return "stale view";
	case SITU_ERR_TRUNCATED:	return "incomplete: more bytes needed";
	}
	return "unknown error";
}
