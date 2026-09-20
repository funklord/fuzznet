/* See retention.h. */

#include "retention.h"

#include <string.h>

const char *fzn_catalog_retention_str(fzn_catalog_retention_t mode)
{
	switch (mode) {
	case FZN_CATALOG_RETAIN_DEFAULT: return "default";
	case FZN_CATALOG_RETAIN_KEEP:    return "keep";
	case FZN_CATALOG_RETAIN_DROP:    return "drop";
	}
	return "unknown";
}

/* A mode this build knows. Refused rather than skipped, which is C28's rule
 * and facet's F26: a value outside the enum is a statement from a build that
 * knew something this one does not, and guessing at it is how a DROP arrives
 * as a KEEP. */
static int known_mode(fzn_catalog_retention_t mode)
{
	return mode == FZN_CATALOG_RETAIN_DEFAULT ||
	       mode == FZN_CATALOG_RETAIN_KEEP ||
	       mode == FZN_CATALOG_RETAIN_DROP;
}

/* The row for `entity`, or NULL. */
static fzn_catalog_hold_t *find(const fzn_catalog_holds_t *holds, const uint8_t *entity)
{
	size_t i;

	for (i = 0; i < holds->used; i++) {
		if (memcmp(holds->rows[i].entity, entity, FZN_CATALOG_ENTITY_LEN) == 0)
			return &holds->rows[i];
	}

	return NULL;
}

/* Every entry point's first act: a usable table and an entity that is one. */
static int usable(const fzn_catalog_holds_t *holds, const uint8_t *entity,
                  size_t entity_len)
{
	if (!holds || !entity)
		return 0;
	if (entity_len != FZN_CATALOG_ENTITY_LEN)
		return 0;
	/* `rows` may be null only while `capacity` is zero, which is the
	 * bit-less table retention.h allows. */
	return holds->capacity == 0 || holds->rows != NULL;
}

fzn_catalog_err_t fzn_catalog_holds_init(fzn_catalog_holds_t *holds,
                                             fzn_catalog_hold_t *rows, size_t capacity)
{
	if (!holds)
		return FZN_CATALOG_ERR_MALFORMED;
	if (capacity > 0 && !rows)
		return FZN_CATALOG_ERR_MALFORMED;

	memset(holds, 0, sizeof(*holds));
	holds->rows = rows;
	holds->capacity = capacity;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_retain_all(fzn_catalog_holds_t *holds, int keep)
{
	if (!holds)
		return FZN_CATALOG_ERR_MALFORMED;

	holds->keep_all = keep != 0;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_retain_until(fzn_catalog_holds_t *holds,
                                               const uint8_t *entity, size_t entity_len,
                                               fzn_catalog_retention_t mode,
                                               uint64_t until,
                                               fzn_catalog_retention_t then)
{
	fzn_catalog_hold_t *row;

	if (!usable(holds, entity, entity_len))
		return FZN_CATALOG_ERR_MALFORMED;
	if (!known_mode(mode) || !known_mode(then))
		return FZN_CATALOG_ERR_KIND;
	/* A DEADLINE ON A DEFAULT MODE SAYS NOTHING. "Follow the catalogue
	 * until T, then follow the catalogue" and "follow the catalogue until
	 * T, then DROP" are a row with no opinion and a row whose opinion
	 * starts later; the second is expressible as KEEP-until-T only if the
	 * caller means KEEP, so there is nothing to rescue here. Refused, so
	 * the table cannot fill with statements this module would not keep. */
	if (mode == FZN_CATALOG_RETAIN_DEFAULT && until != 0)
		return FZN_CATALOG_ERR_MALFORMED;

	row = find(holds, entity);

	/* DEFAULT GIVES THE ROW BACK rather than storing "no opinion". */
	if (mode == FZN_CATALOG_RETAIN_DEFAULT) {
		if (!row)
			return FZN_CATALOG_OK;
		*row = holds->rows[holds->used - 1u];
		holds->used--;
		return FZN_CATALOG_OK;
	}

	if (!row) {
		if (holds->used >= holds->capacity)
			return FZN_CATALOG_ERR_RANGE;
		row = &holds->rows[holds->used];
		memcpy(row->entity, entity, FZN_CATALOG_ENTITY_LEN);
		holds->used++;
	}
	row->mode = mode;
	row->until = until;
	row->then = until == 0 ? FZN_CATALOG_RETAIN_DEFAULT : then;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_retain(fzn_catalog_holds_t *holds,
                                         const uint8_t *entity, size_t entity_len,
                                         fzn_catalog_retention_t mode)
{
	return fzn_catalog_retain_until(holds, entity, entity_len, mode, 0,
	                                  FZN_CATALOG_RETAIN_DEFAULT);
}

fzn_catalog_retention_t fzn_catalog_retention_of(const fzn_catalog_holds_t *holds,
                                                     const uint8_t *entity,
                                                     size_t entity_len, uint64_t now)
{
	const fzn_catalog_hold_t *row;

	if (!usable(holds, entity, entity_len))
		return FZN_CATALOG_RETAIN_DEFAULT;

	row = find(holds, entity);
	if (!row)
		return FZN_CATALOG_RETAIN_DEFAULT;
	/* THE DEADLINE HAS PASSED AT `until`, NOT AFTER IT. "Keep until T"
	 * means the row stops saying KEEP when T arrives; >= rather than > is
	 * what makes `fzn_catalog_due` at T and this answer agree, and a
	 * consumer that drew a due list at T would otherwise find the row
	 * still saying its old word. */
	if (row->until != 0 && now >= row->until)
		return row->then;
	return row->mode;
}

int fzn_catalog_keeps(const fzn_catalog_holds_t *holds, const uint8_t *entity,
                        size_t entity_len, uint64_t now)
{
	switch (fzn_catalog_retention_of(holds, entity, entity_len, now)) {
	case FZN_CATALOG_RETAIN_KEEP:
		return 1;
	case FZN_CATALOG_RETAIN_DROP:
		return 0;
	case FZN_CATALOG_RETAIN_DEFAULT:
		break;
	}
	/* No word of its own, so the catalogue's. A null table has none and
	 * keeps nothing. */
	return holds && holds->keep_all;
}

size_t fzn_catalog_due(const fzn_catalog_holds_t *holds, uint64_t now,
                         fzn_catalog_entity_t *out, size_t out_cap, size_t *dropped)
{
	size_t i;
	size_t written = 0;

	if (!dropped)
		return 0;
	*dropped = 0;
	if (!holds || !holds->rows || (!out && out_cap > 0))
		return 0;

	for (i = 0; i < holds->used; i++) {
		const fzn_catalog_hold_t *row = &holds->rows[i];

		if (row->until == 0 || now < row->until)
			continue;
		if (written >= out_cap) {
			(*dropped)++;
			continue;
		}
		memcpy(out[written].b, row->entity, FZN_CATALOG_ENTITY_LEN);
		written++;
	}

	return written;
}

size_t fzn_catalog_hold_count(const fzn_catalog_holds_t *holds)
{
	return holds ? holds->used : 0;
}
