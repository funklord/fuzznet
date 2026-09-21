/* See source.h. */

#include "source.h"

#include <string.h>

static int bytes_eq(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
	if (alen != blen)
		return 0;
	if (alen == 0)
		return 1;
	return memcmp(a, b, alen) == 0;
}

fzn_catalog_err_t fzn_catalog_sources_init(fzn_catalog_source_table_t *sources,
                                           fzn_catalog_source_t *rows,
                                           size_t capacity)
{
	if (!sources)
		return FZN_CATALOG_ERR_MALFORMED;
	if (capacity > 0 && !rows)
		return FZN_CATALOG_ERR_MALFORMED;
	sources->rows = rows;
	sources->capacity = capacity;
	sources->used = 0;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_promotions_init(fzn_catalog_promotions_t *proms,
                                              fzn_catalog_promotion_t *rows,
                                              size_t capacity)
{
	if (!proms)
		return FZN_CATALOG_ERR_MALFORMED;
	if (capacity > 0 && !rows)
		return FZN_CATALOG_ERR_MALFORMED;
	proms->rows = rows;
	proms->capacity = capacity;
	proms->used = 0;
	return FZN_CATALOG_OK;
}

const fzn_catalog_source_t *fzn_catalog_source_find(
        const fzn_catalog_source_table_t *sources, const uint8_t *name,
        size_t name_len)
{
	size_t i;

	if (!sources || !name || name_len == 0)
		return NULL;
	for (i = 0; i < sources->used; i++) {
		if (bytes_eq(sources->rows[i].name, sources->rows[i].name_len,
		             name, name_len))
			return &sources->rows[i];
	}
	return NULL;
}

size_t fzn_catalog_source_count(const fzn_catalog_source_table_t *sources)
{
	return sources ? sources->used : 0;
}

fzn_catalog_err_t fzn_catalog_source_declare(
        fzn_catalog_source_table_t *sources, const uint8_t *name,
        size_t name_len, fzn_catalog_policy_t policy)
{
	const fzn_catalog_source_t *found;
	fzn_catalog_source_t *row;

	if (!sources || !name || name_len == 0)
		return FZN_CATALOG_ERR_MALFORMED;
	/* C28/F26: a policy outside the enum is a kind this build does not
	 * know, and guessing which of the two was meant is guessing whether a
	 * collection may be written to. */
	if (policy != FZN_CATALOG_POLICY_REFERENCED
	    && policy != FZN_CATALOG_POLICY_MANAGED)
		return FZN_CATALOG_ERR_KIND;
	if (name_len > FZN_CATALOG_SOURCE_NAME_MAX)
		return FZN_CATALOG_ERR_RANGE;

	found = fzn_catalog_source_find(sources, name, name_len);
	if (found) {
		/* Replaying the same configuration is not an error. CHANGING a
		 * policy is refused: that one call is the only gesture that
		 * would make an entire referenced collection writable at once,
		 * and a typo in this argument is exactly how it would happen.
		 * A person who means it removes the source and declares it
		 * afresh, which is a different act with a different name. */
		return found->policy == policy ? FZN_CATALOG_OK
		                               : FZN_CATALOG_ERR_KIND;
	}

	if (sources->used >= sources->capacity)
		return FZN_CATALOG_ERR_RANGE;
	row = &sources->rows[sources->used];
	memset(row, 0, sizeof(*row));
	memcpy(row->name, name, name_len);
	row->name_len = name_len;
	row->policy = policy;
	sources->used++;
	return FZN_CATALOG_OK;
}

int fzn_catalog_relative_path_ok(const uint8_t *path, size_t len)
{
	size_t start = 0, i;

	if (!path || len == 0)
		return 0;
	if (len > FZN_CATALOG_SOURCE_PATH_MAX)
		return 0;
	/* An absolute path is not a path INSIDE a source; it is a second way of
	 * naming a place, which is what C13 refuses. */
	if (path[0] == '/')
		return 0;

	for (i = 0; i <= len; i++) {
		if (i < len && path[i] != '/')
			continue;
		/* An empty component is a doubled or trailing separator. Both
		 * name the same place as some other spelling, and two spellings
		 * for one place is what makes a promotion comparison unsound --
		 * the row would match one of them and not the other. */
		if (i == start)
			return 0;
		/* C22's rule, asked per component rather than restated. */
		if (!fzn_catalog_path_component_ok(&path[start], i - start))
			return 0;
		start = i + 1u;
	}
	return 1;
}

static fzn_catalog_promotion_t *promotion_row(fzn_catalog_promotions_t *proms,
                                              const uint8_t *entity,
                                              size_t entity_len)
{
	size_t i;

	for (i = 0; i < proms->used; i++) {
		if (bytes_eq(proms->rows[i].entity, FZN_CATALOG_ENTITY_LEN,
		             entity, entity_len))
			return &proms->rows[i];
	}
	return NULL;
}

fzn_catalog_err_t fzn_catalog_promote(
        fzn_catalog_promotions_t *proms,
        const fzn_catalog_source_table_t *sources, const uint8_t *entity,
        size_t entity_len, const uint8_t *source, size_t source_len,
        const uint8_t *path, size_t path_len)
{
	const fzn_catalog_source_t *src;
	fzn_catalog_promotion_t *row;

	if (!proms || !sources || !entity || !source || !path)
		return FZN_CATALOG_ERR_MALFORMED;
	if (entity_len != FZN_CATALOG_ENTITY_LEN)
		return FZN_CATALOG_ERR_MALFORMED;
	if (!fzn_catalog_relative_path_ok(path, path_len))
		return FZN_CATALOG_ERR_MALFORMED;

	src = fzn_catalog_source_find(sources, source, source_len);
	/* A permission about a place this host does not know is not a
	 * permission -- and answering OK would put a row in the table that
	 * `fzn_catalog_writable` could never say yes to. */
	if (!src)
		return FZN_CATALOG_ERR_ABSENT;
	/* Already writable by C14. Saying OK would leave the caller believing
	 * the promotion is what made it so, and their next thought is that
	 * demoting takes it away again. It would not. */
	if (src->policy == FZN_CATALOG_POLICY_MANAGED)
		return FZN_CATALOG_ERR_KIND;

	row = promotion_row(proms, entity, entity_len);
	if (!row) {
		if (proms->used >= proms->capacity)
			return FZN_CATALOG_ERR_RANGE;
		row = &proms->rows[proms->used];
		proms->used++;
	}
	/* At most one row per entity, replaced rather than added to: two rows
	 * would be two places a caller could be told yes about. */
	memset(row, 0, sizeof(*row));
	memcpy(row->entity, entity, FZN_CATALOG_ENTITY_LEN);
	memcpy(row->source, source, source_len);
	row->source_len = source_len;
	memcpy(row->path, path, path_len);
	row->path_len = path_len;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_demote(fzn_catalog_promotions_t *proms,
                                     const uint8_t *entity, size_t entity_len)
{
	fzn_catalog_promotion_t *row;
	size_t index;

	if (!proms || !entity)
		return FZN_CATALOG_ERR_MALFORMED;
	if (entity_len != FZN_CATALOG_ENTITY_LEN)
		return FZN_CATALOG_ERR_MALFORMED;

	row = promotion_row(proms, entity, entity_len);
	if (!row)
		return FZN_CATALOG_OK;
	index = (size_t)(row - proms->rows);
	if (index + 1u < proms->used)
		*row = proms->rows[proms->used - 1u];
	proms->used--;
	return FZN_CATALOG_OK;
}

const fzn_catalog_promotion_t *fzn_catalog_promoted(
        const fzn_catalog_promotions_t *proms, const uint8_t *entity,
        size_t entity_len)
{
	size_t i;

	if (!proms || !entity || entity_len != FZN_CATALOG_ENTITY_LEN)
		return NULL;
	for (i = 0; i < proms->used; i++) {
		if (bytes_eq(proms->rows[i].entity, FZN_CATALOG_ENTITY_LEN,
		             entity, entity_len))
			return &proms->rows[i];
	}
	return NULL;
}

size_t fzn_catalog_promotion_count(const fzn_catalog_promotions_t *proms)
{
	return proms ? proms->used : 0;
}

int fzn_catalog_writable(const fzn_catalog_source_table_t *sources,
                         const fzn_catalog_promotions_t *proms,
                         const uint8_t *entity, size_t entity_len,
                         const uint8_t *source, size_t source_len,
                         const uint8_t *path, size_t path_len)
{
	const fzn_catalog_source_t *src;
	const fzn_catalog_promotion_t *row;

	if (!sources || !entity || !source || !path)
		return 0;
	if (entity_len != FZN_CATALOG_ENTITY_LEN)
		return 0;
	/* A path this module would refuse to record is one it must not approve
	 * a write to either, or the refusal is only as strong as the caller's
	 * habit of going through `fzn_catalog_promote`. */
	if (!fzn_catalog_relative_path_ok(path, path_len))
		return 0;

	src = fzn_catalog_source_find(sources, source, source_len);
	if (!src)
		return 0;
	if (src->policy == FZN_CATALOG_POLICY_MANAGED)
		return 1;

	/* C15 as settled: writable where it lies, and only there. Both halves
	 * are compared, so a file its owner has moved is no longer the file
	 * this permission was about. */
	row = fzn_catalog_promoted(proms, entity, entity_len);
	if (!row)
		return 0;
	if (!bytes_eq(row->source, row->source_len, source, source_len))
		return 0;
	return bytes_eq(row->path, row->path_len, path, path_len);
}
