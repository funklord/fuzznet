/* See materialise.h. */

#include "materialise.h"

#include <string.h>

static int bytes_eq(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
	if (alen != blen)
		return 0;
	if (alen == 0)
		return 1;
	return memcmp(a, b, alen) == 0;
}

int fzn_catalog_path_component_ok(const uint8_t *value, size_t len)
{
	size_t i;

	if (!value || len == 0)
		return 0;
	if (len > FZN_CATALOG_COMPONENT_MAX)
		return 0;
	/* `.` AND `..` CLIMB OUT, which is a write outside the one place C14
	 * says an organiser may write. */
	if (len == 1u && value[0] == '.')
		return 0;
	if (len == 2u && value[0] == '.' && value[1] == '.')
		return 0;

	for (i = 0; i < len; i++) {
		/* A SEPARATOR IN A VALUE MAKES DIRECTORIES THE TEMPLATE DID NOT
		 * ASK FOR. The backslash goes too: this library runs on POSIX
		 * hosts, but the estate is mixed and a value that is a filename
		 * here is a separator on a host mounting the same collection. */
		if (value[i] == '/' || value[i] == '\\')
			return 0;
		/* NUL truncates a path at the C boundary, so everything after it
		 * silently disappears; the controls are refused with it because
		 * a name nobody can type is a name nobody can remove. */
		if (value[i] < 0x20u || value[i] == 0x7fu)
			return 0;
	}

	return 1;
}

/* The single live value of `name` for `entity`, or an error saying why there
 * is not exactly one. */
static fzn_catalog_err_t one_value(const fzn_catalog_assertion_t *set, size_t count,
                                   const uint8_t *entity, size_t entity_len,
                                   const uint8_t *name, size_t name_len,
                                   const uint8_t **value, size_t *value_len)
{
	size_t i;
	int found = 0;

	for (i = 0; i < count; i++) {
		const fzn_catalog_assertion_t *a = &set[i];

		if (!a->live)
			continue;
		if (!bytes_eq(a->entity, a->entity_len, entity, entity_len))
			continue;
		if (!bytes_eq(a->name, a->name_len, name, name_len))
			continue;
		/* THE SAME VALUE ASSERTED TWICE IS ONE VALUE. Two hosts agreeing
		 * is not a disagreement, and refusing it would make a filename
		 * depend on how many hosts happened to say the same thing. */
		if (found && bytes_eq(*value, *value_len, a->value, a->value_len))
			continue;
		/* NEVER SILENTLY PICK A WINNER (C5b). Two DIFFERENT live values
		 * is a disagreement between hosts, and resolving it here would
		 * resolve it in the one place nobody would look. */
		if (found)
			return FZN_CATALOG_ERR_KIND;
		*value = a->value;
		*value_len = a->value_len;
		found = 1;
	}

	return found ? FZN_CATALOG_OK : FZN_CATALOG_ERR_ABSENT;
}

fzn_catalog_err_t fzn_catalog_materialise(const uint8_t *pattern, size_t pattern_len,
                                          const fzn_catalog_assertion_t *set,
                                          size_t count, const uint8_t *entity,
                                          size_t entity_len, uint8_t *out, size_t cap,
                                          size_t *len_out, size_t *at_out)
{
	uint8_t path[FZN_CATALOG_PATH_MAX];
	size_t i = 0, w = 0, component = 0;

	if (at_out)
		*at_out = 0;
	if (!len_out)
		return FZN_CATALOG_ERR_MALFORMED;
	*len_out = 0;
	if (!pattern || (count != 0 && !set) || !entity || (!out && cap > 0))
		return FZN_CATALOG_ERR_MALFORMED;
	if (pattern_len > FZN_CATALOG_PATTERN_MAX)
		return FZN_CATALOG_ERR_MALFORMED;

	while (i < pattern_len) {
		const uint8_t *value = NULL;
		size_t value_len = 0, name_at, name_len, k;
		fzn_catalog_err_t r;

		if (at_out)
			*at_out = i;

		if (pattern[i] == '}') {
			/* `}}` IS A LITERAL BRACE; a lone `}` is a pattern
			 * somebody mistyped, and guessing which they meant is
			 * how a path ends up with a brace in it. */
			if (i + 1u < pattern_len && pattern[i + 1u] == '}') {
				if (w >= sizeof(path))
					return FZN_CATALOG_ERR_RANGE;
				path[w++] = '}';
				/* THE COMPONENT BOUND APPLIES HERE TOO. Both
				 * brace-escape branches lengthened a component
				 * without checking it until sec 357, so a
				 * pattern of repeated `{{` or `}}` built a
				 * component longer than any filesystem takes
				 * while this function reported success. */
				if (++component > FZN_CATALOG_COMPONENT_MAX)
					return FZN_CATALOG_ERR_RANGE;
				i += 2u;
				continue;
			}
			return FZN_CATALOG_ERR_MALFORMED;
		}

		if (pattern[i] != '{') {
			if (w >= sizeof(path))
				return FZN_CATALOG_ERR_RANGE;
			path[w++] = pattern[i];
			/* A SEPARATOR IN THE TEMPLATE ENDS A COMPONENT, which is
			 * what makes the component bound a bound on each
			 * directory name rather than on the whole path. */
			component = pattern[i] == '/' ? 0 : component + 1u;
			if (component > FZN_CATALOG_COMPONENT_MAX)
				return FZN_CATALOG_ERR_RANGE;
			i++;
			continue;
		}

		if (i + 1u < pattern_len && pattern[i + 1u] == '{') {
			if (w >= sizeof(path))
				return FZN_CATALOG_ERR_RANGE;
			path[w++] = '{';
			if (++component > FZN_CATALOG_COMPONENT_MAX)
				return FZN_CATALOG_ERR_RANGE;
			i += 2u;
			continue;
		}

		/* A substitution. Find its close. */
		name_at = i + 1u;
		k = name_at;
		while (k < pattern_len && pattern[k] != '}')
			k++;
		if (k >= pattern_len)
			return FZN_CATALOG_ERR_MALFORMED; /* unterminated */
		name_len = k - name_at;
		if (name_len == 0)
			return FZN_CATALOG_ERR_MALFORMED;

		r = one_value(set, count, entity, entity_len, pattern + name_at, name_len,
		              &value, &value_len);
		if (r != FZN_CATALOG_OK)
			return r;

		/* THE ASYMMETRY. The pattern's own bytes may hold a separator;
		 * a value may not. See materialise.h -- the pattern is the
		 * operator's and the value is another host's assertion. */
		if (!fzn_catalog_path_component_ok(value, value_len))
			return FZN_CATALOG_ERR_KIND;

		if (w + value_len > sizeof(path))
			return FZN_CATALOG_ERR_RANGE;
		memcpy(path + w, value, value_len);
		w += value_len;
		component += value_len;
		if (component > FZN_CATALOG_COMPONENT_MAX)
			return FZN_CATALOG_ERR_RANGE;
		i = k + 1u;
	}

	if (at_out)
		*at_out = pattern_len;
	if (w == 0)
		return FZN_CATALOG_ERR_MALFORMED;
	/* NOTHING IS WRITTEN UNLESS THE WHOLE PATH FITS, so a caller that did
	 * not read the status does not act on half a path. */
	if (w > cap)
		return FZN_CATALOG_ERR_RANGE;

	memcpy(out, path, w);
	*len_out = w;
	return FZN_CATALOG_OK;
}
