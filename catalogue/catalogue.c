/*
 * The settled merge core of catalogue.h: the in-memory attribute model and the
 * C5b resolution of concurrent assertions. It holds every decision and touches
 * no wire format, no record, no journal and no store -- section 7 leaves the
 * encoding unsettled, and the deletion, import and source machinery are
 * behaviour over other subsystems rather than an algebra. Assertions carry
 * borrowed views; this file never allocates (C30).
 *
 * What is deliberately absent: the encode/decode of an assertion as a record
 * (section 7), and deciding WHICH assertions are live -- that is read-time
 * state a caller derives from per-(issuer, stream) journal position (C5c), and
 * resolve takes the live set it is given.
 */

#include "catalogue.h"

#include <string.h>

/* memcmp is undefined on a NULL pointer even for length 0, so guard length. */
static int bytes_eq(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len)
{
	if (a_len != b_len)
		return 0;
	if (a_len == 0)
		return 1;
	return memcmp(a, b, a_len) == 0;
}

static int class_known(fzn_catalogue_class_t c)
{
	return c == FZN_CATALOGUE_LABEL || c == FZN_CATALOGUE_FACT
	    || c == FZN_CATALOGUE_IDENTIFIER;
}

static int scope_known(fzn_catalogue_scope_t s)
{
	return s == FZN_CATALOGUE_HOST || s == FZN_CATALOGUE_ESTATE
	    || s == FZN_CATALOGUE_ADVERTISED;
}

static int merge_known(fzn_catalogue_merge_t m)
{
	return m == FZN_CATALOGUE_AUTHORITATIVE || m == FZN_CATALOGUE_UNION
	    || m == FZN_CATALOGUE_DISTINCT;
}

static int capability_known(fzn_catalogue_capability_t c)
{
	return c == FZN_CATALOGUE_CAP_NONE || c == FZN_CATALOGUE_CAP_HOLDER
	    || c == FZN_CATALOGUE_CAP_GRANTED;
}

int fzn_catalogue_assertion_eq(const fzn_catalogue_assertion_t *a,
                               const fzn_catalogue_assertion_t *b)
{
	if (!a || !b)
		return 0;
	return a->attr_class == b->attr_class && a->scope == b->scope
	    && a->merge == b->merge && a->capability == b->capability
	    && bytes_eq(a->issuer, a->issuer_len, b->issuer, b->issuer_len)
	    && bytes_eq(a->entity, a->entity_len, b->entity, b->entity_len)
	    && bytes_eq(a->name, a->name_len, b->name, b->name_len)
	    && bytes_eq(a->value, a->value_len, b->value, b->value_len);
}

/* Two assertions are about the same ATTRIBUTE when they share the entity, the
 * name, and the four axes the attribute declares (C5). The issuer and value
 * are what differ between assertions of one attribute. */
static int same_attribute(const fzn_catalogue_assertion_t *a,
                          const fzn_catalogue_assertion_t *b)
{
	return a->attr_class == b->attr_class && a->scope == b->scope
	    && a->merge == b->merge && a->capability == b->capability
	    && bytes_eq(a->entity, a->entity_len, b->entity, b->entity_len)
	    && bytes_eq(a->name, a->name_len, b->name, b->name_len);
}

fzn_catalogue_err_t fzn_catalogue_validate(const fzn_catalogue_assertion_t *set,
                                           size_t count)
{
	size_t i;

	if (count != 0 && !set)
		return FZN_CATALOGUE_ERR_MALFORMED;

	for (i = 0; i < count; i++) {
		if (!class_known(set[i].attr_class) || !scope_known(set[i].scope)
		    || !merge_known(set[i].merge)
		    || !capability_known(set[i].capability))
			return FZN_CATALOGUE_ERR_KIND;
	}

	/* C28: a resolution set is one attribute or it is refused; resolving a
	 * mixture would combine values that were never about the same thing. */
	for (i = 1; i < count; i++)
		if (!same_attribute(&set[0], &set[i]))
			return FZN_CATALOGUE_ERR_NOT_ONE_ATTRIBUTE;

	return FZN_CATALOGUE_OK;
}

static int value_present(const fzn_catalogue_resolved_t *out, size_t n,
                         const uint8_t *value, size_t value_len)
{
	size_t i;
	for (i = 0; i < n; i++)
		if (bytes_eq(out[i].value, out[i].value_len, value, value_len))
			return 1;
	return 0;
}

static fzn_catalogue_err_t emit(fzn_catalogue_resolved_t *out, size_t *n,
                                size_t out_cap,
                                const fzn_catalogue_assertion_t *a, int authoritative)
{
	if (*n >= out_cap)
		return FZN_CATALOGUE_ERR_RANGE;
	out[*n].value = a->value;
	out[*n].value_len = a->value_len;
	out[*n].issuer = a->issuer;
	out[*n].issuer_len = a->issuer_len;
	out[*n].authoritative = authoritative;
	(*n)++;
	return FZN_CATALOGUE_OK;
}

fzn_catalogue_err_t fzn_catalogue_resolve(const fzn_catalogue_assertion_t *set,
                                          size_t count,
                                          const uint8_t *authority,
                                          size_t authority_len,
                                          fzn_catalogue_resolved_t *out,
                                          size_t out_cap, size_t *out_count)
{
	fzn_catalogue_err_t e;
	fzn_catalogue_merge_t merge;
	size_t i, n = 0;

	if (!out_count)
		return FZN_CATALOGUE_ERR_MALFORMED;
	if (out_cap != 0 && !out)
		return FZN_CATALOGUE_ERR_MALFORMED;

	e = fzn_catalogue_validate(set, count);
	if (e != FZN_CATALOGUE_OK)
		return e;

	if (count == 0) {
		*out_count = 0;
		return FZN_CATALOGUE_OK;
	}

	merge = set[0].merge;

	switch (merge) {
	case FZN_CATALOGUE_UNION:
		/* The distinct live values (C5c makes this race-free). */
		for (i = 0; i < count; i++) {
			if (!set[i].live)
				continue;
			if (value_present(out, n, set[i].value, set[i].value_len))
				continue;
			e = emit(out, &n, out_cap, &set[i], 0);
			if (e != FZN_CATALOGUE_OK)
				return e;
		}
		break;

	case FZN_CATALOGUE_AUTHORITATIVE:
		/* Precedence, not exclusivity: the authority's live values first,
		 * marked, then the other distinct live values -- so where the
		 * authority is silent about a value, another issuer's stands. */
		if (!authority || authority_len == 0)
			return FZN_CATALOGUE_ERR_NO_AUTHORITY;
		for (i = 0; i < count; i++) {
			if (!set[i].live)
				continue;
			if (!bytes_eq(set[i].issuer, set[i].issuer_len,
			              authority, authority_len))
				continue;
			if (value_present(out, n, set[i].value, set[i].value_len))
				continue;
			e = emit(out, &n, out_cap, &set[i], 1);
			if (e != FZN_CATALOGUE_OK)
				return e;
		}
		for (i = 0; i < count; i++) {
			if (!set[i].live)
				continue;
			if (bytes_eq(set[i].issuer, set[i].issuer_len,
			             authority, authority_len))
				continue;
			if (value_present(out, n, set[i].value, set[i].value_len))
				continue;
			e = emit(out, &n, out_cap, &set[i], 0);
			if (e != FZN_CATALOGUE_OK)
				return e;
		}
		break;

	case FZN_CATALOGUE_DISTINCT:
		/* Every live assertion retained with its issuer, no winner: the
		 * disagreement is presented and the display pick is the caller's. */
		for (i = 0; i < count; i++) {
			if (!set[i].live)
				continue;
			e = emit(out, &n, out_cap, &set[i], 0);
			if (e != FZN_CATALOGUE_OK)
				return e;
		}
		break;
	}

	*out_count = n;
	return FZN_CATALOGUE_OK;
}

const char *fzn_catalogue_err_str(fzn_catalogue_err_t err)
{
	switch (err) {
	case FZN_CATALOGUE_OK:
		return "ok";
	case FZN_CATALOGUE_ERR_MALFORMED:
		return "malformed argument";
	case FZN_CATALOGUE_ERR_NOT_ONE_ATTRIBUTE:
		return "resolution set is not one attribute";
	case FZN_CATALOGUE_ERR_KIND:
		return "unknown enum value";
	case FZN_CATALOGUE_ERR_NO_AUTHORITY:
		return "authoritative merge needs a named authority";
	case FZN_CATALOGUE_ERR_RANGE:
		return "output buffer too small";
	}
	return "unknown";
}
