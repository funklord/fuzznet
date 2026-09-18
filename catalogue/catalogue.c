/*
 * The settled merge core of catalogue.h, plus the ATTRIBUTE wire encoding the
 * copyright holder settled on 2026-09-18 ("follow the new model"): the in-memory
 * attribute model, the C5b resolution of concurrent assertions, and the
 * encode/decode of an assertion's record body. It holds every decision and
 * still touches no journal and no store -- the deletion, import and source
 * machinery are behaviour over other subsystems rather than an algebra. It
 * touches no record TYPE either: encode writes a body buffer and decode takes
 * the issuer and entity as raw pointers, which the caller lifts from the
 * record's issuer and subject where record/ is already a dependency. Assertions
 * carry borrowed views; this file never allocates (C30).
 *
 * What is deliberately absent: deciding WHICH assertions are live -- that is
 * read-time state a caller derives from per-(issuer, stream) journal position
 * (C5c), and resolve takes the live set it is given; the EDGE-equivalent
 * membership encoding, which is facet/'s; and blob content, which is the
 * filestore's (the entity IS the content hash).
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

/* Big-endian u16, the endianness catalogue/attribute.situ declares. */
static void put_u16(uint8_t *p, size_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)(v & 0xffu);
}

static size_t get_u16(const uint8_t *p)
{
	return ((size_t)p[0] << 8) | (size_t)p[1];
}

fzn_catalogue_err_t fzn_catalogue_attribute_encode(const fzn_catalogue_assertion_t *a,
                                                   uint8_t *out, size_t cap,
                                                   size_t *len_out)
{
	size_t total, off;

	if (!a || !len_out)
		return FZN_CATALOGUE_ERR_MALFORMED;
	if ((a->name_len != 0 && !a->name) || (a->value_len != 0 && !a->value))
		return FZN_CATALOGUE_ERR_MALFORMED;
	/* One canonical encoding: an axis outside its enum has no byte to write. */
	if (!class_known(a->attr_class) || !scope_known(a->scope)
	    || !merge_known(a->merge) || !capability_known(a->capability))
		return FZN_CATALOGUE_ERR_KIND;
	/* The length fields are one byte (name) and two (value); a length that does
	 * not fit its field is not a small-buffer problem but an unencodable one. */
	if (a->name_len > FZN_CATALOGUE_ATTR_NAME_MAX || a->value_len > 0xffffu)
		return FZN_CATALOGUE_ERR_MALFORMED;

	total = FZN_CATALOGUE_ATTR_HEAD_LEN + a->name_len + 2u + a->value_len;
	/* The body must fit both the caller's buffer AND a record body: the
	 * signature is over what the record carries, so a body no record can hold is
	 * not an encoding at all -- catalog/ found this as FZN_CATALOG_INLINE_MAX. */
	if (total > cap || total > (size_t)FZN_RECORD_BODY_MAX)
		return FZN_CATALOGUE_ERR_RANGE;

	out[0] = FZN_CATALOGUE_OBJECT_ATTRIBUTE;
	out[1] = (uint8_t)a->attr_class;
	out[2] = (uint8_t)a->scope;
	out[3] = (uint8_t)a->merge;
	out[4] = (uint8_t)a->capability;
	out[5] = (uint8_t)a->name_len;
	off = FZN_CATALOGUE_ATTR_HEAD_LEN;
	if (a->name_len)
		memcpy(out + off, a->name, a->name_len);
	off += a->name_len;
	put_u16(out + off, a->value_len);
	off += 2u;
	if (a->value_len)
		memcpy(out + off, a->value, a->value_len);
	*len_out = total;
	return FZN_CATALOGUE_OK;
}

fzn_catalogue_err_t fzn_catalogue_attribute_decode(const uint8_t *issuer, size_t issuer_len,
                                                   const uint8_t *entity, size_t entity_len,
                                                   const uint8_t *body, size_t body_len,
                                                   fzn_catalogue_assertion_t *out)
{
	fzn_catalogue_class_t cls;
	fzn_catalogue_scope_t scope;
	fzn_catalogue_merge_t merge;
	fzn_catalogue_capability_t cap;
	size_t name_len, value_len, off;

	if (!out)
		return FZN_CATALOGUE_ERR_MALFORMED;
	if ((issuer_len != 0 && !issuer) || (entity_len != 0 && !entity)
	    || (body_len != 0 && !body))
		return FZN_CATALOGUE_ERR_MALFORMED;

	/* A body no record could carry is not one this decodes -- the symmetric
	 * bound to encode's, so that a body which decodes always re-encodes. */
	if (body_len > (size_t)FZN_RECORD_BODY_MAX)
		return FZN_CATALOGUE_ERR_RANGE;

	/* The fixed head must be whole before any field is read. */
	if (body_len < FZN_CATALOGUE_ATTR_HEAD_LEN
	    || body[0] != FZN_CATALOGUE_OBJECT_ATTRIBUTE)
		return FZN_CATALOGUE_ERR_MALFORMED;

	cls = (fzn_catalogue_class_t)body[1];
	scope = (fzn_catalogue_scope_t)body[2];
	merge = (fzn_catalogue_merge_t)body[3];
	cap = (fzn_catalogue_capability_t)body[4];
	if (!class_known(cls) || !scope_known(scope) || !merge_known(merge)
	    || !capability_known(cap))
		return FZN_CATALOGUE_ERR_KIND;

	name_len = body[5];
	off = FZN_CATALOGUE_ATTR_HEAD_LEN;
	/* name, then the two-byte value length, then value: each must lie within the
	 * body, and the value must be EXACTLY the remaining bytes -- one canonical
	 * encoding, so a trailing byte is refused rather than ignored. */
	if (name_len > body_len - off)
		return FZN_CATALOGUE_ERR_RANGE;
	off += name_len;
	if (body_len - off < 2u)
		return FZN_CATALOGUE_ERR_RANGE;
	value_len = get_u16(body + off);
	off += 2u;
	if (value_len != body_len - off)
		return FZN_CATALOGUE_ERR_RANGE;

	out->issuer = issuer;
	out->issuer_len = issuer_len;
	out->entity = entity;
	out->entity_len = entity_len;
	out->name = name_len ? body + FZN_CATALOGUE_ATTR_HEAD_LEN : NULL;
	out->name_len = name_len;
	out->value = value_len ? body + off : NULL;
	out->value_len = value_len;
	out->attr_class = cls;
	out->scope = scope;
	out->merge = merge;
	out->capability = cap;
	out->live = 0;
	return FZN_CATALOGUE_OK;
}

int fzn_catalogue_referenced(const fzn_catalogue_assertion_t *set, size_t count,
                             const uint8_t *entity, size_t entity_len)
{
	size_t i;

	if ((count != 0 && !set) || (entity_len != 0 && !entity))
		return 0;
	/* Referenced == some LIVE assertion names it. C9: a curated link is a
	 * reference; the host observation (C7) is not an assertion here -- it is
	 * derived from who holds the bytes (C8) -- so an entity with no live
	 * assertion is unreferenced, which is not the same as not existing. */
	for (i = 0; i < count; i++)
		if (set[i].live
		    && bytes_eq(set[i].entity, set[i].entity_len, entity, entity_len))
			return 1;
	return 0;
}

fzn_catalogue_err_t fzn_catalogue_sources(const fzn_catalogue_assertion_t *set,
                                          size_t count, fzn_catalogue_source_t *out,
                                          size_t out_cap, size_t *out_count,
                                          size_t *dropped)
{
	size_t i, j, w = 0, d = 0;

	if (!out_count || !dropped)
		return FZN_CATALOGUE_ERR_MALFORMED;
	if ((count != 0 && !set) || (out_cap != 0 && !out))
		return FZN_CATALOGUE_ERR_MALFORMED;

	/* The distinct issuers the set depends on, and how many of each -- the
	 * hosts a reader must catch up with to account for these assertions. Every
	 * issuer is counted, live or not, because a retraction is still that
	 * issuer's word and catching up needs to see it (C5c). */
	for (i = 0; i < count; i++) {
		const fzn_catalogue_assertion_t *a = &set[i];
		int found = 0;

		for (j = 0; j < w; j++) {
			if (bytes_eq(out[j].issuer, out[j].issuer_len,
			             a->issuer, a->issuer_len)) {
				out[j].assertions++;
				found = 1;
				break;
			}
		}
		if (found)
			continue;
		if (w < out_cap) {
			out[w].issuer = a->issuer;
			out[w].issuer_len = a->issuer_len;
			out[w].assertions = 1;
			w++;
		} else {
			/* Does not fit. Count a dropped issuer once: only on its first
			 * appearance in the set, so many assertions from one dropped
			 * issuer count as one -- reach.c's rule. */
			int earlier = 0;
			for (j = 0; j < i; j++)
				if (bytes_eq(set[j].issuer, set[j].issuer_len,
				             a->issuer, a->issuer_len)) {
					earlier = 1;
					break;
				}
			if (!earlier)
				d++;
		}
	}
	*out_count = w;
	*dropped = d;
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
