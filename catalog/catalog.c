/*
 * The settled merge core of catalog.h, plus the ATTRIBUTE wire encoding the
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

#include "catalog.h"

#include "../wire/generated/attribute_row.h"
#include "../wire/generated/attribute_row_build.h"

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

static int class_known(fzn_catalog_class_t c)
{
	return c == FZN_CATALOG_LABEL || c == FZN_CATALOG_FACT
	    || c == FZN_CATALOG_IDENTIFIER;
}

static int scope_known(fzn_catalog_scope_t s)
{
	return s == FZN_CATALOG_HOST || s == FZN_CATALOG_ESTATE
	    || s == FZN_CATALOG_ADVERTISED;
}

static int merge_known(fzn_catalog_merge_t m)
{
	return m == FZN_CATALOG_AUTHORITATIVE || m == FZN_CATALOG_UNION
	    || m == FZN_CATALOG_DISTINCT;
}

static int capability_known(fzn_catalog_capability_t c)
{
	return c == FZN_CATALOG_CAP_NONE || c == FZN_CATALOG_CAP_HOLDER
	    || c == FZN_CATALOG_CAP_GRANTED;
}

int fzn_catalog_assertion_eq(const fzn_catalog_assertion_t *a,
                               const fzn_catalog_assertion_t *b)
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
static int same_attribute(const fzn_catalog_assertion_t *a,
                          const fzn_catalog_assertion_t *b)
{
	return a->attr_class == b->attr_class && a->scope == b->scope
	    && a->merge == b->merge && a->capability == b->capability
	    && bytes_eq(a->entity, a->entity_len, b->entity, b->entity_len)
	    && bytes_eq(a->name, a->name_len, b->name, b->name_len);
}

fzn_catalog_err_t fzn_catalog_validate(const fzn_catalog_assertion_t *set,
                                           size_t count)
{
	size_t i;

	if (count != 0 && !set)
		return FZN_CATALOG_ERR_MALFORMED;

	for (i = 0; i < count; i++) {
		if (!class_known(set[i].attr_class) || !scope_known(set[i].scope)
		    || !merge_known(set[i].merge)
		    || !capability_known(set[i].capability))
			return FZN_CATALOG_ERR_KIND;
	}

	/* C28: a resolution set is one attribute or it is refused; resolving a
	 * mixture would combine values that were never about the same thing. */
	for (i = 1; i < count; i++)
		if (!same_attribute(&set[0], &set[i]))
			return FZN_CATALOG_ERR_NOT_ONE_ATTRIBUTE;

	return FZN_CATALOG_OK;
}

static int value_present(const fzn_catalog_resolved_t *out, size_t n,
                         const uint8_t *value, size_t value_len)
{
	size_t i;
	for (i = 0; i < n; i++)
		if (bytes_eq(out[i].value, out[i].value_len, value, value_len))
			return 1;
	return 0;
}

static fzn_catalog_err_t emit(fzn_catalog_resolved_t *out, size_t *n,
                                size_t out_cap,
                                const fzn_catalog_assertion_t *a, int authoritative)
{
	if (*n >= out_cap)
		return FZN_CATALOG_ERR_RANGE;
	out[*n].value = a->value;
	out[*n].value_len = a->value_len;
	out[*n].issuer = a->issuer;
	out[*n].issuer_len = a->issuer_len;
	out[*n].authoritative = authoritative;
	(*n)++;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_resolve(const fzn_catalog_assertion_t *set,
                                          size_t count,
                                          const uint8_t *authority,
                                          size_t authority_len,
                                          fzn_catalog_resolved_t *out,
                                          size_t out_cap, size_t *out_count)
{
	fzn_catalog_err_t e;
	fzn_catalog_merge_t merge;
	size_t i, n = 0;

	if (!out_count)
		return FZN_CATALOG_ERR_MALFORMED;
	if (out_cap != 0 && !out)
		return FZN_CATALOG_ERR_MALFORMED;

	e = fzn_catalog_validate(set, count);
	if (e != FZN_CATALOG_OK)
		return e;

	if (count == 0) {
		*out_count = 0;
		return FZN_CATALOG_OK;
	}

	merge = set[0].merge;

	switch (merge) {
	case FZN_CATALOG_UNION:
		/* The distinct live values (C5c makes this race-free). */
		for (i = 0; i < count; i++) {
			if (!set[i].live)
				continue;
			if (value_present(out, n, set[i].value, set[i].value_len))
				continue;
			e = emit(out, &n, out_cap, &set[i], 0);
			if (e != FZN_CATALOG_OK)
				return e;
		}
		break;

	case FZN_CATALOG_AUTHORITATIVE:
		/* Precedence, not exclusivity: the authority's live values first,
		 * marked, then the other distinct live values -- so where the
		 * authority is silent about a value, another issuer's stands. */
		if (!authority || authority_len == 0)
			return FZN_CATALOG_ERR_NO_AUTHORITY;
		for (i = 0; i < count; i++) {
			if (!set[i].live)
				continue;
			if (!bytes_eq(set[i].issuer, set[i].issuer_len,
			              authority, authority_len))
				continue;
			if (value_present(out, n, set[i].value, set[i].value_len))
				continue;
			e = emit(out, &n, out_cap, &set[i], 1);
			if (e != FZN_CATALOG_OK)
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
			if (e != FZN_CATALOG_OK)
				return e;
		}
		break;

	case FZN_CATALOG_DISTINCT:
		/* Every live assertion retained with its issuer, no winner: the
		 * disagreement is presented and the display pick is the caller's. */
		for (i = 0; i < count; i++) {
			if (!set[i].live)
				continue;
			e = emit(out, &n, out_cap, &set[i], 0);
			if (e != FZN_CATALOG_OK)
				return e;
		}
		break;
	}

	*out_count = n;
	return FZN_CATALOG_OK;
}

/* BUILT AND READ BY THE CODE situ GENERATES from `catalog/attribute_row.situ`
 * (sec 1370): the enums, the bounds and every byte accounted for are the
 * schema's; `check` names the member it refused at, so each refusal keeps
 * the answer it had -- the object byte MALFORMED, an axis outside its enum
 * KIND, a length that does not fit RANGE. */
fzn_catalog_err_t fzn_catalog_attribute_encode(const fzn_catalog_assertion_t *a,
                                                   uint8_t *out, size_t cap,
                                                   size_t *len_out)
{
	size_t total;
	uint32_t wrote = 0;

	if (!a || !len_out)
		return FZN_CATALOG_ERR_MALFORMED;
	if ((a->name_len != 0 && !a->name) || (a->value_len != 0 && !a->value))
		return FZN_CATALOG_ERR_MALFORMED;
	/* One canonical encoding: an axis outside its enum has no byte to write. */
	if (!class_known(a->attr_class) || !scope_known(a->scope)
	    || !merge_known(a->merge) || !capability_known(a->capability))
		return FZN_CATALOG_ERR_KIND;
	/* The length fields are one byte (name) and two (value); a length that does
	 * not fit its field is not a small-buffer problem but an unencodable one. */
	if (a->name_len > FZN_CATALOG_ATTR_NAME_MAX || a->value_len > 0xffffu)
		return FZN_CATALOG_ERR_MALFORMED;

	total = FZN_CATALOG_ATTR_HEAD_LEN + a->name_len + 2u + a->value_len;
	/* The body must fit both the caller's buffer AND a record body: the
	 * signature is over what the record carries, so a body no record can hold is
	 * not an encoding at all -- catalog/ found this as FZN_CATALOG_INLINE_MAX. */
	if (total > cap || total > (size_t)FZN_RECORD_BODY_MAX)
		return FZN_CATALOG_ERR_RANGE;
	if (fzn_attribute_row_fzn_catalog_attribute_build(
	            out, (uint32_t)cap, FZN_CATALOG_OBJECT_ATTRIBUTE,
	            (fzn_attribute_row_fzn_catalog_class_t)a->attr_class,
	            (fzn_attribute_row_fzn_catalog_scope_t)a->scope,
	            (fzn_attribute_row_fzn_catalog_merge_t)a->merge,
	            (fzn_attribute_row_fzn_catalog_capability_t)a->capability, a->name, (uint32_t)a->name_len,
	            a->value, (uint32_t)a->value_len, &wrote)
	    != SITU_OK)
		return FZN_CATALOG_ERR_RANGE;
	*len_out = wrote;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_attribute_decode(const uint8_t *issuer, size_t issuer_len,
                                                   const uint8_t *entity, size_t entity_len,
                                                   const uint8_t *body, size_t body_len,
                                                   fzn_catalog_assertion_t *out)
{
	situ_msg_t m;
	situ_view_t v;
	uint32_t which = 0, need = 0;
	size_t name_len, value_len;

	if (!out)
		return FZN_CATALOG_ERR_MALFORMED;
	if ((issuer_len != 0 && !issuer) || (entity_len != 0 && !entity)
	    || (body_len != 0 && !body))
		return FZN_CATALOG_ERR_MALFORMED;

	/* A body no record could carry is not one this decodes -- the symmetric
	 * bound to encode's, so that a body which decodes always re-encodes. */
	if (body_len > (size_t)FZN_RECORD_BODY_MAX)
		return FZN_CATALOG_ERR_RANGE;

	/* The fixed head must be whole before any field is read. */
	if (body_len < FZN_CATALOG_ATTR_HEAD_LEN)
		return FZN_CATALOG_ERR_MALFORMED;

	situ_msg_init(&m, (uint8_t *)(uintptr_t)body, (uint32_t)body_len);
	if (fzn_attribute_row_fzn_catalog_attribute_view(&m, 0u, (uint32_t)body_len, &v) != SITU_OK)
		return FZN_CATALOG_ERR_MALFORMED;
	if (fzn_attribute_row_fzn_catalog_attribute_check(v, &which) != SITU_OK) {
		if (which == FZN_ATTRIBUTE_ROW_FZN_CATALOG_ATTRIBUTE_OBJECT_CHECK)
			return FZN_CATALOG_ERR_MALFORMED;
		if (which == FZN_ATTRIBUTE_ROW_FZN_CATALOG_ATTRIBUTE_ATTR_CLASS_CHECK
		    || which == FZN_ATTRIBUTE_ROW_FZN_CATALOG_ATTRIBUTE_SCOPE_CHECK
		    || which == FZN_ATTRIBUTE_ROW_FZN_CATALOG_ATTRIBUTE_MERGE_CHECK
		    || which == FZN_ATTRIBUTE_ROW_FZN_CATALOG_ATTRIBUTE_CAPABILITY_CHECK)
			return FZN_CATALOG_ERR_KIND;
		return FZN_CATALOG_ERR_RANGE;
	}
	/* The value must be EXACTLY the remaining bytes -- one canonical
	 * encoding, so a trailing byte is refused rather than ignored. */
	if (fzn_attribute_row_fzn_catalog_attribute_required(body, (uint32_t)body_len, &need) != SITU_OK
	    || need != body_len)
		return FZN_CATALOG_ERR_RANGE;
	name_len = fzn_attribute_row_fzn_catalog_attribute_name_len_get(v);
	value_len = fzn_attribute_row_fzn_catalog_attribute_value_len_get(v);

	out->issuer = issuer;
	out->issuer_len = issuer_len;
	out->entity = entity;
	out->entity_len = entity_len;
	out->name = name_len ? fzn_attribute_row_fzn_catalog_attribute_name_ptr(v) : NULL;
	out->name_len = name_len;
	out->value = value_len ? fzn_attribute_row_fzn_catalog_attribute_value_ptr(v) : NULL;
	out->value_len = value_len;
	out->attr_class = (fzn_catalog_class_t)fzn_attribute_row_fzn_catalog_attribute_attr_class_get(v);
	out->scope = (fzn_catalog_scope_t)fzn_attribute_row_fzn_catalog_attribute_scope_get(v);
	out->merge = (fzn_catalog_merge_t)fzn_attribute_row_fzn_catalog_attribute_merge_get(v);
	out->capability = (fzn_catalog_capability_t)fzn_attribute_row_fzn_catalog_attribute_capability_get(v);
	out->live = 0;
	return FZN_CATALOG_OK;
}

int fzn_catalog_referenced(const fzn_catalog_assertion_t *set, size_t count,
                             const uint8_t *entity, size_t entity_len)
{
	size_t i;

	if ((count != 0 && !set) || (entity_len != 0 && !entity))
		return 0;
	/* Referenced == some LIVE CURATED assertion names it. C9: a curated link
	 * is a reference; the host observation (C7) is not -- it is derived from
	 * who holds the bytes (C8) -- so an entity with no live curated assertion
	 * is unreferenced, which is not the same as not existing.
	 *
	 * A HOLDER-CAPABILITY ASSERTION IS THAT HOST OBSERVATION, AND IS SKIPPED.
	 * "I hold these bytes" says where they are, not that anything wants them
	 * kept. Counting it made every entity a host holds permanently referenced
	 * BY THE FACT OF HOLDING IT, which is a fixpoint no sweep can escape: sec
	 * 317's step 2 maps its reachability guard onto this call, so the planner
	 * would have kept everything and planned nothing, for ever. Found by
	 * building that planner (sec 321); C9 had said so from the start and this
	 * loop had not, and no test reached the case because the reachability
	 * fixture zeroes `capability`, which is outside the enum entirely. */
	for (i = 0; i < count; i++)
		if (set[i].live && set[i].capability != FZN_CATALOG_CAP_HOLDER
		    && bytes_eq(set[i].entity, set[i].entity_len, entity, entity_len))
			return 1;
	return 0;
}

fzn_catalog_err_t fzn_catalog_issuers(const fzn_catalog_assertion_t *set,
                                          size_t count, fzn_catalog_issuer_t *out,
                                          size_t out_cap, size_t *out_count,
                                          size_t *dropped)
{
	size_t i, j, w = 0, d = 0;

	if (!out_count || !dropped)
		return FZN_CATALOG_ERR_MALFORMED;
	if ((count != 0 && !set) || (out_cap != 0 && !out))
		return FZN_CATALOG_ERR_MALFORMED;

	/* The distinct issuers the set depends on, and how many of each -- the
	 * hosts a reader must catch up with to account for these assertions. Every
	 * issuer is counted, live or not, because a retraction is still that
	 * issuer's word and catching up needs to see it (C5c). */
	for (i = 0; i < count; i++) {
		const fzn_catalog_assertion_t *a = &set[i];
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
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_holders(const fzn_catalog_assertion_t *set,
                                          size_t count, const uint8_t *entity,
                                          size_t entity_len,
                                          fzn_catalog_issuer_t *out, size_t out_cap,
                                          size_t *out_count, size_t *dropped)
{
	size_t i, j, w = 0, d = 0;

	if (!out_count || !dropped)
		return FZN_CATALOG_ERR_MALFORMED;
	if ((count != 0 && !set) || (out_cap != 0 && !out)
	    || (entity_len != 0 && !entity))
		return FZN_CATALOG_ERR_MALFORMED;

	/* The hosts that hold the entity (C8). Only a LIVE HOLDER-capability
	 * assertion is a holding: C5e lets only a host that holds the bytes make
	 * one, so its issuer holds the entity and that falls out of the record
	 * shape rather than being enforced on top of it (C8a). A NONE or GRANTED
	 * assertion says nothing about holding. `out_count` == 1 is a last copy;
	 * a caller finds itself among the holders to answer this-host-holds. */
	for (i = 0; i < count; i++) {
		const fzn_catalog_assertion_t *a = &set[i];
		int found = 0;

		if (!a->live || a->capability != FZN_CATALOG_CAP_HOLDER
		    || !bytes_eq(a->entity, a->entity_len, entity, entity_len))
			continue;
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
			/* Count a dropped holder once -- its first qualifying appearance,
			 * under the same filter, so a repeated holder is not over-counted. */
			int earlier = 0;
			for (j = 0; j < i; j++)
				if (set[j].live
				    && set[j].capability == FZN_CATALOG_CAP_HOLDER
				    && bytes_eq(set[j].entity, set[j].entity_len,
				                entity, entity_len)
				    && bytes_eq(set[j].issuer, set[j].issuer_len,
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
	return FZN_CATALOG_OK;
}

const char *fzn_catalog_err_str(fzn_catalog_err_t err)
{
	switch (err) {
	case FZN_CATALOG_OK:
		return "ok";
	case FZN_CATALOG_ERR_MALFORMED:
		return "malformed argument";
	case FZN_CATALOG_ERR_NOT_ONE_ATTRIBUTE:
		return "resolution set is not one attribute";
	case FZN_CATALOG_ERR_KIND:
		return "unknown enum value";
	case FZN_CATALOG_ERR_NO_AUTHORITY:
		return "authoritative merge needs a named authority";
	case FZN_CATALOG_ERR_RANGE:
		return "output buffer too small";
	case FZN_CATALOG_ERR_ABSENT:
		return "not asserted by the records";
	case FZN_CATALOG_ERR_BUSY:
		return "still under way";
	}
	return "unknown";
}
