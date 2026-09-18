/*
 * The settled in-memory core of facet.h: the model's structural operations and
 * the collation key. It holds every decision and touches no platform, no wire
 * format and no index -- facet.h's section 8 leaves those unsettled, so nothing
 * here fixes them. Terms carry borrowed views; this file never allocates.
 *
 * What is deliberately absent, and why, so a reader does not take the gap for
 * an oversight: no evaluation (needs the index interface, section 8), no
 * encode/decode (needs the wire encoding, section 8), and no F16 canonical
 * SORT of terms or F18 sort/dedup of alternation members (both order by the
 * canonical-encoding bytes the wire format has not fixed). Equality does not
 * need an order, so term equality IS here; ordering is not.
 */

#include "facet.h"

#include <string.h>

static int is_digit(uint8_t c)
{
	return c >= '0' && c <= '9';
}

/* memcmp is undefined on a NULL pointer even for length 0, so guard length. */
static int bytes_eq(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len)
{
	if (a_len != b_len)
		return 0;
	if (a_len == 0)
		return 1;
	return memcmp(a, b, a_len) == 0;
}

static int node_eq(const fzn_facet_node_t *a, const fzn_facet_node_t *b)
{
	return bytes_eq(a->dim, a->dim_len, b->dim, b->dim_len)
	    && bytes_eq(a->id, a->id_len, b->id, b->id_len);
}

/* A bound (F7). Open on a side means no id there; two open sides are equal, an
 * open and a closed side are not, and `inclusive` decides only closed bounds. */
static int bound_open(const fzn_facet_bound_t *b)
{
	return b->id == NULL || b->id_len == 0;
}

static int bound_eq(const fzn_facet_bound_t *a, const fzn_facet_bound_t *b)
{
	if (bound_open(a) || bound_open(b))
		return bound_open(a) && bound_open(b);
	return bytes_eq(a->id, a->id_len, b->id, b->id_len)
	    && a->inclusive == b->inclusive;
}

static int member_in(const fzn_facet_node_t *m,
                     const fzn_facet_node_t *arr, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		if (node_eq(m, &arr[i]))
			return 1;
	return 0;
}

/* ALT members compared as a SET (F18 treats them as one): same size, and each
 * side's members are all found in the other. Exact for deduplicated members,
 * which is what a canonical alternation carries. */
static int alt_members_eq(const fzn_facet_term_t *a, const fzn_facet_term_t *b)
{
	size_t i;
	if (a->member_count != b->member_count)
		return 0;
	for (i = 0; i < a->member_count; i++)
		if (!member_in(&a->members[i], b->members, b->member_count))
			return 0;
	for (i = 0; i < b->member_count; i++)
		if (!member_in(&b->members[i], a->members, a->member_count))
			return 0;
	return 1;
}

int fzn_facet_term_eq(const fzn_facet_term_t *a, const fzn_facet_term_t *b)
{
	if (!a || !b)
		return 0;
	if (a->kind != b->kind)
		return 0;
	switch (a->kind) {
	case FZN_FACET_PREFIX:
		return node_eq(&a->node, &b->node);
	case FZN_FACET_RANGE:
		return node_eq(&a->node, &b->node)
		    && bound_eq(&a->lo, &b->lo) && bound_eq(&a->hi, &b->hi);
	case FZN_FACET_ALT:
		return alt_members_eq(a, b);
	default:
		/* An unknown kind is equal to nothing; F26 refusal is
		 * fzn_facet_validate's job, not equality's. */
		return 0;
	}
}

/* F8: every member of an alternation shares one dimension. An alternation with
 * no members is degenerate (the union of nothing) and is refused as malformed
 * rather than silently denoting the empty set. */
static fzn_facet_err_t check_alt(const fzn_facet_term_t *t)
{
	size_t i;
	if (t->member_count == 0 || t->members == NULL)
		return FZN_FACET_ERR_MALFORMED;
	for (i = 1; i < t->member_count; i++)
		if (!bytes_eq(t->members[i].dim, t->members[i].dim_len,
		              t->members[0].dim, t->members[0].dim_len))
			return FZN_FACET_ERR_ALT_DIMENSION;
	return FZN_FACET_OK;
}

static fzn_facet_err_t check_side(const fzn_facet_term_t *arr, size_t count)
{
	size_t i;
	if (count != 0 && arr == NULL)
		return FZN_FACET_ERR_MALFORMED;
	for (i = 0; i < count; i++) {
		switch (arr[i].kind) {
		case FZN_FACET_PREFIX:
		case FZN_FACET_RANGE:
			break;
		case FZN_FACET_ALT: {
			fzn_facet_err_t e = check_alt(&arr[i]);
			if (e != FZN_FACET_OK)
				return e;
			break;
		}
		default:
			return FZN_FACET_ERR_KIND; /* F26 */
		}
	}
	return FZN_FACET_OK;
}

fzn_facet_err_t fzn_facet_validate(const fzn_facet_expr_t *expr)
{
	fzn_facet_err_t e;
	size_t i, j;

	if (!expr)
		return FZN_FACET_ERR_MALFORMED;
	if (expr->pos_count == 0)
		return FZN_FACET_ERR_EMPTY_POS; /* F14 */

	e = check_side(expr->pos, expr->pos_count);
	if (e != FZN_FACET_OK)
		return e;
	e = check_side(expr->neg, expr->neg_count);
	if (e != FZN_FACET_OK)
		return e;

	/* F27: no term in both P and N. A parent in P and its child in N is a
	 * different term, so this only catches an identical term on both sides. */
	for (i = 0; i < expr->pos_count; i++)
		for (j = 0; j < expr->neg_count; j++)
			if (fzn_facet_term_eq(&expr->pos[i], &expr->neg[j]))
				return FZN_FACET_ERR_BOTH_SIDES;

	return FZN_FACET_OK;
}

/* F19, the part that needs neither the encoding nor the index: collapse a
 * single-member alternation to a prefix, then remove duplicate terms keeping
 * the first. The F16 canonical sort and the F18 member sort/dedup are NOT done
 * -- they order by the unsettled canonical encoding -- and neither is the
 * single-child RANGE collapse, which needs the index. */
static void normalize_side(fzn_facet_term_t *arr, size_t *count)
{
	size_t i, j, w;

	for (i = 0; i < *count; i++) {
		if (arr[i].kind == FZN_FACET_ALT && arr[i].member_count == 1) {
			arr[i].kind = FZN_FACET_PREFIX;
			arr[i].node = arr[i].members[0];
			arr[i].members = NULL;
			arr[i].member_count = 0;
		}
	}

	w = 0;
	for (i = 0; i < *count; i++) {
		int dup = 0;
		for (j = 0; j < w; j++) {
			if (fzn_facet_term_eq(&arr[i], &arr[j])) {
				dup = 1;
				break;
			}
		}
		if (!dup)
			arr[w++] = arr[i];
	}
	*count = w;
}

fzn_facet_err_t fzn_facet_normalize(fzn_facet_term_t *pos, size_t *pos_count,
                                    fzn_facet_term_t *neg, size_t *neg_count)
{
	if (!pos_count || !neg_count)
		return FZN_FACET_ERR_MALFORMED;
	if ((*pos_count != 0 && !pos) || (*neg_count != 0 && !neg))
		return FZN_FACET_ERR_MALFORMED;
	normalize_side(pos, pos_count);
	normalize_side(neg, neg_count);
	return FZN_FACET_OK;
}

fzn_facet_err_t fzn_facet_collate(const uint8_t *value, size_t value_len,
                                  unsigned digit_width,
                                  uint8_t *out, size_t out_cap, size_t *out_len)
{
	size_t i = 0, w = 0;

	if (!out_len)
		return FZN_FACET_ERR_MALFORMED;
	if ((value_len != 0 && !value) || (out_cap != 0 && !out))
		return FZN_FACET_ERR_MALFORMED;

	while (i < value_len) {
		if (is_digit(value[i])) {
			size_t start = i, run, pad, k;
			while (i < value_len && is_digit(value[i]))
				i++;
			run = i - start;
			pad = (run < digit_width) ? (digit_width - run) : 0;
			if (pad > out_cap - w || run > out_cap - w - pad)
				return FZN_FACET_ERR_RANGE;
			for (k = 0; k < pad; k++)
				out[w++] = '0';
			memcpy(out + w, value + start, run);
			w += run;
		} else {
			if (w >= out_cap)
				return FZN_FACET_ERR_RANGE;
			out[w++] = value[i++];
		}
	}
	*out_len = w;
	return FZN_FACET_OK;
}

const char *fzn_facet_err_str(fzn_facet_err_t err)
{
	switch (err) {
	case FZN_FACET_OK:
		return "ok";
	case FZN_FACET_ERR_MALFORMED:
		return "malformed argument";
	case FZN_FACET_ERR_EMPTY_POS:
		return "positive set is empty";
	case FZN_FACET_ERR_ALT_DIMENSION:
		return "alternation spans dimensions";
	case FZN_FACET_ERR_BOTH_SIDES:
		return "term present in both P and N";
	case FZN_FACET_ERR_KIND:
		return "unknown term kind";
	case FZN_FACET_ERR_RANGE:
		return "output buffer too small";
	}
	return "unknown";
}
