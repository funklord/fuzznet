/* See codec.h. */

#include "codec.h"

#include <string.h>

/* F16: memcmp order, and where one encoding is a prefix of another the
 * shorter sorts first. The one comparison in this file; F18 is this same
 * function over a member's own encoding. */
static int enc_cmp(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
	size_t n = alen < blen ? alen : blen;
	int r = n ? memcmp(a, b, n) : 0;

	if (r != 0)
		return r;
	if (alen == blen)
		return 0;
	return alen < blen ? -1 : 1;
}

static void put_u16(uint8_t *p, size_t v)
{
	p[0] = (uint8_t)((v >> 8) & 0xffu);
	p[1] = (uint8_t)(v & 0xffu);
}

static size_t get_u16(const uint8_t *p)
{
	return ((size_t)p[0] << 8) | (size_t)p[1];
}

static int name_ok(const uint8_t *b, size_t len)
{
	return b != NULL && len > 0 && len <= FZN_FACET_NAME_MAX;
}

/* How many bytes a bound takes: one for what it is, plus the identifier when
 * it is closed. */
static size_t bound_len(const fzn_facet_bound_t *b)
{
	if (!b->id || b->id_len == 0)
		return 1u;
	return 1u + 1u + b->id_len;
}

/* The encoded length of `term`, or the error that stops it encoding. Computed
 * before anything is written, so a refusal happens before the buffer is
 * touched -- and returning the ERROR rather than a zero length is what lets
 * one caller say RANGE for a name over its field and MALFORMED for a
 * structural fault without working it out a second time. */
static fzn_facet_err_t term_size(const fzn_facet_term_t *t, size_t *out)
{
	size_t n;

	if (t->kind != FZN_FACET_PREFIX && t->kind != FZN_FACET_RANGE
	    && t->kind != FZN_FACET_ALT)
		return FZN_FACET_ERR_KIND;
	if (t->node.dim_len > FZN_FACET_NAME_MAX
	    || t->node.id_len > FZN_FACET_NAME_MAX
	    || t->lo.id_len > FZN_FACET_NAME_MAX
	    || t->hi.id_len > FZN_FACET_NAME_MAX)
		return FZN_FACET_ERR_RANGE;
	if (!name_ok(t->node.dim, t->node.dim_len))
		return FZN_FACET_ERR_MALFORMED;

	switch (t->kind) {
	case FZN_FACET_PREFIX:
		if (!name_ok(t->node.id, t->node.id_len))
			return FZN_FACET_ERR_MALFORMED;
		*out = 1u + 1u + t->node.dim_len + 1u + t->node.id_len;
		return FZN_FACET_OK;
	case FZN_FACET_RANGE:
		if (!name_ok(t->node.id, t->node.id_len))
			return FZN_FACET_ERR_MALFORMED;
		if (t->lo.id && !name_ok(t->lo.id, t->lo.id_len))
			return FZN_FACET_ERR_MALFORMED;
		if (t->hi.id && !name_ok(t->hi.id, t->hi.id_len))
			return FZN_FACET_ERR_MALFORMED;
		*out = 1u + 1u + t->node.dim_len + 1u + t->node.id_len
		       + bound_len(&t->lo) + bound_len(&t->hi);
		return FZN_FACET_OK;
	default: {
		size_t i;

		if (t->member_count > 0xffffu)
			return FZN_FACET_ERR_RANGE;
		/* F19: one member is a PREFIX term, so an alternation that
		 * reaches the wire has at least two. */
		if (!t->members || t->member_count < 2u)
			return FZN_FACET_ERR_MALFORMED;
		n = 1u + 1u + t->node.dim_len + 2u;
		for (i = 0; i < t->member_count; i++) {
			if (t->members[i].id_len > FZN_FACET_NAME_MAX)
				return FZN_FACET_ERR_RANGE;
			if (!name_ok(t->members[i].id, t->members[i].id_len))
				return FZN_FACET_ERR_MALFORMED;
			/* F8, and this is why the dimension is hoisted: a
			 * member in another dimension has nowhere to go. */
			if (enc_cmp(t->members[i].dim, t->members[i].dim_len,
			            t->node.dim, t->node.dim_len) != 0)
				return FZN_FACET_ERR_ALT_DIMENSION;
			n += 1u + t->members[i].id_len;
		}
		*out = n;
		return FZN_FACET_OK;
	}
	}
}

static void put_name(uint8_t *out, size_t *w, const uint8_t *b, size_t len)
{
	out[*w] = (uint8_t)len;
	memcpy(&out[*w + 1u], b, len);
	*w += 1u + len;
}

static void put_bound(uint8_t *out, size_t *w, const fzn_facet_bound_t *b)
{
	if (!b->id || b->id_len == 0) {
		/* An open bound carries no identifier, so `inclusive` has
		 * nothing to apply to and is not written. */
		out[(*w)++] = (uint8_t)FZN_FACET_BOUND_OPEN;
		return;
	}
	out[(*w)++] = (uint8_t)(b->inclusive ? FZN_FACET_BOUND_INCLUSIVE
	                                     : FZN_FACET_BOUND_EXCLUSIVE);
	put_name(out, w, b->id, b->id_len);
}

fzn_facet_err_t fzn_facet_term_encode(const fzn_facet_term_t *term,
                                      uint8_t *out, size_t cap,
                                      size_t *len_out)
{
	size_t need = 0, w = 0;
	fzn_facet_err_t r;

	if (!term || !out || !len_out)
		return FZN_FACET_ERR_MALFORMED;
	r = term_size(term, &need);
	if (r != FZN_FACET_OK)
		return r;
	if (need > cap)
		return FZN_FACET_ERR_RANGE;

	out[w++] = (uint8_t)term->kind;
	put_name(out, &w, term->node.dim, term->node.dim_len);

	switch (term->kind) {
	case FZN_FACET_PREFIX:
		put_name(out, &w, term->node.id, term->node.id_len);
		break;
	case FZN_FACET_RANGE:
		put_name(out, &w, term->node.id, term->node.id_len);
		put_bound(out, &w, &term->lo);
		put_bound(out, &w, &term->hi);
		break;
	case FZN_FACET_ALT: {
		size_t i;

		put_u16(&out[w], term->member_count);
		w += 2u;
		for (i = 0; i < term->member_count; i++)
			put_name(out, &w, term->members[i].id,
			         term->members[i].id_len);
		break;
	}
	default:
		return FZN_FACET_ERR_KIND;
	}

	*len_out = w;
	return FZN_FACET_OK;
}

int fzn_facet_expr_ordered(const fzn_facet_expr_t *expr, uint8_t *scratch,
                           size_t scratch_cap)
{
	const fzn_facet_term_t *side[2];
	size_t counts[2], s;

	if (!expr || !scratch)
		return 0;
	side[0] = expr->pos;
	counts[0] = expr->pos_count;
	side[1] = expr->neg;
	counts[1] = expr->neg_count;

	for (s = 0; s < 2; s++) {
		size_t i, alen = 0, blen = 0;

		for (i = 1; i < counts[s]; i++) {
			size_t half = scratch_cap / 2u;

			if (fzn_facet_term_encode(&side[s][i - 1u], scratch,
			                          half, &alen) != FZN_FACET_OK)
				return 0;
			if (fzn_facet_term_encode(&side[s][i], &scratch[half],
			                          scratch_cap - half, &blen)
			    != FZN_FACET_OK)
				return 0;
			/* STRICTLY ascending: equal is F19's duplicate, which
			 * normalisation removes and an encoding must not
			 * carry. */
			if (enc_cmp(scratch, alen, &scratch[half], blen) >= 0)
				return 0;
		}
	}
	return 1;
}

fzn_facet_err_t fzn_facet_expr_encode(const fzn_facet_expr_t *expr,
                                      uint8_t *out, size_t cap,
                                      size_t *len_out)
{
	fzn_facet_err_t r;
	size_t total = FZN_FACET_EXPR_HEAD_LEN, w, i, s;

	if (!expr || !out || !len_out)
		return FZN_FACET_ERR_MALFORMED;
	r = fzn_facet_validate(expr);
	if (r != FZN_FACET_OK)
		return r;
	if (expr->pos_count > 0xffffu || expr->neg_count > 0xffffu)
		return FZN_FACET_ERR_RANGE;

	for (s = 0; s < 2; s++) {
		const fzn_facet_term_t *terms = s == 0 ? expr->pos : expr->neg;
		size_t count = s == 0 ? expr->pos_count : expr->neg_count;

		for (i = 0; i < count; i++) {
			size_t n = 0;

			r = term_size(&terms[i], &n);
			if (r != FZN_FACET_OK)
				return r;
			total += n;
		}
	}
	if (total > cap)
		return FZN_FACET_ERR_RANGE;

	out[0] = (uint8_t)FZN_FACET_OBJECT_EXPR;
	put_u16(&out[1], expr->pos_count);
	put_u16(&out[3], expr->neg_count);
	w = FZN_FACET_EXPR_HEAD_LEN;

	/* F16 IS CHECKED OVER THE BYTES AS THEY ARE WRITTEN, which is what
	 * makes it cheap: each term is compared with the one before it where
	 * both already lie in `out`, so nothing is encoded twice and no
	 * scratch is needed. */
	for (s = 0; s < 2; s++) {
		const fzn_facet_term_t *terms = s == 0 ? expr->pos : expr->neg;
		size_t count = s == 0 ? expr->pos_count : expr->neg_count;
		size_t prev = w, prev_len = 0;

		for (i = 0; i < count; i++) {
			size_t n = 0;

			r = fzn_facet_term_encode(&terms[i], &out[w], cap - w,
			                          &n);
			if (r != FZN_FACET_OK) {
				memset(out, 0, total);
				return r;
			}
			/* STRICTLY ascending: equal is F19's duplicate, which
			 * normalisation removes and an encoding must not
			 * carry. */
			if (i > 0
			    && enc_cmp(&out[prev], prev_len, &out[w], n) >= 0) {
				/* A refused call leaves nothing a caller that
				 * did not read the status could sign. */
				memset(out, 0, total);
				return FZN_FACET_ERR_MALFORMED;
			}
			prev = w;
			prev_len = n;
			w += n;
		}
	}

	*len_out = w;
	return FZN_FACET_OK;
}

/* Read a length-prefixed name at `*at`, bounded by `len`. */
static int take_name(const uint8_t *body, size_t len, size_t *at,
                     const uint8_t **out, size_t *out_len)
{
	size_t n;

	if (*at >= len)
		return 0;
	n = body[*at];
	if (n == 0 || *at + 1u + n > len)
		return 0;
	*out = &body[*at + 1u];
	*out_len = n;
	*at += 1u + n;
	return 1;
}

static int take_bound(const uint8_t *body, size_t len, size_t *at,
                      fzn_facet_bound_t *b)
{
	uint8_t what;

	if (*at >= len)
		return 0;
	what = body[(*at)++];
	b->id = NULL;
	b->id_len = 0;
	b->inclusive = 0;
	if (what == (uint8_t)FZN_FACET_BOUND_OPEN)
		return 1;
	if (what != (uint8_t)FZN_FACET_BOUND_EXCLUSIVE
	    && what != (uint8_t)FZN_FACET_BOUND_INCLUSIVE)
		return 0;
	b->inclusive = what == (uint8_t)FZN_FACET_BOUND_INCLUSIVE;
	return take_name(body, len, at, &b->id, &b->id_len);
}

/* Decode one term at `*at`. `*used` receives how many alternation member slots
 * were taken. Returns an error, with `*at` left at the fault. */
static fzn_facet_err_t take_term(const uint8_t *body, size_t len, size_t *at,
                                 fzn_facet_term_t *t,
                                 fzn_facet_node_t *members, size_t member_cap,
                                 size_t *used)
{
	uint8_t kind;

	*used = 0;
	memset(t, 0, sizeof(*t));
	if (*at >= len)
		return FZN_FACET_ERR_MALFORMED;
	kind = body[(*at)++];
	/* F26: refused, never skipped -- skipping evaluates a DIFFERENT
	 * expression while reporting success. */
	if (kind != (uint8_t)FZN_FACET_PREFIX && kind != (uint8_t)FZN_FACET_RANGE
	    && kind != (uint8_t)FZN_FACET_ALT)
		return FZN_FACET_ERR_KIND;
	t->kind = (fzn_facet_kind_t)kind;

	if (!take_name(body, len, at, &t->node.dim, &t->node.dim_len))
		return FZN_FACET_ERR_MALFORMED;

	if (kind == (uint8_t)FZN_FACET_PREFIX) {
		if (!take_name(body, len, at, &t->node.id, &t->node.id_len))
			return FZN_FACET_ERR_MALFORMED;
		return FZN_FACET_OK;
	}
	if (kind == (uint8_t)FZN_FACET_RANGE) {
		if (!take_name(body, len, at, &t->node.id, &t->node.id_len))
			return FZN_FACET_ERR_MALFORMED;
		if (!take_bound(body, len, at, &t->lo))
			return FZN_FACET_ERR_MALFORMED;
		if (!take_bound(body, len, at, &t->hi))
			return FZN_FACET_ERR_MALFORMED;
		return FZN_FACET_OK;
	}

	{
		size_t count, i, prev_at = 0, prev_len = 0;

		if (*at + 2u > len)
			return FZN_FACET_ERR_MALFORMED;
		count = get_u16(&body[*at]);
		*at += 2u;
		/* F19: a single-member alternation is a PREFIX term, so this
		 * is not a spelling the format has. */
		if (count < 2u)
			return FZN_FACET_ERR_MALFORMED;
		if (count > member_cap)
			return FZN_FACET_ERR_RANGE;
		for (i = 0; i < count; i++) {
			size_t here = *at;

			/* F8 by construction: every member takes the term's
			 * one dimension, so a member in another dimension is
			 * not expressible. */
			members[i].dim = t->node.dim;
			members[i].dim_len = t->node.dim_len;
			if (!take_name(body, len, at, &members[i].id,
			               &members[i].id_len))
				return FZN_FACET_ERR_MALFORMED;
			/* F18: the same order rule, over a member's own
			 * encoding. */
			if (i > 0 && enc_cmp(&body[prev_at], prev_len,
			                     &body[here], *at - here) >= 0) {
				*at = here;
				return FZN_FACET_ERR_MALFORMED;
			}
			prev_at = here;
			prev_len = *at - here;
		}
		t->members = members;
		t->member_count = count;
		*used = count;
	}
	return FZN_FACET_OK;
}

fzn_facet_err_t fzn_facet_expr_decode(const uint8_t *body, size_t body_len,
                                      fzn_facet_term_t *pos, size_t pos_cap,
                                      fzn_facet_term_t *neg, size_t neg_cap,
                                      fzn_facet_node_t *alt_members,
                                      size_t alt_cap, fzn_facet_expr_t *expr,
                                      size_t *at_out)
{
	size_t at = FZN_FACET_EXPR_HEAD_LEN, pos_count, neg_count, s;
	size_t taken = 0;
	size_t side_start[2];
	fzn_facet_err_t r;

	if (at_out)
		*at_out = 0;
	if (!body || !expr)
		return FZN_FACET_ERR_MALFORMED;
	if (body_len < FZN_FACET_EXPR_HEAD_LEN)
		return FZN_FACET_ERR_MALFORMED;
	if (body[0] != (uint8_t)FZN_FACET_OBJECT_EXPR)
		return FZN_FACET_ERR_MALFORMED;
	pos_count = get_u16(&body[1]);
	neg_count = get_u16(&body[3]);
	/* F14: there is no bare negation. */
	if (pos_count == 0)
		return FZN_FACET_ERR_EMPTY_POS;
	if (pos_count > pos_cap || neg_count > neg_cap)
		return FZN_FACET_ERR_RANGE;

	for (s = 0; s < 2; s++) {
		fzn_facet_term_t *terms = s == 0 ? pos : neg;
		size_t count = s == 0 ? pos_count : neg_count;
		size_t i, prev_at = 0, prev_len = 0;

		side_start[s] = at;
		for (i = 0; i < count; i++) {
			size_t here = at, used = 0;

			r = take_term(body, body_len, &at, &terms[i],
			              &alt_members[taken], alt_cap - taken,
			              &used);
			if (r != FZN_FACET_OK) {
				if (at_out)
					*at_out = at;
				return r;
			}
			taken += used;
			/* F16, over the bytes as they lie -- nothing is
			 * re-encoded to compare two neighbours. */
			if (i > 0 && enc_cmp(&body[prev_at], prev_len,
			                     &body[here], at - here) >= 0) {
				if (at_out)
					*at_out = here;
				return FZN_FACET_ERR_MALFORMED;
			}
			prev_at = here;
			prev_len = at - here;
		}
	}

	/* A TRAILING BYTE IS REFUSED, not ignored: an expression is hashed for
	 * identity, so two spellings of one expression would be two
	 * identities. */
	if (at != body_len) {
		if (at_out)
			*at_out = at;
		return FZN_FACET_ERR_MALFORMED;
	}

	expr->pos = pos;
	expr->pos_count = pos_count;
	expr->neg = neg;
	expr->neg_count = neg_count;

	/* F27: a term in both P and N denotes the empty set and arrives only
	 * from a hand-written rendering. Both sides are in F16 order, so this
	 * is a merge rather than a product -- and each term's encoded length
	 * comes from the term this parse just filled, never from parsing the
	 * bytes a second time with different arguments. */
	{
		size_t a = side_start[0], b = side_start[1], ia = 0, ib = 0;

		while (ia < pos_count && ib < neg_count) {
			size_t alen = 0, blen = 0;
			int c;

			if (term_size(&pos[ia], &alen) != FZN_FACET_OK
			    || term_size(&neg[ib], &blen) != FZN_FACET_OK)
				return FZN_FACET_ERR_MALFORMED;
			c = enc_cmp(&body[a], alen, &body[b], blen);
			if (c == 0) {
				if (at_out)
					*at_out = a;
				return FZN_FACET_ERR_BOTH_SIDES;
			}
			if (c < 0) {
				a += alen;
				ia++;
			} else {
				b += blen;
				ib++;
			}
		}
	}
	return FZN_FACET_OK;
}
