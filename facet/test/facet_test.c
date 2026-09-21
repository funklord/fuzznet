/* Tests for facet/facet.c: the settled in-memory core of facet.h.
 *
 * THE CASES THIS SUITE EXISTS FOR are the F27 refusals -- an empty P, an
 * alternation spanning dimensions, and a term on both sides. facet.h's
 * section 6 calls refusal the safety core: a wrong set drives a placement or a
 * deletion, so each refusal is checked WITH a well-formed control that passes,
 * because "refused" is worthless if the validator refuses everything. The
 * collation and normalisation checks are shapes and are cheaper.
 *
 * Not tested here because not implemented (facet.h section 8): the wire
 * encoding, evaluation against an index, and the F16 canonical sort.
 */

#include "../facet.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL facet_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* --- constructors over borrowed literals ------------------------------- */

static fzn_facet_node_t node(const char *dim, const char *id)
{
	fzn_facet_node_t n;
	n.dim = (const uint8_t *)dim;
	n.dim_len = strlen(dim);
	n.id = (const uint8_t *)id;
	n.id_len = strlen(id);
	return n;
}

static fzn_facet_term_t prefix(const char *dim, const char *id)
{
	fzn_facet_term_t t;
	memset(&t, 0, sizeof(t));
	t.kind = FZN_FACET_PREFIX;
	t.node = node(dim, id);
	return t;
}

/* --- F20: the collation key -------------------------------------------- */

static int collate_is(const char *in, unsigned width, const char *want)
{
	uint8_t out[64];
	size_t out_len = 0;
	fzn_facet_err_t e = fzn_facet_collate((const uint8_t *)in, strlen(in),
	                                      width, out, sizeof(out), &out_len, NULL);
	if (e != FZN_FACET_OK)
		return 0;
	return out_len == strlen(want) && memcmp(out, want, out_len) == 0;
}

static void test_collation(void)
{
	/* The header's own examples, digit width 4. */
	CHECK(collate_is("1994", 4, "1994"), "1994 unchanged");
	CHECK(collate_is("9", 4, "0009"), "9 pads to 0009");
	CHECK(collate_is("10", 4, "0010"), "10 pads to 0010");
	CHECK(collate_is("720p", 4, "0720p"), "720p pads the digit run only");
	CHECK(collate_is("1080p", 4, "1080p"), "1080p already four digits");

	/* Natural order holds after collation: 9 sorts before 10. */
	{
		uint8_t a[8], b[8];
		size_t al = 0, bl = 0;
		fzn_facet_collate((const uint8_t *)"9", 1, 4, a, sizeof(a), &al, NULL);
		fzn_facet_collate((const uint8_t *)"10", 2, 4, b, sizeof(b), &bl, NULL);
		CHECK(memcmp(a, b, 4) < 0, "collated 9 sorts before 10");
	}

	/* Several runs in one value are each padded. */
	CHECK(collate_is("s1e9", 4, "s0001e0009"), "each digit run padded");

	/* A run already at/above the width is not truncated. */
	CHECK(collate_is("12345", 4, "12345"), "over-width run kept whole");

	/* Empty value is an empty key, not an error. */
	{
		uint8_t out[4];
		size_t out_len = 123;
		fzn_facet_err_t e = fzn_facet_collate((const uint8_t *)"", 0, 4,
		                                      out, sizeof(out), &out_len, NULL);
		CHECK(e == FZN_FACET_OK && out_len == 0, "empty value -> empty key");
	}

	/* A buffer too small is refused, not truncated (control for the above:
	 * the same value fits in a bigger buffer). */
	{
		uint8_t small[3];
		size_t out_len = 0;
		fzn_facet_err_t e = fzn_facet_collate((const uint8_t *)"9", 1, 4,
		                                      small, sizeof(small), &out_len, NULL);
		CHECK(e == FZN_FACET_ERR_RANGE, "0009 refuses a 3-byte buffer");
		CHECK(collate_is("9", 4, "0009"), "and fits a large one (control)");
	}
}

/* --- structural equality ----------------------------------------------- */

static void test_the_width_belongs_to_the_dimension(void)
{
	/* F20, settled 2026-09-21: the width is declared by the dimension, so
	 * a year dimension pads to 4 and a size dimension to 10 and neither
	 * pays for the other's range. */
	static const uint8_t YEAR[] = "year";
	static const uint8_t SIZE[] = "size";
	static const uint8_t CODE[] = "code";
	fzn_facet_dimension_t dims[3];
	uint8_t out[64];
	size_t len = 0;
	int unpadded = -1;

	dims[0].name = YEAR;
	dims[0].name_len = sizeof(YEAR) - 1u;
	dims[0].collation = FZN_FACET_COLLATE_NATURAL;
	dims[0].digit_width = 4;
	dims[1].name = SIZE;
	dims[1].name_len = sizeof(SIZE) - 1u;
	dims[1].collation = FZN_FACET_COLLATE_NATURAL;
	dims[1].digit_width = 10;
	dims[2].name = CODE;
	dims[2].name_len = sizeof(CODE) - 1u;
	dims[2].collation = FZN_FACET_COLLATE_RAW;
	dims[2].digit_width = 0;

	CHECK(fzn_facet_dimension_find(dims, 3, YEAR, 4) == &dims[0],
	      "a declared dimension was not found");
	CHECK(fzn_facet_dimension_find(dims, 3, (const uint8_t *)"nope", 4)
	          == NULL, "an undeclared dimension was found");
	CHECK(fzn_facet_dimension_find(dims, 3, YEAR, 3) == NULL,
	      "a prefix of a dimension name matched it");

	/* Each dimension pays only its own width. */
	CHECK(fzn_facet_collate_for(&dims[0], (const uint8_t *)"7", 1, out,
	                            sizeof(out), &len, &unpadded)
	          == FZN_FACET_OK && len == 4 && memcmp(out, "0007", 4) == 0,
	      "the year dimension did not pad to 4");
	CHECK(unpadded == 0, "a padded run reported itself unpadded");
	CHECK(fzn_facet_collate_for(&dims[1], (const uint8_t *)"7", 1, out,
	                            sizeof(out), &len, &unpadded)
	          == FZN_FACET_OK && len == 10
	          && memcmp(out, "0000000007", 10) == 0,
	      "the size dimension did not pad to 10");

	/* RAW copies the value and never reports an unpadded run: there is no
	 * padding to fall short of. */
	unpadded = -1;
	CHECK(fzn_facet_collate_for(&dims[2], (const uint8_t *)"0009", 4, out,
	                            sizeof(out), &len, &unpadded)
	          == FZN_FACET_OK && len == 4 && memcmp(out, "0009", 4) == 0,
	      "a RAW dimension did not copy its value");
	CHECK(unpadded == 0, "a RAW dimension reported an unpadded run");

	/* THE SIGNAL, which is what makes the per-dimension width safe: a run
	 * at or above the width is left unpadded and the key MISORDERS from
	 * there -- unpadded 9999 sorts after unpadded 10000 -- and nothing
	 * else would say so. */
	unpadded = -1;
	CHECK(fzn_facet_collate_for(&dims[0], (const uint8_t *)"44100", 5, out,
	                            sizeof(out), &len, &unpadded)
	          == FZN_FACET_OK, "a long run would not collate");
	CHECK(unpadded == 1,
	      "a run over the dimension's width was not reported");
	/* And the misordering it warns about is real, which is why the flag
	 * is not decoration. */
	{
		uint8_t a[16], b[16];
		size_t la = 0, lb = 0;
		int ua = 0, ub = 0;

		fzn_facet_collate((const uint8_t *)"9999", 4, 4, a, sizeof(a),
		                  &la, &ua);
		fzn_facet_collate((const uint8_t *)"10000", 5, 4, b, sizeof(b),
		                  &lb, &ub);
		CHECK(ua == 1 && ub == 1, "neither long run was reported");
		CHECK(memcmp(a, b, la < lb ? la : lb) > 0,
		      "9999 did not misorder against 10000 -- the flag would "
		      "then be warning about nothing");
	}

	/* A NATURAL declaration of width zero pads nothing, which is RAW said
	 * a second way. One spelling per thing. */
	dims[0].digit_width = 0;
	CHECK(fzn_facet_collate_for(&dims[0], (const uint8_t *)"7", 1, out,
	                            sizeof(out), &len, &unpadded)
	          == FZN_FACET_ERR_MALFORMED,
	      "a NATURAL dimension of width zero collated");
	dims[0].digit_width = 4;
	/* The control: putting the width back makes it work again. */
	CHECK(fzn_facet_collate_for(&dims[0], (const uint8_t *)"7", 1, out,
	                            sizeof(out), &len, &unpadded)
	          == FZN_FACET_OK, "the restored declaration would not collate");
	/* A collation this build does not know, F26's instinct one layer out. */
	dims[0].collation = (fzn_facet_collation_t)7;
	CHECK(fzn_facet_collate_for(&dims[0], (const uint8_t *)"7", 1, out,
	                            sizeof(out), &len, &unpadded)
	          == FZN_FACET_ERR_MALFORMED, "an unknown collation collated");
	CHECK(fzn_facet_collate_for(NULL, (const uint8_t *)"7", 1, out,
	                            sizeof(out), &len, &unpadded)
	          == FZN_FACET_ERR_MALFORMED, "a null declaration collated");
}

static void test_term_eq(void)
{
	fzn_facet_term_t a = prefix("genre", "house");
	fzn_facet_term_t b = prefix("genre", "house");
	fzn_facet_term_t c = prefix("genre", "techno");
	fzn_facet_term_t d = prefix("year", "house");

	CHECK(fzn_facet_term_eq(&a, &b), "same prefix equal");
	CHECK(!fzn_facet_term_eq(&a, &c), "different id not equal");
	CHECK(!fzn_facet_term_eq(&a, &d), "different dimension not equal");

	/* ALT compares as a set: order does not matter. */
	{
		fzn_facet_node_t m1[2] = { node("g", "a"), node("g", "b") };
		fzn_facet_node_t m2[2] = { node("g", "b"), node("g", "a") };
		fzn_facet_term_t alt1, alt2;
		memset(&alt1, 0, sizeof(alt1));
		memset(&alt2, 0, sizeof(alt2));
		alt1.kind = FZN_FACET_ALT;
		alt1.members = m1;
		alt1.member_count = 2;
		alt2.kind = FZN_FACET_ALT;
		alt2.members = m2;
		alt2.member_count = 2;
		CHECK(fzn_facet_term_eq(&alt1, &alt2), "alternation equal regardless of order");

		alt2.member_count = 1;
		CHECK(!fzn_facet_term_eq(&alt1, &alt2), "different member count not equal");
	}

	/* RANGE bounds participate: an inclusive and an exclusive hi differ. */
	{
		fzn_facet_term_t r1, r2;
		memset(&r1, 0, sizeof(r1));
		memset(&r2, 0, sizeof(r2));
		r1.kind = r2.kind = FZN_FACET_RANGE;
		r1.node = r2.node = node("year", "y");
		r1.hi.id = r2.hi.id = (const uint8_t *)"1997";
		r1.hi.id_len = r2.hi.id_len = 4;
		r1.hi.inclusive = 1;
		r2.hi.inclusive = 0;
		CHECK(!fzn_facet_term_eq(&r1, &r2), "inclusive vs exclusive bound differ");
		r2.hi.inclusive = 1;
		CHECK(fzn_facet_term_eq(&r1, &r2), "identical ranges equal (control)");
	}
}

/* --- F27 refusals, each with a passing control ------------------------- */

static void test_validate_refusals(void)
{
	fzn_facet_term_t p[2];
	fzn_facet_term_t n[2];
	fzn_facet_expr_t e;

	/* Control: a plain well-formed expression passes. */
	p[0] = prefix("genre", "action");
	p[1] = prefix("year", "1994");
	e.pos = p;
	e.pos_count = 2;
	e.neg = NULL;
	e.neg_count = 0;
	CHECK(fzn_facet_validate(&e) == FZN_FACET_OK, "well-formed passes (control)");

	/* F14: P empty is refused. */
	e.pos_count = 0;
	CHECK(fzn_facet_validate(&e) == FZN_FACET_ERR_EMPTY_POS, "empty P refused");
	e.pos_count = 2; /* restore */

	/* F27: a term in both P and N is refused; a parent/child split is not. */
	n[0] = prefix("genre", "action"); /* identical to p[0] */
	e.neg = n;
	e.neg_count = 1;
	CHECK(fzn_facet_validate(&e) == FZN_FACET_ERR_BOTH_SIDES, "same term both sides refused");
	n[0] = prefix("genre", "action/hard"); /* a child, different term */
	CHECK(fzn_facet_validate(&e) == FZN_FACET_OK, "parent in P, child in N is fine (control)");
	e.neg_count = 0;

	/* F8/F27: an alternation spanning dimensions is refused; one dimension
	 * passes. */
	{
		fzn_facet_node_t cross[2] = { node("genre", "a"), node("year", "1994") };
		fzn_facet_node_t same[2] = { node("genre", "a"), node("genre", "b") };
		p[0].kind = FZN_FACET_ALT;
		p[0].members = cross;
		p[0].member_count = 2;
		CHECK(fzn_facet_validate(&e) == FZN_FACET_ERR_ALT_DIMENSION,
		      "cross-dimension alternation refused");
		p[0].members = same;
		CHECK(fzn_facet_validate(&e) == FZN_FACET_OK,
		      "single-dimension alternation passes (control)");

		/* An empty alternation is degenerate and refused. */
		p[0].member_count = 0;
		CHECK(fzn_facet_validate(&e) == FZN_FACET_ERR_MALFORMED,
		      "empty alternation refused");
	}

	/* F26: an unknown term kind is refused, never skipped. */
	p[0] = prefix("genre", "action");
	p[0].kind = (fzn_facet_kind_t)99;
	CHECK(fzn_facet_validate(&e) == FZN_FACET_ERR_KIND, "unknown kind refused");
}

/* --- F19 normalisation ------------------------------------------------- */

static void test_normalize(void)
{
	/* A single-member alternation collapses to a prefix, and then equals the
	 * prefix written directly -- so the two spellings dedup (F19). */
	{
		fzn_facet_node_t m[1] = { node("genre", "house") };
		fzn_facet_term_t pos[2];
		fzn_facet_term_t neg[1];
		size_t pc = 2, nc = 0;

		memset(&pos[0], 0, sizeof(pos[0]));
		pos[0].kind = FZN_FACET_ALT;
		pos[0].members = m;
		pos[0].member_count = 1;
		pos[1] = prefix("genre", "house");

		CHECK(fzn_facet_normalize(pos, &pc, neg, &nc) == FZN_FACET_OK, "normalize ok");
		CHECK(pc == 1, "single-member alt and its prefix dedup to one");
		CHECK(pos[0].kind == FZN_FACET_PREFIX, "collapsed to a prefix");
		CHECK(pos[0].node.id_len == 5 && memcmp(pos[0].node.id, "house", 5) == 0,
		      "collapsed prefix keeps the member");
	}

	/* Duplicate terms within a side are removed, first kept, order otherwise
	 * preserved. */
	{
		fzn_facet_term_t pos[3];
		size_t pc = 3, nc = 0;
		pos[0] = prefix("genre", "a");
		pos[1] = prefix("genre", "b");
		pos[2] = prefix("genre", "a");
		CHECK(fzn_facet_normalize(pos, &pc, NULL, &nc) == FZN_FACET_OK, "normalize ok");
		CHECK(pc == 2, "duplicate term removed");
		{
			fzn_facet_term_t want = prefix("genre", "a");
			CHECK(fzn_facet_term_eq(&pos[0], &want), "first occurrence kept");
		}
	}
}

/* --- F11-F13, F24: evaluation against a stub index --------------------- */

/* A stub ordered index: each prefix node maps to a fixed entity set, one of
 * them marked incomplete so F24 can be exercised. Keyed on the term's node id,
 * which is all the prefix terms below use. */
struct stub_post {
	const char *node;
	const char *ents[4];
	size_t n;
	int incomplete;
};

static const struct stub_post STUB[] = {
	{ "house", { "e1", "e2", "e3" }, 3, 0 },
	{ "y1994", { "e2", "e3", "e4" }, 3, 0 },
	{ "y1990", { "e1" }, 1, 0 },
	{ "partial", { "e9" }, 1, 1 },
};

static fzn_facet_err_t stub_postings(void *ctx, const fzn_facet_term_t *term,
                                     fzn_facet_entity_t *out, size_t out_cap,
                                     size_t *out_count, int *incomplete)
{
	size_t i, k;

	(void)ctx;
	*out_count = 0;
	*incomplete = 0;
	for (i = 0; i < sizeof(STUB) / sizeof(STUB[0]); i++) {
		if (term->node.id_len != strlen(STUB[i].node)
		    || memcmp(term->node.id, STUB[i].node, term->node.id_len) != 0)
			continue;
		if (STUB[i].n > out_cap)
			return FZN_FACET_ERR_RANGE;
		for (k = 0; k < STUB[i].n; k++) {
			out[k].id = (const uint8_t *)STUB[i].ents[k];
			out[k].id_len = strlen(STUB[i].ents[k]);
		}
		*out_count = STUB[i].n;
		*incomplete = STUB[i].incomplete;
		return FZN_FACET_OK;
	}
	return FZN_FACET_OK; /* an unknown node selects nothing */
}

static int has(const fzn_facet_entity_t *out, size_t n, const char *s)
{
	size_t i;
	for (i = 0; i < n; i++)
		if (out[i].id_len == strlen(s) && memcmp(out[i].id, s, out[i].id_len) == 0)
			return 1;
	return 0;
}

static void test_evaluate(void)
{
	fzn_facet_index_ops_t index = { NULL, stub_postings };
	fzn_facet_entity_t out[16], scratch[16];
	size_t n = 0;

	/* Intersection: house AND y1994 = {e2, e3}. */
	{
		fzn_facet_term_t p[2] = { prefix("genre", "house"),
		                          prefix("year", "y1994") };
		fzn_facet_expr_t e = { p, 2, NULL, 0 };
		CHECK(fzn_facet_evaluate(&e, &index, out, 16, &n, scratch, 16)
		      == FZN_FACET_OK, "evaluate ok");
		CHECK(n == 2 && has(out, n, "e2") && has(out, n, "e3") && !has(out, n, "e1"),
		      "house AND y1994 is e2, e3");
	}

	/* Difference: house MINUS y1990 = {e2, e3} (e1 removed). */
	{
		fzn_facet_term_t p[1] = { prefix("genre", "house") };
		fzn_facet_term_t neg[1] = { prefix("year", "y1990") };
		fzn_facet_expr_t e = { p, 1, neg, 1 };
		CHECK(fzn_facet_evaluate(&e, &index, out, 16, &n, scratch, 16)
		      == FZN_FACET_OK, "evaluate ok");
		CHECK(n == 2 && !has(out, n, "e1") && has(out, n, "e2"),
		      "house minus y1990 drops e1");
	}

	/* F24: an incomplete term in N is refused -- subtracting a partial set
	 * over-includes, which could drive a deletion. */
	{
		fzn_facet_term_t p[1] = { prefix("genre", "house") };
		fzn_facet_term_t neg[1] = { prefix("x", "partial") };
		fzn_facet_expr_t e = { p, 1, neg, 1 };
		CHECK(fzn_facet_evaluate(&e, &index, out, 16, &n, scratch, 16)
		      == FZN_FACET_ERR_INCOMPLETE, "incomplete N term refused (F24)");
	}

	/* F24 asymmetry: an incomplete term in P is a partial, not a refusal --
	 * it under-includes, which is a visible absence. */
	{
		fzn_facet_term_t p[1] = { prefix("x", "partial") };
		fzn_facet_expr_t e = { p, 1, NULL, 0 };
		CHECK(fzn_facet_evaluate(&e, &index, out, 16, &n, scratch, 16)
		      == FZN_FACET_OK && n == 1,
		      "incomplete P term is a partial, not a refusal");
	}

	/* A malformed expression is refused before the index is touched. */
	{
		fzn_facet_expr_t e = { NULL, 0, NULL, 0 };
		CHECK(fzn_facet_evaluate(&e, &index, out, 16, &n, scratch, 16)
		      == FZN_FACET_ERR_EMPTY_POS, "empty P refused before the index");
	}
}

int main(void)
{
	test_collation();
	test_the_width_belongs_to_the_dimension();
	test_term_eq();
	test_validate_refusals();
	test_normalize();
	test_evaluate();

	printf("facet_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
