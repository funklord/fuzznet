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
	                                      width, out, sizeof(out), &out_len);
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
		fzn_facet_collate((const uint8_t *)"9", 1, 4, a, sizeof(a), &al);
		fzn_facet_collate((const uint8_t *)"10", 2, 4, b, sizeof(b), &bl);
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
		                                      out, sizeof(out), &out_len);
		CHECK(e == FZN_FACET_OK && out_len == 0, "empty value -> empty key");
	}

	/* A buffer too small is refused, not truncated (control for the above:
	 * the same value fits in a bigger buffer). */
	{
		uint8_t small[3];
		size_t out_len = 0;
		fzn_facet_err_t e = fzn_facet_collate((const uint8_t *)"9", 1, 4,
		                                      small, sizeof(small), &out_len);
		CHECK(e == FZN_FACET_ERR_RANGE, "0009 refuses a 3-byte buffer");
		CHECK(collate_is("9", 4, "0009"), "and fits a large one (control)");
	}
}

/* --- structural equality ----------------------------------------------- */

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

int main(void)
{
	test_collation();
	test_term_eq();
	test_validate_refusals();
	test_normalize();

	printf("facet_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
