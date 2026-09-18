/* Tests for catalogue/catalogue.c: the settled merge core of catalogue.h.
 *
 * THE CASES THIS SUITE EXISTS FOR are the C5b resolutions and the C28 refusal.
 * "Never silently pick a winner" is the property being defended, so each merge
 * rule is checked for what it retains and what it attributes, and the refusal
 * of a mixed resolution set is paired with a well-formed control that passes.
 *
 * Not tested because not implemented (catalogue.h section 7): the wire
 * encoding, and the deletion/import/source machinery.
 */

#include "../catalogue.h"

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
	fprintf(stderr, "  FAIL catalogue_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* One assertion about the entity "E", attribute "genre", with the given issuer,
 * value, merge rule and live flag. The other axes are fixed so a set built with
 * this helper is one attribute unless a test changes a field on purpose. */
static fzn_catalogue_assertion_t mk(const char *issuer, const char *value,
                                    fzn_catalogue_merge_t merge, int live)
{
	fzn_catalogue_assertion_t a;
	memset(&a, 0, sizeof(a));
	a.issuer = (const uint8_t *)issuer;
	a.issuer_len = strlen(issuer);
	a.entity = (const uint8_t *)"E";
	a.entity_len = 1;
	a.name = (const uint8_t *)"genre";
	a.name_len = 5;
	a.value = (const uint8_t *)value;
	a.value_len = strlen(value);
	a.attr_class = FZN_CATALOGUE_LABEL;
	a.scope = FZN_CATALOGUE_ESTATE;
	a.merge = merge;
	a.capability = FZN_CATALOGUE_CAP_NONE;
	a.live = live;
	return a;
}

static int val_is(const fzn_catalogue_resolved_t *r, const char *s)
{
	return r->value_len == strlen(s) && memcmp(r->value, s, r->value_len) == 0;
}

static int iss_is(const fzn_catalogue_resolved_t *r, const char *s)
{
	return r->issuer_len == strlen(s) && memcmp(r->issuer, s, r->issuer_len) == 0;
}

/* --- C28 validation, each refusal with a passing control --------------- */

static void test_validate(void)
{
	fzn_catalogue_assertion_t set[2];

	/* Control: two assertions about one attribute pass. */
	set[0] = mk("reg", "house", FZN_CATALOGUE_UNION, 1);
	set[1] = mk("fan", "techno", FZN_CATALOGUE_UNION, 1);
	CHECK(fzn_catalogue_validate(set, 2) == FZN_CATALOGUE_OK,
	      "one attribute passes (control)");

	/* Empty set is sound (resolves to nothing). */
	CHECK(fzn_catalogue_validate(NULL, 0) == FZN_CATALOGUE_OK, "empty set ok");

	/* A different name is a different attribute -> refused. */
	set[1].name = (const uint8_t *)"year";
	set[1].name_len = 4;
	CHECK(fzn_catalogue_validate(set, 2) == FZN_CATALOGUE_ERR_NOT_ONE_ATTRIBUTE,
	      "different name refused");
	set[1] = mk("fan", "techno", FZN_CATALOGUE_UNION, 1); /* restore */

	/* A different merge rule is a different attribute declaration -> refused. */
	set[1].merge = FZN_CATALOGUE_DISTINCT;
	CHECK(fzn_catalogue_validate(set, 2) == FZN_CATALOGUE_ERR_NOT_ONE_ATTRIBUTE,
	      "different merge rule refused");
	set[1] = mk("fan", "techno", FZN_CATALOGUE_UNION, 1);

	/* A different entity -> refused. */
	set[1].entity = (const uint8_t *)"F";
	CHECK(fzn_catalogue_validate(set, 2) == FZN_CATALOGUE_ERR_NOT_ONE_ATTRIBUTE,
	      "different entity refused");
	set[1] = mk("fan", "techno", FZN_CATALOGUE_UNION, 1);

	/* An unknown enum value is refused, never skipped (C28/F26). */
	set[1].attr_class = (fzn_catalogue_class_t)99;
	CHECK(fzn_catalogue_validate(set, 2) == FZN_CATALOGUE_ERR_KIND,
	      "unknown class refused");
}

/* --- C5b UNION --------------------------------------------------------- */

static void test_union(void)
{
	fzn_catalogue_assertion_t set[4];
	fzn_catalogue_resolved_t out[8];
	size_t n = 0;

	set[0] = mk("i1", "a", FZN_CATALOGUE_UNION, 1);
	set[1] = mk("i2", "b", FZN_CATALOGUE_UNION, 1);
	set[2] = mk("i3", "a", FZN_CATALOGUE_UNION, 1); /* same value as set[0] */
	set[3] = mk("i4", "c", FZN_CATALOGUE_UNION, 0); /* not live */

	CHECK(fzn_catalogue_resolve(set, 4, NULL, 0, out, 8, &n) == FZN_CATALOGUE_OK,
	      "union resolves");
	CHECK(n == 2, "union is the distinct live values (a, b; c dropped, a deduped)");
	CHECK(val_is(&out[0], "a") && val_is(&out[1], "b"), "union values a then b");
	CHECK(!out[0].authoritative && !out[1].authoritative, "union marks nothing authoritative");
}

/* --- C5b AUTHORITATIVE ------------------------------------------------- */

static void test_authoritative(void)
{
	fzn_catalogue_assertion_t set[3];
	fzn_catalogue_resolved_t out[8];
	size_t n = 0;

	set[0] = mk("fan", "fan-name", FZN_CATALOGUE_AUTHORITATIVE, 1);
	set[1] = mk("reg", "official", FZN_CATALOGUE_AUTHORITATIVE, 1); /* authority */
	set[2] = mk("other", "official", FZN_CATALOGUE_AUTHORITATIVE, 1); /* dup value */

	/* The authority's value comes first and is marked; the other distinct
	 * value stands (precedence, not exclusivity); the duplicate is deduped. */
	CHECK(fzn_catalogue_resolve(set, 3, (const uint8_t *)"reg", 3, out, 8, &n)
	      == FZN_CATALOGUE_OK, "authoritative resolves");
	CHECK(n == 2, "authority's value plus the one other distinct value");
	CHECK(val_is(&out[0], "official") && iss_is(&out[0], "reg") && out[0].authoritative,
	      "authority's value first and marked");
	CHECK(val_is(&out[1], "fan-name") && !out[1].authoritative,
	      "the other issuer's value stands, unmarked");

	/* Authority silent: the others stand, none marked authoritative. */
	n = 0;
	CHECK(fzn_catalogue_resolve(set, 3, (const uint8_t *)"absent", 6, out, 8, &n)
	      == FZN_CATALOGUE_OK, "authoritative with silent authority resolves");
	CHECK(n == 2 && !out[0].authoritative && !out[1].authoritative,
	      "silent authority leaves others standing, unmarked");

	/* No authority named at all is a refusal, not a guess. */
	n = 0;
	CHECK(fzn_catalogue_resolve(set, 3, NULL, 0, out, 8, &n)
	      == FZN_CATALOGUE_ERR_NO_AUTHORITY, "authoritative needs a named authority");
}

/* --- C5b DISTINCT ------------------------------------------------------ */

static void test_distinct(void)
{
	fzn_catalogue_assertion_t set[3];
	fzn_catalogue_resolved_t out[8];
	size_t n = 0;

	set[0] = mk("i1", "a", FZN_CATALOGUE_DISTINCT, 1);
	set[1] = mk("i2", "b", FZN_CATALOGUE_DISTINCT, 1);
	set[2] = mk("i3", "a", FZN_CATALOGUE_DISTINCT, 1); /* same value, kept */

	/* Every live assertion retained with its issuer -- no dedup, no winner. */
	CHECK(fzn_catalogue_resolve(set, 3, NULL, 0, out, 8, &n) == FZN_CATALOGUE_OK,
	      "distinct resolves");
	CHECK(n == 3, "distinct retains every live assertion, even equal values");
	CHECK(iss_is(&out[0], "i1") && iss_is(&out[2], "i3"),
	      "distinct keeps attribution -- whose value each is");
}

/* --- equality and bounds ----------------------------------------------- */

static void test_eq_and_bounds(void)
{
	fzn_catalogue_assertion_t a = mk("i1", "x", FZN_CATALOGUE_UNION, 1);
	fzn_catalogue_assertion_t b = mk("i1", "x", FZN_CATALOGUE_UNION, 0); /* live differs */
	fzn_catalogue_assertion_t c = mk("i2", "x", FZN_CATALOGUE_UNION, 1);
	fzn_catalogue_resolved_t out[1];
	size_t n = 0;

	CHECK(fzn_catalogue_assertion_eq(&a, &b), "eq ignores the live flag");
	CHECK(!fzn_catalogue_assertion_eq(&a, &c), "eq distinguishes the issuer");

	/* A resolved set that will not fit is refused, not truncated. */
	{
		fzn_catalogue_assertion_t set[2];
		set[0] = mk("i1", "a", FZN_CATALOGUE_UNION, 1);
		set[1] = mk("i2", "b", FZN_CATALOGUE_UNION, 1);
		CHECK(fzn_catalogue_resolve(set, 2, NULL, 0, out, 1, &n)
		      == FZN_CATALOGUE_ERR_RANGE, "resolve refuses a too-small buffer");
	}
}

int main(void)
{
	test_validate();
	test_union();
	test_authoritative();
	test_distinct();
	test_eq_and_bounds();

	printf("catalogue_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
