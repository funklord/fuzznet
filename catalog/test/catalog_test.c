/* Tests for catalog/catalog.c: the settled merge core of catalog.h.
 *
 * THE CASES THIS SUITE EXISTS FOR are the C5b resolutions and the C28 refusal.
 * "Never silently pick a winner" is the property being defended, so each merge
 * rule is checked for what it retains and what it attributes, and the refusal
 * of a mixed resolution set is paired with a well-formed control that passes.
 *
 * Not tested because not implemented (catalog.h section 7): the wire
 * encoding, and the deletion/import/source machinery.
 */

#include "../catalog.h"

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
	fprintf(stderr, "  FAIL catalog_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* One assertion about the entity "E", attribute "genre", with the given issuer,
 * value, merge rule and live flag. The other axes are fixed so a set built with
 * this helper is one attribute unless a test changes a field on purpose. */
static fzn_catalog_assertion_t mk(const char *issuer, const char *value,
                                    fzn_catalog_merge_t merge, int live)
{
	fzn_catalog_assertion_t a;
	memset(&a, 0, sizeof(a));
	a.issuer = (const uint8_t *)issuer;
	a.issuer_len = strlen(issuer);
	a.entity = (const uint8_t *)"E";
	a.entity_len = 1;
	a.name = (const uint8_t *)"genre";
	a.name_len = 5;
	a.value = (const uint8_t *)value;
	a.value_len = strlen(value);
	a.attr_class = FZN_CATALOG_LABEL;
	a.scope = FZN_CATALOG_ESTATE;
	a.merge = merge;
	a.capability = FZN_CATALOG_CAP_NONE;
	a.live = live;
	return a;
}

static int val_is(const fzn_catalog_resolved_t *r, const char *s)
{
	return r->value_len == strlen(s) && memcmp(r->value, s, r->value_len) == 0;
}

static int iss_is(const fzn_catalog_resolved_t *r, const char *s)
{
	return r->issuer_len == strlen(s) && memcmp(r->issuer, s, r->issuer_len) == 0;
}

/* --- C28 validation, each refusal with a passing control --------------- */

static void test_validate(void)
{
	fzn_catalog_assertion_t set[2];

	/* Control: two assertions about one attribute pass. */
	set[0] = mk("reg", "house", FZN_CATALOG_UNION, 1);
	set[1] = mk("fan", "techno", FZN_CATALOG_UNION, 1);
	CHECK(fzn_catalog_validate(set, 2) == FZN_CATALOG_OK,
	      "one attribute passes (control)");

	/* Empty set is sound (resolves to nothing). */
	CHECK(fzn_catalog_validate(NULL, 0) == FZN_CATALOG_OK, "empty set ok");

	/* A different name is a different attribute -> refused. */
	set[1].name = (const uint8_t *)"year";
	set[1].name_len = 4;
	CHECK(fzn_catalog_validate(set, 2) == FZN_CATALOG_ERR_NOT_ONE_ATTRIBUTE,
	      "different name refused");
	set[1] = mk("fan", "techno", FZN_CATALOG_UNION, 1); /* restore */

	/* A different merge rule is a different attribute declaration -> refused. */
	set[1].merge = FZN_CATALOG_DISTINCT;
	CHECK(fzn_catalog_validate(set, 2) == FZN_CATALOG_ERR_NOT_ONE_ATTRIBUTE,
	      "different merge rule refused");
	set[1] = mk("fan", "techno", FZN_CATALOG_UNION, 1);

	/* A different entity -> refused. */
	set[1].entity = (const uint8_t *)"F";
	CHECK(fzn_catalog_validate(set, 2) == FZN_CATALOG_ERR_NOT_ONE_ATTRIBUTE,
	      "different entity refused");
	set[1] = mk("fan", "techno", FZN_CATALOG_UNION, 1);

	/* An unknown enum value is refused, never skipped (C28/F26). */
	set[1].attr_class = (fzn_catalog_class_t)99;
	CHECK(fzn_catalog_validate(set, 2) == FZN_CATALOG_ERR_KIND,
	      "unknown class refused");
}

/* --- C5b UNION --------------------------------------------------------- */

static void test_union(void)
{
	fzn_catalog_assertion_t set[4];
	fzn_catalog_resolved_t out[8];
	size_t n = 0;

	set[0] = mk("i1", "a", FZN_CATALOG_UNION, 1);
	set[1] = mk("i2", "b", FZN_CATALOG_UNION, 1);
	set[2] = mk("i3", "a", FZN_CATALOG_UNION, 1); /* same value as set[0] */
	set[3] = mk("i4", "c", FZN_CATALOG_UNION, 0); /* not live */

	CHECK(fzn_catalog_resolve(set, 4, NULL, 0, out, 8, &n) == FZN_CATALOG_OK,
	      "union resolves");
	CHECK(n == 2, "union is the distinct live values (a, b; c dropped, a deduped)");
	CHECK(val_is(&out[0], "a") && val_is(&out[1], "b"), "union values a then b");
	CHECK(!out[0].authoritative && !out[1].authoritative, "union marks nothing authoritative");
}

/* --- C5b AUTHORITATIVE ------------------------------------------------- */

static void test_authoritative(void)
{
	fzn_catalog_assertion_t set[3];
	fzn_catalog_resolved_t out[8];
	size_t n = 0;

	set[0] = mk("fan", "fan-name", FZN_CATALOG_AUTHORITATIVE, 1);
	set[1] = mk("reg", "official", FZN_CATALOG_AUTHORITATIVE, 1); /* authority */
	set[2] = mk("other", "official", FZN_CATALOG_AUTHORITATIVE, 1); /* dup value */

	/* The authority's value comes first and is marked; the other distinct
	 * value stands (precedence, not exclusivity); the duplicate is deduped. */
	CHECK(fzn_catalog_resolve(set, 3, (const uint8_t *)"reg", 3, out, 8, &n)
	      == FZN_CATALOG_OK, "authoritative resolves");
	CHECK(n == 2, "authority's value plus the one other distinct value");
	CHECK(val_is(&out[0], "official") && iss_is(&out[0], "reg") && out[0].authoritative,
	      "authority's value first and marked");
	CHECK(val_is(&out[1], "fan-name") && !out[1].authoritative,
	      "the other issuer's value stands, unmarked");

	/* Authority silent: the others stand, none marked authoritative. */
	n = 0;
	CHECK(fzn_catalog_resolve(set, 3, (const uint8_t *)"absent", 6, out, 8, &n)
	      == FZN_CATALOG_OK, "authoritative with silent authority resolves");
	CHECK(n == 2 && !out[0].authoritative && !out[1].authoritative,
	      "silent authority leaves others standing, unmarked");

	/* No authority named at all is a refusal, not a guess. */
	n = 0;
	CHECK(fzn_catalog_resolve(set, 3, NULL, 0, out, 8, &n)
	      == FZN_CATALOG_ERR_NO_AUTHORITY, "authoritative needs a named authority");
}

/* --- C5b DISTINCT ------------------------------------------------------ */

static void test_distinct(void)
{
	fzn_catalog_assertion_t set[3];
	fzn_catalog_resolved_t out[8];
	size_t n = 0;

	set[0] = mk("i1", "a", FZN_CATALOG_DISTINCT, 1);
	set[1] = mk("i2", "b", FZN_CATALOG_DISTINCT, 1);
	set[2] = mk("i3", "a", FZN_CATALOG_DISTINCT, 1); /* same value, kept */

	/* Every live assertion retained with its issuer -- no dedup, no winner. */
	CHECK(fzn_catalog_resolve(set, 3, NULL, 0, out, 8, &n) == FZN_CATALOG_OK,
	      "distinct resolves");
	CHECK(n == 3, "distinct retains every live assertion, even equal values");
	CHECK(iss_is(&out[0], "i1") && iss_is(&out[2], "i3"),
	      "distinct keeps attribution -- whose value each is");
}

/* --- equality and bounds ----------------------------------------------- */

static void test_eq_and_bounds(void)
{
	fzn_catalog_assertion_t a = mk("i1", "x", FZN_CATALOG_UNION, 1);
	fzn_catalog_assertion_t b = mk("i1", "x", FZN_CATALOG_UNION, 0); /* live differs */
	fzn_catalog_assertion_t c = mk("i2", "x", FZN_CATALOG_UNION, 1);
	fzn_catalog_resolved_t out[1];
	size_t n = 0;

	CHECK(fzn_catalog_assertion_eq(&a, &b), "eq ignores the live flag");
	CHECK(!fzn_catalog_assertion_eq(&a, &c), "eq distinguishes the issuer");

	/* A resolved set that will not fit is refused, not truncated. */
	{
		fzn_catalog_assertion_t set[2];
		set[0] = mk("i1", "a", FZN_CATALOG_UNION, 1);
		set[1] = mk("i2", "b", FZN_CATALOG_UNION, 1);
		CHECK(fzn_catalog_resolve(set, 2, NULL, 0, out, 1, &n)
		      == FZN_CATALOG_ERR_RANGE, "resolve refuses a too-small buffer");
	}
}

/* --- the ATTRIBUTE wire encoding --------------------------------------- */

/* An ATTRIBUTE assertion with explicit axes, name and value. issuer and entity
 * are the RECORD's on the wire, so encode ignores them; a decoded assertion
 * takes them from the caller's pointers instead. */
static fzn_catalog_assertion_t attr(const char *name, const char *value,
                                      fzn_catalog_class_t cls,
                                      fzn_catalog_scope_t scope,
                                      fzn_catalog_merge_t merge,
                                      fzn_catalog_capability_t cap)
{
	fzn_catalog_assertion_t a;
	memset(&a, 0, sizeof(a));
	a.name = (const uint8_t *)name;
	a.name_len = strlen(name);
	a.value = (const uint8_t *)value;
	a.value_len = strlen(value);
	a.attr_class = cls;
	a.scope = scope;
	a.merge = merge;
	a.capability = cap;
	a.live = 1;
	return a;
}

static void test_encode(void)
{
	uint8_t body[FZN_RECORD_BODY_MAX];
	uint8_t big[FZN_RECORD_BODY_MAX + 8];
	static uint8_t huge[FZN_RECORD_BODY_MAX];
	const uint8_t iss[4] = { 1, 2, 3, 4 };
	const uint8_t ent[3] = { 9, 8, 7 };
	fzn_catalog_assertion_t a, got;
	size_t len = 0;

	a = attr("genre", "jazz", FZN_CATALOG_LABEL, FZN_CATALOG_ADVERTISED,
	         FZN_CATALOG_UNION, FZN_CATALOG_CAP_NONE);

	CHECK(fzn_catalog_attribute_encode(&a, body, sizeof(body), &len)
	      == FZN_CATALOG_OK, "encode a well-formed attribute");
	CHECK(len == FZN_CATALOG_ATTR_HEAD_LEN + 5 + 2 + 4,
	      "encoded length is head + name + 2 + value");
	CHECK(body[0] == FZN_CATALOG_OBJECT_ATTRIBUTE && body[1] == FZN_CATALOG_LABEL
	      && body[2] == FZN_CATALOG_ADVERTISED && body[3] == FZN_CATALOG_UNION
	      && body[4] == FZN_CATALOG_CAP_NONE && body[5] == 5,
	      "the head carries the tag and the four axes");
	CHECK(memcmp(body + 6, "genre", 5) == 0, "the name follows the head");
	CHECK(body[11] == 0 && body[12] == 4, "value length is a big-endian u16");
	CHECK(memcmp(body + 13, "jazz", 4) == 0, "the value follows its length");

	CHECK(fzn_catalog_attribute_decode(iss, sizeof(iss), ent, sizeof(ent),
	                                     body, len, &got) == FZN_CATALOG_OK,
	      "decode the body back");
	CHECK(got.issuer == iss && got.issuer_len == sizeof(iss)
	      && got.entity == ent && got.entity_len == sizeof(ent),
	      "decode takes issuer and entity from the caller, not the body");
	CHECK(got.name_len == 5 && memcmp(got.name, "genre", 5) == 0
	      && got.value_len == 4 && memcmp(got.value, "jazz", 4) == 0,
	      "decode borrows name and value from the body");
	CHECK(got.attr_class == FZN_CATALOG_LABEL && got.scope == FZN_CATALOG_ADVERTISED
	      && got.merge == FZN_CATALOG_UNION && got.capability == FZN_CATALOG_CAP_NONE,
	      "decode recovers the four axes");
	CHECK(got.live == 0, "decode leaves liveness to the caller (C5c)");

	/* One byte perturbed in an axis is refused -- the layout check above defends
	 * a property that can actually fail. */
	body[1] = 0;
	CHECK(fzn_catalog_attribute_decode(iss, 4, ent, 3, body, len, &got)
	      == FZN_CATALOG_ERR_KIND, "an unknown class byte is refused");
	body[1] = FZN_CATALOG_LABEL;

	/* Empty name and value round-trip to NULL borrowed views. */
	a = attr("", "", FZN_CATALOG_FACT, FZN_CATALOG_HOST,
	         FZN_CATALOG_DISTINCT, FZN_CATALOG_CAP_HOLDER);
	CHECK(fzn_catalog_attribute_encode(&a, body, sizeof(body), &len)
	      == FZN_CATALOG_OK && len == FZN_CATALOG_ATTR_HEAD_LEN + 2,
	      "an empty name and value encode to head + 2");
	CHECK(fzn_catalog_attribute_decode(iss, 4, ent, 3, body, len, &got)
	      == FZN_CATALOG_OK && got.name == NULL && got.name_len == 0
	      && got.value == NULL && got.value_len == 0,
	      "empty name and value decode to NULL borrowed views");

	/* A value that overflows a record body is refused, not truncated, even with
	 * room in the caller's buffer -- catalog/'s FZN_CATALOG_INLINE_MAX lesson. */
	a = attr("n", "", FZN_CATALOG_FACT, FZN_CATALOG_HOST,
	         FZN_CATALOG_UNION, FZN_CATALOG_CAP_NONE);
	a.value = huge;
	a.value_len = FZN_CATALOG_ATTR_VALUE_MAX; /* head + name pushes it over */
	CHECK(fzn_catalog_attribute_encode(&a, big, sizeof(big), &len)
	      == FZN_CATALOG_ERR_RANGE,
	      "a value that overflows a record body is refused");

	/* An axis outside its enum is refused on encode too. */
	a = attr("n", "v", (fzn_catalog_class_t)0, FZN_CATALOG_HOST,
	         FZN_CATALOG_UNION, FZN_CATALOG_CAP_NONE);
	CHECK(fzn_catalog_attribute_encode(&a, body, sizeof(body), &len)
	      == FZN_CATALOG_ERR_KIND, "encode refuses an axis outside its enum");

	/* One canonical encoding: neither a trailing byte nor a short value. */
	a = attr("k", "v", FZN_CATALOG_LABEL, FZN_CATALOG_HOST,
	         FZN_CATALOG_UNION, FZN_CATALOG_CAP_NONE);
	CHECK(fzn_catalog_attribute_encode(&a, body, sizeof(body), &len)
	      == FZN_CATALOG_OK, "encode k=v");
	CHECK(fzn_catalog_attribute_decode(iss, 4, ent, 3, body, len, &got)
	      == FZN_CATALOG_OK, "control: k=v decodes");
	CHECK(fzn_catalog_attribute_decode(iss, 4, ent, 3, body, len + 1, &got)
	      == FZN_CATALOG_ERR_RANGE, "a trailing byte is refused");
	CHECK(fzn_catalog_attribute_decode(iss, 4, ent, 3, body, len - 1, &got)
	      == FZN_CATALOG_ERR_RANGE, "a value shorter than its length is refused");

	/* A wrong object tag and a body shorter than the head. */
	body[0] = 2;
	CHECK(fzn_catalog_attribute_decode(iss, 4, ent, 3, body, len, &got)
	      == FZN_CATALOG_ERR_MALFORMED, "a wrong object tag is refused");
	body[0] = FZN_CATALOG_OBJECT_ATTRIBUTE;
	CHECK(fzn_catalog_attribute_decode(iss, 4, ent, 3, body, 3, &got)
	      == FZN_CATALOG_ERR_MALFORMED, "a body shorter than the head is refused");

	/* A body larger than a record can carry is refused, symmetric with encode's
	 * bound. Built internally-consistent (value_len == the bytes present) so it
	 * would decode WITHOUT the size cap -- the property attribute_fuzz's
	 * canonical check rests on: a body that decodes always re-encodes. */
	memset(big, 0, sizeof(big));
	big[0] = FZN_CATALOG_OBJECT_ATTRIBUTE;
	big[1] = FZN_CATALOG_LABEL;
	big[2] = FZN_CATALOG_HOST;
	big[3] = FZN_CATALOG_UNION;
	big[4] = FZN_CATALOG_CAP_NONE;
	big[5] = 0; /* name_len */
	/* value_len so that 8 + value_len == FZN_RECORD_BODY_MAX + 1 */
	big[6] = (uint8_t)((FZN_RECORD_BODY_MAX - 7u) >> 8);
	big[7] = (uint8_t)((FZN_RECORD_BODY_MAX - 7u) & 0xffu);
	CHECK(fzn_catalog_attribute_decode(iss, 4, ent, 3, big,
	                                     (size_t)FZN_RECORD_BODY_MAX + 1u, &got)
	      == FZN_CATALOG_ERR_RANGE, "a body larger than a record is refused");
}

/* --- reachability (sec 317, step 1) ------------------------------------ */

static void test_reachability(void)
{
	fzn_catalog_assertion_t set[4];
	fzn_catalog_issuer_t src[4];
	size_t n = 0, dropped = 0, i;

	for (i = 0; i < 4; i++) {
		memset(&set[i], 0, sizeof(set[i]));
		/* A LEGAL CAPABILITY, because zero is not one. The fixture used
		 * to leave this at 0 -- outside the enum entirely -- which is
		 * why nothing here reached the holder case below, and why sec
		 * 321 found that defect by building a planner rather than by
		 * running this suite. */
		set[i].capability = FZN_CATALOG_CAP_NONE;
	}
	/* e1 by i1 (live), e1 by i2 (live), e2 by i1 (NOT live), e3 by i1 (live). */
	set[0].entity = (const uint8_t *)"e1"; set[0].entity_len = 2;
	set[0].issuer = (const uint8_t *)"i1"; set[0].issuer_len = 2; set[0].live = 1;
	set[1].entity = (const uint8_t *)"e1"; set[1].entity_len = 2;
	set[1].issuer = (const uint8_t *)"i2"; set[1].issuer_len = 2; set[1].live = 1;
	set[2].entity = (const uint8_t *)"e2"; set[2].entity_len = 2;
	set[2].issuer = (const uint8_t *)"i1"; set[2].issuer_len = 2; set[2].live = 0;
	set[3].entity = (const uint8_t *)"e3"; set[3].entity_len = 2;
	set[3].issuer = (const uint8_t *)"i1"; set[3].issuer_len = 2; set[3].live = 1;

	CHECK(fzn_catalog_referenced(set, 4, (const uint8_t *)"e1", 2),
	      "an entity with a live assertion is referenced");
	CHECK(!fzn_catalog_referenced(set, 4, (const uint8_t *)"e2", 2),
	      "an entity named only by a non-live assertion is unreferenced");
	CHECK(!fzn_catalog_referenced(set, 4, (const uint8_t *)"e9", 2),
	      "an entity no assertion names is unreferenced");
	CHECK(fzn_catalog_referenced(set, 4, (const uint8_t *)"e3", 2),
	      "e3 is referenced");

	/* A HOLDER ASSERTION IS NOT A REFERENCE, which is C9 and which this
	 * suite could not see until the fixture carried a legal capability.
	 *
	 * "I hold these bytes" says WHERE they are; it does not say anything
	 * wants them kept. Counting it would make every entity a host holds
	 * referenced BY THE FACT OF HOLDING IT -- a fixpoint the sweep planner
	 * of sec 321 can never escape, so it would keep everything and plan
	 * nothing. Asserted against `holders` in the same breath, because the
	 * pair is the point: the same assertion must be invisible to one query
	 * and decisive for the other. */
	{
		fzn_catalog_assertion_t held[1];
		fzn_catalog_issuer_t who[2];
		size_t hn = 0, hdropped = 0;

		memset(held, 0, sizeof(held));
		held[0].entity = (const uint8_t *)"e4"; held[0].entity_len = 2;
		held[0].issuer = (const uint8_t *)"i1"; held[0].issuer_len = 2;
		held[0].capability = FZN_CATALOG_CAP_HOLDER;
		held[0].live = 1;

		CHECK(!fzn_catalog_referenced(held, 1, (const uint8_t *)"e4", 2),
		      "a live HOLDER assertion made its entity referenced, so nothing "
		      "a host holds can ever become unreferenced and no sweep can plan "
		      "a removal");
		CHECK(fzn_catalog_holders(held, 1, (const uint8_t *)"e4", 2, who, 2,
		                            &hn, &hdropped) == FZN_CATALOG_OK &&
		          hn == 1,
		      "the same assertion must still be decisive for `holders` -- if it "
		      "is invisible to both, the skip is too wide");

		/* And the control: a CURATED assertion by the same issuer about
		 * the same entity IS a reference, so the skip is keyed on the
		 * capability rather than refusing that issuer or entity. */
		held[0].capability = FZN_CATALOG_CAP_NONE;
		CHECK(fzn_catalog_referenced(held, 1, (const uint8_t *)"e4", 2),
		      "a curated assertion stopped being a reference, so the holder "
		      "skip is refusing more than holder assertions");
	}

	CHECK(fzn_catalog_issuers(set, 4, src, 4, &n, &dropped) == FZN_CATALOG_OK,
	      "sources resolves");
	CHECK(n == 2 && dropped == 0, "two distinct issuers, none dropped");
	CHECK(src[0].assertions == 3 && src[1].assertions == 1,
	      "per-issuer counts -- i1 asserted three, i2 one");

	n = 0; dropped = 0;
	CHECK(fzn_catalog_issuers(set, 4, src, 1, &n, &dropped) == FZN_CATALOG_OK,
	      "sources with a one-slot buffer");
	CHECK(n == 1 && dropped == 1,
	      "one issuer fits and one distinct issuer is dropped, counted once");

	/* A dropped issuer with SEVERAL assertions is counted once, not per row. */
	{
		fzn_catalog_assertion_t s2[3];
		size_t m = 0, dr = 0, k;

		for (k = 0; k < 3; k++)
			memset(&s2[k], 0, sizeof(s2[k]));
		s2[0].issuer = (const uint8_t *)"i1"; s2[0].issuer_len = 2;
		s2[0].entity = (const uint8_t *)"e"; s2[0].entity_len = 1; s2[0].live = 1;
		s2[1].issuer = (const uint8_t *)"i2"; s2[1].issuer_len = 2;
		s2[1].entity = (const uint8_t *)"e"; s2[1].entity_len = 1; s2[1].live = 1;
		s2[2].issuer = (const uint8_t *)"i2"; s2[2].issuer_len = 2;
		s2[2].entity = (const uint8_t *)"e"; s2[2].entity_len = 1; s2[2].live = 1;
		CHECK(fzn_catalog_issuers(s2, 3, src, 1, &m, &dr) == FZN_CATALOG_OK,
		      "sources over a set with a repeated dropped issuer");
		CHECK(m == 1 && dr == 1,
		      "a dropped issuer with two assertions is dropped once");
	}
}

/* --- holders (C8 availability, sec 317 step 5 foundation) -------------- */

static void seth(fzn_catalog_assertion_t *a, const char *ent, const char *iss,
                 fzn_catalog_capability_t cap, int live)
{
	memset(a, 0, sizeof(*a));
	a->entity = (const uint8_t *)ent;
	a->entity_len = strlen(ent);
	a->issuer = (const uint8_t *)iss;
	a->issuer_len = strlen(iss);
	a->capability = cap;
	a->live = live;
}

static void test_holders(void)
{
	fzn_catalog_assertion_t s[7];
	fzn_catalog_issuer_t out[7];
	size_t n = 0, dropped = 0;

	seth(&s[0], "R", "i1", FZN_CATALOG_CAP_HOLDER, 1);
	seth(&s[1], "R", "i2", FZN_CATALOG_CAP_NONE, 1);   /* not a holding */
	seth(&s[2], "R", "i3", FZN_CATALOG_CAP_HOLDER, 0); /* not live */
	seth(&s[3], "R", "i1", FZN_CATALOG_CAP_HOLDER, 1); /* i1 again */
	seth(&s[4], "R", "i5", FZN_CATALOG_CAP_HOLDER, 1);
	seth(&s[5], "S", "i6", FZN_CATALOG_CAP_HOLDER, 1); /* another entity */
	seth(&s[6], "R", "i5", FZN_CATALOG_CAP_HOLDER, 1); /* i5 again */

	CHECK(fzn_catalog_holders(s, 7, (const uint8_t *)"R", 1, out, 7, &n, &dropped)
	      == FZN_CATALOG_OK, "holders resolves");
	CHECK(n == 2 && dropped == 0,
	      "two hosts hold R -- a NONE claim and a non-live one are not holdings");

	n = 0; dropped = 0;
	CHECK(fzn_catalog_holders(s, 7, (const uint8_t *)"S", 1, out, 7, &n, &dropped)
	      == FZN_CATALOG_OK && n == 1, "S has a single holder -- a last copy");

	n = 0; dropped = 0;
	CHECK(fzn_catalog_holders(s, 7, (const uint8_t *)"R", 1, out, 1, &n, &dropped)
	      == FZN_CATALOG_OK, "holders with a one-slot buffer");
	CHECK(n == 1 && dropped == 1,
	      "one holder fits and the repeated other is dropped once");
}

/* A NEAR MISS IS A DIFFERENT THING, on BOTH axes.
 *
 * The prefix-compare defect class, which the old reach_test guarded with
 * `test_the_walk_reads_the_whole_id` and `test_the_frontier_reads_the_whole_
 * issuer`. These queries compare an entity and an issuer over their whole
 * length; a compare that stopped early would answer about a different file, or
 * credit a different host with holding one. The pairs below differ in their
 * LAST byte, which a truncated compare cannot see at all.
 *
 * The issuer axis matters most: `holders` decides who has the bytes, and
 * folding two hosts into one makes a last copy look replicated.
 */
static void test_near_misses(void)
{
	fzn_catalog_assertion_t set[2];
	fzn_catalog_issuer_t who[4];
	size_t n = 0, dropped = 0, i;
	static uint8_t ent_a[32], ent_b[32], iss_a[32], iss_b[32];

	memset(ent_a, 0x51, sizeof(ent_a));
	memset(ent_b, 0x51, sizeof(ent_b)); ent_b[31] ^= 0x01u;
	memset(iss_a, 0x62, sizeof(iss_a));
	memset(iss_b, 0x62, sizeof(iss_b)); iss_b[31] ^= 0x01u;

	for (i = 0; i < 2; i++) {
		memset(&set[i], 0, sizeof(set[i]));
		set[i].capability = FZN_CATALOG_CAP_NONE;
		set[i].live = 1;
		set[i].issuer = iss_a; set[i].issuer_len = 32;
	}
	set[0].entity = ent_a; set[0].entity_len = 32;
	set[1].entity = ent_b; set[1].entity_len = 32;

	CHECK(fzn_catalog_referenced(set, 1, ent_a, 32),
	      "the entity its own assertion names is not referenced");
	CHECK(!fzn_catalog_referenced(set, 1, ent_b, 32),
	      "an entity differing in its LAST byte was reported referenced by "
	      "another entity's assertion, so the compare stops short");

	/* THE ISSUER AXIS. Two hosts differing in one byte must be two holders,
	 * or a last copy looks replicated and the sweep removes it. */
	set[0].entity = ent_a; set[0].entity_len = 32;
	set[1].entity = ent_a; set[1].entity_len = 32;
	set[0].capability = FZN_CATALOG_CAP_HOLDER;
	set[1].capability = FZN_CATALOG_CAP_HOLDER;
	set[0].issuer = iss_a;
	set[1].issuer = iss_b;
	CHECK(fzn_catalog_holders(set, 2, ent_a, 32, who, 4, &n, &dropped) ==
	          FZN_CATALOG_OK && n == 2,
	      "two issuers differing in their last byte counted as one holder, so a "
	      "last copy reads as replicated (n=%zu)", n);

	n = 0; dropped = 0;
	CHECK(fzn_catalog_issuers(set, 2, who, 4, &n, &dropped) == FZN_CATALOG_OK &&
	          n == 2,
	      "two near-miss issuers counted as one source (n=%zu)", n);
}

int main(void)
{
	test_validate();
	test_union();
	test_authoritative();
	test_distinct();
	test_eq_and_bounds();
	test_encode();
	test_reachability();
	test_holders();
	test_near_misses();

	printf("catalog_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
