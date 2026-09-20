/* Tests for catalogue/copy.c: what to fetch, announce and serve. sec 322.
 *
 * THE PROPERTY THIS SUITE DEFENDS is the pair of sums copy.h states. Every
 * examined item lands in exactly one classification counter, and everything a
 * walk chose to emit lands in exactly one emission counter:
 *
 *     examined = not_retained + not_referenced + already_held + missing
 *              + unknown + incomplete
 *     emitted  = written + duplicates + truncated
 *
 * A count that does not have to add up is a count nobody can check, and the
 * three entry points are asserted against the SAME arithmetic -- which is what
 * makes it worth asserting rather than three sums that each hold in one place.
 *
 * AND WANT AND HOLDINGS ARE ASSERTED TO DIFFER. They share a walk, so the
 * cheapest defect here is one collapsing into the other: a holdings walk that
 * quietly filtered by retention would announce less than this host can serve
 * and would leak the policy while doing it, and every test that only ever
 * looked at `want` would still pass.
 */

#include "../copy.h"

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
	fprintf(stderr, "  FAIL copy_plan_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

static uint8_t me[32], peer[32];
static uint8_t e1[FZN_CATALOGUE_ENTITY_LEN];
static uint8_t e2[FZN_CATALOGUE_ENTITY_LEN];
static uint8_t e3[FZN_CATALOGUE_ENTITY_LEN];

static void fixtures(void)
{
	memset(me, 0x01, sizeof(me));
	memset(peer, 0x02, sizeof(peer));
	memset(e1, 0xe1, sizeof(e1));
	memset(e2, 0xe2, sizeof(e2));
	memset(e3, 0xe3, sizeof(e3));
}

static void holder(fzn_catalogue_assertion_t *a, const uint8_t *issuer,
                   const uint8_t *entity)
{
	memset(a, 0, sizeof(*a));
	a->issuer = issuer;  a->issuer_len = 32;
	a->entity = entity;  a->entity_len = FZN_CATALOGUE_ENTITY_LEN;
	a->name = (const uint8_t *)"held"; a->name_len = 4;
	a->attr_class = FZN_CATALOGUE_FACT;
	a->scope = FZN_CATALOGUE_ESTATE;
	a->merge = FZN_CATALOGUE_UNION;
	a->capability = FZN_CATALOGUE_CAP_HOLDER;
	a->live = 1;
}

static void curated(fzn_catalogue_assertion_t *a, const uint8_t *issuer,
                    const uint8_t *entity, int live)
{
	memset(a, 0, sizeof(*a));
	a->issuer = issuer;  a->issuer_len = 32;
	a->entity = entity;  a->entity_len = FZN_CATALOGUE_ENTITY_LEN;
	a->name = (const uint8_t *)"link"; a->name_len = 4;
	a->attr_class = FZN_CATALOGUE_LABEL;
	a->scope = FZN_CATALOGUE_ESTATE;
	a->merge = FZN_CATALOGUE_UNION;
	a->capability = FZN_CATALOGUE_CAP_NONE;
	a->live = live;
}

static size_t classified(const fzn_catalogue_copy_t *p)
{
	return p->not_retained + p->not_referenced + p->already_held + p->missing +
	       p->unknown + p->incomplete;
}

static size_t emitted(const fzn_catalogue_copy_t *p)
{
	return p->written + p->duplicates + p->truncated;
}

/* Distinct entities, counted without the module under test. */
static size_t distinct(const fzn_catalogue_assertion_t *set, size_t n)
{
	size_t i, j, d = 0;

	for (i = 0; i < n; i++) {
		int seen = 0;

		if (set[i].entity_len != FZN_CATALOGUE_ENTITY_LEN)
			continue;
		for (j = 0; j < i; j++)
			if (set[j].entity_len == set[i].entity_len &&
			    memcmp(set[j].entity, set[i].entity, set[i].entity_len) == 0)
				seen = 1;
		if (!seen)
			d++;
	}
	return d;
}

/* A HOST CATCHING UP. e1 is curated and held by the peer only, so it is
 * wanted; e2 is curated and already here, so it is not. */
static void test_want(void)
{
	fzn_catalogue_assertion_t set[4];
	fzn_catalogue_copy_t plan;
	fzn_catalogue_hold_t hold_rows[4];
	fzn_catalogue_holds_t holds;
	fzn_catalogue_entity_t out[4];

	curated(&set[0], peer, e1, 1);
	holder(&set[1], peer, e1);
	curated(&set[2], peer, e2, 1);
	holder(&set[3], me, e2);

	fzn_catalogue_holds_init(&holds, hold_rows, 4);
	fzn_catalogue_retain_all(&holds, 1);

	CHECK(fzn_catalogue_copy_want(set, 4, &holds, me, 32, 0, out, 4, &plan) ==
	          FZN_CATALOGUE_OK,
	      "a want walk was refused");
	CHECK(plan.written == 1 && memcmp(out[0].b, e1, sizeof(e1)) == 0,
	      "the entity this host lacks was not the one wanted (written=%zu)",
	      plan.written);
	CHECK(plan.already_held == 1 && plan.missing == 1,
	      "classification is wrong (held=%zu missing=%zu)", plan.already_held,
	      plan.missing);
	CHECK(classified(&plan) == distinct(set, 4),
	      "the classification does not partition: %zu over %zu distinct entities",
	      classified(&plan), distinct(set, 4));
	CHECK(emitted(&plan) == 1, "the emission sum is %zu, not 1", emitted(&plan));

	/* RETENTION IS LOAD-BEARING: with the wide bit off, nothing is wanted,
	 * and a host does not fetch an estate's worth of bytes it had already
	 * decided not to keep. */
	fzn_catalogue_retain_all(&holds, 0);
	CHECK(fzn_catalogue_copy_want(set, 4, &holds, me, 32, 0, out, 4, &plan) ==
	          FZN_CATALOGUE_OK,
	      "a want walk with nothing retained was refused");
	CHECK(plan.written == 0 && plan.not_retained == 2,
	      "retention was not consulted (written=%zu not_retained=%zu)",
	      plan.written, plan.not_retained);
	CHECK(classified(&plan) == distinct(set, 4),
	      "the not-retained case does not partition");

	/* AND SO IS BEING CURATED: retained, not held, and nothing links to it.
	 * A holder assertion is not a link -- sec 321. */
	fzn_catalogue_retain_all(&holds, 1);
	holder(&set[0], peer, e3);
	CHECK(fzn_catalogue_copy_want(set, 1, &holds, me, 32, 0, out, 4, &plan) ==
	          FZN_CATALOGUE_OK,
	      "a want walk over an uncurated entity was refused");
	CHECK(plan.written == 0 && plan.not_referenced == 1,
	      "an entity nothing curates was fetched anyway (written=%zu "
	      "not_referenced=%zu)", plan.written, plan.not_referenced);
	CHECK(classified(&plan) == 1, "the not-referenced case does not partition");
}

/* HOLDINGS ANNOUNCES A FACT, NOT AN INTENTION, and this is the case that
 * separates the two walks. Same set, same host, retention saying DROP on
 * everything: `want` asks for nothing and `holdings` still announces what this
 * host can serve. A holdings walk that filtered by retention would pass every
 * test that only looked at `want`. */
static void test_holdings_ignores_policy(void)
{
	fzn_catalogue_assertion_t set[3];
	fzn_catalogue_copy_t want_plan, hold_plan;
	fzn_catalogue_hold_t hold_rows[4];
	fzn_catalogue_holds_t holds;
	fzn_catalogue_entity_t out[4];

	curated(&set[0], peer, e1, 1);
	holder(&set[1], me, e1);
	holder(&set[2], peer, e2);

	fzn_catalogue_holds_init(&holds, hold_rows, 4);
	fzn_catalogue_retain_all(&holds, 0);
	fzn_catalogue_retain(&holds, e1, sizeof(e1), FZN_CATALOGUE_RETAIN_DROP);

	fzn_catalogue_copy_want(set, 3, &holds, me, 32, 0, out, 4, &want_plan);
	CHECK(want_plan.written == 0,
	      "a want walk asked for something this host had dropped");

	CHECK(fzn_catalogue_copy_holdings(set, 3, me, 32, out, 4, &hold_plan) ==
	          FZN_CATALOGUE_OK,
	      "a holdings walk was refused");
	CHECK(hold_plan.written == 1 && memcmp(out[0].b, e1, sizeof(e1)) == 0,
	      "a holdings walk did not announce bytes this host holds -- it is a "
	      "fact about what can be served, and a retention filter here would "
	      "both under-announce and leak the policy (written=%zu)",
	      hold_plan.written);
	CHECK(hold_plan.not_retained == 0 && hold_plan.not_referenced == 0,
	      "a holdings walk consulted policy (not_retained=%zu not_referenced=%zu)",
	      hold_plan.not_retained, hold_plan.not_referenced);
	CHECK(hold_plan.already_held == 1 && hold_plan.missing == 1,
	      "holdings classification is wrong (held=%zu missing=%zu)",
	      hold_plan.already_held, hold_plan.missing);
	CHECK(classified(&hold_plan) == distinct(set, 3),
	      "the holdings walk does not partition");
}

/* THE SCOPE CHECK is the point of an offer rather than a detail: without it a
 * want list is a request for any bytes whose hash a peer can name. */
static void test_offer(void)
{
	fzn_catalogue_assertion_t set[3];
	fzn_catalogue_copy_t plan;
	fzn_catalogue_entity_t out[4];
	fzn_catalogue_entity_t wants[4];

	curated(&set[0], peer, e1, 1);
	holder(&set[1], me, e1);
	holder(&set[2], peer, e2);

	memcpy(wants[0].b, e1, sizeof(e1));  /* known and held -- served */
	memcpy(wants[1].b, e2, sizeof(e2));  /* known, not held here */
	memcpy(wants[2].b, e3, sizeof(e3));  /* outside this host's view */

	CHECK(fzn_catalogue_copy_offer(set, 3, me, 32, wants, 3, out, 4, &plan) ==
	          FZN_CATALOGUE_OK,
	      "an offer was refused");
	CHECK(plan.written == 1 && memcmp(out[0].b, e1, sizeof(e1)) == 0,
	      "the offer did not serve the one entity this host holds (written=%zu)",
	      plan.written);
	CHECK(plan.unknown == 1,
	      "a peer asked for bytes outside this host's view and was not refused -- "
	      "without the scope check a want list is a request for anything whose "
	      "hash a peer can name (unknown=%zu)", plan.unknown);
	CHECK(plan.missing == 1, "known-and-not-held was not counted (missing=%zu)",
	      plan.missing);
	CHECK(classified(&plan) == 3, "the offer does not partition: %zu over 3 wants",
	      classified(&plan));

	/* A PEER MAY NAME ONE ENTITY TWICE, which is where `duplicates` can
	 * still rise -- a walk dedupes its own set, an offer examines the
	 * peer's list. */
	memcpy(wants[3].b, e1, sizeof(e1));
	CHECK(fzn_catalogue_copy_offer(set, 3, me, 32, wants, 4, out, 4, &plan) ==
	          FZN_CATALOGUE_OK,
	      "an offer with a repeated want was refused");
	CHECK(plan.written == 1 && plan.duplicates == 1,
	      "a repeated want was served twice (written=%zu duplicates=%zu)",
	      plan.written, plan.duplicates);
	CHECK(emitted(&plan) == 2, "the emission sum is %zu, not 2", emitted(&plan));
	CHECK(classified(&plan) == 4, "the repeated-want offer does not partition");

	/* AN UNCURATED ENTITY THIS HOST HOLDS IS STILL SERVED. The scope check
	 * asks whether the entity is in this host's view at all, which is
	 * broader than `referenced` on purpose: bytes nothing links to any more
	 * are exactly what a peer catching up is likely to ask for. */
	{
		fzn_catalogue_assertion_t only_held[1];

		holder(&only_held[0], me, e3);
		memcpy(wants[0].b, e3, sizeof(e3));
		CHECK(fzn_catalogue_copy_offer(only_held, 1, me, 32, wants, 1, out, 4,
		                               &plan) == FZN_CATALOGUE_OK,
		      "an offer over a held-but-uncurated entity was refused");
		CHECK(plan.written == 1 && plan.unknown == 0,
		      "an entity this host holds was treated as outside its view "
		      "because nothing curates it (written=%zu unknown=%zu)",
		      plan.written, plan.unknown);
	}
}

/* A NEAR MISS IS NEITHER A DUPLICATE NOR A MATCH, which the old copy_test
 * guarded in both directions and these did not. A prefix compare would make
 * the second entity a duplicate of the first in `already_listed`, and would
 * make a peer's want for one entity match another in the scope check -- which
 * is the direction that serves bytes the peer never asked for. */
static void test_a_near_miss(void)
{
	fzn_catalogue_assertion_t set[4];
	fzn_catalogue_copy_t plan;
	fzn_catalogue_entity_t out[4], wants[2];
	static uint8_t near_a[FZN_CATALOGUE_ENTITY_LEN];
	static uint8_t near_b[FZN_CATALOGUE_ENTITY_LEN];

	memset(near_a, 0x77, sizeof(near_a));
	memset(near_b, 0x77, sizeof(near_b));
	near_b[FZN_CATALOGUE_ENTITY_LEN - 1u] ^= 0x01u;

	holder(&set[0], me, near_a);
	holder(&set[1], me, near_b);

	fzn_catalogue_copy_holdings(set, 2, me, 32, out, 4, &plan);
	CHECK(plan.written == 2 && plan.duplicates == 0,
	      "two entities differing in their last byte were announced as one "
	      "(written=%zu duplicates=%zu)", plan.written, plan.duplicates);

	/* AND THE SCOPE CHECK READS THE WHOLE ENTITY: a set holding only
	 * near_a must not answer for a want naming near_b. */
	holder(&set[0], me, near_a);
	memcpy(wants[0].b, near_b, sizeof(near_b));
	fzn_catalogue_copy_offer(set, 1, me, 32, wants, 1, out, 4, &plan);
	CHECK(plan.unknown == 1 && plan.written == 0,
	      "a want for a near-miss entity was served from another entity's "
	      "record (unknown=%zu written=%zu)", plan.unknown, plan.written);
}

/* TRUNCATION IS A BOUND ONCE THE ARRAY IS FULL, NOT A COUNT, which copy.h
 * states and which only a test can keep honest. */
static void test_truncation(void)
{
	fzn_catalogue_assertion_t set[6];
	fzn_catalogue_copy_t plan;
	fzn_catalogue_hold_t hold_rows[4];
	fzn_catalogue_holds_t holds;
	fzn_catalogue_entity_t out[1];

	curated(&set[0], peer, e1, 1);  holder(&set[1], peer, e1);
	curated(&set[2], peer, e2, 1);  holder(&set[3], peer, e2);
	curated(&set[4], peer, e3, 1);  holder(&set[5], peer, e3);

	fzn_catalogue_holds_init(&holds, hold_rows, 4);
	fzn_catalogue_retain_all(&holds, 1);

	fzn_catalogue_copy_want(set, 6, &holds, me, 32, 0, out, 1, &plan);
	CHECK(plan.written == 1 && plan.truncated == 2,
	      "a one-row array did not report the two that did not fit "
	      "(written=%zu truncated=%zu)", plan.written, plan.truncated);
	CHECK(emitted(&plan) == 3, "the emission sum is %zu, not 3", emitted(&plan));
	CHECK(classified(&plan) == distinct(set, 6), "the truncated walk does not partition");

	/* A ZERO-CAPACITY WALK IS A SIZING PASS, not an error: written stays 0
	 * and truncated is what to allocate. */
	fzn_catalogue_copy_want(set, 6, &holds, me, 32, 0, NULL, 0, &plan);
	CHECK(plan.written == 0 && plan.truncated == 3,
	      "a sizing pass did not report what to allocate (written=%zu "
	      "truncated=%zu)", plan.written, plan.truncated);
}

/* INCOMPLETE: more holders than the scratch, with this host beyond the cut. */
static void test_incomplete(void)
{
	enum { MANY = 20 };
	fzn_catalogue_assertion_t set[MANY];
	static uint8_t hosts[MANY][32];
	fzn_catalogue_copy_t plan;
	fzn_catalogue_entity_t out[4];
	size_t i;

	for (i = 0; i < MANY; i++)
		memset(hosts[i], (int)(0x40u + i), sizeof(hosts[i]));
	for (i = 0; i < MANY - 1u; i++)
		holder(&set[i], hosts[i], e1);
	holder(&set[MANY - 1u], me, e1);

	fzn_catalogue_copy_holdings(set, MANY, me, 32, out, 4, &plan);
	CHECK(plan.incomplete == 1 && plan.already_held == 0 && plan.missing == 0,
	      "a holder list too large to read was decided anyway (incomplete=%zu "
	      "held=%zu missing=%zu)", plan.incomplete, plan.already_held, plan.missing);
	CHECK(classified(&plan) == distinct(set, MANY),
	      "the incomplete case does not partition");

	/* THE CONTROL: this host first, everything else the same. */
	holder(&set[0], me, e1);
	for (i = 1; i < MANY; i++)
		holder(&set[i], hosts[i], e1);
	fzn_catalogue_copy_holdings(set, MANY, me, 32, out, 4, &plan);
	CHECK(plan.already_held == 1 && plan.incomplete == 0,
	      "the control was reported incomplete too, so the refusal is about the "
	      "size of the set rather than the answer that was missing");
}

/* WHAT IS REFUSED, each with a control. */
static void test_refusals(void)
{
	fzn_catalogue_assertion_t set[1];
	fzn_catalogue_copy_t plan;
	fzn_catalogue_entity_t out[2];
	fzn_catalogue_entity_t wants[1];

	holder(&set[0], me, e1);
	memcpy(wants[0].b, e1, sizeof(e1));

	CHECK(fzn_catalogue_copy_want(set, 1, NULL, NULL, 32, 0, out, 2, &plan) ==
	          FZN_CATALOGUE_ERR_MALFORMED, "a want walk with no host key");
	CHECK(fzn_catalogue_copy_want(set, 1, NULL, me, 0, 0, out, 2, &plan) ==
	          FZN_CATALOGUE_ERR_MALFORMED, "a want walk with a zero-length key");
	CHECK(fzn_catalogue_copy_want(set, 1, NULL, me, 32, 0, NULL, 2, &plan) ==
	          FZN_CATALOGUE_ERR_MALFORMED, "a capacity with no array");
	CHECK(fzn_catalogue_copy_want(set, 1, NULL, me, 32, 0, out, 2, NULL) ==
	          FZN_CATALOGUE_ERR_MALFORMED, "nowhere to put the plan");
	CHECK(fzn_catalogue_copy_want(set, 1, NULL, me, 32, 0, out, 2, &plan) ==
	          FZN_CATALOGUE_OK, "the control -- every argument present");

	CHECK(fzn_catalogue_copy_holdings(set, 1, NULL, 32, out, 2, &plan) ==
	          FZN_CATALOGUE_ERR_MALFORMED, "a holdings walk with no host key");
	CHECK(fzn_catalogue_copy_holdings(set, 1, me, 32, out, 2, &plan) ==
	          FZN_CATALOGUE_OK, "the holdings control");

	CHECK(fzn_catalogue_copy_offer(set, 1, me, 32, NULL, 1, out, 2, &plan) ==
	          FZN_CATALOGUE_ERR_MALFORMED, "a want count with no want list");
	CHECK(fzn_catalogue_copy_offer(set, 1, NULL, 32, wants, 1, out, 2, &plan) ==
	          FZN_CATALOGUE_ERR_MALFORMED, "an offer with no host key");
	CHECK(fzn_catalogue_copy_offer(set, 1, me, 32, wants, 1, out, 2, &plan) ==
	          FZN_CATALOGUE_OK, "the offer control");

	/* THE PLAN IS ZEROED BEFORE THE ARGUMENTS ARE CHECKED, so a caller
	 * reading it after an error does not read the last walk's numbers. */
	plan.written = 99;
	(void)fzn_catalogue_copy_want(set, 1, NULL, NULL, 32, 0, out, 2, &plan);
	CHECK(plan.written == 0, "a refused walk left stale counters in the plan");

	/* An empty set is a clean zero rather than a refusal. */
	CHECK(fzn_catalogue_copy_holdings(NULL, 0, me, 32, out, 2, &plan) ==
	          FZN_CATALOGUE_OK, "an empty set was refused");
	CHECK(classified(&plan) == 0 && emitted(&plan) == 0,
	      "an empty set produced counters");
}

int main(void)
{
	fixtures();

	test_want();
	test_holdings_ignores_policy();
	test_offer();
	test_a_near_miss();
	test_truncation();
	test_incomplete();
	test_refusals();

	printf("copy_plan_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
