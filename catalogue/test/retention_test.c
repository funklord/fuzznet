/* Tests for catalogue/retention.c: what this host keeps. sec 320.
 *
 * THE CASES THIS SUITE EXISTS FOR are the ones the old catalog/'s retention
 * paid for and that a re-home is most likely to drop on the floor: that the
 * state is TRI-state rather than keep-or-drop, that a deadline replaces the
 * row's word at the deadline rather than after it, that DEFAULT gives a row
 * back instead of storing "no opinion", and that a table which has said
 * nothing keeps nothing.
 *
 * ASSERTED AGAINST THE CATALOGUE-WIDE BIT IN BOTH POSITIONS wherever a row's
 * own word decides. A KEEP row over a keep-everything table and a DROP row
 * over a keep-nothing table both agree with the bit, so either alone would
 * pass with the override ignored entirely.
 *
 * Not tested because it does not exist, and deliberately: any wire form. The
 * header's argument is that this must not sync (C5a HOST), so there is no
 * encode to round-trip and a test asserting one would be asserting a feature
 * the design refuses.
 */

#include "../retention.h"

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
	fprintf(stderr, "  FAIL retention_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* Three distinct entities, each filled with its own byte. */
static uint8_t ent_a[FZN_CATALOGUE_ENTITY_LEN];
static uint8_t ent_b[FZN_CATALOGUE_ENTITY_LEN];
static uint8_t ent_c[FZN_CATALOGUE_ENTITY_LEN];

static void entities(void)
{
	memset(ent_a, 0xa1, sizeof(ent_a));
	memset(ent_b, 0xb2, sizeof(ent_b));
	memset(ent_c, 0xc3, sizeof(ent_c));
}

#define E(x) (x), sizeof(x)

/* THE CATALOGUE-WIDE BIT, and that a table which has said nothing keeps
 * nothing. The default nobody chose is the one discovered when the disk is
 * full, so a zeroed table answering "keep" would be the defect. */
static void test_the_wide_bit(void)
{
	fzn_catalogue_hold_t rows[4];
	fzn_catalogue_holds_t holds;

	CHECK(fzn_catalogue_holds_init(&holds, rows, 4) == FZN_CATALOGUE_OK,
	      "a table over caller-owned rows was refused");
	CHECK(fzn_catalogue_keeps(&holds, E(ent_a), 0) == 0,
	      "a table that has said nothing keeps something");
	CHECK(fzn_catalogue_hold_count(&holds) == 0, "a fresh table holds a row");

	CHECK(fzn_catalogue_retain_all(&holds, 1) == FZN_CATALOGUE_OK, "retain_all(1)");
	CHECK(fzn_catalogue_keeps(&holds, E(ent_a), 0) == 1,
	      "an entity with no word of its own did not follow the catalogue");
	CHECK(fzn_catalogue_retain_all(&holds, 0) == FZN_CATALOGUE_OK, "retain_all(0)");
	CHECK(fzn_catalogue_keeps(&holds, E(ent_a), 0) == 0,
	      "the catalogue-wide bit did not go back off");

	/* A NULL TABLE KEEPS NOTHING rather than crashing or keeping. */
	CHECK(fzn_catalogue_keeps(NULL, E(ent_a), 0) == 0, "a null table kept something");
	CHECK(fzn_catalogue_retention_of(NULL, E(ent_a), 0) == FZN_CATALOGUE_RETAIN_DEFAULT,
	      "a null table said something about an entity");
	CHECK(fzn_catalogue_hold_count(NULL) == 0, "a null table holds rows");
}

/* TRI-STATE, NOT KEEP-OR-DROP -- and each of the three asserted against BOTH
 * settings of the wide bit, so a row that was being ignored cannot pass by
 * agreeing with the bit behind it. */
static void test_tri_state(void)
{
	fzn_catalogue_hold_t rows[4];
	fzn_catalogue_holds_t holds;
	int wide;

	for (wide = 0; wide <= 1; wide++) {
		fzn_catalogue_holds_init(&holds, rows, 4);
		fzn_catalogue_retain_all(&holds, wide);

		CHECK(fzn_catalogue_retain(&holds, E(ent_a),
		                           FZN_CATALOGUE_RETAIN_KEEP) == FZN_CATALOGUE_OK,
		      "KEEP was refused (wide=%d)", wide);
		CHECK(fzn_catalogue_retain(&holds, E(ent_b),
		                           FZN_CATALOGUE_RETAIN_DROP) == FZN_CATALOGUE_OK,
		      "DROP was refused (wide=%d)", wide);

		CHECK(fzn_catalogue_keeps(&holds, E(ent_a), 0) == 1,
		      "KEEP did not keep (wide=%d)", wide);
		CHECK(fzn_catalogue_keeps(&holds, E(ent_b), 0) == 0,
		      "DROP did not drop (wide=%d)", wide);
		/* The third state: no row at all, so the bit decides. */
		CHECK(fzn_catalogue_keeps(&holds, E(ent_c), 0) == wide,
		      "an entity with no row did not follow the catalogue (wide=%d)", wide);

		CHECK(fzn_catalogue_retention_of(&holds, E(ent_a), 0) ==
		          FZN_CATALOGUE_RETAIN_KEEP, "retention_of lost KEEP (wide=%d)", wide);
		CHECK(fzn_catalogue_retention_of(&holds, E(ent_b), 0) ==
		          FZN_CATALOGUE_RETAIN_DROP, "retention_of lost DROP (wide=%d)", wide);
		CHECK(fzn_catalogue_retention_of(&holds, E(ent_c), 0) ==
		          FZN_CATALOGUE_RETAIN_DEFAULT,
		      "an entity with no row reported an opinion (wide=%d)", wide);
		CHECK(fzn_catalogue_hold_count(&holds) == 2,
		      "two overrides were not two rows (wide=%d)", wide);
	}
}

/* DEFAULT GIVES THE ROW BACK. A consumer changing its mind must not fill the
 * table with entities that say "whatever the catalogue says" -- and the count
 * is what shows it, since keeps() reads the same either way. */
static void test_default_reclaims(void)
{
	fzn_catalogue_hold_t rows[2];
	fzn_catalogue_holds_t holds;

	fzn_catalogue_holds_init(&holds, rows, 2);
	fzn_catalogue_retain(&holds, E(ent_a), FZN_CATALOGUE_RETAIN_KEEP);
	fzn_catalogue_retain(&holds, E(ent_b), FZN_CATALOGUE_RETAIN_DROP);
	CHECK(fzn_catalogue_hold_count(&holds) == 2, "two rows were not stored");

	/* Full: a third entity has nowhere to go. */
	CHECK(fzn_catalogue_retain(&holds, E(ent_c), FZN_CATALOGUE_RETAIN_KEEP) ==
	          FZN_CATALOGUE_ERR_RANGE,
	      "a row was stored in a full table");
	/* But an entity that already has a row is rewritten in place, so a full
	 * table does not stop a consumer changing its mind. */
	CHECK(fzn_catalogue_retain(&holds, E(ent_a), FZN_CATALOGUE_RETAIN_DROP) ==
	          FZN_CATALOGUE_OK,
	      "rewriting an existing row failed because the table was full");
	CHECK(fzn_catalogue_keeps(&holds, E(ent_a), 0) == 0, "the rewrite did not take");
	CHECK(fzn_catalogue_hold_count(&holds) == 2, "the rewrite added a row");

	CHECK(fzn_catalogue_retain(&holds, E(ent_a), FZN_CATALOGUE_RETAIN_DEFAULT) ==
	          FZN_CATALOGUE_OK,
	      "DEFAULT was refused");
	CHECK(fzn_catalogue_hold_count(&holds) == 1, "DEFAULT did not give the row back");
	/* And the OTHER row survived the removal -- a swap-with-last that got
	 * its indices wrong would lose or duplicate it. */
	CHECK(fzn_catalogue_retention_of(&holds, E(ent_b), 0) == FZN_CATALOGUE_RETAIN_DROP,
	      "removing one row disturbed another");
	CHECK(fzn_catalogue_retention_of(&holds, E(ent_a), 0) == FZN_CATALOGUE_RETAIN_DEFAULT,
	      "the removed row still speaks");

	/* Now there is room again. */
	CHECK(fzn_catalogue_retain(&holds, E(ent_c), FZN_CATALOGUE_RETAIN_KEEP) ==
	          FZN_CATALOGUE_OK,
	      "the reclaimed slot was not reusable");
	/* DEFAULT on an entity that has no row is a no-op, not an error. */
	CHECK(fzn_catalogue_retain(&holds, E(ent_a), FZN_CATALOGUE_RETAIN_DEFAULT) ==
	          FZN_CATALOGUE_OK,
	      "DEFAULT on an absent entity was refused");
}

/* THE DEADLINE. "Keep this for thirty days" is KEEP until T then DROP, and the
 * row changes its word AT T rather than after it -- which is what makes `due`
 * at T and `retention_of` at T agree. */
static void test_deadline(void)
{
	fzn_catalogue_hold_t rows[4];
	fzn_catalogue_holds_t holds;
	fzn_catalogue_entity_t out[4];
	size_t dropped = 99;
	size_t n;

	fzn_catalogue_holds_init(&holds, rows, 4);

	CHECK(fzn_catalogue_retain_until(&holds, E(ent_a), FZN_CATALOGUE_RETAIN_KEEP,
	                                 100, FZN_CATALOGUE_RETAIN_DROP) == FZN_CATALOGUE_OK,
	      "keep-until-then-drop was refused");

	CHECK(fzn_catalogue_keeps(&holds, E(ent_a), 0) == 1, "before the deadline it dropped");
	CHECK(fzn_catalogue_keeps(&holds, E(ent_a), 99) == 1,
	      "one tick before the deadline it dropped");
	CHECK(fzn_catalogue_keeps(&holds, E(ent_a), 100) == 0,
	      "at the deadline it still kept -- the row changes its word AT the "
	      "deadline, or `due` and `retention_of` disagree at exactly T");
	CHECK(fzn_catalogue_keeps(&holds, E(ent_a), 101) == 0, "past the deadline it kept");

	/* THE WEAKER FORM: keep until T, afterwards follow the catalogue. */
	fzn_catalogue_retain_until(&holds, E(ent_b), FZN_CATALOGUE_RETAIN_KEEP, 100,
	                           FZN_CATALOGUE_RETAIN_DEFAULT);
	fzn_catalogue_retain_all(&holds, 1);
	CHECK(fzn_catalogue_keeps(&holds, E(ent_b), 100) == 1,
	      "a `then` of DEFAULT did not fall back to a keeping catalogue");
	fzn_catalogue_retain_all(&holds, 0);
	CHECK(fzn_catalogue_keeps(&holds, E(ent_b), 100) == 0,
	      "a `then` of DEFAULT did not fall back to a non-keeping catalogue");
	CHECK(fzn_catalogue_keeps(&holds, E(ent_b), 99) == 1,
	      "a `then` of DEFAULT was consulted before the deadline");

	/* DUE lists exactly the rows whose deadline has passed, and does not
	 * reclaim them -- a read must not write. */
	n = fzn_catalogue_due(&holds, 99, out, 4, &dropped);
	CHECK(n == 0 && dropped == 0, "a deadline came due early (%zu, %zu)", n, dropped);
	n = fzn_catalogue_due(&holds, 100, out, 4, &dropped);
	CHECK(n == 2 && dropped == 0, "both deadlines did not come due at T (%zu, %zu)",
	      n, dropped);
	CHECK(fzn_catalogue_hold_count(&holds) == 2, "`due` reclaimed rows, and it must not");

	/* A row with no deadline never comes due. */
	fzn_catalogue_retain(&holds, E(ent_c), FZN_CATALOGUE_RETAIN_KEEP);
	n = fzn_catalogue_due(&holds, 0xffffffffffffffffu, out, 4, &dropped);
	CHECK(n == 2 && dropped == 0, "a row with no deadline came due (%zu)", n);

	/* AND THE REMAINDER IS REPORTED. A count that silently omitted them
	 * would let a consumer believe it had seen every deadline. */
	n = fzn_catalogue_due(&holds, 100, out, 1, &dropped);
	CHECK(n == 1 && dropped == 1, "a too-small buffer did not report the rest (%zu, %zu)",
	      n, dropped);
	n = fzn_catalogue_due(&holds, 100, out, 0, &dropped);
	CHECK(n == 0 && dropped == 2, "a zero buffer did not report all of them (%zu, %zu)",
	      n, dropped);
}

/* WHAT IS REFUSED. Each paired with a control that passes, so a refusal that
 * refused everything cannot look like a working guard. */
static void test_refusals(void)
{
	fzn_catalogue_hold_t rows[4];
	fzn_catalogue_holds_t holds;
	fzn_catalogue_entity_t out[2];
	size_t dropped;

	fzn_catalogue_holds_init(&holds, rows, 4);

	/* A DEADLINE ON A DEFAULT MODE IS A ROW THAT SAYS NOTHING. */
	CHECK(fzn_catalogue_retain_until(&holds, E(ent_a), FZN_CATALOGUE_RETAIN_DEFAULT,
	                                 100, FZN_CATALOGUE_RETAIN_DROP) ==
	          FZN_CATALOGUE_ERR_MALFORMED,
	      "a deadline on a DEFAULT mode was stored");
	CHECK(fzn_catalogue_retain_until(&holds, E(ent_a), FZN_CATALOGUE_RETAIN_DEFAULT, 0,
	                                 FZN_CATALOGUE_RETAIN_DROP) == FZN_CATALOGUE_OK,
	      "the control -- DEFAULT with no deadline -- was refused too");
	CHECK(fzn_catalogue_hold_count(&holds) == 0, "a refused row was stored anyway");

	/* AN UNKNOWN MODE IS REFUSED, NOT SKIPPED. */
	CHECK(fzn_catalogue_retain(&holds, E(ent_a), (fzn_catalogue_retention_t)7) ==
	          FZN_CATALOGUE_ERR_KIND,
	      "a mode outside the three was accepted");
	CHECK(fzn_catalogue_retain_until(&holds, E(ent_a), FZN_CATALOGUE_RETAIN_KEEP, 100,
	                                 (fzn_catalogue_retention_t)7) ==
	          FZN_CATALOGUE_ERR_KIND,
	      "a `then` outside the three was accepted");
	CHECK(fzn_catalogue_retain_until(&holds, E(ent_a), FZN_CATALOGUE_RETAIN_KEEP, 100,
	                                 FZN_CATALOGUE_RETAIN_DROP) == FZN_CATALOGUE_OK,
	      "the control -- both modes known -- was refused too");

	/* AN ENTITY IS A RECORD SUBJECT. A shorter or longer key is a caller
	 * confusing an entity with something that is not one, and truncating
	 * it would silently key the row on a prefix. */
	CHECK(fzn_catalogue_retain(&holds, ent_b, FZN_CATALOGUE_ENTITY_LEN - 1u,
	                           FZN_CATALOGUE_RETAIN_KEEP) == FZN_CATALOGUE_ERR_MALFORMED,
	      "a short entity was accepted");
	CHECK(fzn_catalogue_retain(&holds, ent_b, FZN_CATALOGUE_ENTITY_LEN + 1u,
	                           FZN_CATALOGUE_RETAIN_KEEP) == FZN_CATALOGUE_ERR_MALFORMED,
	      "a long entity was accepted");
	CHECK(fzn_catalogue_retention_of(&holds, ent_b, FZN_CATALOGUE_ENTITY_LEN - 1u, 0) ==
	          FZN_CATALOGUE_RETAIN_DEFAULT,
	      "a short entity was looked up rather than refused");
	CHECK(fzn_catalogue_retain(&holds, E(ent_b), FZN_CATALOGUE_RETAIN_KEEP) ==
	          FZN_CATALOGUE_OK,
	      "the control -- a full-length entity -- was refused too");

	/* Arguments. */
	CHECK(fzn_catalogue_holds_init(NULL, rows, 4) == FZN_CATALOGUE_ERR_MALFORMED,
	      "a null table initialised");
	CHECK(fzn_catalogue_holds_init(&holds, NULL, 4) == FZN_CATALOGUE_ERR_MALFORMED,
	      "a capacity with no rows initialised");
	CHECK(fzn_catalogue_holds_init(&holds, NULL, 0) == FZN_CATALOGUE_OK,
	      "a table with no capacity at all was refused, and it is the shape a "
	      "consumer whose whole policy is the wide bit wants");
	CHECK(fzn_catalogue_retain(&holds, E(ent_a), FZN_CATALOGUE_RETAIN_KEEP) ==
	          FZN_CATALOGUE_ERR_RANGE,
	      "a zero-capacity table stored a row");
	CHECK(fzn_catalogue_retain_all(NULL, 1) == FZN_CATALOGUE_ERR_MALFORMED,
	      "a null table took a wide bit");
	CHECK(fzn_catalogue_retain(NULL, E(ent_a), FZN_CATALOGUE_RETAIN_KEEP) ==
	          FZN_CATALOGUE_ERR_MALFORMED,
	      "a null table took a row");
	CHECK(fzn_catalogue_retain(&holds, NULL, FZN_CATALOGUE_ENTITY_LEN,
	                           FZN_CATALOGUE_RETAIN_KEEP) == FZN_CATALOGUE_ERR_MALFORMED,
	      "a null entity was accepted");

	fzn_catalogue_holds_init(&holds, rows, 4);
	CHECK(fzn_catalogue_due(&holds, 0, out, 2, NULL) == 0,
	      "`due` answered without somewhere to report the remainder");
	CHECK(fzn_catalogue_due(NULL, 0, out, 2, &dropped) == 0, "`due` read a null table");
}

/* The names, because an arm that renders text no test reads is an arm that
 * can say the wrong thing for ever. */
static void test_names(void)
{
	CHECK(strcmp(fzn_catalogue_retention_str(FZN_CATALOGUE_RETAIN_DEFAULT), "default") == 0,
	      "DEFAULT is not named 'default'");
	CHECK(strcmp(fzn_catalogue_retention_str(FZN_CATALOGUE_RETAIN_KEEP), "keep") == 0,
	      "KEEP is not named 'keep'");
	CHECK(strcmp(fzn_catalogue_retention_str(FZN_CATALOGUE_RETAIN_DROP), "drop") == 0,
	      "DROP is not named 'drop'");
	CHECK(strcmp(fzn_catalogue_retention_str((fzn_catalogue_retention_t)7), "unknown") == 0,
	      "an unknown mode is not named 'unknown'");
}

int main(void)
{
	entities();

	test_the_wide_bit();
	test_tri_state();
	test_default_reclaims();
	test_deadline();
	test_refusals();
	test_names();

	printf("retention_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
