/* Tests for catalog/source.c: C13's sources and C15's in-place promotion.
 * sec 340.
 *
 * THE CASE THIS SUITE EXISTS FOR is the one the holder's decision created. A
 * referenced source is a collection somebody built over decades and asked to
 * have INDEXED RATHER THAN REARRANGED, and C15 as settled lets one entry in it
 * be made writable where it lies. So the property under test is not that
 * promotion works -- it is that nothing makes MORE than the named entry
 * writable, and that every route to a yes goes through a promotion somebody
 * asked for by name.
 *
 * Every refusal below is driven against a CONTROL that must still pass: the
 * promoted entry itself, at its own path. A guard that answered no to
 * everything would satisfy each case here and give a person a catalogue that
 * can never write anything.
 */

#include "../source.h"

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
	fprintf(stderr, "  FAIL source_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

static uint8_t e1[FZN_CATALOG_ENTITY_LEN];
static uint8_t e2[FZN_CATALOG_ENTITY_LEN];

#define REF ((const uint8_t *)"archive")
#define REF_LEN 7u
#define MAN ((const uint8_t *)"managed")
#define MAN_LEN 7u

static void declare_both(fzn_catalog_source_table_t *sources,
                         fzn_catalog_source_t *rows, size_t cap)
{
	CHECK(fzn_catalog_sources_init(sources, rows, cap) == FZN_CATALOG_OK,
	      "the source table would not initialise");
	CHECK(fzn_catalog_source_declare(sources, REF, REF_LEN,
	                                 FZN_CATALOG_POLICY_REFERENCED)
	          == FZN_CATALOG_OK, "the referenced source would not declare");
	CHECK(fzn_catalog_source_declare(sources, MAN, MAN_LEN,
	                                 FZN_CATALOG_POLICY_MANAGED)
	          == FZN_CATALOG_OK, "the managed source would not declare");
}

static void test_a_policy_cannot_be_flipped(void)
{
	fzn_catalog_source_t rows[4];
	fzn_catalog_source_table_t sources;

	declare_both(&sources, rows, 4);

	/* The control: replaying the same configuration is not an error, so a
	 * caller re-reading its own config file is not punished for it. */
	CHECK(fzn_catalog_source_declare(&sources, REF, REF_LEN,
	                                 FZN_CATALOG_POLICY_REFERENCED)
	          == FZN_CATALOG_OK, "replaying the same policy was refused");
	CHECK(fzn_catalog_source_count(&sources) == 2,
	      "replaying a declaration added a row");

	/* THE ONE CALL THAT COULD MAKE A WHOLE COLLECTION WRITABLE AT ONCE. */
	CHECK(fzn_catalog_source_declare(&sources, REF, REF_LEN,
	                                 FZN_CATALOG_POLICY_MANAGED)
	          == FZN_CATALOG_ERR_KIND,
	      "a referenced source was flipped to managed by re-declaring it");
	CHECK(fzn_catalog_source_find(&sources, REF, REF_LEN)->policy
	          == FZN_CATALOG_POLICY_REFERENCED,
	      "the refused re-declaration changed the policy anyway");

	/* And the other direction, which is not dangerous and is refused for
	 * the same reason: one rule, not a rule with an exception. */
	CHECK(fzn_catalog_source_declare(&sources, MAN, MAN_LEN,
	                                 FZN_CATALOG_POLICY_REFERENCED)
	          == FZN_CATALOG_ERR_KIND,
	      "a managed source was flipped to referenced");

	/* C28/F26: a policy this build does not know. */
	CHECK(fzn_catalog_source_declare(&sources, (const uint8_t *)"x", 1,
	                                 (fzn_catalog_policy_t)7)
	          == FZN_CATALOG_ERR_KIND, "an unknown policy was accepted");
}

static void test_promotion_is_one_entry_in_one_place(void)
{
	fzn_catalog_source_t rows[4];
	fzn_catalog_source_table_t sources;
	fzn_catalog_promotion_t prows[4];
	fzn_catalog_promotions_t proms;

	declare_both(&sources, rows, 4);
	CHECK(fzn_catalog_promotions_init(&proms, prows, 4) == FZN_CATALOG_OK,
	      "the promotion table would not initialise");

	/* Nothing is writable in a referenced source to begin with. */
	CHECK(!fzn_catalog_writable(&sources, &proms, e1, sizeof(e1), REF,
	                            REF_LEN, (const uint8_t *)"a/b.flac", 8),
	      "a referenced entry was writable before anybody promoted it");

	CHECK(fzn_catalog_promote(&proms, &sources, e1, sizeof(e1), REF, REF_LEN,
	                          (const uint8_t *)"a/b.flac", 8)
	          == FZN_CATALOG_OK, "the promotion was refused");

	/* THE CONTROL: the promoted entry, at its own path, is writable. */
	CHECK(fzn_catalog_writable(&sources, &proms, e1, sizeof(e1), REF,
	                           REF_LEN, (const uint8_t *)"a/b.flac", 8),
	      "the promoted entry was not writable");

	/* AND NOTHING ELSE IS. A sibling in the same directory. */
	CHECK(!fzn_catalog_writable(&sources, &proms, e2, sizeof(e2), REF,
	                            REF_LEN, (const uint8_t *)"a/c.flac", 8),
	      "promoting one entry made a sibling writable");
	/* The same entity at a different path -- which is what a file its
	 * owner has moved looks like from here (C16). */
	CHECK(!fzn_catalog_writable(&sources, &proms, e1, sizeof(e1), REF,
	                            REF_LEN, (const uint8_t *)"a/moved.flac", 12),
	      "the permission followed the entity to another path");
	/* The directory the promoted file is in. */
	CHECK(!fzn_catalog_writable(&sources, &proms, e1, sizeof(e1), REF,
	                            REF_LEN, (const uint8_t *)"a", 1),
	      "promoting a file made its directory writable");
	/* A prefix of the promoted path, which is the subtree case spelled the
	 * way a comparison bug would spell it. */
	CHECK(!fzn_catalog_writable(&sources, &proms, e1, sizeof(e1), REF,
	                            REF_LEN, (const uint8_t *)"a/b", 3),
	      "a prefix of the promoted path was writable");
	/* The same path in another source. */
	CHECK(!fzn_catalog_writable(&sources, &proms, e1, sizeof(e1),
	                            (const uint8_t *)"other", 5,
	                            (const uint8_t *)"a/b.flac", 8),
	      "an undeclared source answered yes");
	/* AND IN A SECOND REFERENCED SOURCE THAT IS DECLARED, which is the
	 * case an undeclared name cannot test: two collections can easily
	 * share a relative path, and a promotion is about one of them. */
	CHECK(fzn_catalog_source_declare(&sources, (const uint8_t *)"vault", 5,
	                                 FZN_CATALOG_POLICY_REFERENCED)
	          == FZN_CATALOG_OK, "the second referenced source was refused");
	CHECK(!fzn_catalog_writable(&sources, &proms, e1, sizeof(e1),
	                            (const uint8_t *)"vault", 5,
	                            (const uint8_t *)"a/b.flac", 8),
	      "the promotion reached the same path in another source");
}

static void test_demotion_and_replacement(void)
{
	fzn_catalog_source_t rows[4];
	fzn_catalog_source_table_t sources;
	fzn_catalog_promotion_t prows[4];
	fzn_catalog_promotions_t proms;

	declare_both(&sources, rows, 4);
	fzn_catalog_promotions_init(&proms, prows, 4);

	CHECK(fzn_catalog_promote(&proms, &sources, e1, sizeof(e1), REF, REF_LEN,
	                          (const uint8_t *)"a/b.flac", 8)
	          == FZN_CATALOG_OK, "the promotion was refused");
	CHECK(fzn_catalog_promotion_count(&proms) == 1, "the row is not there");

	/* At most one row per entity: promoting it elsewhere REPLACES. Two rows
	 * would be two places a caller could be told yes about. */
	CHECK(fzn_catalog_promote(&proms, &sources, e1, sizeof(e1), REF, REF_LEN,
	                          (const uint8_t *)"a/c.flac", 8)
	          == FZN_CATALOG_OK, "re-promoting was refused");
	CHECK(fzn_catalog_promotion_count(&proms) == 1,
	      "re-promoting added a second row for one entity");
	CHECK(!fzn_catalog_writable(&sources, &proms, e1, sizeof(e1), REF,
	                            REF_LEN, (const uint8_t *)"a/b.flac", 8),
	      "the replaced promotion still answered yes");
	CHECK(fzn_catalog_writable(&sources, &proms, e1, sizeof(e1), REF,
	                           REF_LEN, (const uint8_t *)"a/c.flac", 8),
	      "the replacing promotion did not answer yes");

	CHECK(fzn_catalog_demote(&proms, e1, sizeof(e1)) == FZN_CATALOG_OK,
	      "demotion was refused");
	CHECK(fzn_catalog_promotion_count(&proms) == 0, "the row survived");
	CHECK(!fzn_catalog_writable(&sources, &proms, e1, sizeof(e1), REF,
	                            REF_LEN, (const uint8_t *)"a/c.flac", 8),
	      "a demoted entry was still writable");
	/* Demoting what was never promoted is not an error. */
	CHECK(fzn_catalog_demote(&proms, e2, sizeof(e2)) == FZN_CATALOG_OK,
	      "demoting an unpromoted entity was an error");
	CHECK(fzn_catalog_promoted(&proms, e1, sizeof(e1)) == NULL,
	      "a demoted entity still reads as promoted");
}

static void test_managed_needs_no_promotion(void)
{
	fzn_catalog_source_t rows[4];
	fzn_catalog_source_table_t sources;
	fzn_catalog_promotion_t prows[4];
	fzn_catalog_promotions_t proms;

	declare_both(&sources, rows, 4);
	fzn_catalog_promotions_init(&proms, prows, 4);

	/* C14: writable throughout, with nothing promoted. */
	CHECK(fzn_catalog_writable(&sources, &proms, e1, sizeof(e1), MAN,
	                           MAN_LEN, (const uint8_t *)"x/y.flac", 8),
	      "a managed entry was not writable");
	/* And promoting inside it is refused rather than accepted as a no-op:
	 * a caller who thinks the promotion granted this also thinks demoting
	 * would take it away. */
	CHECK(fzn_catalog_promote(&proms, &sources, e1, sizeof(e1), MAN, MAN_LEN,
	                          (const uint8_t *)"x/y.flac", 8)
	          == FZN_CATALOG_ERR_KIND,
	      "promoting inside a managed source was accepted");
	CHECK(fzn_catalog_promotion_count(&proms) == 0,
	      "the refused promotion left a row behind");
	/* A source nobody declared. */
	CHECK(fzn_catalog_promote(&proms, &sources, e1, sizeof(e1),
	                          (const uint8_t *)"nope", 4,
	                          (const uint8_t *)"x", 1)
	          == FZN_CATALOG_ERR_ABSENT,
	      "promoting in an undeclared source was accepted");
}

static void test_the_path_rule_is_c22s(void)
{
	fzn_catalog_source_t rows[4];
	fzn_catalog_source_table_t sources;
	fzn_catalog_promotion_t prows[4];
	fzn_catalog_promotions_t proms;
	size_t i;
	static const char *bad[] = {
		"..", "a/../../etc", "/a/b", "a//b", "a/", "./a", "a/.",
		"a\\b"
	};

	declare_both(&sources, rows, 4);
	fzn_catalog_promotions_init(&proms, prows, 4);

	/* THE CONTROL: an unusual but honest name, which must still pass, or
	 * the cases below prove only that the guard refuses things. */
	CHECK(fzn_catalog_relative_path_ok((const uint8_t *)"a b/...c- d.flac",
	                                   16),
	      "an unusual but legal relative path was refused");

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		const uint8_t *p = (const uint8_t *)bad[i];
		size_t n = strlen(bad[i]);

		CHECK(!fzn_catalog_relative_path_ok(p, n),
		      "the path `%s` was accepted", bad[i]);
		CHECK(fzn_catalog_promote(&proms, &sources, e1, sizeof(e1), REF,
		                          REF_LEN, p, n)
		          == FZN_CATALOG_ERR_MALFORMED,
		      "`%s` was promotable", bad[i]);
		/* AND THE PREDICATE REFUSES IT TOO. Otherwise the refusal is
		 * only as strong as the caller's habit of going through
		 * `fzn_catalog_promote`. */
		CHECK(!fzn_catalog_writable(&sources, &proms, e1, sizeof(e1), MAN,
		                            MAN_LEN, p, n),
		      "`%s` was writable in the managed source", bad[i]);
	}
	CHECK(fzn_catalog_promotion_count(&proms) == 0,
	      "a refused promotion left a row behind");
}

static void test_bounds_and_nulls(void)
{
	fzn_catalog_source_t rows[1];
	fzn_catalog_source_table_t sources;
	fzn_catalog_promotion_t prows[1];
	fzn_catalog_promotions_t proms;
	uint8_t big[FZN_CATALOG_SOURCE_PATH_MAX + 1u];

	memset(big, 'a', sizeof(big));

	CHECK(fzn_catalog_sources_init(&sources, rows, 1) == FZN_CATALOG_OK,
	      "init refused a one-row table");
	CHECK(fzn_catalog_source_declare(&sources, REF, REF_LEN,
	                                 FZN_CATALOG_POLICY_REFERENCED)
	          == FZN_CATALOG_OK, "the first declaration was refused");
	CHECK(fzn_catalog_source_declare(&sources, MAN, MAN_LEN,
	                                 FZN_CATALOG_POLICY_MANAGED)
	          == FZN_CATALOG_ERR_RANGE, "a full table accepted a row");
	/* THE OVER-LONG NAME NEEDS A TABLE WITH ROOM. Run against the full
	 * table above it, this passed because the table was FULL -- the same
	 * FZN_CATALOG_ERR_RANGE for a different reason, so the length check
	 * was never reached and the assertion proved nothing. */
	{
		fzn_catalog_source_t roomy_rows[2];
		fzn_catalog_source_table_t roomy;

		fzn_catalog_sources_init(&roomy, roomy_rows, 2);
		CHECK(fzn_catalog_source_declare(&roomy, big,
		                                 FZN_CATALOG_SOURCE_NAME_MAX + 1u,
		                                 FZN_CATALOG_POLICY_MANAGED)
		          == FZN_CATALOG_ERR_RANGE,
		      "an over-long name was accepted");
		/* The control: one byte shorter, in the same table, is
		 * accepted -- so the refusal above is about the length. */
		CHECK(fzn_catalog_source_declare(&roomy, big,
		                                 FZN_CATALOG_SOURCE_NAME_MAX,
		                                 FZN_CATALOG_POLICY_MANAGED)
		          == FZN_CATALOG_OK,
		      "a name at exactly the bound was refused");
	}
	CHECK(fzn_catalog_source_declare(&sources, REF, 0,
	                                 FZN_CATALOG_POLICY_MANAGED)
	          == FZN_CATALOG_ERR_MALFORMED, "an empty name was accepted");

	fzn_catalog_promotions_init(&proms, prows, 1);
	CHECK(!fzn_catalog_relative_path_ok(big, sizeof(big)),
	      "a path over the bound was accepted");
	CHECK(fzn_catalog_promote(&proms, &sources, e1, sizeof(e1) - 1u, REF,
	                          REF_LEN, (const uint8_t *)"a", 1)
	          == FZN_CATALOG_ERR_MALFORMED,
	      "a short entity was accepted");
	CHECK(fzn_catalog_promote(&proms, &sources, e1, sizeof(e1), REF, REF_LEN,
	                          (const uint8_t *)"a", 1) == FZN_CATALOG_OK,
	      "the one row was refused");
	CHECK(fzn_catalog_promote(&proms, &sources, e2, sizeof(e2), REF, REF_LEN,
	                          (const uint8_t *)"b", 1) == FZN_CATALOG_ERR_RANGE,
	      "a full promotion table accepted a row");

	/* Nulls answer no rather than crashing, and a zero capacity is an
	 * ordinary state for a host that has declared nothing. */
	CHECK(!fzn_catalog_writable(NULL, &proms, e1, sizeof(e1), REF, REF_LEN,
	                            (const uint8_t *)"a", 1),
	      "a null source table answered yes");
	CHECK(!fzn_catalog_writable(&sources, NULL, e1, sizeof(e1), REF, REF_LEN,
	                            (const uint8_t *)"a", 1),
	      "a null promotion table answered yes in a referenced source");
	CHECK(fzn_catalog_sources_init(&sources, NULL, 0) == FZN_CATALOG_OK,
	      "a zero-capacity table was an error");
	CHECK(fzn_catalog_source_count(&sources) == 0, "it was not empty");
	CHECK(fzn_catalog_source_find(&sources, REF, REF_LEN) == NULL,
	      "an empty table found something");
}

int main(void)
{
	memset(e1, 0xe1, sizeof(e1));
	memset(e2, 0xe2, sizeof(e2));

	test_a_policy_cannot_be_flipped();
	test_promotion_is_one_entry_in_one_place();
	test_demotion_and_replacement();
	test_managed_needs_no_promotion();
	test_the_path_rule_is_c22s();
	test_bounds_and_nulls();

	printf("source_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
