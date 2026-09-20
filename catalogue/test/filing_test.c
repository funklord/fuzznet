/* Tests for catalogue/filing.c: where this host puts the bytes. sec 323.
 *
 * THE CASES THIS SUITE EXISTS FOR are the three properties the old module got
 * structurally and this one has to get some other way.
 *
 *   A FILING IS A SUBSET OF WHAT THE RECORDS ASSERT. The old module marked an
 *   existing edge, so an unasserted filing was not expressible. Here it is
 *   expressible and must be refused, which means a test rather than a type.
 *
 *   EXACTLY ONCE PER ENTITY. Still structural -- setting replaces -- so what
 *   is asserted is that a second filing does not add a row.
 *
 *   A RETRACTED LINK STOPS BACKING ITS FILING. The old module cleared the mark
 *   when the edge was unlinked; this one has no unlink to hook, so it refuses
 *   at read. That difference is the whole of what could go wrong here, and it
 *   is driven from both sides: the read refusing, and the prune reclaiming.
 *
 * AND THE REFILE IS DRIVEN THROUGH A RESTART, because resuming from a count is
 * the property the old module leaned on a lock for and this one states as a
 * precondition. A test that only ever walked a job start to finish would never
 * exercise the thing the lock used to protect.
 */

#include "../filing.h"

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
	fprintf(stderr, "  FAIL filing_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

static uint8_t host[32];
static uint8_t e1[FZN_CATALOGUE_ENTITY_LEN];
static uint8_t e2[FZN_CATALOGUE_ENTITY_LEN];

#define DIM   ((const uint8_t *)"place"), 5u
#define PHOTO ((const uint8_t *)"/photos/2026"), 12u
#define MUSIC ((const uint8_t *)"/music/live"), 11u

static void fixtures(void)
{
	memset(host, 0x01, sizeof(host));
	memset(e1, 0xe1, sizeof(e1));
	memset(e2, 0xe2, sizeof(e2));
}

/* A curated link: an attribute whose NAME is the dimension and whose VALUE is
 * a path in that dimension's tree. sec 315. */
static void link(fzn_catalogue_assertion_t *a, const uint8_t *entity,
                 const uint8_t *name, size_t name_len, const uint8_t *path,
                 size_t path_len, int live)
{
	memset(a, 0, sizeof(*a));
	a->issuer = host;    a->issuer_len = 32;
	a->entity = entity;  a->entity_len = FZN_CATALOGUE_ENTITY_LEN;
	a->name = name;      a->name_len = name_len;
	a->value = path;     a->value_len = path_len;
	a->attr_class = FZN_CATALOGUE_LABEL;
	a->scope = FZN_CATALOGUE_ESTATE;
	a->merge = FZN_CATALOGUE_UNION;
	a->capability = FZN_CATALOGUE_CAP_NONE;
	a->live = live;
}

static void holder_link(fzn_catalogue_assertion_t *a, const uint8_t *entity,
                        const uint8_t *name, size_t name_len, const uint8_t *path,
                        size_t path_len)
{
	link(a, entity, name, name_len, path, path_len, 1);
	a->capability = FZN_CATALOGUE_CAP_HOLDER;
}

static int is_path(const fzn_catalogue_filing_t *f, const uint8_t *path, size_t len)
{
	return f && f->path_len == len && memcmp(f->path, path, len) == 0;
}

/* AN ENTITY MAY SIT IN MANY PLACES AND BE FILED IN ONE. */
static void test_file_under(void)
{
	fzn_catalogue_assertion_t set[2];
	fzn_catalogue_filing_t rows[4];
	fzn_catalogue_filings_t filings;
	const fzn_catalogue_filing_t *got;

	link(&set[0], e1, DIM, PHOTO, 1);
	link(&set[1], e1, DIM, MUSIC, 1);

	CHECK(fzn_catalogue_filings_init(&filings, rows, 4) == FZN_CATALOGUE_OK,
	      "a table over caller-owned rows was refused");
	CHECK(fzn_catalogue_filed_under(&filings, set, 2, e1, sizeof(e1)) == NULL,
	      "an entity nobody has filed reported a filing");

	CHECK(fzn_catalogue_file_under(&filings, set, 2, e1, sizeof(e1), DIM, PHOTO) ==
	          FZN_CATALOGUE_OK,
	      "filing under an asserted link was refused");
	got = fzn_catalogue_filed_under(&filings, set, 2, e1, sizeof(e1));
	CHECK(is_path(got, PHOTO), "the filing did not come back");
	CHECK(fzn_catalogue_filing_count(&filings) == 1, "one filing was not one row");

	/* EXACTLY ONCE: filing it elsewhere REPLACES rather than adding. */
	CHECK(fzn_catalogue_file_under(&filings, set, 2, e1, sizeof(e1), DIM, MUSIC) ==
	          FZN_CATALOGUE_OK,
	      "re-filing to another asserted link was refused");
	got = fzn_catalogue_filed_under(&filings, set, 2, e1, sizeof(e1));
	CHECK(is_path(got, MUSIC), "the re-filing did not take");
	CHECK(fzn_catalogue_filing_count(&filings) == 1,
	      "re-filing added a second row, so an entity is filed in two places at "
	      "once and the exactly-once invariant is gone (count=%zu)",
	      fzn_catalogue_filing_count(&filings));

	CHECK(fzn_catalogue_unfile(&filings, e1, sizeof(e1)) == FZN_CATALOGUE_OK,
	      "unfiling was refused");
	CHECK(fzn_catalogue_filing_count(&filings) == 0, "unfiling did not give the row back");
	CHECK(fzn_catalogue_unfile(&filings, e1, sizeof(e1)) == FZN_CATALOGUE_OK,
	      "unfiling something already unfiled was an error");
}

/* A FILING IS A SUBSET OF WHAT THE RECORDS ASSERT, which the old module got
 * from marking an existing edge and this one must refuse for. */
static void test_must_be_asserted(void)
{
	fzn_catalogue_assertion_t set[3];
	fzn_catalogue_filing_t rows[4];
	fzn_catalogue_filings_t filings;

	link(&set[0], e1, DIM, PHOTO, 1);

	fzn_catalogue_filings_init(&filings, rows, 4);

	/* A path nothing asserts. */
	CHECK(fzn_catalogue_file_under(&filings, set, 1, e1, sizeof(e1), DIM, MUSIC) ==
	          FZN_CATALOGUE_ERR_ABSENT,
	      "an entity was filed somewhere the records do not put it");
	/* A dimension nothing asserts. */
	CHECK(fzn_catalogue_file_under(&filings, set, 1, e1, sizeof(e1),
	                               (const uint8_t *)"other", 5u, PHOTO) ==
	          FZN_CATALOGUE_ERR_ABSENT,
	      "an entity was filed in a dimension the records do not use");
	/* Another entity's link is not this one's. */
	CHECK(fzn_catalogue_file_under(&filings, set, 1, e2, sizeof(e2), DIM, PHOTO) ==
	          FZN_CATALOGUE_ERR_ABSENT,
	      "one entity was filed on another entity's link");
	CHECK(fzn_catalogue_filing_count(&filings) == 0, "a refused filing stored a row");

	/* A RETRACTED LINK IS NOT A PLACE IT BELONGS. */
	link(&set[1], e2, DIM, MUSIC, 0);
	CHECK(fzn_catalogue_file_under(&filings, set, 2, e2, sizeof(e2), DIM, MUSIC) ==
	          FZN_CATALOGUE_ERR_ABSENT,
	      "an entity was filed on a retracted link");

	/* AND A HOLDER ASSERTION IS NOT A LINK. It says where the bytes ARE,
	 * not where they BELONG -- sec 321, in different clothes: filing on one
	 * would let the fact that a host holds something decide where it files
	 * it. */
	holder_link(&set[2], e2, DIM, MUSIC);
	CHECK(fzn_catalogue_file_under(&filings, set, 3, e2, sizeof(e2), DIM, MUSIC) ==
	          FZN_CATALOGUE_ERR_ABSENT,
	      "a HOLDER assertion backed a filing, so where a host happens to hold "
	      "bytes decides where it files them");

	/* THE CONTROL: the same entity, the same path, as a live curated link. */
	link(&set[2], e2, DIM, MUSIC, 1);
	CHECK(fzn_catalogue_file_under(&filings, set, 3, e2, sizeof(e2), DIM, MUSIC) ==
	          FZN_CATALOGUE_OK,
	      "the control -- a live curated link -- was refused too, so the check "
	      "refuses everything and the cases above hold for the wrong reason");
}

/* THE RULE THAT MOVED: a filing whose link is retracted is refused at READ,
 * because there is no unlink to hook. Driven from both sides. */
static void test_stale_filing(void)
{
	fzn_catalogue_assertion_t set[2];
	fzn_catalogue_filing_t rows[4];
	fzn_catalogue_filings_t filings;

	link(&set[0], e1, DIM, PHOTO, 1);
	link(&set[1], e2, DIM, MUSIC, 1);

	fzn_catalogue_filings_init(&filings, rows, 4);
	fzn_catalogue_file_under(&filings, set, 2, e1, sizeof(e1), DIM, PHOTO);
	fzn_catalogue_file_under(&filings, set, 2, e2, sizeof(e2), DIM, MUSIC);
	CHECK(fzn_catalogue_filing_count(&filings) == 2, "two filings were not two rows");

	/* The link is retracted. Nothing calls into this module to say so. */
	set[0].live = 0;

	CHECK(fzn_catalogue_filed_under(&filings, set, 2, e1, sizeof(e1)) == NULL,
	      "a filing whose link has been retracted still answered, so this host "
	      "computes a path from a membership nobody asserts");
	CHECK(fzn_catalogue_filed_under(&filings, set, 2, e2, sizeof(e2)) != NULL,
	      "the entity whose link is still live stopped answering too, so the "
	      "re-check refuses everything");
	CHECK(fzn_catalogue_filing_count(&filings) == 2,
	      "the read reclaimed a row, and it is a read");

	/* AND THE PRUNE IS WHAT GIVES THE SLOT BACK, deliberately. */
	CHECK(fzn_catalogue_filing_prune(&filings, set, 2) == 1,
	      "the prune did not drop the unbacked row");
	CHECK(fzn_catalogue_filing_count(&filings) == 1, "the prune dropped the wrong count");
	CHECK(fzn_catalogue_filed_under(&filings, set, 2, e2, sizeof(e2)) != NULL,
	      "the prune took the row that was still backed");
	CHECK(fzn_catalogue_filing_prune(&filings, set, 2) == 0,
	      "a second prune dropped something that was backed");

	/* A PRUNE OVER AN EMPTY SET DROPS EVERYTHING, which is the degenerate
	 * case and has to be the conservative direction: nothing is asserted,
	 * so nothing is backed. */
	CHECK(fzn_catalogue_filing_prune(&filings, NULL, 0) == 1,
	      "an empty set left a filing standing");
	CHECK(fzn_catalogue_filing_count(&filings) == 0, "the table did not empty");
}

/* THE REFILE, INCLUDING A RESTART. */
static void test_refile(void)
{
	fzn_catalogue_assertion_t set[4];
	fzn_catalogue_filing_t rows[4];
	fzn_catalogue_filings_t filings;
	fzn_catalogue_move_t moves[4];
	fzn_catalogue_refile_t job, resumed;
	const fzn_catalogue_move_t *from;
	const fzn_catalogue_filing_t *to;
	size_t done = 0, total = 0;

	link(&set[0], e1, DIM, PHOTO, 1);
	link(&set[1], e1, DIM, MUSIC, 1);
	link(&set[2], e2, DIM, PHOTO, 1);
	link(&set[3], e2, DIM, MUSIC, 1);

	fzn_catalogue_filings_init(&filings, rows, 4);
	fzn_catalogue_file_under(&filings, set, 4, e1, sizeof(e1), DIM, PHOTO);
	fzn_catalogue_file_under(&filings, set, 4, e2, sizeof(e2), DIM, PHOTO);

	/* 1. CAPTURE BEFORE THE CHANGE, which is the only order that works:
	 *    afterwards the old paths are gone and there is nothing to move
	 *    files from. */
	CHECK(fzn_catalogue_refile_capture(&filings, &job, moves, 4) == FZN_CATALOGUE_OK,
	      "a capture was refused");
	CHECK(job.used == 2, "the capture did not take both filings (%zu)", job.used);

	/* 2. the consumer changes the filing freely. */
	fzn_catalogue_file_under(&filings, set, 4, e1, sizeof(e1), DIM, MUSIC);
	fzn_catalogue_unfile(&filings, e2, sizeof(e2));

	/* 3. both paths, from the capture and from the table as it stands. */
	CHECK(fzn_catalogue_refile_at(&job, &filings, set, 4, &from, &to) ==
	          FZN_CATALOGUE_OK,
	      "no move at the cursor");
	CHECK(memcmp(from->entity, e1, sizeof(e1)) == 0,
	      "the moves are not in entity order, so a restart resumes at a "
	      "different one");
	CHECK(from->was_path_len == 12u && memcmp(from->was_path, "/photos/2026", 12) == 0,
	      "the capture did not hold where the file WAS");
	CHECK(is_path(to, MUSIC), "the move does not name where the file should go");

	/* A RESTART: the job is plain data, so a consumer writes it out and
	 * reads it back. Re-entering is what a restart does and is not an
	 * error. */
	CHECK(fzn_catalogue_refile_advance(&job) == FZN_CATALOGUE_OK, "advance failed");
	memcpy(&resumed, &job, sizeof(resumed));
	resumed.moves = moves;
	CHECK(fzn_catalogue_refile_progress(&resumed, &done, &total) == FZN_CATALOGUE_OK,
	      "progress on a resumed job failed");
	CHECK(done == 1 && total == 2, "a resumed job lost its place (%zu/%zu)", done, total);

	/* THE SECOND ENTITY HAS NO HOME NOW, and NULL is a real answer rather
	 * than an error: the consumer unfiled it, and what to do with a file
	 * whose entity has nowhere to go is the consumer's decision. */
	CHECK(fzn_catalogue_refile_at(&resumed, &filings, set, 4, &from, &to) ==
	          FZN_CATALOGUE_OK,
	      "the resumed job had no move at its cursor");
	CHECK(memcmp(from->entity, e2, sizeof(e2)) == 0, "the resumed move is the wrong one");
	CHECK(to == NULL,
	      "an unfiled entity reported somewhere to move its file to");

	CHECK(fzn_catalogue_refile_advance(&resumed) == FZN_CATALOGUE_OK, "advance failed");
	CHECK(fzn_catalogue_refile_at(&resumed, &filings, set, 4, &from, &to) ==
	          FZN_CATALOGUE_ERR_RANGE,
	      "the cursor ran past the end without saying so");
	CHECK(fzn_catalogue_refile_advance(&resumed) == FZN_CATALOGUE_ERR_RANGE,
	      "advancing past the end was allowed");
}

/* A CAPTURE THAT DOES NOT FIT IS LOUD, because holding some of them would move
 * some of the files and leave the rest where a stale path says they are. */
static void test_capture_must_fit(void)
{
	fzn_catalogue_assertion_t set[2];
	fzn_catalogue_filing_t rows[4];
	fzn_catalogue_filings_t filings;
	fzn_catalogue_move_t moves[1];
	fzn_catalogue_refile_t job;

	link(&set[0], e1, DIM, PHOTO, 1);
	link(&set[1], e2, DIM, PHOTO, 1);

	fzn_catalogue_filings_init(&filings, rows, 4);
	fzn_catalogue_file_under(&filings, set, 2, e1, sizeof(e1), DIM, PHOTO);
	fzn_catalogue_file_under(&filings, set, 2, e2, sizeof(e2), DIM, PHOTO);

	CHECK(fzn_catalogue_refile_capture(&filings, &job, moves, 1) ==
	          FZN_CATALOGUE_ERR_RANGE,
	      "a capture too small for the filings succeeded, so some files move and "
	      "the rest are left where a stale path says they are");
	CHECK(job.captured == 0, "a refused capture left a usable job");

	/* An empty table captures cleanly into no rows at all. */
	fzn_catalogue_filings_init(&filings, rows, 4);
	CHECK(fzn_catalogue_refile_capture(&filings, &job, NULL, 0) == FZN_CATALOGUE_OK,
	      "capturing an empty filing was refused");
	CHECK(job.used == 0 && job.captured == 1, "an empty capture is not an empty job");
}

/* WHAT IS REFUSED, each with a control. */
static void test_refusals(void)
{
	fzn_catalogue_assertion_t set[1];
	fzn_catalogue_filing_t rows[2];
	fzn_catalogue_filings_t filings;
	fzn_catalogue_refile_t job;
	fzn_catalogue_move_t moves[2];
	const fzn_catalogue_move_t *from;
	const fzn_catalogue_filing_t *to;
	uint8_t longname[FZN_CATALOGUE_FILING_NAME_MAX + 1u];
	uint8_t longpath[FZN_CATALOGUE_FILING_PATH_MAX + 1u];

	link(&set[0], e1, DIM, PHOTO, 1);
	fzn_catalogue_filings_init(&filings, rows, 2);

	memset(longname, 'n', sizeof(longname));
	memset(longpath, 'p', sizeof(longpath));

	CHECK(fzn_catalogue_file_under(&filings, set, 1, e1, sizeof(e1), longname,
	                               sizeof(longname), PHOTO) == FZN_CATALOGUE_ERR_RANGE,
	      "a dimension name too long for a row was accepted");
	CHECK(fzn_catalogue_file_under(&filings, set, 1, e1, sizeof(e1), DIM, longpath,
	                               sizeof(longpath)) == FZN_CATALOGUE_ERR_RANGE,
	      "a path too long for a row was accepted -- truncating it would name a "
	      "different place and move the file there");
	CHECK(fzn_catalogue_file_under(&filings, set, 1, e1, FZN_CATALOGUE_ENTITY_LEN - 1u,
	                               DIM, PHOTO) == FZN_CATALOGUE_ERR_MALFORMED,
	      "a short entity was accepted");
	CHECK(fzn_catalogue_file_under(NULL, set, 1, e1, sizeof(e1), DIM, PHOTO) ==
	          FZN_CATALOGUE_ERR_MALFORMED, "a null table took a filing");
	CHECK(fzn_catalogue_file_under(&filings, set, 1, e1, sizeof(e1), DIM, PHOTO) ==
	          FZN_CATALOGUE_OK, "the control -- every argument in range");

	/* A full table still lets an existing entity be re-filed. */
	{
		fzn_catalogue_assertion_t two[2];
		fzn_catalogue_filing_t one_row[1];
		fzn_catalogue_filings_t small;

		link(&two[0], e1, DIM, PHOTO, 1);
		link(&two[1], e2, DIM, PHOTO, 1);
		fzn_catalogue_filings_init(&small, one_row, 1);
		CHECK(fzn_catalogue_file_under(&small, two, 2, e1, sizeof(e1), DIM, PHOTO) ==
		          FZN_CATALOGUE_OK, "the first filing was refused");
		CHECK(fzn_catalogue_file_under(&small, two, 2, e2, sizeof(e2), DIM, PHOTO) ==
		          FZN_CATALOGUE_ERR_RANGE, "a full table took a second entity");
		link(&two[0], e1, DIM, MUSIC, 1);
		CHECK(fzn_catalogue_file_under(&small, two, 2, e1, sizeof(e1), DIM, MUSIC) ==
		          FZN_CATALOGUE_OK,
		      "a full table refused to re-file an entity it already holds");
	}

	/* The cursor refuses an uncaptured job rather than reading its rows. */
	memset(&job, 0, sizeof(job));
	job.moves = moves;
	CHECK(fzn_catalogue_refile_at(&job, &filings, set, 1, &from, &to) ==
	          FZN_CATALOGUE_ERR_MALFORMED, "an uncaptured job answered at the cursor");
	CHECK(fzn_catalogue_refile_advance(&job) == FZN_CATALOGUE_ERR_MALFORMED,
	      "an uncaptured job advanced");
	{
		size_t a = 0, b = 0;

		CHECK(fzn_catalogue_refile_progress(&job, &a, &b) ==
		          FZN_CATALOGUE_ERR_MALFORMED, "an uncaptured job reported progress");
	}
	CHECK(fzn_catalogue_filings_init(&filings, NULL, 2) == FZN_CATALOGUE_ERR_MALFORMED,
	      "a capacity with no rows initialised");
	CHECK(fzn_catalogue_filings_init(&filings, NULL, 0) == FZN_CATALOGUE_OK,
	      "a table with no capacity was refused, and it is the state a host that "
	      "has placed nothing on disk is in");
}

int main(void)
{
	fixtures();

	test_file_under();
	test_must_be_asserted();
	test_stale_filing();
	test_refile();
	test_capture_must_fit();
	test_refusals();

	printf("filing_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
