/* Tests for cli/sweep_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is `catalog/sweep.h`'s own: "a sweep held
 * back by the last-copy guard would be indistinguishable from a catalogue
 * with nothing to sweep -- and those want opposite responses". On a screen
 * that is a person misreading a zero; in an alerting rule it is a host whose
 * disk cannot be reclaimed reporting the same as one with nothing to reclaim,
 * and only the first needs anybody to do something.
 *
 * So both channels are checked: the words differ for a person and the enum
 * differs for a script.
 */

#include "../sweep_print.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL sweep_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_catalog_removal_t REMOVALS[4];

static void job_at(fzn_catalog_sweep_t *job, size_t used, size_t done)
{
	memset(job, 0, sizeof(*job));
	memset(REMOVALS, 0, sizeof(REMOVALS));
	job->removals = REMOVALS;
	job->capacity = 4u;
	job->used = used;
	job->done = done;
	job->captured = 1;
}

int main(void)
{
	char line[FZN_SWEEP_PRINT_MAX];
	char empty_line[FZN_SWEEP_PRINT_MAX];
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_sweep_t job;
	fzn_sweep_state_t s;
	size_t len = 0;
	int trunc = 0;

	/* NOTHING CAPTURED IS NOT AN EMPTY PLAN, and it is the zero value so a
	 * caller that ignores the state is told nobody asked. */
	s = FZN_SWEEP_DONE;
	CHECK(fzn_sweep_print(NULL, NULL, line, sizeof(line), &len, &s, &trunc) ==
	              FZN_CATALOG_OK,
	      "a null plan would not render");
	CHECK(s == FZN_SWEEP_NOTHING_CAPTURED, "a null plan was not reported as uncaptured");

	/* AN EMPTY PLAN. */
	memset(&plan, 0, sizeof(plan));
	CHECK(fzn_sweep_print(&plan, NULL, line, sizeof(line), &len, &s, &trunc) ==
	              FZN_CATALOG_OK,
	      "an empty plan would not render");
	CHECK(s == FZN_SWEEP_EMPTY, "an empty plan was not empty");
	memcpy(empty_line, line, sizeof(line));

	/* THE CASE THIS FILE EXISTS FOR, ON BOTH CHANNELS. */
	memset(&plan, 0, sizeof(plan));
	plan.last_copy = 3u;
	CHECK(fzn_sweep_print(&plan, NULL, line, sizeof(line), &len, &s, &trunc) ==
	              FZN_CATALOG_OK,
	      "a held-back plan would not render");
	CHECK(s == FZN_SWEEP_HELD_BACK,
	      "a sweep stopped by the last-copy guard reported the same state as a "
	      "catalogue with nothing in it, so a script cannot tell them apart");
	CHECK(strcmp(line, empty_line) != 0,
	      "held-back and empty print the same line, so a person cannot either");
	CHECK(strstr(line, "more replicas") != NULL,
	      "the line does not say what would actually help");

	/* EACH REASON NAMED, NEVER SUMMED. */
	memset(&plan, 0, sizeof(plan));
	plan.retained = 1u;
	plan.shared = 2u;
	plan.last_copy = 3u;
	plan.absent = 4u;
	CHECK(fzn_sweep_print(&plan, NULL, line, sizeof(line), &len, &s, &trunc) ==
	              FZN_CATALOG_OK,
	      "a plan with four reasons would not render");
	CHECK(strstr(line, "1 retained") != NULL && strstr(line, "2 shared") != NULL &&
	              strstr(line, "3 the last known copy") != NULL &&
	              strstr(line, "4 not held here") != NULL,
	      "the four reasons were summed rather than named");

	/* READY, RUNNING, DONE. */
	memset(&plan, 0, sizeof(plan));
	plan.planned = 4u;
	CHECK(fzn_sweep_print(&plan, NULL, line, sizeof(line), &len, &s, &trunc) ==
	              FZN_CATALOG_OK,
	      "a ready plan would not render");
	CHECK(s == FZN_SWEEP_READY, "a captured plan with no job was not ready");

	job_at(&job, 4u, 1u);
	CHECK(fzn_sweep_print(&plan, &job, line, sizeof(line), &len, &s, &trunc) ==
	              FZN_CATALOG_OK,
	      "a running job would not render");
	CHECK(s == FZN_SWEEP_RUNNING, "a part-done job was not running");
	CHECK(strstr(line, "1 of 4") != NULL, "the progress is not on the line");

	job_at(&job, 4u, 4u);
	CHECK(fzn_sweep_print(&plan, &job, line, sizeof(line), &len, &s, &trunc) ==
	              FZN_CATALOG_OK,
	      "a finished job would not render");
	CHECK(s == FZN_SWEEP_DONE, "a finished job was not done");

	/* REPORTING MUST NOT ADVANCE THE CURSOR. sec 181: `_advance` is called
	 * after the bytes are gone. Render an overdue-looking job repeatedly
	 * and require the position to be where it was. */
	{
		size_t before = 0;
		size_t total = 0;

		job_at(&job, 4u, 1u);
		CHECK(fzn_catalog_sweep_progress(&job, &before, &total) == FZN_CATALOG_OK,
		      "the fixture has no progress to read");
		fzn_sweep_print(&plan, &job, line, sizeof(line), &len, &s, &trunc);
		fzn_sweep_print(&plan, &job, line, sizeof(line), &len, &s, &trunc);
		CHECK(job.done == before,
		      "printing a sweep advanced its cursor, recording a removal that "
		      "never happened");
	}

	/* TRUNCATION IS ORTHOGONAL: ready AND short at once. */
	memset(&plan, 0, sizeof(plan));
	plan.planned = 4u;
	plan.truncated = 7u;
	CHECK(fzn_sweep_print(&plan, NULL, line, sizeof(line), &len, &s, &trunc) ==
	              FZN_CATALOG_OK,
	      "a truncated plan would not render");
	CHECK(s == FZN_SWEEP_READY && trunc == 1,
	      "truncation and the state are not independent, so a ready-and-short plan "
	      "cannot be reported as both");
	CHECK(strstr(line, "short") != NULL, "a short plan did not say its counts are short");

	/* BOTH OUT-PARAMETERS ARE REQUIRED. */
	CHECK(fzn_sweep_print(&plan, NULL, line, sizeof(line), &len, NULL, &trunc) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "the state was optional after all");
	CHECK(fzn_sweep_print(&plan, NULL, line, sizeof(line), &len, &s, NULL) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "truncation was optional after all");

	/* IT REFUSES RATHER THAN TRUNCATES, and leaves the conservative state. */
	{
		char small[4];
		size_t needed = 0;

		memset(small, '@', sizeof(small));
		s = FZN_SWEEP_DONE;
		trunc = 0;
		CHECK(fzn_sweep_print(&plan, NULL, small, sizeof(small), &needed, &s,
		                      &trunc) == FZN_CATALOG_ERR_MALFORMED,
		      "a buffer too small was written anyway");
		CHECK(needed > sizeof(small), "the size needed was not reported");
		CHECK(small[0] == '@', "a refused render left bytes in the buffer");
		CHECK(s == FZN_SWEEP_NOTHING_CAPTURED,
		      "a refused render left a reassuring state behind");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("sweep_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
