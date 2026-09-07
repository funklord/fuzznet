/* Tests for gui/sweep_view.cpp, headless.
 *
 * THE CASE THIS FILE EXISTS FOR is the one `catalog/sweep.h` states as the
 * reason its counters are kept apart: "a sweep held back by the last-copy
 * guard would be indistinguishable from a catalogue with nothing to sweep --
 * and those want opposite responses". Both plan zero. One means the disk
 * cannot be reclaimed because too few other hosts hold the bytes; the other
 * means there is nothing there. A screen that reported "0 planned" for both
 * would undo the distinction the library exists to keep.
 *
 * The second is that a view of a deletion must not perform one.
 * `fzn_catalog_sweep_advance` is called AFTER the bytes are gone, so a widget
 * that advanced a cursor while drawing would record a removal that never
 * happened -- and the record is what says the bytes are gone.
 */

#include "../sweep_view.h"

#include <QApplication>

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
	fprintf(stderr, "  FAIL sweep_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_catalog_removal_t REMOVALS[4];

/* A job holding `used` rows with `done` of them removed. The rows and the
 * cursor are caller-owned public state -- `fzn_catalog_sweep_capture` fills
 * them from a catalogue, which is `catalog/test/sweep_test.c`'s job. What
 * this file needs is a job in a particular position. */
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

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_sweep_view view;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_sweep_t job;

	/* NO PLAN IS NOT AN EMPTY PLAN. A consumer that has not captured has
	 * not asked; one that captured and got nothing has an answer. */
	CHECK(view.shown_state() == fzn_sweep_view::NOTHING,
	      "a fresh view is not in the nothing-captured state");
	{
		QString uncaptured = view.state_text();

		memset(&plan, 0, sizeof(plan));
		view.show_sweep(&plan, nullptr);
		CHECK(view.shown_state() == fzn_sweep_view::EMPTY,
		      "an empty plan was not shown as nothing to remove");
		CHECK(view.state_text() != uncaptured,
		      "a catalogue with nothing to remove reads exactly like one nobody "
		      "has asked about yet");
	}

	/* THE CASE THIS FILE EXISTS FOR. Zero planned, and the last-copy guard
	 * is why -- which must not read like an empty catalogue. */
	{
		QString empty_text = view.state_text();

		memset(&plan, 0, sizeof(plan));
		plan.last_copy = 3u;
		view.show_sweep(&plan, nullptr);

		CHECK(view.shown_state() == fzn_sweep_view::HELD_BACK,
		      "a sweep stopped by the last-copy guard was not distinguished from "
		      "a catalogue with nothing in it");
		CHECK(view.state_text() != empty_text,
		      "held-back and empty are shown in the same words, so a full disk "
		      "that cannot be reclaimed reads as a disk with nothing on it");
		CHECK(view.reasons_text().contains(QStringLiteral("last known copy")),
		      "the reason the sweep was held back is not on the screen");
	}

	/* EACH GUARD IS NAMED, because each calls for a different action:
	 * retention is this host's policy, shared and last_copy are guards, and
	 * absent is nothing to do. */
	{
		memset(&plan, 0, sizeof(plan));
		plan.retained = 1u;
		plan.shared = 2u;
		plan.last_copy = 3u;
		plan.absent = 4u;
		view.show_sweep(&plan, nullptr);

		CHECK(view.reasons_text().contains(QStringLiteral("1")) &&
		              view.reasons_text().contains(QStringLiteral("2")) &&
		              view.reasons_text().contains(QStringLiteral("3")) &&
		              view.reasons_text().contains(QStringLiteral("4")),
		      "the four reasons were summed rather than named");
		CHECK(view.reasons_text().contains(QStringLiteral("policy")),
		      "retention is not distinguished from a guard refusing");
	}

	/* TRUNCATION IS LOUD, AND SAID WHATEVER ELSE IS TRUE -- it means every
	 * other number on the screen is short. */
	{
		memset(&plan, 0, sizeof(plan));
		plan.planned = 4u;
		plan.truncated = 7u;
		view.show_sweep(&plan, nullptr);

		CHECK(view.truncated(), "a truncated plan did not report itself");
		CHECK(view.state_text().contains(QStringLiteral("short")),
		      "a plan that ran out of rows did not say the counts are short, so a "
		      "consumer would believe it had reclaimed what it had not");
	}

	/* READY, RUNNING, DONE. */
	memset(&plan, 0, sizeof(plan));
	plan.planned = 4u;

	view.show_sweep(&plan, nullptr);
	CHECK(view.shown_state() == fzn_sweep_view::READY,
	      "a captured plan with no job was not shown as ready");

	job_at(&job, 4u, 1u);
	view.show_sweep(&plan, &job);
	CHECK(view.shown_state() == fzn_sweep_view::RUNNING,
	      "a job part way through was not shown as running");
	CHECK(view.progress_text() == QStringLiteral("1 of 4"),
	      "the progress is not the library's answer");

	job_at(&job, 4u, 4u);
	view.show_sweep(&plan, &job);
	CHECK(view.shown_state() == fzn_sweep_view::DONE,
	      "a finished job was not shown as done");

	/* THE SECOND CASE. Drawing must not advance the cursor: `_advance` is
	 * called after bytes are gone, so a view that called it would record a
	 * removal that never happened. Render a part-done job repeatedly and
	 * require the cursor to be where it was. */
	{
		size_t before;
		size_t after;
		size_t total = 0;

		job_at(&job, 4u, 1u);
		CHECK(fzn_catalog_sweep_progress(&job, &before, &total) == FZN_CATALOG_OK,
		      "the fixture job has no progress to read");
		CHECK(before == 1u && total == 4u, "the fixture is not part way through");

		view.show_sweep(&plan, &job);
		view.show_sweep(&plan, &job);
		view.show_sweep(&plan, &job);

		CHECK(fzn_catalog_sweep_progress(&job, &after, &total) == FZN_CATALOG_OK,
		      "the job lost its progress");
		CHECK(after == before,
		      "drawing a sweep advanced its cursor, which records a removal that "
		      "never happened and loses the bytes from the record while they are "
		      "still on disk");
		CHECK(job.used == 4u && job.captured == 1,
		      "drawing a sweep changed the job");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("sweep_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
