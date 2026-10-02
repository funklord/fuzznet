/* capture_run_test -- running a tool and capturing it, against /bin/sh.
 * sec 441.
 *
 * EVERY TOOL STARTED HERE RUNS UNDER A DEADLINE of at most two seconds, so
 * this test cannot outlive itself by much, and the one case whose tool would
 * run for thirty seconds asserts afterwards that its child is gone -- read
 * from /proc, since `kill(pid, 0)` answers yes for a zombie. */

#define _POSIX_C_SOURCE 200809L

#include "../capture_run.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL capture_run_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

static size_t out_lines, err_lines;
static char first_out[256], first_err[256];

static void collect(void *ctx, const fzn_capture_entry_t *e)
{
	(void)ctx;
	if (e->stream == FZN_CAPTURE_STDOUT) {
		if (!out_lines)
			snprintf(first_out, sizeof(first_out), "%s", e->text);
		out_lines++;
	} else {
		if (!err_lines)
			snprintf(first_err, sizeof(first_err), "%s", e->text);
		err_lines++;
	}
}

static fzn_capture_t cap;
static fzn_capture_end_t end;
static int code;
static uint64_t elapsed;

static fzn_capture_err_t run_sh(const char *script, uint64_t deadline_ms)
{
	const char *argv[] = { "/bin/sh", "-c", script, NULL };

	out_lines = err_lines = 0;
	first_out[0] = first_err[0] = '\0';
	(void)fzn_capture_init(&cap, collect, NULL, fzn_capture_rule_default(), 0);
	return fzn_capture_run(&cap, argv, deadline_ms, &end, &code, &elapsed);
}

/* Whether `pid` is a live process: present in /proc with a command line,
 * which a zombie does not have. Waited for up to a second, since init reaps
 * an orphan in its own time. */
static int alive(long pid)
{
	char path[64];
	int tries;

	snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
	for (tries = 0; tries < 100; tries++) {
		FILE *f = fopen(path, "rb");
		int c = f ? fgetc(f) : EOF;
		struct timespec ten_ms = { 0, 10000000L };

		if (f)
			(void)fclose(f);
		if (c == EOF)
			return 0;
		(void)nanosleep(&ten_ms, NULL);
	}
	return 1;
}

int main(void)
{
	CHECK(run_sh("echo out; echo err >&2; exit 3", 2000u) == FZN_CAPTURE_OK
	              && end == FZN_CAPTURE_EXITED && code == 3,
	      "a tool's exit status is reported");
	CHECK(out_lines == 1u && err_lines == 1u && !strcmp(first_out, "out")
	              && !strcmp(first_err, "err"),
	      "and what it printed on each stream is captured on that stream");

	{
		const char *argv[] = { "fzn-capture-no-such-tool", NULL };

		(void)fzn_capture_init(&cap, collect, NULL, fzn_capture_rule_default(), 0);
		CHECK(fzn_capture_run(&cap, argv, 2000u, &end, &code, &elapsed) == FZN_CAPTURE_OK
		              && end == FZN_CAPTURE_NOT_RUN && code == ENOENT,
		      "a tool that is not there is NOT_RUN with exec's errno, not exit 127");
	}

	CHECK(run_sh("read x; echo \"got:$x:$?\"", 2000u) == FZN_CAPTURE_OK
	              && end == FZN_CAPTURE_EXITED && !strcmp(first_out, "got::1"),
	      "stdin is /dev/null, so a tool that reads gets end of file at once");

	CHECK(run_sh("kill -9 $$", 2000u) == FZN_CAPTURE_OK && end == FZN_CAPTURE_SIGNALLED
	              && code == SIGKILL,
	      "a tool killed by a signal says which");

	CHECK(run_sh("i=0; while [ $i -lt 3000 ]; do echo o$i; echo e$i >&2; i=$((i+1)); done",
	             2000u)
	                      == FZN_CAPTURE_OK
	              && end == FZN_CAPTURE_EXITED && code == 0 && out_lines == 3000u
	              && err_lines == 3000u,
	      "both streams past a pipe's buffer are read whole, without a deadlock");

	{
		long grandchild;

		CHECK(run_sh("sleep 30 & echo $!; wait", 300u) == FZN_CAPTURE_OK
		              && end == FZN_CAPTURE_TIMED_OUT && elapsed < 2000u,
		      "a tool past its deadline is stopped there");
		grandchild = strtol(first_out, NULL, 10);
		CHECK(grandchild > 0 && !alive(grandchild),
		      "and what it started went with it: the whole group is killed");
	}

	CHECK(run_sh("exec >&- 2>&-; sleep 30", 300u) == FZN_CAPTURE_OK
	              && end == FZN_CAPTURE_TIMED_OUT && elapsed < 2000u,
	      "a tool that closed its streams and kept running is stopped at the deadline");

	CHECK(fzn_capture_run(NULL, NULL, 0u, &end, &code, &elapsed) == FZN_CAPTURE_ERR_MALFORMED,
	      "a null is malformed");

	if (failures) {
		fprintf(stderr, "capture_run_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("capture_run_test: all %d checks passed\n", checks);
	return 0;
}
