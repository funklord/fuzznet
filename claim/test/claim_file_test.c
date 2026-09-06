/* Tests for claim/claim_file.c: the property the whole of project.md sec 132
 * rests on.
 *
 * THE CASE THIS FILE EXISTS FOR is that the kernel releases the claim when
 * its holder DIES, so that taking it is safe enough to resume somebody
 * else's ratchet chains with. Every other arrangement considered -- a
 * heartbeat, a timeout, a lease -- can declare a live process dead, and two
 * processes on one ratchet chain is the failure a ratchet cannot survive. So
 * this is not a test that a lock works; it is the evidence for a design
 * decision, and it is written to fail loudly if the platform ever stops
 * providing it.
 *
 * HOW IT TERMINATES, because this file forks and kills. One child, no loop.
 * The child sets `alarm` before it waits, so it dies on its own if this
 * process vanishes and can never be orphaned; the parent kills it with
 * SIGKILL, which cannot be caught, so the `waitpid` that follows is bounded.
 * The scratch file is named for the process and removed by name -- a sweep
 * over a prefix would delete a concurrent run's, which on this machine is
 * somebody else's live state.
 */
#define _POSIX_C_SOURCE 200809L

#include "../claim_file.h"

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

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
	fprintf(stderr, "  FAIL claim_file_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)
#define REQUIRE(cond, ...)                                   \
	do {                                                 \
		int require_ok = (cond) ? 1 : 0;             \
		check_at(require_ok, __LINE__, __VA_ARGS__); \
		if (!require_ok)                             \
			return;                              \
	} while (0)

/* Named for the process so two runs cannot collide, and removed BY NAME. */
static char path[256];

static void test_open_take_release(void)
{
	fzn_claim_file_t cf;
	fzn_claim_ops_t ops;
	fzn_claim_t claim;

	REQUIRE(fzn_claim_file_open(&cf, path, &ops) == FZN_CLAIM_OK, "open refused");
	REQUIRE(fzn_claim_init(&claim, &ops) == FZN_CLAIM_OK, "init refused");
	CHECK(fzn_claim_take(&claim) == FZN_CLAIM_OK, "a free claim was not taken");
	CHECK(fzn_claim_held(&claim), "a taken claim does not say it is held");
	CHECK(fzn_claim_release(&claim) == FZN_CLAIM_OK, "release refused");
	CHECK(fzn_claim_file_close(&cf) == FZN_CLAIM_OK, "close refused");
	CHECK(fzn_claim_file_close(&cf) == FZN_CLAIM_OK, "close is not idempotent");
}

/* EVIDENCE FOR THE HEADER'S CLAIM that the lock belongs to the open file
 * description rather than to the process. If it were per process this would
 * succeed, and the fork hazard the header warns about would not exist -- so
 * this case is what makes that warning a measured fact rather than received
 * wisdom about flock. */
static void test_one_process_cannot_take_it_twice_through_two_descriptions(void)
{
	fzn_claim_file_t a, b;
	fzn_claim_ops_t ops_a, ops_b;
	fzn_claim_t claim_a, claim_b;

	REQUIRE(fzn_claim_file_open(&a, path, &ops_a) == FZN_CLAIM_OK, "first open refused");
	REQUIRE(fzn_claim_file_open(&b, path, &ops_b) == FZN_CLAIM_OK, "second open refused");
	REQUIRE(fzn_claim_init(&claim_a, &ops_a) == FZN_CLAIM_OK, "init a refused");
	REQUIRE(fzn_claim_init(&claim_b, &ops_b) == FZN_CLAIM_OK, "init b refused");

	CHECK(fzn_claim_take(&claim_a) == FZN_CLAIM_OK, "the first take failed");
	CHECK(fzn_claim_take(&claim_b) == FZN_CLAIM_ERR_HELD,
	      "a second description in one process took a claim already held");
	CHECK(!fzn_claim_held(&claim_b), "the refused claim says it is held");

	(void)fzn_claim_release(&claim_a);
	(void)fzn_claim_file_close(&a);
	(void)fzn_claim_file_close(&b);
}

/*
 * THE ONE THAT MATTERS. A child takes the claim and is killed with a signal
 * it cannot catch, so nothing in it runs on the way out -- no atexit, no
 * handler, no release. If the claim is still held afterwards the design in
 * sec 132 does not work on this platform, and a watchdog cannot rescue it.
 */
static void test_the_kernel_releases_a_dead_holders_claim(void)
{
	fzn_claim_file_t cf;
	fzn_claim_ops_t ops;
	fzn_claim_t claim;
	int ready[2];
	pid_t child;
	char token = 0;
	int status = 0;

	REQUIRE(pipe(ready) == 0, "the readiness pipe could not be made");

	child = fork();
	REQUIRE(child >= 0, "fork failed");

	if (child == 0) {
		fzn_claim_file_t child_cf;
		fzn_claim_ops_t child_ops;
		fzn_claim_t child_claim;
		char go = 1;

		(void)close(ready[0]);
		if (fzn_claim_file_open(&child_cf, path, &child_ops) != FZN_CLAIM_OK)
			_exit(2);
		if (fzn_claim_init(&child_claim, &child_ops) != FZN_CLAIM_OK)
			_exit(3);
		if (fzn_claim_take(&child_claim) != FZN_CLAIM_OK)
			_exit(4);
		if (write(ready[1], &go, 1) != 1)
			_exit(5);
		/* THE TERMINATION CONDITION. If this process is never killed --
		 * because the parent died first -- the alarm ends it, so it can
		 * never be orphaned holding a claim. */
		alarm(20);
		for (;;)
			pause();
	}

	(void)close(ready[1]);
	REQUIRE(read(ready[0], &token, 1) == 1, "the child never reported holding the claim");

	REQUIRE(fzn_claim_file_open(&cf, path, &ops) == FZN_CLAIM_OK, "parent open refused");
	REQUIRE(fzn_claim_init(&claim, &ops) == FZN_CLAIM_OK, "parent init refused");

	/* The control: while the holder lives, this must be refused. Without
	 * it a claim that was never taken would pass the test below. */
	CHECK(fzn_claim_take(&claim) == FZN_CLAIM_ERR_HELD,
	      "the claim was free while another process held it");

	CHECK(kill(child, SIGKILL) == 0, "the child could not be killed");
	CHECK(waitpid(child, &status, 0) == child, "the child was not reaped");
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
	      "the child did not die of the signal it was sent");

	CHECK(fzn_claim_take(&claim) == FZN_CLAIM_OK,
	      "the kernel did not release a dead holder's claim, so sec 132 does not hold here");
	CHECK(fzn_claim_held(&claim), "the claim was taken and does not say so");

	(void)fzn_claim_release(&claim);
	(void)fzn_claim_file_close(&cf);
	(void)close(ready[0]);
}

static void test_a_path_that_cannot_be_opened_is_a_backend_error(void)
{
	fzn_claim_file_t cf;
	fzn_claim_ops_t ops;

	CHECK(fzn_claim_file_open(&cf, "/nonexistent-directory-for-fuzznet/claim", &ops)
	              == FZN_CLAIM_ERR_BACKEND,
	      "an unopenable path was not a backend error");
	CHECK(fzn_claim_file_open(NULL, path, &ops) == FZN_CLAIM_ERR_MALFORMED,
	      "a null claim_file was accepted");
	CHECK(fzn_claim_file_open(&cf, NULL, &ops) == FZN_CLAIM_ERR_MALFORMED,
	      "a null path was accepted");
	CHECK(fzn_claim_file_open(&cf, path, NULL) == FZN_CLAIM_ERR_MALFORMED,
	      "a null ops was accepted");
	CHECK(fzn_claim_file_close(NULL) == FZN_CLAIM_ERR_MALFORMED,
	      "closing a null claim_file was accepted");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	snprintf(path, sizeof(path), "fzn-claim-test-%ld", (long)getpid());

	test_open_take_release();
	test_one_process_cannot_take_it_twice_through_two_descriptions();
	test_the_kernel_releases_a_dead_holders_claim();
	test_a_path_that_cannot_be_opened_is_a_backend_error();
	test_the_suite_can_tell_pass_from_fail();

	/* Removed by name, and the status is read: a cleanup nobody checks is
	 * how a directory fills while a suite reports success. */
	if (unlink(path) != 0)
		check_at(0, __LINE__, "the scratch file %s could not be removed", path);

	printf("claim_file_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
