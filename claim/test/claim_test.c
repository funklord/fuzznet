/* Tests for claim/claim.c: the state machine over a backend, without one.
 *
 * THE CASE THIS FILE EXISTS FOR is that `fzn_claim_held` must be right, in
 * both directions and after every path. project.md sec 132 predicts the bug
 * it prevents: a shared submit path that opens a socket to the owner blocks
 * on itself when the caller IS the owner, and the only thing standing
 * between that and a wedged process is this question being answered
 * correctly. So the assertions here are about what `held` says after each
 * transition, including the ones that fail.
 *
 * The backend is a stub whose answers are set per case, which is the point:
 * the real one cannot be made to fail on demand, and a state machine that is
 * only ever driven by a working backend has never been asked what it does
 * with a broken one.
 */

#include "../claim.h"

#include <stdarg.h>
#include <stdio.h>

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
	fprintf(stderr, "  FAIL claim_test.c:%d: ", line);
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

struct stub {
	int take_result;
	int take_held;
	int release_result;
	int takes;
	int releases;
};

static int stub_take(void *ctx, int *held_out)
{
	struct stub *s = (struct stub *)ctx;

	s->takes++;
	if (held_out)
		*held_out = s->take_held;
	return s->take_result;
}

static int stub_release(void *ctx)
{
	struct stub *s = (struct stub *)ctx;

	s->releases++;
	return s->release_result;
}

static void stub_init(struct stub *s, fzn_claim_ops_t *ops)
{
	s->take_result = 1;
	s->take_held = 0;
	s->release_result = 1;
	s->takes = 0;
	s->releases = 0;
	ops->take = stub_take;
	ops->release = stub_release;
	ops->ctx = s;
}

static void test_a_fresh_claim_is_not_held(void)
{
	fzn_claim_t claim;
	fzn_claim_ops_t ops;
	struct stub s;

	stub_init(&s, &ops);
	REQUIRE(fzn_claim_init(&claim, &ops) == FZN_CLAIM_OK, "init refused");
	CHECK(!fzn_claim_held(&claim), "a claim was held before it was taken");
	CHECK(s.takes == 0, "init took the claim, which is not its job");
}

static void test_taking_and_releasing_move_held(void)
{
	fzn_claim_t claim;
	fzn_claim_ops_t ops;
	struct stub s;

	stub_init(&s, &ops);
	REQUIRE(fzn_claim_init(&claim, &ops) == FZN_CLAIM_OK, "init refused");
	CHECK(fzn_claim_take(&claim) == FZN_CLAIM_OK, "a free claim was not taken");
	CHECK(fzn_claim_held(&claim), "a taken claim does not say it is held");
	CHECK(fzn_claim_release(&claim) == FZN_CLAIM_OK, "a held claim was not released");
	CHECK(!fzn_claim_held(&claim), "a released claim still says it is held");
	CHECK(s.takes == 1 && s.releases == 1, "the backend was not called once each");
}

/* Contention is the normal outcome for every process but one. */
static void test_held_by_another_is_not_a_backend_failure(void)
{
	fzn_claim_t claim;
	fzn_claim_ops_t ops;
	struct stub s;

	stub_init(&s, &ops);
	s.take_result = 0;
	s.take_held = 1;
	REQUIRE(fzn_claim_init(&claim, &ops) == FZN_CLAIM_OK, "init refused");
	CHECK(fzn_claim_take(&claim) == FZN_CLAIM_ERR_HELD,
	      "contention was not reported as contention");
	CHECK(!fzn_claim_held(&claim), "a refused take left the claim held");
}

/* A store that cannot arbitrate at all must not look like a busy one. */
static void test_a_broken_backend_is_not_contention(void)
{
	fzn_claim_t claim;
	fzn_claim_ops_t ops;
	struct stub s;

	stub_init(&s, &ops);
	s.take_result = 0;
	s.take_held = 0;
	REQUIRE(fzn_claim_init(&claim, &ops) == FZN_CLAIM_OK, "init refused");
	CHECK(fzn_claim_take(&claim) == FZN_CLAIM_ERR_BACKEND,
	      "a backend failure was reported as contention");
	CHECK(!fzn_claim_held(&claim), "a failed take left the claim held");
}

/* Both mean the caller has lost track of which process it is. */
static void test_losing_track_is_reported(void)
{
	fzn_claim_t claim;
	fzn_claim_ops_t ops;
	struct stub s;

	stub_init(&s, &ops);
	REQUIRE(fzn_claim_init(&claim, &ops) == FZN_CLAIM_OK, "init refused");
	CHECK(fzn_claim_release(&claim) == FZN_CLAIM_ERR_STATE,
	      "releasing an unheld claim was accepted");
	REQUIRE(fzn_claim_take(&claim) == FZN_CLAIM_OK, "take refused");
	CHECK(fzn_claim_take(&claim) == FZN_CLAIM_ERR_STATE,
	      "taking a held claim was accepted");
	CHECK(s.takes == 1, "a second take reached the backend");
	CHECK(fzn_claim_held(&claim), "a refused second take cleared held");
}

/* Of the two wrong answers after a failed release, refusing to act is the
 * one that cannot desynchronise a ratchet. */
static void test_a_failed_release_still_gives_up_ownership(void)
{
	fzn_claim_t claim;
	fzn_claim_ops_t ops;
	struct stub s;

	stub_init(&s, &ops);
	s.release_result = 0;
	REQUIRE(fzn_claim_init(&claim, &ops) == FZN_CLAIM_OK, "init refused");
	REQUIRE(fzn_claim_take(&claim) == FZN_CLAIM_OK, "take refused");
	CHECK(fzn_claim_release(&claim) == FZN_CLAIM_ERR_BACKEND,
	      "a failing release reported success");
	CHECK(!fzn_claim_held(&claim),
	      "a failed release left this process believing it still owns the state");
}

static void test_the_caller_bugs_are_refused(void)
{
	fzn_claim_t claim;
	fzn_claim_ops_t ops;
	struct stub s;

	stub_init(&s, &ops);
	CHECK(fzn_claim_init(NULL, &ops) == FZN_CLAIM_ERR_MALFORMED, "null claim accepted");
	CHECK(fzn_claim_init(&claim, NULL) == FZN_CLAIM_ERR_MALFORMED, "null ops accepted");
	ops.take = NULL;
	CHECK(fzn_claim_init(&claim, &ops) == FZN_CLAIM_ERR_MALFORMED, "ops with no take accepted");
	stub_init(&s, &ops);
	ops.release = NULL;
	CHECK(fzn_claim_init(&claim, &ops) == FZN_CLAIM_ERR_MALFORMED,
	      "ops with no release accepted");
	CHECK(fzn_claim_take(NULL) == FZN_CLAIM_ERR_MALFORMED, "take of a null claim accepted");
	CHECK(fzn_claim_release(NULL) == FZN_CLAIM_ERR_MALFORMED,
	      "release of a null claim accepted");
}

/* A process that does not know whether it is the owner is not the owner. */
static void test_held_is_total(void)
{
	fzn_claim_t claim;

	claim.ops = NULL;
	claim.held = 1;
	CHECK(!fzn_claim_held(NULL), "a null claim reported itself held");
	CHECK(!fzn_claim_held(&claim), "an uninitialised claim reported itself held");
}

static void test_the_errors_render(void)
{
	CHECK(fzn_claim_err_str(FZN_CLAIM_OK)[0] != '\0', "OK renders empty");
	CHECK(fzn_claim_err_str(FZN_CLAIM_ERR_MALFORMED)[0] != '\0', "MALFORMED renders empty");
	CHECK(fzn_claim_err_str(FZN_CLAIM_ERR_HELD)[0] != '\0', "HELD renders empty");
	CHECK(fzn_claim_err_str(FZN_CLAIM_ERR_BACKEND)[0] != '\0', "BACKEND renders empty");
	CHECK(fzn_claim_err_str(FZN_CLAIM_ERR_STATE)[0] != '\0', "STATE renders empty");
	CHECK(fzn_claim_err_str((fzn_claim_err_t)-99)[0] != '\0', "an unknown error renders empty");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

#ifdef FZN_FLOG_ON
#include "flog.h"

#include <string.h>

/* Borrowed strings, so anything kept is copied. */
static struct {
	int calls;
	flog_msg_type_t type;
	char subsystem[64];
	char text[512];
} claim_log_seen;

static int claim_log_capture(flog_t *p, const flog_msg_t *m)
{
	(void)p;
	claim_log_seen.calls++;
	claim_log_seen.type = m->type;
	claim_log_seen.subsystem[0] = '\0';
	claim_log_seen.text[0] = '\0';
	if (m->subsystem)
		snprintf(claim_log_seen.subsystem, sizeof(claim_log_seen.subsystem), "%s",
		         m->subsystem);
	if (m->text)
		snprintf(claim_log_seen.text, sizeof(claim_log_seen.text), "%s", m->text);
	return 0;
}

/*
 * A RELEASE THE BACKEND REFUSED, WITH `held` ALREADY CLEARED. sec 216.
 *
 * This object now believes the claim is gone and the world may disagree.
 * Nothing later in this process retries it, and FZN_CLAIM_ERR_BACKEND reaches
 * a caller unwinding a failure path that is unlikely to look -- which is
 * exactly the shape a log exists for.
 */
static void test_the_claim_says_a_release_was_refused(void)
{
	struct stub s;
	fzn_claim_ops_t ops;
	fzn_claim_t c;
	flog_t log;

	init_flog_t(&log);
	log.name = NULL;
	log.accepted_msg_type = FLOG_ACCEPT_ALL;
	log.output_func = claim_log_capture;

	stub_init(&s, &ops);

	/* QUIET UNTIL ASKED: planted before the init that clears it. */
	CHECK(fzn_claim_init(&c, &ops) == FZN_CLAIM_OK, "init refused");
	fzn_claim_set_log(&c, &log);
	CHECK(fzn_claim_init(&c, &ops) == FZN_CLAIM_OK, "re-init refused");
	memset(&claim_log_seen, 0, sizeof(claim_log_seen));
	CHECK(fzn_claim_take(&c) == FZN_CLAIM_OK, "take refused");
	CHECK(fzn_claim_release(&c) == FZN_CLAIM_OK, "release refused");
	CHECK(claim_log_seen.calls == 0, "a claim nobody gave a log to emitted anyway");

	fzn_claim_set_log(&c, &log);
	CHECK(fzn_claim_take(&c) == FZN_CLAIM_OK, "take refused");
	s.release_result = 0;
	memset(&claim_log_seen, 0, sizeof(claim_log_seen));
	CHECK(fzn_claim_release(&c) == FZN_CLAIM_ERR_BACKEND, "a refused release passed");
	CHECK(claim_log_seen.calls == 1, "a refused release said nothing");
	CHECK(claim_log_seen.type == FLOG_ERR, "a claim possibly still held was not an error");
	CHECK(strcmp(claim_log_seen.subsystem, "claim/hold") == 0,
	      "the event did not name its subsystem");
	CHECK(strstr(claim_log_seen.text, "still be held") != NULL,
	      "the line reports a refused call and not that the claim may still be held "
	      "elsewhere, which is the part nothing else will notice");
}
#endif

int main(void)
{
	test_a_fresh_claim_is_not_held();
	test_taking_and_releasing_move_held();
	test_held_by_another_is_not_a_backend_failure();
	test_a_broken_backend_is_not_contention();
	test_losing_track_is_reported();
	test_a_failed_release_still_gives_up_ownership();
	test_the_caller_bugs_are_refused();
	test_held_is_total();
	test_the_errors_render();
	test_the_suite_can_tell_pass_from_fail();

#ifdef FZN_FLOG_ON
	test_the_claim_says_a_release_was_refused();
#endif

	printf("claim_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
