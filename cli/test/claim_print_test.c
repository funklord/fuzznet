/* Tests for cli/claim_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is that the working answer must not read as a
 * fault. `claim.h` says FZN_CLAIM_ERR_HELD is "AN ANSWER RATHER THAN A FAULT
 * -- it is the expected result for every process but one", and a consumer
 * showing a person "could not start: error -2" has alarmed them about a host
 * that is fine. The cases below require that line to carry the word normal
 * and to carry no word of alarm.
 *
 * THE SECOND is that a backend that cannot answer and a caller that lost
 * track of itself are both negative integers to whoever reads a dialog, and
 * they want different people: an operator and a programmer.
 */

#include "../claim_print.h"

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
	fprintf(stderr, "  FAIL claim_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* A seam whose answers the case chooses, so every arm of the printer is
 * reachable from a real claim rather than from a hand-built struct. */
static int seam_take_result;
static int seam_held_out;
static int seam_release_result;

static int seam_take(void *ctx, int *held_out)
{
	(void)ctx;
	*held_out = seam_held_out;
	return seam_take_result;
}

static int seam_release(void *ctx)
{
	(void)ctx;
	return seam_release_result;
}

static const fzn_claim_ops_t OPS = { seam_take, seam_release, NULL };

static size_t line_of(const fzn_claim_t *c, fzn_claim_err_t err, char *out,
                      fzn_claim_line_t *said)
{
	size_t len = 99;

	*said = (fzn_claim_line_t)-1;
	CHECK(fzn_claim_print(c, err, out, FZN_CLAIM_PRINT_MAX, &len, said) == FZN_CLAIM_OK,
	      "rendering refused a claim it should have printed");
	return len;
}

int main(void)
{
	char line[FZN_CLAIM_PRINT_MAX];
	char elsewhere[FZN_CLAIM_PRINT_MAX];
	char backend[FZN_CLAIM_PRINT_MAX];
	char misuse[FZN_CLAIM_PRINT_MAX];
	fzn_claim_t c;
	fzn_claim_line_t said;
	fzn_claim_err_t err;
	size_t len = 0;

	/* ---- NOTHING TO REPORT ON. */
	len = line_of(NULL, FZN_CLAIM_ERR_HELD, line, &said);
	CHECK(said == FZN_CLAIM_LINE_NONE, "a null claim was given a verdict");
	CHECK(len > 0 && line[len] == '\0', "the line is not terminated at its length");
	CHECK(strstr(line, "cannot say") != NULL, "the line does not say it cannot say");

	/* ---- THIS PROCESS TAKES IT. */
	CHECK(fzn_claim_init(&c, &OPS) == FZN_CLAIM_OK, "init refused");
	seam_take_result = 1;
	seam_held_out = 1;
	err = fzn_claim_take(&c);
	CHECK(err == FZN_CLAIM_OK, "taking a free claim was refused");
	len = line_of(&c, err, line, &said);
	CHECK(said == FZN_CLAIM_LINE_OWNED, "the owner was not reported as the owner");
	CHECK(strstr(line, "PROBLEM") == NULL, "owning the claim was reported as a problem");

	/* ---- AND GIVES IT UP. An OK with the claim unheld is a release, and
	 * saying "another process owns it" there would be a sentence about a
	 * host nobody asked about. */
	seam_release_result = 1;
	err = fzn_claim_release(&c);
	CHECK(err == FZN_CLAIM_OK, "releasing a held claim was refused");
	len = line_of(&c, err, line, &said);
	CHECK(said == FZN_CLAIM_LINE_RELEASED,
	      "a release was reported as somebody else holding the claim");
	CHECK(strstr(line, "no longer owns") != NULL, "the line does not say it let go");

	/* ---- SOMEBODY ELSE HAS IT, which is the working case.
	 *
	 * THE SEAM'S CONVENTION IS "DID WE GET IT", and `held_out` only
	 * disambiguates a FAILURE: a zero return with held set is contention,
	 * a zero return with it clear is a backend that could not answer. The
	 * first draft of this fixture had that backwards and the module said
	 * so. */
	CHECK(fzn_claim_init(&c, &OPS) == FZN_CLAIM_OK, "re-init refused");
	seam_take_result = 0;
	seam_held_out = 1;
	err = fzn_claim_take(&c);
	CHECK(err == FZN_CLAIM_ERR_HELD, "a contended claim was not reported as held");
	len = line_of(&c, err, elsewhere, &said);
	CHECK(said == FZN_CLAIM_LINE_ELSEWHERE,
	      "another process holding the claim was not reported as such");
	CHECK(strstr(elsewhere, "normal") != NULL,
	      "the line does not say this is the normal arrangement, which is the whole "
	      "reason it is not an error");
	CHECK(strstr(elsewhere, "PROBLEM") == NULL,
	      "the expected result for every process but one was reported as a problem");

	/* ---- THE BACKEND CANNOT ANSWER, which needs an operator. */
	CHECK(fzn_claim_init(&c, &OPS) == FZN_CLAIM_OK, "re-init refused");
	seam_take_result = 0;
	seam_held_out = 0;
	err = fzn_claim_take(&c);
	CHECK(err == FZN_CLAIM_ERR_BACKEND, "a failing seam was not reported as backend");
	len = line_of(&c, err, backend, &said);
	CHECK(said == FZN_CLAIM_LINE_UNARBITRATED,
	      "a host that cannot arbitrate at all was not reported as such");
	CHECK(strstr(backend, "unusable rather than busy") != NULL,
	      "the line does not separate a host that cannot arbitrate from one that is "
	      "merely contended");

	/* ---- THE CALLER LOST TRACK, which needs a programmer. */
	len = line_of(&c, FZN_CLAIM_ERR_STATE, misuse, &said);
	CHECK(said == FZN_CLAIM_LINE_MISUSE, "a caller's own mistake was not reported");
	CHECK(strstr(misuse, "bug in it") != NULL,
	      "the line does not say whose fault it is, which is the difference between "
	      "sending an operator to the host and sending a programmer to the code");
	len = line_of(&c, FZN_CLAIM_ERR_MALFORMED, line, &said);
	CHECK(said == FZN_CLAIM_LINE_MISUSE,
	      "a null argument and a lost-track release were told apart on a surface a "
	      "person reads, where neither is actionable");

	/* ---- AND THE FOUR ARE FOUR SENTENCES. */
	CHECK(strcmp(elsewhere, backend) != 0 && strcmp(backend, misuse) != 0
	              && strcmp(elsewhere, misuse) != 0,
	      "two answers wanting different people produced the same sentence");

	/* ---- THE OPERANDS. */
	CHECK(fzn_claim_print(&c, FZN_CLAIM_OK, NULL, sizeof(line), &len, &said)
	              == FZN_CLAIM_ERR_MALFORMED, "printing accepted a null buffer");
	CHECK(fzn_claim_print(&c, FZN_CLAIM_OK, line, sizeof(line), NULL, &said)
	              == FZN_CLAIM_ERR_MALFORMED, "printing accepted a null length");
	CHECK(fzn_claim_print(&c, FZN_CLAIM_OK, line, sizeof(line), &len, NULL)
	              == FZN_CLAIM_ERR_MALFORMED,
	      "printing accepted a null state out-parameter, which is the required half");

	/* ---- A BUFFER TOO SMALL REPORTS WHAT IT NEEDED AND WRITES NOTHING. */
	said = FZN_CLAIM_LINE_OWNED;
	len = 0;
	CHECK(fzn_claim_print(&c, FZN_CLAIM_ERR_HELD, line, 4u, &len, &said)
	              == FZN_CLAIM_ERR_MALFORMED, "a four-byte buffer took a line");
	CHECK(len > 4u, "the refusal does not say how much room the line needed");
	CHECK(said == FZN_CLAIM_LINE_NONE,
	      "a refused render left a verdict behind, which a caller would read as one");

	printf("claim_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
