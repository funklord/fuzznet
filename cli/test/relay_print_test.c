/* Tests for cli/relay_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is the one `wire/relay.h` argues at length:
 * EXHAUSTED is every frame's ordinary end and says nothing about this host,
 * REFUSED is this host declining a subsystem it could have carried, and
 * "collapsing them would make a misconfigured policy indistinguishable from
 * normal traffic reaching the end of its budget". They reach a consumer as
 * two negative integers.
 *
 * THE SECOND is that a refusal has a row somebody wrote, or does not. An
 * operator looking for the line to edit needs to know which, and the ceiling
 * being zero in a table is a different fix from there being no table entry at
 * all.
 */

#include "../relay_print.h"

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
	fprintf(stderr, "  FAIL relay_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static size_t line_of(const fzn_relay_policy_t *p, size_t n, uint16_t service,
                      fzn_relay_err_t err, uint8_t budget, char *out, fzn_relay_line_t *said)
{
	size_t len = 99;

	*said = (fzn_relay_line_t)-1;
	CHECK(fzn_relay_print(p, n, service, err, budget, out, FZN_RELAY_PRINT_MAX, &len, said)
	              == FZN_RELAY_OK,
	      "rendering refused a decision it should have printed");
	return len;
}

int main(void)
{
	char line[FZN_RELAY_PRINT_MAX];
	char ended[FZN_RELAY_PRINT_MAX];
	char refused[FZN_RELAY_PRINT_MAX];
	char no_row[FZN_RELAY_PRINT_MAX];
	fzn_relay_line_t said;
	size_t len = 0;

	/* A host that carries subsystem 7 and refuses 9 by writing it down. */
	static const fzn_relay_policy_t POLICY[2] = { { 7u, 4u }, { 9u, 0u } };

	/* ---- CARRIED. */
	len = line_of(POLICY, 2u, 7u, FZN_RELAY_OK, 3u, line, &said);
	CHECK(said == FZN_RELAY_LINE_CARRIED, "a carried frame was not reported as one");
	CHECK(strstr(line, "subsystem 7") != NULL, "the line does not name the subsystem");
	CHECK(strstr(line, "3 hops") != NULL, "the line does not say what budget survived");
	CHECK(strstr(line, "REFUSING") == NULL, "a carried frame was reported as refused");

	/* ---- THE FRAME'S ORDINARY END. */
	len = line_of(POLICY, 2u, 7u, FZN_RELAY_ERR_EXHAUSTED, 0u, ended, &said);
	CHECK(said == FZN_RELAY_LINE_ENDED, "a spent budget was not reported as an ending");
	CHECK(strstr(ended, "says nothing about this host") != NULL,
	      "the line does not say the ordinary end is not about this host, which is "
	      "the whole reason it is kept apart from a refusal");
	CHECK(strstr(ended, "REFUSING") == NULL, "a frame ending was reported as a refusal");

	/* ---- AND THE ONE SOMEBODY CHOSE. Same stop, different fact. */
	len = line_of(POLICY, 2u, 9u, FZN_RELAY_ERR_REFUSED, 0u, refused, &said);
	CHECK(said == FZN_RELAY_LINE_REFUSED, "a policy refusal was not reported as one");
	CHECK(strstr(refused, "own policy") != NULL,
	      "the line does not say this host chose it");
	CHECK(strstr(refused, "could have been carried") != NULL,
	      "the line does not say the frame had budget left, which is what separates "
	      "a decision from an ending");
	CHECK(strstr(refused, "ceiling for it is zero") != NULL,
	      "the line does not point at the row an operator would change");
	CHECK(strcmp(ended, refused) != 0,
	      "a frame reaching its ordinary end and a host refusing one produced the "
	      "same sentence, which relay.h says makes a misconfigured policy "
	      "indistinguishable from normal traffic");

	/* ---- A SUBSYSTEM WITH NO ROW AT ALL takes the fallback, and the line
	 * must say so: there is no row to edit. */
	len = line_of(POLICY, 2u, 11u, FZN_RELAY_ERR_REFUSED, 0u, no_row, &said);
	CHECK(said == FZN_RELAY_LINE_REFUSED, "a fallback refusal was not reported");
	CHECK(strstr(no_row, "no row of its own") != NULL,
	      "the line sends an operator looking for a policy row that does not exist");
	CHECK(strcmp(no_row, refused) != 0,
	      "a written-down zero and an absent row produced the same sentence, and "
	      "they are different edits");

	/* ---- NOT A FRAME THIS HOST READS. */
	len = line_of(POLICY, 2u, 7u, FZN_RELAY_ERR_SHAPE, 0u, line, &said);
	CHECK(said == FZN_RELAY_LINE_FOREIGN, "a bad shape was not reported as foreign");
	CHECK(strstr(line, "rather than a decision") != NULL,
	      "the line lets a version difference read as a policy choice");

	/* ---- AND THE CALLER'S OWN BUG. */
	len = line_of(POLICY, 2u, 7u, FZN_RELAY_ERR_MALFORMED, 0u, line, &said);
	CHECK(said == FZN_RELAY_LINE_LOCAL, "a caller's bug was not reported as one");
	CHECK(strstr(line, "bug in it") != NULL, "the line does not say whose fault it is");

	/* ---- NO POLICY TABLE AT ALL still names the subsystem, because that
	 * is what a reader has to go on. */
	len = line_of(NULL, 0u, 9u, FZN_RELAY_ERR_REFUSED, 0u, line, &said);
	CHECK(said == FZN_RELAY_LINE_REFUSED, "a refusal without a table was not reported");
	CHECK(strstr(line, "subsystem 9") != NULL,
	      "the line does not name the subsystem, so a reader with no table has "
	      "nothing at all to go on");

	/* ---- THE OPERANDS. */
	CHECK(fzn_relay_print(POLICY, 2u, 7u, FZN_RELAY_OK, 1u, NULL, sizeof(line), &len,
	                      &said) == FZN_RELAY_ERR_MALFORMED,
	      "printing accepted a null buffer");
	CHECK(fzn_relay_print(POLICY, 2u, 7u, FZN_RELAY_OK, 1u, line, sizeof(line), NULL,
	                      &said) == FZN_RELAY_ERR_MALFORMED,
	      "printing accepted a null length");
	CHECK(fzn_relay_print(POLICY, 2u, 7u, FZN_RELAY_OK, 1u, line, sizeof(line), &len,
	                      NULL) == FZN_RELAY_ERR_MALFORMED,
	      "printing accepted a null state out-parameter, which is the required half");

	/* ---- A BUFFER TOO SMALL REPORTS WHAT IT NEEDED AND WRITES NOTHING. */
	said = FZN_RELAY_LINE_CARRIED;
	len = 0;
	CHECK(fzn_relay_print(POLICY, 2u, 9u, FZN_RELAY_ERR_REFUSED, 0u, line, 4u, &len, &said)
	              == FZN_RELAY_ERR_MALFORMED, "a four-byte buffer took a line");
	CHECK(len > 4u, "the refusal does not say how much room the line needed");
	CHECK(said == FZN_RELAY_LINE_NONE,
	      "a refused render left a verdict behind, which a caller would read as one");

	printf("relay_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
