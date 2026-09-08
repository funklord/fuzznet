/* Tests for cli/trust_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is that an absent anchor is not an empty
 * fingerprint. A blank where one belongs reads as a fingerprint of something,
 * and somebody comparing would conclude the peer is wrong when the truth is
 * this host has no anchor at all.
 *
 * The second is that FZN_TRUST_SELF is not an absence. trust.h: a
 * self-anchored node "is a complete estate of one ... a working state rather
 * than a placeholder waiting to be filled", and an UNANCHORED node "adopts
 * the next root offered, so whoever reaches it first owns it". Reporting the
 * first as the second invites an operator to fix a correct state in a way
 * that opens the dangerous one.
 */

#include "../trust_print.h"

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
	fprintf(stderr, "  FAIL trust_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

int main(void)
{
	char line[FZN_TRUST_PRINT_MAX];
	char none_line[FZN_TRUST_PRINT_MAX];
	char print[FZN_TRUST_FINGERPRINT_LEN];
	fzn_trust_t trust;
	fzn_trust_line_t s;
	uint8_t root[FZN_PUBKEY_LEN];
	size_t len = 0;

	memset(root, 0xa5, sizeof(root));
	CHECK(fzn_trust_fingerprint(root, print, sizeof(print)) == FZN_TRUST_OK,
	      "the fixture could not spell a fingerprint");

	/* NO ANCHOR IS THE ZERO VALUE AND PRINTS NO FINGERPRINT. */
	s = FZN_TRUST_LINE_PINNED;
	CHECK(fzn_trust_print(NULL, line, sizeof(line), &len, &s) == FZN_TRUST_OK,
	      "a null anchor would not render");
	CHECK(s == FZN_TRUST_LINE_NONE, "a null anchor was not reported as none");
	CHECK(strstr(line, print) == NULL, "a host with no anchor printed a fingerprint");
	memcpy(none_line, line, sizeof(line));

	fzn_trust_init(&trust);
	CHECK(fzn_trust_print(&trust, line, sizeof(line), &len, &s) == FZN_TRUST_OK,
	      "an empty anchor would not render");
	CHECK(s == FZN_TRUST_LINE_NONE, "an initialised but unset anchor was not none");

	/* PINNED: configured out of band by somebody who checked. */
	fzn_trust_init(&trust);
	CHECK(fzn_trust_pin(&trust, root) == FZN_TRUST_OK, "pin refused");
	CHECK(fzn_trust_print(&trust, line, sizeof(line), &len, &s) == FZN_TRUST_OK,
	      "a pinned anchor would not render");
	CHECK(s == FZN_TRUST_LINE_PINNED, "a pinned anchor was not pinned");
	CHECK(strstr(line, print) != NULL, "a pinned anchor did not print its fingerprint");
	CHECK(strstr(line, "authenticated by nothing") == NULL,
	      "a pinned anchor was described as authenticated by nothing");

	/* ADOPTED: taken on first contact, and the line says what that means. */
	fzn_trust_init(&trust);
	CHECK(fzn_trust_adopt(&trust, root, 100u) == FZN_TRUST_OK, "adopt refused");
	CHECK(fzn_trust_print(&trust, line, sizeof(line), &len, &s) == FZN_TRUST_OK,
	      "an adopted anchor would not render");
	CHECK(s == FZN_TRUST_LINE_ADOPTED, "an adopted anchor was not adopted");
	CHECK(strstr(line, "authenticated by nothing") != NULL,
	      "an adopted anchor did not say what trust.h says it is, so a "
	      "fingerprint invites comparing it as though somebody had vouched");
	CHECK(strstr(line, "100") != NULL, "the adoption instant is not on the line");

	/* THE SECOND CASE. A self-anchored node is a working state, not an
	 * absence, and must not read like one. */
	fzn_trust_init(&trust);
	CHECK(fzn_trust_self(&trust, root) == FZN_TRUST_OK, "self refused");
	CHECK(fzn_trust_print(&trust, line, sizeof(line), &len, &s) == FZN_TRUST_OK,
	      "a self anchor would not render");
	CHECK(s == FZN_TRUST_LINE_SELF,
	      "a node anchored to its own key was reported as having no anchor, which "
	      "invites fixing a correct state -- and an unanchored node adopts "
	      "whoever reaches it first");
	CHECK(strcmp(line, none_line) != 0,
	      "a self-anchored node and one with no anchor print the same line");
	CHECK(strstr(line, print) != NULL, "a self anchor did not print its fingerprint");

	/* THE STATE IS REQUIRED, and a refusal leaves the conservative value. */
	CHECK(fzn_trust_print(&trust, line, sizeof(line), &len, NULL) ==
	              FZN_TRUST_ERR_MALFORMED,
	      "the state was optional after all");
	{
		char small[4];
		size_t needed = 0;

		memset(small, '@', sizeof(small));
		s = FZN_TRUST_LINE_PINNED;
		CHECK(fzn_trust_print(&trust, small, sizeof(small), &needed, &s) ==
		              FZN_TRUST_ERR_MALFORMED,
		      "a buffer too small was written anyway");
		CHECK(needed > sizeof(small), "the size needed was not reported");
		CHECK(small[0] == '@', "a refused render left bytes in the buffer");
		CHECK(s == FZN_TRUST_LINE_NONE, "a refused render left an anchored state");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("trust_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
