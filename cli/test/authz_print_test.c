/* Tests for cli/authz_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is that an unspelled policy and one written
 * to refuse everything both DENY. `chain/authz.h` calls `spelled` "the field
 * the whole design rests on" because it is what tells them apart, and only
 * one of them is a configuration fault somebody has to find. On a host
 * refusing requests that is the entire question.
 *
 * The second is that guarded and unguarded are different words, for the
 * reason fzn_authz_verdict_t keeps GRANTED_BY_CHAIN and GRANTED_UNGUARDED
 * apart: a policy that has drifted open is a thing somebody has to be able to
 * find.
 *
 * The central case does not assert which origins reach which policy. It
 * builds every combination of origin bits and requires the LINE and
 * `fzn_authz_origin_permitted` to agree about all of them -- a relationship
 * rather than a table, which survives the rule changing.
 */

#include "../authz_print.h"

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
	fprintf(stderr, "  FAIL authz_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static const fzn_origin_t ORIGINS[] = { FZN_ORIGIN_SAME_USER, FZN_ORIGIN_LOCAL,
                                        FZN_ORIGIN_REMOTE };
static const char *const LABELS[] = { "same user", "local", "remote" };

int main(void)
{
	char line[FZN_AUTHZ_PRINT_MAX];
	char unspelled_line[FZN_AUTHZ_PRINT_MAX];
	fzn_authz_policy_t policy;
	fzn_authz_line_t s;
	fzn_cap_id_t cap;
	size_t len = 0;
	unsigned bits;
	size_t i;

	memset(&cap, 0xc0, sizeof(cap));

	/* UNSPELLED IS THE ZERO VALUE, so a caller that ignores the state is
	 * told nobody configured this rather than that it is deliberately
	 * closed. */
	s = FZN_AUTHZ_LINE_GUARDED;
	CHECK(fzn_authz_print(NULL, line, sizeof(line), &len, &s) == FZN_CHAIN_OK,
	      "a null policy would not render");
	CHECK(s == FZN_AUTHZ_LINE_UNSPELLED, "a null policy was not reported unspelled");
	memcpy(unspelled_line, line, sizeof(line));

	/* AND A ZEROED POLICY IS THE SAME THING -- what a consumer that forgot
	 * to spell one actually holds. */
	memset(&policy, 0, sizeof(policy));
	CHECK(fzn_authz_print(&policy, line, sizeof(line), &len, &s) == FZN_CHAIN_OK,
	      "a zeroed policy would not render");
	CHECK(s == FZN_AUTHZ_LINE_UNSPELLED, "a zeroed policy was not unspelled");

	/* THE CASE THIS FILE EXISTS FOR. A policy somebody wrote to refuse
	 * everything denies exactly as an unspelled one does, and must not
	 * read the same. */
	{
		fzn_authz_policy_t closed = fzn_authz_requires(&cap, 0);

		CHECK(fzn_authz_print(&closed, line, sizeof(line), &len, &s) ==
		              FZN_CHAIN_OK,
		      "a closed policy would not render");
		CHECK(s == FZN_AUTHZ_LINE_GUARDED,
		      "a policy written to refuse everything was reported unspelled");
		CHECK(strcmp(line, unspelled_line) != 0,
		      "a policy nobody wrote and one written to refuse everything print "
		      "the same line, so a configuration fault cannot be found");
		CHECK(strstr(line, "nothing") != NULL,
		      "a policy reaching no origin did not say so");
	}

	/* GUARDED AND UNGUARDED ARE DIFFERENT WORDS. */
	{
		fzn_authz_policy_t open_p = fzn_authz_unguarded(FZN_ORIGIN_ANY);
		char open_line[FZN_AUTHZ_PRINT_MAX];

		CHECK(fzn_authz_print(&open_p, line, sizeof(line), &len, &s) ==
		              FZN_CHAIN_OK,
		      "an unguarded policy would not render");
		CHECK(s == FZN_AUTHZ_LINE_UNGUARDED, "an unguarded policy was not unguarded");
		CHECK(strstr(line, "UNGUARDED") != NULL,
		      "a policy that has drifted open does not say so, so nobody can find "
		      "it");
		memcpy(open_line, line, sizeof(line));

		policy = fzn_authz_requires(&cap, FZN_ORIGIN_ANY);
		CHECK(fzn_authz_print(&policy, line, sizeof(line), &len, &s) ==
		              FZN_CHAIN_OK,
		      "a guarded policy would not render");
		CHECK(s == FZN_AUTHZ_LINE_GUARDED, "a guarded policy was not guarded");
		CHECK(strcmp(line, open_line) != 0,
		      "guarded and unguarded print the same line, so a policy that has "
		      "drifted open reads as one that never needed a capability");
	}

	/* THE CENTRAL CASE. Every combination of the three origin bits, both
	 * guarded and unguarded, and the LINE must agree with the library for
	 * each. */
	{
		int agreed = 1;
		int reached = 0;

		for (bits = 0; bits < 8u; bits++) {
			unsigned mask = 0;
			int guarded;

			for (i = 0; i < 3u; i++)
				if (bits & (1u << i))
					mask |= FZN_ORIGIN_BIT(ORIGINS[i]);

			for (guarded = 0; guarded < 2; guarded++) {
				policy = guarded ? fzn_authz_requires(&cap, mask)
				                 : fzn_authz_unguarded(mask);

				if (fzn_authz_print(&policy, line, sizeof(line), &len, &s) !=
				    FZN_CHAIN_OK) {
					agreed = 0;
					continue;
				}

				for (i = 0; i < 3u; i++) {
					int said_line = strstr(line, LABELS[i]) != NULL;
					int said_lib = fzn_authz_origin_permitted(
					        policy, ORIGINS[i]);

					if (said_line != !!said_lib)
						agreed = 0;
					if (said_lib)
						reached = 1;
				}
			}
		}

		CHECK(agreed,
		      "the line and fzn_authz_origin_permitted disagree about an origin, "
		      "so the printer is a second implementation of the rule that gates "
		      "requests");
		CHECK(reached,
		      "no origin reached any policy, so the agreement above is vacuous");
	}

	/* THE STATE IS REQUIRED, and a refusal leaves the conservative value. */
	CHECK(fzn_authz_print(&policy, line, sizeof(line), &len, NULL) ==
	              FZN_CHAIN_ERR_MALFORMED,
	      "the state was optional after all");
	{
		char small[4];
		size_t needed = 0;

		memset(small, '@', sizeof(small));
		s = FZN_AUTHZ_LINE_GUARDED;
		CHECK(fzn_authz_print(&policy, small, sizeof(small), &needed, &s) ==
		              FZN_CHAIN_ERR_MALFORMED,
		      "a buffer too small was written anyway");
		CHECK(needed > sizeof(small), "the size needed was not reported");
		CHECK(small[0] == '@', "a refused render left bytes in the buffer");
		CHECK(s == FZN_AUTHZ_LINE_UNSPELLED,
		      "a refused render left a state claiming a policy was written");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	/*
	 * THE ANSWER MUST SURVIVE AN 80-COLUMN TERMINAL. sec 207.
	 *
	 * A capability and an anchor both spell to 64 hex characters, and a
	 * terminal clips a line from the RIGHT -- so a line that puts the
	 * identifier before the verdict loses the verdict and keeps the bytes
	 * nobody compares by eye. Measured before the fix: `reachable from` began at column 93.
	 * The bound is 72 rather than 80 to leave room for whatever prefixes
	 * this in a log.
	 */
	{
		const char *at;

		memset(&cap, 0xa5, sizeof(cap));
		policy = fzn_authz_requires(&cap, FZN_ORIGIN_ANY);
		CHECK(fzn_authz_print(&policy, line, sizeof(line), &len, &s) ==
		              FZN_CHAIN_OK,
		      "a guarded policy would not render");
		at = strstr(line, "reachable from");
		CHECK(at != NULL, "the reachability is not on the line at all");
		CHECK(at != NULL && (size_t)(at - line) < 72u,
		      "the reachability begins past column 72, so an 80-column terminal "
		      "shows the capability and not who may use it");
	}

	printf("authz_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
