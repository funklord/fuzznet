/* Tests for cli/manifest_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is a host that is missing more than it can
 * count. `chain/manifest.h` calls a dropped pair the one refusal in the
 * library that fails OPEN -- it "makes it report a SMALLER deficit than it
 * has, which is to say it looks MORE complete than it is" -- and until this
 * line existed nothing said so anywhere a person looks.
 *
 * THE SECOND IS AN AMBIGUITY THE LIBRARY COULD NOT RESOLVE. `pending` answers
 * 0 for an issuer that is not followed and `overflowed` answers 1 for the same
 * case, so the pair (0, 1) meant either "nothing is tracked from that key" or
 * "the count is a floor and what was recorded has since been satisfied". The
 * case below constructs both and requires the lines to differ, which is what
 * `fzn_manifest_follows` was added for.
 */

#include "../manifest_print.h"

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
	fprintf(stderr, "  FAIL manifest_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_manifest_issuer_t ISSUERS[2];
static fzn_manifest_deficit_t DEFICIT[4];

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	memset(out, (int)seed, FZN_PUBKEY_LEN);
}

/*
 * A state a consumer could hold, built directly rather than admitted.
 *
 * The same technique `cli/test/revocation_print_test.c` uses and for its
 * reason: what this file tests is the RENDERING of a state, and driving the
 * whole admit path to reach one is `chain/test/manifest_test.c`'s job. Every
 * arrangement below is reachable -- `fzn_manifest_satisfy` drains the deficit
 * table while `overflowed` clears only on an admission that drops nothing, so
 * followed-overflowed-with-nothing-pending is a real host and not a fiction.
 */
static int state_of(fzn_manifest_state_t *state, const uint8_t *issuer, int followed,
                    int overflowed, size_t pending)
{
	size_t i;

	memset(ISSUERS, 0, sizeof(ISSUERS));
	memset(DEFICIT, 0, sizeof(DEFICIT));
	if (fzn_manifest_init(state, ISSUERS, 2u, DEFICIT, 4u) != FZN_MANIFEST_OK)
		return 0;

	if (followed) {
		memcpy(ISSUERS[0].issuer, issuer, FZN_PUBKEY_LEN);
		ISSUERS[0].overflowed = overflowed;
		ISSUERS[0].pairs_seen = pending;
		state->issuer_used = 1u;
	}
	for (i = 0; i < pending && i < 4u; i++) {
		memcpy(DEFICIT[i].issuer, issuer, FZN_PUBKEY_LEN);
		memset(&DEFICIT[i].capability, (int)(0x40u + i), sizeof(DEFICIT[i].capability));
		memset(DEFICIT[i].grantee, (int)(0x50u + i), FZN_PUBKEY_LEN);
	}
	state->deficit_used = pending < 4u ? pending : 4u;
	return 1;
}

static size_t line_of(const fzn_manifest_state_t *state, const uint8_t *issuer, char *out,
                      fzn_manifest_line_t *said)
{
	size_t len = 99;

	*said = (fzn_manifest_line_t)-1;
	CHECK(fzn_manifest_print(state, issuer, out, FZN_MANIFEST_PRINT_MAX, &len, said)
	              == FZN_MANIFEST_OK,
	      "rendering refused a state it should have printed");
	return len;
}

int main(void)
{
	fzn_manifest_state_t state;
	uint8_t issuer[FZN_PUBKEY_LEN], other[FZN_PUBKEY_LEN];
	char line[FZN_MANIFEST_PRINT_MAX];
	char unfollowed_line[FZN_MANIFEST_PRINT_MAX];
	char understated_line[FZN_MANIFEST_PRINT_MAX];
	fzn_manifest_line_t said;
	size_t len = 0;

	key(issuer, 0x21);
	key(other, 0x22);

	/* ---- NO STATE AT ALL. Not "0 outstanding": a zero here would read as
	 * a measurement of a real thing. */
	len = line_of(NULL, issuer, line, &said);
	CHECK(said == FZN_MANIFEST_LINE_NONE, "a NULL state was given a verdict");
	CHECK(len > 0 && line[len] == '\0', "the line is not terminated at its length");
	CHECK(strstr(line, "cannot say") != NULL,
	      "a host with no manifest state did not say it cannot say");
	CHECK(strstr(line, "outstanding") == NULL,
	      "a host with no state used the word a real count uses");

	/* ---- NOT FOLLOWED. `pending` answers 0 here and calls it "the
	 * absence of a question"; a person shown 0 reads an answer. */
	CHECK(state_of(&state, issuer, 0, 0, 0), "the fixture does not build");
	len = line_of(&state, issuer, unfollowed_line, &said);
	CHECK(said == FZN_MANIFEST_LINE_UNFOLLOWED, "an unfollowed issuer was not named as one");
	CHECK(strstr(unfollowed_line, "not followed") != NULL,
	      "the line does not say the issuer is not followed");
	CHECK(strstr(unfollowed_line, "up to date") == NULL,
	      "an issuer nothing is tracked from read as up to date, which is the fail-open "
	      "this file exists to remove");

	/* ---- FOLLOWED, NOTHING OUTSTANDING, COUNT SOUND. */
	CHECK(state_of(&state, issuer, 1, 0, 0), "the fixture does not build");
	len = line_of(&state, issuer, line, &said);
	CHECK(said == FZN_MANIFEST_LINE_COMPLETE, "a sound empty deficit was not COMPLETE");
	CHECK(strstr(line, "up to date") != NULL, "the line does not say the host is current");
	CHECK(strcmp(line, unfollowed_line) != 0,
	      "a followed issuer with nothing outstanding and one that is not followed at "
	      "all produced the same sentence");

	/* ---- FOLLOWED, THREE OUTSTANDING, COUNT SOUND. */
	CHECK(state_of(&state, issuer, 1, 0, 3), "the fixture does not build");
	len = line_of(&state, issuer, line, &said);
	CHECK(said == FZN_MANIFEST_LINE_PENDING, "three outstanding was not PENDING");
	CHECK(strstr(line, "3 revocations outstanding") != NULL,
	      "the line does not carry the count");
	CHECK(strstr(line, "AT LEAST") == NULL,
	      "a sound count was hedged, which would make the real hedge meaningless");

	/* ---- ONE OUTSTANDING, and the noun agrees with it. */
	CHECK(state_of(&state, issuer, 1, 0, 1), "the fixture does not build");
	len = line_of(&state, issuer, line, &said);
	CHECK(strstr(line, "1 revocation outstanding") != NULL,
	      "one outstanding revocation was printed in the plural");

	/* ---- FOLLOWED, THREE OUTSTANDING, AND THE COUNT IS A FLOOR. */
	CHECK(state_of(&state, issuer, 1, 1, 3), "the fixture does not build");
	len = line_of(&state, issuer, understated_line, &said);
	CHECK(said == FZN_MANIFEST_LINE_UNDERSTATED, "a dropped pair was not reported");
	CHECK(strstr(understated_line, "AT LEAST 3") != NULL,
	      "the line states a floor as though it were a count");
	CHECK(strstr(understated_line, "cannot name") != NULL,
	      "the line does not say there are more this host cannot name, which is the "
	      "whole of what the number is missing");

	/* ---- THE AMBIGUITY `fzn_manifest_follows` WAS ADDED FOR. Both of the
	 * next two answer `pending` 0 and `overflowed` 1, and they are opposite
	 * sentences: one host tracks nothing from that key, the other tracks it
	 * and knows its own number is a floor. */
	CHECK(state_of(&state, issuer, 1, 1, 0), "the fixture does not build");
	len = line_of(&state, issuer, line, &said);
	CHECK(fzn_manifest_pending(&state, issuer) == 0
	              && fzn_manifest_overflowed(&state, issuer) == 1,
	      "the fixture does not reproduce the (0, 1) pair, so it tests nothing");
	CHECK(said == FZN_MANIFEST_LINE_UNDERSTATED,
	      "a followed issuer whose recorded deficit was satisfied, and whose count is "
	      "still a floor, read as something other than understated");
	CHECK(strcmp(line, unfollowed_line) != 0,
	      "(pending 0, overflowed 1) produced one sentence for two opposite states, "
	      "which is what `fzn_manifest_follows` exists to prevent");
	CHECK(strstr(line, "up to date") == NULL,
	      "a host that knows it is missing revocations read as current");

	/* ---- AN ISSUER THIS STATE HAS NEVER HEARD OF, while another is
	 * followed: the answer is about the issuer asked for, not the table. */
	CHECK(state_of(&state, issuer, 1, 0, 2), "the fixture does not build");
	len = line_of(&state, other, line, &said);
	CHECK(said == FZN_MANIFEST_LINE_UNFOLLOWED,
	      "a state that follows somebody else answered for the issuer asked about");

	/* ---- A STATE THAT CANNOT BE READ. `overflowed` answers 1 and
	 * `follows` answers 0, and the conservative pair is UNFOLLOWED: a
	 * table nobody can walk tracks nothing, which is the sentence that does
	 * not flatter the host. */
	CHECK(state_of(&state, issuer, 1, 0, 1), "the fixture does not build");
	state.issuer_used = state.issuer_capacity + 1u;
	len = line_of(&state, issuer, line, &said);
	CHECK(said == FZN_MANIFEST_LINE_UNFOLLOWED,
	      "a state whose own fields disagree did not read as tracking nothing -- the "
	      "conservative answer here is the one that does not flatter the host");

	/* ---- THE OPERANDS. */
	CHECK(state_of(&state, issuer, 1, 0, 1), "the fixture does not build");
	CHECK(fzn_manifest_print(&state, issuer, NULL, sizeof(line), &len, &said)
	              == FZN_MANIFEST_ERR_MALFORMED, "printing accepted a null buffer");
	CHECK(fzn_manifest_print(&state, issuer, line, sizeof(line), NULL, &said)
	              == FZN_MANIFEST_ERR_MALFORMED, "printing accepted a null length");
	CHECK(fzn_manifest_print(&state, issuer, line, sizeof(line), &len, NULL)
	              == FZN_MANIFEST_ERR_MALFORMED,
	      "printing accepted a null state out-parameter, which is the required half");

	/* ---- A BUFFER TOO SMALL REPORTS WHAT IT NEEDED AND WRITES NOTHING. */
	said = FZN_MANIFEST_LINE_PENDING;
	len = 0;
	CHECK(fzn_manifest_print(&state, issuer, line, 4u, &len, &said)
	              == FZN_MANIFEST_ERR_MALFORMED, "a four-byte buffer took a line");
	CHECK(len > 4u, "the refusal does not say how much room the line needed");
	CHECK(said == FZN_MANIFEST_LINE_NONE,
	      "a refused render left a verdict behind, which a caller would read as one");

	printf("manifest_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
