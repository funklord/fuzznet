/* Tests for cli/state_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is the pair `fzn_state_get` deliberately
 * refuses to separate. It answers NULL for a tombstone and for a subject
 * nothing ever set, because "a caller asking what a subject says must not
 * have to know that this file remembers who unset it".
 *
 * Right for code taking a decision, wrong for a report: "nobody configured
 * this" and "somebody took it back" are the two answers to why a host will
 * not do what was asked, and they call for opposite next steps. The suite
 * asserts the LIBRARY really does collapse them before checking the printer
 * separates them, so the case cannot pass against a library that never did.
 */

#include "../state_print.h"

#include "../../record/record.h"

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
	fprintf(stderr, "  FAIL state_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static uint8_t WIRE[4][FZN_RECORD_MAX_LEN];
static size_t wire_next;

static int fixture_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	uint64_t h = 1469598103934665603u;
	size_t i;

	(void)ctx;
	for (i = 0; i < msg_len; i++) {
		h ^= msg[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i;
		h *= 1099511628211u;
		sig[i] = (uint8_t)(h >> 32);
	}
	return 1;
}

static int make(fzn_record_t *r, const uint8_t issuer[FZN_PUBKEY_LEN],
                const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind, uint64_t seq,
                const uint8_t *body, size_t body_len)
{
	fzn_sign_ops_t ops;
	uint8_t *slot = WIRE[wire_next % 4u];
	size_t wrote = 0;

	wire_next++;
	memset(&ops, 0, sizeof(ops));
	ops.sign = fixture_sign;

	if (fzn_record_sign(issuer, subject, 1u, kind, seq, 1, body, body_len, &ops, slot,
	                    FZN_RECORD_MAX_LEN, &wrote) != FZN_RECORD_OK)
		return 0;
	return fzn_record_open(slot, wrote, r) == FZN_RECORD_OK;
}

int main(void)
{
	char line[FZN_STATE_PRINT_MAX];
	char never_line[FZN_STATE_PRINT_MAX];
	fzn_state_entry_t cells[4];
	fzn_state_t st;
	fzn_record_t rec;
	fzn_state_cell_t s;
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint8_t subject[FZN_SUBJECT_LEN];
	uint8_t other[FZN_SUBJECT_LEN];
	const uint8_t body[2] = { 'o', 'n' };
	size_t len = 0;

	memset(issuer, 0x71, sizeof(issuer));
	memset(subject, 0x81, sizeof(subject));
	memset(other, 0x82, sizeof(other));

	/* A NULL STATE IS UNREADABLE, NOT UNSET -- and it is the zero value,
	 * so a caller that ignores the state is not invited to write. */
	s = FZN_STATE_CELL_SET;
	CHECK(fzn_state_print(NULL, subject, 5u, line, sizeof(line), &len, &s) ==
	              FZN_STATE_OK,
	      "a null state would not render");
	CHECK(s == FZN_STATE_CELL_UNREADABLE, "a null state was not reported unreadable");

	CHECK(fzn_state_init(&st, cells, 4) == FZN_STATE_OK, "the state would not init");

	/* NOBODY HAS SET IT. */
	CHECK(fzn_state_print(&st, subject, 5u, line, sizeof(line), &len, &s) ==
	              FZN_STATE_OK,
	      "an unset subject would not render");
	CHECK(s == FZN_STATE_CELL_NEVER_SET, "an unset subject was not never-set");
	memcpy(never_line, line, sizeof(line));

	/* SET, and the issuer is named. */
	CHECK(make(&rec, issuer, subject, 5u, 1u, body, sizeof(body)),
	      "the fixture could not sign a record");
	CHECK(fzn_state_apply(&st, &rec) == FZN_STATE_OK, "apply refused");
	CHECK(fzn_state_print(&st, subject, 5u, line, sizeof(line), &len, &s) ==
	              FZN_STATE_OK,
	      "a set cell would not render");
	CHECK(s == FZN_STATE_CELL_SET, "a set cell was not set");
	CHECK(strstr(line, "set by") != NULL, "the line does not say who set it");
	CHECK(strstr(line, " at 1") != NULL, "the sequence is not on the line");

	/* THE CASE THIS FILE EXISTS FOR. */
	CHECK(make(&rec, issuer, subject, 5u, 2u, NULL, 0),
	      "the fixture could not sign the clearing record");
	CHECK(fzn_state_clear(&st, &rec) == FZN_STATE_OK, "clear refused");
	CHECK(fzn_state_get(&st, subject, 5u) == NULL,
	      "the library still answers for a cleared cell, so this proves nothing "
	      "about looking past it");

	CHECK(fzn_state_print(&st, subject, 5u, line, sizeof(line), &len, &s) ==
	              FZN_STATE_OK,
	      "a cleared cell would not render");
	CHECK(s == FZN_STATE_CELL_CLEARED,
	      "a cleared cell was not distinguished from one nobody ever set");
	CHECK(strcmp(line, never_line) != 0,
	      "cleared and never-set print the same line, which is the one thing "
	      "fzn_state_get cannot tell a caller and the one a report must");
	CHECK(strstr(line, "taken back by") != NULL,
	      "the line does not name who cleared it, which is the reason for walking");

	/* AND AN UNTOUCHED SUBJECT IS STILL NEVER-SET, so a printer that
	 * called everything CLEARED would not pass. */
	CHECK(fzn_state_print(&st, other, 5u, line, sizeof(line), &len, &s) ==
	              FZN_STATE_OK,
	      "an untouched subject would not render");
	CHECK(s == FZN_STATE_CELL_NEVER_SET, "an untouched subject was reported cleared");

	/* AN UNREADABLE STATE IS NOT AN UNSET ONE. */
	st.used = st.capacity + 1u;
	CHECK(fzn_state_print(&st, subject, 5u, line, sizeof(line), &len, &s) ==
	              FZN_STATE_OK,
	      "an unreadable state would not render");
	CHECK(s == FZN_STATE_CELL_UNREADABLE,
	      "a state counting more cells than it holds was walked anyway");
	CHECK(strcmp(line, never_line) != 0,
	      "an unreadable state reads as an unset subject, which invites writing "
	      "over something nobody looked at");
	st.used = 2u;

	/* THE STATE IS REQUIRED, and a refusal leaves the conservative value. */
	CHECK(fzn_state_print(&st, subject, 5u, line, sizeof(line), &len, NULL) ==
	              FZN_STATE_ERR_MALFORMED,
	      "the state was optional after all");
	{
		char small[4];
		size_t needed = 0;

		memset(small, '@', sizeof(small));
		s = FZN_STATE_CELL_SET;
		CHECK(fzn_state_print(&st, subject, 5u, small, sizeof(small), &needed, &s) ==
		              FZN_STATE_ERR_MALFORMED,
		      "a buffer too small was written anyway");
		CHECK(needed > sizeof(small), "the size needed was not reported");
		CHECK(small[0] == '@', "a refused render left bytes in the buffer");
		CHECK(s == FZN_STATE_CELL_UNREADABLE,
		      "a refused render left a state that invites writing");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("state_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
