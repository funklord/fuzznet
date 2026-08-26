/* Current values, and the two ways they are allowed to change.
 *
 * The cases are chosen for what each would cost. A state that let an older
 * record win reverts a setting whenever the network re-delivers one. One that
 * resolved conflicts silently lets any authorised issuer overwrite any
 * other's configuration with nothing to show it happened. One that evicted to
 * make room reverts a setting to a default nobody can trace.
 */

#include "../state.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void expect(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

static void expect_err(fzn_state_err_t got, fzn_state_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		printf("  FAIL: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_state_err_str(got),
		       fzn_state_err_str(want));
	}
}

static const uint8_t BODY_A[] = "value from alice";
static const uint8_t BODY_B[] = "value from bob";
static const uint8_t BODY_A2[] = "alice's second thought";

static void make(fzn_record_t *r, uint8_t issuer_seed, uint8_t subject_seed, uint32_t kind,
                 uint64_t seq, const uint8_t *body, size_t body_len)
{
	memset(r, 0, sizeof(*r));
	memset(r->issuer, issuer_seed, FZN_PUBKEY_LEN);
	memset(r->subject, subject_seed, FZN_SUBJECT_LEN);
	r->kind = kind;
	r->seq = seq;
	r->body = body;
	r->body_len = body_len;
}

int main(void)
{
	fzn_state_t st;
	fzn_state_entry_t entries[3];
	fzn_record_t rec;
	const fzn_state_entry_t *got;
	uint8_t alice[FZN_PUBKEY_LEN], bob[FZN_PUBKEY_LEN], subj[FZN_SUBJECT_LEN];

	memset(alice, 0xa1, sizeof(alice));
	memset(bob, 0xb2, sizeof(bob));
	memset(subj, 0x51, sizeof(subj));

	expect_err(fzn_state_init(NULL, entries, 3), FZN_STATE_ERR_MALFORMED, "a null state");
	expect_err(fzn_state_init(&st, NULL, 3), FZN_STATE_ERR_MALFORMED, "null entries");
	expect_err(fzn_state_init(&st, entries, 0), FZN_STATE_ERR_MALFORMED, "zero capacity");
	expect_err(fzn_state_init(&st, entries, 3), FZN_STATE_OK, "a well-formed state");
	expect(fzn_state_count(&st) == 0, "a new state holds nothing");
	expect(fzn_state_get(&st, subj, 1) == NULL, "nothing is set yet");

	/* SETTING, AND SUPERSEDING FROM THE SAME ISSUER. */
	make(&rec, 0xa1, 0x51, 1, 5, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_OK, "alice sets a subject");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->body == BODY_A, "the value is alice's");
	expect(got != NULL && got->seq == 5, "and carries her sequence");

	make(&rec, 0xa1, 0x51, 1, 6, BODY_A2, sizeof(BODY_A2));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_OK, "alice changes her mind");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->body == BODY_A2, "the newer value wins");
	expect(fzn_state_count(&st) == 1, "superseding does not add a subject");

	/* AN OLDER RECORD MUST NOT UNDO A NEWER ONE. A re-delivery is exactly
	 * this, and a state that took it would revert settings at random. */
	make(&rec, 0xa1, 0x51, 1, 5, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_STALE, "an older record arriving late");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->body == BODY_A2, "and the newer value still stands");

	make(&rec, 0xa1, 0x51, 1, 6, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_STALE, "the same sequence again");

	/* A DIFFERENT KIND IS A DIFFERENT SUBJECT. */
	make(&rec, 0xa1, 0x51, 2, 7, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_OK, "the same subject, another kind");
	expect(fzn_state_count(&st) == 2, "which is a second entry");

	/* CONFLICT IS REPORTED AND CHANGES NOTHING. */
	make(&rec, 0xb2, 0x51, 1, 99, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_CONFLICT, "bob writing alice's subject");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->body == BODY_A2, "a refused conflict left the value alone");
	expect(got != NULL && memcmp(got->issuer, alice, FZN_PUBKEY_LEN) == 0,
	       "and left the issuer alone");

	/* RESOLVING IS DELIBERATE, and then bob holds it. */
	expect_err(fzn_state_resolve(&st, &rec), FZN_STATE_OK, "resolving in bob's favour");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->body == BODY_B, "bob's value now stands");
	expect(got != NULL && memcmp(got->issuer, bob, FZN_PUBKEY_LEN) == 0,
	       "and bob is recorded as having set it");
	expect(fzn_state_count(&st) == 2, "resolving did not add an entry");

	/* And now ALICE is the conflicting one, which is the direction that
	 * proves the check is about identity rather than about order. */
	make(&rec, 0xa1, 0x51, 1, 100, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_CONFLICT,
	           "alice writing what is now bob's");

	/* CLEARING. */
	expect_err(fzn_state_clear(&st, subj, 1, alice, 101), FZN_STATE_ERR_CONFLICT,
	           "alice clearing bob's subject");
	expect_err(fzn_state_clear(&st, subj, 1, bob, 50), FZN_STATE_ERR_STALE,
	           "bob clearing with an older sequence");
	expect_err(fzn_state_clear(&st, subj, 9, bob, 200), FZN_STATE_ERR_ABSENT,
	           "clearing something never set");
	expect_err(fzn_state_clear(&st, subj, 1, bob, 200), FZN_STATE_OK, "bob clearing his own");
	expect(fzn_state_get(&st, subj, 1) == NULL, "and it is gone");
	expect(fzn_state_count(&st) == 1, "leaving the other kind");

	/* FULL IS REFUSED, NOT EVICTED. */
	{
		uint8_t other[FZN_SUBJECT_LEN];

		make(&rec, 0xa1, 0x60, 1, 1, BODY_A, sizeof(BODY_A));
		expect_err(fzn_state_apply(&st, &rec), FZN_STATE_OK, "a second subject");
		make(&rec, 0xa1, 0x61, 1, 1, BODY_A, sizeof(BODY_A));
		expect_err(fzn_state_apply(&st, &rec), FZN_STATE_OK, "a third subject");
		make(&rec, 0xa1, 0x62, 1, 1, BODY_A, sizeof(BODY_A));
		expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_FULL, "a fourth subject");

		memset(other, 0x60, sizeof(other));
		expect(fzn_state_get(&st, other, 1) != NULL,
		       "a full state must not have evicted an earlier subject");
	}

	/* Arguments. */
	expect_err(fzn_state_apply(&st, NULL), FZN_STATE_ERR_MALFORMED, "a null record");
	expect_err(fzn_state_apply(NULL, &rec), FZN_STATE_ERR_MALFORMED, "a null state to apply to");
	make(&rec, 0xa1, 0x70, 1, 0, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_MALFORMED, "sequence zero");
	make(&rec, 0xa1, 0x70, 1, 1, NULL, 4);
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_MALFORMED,
	           "a null body of non-zero length");
	expect(fzn_state_get(NULL, subj, 1) == NULL, "a null state answers nothing");
	expect(fzn_state_count(NULL) == 0, "a null state counts nothing");
	expect_err(fzn_state_clear(&st, subj, 1, NULL, 1), FZN_STATE_ERR_MALFORMED,
	           "clearing with no issuer");

	printf("state_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
