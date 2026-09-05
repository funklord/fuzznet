/* Tests for record/ledger.c: what each peer has confirmed holding.
 *
 * THE TWO PROPERTIES THAT ARE NOT BOOKKEEPING.
 *
 * A confirmation never moves backwards, and the reason is not caution: a
 * late acknowledgement is reordering rather than retraction, so the higher
 * number is the better evidence and keeping it is not over-claiming. The
 * case sends 5, then 3, and requires both that the answer stays 5 and that
 * the caller is TOLD the 3 was stale -- the table being identical either way
 * is exactly why silently dropping it would be undetectable.
 *
 * And every unknown resolves to "behind". A peer never heard from, a subject
 * never sent and a ledger too corrupt to scan all answer the same way, which
 * costs a retransmission rather than a delivery. That polarity is the
 * opposite of `fzn_revocation_covers`'s and it is checked against a sound
 * ledger too, because three readers agreeing by value proves nothing unless
 * a case exists where they would differ.
 */

#include "../ledger.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

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
	fprintf(stderr, "  FAIL ledger_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)
/* EVALUATES `cond` ONCE. The obvious spelling calls it twice -- in the CHECK
 * and again in the `if` -- which is silent and fatal for a condition with a
 * side effect. This file was written with that spelling and
 * `REQUIRE(fzn_ledger_confirm(...) == FZN_LEDGER_OK, ...)` re-confirmed the
 * same version on the second evaluation, which the monotonic rule correctly
 * calls STALE, so the test returned there and every case after it silently
 * did not run. The check count was identical either way, which is what made
 * it invisible: two sabotages appeared uncaught and were simply never
 * reached. Nine other suites in this tree already spell it this way. */
#define REQUIRE(cond, ...)                                   \
	do {                                                 \
		int require_ok = (cond) ? 1 : 0;             \
		check_at(require_ok, __LINE__, __VA_ARGS__); \
		if (!require_ok)                             \
			return;                              \
	} while (0)

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed + (i * 7u));
}

static void subj(uint8_t out[FZN_SUBJECT_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_SUBJECT_LEN; i++)
		out[i] = (uint8_t)(seed + (i * 11u));
}

/* ---- the cases -------------------------------------------------------- */

static void test_init_refuses_what_cannot_hold_anything(void)
{
	fzn_ledger_t l;
	fzn_ledger_entry_t e[2];

	CHECK(fzn_ledger_init(NULL, e, 2) == FZN_LEDGER_ERR_MALFORMED,
	      "init accepted a null ledger");
	CHECK(fzn_ledger_init(&l, NULL, 2) == FZN_LEDGER_ERR_MALFORMED,
	      "init accepted null entries");
	CHECK(fzn_ledger_init(&l, e, 0) == FZN_LEDGER_ERR_MALFORMED,
	      "init accepted a capacity of zero, which records nothing and reports success");
	CHECK(fzn_ledger_init(&l, e, 2) == FZN_LEDGER_OK, "init refused a sound ledger");
	CHECK(fzn_ledger_count(&l) == 0u, "a fresh ledger already held something");
}

static void test_init_does_not_leave_the_callers_bytes(void)
{
	fzn_ledger_t from_dirty, from_clean;
	static fzn_ledger_entry_t dirty[2], clean[2];

	memset(dirty, 0xab, sizeof(dirty));
	memset(clean, 0, sizeof(clean));
	CHECK(fzn_ledger_init(&from_dirty, dirty, 2) == FZN_LEDGER_OK, "init refused a dirty array");
	CHECK(fzn_ledger_init(&from_clean, clean, 2) == FZN_LEDGER_OK, "init refused a clean array");
	CHECK(memcmp(dirty, clean, sizeof(dirty)) == 0,
	      "init left the caller's bytes in the entry array, so what a fresh ledger holds "
	      "depends on what its memory held");
}

static void test_a_confirmation_is_remembered_per_peer_and_subject(void)
{
	fzn_ledger_t l;
	fzn_ledger_entry_t e[4];
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN];
	uint8_t s1[FZN_SUBJECT_LEN], s2[FZN_SUBJECT_LEN];

	REQUIRE(fzn_ledger_init(&l, e, 4) == FZN_LEDGER_OK, "init");
	key(a, 0x11);
	key(b, 0x22);
	subj(s1, 0x31);
	subj(s2, 0x32);

	CHECK(fzn_ledger_confirmed(&l, a, s1, 1u) == 0u, "an unknown peer confirmed something");
	CHECK(fzn_ledger_confirm(&l, a, s1, 1u, 5u) == FZN_LEDGER_OK, "confirm refused");
	CHECK(fzn_ledger_confirmed(&l, a, s1, 1u) == 5u, "the confirmation was not remembered");
	CHECK(fzn_ledger_count(&l) == 1u, "the row was not counted");

	/* EVERY PART OF THE KEY SEPARATES. A host may be current on one
	 * subject and behind on another, which is the whole reason `subject`
	 * is not optional -- collapsing it into one number per peer would be
	 * a lie in whichever direction was convenient. */
	CHECK(fzn_ledger_confirmed(&l, b, s1, 1u) == 0u, "another peer inherited a confirmation");
	CHECK(fzn_ledger_confirmed(&l, a, s2, 1u) == 0u, "another subject inherited one");
	CHECK(fzn_ledger_confirmed(&l, a, s1, 2u) == 0u, "another kind inherited one");

	CHECK(fzn_ledger_confirm(&l, a, s2, 1u, 9u) == FZN_LEDGER_OK, "a second subject");
	CHECK(fzn_ledger_confirmed(&l, a, s1, 1u) == 5u, "the first subject moved");
	CHECK(fzn_ledger_confirmed(&l, a, s2, 1u) == 9u, "the second subject is wrong");
	CHECK(fzn_ledger_count(&l) == 2u, "the second row was not counted");

	/* AN ALL-ZERO SUBJECT IS A REAL SUBJECT, which is the consumer whose
	 * document is single and whose one version says everything. */
	{
		uint8_t empty[FZN_SUBJECT_LEN];

		memset(empty, 0, sizeof(empty));
		CHECK(fzn_ledger_confirm(&l, a, empty, 1u, 7u) == FZN_LEDGER_OK,
		      "an all-zero subject was refused");
		CHECK(fzn_ledger_confirmed(&l, a, empty, 1u) == 7u,
		      "an all-zero subject is not a distinct row");
		CHECK(fzn_ledger_confirmed(&l, a, s1, 1u) == 5u,
		      "the all-zero subject collided with a real one");
	}
}

static void test_a_confirmation_never_moves_backwards(void)
{
	fzn_ledger_t l;
	fzn_ledger_entry_t e[2];
	uint8_t a[FZN_PUBKEY_LEN], s[FZN_SUBJECT_LEN];

	REQUIRE(fzn_ledger_init(&l, e, 2) == FZN_LEDGER_OK, "init");
	key(a, 0x41);
	subj(s, 0x42);

	REQUIRE(fzn_ledger_confirm(&l, a, s, 1u, 5u) == FZN_LEDGER_OK, "the first confirmation");

	/* A LATE ACKNOWLEDGEMENT IS REORDERING, NOT RETRACTION. Both numbers
	 * were real when they were sent, so the higher is the better evidence
	 * and keeping it is not over-claiming. */
	CHECK(fzn_ledger_confirm(&l, a, s, 1u, 3u) == FZN_LEDGER_ERR_STALE,
	      "a confirmation that moved backwards was accepted silently");
	CHECK(fzn_ledger_confirmed(&l, a, s, 1u) == 5u,
	      "a late acknowledgement forgot a delivery, so a datagram overtaking another "
	      "loses a peer's progress");

	/* The same number twice is stale too: it is no new evidence. */
	CHECK(fzn_ledger_confirm(&l, a, s, 1u, 5u) == FZN_LEDGER_ERR_STALE,
	      "a repeated confirmation was reported as progress");
	CHECK(fzn_ledger_confirmed(&l, a, s, 1u) == 5u, "a repeat changed the row");

	/* And forwards still moves. */
	CHECK(fzn_ledger_confirm(&l, a, s, 1u, 6u) == FZN_LEDGER_OK, "a real advance was refused");
	CHECK(fzn_ledger_confirmed(&l, a, s, 1u) == 6u, "the advance was not recorded");
	CHECK(fzn_ledger_count(&l) == 1u, "an advance took a second row");
}

static void test_everything_unknown_is_behind(void)
{
	fzn_ledger_t l;
	fzn_ledger_entry_t e[2];
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN], s[FZN_SUBJECT_LEN];

	REQUIRE(fzn_ledger_init(&l, e, 2) == FZN_LEDGER_OK, "init");
	key(a, 0x51);
	key(b, 0x52);
	subj(s, 0x53);

	CHECK(fzn_ledger_behind(&l, a, s, 1u, 1u) != 0,
	      "a peer never heard from was reported as current, which skips a delivery");
	REQUIRE(fzn_ledger_confirm(&l, a, s, 1u, 5u) == FZN_LEDGER_OK, "confirm");

	/* AND A SOUND LEDGER ANSWERS THE OTHER WAY, which is what stops the
	 * cases above passing for a constant. */
	CHECK(fzn_ledger_behind(&l, a, s, 1u, 5u) == 0, "a peer that is level was reported behind");
	CHECK(fzn_ledger_behind(&l, a, s, 1u, 4u) == 0, "a peer that is ahead was reported behind");
	CHECK(fzn_ledger_behind(&l, a, s, 1u, 6u) != 0, "a peer that is behind was reported current");
	CHECK(fzn_ledger_behind(&l, b, s, 1u, 6u) != 0, "an unknown peer was reported current");
}

static void test_a_ledger_that_cannot_be_scanned_withholds_nothing(void)
{
	fzn_ledger_t l;
	fzn_ledger_entry_t e[2];
	uint8_t a[FZN_PUBKEY_LEN], s[FZN_SUBJECT_LEN];

	REQUIRE(fzn_ledger_init(&l, e, 2) == FZN_LEDGER_OK, "init");
	key(a, 0x61);
	subj(s, 0x62);
	REQUIRE(fzn_ledger_confirm(&l, a, s, 1u, 5u) == FZN_LEDGER_OK, "confirm");
	REQUIRE(fzn_ledger_behind(&l, a, s, 1u, 5u) == 0, "level before the corruption");

	/* Neither state is reachable through `_init`. It is what a caller
	 * holds who restored a struct from a file and got the count without
	 * the array. */
	{
		fzn_ledger_t hollow = l;

		hollow.used = hollow.capacity + 1u;
		CHECK(fzn_ledger_count(&hollow) == 0u, "a count past capacity was reported");
		CHECK(fzn_ledger_confirmed(&hollow, a, s, 1u) == 0u,
		      "a ledger that cannot be scanned answered a confirmation");
		CHECK(fzn_ledger_behind(&hollow, a, s, 1u, 5u) != 0,
		      "a ledger that cannot be scanned reported a peer current, which withholds "
		      "a delivery on the strength of rows nobody can read");
		CHECK(fzn_ledger_confirm(&hollow, a, s, 1u, 9u) == FZN_LEDGER_ERR_MALFORMED,
		      "a corrupt ledger was written into");

		hollow = l;
		hollow.entries = NULL;
		hollow.used = 1u;
		CHECK(fzn_ledger_behind(&hollow, a, s, 1u, 5u) != 0,
		      "a ledger with no array reported a peer current");
		hollow.used = 0u;
		CHECK(fzn_ledger_confirmed(&hollow, a, s, 1u) == 0u,
		      "an empty ledger with no array answered, which corrupt() does not catch "
		      "because it holds nothing");
		/* AND THE WRITE PATH REFUSES IT TOO. `corrupt()` reports this
		 * one sound -- its second clause is `used > 0 && !entries` --
		 * so the `!entries` operand beside it is the only thing
		 * standing between a caller and a write through a null array.
		 * Covered for `confirmed` above and not for `confirm` until
		 * now, which `make coverage` is what said. */
		CHECK(fzn_ledger_confirm(&hollow, a, s, 1u, 9u) == FZN_LEDGER_ERR_MALFORMED,
		      "an empty ledger with no array was written into");
	}
	CHECK(fzn_ledger_behind(NULL, a, s, 1u, 5u) != 0, "a null ledger reported a peer current");
	CHECK(fzn_ledger_count(NULL) == 0u, "a null ledger reported a count");
}

static void test_a_full_ledger_refuses_rather_than_forgetting(void)
{
	fzn_ledger_t l;
	fzn_ledger_entry_t e[2];
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN], c[FZN_PUBKEY_LEN], s[FZN_SUBJECT_LEN];

	REQUIRE(fzn_ledger_init(&l, e, 2) == FZN_LEDGER_OK, "init");
	key(a, 0x71);
	key(b, 0x72);
	key(c, 0x73);
	subj(s, 0x74);

	REQUIRE(fzn_ledger_confirm(&l, a, s, 1u, 1u) == FZN_LEDGER_OK, "first");
	REQUIRE(fzn_ledger_confirm(&l, b, s, 1u, 1u) == FZN_LEDGER_OK, "second");

	/* NOTHING HERE EXPIRES, so unlike chain/chain_store.c there is no dead
	 * row to spend and no eviction to do. A confirmation is true for ever. */
	CHECK(fzn_ledger_confirm(&l, c, s, 1u, 1u) == FZN_LEDGER_ERR_FULL,
	      "a full ledger took a third row");
	CHECK(fzn_ledger_count(&l) == 2u, "a refused confirmation changed the count");
	CHECK(fzn_ledger_confirmed(&l, a, s, 1u) == 1u, "a refused confirmation evicted a row");
	/* And an ADVANCE on a row already held still works when full, because
	 * it needs no room. */
	CHECK(fzn_ledger_confirm(&l, a, s, 1u, 2u) == FZN_LEDGER_OK,
	      "a full ledger refused an advance on a row it already holds");
}

static void test_every_guard_refuses_its_own_argument(void)
{
	fzn_ledger_t l;
	fzn_ledger_entry_t e[2];
	uint8_t a[FZN_PUBKEY_LEN], s[FZN_SUBJECT_LEN];

	REQUIRE(fzn_ledger_init(&l, e, 2) == FZN_LEDGER_OK, "init");
	key(a, 0x81);
	subj(s, 0x82);

	CHECK(fzn_ledger_confirm(NULL, a, s, 1u, 1u) == FZN_LEDGER_ERR_MALFORMED,
	      "confirm accepted a null ledger");
	CHECK(fzn_ledger_confirm(&l, NULL, s, 1u, 1u) == FZN_LEDGER_ERR_MALFORMED,
	      "confirm accepted a null peer");
	CHECK(fzn_ledger_confirm(&l, a, NULL, 1u, 1u) == FZN_LEDGER_ERR_MALFORMED,
	      "confirm accepted a null subject");
	/* Zero is what an absent row answers, so storing it would make
	 * "confirmed nothing" and "never heard of" one state. */
	CHECK(fzn_ledger_confirm(&l, a, s, 1u, 0u) == FZN_LEDGER_ERR_MALFORMED,
	      "confirm accepted version zero, which is what an absent row already answers");
	CHECK(fzn_ledger_count(&l) == 0u, "a refused confirmation took a row");

	CHECK(fzn_ledger_confirmed(NULL, a, s, 1u) == 0u, "confirmed accepted a null ledger");
	CHECK(fzn_ledger_confirmed(&l, NULL, s, 1u) == 0u, "confirmed accepted a null peer");
	CHECK(fzn_ledger_confirmed(&l, a, NULL, 1u) == 0u, "confirmed accepted a null subject");
	CHECK(fzn_ledger_behind(&l, NULL, s, 1u, 1u) != 0, "behind accepted a null peer");
	CHECK(fzn_ledger_behind(&l, a, NULL, 1u, 1u) != 0, "behind accepted a null subject");
}

static void test_every_error_has_a_name(void)
{
	CHECK(strcmp(fzn_ledger_err_str(FZN_LEDGER_OK), "ok") == 0, "OK");
	CHECK(strcmp(fzn_ledger_err_str(FZN_LEDGER_ERR_MALFORMED), "malformed") == 0, "MALFORMED");
	CHECK(strcmp(fzn_ledger_err_str(FZN_LEDGER_ERR_FULL), "ledger full") == 0, "FULL");
	CHECK(strcmp(fzn_ledger_err_str(FZN_LEDGER_ERR_STALE), "stale confirmation") == 0, "STALE");
	CHECK(fzn_ledger_err_str((fzn_ledger_err_t)-99) != NULL, "err_str returned NULL");
}

int main(void)
{
	test_init_refuses_what_cannot_hold_anything();
	test_init_does_not_leave_the_callers_bytes();
	test_a_confirmation_is_remembered_per_peer_and_subject();
	test_a_confirmation_never_moves_backwards();
	test_everything_unknown_is_behind();
	test_a_ledger_that_cannot_be_scanned_withholds_nothing();
	test_a_full_ledger_refuses_rather_than_forgetting();
	test_every_guard_refuses_its_own_argument();
	test_every_error_has_a_name();

	printf("ledger_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
