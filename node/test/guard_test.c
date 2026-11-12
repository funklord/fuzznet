/* node guard_test -- the guard against hammering, sec 1074: a burst admitted,
 * the next refused and said once, refused again blocked, the block doubling an
 * offence, a quiet key clean again, keys apart, a table grown keeping every
 * key, and one that cannot grow never freeing a blocked key. */

#include "../guard.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                  \
	do {                                                                               \
		checks++;                                                                  \
		if (!(cond)) {                                                             \
			failures++;                                                        \
			fprintf(stderr, "  FAIL guard_test.c:%d: %s\n", __LINE__, what);   \
		}                                                                          \
	} while (0)

#define MIN 60000u
#define REFILL (5u * MIN)
#define DAY (1440u * MIN)

static fzn_guard_verdict_t ask(fzn_guard_t *g, uint8_t who, uint64_t at, int *first)
{
	uint8_t key[FZN_GUARD_KEY_LEN];

	memset(key, who, sizeof(key));
	return fzn_guard_ask(g, key, at, 3u, REFILL, DAY, first);
}

static void test_a_hammer(void)
{
	static fzn_guard_slot_t rows[8];
	fzn_guard_t g;
	int first = 0, i, admitted = 0;

	fzn_guard_init(&g, rows, 8u);
	for (i = 0; i < 3; i++)
		admitted += ask(&g, 0xa1, 1000u + (uint64_t)i, &first) == FZN_GUARD_ADMIT;
	CHECK(admitted == 3, "the burst was not admitted");
	CHECK(ask(&g, 0xa1, 1010u, &first) == FZN_GUARD_REFUSED && first == 1,
	      "past the burst an ask was not refused, said once");
	CHECK(ask(&g, 0xa1, 1020u, &first) == FZN_GUARD_BLOCKED && first == 0,
	      "refused again while refused was not blocked, or said again");
	CHECK(ask(&g, 0xa1, 1020u + MIN, &first) == FZN_GUARD_BLOCKED,
	      "a block of one refill let an ask through a minute on");
	CHECK(ask(&g, 0xb2, 1030u, &first) == FZN_GUARD_ADMIT, "another key was held by this one's block");
	/* ONE REFILL ON: a token earned, the block over. */
	CHECK(ask(&g, 0xa1, 1020u + REFILL, &first) == FZN_GUARD_ADMIT,
	      "a refill on, the blocked key was not admitted");
	/* AGAIN: refused, then blocked twice as long. */
	(void)ask(&g, 0xa1, 1030u + REFILL, &first);
	CHECK(ask(&g, 0xa1, 1040u + REFILL, &first) == FZN_GUARD_BLOCKED
	              && ask(&g, 0xa1, 1040u + 2u * REFILL - 1u, &first) == FZN_GUARD_BLOCKED,
	      "a second offence's block was not twice the first");
	CHECK(g.refused_total >= 5u, "refusals were not counted");
	/* QUIET A DAY: clean, the burst whole again. */
	admitted = 0;
	for (i = 0; i < 3; i++)
		admitted += ask(&g, 0xa1, 2u * DAY + (uint64_t)i, &first) == FZN_GUARD_ADMIT;
	CHECK(admitted == 3, "a key quiet a day was not clean again");
}

/* A FULL TABLE gives way its least recently seen key, never a blocked one. */
static void test_a_full_table(void)
{
	static fzn_guard_slot_t rows[2];
	fzn_guard_t g;
	int first;

	fzn_guard_init(&g, rows, 2u);
	(void)ask(&g, 0x01, 100u, &first);
	(void)ask(&g, 0x01, 101u, &first);
	(void)ask(&g, 0x01, 102u, &first);
	(void)ask(&g, 0x01, 103u, &first);
	CHECK(ask(&g, 0x01, 104u, &first) == FZN_GUARD_BLOCKED, "fixture: key 1 blocked");
	(void)ask(&g, 0x02, 50u, &first);
	(void)ask(&g, 0x03, 200u, &first);
	CHECK(ask(&g, 0x01, 300u, &first) == FZN_GUARD_BLOCKED,
	      "a new key took a blocked key's place, setting it free");
}

/* GROWN, NOT FULL, sec 1074: the caller grows a full table, and every key
 * keeps its tokens and its block. */
static void test_grown(void)
{
	static fzn_guard_slot_t small[2], big[6];
	fzn_guard_t g;
	int first;

	fzn_guard_init(&g, small, 2u);
	CHECK(!fzn_guard_full(&g), "an empty table was full");
	(void)ask(&g, 0x01, 100u, &first);
	(void)ask(&g, 0x01, 101u, &first);
	(void)ask(&g, 0x01, 102u, &first);
	(void)ask(&g, 0x01, 103u, &first);
	(void)ask(&g, 0x01, 104u, &first);
	(void)ask(&g, 0x02, 105u, &first);
	(void)ask(&g, 0x02, 106u, &first);
	CHECK(fzn_guard_full(&g) && g.used == 2u, "two keys in two rows were not full");
	memcpy(big, small, sizeof(small));
	CHECK(!fzn_guard_rows(&g, big, 1u), "the rows were shrunk");
	CHECK(fzn_guard_rows(&g, big, 6u) && !fzn_guard_full(&g) && g.cap == 6u,
	      "the rows did not grow");
	CHECK(ask(&g, 0x03, 107u, &first) == FZN_GUARD_ADMIT && g.used == 3u,
	      "a third key had no row of its own");
	CHECK(ask(&g, 0x01, 108u, &first) == FZN_GUARD_BLOCKED, "key 1's block was lost growing");
	CHECK(ask(&g, 0x02, 109u, &first) == FZN_GUARD_ADMIT
	              && ask(&g, 0x02, 110u, &first) == FZN_GUARD_REFUSED,
	      "key 2's tokens were lost growing");
}

/* A BURST LOWERED holds at the next ask, not once the tokens held run out. */
static void test_burst_lowered(void)
{
	static fzn_guard_slot_t rows[2];
	uint8_t key[FZN_GUARD_KEY_LEN];
	fzn_guard_t g;
	int first;

	memset(key, 0x05, sizeof(key));
	fzn_guard_init(&g, rows, 2u);
	CHECK(fzn_guard_ask(&g, key, 100u, 10u, REFILL, DAY, &first) == FZN_GUARD_ADMIT,
	      "fixture: a ring under a burst of ten");
	CHECK(fzn_guard_ask(&g, key, 101u, 2u, REFILL, DAY, &first) == FZN_GUARD_ADMIT
	              && fzn_guard_ask(&g, key, 102u, 2u, REFILL, DAY, &first) == FZN_GUARD_ADMIT
	              && fzn_guard_ask(&g, key, 103u, 2u, REFILL, DAY, &first) == FZN_GUARD_REFUSED,
	      "a burst lowered to two let a third ring through");
}

static void test_no_room_admits(void)
{
	fzn_guard_t g;
	int first = 1;

	fzn_guard_init(&g, NULL, 0u);
	CHECK(ask(&g, 0x09, 1u, &first) == FZN_GUARD_ADMIT && first == 0,
	      "a guard with no room refused");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failure counts");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_the_suite_can_tell_pass_from_fail();
	test_a_hammer();
	test_a_full_table();
	test_grown();
	test_burst_lowered();
	test_no_room_admits();
	if (failures) {
		fprintf(stderr, "node guard_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node guard_test: all %d checks passed\n", checks);
	return 0;
}
