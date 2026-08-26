/* A log that evicts, and the difference between "gone" and "not yet".
 *
 * That distinction is the reason this module exists rather than being a
 * second journal. A peer that fell behind asks for a sequence; if the answer
 * to "evicted" and the answer to "not arrived" are the same, it asks for ever
 * and neither side can tell that from a lost datagram.
 */

#include "../log.h"

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

static void expect_err(fzn_log_err_t got, fzn_log_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		printf("  FAIL: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_log_err_str(got),
		       fzn_log_err_str(want));
	}
}

static uint8_t BODIES[16][4];

static void make(fzn_record_t *r, uint8_t issuer_seed, uint64_t seq)
{
	memset(r, 0, sizeof(*r));
	memset(r->issuer, issuer_seed, FZN_PUBKEY_LEN);
	r->kind = 3;
	r->seq = seq;
	r->body = BODIES[seq % 16u];
	r->body_len = sizeof(BODIES[0]);
}

int main(void)
{
	fzn_log_t log;
	fzn_log_entry_t entries[4];
	fzn_record_t rec;
	const fzn_log_entry_t *got;
	const fzn_log_entry_t *page[8];
	uint8_t alice[FZN_PUBKEY_LEN], bob[FZN_PUBKEY_LEN];
	uint64_t first, last;

	memset(alice, 0xa1, sizeof(alice));
	memset(bob, 0xb2, sizeof(bob));
	for (size_t i = 0; i < 16; i++)
		memset(BODIES[i], (int)i, sizeof(BODIES[0]));

	expect_err(fzn_log_init(NULL, entries, 4), FZN_LOG_ERR_MALFORMED, "a null log");
	expect_err(fzn_log_init(&log, NULL, 4), FZN_LOG_ERR_MALFORMED, "null entries");
	expect_err(fzn_log_init(&log, entries, 0), FZN_LOG_ERR_MALFORMED, "zero capacity");
	expect_err(fzn_log_init(&log, entries, 4), FZN_LOG_OK, "a well-formed log");

	fzn_log_range(&log, alice, 0, &first, &last);
	expect(first == 0 && last == 0, "an empty log holds no range");
	expect_err(fzn_log_get(&log, alice, 0, 1, &got), FZN_LOG_ERR_ABSENT,
	           "asking an empty log for anything");

	/* APPEND, AND WHAT IS HELD. */
	for (uint64_t seq = 1; seq <= 3; seq++) {
		make(&rec, 0xa1, seq);
		expect_err(fzn_log_append(&log, &rec), FZN_LOG_OK, "appending in order");
	}
	fzn_log_range(&log, alice, 0, &first, &last);
	expect(first == 1 && last == 3, "the range should be one to three");
	expect_err(fzn_log_get(&log, alice, 0, 2, &got), FZN_LOG_OK, "fetching a held entry");
	expect(got != NULL && got->seq == 2, "and it is the right one");
	expect_err(fzn_log_get(&log, alice, 0, 9, &got), FZN_LOG_ERR_ABSENT,
	           "asking beyond the newest");

	make(&rec, 0xa1, 2);
	expect_err(fzn_log_append(&log, &rec), FZN_LOG_ERR_DUPLICATE, "appending one held already");

	/* EVICTION. A log evicts where a journal refuses, because losing its
	 * oldest is a log's normal condition rather than a failure. */
	expect(fzn_log_dropped(&log) == 0, "nothing dropped yet");
	make(&rec, 0xa1, 4);
	expect_err(fzn_log_append(&log, &rec), FZN_LOG_OK, "the fourth fills it");
	make(&rec, 0xa1, 5);
	expect_err(fzn_log_append(&log, &rec), FZN_LOG_OK, "the fifth evicts the oldest");
	expect(fzn_log_dropped(&log) == 1, "and says that it dropped one");

	fzn_log_range(&log, alice, 0, &first, &last);
	expect(first == 2 && last == 5, "the log now starts at two");

	/* THE WHOLE POINT: two different answers for two different reasons. */
	expect_err(fzn_log_get(&log, alice, 0, 1, &got), FZN_LOG_ERR_GONE,
	           "asking for what retention removed");
	expect_err(fzn_log_get(&log, alice, 0, 6, &got), FZN_LOG_ERR_ABSENT,
	           "asking for what has not arrived");

	/* READING A RANGE, OLDEST FIRST, because a receiver admits by one and
	 * refuses a jump -- newest-first would be refused entry by entry. */
	{
		size_t n = fzn_log_read_since(&log, alice, 0, 2, page, 8);

		expect(n == 3, "three entries after two");
		expect(n == 3 && page[0]->seq == 3 && page[1]->seq == 4 && page[2]->seq == 5,
		       "and they must be oldest first");
	}
	expect(fzn_log_read_since(&log, alice, 0, 5, page, 8) == 0, "nothing after the newest");
	expect(fzn_log_read_since(&log, alice, 0, 0, page, 2) == 2, "a bounded read stops at its cap");

	/* ANOTHER ISSUER IS A SEPARATE STREAM. */
	expect(fzn_log_read_since(&log, bob, 0, 0, page, 8) == 0, "an unheard issuer has nothing");
	fzn_log_range(&log, bob, 0, &first, &last);
	expect(first == 0 && last == 0, "and no range");
	make(&rec, 0xb2, 1);
	expect_err(fzn_log_append(&log, &rec), FZN_LOG_OK, "bob's first entry");
	expect(fzn_log_read_since(&log, bob, 0, 0, page, 8) == 1, "which is bob's alone");

	/* Arguments. */
	expect_err(fzn_log_append(&log, NULL), FZN_LOG_ERR_MALFORMED, "a null record");
	expect_err(fzn_log_append(NULL, &rec), FZN_LOG_ERR_MALFORMED, "a null log to append to");
	make(&rec, 0xa1, 0);
	expect_err(fzn_log_append(&log, &rec), FZN_LOG_ERR_MALFORMED, "sequence zero");
	make(&rec, 0xa1, 9);
	rec.body = NULL;
	rec.body_len = 4;
	expect_err(fzn_log_append(&log, &rec), FZN_LOG_ERR_MALFORMED,
	           "a null body of non-zero length");
	expect_err(fzn_log_get(&log, alice, 0, 0, &got), FZN_LOG_ERR_MALFORMED, "asking for zero");
	expect_err(fzn_log_get(&log, alice, 0, 1, NULL), FZN_LOG_ERR_MALFORMED, "nowhere to answer");
	expect(fzn_log_read_since(&log, alice, 0, 0, page, 0) == 0, "a zero-capacity read");
	expect(fzn_log_read_since(NULL, alice, 0, 0, page, 8) == 0, "reading a null log");
	expect(fzn_log_dropped(NULL) == 0, "a null log dropped nothing");
	fzn_log_range(NULL, alice, 0, &first, &last);
	expect(first == 0 && last == 0, "a null log has no range");

	printf("log_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
