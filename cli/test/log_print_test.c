/* Tests for cli/log_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is the one a terminal makes worse than a
 * screen. `log/log.h` says a body is opaque bytes and must be escaped, and
 * gives two reasons: a newline draws a second entry no issuer signed, and an
 * escape byte drives the terminal the log is printed on. A widget handed an
 * escape byte displays something wrong; a terminal OBEYS it. So both are
 * tested here, and the escape case is the one that only exists on this side.
 *
 * The other is the eviction case, which a viewer gets wrong by omission: a
 * log that has dropped entries must say so, or a reader is handed a shorter
 * history presented as a complete one. project.md sec 141 and sec 167.
 */

#include "../log_print.h"

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
	fprintf(stderr, "  FAIL log_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* ---- a signer, so the fixtures are real records ------------------------ */

static void tag(uint8_t out[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	uint64_t h = 1469598103934665603u;
	size_t i;

	for (i = 0; i < msg_len; i++) {
		h ^= msg[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i;
		h *= 1099511628211u;
		out[i] = (uint8_t)(h >> 32);
	}
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	tag(sig, msg, msg_len);
	return 1;
}

static uint8_t ISSUER[FZN_PUBKEY_LEN];
static uint8_t SUBJECT[FZN_SUBJECT_LEN];
static uint8_t SLOTS[8][FZN_RECORD_MAX_LEN];

static int make_from(fzn_record_t *r, const uint8_t *issuer, size_t which, uint64_t seq,
                     const uint8_t *body, size_t body_len)
{
	fzn_sign_ops_t ops;
	size_t wrote = 0;

	memset(&ops, 0, sizeof(ops));
	ops.sign = stub_sign;
	if (fzn_record_sign(issuer, SUBJECT, 5u, 3u, seq, 1u, body, body_len, &ops,
	                    SLOTS[which], FZN_RECORD_MAX_LEN, &wrote) != FZN_RECORD_OK)
		return 0;
	return fzn_record_open(SLOTS[which], wrote, r) == FZN_RECORD_OK;
}

static int make(fzn_record_t *r, size_t which, uint64_t seq, const uint8_t *body,
                size_t body_len)
{
	return make_from(r, ISSUER, which, seq, body, body_len);
}

static size_t lines_in(const char *text)
{
	size_t n = 0;

	while (*text)
		if (*text++ == '\n')
			n++;
	return n;
}

int main(void)
{
	static char out[FZN_LOG_PRINT_MAX(8)];
	fzn_log_entry_t rows[4];
	fzn_journal_entry_t positions[2];
	fzn_log_t log;
	fzn_journal_t journal;
	fzn_record_t rec;
	size_t len = 0;
	uint64_t seq;

	memset(ISSUER, 0xa1, sizeof(ISSUER));
	memset(SUBJECT, 0x51, sizeof(SUBJECT));

	CHECK(fzn_log_init(&log, rows, 4) == FZN_LOG_OK, "the log would not init");
	CHECK(fzn_journal_init(&journal, positions, 2) == FZN_JOURNAL_OK,
	      "the journal would not init");
	CHECK(fzn_journal_anchor(&journal, ISSUER, 5u, 0u) == FZN_JOURNAL_OK,
	      "the stream could not be followed");

	/* A NULL ARGUMENT REFUSES, and leaves nothing to retry with -- a
	 * caller cannot size its way out of a null pointer. */
	len = 12345u;
	CHECK(fzn_log_print(NULL, &journal, ISSUER, 5u, 4u, out, sizeof(out), &len) ==
	              FZN_LOG_ERR_MALFORMED,
	      "a null log was rendered");
	CHECK(len == 0u, "a null argument set a size to retry with");

	/* AN EMPTY LOG SAYS SO. */
	CHECK(fzn_log_print(&log, &journal, ISSUER, 5u, 4u, out, sizeof(out), &len) ==
	              FZN_LOG_OK,
	      "an empty log would not render");
	CHECK(strstr(out, "nothing held") != NULL, "an empty log did not say it holds nothing");
	CHECK(lines_in(out) == 1u, "an empty log printed entry lines");

	/* Three printable entries, held in full. */
	for (seq = 1u; seq <= 3u; seq++) {
		const uint8_t body[3] = { 'a', (uint8_t)('0' + seq), 'z' };

		CHECK(make(&rec, (size_t)seq, seq, body, sizeof(body)),
		      "the fixture could not build a record");
		CHECK(fzn_log_append(&log, &rec) == FZN_LOG_OK, "append refused");
		CHECK(fzn_journal_admit(&journal, ISSUER, 5u, seq) == FZN_JOURNAL_OK,
		      "the journal refused the record");
	}

	CHECK(fzn_log_print(&log, &journal, ISSUER, 5u, 4u, out, sizeof(out), &len) ==
	              FZN_LOG_OK,
	      "a held log would not render");
	CHECK(lines_in(out) == 4u, "three entries did not produce a summary and three lines");
	CHECK(strstr(out, "1 to 3; complete") != NULL, "a complete log was not called complete");
	CHECK(strstr(out, "a1z") != NULL && strstr(out, "a3z") != NULL,
	      "an entry body is missing");
	CHECK(len == strlen(out), "the reported length is not the string's");

	/* OLDEST FIRST, which is the order a receiver can admit them in. */
	CHECK(strstr(out, "a1z") < strstr(out, "a3z"), "entries are not oldest first");

	/* THE SUMMARY-ONLY CALL. `rows = 0` is the health check's question,
	 * and it must not answer "nothing held" about a log that is full. */
	CHECK(fzn_log_print(&log, &journal, ISSUER, 5u, 0u, out, sizeof(out), &len) ==
	              FZN_LOG_OK,
	      "a summary-only render refused");
	CHECK(lines_in(out) == 1u, "a summary-only render printed entries");
	CHECK(strstr(out, "nothing held") == NULL,
	      "asking for no rows reported a full log as holding nothing");
	CHECK(strstr(out, "1 to 3") != NULL, "the summary-only render lost the range");

	/* A WINDOW IS SAID, AND IT IS THE TAIL. Two of three, and the two
	 * shown must be the NEWEST or the word in the summary is wrong. */
	CHECK(fzn_log_print(&log, &journal, ISSUER, 5u, 2u, out, sizeof(out), &len) ==
	              FZN_LOG_OK,
	      "a windowed render refused");
	CHECK(strstr(out, "showing 2 newest") != NULL, "a shortened window was not declared");
	CHECK(strstr(out, "a3z") != NULL, "the newest entry is not in the window");
	CHECK(strstr(out, "a1z") == NULL, "the window showed the oldest, not the newest");

	/* THE INJECTION CASE. A body carrying a newline and a plausible
	 * sequence must not draw a fourth entry that nobody signed. */
	{
		const uint8_t nasty[] = { 'x', '\n', '9', '9', ' ', ' ', 'f', 'o', 'r', 'g', 'e',
			                  'd' };

		CHECK(make(&rec, 4u, 4u, nasty, sizeof(nasty)),
		      "the fixture could not build the injection record");
		CHECK(fzn_log_append(&log, &rec) == FZN_LOG_OK, "append refused");
		CHECK(fzn_journal_admit(&journal, ISSUER, 5u, 4u) == FZN_JOURNAL_OK,
		      "the journal refused the record");

		CHECK(fzn_log_print(&log, &journal, ISSUER, 5u, 4u, out, sizeof(out), &len) ==
		              FZN_LOG_OK,
		      "the injection log would not render");
		CHECK(lines_in(out) == 5u,
		      "a body with a newline in it drew an entry no issuer signed");
		CHECK(strstr(out, "\n99  forged") == NULL, "the forged line is on the screen");
		CHECK(strstr(out, "\\x0a") != NULL, "the newline was not escaped");
	}

	/* THE CASE THAT ONLY EXISTS ON A TERMINAL. An escape byte in a body
	 * must not reach the output, where it would be obeyed rather than
	 * shown -- clearing the screen, or moving the cursor back over the
	 * summary that says entries were evicted. */
	{
		const uint8_t esc[] = { 0x1b, '[', '2', 'J', 0x1b, '[', 'H' };
		size_t i;
		int raw = 0;

		CHECK(make(&rec, 5u, 5u, esc, sizeof(esc)),
		      "the fixture could not build the escape record");
		CHECK(fzn_log_append(&log, &rec) == FZN_LOG_OK, "append refused");
		CHECK(fzn_journal_admit(&journal, ISSUER, 5u, 5u) == FZN_JOURNAL_OK,
		      "the journal refused the record");

		CHECK(fzn_log_print(&log, &journal, ISSUER, 5u, 4u, out, sizeof(out), &len) ==
		              FZN_LOG_OK,
		      "the escape log would not render");
		for (i = 0; i < len; i++)
			if ((unsigned char)out[i] == 0x1bu)
				raw = 1;
		CHECK(!raw, "an escape byte from a body reached the terminal");
		CHECK(strstr(out, "\\x1b") != NULL, "the escape byte was not escaped");
	}

	/* EVICTION IS NAMED. The log holds four; five have been received. */
	CHECK(fzn_log_print(&log, &journal, ISSUER, 5u, 4u, out, sizeof(out), &len) ==
	              FZN_LOG_OK,
	      "the evicted log would not render");
	CHECK(strstr(out, "evicted") != NULL,
	      "a log that dropped an entry was presented as a complete history");

	/* A BODY THAT WILL NOT RENDER IS SAID, NOT SKIPPED. The entries are
	 * caller-owned memory, so a length past the maximum is reachable --
	 * and a row silently missing is indistinguishable from a record that
	 * was never appended. */
	{
		size_t before = 0;
		size_t after = 0;

		CHECK(fzn_log_print(&log, &journal, ISSUER, 5u, 4u, out, sizeof(out), &len) ==
		              FZN_LOG_OK,
		      "the log would not render before the corruption");
		before = lines_in(out);

		rows[0].body_len = (size_t)FZN_RECORD_BODY_MAX + 1u;

		CHECK(fzn_log_print(&log, &journal, ISSUER, 5u, 4u, out, sizeof(out), &len) ==
		              FZN_LOG_OK,
		      "an unrenderable body stopped the whole render");
		after = lines_in(out);
		CHECK(after == before, "an unrenderable body cost a line rather than gaining a note");
		CHECK(strstr(out, "(unrenderable body)") != NULL,
		      "an unrenderable body was skipped rather than said");
	}

	/* IT REFUSES RATHER THAN TRUNCATES, and says what it needed. */
	{
		char small[24];
		size_t needed = 0;

		memset(small, '@', sizeof(small));
		CHECK(fzn_log_print(&log, &journal, ISSUER, 5u, 4u, small, sizeof(small),
		                    &needed) == FZN_LOG_ERR_MALFORMED,
		      "a buffer that could not hold the result was written anyway");
		CHECK(needed > sizeof(small), "the size needed was not reported");
		CHECK(small[0] == '@' && small[sizeof(small) - 1u] == '@',
		      "a refused render left bytes in the caller's buffer");

		/* And the size it asked for is one that works. */
		CHECK(needed <= sizeof(out), "the fixture buffer cannot hold the retry");
		CHECK(fzn_log_print(&log, &journal, ISSUER, 5u, 4u, out, needed, &len) ==
		              FZN_LOG_OK,
		      "the size it asked for was not enough");
		CHECK(len + 1u == needed, "the retry did not produce exactly what was promised");
	}

	/* A WINDOW LARGER THAN THIS WILL RENDER REFUSES rather than clamping,
	 * because a silent clamp is the unmarked shortening this module
	 * refuses everywhere else. */
	CHECK(fzn_log_print(&log, &journal, ISSUER, 5u, FZN_LOG_PRINT_WINDOW_MAX + 1u, out,
	                    sizeof(out), &len) == FZN_LOG_ERR_MALFORMED,
	      "an oversized window was quietly clamped");

	/* THE CASE THE JOURNAL IS A PARAMETER FOR, and the only one that
	 * needs it. Eviction inside a stream is visible from the range alone
	 * -- `first > 1` says seqs below it are gone -- so every case above
	 * would pass with the journal ignored entirely. When a stream is
	 * evicted ENTIRELY the range is all zeroes and the log knows nothing;
	 * only the journal can say that five records were received and are
	 * now gone, rather than that this host never followed the issuer.
	 *
	 * A second issuer fills the log to push the first one out, which is
	 * how a real host loses a quiet stream to a noisy one. */
	{
		static uint8_t other[FZN_PUBKEY_LEN];
		size_t i;

		memset(other, 0xb2, sizeof(other));
		CHECK(fzn_journal_anchor(&journal, other, 5u, 0u) == FZN_JOURNAL_OK,
		      "the second stream could not be followed");

		for (i = 1u; i <= 4u; i++) {
			const uint8_t body[2] = { 'q', (uint8_t)('0' + i) };

			CHECK(make_from(&rec, other, 6u, (uint64_t)i, body, sizeof(body)),
			      "the fixture could not build the crowding record");
			CHECK(fzn_log_append(&log, &rec) == FZN_LOG_OK, "append refused");
		}

		CHECK(fzn_log_print(&log, &journal, ISSUER, 5u, 4u, out, sizeof(out), &len) ==
		              FZN_LOG_OK,
		      "an entirely evicted stream would not render");
		CHECK(strstr(out, "nothing held") != NULL,
		      "an entirely evicted stream did not say it holds nothing");
		CHECK(strstr(out, "5 received and evicted") != NULL,
		      "an entirely evicted stream lost the count only the journal knows, so "
		      "a reader cannot tell it from a stream this host never followed");
	}

	/* AND AN UNFOLLOWED STREAM IS NOT AN EVICTED ONE. Same empty log,
	 * an issuer nobody follows: the journal has nothing to report and the
	 * summary must not invent a loss. */
	{
		static uint8_t stranger[FZN_PUBKEY_LEN];

		memset(stranger, 0xc3, sizeof(stranger));
		CHECK(fzn_log_print(&log, &journal, stranger, 5u, 4u, out, sizeof(out),
		                    &len) == FZN_LOG_OK,
		      "an unfollowed stream would not render");
		CHECK(strstr(out, "nothing held") != NULL,
		      "an unfollowed stream did not say it holds nothing");
		CHECK(strstr(out, "evicted") == NULL,
		      "a stream this host never followed was reported as having lost "
		      "entries");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("log_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
