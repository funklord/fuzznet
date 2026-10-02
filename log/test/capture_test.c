/* capture_test -- an external program's output made into entries: one line
 * one entry, escaped so it cannot forge a line or steer a terminal, bounded
 * per line and per invocation with both bounds said, and a closing entry
 * that says how the tool ended. sec 441. */

#include "../capture.h"

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
	fprintf(stderr, "  FAIL capture_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

/* ---- what was emitted ----------------------------------------------------- */

#define SEEN_MAX 16u

static struct seen {
	fzn_capture_stream_t stream;
	fzn_capture_level_t level;
	char text[FZN_CAPTURE_TEXT_MAX];
	size_t text_len;
	size_t cut;
	int unterminated;
} seen[SEEN_MAX];
static size_t seen_count;

static void collect(void *ctx, const fzn_capture_entry_t *e)
{
	(void)ctx;
	if (seen_count >= SEEN_MAX)
		return;
	seen[seen_count].stream = e->stream;
	seen[seen_count].level = e->level;
	memcpy(seen[seen_count].text, e->text, e->text_len + 1u);
	seen[seen_count].text_len = e->text_len;
	seen[seen_count].cut = e->cut;
	seen[seen_count].unterminated = e->unterminated;
	seen_count++;
}

static fzn_capture_t cap;

static void start(size_t volume_max)
{
	seen_count = 0;
	CHECK(fzn_capture_init(&cap, collect, NULL, fzn_capture_rule_default(), volume_max)
	              == FZN_CAPTURE_OK,
	      "fixture: a capture starts");
}

static void out(const char *s)
{
	(void)fzn_capture_feed(&cap, FZN_CAPTURE_STDOUT, (const uint8_t *)s, strlen(s));
}

static void err(const char *s)
{
	(void)fzn_capture_feed(&cap, FZN_CAPTURE_STDERR, (const uint8_t *)s, strlen(s));
}

static int text_is(size_t i, const char *want)
{
	return i < seen_count && !strcmp(seen[i].text, want);
}

/* ---- cases --------------------------------------------------------------- */

static void test_lines(void)
{
	start(0);
	out("first\nsecond\n");
	CHECK(seen_count == 2u && text_is(0, "first") && text_is(1, "second"),
	      "two lines are two entries");
	CHECK(seen[0].stream == FZN_CAPTURE_STDOUT && seen[0].level == FZN_CAPTURE_INFO,
	      "stdout is information by default");
	start(0);
	out("hel");
	out("lo\n");
	CHECK(seen_count == 1u && text_is(0, "hello"), "a line split across two reads is one entry");
	start(0);
	out("a");
	err("warned\n");
	out("b\n");
	CHECK(seen_count == 2u && text_is(0, "warned") && seen[0].stream == FZN_CAPTURE_STDERR
	              && seen[0].level == FZN_CAPTURE_WARNING && text_is(1, "ab"),
	      "each stream keeps its own part line, and stderr is a warning");
	start(0);
	out("\n");
	CHECK(seen_count == 1u && text_is(0, ""), "an empty line is still a line");
	start(0);
	out("x\r\ny\rz\n");
	CHECK(seen_count == 2u && text_is(0, "x") && text_is(1, "y\\x0dz"),
	      "\\r\\n ends a line, and a lone \\r is escaped text");
	start(0);
	out("x\r");
	out("\n");
	CHECK(seen_count == 1u && text_is(0, "x"), "even when the \\r and \\n arrive apart");
	start(0);
	out("done\nlast");
	CHECK(seen_count == 1u, "a line with no newline waits");
	CHECK(fzn_capture_finish(&cap) == FZN_CAPTURE_OK && seen_count == 2u && text_is(1, "last")
	              && seen[1].unterminated && !seen[0].unterminated,
	      "and is emitted at the end, marked unterminated");
	start(0);
	out("ends\r");
	CHECK(fzn_capture_finish(&cap) == FZN_CAPTURE_OK && seen_count == 1u
	              && text_is(0, "ends\\x0d"),
	      "a trailing \\r with nothing after it is text");
	{
		fzn_capture_rule_t r = { FZN_CAPTURE_DEBUG, FZN_CAPTURE_ERROR };

		seen_count = 0;
		CHECK(fzn_capture_init(&cap, collect, NULL, r, 0) == FZN_CAPTURE_OK,
		      "fixture: a caller's own rule");
		out("o\n");
		err("e\n");
		CHECK(seen[0].level == FZN_CAPTURE_DEBUG && seen[1].level == FZN_CAPTURE_ERROR,
		      "the caller's rule decides each stream's level");
	}
}

static void test_escaping(void)
{
	start(0);
	out("ok\n2026-10-01T12:34:56Z nabbe root fuzznetd 1@2 #3 forged\n");
	CHECK(seen_count == 2u && text_is(1, "2026-10-01T12:34:56Z nabbe root fuzznetd 1@2 #3 forged"),
	      "a line shaped like an entry is one entry of the tool's, not a second line of ours");
	start(0);
	out("\x1b[31mred\x1b[0m\n");
	CHECK(text_is(0, "\\x1b[31mred\\x1b[0m"), "a terminal escape is written as bytes");
	start(0);
	(void)fzn_capture_feed(&cap, FZN_CAPTURE_STDOUT, (const uint8_t *)"a\0b\n", 4u);
	CHECK(text_is(0, "a\\x00b"), "a NUL is written as a byte");
	start(0);
	out("C:\\path\x7f\n");
	CHECK(text_is(0, "C:\\x5cpath\\x7f"), "a backslash and DEL are escaped, so \\x reads back");
	start(0);
	out("caf\xc3\xa9 \xe2\x82\xac\n");
	CHECK(text_is(0, "caf\xc3\xa9 \xe2\x82\xac"), "valid UTF-8 passes as it is");
	start(0);
	out("\xff\xc0\xaf\xed\xa0\x80\n");
	CHECK(text_is(0, "\\xff\\xc0\\xaf\\xed\\xa0\\x80"),
	      "invalid UTF-8, an overlong form and a surrogate are bytes");
	start(0);
	out("\xc2\x9b" "2J\xe2\x80\xa8x\n");
	CHECK(text_is(0, "\\xc2\\x9b2J\\xe2\\x80\\xa8x"),
	      "a C1 control and a Unicode line separator are escaped though valid");
	{
		char o[8];

		CHECK(fzn_capture_escape((const uint8_t *)"\x01\x02", 2u, o, 6u) == 4u
		              && !strcmp(o, "\\x01"),
		      "a short buffer gets whole escapes and never half of one");
		CHECK(fzn_capture_escape((const uint8_t *)"abc", 3u, o, 1u) == 0u && o[0] == '\0',
		      "room for only the NUL is an empty text");
	}
}

static void test_bounds(void)
{
	static char line[FZN_CAPTURE_LINE_MAX + 905u];
	char sum[256];
	fzn_capture_level_t level;

	memset(line, 'a', sizeof(line) - 2u);
	line[sizeof(line) - 2u] = '\n';
	line[sizeof(line) - 1u] = '\0';
	start(0);
	out(line);
	CHECK(seen_count == 1u && seen[0].text_len == FZN_CAPTURE_LINE_MAX && seen[0].cut == 903u,
	      "a long line keeps the bound and counts the rest");
	CHECK(fzn_capture_summary(&cap, FZN_CAPTURE_EXITED, 0, 3u, sum, sizeof(sum), &level)
	                      == FZN_CAPTURE_OK
	              && !strcmp(sum, "exit 0 after 3 ms, 1 line; 903 bytes of long lines not kept"),
	      "and the summary says how much was not kept");

	start(2);
	out("1\n22\n333\n4444\n55555\n");
	CHECK(seen_count == 2u && text_is(1, "22"), "past the volume bound, nothing is emitted");
	CHECK(fzn_capture_summary(&cap, FZN_CAPTURE_EXITED, 0, 9u, sum, sizeof(sum), &level)
	                      == FZN_CAPTURE_OK
	              && !strcmp(sum, "exit 0 after 9 ms, 5 lines; 3 lines, 12 bytes past the bound "
	                              "not kept"),
	      "and the summary counts every line, and the ones not kept");
}

static void test_summary(void)
{
	char sum[96];
	fzn_capture_level_t level = FZN_CAPTURE_DEBUG;

	start(0);
	out("RTNETLINK answers: File exists\n");
	CHECK(fzn_capture_summary(&cap, FZN_CAPTURE_EXITED, 2, 14u, sum, sizeof(sum), &level)
	                      == FZN_CAPTURE_OK
	              && !strcmp(sum, "exit 2 after 14 ms, 1 line") && level == FZN_CAPTURE_ERROR,
	      "a nonzero exit is an error, worded as sec 428 drew it");
	CHECK(fzn_capture_summary(&cap, FZN_CAPTURE_EXITED, 0, 14u, sum, sizeof(sum), &level)
	                      == FZN_CAPTURE_OK
	              && level == FZN_CAPTURE_INFO,
	      "exit 0 is information");
	CHECK(fzn_capture_summary(&cap, FZN_CAPTURE_SIGNALLED, 9, 5u, sum, sizeof(sum), &level)
	                      == FZN_CAPTURE_OK
	              && !strcmp(sum, "killed by signal 9 after 5 ms, 1 line")
	              && level == FZN_CAPTURE_ERROR,
	      "a signal is said and is an error");
	CHECK(fzn_capture_summary(&cap, FZN_CAPTURE_TIMED_OUT, 0, 5000u, sum, sizeof(sum), &level)
	                      == FZN_CAPTURE_OK
	              && !strcmp(sum, "stopped at its deadline after 5000 ms, 1 line")
	              && level == FZN_CAPTURE_ERROR,
	      "a deadline is said, and an exit code 0 beside it does not make it a success");
	start(0);
	CHECK(fzn_capture_summary(&cap, FZN_CAPTURE_NOT_RUN, 2, 0u, sum, sizeof(sum), &level)
	                      == FZN_CAPTURE_OK
	              && !strcmp(sum, "could not be started, errno 2") && level == FZN_CAPTURE_ERROR,
	      "a tool that could not start says so, with no line count");
	CHECK(fzn_capture_summary(&cap, FZN_CAPTURE_EXITED, 0, 1u, sum, 8u, &level)
	              == FZN_CAPTURE_ERR_ROOM,
	      "a summary that does not fit is refused, not cut");
	CHECK(fzn_capture_summary(&cap, (fzn_capture_end_t)9, 0, 1u, sum, sizeof(sum), &level)
	              == FZN_CAPTURE_ERR_MALFORMED,
	      "an end that is none of them is malformed");
}

static void test_argv(void)
{
	static const char *const argv[] = { "ossacli", "ctrl", "pass word", "hunter2" };
	static const unsigned char secret[] = { 0, 0, 0, 1 };
	char line[64];

	CHECK(fzn_capture_argv(argv, 4u, secret, line, sizeof(line)) == FZN_CAPTURE_OK
	              && !strcmp(line, "ossacli ctrl pass\\x20word ***"),
	      "the invocation is one line, a space inside an argument escaped, the secret hidden");
	CHECK(fzn_capture_argv(argv, 4u, NULL, line, sizeof(line)) == FZN_CAPTURE_OK
	              && strstr(line, "hunter2") != NULL,
	      "with no secret marked, nothing is hidden -- the caller decides");
	CHECK(fzn_capture_argv(argv, 4u, secret, line, 16u) == FZN_CAPTURE_ERR_ROOM,
	      "an invocation that does not fit is refused rather than an argument cut");
	{
		const char *const holed[] = { "a", NULL };

		CHECK(fzn_capture_argv(holed, 2u, NULL, line, sizeof(line))
		              == FZN_CAPTURE_ERR_MALFORMED,
		      "a null argument is malformed");
	}
}

static void test_refusals(void)
{
	CHECK(fzn_capture_init(NULL, collect, NULL, fzn_capture_rule_default(), 0)
	              == FZN_CAPTURE_ERR_MALFORMED
	              && fzn_capture_init(&cap, NULL, NULL, fzn_capture_rule_default(), 0)
	                         == FZN_CAPTURE_ERR_MALFORMED,
	      "a capture with nowhere to emit is refused");
	start(0);
	CHECK(fzn_capture_feed(&cap, (fzn_capture_stream_t)3, (const uint8_t *)"x", 1u)
	              == FZN_CAPTURE_ERR_MALFORMED,
	      "a stream that is neither is refused");
	CHECK(fzn_capture_feed(&cap, FZN_CAPTURE_STDOUT, NULL, 1u) == FZN_CAPTURE_ERR_MALFORMED,
	      "and bytes that are not there");
}

int main(void)
{
	test_lines();
	test_escaping();
	test_bounds();
	test_summary();
	test_argv();
	test_refusals();
	if (failures) {
		fprintf(stderr, "capture_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("capture_test: all %d checks passed\n", checks);
	return 0;
}
