/* attachment_test -- a file sent in a conversation, its reference
 * fuzznet's, sec 794: written as `fzn:file/`, read as that or as
 * fuzzypickles' `fzp:file/`, and every name or size the format will not
 * carry refused rather than cleaned. */
#include "../attachment.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL attachment_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

#define ROOT "0101010101010101010101010101010101010101010101010101010101010101"
#define KEY "0202020202020202020202020202020202020202020202020202020202020202"

static int parses(const char *text, fzn_attachment_t *a)
{
	return fzn_attachment_parse(text, strlen(text), a);
}

static void test_written_and_read_back(void)
{
	fzn_attachment_t a, b;
	char out[FZN_ATTACHMENT_REF_MAX + 1u];
	size_t len = 0;

	memset(&a, 0, sizeof(a));
	memset(a.root, 0x01, sizeof(a.root));
	memset(a.key, 0x02, sizeof(a.key));
	a.size = 1048576u;
	memcpy(a.name, "holiday photo.jpg", 17u);
	a.name_len = 17u;
	CHECK(fzn_attachment_format(&a, out, sizeof(out), &len)
	              && strcmp(out, "fzn:file/" ROOT "/" KEY "/1048576 holiday photo.jpg") == 0
	              && len == strlen(out),
	      "written under fzn:, its root and key in hex, the size, a space and the name");
	CHECK(parses(out, &b) && memcmp(&a, &b, sizeof(a)) == 0, "and read back as it was");
	CHECK(parses("fzp:file/" ROOT "/" KEY "/1048576 holiday photo.jpg", &b)
	              && memcmp(&a, &b, sizeof(a)) == 0,
	      "fuzzypickles' fzp: reference reads as the same file");
	CHECK(parses("fzn:file/" ROOT "/" KEY "/0 empty", &b) && b.size == 0u,
	      "an empty file is a file");
	CHECK(parses("fzn:file/" ROOT "/" KEY "/18446744073709551615 big", &b)
	              && b.size == 18446744073709551615ull,
	      "the largest size a u64 holds");
	CHECK(!fzn_attachment_format(&a, out, 40u, &len), "a room too small is refused, not cut");
}

static void test_what_is_refused(void)
{
	static const char *const BAD[] = {
		"fzn:file/",
		"fzx:file/" ROOT "/" KEY "/1 a",
		"fzn:file/" ROOT "/" KEY "/1",
		"fzn:file/" ROOT "/" KEY "/1 ",
		"fzn:file/" ROOT "/" KEY "/ a",
		"fzn:file/" ROOT "/" KEY "/01 a",
		"fzn:file/" ROOT "/" KEY "/18446744073709551616 a",
		"fzn:file/" ROOT "/" KEY "/123456789012345678901 a",
		"fzn:file/" ROOT "/" KEY "/1 ../etc",
		"fzn:file/" ROOT "/" KEY "/1 .hidden",
		"fzn:file/" ROOT "/" KEY "/1 a/b",
		"fzn:file/" ROOT "/" KEY "/1 a\\b",
		"fzn:file/" ROOT "/" KEY "/1 a\nb",
		"fzn:file/" ROOT "/" KEY "/1  lead",
		"fzn:file/" ROOT "/" KEY "/1 trail ",
		"fzn:file/" ROOT "/" KEY "/1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"fzn:file/0101/" KEY "/1 a",
		"fzn:file/" ROOT KEY "/1 a",
		"fzn:file/" ROOT "/" KEY "x1 a",
		"fzn:file/" "g101010101010101010101010101010101010101010101010101010101010101" "/" KEY
		"/1 a",
		"hello there",
	};
	fzn_attachment_t a;
	size_t i;
	int all = 1;

	for (i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
		int refused = !parses(BAD[i], &a);

		if (!refused)
			printf("    taken: %s\n", BAD[i]);
		all &= refused;
	}
	CHECK(all, "a wrong scheme, a missing name, a size with a leading zero or past a u64, a "
	           "name that climbs, hides, separates, breaks a line or is past 64 bytes, and "
	           "hex that is short, missing its separator or not hex are refused");
	memset(&a, 0, sizeof(a));
	memcpy(a.name, "../x", 4u);
	a.name_len = 4u;
	{
		char out[FZN_ATTACHMENT_REF_MAX + 1u];
		size_t len = 0;

		CHECK(!fzn_attachment_format(&a, out, sizeof(out), &len) && (a.name_len = 0u, 1)
		              && !fzn_attachment_format(&a, out, sizeof(out), &len),
		      "and no name it would refuse is written, an empty one neither");
	}
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_written_and_read_back();
	test_what_is_refused();
	test_the_suite_can_tell_pass_from_fail();
	printf("attachment_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
