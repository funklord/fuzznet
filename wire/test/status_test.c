/* wire status_test -- a status between hosts, sec 1076: every code written and
 * read back, a reason carried and cut, and what is no status refused -- the
 * wrong family or type, a byte after the reason, a length that disagrees, a
 * code the schema does not name, a buffer too short. */

#include "../status.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                  \
	do {                                                                               \
		checks++;                                                                  \
		if (!(cond)) {                                                             \
			failures++;                                                        \
			fprintf(stderr, "  FAIL status_test.c:%d: %s\n", __LINE__, what);  \
		}                                                                          \
	} while (0)

static void test_every_code(void)
{
	static const fzn_status_t codes[] = { FZN_STATUS_OK,        FZN_STATUS_DENIED,
		                              FZN_STATUS_MALFORMED, FZN_STATUS_ERROR,
		                              FZN_STATUS_UNSUPPORTED, FZN_STATUS_SHEDDING,
		                              FZN_STATUS_BUSY };
	uint8_t buf[FZN_STATUS_LEN_MAX];
	size_t i, n, why_len;
	const uint8_t *why;
	fzn_status_t code;

	for (i = 0; i < sizeof(codes) / sizeof(codes[0]); i++) {
		n = fzn_status_write(buf, sizeof(buf), codes[i], NULL);
		CHECK(n == FZN_STATUS_HEAD_LEN && buf[0] == FZN_CMD_STATUS && buf[1] == (uint8_t)codes[i]
		              && buf[2] == 0u,
		      "a status with no reason is not its three bytes");
		CHECK(fzn_status_read(buf, n, &code, &why, &why_len) && code == codes[i] && why_len == 0u,
		      "a status did not read back as written");
		CHECK(strcmp(fzn_status_name(codes[i]), "unknown") != 0, "a code has no name");
	}
	CHECK(strcmp(fzn_status_name(FZN_STATUS_DENIED), "denied") == 0
	              && strcmp(fzn_status_name((fzn_status_t)42), "unknown") == 0,
	      "the names are not the words a log says");
}

static void test_a_reason(void)
{
	uint8_t buf[FZN_STATUS_LEN_MAX + 8u];
	char long_why[FZN_STATUS_WHY_MAX + 50u];
	const uint8_t *why;
	size_t n, why_len;
	fzn_status_t code;

	n = fzn_status_write(buf, sizeof(buf), FZN_STATUS_DENIED, "over this host's relay quota");
	CHECK(n == FZN_STATUS_HEAD_LEN + 28u && fzn_status_read(buf, n, &code, &why, &why_len)
	              && code == FZN_STATUS_DENIED && why_len == 28u
	              && memcmp(why, "over this host's relay quota", 28u) == 0,
	      "a reason did not come back");
	memset(long_why, 'x', sizeof(long_why) - 1u);
	long_why[sizeof(long_why) - 1u] = '\0';
	n = fzn_status_write(buf, sizeof(buf), FZN_STATUS_ERROR, long_why);
	CHECK(n == FZN_STATUS_LEN_MAX && fzn_status_read(buf, n, &code, NULL, &why_len)
	              && why_len == FZN_STATUS_WHY_MAX,
	      "a long reason was not cut to FZN_STATUS_WHY_MAX");
	CHECK(fzn_status_write(buf, FZN_STATUS_HEAD_LEN + 3u, FZN_STATUS_DENIED, "four") == 0u,
	      "a status was written past its buffer");
	CHECK(fzn_status_write(buf, sizeof(buf), (fzn_status_t)7, NULL) == 0u,
	      "a code the schema does not name was written");
}

static void test_no_status(void)
{
	uint8_t buf[FZN_STATUS_LEN_MAX + 1u];
	size_t n = fzn_status_write(buf, sizeof(buf), FZN_STATUS_DENIED, "no");
	fzn_status_t code;

	CHECK(n == 5u, "fixture: a denial with a reason of two");
	CHECK(!fzn_status_read(buf, n - 1u, &code, NULL, NULL), "a status cut short was read");
	buf[n] = 'x';
	CHECK(!fzn_status_read(buf, n + 1u, &code, NULL, NULL), "a byte after the reason was read");
	buf[0] = FZN_CMD_CALL;
	CHECK(!fzn_status_read(buf, n, &code, NULL, NULL), "another CMD's message was read");
	buf[0] = FZN_CMD_STATUS;
	buf[1] = 9u;
	CHECK(!fzn_status_read(buf, n, &code, NULL, NULL), "a code the schema does not name was read");
	buf[1] = FZN_STATUS_DENIED;
	buf[2] = 201u;
	CHECK(!fzn_status_read(buf, n, &code, NULL, NULL), "a reason length past the bytes was read");
	CHECK(!fzn_status_read((const uint8_t *)"denied no\n", 10u, &code, NULL, NULL),
	      "a text refusal was read as a status");
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
	test_every_code();
	test_a_reason();
	test_no_status();
	if (failures) {
		fprintf(stderr, "wire status_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("wire status_test: all %d checks passed\n", checks);
	return 0;
}
