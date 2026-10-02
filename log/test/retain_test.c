/* retain_test -- the prune and keep rules: their lines, and the plan over a
 * program's closed segments. sec 460. */

#include "../retain.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL retain_test.c:%d: %s\n", __LINE__, what);      \
		}                                                                              \
	} while (0)

#define DAY (86400ull * 1000000ull)

static fzn_retain_rule_t rule(const char *line)
{
	fzn_retain_rule_t r;

	if (fzn_retain_parse(line, strlen(line), &r) != FZN_RETAIN_OK)
		memset(&r, 0, sizeof(r));
	return r;
}

/* Which of `n` go, as a string of 0 and 1 in the segments' own order. */
static const char *plan(const fzn_retain_segment_t *s, size_t n, const fzn_retain_rule_t *r,
                        size_t nr, uint64_t now)
{
	static char out[64];
	uint8_t gone[16];
	size_t i;

	if (fzn_retain_plan("netcfgd", s, n, r, nr, now, gone) != FZN_RETAIN_OK)
		return "refused";
	for (i = 0; i < n; i++)
		out[i] = (char)('0' + gone[i]);
	out[n] = '\0';
	return out;
}

static void test_lines(void)
{
	fzn_retain_rule_t r;

	CHECK(fzn_retain_parse("prune * age 30d", 15u, &r) == FZN_RETAIN_OK
	              && r.kind == FZN_RETAIN_PRUNE && strcmp(r.program, "*") == 0
	              && r.limit == FZN_RETAIN_AGE && r.value == 30u * DAY,
	      "prune every program older than 30 days");
	CHECK(fzn_retain_parse("keep netcfgd size 100M\n", 23u, &r) == FZN_RETAIN_OK
	              && r.kind == FZN_RETAIN_KEEP && strcmp(r.program, "netcfgd") == 0
	              && r.limit == FZN_RETAIN_SIZE && r.value == 100u * 1024u * 1024u,
	      "keep netcfgd's newest 100 MiB, with its newline");
	CHECK(fzn_retain_parse("prune fuzznetd count 5", 22u, &r) == FZN_RETAIN_OK
	              && r.limit == FZN_RETAIN_COUNT && r.value == 5u,
	      "prune past fuzznetd's newest 5 segments");
	CHECK(fzn_retain_parse("prune * age 90", 14u, &r) == FZN_RETAIN_OK
	              && r.value == 90u * 1000000u,
	      "a bare age is seconds");
	{
		static const char *const BAD[] = {
			"trim * age 1d",         "prune * age",           "prune * age 1d extra",
			"prune * count 5d",      "prune * size 5d",       "prune * age 5K",
			"prune a/b age 1d",      "prune * age 99999999999999999999d",
			"prune * age d",         "",                      "prune * weight 1",
		};
		size_t i;
		int all = 1;

		for (i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++)
			all = all && fzn_retain_parse(BAD[i], strlen(BAD[i]), &r) == FZN_RETAIN_ERR_MALFORMED;
		CHECK(all, "an unknown kind or limit, a missing or extra word, a unit the limit does "
		           "not take, a slash in the program, an overflow and an empty line are refused");
	}
}

static void test_plans(void)
{
	const uint64_t now = 100u * DAY;
	/* Closed 1, 5 and 10 days ago, 100 bytes each, oldest first. */
	const fzn_retain_segment_t s[3] = { { now - (10u * DAY), 100u },
		                            { now - (5u * DAY), 100u },
		                            { now - (1u * DAY), 100u } };
	fzn_retain_rule_t r[3];

	memset(r, 0, sizeof(r));
	CHECK(strcmp(plan(s, 3u, r, 0u, now), "000") == 0, "no rules, nothing goes");
	r[0] = rule("prune * age 7d");
	CHECK(strcmp(plan(s, 3u, r, 1u, now), "100") == 0,
	      "prune older than 7 days takes the ten-day-old segment");
	/* THE HOLDER'S EXAMPLE: keep expands. */
	r[1] = rule("keep * age 30d");
	CHECK(strcmp(plan(s, 3u, r, 2u, now), "000") == 0,
	      "with keep 30 days beside it, the ten-day-old segment stays: keep expands");
	r[0] = rule("prune * count 2");
	CHECK(strcmp(plan(s, 3u, r, 1u, now), "100") == 0, "prune past the newest two");
	r[0] = rule("prune * size 150");
	CHECK(strcmp(plan(s, 3u, r, 1u, now), "100") == 0,
	      "prune past the newest 150 bytes keeps the segment straddling the limit");
	/* EVERY PRUNE RULE APPLIES: the strictest decides. */
	r[0] = rule("prune * age 30d");
	r[1] = rule("prune * count 1");
	CHECK(strcmp(plan(s, 3u, r, 2u, now), "110") == 0,
	      "two prune rules both apply, so the stricter decides");
	r[2] = rule("keep * count 2");
	CHECK(strcmp(plan(s, 3u, r, 3u, now), "100") == 0,
	      "and a keep rule protects what it covers from both");
	r[0] = rule("prune fuzznetd age 0");
	CHECK(strcmp(plan(s, 3u, r, 1u, now), "000") == 0, "a rule for another program does not apply");
	r[0] = rule("prune netcfgd age 0");
	CHECK(strcmp(plan(s, 3u, r, 1u, now), "111") == 0, "one naming this program does");
	/* ORDER DOES NOT MATTER: the same segments shuffled. */
	{
		const fzn_retain_segment_t t[3] = { s[2], s[0], s[1] };

		r[0] = rule("prune * count 2");
		CHECK(strcmp(plan(t, 3u, r, 1u, now), "010") == 0,
		      "the segments shuffled, the oldest is still the one that goes");
	}
	r[0].kind = (fzn_retain_kind_t)3;
	CHECK(strcmp(plan(s, 3u, r, 1u, now), "refused") == 0, "a rule that is not one is refused");
}

int main(void)
{
	test_lines();
	test_plans();
	if (failures) {
		fprintf(stderr, "retain_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("retain_test: all %d checks passed\n", checks);
	return 0;
}
