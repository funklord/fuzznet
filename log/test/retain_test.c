/* retain_test -- the prune and keep rules: their lines, and the plan over a
 * program's closed segments. sec 460. Entries by level and subsystem, and
 * the walk over them, sec 474. */

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

/* ENTRY RULES, sec 474. */
static void test_entries(void)
{
	const uint64_t now = 100u * DAY;
	fzn_retain_rule_t r[4];
	fzn_retain_walk_t w;
	fzn_retain_segment_t s[2] = { { now - (40u * DAY), 1000u }, { now - DAY, 1000u } };
	uint8_t marks[2];

	r[0] = rule("prune netcfgd level=DT age 1d");
	CHECK(r[0].kind == FZN_RETAIN_PRUNE
	              && r[0].levels == ((1u << FZN_ENTRY_DEBUG) | (1u << FZN_ENTRY_TRACE))
	              && !r[0].subsystem[0] && r[0].value == DAY
	              && fzn_retain_rule_selects_entries(&r[0]),
	      "a level set selects entries");
	r[1] = rule("keep * subsystem=notes/sync level=E count 3");
	CHECK(r[1].kind == FZN_RETAIN_KEEP && strcmp(r[1].subsystem, "notes/sync") == 0
	              && r[1].levels == (1u << FZN_ENTRY_ERROR) && r[1].limit == FZN_RETAIN_COUNT,
	      "a subsystem and a level, in either order");
	{
		static const char *const BAD[] = {
			"prune * level= age 1d",      "prune * level=X age 1d",
			"prune * level=DD age 1d",    "prune * subsystem=/a age 1d",
			"prune * subsystem=a//b age 1d", "prune * subsystem=a/ age 1d",
			"prune * level=D level=T age 1d", "prune * age 1d level=D",
			"prune * level=D subsystem=a subsystem=b age 1d",
		};
		fzn_retain_rule_t x;
		size_t i;
		int all = 1;

		for (i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++)
			all = all && fzn_retain_parse(BAD[i], strlen(BAD[i]), &x) == FZN_RETAIN_ERR_MALFORMED;
		CHECK(all, "an empty or unknown level, a level twice, a subsystem with an empty "
		           "step, a selector twice and one after the limit are refused");
	}
	CHECK(fzn_retain_reads_entries("netcfgd", r, 1u) && !fzn_retain_reads_entries("other", r, 1u),
	      "only a program an entry rule names has its segments read");
	CHECK(strcmp(plan(s, 2u, r, 1u, now), "00") == 0, "the segment plan does not weigh it");

	/* AGE BY ENTRY: a debug line two days old goes, an info line stays. */
	CHECK(fzn_retain_walk_init(&w, "netcfgd", r, 1u, now) == FZN_RETAIN_OK
	              && fzn_retain_walk_entry(&w, 0u, now - (2u * DAY), FZN_ENTRY_DEBUG, "apply", 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now - (2u * DAY), FZN_ENTRY_INFO, "apply", 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now - 1000u, FZN_ENTRY_TRACE, "apply", 60u),
	      "an old debug entry goes, an old info entry and a new trace entry stay");

	/* A SEGMENT RULE AND AN ENTRY KEEP: the segment is pruned, its errors kept. */
	r[0] = rule("prune netcfgd age 30d");
	r[1] = rule("keep netcfgd level=CEW age 90d");
	CHECK(fzn_retain_marks("netcfgd", s, 2u, r, 2u, now, marks) == FZN_RETAIN_OK
	              && marks[0] == FZN_RETAIN_MARK_PRUNED && marks[1] == 0u,
	      "the segment rule marks the old segment, and only it");
	CHECK(fzn_retain_walk_init(&w, "netcfgd", r, 2u, now) == FZN_RETAIN_OK
	              && !fzn_retain_walk_entry(&w, marks[0], now - (41u * DAY), FZN_ENTRY_ERROR, "a",
	                                        60u)
	              && fzn_retain_walk_entry(&w, marks[0], now - (41u * DAY), FZN_ENTRY_INFO, "a",
	                                       60u)
	              && !fzn_retain_walk_entry(&w, marks[1], now - DAY, FZN_ENTRY_INFO, "a", 60u),
	      "in the pruned segment an error is kept by the entry rule and an info entry goes; "
	      "the unmarked segment keeps all");
	r[1] = rule("keep netcfgd level=CEW age 30d");
	CHECK(fzn_retain_walk_init(&w, "netcfgd", r, 2u, now) == FZN_RETAIN_OK
	              && fzn_retain_walk_entry(&w, marks[0], now - (41u * DAY), FZN_ENTRY_ERROR, "a",
	                                       60u),
	      "a keep rule whose age the error is past keeps nothing");

	/* COUNT AND SIZE COUNT ONLY WHAT THE RULE SELECTS, newest first. */
	r[0] = rule("prune * subsystem=notes count 2");
	CHECK(fzn_retain_walk_init(&w, "netcfgd", r, 1u, now) == FZN_RETAIN_OK
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "notes", 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "notesx", 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "notes/sync", 60u)
	              && fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "notes/sync/x", 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "apply", 60u),
	      "the newest two under notes stay, the third goes, and notesx and apply are not "
	      "under it");
	r[0] = rule("prune * level=I size 100");
	CHECK(fzn_retain_walk_init(&w, "netcfgd", r, 1u, now) == FZN_RETAIN_OK
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "a", 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "a", 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_DEBUG, "a", 60u)
	              && fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "a", 60u),
	      "the newest 100 bytes of info entries keep an entry that begins within them");
	r[0] = rule("prune other level=I age 0");
	CHECK(fzn_retain_walk_init(&w, "netcfgd", r, 1u, now) == FZN_RETAIN_OK
	              && !fzn_retain_walk_entry(&w, 0u, 0u, FZN_ENTRY_INFO, "a", 60u),
	      "a rule for another program does not apply");
	CHECK(fzn_retain_walk_init(&w, "*", r, 1u, now) == FZN_RETAIN_ERR_MALFORMED
	              && fzn_retain_walk_init(&w, "netcfgd", r, FZN_RETAIN_RULES_MAX + 1u, now)
	                         == FZN_RETAIN_ERR_MALFORMED,
	      "a walk over every program, or past the rule bound, is refused");
}

/* ONE SPELLING, sec 475: a rule kept under its text is kept once. */
static void test_text(void)
{
	static const char *const PAIRS[][2] = {
		{ "prune * age 720h", "prune * age 30d" },
		{ "keep netcfgd level=TD subsystem=notes count 5",
		  "keep netcfgd level=DT subsystem=notes count 5" },
		{ "prune * subsystem=a/b level=E age 90", "prune * level=E subsystem=a/b age 90s" },
		{ "keep * size 1048576", "keep * size 1M" },
		{ "keep * size 1000", "keep * size 1000" },
		{ "prune x age 0", "prune x age 0d" },
	};
	size_t i;
	int all = 1;

	for (i = 0; i < sizeof(PAIRS) / sizeof(PAIRS[0]); i++) {
		fzn_retain_rule_t a = rule(PAIRS[i][0]), back;
		char t[FZN_RETAIN_TEXT_MAX];
		size_t len = 0;

		if (fzn_retain_text(&a, t, sizeof(t), &len) != FZN_RETAIN_OK
		    || strcmp(t, PAIRS[i][1]) != 0 || len != strlen(t)
		    || fzn_retain_parse(t, len, &back) != FZN_RETAIN_OK
		    || memcmp(&a, &back, sizeof(a)) != 0) {
			fprintf(stderr, "  text of \"%s\" was \"%s\"\n", PAIRS[i][0], t);
			all = 0;
		}
	}
	CHECK(all, "every rule has one text, the largest unit dividing it, the levels and "
	           "selectors in order, and it parses back to the same rule");
	{
		fzn_retain_rule_t a = rule("prune * age 1d");
		char t[8], big[FZN_RETAIN_TEXT_MAX];
		size_t len = 0;

		CHECK(fzn_retain_text(&a, t, sizeof(t), &len) == FZN_RETAIN_ERR_MALFORMED,
		      "a text that does not fit is refused, not cut");
		a.value += 1u;
		CHECK(fzn_retain_text(&a, big, sizeof(big), &len) == FZN_RETAIN_ERR_MALFORMED,
		      "an age the parser could not have given is refused");
	}
}

int main(void)
{
	test_lines();
	test_plans();
	test_entries();
	test_text();
	if (failures) {
		fprintf(stderr, "retain_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("retain_test: all %d checks passed\n", checks);
	return 0;
}
