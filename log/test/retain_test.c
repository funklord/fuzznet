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
	              && fzn_retain_walk_entry(&w, 0u, now - (2u * DAY), FZN_ENTRY_DEBUG, "apply", NULL, 0u, 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now - (2u * DAY), FZN_ENTRY_INFO, "apply", NULL, 0u, 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now - 1000u, FZN_ENTRY_TRACE, "apply", NULL, 0u, 60u),
	      "an old debug entry goes, an old info entry and a new trace entry stay");

	/* A SEGMENT RULE AND AN ENTRY KEEP: the segment is pruned, its errors kept. */
	r[0] = rule("prune netcfgd age 30d");
	r[1] = rule("keep netcfgd level=CEW age 90d");
	CHECK(fzn_retain_marks("netcfgd", s, 2u, r, 2u, now, marks) == FZN_RETAIN_OK
	              && marks[0] == FZN_RETAIN_MARK_PRUNED && marks[1] == 0u,
	      "the segment rule marks the old segment, and only it");
	CHECK(fzn_retain_walk_init(&w, "netcfgd", r, 2u, now) == FZN_RETAIN_OK
	              && !fzn_retain_walk_entry(&w, marks[0], now - (41u * DAY), FZN_ENTRY_ERROR, "a",
	                                        NULL, 0u, 60u)
	              && fzn_retain_walk_entry(&w, marks[0], now - (41u * DAY), FZN_ENTRY_INFO, "a",
	                                       NULL, 0u, 60u)
	              && !fzn_retain_walk_entry(&w, marks[1], now - DAY, FZN_ENTRY_INFO, "a", NULL, 0u, 60u),
	      "in the pruned segment an error is kept by the entry rule and an info entry goes; "
	      "the unmarked segment keeps all");
	r[1] = rule("keep netcfgd level=CEW age 30d");
	CHECK(fzn_retain_walk_init(&w, "netcfgd", r, 2u, now) == FZN_RETAIN_OK
	              && fzn_retain_walk_entry(&w, marks[0], now - (41u * DAY), FZN_ENTRY_ERROR, "a",
	                                       NULL, 0u, 60u),
	      "a keep rule whose age the error is past keeps nothing");

	/* COUNT AND SIZE COUNT ONLY WHAT THE RULE SELECTS, newest first. */
	r[0] = rule("prune * subsystem=notes count 2");
	CHECK(fzn_retain_walk_init(&w, "netcfgd", r, 1u, now) == FZN_RETAIN_OK
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "notes", NULL, 0u, 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "notesx", NULL, 0u, 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "notes/sync", NULL, 0u, 60u)
	              && fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "notes/sync/x", NULL, 0u, 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "apply", NULL, 0u, 60u),
	      "the newest two under notes stay, the third goes, and notesx and apply are not "
	      "under it");
	r[0] = rule("prune * level=I size 100");
	CHECK(fzn_retain_walk_init(&w, "netcfgd", r, 1u, now) == FZN_RETAIN_OK
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "a", NULL, 0u, 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "a", NULL, 0u, 60u)
	              && !fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_DEBUG, "a", NULL, 0u, 60u)
	              && fzn_retain_walk_entry(&w, 0u, now, FZN_ENTRY_INFO, "a", NULL, 0u, 60u),
	      "the newest 100 bytes of info entries keep an entry that begins within them");
	r[0] = rule("prune other level=I age 0");
	CHECK(fzn_retain_walk_init(&w, "netcfgd", r, 1u, now) == FZN_RETAIN_OK
	              && !fzn_retain_walk_entry(&w, 0u, 0u, FZN_ENTRY_INFO, "a", NULL, 0u, 60u),
	      "a rule for another program does not apply");
	CHECK(fzn_retain_walk_init(&w, "*", r, 1u, now) == FZN_RETAIN_ERR_MALFORMED
	              && fzn_retain_walk_init(&w, "netcfgd", r, FZN_RETAIN_RULES_MAX + 1u, now)
	                         == FZN_RETAIN_ERR_MALFORMED,
	      "a walk over every program, or past the rule bound, is refused");
}

/* TEXT AS A SELECTOR, sec 477. */
static void test_text_selector(void)
{
	static const char *const BAD[] = {
		"prune * text= age 1d",     "prune * text=%00 age 1d", "prune * text=%2 age 1d",
		"prune * text=%zz age 1d",  "prune * text=a,b age 1d", "prune * text=a text=b age 1d",
		"prune * text=0123456789012345678901234567890123456789012345678901234567890123x age 1d",
	};
	fzn_retain_rule_t r[1], x;
	fzn_retain_walk_t w;
	const uint8_t up[] = "eth0 link up now", down[] = "eth0 link down";
	size_t i;
	int all = 1;

	r[0] = rule("prune * text=link%20up age 0");
	CHECK(r[0].match_len == 7u && memcmp(r[0].match, "link up", 7u) == 0
	              && fzn_retain_rule_selects_entries(&r[0]),
	      "a text match is unescaped and selects entries");
	for (i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++)
		all = all && fzn_retain_parse(BAD[i], strlen(BAD[i]), &x) == FZN_RETAIN_ERR_MALFORMED;
	CHECK(all, "an empty match, a NUL, a short or bad escape, a bare comma, a match twice and "
	           "one past 64 bytes are refused");
	CHECK(fzn_retain_walk_init(&w, "netcfgd", r, 1u, 100u) == FZN_RETAIN_OK
	              && fzn_retain_walk_entry(&w, 0u, 1u, FZN_ENTRY_INFO, "a", up, sizeof(up) - 1u,
	                                       60u)
	              && !fzn_retain_walk_entry(&w, 0u, 1u, FZN_ENTRY_INFO, "a", down,
	                                        sizeof(down) - 1u, 60u)
	              && !fzn_retain_walk_entry(&w, 0u, 1u, FZN_ENTRY_INFO, "a", NULL, 0u, 60u),
	      "an entry holding the text goes; one without it, and one with no text, stay");
}

/* SCOPE, sec 480: where a rule applies. */
static void test_scope(void)
{
	static const char *const BAD[] = {
		"prune * host=aa age 1d",
		"prune * host=AAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa age 1d",
		"prune * machine=0B0B age 1d",
		"prune * machine=0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b machine=0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b age 1d",
	};
	fzn_retain_rule_t in[3], out[3], x;
	uint8_t host[32], other[32], machine[FZN_ENTRY_MACHINE_LEN];
	char t[FZN_RETAIN_TEXT_MAX];
	size_t i, len = 0;
	int all = 1;

	memset(host, 0xaa, sizeof(host));
	memset(other, 0xab, sizeof(other));
	memset(machine, 0x0b, sizeof(machine));
	in[0] = rule("prune * machine=0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b host=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa level=D age 1d");
	CHECK(in[0].has_host && in[0].has_machine && memcmp(in[0].host, host, 32u) == 0
	              && memcmp(in[0].machine, machine, sizeof(machine)) == 0
	              && fzn_retain_rule_selects_entries(&in[0]),
	      "a host and a machine are read, in either order");
	CHECK(fzn_retain_text(&in[0], t, sizeof(t), &len) == FZN_RETAIN_OK
	              && strcmp(t, "prune * host=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa machine=0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b level=D age 1d") == 0,
	      "the scope's text is host then machine, after the program");
	for (i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++)
		all = all && fzn_retain_parse(BAD[i], strlen(BAD[i]), &x) == FZN_RETAIN_ERR_MALFORMED;
	CHECK(all, "a short key, upper-case hex, a short machine and a scope twice are refused");
	CHECK(fzn_retain_reaches(&in[0], host, machine) && !fzn_retain_reaches(&in[0], other, machine)
	              && !fzn_retain_reaches(&in[0], NULL, machine),
	      "a host-scoped rule reaches its node alone, and nothing where no key is known");
	in[1] = rule("prune * machine=0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b age 1d");
	in[2] = rule("prune * age 1d");
	machine[0] ^= 1u;
	CHECK(fzn_retain_select_here(in, 3u, host, machine, out) == 1u && out[0].value == in[2].value
	              && !out[0].has_machine && !out[0].has_host,
	      "on another machine only the unscoped rule reaches");
	machine[0] ^= 1u;
	CHECK(fzn_retain_select_here(in, 3u, other, machine, out) == 2u && out[0].has_machine
	              && !out[0].has_host,
	      "on another node of the machine the machine's rule and the unscoped one reach");
}

/* COPY RULES, sec 483: they reach copies, and only copies. */
static void test_copy_rules(void)
{
	fzn_retain_rule_t in[3], out[3], x;
	uint8_t host[32], machine[FZN_ENTRY_MACHINE_LEN];
	char t[FZN_RETAIN_TEXT_MAX];
	size_t len = 0;

	memset(host, 0xaa, sizeof(host));
	memset(machine, 0x0b, sizeof(machine));
	in[0] = rule("prune * copy age 30d");
	in[1] = rule("prune * age 7d");
	in[2] = rule("keep netcfgd copy count 3");
	CHECK(in[0].copy && !in[1].copy && in[2].copy && !fzn_retain_rule_selects_entries(&in[0]),
	      "the copy word is read, and a copy rule is a segment rule");
	CHECK(fzn_retain_parse("prune * copy level=D age 1d", 27u, &x) == FZN_RETAIN_ERR_MALFORMED
	              && fzn_retain_parse("prune * copy text=a age 1d", 26u, &x)
	                         == FZN_RETAIN_ERR_MALFORMED
	              && fzn_retain_parse("prune * copy copy age 1d", 24u, &x)
	                         == FZN_RETAIN_ERR_MALFORMED,
	      "a copy rule naming a selector, or copy twice, is refused");
	CHECK(fzn_retain_text(&in[0], t, sizeof(t), &len) == FZN_RETAIN_OK
	              && strcmp(t, "prune * copy age 30d") == 0,
	      "copy is written after the program");
	CHECK(fzn_retain_select_here(in, 3u, host, machine, out) == 1u && !out[0].copy
	              && fzn_retain_select_copies(in, 3u, host, machine, out) == 2u && out[0].copy
	              && out[1].copy,
	      "the node's own log takes the plain rule, its copies the two copy rules");
}

/* WHOSE COPIES, sec 487: a copy rule naming a source applies to that host's
 * copies alone; whoever applies it is still `host=`. */
static void test_source(void)
{
	static const char B[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	static const char A[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	fzn_retain_rule_t in[3], out[3], x;
	uint8_t a[32], b[32];
	char line[FZN_RETAIN_TEXT_MAX], t[FZN_RETAIN_TEXT_MAX];
	size_t len = 0, n;

	memset(a, 0xaa, sizeof(a));
	memset(b, 0xbb, sizeof(b));
	(void)snprintf(line, sizeof(line), "prune * host=%s copy source=%s age 7d", A, B);
	in[0] = rule(line);
	in[1] = rule("prune * copy age 30d");
	(void)snprintf(line, sizeof(line), "keep * copy source=%s count 2", A);
	in[2] = rule(line);
	CHECK(in[0].copy && in[0].has_source && memcmp(in[0].source, b, 32u) == 0
	              && in[0].has_host && memcmp(in[0].host, a, 32u) == 0,
	      "a source and a host read apart, in either order");
	(void)snprintf(line, sizeof(line), "prune * copy source=%s host=%s age 7d", B, A);
	CHECK(fzn_retain_text(&in[0], t, sizeof(t), &len) == FZN_RETAIN_OK && strcmp(t, line) == 0,
	      "the source written after copy and before the host");
	(void)snprintf(line, sizeof(line), "prune * source=%s age 7d", B);
	n = strlen(line);
	CHECK(fzn_retain_parse(line, n, &x) == FZN_RETAIN_ERR_MALFORMED,
	      "a source on a rule that is not a copy rule is refused");
	(void)snprintf(line, sizeof(line), "prune * copy source=%s source=%s age 7d", B, B);
	n = strlen(line);
	CHECK(fzn_retain_parse(line, n, &x) == FZN_RETAIN_ERR_MALFORMED
	              && fzn_retain_parse("prune * copy source=bb age 7d", 29u, &x)
	                         == FZN_RETAIN_ERR_MALFORMED,
	      "a source twice, or a short one, is refused");
	x = in[1];
	x.has_source = 1;
	x.copy = 0;
	CHECK(fzn_retain_text(&x, t, sizeof(t), &len) == FZN_RETAIN_ERR_MALFORMED,
	      "a rule holding a source and no copy is not written");
	CHECK(fzn_retain_select_source(in, 3u, b, out) == 2u && out[0].has_source
	              && !out[1].has_source,
	      "B's copies take B's rule and the rule naming no source");
	CHECK(fzn_retain_select_source(in, 3u, a, out) == 2u && !out[0].has_source
	              && out[1].has_source && memcmp(out[1].source, a, 32u) == 0,
	      "A's copies take A's rule and the rule naming no source, not B's");
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
		{ "prune * text=link%20up%2c level=D age 1d",
		  "prune * level=D text=link%20up%2C age 1d" },
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

/* WHAT DATA, sec 531: message rules in the same grammar, kept apart from
 * the log's; and every log rule written before reads and writes as it did. */
static void test_message_rules(void)
{
	static const char *const BAD[] = {
		"prune messages level=D age 1d",
		"prune messages subsystem=notes age 1d",
		"prune messages text=hi age 1d",
		"prune messages copy age 1d",
		"prune * contact=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa age 1d",
		"prune messages contact=aa age 1d",
		"prune messages",
	};
	static const char C[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	fzn_retain_rule_t in[4], out[4], x;
	uint8_t host[32], machine[FZN_ENTRY_MACHINE_LEN];
	char line[FZN_RETAIN_TEXT_MAX], t[FZN_RETAIN_TEXT_MAX];
	size_t i, len = 0;
	int all = 1;

	memset(host, 0xbb, sizeof(host));
	memset(machine, 0x0b, sizeof(machine));
	snprintf(line, sizeof(line), "keep messages contact=%s count 100", C);
	in[0] = rule(line);
	CHECK(in[0].data == FZN_RETAIN_MESSAGES && in[0].has_contact && in[0].contact[0] == 0xaau
	              && in[0].kind == FZN_RETAIN_KEEP && in[0].limit == FZN_RETAIN_COUNT
	              && in[0].value == 100u && in[0].program[0] == '\0',
	      "a message rule reads, its contact named");
	CHECK(fzn_retain_text(&in[0], t, sizeof(t), &len) == FZN_RETAIN_OK && strcmp(t, line) == 0,
	      "and writes back as it was given");
	in[1] = rule("prune messages age 360d");
	CHECK(in[1].data == FZN_RETAIN_MESSAGES && !in[1].has_contact
	              && fzn_retain_text(&in[1], t, sizeof(t), &len) == FZN_RETAIN_OK
	              && strcmp(t, "prune messages age 360d") == 0,
	      "and one for every conversation");
	for (i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++)
		all = all && fzn_retain_parse(BAD[i], strlen(BAD[i]), &x) == FZN_RETAIN_ERR_MALFORMED;
	CHECK(all, "a message rule naming a log selector is refused, and a contact on a log rule");
	in[2] = rule("prune log messages age 1d");
	CHECK(in[2].data == FZN_RETAIN_LOG && strcmp(in[2].program, "messages") == 0
	              && fzn_retain_text(&in[2], t, sizeof(t), &len) == FZN_RETAIN_OK
	              && strcmp(t, "prune log messages age 1d") == 0,
	      "a program called messages is a log rule, written with its data word");
	in[3] = rule("prune log netcfgd age 1d");
	CHECK(in[3].data == FZN_RETAIN_LOG && strcmp(in[3].program, "netcfgd") == 0
	              && fzn_retain_text(&in[3], t, sizeof(t), &len) == FZN_RETAIN_OK
	              && strcmp(t, "prune netcfgd age 1d") == 0,
	      "and any other log rule keeps the text it always had");
	CHECK(fzn_retain_select_here(in, 4u, host, machine, out) == 2u
	              && out[0].data == FZN_RETAIN_LOG && out[1].data == FZN_RETAIN_LOG,
	      "the log's selection leaves the message rules out");
	CHECK(fzn_retain_select_messages(in, 4u, host, machine, out) == 2u
	              && out[0].data == FZN_RETAIN_MESSAGES && out[1].data == FZN_RETAIN_MESSAGES,
	      "and the messages' takes them alone");
	snprintf(line, sizeof(line), "prune messages host=%s age 1d",
	         "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
	in[0] = rule(line);
	CHECK(in[0].data == FZN_RETAIN_MESSAGES && in[0].has_host
	              && fzn_retain_select_messages(in, 4u, host, machine, out) == 1u
	              && !out[0].has_host,
	      "a message rule scoped to another host is that host's, not this one's");
	{
		fzn_retain_segment_t s[1] = { { 0u, 10u } };
		uint8_t gone[1] = { 9u };

		CHECK(fzn_retain_plan("messages", s, 1u, &in[1], 1u, 400u * DAY, gone)
		                      == FZN_RETAIN_OK
		              && gone[0] == 0u,
		      "nor does a log plan weigh a message rule, whatever its program is called");
	}
}

int main(void)
{
	test_lines();
	test_plans();
	test_entries();
	test_text();
	test_text_selector();
	test_scope();
	test_copy_rules();
	test_source();
	test_message_rules();
	if (failures) {
		fprintf(stderr, "retain_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("retain_test: all %d checks passed\n", checks);
	return 0;
}
