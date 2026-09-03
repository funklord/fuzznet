/* Tests for local/peer.c.
 *
 * Every case here is text and a struct. No socket, no process, no /proc --
 * which is the point of splitting the parser and the policy away from
 * `fzn_peer_from_fd`: the decisions can be driven exhaustively, including
 * into states a real /proc would rarely produce and an attacker might.
 *
 * The distinction under test throughout is project.md sec 2's: **"could not
 * tell" is not "none"**. A parser that returns an empty list for both is
 * the bug this module exists to prevent, and it is the one a naive
 * implementation writes.
 */

#include "../peer.h"

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
	fprintf(stderr, "  FAIL peer_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

static int parse(const char *text, fzn_peer_t *p)
{
	memset(p, 0, sizeof(*p));
	return fzn_peer_groups_parse(text, text ? strlen(text) : 0, p);
}

/* A realistic status file, shortened. The Groups line is the one measured
 * on the machine this family is developed on. */
static const char REAL_STATUS[] =
        "Name:\tcat\n"
        "Umask:\t0022\n"
        "State:\tR (running)\n"
        "Tgid:\t1234\n"
        "Ngid:\t0\n"
        "Pid:\t1234\n"
        "Uid:\t1000\t1000\t1000\t1000\n"
        "Gid:\t1000\t1000\t1000\t1000\n"
        "Groups:\t20 24 25 27 29 30 44 46 60 103 110 111 116 121 132 1000 \n"
        "NStgid:\t1234\n";

static void test_parses_a_real_status(void)
{
	fzn_peer_t p;

	CHECK(parse(REAL_STATUS, &p) == 1, "a real status file did not parse");
	CHECK(p.groups_known == 1, "groups not marked known");
	CHECK(p.group_count == 16, "parsed %zu groups, wanted 16", p.group_count);
	CHECK(p.groups[0] == 20, "first group %u, wanted 20", p.groups[0]);
	CHECK(p.groups[15] == 1000, "last group %u, wanted 1000", p.groups[15]);
}

static void test_missing_groups_line_is_unknown_not_empty(void)
{
	fzn_peer_t p;

	/* THE case. A status file without a Groups: line means we could not
	 * establish membership. A parser that returned an empty list here
	 * would report "member of nothing", which denies -- and would report
	 * it as a definite answer, which is what turns a failed read into an
	 * allow the moment somebody inverts the test. */
	CHECK(parse("Name:\tcat\nPid:\t1\n", &p) == 0,
	      "a status file with no Groups: line reported success");
	CHECK(p.groups_known == 0, "no Groups: line was reported as a KNOWN empty list");
	CHECK(p.group_count == 0, "count set despite unknown");
}

static void test_an_empty_groups_line_is_a_real_empty_membership(void)
{
	fzn_peer_t p;

	/* The mirror, and the reason the two need different answers: a
	 * process genuinely in no supplementary groups has a Groups: line
	 * with nothing after it, and that IS knowable. */
	CHECK(parse("Name:\tcat\nGroups:\t\nPid:\t1\n", &p) == 1,
	      "an empty Groups: line was treated as a failure");
	CHECK(p.groups_known == 1, "a real empty membership was marked unknown");
	CHECK(p.group_count == 0, "count %zu, wanted 0", p.group_count);

	CHECK(parse("Groups:\n", &p) == 1, "an empty Groups: line with no tab failed");
	CHECK(p.groups_known == 1 && p.group_count == 0, "empty membership not recorded");
}

static void test_lines_that_merely_start_alike(void)
{
	fzn_peer_t p;

	/* `Gid:` and `Ngid:` are real neighbours in this file. A prefix match
	 * that is not anchored to a line start would also match a `Groups:`
	 * appearing inside another field's value. */
	CHECK(parse("Ngid:\t0\nGid:\t1000 1000\n", &p) == 0,
	      "Gid:/Ngid: satisfied the Groups: match");
	CHECK(p.groups_known == 0, "and were treated as a known list");

	CHECK(parse("Name:\tGroups: 1 2 3\nPid:\t1\n", &p) == 0,
	      "a Groups: inside another field's value was parsed as the real line");
}

static void test_malformed_entries_are_unknown_not_partial(void)
{
	fzn_peer_t p;

	/* Partial success is the failure mode here: a list that parsed three
	 * of five entries and reported success answers "not a member" wrongly
	 * and definitely. */
	CHECK(parse("Groups:\t20 24 banana 27\n", &p) == 0,
	      "a non-numeric entry was accepted");
	CHECK(p.groups_known == 0, "a partly-parsed list was marked known");
	CHECK(p.group_count == 0, "a partly-parsed list left a count behind");

	CHECK(parse("Groups:\t20 4294967296\n", &p) == 0,
	      "a gid past 32 bits was accepted");
	CHECK(p.groups_known == 0, "and the list was marked known");

	CHECK(parse("Groups:\t20 -5 27\n", &p) == 0, "a negative entry was accepted");
}

static void test_overflow_is_unknown_not_truncated(void)
{
	fzn_peer_t p;
	char big[8192];
	size_t n = 0;

	/* Truncating would answer "not a member" definitely and wrongly for
	 * anybody whose group fell off the end. Unknown denies and stays
	 * honest about why. */
	n += (size_t)snprintf(big + n, sizeof(big) - n, "Groups:\t");
	for (int i = 0; i < FZN_PEER_MAX_GROUPS + 5; i++)
		n += (size_t)snprintf(big + n, sizeof(big) - n, "%d ", 100 + i);
	snprintf(big + n, sizeof(big) - n, "\n");

	CHECK(parse(big, &p) == 0, "more groups than the bound were accepted");
	CHECK(p.groups_known == 0, "an overflowing list was marked known -- truncated");
	CHECK(p.group_count == 0, "an overflowing list left a count behind");
}

static void test_membership_is_three_valued(void)
{
	fzn_peer_t p;

	parse(REAL_STATUS, &p);
	p.primary_gid = 1000;

	CHECK(fzn_peer_group_verdict(&p, 103) == FZN_PEER_MEMBER, "netdev membership missed");
	CHECK(fzn_peer_group_verdict(&p, 6) == FZN_PEER_NOT_MEMBER,
	      "reported membership of a group not held");

	/* The primary gid counts. A group that IS somebody's primary one must
	 * not be refused -- that would be the mirror of the bug this module
	 * is about. */
	CHECK(fzn_peer_group_verdict(&p, 1000) == FZN_PEER_MEMBER, "primary gid not counted");

	/* And when the list is unknown, the answer is UNKNOWN rather than
	 * NOT_MEMBER -- except where the primary gid settles it, which is
	 * always knowable. */
	parse("Name:\tcat\n", &p);
	p.primary_gid = 1000;
	CHECK(fzn_peer_group_verdict(&p, 103) == FZN_PEER_UNKNOWN,
	      "an unknown list answered a definite NOT_MEMBER");
	CHECK(fzn_peer_group_verdict(&p, 1000) == FZN_PEER_MEMBER,
	      "the primary gid was not answered while the list was unknown");

	CHECK(fzn_peer_group_verdict(NULL, 1) == FZN_PEER_UNKNOWN, "null peer was not unknown");
}

static void test_the_careless_reading_is_loudly_wrong(void)
{
	fzn_peer_t p;

	/* peer.h chooses the enum values so that `if (fzn_peer_group_verdict(...))`
	 * -- the mistake the tri-state exists to make hard -- is TRUE for
	 * UNKNOWN as well as MEMBER, and so fails immediately rather than
	 * denying quietly and being discovered in production. This asserts
	 * that property so nobody "tidies" the values later. */
	parse("Name:\tcat\n", &p);
	p.primary_gid = 1;
	CHECK(fzn_peer_group_verdict(&p, 103) != FZN_PEER_NOT_MEMBER,
	      "UNKNOWN compares equal to NOT_MEMBER, so a careless test denies silently");
	CHECK((int)FZN_PEER_NOT_MEMBER == 0,
	      "NOT_MEMBER is not zero, so a careless test admits a non-member");
	CHECK((int)FZN_PEER_UNKNOWN != 0,
	      "UNKNOWN is zero, so a careless test reads it as a definite no");
}

static void test_is_member_denies_on_unknown(void)
{
	fzn_peer_t p;

	/* The whole reason this function exists: it is the name that invites
	 * `if (...)`, so it must be the one that cannot be misread. UNKNOWN
	 * has to deny, and that is the case worth a test rather than the two
	 * obvious ones.
	 *
	 * Added because coverage said nothing executed this function at all.
	 * It was written in response to raidcfgd's suggestion and shipped
	 * without a test -- which is the shape a gap takes when an API is
	 * added to answer a question rather than to answer a failing case. */
	parse(REAL_STATUS, &p);
	p.primary_gid = 1000;
	CHECK(fzn_peer_is_member(&p, 103) == 1, "a real member was not reported");
	CHECK(fzn_peer_is_member(&p, 6) == 0, "a non-member was reported as a member");
	CHECK(fzn_peer_is_member(&p, 1000) == 1, "the primary gid was not counted");

	parse("Name:\tcat\n", &p);
	p.primary_gid = 1;
	CHECK(fzn_peer_group_verdict(&p, 103) == FZN_PEER_UNKNOWN, "expected UNKNOWN");
	CHECK(fzn_peer_is_member(&p, 103) == 0,
	      "UNKNOWN was reported as membership -- the safe default is not safe");

	CHECK(fzn_peer_is_member(NULL, 1) == 0, "a null peer was reported as a member");

	/* And it must agree with the verdict wherever the verdict is
	 * definite, or there are two answers to one question. */
	parse(REAL_STATUS, &p);
	p.primary_gid = 1000;
	for (uint32_t g = 0; g < 200; g++) {
		fzn_peer_verdict_t v = fzn_peer_group_verdict(&p, g);
		int m = fzn_peer_is_member(&p, g);

		if (v == FZN_PEER_MEMBER)
			CHECK(m == 1, "verdict says member for %u and is_member says no", g);
		else
			CHECK(m == 0, "verdict says %d for %u and is_member says yes", (int)v, g);
	}
}

static void test_bad_arguments(void)
{
	fzn_peer_t p;

	CHECK(fzn_peer_groups_parse(NULL, 10, &p) == 0, "null text accepted");
	CHECK(fzn_peer_groups_parse("Groups:\t1\n", 0, &p) == 0, "zero length accepted");
	CHECK(fzn_peer_groups_parse("Groups:\t1\n", 9, NULL) == 0, "null peer accepted");

	/* Not null-terminated: the length must bound the scan. */
	{
		char buf[8] = { 'G', 'r', 'o', 'u', 'p', 's', ':', ' ' };
		memset(&p, 0, sizeof(p));
		CHECK(fzn_peer_groups_parse(buf, sizeof(buf), &p) == 1,
		      "a Groups: line at the very end of the buffer was not handled");
		CHECK(p.groups_known == 1 && p.group_count == 0,
		      "a truncated-but-complete empty line was misread");
	}
}

/* THE UNTERMINATED LINE IS PARSED, AND THAT IS THE CONTRACT RATHER THAN A
 * DEFECT. This case exists to say so, because it reads as a defect.
 *
 * A `Groups:` line running to `len` with no newline is taken for a whole
 * line. Reached with a buffer a read merely FILLED, that yields every gid
 * before the cut with `groups_known` set, and a number at the cut that may
 * be half a number -- 250 read as 25, a wrong entry rather than a missing
 * one -- which is a definite FZN_PEER_NOT_MEMBER for a real member.
 *
 * IT IS NOT FIXABLE HERE. `len` does not say whether it means "the whole
 * file" or "as much as fitted", and only the caller knows which; refusing
 * every unterminated line would break the caller that legitimately holds a
 * short unterminated text, which is the case directly above. So peer.h
 * makes whole lines a PRECONDITION and `fzn_peer_from_fd` satisfies it by
 * trimming to the last newline whenever its read filled the buffer.
 *
 * WRITTEN AFTER MISTAKING IT FOR A BUG. The hazard is real and the fix
 * belongs one layer up; with nothing beside it saying so, the next reader
 * makes the same trip -- and the plausible wrong turn is to "fix" the
 * parser, which breaks the case above and rewrites peer_fuzz's model to
 * agree with the code it is meant to check independently. */
/* THE TRIM, TESTED HERE BECAUSE THE PLACE IT IS USED CANNOT BE.
 *
 * `fzn_peer_from_fd` calls this when its `fread` filled the 8192-byte
 * buffer, which is the case where the read may have stopped mid-line. No
 * test can drive that: it needs a /proc/<pid>/status longer than 8192
 * bytes, and this process's own is not. So the wiring is exercised by
 * nothing and the LOGIC is exercised here -- stated rather than glossed,
 * because a fix whose only verification is that it compiles is the thing
 * this suite exists to catch elsewhere.
 *
 * It is a public function for the same reason it is a separate one: peer.h
 * makes whole lines a precondition that only a caller can satisfy, and a
 * precondition every consumer has to implement by hand gets implemented
 * three ways and one of them wrongly. */
static void test_whole_lines_stops_at_the_last_newline(void)
{
	CHECK(fzn_peer_whole_lines(NULL, 10) == 0, "a null text reported a length");
	CHECK(fzn_peer_whole_lines("", 0) == 0, "an empty text reported a length");

	/* Nothing is known to be whole, so nothing is. */
	CHECK(fzn_peer_whole_lines("Groups:\t1 2 3", 13) == 0,
	      "a text with no newline at all reported %zu whole bytes",
	      fzn_peer_whole_lines("Groups:\t1 2 3", 13));

	/* Already whole: nothing is given up. A trim that shortened a
	 * complete read would silently drop the last line of every file. */
	CHECK(fzn_peer_whole_lines("a\nb\n", 4) == 4, "a terminated text was shortened");
	CHECK(fzn_peer_whole_lines("\n", 1) == 1, "a lone newline was dropped");

	/* The case it exists for: a partial last line goes and the rest
	 * stays. */
	CHECK(fzn_peer_whole_lines("a\nb\nGroups:\t20 2", 15) == 4,
	      "a partial last line left %zu bytes rather than 4",
	      fzn_peer_whole_lines("a\nb\nGroups:\t20 2", 15));
}

/* AND THE TWO TOGETHER, which is what the fix actually is: neither function
 * alone prevents the wrong definite answer. */
static void test_a_trimmed_read_answers_could_not_tell(void)
{
	static const char cut[] = "Name:\tcat\nGroups:\t20 24 250";
	static const char whole[] = "Name:\tcat\nGroups:\t20 24 250\nPid:\t1\n";
	fzn_peer_t p;
	size_t n;
	/* One byte short of the literal, which is where a read that filled its
	 * buffer would have stopped: the trailing `0` of 250 is on the far
	 * side of the cut. */
	const size_t cut_len = sizeof(cut) - 2u;

	/* Untrimmed, that is a KNOWN list whose last entry is 25 -- a gid this
	 * process is not in, indistinguishable from a real 25. */
	memset(&p, 0, sizeof(p));
	CHECK(fzn_peer_groups_parse(cut, cut_len, &p) == 1 && p.groups_known == 1 &&
	              p.group_count == 3 && p.groups[2] == 25u,
	      "the untrimmed cut read did not produce the wrong definite answer, so "
	      "the trim below has nothing to prevent");

	n = fzn_peer_whole_lines(cut, cut_len);
	memset(&p, 0, sizeof(p));
	CHECK(fzn_peer_groups_parse(cut, n, &p) == 0,
	      "a trimmed cut read still reported a group list");
	CHECK(p.groups_known == 0,
	      "a trimmed cut read left a KNOWN list, so the wrong definite answer "
	      "survives the trim");

	/* THE CONTROL. The same Groups: line arriving whole, trimmed by the
	 * same call, still answers -- otherwise the rule would be "refuse
	 * large reads" rather than "refuse cut ones". */
	n = fzn_peer_whole_lines(whole, sizeof(whole) - 1u);
	memset(&p, 0, sizeof(p));
	CHECK(fzn_peer_groups_parse(whole, n, &p) == 1 && p.groups_known == 1 &&
	              p.group_count == 3 && p.groups[2] == 250u,
	      "a whole Groups: line did not survive the trim, so trimming costs the "
	      "answer it is meant to protect");
}

static void test_an_unterminated_line_is_the_callers_problem(void)
{
	fzn_peer_t p;

	CHECK(parse("Name:\tcat\nGroups:\t20 24 25", &p) == 1,
	      "an unterminated Groups: line was refused, which would break a caller "
	      "holding a short text that legitimately ends without a newline");
	CHECK(p.groups_known == 1 && p.group_count == 3,
	      "and it is read as the three entries it appears to hold");

	/* The same bytes as a caller must actually present them: trimmed to
	 * the last newline, the cut line is gone and the answer is honest. */
	CHECK(parse("Name:\tcat\n", &p) == 0,
	      "text trimmed to its last newline still reported a group list");
	CHECK(p.groups_known == 0,
	      "a trimmed-away Groups: line left a KNOWN list behind, so trimming does "
	      "not give the caller the honest answer it is for");
}

/* The positive control: nearly every case asserts a refusal or an unknown,
 * and a parser that always failed would satisfy them. */
static void test_the_suite_can_tell_pass_from_fail(void)
{
	fzn_peer_t p;

	CHECK(parse(REAL_STATUS, &p) == 1 && p.groups_known == 1 && p.group_count == 16,
	      "the positive control fails, so every refusal above proves nothing");
}

/* A count larger than the array it indexes.
 *
 * THE ONLY PATH IN THIS FILE THAT COULD FAIL OPEN, which is why it is worth a
 * test of its own. Every other refusal here denies; reading past `groups` can
 * only ADD matches, so a struct with a nonsense count answers MEMBER on the
 * strength of whatever sits next to the array.
 *
 * The struct that produces it is not exotic. It is one declared on a stack and
 * never initialised, where `groups_known` is garbage that happens to be
 * non-zero and `group_count` is garbage too -- which is what a consumer gets
 * for forgetting a memset, and this library's consumers are other projects.
 *
 * Simulated here by filling the struct legitimately and then setting the count
 * past the bound, so the array holds known values and the test is about the
 * count alone. */
static void test_an_impossible_group_count_denies(void)
{
	fzn_peer_t p;
	size_t i;

	parse(REAL_STATUS, &p);
	p.primary_gid = 1;
	CHECK(p.groups_known == 1, "the fixture did not parse");
	CHECK(fzn_peer_group_verdict(&p, 103) == FZN_PEER_MEMBER,
	      "the fixture does not hold the group the rest of this test needs");

	/* Every slot set to the gid we will ask about, so that a scan running
	 * past `group_count` would certainly find one. */
	for (i = 0; i < FZN_PEER_MAX_GROUPS; i++)
		p.groups[i] = 4242;

	p.group_count = FZN_PEER_MAX_GROUPS;
	CHECK(fzn_peer_group_verdict(&p, 4242) == FZN_PEER_MEMBER,
	      "a full but legal list was not scanned, so the bound is off by one");

	p.group_count = FZN_PEER_MAX_GROUPS + 1u;
	CHECK(fzn_peer_group_verdict(&p, 4242) == FZN_PEER_UNKNOWN,
	      "a count past the array was scanned rather than refused");
	CHECK(fzn_peer_is_member(&p, 4242) == 0,
	      "an impossible count granted membership, which is the one direction "
	      "this module must not fail in");

	/* And it is UNKNOWN rather than NOT_MEMBER: a definite answer from a
	 * struct known to be nonsense is what the tri-state exists to stop. */
	p.group_count = (size_t)-1;
	CHECK(fzn_peer_group_verdict(&p, 7) == FZN_PEER_UNKNOWN,
	      "a count of SIZE_MAX produced a definite answer");

	/* The primary gid still answers, because it is not in the array and
	 * does not depend on the count being sane. */
	p.group_count = (size_t)-1;
	CHECK(fzn_peer_group_verdict(&p, 1) == FZN_PEER_MEMBER,
	      "the primary gid stopped being answerable when the list was corrupt");
}

int main(void)
{
	test_parses_a_real_status();
	test_missing_groups_line_is_unknown_not_empty();
	test_an_empty_groups_line_is_a_real_empty_membership();
	test_lines_that_merely_start_alike();
	test_malformed_entries_are_unknown_not_partial();
	test_overflow_is_unknown_not_truncated();
	test_membership_is_three_valued();
	test_the_careless_reading_is_loudly_wrong();
	test_is_member_denies_on_unknown();
	test_bad_arguments();
	test_whole_lines_stops_at_the_last_newline();
	test_a_trimmed_read_answers_could_not_tell();
	test_an_unterminated_line_is_the_callers_problem();
	test_an_impossible_group_count_denies();
	test_the_suite_can_tell_pass_from_fail();

	printf("peer_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
