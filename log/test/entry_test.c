/* entry_test -- one log entry, its name and the classic line. sec 456.
 *
 * The times are checked against values computed outside this code, by
 * Python's datetime, so the calendar here is not checked against itself. */

#include "../entry.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL entry_test.c:%d: %s\n", __LINE__, what);       \
		}                                                                              \
	} while (0)

static const char MACHINE_HEX[] = "0123456789abcdeffedcba9876543210";
static uint8_t machine[FZN_ENTRY_MACHINE_LEN];
static char line[FZN_ENTRY_LINE_MAX];
static uint8_t text_back[FZN_ENTRY_TEXT_MAX];

static fzn_entry_t base(void)
{
	fzn_entry_t e;

	memset(&e, 0, sizeof(e));
	memcpy(e.name.machine, machine, sizeof(machine));
	strcpy(e.name.user, "root");
	strcpy(e.name.program, "fuzznetd");
	e.name.pid = 4121u;
	e.name.start_ms = 1727778896123u;
	e.name.position = 1834u;
	e.time_us = 1790944496789123u; /* 2026-10-02T12:34:56.789123Z */
	e.level = FZN_ENTRY_WARNING;
	strcpy(e.subsystem, "notes/sync");
	e.text = (const uint8_t *)"a record refused";
	e.text_len = strlen("a record refused");
	return e;
}

static int same_name(const fzn_entry_name_t *a, const fzn_entry_name_t *b)
{
	return memcmp(a->machine, b->machine, FZN_ENTRY_MACHINE_LEN) == 0
	       && strcmp(a->user, b->user) == 0 && strcmp(a->program, b->program) == 0
	       && a->pid == b->pid && a->start_ms == b->start_ms && a->position == b->position;
}

/* Encoded, parsed back, and every field the same. */
static int round_trips(const fzn_entry_t *e, const char *host)
{
	fzn_entry_t back;
	char host_back[FZN_ENTRY_WORD_MAX + 1u];
	size_t len = 0;

	return fzn_entry_classic(e, host, line, sizeof(line), &len) == FZN_ENTRY_OK
	       && len == strlen(line) && line[len - 1u] == '\n'
	       && memchr(line, '\n', len - 1u) == NULL
	       && fzn_entry_classic_parse(line, len, machine, &back, host_back, text_back,
	                                sizeof(text_back))
	                  == FZN_ENTRY_OK
	       && strcmp(host_back, host) == 0 && same_name(&back.name, &e->name)
	       && back.time_us == e->time_us && back.level == e->level
	       && strcmp(back.subsystem, e->subsystem) == 0 && back.caused == e->caused
	       && (!e->caused
	           || (same_name(&back.cause, &e->cause) && same_name(&back.origin, &e->origin)))
	       && back.text_len == e->text_len
	       && (e->text_len == 0u || memcmp(back.text, e->text, e->text_len) == 0);
}

static void test_the_line(void)
{
	fzn_entry_t e = base();
	size_t len = 0;

	CHECK(fzn_entry_classic(&e, "nabbe", line, sizeof(line), &len) == FZN_ENTRY_OK
	              && strcmp(line, "2026-10-02T12:34:56.789123Z nabbe root fuzznetd "
	                              "4121@1727778896123#1834 W notes/sync - - a record refused\n")
	                         == 0,
	      "the line is the positional fields and the text, as sec 456 lays it out");
	CHECK(round_trips(&e, "nabbe"), "and reads back to the entry");
}

static void test_times(void)
{
	static const struct {
		uint64_t us;
		const char *text;
	} V[] = {
		{ 0u, "1970-01-01T00:00:00.000000Z" },
		{ 1709251199999999u, "2024-02-29T23:59:59.999999Z" },
		{ 951868800000001u, "2000-03-01T00:00:00.000001Z" },
		{ 253402300799999999u, "9999-12-31T23:59:59.999999Z" },
	};
	fzn_entry_t e = base();
	size_t i, len = 0;

	for (i = 0; i < sizeof(V) / sizeof(V[0]); i++) {
		e.time_us = V[i].us;
		CHECK(fzn_entry_classic(&e, "h", line, sizeof(line), &len) == FZN_ENTRY_OK
		              && strncmp(line, V[i].text, 27u) == 0 && round_trips(&e, "h"),
		      "a time is written as Python's datetime writes it, and reads back");
	}
	e.time_us = 253402300800000000u;
	CHECK(fzn_entry_classic(&e, "h", line, sizeof(line), &len) == FZN_ENTRY_ERR_MALFORMED,
	      "the year 10000 does not fit the field and is refused");
}

static void test_text_is_one_line_and_reads_back(void)
{
	static const uint8_t awkward[] = "two\nlines\r and \\ a tab\t, NUL\0, \x1b[31mred, "
	                                 "\xff bad utf-8, caf\xc3\xa9";
	static uint8_t big[FZN_ENTRY_TEXT_MAX];
	fzn_entry_t e = base();
	size_t len = 0;

	e.text = awkward;
	e.text_len = sizeof(awkward) - 1u;
	CHECK(round_trips(&e, "nabbe"),
	      "newlines, a backslash, NUL, an escape and bad UTF-8 stay one line and read back");
	CHECK(strstr(line, "caf\xc3\xa9") != NULL && strstr(line, "\\x0a") != NULL,
	      "valid UTF-8 is written as itself, a newline as \\x0a");
	e.text = (const uint8_t *)"";
	e.text_len = 0u;
	CHECK(round_trips(&e, "nabbe"), "an empty text reads back empty");
	/* A TEXT SHAPED LIKE A LINE OF OURS is the text of one entry. */
	e.text = (const uint8_t *)"x\n2026-10-02T12:34:56.789123Z evil root sshd 1@1#1 E auth - - ok";
	e.text_len = strlen((const char *)e.text);
	CHECK(round_trips(&e, "nabbe") && strchr(line, '\n') == line + strlen(line) - 1u,
	      "a forged line inside the text cannot become a second line");
	/* AT THE BOUND, every byte escaped: the worst line fits LINE_MAX. */
	memset(big, 0x01, sizeof(big));
	e.text = big;
	e.text_len = sizeof(big);
	CHECK(round_trips(&e, "nabbe"), "the longest text, all escapes, fits and reads back");
	e.text_len = sizeof(big) + 1u;
	CHECK(fzn_entry_classic(&e, "nabbe", line, sizeof(line), &len)
	              == FZN_ENTRY_ERR_MALFORMED,
	      "a text past the bound is refused, not cut");
}

static void test_causes(void)
{
	fzn_entry_t e = base(), cause = base();
	char name[256];
	size_t len = 0;

	e.caused = 1;
	e.cause = cause.name;
	e.cause.machine[0] = 0xaa;
	e.cause.position = 7u;
	e.origin = e.cause;
	e.origin.position = 2u;
	CHECK(round_trips(&e, "nabbe"), "an entry with a cause and an origin reads back");
	CHECK(strstr(line, " <aa23456789abcdeffedcba9876543210/root/fuzznetd/4121@1727778896123#7 "
	                   "<<aa23456789abcdeffedcba9876543210/root/fuzznetd/4121@1727778896123#2 ")
	              != NULL,
	      "the cause and the origin are written as names");
	/* THE GREP: the instance field of the causing entry is in the caused
	 * entry's line. */
	CHECK(fzn_entry_name_text(&e.cause, name, sizeof(name), &len) == FZN_ENTRY_OK
	              && strstr(line, "4121@1727778896123#7") != NULL
	              && strstr(name, "4121@1727778896123#7") == name + len - 20u,
	      "a name ends in the instance field, so one grep finds the entry and what it caused");
	CHECK(fzn_entry_name_text(&e.cause, name, 10u, &len) == FZN_ENTRY_ERR_ROOM
	              && name[0] == '\0',
	      "a name that does not fit is refused, and nothing left");
}

static void test_names(void)
{
	fzn_entry_name_t n, back;
	char text[256];
	size_t len = 0;

	memset(&n, 0, sizeof(n));
	memcpy(n.machine, machine, sizeof(machine));
	strcpy(n.user, "funk");
	strcpy(n.program, "qtty");
	n.pid = UINT32_MAX;
	n.start_ms = UINT64_MAX;
	n.position = 0u;
	CHECK(fzn_entry_name_text(&n, text, sizeof(text), &len) == FZN_ENTRY_OK
	              && fzn_entry_name_parse(text, len, &back) == FZN_ENTRY_OK
	              && same_name(&n, &back),
	      "a name at its numbers' bounds reads back");
	CHECK(fzn_entry_name_parse("0123456789abcdeffedcba9876543210/u/p/1@2", 40u, &back)
	                      == FZN_ENTRY_ERR_MALFORMED
	              && fzn_entry_name_parse("0123456789abcdeffedcba9876543210/u/p/1@2#03", 43u, &back)
	                         == FZN_ENTRY_ERR_MALFORMED
	              && fzn_entry_name_parse("0123456789abcdeffedcba98765432/u/p/1@2#3", 40u, &back)
	                         == FZN_ENTRY_ERR_MALFORMED
	              && fzn_entry_name_parse("0123456789abcdeffedcba9876543210/u/p/4294967296@2#3",
	                                    51u, &back)
	                         == FZN_ENTRY_ERR_MALFORMED,
	      "a name with no position, a leading zero, a short machine or a pid past 32 bits is "
	      "refused");
	CHECK(fzn_entry_machine_parse(MACHINE_HEX, 32u, back.machine) == FZN_ENTRY_OK
	              && fzn_entry_machine_parse("0123456789abcdeffedcba9876543210\n", 33u,
	                                       back.machine)
	                         == FZN_ENTRY_OK
	              && fzn_entry_machine_parse("0123456789ABCDEFfedcba9876543210", 32u, back.machine)
	                         == FZN_ENTRY_ERR_MALFORMED,
	      "machine-id's text is read with or without its newline, and only as it is written");
}

static void test_fields_a_line_cannot_hold(void)
{
	fzn_entry_t e;
	size_t len = 0;

	e = base();
	strcpy(e.name.user, "two words");
	CHECK(fzn_entry_classic(&e, "h", line, sizeof(line), &len) == FZN_ENTRY_ERR_MALFORMED,
	      "a user with a space is refused, since it would move every field after it");
	e = base();
	strcpy(e.subsystem, "notes//sync");
	CHECK(fzn_entry_classic(&e, "h", line, sizeof(line), &len) == FZN_ENTRY_ERR_MALFORMED,
	      "a subsystem with an empty part is refused");
	e = base();
	e.level = (fzn_entry_level_t)9;
	CHECK(fzn_entry_classic(&e, "h", line, sizeof(line), &len) == FZN_ENTRY_ERR_MALFORMED,
	      "a level that is none of the eight is refused");
	e = base();
	CHECK(fzn_entry_classic(&e, "", line, sizeof(line), &len) == FZN_ENTRY_ERR_MALFORMED,
	      "an empty host is refused");
	CHECK(fzn_entry_classic(&e, "h", line, 40u, &len) == FZN_ENTRY_ERR_ROOM && line[0] == '\0',
	      "a line that does not fit is refused, and nothing left that could be read as one");
}

static void test_lines_that_are_not_ours(void)
{
	static const char *const BAD[] = {
		"2026-10-02T12:34:56.789123Z nabbe root fuzznetd 4121@1727778896123#1834 W notes/sync - -",
		"2026-10-02T12:34:56.789123 nabbe root fuzznetd 4121@1727778896123#1834 W notes/sync - - x",
		"2026-02-30T12:34:56.789123Z nabbe root fuzznetd 4121@1727778896123#1834 W notes/sync - - x",
		"2026-02-29T12:34:56.789123Z nabbe root fuzznetd 4121@1727778896123#1834 W notes/sync - - x",
		"2026-10-02T12:34:56.789123Z nabbe root fuzznetd 4121@1727778896123#1834 Q notes/sync - - x",
		"2026-10-02T12:34:56.789123Z nabbe root fuzznetd 4121@1727778896123#1834 W notes/sync - <<x x",
		"2026-10-02T12:34:56.789123Z nabbe root fuzznetd 4121@1727778896123#1834 W notes/sync - - a\\q",
		"2026-10-02T12:34:56.789123Z nabbe root fuzznetd 4121@1727778896123#1834 W notes/sync - - a\tb",
		"2026-10-02T12:34:56.789123Z  root fuzznetd 4121@1727778896123#1834 W notes/sync - - x",
	};
	fzn_entry_t back;
	char host[FZN_ENTRY_WORD_MAX + 1u];
	size_t i;
	int refused = 1;

	for (i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++)
		refused = refused
		          && fzn_entry_classic_parse(BAD[i], strlen(BAD[i]), machine, &back, host,
		                                   text_back, sizeof(text_back))
		                     == FZN_ENTRY_ERR_MALFORMED;
	CHECK(refused,
	      "a line short of a field, a time without Z or on no day -- 29 February of 2026 "
	      "included -- an unknown level, half a "
	      "cause, a stray backslash, a raw tab or an empty field is refused");
}

/* THE PERFORMANT RECORD, sec 457, against log/entry.situ's offsets and
 * the sizes situc computed for it, 55..4672. */
static void test_the_record(void)
{
	static uint8_t rec[FZN_ENTRY_RECORD_MAX + 8u], big[FZN_ENTRY_TEXT_MAX];
	fzn_entry_t e = base(), back;
	size_t len = 0;
	char host[FZN_ENTRY_WORD_MAX + 1u];

	CHECK(fzn_entry_pack(&e, rec, sizeof(rec), &len) == FZN_ENTRY_OK && rec[0] == 1u
	              && rec[1] == FZN_ENTRY_WARNING && rec[2] == 0x00u && rec[3] == 0x06u
	              && rec[9] == 0x83u && memcmp(rec + 10, machine, 16u) == 0 && rec[26] == 4u
	              && memcmp(rec + 27, "root", 4u) == 0,
	      "the version, the level, the time big-endian and the name at the schema's offsets");
	CHECK(fzn_entry_unpack(rec, len, &back) == FZN_ENTRY_OK && same_name(&back.name, &e.name)
	              && back.time_us == e.time_us && back.level == e.level
	              && strcmp(back.subsystem, e.subsystem) == 0 && !back.caused
	              && back.text_len == e.text_len && memcmp(back.text, e.text, e.text_len) == 0,
	      "a record unpacks to the entry");
	/* AND THE SAME ENTRY AS A LINE: the two formats convert. */
	CHECK(fzn_entry_classic(&back, "nabbe", line, sizeof(line), &len) == FZN_ENTRY_OK
	              && strcmp(line, "2026-10-02T12:34:56.789123Z nabbe root fuzznetd "
	                              "4121@1727778896123#1834 W notes/sync - - a record refused\n")
	                         == 0,
	      "the unpacked record writes the same classic line");

	/* THE SMALLEST AND THE LARGEST, which situc measured. */
	e = base();
	strcpy(e.name.user, "u");
	strcpy(e.name.program, "p");
	strcpy(e.subsystem, "s");
	e.text_len = 0u;
	CHECK(fzn_entry_pack(&e, rec, sizeof(rec), &len) == FZN_ENTRY_OK
	              && len == FZN_ENTRY_RECORD_MIN,
	      "the smallest record is 55 bytes, as the schema says");
	e = base();
	memset(e.name.user, 'u', FZN_ENTRY_WORD_MAX);
	e.name.user[FZN_ENTRY_WORD_MAX] = '\0';
	memset(e.name.program, 'p', FZN_ENTRY_WORD_MAX);
	e.name.program[FZN_ENTRY_WORD_MAX] = '\0';
	memset(e.subsystem, 's', FZN_ENTRY_SUBSYSTEM_MAX);
	e.subsystem[FZN_ENTRY_SUBSYSTEM_MAX] = '\0';
	e.caused = 1;
	e.cause = e.name;
	e.origin = e.name;
	memset(big, 0xfe, sizeof(big));
	e.text = big;
	e.text_len = sizeof(big);
	CHECK(fzn_entry_pack(&e, rec, sizeof(rec), &len) == FZN_ENTRY_OK
	              && len == FZN_ENTRY_RECORD_MAX && fzn_entry_unpack(rec, len, &back) == FZN_ENTRY_OK
	              && back.caused && same_name(&back.origin, &e.origin)
	              && back.text_len == sizeof(big),
	      "the largest record is 4672 bytes, as the schema says, and unpacks");
	CHECK(fzn_entry_pack(&e, rec, len - 1u, &len) == FZN_ENTRY_ERR_ROOM,
	      "a buffer one short is refused");
	(void)host;

	/* RECORDS THAT ARE NOT ONES. */
	e = base();
	(void)fzn_entry_pack(&e, rec, sizeof(rec), &len);
	CHECK(fzn_entry_unpack(rec, len - 1u, &back) == FZN_ENTRY_ERR_MALFORMED
	              && fzn_entry_unpack(rec, len + 1u, &back) == FZN_ENTRY_ERR_MALFORMED,
	      "a record one byte short, or with one byte past it, is refused");
	rec[0] = 2u;
	CHECK(fzn_entry_unpack(rec, len, &back) == FZN_ENTRY_ERR_MALFORMED,
	      "another version is refused");
	rec[0] = 1u;
	rec[1] = 9u;
	CHECK(fzn_entry_unpack(rec, len, &back) == FZN_ENTRY_ERR_MALFORMED,
	      "a ninth level is refused");
	rec[1] = FZN_ENTRY_WARNING;
	rec[len - 2u - e.text_len - 1u] = 1u; /* the cause count */
	CHECK(fzn_entry_unpack(rec, len, &back) == FZN_ENTRY_ERR_MALFORMED,
	      "a cause count of one -- half a cause -- is refused");
	e = base();
	strcpy(e.name.user, "a b");
	CHECK(fzn_entry_pack(&e, rec, sizeof(rec), &len) == FZN_ENTRY_ERR_MALFORMED,
	      "a record refuses what the line refuses");
}

int main(void)
{
	if (fzn_entry_machine_parse(MACHINE_HEX, 32u, machine) != FZN_ENTRY_OK) {
		fprintf(stderr, "  FAIL entry_test.c: the fixture's machine did not parse\n");
		return 1;
	}
	test_the_line();
	test_times();
	test_text_is_one_line_and_reads_back();
	test_causes();
	test_names();
	test_fields_a_line_cannot_hold();
	test_lines_that_are_not_ours();
	test_the_record();
	CHECK(fzn_entry_level_letter(FZN_ENTRY_CRITICAL) == 'C' && fzn_entry_level_letter(FZN_ENTRY_TRACE) == 'T'
	              && fzn_entry_level_letter((fzn_entry_level_t)0) == 0,
	      "the levels' letters");

	if (failures) {
		fprintf(stderr, "entry_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("entry_test: all %d checks passed\n", checks);
	return 0;
}
