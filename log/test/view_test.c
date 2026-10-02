/* view_test -- the shortened view of a run of entries. sec 467. */

#include "../view.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL view_test.c:%d: %s\n", __LINE__, what);        \
		}                                                                              \
	} while (0)

static fzn_entry_t entry(uint64_t position, uint64_t time_us, const char *subsystem,
                         const char *text)
{
	fzn_entry_t e;

	memset(&e, 0, sizeof(e));
	strcpy(e.name.user, "root");
	strcpy(e.name.program, "fuzznetd");
	e.name.pid = 4121u;
	e.name.start_ms = 1727778896123u;
	e.name.position = position;
	e.time_us = time_us;
	e.level = FZN_ENTRY_WARNING;
	strcpy(e.subsystem, subsystem);
	e.text = (const uint8_t *)text;
	e.text_len = strlen(text);
	return e;
}

static char out[20000];

static const char *view(const fzn_entry_t *prev, const fzn_entry_t *cur, const char *host)
{
	size_t len = 0;

	if (fzn_entry_view(prev, prev ? "nabbe" : NULL, cur, host, out, sizeof(out), &len)
	    != FZN_ENTRY_OK)
		return "refused";
	return out;
}

int main(void)
{
	/* 2026-10-02T12:34:56.789123Z, as entry_test's datetime vector. */
	const uint64_t T = 1790944496789123u;
	fzn_entry_t a = entry(1834u, T, "notes/sync", "a record refused");
	fzn_entry_t b = entry(1835u, T + 1u, "notes/push", "1 record to R");
	fzn_entry_t c = entry(1836u, T + 2u, "notes/push", "1 record from R");
	fzn_entry_t d = entry(0u, T + 3u, "notes/push", "started");
	fzn_entry_t e = entry(1837u, T + 86400000000u, "notes/push", "a day on");
	fzn_entry_t f = entry(1838u, T + 86400000001u, "notes/push", "two\nlines");
	size_t len = 0;

	CHECK(strcmp(view(NULL, &a, "nabbe"), "-- 2026-10-02 --\n12:34:56.789123 nabbe root fuzznetd "
	                                      "4121@1727778896123 #1834 W notes/sync a record refused\n")
	              == 0,
	      "the first entry shows its date, then every field");
	CHECK(strcmp(view(&a, &b, "nabbe"), "12:34:56.789124 #1835 W notes/push 1 record to R\n") == 0,
	      "the same instance hides its host, user, program and instance; a new subsystem shows");
	CHECK(strcmp(view(&b, &c, "nabbe"), "12:34:56.789125 #1836 W 1 record from R\n") == 0,
	      "and the same subsystem hides too; the position and the level always show");
	d.name.pid = 4200u;
	CHECK(strcmp(view(&c, &d, "nabbe"),
	             "12:34:56.789126 4200@1727778896123 #0 W notes/push started\n")
	              == 0,
	      "a new instance shows from the instance down, its subsystem included though the same");
	CHECK(strcmp(view(&c, &c, "other"),
	             "12:34:56.789125 other root fuzznetd 4121@1727778896123 #1836 W notes/push 1 "
	             "record from R\n")
	              == 0,
	      "another host shows the whole tree");
	CHECK(strcmp(view(&c, &e, "nabbe"), "-- 2026-10-03 --\n12:34:56.789123 nabbe root fuzznetd "
	                                    "4121@1727778896123 #1837 W notes/push a day on\n")
	              == 0,
	      "a new day writes its date and starts the tree again");
	CHECK(strstr(view(&e, &f, "nabbe"), "two\\x0alines\n") != NULL,
	      "the text is escaped as the line escapes it, one entry one line");
	c.caused = 1;
	c.cause = a.name;
	c.origin = a.name;
	CHECK(strcmp(view(&b, &c, "nabbe"),
	             "12:34:56.789125 #1836 W <4121@1727778896123#1834 1 record from R\n")
	              == 0,
	      "a cause shows as its instance field, and an origin the same as it does not");
	c.origin.position = 2u;
	CHECK(strstr(view(&b, &c, "nabbe"), " <4121@1727778896123#1834 <<4121@1727778896123#2 ")
	              != NULL,
	      "an origin that is another entry shows as well");
	CHECK(fzn_entry_view(&b, "nabbe", &c, "nabbe", out, 20u, &len) == FZN_ENTRY_ERR_ROOM
	              && out[0] == '\0',
	      "a view that does not fit is refused, and nothing left");
	CHECK(fzn_entry_view(&b, NULL, &c, "nabbe", out, sizeof(out), &len)
	              == FZN_ENTRY_ERR_MALFORMED,
	      "a previous entry with no host is refused");

	if (failures) {
		fprintf(stderr, "view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("view_test: all %d checks passed\n", checks);
	return 0;
}
