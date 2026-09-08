/* Tests that `link/` says what happened, not only what it returned.
 *
 * THE CASE THIS FILE EXISTS FOR is the hazard `link.h` documents and no
 * return value carries: `fzn_link_snapshot` reports a `dropped` count, and
 * what that number does not say is that the dropped links are the SAME ones
 * every call. This table never reorders, so truncation always takes the most
 * recently registered -- and being dropped is self-sustaining, since `sched/`
 * never sees them, so nothing is sent on them, so they are never measured. A
 * consumer can be told the network is down while a healthy link sits one
 * index past the bound, for ever.
 *
 * A caller that reads `dropped` learns a number. A caller reading a log
 * learns the sentence. project.md sec 209, and the copyright holder's
 * requirement that the first line of troubleshooting is always a log.
 *
 * BUILT ONLY WITH flog, like the Monocypher suites: the library compiles and
 * behaves identically without it, and there is nothing to assert about a
 * logger that is not there.
 */

#include "../link.h"
#include "flog.h"

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
	fprintf(stderr, "  FAIL link_log_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* What the log saw. The strings are BORROWED for the length of the call, so
 * anything kept has to be copied here -- which is flog's documented contract
 * and is why it needs no allocator. */
static struct {
	int calls;
	flog_msg_type_t type;
	char subsystem[128];
	char text[512];
} seen;

static int capture(flog_t *p, const flog_msg_t *m)
{
	(void)p;
	seen.calls++;
	seen.type = m->type;
	seen.subsystem[0] = '\0';
	seen.text[0] = '\0';
	if (m->subsystem)
		snprintf(seen.subsystem, sizeof(seen.subsystem), "%s", m->subsystem);
	if (m->text)
		snprintf(seen.text, sizeof(seen.text), "%s", m->text);
	return 0;
}

int main(void)
{
	fzn_link_entry_t entries[8];
	fzn_link_table_t table;
	fzn_sched_candidate_t out[2];
	flog_t log;
	size_t dropped = 0u;
	size_t n;
	uint32_t i;

	/* A LOG ON THE STACK, which is the arrangement that makes this usable
	 * from a library that never allocates: flog's default config puts a
	 * `flog_t` wherever the caller puts it. */
	init_flog_t(&log);
	log.name = NULL;
	log.accepted_msg_type = FLOG_ACCEPT_ALL;
	log.output_func = capture;

	CHECK(fzn_link_table_init(&table, entries, 8u) == FZN_LINK_OK, "init refused");

	/*
	 * A TABLE IS QUIET UNTIL SOMEBODY ASKS, and this creates the condition
	 * rather than hoping for it.
	 *
	 * `fzn_link_table_init` clears the log so a table on a caller's stack
	 * does not carry whatever was there. Testing that by leaving the
	 * struct uninitialised would depend on stack luck and, when the guard
	 * IS removed, on following a garbage pointer -- undefined behaviour
	 * that crashes rather than failing. So a REAL log is planted first:
	 * with the clear in place `init` removes it and nothing is emitted;
	 * with the clear gone the log survives and the emit is recorded, which
	 * is an assertion failing rather than a segfault.
	 */
	fzn_link_set_log(&table, &log);
	CHECK(fzn_link_table_init(&table, entries, 8u) == FZN_LINK_OK, "init refused");
	memset(&seen, 0, sizeof(seen));
	for (i = 0u; i < 4u; i++)
		CHECK(fzn_link_register(&table, i, 10u, 40u, 0u, 1200u) == FZN_LINK_OK,
		      "register refused");
	n = fzn_link_snapshot(&table, out, 2u, &dropped);
	CHECK(n == 2u && dropped == 2u, "the fixture did not drop anything");
	CHECK(seen.calls == 0,
	      "a table nobody gave a log to emitted anyway, so a caller's stack decides "
	      "whether this library talks");

	/* THE CASE THIS FILE EXISTS FOR. */
	fzn_link_set_log(&table, &log);
	memset(&seen, 0, sizeof(seen));
	dropped = 0u;
	n = fzn_link_snapshot(&table, out, 2u, &dropped);
	CHECK(n == 2u, "the snapshot did not fill what it could");
	CHECK(dropped == 2u, "the fixture stopped dropping links");
	CHECK(seen.calls == 1, "links fell past the bound and nothing was said");
	CHECK(seen.type == FLOG_WARN,
	      "links permanently invisible to selection were not reported as a warning");
	CHECK(strcmp(seen.subsystem, "link/snapshot") == 0,
	      "the event did not name the subsystem it came from, so a consumer cannot "
	      "filter it or find it");
	CHECK(strstr(seen.text, "never measured") != NULL,
	      "the line reports the count and not the consequence -- a caller already "
	      "HAD the count, and what it could not have is that these links are never "
	      "sent on and so never gather evidence");

	/* NOTHING DROPPED, NOTHING SAID. A log that speaks on the ordinary path
	 * is one whose warnings nobody reads. */
	memset(&seen, 0, sizeof(seen));
	dropped = 0u;
	n = fzn_link_snapshot(&table, out, 2u, &dropped);
	CHECK(n == 2u && dropped == 2u, "the fixture changed under the test");
	{
		fzn_link_entry_t few[2];
		fzn_link_table_t small;

		CHECK(fzn_link_table_init(&small, few, 2u) == FZN_LINK_OK, "init refused");
		fzn_link_set_log(&small, &log);
		CHECK(fzn_link_register(&small, 1u, 10u, 40u, 0u, 1200u) == FZN_LINK_OK,
		      "register refused");
		memset(&seen, 0, sizeof(seen));
		dropped = 0u;
		n = fzn_link_snapshot(&small, out, 2u, &dropped);
		CHECK(n == 1u && dropped == 0u, "a table that fits reported a drop");
		CHECK(seen.calls == 0,
		      "a snapshot that dropped nothing warned anyway, which is how a "
		      "warning stops meaning anything");
	}

	/* THE MASK IS OBEYED, so a consumer that does not want warnings does
	 * not get them -- and this is flog's filter rather than ours, which is
	 * the point of not having written one. */
	log.accepted_msg_type = FLOG_ACCEPT_ONLY_CRITICAL;
	memset(&seen, 0, sizeof(seen));
	dropped = 0u;
	(void)fzn_link_snapshot(&table, out, 2u, &dropped);
	CHECK(dropped == 2u, "the fixture stopped dropping links");
	CHECK(seen.calls == 0, "a severity outside the consumer's mask was delivered");
	log.accepted_msg_type = FLOG_ACCEPT_ALL;

	/* AND SILENCE IS RESTORABLE, since a consumer may want to stop. */
	fzn_link_set_log(&table, NULL);
	memset(&seen, 0, sizeof(seen));
	dropped = 0u;
	(void)fzn_link_snapshot(&table, out, 2u, &dropped);
	CHECK(seen.calls == 0, "a table told to be quiet kept talking");

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("link_log_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
