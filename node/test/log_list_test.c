/* node/log_list.h, sec 711: `list log` reads a daemon's flight recorder
 * newest first, at a level and more severe, a page within one reply; every
 * entry once over the pages; a text too long cut and said so; and the
 * refusals. */
#define _POSIX_C_SOURCE 200809L
#include "../log_list.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL log_list_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_ring_t ring;
static char reply[FZN_REPLY_MAX];

static int put(uint64_t position, fzn_entry_level_t level, const char *text, size_t text_len)
{
	fzn_entry_t e;

	memset(&e, 0, sizeof(e));
	memset(e.name.machine, 0x5a, sizeof(e.name.machine));
	strcpy(e.name.user, "funk");
	strcpy(e.name.program, "fuzznetd");
	e.name.pid = 812u;
	e.name.start_ms = 1727778001000u;
	e.name.position = position;
	e.time_us = 1790944496000000u + position;
	e.level = level;
	strcpy(e.subsystem, "node/round");
	e.text = (const uint8_t *)text;
	e.text_len = text_len;
	return fzn_ring_put(&ring, &e) == FZN_RING_OK;
}

static size_t ask(const fzn_ring_t *r, fzn_origin_t origin, fzn_verb_t verb, const char *arg)
{
	fzn_request_t req;

	memset(&req, 0, sizeof(req));
	req.parsed = verb;
	req.arg = (const uint8_t *)arg;
	req.arg_len = strlen(arg);
	memset(reply, 0, sizeof(reply));
	return fzn_node_log_list_local(r, origin, &req, reply, sizeof(reply));
}

static size_t listed(const char *arg)
{
	return ask(&ring, FZN_ORIGIN_SAME_USER, FZN_VERB_LIST, arg);
}

/* THE FIRST PAGES: empty, then five entries of three levels read newest
 * first, at the default level, from an offset, at another level; a text
 * escaped. */
static void test_a_page(void)
{
	fzn_ring_init(&ring);
	CHECK(listed("log") > 0 && strcmp(reply, "ok 0 0\n") == 0,
	      "an empty ring is not nothing logged yet");
	CHECK(put(1, FZN_ENTRY_INFO, "one", 3) && put(2, FZN_ENTRY_DEBUG, "two", 3)
	              && put(3, FZN_ENTRY_WARNING, "three", 5) && put(4, FZN_ENTRY_INFO, "four", 4)
	              && put(5, FZN_ENTRY_ERROR, "a b,c", 5),
	      "fixture: five entries");
	CHECK(listed("log") > 0
	              && strcmp(reply, "ok 4 0 1790944496000005,E,node/round,0,a%20b%2cc"
	                               " 1790944496000004,I,node/round,0,four"
	                               " 1790944496000003,W,node/round,0,three"
	                               " 1790944496000001,I,node/round,0,one\n")
	                         == 0,
	      "not the four at info and above, newest first, the space and comma escaped");
	CHECK(listed("log 2") > 0
	              && strcmp(reply, "ok 4 2 1790944496000003,W,node/round,0,three"
	                               " 1790944496000001,I,node/round,0,one\n")
	                         == 0,
	      "from 2 did not pass over the two newest");
	CHECK(listed("log 9") > 0 && strcmp(reply, "ok 4 4\n") == 0,
	      "from past the end is not an empty page at the end");
	CHECK(listed("log 0 D") > 0 && strncmp(reply, "ok 5 0 ", 7u) == 0
	              && strstr(reply, ",D,node/round,0,two") != NULL,
	      "at D the debug entry is not listed");
	CHECK(listed("log 0 E") > 0
	              && strcmp(reply, "ok 1 0 1790944496000005,E,node/round,0,a%20b%2cc\n") == 0,
	      "at E not the error alone");
}

/* EVERY ENTRY ONCE over the pages, each page within a reply; a text too
 * long for one cut, said so, and the page still moving on. */
static void test_the_pages(void)
{
	static char seen[300];
	static char text[4000];
	size_t from = 0, total = 0, pages = 0, i;
	int ordered = 1, within = 1;
	unsigned long long last = ~0ull;

	fzn_ring_init(&ring);
	for (i = 0; i < 300u; i++) {
		char t[16];

		(void)snprintf(t, sizeof(t), "entry %zu", i);
		if (!put(i, FZN_ENTRY_INFO, t, strlen(t)))
			break;
	}
	CHECK(i == 300u, "fixture: three hundred entries");
	memset(seen, 0, sizeof(seen));
	for (;;) {
		size_t n = listed(from ? (snprintf(text, sizeof(text), "log %zu", from), text) : "log");
		char *at, *save = NULL, *word;
		size_t got = 0, f = 0;

		if (!n || n >= sizeof(reply) || sscanf(reply, "ok %zu %zu", &total, &f) != 2
		    || f != from) {
			within = 0;
			break;
		}
		pages++;
		/* PAST "ok TOTAL FROM": the third space. */
		at = strchr(strchr(strchr(reply, ' ') + 1, ' ') + 1, ' ');
		/* NONE PAST IT: the page past the last, which ends the paging. */
		if (!at)
			break;
		for (word = strtok_r(at, " \n", &save); word; word = strtok_r(NULL, " \n", &save)) {
			unsigned long long t = strtoull(word, NULL, 10);
			const char *p = strstr(word, ",entry%20");
			size_t k = p ? (size_t)strtoul(p + 9, NULL, 10) : 300u;

			if (t >= last)
				ordered = 0;
			last = t;
			if (k < 300u)
				seen[k]++;
			got++;
		}
		if (!got)
			break;
		from += got;
		if (pages > 300u)
			break;
	}
	for (i = 0; i < 300u && seen[i] == 1; i++)
		;
	CHECK(within && total == 300u && i == 300u && pages > 1u && ordered,
	      "over the pages, not every entry once, newest first, each page within a reply");

	fzn_ring_init(&ring);
	memset(text, 'x', sizeof(text));
	CHECK(put(1, FZN_ENTRY_INFO, "short", 5) && put(2, FZN_ENTRY_WARNING, text, sizeof(text)),
	      "fixture: a text past a reply");
	CHECK(listed("log") > 0 && strlen(reply) < sizeof(reply)
	              && strncmp(reply, "ok 2 0 1790944496000002,W,node/round,1,xxx", 42u) == 0,
	      "a text too long for a reply was not cut and said to be");
	CHECK(listed("log 1") > 0
	              && strcmp(reply, "ok 2 1 1790944496000001,I,node/round,0,short\n") == 0,
	      "the page after a cut entry did not move on");
}

static void test_the_refusals(void)
{
	CHECK(ask(&ring, FZN_ORIGIN_LOCAL, FZN_VERB_LIST, "log") > 0
	              && strncmp(reply, "denied", 6u) == 0,
	      "another local user read the node's log");
	CHECK(listed("log x") > 0 && strncmp(reply, "malformed", 9u) == 0
	              && listed("log 0 Q") > 0 && strncmp(reply, "malformed", 9u) == 0
	              && listed("log 0 I extra") > 0 && strncmp(reply, "malformed", 9u) == 0,
	      "a malformed list log was answered");
	CHECK(ask(NULL, FZN_ORIGIN_SAME_USER, FZN_VERB_LIST, "log") > 0
	              && strncmp(reply, "error this node keeps no log", 28u) == 0,
	      "a node with no log did not say so");
	CHECK(listed("logs") == 0 && ask(&ring, FZN_ORIGIN_SAME_USER, FZN_VERB_GET, "log") == 0
	              && listed("contact") == 0,
	      "another request was answered as list log");
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
	test_a_page();
	test_the_pages();
	test_the_refusals();
	test_the_suite_can_tell_pass_from_fail();

	printf("log_list_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
