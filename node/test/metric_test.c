/* node metric_test -- the metric layer's table, sec 1055: names, the estimate
 * `link/`'s to the bit, the caller's room, and a listing by prefix in pages. */

#include "../metric.h"
#include "../../link/link.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                  \
	do {                                                                               \
		checks++;                                                                  \
		if (!(cond)) {                                                             \
			failures++;                                                        \
			fprintf(stderr, "  FAIL metric_test.c:%d: %s\n", __LINE__, what);  \
		}                                                                          \
	} while (0)

static void test_names(void)
{
	static fzn_metrics_t m;
	char long_name[FZN_METRIC_NAME_MAX + 2u];

	fzn_metrics_init(&m);
	memset(long_name, 'a', sizeof(long_name) - 1u);
	long_name[sizeof(long_name) - 1u] = '\0';
	CHECK(!fzn_metrics_open(&m, "", 1u) && !fzn_metrics_open(&m, NULL, 1u)
	              && !fzn_metrics_open(&m, "a b", 1u) && !fzn_metrics_open(&m, "a,b", 1u)
	              && !fzn_metrics_open(&m, long_name, 1u),
	      "a name out of shape was taken");
	CHECK(fzn_metrics_open(&m, "link/x/latency", 1000u) != NULL
	              && fzn_metrics_open(&m, "link/x/latency", 5u) == fzn_metrics_get(&m, "link/x/latency")
	              && m.n == 1u && fzn_metrics_get(&m, "link/x/latency")->estimate == 1000u,
	      "a name opened again was not the row it named, its prior kept");
	CHECK(fzn_metrics_get(&m, "link/y/latency") == NULL
	              && !fzn_metrics_observe(&m, "link/y/latency", 1u, 1u),
	      "a name never opened was found or observed");
	CHECK(fzn_metrics_get(&m, "link/x/latency")->observations == 0u,
	      "a prior read as an observation");
}

/* THE ESTIMATE IS `link/`'s, sample for sample, rising and falling. */
static void test_the_estimate_is_links(void)
{
	static fzn_metrics_t m;
	static fzn_link_entry_t entries[1];
	fzn_link_table_t t;
	static const uint32_t samples[] = { 40, 40, 900, 12, 12, 12, 3000, 7, 7, 7, 7, 7, 7, 7, 7,
		                            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7 };
	size_t i, same = 0;

	fzn_metrics_init(&m);
	(void)fzn_metrics_open(&m, "link/a/latency", 1000u);
	(void)fzn_link_table_init(&t, entries, 1u);
	(void)fzn_link_register(&t, 1u, 1u, 1000u, 250u, 1200u);
	for (i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
		(void)fzn_metrics_observe(&m, "link/a/latency", samples[i], 100u + i);
		(void)fzn_link_observe_ack(&t, 1u, samples[i], 100u + i);
		same += fzn_metrics_get(&m, "link/a/latency")->estimate == fzn_link_get(&t, 1u)->latency_ms;
	}
	CHECK(same == sizeof(samples) / sizeof(samples[0]), "the estimate parted from link/'s");
	CHECK(fzn_metrics_get(&m, "link/a/latency")->observations == i
	              && fzn_metrics_get(&m, "link/a/latency")->last_ms == 100u + i - 1u,
	      "observations or their time were not kept");
	/* A STEADY SAMPLE REACHED, not approached for ever: from 3000 at one part
	 * in eight, well within a hundred more. */
	for (i = 0; i < 100u; i++)
		(void)fzn_metrics_observe(&m, "link/a/latency", 7u, 200u + i);
	CHECK(fzn_metrics_get(&m, "link/a/latency")->estimate == 7u,
	      "a steady sample was not reached");
}

/* THE CALLER'S ROOM: a full table refuses a new name and keeps the old; moved
 * to larger room it keeps what it held and takes more. */
static void test_the_callers_room(void)
{
	static fzn_metrics_t m;
	static fzn_metric_t more[64];
	char name[32];
	size_t i;

	fzn_metrics_init(&m);
	for (i = 0; i < FZN_METRIC_OWN; i++) {
		(void)snprintf(name, sizeof(name), "n/%zu", i);
		(void)fzn_metrics_open(&m, name, i);
	}
	CHECK(!fzn_metrics_open(&m, "n/over", 1u) && fzn_metrics_get(&m, "n/0") != NULL,
	      "a full table took a new name, or forgot an old one");
	CHECK(!fzn_metrics_use(&m, more, FZN_METRIC_OWN - 1u),
	      "room smaller than what is held was taken");
	CHECK(fzn_metrics_use(&m, more, 64u) && fzn_metrics_open(&m, "n/over", 1u) != NULL
	              && fzn_metrics_get(&m, "n/15")->estimate == 15u && m.n == FZN_METRIC_OWN + 1u,
	      "larger room lost what was held, or took nothing more");
}

struct seen {
	char names[8][FZN_METRIC_NAME_MAX + 1u];
	size_t n;
};

static void seen_row(void *ctx, const fzn_metric_t *r)
{
	struct seen *s = ctx;

	if (s->n < 8u)
		(void)snprintf(s->names[s->n++], sizeof(s->names[0]), "%s", r->name);
}

/* A LISTING BY PREFIX, in pages. */
static void test_pages(void)
{
	static fzn_metrics_t m;
	struct seen s;
	size_t next = 0, got;

	fzn_metrics_init(&m);
	(void)fzn_metrics_open(&m, "link/a/latency", 1u);
	(void)fzn_metrics_open(&m, "meter/notes/up", 1u);
	(void)fzn_metrics_open(&m, "link/a/loss", 1u);
	(void)fzn_metrics_open(&m, "link/b/latency", 1u);
	memset(&s, 0, sizeof(s));
	got = fzn_metrics_page(&m, "link/", 0u, 2u, seen_row, &s, &next);
	CHECK(got == 2u && next == 2u && strcmp(s.names[0], "link/a/latency") == 0
	              && strcmp(s.names[1], "link/a/loss") == 0,
	      "a page under a prefix was not its first two, in order");
	memset(&s, 0, sizeof(s));
	got = fzn_metrics_page(&m, "link/", next, 2u, seen_row, &s, &next);
	CHECK(got == 1u && next == 3u && strcmp(s.names[0], "link/b/latency") == 0,
	      "the next page was not the rest");
	memset(&s, 0, sizeof(s));
	got = fzn_metrics_page(&m, "", 0u, 10u, seen_row, &s, &next);
	CHECK(got == 4u && next == 4u, "all of them were not listed under the empty prefix");
}

/* A COUNT, sec 1057: amounts added to a total, the rate the last whole window's
 * a second, nothing estimated. */
static void test_a_count(void)
{
	static fzn_metrics_t m;
	const fzn_metric_t *r;

	fzn_metrics_init(&m);
	(void)fzn_metrics_open(&m, "meter/notes/up", 0u);
	CHECK(fzn_metrics_count(&m, "meter/notes/up", 1000u, 10000u)
	              && fzn_metrics_count(&m, "meter/notes/up", 4000u, 12000u)
	              && fzn_metrics_count(&m, "meter/notes/up", 5000u, 14999u),
	      "fixture: three amounts within one window");
	r = fzn_metrics_get(&m, "meter/notes/up");
	CHECK(r->total == 10000u && r->rate == 0u && r->observations == 3u && r->estimate == 0u,
	      "amounts were not totalled, or a rate was said before a window ended");
	(void)fzn_metrics_count(&m, "meter/notes/up", 500u, 15000u);
	CHECK(r->total == 10500u && r->rate == 2000u,
	      "the window's end did not give its 10000 bytes over 5 s as 2000 a second");
	(void)fzn_metrics_count(&m, "meter/notes/up", 0u, 25000u);
	CHECK(r->rate == 50u, "a quiet window's rate was not what it carried, 500 over 10 s");
	CHECK(!fzn_metrics_count(&m, "meter/none", 1u, 1u), "a count with no row was taken");
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
	test_names();
	test_the_estimate_is_links();
	test_the_callers_room();
	test_pages();
	test_a_count();
	if (failures) {
		fprintf(stderr, "node metric_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node metric_test: all %d checks passed\n", checks);
	return 0;
}
