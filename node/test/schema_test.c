/* state/schema.h and node/schema.h, sec 686: the parsers a reader and a
 * writer share, a family found and its edges, overlap, fuzznet's own
 * declarations each sound, an extension's refused where it claims a cell,
 * and the verbs paged within one reply. */
#include "../schema.h"
#include "../../state/schema.h"
#include "../../state/setting.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL schema_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

#define B(s) (const uint8_t *)(s), strlen(s)

static void test_the_parsers(void)
{
	uint64_t n = 0;
	char host[16];
	uint16_t port = 0;

	CHECK(fzn_schema_flag(B("on")) == 1 && fzn_schema_flag(B("1")) == 1
	              && fzn_schema_flag(B("off")) == 0 && fzn_schema_flag(B("0")) == 0
	              && fzn_schema_flag(B("yes")) == -1 && fzn_schema_flag(B("01")) == -1
	              && fzn_schema_flag(B("")) == -1,
	      "a flag is not on, 1, off or 0 alone");
	CHECK(fzn_schema_count(B("255"), 1u, 255u, &n) && n == 255u
	              && !fzn_schema_count(B("256"), 1u, 255u, &n)
	              && !fzn_schema_count(B("0"), 1u, 255u, &n)
	              && fzn_schema_count(B("0"), 0u, 255u, &n) && n == 0u
	              && !fzn_schema_count(B("0001"), 0u, 255u, &n)
	              && !fzn_schema_count(B("1a"), 0u, 255u, &n) && !fzn_schema_count(B(""), 0u, 9u, &n),
	      "a count's bounds, its digit limit or its digits are wrong");
	CHECK(fzn_schema_count(B("1000000000000000000"), 0u, 1000000000000000000u, &n)
	              && n == 1000000000000000000u
	              && !fzn_schema_count(B("9999999999999999999"), 0u, 1000000000000000000u, &n),
	      "a count near the 64-bit edge overflowed or was taken past its bound");
	CHECK(fzn_schema_duration(B("14d"), 1u, 315360000u, &n) && n == 14u * 86400u
	              && fzn_schema_duration(B("90m"), 1u, 315360000u, &n) && n == 5400u
	              && fzn_schema_duration(B("30s"), 1u, 315360000u, &n) && n == 30u
	              && !fzn_schema_duration(B("3651d"), 1u, 315360000u, &n)
	              && !fzn_schema_duration(B("2w"), 1u, 315360000u, &n)
	              && !fzn_schema_duration(B("d"), 1u, 315360000u, &n)
	              && !fzn_schema_duration(B("0s"), 1u, 315360000u, &n),
	      "a duration's units, its bound or its shape are wrong");
	CHECK(fzn_schema_address(B("10.0.0.1 2947"), host, sizeof(host), &port)
	              && strcmp(host, "10.0.0.1") == 0 && port == 2947u
	              && fzn_schema_address(B("::1 9"), host, sizeof(host), &port) && port == 9u
	              && !fzn_schema_address(B("host"), host, sizeof(host), &port)
	              && !fzn_schema_address(B("h 0"), host, sizeof(host), &port)
	              && !fzn_schema_address(B("h 65536"), host, sizeof(host), &port)
	              && !fzn_schema_address(B("a_b 1"), host, sizeof(host), &port)
	              && !fzn_schema_address(B("averyveryverylonghost 1"), host, sizeof(host), &port)
	              && !fzn_schema_address(B("averyveryverylonghost 1"), NULL, 10u, NULL)
	              && fzn_schema_address(B("averyveryverylonghost 1"), NULL, 0u, NULL),
	      "an address's host, its port or its bound is read wrongly");
}

static const fzn_schema_entry_t TABLE[] = {
	{ "a/b", FZN_SCHEMA_COUNT, FZN_SCHEMA_ESTATE, 1u, 9u, "1", "", 0u, "an a", NULL },
	{ "fam/", FZN_SCHEMA_TEXT, FZN_SCHEMA_HOST, 1u, 4u, "", "", FZN_SCHEMA_VERB, "a family", NULL },
};

static void test_find_and_overlap(void)
{
	CHECK(fzn_schema_find(TABLE, 2u, B("a/b")) == &TABLE[0]
	              && fzn_schema_find(TABLE, 2u, B("a/bc")) == NULL
	              && fzn_schema_find(TABLE, 2u, B("a/")) == NULL,
	      "an exact key was found by a prefix of it, or a longer key found it");
	CHECK(fzn_schema_find(TABLE, 2u, B("fam/0af3")) == &TABLE[1]
	              && fzn_schema_find(TABLE, 2u, B("fam/")) == NULL
	              && fzn_schema_find(TABLE, 2u, B("fam/x/y")) == NULL
	              && fzn_schema_find(TABLE, 2u, B("fam/A")) == NULL,
	      "a family's instance is not one word of a-z and 0-9");
	CHECK(fzn_schema_overlap("a/b", "a/b") && fzn_schema_overlap("fam/", "fam/x")
	              && fzn_schema_overlap("fam/x", "fam/") && fzn_schema_overlap("fam/", "fam/sub/")
	              && !fzn_schema_overlap("a/b", "a/bc") && !fzn_schema_overlap("a/b", "b/a")
	              && fzn_schema_overlap("a/", "a/b"),
	      "two declarations claiming one cell were not seen, or two apart were");
	CHECK(fzn_schema_check(&TABLE[1], B("abcd")) == NULL
	              && fzn_schema_check(&TABLE[1], B("abcde")) != NULL
	              && fzn_schema_check(&TABLE[1], (const uint8_t *)"a\tb", 3u) != NULL,
	      "a text's length or printability was not checked");
}

/* FUZZNET'S OWN, each sound: a key that is a key, a type, a scope, a
 * default its own check takes, and no two claiming one cell. */
static void test_fuzznets_declarations(void)
{
	size_t i, j, bad = 0, overlapping = 0;

	for (i = 0; i < fzn_node_schema_own_n; i++) {
		const fzn_schema_entry_t *e = &fzn_node_schema_own[i];

		if (!fzn_setting_key_ok((const uint8_t *)e->key, strlen(e->key)) || !e->scopes
		    || !e->summary || !e->summary[0]
		    || (e->def[0] && fzn_schema_check(e, B(e->def)) != NULL)) {
			printf("  declaration %s is not sound\n", e->key);
			bad++;
		}
		for (j = i + 1u; j < fzn_node_schema_own_n; j++)
			overlapping += fzn_schema_overlap(e->key, fzn_node_schema_own[j].key) ? 1u : 0u;
	}
	CHECK(fzn_node_schema_own_n >= 20u && bad == 0u && overlapping == 0u,
	      "one of fuzznet's declarations is not sound, or two claim one cell");
	CHECK(fzn_node_schema_find(NULL, B("archive/erasure")) != NULL
	              && fzn_schema_check(fzn_node_schema_find(NULL, B("archive/erasure")), B("30+3"))
	                         != NULL
	              && fzn_schema_check(fzn_node_schema_find(NULL, B("archive/erasure")), B("31+1"))
	                         == NULL,
	      "the erasure's K+M is not checked as its reader reads it");
}

static const fzn_schema_entry_t EXTRA[] = {
	{ "app/theme", FZN_SCHEMA_TEXT, FZN_SCHEMA_HOST, 1u, 16u, "dark", "", 0u, "a theme", NULL },
};

static void test_an_extensions(void)
{
	static const fzn_schema_entry_t claims[] = {
		{ "location/enabled", FZN_SCHEMA_FLAG, FZN_SCHEMA_HOST, 0u, 0u, "", "", 0u, "x", NULL },
	};
	static const fzn_schema_entry_t inside[] = {
		{ "sticker/abc", FZN_SCHEMA_TEXT, FZN_SCHEMA_HOST, 0u, 0u, "", "", 0u, "x", NULL },
	};
	static const fzn_schema_entry_t twice[] = {
		{ "app/", FZN_SCHEMA_TEXT, FZN_SCHEMA_HOST, 0u, 0u, "", "", 0u, "x", NULL },
		{ "app/x", FZN_SCHEMA_TEXT, FZN_SCHEMA_HOST, 0u, 0u, "", "", 0u, "x", NULL },
	};
	static const fzn_schema_entry_t scopeless[] = {
		{ "app/x", FZN_SCHEMA_TEXT, 0u, 0u, 0u, "", "", 0u, "x", NULL },
	};
	fzn_node_schema_t s = { EXTRA, 1u };

	CHECK(fzn_node_schema_refused(EXTRA, 1u) == NULL, "a sound extension's table was refused");
	CHECK(fzn_node_schema_refused(claims, 1u) && fzn_node_schema_refused(inside, 1u)
	              && fzn_node_schema_refused(twice, 2u) && fzn_node_schema_refused(scopeless, 1u),
	      "an extension claiming fuzznet's cell, inside its family, twice, or with no scope "
	      "was taken");
	CHECK(fzn_node_schema_find(&s, B("app/theme")) == &EXTRA[0]
	              && fzn_node_schema_find(&s, B("location/every")) != NULL
	              && fzn_node_schema_find(&s, B("app/other")) == NULL,
	      "an extension's key, or fuzznet's beside it, was not found");
}

static size_t ask(const fzn_node_schema_t *s, fzn_verb_t verb, const char *arg, char *reply,
                  size_t cap)
{
	fzn_request_t r;

	memset(&r, 0, sizeof(r));
	r.parsed = verb;
	r.arg = (const uint8_t *)arg;
	r.arg_len = strlen(arg);
	return fzn_node_schema_local((void *)s, FZN_ORIGIN_LOCAL, &r, reply, cap);
}

static void test_the_verbs(void)
{
	fzn_node_schema_t s = { EXTRA, 1u };
	/* TWICE THE CAP ASKED WITH, so a page past it is a failed check. */
	char reply[2048];
	const size_t cap = 1024u;
	size_t from = 0, seen = 0, pages = 0, total = fzn_node_schema_own_n + 1u, n;
	char want[16];
	int theme = 0;

	(void)snprintf(want, sizeof(want), "ok %zu ", total);
	for (;;) {
		char arg[32];
		size_t rows = 0;
		const char *w;

		(void)snprintf(arg, sizeof(arg), "schema %zu", from);
		n = ask(&s, FZN_VERB_LIST, arg, reply, cap);
		CHECK(n > 0 && n < cap && strncmp(reply, want, strlen(want)) == 0,
		      "a page is not within one reply, or does not say the total");
		if (!n || strncmp(reply, want, strlen(want)) != 0)
			return;
		w = strchr(reply + strlen(want), ' ');
		while (w && w[1] && w[1] != '\n') {
			rows++;
			theme |= strncmp(w + 1, "app/theme,text,host,1,16,dark,-,-,a%20theme", 43) == 0;
			w = strchr(w + 1, ' ');
		}
		if (!rows)
			break;
		seen += rows;
		from += rows;
		if (++pages > 50u)
			break;
	}
	CHECK(seen == total && pages >= 2u && theme,
	      "the pages did not give every declaration once, the extension's among them");
	CHECK(ask(&s, FZN_VERB_LIST, "schema location/", reply, cap) > 0
	              && strncmp(reply, "ok 4 0 location/enabled,flag,host,0,0,off,-,-,", 46) == 0,
	      "a prefix did not narrow the listing");
	CHECK(ask(&s, FZN_VERB_LIST, "schema location/ 3", reply, cap) > 0
	              && strncmp(reply, "ok 4 3 location/accuracy,count,host,0,1000000,100,metres,-,",
	                         59) == 0,
	      "a prefix and a FROM together were not read");
	CHECK(ask(&s, FZN_VERB_GET, "schema sticker/0aff", reply, cap) > 0
	              && strncmp(reply, "ok sticker/,text,estate+host,1,256,-,-,verb,", 44) == 0
	              && ask(&s, FZN_VERB_GET, "schema nope", reply, cap) > 0
	              && strcmp(reply, "error no such setting is declared\n") == 0,
	      "a family's instance was not answered as its family, or an undeclared key was");
	CHECK(ask(&s, FZN_VERB_LIST, "schema a b c", reply, cap) > 0
	              && strncmp(reply, "malformed", 9) == 0
	              && ask(&s, FZN_VERB_GET, "schema", reply, cap) > 0
	              && strncmp(reply, "malformed", 9) == 0
	              && ask(&s, FZN_VERB_LIST, "setting", reply, cap) == 0u,
	      "a bad listing or get was not refused, or another subject was answered");
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
	test_the_parsers();
	test_find_and_overlap();
	test_fuzznets_declarations();
	test_an_extensions();
	test_the_verbs();
	test_the_suite_can_tell_pass_from_fail();

	printf("schema_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
