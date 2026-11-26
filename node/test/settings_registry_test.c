/*
 * settings_registry_test -- fuzznet's own settings as situ generates them
 * from node/settings_registry.situ, held to agreeing with the table
 * node/schema.c writes by hand (project.md sec 1330): row by row -- the
 * key, its scope, its safe direction, its display words, its bounds, its
 * default, unit and summary -- and value by value, a corpus run through
 * both checkers.
 *
 * Where the hand entry has no check of its own the two must agree, but for
 * one known difference, counted and named: a number padded with leading
 * zeros past its bound's digits ("007" where 16 is the most), which the
 * hand parser refuses by counting digits and the registry, without
 * `[minimal]` since sec 1408, takes. A leading zero within the digits
 * ("07") the two now take alike. Where it has one -- a permit, a rank, a
 * group list, a log level or scope -- situ types the cell as printable
 * text, so it must take at least what the hand table takes.
 */
#include "../schema.h"
#include "../../state/schema.h"
#include "../../wire/generated/settings_registry.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

#define CHECK(cond, ...)                                                                                     \
	do {                                                                                                 \
		checks++;                                                                                    \
		if (!(cond)) {                                                                               \
			failures++;                                                                          \
			fprintf(stderr, "  FAIL settings_registry_test.c:%d: ", __LINE__);                   \
			fprintf(stderr, __VA_ARGS__);                                                        \
			fprintf(stderr, "\n");                                                               \
		}                                                                                            \
	} while (0)

static const fzn_settings_registry_node_entry_t *generated(const char *key)
{
	size_t i;

	for (i = 0; i < FZN_SETTINGS_REGISTRY_NODE_COUNT; i++)
		if (!strcmp(fzn_settings_registry_node_entries[i].key, key))
			return &fzn_settings_registry_node_entries[i];
	return NULL;
}

static int same_text(const char *hand, const char *gen)
{
	return (!hand || !*hand) ? (!gen || !*gen) : (gen && !strcmp(hand, gen));
}

/* THE HAND FLAGS AS SITU'S DISPLAY BITS. */
static uint32_t display_of(unsigned flags)
{
	return ((flags & FZN_SCHEMA_RESTART) ? FZN_SETTINGS_REGISTRY_DISPLAY_RESTART : 0u)
	       | ((flags & FZN_SCHEMA_SENSITIVE) ? FZN_SETTINGS_REGISTRY_DISPLAY_SENSITIVE : 0u)
	       | ((flags & FZN_SCHEMA_ADVANCED) ? FZN_SETTINGS_REGISTRY_DISPLAY_ADVANCED : 0u)
	       | ((flags & FZN_SCHEMA_VERB) ? FZN_SETTINGS_REGISTRY_DISPLAY_VERB : 0u)
	       | ((flags & FZN_SCHEMA_ADVERTISED) ? FZN_SETTINGS_REGISTRY_DISPLAY_ADVERTISED : 0u);
}

static void test_every_row_agrees(void)
{
	size_t i;

	CHECK(fzn_node_schema_own_n == FZN_SETTINGS_REGISTRY_NODE_COUNT, "the hand table has %zu cells, the registry %u",
	      fzn_node_schema_own_n, (unsigned)FZN_SETTINGS_REGISTRY_NODE_COUNT);
	for (i = 0; i < fzn_node_schema_own_n; i++) {
		const fzn_schema_entry_t *e = &fzn_node_schema_own()[i];
		const fzn_settings_registry_node_entry_t *g = generated(e->key);
		const int bounded = e->type == FZN_SCHEMA_COUNT || e->type == FZN_SCHEMA_DURATION;
		const int sized = e->type == FZN_SCHEMA_TEXT || e->type == FZN_SCHEMA_ADDRESS;
		const uint8_t safe = (e->flags & FZN_SCHEMA_SAFE_HIGHER)  ? FZN_SETTINGS_REGISTRY_SAFE_HIGHER
		                     : (e->flags & FZN_SCHEMA_SAFE_LOWER) ? FZN_SETTINGS_REGISTRY_SAFE_LOWER
		                                                          : 0u;

		CHECK(g != NULL, "%s is in the hand table and not the registry", e->key);
		if (!g)
			continue;
		CHECK(g->scope == e->scopes, "%s: scope %u, the hand table's %u", e->key, g->scope, e->scopes);
		CHECK(g->safe == safe, "%s: safe %u, the hand table's %u", e->key, g->safe, safe);
		CHECK(g->display == display_of(e->flags), "%s: display %u, the hand table's flags %u", e->key, g->display,
		      e->flags);
		CHECK(same_text(e->def, g->def), "%s: default %s, the hand table's %s", e->key, g->def ? g->def : "none",
		      e->def);
		CHECK(same_text(e->unit, g->unit), "%s: unit differs", e->key);
		CHECK(same_text(e->summary, g->summary), "%s: summary differs", e->key);
		if (bounded)
			CHECK(g->has_min && g->has_max && (uint64_t)g->min == e->min && (uint64_t)g->max == e->max,
			      "%s: bounds %lld..%lld, the hand table's %llu..%llu", e->key, (long long)g->min,
			      (long long)g->max, (unsigned long long)e->min, (unsigned long long)e->max);
		if (sized)
			CHECK(g->min_size == (uint32_t)e->min && g->max_size == (uint32_t)e->max,
			      "%s: sizes %u..%u, the hand table's %llu..%llu", e->key, g->min_size, g->max_size,
			      (unsigned long long)e->min, (unsigned long long)e->max);
	}
}

/* A NUMBER PADDED PAST ITS BOUND'S DIGITS -- the value, or an address's
 * port after its space, with a leading zero and more digits than `max`
 * (65535 for a port) has: the one difference allowed (sec 1408). */
static int padded_past(const char *v, uint64_t max)
{
	const char *space = strchr(v, ' ');
	const char *n = space ? space + 1 : v;
	size_t digits = 1;

	if (space)
		max = 65535u;
	while (max /= 10u)
		digits++;
	return n[0] == '0' && n[1] >= '0' && n[1] <= '9' && strlen(n) > digits;
}

/* THE TABLE IS THE REGISTRY'S ROWS, sec 1412: each row typed -- a cell
 * situ names that the table has no type for would read as none -- and
 * the nine grammars the registry types as text carry their checks. */
static void test_the_table_is_made_from_the_registry(void)
{
	static const char *const checked[] = { "archive/erasure", "local/permit/", "remote/permit/",
		                               "remote/permit", "local/events",  "pressure/rank/",
		                               "group/member",   "log/level",     "log/scope",
		                               "library/keep" };
	const fzn_schema_entry_t *own = fzn_node_schema_own();
	size_t i, k, with_check = 0, untyped = 0;

	CHECK(fzn_node_schema_own_n == FZN_SETTINGS_REGISTRY_NODE_COUNT, "the table is not the registry's rows");
	for (i = 0; i < fzn_node_schema_own_n; i++) {
		untyped += own[i].type < FZN_SCHEMA_FLAG || own[i].type > FZN_SCHEMA_TEXT;
		with_check += own[i].check != NULL;
	}
	CHECK(untyped == 0, "a row of the registry has no type in the table");
	CHECK(with_check == sizeof(checked) / sizeof(checked[0]), "%zu rows carry a check, not ten", with_check);
	for (k = 0; k < sizeof(checked) / sizeof(checked[0]); k++) {
		/* A FAMILY BY AN INSTANCE of it, as a setting names one. */
		char key[64];
		const size_t len = (size_t)snprintf(key, sizeof(key), "%s%s", checked[k],
		                                    checked[k][strlen(checked[k]) - 1u] == '/' ? "x" : "");
		const fzn_schema_entry_t *e = fzn_node_schema_find(NULL, (const uint8_t *)key, len);

		CHECK(e && e->check, "%s lost its own check", checked[k]);
	}
	/* `library/keep`, sec 1473: classes apart by single spaces, none twice. */
	{
		static const char *const good[] = { "music", "music video", "all", "video photos music" };
		static const char *const bad[] = { "", "music music", "music bogus", "music ", " music",
			                           "music  video", "Music" };
		const fzn_schema_entry_t *e = fzn_node_schema_find(NULL, (const uint8_t *)"library/keep", 12u);

		for (k = 0; e && e->check && k < sizeof(good) / sizeof(good[0]); k++)
			CHECK(!e->check((const uint8_t *)good[k], strlen(good[k])), "library/keep refused %s", good[k]);
		for (k = 0; e && e->check && k < sizeof(bad) / sizeof(bad[0]); k++)
			CHECK(e->check((const uint8_t *)bad[k], strlen(bad[k])) != NULL, "library/keep took '%s'", bad[k]);
	}
}

static void test_every_value_agrees(void)
{
	static const char *const corpus[] = {
		"", "0", "1", "2", "3", "4", "7", "10", "60", "100", "255", "256", "007", "00", "-1", "1e3",
		"on", "off", "yes", "ON", "45s", "14d", "1m", "1d", "0s", "10x", "d", "4+2", "3+3", "x",
		"laptop", "a b", "localhost 2947", "host 0", "host 65536", "host 007", " 2947", "ho_st 1",
		"255.255.255.255", "off ", "\x7f", "tab\there", "debug", "info", "estate", "host-private",
		"member", "group:x=r", "36500", "36501", "86400", "315360000", "315360001",
		"18446744073709551616", "1099511627776", "1099511627777",
	};
	size_t i, k, padded_only = 0, values = 0;

	for (i = 0; i < fzn_node_schema_own_n; i++) {
		const fzn_schema_entry_t *e = &fzn_node_schema_own()[i];
		const fzn_settings_registry_node_entry_t *g = generated(e->key);
		const char *extra[3] = { e->def, NULL, NULL };
		char lo[24], hi[24];

		if (!g)
			continue;
		if (e->type == FZN_SCHEMA_COUNT) {
			snprintf(lo, sizeof(lo), "%llu", (unsigned long long)e->min);
			snprintf(hi, sizeof(hi), "%llu", (unsigned long long)e->max);
			extra[1] = lo;
			extra[2] = hi;
		}
		for (k = 0; k < sizeof(corpus) / sizeof(corpus[0]) + 3u; k++) {
			const char *v = k < 3u ? extra[k] : corpus[k - 3u];
			int hand, gen;

			if (!v)
				continue;
			values++;
			hand = fzn_schema_check(e, (const uint8_t *)v, strlen(v)) == NULL;
			gen = fzn_settings_registry_node_check(g, (const uint8_t *)v, (uint32_t)strlen(v)) == SITU_OK;
			if (e->check) {
				CHECK(!hand || gen, "%s: \"%s\" the hand table takes and the registry refuses", e->key, v);
				continue;
			}
			if (!hand && gen && padded_past(v, e->max)) {
				padded_only++;
				continue;
			}
			CHECK(hand == gen, "%s: \"%s\" the hand table %s and the registry %s", e->key, v,
			      hand ? "takes" : "refuses", gen ? "takes" : "refuses");
		}
	}
	CHECK(padded_only > 0, "no padded spelling told the two apart: the known difference is gone, say so");
	printf("settings_registry_test: %zu values through both; %zu spellings padded past their bound the "
	       "registry alone takes\n",
	       values, padded_only);
}

/* A FAMILY'S INSTANCE is found as the hand table finds it. */
static void test_a_family_instance_is_found(void)
{
	static const char *const keys[] = { "stream/grant/abc", "metric/log/rate", "retention/r1", "stream/grant/",
		                            "stream/grant/A", "nowhere" };
	size_t i;

	for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		const fzn_schema_entry_t *e = fzn_schema_find(fzn_node_schema_own(), fzn_node_schema_own_n,
		                                              (const uint8_t *)keys[i], strlen(keys[i]));
		const fzn_settings_registry_node_entry_t *g =
		        fzn_settings_registry_node_find((const uint8_t *)keys[i], (uint32_t)strlen(keys[i]));

		CHECK((!e && !g) || (e && g && !strcmp(e->key, g->key)), "%s found as %s by hand and %s by situ", keys[i],
		      e ? e->key : "nothing", g ? g->key : "nothing");
	}
}

int main(void)
{
	test_every_row_agrees();
	test_the_table_is_made_from_the_registry();
	test_every_value_agrees();
	test_a_family_instance_is_found();
	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "node settings_registry_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node settings_registry_test: all %d checks passed\n", checks);
	return 0;
}
