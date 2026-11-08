/* node node_catalog_test -- the catalogue as a node's journal says it, sec
 * 633: an issuer's latest record of an attribute stands, a retraction takes
 * it back, an older record changes nothing, and who holds a file is read as
 * `catalog/` reads it. */

#include "../catalog.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                    \
	do {                                                                                 \
		checks++;                                                                    \
		if (!(cond)) {                                                               \
			failures++;                                                          \
			fprintf(stderr, "  FAIL node_catalog_test.c:%d: %s\n", __LINE__, what); \
		}                                                                            \
	} while (0)

static fzn_node_catalog_t cat;

/* An ATTRIBUTE body: `name` = `value`, a label each host may hold. */
static size_t attribute(const char *name, const char *value, uint8_t *out, size_t cap)
{
	fzn_catalog_assertion_t a;
	size_t len = 0;

	memset(&a, 0, sizeof(a));
	a.name = (const uint8_t *)name;
	a.name_len = strlen(name);
	a.value = (const uint8_t *)value;
	a.value_len = strlen(value);
	a.attr_class = FZN_CATALOG_LABEL;
	a.scope = FZN_CATALOG_ESTATE;
	a.merge = FZN_CATALOG_DISTINCT;
	a.capability = FZN_CATALOG_CAP_HOLDER;
	return fzn_catalog_attribute_encode(&a, out, cap, &len) == FZN_CATALOG_OK ? len : 0u;
}

static size_t holders_of(const uint8_t *entity)
{
	static fzn_catalog_assertion_t set[16];
	fzn_catalog_issuer_t who[4];
	size_t n = fzn_node_catalog_assertions(&cat, entity, set, 16u), count = 0, dropped = 0;

	if (fzn_catalog_holders(set, n, entity, 32u, who, 4u, &count, &dropped) != FZN_CATALOG_OK)
		return 99u;
	return count;
}

static void test_the_latest_record_stands(void)
{
	uint8_t a[32], b[32], song[32], body[256];
	fzn_catalog_assertion_t set[8];
	size_t len, n;

	memset(a, 0xaa, sizeof(a));
	memset(b, 0xbb, sizeof(b));
	memset(song, 0x50, sizeof(song));
	fzn_node_catalog_init(&cat);
	len = attribute("name", "first", body, sizeof(body));
	CHECK(len && fzn_node_catalog_take(&cat, a, song, 5u, FZN_CATALOG_ATTRIBUTE_KIND, body, len)
	                     == FZN_NODE_CATALOG_OK,
	      "an attribute was not taken");
	len = attribute("name", "second", body, sizeof(body));
	CHECK(fzn_node_catalog_take(&cat, a, song, 7u, FZN_CATALOG_ATTRIBUTE_KIND, body, len)
	              == FZN_NODE_CATALOG_OK,
	      "a later attribute was not taken");
	len = attribute("name", "older", body, sizeof(body));
	CHECK(fzn_node_catalog_take(&cat, a, song, 6u, FZN_CATALOG_ATTRIBUTE_KIND, body, len)
	              == FZN_NODE_CATALOG_ERR_STALE,
	      "an older record replaced a later one");
	n = fzn_node_catalog_assertions(&cat, song, set, 8u);
	CHECK(n == 1u && set[0].live && set[0].value_len == 6u
	              && memcmp(set[0].value, "second", 6u) == 0,
	      "the latest value did not stand alone");
	len = attribute("name", "mine", body, sizeof(body));
	(void)fzn_node_catalog_take(&cat, b, song, 2u, FZN_CATALOG_ATTRIBUTE_KIND, body, len);
	CHECK(fzn_node_catalog_assertions(&cat, song, set, 8u) == 2u && holders_of(song) == 2u,
	      "two issuers' assertions were not two holders");
	CHECK(fzn_node_catalog_take(&cat, a, song, 8u, FZN_CATALOG_RETRACT_KIND,
	                            (const uint8_t *)"name", 4u)
	                      == FZN_NODE_CATALOG_OK
	              && holders_of(song) == 1u,
	      "a retraction did not take the issuer's assertion back");
	len = attribute("name", "back", body, sizeof(body));
	CHECK(fzn_node_catalog_take(&cat, a, song, 7u, FZN_CATALOG_ATTRIBUTE_KIND, body, len)
	                      == FZN_NODE_CATALOG_ERR_STALE
	              && holders_of(song) == 1u,
	      "a record from before the retraction brought it back");
	CHECK(fzn_node_catalog_take(&cat, a, song, 9u, 0x36u, body, len)
	              == FZN_NODE_CATALOG_ERR_MALFORMED,
	      "a record of another kind was taken");
}

/* A LIBRARY, sec 953: 20000 files of three attributes each, held by two
 * hosts, every one kept and found -- a fixed 1024 listed about 340 files.
 * Retracting a third of the names leaves them counted dead; a later record
 * of an entry changes it in place. */
#define LIBRARY 20000u

static void test_a_library_is_kept_whole(void)
{
	static const char *const NAMES[] = { "name", "kind", "duration" };
	uint8_t a[32], b[32], file[32], body[256];
	fzn_catalog_assertion_t set[8], one;
	size_t i, k, len, wrong = 0, live = 0;
	char value[32];

	fzn_node_catalog_free(&cat);
	memset(a, 0xaa, sizeof(a));
	memset(b, 0xbb, sizeof(b));
	memset(file, 0, sizeof(file));
	for (i = 0; i < LIBRARY; i++) {
		memcpy(file, &i, sizeof(i));
		for (k = 0; k < 3u; k++) {
			snprintf(value, sizeof(value), "%s%zu", NAMES[k], i);
			len = attribute(NAMES[k], value, body, sizeof(body));
			wrong += fzn_node_catalog_take(&cat, i % 2u ? a : b, file, i + 1u,
			                               FZN_CATALOG_ATTRIBUTE_KIND, body, len)
			         != FZN_NODE_CATALOG_OK;
		}
	}
	CHECK(wrong == 0u && cat.count == 3u * LIBRARY && cat.live == 3u * LIBRARY,
	      "a library past any table was not kept whole");
	for (i = 0; i < LIBRARY; i += 3u) {
		memcpy(file, &i, sizeof(i));
		wrong += fzn_node_catalog_take(&cat, i % 2u ? a : b, file, i + 2u,
		                               FZN_CATALOG_RETRACT_KIND, (const uint8_t *)"name", 4u)
		         != FZN_NODE_CATALOG_OK;
	}
	for (i = 0; i < LIBRARY; i++) {
		memcpy(file, &i, sizeof(i));
		snprintf(value, sizeof(value), "kind%zu", i);
		if (fzn_node_catalog_count_of(&cat, file) != 3u
		    || fzn_node_catalog_assertions(&cat, file, set, 8u) != 3u
		    || set[0].name_len != 4u || memcmp(set[0].name, "name", 4u) != 0
		    || set[0].live != (i % 3u != 0u) || set[1].value_len != strlen(value)
		    || memcmp(set[1].value, value, set[1].value_len) != 0)
			wrong++;
	}
	for (i = 0; i < cat.count; i++) {
		fzn_node_catalog_assertion_at(&cat, i, &one);
		live += one.live != 0;
	}
	CHECK(wrong == 0u && cat.count == 3u * LIBRARY && cat.live == live
	              && live == 3u * LIBRARY - (LIBRARY + 2u) / 3u,
	      "a file's entries were not found by it, in order, or the live count drifted");
	/* THE FIRST `cap` TAKEN, when fewer are asked for than there are. */
	memset(file, 0, sizeof(file));
	i = 7u;
	memcpy(file, &i, sizeof(i));
	memset(set, 0, sizeof(set));
	CHECK(fzn_node_catalog_assertions(&cat, file, set, 2u) == 2u && set[0].name_len == 4u
	              && memcmp(set[0].name, "name", 4u) == 0 && set[1].name_len == 4u
	              && memcmp(set[1].name, "kind", 4u) == 0 && !set[2].name,
	      "a short read of a file's entries was not its first ones");
	fzn_node_catalog_free(&cat);
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
	test_the_latest_record_stands();
	test_a_library_is_kept_whole();
	if (failures) {
		fprintf(stderr, "node node_catalog_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node node_catalog_test: all %d checks passed\n", checks);
	return 0;
}
