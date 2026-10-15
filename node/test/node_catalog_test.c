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
	if (failures) {
		fprintf(stderr, "node node_catalog_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node node_catalog_test: all %d checks passed\n", checks);
	return 0;
}
