/* Tests for chain/service.c: the service namespace a capability must name,
 * and the product namespace that filters what a holder may see.
 *
 * THE CASE THIS FILE EXISTS FOR is that a capability minted for one service
 * must not authorise another, and the only thing making that true is that
 * the service is inside the derivation. So the assertions here are
 * RELATIONSHIPS between derivations -- change one input, the capability
 * changes -- rather than any particular thirty-two bytes, which would pin
 * this stub hash instead of the property. project.md sec 129.
 *
 * A plausible wrong implementation drops one of the three inputs on the
 * floor, and each of those has a case here that separates it: drop the
 * service and two services collide, drop the product and the scoped
 * capability equals the wildcard one, drop the name and two verbs collide.
 */

#include "../service.h"
#include "../../record/record.h"

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
	fprintf(stderr, "  FAIL service_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)
#define REQUIRE(cond, ...)                                   \
	do {                                                 \
		int require_ok = (cond) ? 1 : 0;             \
		check_at(require_ok, __LINE__, __VA_ARGS__); \
		if (!require_ok)                             \
			return;                              \
	} while (0)

static int hash_refuses;

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	if (hash_refuses)
		return 0;
	for (i = 0; i < in_len; i++) {
		h ^= in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

#define LOGS 7u
#define FILESTORE 9u
#define NETCFGD 100u
#define FUZZYPICKLES 101u

static int same(fzn_cap_id_t a, fzn_cap_id_t b)
{
	return memcmp(a.b, b.b, FZN_CAP_ID_LEN) == 0;
}

static fzn_cap_id_t derive(uint32_t service, uint32_t product, const char *name)
{
	fzn_cap_id_t out;

	memset(&out, 0, sizeof(out));
	(void)fzn_service_capability(service, product, (const uint8_t *)name,
	                             name ? strlen(name) : 0u, &HASH, &out);
	return out;
}

/* THE MANDATORY HALF. A capability naming no service cannot be built, so
 * one cannot be presented. */
static void test_a_service_is_mandatory(void)
{
	fzn_cap_id_t out;

	memset(&out, 0xaa, sizeof(out));
	CHECK(fzn_service_capability(FZN_SERVICE_NONE, NETCFGD, NULL, 0, &HASH, &out)
	              == FZN_CHAIN_ERR_MALFORMED,
	      "an unspelled service produced a capability");
	CHECK(out.b[0] == 0xaa, "a refused derivation wrote to the caller's buffer");
}

/* The wildcard is not zero on purpose: a caller that forgets the field must
 * not thereby ask for every project's records. */
static void test_an_unspelled_product_is_refused_not_widened(void)
{
	fzn_cap_id_t zeroed, any;

	memset(&zeroed, 0, sizeof(zeroed));
	CHECK(fzn_service_capability(LOGS, FZN_PRODUCT_NONE, NULL, 0, &HASH, &zeroed)
	              == FZN_CHAIN_ERR_MALFORMED,
	      "an unspelled product was accepted");
	CHECK(FZN_PRODUCT_ANY != FZN_PRODUCT_NONE,
	      "the wildcard is the zero value, so a forgotten field grants everything");
	CHECK(fzn_service_capability(LOGS, FZN_PRODUCT_ANY, NULL, 0, &HASH, &any)
	              == FZN_CHAIN_OK,
	      "the wildcard was refused as a subject of a derivation");
}

/* Drop the service from the derivation and these two collide. */
static void test_two_services_do_not_collide(void)
{
	CHECK(!same(derive(LOGS, NETCFGD, "read"), derive(FILESTORE, NETCFGD, "read")),
	      "a capability for one service equals one for another");
}

/* Drop the product and the scoped capability equals the wildcard, which is
 * the quiet failure this pair exists to prevent. */
static void test_two_products_do_not_collide(void)
{
	CHECK(!same(derive(LOGS, NETCFGD, "read"), derive(LOGS, FUZZYPICKLES, "read")),
	      "two products share a capability, so the filter does nothing");
	CHECK(!same(derive(LOGS, NETCFGD, "read"), derive(LOGS, FZN_PRODUCT_ANY, "read")),
	      "a product-scoped capability equals the see-everything one");
}

/* Drop the name and two verbs collide. */
static void test_two_names_do_not_collide(void)
{
	CHECK(!same(derive(LOGS, NETCFGD, "read"), derive(LOGS, NETCFGD, "write")),
	      "two names share a capability");
	CHECK(!same(derive(LOGS, NETCFGD, ""), derive(LOGS, NETCFGD, "read")),
	      "an empty name equals a spelled one");
}

static void test_the_derivation_is_deterministic(void)
{
	CHECK(same(derive(LOGS, NETCFGD, "read"), derive(LOGS, NETCFGD, "read")),
	      "the same inputs produced two different capabilities");
}

static void test_the_pair_is_the_scoped_one_and_the_wildcard(void)
{
	fzn_cap_id_t scoped, any;

	REQUIRE(fzn_service_capability_pair(LOGS, NETCFGD, (const uint8_t *)"read", 4,
	                                    &HASH, &scoped, &any)
	                == FZN_CHAIN_OK,
	        "the pair refused a well-formed request");
	CHECK(same(scoped, derive(LOGS, NETCFGD, "read")),
	      "the pair's scoped half is not the scoped capability");
	CHECK(same(any, derive(LOGS, FZN_PRODUCT_ANY, "read")),
	      "the pair's wildcard half is not the see-everything capability");
	CHECK(!same(scoped, any), "the pair returned one capability twice");
}

/* A record belongs to a project. Asking whether a holder may see the
 * wildcard's records is the wrong question, so it is refused rather than
 * answered. */
static void test_the_pair_refuses_the_wildcard_as_a_subject(void)
{
	fzn_cap_id_t scoped, any;

	CHECK(fzn_service_capability_pair(LOGS, FZN_PRODUCT_ANY, NULL, 0, &HASH,
	                                  &scoped, &any)
	              == FZN_CHAIN_ERR_MALFORMED,
	      "a check subject of every-product was accepted");
}

static void test_the_caller_bugs_are_refused(void)
{
	fzn_cap_id_t out;
	uint8_t name[FZN_SERVICE_NAME_MAX + 1];

	memset(name, 'x', sizeof(name));
	CHECK(fzn_service_capability(LOGS, NETCFGD, NULL, 0, NULL, &out)
	              == FZN_CHAIN_ERR_MALFORMED, "a null hash seam was accepted");
	CHECK(fzn_service_capability(LOGS, NETCFGD, NULL, 0, &HASH, NULL)
	              == FZN_CHAIN_ERR_MALFORMED, "a null output was accepted");
	CHECK(fzn_service_capability(LOGS, NETCFGD, name, sizeof(name), &HASH, &out)
	              == FZN_CHAIN_ERR_MALFORMED, "a name past the bound was accepted");
	CHECK(fzn_service_capability(LOGS, NETCFGD, name, FZN_SERVICE_NAME_MAX, &HASH, &out)
	              == FZN_CHAIN_OK, "a name at the bound was refused");
	CHECK(fzn_service_capability(LOGS, NETCFGD, NULL, 4, &HASH, &out)
	              == FZN_CHAIN_ERR_MALFORMED, "a length with no bytes was accepted");
}

/* A refusing hash seam must be reported and must leave the caller's buffer
 * as it found it -- the rule session/commitment.c states. */
static void test_a_refusing_hash_is_reported_and_writes_nothing(void)
{
	fzn_cap_id_t out;

	memset(&out, 0x5a, sizeof(out));
	hash_refuses = 1;
	CHECK(fzn_service_capability(LOGS, NETCFGD, NULL, 0, &HASH, &out)
	              == FZN_CHAIN_ERR_MALFORMED, "a refusing hash reported success");
	hash_refuses = 0;
	CHECK(out.b[0] == 0x5a && out.b[FZN_CAP_ID_LEN - 1] == 0x5a,
	      "a refused derivation left a half-written capability");
}

/* The pair's second derivation can fail too, and its failure has to be the
 * caller's. A pair that reported OK with only its first half written is the
 * shape this checks for. */
static void test_the_pair_reports_a_late_failure(void)
{
	fzn_cap_id_t scoped, any;

	memset(&any, 0x33, sizeof(any));
	hash_refuses = 1;
	CHECK(fzn_service_capability_pair(LOGS, NETCFGD, NULL, 0, &HASH, &scoped, &any)
	              == FZN_CHAIN_ERR_MALFORMED, "a refusing hash reported a pair");
	hash_refuses = 0;
	CHECK(any.b[0] == 0x33, "a failed pair left a written wildcard half");
	CHECK(fzn_service_capability_pair(LOGS, NETCFGD, NULL, 0, NULL, &scoped, &any)
	              == FZN_CHAIN_ERR_MALFORMED, "the pair accepted a null hash seam");
	CHECK(fzn_service_capability_pair(LOGS, NETCFGD, NULL, 0, &HASH, &scoped, NULL)
	              == FZN_CHAIN_ERR_MALFORMED, "the pair accepted a null output");
}

/* A stream carries its product, so a receiver reads the product out of a
 * signed field rather than trusting one a sender set. */
static void test_a_stream_round_trips_its_product(void)
{
	uint32_t stream = 0;

	REQUIRE(fzn_service_stream(NETCFGD, 3u, &stream) == FZN_CHAIN_OK,
	        "a well-formed stream was refused");
	CHECK(fzn_service_stream_product(stream) == NETCFGD,
	      "a stream did not carry back the product it was derived for");
	CHECK((stream & FZN_STREAM_INDEX_MAX) == 3u,
	      "the issuer's own index did not survive the derivation");
}

/* Two products cannot land in one stream, which is the whole point: sharing
 * one is authorised correctly and syncs into a permanent wedge. */
static void test_two_products_never_share_a_stream(void)
{
	uint32_t a = 0, b = 0;

	REQUIRE(fzn_service_stream(NETCFGD, 5u, &a) == FZN_CHAIN_OK, "derive a");
	REQUIRE(fzn_service_stream(FUZZYPICKLES, 5u, &b) == FZN_CHAIN_OK, "derive b");
	CHECK(a != b, "two products at the same index share a stream");
	CHECK(fzn_service_stream_product(a) != fzn_service_stream_product(b),
	      "two streams answer the same product");
}

/* An issuer keeps the freedom record.h gives it, inside its product's half. */
static void test_an_issuer_still_assigns_its_own_index(void)
{
	uint32_t low = 0, high = 0;

	REQUIRE(fzn_service_stream(NETCFGD, 0u, &low) == FZN_CHAIN_OK, "index 0");
	REQUIRE(fzn_service_stream(NETCFGD, FZN_STREAM_INDEX_MAX, &high) == FZN_CHAIN_OK,
	        "the top index was refused");
	CHECK(low != high, "two indices in one product share a stream");
	CHECK(fzn_service_stream_product(low) == fzn_service_stream_product(high),
	      "two indices of one product answer different products");
}

/* Fuzznet's own space is product 0, and the reserved range sits inside it. */
static void test_fuzznets_own_space_is_product_none(void)
{
	CHECK(fzn_service_stream_product(0u) == FZN_PRODUCT_NONE,
	      "stream 0 belongs to a product");
	CHECK(fzn_service_stream_product(FZN_STREAM_RESERVED - 1u) == FZN_PRODUCT_NONE,
	      "the top of the reserved range belongs to a product");
	CHECK(fzn_service_stream_product(FZN_STREAM_INDEX_MAX) == FZN_PRODUCT_NONE,
	      "the top of fuzznet's half belongs to a product");
	CHECK(fzn_service_stream_product(FZN_STREAM_INDEX_MAX + 1u) != FZN_PRODUCT_NONE,
	      "the first product stream is still fuzznet's");
}

static void test_the_sentinels_have_no_stream(void)
{
	uint32_t stream = 0xdeadbeefu;

	CHECK(fzn_service_stream(FZN_PRODUCT_NONE, 0u, &stream) == FZN_CHAIN_ERR_MALFORMED,
	      "nobody's records were given a stream");
	CHECK(fzn_service_stream(FZN_PRODUCT_ANY, 0u, &stream) == FZN_CHAIN_ERR_MALFORMED,
	      "everybody's records were given a stream");
	CHECK(fzn_service_stream(NETCFGD, FZN_STREAM_INDEX_MAX + 1u, &stream)
	              == FZN_CHAIN_ERR_MALFORMED, "an index past the bound was accepted");
	CHECK(fzn_service_stream(NETCFGD, 0u, NULL) == FZN_CHAIN_ERR_MALFORMED,
	      "a null output was accepted");
	CHECK(stream == 0xdeadbeefu, "a refused derivation wrote to the caller's buffer");
}

/* A capability cannot be minted for a product no stream could carry, because
 * one that corresponds to no record is a bug rather than a narrow grant. */
static void test_a_product_past_the_stream_space_has_no_capability(void)
{
	fzn_cap_id_t out;

	/* FZN_PRODUCT_MAX + 1 is the wildcard itself, which IS allowed here --
	 * a see-everything capability is the point. The refusal starts above
	 * it, where a value is neither a real product nor a sentinel. */
	CHECK(fzn_service_capability(LOGS, (uint32_t)FZN_PRODUCT_ANY + 1u, NULL, 0,
	                             &HASH, &out) == FZN_CHAIN_ERR_MALFORMED,
	      "a product past the stream space was given a capability");
	CHECK(fzn_service_capability(LOGS, 0x10000u, NULL, 0, &HASH, &out)
	              == FZN_CHAIN_ERR_MALFORMED,
	      "a product outside the high half was given a capability");
	CHECK(fzn_service_capability(LOGS, FZN_PRODUCT_MAX, NULL, 0, &HASH, &out)
	              == FZN_CHAIN_OK, "the largest real product was refused");
}

/* A PEER CAN SEND A STREAM NOBODY COULD DERIVE. The top sixteenth of the
 * space reads back as FZN_PRODUCT_ANY, which no honest issuer can produce --
 * and the pair refuses it as a subject, so the forgery fails closed rather
 * than being checked as a wildcard. */
static void test_an_underivable_stream_fails_closed(void)
{
	fzn_cap_id_t scoped, any;
	uint32_t forged = 0xffff0001u;
	uint32_t product = fzn_service_stream_product(forged);

	CHECK(product == FZN_PRODUCT_ANY,
	      "the underivable range does not read back as the wildcard");
	CHECK(fzn_service_capability_pair(LOGS, product, NULL, 0, &HASH, &scoped, &any)
	              == FZN_CHAIN_ERR_MALFORMED,
	      "a stream nobody could derive was checked as a real product");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_a_service_is_mandatory();
	test_an_unspelled_product_is_refused_not_widened();
	test_two_services_do_not_collide();
	test_two_products_do_not_collide();
	test_two_names_do_not_collide();
	test_the_derivation_is_deterministic();
	test_the_pair_is_the_scoped_one_and_the_wildcard();
	test_the_pair_refuses_the_wildcard_as_a_subject();
	test_the_caller_bugs_are_refused();
	test_a_refusing_hash_is_reported_and_writes_nothing();
	test_the_pair_reports_a_late_failure();
	test_a_stream_round_trips_its_product();
	test_two_products_never_share_a_stream();
	test_an_issuer_still_assigns_its_own_index();
	test_fuzznets_own_space_is_product_none();
	test_the_sentinels_have_no_stream();
	test_a_product_past_the_stream_space_has_no_capability();
	test_an_underivable_stream_fails_closed();
	test_the_suite_can_tell_pass_from_fail();

	printf("service_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
